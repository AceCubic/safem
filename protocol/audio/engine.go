package audio

import (
	"encoding/binary"
	"fmt"
	"maps"
	"math"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/gen2brain/malgo"
	"github.com/hraban/opus"
)

const (
	// SampleRate is the audio sampling rate in Hz (Opus Standard).
	SampleRate = 48000

	// Channels defines Mono audio (sufficient for voice).
	Channels = 1

	// FrameSizeMs is the duration of a single audio frame in milliseconds.
	// 20ms is a standard trade-off between latency and overhead.
	FrameSizeMs = 20

	// FrameSizeSamples is the number of samples per frame (960 @ 48kHz).
	FrameSizeSamples = SampleRate * FrameSizeMs / 1000

	// MaxEncodedSize is the buffer size for Opus packets (conservative upper bound).
	MaxEncodedSize = 1200

	// JitterBufferTarget is the target latency in frames.
	// 3 frames * 20ms = 60ms added latency to absorb network jitter.
	JitterBufferTarget = 3

	// MaxSeq is the size of the uint16 sequence space.
	MaxSeq = 65536

	// MaxDropout is the sequence difference threshold to detect "ancient" packets
	// vs. wrapped-around packets.
	// 3000 frames @ 20ms = 60 seconds.
	MaxDropout = 3000
)

// Helper functions for float32 bit manipulation.
func float32FromBits(b uint32) float32 { return math.Float32frombits(b) }
func float32bits(f float32) uint32     { return math.Float32bits(f) }

// Memory Pooling

// packetPool recycles *[]byte objects to reduce GC pressure from high-frequency
// audio packet allocations (50 packets/sec per peer).
var packetPool = sync.Pool{
	New: func() any {
		// Pre-allocate buffer with capacity for standard Opus packet
		b := make([]byte, 0, MaxEncodedSize)
		return &b
	},
}

// releasePacket returns a packet buffer to the pool.
// It should be called immediately after the packet data is consumed.
func releasePacket(p *[]byte) {
	if p != nil {
		packetPool.Put(p)
	}
}

// Lock-Free Jitter Buffer

// JitterBuffer manages incoming audio packets for a single peer stream.
// It is designed for high-concurrency access (Network Push vs Audio Pop)
// using lock-free atomic operations for the critical data path.
type JitterBuffer struct {
	// slots is the storage backing. It is a direct map of SequenceID -> Data Pointer.
	// We use unsafe.Pointer to allow atomic Swap operations on the slice data.
	// stored type: *[]byte
	slots [MaxSeq]unsafe.Pointer

	// count tracks the number of filled slots atomically.
	count int32

	// latestSeq stores the highest SequenceID seen so far.
	// Used to calculate the "horizon" for rejecting old packets.
	latestSeq uint32

	// closed prevents new pushes during cleanup to avoid leaks.
	closed int32

	// Consumer state (Thread-local to the Audio Callback)
	lastPopped  uint16
	buffering   bool // True if we are filling the buffer (silence output)
	targetDepth int
	decoder     *opus.Decoder
}

// NewJitterBuffer creates a buffer with a specific target latency depth.
// The depth represents the number of frames to buffer before starting playback
// to handle network jitter.
func NewJitterBuffer(targetDepth int) *JitterBuffer {
	dec, _ := opus.NewDecoder(SampleRate, Channels)

	return &JitterBuffer{
		buffering:   true,
		targetDepth: targetDepth,
		lastPopped:  65535, // Initialize to -1 (uint16 wrap)
		latestSeq:   65535,
		decoder:     dec,
	}
}

// Level returns the approximate number of packets currently in the buffer.
// It is safe for concurrent calls and provides an atomic snapshot of the fill level.
func (jb *JitterBuffer) Level() int {
	return int(atomic.LoadInt32(&jb.count))
}

// Push inserts a packet into the buffer based on its Sequence ID.
// It handles out-of-order arrival, duplicate detection, and protection against
// sequence wrapping.
//
// Push accepts ownership of the *[]byte data. If the packet
// is rejected (old/duplicate) or overwritten, Push handles freeing it back to the pool.
// This method is safe to call from multiple network routines concurrently.
func (jb *JitterBuffer) Push(seq uint16, data *[]byte) {
	// Check if buffer is closed (Cleanup in progress)
	if atomic.LoadInt32(&jb.closed) == 1 {
		releasePacket(data)
		return
	}

	// Horizon Check: Is the packet too old?
	latest := uint16(atomic.LoadUint32(&jb.latestSeq))

	// Circular difference:
	// If diff < 0, seq is "behind" latest.
	// If diff > 0, seq is "ahead" (new latest).
	diff := int16(seq - latest)

	// If the packet is extremely old (behind by more than MaxDropout), drop it.
	// This protects against sequence number wrap-around collision.
	if diff < -MaxDropout {
		releasePacket(data)
		return
	}

	// Atomic Insertion (Zero-Copy)
	ptr := unsafe.Pointer(data)

	// SwapPointer writes the new data pointer into the slot.
	// It returns the OLD value.
	old := atomic.SwapPointer(&jb.slots[seq], ptr)

	// If old was nil, this is a new packet -> Increment count.
	if old == nil {
		atomic.AddInt32(&jb.count, 1)
	} else {
		// If old was NOT nil, we overwrote a packet (duplicate or stalled).
		// We must release the old packet back to the pool to prevent leaks.
		releasePacket((*[]byte)(old))
	}

	// Re-validate Horizon
	// Race Condition Handling: Another thread might have advanced latestSeq
	// significantly while we were working.
	newLatest := uint16(atomic.LoadUint32(&jb.latestSeq))
	if int16(seq-newLatest) < -MaxDropout {
		// Note: We might be removing the packet we just inserted, or a newer one
		// if a race occurred. Swapping nil handles cleanup correctly.
		if removed := atomic.SwapPointer(&jb.slots[seq], nil); removed != nil {
			atomic.AddInt32(&jb.count, -1)
			releasePacket((*[]byte)(removed))
		}
		return
	}

	// Update latestSeq (Compare-and-Swap loop)
	for {
		currentLatest := atomic.LoadUint32(&jb.latestSeq)
		currentLatest16 := uint16(currentLatest)

		if int16(seq-currentLatest16) <= 0 {
			// Current latest is already ahead or equal to this seq.
			break
		}

		if atomic.CompareAndSwapUint32(&jb.latestSeq, currentLatest, uint32(seq)) {
			break
		}
		// CAS failed, retry
	}
}

// Pop retrieves the next sequential audio packet pointer for playback.
// It returns a *[]byte from the pool, or nil if the buffer is buffering/empty (underrun).
// The caller MUST call releasePacket() on the returned pointer after use.
//
// This method MUST ONLY be called by the single audio consumer thread (e.g., the audio callback).
func (jb *JitterBuffer) Pop() *[]byte {
	// Buffering State Logic
	// If we are in buffering mode, wait until we hit targetDepth.
	if jb.buffering {
		currentLevel := atomic.LoadInt32(&jb.count)
		if int(currentLevel) >= jb.targetDepth {
			jb.buffering = false

			// Fast-Forward Logic:
			// If we buffered for too long, the "latest" might be far ahead.
			// Jump the read head (lastPopped) to [latest - depth] to reduce latency.
			latest := uint16(atomic.LoadUint32(&jb.latestSeq))
			newLastPopped := latest - uint16(jb.targetDepth)

			if jb.lastPopped != newLastPopped {
				// Clean up skipped slots to correct the count and free memory
				for i := uint16(jb.lastPopped + 1); i != newLastPopped; i++ {
					if ptr := atomic.SwapPointer(&jb.slots[i], nil); ptr != nil {
						atomic.AddInt32(&jb.count, -1)
						releasePacket((*[]byte)(ptr))
					}
				}
				jb.lastPopped = newLastPopped
			}
		} else {
			// Still buffering, output silence
			return nil
		}
	}

	// Retrieve Next Packet
	next := jb.lastPopped + 1

	// Atomic Swap: Get data and set slot to nil (consumes the packet)
	ptr := atomic.SwapPointer(&jb.slots[next], nil)
	jb.lastPopped = next

	if ptr != nil {
		atomic.AddInt32(&jb.count, -1)
		return (*[]byte)(ptr)
	}

	// Underrun / Packet Loss
	// If buffer is completely empty, re-enter buffering state.
	if atomic.LoadInt32(&jb.count) == 0 {
		jb.buffering = true
	}

	// Return nil triggers Packet Loss Concealment (PLC) in the Opus decoder.
	return nil
}

// Cleanup releases all buffered packets back to the pool and marks the buffer as closed.
// It must be called when removing a peer to prevent memory leaks of pooled buffers.
func (jb *JitterBuffer) Cleanup() {
	// Mark closed to stop new pushes
	if !atomic.CompareAndSwapInt32(&jb.closed, 0, 1) {
		return // Already closed
	}

	// Iterate all slots and free any remaining packets
	// Note: We scan the whole array. Since this happens only on disconnect,
	// the overhead of 65k iterations is acceptable for leak safety.
	for i := 0; i < len(jb.slots); i++ {
		if ptr := atomic.SwapPointer(&jb.slots[i], nil); ptr != nil {
			releasePacket((*[]byte)(ptr))
			atomic.AddInt32(&jb.count, -1)
		}
	}
}

// Audio Engine

// Engine manages the audio hardware interface (via Malgo/PortAudio) and the mixing pipeline.
// It handles capture, encoding, networking callbacks, mixing, decoding, and playback.
type Engine struct {
	context *malgo.AllocatedContext
	device  *malgo.Device
	enc     *opus.Encoder

	// sendFunc is the callback to push encoded packets to the network.
	sendFunc func([]byte)

	// inputs stores active JitterBuffers for mixing.
	// Key: PeerID
	// Value: *JitterBuffer
	// We use atomic.Value to implement Copy-On-Write for lock-free iteration in the audio callback.
	inputs atomic.Value

	// stateMu serializes updates to the inputs map (Add/Remove peer).
	// It is NOT held during the audio callback.
	stateMu sync.Mutex

	sendSeq uint16

	// Hardware Device Selection
	inputID  *malgo.DeviceID
	outputID *malgo.DeviceID

	// muted state: 0 = unmuted, 1 = muted
	muted int32
}

// NewEngine creates a new, idle audio engine with initialized internal state.
// It does not allocate hardware resources until Init() or Start() is called.
func NewEngine() *Engine {
	e := &Engine{}
	// Initialize the atomic inputs map
	e.inputs.Store(make(map[string]*JitterBuffer))
	return e
}

// SetMute controls the microphone input state.
// If muted, the engine continues to process and send packets, but with silence (0.0),
// ensuring the connection remains alive (Keep-Alive via RTP/Opus).
func (e *Engine) SetMute(muted bool) {
	var val int32 = 0
	if muted {
		val = 1
	}
	atomic.StoreInt32(&e.muted, val)
}

// IsMuted returns the current mute status of the microphone.
// It is safe for concurrent use.
func (e *Engine) IsMuted() bool {
	return atomic.LoadInt32(&e.muted) == 1
}

// EnsureContext initializes the underlying audio context (Malgo/PortAudio) if it is not already active.
func (e *Engine) EnsureContext() error {
	if e.context != nil {
		return nil
	}
	ctx, err := malgo.InitContext(nil, malgo.ContextConfig{}, nil)
	if err != nil {
		return err
	}
	e.context = ctx
	return nil
}

// ListDevices returns the available audio capture and playback devices found on the system.
func (e *Engine) ListDevices() ([]malgo.DeviceInfo, []malgo.DeviceInfo, error) {
	if err := e.EnsureContext(); err != nil {
		return nil, nil, err
	}
	capture, err := e.context.Devices(malgo.Capture)
	if err != nil {
		return nil, nil, err
	}
	playback, err := e.context.Devices(malgo.Playback)
	if err != nil {
		return nil, nil, err
	}
	return capture, playback, nil
}

// SetInputDevice configures the specific capture device to use by ID.
func (e *Engine) SetInputDevice(id *malgo.DeviceID) {
	e.inputID = id
}

// SetOutputDevice configures the specific playback device to use by ID.
func (e *Engine) SetOutputDevice(id *malgo.DeviceID) {
	e.outputID = id
}

// Init initializes the Opus encoder and prepares the hardware device configuration.
// It allocates the audio context but does not start the audio processing loop.
func (e *Engine) Init() error {
	var err error
	// VoIP application type optimizes for voice frequencies.
	e.enc, err = opus.NewEncoder(SampleRate, Channels, opus.AppVoIP)
	if err != nil {
		return fmt.Errorf("failed to create opus encoder: %v", err)
	}

	if err := e.EnsureContext(); err != nil {
		return err
	}

	// Configure Hardware Device
	cfg := malgo.DefaultDeviceConfig(malgo.Duplex)
	cfg.Capture.Format = malgo.FormatF32
	cfg.Capture.Channels = Channels
	cfg.Playback.Format = malgo.FormatF32
	cfg.Playback.Channels = Channels
	cfg.SampleRate = SampleRate
	cfg.PeriodSizeInMilliseconds = FrameSizeMs

	if e.inputID != nil {
		cfg.Capture.DeviceID = e.inputID.Pointer()
	}
	if e.outputID != nil {
		cfg.Playback.DeviceID = e.outputID.Pointer()
	}

	// Buffer Initialization
	// We pre-allocate buffers to avoid GC pressure in the realtime callback.

	// Ring buffer to adapt arbitrary hardware buffer sizes to fixed Opus frame sizes.
	ringSize := FrameSizeSamples * 8
	captureRing := make([]float32, ringSize)
	ringHead := 0
	ringTail := 0
	ringLen := 0

	inputBuf := make([]float32, FrameSizeSamples*2)
	processingBuf := make([]float32, FrameSizeSamples) // Holds exactly one frame for encoding
	encodeBuf := make([]byte, MaxEncodedSize)          // Destination for Opus bytes

	// Mixing Buffers
	mixBuf := make([]float32, FrameSizeSamples)
	decodeBuf := make([]float32, FrameSizeSamples)

	// Packet Pool prevents allocs when sending data to the channel
	pktPool := make(chan []byte, 100)
	for range 100 {
		pktPool <- make([]byte, MaxEncodedSize)
	}

	// Realtime Audio Callback
	callbacks := malgo.DeviceCallbacks{
		Data: func(pOutput, pInput []byte, framecount uint32) {
			sampleCount := int(framecount) * Channels

			// ============================
			// CAPTURE & ENCODE PATH
			// ============================

			// Cast raw bytes to float32
			if len(inputBuf) < sampleCount {
				inputBuf = make([]float32, sampleCount)
			}

			isMuted := atomic.LoadInt32(&e.muted) == 1

			for i := range sampleCount {
				// If muted, we write silence (0.0) into the input buffer.
				// This keeps the encoder running and sending packets (Silence frames),
				// preventing the connection from appearing dead.
				if isMuted {
					inputBuf[i] = 0.0
				} else {
					start := i * 4
					bits := binary.LittleEndian.Uint32(pInput[start : start+4])
					inputBuf[i] = float32FromBits(bits)
				}
			}

			// Push to Ring Buffer
			for i := range sampleCount {
				captureRing[ringHead] = inputBuf[i]
				ringHead = (ringHead + 1) % ringSize
				ringLen++

				if ringLen > ringSize {
					// Overrun: advance tail to drop oldest data
					ringTail = (ringTail + 1) % ringSize
					ringLen = ringSize
				}
			}

			// Drain Ring Buffer in exact FrameSize chunks
			for ringLen >= FrameSizeSamples {
				for i := range FrameSizeSamples {
					processingBuf[i] = captureRing[ringTail]
					ringTail = (ringTail + 1) % ringSize
				}
				ringLen -= FrameSizeSamples

				// Encode Opus Frame
				n, err := e.enc.EncodeFloat32(processingBuf, encodeBuf)
				if err != nil {
					continue
				}

				// Send to Network
				if n > 0 && e.sendFunc != nil {
					var pkt []byte
					select {
					case pkt = <-pktPool:
					default:
						pkt = make([]byte, MaxEncodedSize)
					}

					// Packet Format: [SeqID uint16][Opus Data]
					if cap(pkt) >= n+2 {
						pkt = pkt[:n+2]
						binary.BigEndian.PutUint16(pkt[0:2], e.sendSeq)
						e.sendSeq++
						copy(pkt[2:], encodeBuf[:n])

						e.sendFunc(pkt)

						// Return buffer to pool if possible
						if cap(pkt) == MaxEncodedSize {
							select {
							case pktPool <- pkt[:MaxEncodedSize]:
							default:
							}
						}
					}
				}
			}

			// ============================
			// PLAYBACK & MIXING PATH
			// ============================

			// Clear mixing buffer (Silence)
			for i := range sampleCount {
				mixBuf[i] = 0
			}

			// Snapshot active inputs using Atomic Load.
			// This avoids RWMutex contention with AddPeer/RemovePeer.
			currentInputs := e.inputs.Load().(map[string]*JitterBuffer)

			if len(currentInputs) == 0 {
				// No peers, write silence to hardware
				for i := range pOutput {
					pOutput[i] = 0
				}
				return
			}

			// Mix Loop: Sum audio from all active peers
			for _, jb := range currentInputs {
				// Prevent latency buildup: Drop frame if buffer is too full
				level := jb.Level()
				if level > JitterBufferTarget+8 {
					// Pop and release immediately to catch up
					if ptr := jb.Pop(); ptr != nil {
						releasePacket(ptr)
					}
				}

				// Get Opus packet pointer from Jitter Buffer (from Pool)
				packetPtr := jb.Pop()
				var packet []byte
				if packetPtr != nil {
					packet = *packetPtr
				}

				// Decode to PCM float32
				// Note: Decoder handles nil packet by generating PLC
				n, err := jb.decoder.DecodeFloat32(packet, decodeBuf)

				// Important: Release buffer back to pool after decoding
				if packetPtr != nil {
					releasePacket(packetPtr)
				}

				// Accumulate (Mix)
				if err == nil && n > 0 {
					for i := 0; i < n && i < sampleCount; i++ {
						mixBuf[i] += decodeBuf[i]
					}
				} else if packet == nil && err != nil {
					// Packet Loss Concealment (PLC)
					if n > 0 {
						for i := 0; i < n && i < sampleCount; i++ {
							mixBuf[i] += decodeBuf[i]
						}
					}
				}
			}

			// Write to Hardware Output (with soft clipping)
			for i := range sampleCount {
				sample := mixBuf[i]
				// Clamp values to valid float32 range [-1.0, 1.0]
				if sample > 1.0 {
					sample = 1.0
				} else if sample < -1.0 {
					sample = -1.0
				}

				bits := float32bits(sample)
				start := i * 4
				binary.LittleEndian.PutUint32(pOutput[start:start+4], bits)
			}
		},
	}

	e.device, err = malgo.InitDevice(e.context.Context, cfg, callbacks)
	return err
}

// Start begins the realtime audio processing loop.
// sendCallback is the function that will be invoked whenever an encoded audio packet
// is ready to be transmitted to the network.
func (e *Engine) Start(sendCallback func([]byte)) error {
	e.sendFunc = sendCallback
	e.sendSeq = 0
	if e.device == nil {
		if err := e.Init(); err != nil {
			return err
		}
	}
	return e.device.Start()
}

// Stop halts the audio processing loop and pauses hardware I/O.
func (e *Engine) Stop() {
	e.sendFunc = nil
	if e.device != nil {
		e.device.Stop()
	}
}

// Restart halts and re-initializes the engine, applying any new device configurations.
func (e *Engine) Restart() error {
	cb := e.sendFunc
	if cb == nil {
		return nil
	}
	e.Stop()
	e.Reset()
	return e.Start(cb)
}

// Reset fully tears down the device handle and uninitializes the hardware interface.
func (e *Engine) Reset() {
	if e.device != nil {
		e.device.Stop()
		e.device.Uninit()
		e.device = nil
	}
}

// Cleanup stops the engine and frees all native resources (Context, Encoder).
func (e *Engine) Cleanup() {
	e.Stop()
	if e.context != nil {
		e.context.Free()
	}
	e.enc = nil
}

// AddPeer creates a new JitterBuffer for the specified peer ID and adds them to the mix.
// It uses a Copy-On-Write strategy to safely update the active inputs list without
// blocking the realtime audio callback.
func (e *Engine) AddPeer(id string) {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	oldMap := e.inputs.Load().(map[string]*JitterBuffer)

	// Check if already exists
	if _, exists := oldMap[id]; exists {
		return
	}

	// Clone to new map
	newMap := make(map[string]*JitterBuffer, len(oldMap)+1)
	maps.Copy(newMap, oldMap)

	// Add new peer
	newMap[id] = NewJitterBuffer(JitterBufferTarget)

	// Atomically Swap
	e.inputs.Store(newMap)
}

// RemovePeer removes the specified peer from the audio mix and cleans up their resources.
// It uses Copy-On-Write for thread safety and ensures the JitterBuffer is drained.
func (e *Engine) RemovePeer(id string) {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	oldMap := e.inputs.Load().(map[string]*JitterBuffer)

	if _, exists := oldMap[id]; !exists {
		return
	}

	// Clone and Delete
	newMap := make(map[string]*JitterBuffer, len(oldMap))
	for k, v := range oldMap {
		if k != id {
			newMap[k] = v
		} else {
			// Clean up the removed buffer to return pooled objects
			v.Cleanup()
		}
	}

	e.inputs.Store(newMap)
}

// RemoveAllPeers clears all active peers from the engine and cleans up their buffers.
// This is typically called when a call ends to reset the mixing state.
func (e *Engine) RemoveAllPeers() {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	// Clean up all existing buffers
	oldMap := e.inputs.Load().(map[string]*JitterBuffer)
	for _, v := range oldMap {
		v.Cleanup()
	}

	// Store empty map
	e.inputs.Store(make(map[string]*JitterBuffer))
}

// ProcessIncoming routes an incoming audio packet to the appropriate peer's JitterBuffer.
//
// This method accepts ownership of the data pointer. If the peer is unknown
// or the data is invalid, it frees the packet immediately back to the pool.
// It is designed to be called directly from the network ingress layer.
func (e *Engine) ProcessIncoming(sourceID string, data *[]byte) {
	if data == nil {
		return
	}

	if len(*data) < 2 {
		releasePacket(data)
		return
	}
	// Parse Sequence ID from first 2 bytes
	seq := binary.BigEndian.Uint16((*data)[0:2])

	// Reslice to remove header (safe in-place)
	*data = (*data)[2:]

	// Lock-free read for network thread
	currentInputs := e.inputs.Load().(map[string]*JitterBuffer)

	if jb, exists := currentInputs[sourceID]; exists {
		// Pass ownership to JitterBuffer
		jb.Push(seq, data)
	} else {
		// Peer not active in audio engine, drop packet to prevent leak
		releasePacket(data)
	}
}