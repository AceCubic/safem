package p2p

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	bstd "github.com/banditmoscow1337/benc/std/golang"
	"github.com/banditmoscow1337/safem/protocol"
	"github.com/banditmoscow1337/safem/protocol/cryptolib"
	"golang.org/x/time/rate"
)

// packetBufferPool recycles inbound packet buffers to reduce GC pressure.
// We use a pointer to slice (*[]byte) to avoid allocation when putting/getting from pool.
var packetBufferPool = sync.Pool{
	New: func() any {
		// Allocate a slice with maximum capacity for standard UDP packets
		b := make([]byte, MaxPacketSize)
		return &b
	},
}

const (
	// IngressRateLimit is the allowed packets per second per IP.
	// 500 pps allows for active voice (50pps) + file transfer + signaling overhead
	// while still blocking aggressive floods.
	IngressRateLimit = 500

	// IngressBurstLimit is the maximum burst size allowed.
	IngressBurstLimit = 100

	// LimiterCleanupInterval controls how often we purge stale IPs from the limiter map.
	LimiterCleanupInterval = 5 * time.Minute

	// LimiterStaleDuration is the time after which an inactive IP is removed from tracking.
	LimiterStaleDuration = 10 * time.Minute
)

// Transport manages the underlying UDP connection and the ingress packet processing loop.
// It handles reading from the socket, decrypting packets, and dispatching them to the Peer.
type Transport struct {
	conn *net.UDPConn

	// Callbacks to interact with the Peer's session and handling layers.
	GetSession func(addr string) (*Session, bool)
	Dispatch   func(remote *net.UDPAddr, sess *Session, keyID uint32, pkt protocol.Packet)
	Logger     func(format string, args ...any)

	// Metrics Pointer
	PacketsDropped *atomic.Uint64

	// Rate Limiting
	limiterMu   sync.Mutex
	limiters    map[string]*rate.Limiter
	lastSeen    map[string]time.Time
	stopCleanup chan struct{}
}

// Start binds the UDP listener and starts the listen loop.
func (t *Transport) Start(port int) (string, error) {
	addrStr := fmt.Sprintf(":%d", port)
	udpAddr, _ := net.ResolveUDPAddr("udp", addrStr)
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return "", err
	}
	t.conn = conn

	// Initialize Rate Limiting state
	t.limiters = make(map[string]*rate.Limiter)
	t.lastSeen = make(map[string]time.Time)
	t.stopCleanup = make(chan struct{})

	// Start background cleanup for rate limiters
	go t.cleanupLimiters()

	go t.listenLoop()
	return conn.LocalAddr().String(), nil
}

// cleanupLimiters removes stale limiters to prevent memory leaks from old IPs.
func (t *Transport) cleanupLimiters() {
	ticker := time.NewTicker(LimiterCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCleanup:
			return
		case <-ticker.C:
			t.limiterMu.Lock()
			now := time.Now()
			for ip, seen := range t.lastSeen {
				if now.Sub(seen) > LimiterStaleDuration {
					delete(t.limiters, ip)
					delete(t.lastSeen, ip)
				}
			}
			t.limiterMu.Unlock()
		}
	}
}

// allowIP checks if the IP is allowed to send packets based on rate limits.
func (t *Transport) allowIP(ip string) bool {
	t.limiterMu.Lock()
	defer t.limiterMu.Unlock()

	lim, exists := t.limiters[ip]
	if !exists {
		lim = rate.NewLimiter(rate.Limit(IngressRateLimit), IngressBurstLimit)
		t.limiters[ip] = lim
	}
	t.lastSeen[ip] = time.Now()

	return lim.Allow()
}

// listenLoop continuously reads from the UDP socket and dispatches packets to workers.
func (t *Transport) listenLoop() {
	type packetJob struct {
		remote  *net.UDPAddr
		data    []byte
		poolRef *[]byte // Reference to the original buffer for cleanup
	}

	// Buffer job channel to handle burst traffic.
	// Increased to 1024 to prevent blocking the UDP reader during high-throughput bursts.
	jobChan := make(chan packetJob, 1024)

	// Spawn a pool of worker goroutines for packet processing (decryption/handling)
	numWorkers := runtime.NumCPU()
	for i := 0; i < numWorkers; i++ {
		go func() {
			for job := range jobChan {
				// Process using standard IP lookup
				t.ProcessPacket(job.remote, nil, job.data)

				// Return the buffer to the pool after processing.
				// This enables zero-copy unmarshalling in 'process' by guaranteeing
				// the buffer is valid for the duration of the synchronous handler chain.
				if job.poolRef != nil {
					packetBufferPool.Put(job.poolRef)
				}
			}
		}()
	}

	// Local buffer for the syscall read, effectively bypassed by the pool logic below
	// but kept for fallback or specific io patterns if needed.
	// For this implementation, we read directly into the pooled buffer.
	for {
		// Acquire buffer from pool
		ptr := packetBufferPool.Get().(*[]byte)
		pooledBuf := *ptr

		// ReadFromUDP can read directly into the pooled slice
		n, remote, err := t.conn.ReadFromUDP(pooledBuf)
		if err != nil {
			// Recycle buffer on error
			packetBufferPool.Put(ptr)

			// In a real app, handle temporary errors (Backoff) or exit if closed.
			// For now, we check if the connection is closed.
			if t.conn == nil {
				return
			}
			continue
		}

		// Send job with the slice of valid data and the pointer for cleanup
		// job.data is a slice of the backing array in pooledBuf
		jobChan <- packetJob{remote: remote, data: pooledBuf[:n], poolRef: ptr}
	}
}

// ProcessPacket handles the decryption and routing of a single packet.
// It allows injecting a specific session (for Relay) or using IP lookup if sess is nil.
func (t *Transport) ProcessPacket(remote *net.UDPAddr, overrideSess *Session, data []byte) {
	// Ingress Rate Limiting (Before Decryption)
	// We only limit direct packets (overrideSess == nil).
	// Relayed packets are effectively limited by the outer OpRelay packet's check
	// when they first arrived at the transport.
	if overrideSess == nil {
		if !t.allowIP(remote.IP.String()) {
			if t.PacketsDropped != nil {
				t.PacketsDropped.Add(1)
			}
			// Silently drop to prevent CPU exhaustion
			return
		}
	}

	if len(data) < 4 {
		if t.PacketsDropped != nil {
			t.PacketsDropped.Add(1)
		}
		return
	}

	// WireID identifies the session (or 0 for cleartext)
	keyID := binary.BigEndian.Uint32(data[0:4])
	body := data[4:]

	var pkt protocol.Packet
	var err error
	var sess *Session

	// Handle Cleartext (Handshake/Punch only)
	if keyID == 0 {
		pkt, err = protocol.UnmarshalPacket(body)
		if err != nil {
			if t.PacketsDropped != nil {
				t.PacketsDropped.Add(1)
			}
			return
		}
		if pkt.Op != protocol.OpHandshake && pkt.Op != protocol.OpPunch {
			t.Logger("[Net] Dropped Cleartext non-handshake packet from %s\n", remote.String())
			if t.PacketsDropped != nil {
				t.PacketsDropped.Add(1)
			}
			return
		}
	} else {
		// Handle Encrypted Packets
		if overrideSess != nil {
			sess = overrideSess
		} else {
			var ok bool
			sess, ok = t.GetSession(remote.String())
			if !ok {
				// Unknown session usually means we can't decrypt, drop.
				if t.PacketsDropped != nil {
					t.PacketsDropped.Add(1)
				}
				return
			}
		}

		// Verify WireID matches session
		if sess.WireID != keyID {
			if t.PacketsDropped != nil {
				t.PacketsDropped.Add(1)
			}
			return // Mismatch
		}

		// Parse Header: [SeqID 8][Flag 1][RatchetKey?][Nonce 12][Ciphertext...]
		// Minimum size check: 8 + 1 + 12 = 21
		if len(body) < 21 {
			if t.PacketsDropped != nil {
				t.PacketsDropped.Add(1)
			}
			return
		}

		seqID := binary.BigEndian.Uint64(body[0:8])
		flag := body[8]
		offset := 9

		var newRemoteKey []byte

		// Check for Ratchet Key in header
		if flag&0x01 != 0 {
			if len(body) < offset+32+12 {
				if t.PacketsDropped != nil {
					t.PacketsDropped.Add(1)
				}
				return
			}
			newRemoteKey = body[offset : offset+32]
			offset += 32
		}

		nonce := body[offset : offset+12]
		ciphertext := body[offset+12:]

		// Handle Ratchet Step *BEFORE* Decryption
		if newRemoteKey != nil {
			// Atomic Check-and-Mix to prevent race conditions
			if _, err := sess.CheckAndMixRatchet(newRemoteKey); err != nil {
				t.Logger("[Ratchet] Mix failed: %v\n", err)
			}
		}

		sess.Lock()
		sess.LastRx = time.Now()

		// Retrieve correct Message Key via Symmetric Ratchet
		// This uses the chain state potentially updated by MixRatchet above
		_, currentAEAD, err := sess.GetDecryptionKey(seqID)
		sess.Unlock()

		if err != nil {
			if t.PacketsDropped != nil {
				t.PacketsDropped.Add(1)
			}
			return
		}

		var dec []byte
		if currentAEAD != nil {
			// We reuse the 'ciphertext' backing array (which is part of our pooled buffer)
			// as the destination for the decrypted plaintext.
			// ciphertext[:0] keeps the capacity but resets length.
			dec, err = currentAEAD.Open(ciphertext[:0], nonce, ciphertext, nil)
		} else {
			err = fmt.Errorf("session cipher not ready")
		}

		if err != nil {
			if t.PacketsDropped != nil {
				t.PacketsDropped.Add(1)
			}
			return // Decryption failed
		}

		// pkt.Payload now points to a slice of 'dec', which is inside our pooled buffer.
		pkt, err = protocol.UnmarshalPacket(dec)
		if err != nil {
			if t.PacketsDropped != nil {
				t.PacketsDropped.Add(1)
			}
			return
		}
		if pkt.SequenceID != seqID {
			if t.PacketsDropped != nil {
				t.PacketsDropped.Add(1)
			}
			return // Mismatch implies tampering
		}
	}

	// Dispatch Packet to Peer
	// The Packet payload is valid ONLY for the duration of this call.
	// Asynchronous handlers must copy the data.
	t.Dispatch(remote, sess, keyID, pkt)
}

// dispatchPacket routes a decoded packet to the appropriate handler or waiting RPC channel.
func (p *Peer) dispatchPacket(remote *net.UDPAddr, sess *Session, keyID uint32, pkt protocol.Packet) {
	if pkt.Op == protocol.OpPunch {
		return // NAT keep-alive, no processing needed
	}

	// Handle RPC Response
	if pkt.IsReply {
		p.pendingMu.Lock()
		if ch, ok := p.pending[pkt.ReqID]; ok {
			ch <- &pkt
		}
		p.pendingMu.Unlock()
		return
	}

	// Replay Protection (for non-idempotent ops)
	if keyID != 0 && sess != nil {
		p.replayMu.Lock()
		state, exists := p.replayStates[sess.ID]
		if !exists {
			state = &ReplayWindow{}
			p.replayStates[sess.ID] = state
		}
		allowed := state.CheckAndUpdate(pkt.SequenceID)
		p.replayMu.Unlock()

		if !allowed {
			p.PacketsDropped.Add(1)
			return // Drop replay
		}
	}

	p.handlersMu.RLock()
	handler, ok := p.handlers[pkt.Op]
	p.handlersMu.RUnlock()

	// Special handling for Voice/Disconnect (No response needed)
	if pkt.Op == protocol.OpVoice || pkt.Op == protocol.OpDisconnect {
		if ok {
			handler(remote, pkt.Payload)
		}

		// Trigger session closed callback upon receiving OpDisconnect.
		// This ensures upper layers (like VoiceManager) handle the cleanup (hangup).
		if pkt.Op == protocol.OpDisconnect && p.OnSessionClosed != nil {
			var id string
			if sess != nil {
				id = sess.ID
			} else {
				id = p.GetID(remote.String())
			}
			if id != "" {
				p.OnSessionClosed(id)
			}
		}

		return
	}

	var resp []byte
	if ok {
		resp, _ = handler(remote, pkt.Payload)
	}

	// Default ACK for Ping if no specific response
	if resp == nil && pkt.Op != protocol.OpPing {
		return
	}
	if resp == nil && pkt.Op == protocol.OpPing {
		resp = []byte("ACK")
	}

	// Send Response (Implicit RPC)
	// Response doesn't need to increment global request counter, but needs a sequence ID.
	// sendPacket will overwrite the SequenceID with the session's ratchet ID anyway.
	respPkt := protocol.Packet{
		ReqID:      pkt.ReqID,
		SequenceID: 0, // Placeholder, updated in sendPacket
		IsReply:    true,
		Op:         pkt.Op,
		Payload:    resp,
	}

	// Send directly to the remote address
	target := remote.String()
	p.sendPacket(target, respPkt)
}

// sealPacket encrypts a packet for a specific session without sending it.
// Returns the raw bytes ready for the wire.
func (p *Peer) sealPacket(sess *Session, pkt protocol.Packet) ([]byte, error) {
	sess.Lock()
	// Trigger DH Ratchet Update if interval reached
	if sess.TxCount%DHRatchetInterval == 0 && sess.TxCount > 0 {
		if err := sess.RotateRatchet(); err != nil {
			p.Logger("[Ratchet] Rotation failed: %v\n", err)
		} else {
			p.Logger("[Ratchet] Session Key Self-Healed (Tx)\n")
		}
	}

	// Advance Symmetric Ratchet to get unique Message Key for this packet
	seqID := sess.TxCount

	_, currentAEAD, err := sess.AdvanceSendRatchet()
	if err != nil {
		sess.Unlock()
		return nil, err
	}

	wireID := sess.WireID
	ratchetPub := sess.RatchetPubBytes
	sess.Unlock()

	// Update packet sequence to match session sequence (for validation on rx side)
	pkt.SequenceID = seqID
	marshaled := protocol.MarshalPacket(pkt)
	defer protocol.FreePacketBuffer(marshaled)

	// Acquire buffer from pool
	bufPtr := sendBufferPool.Get().(*[]byte)
	// Reset but keep capacity
	finalBuf := (*bufPtr)[:0]

	// Random Nonce Generation
	nonce, err := cryptolib.GenerateRandomBytes(12)
	if err != nil {
		sendBufferPool.Put(bufPtr)
		return nil, err
	}

	// Header: [WireID 4][SeqID 8][Flag 1][RatchetKey?][Nonce 12]
	finalBuf = binary.BigEndian.AppendUint32(finalBuf, wireID)
	finalBuf = binary.BigEndian.AppendUint64(finalBuf, seqID)

	var flag uint8 = 0
	if len(ratchetPub) == 32 {
		flag = 1
	}
	finalBuf = append(finalBuf, flag)

	if flag == 1 {
		finalBuf = append(finalBuf, ratchetPub...)
	}

	finalBuf = append(finalBuf, nonce...)

	// Encrypt-in-place
	finalBuf = currentAEAD.Seal(finalBuf, nonce, marshaled, nil)

	out := make([]byte, len(finalBuf))
	copy(out, finalBuf)
	sendBufferPool.Put(bufPtr)

	return out, nil
}

// sendPacket encrypts and transmits a packet directly to the target.
// It uses sendBufferPool to minimize allocations and encrypts in-place.
func (p *Peer) sendPacket(targetAddr string, pkt protocol.Packet) error {
	sess, ok := p.GetSessionByAddr(targetAddr)

	// RELAY LOGIC
	if ok && sess.IsRelayed && pkt.Op != protocol.OpHandshake && pkt.Op != protocol.OpPunch {
		// Encrypt the packet using the PEER session keys (Inner Layer)
		encryptedInner, err := p.sealPacket(sess, pkt)
		if err != nil {
			return err
		}

		// Wrap in OpRelay Packet: [TargetID (Peer)][InnerPacket (Encrypted)]
		// We marshal ID + Bytes manually to avoid overhead.
		targetID := sess.ID

		// Use bstd to pack: [Len][ID][InnerData]
		// Actually, standard manual pack is safer with protocol utils.
		// server expects: PackStrings(id) + innerData. But PackStrings uses Benc encoding for strings.
		// Let's use bstd.MarshalString + append.

		importSize := 10 + len(targetID) + len(encryptedInner) // rough estimate
		buf := make([]byte, importSize)
		n := bstd.MarshalString(0, buf, targetID)
		buf = buf[:n]
		buf = append(buf, encryptedInner...)

		// Send to Relay Server using the RELAY session (Outer Layer)
		return p.SendFast(context.Background(), sess.RelayAddr, protocol.OpRelay, buf)
	}

	var currentAEAD cipher.AEAD
	var wireID uint32
	var ratchetPub []byte
	var seqID uint64

	if ok {
		sess.Lock()
		// Trigger DH Ratchet Update if interval reached
		if sess.TxCount%DHRatchetInterval == 0 && sess.TxCount > 0 {
			if err := sess.RotateRatchet(); err != nil {
				p.Logger("[Ratchet] Rotation failed: %v\n", err)
			} else {
				p.Logger("[Ratchet] Session Key Self-Healed (Tx)\n")
			}
		}

		// Advance Symmetric Ratchet to get unique Message Key for this packet
		seqID = sess.TxCount

		_, aead, err := sess.AdvanceSendRatchet()
		if err != nil {
			sess.Unlock()
			return err
		}
		currentAEAD = aead
		wireID = sess.WireID
		ratchetPub = sess.RatchetPubBytes
		sess.Unlock()
	}

	// Resolve Address: If not relayed, use direct address.
	addr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return err
	}

	// Acquire a buffer for the final packet from the pool.
	bufPtr := sendBufferPool.Get().(*[]byte)
	defer sendBufferPool.Put(bufPtr)

	// Reset length to 0, keeping the capacity.
	finalBuf := (*bufPtr)[:0]

	// Encrypt (Normal Session)
	if ok && currentAEAD != nil && pkt.Op != protocol.OpHandshake && pkt.Op != protocol.OpPunch {
		pkt.SequenceID = seqID

		marshaled := protocol.MarshalPacket(pkt)
		defer protocol.FreePacketBuffer(marshaled)

		nonce, err := cryptolib.GenerateRandomBytes(12)
		if err != nil {
			return err
		}

		// Header: [WireID 4][SeqID 8][Flag 1][RatchetKey?][Nonce 12]
		finalBuf = binary.BigEndian.AppendUint32(finalBuf, wireID)
		finalBuf = binary.BigEndian.AppendUint64(finalBuf, seqID)

		var flag uint8 = 0
		if len(ratchetPub) == 32 {
			flag = 1
		}
		finalBuf = append(finalBuf, flag)

		if flag == 1 {
			finalBuf = append(finalBuf, ratchetPub...)
		}

		finalBuf = append(finalBuf, nonce...)

		finalBuf = currentAEAD.Seal(finalBuf, nonce, marshaled, nil)

	} else {
		// Cleartext (Handshake/Punch)
		if pkt.Op != protocol.OpHandshake && pkt.Op != protocol.OpPunch {
			return fmt.Errorf("security: attempt to send Op %v without session", pkt.Op)
		}

		marshaled := protocol.MarshalPacket(pkt)
		defer protocol.FreePacketBuffer(marshaled)

		finalBuf = binary.BigEndian.AppendUint32(finalBuf, 0)
		finalBuf = append(finalBuf, marshaled...)
	}

	if p.transport.conn != nil {
		_, err = p.transport.conn.WriteToUDP(finalBuf, addr)
		return err
	}
	return fmt.Errorf("transport not started")
}

// Call sends a request to the target address and blocks waiting for a response (RPC style).
// It handles reliability, timeouts, and automatic handshakes if a session is missing.
func (p *Peer) Call(ctx context.Context, targetAddr string, op protocol.OpCode, payload []byte) ([]byte, error) {
	reqID := atomic.AddUint64(&p.reqIDSeq, 1)

	// Ensure session is active before sending application data
	if op != protocol.OpHandshake && op != protocol.OpPunch {
		sess, ok := p.GetSessionByAddr(targetAddr)

		if !ok || sess == nil || len(sess.SendChainKey) == 0 {
			p.Logger("[Security] No session with %s. Initiating Handshake...\n", targetAddr)

			if err := p.PerformHandshake(ctx, targetAddr); err != nil {
				return nil, fmt.Errorf("handshake required but failed: %v", err)
			}

			sess, ok = p.GetSessionByAddr(targetAddr)
			if !ok {
				return nil, fmt.Errorf("handshake claimed success but session missing")
			}
		}
	}

	pkt := protocol.Packet{
		ReqID:      reqID,
		SequenceID: 0, // Will be overwritten by sendPacket
		Op:         op,
		Payload:    payload,
	}

	respCh := make(chan *protocol.Packet, 1)
	p.pendingMu.Lock()
	p.pending[reqID] = respCh
	p.pendingMu.Unlock()
	defer func() {
		p.pendingMu.Lock()
		delete(p.pending, reqID)
		p.pendingMu.Unlock()
	}()

	for range RPCRetries {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if err := p.sendPacket(targetAddr, pkt); err != nil {
			return nil, err
		}

		select {
		case resp := <-respCh:
			return resp.Payload, nil

		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(RPCTimeout):
			continue // Timeout, retry
		}
	}
	return nil, fmt.Errorf("timeout")
}

// SendFast transmits a packet without waiting for a response (Fire-and-Forget).
// It is useful for high-frequency or non-critical data like voice or heartbeats.
func (p *Peer) SendFast(ctx context.Context, targetAddr string, op protocol.OpCode, payload []byte) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	reqID := atomic.AddUint64(&p.reqIDSeq, 1)

	if op != protocol.OpHandshake && op != protocol.OpPunch {
		sess, ok := p.GetSessionByAddr(targetAddr)
		if !ok || sess == nil || len(sess.SendChainKey) == 0 {
			if err := p.PerformHandshake(ctx, targetAddr); err != nil {
				return fmt.Errorf("handshake required but failed: %v", err)
			}
		}
	}

	pkt := protocol.Packet{
		ReqID:      reqID,
		SequenceID: 0, // Will be overwritten by sendPacket
		Op:         op,
		Payload:    payload,
	}

	return p.sendPacket(targetAddr, pkt)
}

// HolePunch sends a burst of low-overhead packets to open a NAT mapping for the target address.
func (p *Peer) HolePunch(targetAddr string) {
	addr, _ := net.ResolveUDPAddr("udp", targetAddr)
	go func() {
		for i := 0; i < PunchCount; i++ {
			pkt := protocol.Packet{SequenceID: 0, Op: protocol.OpPunch, Payload: []byte{0}}

			marshaled := protocol.MarshalPacket(pkt)

			finalBuf := make([]byte, 4+len(marshaled))
			binary.BigEndian.PutUint32(finalBuf[0:4], 0)
			copy(finalBuf[4:], marshaled)

			protocol.FreePacketBuffer(marshaled)

			if p.transport.conn != nil {
				p.transport.conn.WriteToUDP(finalBuf, addr)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
}