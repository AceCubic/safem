package p2p

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/banditmoscow1337/safem/protocol"
	"github.com/banditmoscow1337/safem/protocol/cryptolib"
)

const (
	// MaxPacketSize defines the maximum allowed size for a UDP packet.
	// 65000 is chosen to fit within the standard IPv4 UDP max size (65535) minus headers.
	MaxPacketSize = 65000

	// RPCTimeout defines the duration to wait for a response to a Call request.
	RPCTimeout = 5 * time.Second

	// RPCRetries defines the number of times to retry a Call request before failing.
	RPCRetries = 3

	// PunchCount defines the number of UDP hole punching packets to send in a burst.
	PunchCount = 5

	// WindowSize is the size of the sliding window used for replay protection.
	WindowSize = 64

	// SafePayloadSize is the maximum safe payload size to avoid fragmentation on most networks (MTU 1500).
	SafePayloadSize = 1200

	// CookieValidity defines the lifetime of a handshake cookie.
	CookieValidity = 30 * time.Second

	// VoicePacketBufferSize is the size of pooled buffers for voice packets.
	// It is set slightly larger than typical Opus packets (1200 bytes)
	// to avoid reallocation for standard voice traffic.
	VoicePacketBufferSize = 2048
)

// sendBufferPool recycles outbound packet buffers to reduce GC pressure.
var sendBufferPool = sync.Pool{
	New: func() any {
		// Allocate a slice with maximum capacity for standard UDP packets.
		// We use a pointer to slice to avoid allocation when putting/getting from pool.
		b := make([]byte, MaxPacketSize)
		return &b
	},
}

// HandlerFunc is the signature for functions that process specific protocol OpCodes.
type HandlerFunc func(remoteAddr *net.UDPAddr, payload []byte) ([]byte, error)

// VoicePacket represents a received audio packet destined for the voice engine.
type VoicePacket struct {
	Addr string
	Data *[]byte // Pointer to pooled buffer
}

// voiceBufferPool recycles slices for incoming voice packets to reduce GC pressure
// in the high-frequency audio path.
var voiceBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, VoicePacketBufferSize)
		return &b
	},
}

// ReplayWindow tracks received sequence numbers to prevent replay attacks.
type ReplayWindow struct {
	Highest uint64
	Bitmap  uint64
}

// CheckAndUpdate verifies if a sequence number is valid (new or within window but not seen)
// and updates the window state. Returns true if the packet should be accepted.
func (w *ReplayWindow) CheckAndUpdate(seq uint64) bool {
	if seq == 0 {
		return false
	}
	if seq > w.Highest {
		shift := seq - w.Highest
		if shift >= WindowSize {
			w.Bitmap = 1
		} else {
			w.Bitmap <<= shift
			w.Bitmap |= 1
		}
		w.Highest = seq
		return true
	}
	diff := w.Highest - seq
	if diff >= WindowSize {
		return false // Too old
	}
	mask := uint64(1) << diff
	if (w.Bitmap & mask) != 0 {
		return false // Replay
	}
	w.Bitmap |= mask
	return true
}

// Peer represents a local P2P node. It manages cryptographic identity,
// active sessions, transport layers, and protocol message dispatching.
type Peer struct {
	transport  *Transport
	handlers   map[protocol.OpCode]HandlerFunc
	handlersMu sync.RWMutex

	pending   map[uint64]chan *protocol.Packet
	pendingMu sync.Mutex
	reqIDSeq  uint64

	sendSeq      uint64
	replayStates map[string]*ReplayWindow
	replayMu     sync.Mutex

	PrivKey ed25519.PrivateKey
	PubKey  ed25519.PublicKey

	EncPrivKey *ecdh.PrivateKey
	EncPubKey  *ecdh.PublicKey

	cookieSecret []byte

	peerIDs       map[string]string
	identities    map[string]ed25519.PublicKey
	encIdentities map[string]*ecdh.PublicKey
	aliases       map[string]string

	PendingInvites map[string]InviteData
	KeysMu         sync.RWMutex

	Sessions sync.Map

	handshakeCache   map[string]time.Time
	handshakeCacheMu sync.Mutex

	// handshakeInFlight ensures only one handshake happens per target address at a time (SingleFlight)
	handshakeInFlight   map[string]chan struct{}
	handshakeInFlightMu sync.Mutex

	chunkBuffers map[uint64]*ChunkBuffer
	chunkMu      sync.Mutex

	monitorStop    chan struct{}
	monitorRunning bool

	VoiceIn  chan VoicePacket
	VoiceOut chan VoicePacket

	OnSessionClosed func(id string)
	Logger          func(format string, args ...any)
	OnFileComplete  func(remote *net.UDPAddr, path string)

	// Metrics
	PacketsDropped atomic.Uint64
	Retransmits    atomic.Uint64
	PoolStarvation atomic.Uint64
}

// NewPeer initializes a new Peer with the provided cryptographic keys.
// If keys are nil, new ones will be generated.
func NewPeer(priv ed25519.PrivateKey, pub ed25519.PublicKey, encPriv *ecdh.PrivateKey, encPub *ecdh.PublicKey) *Peer {
	if priv == nil || pub == nil {
		priv, pub, _ = cryptolib.GenerateKeyPair(0)
	}
	if encPriv == nil || encPub == nil {
		encPriv, encPub, _ = cryptolib.GenerateECDH()
	}

	secret, _ := cryptolib.GenerateRandomBytes(32)

	p := &Peer{
		handlers:          make(map[protocol.OpCode]HandlerFunc),
		pending:           make(map[uint64]chan *protocol.Packet),
		replayStates:      make(map[string]*ReplayWindow),
		PrivKey:           priv,
		PubKey:            pub,
		EncPrivKey:        encPriv,
		EncPubKey:         encPub,
		cookieSecret:      secret,
		peerIDs:           make(map[string]string),
		identities:        make(map[string]ed25519.PublicKey),
		encIdentities:     make(map[string]*ecdh.PublicKey),
		aliases:           make(map[string]string),
		PendingInvites:    make(map[string]InviteData),
		chunkBuffers:      make(map[uint64]*ChunkBuffer),
		handshakeCache:    make(map[string]time.Time),
		handshakeInFlight: make(map[string]chan struct{}),
		VoiceIn:           make(chan VoicePacket, 128),
		VoiceOut:          make(chan VoicePacket, 128),

		Logger: func(format string, args ...any) {
			fmt.Printf(format, args...)
		},
	}

	p.transport = &Transport{
		GetSession: p.GetSessionByAddr,
		Dispatch:   p.dispatchPacket,
		Logger:     p.Logger,
		// Link drops in transport to peer metrics
		PacketsDropped: &p.PacketsDropped,
	}

	p.RegisterHandler(protocol.OpChunk, p.handleChunk)
	p.RegisterHandler(protocol.OpHandshake, p.handleHandshake)
	// Register the Relay Handler to unwrap forwarded packets
	p.RegisterHandler(protocol.OpRelay, p.handleRelayedPacket)

	p.StartChunkGC()
	p.StartHandshakeGC()

	return p
}

// Start binds the underlying transport to the specified UDP port.
// Returns the actual bound address string or an error.
func (p *Peer) Start(port int) (string, error) {
	addr, err := p.transport.Start(port)
	if err != nil {
		return "", err
	}

	// Use a sync.Pool for voice buffers instead of allocating a new slice for every packet.
	p.RegisterHandler(protocol.OpVoice, func(remote *net.UDPAddr, data []byte) ([]byte, error) {
		// Get buffer from pool
		ptr := voiceBufferPool.Get().(*[]byte)

		// Ensure capacity
		if cap(*ptr) < len(data) {
			// If packet is unusually large, allocate a fresh one (rare case)
			// to avoid polluting the pool with huge buffers or panicking.
			b := make([]byte, len(data))
			ptr = &b
		}

		// Reslice and copy
		*ptr = (*ptr)[:len(data)]
		copy(*ptr, data)

		select {
		// ZERO-COPY: Send the pointer directly. The consumer MUST free it.
		case p.VoiceIn <- VoicePacket{Addr: remote.String(), Data: ptr}:
		default:
			// Drop voice packet if buffer full and recycle immediately
			p.PoolStarvation.Add(1)
			voiceBufferPool.Put(ptr)
		}
		return nil, nil
	})

	p.RegisterHandler(protocol.OpPing, func(remote *net.UDPAddr, data []byte) ([]byte, error) {
		return []byte("PONG"), nil
	})

	go p.voiceSendLoop()
	return addr, nil
}

// RecycleVoiceBufferPtr returns a pointer-based buffer to the pool.
// It is safe to call with nil.
func (p *Peer) RecycleVoiceBufferPtr(buf *[]byte) {
	if buf != nil && cap(*buf) >= VoicePacketBufferSize {
		voiceBufferPool.Put(buf)
	}
}

// GetVoiceBuffer returns a new buffer from the voice pool.
// This is used for outgoing voice packets to reduce allocation.
func (p *Peer) GetVoiceBuffer() *[]byte {
	return voiceBufferPool.Get().(*[]byte)
}

func (p *Peer) voiceSendLoop() {
	for pkt := range p.VoiceOut {
		// SendFast copies the data into the packet buffer, so we can recycle immediately.
		if pkt.Data != nil {
			p.SendFast(context.Background(), pkt.Addr, protocol.OpVoice, *pkt.Data)
			p.RecycleVoiceBufferPtr(pkt.Data)
		}
	}
}

// RegisterHandler maps a protocol OpCode to a specific handler function.
func (p *Peer) RegisterHandler(op protocol.OpCode, handler HandlerFunc) {
	p.handlersMu.Lock()
	p.handlers[op] = handler
	p.handlersMu.Unlock()
}

// TrustPeer adds a trusted peer's identity (Signing and Encryption keys) to the local store.
func (p *Peer) TrustPeer(id string, signPEM, encPEM []byte) {
	pub, err := cryptolib.PEMToPubKey(signPEM)
	if err == nil {
		p.KeysMu.Lock()
		p.identities[id] = pub

		if len(encPEM) > 0 {
			encPub, err := cryptolib.PEMToEncPubKey(encPEM)
			if err == nil {
				p.encIdentities[id] = encPub
			}
		}
		p.KeysMu.Unlock()
	}
}

// MapPeer associates a network address with a Peer ID and optional alias/nickname.
func (p *Peer) MapPeer(addr, id, name string) {
	p.KeysMu.Lock()
	defer p.KeysMu.Unlock()
	p.peerIDs[addr] = id
	if name != "" {
		p.aliases[id] = name
	}
}

// UnmapPeer removes the association between a network address and a Peer ID.
func (p *Peer) UnmapPeer(addr string) {
	p.KeysMu.Lock()
	defer p.KeysMu.Unlock()
	delete(p.peerIDs, addr)
}

// GetID resolves a network address to a Peer ID.
func (p *Peer) GetID(addr string) string {
	p.KeysMu.RLock()
	defer p.KeysMu.RUnlock()
	return p.peerIDs[addr]
}

// GetIdentity retrieves the Ed25519 signing public key for a given Peer ID.
func (p *Peer) GetIdentity(id string) (ed25519.PublicKey, bool) {
	p.KeysMu.RLock()
	defer p.KeysMu.RUnlock()
	pub, ok := p.identities[id]
	return pub, ok
}

// GetEncIdentity retrieves the X25519 encryption public key for a given Peer ID.
func (p *Peer) GetEncIdentity(id string) (*ecdh.PublicKey, bool) {
	p.KeysMu.RLock()
	defer p.KeysMu.RUnlock()
	pub, ok := p.encIdentities[id]
	return pub, ok
}

// GetName retrieves the alias/nickname associated with a Peer ID, or returns the ID if unknown.
func (p *Peer) GetName(id string) string {
	p.KeysMu.RLock()
	defer p.KeysMu.RUnlock()
	if n, ok := p.aliases[id]; ok {
		return n
	}
	return id
}

func (p *Peer) generateCookie(ip string) []byte {
	ts := time.Now().UnixNano()

	buf := make([]byte, 8+sha256.Size)
	binary.BigEndian.PutUint64(buf[0:8], uint64(ts))

	h := hmac.New(sha256.New, p.cookieSecret)
	h.Write([]byte(ip))
	h.Write(buf[0:8])
	sum := h.Sum(nil)

	copy(buf[8:], sum)
	return buf
}

func (p *Peer) verifyCookie(ip string, cookie []byte) bool {
	if len(cookie) != 8+sha256.Size {
		return false
	}

	tsVal := binary.BigEndian.Uint64(cookie[0:8])
	ts := time.Unix(0, int64(tsVal))

	if time.Since(ts) > CookieValidity {
		return false
	}
	if time.Until(ts) > CookieValidity {
		return false // Future timestamp?
	}

	h := hmac.New(sha256.New, p.cookieSecret)
	h.Write([]byte(ip))
	h.Write(cookie[0:8])
	expectedSum := h.Sum(nil)

	return hmac.Equal(cookie[8:], expectedSum)
}

// StartHandshakeGC starts a background goroutine to clean up the handshake replay cache.
func (p *Peer) StartHandshakeGC() {
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			p.handshakeCacheMu.Lock()
			now := time.Now()
			for sig, seen := range p.handshakeCache {
				if now.Sub(seen) > HandshakeWindow*2 {
					delete(p.handshakeCache, sig)
				}
			}
			p.handshakeCacheMu.Unlock()
		}
	}()
}