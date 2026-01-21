package p2p

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"fmt"
	"sync"
	"time"

	"github.com/banditmoscow1337/safem/protocol"
	"github.com/banditmoscow1337/safem/protocol/cryptolib"
)

const (
	// RatchetInterval is the number of messages sent before forcing a DH ratchet step.
	// Lower values provide finer-grained forward secrecy at the cost of CPU.
	RatchetInterval = 1

	// DHRatchetInterval is the number of messages before performing a full DH Cycle.
	// This enables self-healing if a session key is compromised.
	DHRatchetInterval = 50

	// RatchetTimeInterval forces a key rotation if the session is idle.
	RatchetTimeInterval = 30 * time.Minute

	// MaxSkippedKeys limits the memory usage for out-of-order packet buffering.
	MaxSkippedKeys = 1000
)

// Session represents an active, authenticated, and encrypted connection with a peer.
// It implements the Double Ratchet Algorithm, maintaining separate Root Keys and Chain Keys.
type Session struct {
	sync.Mutex
	Addr string
	ID   string
	Name string

	// Relay State
	IsRelayed bool
	RelayAddr string

	// Double Ratchet State
	RootKey      []byte // RK: Shared secret updated by DH exchange
	SendChainKey []byte // CKs: Chain key for sending
	RecvChainKey []byte // CKr: Chain key for receiving

	// Ratchet Keys (ECDH) for Post-Compromise Security (Self-Healing).
	RatchetPriv      *ecdh.PrivateKey
	RatchetPub       *ecdh.PublicKey
	RatchetPubBytes  []byte
	RemoteRatchetPub *ecdh.PublicKey

	// WireID is a negotiated opaque identifier used in the packet header
	// to identify the session without revealing the PeerID (Privacy).
	WireID uint32

	// Ratchet Counters
	TxCount uint64 // Next Sequence ID to send
	RxCount uint64 // Next Expected Sequence ID to receive

	// SkippedMessageKeys buffers keys for messages that were skipped (gap in sequence).
	// Key: SequenceID, Value: MessageKey
	SkippedMessageKeys map[uint64][]byte

	LastRx     time.Time
	LastRotate time.Time
}

// InitRatchet seeds the DH Ratchet state with the initial key pair and remote public key.
func (s *Session) InitRatchet(myPriv *ecdh.PrivateKey, remotePub *ecdh.PublicKey) {
	s.RatchetPriv = myPriv
	s.RatchetPub = myPriv.PublicKey()
	s.RatchetPubBytes = s.RatchetPub.Bytes()
	s.RemoteRatchetPub = remotePub
	s.SkippedMessageKeys = make(map[uint64][]byte)
}

// RotateRatchet performs a Diffie-Hellman Ratchet step (Sending Side).
// It generates a new keypair, mixes the secret into the Root Key, and starts a new Sending Chain.
func (s *Session) RotateRatchet() error {
	// Generate New Keypair
	priv, pub, err := cryptolib.GenerateECDH()
	if err != nil {
		return err
	}

	// Perform DH with Remote's current Public Key (NewPriv * OldRemotePub)
	secret, err := priv.ECDH(s.RemoteRatchetPub)
	if err != nil {
		return err
	}

	// KDF_RK Step: Update Root Key and Derive new Sending Chain Key
	newRootKey, newSendChainKey, err := cryptolib.KDF_RK(s.RootKey, secret)
	if err != nil {
		return err
	}

	// Update State
	s.RootKey = newRootKey
	s.SendChainKey = newSendChainKey
	s.RatchetPriv = priv
	s.RatchetPub = pub
	s.RatchetPubBytes = pub.Bytes()
	s.LastRotate = time.Now()

	return nil
}

// CheckAndMixRatchet atomically checks if the provided key is new and mixes it if so.
// It holds the lock for the entire operation to prevent "Ratchet Race" conditions
// where concurrent packets might trigger multiple mixes.
// Returns true if a mix was performed.
func (s *Session) CheckAndMixRatchet(newRemotePubBytes []byte) (bool, error) {
	s.Lock()
	defer s.Unlock()

	// Ensure session is fully initialized
	if s.RatchetPubBytes == nil || s.RemoteRatchetPub == nil {
		return false, nil
	}

	// Check if we already have this key (Idempotency)
	if bytes.Equal(newRemotePubBytes, s.RemoteRatchetPub.Bytes()) {
		return false, nil
	}

	curve := ecdh.X25519()
	newRemotePub, err := curve.NewPublicKey(newRemotePubBytes)
	if err != nil {
		return false, err
	}

	// Perform DH (MyPriv * NewRemotePub)
	secret, err := s.RatchetPriv.ECDH(newRemotePub)
	if err != nil {
		return false, err
	}

	// KDF_RK Step: Update Root Key and Derive new Receiving Chain Key
	newRootKey, newRecvChainKey, err := cryptolib.KDF_RK(s.RootKey, secret)
	if err != nil {
		return false, err
	}

	// Update State
	s.RootKey = newRootKey
	s.RecvChainKey = newRecvChainKey
	s.RemoteRatchetPub = newRemotePub

	return true, nil
}

// GetSession retrieves a thread-safe session pointer by Peer ID.
func (p *Peer) GetSession(id string) (*Session, bool) {
	v, ok := p.Sessions.Load(id)
	if !ok {
		return nil, false
	}
	return v.(*Session), true
}

// GetSessionByAddr retrieves a session by Remote Address (resolving via internal map).
func (p *Peer) GetSessionByAddr(addr string) (*Session, bool) {
	id := p.GetID(addr)
	if id == "" {
		return nil, false
	}
	return p.GetSession(id)
}

// AddSession registers a session in the peer's state.
func (p *Peer) AddSession(id string, s *Session) {
	p.Sessions.Store(id, s)
}

// RemoveSession deletes a session from the peer's state.
func (p *Peer) RemoveSession(id string) {
	p.Sessions.Delete(id)

	// Clean up replay state to free memory and allow fresh reconnections
	p.replayMu.Lock()
	delete(p.replayStates, id)
	p.replayMu.Unlock()
}

// StartSessionMonitor begins the background task that manages keep-alives,
// hole-punching, and session timeouts.
func (p *Peer) StartSessionMonitor() {
	p.KeysMu.Lock()
	if p.monitorRunning {
		p.KeysMu.Unlock()
		return
	}
	p.monitorRunning = true
	p.monitorStop = make(chan struct{})
	p.KeysMu.Unlock()

	go p.monitorLoop()
}

// StopSessionMonitor halts the session background task.
func (p *Peer) StopSessionMonitor() {
	p.KeysMu.Lock()
	defer p.KeysMu.Unlock()
	if p.monitorRunning {
		close(p.monitorStop)
		p.monitorRunning = false
	}
}

// monitorLoop is the main event loop for session maintenance.
func (p *Peer) monitorLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.monitorStop:
			return
		case <-ticker.C:
			// Snapshot active sessions to avoid holding locks during network I/O
			type sessSnapshot struct {
				ID        string
				Name      string
				Addr      string
				RelayAddr string
				IsRelayed bool
				LastRx    time.Time
			}

			activeSessions := make([]sessSnapshot, 0)
			p.Sessions.Range(func(key, value any) bool {
				s := value.(*Session)
				s.Lock()
				activeSessions = append(activeSessions, sessSnapshot{
					ID:        s.ID,
					Name:      s.Name,
					Addr:      s.Addr,
					RelayAddr: s.RelayAddr,
					IsRelayed: s.IsRelayed,
					LastRx:    s.LastRx,
				})
				s.Unlock()
				return true
			})

			for _, sess := range activeSessions {
				targetAddr := sess.Addr
				if sess.IsRelayed {
					targetAddr = sess.RelayAddr
				}

				if targetAddr == "" || sess.LastRx.IsZero() {
					continue
				}

				since := time.Since(sess.LastRx)

				// Keep-Alive (5s idle)
				if since > 5*time.Second {
					padSize := 32 + int(time.Now().UnixNano()%96)
					padding, _ := cryptolib.GenerateRandomBytes(padSize)
					// SendFast handles IsRelayed check internally via sendPacket
					p.SendFast(context.Background(), sess.Addr, protocol.OpPing, padding)
				}

				// Hole Punching / Re-Handshake (12s idle)
				// Only attempt Hole Punching if NOT relayed (Direct connection attempt)
				if !sess.IsRelayed && since > 12*time.Second {
					p.HolePunch(sess.Addr)
					go func(target string, targetID string) {
						// Logic to determine who initiates the re-handshake (Collision Avoidance)
						myID := cryptolib.Fingerprint(p.PubKey)

						if myID > targetID {
							time.Sleep(2000 * time.Millisecond)
							// Check if resolved by the other peer already
							if s, ok := p.GetSession(targetID); ok {
								if time.Since(s.LastRx) < 10*time.Second {
									return
								}
							}
						}

						if _, ok := p.GetSession(targetID); ok {
							ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
							defer cancel()
							p.PerformHandshake(ctx, target)
						}
					}(sess.Addr, sess.ID)
				}

				// Timeout (30s idle)
				if since > 30*time.Second {
					if liveSess, ok := p.GetSession(sess.ID); ok {
						liveSess.Lock()
						freshSince := time.Since(liveSess.LastRx)
						liveSess.Unlock()

						if freshSince < 30*time.Second {
							continue
						}
					}

					p.Logger("\n[System] Connection to %s timed out.\n", sess.Name)
					p.Disconnect(sess.ID)
					continue
				}
			}
		}
	}
}

// Disconnect gracefully terminates a session, sending a disconnect packet
// and invoking the close callback.
func (p *Peer) Disconnect(id string) {
	sess, ok := p.GetSession(id)
	if !ok {
		return
	}

	targetAddr := sess.Addr
	if sess.IsRelayed {
		targetAddr = sess.Addr // sendPacket handles routing logic using IsRelayed flag
	}

	if targetAddr != "" {
		sess.Lock()
		ready := len(sess.SendChainKey) > 0
		sess.Unlock()

		if ready {
			p.SendFast(context.TODO(), sess.Addr, protocol.OpDisconnect, []byte("Bye"))
		}
	}

	p.RemoveSession(id)

	if p.OnSessionClosed != nil {
		p.OnSessionClosed(id)
	}
}

// DisconnectAll terminates all active sessions.
func (p *Peer) DisconnectAll() {
	p.StopSessionMonitor()

	p.Sessions.Range(func(key, value any) bool {
		p.Disconnect(key.(string))
		return true
	})

	time.Sleep(100 * time.Millisecond)
}

// GetDecryptionKey locates the correct message key for a given sequence number.
// It handles out-of-order delivery by advancing the chain and buffering skipped keys.
func (s *Session) GetDecryptionKey(seq uint64) ([]byte, cipher.AEAD, error) {
	// Check Skipped Keys (Out-of-Order arrival from the past)
	if key, ok := s.SkippedMessageKeys[seq]; ok {
		delete(s.SkippedMessageKeys, seq)
		aead, err := cryptolib.NewAEAD(key)
		return key, aead, err
	}

	// Exact Match (In-Order)
	if seq == s.RxCount {
		// Advance Chain, get Message Key
		newChainKey, msgKey, err := cryptolib.KDF_CK(s.RecvChainKey)
		if err != nil {
			return nil, nil, err
		}

		s.RecvChainKey = newChainKey
		s.RxCount++

		aead, err := cryptolib.NewAEAD(msgKey)
		return msgKey, aead, err
	}

	// Handle Future Sequence (Gap Detected)
	if seq > s.RxCount {
		if seq-s.RxCount > MaxSkippedKeys {
			return nil, nil, fmt.Errorf("too many skipped messages (gap %d)", seq-s.RxCount)
		}

		if s.SkippedMessageKeys == nil {
			s.SkippedMessageKeys = make(map[uint64][]byte)
		}

		// Fast-forward the Symmetric Ratchet to the target sequence
		for s.RxCount < seq {
			newChainKey, skippedMsgKey, err := cryptolib.KDF_CK(s.RecvChainKey)
			if err != nil {
				return nil, nil, err
			}
			s.SkippedMessageKeys[s.RxCount] = skippedMsgKey
			s.RecvChainKey = newChainKey
			s.RxCount++
		}

		// Now we are at the target sequence
		newChainKey, msgKey, err := cryptolib.KDF_CK(s.RecvChainKey)
		if err != nil {
			return nil, nil, err
		}
		s.RecvChainKey = newChainKey
		s.RxCount++

		aead, err := cryptolib.NewAEAD(msgKey)
		return msgKey, aead, err
	}

	return nil, nil, fmt.Errorf("duplicate or old message (seq %d < expected %d)", seq, s.RxCount)
}

// AdvanceSendRatchet advances the Sending Chain for a new message.
// Returns the Message Key for the current message and the corresponding AEAD.
func (s *Session) AdvanceSendRatchet() ([]byte, cipher.AEAD, error) {
	newChainKey, msgKey, err := cryptolib.KDF_CK(s.SendChainKey)
	if err != nil {
		return nil, nil, err
	}

	s.SendChainKey = newChainKey
	s.TxCount++

	aead, err := cryptolib.NewAEAD(msgKey)
	return msgKey, aead, err
}