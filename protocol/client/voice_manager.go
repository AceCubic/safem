package client

import (
	"errors"
	"sync"

	"github.com/banditmoscow1337/safem/protocol/audio"
	"github.com/banditmoscow1337/safem/protocol/p2p"
)

// VoiceManager controls the audio engine and maps network peers to audio streams.
// It handles the mixing of multiple peer streams for conference calls.
type VoiceManager struct {
	// Engine is the underlying audio processing unit responsible for capture, encoding, and playback.
	Engine *audio.Engine
	// Peer is the associated P2P network peer used for transport.
	Peer   *p2p.Peer

	mu          sync.Mutex
	// ActivePeers maps PeerIDs to their current network addresses for the ongoing call.
	ActivePeers map[string]string

	stopLoop chan struct{}
}

// NewVoiceManager creates a new manager linked to the P2P peer.
func NewVoiceManager(p *p2p.Peer) *VoiceManager {
	return &VoiceManager{
		Engine:      audio.NewEngine(),
		Peer:        p,
		ActivePeers: make(map[string]string),
	}
}

// SetMute directly sets the mute state of the audio engine.
func (vm *VoiceManager) SetMute(muted bool) {
	vm.Engine.SetMute(muted)
}

// ToggleMute toggles the mute state and returns the new value.
func (vm *VoiceManager) ToggleMute() bool {
	currentState := vm.Engine.IsMuted()
	newState := !currentState
	vm.Engine.SetMute(newState)
	return newState
}

// IsMuted returns the current mute status.
func (vm *VoiceManager) IsMuted() bool {
	return vm.Engine.IsMuted()
}

// Init initializes the audio engine and starts the packet ingress loop.
// This must be called before any calls can be established.
func (vm *VoiceManager) Init() {
	vm.Engine.Init()
	vm.stopLoop = make(chan struct{})
	go vm.ingressLoop()
}

// Cleanup stops the ingress loop and releases audio resources.
func (vm *VoiceManager) Cleanup() {
	if vm.stopLoop != nil {
		close(vm.stopLoop)
	}
	vm.Engine.Cleanup()
}

// ingressLoop consumes incoming voice packets from the Peer and feeds them to the Audio Engine.
func (vm *VoiceManager) ingressLoop() {
	for {
		select {
		case <-vm.stopLoop:
			return
		case pkt := <-vm.Peer.VoiceIn:
			vm.mu.Lock()
			// Resolve Peer ID from Address.
			// Only process audio from peers currently in the ActivePeers list (authorized call).
			peerID := vm.Peer.GetID(pkt.Addr)
			_, active := vm.ActivePeers[peerID]
			vm.mu.Unlock()

			if active {
				// Engine now accepts the pointer and takes ownership (frees it eventually)
				vm.Engine.ProcessIncoming(peerID, pkt.Data)
			} else {
				// If not passed to Engine, we must recycle it ourselves
				vm.Peer.RecycleVoiceBufferPtr(pkt.Data)
			}
		}
	}
}

// StartAddPeer adds a peer to the active call.
// It initializes the audio engine if it is not already running.
func (vm *VoiceManager) StartAddPeer(targetID string) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Resolve Address
	sess, ok := vm.Peer.GetSession(targetID)
	if !ok || sess.Addr == "" {
		return errors.New("peer offline or unknown")
	}

	// Register peer for voice logic
	vm.ActivePeers[targetID] = sess.Addr
	vm.Engine.AddPeer(targetID)

	// If engine is already running (multi-party call), we just added the peer.
	if len(vm.ActivePeers) > 1 {
		return nil
	}

	// Start Audio Engine with a callback for encoded audio data.
	err := vm.Engine.Start(func(data []byte) {
		vm.mu.Lock()
		defer vm.mu.Unlock()

		if len(vm.ActivePeers) == 0 {
			return
		}

		// Allocate ONE pooled buffer for multicast
		// Note: Since 'data' is ephemeral from the Engine, we MUST copy it to a persistent buffer
		// for the outbound channel.
		
		// Get buffer from P2P pool
		bufPtr := vm.Peer.GetVoiceBuffer()
		
		// Ensure capacity & Copy
		if cap(*bufPtr) < len(data) {
			*bufPtr = make([]byte, len(data))
		}
		*bufPtr = (*bufPtr)[:len(data)]
		copy(*bufPtr, data)

		// Multicast: Note that sending the SAME pointer to multiple channels
		// would be a race condition if p2p recycles it after the first send.
		// However, currently we only support 1-to-1 or simplistic flooding.
		// For proper multicast with zero-copy, we would need ref-counting.
		// For now, we only support single active peer or copy for each if multiple.
		
		// FAST PATH: Single Peer
		if len(vm.ActivePeers) == 1 {
			for _, addr := range vm.ActivePeers {
				if addr != "" {
					select {
					case vm.Peer.VoiceOut <- p2p.VoicePacket{Addr: addr, Data: bufPtr}:
						// Success, p2p will recycle
						return 
					default:
						// Drop
						vm.Peer.RecycleVoiceBufferPtr(bufPtr)
						return
					}
				}
			}
		}

		// Multiple Peers (Conference Host) -> Copy for each
		// First peer gets bufPtr, others get copies.
		first := true
		for _, addr := range vm.ActivePeers {
			if addr != "" {
				var pktPtr *[]byte
				if first {
					pktPtr = bufPtr
					first = false
				} else {
					// Duplicate buffer for other peers
					newPtr := vm.Peer.GetVoiceBuffer()
					*newPtr = (*newPtr)[:len(data)]
					copy(*newPtr, data)
					pktPtr = newPtr
				}
				
				select {
				case vm.Peer.VoiceOut <- p2p.VoicePacket{Addr: addr, Data: pktPtr}:
				default:
					vm.Peer.RecycleVoiceBufferPtr(pktPtr)
				}
			}
		}
		
		// If first was unused (no peers found in loop, theoretically impossible here), recycle
		if first {
			vm.Peer.RecycleVoiceBufferPtr(bufPtr)
		}
	})

	if err != nil {
		// Rollback state on failure
		delete(vm.ActivePeers, targetID)
		vm.Engine.RemovePeer(targetID)
		return err
	}
	return nil
}

// StopPeer removes a specific peer from the active call.
func (vm *VoiceManager) StopPeer(targetID string) {
	vm.mu.Lock()
	delete(vm.ActivePeers, targetID)
	remaining := len(vm.ActivePeers)
	vm.mu.Unlock()

	vm.Engine.RemovePeer(targetID)

	// If call is empty, stop the engine to save CPU/Battery.
	if remaining == 0 {
		vm.Engine.Stop()
	}
}

// StopAll ends the call completely, removing all peers and stopping the engine.
func (vm *VoiceManager) StopAll() {
	vm.mu.Lock()
	vm.ActivePeers = make(map[string]string)
	vm.mu.Unlock()
	
	// Clean up ALL jitter buffers when call ends, otherwise next call might have stale state
	vm.Engine.RemoveAllPeers()
	vm.Engine.Stop()
}

// Active returns true if there is at least one peer currently in the call.
func (vm *VoiceManager) Active() bool {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	return len(vm.ActivePeers) > 0
}

// IsPeerActive checks if a specific peer is currently participating in the call.
func (vm *VoiceManager) IsPeerActive(id string) bool {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	_, ok := vm.ActivePeers[id]
	return ok
}

// GetTargetID returns the ID of the peer if in a 1-on-1 call, or "Group Call" if multiple peers are active.
func (vm *VoiceManager) GetTargetID() string {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	if len(vm.ActivePeers) == 1 {
		for k := range vm.ActivePeers {
			return k
		}
	}
	if len(vm.ActivePeers) > 1 {
		return "Group Call"
	}
	return ""
}