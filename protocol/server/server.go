package server

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	bstd "github.com/banditmoscow1337/benc/std/golang"
	"github.com/banditmoscow1337/safem/protocol"
	"github.com/banditmoscow1337/safem/protocol/cryptolib"
	"github.com/banditmoscow1337/safem/protocol/p2p"
)

// DefaultIdentityFile is the default filename used to persist the server's cryptographic keys to disk.
const DefaultIdentityFile = "server.safem"

// ServerIdentity represents the serialized structure of the server's persistent cryptographic identity.
// It includes both the Ed25519 keys for signing/authentication and X25519 keys for encryption.
type ServerIdentity struct {
	PrivateKeyPEM    string // Ed25519 Private Key in PEM format
	PublicKeyPEM     string // Ed25519 Public Key in PEM format
	EncPrivateKeyPEM string // X25519 Private Key in PEM format
	EncPublicKeyPEM  string // X25519 Public Key in PEM format
}

// ClientInfo stores the contact information and public keys for a registered peer.
// This struct is used by the server's registry to map User IDs to their current network location.
type ClientInfo struct {
	Name   string // Human-readable nickname
	Addr   string // Physical UDP network address (IP:Port)
	PEM    string // Ed25519 Public Key (Signing)
	EncPEM string // X25519 Public Key (Encryption)
}

// Server constitutes the main state of the Rendezvous and Relay service.
// It manages the P2P node, maintains a registry of connected peers, and handles signaling.
type Server struct {
	// Peer is the underlying P2P network node used to send/receive packets.
	Peer *p2p.Peer

	// Registry maps User IDs (Fingerprints) to their current contact info.
	Registry map[string]ClientInfo

	// NameIndex provides O(1) lookups of User IDs by Nickname.
	NameIndex map[string]string

	// regMu protects Registry and NameIndex from concurrent access.
	regMu sync.Mutex

	// Log is a pluggable logger function for outputting server events.
	Log func(string, ...any)

	// RelayEnabled determines if the server will process OpRelay packets to forward traffic
	// between peers that cannot establish direct connections (NAT traversal failure).
	RelayEnabled bool
}

// New creates a new Server instance with initialized registries and the specified configuration.
//
// Parameters:
//   - relay: If true, enables the TURN-like packet forwarding functionality for NAT traversal.
func New(relay bool) *Server {
	return &Server{
		Registry:     make(map[string]ClientInfo),
		NameIndex:    make(map[string]string),
		Log:          func(f string, a ...any) { fmt.Printf(f, a...) },
		RelayEnabled: relay,
	}
}

// Start initializes the server identity, binds the UDP listener, and begins the event loop.
// It loads existing keys from DefaultIdentityFile or generates new ones if missing.
//
// Parameters:
//   - port: The UDP port to listen on. If 0, the system will choose a random available port.
//
// Returns:
//   - finalAddr: The public-facing address string (IP:Port) of the server.
//   - pubPEM: The server's Ed25519 signing public key in PEM format.
//   - encPEM: The server's X25519 encryption public key in PEM format.
//   - err: Any error encountered during initialization or binding.
func (s *Server) Start(port int) (string, string, string, error) {
	priv, pub, encPriv, encPub, err := s.loadOrGenIdentity(DefaultIdentityFile)
	if err != nil {
		return "", "", "", err
	}

	s.Peer = p2p.NewPeer(priv, pub, encPriv, encPub)
	s.Peer.Logger = s.Log

	// Register Protocol Handlers
	s.Peer.RegisterHandler(protocol.OpRegister, s.handleRegister)
	s.Peer.RegisterHandler(protocol.OpInvite, s.handleInvite)
	s.Peer.RegisterHandler(protocol.OpAcceptInvite, s.handleAccept)
	s.Peer.RegisterHandler(protocol.OpQuery, s.handleQuery)
	s.Peer.RegisterHandler(protocol.OpRelay, s.handleRelay)
	
	s.Peer.RegisterHandler(protocol.OpDisconnect, s.handleDisconnect)

	// Hook into P2P Session Closure to clean up the Registry.
	// This ensures users are removed when they time out or explicitly disconnect.
	s.Peer.OnSessionClosed = func(id string) {
		s.regMu.Lock()
		defer s.regMu.Unlock()

		if info, ok := s.Registry[id]; ok {
			s.Log("[Server] Session closed for %s. Cleaning up registry.\\n", info.Name)
			
			// Remove from registry
			delete(s.NameIndex, info.Name)
			delete(s.Registry, id)
			
			// Unmap the peer address so future traffic isn't routed to a dead session
			s.Peer.UnmapPeer(info.Addr)
		}
	}

	actualAddr, err := s.Peer.Start(port)
	if err != nil {
		return "", "", "", err
	}

	// Start Session Monitor to maintain active encrypted sessions
	s.Peer.StartSessionMonitor()

	// Determine public IP for the connection string
	_, portStr, _ := net.SplitHostPort(actualAddr)
	displayIP := "127.0.0.1"
	if port != 0 || portStr == "14228" {
		displayIP = s.getOutboundIP()
	}

	finalAddr := fmt.Sprintf("%s:%s", displayIP, portStr)
	pubPEM := string(cryptolib.PubKeyToPEM(pub))
	encPEM := string(cryptolib.EncPubKeyToPEM(encPub))

	return finalAddr, pubPEM, encPEM, nil
}

// handleDisconnect removes the user from the registry and cleans up the session.
// It ensures that stale disconnect requests from old addresses do not affect active sessions.
func (s *Server) handleDisconnect(remote *net.UDPAddr, data []byte) ([]byte, error) {
	id := s.Peer.GetID(remote.String())
	if id == "" {
		return nil, nil
	}

	s.regMu.Lock()
	if info, ok := s.Registry[id]; ok {
		// This prevents delayed/stale disconnect packets from the old session (on Client restart)
		// from killing the NEW session initiated on a different port.
		if info.Addr != remote.String() {
			s.regMu.Unlock()
			s.Log("[Server] Ignored stale disconnect for %s from %s (Current: %s)\\n", info.Name, remote.String(), info.Addr)
			return nil, nil
		}
	}
	s.regMu.Unlock()

	// This will trigger OnSessionClosed, which performs the actual registry cleanup.
	s.Peer.Disconnect(id)
	return nil, nil
}

// handleRegister processes OpRegister packets to authenticate and add a user to the directory.
// It verifies the cryptographic signature of the payload to ensure the sender owns the keys.
func (s *Server) handleRegister(remote *net.UDPAddr, data []byte) ([]byte, error) {
	args := protocol.UnpackStrings(data)
	// Expected Payload: [Name, SignPEM, EncPEM, Sig, TS]
	if len(args) < 5 {
		return nil, fmt.Errorf("invalid register format")
	}
	name, signPEM, encPEM, sigStr, tsStr := args[0], args[1], args[2], args[3], args[4]

	// Replay Protection (Timestamp Check)
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return protocol.PackStrings("ERROR: Invalid Timestamp"), nil
	}
	now := time.Now().Unix()
	if now-ts > 300 || ts-now > 300 {
		return protocol.PackStrings("ERROR: Request Expired"), nil
	}

	// Signature Verification
	pubKey, err := cryptolib.PEMToPubKey([]byte(signPEM))
	if err != nil {
		return protocol.PackStrings("ERROR: Invalid Public Key"), nil
	}

	verifyData := []byte(name + encPEM + tsStr)
	if err := cryptolib.Verify(verifyData, []byte(sigStr), pubKey); err != nil {
		s.Log("[Security] Registration failed: Invalid signature for %s from %s\\n", name, remote.String())
		return protocol.PackStrings("ERROR: Signature Verification Failed"), nil
	}

	id := cryptolib.Fingerprint(pubKey)

	// Update Registry
	s.regMu.Lock()
	defer s.regMu.Unlock()

	s.Log("[Server] User '%s' (%s) connected from %s\\n", name, id, remote.String())

	// This ensures that if a user restarts and grabs a new port, we don't leave
	// the old port mapping in the Peer state, preventing confusion.
	if old, exists := s.Registry[id]; exists {
		if old.Addr != remote.String() {
			s.Log("[Server] Flush: User %s moved from %s to %s. Cleaning up old mapping.\\n", name, old.Addr, remote.String())
			s.Peer.UnmapPeer(old.Addr)
		}
	}

	s.Registry[id] = ClientInfo{Name: name, Addr: remote.String(), PEM: signPEM, EncPEM: encPEM}
	s.NameIndex[name] = id

	s.Peer.TrustPeer(id, []byte(signPEM), []byte(encPEM))
	s.Peer.MapPeer(remote.String(), id, name)

	pemBytes := cryptolib.PubKeyToPEM(s.Peer.PubKey)

	return protocol.PackStrings(string(pemBytes)), nil
}

// handleRelay processes OpRelay packets to forward encrypted data to another peer.
// This is used when direct P2P connection fails. It wraps the inner packet with the source ID
// so the target can identify the sender.
func (s *Server) handleRelay(remote *net.UDPAddr, data []byte) ([]byte, error) {
	if !s.RelayEnabled {
		return protocol.PackStrings("ERROR", "Relay Disabled"), nil
	}

	// Identify Sender
	senderID := s.Peer.GetID(remote.String())
	if senderID == "" {
		return nil, fmt.Errorf("relay denied: unknown sender")
	}

	// Parse Payload: [TargetID (string)][InnerPacket (bytes)]
	// We use manual Benc unmarshalling since PackStrings is only for []string.
	// Format: [Len][TargetID][Len][InnerPacket]
	n, targetID, err := bstd.UnmarshalString(0, data)
	if err != nil {
		return nil, err
	}
	
	innerPacket := data[n:] // Zero-copy slice

	// 3. Lookup Target
	s.regMu.Lock()
	target, ok := s.Registry[targetID]
	s.regMu.Unlock()

	if !ok {
		return protocol.PackStrings("ERROR", "Target Not Found"), nil
	}

	// Construct Forwarding Payload: [SourceID][InnerPacket]
	// We wrap the original SenderID so the target knows who it's from.
	// The target will use this ID to locate the correct decryption session.
	
	// Pre-calculate size
	size := bstd.SizeString(senderID) + len(innerPacket)
	fwdPayload := protocol.GetPacketBuffer()
	
	// Resize if needed
	if cap(fwdPayload) < size {
		fwdPayload = make([]byte, size)
	}
	fwdPayload = fwdPayload[:size]

	n = bstd.MarshalString(0, fwdPayload, senderID)
	copy(fwdPayload[n:], innerPacket)

	// Send to Target
	// We use SendFast directly. The packet is encrypted with the SERVER-TARGET session key.
	// The InnerPacket remains encrypted with the SENDER-TARGET session key.
	s.Peer.SendFast(context.Background(), target.Addr, protocol.OpRelay, fwdPayload)

	return nil, nil
}

// handleQuery processes address lookup requests (OpQuery).
// It returns the target's current address and public keys.
// The request must be signed to prevent unauthorized address harvesting.
func (s *Server) handleQuery(remote *net.UDPAddr, data []byte) ([]byte, error) {
	args := protocol.UnpackStrings(data)
	// Payload: [TargetID, SignPEM, EncPEM, TS, Sig] (Similar to Invite proof)
	if len(args) < 5 {
		return nil, nil
	}
	targetID := args[0]
	signPEM, encPEM, tsStr, sigStr := args[1], args[2], args[3], args[4]

	// Authenticate Sender by IP
	s.regMu.Lock()
	var senderInfo ClientInfo
	foundSender := false
	for _, info := range s.Registry {
		if info.Addr == remote.String() {
			senderInfo = info
			foundSender = true
			break
		}
	}
	
	// Lookup Target
	target, ok := s.Registry[targetID]
	s.regMu.Unlock()

	if !ok {
		return protocol.PackStrings("ERROR", "User not found"), nil
	}
	if !foundSender {
		return protocol.PackStrings("ERROR", "Unauthorized"), nil
	}

	// Verify Sender's Keys & Signature
	// The requester claims to be 'signPEM'. This must match the registry for their IP.
	if signPEM != senderInfo.PEM {
		return protocol.PackStrings("ERROR", "Key Mismatch"), nil
	}

	pub, err := cryptolib.PEMToPubKey([]byte(signPEM))
	if err != nil {
		return protocol.PackStrings("ERROR", "Invalid Key"), nil
	}

	// Data signed by the requester: TargetID + SignPEM + EncPEM + Timestamp
	dataToVerify := fmt.Sprintf("%s%s%s%s", targetID, signPEM, encPEM, tsStr)
	if err := cryptolib.Verify([]byte(dataToVerify), []byte(sigStr), pub); err != nil {
		s.Log("[Security] Query failed: Invalid signature from %s\\n", senderInfo.Name)
		return protocol.PackStrings("ERROR", "Invalid Signature"), nil
	}

	// Return Info: [Status, Addr, SignPEM, EncPEM]
	// We do NOT notify the target, unlike OpInvite.
	return protocol.PackStrings("OK", target.Addr, target.PEM, target.EncPEM), nil
}

// handleInvite forwards an invitation request from a sender to a target peer (OpInvite).
// It verifies that the sender's payload signature is valid before forwarding, preventing spoofing.
func (s *Server) handleInvite(remote *net.UDPAddr, data []byte) ([]byte, error) {
	args := protocol.UnpackStrings(data)
	// Payload: [TargetID, SignPEM, EncPEM, TS, Sig]
	if len(args) < 5 {
		return nil, nil
	}
	targetQuery := args[0]
	signPEM, encPEM, ts, sig := args[1], args[2], args[3], args[4]

	s.regMu.Lock()
	target, ok := s.Registry[targetQuery]

	// Identify Sender
	var senderInfo ClientInfo
	foundSender := false
	for _, info := range s.Registry {
		if info.Addr == remote.String() {
			senderInfo = info
			foundSender = true
			break
		}
	}
	s.regMu.Unlock()

	if !ok {
		return protocol.PackStrings("User not found (Check ID)"), nil
	}
	if !foundSender {
		return protocol.PackStrings("You are not registered"), nil
	}

	// Validation: The keys in the payload MUST match the registered sender's keys.
	// This prevents a valid user from spoofing keys in the invite payload.
	if signPEM != senderInfo.PEM {
		return protocol.PackStrings("Security Error: Payload keys do not match registered identity"), nil
	}

	s.Log("[Server] Forwarding invite from %s to %s\\n", senderInfo.Name, target.Name)

	// Forward the PROOF to Target: [Name, Addr, SignPEM, EncPEM, TargetID, TS, Sig]
	fwdPayload := protocol.PackStrings(senderInfo.Name, senderInfo.Addr, signPEM, encPEM, targetQuery, ts, sig)
	go s.Peer.Call(context.Background(), target.Addr, protocol.OpIncomingInvite, fwdPayload)

	// Ack to Sender
	return protocol.PackStrings(fmt.Sprintf("Invite Sent to %s", target.Name), target.Addr, target.PEM, target.EncPEM), nil
}

// handleAccept forwards a "Friend Request Accepted" signal (OpAcceptInvite) to the original inviter.
func (s *Server) handleAccept(remote *net.UDPAddr, data []byte) ([]byte, error) {
	args := protocol.UnpackStrings(data)
	// Payload: [TargetID, SignPEM, EncPEM, TS, Sig]
	if len(args) < 5 {
		return nil, nil
	}
	targetQuery := args[0] // Original Inviter
	signPEM, encPEM, ts, sig := args[1], args[2], args[3], args[4]

	s.regMu.Lock()
	target, ok := s.Registry[targetQuery]

	var senderInfo ClientInfo
	for _, info := range s.Registry {
		if info.Addr == remote.String() {
			senderInfo = info
			break
		}
	}
	s.regMu.Unlock()

	if ok {
		s.Log("[Server] Forwarding Accept from %s to %s\\n", senderInfo.Name, target.Name)
		
		// Forward PROOF: [Name, Addr, SignPEM, EncPEM, TargetID, TS, Sig]
		fwdPayload := protocol.PackStrings(senderInfo.Name, senderInfo.Addr, signPEM, encPEM, targetQuery, ts, sig)
		go s.Peer.Call(context.Background(), target.Addr, protocol.OpInviteFinalized, fwdPayload)
	}

	return protocol.PackStrings("ACK"), nil
}

// loadOrGenIdentity attempts to load the server's identity keys from the specified file.
// If the file does not exist or is corrupt, it generates new secure keys and saves them.
func (s *Server) loadOrGenIdentity(path string) (ed25519.PrivateKey, ed25519.PublicKey, *ecdh.PrivateKey, *ecdh.PublicKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		var id ServerIdentity
		if _, err := id.Unmarshal(0, data); err == nil {
			priv, err := cryptolib.ParsePrivateKey(id.PrivateKeyPEM)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("corrupt private key")
			}
			pub, err := cryptolib.PEMToPubKey([]byte(id.PublicKeyPEM))
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("corrupt public key")
			}

			encPriv, err := cryptolib.ParseEncPrivateKey(id.EncPrivateKeyPEM)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("corrupt enc priv key")
			}
			encPub, err := cryptolib.PEMToEncPubKey([]byte(id.EncPublicKeyPEM))
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("corrupt enc pub key")
			}

			return priv, pub, encPriv, encPub, nil
		}
	}

	s.Log("[Server] No identity found. Generating new secure keys...\\n")

	priv, pub, err := cryptolib.GenerateKeyPair(0)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	encPriv, encPub, err := cryptolib.GenerateECDH()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	privBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	pubPEM := cryptolib.PubKeyToPEM(pub)

	encPrivPEM := cryptolib.EncPrivateKeyToPEM(encPriv)
	encPubPEM := cryptolib.EncPubKeyToPEM(encPub)

	newID := ServerIdentity{
		PrivateKeyPEM:    string(privPEM),
		PublicKeyPEM:     string(pubPEM),
		EncPrivateKeyPEM: string(encPrivPEM),
		EncPublicKeyPEM:  string(encPubPEM),
	}

	buf := make([]byte, newID.Size())
	newID.Marshal(0, buf)

	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to save identity file: %v", err)
	}

	return priv, pub, encPriv, encPub, nil
}

// getOutboundIP determines the preferred outbound IP address of this machine.
// This is used to advertise the correct address in the server connection string.
func (s *Server) getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}