package server

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
type ServerIdentity struct {
	PrivateKeyPEM    string   // Ed25519 Private Key in PEM format
	PublicKeyPEM     string   // Ed25519 Public Key in PEM format
	EncPrivateKeyPEM string   // X25519 Private Key in PEM format
	EncPublicKeyPEM  string   // X25519 Public Key in PEM format
	MerkleLeaves     [][]byte // The persisted leaves of the Merkle Tree
}

// ClientInfo stores the contact information and public keys for a registered peer.
type ClientInfo struct {
	Name   string // Human-readable nickname
	Addr   string // Physical UDP network address (IP:Port)
	PEM    string // Ed25519 Public Key (Signing)
	EncPEM string // X25519 Public Key (Encryption)

	// SubscriptionID is the "Read Token" used by the client to poll their bucket.
	SubscriptionID string

	// WriteToken is the "Write Capability" given to other users to send messages to this user.
	// It maps to the same bucket index as SubscriptionID but allows separation of concerns.
	WriteToken string

	// LogIndex is the index of this user's registration event in the Append-Only Log.
	LogIndex int
}

// RelayMessage represents a stored packet in a PIR bucket.
type RelayMessage struct {
	Data      []byte
	Timestamp time.Time
}

// Server constitutes the main state of the Rendezvous and Relay service.
type Server struct {
	// Peer is the underlying P2P network node used to send/receive packets.
	Peer *p2p.Peer

	// Registry maps User IDs (Fingerprints) to their current contact info.
	Registry map[string]ClientInfo

	// NameIndex provides O(1) lookups of User IDs by Nickname.
	NameIndex map[string]string

	// WriteIndex maps WriteTokens to User IDs.
	// Validates that a sender has a valid token to write to a bucket.
	WriteIndex map[string]string

	// SubIndex maps SubscriptionIDs to User IDs.
	// Used primarily to ensure uniqueness during registration, not for routing.
	SubIndex map[string]string

	// relayBuckets stores messages for PIR retrieval.
	// Map Key: Bucket Index (0-255). Value: List of messages.
	relayBuckets map[uint8][]RelayMessage
	bucketsMu    sync.Mutex

	// Log is the Append-Only Key Transparency Log.
	// It maintains a history of all registrations.
	Log *cryptolib.MerkleLog

	// regMu protects Registry, NameIndex, WriteIndex, SubIndex, and Log.
	regMu sync.Mutex

	// LogFunc is a pluggable logger function for outputting server events.
	LogFunc func(string, ...any)

	// RelayEnabled determines if the server will process OpRelay packets.
	RelayEnabled bool
}

// New creates a new Server instance with initialized registries.
func New(relay bool) *Server {
	return &Server{
		Registry:     make(map[string]ClientInfo),
		NameIndex:    make(map[string]string),
		WriteIndex:   make(map[string]string),
		SubIndex:     make(map[string]string),
		relayBuckets: make(map[uint8][]RelayMessage),
		Log:          cryptolib.NewMerkleLog(),
		LogFunc:      func(f string, a ...any) { fmt.Printf(f, a...) },
		RelayEnabled: relay,
	}
}

// Start initializes the server identity, binds the UDP listener, and begins the event loop.
func (s *Server) Start(port int) (string, string, string, error) {
	priv, pub, encPriv, encPub, leaves, err := s.loadOrGenIdentity(DefaultIdentityFile)
	if err != nil {
		return "", "", "", err
	}

	s.Peer = p2p.NewPeer(priv, pub, encPriv, encPub)
	s.Peer.Logger = s.LogFunc

	// Restore Merkle Log State
	if len(leaves) > 0 {
		s.Log.Leaves = leaves
		s.LogFunc("[Server] Restored Transparency Log (%d entries)\n", len(leaves))
	}

	// Register Protocol Handlers
	s.Peer.RegisterHandler(protocol.OpRegister, s.handleRegister)
	s.Peer.RegisterHandler(protocol.OpInvite, s.handleInvite)
	s.Peer.RegisterHandler(protocol.OpAcceptInvite, s.handleAccept)
	s.Peer.RegisterHandler(protocol.OpQuery, s.handleQuery)
	s.Peer.RegisterHandler(protocol.OpRelay, s.handleRelay)
	s.Peer.RegisterHandler(protocol.OpPIRQuery, s.handlePIRQuery)

	s.Peer.RegisterHandler(protocol.OpDisconnect, s.handleDisconnect)

	// Hook into P2P Session Closure to clean up the Registry.
	s.Peer.OnSessionClosed = func(id string) {
		s.regMu.Lock()
		defer s.regMu.Unlock()

		if info, ok := s.Registry[id]; ok {
			s.LogFunc("[Server] Session closed for %s. Cleaning up registry.\n", info.Name)

			// Remove from Active Registry (Routing)
			delete(s.NameIndex, info.Name)
			delete(s.WriteIndex, info.WriteToken)
			delete(s.SubIndex, info.SubscriptionID)
			delete(s.Registry, id)

			// CRITICAL: We do NOT remove from s.Log.
			// The Log is append-only and immutable.

			// Unmap the peer address
			s.Peer.UnmapPeer(info.Addr)
		}
	}

	actualAddr, err := s.Peer.Start(port)
	if err != nil {
		return "", "", "", err
	}

	// Start Session Monitor & Bucket Cleanup
	s.Peer.StartSessionMonitor()
	go s.cleanupRelay()

	// Determine public IP
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

// cleanupRelay periodically removes old messages from PIR buckets to prevent memory leaks.
func (s *Server) cleanupRelay() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.bucketsMu.Lock()
		now := time.Now()
		for i, msgs := range s.relayBuckets {
			newMsgs := msgs[:0]
			for _, m := range msgs {
				if now.Sub(m.Timestamp) < 30*time.Second {
					newMsgs = append(newMsgs, m)
				}
			}
			if len(newMsgs) > 0 {
				s.relayBuckets[i] = newMsgs
			} else {
				delete(s.relayBuckets, i)
			}
		}
		s.bucketsMu.Unlock()
	}
}

// saveState persists the current server identity and merkle log to disk.
func (s *Server) saveState() error {
	privBytes, _ := x509.MarshalPKCS8PrivateKey(s.Peer.PrivKey)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	pubPEM := cryptolib.PubKeyToPEM(s.Peer.PubKey)

	encPrivPEM := cryptolib.EncPrivateKeyToPEM(s.Peer.EncPrivKey)
	encPubPEM := cryptolib.EncPubKeyToPEM(s.Peer.EncPubKey)

	id := ServerIdentity{
		PrivateKeyPEM:    string(privPEM),
		PublicKeyPEM:     string(pubPEM),
		EncPrivateKeyPEM: string(encPrivPEM),
		EncPublicKeyPEM:  string(encPubPEM),
		MerkleLeaves:     s.Log.Leaves,
	}

	buf := make([]byte, id.Size())
	id.Marshal(0, buf)

	// Atomic Write: Temp File -> Sync -> Rename
	dir := filepath.Dir(DefaultIdentityFile)
	tmpFile, err := os.CreateTemp(dir, "safem_server_*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(buf); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	return os.Rename(tmpFile.Name(), DefaultIdentityFile)
}

// handleRelay processes OpRelay packets using PIR-compatible storage (Dead Drop).
// Instead of forwarding explicitly to a user, it drops the message in a bucket
// derived from the WriteToken.
func (s *Server) handleRelay(remote *net.UDPAddr, data []byte) ([]byte, error) {
	if !s.RelayEnabled {
		return protocol.PackStrings("ERROR", "Relay Disabled"), nil
	}

	// Payload: [WriteToken][InnerPacket]
	n, writeToken, err := bstd.UnmarshalString(0, data)
	if err != nil {
		return nil, err
	}

	if len(writeToken) < 2 {
		return protocol.PackStrings("ERROR", "Invalid Token"), nil
	}

	innerPacket := data[n:]

	// Validate WriteToken exists (Authentication Step)
	// We verify that this is a valid token issued by the server.
	s.regMu.Lock()
	_, exists := s.WriteIndex[writeToken]
	s.regMu.Unlock()

	if !exists {
		return protocol.PackStrings("ERROR", "Invalid Write Token"), nil
	}

	// Determine Bucket Index from WriteToken (First byte of Hex)
	// Currently we enforce WriteToken[0:2] == SubscriptionID[0:2] during registration.
	// This ensures the writer puts it in the bucket the reader is polling.
	bucketIdx, err := strconv.ParseUint(writeToken[0:2], 16, 8)
	if err != nil {
		return nil, err
	}

	// Store in PIR Bucket
	s.bucketsMu.Lock()
	idx := uint8(bucketIdx)
	s.relayBuckets[idx] = append(s.relayBuckets[idx], RelayMessage{
		Data:      innerPacket,
		Timestamp: time.Now(),
	})
	s.bucketsMu.Unlock()

	return nil, nil // No response needed, Ack implied by UDP
}

// handlePIRQuery serves a bucket of messages to a polling client.
func (s *Server) handlePIRQuery(remote *net.UDPAddr, data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, nil
	}
	bucketIdx := uint8(data[0])

	s.bucketsMu.Lock()
	msgs := s.relayBuckets[bucketIdx]
	s.bucketsMu.Unlock()

	// Pack messages into a response
	// We extract just the data byte slices
	rawData := make([][]byte, len(msgs))
	for i, m := range msgs {
		rawData[i] = m.Data
	}

	// Serialize slice of byte slices
	size := bstd.SizeSlice(rawData, func(v []byte) int { return bstd.SizeBytes(v) })
	resp := make([]byte, size)

	bstd.MarshalSlice(0, resp, rawData, func(n int, b []byte, v []byte) int {
		return bstd.MarshalBytes(n, b, v)
	})

	return resp, nil
}

// handleRegister processes OpRegister packets.
func (s *Server) handleRegister(remote *net.UDPAddr, data []byte) ([]byte, error) {
	args := protocol.UnpackStrings(data)
	if len(args) < 5 {
		return nil, fmt.Errorf("invalid register format")
	}
	name, signPEM, encPEM, sigStr, tsStr := args[0], args[1], args[2], args[3], args[4]

	// Replay Protection
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
		s.LogFunc("[Security] Registration failed: Invalid signature for %s from %s\n", name, remote.String())
		return protocol.PackStrings("ERROR: Signature Verification Failed"), nil
	}

	id := cryptolib.Fingerprint(pubKey)

	// Update Registry
	s.regMu.Lock()
	defer s.regMu.Unlock()

	s.LogFunc("[Server] User '%s' (%s) connected from %s\n", name, id, remote.String())

	// Cleanup old session if re-registering
	if old, exists := s.Registry[id]; exists {
		delete(s.SubIndex, old.SubscriptionID) // Remove old subID
		delete(s.WriteIndex, old.WriteToken)   // Remove old writeToken
		if old.Addr != remote.String() {
			s.Peer.UnmapPeer(old.Addr)
		}
	}

	// 1. Generate Sealed Sender Subscription ID (READ Token)
	// This is kept private by the user to poll their bucket.
	subIDBytes, _ := cryptolib.GenerateRandomBytes(16)
	subID := hex.EncodeToString(subIDBytes)

	// 2. Generate Write Token (WRITE Capability)
	// Crucial for PIR: Must map to the SAME bucket as SubID.
	// We extract the bucket prefix (first byte) from SubID and force it onto WriteToken.
	bucketPrefix := subIDBytes[0]
	writeTokenBytes, _ := cryptolib.GenerateRandomBytes(16)
	writeTokenBytes[0] = bucketPrefix
	writeToken := hex.EncodeToString(writeTokenBytes)

	// 3. Generate Leaf Hash
	leafHash := cryptolib.CalculateLeafHash(id, signPEM, encPEM)

	// 4. Append to Transparency Log (O(1))
	logIdx := s.Log.Append(leafHash)

	// 5. PERSIST STATE TO DISK
	if err := s.saveState(); err != nil {
		s.LogFunc("[Error] Failed to persist Merkle Log: %v\n", err)
	}

	// Store in Registry
	s.Registry[id] = ClientInfo{
		Name:           name,
		Addr:           remote.String(),
		PEM:            signPEM,
		EncPEM:         encPEM,
		SubscriptionID: subID,
		WriteToken:     writeToken,
		LogIndex:       logIdx,
	}
	s.NameIndex[name] = id
	s.SubIndex[subID] = id       // Internal lookup (not used for routing anymore)
	s.WriteIndex[writeToken] = id // Validation lookup for writes

	s.Peer.TrustPeer(id, []byte(signPEM), []byte(encPEM))
	s.Peer.MapPeer(remote.String(), id, name)

	// 6. Generate Proof
	proof, proofOk := s.Log.Prove(logIdx)
	if !proofOk {
		s.LogFunc("[cryptolib] Error: Registered user not found in log\n")
		return protocol.PackStrings("ERROR: Internal Tree Error"), nil
	}

	// 7. Encode Proof
	var proofStr string
	for i, sibling := range proof {
		if i > 0 {
			proofStr += ","
		}
		proofStr += hex.EncodeToString(sibling)
	}

	root := s.Log.Root()
	rootHex := hex.EncodeToString(root)
	idxStr := strconv.Itoa(logIdx)
	totalStr := strconv.Itoa(len(s.Log.Leaves))

	// 8. Sign STH
	tsNow := strconv.FormatInt(time.Now().Unix(), 10)
	sthData := []byte(rootHex + tsNow)
	sthSig, _ := cryptolib.Sign(sthData, s.Peer.PrivKey)
	sthSigHex := hex.EncodeToString(sthSig)

	pemBytes := cryptolib.PubKeyToPEM(s.Peer.PubKey)

	// Return: [OK, ServerPEM, Root, Proof, Index, Total, STH_Sig, TS, SubscriptionID]
	// Note: We return SubscriptionID (Read Token) to the user so they know which bucket to poll.
	// We DO NOT return WriteToken here; users query it via OpQuery.
	return protocol.PackStrings(
		"OK",
		string(pemBytes),
		rootHex,
		proofStr,
		idxStr,
		totalStr,
		sthSigHex,
		tsNow,
		subID,
	), nil
}

// handleQuery processes address lookup requests with cryptolib Proofs.
func (s *Server) handleQuery(remote *net.UDPAddr, data []byte) ([]byte, error) {
	args := protocol.UnpackStrings(data)
	if len(args) < 5 {
		return nil, nil
	}
	targetID := args[0]
	signPEM, encPEM, tsStr, sigStr := args[1], args[2], args[3], args[4]

	s.regMu.Lock()
	defer s.regMu.Unlock()

	// Authenticate Sender
	var senderInfo ClientInfo
	foundSender := false
	for _, info := range s.Registry {
		if info.Addr == remote.String() {
			senderInfo = info
			foundSender = true
			break
		}
	}

	target, ok := s.Registry[targetID]

	if !ok {
		return protocol.PackStrings("ERROR", "User not found"), nil
	}
	if !foundSender {
		return protocol.PackStrings("ERROR", "Unauthorized"), nil
	}
	if signPEM != senderInfo.PEM {
		return protocol.PackStrings("ERROR", "Key Mismatch"), nil
	}

	pub, err := cryptolib.PEMToPubKey([]byte(signPEM))
	if err != nil {
		return protocol.PackStrings("ERROR", "Invalid Key"), nil
	}

	dataToVerify := fmt.Sprintf("%s%s%s%s", targetID, signPEM, encPEM, tsStr)
	if err := cryptolib.Verify([]byte(dataToVerify), []byte(sigStr), pub); err != nil {
		return protocol.PackStrings("ERROR", "Invalid Signature"), nil
	}

	// 1. Get Log Index from Registry (Latest Registration)
	idx := target.LogIndex

	// 2. Generate Inclusion Proof
	proof, proofOk := s.Log.Prove(idx)
	if !proofOk {
		s.LogFunc("[cryptolib] Critical Error: Registered user %s not found in log\n", targetID)
		return protocol.PackStrings("ERROR", "cryptolib Failure"), nil
	}

	// 3. Encode Proof
	var proofStr string
	for i, sibling := range proof {
		if i > 0 {
			proofStr += ","
		}
		proofStr += hex.EncodeToString(sibling)
	}

	root := s.Log.Root()
	rootHex := hex.EncodeToString(root)
	idxStr := strconv.Itoa(idx)
	totalStr := strconv.Itoa(len(s.Log.Leaves))

	// 4. Sign STH
	tsNow := strconv.FormatInt(time.Now().Unix(), 10)
	sthData := []byte(rootHex + tsNow)
	sthSig, _ := cryptolib.Sign(sthData, s.Peer.PrivKey)
	sthSigHex := hex.EncodeToString(sthSig)

	// Return Info + cryptolib Data + Sealed Sender WriteToken
	// Note: We return WriteToken here, NOT SubscriptionID.
	// This ensures the querier can WRITE, but cannot read (poll).
	return protocol.PackStrings(
		"OK",
		target.Addr,
		target.PEM,
		target.EncPEM,
		rootHex,
		proofStr,
		idxStr,
		totalStr,
		sthSigHex,
		tsNow,
		target.WriteToken, // Allows sender to route via relay
	), nil
}

func (s *Server) handleDisconnect(remote *net.UDPAddr, data []byte) ([]byte, error) {
	id := s.Peer.GetID(remote.String())
	if id == "" {
		return nil, nil
	}

	s.regMu.Lock()
	if info, ok := s.Registry[id]; ok {
		if info.Addr != remote.String() {
			s.regMu.Unlock()
			return nil, nil
		}
	}
	s.regMu.Unlock()

	s.Peer.Disconnect(id)
	return nil, nil
}

func (s *Server) handleInvite(remote *net.UDPAddr, data []byte) ([]byte, error) {
	args := protocol.UnpackStrings(data)
	if len(args) < 4 {
		return nil, nil
	}
	targetID, blobHex, ts, sig := args[0], args[1], args[2], args[3]

	s.regMu.Lock()
	target, ok := s.Registry[targetID]

	var senderInfo ClientInfo
	var senderID string
	foundSender := false
	for id, info := range s.Registry {
		if info.Addr == remote.String() {
			senderInfo = info
			senderID = id
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

	pub, err := cryptolib.PEMToPubKey([]byte(senderInfo.PEM))
	if err != nil {
		return protocol.PackStrings("Security Error: Invalid Sender Key"), nil
	}

	verifyData := fmt.Sprintf("%s%s%s", targetID, blobHex, ts)
	if err := cryptolib.Verify([]byte(verifyData), []byte(sig), pub); err != nil {
		return protocol.PackStrings("Security Error: Invalid Outer Signature"), nil
	}

	s.LogFunc("[Server] Forwarding Encrypted Invite from %s to %s\n", senderInfo.Name, target.Name)

	fwdPayload := protocol.PackStrings(senderID, blobHex, ts)
	go s.Peer.Call(context.Background(), target.Addr, protocol.OpIncomingInvite, fwdPayload)

	return protocol.PackStrings("Invite Forwarded"), nil
}

func (s *Server) handleAccept(remote *net.UDPAddr, data []byte) ([]byte, error) {
	args := protocol.UnpackStrings(data)
	if len(args) < 4 {
		return nil, nil
	}
	targetID, blobHex, ts, sig := args[0], args[1], args[2], args[3]

	s.regMu.Lock()
	target, ok := s.Registry[targetID]

	var senderInfo ClientInfo
	var senderID string
	foundSender := false
	for id, info := range s.Registry {
		if info.Addr == remote.String() {
			senderInfo = info
			senderID = id
			foundSender = true
			break
		}
	}
	s.regMu.Unlock()

	if !ok {
		return nil, nil
	}
	if !foundSender {
		return nil, nil
	}

	pub, err := cryptolib.PEMToPubKey([]byte(senderInfo.PEM))
	if err != nil {
		return nil, nil
	}
	verifyData := fmt.Sprintf("%s%s%s", targetID, blobHex, ts)
	if err := cryptolib.Verify([]byte(verifyData), []byte(sig), pub); err != nil {
		return nil, nil
	}

	s.LogFunc("[Server] Forwarding Encrypted Acceptance from %s to %s\n", senderInfo.Name, target.Name)

	fwdPayload := protocol.PackStrings(senderID, blobHex, ts)
	go s.Peer.Call(context.Background(), target.Addr, protocol.OpInviteFinalized, fwdPayload)

	return protocol.PackStrings("ACK"), nil
}

func (s *Server) loadOrGenIdentity(path string) (ed25519.PrivateKey, ed25519.PublicKey, *ecdh.PrivateKey, *ecdh.PublicKey, [][]byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		var id ServerIdentity
		if _, err := id.Unmarshal(0, data); err == nil {
			priv, err := cryptolib.ParsePrivateKey(id.PrivateKeyPEM)
			if err != nil {
				return nil, nil, nil, nil, nil, fmt.Errorf("corrupt private key")
			}
			pub, err := cryptolib.PEMToPubKey([]byte(id.PublicKeyPEM))
			if err != nil {
				return nil, nil, nil, nil, nil, fmt.Errorf("corrupt public key")
			}

			encPriv, err := cryptolib.ParseEncPrivateKey(id.EncPrivateKeyPEM)
			if err != nil {
				return nil, nil, nil, nil, nil, fmt.Errorf("corrupt enc priv key")
			}
			encPub, err := cryptolib.PEMToEncPubKey([]byte(id.EncPublicKeyPEM))
			if err != nil {
				return nil, nil, nil, nil, nil, fmt.Errorf("corrupt enc pub key")
			}

			// Return keys AND persistent Merkle Leaves
			return priv, pub, encPriv, encPub, id.MerkleLeaves, nil
		}
	}

	s.LogFunc("[Server] No identity found. Generating new secure keys...\n")

	priv, pub, err := cryptolib.GenerateKeyPair(0)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	encPriv, encPub, err := cryptolib.GenerateECDH()
	if err != nil {
		return nil, nil, nil, nil, nil, err
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
		MerkleLeaves:     nil, // New server has no history
	}

	buf := make([]byte, newID.Size())
	newID.Marshal(0, buf)

	// Atomic Write for new identity
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, "safem_identity_*.tmp")
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(buf); err != nil {
		tmpFile.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to write identity: %v", err)
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to sync identity: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to close temp identity: %v", err)
	}

	if err := os.Rename(tmpFile.Name(), path); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to save identity file: %v", err)
	}

	return priv, pub, encPriv, encPub, nil, nil
}

func (s *Server) getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}