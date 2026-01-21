// Package client provides the high-level API for the SAFEM P2P chat application.
//
// It acts as the coordinator between the user interface (UI), the local identity profile,
// and the low-level P2P networking layer. The Client struct is the primary entry point,
// managing friends, groups, messaging, file transfers, and voice calls.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/banditmoscow1337/safem/protocol"
	"github.com/banditmoscow1337/safem/protocol/cryptolib"
	"github.com/banditmoscow1337/safem/protocol/p2p"
	"github.com/banditmoscow1337/safem/protocol/profile"
	"golang.org/x/time/rate"
)

// Events defines the callback interface that the UI layer (or any consumer)
// must implement to receive asynchronous notifications from the Client.
type Events interface {
	// OnLog handles debug and system logs.
	OnLog(format string, args ...any)
	// OnMessage is triggered when a text message is received.
	OnMessage(id, name, text string)
	// OnInviteReceived is triggered when a new friend request arrives.
	OnInviteReceived(id, name, addr, pem string)
	// OnFriendAdded is triggered when a friend request is accepted and the user is added.
	OnFriendAdded(id, name string)
	// OnFriendStatus is triggered when a friend's online/offline status changes.
	OnFriendStatus(id string, online bool)
	// OnVoiceStatus is triggered when the call state changes (active/inactive).
	OnVoiceStatus(active bool, targetName string)
	// OnFileReceived is triggered when a file transfer completes successfully.
	OnFileReceived(id, name, path string)
	// OnIncomingCall is triggered when a voice call invitation is received.
	OnIncomingCall(id, name string)
	// OnTyping is triggered when a peer is typing.
	OnTyping(id string)
	// OnFileRequest is triggered when a peer wants to send a file, requiring acceptance.
	OnFileRequest(transferID, senderID, name string, size int64)
	// OnFriendUpdated is triggered when a friend's profile content (avatar/status) changes.
	OnFriendUpdated(id string, info profile.UserContent)
}

// Client represents the local P2P node. It manages the identity profile,
// underlying network peer, and high-level application logic.
type Client struct {
	// Peer is the low-level P2P networking handler.
	Peer *p2p.Peer
	// Profile stores the local user's identity, friends, and settings.
	Profile *profile.Profile
	// Events is the interface for notifying the UI.
	Events Events

	// Voice manages audio capture, encoding, and mixing.
	Voice *VoiceManager

	serverID           string

	// inviteLimiter restricts the rate of outbound friend invites to prevent spam.
	inviteLimiter *rate.Limiter

	// transfers tracks active file downloads/uploads.
	transfers   map[string]*FileTransferState
	transfersMu sync.Mutex

	// pendingResponses manages channels for user acceptance/rejection of outgoing requests.
	pendingResponsesMu sync.Mutex
	pendingResponses   map[string]chan bool // Sender side: transferID -> accept/reject

	// pendingIncoming stores metadata for incoming requests waiting for user action.
	pendingIncomingMu sync.Mutex
	pendingIncoming   map[string]incomingFileReq // Receiver side: transferID -> meta
}

// New initializes a new Client instance with the given profile and event handler.
// It sets up the underlying P2P peer using the profile's cryptographic keys.
func New(prof *profile.Profile, events Events) (*Client, error) {
	// Parse identity keys from PEM storage
	privKey, _ := cryptolib.ParsePrivateKey(string(prof.GetPrivateKeyPEM()))
	pubKey, _ := cryptolib.PEMToPubKey([]byte(prof.GetPublicKeyPEM()))

	encPrivKey, _ := cryptolib.ParseEncPrivateKey(string(prof.GetEncPrivateKeyPEM()))
	encPubKey, _ := cryptolib.PEMToEncPubKey(prof.GetEncPublicKeyPEM())

	p := p2p.NewPeer(privKey, pubKey, encPrivKey, encPubKey)

	c := &Client{
		Peer:             p,
		Profile:          prof,
		Events:           events,
		Voice:            NewVoiceManager(p),
		// Rate Limit: 1 invite/sec, burst of 3
		inviteLimiter:    rate.NewLimiter(rate.Every(time.Second), 3),
		transfers:        make(map[string]*FileTransferState),
		pendingResponses: make(map[string]chan bool),
		pendingIncoming:  make(map[string]incomingFileReq),
	}

	c.Peer.Logger = events.OnLog

	// Hook into low-level P2P callbacks
	c.Peer.OnFileComplete = func(remote *net.UDPAddr, path string) {
		c.handleFileRef(remote, []byte(path))
	}

	// Handle Session Closures (Network Timeout / Disconnect)
	// This ensures that if a peer drops, they are removed from any active voice calls.
	c.Peer.OnSessionClosed = func(id string) {
		if c.Voice.IsPeerActive(id) {
			// Remove the specific peer from the voice manager
			c.Voice.StopPeer(id)
			name := c.Peer.GetName(id)

			// If no one else is left in the call, end it locally.
			if !c.Voice.Active() {
				c.Events.OnVoiceStatus(false, "")
				c.Events.OnLog("[Voice] Call ended: %s disconnected.\n", name)
			} else {
				// Conference continues with remaining peers
				c.Events.OnLog("[Voice] %s disconnected from call.\n", name)
			}
		}
	}

	c.registerHandlers()

	return c, nil
}

// Start opens the UDP socket and begins listening for traffic.
// It also initializes background routines for status monitoring and heartbeats.
// Returns the local address string or an error.
func (c *Client) Start() (string, error) {
	// Initialize Voice asynchronously to avoid blocking the main thread (UI).
	// Audio device initialization (PortAudio/Malgo) can be slow.
	go c.Voice.Init()

	addr, err := c.Peer.Start(0) // 0 lets the OS choose a port
	if err != nil {
		return "", err
	}

	// Start background maintenance loops
	go c.statusLoop()
	go c.startHeartbeatLoop()

	return addr, nil
}

// ConnectToServer registers the client with the rendezvous server.
// This is necessary to be discoverable by other peers via ID.
//
// args:
//   ctx: Context for the request.
//   addr: Server address (IP:Port).
//   signPEM: Server's Signing Public Key (PEM).
//   encPEM: Server's Encryption Public Key (PEM).
func (c *Client) ConnectToServer(ctx context.Context, addr, signPEM, encPEM string) error {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nickname := c.Profile.GetNickname()

	// The server verifies: Name + EncPEM + Timestamp signed by the Identity Key.
	encPub := string(c.Profile.GetEncPublicKeyPEM())

	// Sign the registration payload
	sigData := []byte(nickname + encPub + timestamp)
	sig, err := cryptolib.Sign(sigData, c.Peer.PrivKey)
	if err != nil {
		return fmt.Errorf("failed to sign registration: %v", err)
	}

	// Construct Payload: [Nickname, SignPubPEM, EncPubPEM, Signature, Timestamp]
	regPayload := protocol.PackStrings(
		nickname,
		string(c.Profile.GetPublicKeyPEM()),
		encPub,
		string(sig),
		timestamp,
	)

	// Establish trust with the Server's identity
	if signPEM != "" {
		serverPub, _ := cryptolib.PEMToPubKey([]byte(signPEM))
		c.serverID = cryptolib.Fingerprint(serverPub)
		c.Peer.TrustPeer(c.serverID, []byte(signPEM), []byte(encPEM))
		c.Peer.MapPeer(addr, c.serverID, "Server")
	}

	// Send Register Op
	resp, err := c.Peer.Call(ctx, addr, protocol.OpRegister, regPayload)
	if err != nil {
		return err
	}

	// Check response for server errors
	respStrs := protocol.UnpackStrings(resp)
	if len(respStrs) > 0 && strings.HasPrefix(respStrs[0], "ERROR") {
		return fmt.Errorf("%s", respStrs[0])
	}

	// Once connected, attempt to reconnect to known friends
	go c.reconnectFriends()
	
	// Trigger Group Sync
	go func() {
		time.Sleep(2 * time.Second) // Allow P2P handshakes to complete
		groups := c.Profile.ListGroups()
		for _, g := range groups {
			go c.RequestGroupSync(context.Background(), g.ID)
		}
	}()

	return nil
}

// Shutdown gracefully stops the client, disconnecting peers and cleaning up audio resources.
func (c *Client) Shutdown() {
	c.Peer.DisconnectAll()
	c.Voice.Cleanup()
}

// SetMyContent updates the local user profile and broadcasts it to all friends.
func (c *Client) SetMyContent(content profile.UserContent) error {
	c.Profile.SetUserContent(content)
	if err := c.Profile.Save(); err != nil {
		return err
	}
	
	// Broadcast the change to all friends
	c.broadcastMyContent()
	return nil
}

// statusLoop periodically checks friend sessions and updates their online status.
func (c *Client) statusLoop() {
	for {
		time.Sleep(1 * time.Second)
		friends := c.Profile.ListFriends()
		for _, f := range friends {
			sess, online := c.Peer.GetSession(f.ID)

			// A peer is reachable only if we have an active session AND a resolved address
			isReachable := online && sess.Addr != ""

			c.Events.OnFriendStatus(f.ID, isReachable)

			// Store-and-Forward: Flush pending messages if user came online
			if isReachable {
				c.flushPendingMessages(f.ID)
			}
		}
	}
}

// flushPendingMessages attempts to send messages that were queued while a peer was offline.
func (c *Client) flushPendingMessages(targetID string) {
	pending := c.Profile.GetPending(targetID)
	if len(pending) == 0 {
		return
	}

	sess, ok := c.Peer.GetSession(targetID)
	if !ok || sess.Addr == "" {
		return
	}

	var failed []profile.MessageEntry
	var changed bool

	// Use timeout to prevent blocking the status loop indefinitely
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, msg := range pending {
		// Re-construct the packet payload
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, uint16(len(msg.Signature)))
		buf.Write(msg.Signature)
		buf.WriteString(msg.Content)

		// Attempt to send
		if err := c.Peer.SendLarge(ctx, sess.Addr, protocol.OpMsg, buf.Bytes()); err != nil {
			failed = append(failed, msg)
		} else {
			changed = true
		}
	}

	// Update the pending list in the profile
	if changed {
		c.Profile.SetPending(targetID, failed)
		c.Profile.Save()
	}
}

// StorePrivateKey converts an Ed25519 private key to PEM format.
func StorePrivateKey(key ed25519.PrivateKey) []byte {
	b, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})
}

// LeaveGroup removes the local user from a group, deletes it locally,
// and notifies other members.
func (c *Client) LeaveGroup(ctx context.Context, groupID string) error {
	group, ok := c.Profile.GetGroup(groupID)
	if !ok {
		return fmt.Errorf("group not found")
	}

	// Payload: [GID]
	payload := protocol.PackStrings(groupID)

	// Notify all other members
	for _, memberID := range group.Members {
		if memberID == c.Profile.GetID() {
			continue
		}
		go func(uid string) {
			sess, ok := c.Peer.GetSession(uid)
			if ok && sess.Addr != "" {
				c.Peer.SendFast(context.Background(), sess.Addr, protocol.OpGroupLeave, payload)
			}
		}(memberID)
	}

	// Remove locally
	c.Profile.RemoveGroup(groupID)
	return c.Profile.Save()
}

// handleGroupLeave processes a notification that another user has left a group.
func (c *Client) handleGroupLeave(remote *net.UDPAddr, data []byte) ([]byte, error) {
	parts := protocol.UnpackStrings(data)
	if len(parts) < 1 {
		return nil, fmt.Errorf("malformed leave payload")
	}
	gid := parts[0]
	senderID := c.Peer.GetID(remote.String())

	group, ok := c.Profile.GetGroup(gid)
	if !ok {
		return nil, nil // Unknown group, ignore
	}

	// Update local group definition
	if err := c.Profile.RemoveGroupMember(gid, senderID); err == nil {
		c.Profile.Save()
		senderName := c.Peer.GetName(senderID)
		c.Events.OnLog("[Group] %s left group '%s'.\n", senderName, group.Name)
	}

	return protocol.PackStrings("ACK"), nil
}