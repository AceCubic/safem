# SAFEM Protocol

**Simple As F*ck Encrypted Messenger**

SAFEM is a high-performance, peer-to-peer (P2P) communication library written in Go. It provides a robust foundation for building secure chat applications with support for direct messaging, group chats, file transfers, and high-fidelity voice calls.

The protocol implements the **Double Ratchet Algorithm** for end-to-end encryption, ensuring perfect forward secrecy and post-compromise security.

## Key Features

* **End-to-End Encryption:** Hybrid encryption scheme using X25519 (ECDH), Ed25519 (Signing), and AES-256-GCM. Implements a Double Ratchet for message-level security.
* **P2P Networking:** Built on UDP with custom reliability layers. Includes automatic hole-punching for NAT traversal and fallback relay support.
* **Voice over IP:** Integrated Opus audio engine with a jitter buffer and packet loss concealment for low-latency voice calls.
* **Resumable File Transfer:** Chunked, reliable file streaming supporting large files without memory exhaustion.
* **Group Chats:** Causal ordering using Vector Clocks to ensure message consistency across distributed group members.
* **Zero-Copy Logic:** optimized memory pooling for high-frequency network and audio packets.

## Installation

```bash
go get github.com/banditmoscow1337/safem

```

*Note: You will need `libopus` headers installed on your system for the audio engine dependencies.*

## Quick Start

Below is a minimal example of how to initialize a client and connect to the rendezvous server.

```go
package main

import (
	"context"
	"fmt"
	"github.com/banditmoscow1337/safem/protocol/client"
	"github.com/banditmoscow1337/safem/protocol/profile"
)

// Implement the Events interface to handle callbacks
type MyHandler struct{}
func (h *MyHandler) OnMessage(id, name, text string) { fmt.Printf("[%s]: %s\n", name, text) }
func (h *MyHandler) OnLog(format string, args ...any) { fmt.Printf(format, args...) }
// ... implement other methods of client.Events ...

func main() {
	// Load or Create Profile
	prof, err := profile.Load("user.safem", "my-secure-password")
	if err != nil {
		panic(err)
	}

	// Initialize Client
	events := &MyHandler{}
	c, _ := client.New(prof, events)

	// Start Networking (binds to random UDP port)
	addr, _ := c.Start()
	fmt.Printf("Listening on %s\n", addr)

	// Connect to Rendezvous Server
	// (addr, signPEM, and encPEM should be obtained from the server admin)
	ctx := context.Background()
	c.ConnectToServer(ctx, "server-ip:port", "SERVER_SIGN_PEM", "SERVER_ENC_PEM")

	// Prevent exit
	select {}
}

```

---

## API Reference

The core logic resides in the `client` package, which orchestrates the profile, network, and audio subsystems.

### 1. Client Lifecycle

#### `func New(prof *profile.Profile, events Events) (*Client, error)`

Creates a new Client instance.

* **prof**: The loaded user profile containing keys and contact lists.
* **events**: An implementation of the `client.Events` interface to handle UI callbacks (incoming messages, calls, etc.).

#### `func (c *Client) Start() (string, error)`

Opens the UDP socket, initializes the audio engine, and starts background maintenance loops (heartbeats, keep-alives). Returns the local bind address.

#### `func (c *Client) Shutdown()`

Gracefully disconnects all peers, stops the audio engine, and saves the profile state.

#### `func (c *Client) ConnectToServer(ctx context.Context, addr, signPEM, encPEM string) error`

Registers the client with a Rendezvous Server to enable peer discovery.

* **signPEM/encPEM**: The server's public keys for authenticating the connection.

### 2. Identity & Friends

#### `func (c *Client) SendInvite(ctx context.Context, targetID string)`

Sends a cryptographically signed friend request to a target User ID via the server.

#### `func (c *Client) AcceptInvite(ctx context.Context, targetID string)`

Accepts a pending friend request, performs the initial handshake, and adds the user to the local contact list.

#### `func (c *Client) RemoveFriend(id string) error`

Removes a friend from the profile and terminates the network session.

#### `func (c *Client) GetSafetyNumber(friendID string) (string, error)`

Computes the safety number fingerprint (numeric string) for a specific friend for manual verification.

#### `func (c *Client) SetMyContent(content profile.UserContent) error`

Updates local user data (Avatar, Status) and broadcasts the update to all online friends.

### 3. Messaging

#### `func (c *Client) SendText(ctx context.Context, targetID, text string) error`

Sends a secured, signed text message. If the peer is offline, the message is queued locally for store-and-forward delivery.

#### `func (c *Client) SendTyping(ctx context.Context, targetID string) error`

Sends a fleeting "typing..." indicator to the target peer.

### 4. Group Chat

#### `func (c *Client) CreateGroup(name string, initialMembers []string) (string, error)`

Creates a new group locally and sends invites to the specified member IDs. Returns the new Group ID.

#### `func (c *Client) InviteToGroup(groupID string, userIDs []string)`

Invites new members to an existing group.

#### `func (c *Client) SendGroupText(ctx context.Context, groupID, text string) error`

Fans out a text message to all group members. Uses **Vector Clocks** to handle causal ordering and consistency.

#### `func (c *Client) RequestGroupSync(ctx context.Context, groupID string) error`

Broadcasts the local Vector Clock to group members to request missing history.

#### `func (c *Client) LeaveGroup(ctx context.Context, groupID string) error`

Removes the local user from the group and notifies other members.

#### `func (c *Client) KickUserFromGroup(ctx context.Context, groupID, targetID string) error`

Removes a user from the group. Only available to the group owner.

### 5. File Transfer

#### `func (c *Client) SendFile(ctx context.Context, targetID, path string) error`

Initiates a file upload.

1. Sends a request with metadata (Name, Size).
2. Waits for peer acceptance.
3. Streams file in reliable chunks.

#### `func (c *Client) AcceptFileTransfer(transferID string) error`

Accepts an incoming file request and opens a stream to write data to disk.

#### `func (c *Client) RejectFileTransfer(transferID string) error`

Denies an incoming file request.

### 6. Voice (VoIP)

#### `func (c *Client) InviteCall(targetID string) error`

Sends a voice call invitation. If a call is already active, this acts as an "Add User" request for conference calling.

#### `func (c *Client) AnswerCall(targetID string, accept bool)`

Accepts or rejects an incoming call invitation.

#### `func (c *Client) HangupCall()`

Terminates the current call and stops the audio engine.

#### `func (c *Client) ToggleMute() bool`

Toggles the microphone mute state.

---

## Cryptography

SAFEM uses a custom implementation of modern cryptographic primitives:

* **Identity:** Ed25519 keys are used for signing all payloads to ensure non-repudiation.
* **Key Exchange:** X25519 (ECDH) is used for the initial handshake and Ratchet steps.
* **Transport Security:** AES-256-GCM is used for encrypting all wire packets.
* **Double Ratchet:** Every session maintains a KDF chain.
* *Symmetric Ratchet:* Updates keys for every message sent/received.
* *DH Ratchet:* Updates keys periodically or on round-trips to provide self-healing properties.