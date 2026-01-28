# SAFEM (Simple As F*ck Encrypted Messenger)

**SAFEM** is a high-performance, peer-to-peer (P2P) secure communication platform written in Go. It features a modern, terminal-based user interface (TUI) and a robust protocol library designed for privacy, speed, and resistance to censorship.

It implements a custom Double Ratchet protocol over UDP to ensure **Perfect Forward Secrecy (PFS)** and **Post-Compromise Security (PCS)** for all messages, files, and voice calls.

## Key Features

* **End-to-End Encryption:** Built from the ground up using Ed25519 (Identity), X25519 (Key Exchange), and AES-256-GCM.
* **Encrypted VoIP:** Low-latency, high-fidelity voice calls using the **Opus** codec with a custom jitter buffer and packet loss concealment.
* **Resumable File Transfer:** Send large files securely via reliable UDP chunking.
* **Decentralized Groups:** Group chats utilize **Vector Clocks** to ensure causal message ordering and consistency across distributed members without a central timeline.
* **High Performance:** Engineered with **zero-copy** networking logic and aggressive object pooling to minimize Garbage Collection (GC) pressure.
* **NAT Traversal:** Automatic UDP hole-punching with a fallback Relay (TURN-like) mode for restrictive firewalls.
* **TUI Client:** A full-featured keyboard-driven terminal interface.

## Architecture

SAFEM consists of two main components:

1. **Client (`cmd/cli`)**: The TUI chat application.
2. **Rendezvous Server (`cmd/server`)**: A lightweight signaling server used *only* for peer discovery and optional relaying. It **cannot** decrypt messages.

## Prerequisites

To build and run SAFEM, you need **Go 1.25+** and CGO-compatible system libraries for audio.

### Linux (Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y libopus-dev libasound2-dev gcc pkg-config

```

### macOS

```bash
brew install opus

```

### Windows

You need a GCC environment (like MinGW-w64). The client attempts to automatically download `libopus.dll` on first run if missing.

## Installation

```bash
# Clone the repository
git clone https://github.com/banditmoscow1337/safem.git
cd safem

# Build the Client
go build -o safem ./cmd/cli

# Build the Server
go build -o safem-server ./cmd/server

```

## Quick Start

### 1. Start the Server

You (or a friend) must host a rendezvous server. It generates a **Connection Token** on startup.

```bash
./safem-server -port 14888

```

*Copy the `CONNECTION STRING` (Base64 token) printed to the console.*

### 2. Run the Client

Start the client. On the first run, you will be prompted to setup your profile.

```bash
./safem

```

* **Nickname:** Your display name.
* **Server Token:** Paste the Base64 string from the server.
* **Password:** Set a strong password to encrypt your local database (`profile.safem`).

## Usage

The TUI is designed for keyboard efficiency.

### Global Hotkeys

| Key | Action |
| --- | --- |
| `Tab` | Toggle focus between Chat and Friend List |
| `Ctrl+A` | **Add Friend** (Enter User ID) |
| `Ctrl+N` | View/Accept **Pending Invites** |
| `Ctrl+P` | Start or Hangup **Voice Call** |
| `Ctrl+F` | **Send File** to active chat |
| `Ctrl+C` | Quit |

### Slash Commands

Type these in the message input:

* **Identity & Friends**
* `/invite <UserID>`: Send a friend request.
* `/remove <UserID>`: Delete a friend.
* `/safety`: View cryptographic safety number (fingerprint) to verify no MITM.
* `/metrics`: View network stats (packet loss, retransmits).


* **Groups**
* `/group create <Name> <ID1> <ID2>`: Create a new group.
* `/group invite <GID> <ID>`: Add a user to an existing group.
* `/group kick <GID> <ID>`: Remove a user (Owner only).
* `/group leave <GID>`: Leave a group.


* **Media**
* `/call`: Call the current friend.
* `/call add <ID>`: Add a user to the current call (Conference).
* `/mute`: Toggle microphone.
* `/devices`: Select input/output audio devices.



## Library Usage

SAFEM can be used as a library to build custom P2P applications.

```go
package main

import (
    "context"
    "github.com/banditmoscow1337/safem/protocol/client"
    "github.com/banditmoscow1337/safem/protocol/profile"
)

func main() {
    // Load Profile (Encrypted at rest)
    prof, _ := profile.Load("user.safem", "my-password")

    // Initialize Client with Event Handlers
    // (Implement the client.Events interface for callbacks)
    events := &MyUIHandler{} 
    c, _ := client.New(prof, events)

    // Start Networking
    c.Start()
    
    // Connect to Signaling Server
    c.ConnectToServer(context.Background(), "1.2.3.4:14888", "SERVER_KEY...", "SERVER_ENC_KEY...")

    // Send a Message
    c.SendText(context.Background(), "TARGET_PEER_ID", "Hello World!")
}

```

## Cryptography Specs

* **Identity:** Ed25519 (Signing/Verification).
* **Key Agreement:** X25519 (ECDH).
* **Transport:** AES-256-GCM.
* **KDF:** HMAC-SHA-256 / HKDF.
* **Ratchet:** Custom Double Ratchet implementation with header encryption.
* **Database:** PBKDF2-SHA256 encrypted local storage.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Disclaimer

This software is **experimental** and has not been audited by a third-party security firm. While it uses standard cryptographic primitives, **do not use this for life-critical situations** without your own verification.

## License

[MIT](LICENSE)