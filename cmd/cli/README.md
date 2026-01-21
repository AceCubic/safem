# SAFEM CLI Client

The reference Terminal User Interface (TUI) client for the SAFEM protocol. This application provides a secure, encrypted peer-to-peer chat experience with support for direct messaging, group chats, file transfers, and high-fidelity voice calls directly from your terminal.

## Features

* **End-to-End Encryption:** All messages and files are encrypted using Double Ratchet (X25519/AES-256-GCM).
* **Voice Calls:** Low-latency P2P voice calls using the Opus codec.
* **Group Chat:** Decentralized group messaging with causal ordering (Vector Clocks).
* **File Transfer:** Resumable, encrypted large file streaming.
* **TUI:** Keyboard-centric interface built with `tview`.

## Prerequisites

This client requires **CGO** enabled and specific system libraries for audio hardware access (`malgo`/PortAudio) and encoding (`libopus`).

### Linux (Debian/Ubuntu)
```bash
sudo apt-get update
sudo apt-get install -y libopus-dev libasound2-dev gcc pkg-config

```

### macOS

```bash
brew install opus portaudio

```

### Windows

The client attempts to automatically download `libopus.dll` on startup if missing, but you must have a GCC environment (like MinGW-w64) to compile the audio headers.

## Installation

```bash
cd cmd/cli
go build -o safem .

```

## Getting Started

1. **Run the Client:**
```bash
./safem

```


2. **Initial Setup:**
On first run, you will be prompted to create a profile:
* **Nickname:** Your public display name.
* **Server Token:** The base64 connection string provided by your Rendezvous Server administrator (see `cmd/server`).
* **Password:** A strong password to encrypt your local profile database (`profile.safem`).



## Usage & Controls

### Global Keybindings

| Key | Action |
| --- | --- |
| `Tab` | Switch focus between Chat and Friend List |
| `Ctrl + A` | Open "Add Friend" modal |
| `Ctrl + N` | View/Accept pending Friend Invites |
| `Ctrl + F` | Send a file to the active chat |
| `Ctrl + P` | Start/Hangup Voice Call |
| `Ctrl + C` | Quit Application |

### Chat Commands

Type these commands into the message input field:

* **Friends & Identity**
* `/invite <User_ID>` - Send a friend request to a specific User ID.
* `/accept <User_ID>` - Manually accept a friend request.
* `/remove <User_ID>` - Remove a friend and delete connection data.
* `/safety` - View and verify the cryptographic safety number for the active chat to detect MITM attacks.


* **Groups**
* `/group create <Name> <ID1> <ID2>...` - Create a new decentralized group.
* `/group invite <GID> <ID>...` - Invite users to an existing group.
* `/group leave <GID>` - Leave a group.
* `/group kick <GID> <ID>` - Remove a user (Owner only).
* `/group list` - List all groups in the log.


* **Media**
* `/call` - Call the active friend.
* `/call add <ID>` - Add a user to the current call (Conference).
* `/hangup` - End the current call.
* `/mute` - Toggle microphone mute.
* `/sendfile <path>` - Send a file to the active friend.
* `/devices` - Open audio input/output device selector.


* **System**
* `/metrics` - Display network statistics (packet loss, retransmits).
* `/password <new_password>` - Change your profile encryption password.
* `/quit` - Exit the application.



## Troubleshooting

* **Profile Locked:** If you restart the application, you must enter your password to decrypt your keys and history.
* **Audio Issues:** Use `/devices` to ensure the correct microphone and speaker are selected.
* **Connection:** Ensure you have a valid Server Token. If the server is down, P2P connections to existing friends may still work if their addresses are cached and holes are punched, but new connections will fail.