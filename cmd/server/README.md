# SAFEM Rendezvous Server

A lightweight signaling and relay server for the SAFEM P2P network. 

This server does **not** store chat logs or private keys. Its primary purpose is to:
1.  Act as a directory service for User ID to IP Address resolution.
2.  Facilitate "hole punching" for NAT traversal.
3.  (Optional) Act as a blind relay (TURN-like) for peers who cannot establish direct P2P connections.

## Installation

```bash
cd cmd/server
go build -o safem-server .

```

## Usage

```bash
./safem-server [flags]

```

### Flags

* `-port <int>`: The UDP port to listen on (Default: `14888`).
* `-relay`: Enable packet relaying functionality (Default: `false`). Use this if clients are behind restrictive firewalls.

### Server Identity

On the first run, the server generates a cryptographic identity file (`server.safem`) containing its Ed25519 signing keys and X25519 encryption keys. **Keep this file secure.** If lost, all clients will need to update their configuration to trust the new server identity.

### The Connection String

When the server starts, it prints a **Connection String** (Token) to the console:

```text
----------------------------------------------------------------
SERVER STARTED (ID-BASED REGISTRY)
Listen Address: 203.0.113.1:14888
Server ID:      a1b2c3d4...
----------------------------------------------------------------
CONNECTION STRING:
eyJAdZ... (Base64 Encoded Token) ...
----------------------------------------------------------------

```

**You must provide this Connection String to your clients.** It contains the server's IP, port, and public keys required for clients to securely register and authenticate.

## Security Architecture

* **Authentication:** Clients sign their registration requests with their private identity keys. The server verifies signatures before updating the registry.
* **Privacy:** The server only knows the metadata (Who is talking to whom) required for routing. It cannot read the content of messages or files, which are end-to-end encrypted between peers.
* **Relay Security:** If relaying is enabled, packets are wrapped in an outer layer of encryption for the server, but the inner payload remains encrypted with the peer's session keys. The server cannot decrypt the inner payload.