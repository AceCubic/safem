package client

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/banditmoscow1337/safem/protocol"
	"github.com/banditmoscow1337/safem/protocol/cryptolib"
)

// registerHandlers binds all protocol OpCodes to their respective handler functions.
func (c *Client) registerHandlers() {
	// Identity & Friends
	c.Peer.RegisterHandler(protocol.OpIncomingInvite, c.handleIncomingInvite)
	c.Peer.RegisterHandler(protocol.OpInviteFinalized, c.handleInviteFinalized)
	c.Peer.RegisterHandler(protocol.OpDisconnect, c.handleDisconnect)

	// Messaging
	c.Peer.RegisterHandler(protocol.OpMsg, c.handleMsg)

	// Groups
	c.Peer.RegisterHandler(protocol.OpGroupInvite, c.handleGroupInvite)
	c.Peer.RegisterHandler(protocol.OpGroupMsg, c.handleGroupMsg)
	c.Peer.RegisterHandler(protocol.OpGroupKick, c.handleGroupKick)
	c.Peer.RegisterHandler(protocol.OpGroupLeave, c.handleGroupLeave)
	
	// Group Sync
	c.Peer.RegisterHandler(protocol.OpGroupSyncReq, c.handleGroupSyncReq)
	c.Peer.RegisterHandler(protocol.OpGroupSyncRes, c.handleGroupSyncRes)

	// Files
	c.Peer.RegisterHandler(protocol.OpFile, c.handleFile)           // Legacy small file handler
	c.Peer.RegisterHandler(protocol.OpFileStart, c.handleFileStart) // Start streaming transfer
	c.Peer.RegisterHandler(protocol.OpFileBlock, c.handleFileBlock) // Streaming data block
	c.Peer.RegisterHandler(protocol.OpFileAccept, c.handleFileAccept)
	c.Peer.RegisterHandler(protocol.OpFileReject, c.handleFileReject)

	// Voice / Call Signaling
	c.Peer.RegisterHandler(protocol.OpCallInvite, c.handleCallInvite)
	c.Peer.RegisterHandler(protocol.OpCallAccept, c.handleCallAccept)
	c.Peer.RegisterHandler(protocol.OpCallReject, c.handleCallReject)
	c.Peer.RegisterHandler(protocol.OpCallHangup, c.handleCallHangup)
	c.Peer.RegisterHandler(protocol.OpTyping, c.handleTyping)
	
	// User Content Sync
	c.Peer.RegisterHandler(protocol.OpUserUpdate, c.handleUserUpdate)

	// System
	c.Peer.RegisterHandler(protocol.OpHeartbeat, c.handleHeartbeat)
	
	// Security / Audit
	c.Peer.RegisterHandler(protocol.OpRootBroadcast, c.handleRootBroadcast)
}

// handleRootBroadcast processes a peer's report of the server's root hash.
// It verifies the signature and checks against the local view to detect Split View attacks.
func (c *Client) handleRootBroadcast(remote *net.UDPAddr, data []byte) ([]byte, error) {
	parts := protocol.UnpackStrings(data)
	if len(parts) < 4 {
		return nil, fmt.Errorf("malformed audit payload")
	}
	
	remoteRoot := parts[0]
	sizeStr := parts[1]
	tsStr := parts[2]
	sigStr := parts[3]

	senderID := c.Peer.GetID(remote.String())
	if senderID == "" {
		return nil, nil // Unknown peer
	}
	senderName := c.Peer.GetName(senderID)

	// 1. Verify Signature (Sender authentically saw this)
	friend, ok := c.Profile.GetFriend(senderID)
	if !ok {
		return nil, nil
	}
	
	pub, err := cryptolib.PEMToPubKey([]byte(friend.PEM))
	if err != nil {
		return nil, fmt.Errorf("invalid friend key")
	}

	dataToVerify := []byte(remoteRoot + sizeStr + tsStr)
	if err := cryptolib.Verify(dataToVerify, []byte(sigStr), pub); err != nil {
		c.Events.OnLog("[Audit] Warning: Invalid signature on root broadcast from %s", senderName)
		return nil, nil
	}

	// 2. Check for Split View
	c.rootMu.RLock()
	localRoot := c.latestRoot
	localSize := c.latestTreeSize
	c.rootMu.RUnlock()

	remoteSize, _ := strconv.Atoi(sizeStr)

	// Logic:
	// If both clients see the EXACT SAME tree size, the Root Hash MUST be identical.
	// If they differ, the server has given different Merkle Trees to different users (Split View).
	if localSize > 0 && remoteSize == localSize {
		if localRoot != remoteRoot {
			// CRITICAL SECURITY ALERT
			msg := fmt.Sprintf("SPLIT VIEW DETECTED! Server is lying. You and %s see different data for Tree Size %d.\nLocal: %s\nRemote: %s", 
				senderName, localSize, localRoot[:16], remoteRoot[:16])
			
			c.Events.OnLog("[SECURITY ALARM] %s", msg)
			// Ideally, notify user via UI: c.Events.OnSecurityAlert(...)
		} else {
			// Verification Success
			// c.Events.OnLog("[Audit] Consistent view confirmed with %s (Size %d).", senderName, localSize)
		}
	} else if localSize > 0 && remoteSize > localSize {
		// Peer is ahead of us. We haven't seen this size yet, so we can't verify directly
		// without a consistency proof (OldRoot -> NewRoot). 
		// For now, we assume valid forward progress.
	} else if localSize > 0 && remoteSize < localSize {
		// Peer is behind us.
	}

	return nil, nil // No response needed
}

// handleTyping triggers the UI typing indicator.
func (c *Client) handleTyping(remote *net.UDPAddr, data []byte) ([]byte, error) {
	id := c.Peer.GetID(remote.String())
	if id != "" {
		c.Events.OnTyping(id)
	}
	return nil, nil
}

// startHeartbeatLoop sends periodic keep-alives to the server and active friends.
// This maintains NAT mappings and connection state.
func (c *Client) startHeartbeatLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Ping Server
		if serverAddr := c.Profile.GetServerAddr(); serverAddr != "" {
			go func(addr string) {
				// Use a short timeout to prevent goroutine buildup if server is unresponsive
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				c.Peer.SendFast(ctx, addr, protocol.OpPing, []byte{})
			}(serverAddr)
		}

		// Ping Friends
		friends := c.Profile.ListFriends()
		for _, f := range friends {
			sess, ok := c.Peer.GetSession(f.ID)
			if ok && sess.Addr != "" {
				go func(addr string) {
					// Use a short timeout to prevent goroutine buildup if the network or peer locks up
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					c.Peer.SendFast(ctx, addr, protocol.OpHeartbeat, []byte("HB"))
				}(sess.Addr)
			}
		}
	}
}

// handleDisconnect cleans up session state when a peer explicitly disconnects.
func (c *Client) handleDisconnect(remote *net.UDPAddr, data []byte) ([]byte, error) {
	id := c.Peer.GetID(remote.String())
	c.Peer.RemoveSession(id)
	c.Events.OnLog("%s disconnected.\n", c.Peer.GetName(id))
	c.Events.OnFriendStatus(id, false)
	return nil, nil
}

// handleHeartbeat responds to keep-alive packets.
func (c *Client) handleHeartbeat(remote *net.UDPAddr, data []byte) ([]byte, error) {
	return []byte("ACK"), nil
}