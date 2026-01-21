package client

import (
	"context"
	"net"
	"time"

	"github.com/banditmoscow1337/safem/protocol"
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