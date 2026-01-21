package client

import (
	"context"
	"net"

	"github.com/banditmoscow1337/safem/protocol"
	"github.com/banditmoscow1337/safem/protocol/profile"
)

// broadcastMyContent sends the current user's profile content to all online friends.
// It uses OpUserUpdate and SendLarge (via chunking if necessary).
func (c *Client) broadcastMyContent() {
	friends := c.Profile.ListFriends()
	
	for _, f := range friends {
		// Fire-and-forget sync in background
		go c.sendMyContent(context.Background(), f.ID)
	}
}

// sendMyContent marshals the local UserContent and sends it to a specific friend.
func (c *Client) sendMyContent(ctx context.Context, targetID string) {
	sess, ok := c.Peer.GetSession(targetID)
	if !ok || sess.Addr == "" {
		return // Peer offline
	}

	content := c.Profile.GetUserContent()
	
	buf := make([]byte, content.Size())
	content.Marshal(0, buf)

	// Send via Reliable Chunking (OpUserUpdate)
	// We use SendLarge because Avatars can be > MTU
	err := c.Peer.SendLarge(ctx, sess.Addr, protocol.OpUserUpdate, buf)
	if err != nil {
		c.Events.OnLog("[Sync] Failed to push profile to %s: %v\n", c.Peer.GetName(targetID), err)
	}
}

// handleUserUpdate processes an incoming profile update from a friend.
func (c *Client) handleUserUpdate(remote *net.UDPAddr, data []byte) ([]byte, error) {
	senderID := c.Peer.GetID(remote.String())
	if senderID == "" {
		return nil, nil
	}

	var content profile.UserContent
	if _, err := content.Unmarshal(0, data); err != nil {
		return nil, err
	}

	if updated := c.Profile.UpdateFriendContent(senderID, content); updated {
		if err := c.Profile.Save(); err != nil {
			c.Events.OnLog("[Sync] Failed to save friend update: %v\n", err)
		}
		
		c.Events.OnFriendUpdated(senderID, content)
	}

	return []byte("ACK"), nil
}