package client

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	bstd "github.com/banditmoscow1337/benc/std/golang"
	"github.com/banditmoscow1337/safem/protocol"
	"github.com/banditmoscow1337/safem/protocol/cryptolib"
	"github.com/banditmoscow1337/safem/protocol/profile"
)

// CreateGroup creates a new group locally and invites the initial members.
// It returns the newly generated Group ID.
func (c *Client) CreateGroup(name string, initialMembers []string) (string, error) {
	// Generate random Group ID (16 bytes hex)
	rawID, _ := cryptolib.GenerateRandomBytes(16)
	groupID := fmt.Sprintf("G-%x", rawID)

	myID := c.Profile.GetID()

	// Ensure owner is included in the members list
	members := append([]string{myID}, initialMembers...)
	members = uniqueStrings(members)

	group := profile.Group{
		ID:          groupID,
		Name:        name,
		Members:     members,
		OwnerID:     myID,
		VectorClock: make(map[string]uint64),
	}

	c.Profile.AddGroup(group)
	c.Profile.Save()

	// Announce creation to members immediately
	go c.InviteToGroup(groupID, initialMembers)

	return groupID, nil
}

// InviteToGroup sends invitations for an existing group to a list of users.
// The payload contains the full group state so recipients can sync.
func (c *Client) InviteToGroup(groupID string, userIDs []string) {
	group, ok := c.Profile.GetGroup(groupID)
	if !ok {
		return
	}

	// Payload: [GID][GroupName][Member1][Member2]...
	payload := protocol.PackStrings(group.ID, group.Name)
	for _, m := range group.Members {
		payload = append(payload, protocol.PackStrings(m)...)
	}

	for _, uid := range userIDs {
		if uid == c.Profile.GetID() {
			continue
		}

		go func(targetID string) {
			sess, ok := c.Peer.GetSession(targetID)
			if ok && sess.Addr != "" {
				c.Peer.SendFast(context.Background(), sess.Addr, protocol.OpGroupInvite, payload)
			}
		}(uid)
	}
}

// AddUserToGroup adds a new member to the group and announces the updated member list
// to ALL current members to ensure state consistency.
func (c *Client) AddUserToGroup(ctx context.Context, groupID, newMemberID string) error {
	// Update Local Profile
	if err := c.Profile.AddGroupMember(groupID, newMemberID); err != nil {
		return err
	}
	c.Profile.Save()

	// Get updated group info
	group, ok := c.Profile.GetGroup(groupID)
	if !ok {
		return fmt.Errorf("group sync error")
	}

	// Announce update to ALL members (Old + New)
	payload := protocol.PackStrings(group.ID, group.Name)
	for _, m := range group.Members {
		payload = append(payload, protocol.PackStrings(m)...)
	}

	for _, memberID := range group.Members {
		if memberID == c.Profile.GetID() {
			continue
		}

		go func(targetID string) {
			sess, ok := c.Peer.GetSession(targetID)
			if ok && sess.Addr != "" {
				c.Peer.SendFast(context.Background(), sess.Addr, protocol.OpGroupInvite, payload)
			}
		}(memberID)
	}

	return nil
}

// SendGroupText fans out a text message to all members of the group individually.
// It implements Vector Clock logic to ensure causal ordering and consistency.
func (c *Client) SendGroupText(ctx context.Context, groupID, text string) error {
	group, ok := c.Profile.GetGroup(groupID)
	if !ok {
		return fmt.Errorf("group not found")
	}

	myID := c.Profile.GetID()

	// Increment Local Vector Clock
	currentSeq := group.VectorClock[myID]
	newSeq := currentSeq + 1
	c.Profile.UpdateGroupVectorClock(groupID, myID, newSeq)

	// Store locally in group history
	entry := profile.MessageEntry{
		Timestamp: time.Now().Unix(),
		SenderID:  myID,
		Content:   text,
		Sequence:  newSeq,
	}
	c.Profile.AddMessage(groupID, entry)
	go c.Profile.Save()

	// Prepare Payload: [GID][Seq][Text]
	// We convert Seq to string for PackStrings convenience, but could use binary.
	payload := protocol.PackStrings(groupID, strconv.FormatUint(newSeq, 10), text)

	// Fan-out to online members
	for _, memberID := range group.Members {
		if memberID == c.Profile.GetID() {
			continue
		}

		sess, ok := c.Peer.GetSession(memberID)
		if !ok || sess.Addr == "" {
			continue // Member offline, relying on Sync (RequestGroupSync) when they return
		}

		c.Peer.SendFast(ctx, sess.Addr, protocol.OpGroupMsg, payload)
	}

	return nil
}

// RequestGroupSync broadcasts the local Vector Clock to group members.
// Any member with newer messages will reply with an OpGroupSyncRes.
func (c *Client) RequestGroupSync(ctx context.Context, groupID string) error {
	// Get Local Vector Clock
	vc := c.Profile.GetGroupVectorClock(groupID)
	
	// Serialize VC: Using Benc manual map serialization for payload
	// Payload: [GID][BencMapBytes]
	
	// Helper to size map
	size := bstd.SizeMap(vc, func(k string) int { return bstd.SizeString(k) }, func(v uint64) int { return bstd.SizeUint64() })
	vcBytes := make([]byte, size)
	bstd.MarshalMap(0, vcBytes, vc, func(n int, b []byte, k string) int { return bstd.MarshalString(n, b, k) }, func(n int, b []byte, v uint64) int { return bstd.MarshalUint64(n, b, v) })

	// Prepend GID
	gidBytes := protocol.PackStrings(groupID)
	payload := append(gidBytes, vcBytes...)

	// Send to a subset of online members (e.g., 3 random peers to avoid flooding)
	// For now, we send to ALL online members to ensure maximum convergence.
	group, ok := c.Profile.GetGroup(groupID)
	if !ok {
		return fmt.Errorf("group not found")
	}

	sentCount := 0
	for _, memberID := range group.Members {
		if memberID == c.Profile.GetID() {
			continue
		}
		sess, ok := c.Peer.GetSession(memberID)
		if ok && sess.Addr != "" {
			c.Peer.SendFast(ctx, sess.Addr, protocol.OpGroupSyncReq, payload)
			sentCount++
		}
	}
	
	if sentCount > 0 {
		c.Events.OnLog("[Sync] Requested update for group %s from %d peers.\n", group.Name, sentCount)
	}

	return nil
}

// KickUserFromGroup removes a user. Only the Group Owner can perform this action.
func (c *Client) KickUserFromGroup(ctx context.Context, groupID, targetID string) error {
	// Verify Ownership
	group, ok := c.Profile.GetGroup(groupID)
	if !ok {
		return fmt.Errorf("group not found")
	}

	if group.OwnerID != c.Profile.GetID() {
		return fmt.Errorf("permission denied: only the group owner can remove members")
	}

	if targetID == group.OwnerID {
		return fmt.Errorf("cannot kick yourself")
	}

	// Update Local State
	if err := c.Profile.RemoveGroupMember(groupID, targetID); err != nil {
		return err
	}
	c.Profile.Save()

	// Announce Kick to ALL members (including the kicked user)
	// Payload: [GID][KickedID]
	payload := protocol.PackStrings(groupID, targetID)

	// Send to the OLD list so the kicked user receives the notification too
	for _, memberID := range group.Members {
		if memberID == c.Profile.GetID() {
			continue
		}

		go func(uid string) {
			sess, ok := c.Peer.GetSession(uid)
			if ok && sess.Addr != "" {
				c.Peer.SendFast(context.Background(), sess.Addr, protocol.OpGroupKick, payload)
			}
		}(memberID)
	}

	return nil
}

// Handlers

func (c *Client) handleGroupInvite(remote *net.UDPAddr, data []byte) ([]byte, error) {
	parts := protocol.UnpackStrings(data)
	if len(parts) < 3 {
		return nil, fmt.Errorf("malformed group invite")
	}

	gid := parts[0]
	name := parts[1]
	members := parts[2:]

	// Update existing group if found
	if _, exists := c.Profile.GetGroup(gid); exists {
		for _, newM := range members {
			c.Profile.AddGroupMember(gid, newM)
		}
		c.Profile.Save()
		c.Events.OnLog("[Group] Updated members for group '%s'\n", name)
		return protocol.PackStrings("ACK"), nil
	}

	// New Group: Create local entry
	senderID := c.Peer.GetID(remote.String())

	group := profile.Group{
		ID:          gid,
		Name:        name,
		Members:     members,
		OwnerID:     senderID, // Assume inviter is owner/admin for now
		VectorClock: make(map[string]uint64),
	}

	c.Profile.AddGroup(group)
	c.Profile.Save()

	c.Events.OnLog("[Group] Joined group '%s' (ID: %s)\n", name, gid)
	
	// Trigger sync immediately to catch up history
	go c.RequestGroupSync(context.Background(), gid)

	return protocol.PackStrings("ACK"), nil
}

func (c *Client) handleGroupMsg(remote *net.UDPAddr, data []byte) ([]byte, error) {
	parts := protocol.UnpackStrings(data)
	if len(parts) < 3 {
		return nil, fmt.Errorf("malformed group msg")
	}

	gid := parts[0]
	seqStr := parts[1]
	text := parts[2]
	
	seq, _ := strconv.ParseUint(seqStr, 10, 64)
	senderID := c.Peer.GetID(remote.String())

	// Verify group existence
	if _, ok := c.Profile.GetGroup(gid); !ok {
		return nil, fmt.Errorf("received msg for unknown group %s", gid)
	}

	// Update Vector Clock
	// If this returns false, we likely already have this message or a newer one from this user
	// However, in chat, we usually allow re-delivery, but filter duplicates via Sequence.
	
	// Check if already seen
	currentVC := c.Profile.GetGroupVectorClock(gid)
	if seq <= currentVC[senderID] {
		// Duplicate or old message
		return protocol.PackStrings("ACK"), nil
	}

	// Update VC
	c.Profile.UpdateGroupVectorClock(gid, senderID, seq)

	// Store message
	entry := profile.MessageEntry{
		Timestamp: time.Now().Unix(),
		SenderID:  senderID,
		Content:   text,
		Sequence:  seq,
	}
	c.Profile.AddMessage(gid, entry)
	go c.Profile.Save()

	c.Events.OnMessage(gid, c.Peer.GetName(senderID), text)
	return protocol.PackStrings("ACK"), nil
}

func (c *Client) handleGroupKick(remote *net.UDPAddr, data []byte) ([]byte, error) {
	parts := protocol.UnpackStrings(data)
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed kick payload")
	}

	gid := parts[0]
	kickedID := parts[1]

	senderID := c.Peer.GetID(remote.String())
	group, ok := c.Profile.GetGroup(gid)
	if !ok {
		return nil, nil // Unknown group
	}

	// Sender must be Owner
	if senderID != group.OwnerID {
		c.Events.OnLog("[Security] Ignoring unauthorized kick command for group %s from %s\n", group.Name, senderID)
		return nil, nil
	}

	// I am the one kicked
	if kickedID == c.Profile.GetID() {
		c.Profile.RemoveGroup(gid)
		c.Profile.Save()
		c.Events.OnLog("[Group] You have been removed from group '%s' by the admin.\n", group.Name)
		return protocol.PackStrings("ACK"), nil
	}

	// Someone else was kicked
	if err := c.Profile.RemoveGroupMember(gid, kickedID); err == nil {
		c.Profile.Save()
		kickedName := c.Peer.GetName(kickedID)
		c.Events.OnLog("[Group] %s was removed from '%s'.\n", kickedName, group.Name)
	}

	return protocol.PackStrings("ACK"), nil
}

// handleGroupSyncReq processes a peer's request for missing messages.
func (c *Client) handleGroupSyncReq(remote *net.UDPAddr, data []byte) ([]byte, error) {
	// Parse GID strings part
	parts := protocol.UnpackStrings(data)
	if len(parts) < 1 {
		return nil, fmt.Errorf("malformed sync req")
	}
	gid := parts[0]
	
	// The rest of the data is the Benc Map. We need to find where the string part ended.
	// PackStrings uses Benc internally. PackStrings(gid) -> [Size][Str].
	// We can cheat: unmarshal the string again to find 'n', then slice 'data'.
	n, _, err := bstd.UnmarshalSlice[string](0, data, bstd.UnmarshalString)
	if err != nil {
		return nil, err
	}
	
	mapData := data[n:]
	
	// Unmarshal Remote Vector Clock
	var peerVC map[string]uint64
	_, peerVC, err = bstd.UnmarshalMap[string, uint64](0, mapData, 
		func(n int, b []byte, k *string) (int, string, error) {
			return bstd.UnmarshalString(n, b)
		},
		func(n int, b []byte, v *uint64) (int, uint64, error) {
			return bstd.UnmarshalUint64(n, b)
		})
	
	if err != nil {
		return nil, fmt.Errorf("bad VC format")
	}

	// Calculate Missing Messages
	missing := c.Profile.GetMessagesAfter(gid, peerVC)
	if len(missing) == 0 {
		return protocol.PackStrings("ACK"), nil
	}

	// Send Response (Batched Messages)
	// Payload: [GID][MsgListBenc]
	gidBytes := protocol.PackStrings(gid)
	
	// Benc the list
	// We use bstd.SizeSlice logic to alloc then Marshal
	sizer := func(v profile.MessageEntry) int { return v.Size() }
	msgListSize := bstd.SizeSlice(missing, sizer)
	
	msgBytes := make([]byte, msgListSize)
	bstd.MarshalSlice(0, msgBytes, missing, func(n int, b []byte, v profile.MessageEntry) int {
		return v.Marshal(n, b)
	})

	payload := append(gidBytes, msgBytes...)
	
	// Send Large in case history is big
	c.Peer.SendLarge(context.Background(), remote.String(), protocol.OpGroupSyncRes, payload)

	return protocol.PackStrings("ACK"), nil
}

// handleGroupSyncRes processes incoming batched messages.
func (c *Client) handleGroupSyncRes(remote *net.UDPAddr, data []byte) ([]byte, error) {
	// Parse GID
	n, gidStrs, err := bstd.UnmarshalSlice[string](0, data, bstd.UnmarshalString)
	if err != nil || len(gidStrs) == 0 {
		return nil, fmt.Errorf("malformed sync res")
	}
	gid := gidStrs[0]
	
	msgData := data[n:]
	
	// Unmarshal Message List
	var msgs []profile.MessageEntry
	_, msgs, err = bstd.UnmarshalSlice[profile.MessageEntry](0, msgData, func(n int, b []byte, v *profile.MessageEntry) (int, error) {
		return v.Unmarshal(n, b)
	})
	
	if err != nil {
		return nil, err
	}

	count := 0
	for _, msg := range msgs {
		currentVC := c.Profile.GetGroupVectorClock(gid)
		
		// Only process if newer
		if msg.Sequence > currentVC[msg.SenderID] {
			c.Profile.UpdateGroupVectorClock(gid, msg.SenderID, msg.Sequence)
			c.Profile.AddMessage(gid, msg)
			c.Events.OnMessage(gid, c.Peer.GetName(msg.SenderID), msg.Content)
			count++
		}
	}
	
	if count > 0 {
		c.Profile.Save()
		c.Events.OnLog("[Sync] Synced %d messages for group %s\n", count, gid)
	}

	return protocol.PackStrings("ACK"), nil
}

func uniqueStrings(input []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range input {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}