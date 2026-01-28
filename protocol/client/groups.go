package client

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	bstd "github.com/banditmoscow1337/benc/std/golang"
	"github.com/banditmoscow1337/safem/protocol"
	"github.com/banditmoscow1337/safem/protocol/cryptolib"
	"github.com/banditmoscow1337/safem/protocol/profile"
)

// MaxGroupSequenceWindow defines how far ahead a sequence number can be
// before we reject it. This prevents malicious actors from sending MaxUint64
// to break the Vector Clock logic for future messages.
const MaxGroupSequenceWindow = 2000

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

	// Genesis Hash (SHA256 of GroupID) to start the chain
	genesisHash := calculateHashString(groupID)

	group := profile.Group{
		ID:          groupID,
		Name:        name,
		Members:     members,
		OwnerID:     myID,
		VectorClock: make(map[string]uint64),
		LastMsgHash: genesisHash,
	}

	c.Profile.AddGroup(group)
	c.Profile.Save()

	// Announce creation to members immediately
	go c.InviteToGroup(groupID, initialMembers)

	return groupID, nil
}

// InviteToGroup sends invitations for an existing group to a list of users.
// The payload contains the full group state so recipients can sync.
//
// SECURITY: This operation is signed by the Group Owner.
func (c *Client) InviteToGroup(groupID string, userIDs []string) {
	group, ok := c.Profile.GetGroup(groupID)
	if !ok {
		return
	}

	// ENFORCE: Only Owner can add members/send invites (generate valid signature)
	if group.OwnerID != c.Profile.GetID() {
		c.Events.OnLog("[Group] Permission denied: Only the Group Owner can send invites for %s.\n", group.Name)
		return
	}

	// Prepare Data to Sign
	// Canonical Data: GID + Name + LastHash + JoinedMembers
	// Note: We use the full, current member list from the group state as the source of truth.
	membersStr := strings.Join(group.Members, ",")
	dataToSign := group.ID + group.Name + group.LastMsgHash + membersStr

	sig, err := cryptolib.Sign([]byte(dataToSign), c.Peer.PrivKey)
	if err != nil {
		c.Events.OnLog("[Group] Failed to sign invite: %v\n", err)
		return
	}

	// Payload: [GID][GroupName][LastMsgHash][Signature][Member1][Member2]...
	payload := protocol.PackStrings(group.ID, group.Name, group.LastMsgHash, string(sig))
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
//
// SECURITY: This operation is signed by the Group Owner.
func (c *Client) AddUserToGroup(ctx context.Context, groupID, newMemberID string) error {
	// 1. Verify Ownership & Local State
	group, ok := c.Profile.GetGroup(groupID)
	if !ok {
		return fmt.Errorf("group not found")
	}

	if group.OwnerID != c.Profile.GetID() {
		return fmt.Errorf("permission denied: only the group owner can add members")
	}

	// 2. Update Local Profile
	if err := c.Profile.AddGroupMember(groupID, newMemberID); err != nil {
		return err
	}
	c.Profile.Save()

	// Reload group to ensure we have the updated members list
	group, _ = c.Profile.GetGroup(groupID)

	// 3. Generate Signature over new state
	membersStr := strings.Join(group.Members, ",")
	dataToSign := group.ID + group.Name + group.LastMsgHash + membersStr

	sig, err := cryptolib.Sign([]byte(dataToSign), c.Peer.PrivKey)
	if err != nil {
		return fmt.Errorf("signing failed: %v", err)
	}

	// 4. Construct Payload: [GID][GroupName][LastMsgHash][Signature][Members...]
	payload := protocol.PackStrings(group.ID, group.Name, group.LastMsgHash, string(sig))
	for _, m := range group.Members {
		payload = append(payload, protocol.PackStrings(m)...)
	}

	// 5. Announce update to ALL members (Old + New)
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
// It implements Vector Clock logic AND Hash Chaining (Blockchain-style)
// to ensure causal ordering and consistency.
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

	// Calculate Hash Chain
	parentHash := group.LastMsgHash
	if parentHash == "" {
		parentHash = calculateHashString(groupID) // Fallback to genesis
	}

	// Store locally in group history
	entry := profile.MessageEntry{
		Timestamp:  time.Now().Unix(),
		SenderID:   myID,
		Content:    text,
		Sequence:   newSeq,
		ParentHash: parentHash,
	}
	
	entry.Hash = calculateEntryHash(entry)

	// Update Group Head
	c.Profile.SetGroupLastHash(groupID, entry.Hash)
	c.Profile.AddMessage(groupID, entry)
	go c.Profile.Save()

	// Prepare Payload: [GID][Seq][ParentHash][Text]
	payload := protocol.PackStrings(groupID, strconv.FormatUint(newSeq, 10), parentHash, text)

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
//
// SECURITY: This operation is signed by the Group Owner.
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

	// Advance Hash Chain (Kick Block)
	parentHash := group.LastMsgHash
	// Note: We hash the event *without* the signature to create the chain, 
	// but we sign the *data* including the chain link for the packet.
	kickEventHash := calculateHashString(groupID + "KICK" + targetID + parentHash)
	c.Profile.SetGroupLastHash(groupID, kickEventHash)
	c.Profile.Save()

	// Generate Signature for the Packet
	// Data: GID + "KICK" + KickedID + ParentHash
	dataToSign := groupID + "KICK" + targetID + parentHash
	sig, err := cryptolib.Sign([]byte(dataToSign), c.Peer.PrivKey)
	if err != nil {
		return fmt.Errorf("failed to sign kick: %v", err)
	}

	// Announce Kick to ALL members (including the kicked user)
	// Payload: [GID][KickedID][ParentHash][Signature]
	payload := protocol.PackStrings(groupID, targetID, parentHash, string(sig))

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
	
	// Send to the kicked user separately since they are removed from Members list now
	go func(uid string) {
		sess, ok := c.Peer.GetSession(uid)
		if ok && sess.Addr != "" {
			c.Peer.SendFast(context.Background(), sess.Addr, protocol.OpGroupKick, payload)
		}
	}(targetID)

	return nil
}

// Handlers

func (c *Client) handleGroupInvite(remote *net.UDPAddr, data []byte) ([]byte, error) {
	parts := protocol.UnpackStrings(data)
	// Expect at least [GID, Name, LastMsgHash, Signature, Member1...]
	if len(parts) < 4 {
		return nil, fmt.Errorf("malformed group invite")
	}

	gid := parts[0]
	name := parts[1]
	lastHash := parts[2]
	sigStr := parts[3]
	members := parts[4:]

	// 1. Resolve Owner Public Key for Verification
	var ownerKey ed25519.PublicKey
	var ownerID string

	// Check if we already know this group
	if existingGroup, exists := c.Profile.GetGroup(gid); exists {
		ownerID = existingGroup.OwnerID
	} else {
		// New Group: We assume the sender is the Owner/Creator
		ownerID = c.Peer.GetID(remote.String())
	}

	// Try to find the key in Friends list or Active Session
	if f, ok := c.Profile.GetFriend(ownerID); ok {
		ownerKey, _ = cryptolib.PEMToPubKey([]byte(f.PEM))
	} else if pKey, ok := c.Peer.GetIdentity(ownerID); ok {
		ownerKey = pKey
	}

	if ownerKey == nil {
		return nil, fmt.Errorf("security: cannot verify group update, unknown owner %s", ownerID)
	}

	// 2. Verify Signature
	// Data: GID + Name + LastHash + JoinedMembers
	membersStr := strings.Join(members, ",")
	dataToVerify := gid + name + lastHash + membersStr

	if err := cryptolib.Verify([]byte(dataToVerify), []byte(sigStr), ownerKey); err != nil {
		c.Events.OnLog("[Security] Dropped forged group update from %s (Sig Fail)\n", ownerID)
		return nil, nil // Silently drop invalid signature
	}

	// 3. Apply Update
	if _, exists := c.Profile.GetGroup(gid); exists {
		for _, newM := range members {
			c.Profile.AddGroupMember(gid, newM)
		}
		
		// Trust the signed update for hash chain head
		c.Profile.SetGroupLastHash(gid, lastHash)

		c.Profile.Save()
		c.Events.OnLog("[Group] Securely updated members for group '%s'\n", name)
		return protocol.PackStrings("ACK"), nil
	}

	// New Group: Create local entry
	group := profile.Group{
		ID:          gid,
		Name:        name,
		Members:     members,
		OwnerID:     ownerID,
		VectorClock: make(map[string]uint64),
		LastMsgHash: lastHash,
	}

	c.Profile.AddGroup(group)
	c.Profile.Save()

	c.Events.OnLog("[Group] Joined group '%s' (ID: %s) [Verified]\n", name, gid)
	
	// Trigger sync immediately to catch up history
	go c.RequestGroupSync(context.Background(), gid)

	return protocol.PackStrings("ACK"), nil
}

func (c *Client) handleGroupMsg(remote *net.UDPAddr, data []byte) ([]byte, error) {
	parts := protocol.UnpackStrings(data)
	if len(parts) < 4 {
		return nil, fmt.Errorf("malformed group msg")
	}

	gid := parts[0]
	seqStr := parts[1]
	parentHash := parts[2]
	text := parts[3]
	
	seq, _ := strconv.ParseUint(seqStr, 10, 64)
	senderID := c.Peer.GetID(remote.String())

	// Verify group existence
	group, ok := c.Profile.GetGroup(gid)
	if !ok {
		return nil, fmt.Errorf("received msg for unknown group %s", gid)
	}

	// SECURITY CHECK: Verify Sender Membership
	// Ensure the sender is actually in the group before processing the message.
	isMember := false
	for _, member := range group.Members {
		if member == senderID {
			isMember = true
			break
		}
	}

	if !isMember {
		c.Events.OnLog("[Security] Dropped group msg from non-member %s in group %s", senderID, group.Name)
		// We return ACK to stop the attacker from retrying, but we do not process the payload.
		return protocol.PackStrings("ACK"), nil
	}
	
	// SECURITY CHECK: Causal History (Blockchain Rule)
	if group.LastMsgHash != "" && parentHash != group.LastMsgHash {
		c.Events.OnLog("[Security] Dropped forked message from %s (Parent %s != Head %s). Possible kick or stale view.", 
			senderID, parentHash[:8], group.LastMsgHash[:8])
		// Trigger sync to resolve legitimate races
		go c.RequestGroupSync(context.Background(), gid)
		return protocol.PackStrings("ACK"), nil
	}

	// Update Vector Clock
	currentVC := c.Profile.GetGroupVectorClock(gid)
	lastSeq := currentVC[senderID]

	if seq <= lastSeq {
		// Duplicate or old message
		return protocol.PackStrings("ACK"), nil
	}

	// SECURITY CHECK: Verify Sequence Window
	if seq > lastSeq + MaxGroupSequenceWindow {
		c.Events.OnLog("[Security] Dropped group msg from %s: sequence %d exceeds window (Last: %d)", 
			senderID, seq, lastSeq)
		
		go c.RequestGroupSync(context.Background(), gid)
		return protocol.PackStrings("ACK"), nil
	}

	// Update VC
	c.Profile.UpdateGroupVectorClock(gid, senderID, seq)

	// Construct Entry & Calculate Hash
	entry := profile.MessageEntry{
		Timestamp:  time.Now().Unix(),
		SenderID:   senderID,
		Content:    text,
		Sequence:   seq,
		ParentHash: parentHash,
	}
	entry.Hash = calculateEntryHash(entry)

	// Update Group Head
	c.Profile.SetGroupLastHash(gid, entry.Hash)
	c.Profile.AddMessage(gid, entry)
	go c.Profile.Save()

	c.Events.OnMessage(gid, c.Peer.GetName(senderID), text)
	return protocol.PackStrings("ACK"), nil
}

func (c *Client) handleGroupKick(remote *net.UDPAddr, data []byte) ([]byte, error) {
	parts := protocol.UnpackStrings(data)
	if len(parts) < 4 {
		return nil, fmt.Errorf("malformed kick payload")
	}

	gid := parts[0]
	kickedID := parts[1]
	parentHash := parts[2]
	sigStr := parts[3]

	senderID := c.Peer.GetID(remote.String())
	group, ok := c.Profile.GetGroup(gid)
	if !ok {
		return nil, nil // Unknown group
	}

	// Basic check: Sender must match OwnerID (but we rely on Signature)
	if senderID != group.OwnerID {
		c.Events.OnLog("[Security] Ignoring unauthorized kick packet from non-owner %s\n", senderID)
		return nil, nil
	}

	// 1. Resolve Owner Key
	var ownerKey ed25519.PublicKey
	if f, ok := c.Profile.GetFriend(group.OwnerID); ok {
		ownerKey, _ = cryptolib.PEMToPubKey([]byte(f.PEM))
	} else if pKey, ok := c.Peer.GetIdentity(group.OwnerID); ok {
		ownerKey = pKey
	}

	if ownerKey == nil {
		c.Events.OnLog("[Security] Cannot verify kick: unknown owner key for %s", group.OwnerID)
		return nil, nil
	}

	// 2. Verify Signature
	// Data: GID + "KICK" + KickedID + ParentHash
	dataToVerify := gid + "KICK" + kickedID + parentHash
	if err := cryptolib.Verify([]byte(dataToVerify), []byte(sigStr), ownerKey); err != nil {
		c.Events.OnLog("[Security] Kick signature verification failed! Forged packet from %s", senderID)
		return nil, nil
	}
	
	// SECURITY CHECK: Verify Chain Continuity
	if group.LastMsgHash != "" && parentHash != group.LastMsgHash {
		c.Events.OnLog("[Security] Kick rejected: admin is forked or stale.")
		return nil, nil
	}
	
	// Calculate Kick Hash and Advance Chain
	kickEventHash := calculateHashString(gid + "KICK" + kickedID + parentHash)
	c.Profile.SetGroupLastHash(gid, kickEventHash)

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
			
			// Re-verify hash to ensure chain integrity
			msg.Hash = calculateEntryHash(msg)
			c.Profile.SetGroupLastHash(gid, msg.Hash)
			
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

// Helper: Calculate SHA-256 hash of a MessageEntry
func calculateEntryHash(e profile.MessageEntry) string {
	h := sha256.New()
	h.Write([]byte(e.SenderID))
	h.Write([]byte(strconv.FormatInt(e.Timestamp, 10)))
	h.Write(e.Signature) // Non-repudiation
	h.Write([]byte(e.ParentHash))
	h.Write([]byte(e.Content))
	h.Write([]byte(strconv.FormatUint(e.Sequence, 10)))
	return hex.EncodeToString(h.Sum(nil))
}

// Helper: Calculate SHA-256 of a string
func calculateHashString(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}