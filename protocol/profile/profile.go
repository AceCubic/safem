// Package profile manages the local user state, including identity keys,
// friend lists, group memberships, and message history.
//
// It handles persistence to disk using encryption-at-rest (AES-256 via PBKDF2).
// All public methods on the Profile struct are thread-safe.
package profile

import (
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/banditmoscow1337/safem/protocol/cryptolib"
)

const (
	// DefaultPath is the default filename for the profile.
	DefaultPath = "profile.safem"
	// MagicHeader is the 8-byte file signature used to verify file format.
	MagicHeader = "SAFEMSEC"
	// SaltSize is the size of the random salt used for PBKDF2.
	SaltSize = 16

	// IterCurrent is the PBKDF2 iteration count for new or updated profiles.
	IterCurrent = 600000

	// MaxProfileSize limits the file size read into memory to prevent DOS.
	MaxProfileSize = 50 * 1024 * 1024
)

var (
	// ErrPasswordRequired is returned when loading an encrypted profile without a password.
	ErrPasswordRequired = errors.New("encrypted profile: password required")
	// ErrInvalidPassword is returned when the provided password fails to decrypt the profile.
	ErrInvalidPassword = errors.New("invalid password")
)

// MessageEntry represents a single stored chat message.
type MessageEntry struct {
	Timestamp int64
	SenderID  string
	Signature []byte // Ed25519 signature for non-repudiation
	Content   string
	Sequence  uint64 // Group Sequence ID for Vector Clocks (0 for DMs)
	
	// Causal History (Blockchain-style)
	ParentHash string // Hash of the previous message in the chain
	Hash       string // SHA-256 Hash of this entry
}

// UserContent holds the rich media profile data for a user.
type UserContent struct {
	Avatar     []byte
	TextStatus string
	
	DataTypeID int32  // id for custom client types
	Data       []byte // custom client data
}

// Friend represents a trusted peer and their public keys.
type Friend struct {
	ID      string // Fingerprint of the Signing Key
	Name    string
	PEM     string // Signing Key (Ed25519)
	EncPEM  string // Encryption Key (X25519)
	Content UserContent
	
	// Verified indicates the user has manually verified the safety number.
	Verified bool
}

// Group represents a P2P group chat configuration.
type Group struct {
	ID      string
	Name    string
	Members []string // List of Member Peer IDs
	OwnerID string   // The creator (for admin logic)
	
	// VectorClock tracks the highest sequence number seen from each member.
	// Map: MemberID -> HighestSequence
	VectorClock map[string]uint64

	// LastMsgHash points to the head of the hash chain for this group.
	// This enforces strict causal ordering and prevents branching.
	LastMsgHash string
}

// Profile stores the user's data and ensures thread-safe access.
// It supports encryption at rest.
type Profile struct {
	// Fields are private to enforce thread-safety via mutex.
	// Users must use Getters/Setters.
	nickname                    string
	privateKeyPEM, publicKeyPEM []byte

	// Encryption Identity (X25519)
	encPrivateKeyPEM, encPublicKeyPEM []byte
	
	// Local User Content (Avatar, Status, etc)
	userContent UserContent

	friends map[string]Friend
	groups  map[string]Group
	history map[string][]MessageEntry

	// Pending messages for offline users (Store-and-Forward queue).
	pending map[string][]MessageEntry

	// Saved Server Connection Details
	serverAddr   string
	serverPEM    string // Signing Key
	serverEncPEM string // Encryption Key

	filePath string       //benc:ignore
	mu       sync.RWMutex //benc:ignore

	// encryptionKey is derived from the password and salt.
	// If nil, the profile is considered unlocked/in-memory only.
	encryptionKey  []byte //benc:ignore
	encryptionSalt []byte //benc:ignore
}

// SetPassword updates the encryption key for the profile using a new password.
// It generates a new random salt. Passing an empty password disables saving.
func (p *Profile) SetPassword(pw string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if pw == "" {
		p.encryptionKey = nil
		p.encryptionSalt = nil
		return
	}

	salt, _ := cryptolib.GenerateRandomBytes(SaltSize)

	// Explicitly convert to byte slice and wipe it after use to minimize exposure in memory
	pwBytes := []byte(pw)
	defer func() {
		for i := range pwBytes {
			pwBytes[i] = 0
		}
	}()

	key := cryptolib.DeriveKeyPBKDF2(pwBytes, salt, IterCurrent)

	p.encryptionKey = key
	p.encryptionSalt = salt
}

// Thread-Safe Accessors

// SetNickname stores the user's display name in the profile.
func (p *Profile) SetNickname(n string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nickname = n
}

// GetNickname retrieves the user's display name.
func (p *Profile) GetNickname() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.nickname
}

// SetUserContent updates the local user content (Avatar, Status, etc).
func (p *Profile) SetUserContent(c UserContent) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.userContent = c
}

// GetUserContent returns the local user content.
func (p *Profile) GetUserContent() UserContent {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.userContent
}

// SetIdentity updates the local cryptographic keys.
func (p *Profile) SetIdentity(priv, pub, encPriv, encPub []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.privateKeyPEM = priv
	p.publicKeyPEM = pub
	p.encPrivateKeyPEM = encPriv
	p.encPublicKeyPEM = encPub
}

// GetIdentity retrieves the raw PEM-encoded key pairs for signing and encryption.
func (p *Profile) GetIdentity() (priv, pub, encPriv, encPub []byte) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.privateKeyPEM, p.publicKeyPEM, p.encPrivateKeyPEM, p.encPublicKeyPEM
}

// HasIdentity checks if the profile contains both signing and encryption keys.
func (p *Profile) HasIdentity() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.privateKeyPEM != nil && p.encPrivateKeyPEM != nil
}

// GetPrivateKeyPEM retrieves the Ed25519 signing private key in PEM format.
func (p *Profile) GetPrivateKeyPEM() []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.privateKeyPEM
}

// GetPublicKeyPEM retrieves the Ed25519 signing public key in PEM format.
func (p *Profile) GetPublicKeyPEM() []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.publicKeyPEM
}

// GetEncPrivateKeyPEM retrieves the X25519 encryption private key in PEM format.
func (p *Profile) GetEncPrivateKeyPEM() []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.encPrivateKeyPEM
}

// GetEncPublicKeyPEM retrieves the X25519 encryption public key in PEM format.
func (p *Profile) GetEncPublicKeyPEM() []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.encPublicKeyPEM
}

// SetServer configures the rendezvous server connection details.
func (p *Profile) SetServer(addr, signPEM, encPEM string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.serverAddr = addr
	p.serverPEM = signPEM
	p.serverEncPEM = encPEM
}

// GetServer returns the configured rendezvous server address and its public keys.
func (p *Profile) GetServer() (addr, signPEM, encPEM string) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.serverAddr, p.serverPEM, p.serverEncPEM
}

// GetServerAddr returns only the network address of the rendezvous server.
func (p *Profile) GetServerAddr() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.serverAddr
}

// AddFriend adds or updates a friend's details in the local contact list.
// It preserves existing user content (avatar/status) and verification state if the friend already exists.
func (p *Profile) AddFriend(id, name, signPEM, encPEM string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// preserve existing content if present
	content := UserContent{}
	verified := false
	if existing, ok := p.friends[id]; ok {
		content = existing.Content
		verified = existing.Verified
	}
	p.friends[id] = Friend{ID: id, Name: name, PEM: signPEM, EncPEM: encPEM, Content: content, Verified: verified}
}

// SetFriendVerified updates the verified status of a friend.
// Returns true if the friend was found and updated.
func (p *Profile) SetFriendVerified(id string, verified bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if f, ok := p.friends[id]; ok {
		f.Verified = verified
		p.friends[id] = f
		return true
	}
	return false
}

// UpdateFriendContent updates just the UserContent for an existing friend.
// Returns true if the friend was found and updated.
func (p *Profile) UpdateFriendContent(id string, c UserContent) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if f, ok := p.friends[id]; ok {
		f.Content = c
		p.friends[id] = f
		return true
	}
	return false
}

// GetFriend retrieves a friend's details by their ID (fingerprint).
// Returns the Friend struct and a boolean indicating if found.
func (p *Profile) GetFriend(id string) (Friend, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	f, ok := p.friends[id]
	return f, ok
}

// RemoveFriend deletes a friend from the local contact list.
func (p *Profile) RemoveFriend(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.friends, id)
}

// ListFriends returns a slice of all friends in the contact list.
func (p *Profile) ListFriends() []Friend {
	p.mu.RLock()
	defer p.mu.RUnlock()
	list := make([]Friend, 0, len(p.friends))
	for _, f := range p.friends {
		list = append(list, f)
	}
	return list
}

// Group Accessors

// AddGroup saves a group configuration to the profile.
// If the group exists, it is overwritten.
func (p *Profile) AddGroup(g Group) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Initialize VC if nil
	if g.VectorClock == nil {
		g.VectorClock = make(map[string]uint64)
	}
	p.groups[g.ID] = g
}

// GetGroup retrieves a group configuration by its ID.
func (p *Profile) GetGroup(id string) (Group, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	g, ok := p.groups[id]
	return g, ok
}

// ListGroups returns a slice of all groups the user is a member of.
func (p *Profile) ListGroups() []Group {
	p.mu.RLock()
	defer p.mu.RUnlock()
	list := make([]Group, 0, len(p.groups))
	for _, g := range p.groups {
		list = append(list, g)
	}
	return list
}

// GetGroupVectorClock returns a copy of the group's current vector clock.
func (p *Profile) GetGroupVectorClock(groupID string) map[string]uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if g, ok := p.groups[groupID]; ok && g.VectorClock != nil {
		vc := make(map[string]uint64)
		for k, v := range g.VectorClock {
			vc[k] = v
		}
		return vc
	}
	return make(map[string]uint64)
}

// UpdateGroupVectorClock updates the highest seen sequence number for a user in a group.
// It returns true if the sequence was newer than what we had.
func (p *Profile) UpdateGroupVectorClock(groupID, userID string, seq uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	g, ok := p.groups[groupID]
	if !ok {
		return false
	}
	if g.VectorClock == nil {
		g.VectorClock = make(map[string]uint64)
	}

	current := g.VectorClock[userID]
	if seq > current {
		g.VectorClock[userID] = seq
		p.groups[groupID] = g
		return true
	}
	return false
}

// SetGroupLastHash updates the hash chain head for the group.
// This is critical for the Sender Key / Blockchain causal history mechanism.
func (p *Profile) SetGroupLastHash(groupID, hash string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	g, ok := p.groups[groupID]
	if !ok {
		return fmt.Errorf("group not found")
	}

	g.LastMsgHash = hash
	p.groups[groupID] = g
	return nil
}

// GetMessagesAfter returns messages in a group that are newer than the provided vector clock.
func (p *Profile) GetMessagesAfter(groupID string, peerVC map[string]uint64) []MessageEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()

	msgs, ok := p.history[groupID]
	if !ok {
		return nil
	}

	var missing []MessageEntry
	for _, msg := range msgs {
		lastSeen := peerVC[msg.SenderID]
		if msg.Sequence > lastSeen {
			missing = append(missing, msg)
		}
	}
	return missing
}

// AddGroupMember safely adds a member to an existing group, preventing duplicates.
func (p *Profile) AddGroupMember(groupID, memberID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	g, ok := p.groups[groupID]
	if !ok {
		return fmt.Errorf("group not found")
	}

	// Check for duplicates
	if slices.Contains(g.Members, memberID) {
		return nil
	}

	g.Members = append(g.Members, memberID)
	p.groups[groupID] = g
	return nil
}

// AddMessage appends a message to the history of a peer or group.
func (p *Profile) AddMessage(peerID string, entry MessageEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.history == nil {
		p.history = make(map[string][]MessageEntry)
	}
	p.history[peerID] = append(p.history[peerID], entry)
}

// GetHistorySnapshot returns a deep copy of the message history.
// This allows the caller to iterate over messages without holding the profile lock.
func (p *Profile) GetHistorySnapshot() map[string][]MessageEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()

	snap := make(map[string][]MessageEntry)
	for id, msgs := range p.history {
		newMsgs := make([]MessageEntry, len(msgs))
		copy(newMsgs, msgs)
		snap[id] = newMsgs
	}
	return snap
}

// Pending Message Accessors

// AddPending queues a message for delivery to an offline peer.
func (p *Profile) AddPending(id string, msg MessageEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending == nil {
		p.pending = make(map[string][]MessageEntry)
	}
	p.pending[id] = append(p.pending[id], msg)
}

// GetPending retrieves the queue of undelivered messages for a specific peer.
// It returns a copy of the slice to ensure thread safety.
func (p *Profile) GetPending(id string) []MessageEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if msgs, ok := p.pending[id]; ok {
		// Return copy to allow safe iteration/modification of the result
		res := make([]MessageEntry, len(msgs))
		copy(res, msgs)
		return res
	}
	return nil
}

// SetPending updates or clears the message queue for a specific peer.
// Passing an empty slice or nil removes the entry.
func (p *Profile) SetPending(id string, msgs []MessageEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(msgs) == 0 {
		delete(p.pending, id)
	} else {
		p.pending[id] = msgs
	}
}

// GetID returns the fingerprint of the local signing key (the User ID).
func (p *Profile) GetID() string {
	pub := p.GetPublicKeyPEM()
	if pub == nil {
		return ""
	}
	key, err := cryptolib.PEMToPubKey(pub)
	if err != nil {
		return ""
	}
	return cryptolib.Fingerprint(key)
}

// IsComplete checks if the profile has minimal necessary data (Nickname + Identity).
func (p *Profile) IsComplete() bool {
	return p.GetNickname() != "" && p.HasIdentity()
}

// RemoveGroupMember removes a user from the group member list.
func (p *Profile) RemoveGroupMember(groupID, memberID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	g, ok := p.groups[groupID]
	if !ok {
		return fmt.Errorf("group not found")
	}

	newMembers := make([]string, 0, len(g.Members))
	found := false
	for _, m := range g.Members {
		if m != memberID {
			newMembers = append(newMembers, m)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("member not in group")
	}

	g.Members = newMembers
	p.groups[groupID] = g
	return nil
}

// RemoveGroup deletes a group entirely from the local profile.
func (p *Profile) RemoveGroup(groupID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.groups, groupID)
}