package profile

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	bstd "github.com/banditmoscow1337/benc/std/golang"
	"github.com/banditmoscow1337/safem/protocol/cryptolib"
)

func (messageEntry *MessageEntry) Size() (s int) {
	s += bstd.SizeInt64()
	s += bstd.SizeString(messageEntry.SenderID)
	s += bstd.SizeBytes(messageEntry.Signature)
	s += bstd.SizeString(messageEntry.Content)
	s += bstd.SizeUint64() // Sequence
	s += bstd.SizeString(messageEntry.ParentHash)
	s += bstd.SizeString(messageEntry.Hash)
	return
}

func (messageEntry *MessageEntry) Marshal(tn int, b []byte) (n int) {
	n = tn
	n = bstd.MarshalInt64(n, b, messageEntry.Timestamp)
	n = bstd.MarshalString(n, b, messageEntry.SenderID)
	n = bstd.MarshalBytes(n, b, messageEntry.Signature)
	n = bstd.MarshalString(n, b, messageEntry.Content)
	n = bstd.MarshalUint64(n, b, messageEntry.Sequence)
	n = bstd.MarshalString(n, b, messageEntry.ParentHash)
	n = bstd.MarshalString(n, b, messageEntry.Hash)
	return n
}

func (messageEntry *MessageEntry) Unmarshal(tn int, b []byte) (n int, err error) {
	n = tn
	if n, messageEntry.Timestamp, err = bstd.UnmarshalInt64(n, b); err != nil {
		return
	}
	if n, messageEntry.SenderID, err = bstd.UnmarshalString(n, b); err != nil {
		return
	}
	if n, messageEntry.Signature, err = bstd.UnmarshalBytesCopied(n, b); err != nil {
		return
	}
	if n, messageEntry.Content, err = bstd.UnmarshalString(n, b); err != nil {
		return
	}
	if n, messageEntry.Sequence, err = bstd.UnmarshalUint64(n, b); err != nil {
		// Optional/Default for old records
		messageEntry.Sequence = 0
		// Reset err if it was just EOF/Short
		err = nil 
	}
	if n, messageEntry.ParentHash, err = bstd.UnmarshalString(n, b); err != nil {
		messageEntry.ParentHash = ""
		err = nil
	}
	if n, messageEntry.Hash, err = bstd.UnmarshalString(n, b); err != nil {
		messageEntry.Hash = ""
		err = nil
	}
	return
}

func (userContent *UserContent) Size() (s int) {
	s += bstd.SizeBytes(userContent.Avatar)
	s += bstd.SizeString(userContent.TextStatus)
	s += bstd.SizeInt32()
	s += bstd.SizeBytes(userContent.Data)
	return
}

func (userContent *UserContent) Marshal(tn int, b []byte) (n int) {
	n = tn
	n = bstd.MarshalBytes(n, b, userContent.Avatar)
	n = bstd.MarshalString(n, b, userContent.TextStatus)
	n = bstd.MarshalInt32(n, b, userContent.DataTypeID)
	n = bstd.MarshalBytes(n, b, userContent.Data)
	return n
}

func (userContent *UserContent) Unmarshal(tn int, b []byte) (n int, err error) {
	n = tn
	if n, userContent.Avatar, err = bstd.UnmarshalBytesCopied(n, b); err != nil {
		return
	}
	if n, userContent.TextStatus, err = bstd.UnmarshalString(n, b); err != nil {
		return
	}
	if n, userContent.DataTypeID, err = bstd.UnmarshalInt32(n, b); err != nil {
		return
	}
	if n, userContent.Data, err = bstd.UnmarshalBytesCopied(n, b); err != nil {
		return
	}
	return
}

func (friend *Friend) Size() (s int) {
	s += bstd.SizeString(friend.ID)
	s += bstd.SizeString(friend.Name)
	s += bstd.SizeString(friend.PEM)
	s += bstd.SizeString(friend.EncPEM)
	s += friend.Content.Size()
	s += bstd.SizeBool() // Verified
	return
}

func (friend *Friend) Marshal(tn int, b []byte) (n int) {
	n = tn
	n = bstd.MarshalString(n, b, friend.ID)
	n = bstd.MarshalString(n, b, friend.Name)
	n = bstd.MarshalString(n, b, friend.PEM)
	n = bstd.MarshalString(n, b, friend.EncPEM)
	n = friend.Content.Marshal(n, b)
	n = bstd.MarshalBool(n, b, friend.Verified)
	return n
}

func (friend *Friend) Unmarshal(tn int, b []byte) (n int, err error) {
	n = tn
	if n, friend.ID, err = bstd.UnmarshalString(n, b); err != nil {
		return
	}
	if n, friend.Name, err = bstd.UnmarshalString(n, b); err != nil {
		return
	}
	if n, friend.PEM, err = bstd.UnmarshalString(n, b); err != nil {
		return
	}
	if n, friend.EncPEM, err = bstd.UnmarshalString(n, b); err != nil {
		return
	}
	if n, err = friend.Content.Unmarshal(n, b); err != nil {
		return
	}
	if n, friend.Verified, err = bstd.UnmarshalBool(n, b); err != nil {
		// Default for old profiles
		friend.Verified = false
		err = nil
	}
	return
}

func (group *Group) Size() (s int) {
	s += bstd.SizeString(group.ID)
	s += bstd.SizeString(group.Name)
	s += bstd.SizeSlice(group.Members, func(v string) int { return bstd.SizeString(v) })
	s += bstd.SizeString(group.OwnerID)
	s += bstd.SizeMap(group.VectorClock, func(k string) int { return bstd.SizeString(k) }, func(v uint64) int { return bstd.SizeUint64() })
	s += bstd.SizeString(group.LastMsgHash)
	return
}

func (group *Group) Marshal(tn int, b []byte) (n int) {
	n = tn
	n = bstd.MarshalString(n, b, group.ID)
	n = bstd.MarshalString(n, b, group.Name)
	n = bstd.MarshalSlice(n, b, group.Members, func(n int, b []byte, v string) int { return bstd.MarshalString(n, b, v) })
	n = bstd.MarshalString(n, b, group.OwnerID)
	n = bstd.MarshalMap(n, b, group.VectorClock, func(n int, b []byte, k string) int { return bstd.MarshalString(n, b, k) }, func(n int, b []byte, v uint64) int { return bstd.MarshalUint64(n, b, v) })
	n = bstd.MarshalString(n, b, group.LastMsgHash)
	return n
}

func (group *Group) Unmarshal(tn int, b []byte) (n int, err error) {
	n = tn
	if n, group.ID, err = bstd.UnmarshalString(n, b); err != nil {
		return
	}
	if n, group.Name, err = bstd.UnmarshalString(n, b); err != nil {
		return
	}
	if n, group.Members, err = bstd.UnmarshalSlice[string](n, b, func(n int, b []byte, v *string) (int, error) {
		var err error
		n, (*v), err = bstd.UnmarshalString(n, b)
		return n, err
	}); err != nil {
		return
	}
	if n, group.OwnerID, err = bstd.UnmarshalString(n, b); err != nil {
		return
	}
	if n, group.VectorClock, err = bstd.UnmarshalMap[string, uint64](n, b, func(n int, b []byte, k *string) (int, error) {
		var err error
		n, (*k), err = bstd.UnmarshalString(n, b)
		return n, err
	}, func(n int, b []byte, v *uint64) (int, error) {
		var err error
		n, (*v), err = bstd.UnmarshalUint64(n, b)
		return n, err
	}); err != nil {
		// Tolerate missing VC for old profiles
		group.VectorClock = make(map[string]uint64)
		err = nil
	}
	if n, group.LastMsgHash, err = bstd.UnmarshalString(n, b); err != nil {
		group.LastMsgHash = ""
		err = nil
	}
	return
}

func (profile *Profile) Size() (s int) {
	s += bstd.SizeString(profile.nickname)
	s += bstd.SizeBytes(profile.privateKeyPEM)
	s += bstd.SizeBytes(profile.publicKeyPEM)
	s += bstd.SizeBytes(profile.encPrivateKeyPEM)
	s += bstd.SizeBytes(profile.encPublicKeyPEM)
	s += bstd.SizeMap(profile.friends, func(k string) int { return bstd.SizeString(k) }, func(v Friend) int { return v.Size() })
	s += bstd.SizeMap(profile.groups, func(k string) int { return bstd.SizeString(k) }, func(v Group) int { return v.Size() })
	s += bstd.SizeMap(profile.history, func(k string) int { return bstd.SizeString(k) }, func(v []MessageEntry) int { return bstd.SizeSlice(v, func(v MessageEntry) int { return v.Size() }) })
	s += bstd.SizeMap(profile.pending, func(k string) int { return bstd.SizeString(k) }, func(v []MessageEntry) int { return bstd.SizeSlice(v, func(v MessageEntry) int { return v.Size() }) })
	s += bstd.SizeString(profile.serverAddr)
	s += bstd.SizeString(profile.serverPEM)
	s += bstd.SizeString(profile.serverEncPEM)
	s += profile.userContent.Size()
	return
}

func (profile *Profile) Marshal(tn int, b []byte) (n int) {
	n = tn
	n = bstd.MarshalString(n, b, profile.nickname)
	n = bstd.MarshalBytes(n, b, profile.privateKeyPEM)
	n = bstd.MarshalBytes(n, b, profile.publicKeyPEM)
	n = bstd.MarshalBytes(n, b, profile.encPrivateKeyPEM)
	n = bstd.MarshalBytes(n, b, profile.encPublicKeyPEM)
	n = bstd.MarshalMap(n, b, profile.friends, func(n int, b []byte, k string) int { return bstd.MarshalString(n, b, k) }, func(n int, b []byte, v Friend) int { return v.Marshal(n, b) })
	n = bstd.MarshalMap(n, b, profile.groups, func(n int, b []byte, k string) int { return bstd.MarshalString(n, b, k) }, func(n int, b []byte, v Group) int { return v.Marshal(n, b) })
	n = bstd.MarshalMap(n, b, profile.history, func(n int, b []byte, k string) int { return bstd.MarshalString(n, b, k) }, func(n int, b []byte, v []MessageEntry) int {
		return bstd.MarshalSlice(n, b, v, func(n int, b []byte, v MessageEntry) int { return v.Marshal(n, b) })
	})
	n = bstd.MarshalMap(n, b, profile.pending, func(n int, b []byte, k string) int { return bstd.MarshalString(n, b, k) }, func(n int, b []byte, v []MessageEntry) int {
		return bstd.MarshalSlice(n, b, v, func(n int, b []byte, v MessageEntry) int { return v.Marshal(n, b) })
	})
	n = bstd.MarshalString(n, b, profile.serverAddr)
	n = bstd.MarshalString(n, b, profile.serverPEM)
	n = bstd.MarshalString(n, b, profile.serverEncPEM)
	n = profile.userContent.Marshal(n, b)
	return n
}

func (profile *Profile) Unmarshal(tn int, b []byte) (n int, err error) {
	n = tn
	if n, profile.nickname, err = bstd.UnmarshalString(n, b); err != nil {
		return
	}
	if n, profile.privateKeyPEM, err = bstd.UnmarshalBytesCopied(n, b); err != nil {
		return
	}
	if n, profile.publicKeyPEM, err = bstd.UnmarshalBytesCopied(n, b); err != nil {
		return
	}
	if n, profile.encPrivateKeyPEM, err = bstd.UnmarshalBytesCopied(n, b); err != nil {
		return
	}
	if n, profile.encPublicKeyPEM, err = bstd.UnmarshalBytesCopied(n, b); err != nil {
		return
	}
	if n, profile.friends, err = bstd.UnmarshalMap[string, Friend](n, b, func(n int, b []byte, k *string) (int, error) {
		var err error
		n, (*k), err = bstd.UnmarshalString(n, b)
		return n, err
	}, func(n int, b []byte, v *Friend) (int, error) {
		var err error
		n, err = (*v).Unmarshal(n, b)
		return n, err
	}); err != nil {
		return
	}
	if n, profile.groups, err = bstd.UnmarshalMap[string, Group](n, b, func(n int, b []byte, k *string) (int, error) {
		var err error
		n, (*k), err = bstd.UnmarshalString(n, b)
		return n, err
	}, func(n int, b []byte, v *Group) (int, error) {
		var err error
		n, err = (*v).Unmarshal(n, b)
		return n, err
	}); err != nil {
		return
	}
	if n, profile.history, err = bstd.UnmarshalMap[string, []MessageEntry](n, b, func(n int, b []byte, k *string) (int, error) {
		var err error
		n, (*k), err = bstd.UnmarshalString(n, b)
		return n, err
	}, func(n int, b []byte, v *[]MessageEntry) (int, error) {
		var err error
		n, (*v), err = bstd.UnmarshalSlice[MessageEntry](n, b, func(n int, b []byte, v *MessageEntry) (int, error) {
			var err error
			n, err = (*v).Unmarshal(n, b)
			return n, err
		})
		return n, err
	}); err != nil {
		return
	}
	if n, profile.pending, err = bstd.UnmarshalMap[string, []MessageEntry](n, b, func(n int, b []byte, k *string) (int, error) {
		var err error
		n, (*k), err = bstd.UnmarshalString(n, b)
		return n, err
	}, func(n int, b []byte, v *[]MessageEntry) (int, error) {
		var err error
		n, (*v), err = bstd.UnmarshalSlice[MessageEntry](n, b, func(n int, b []byte, v *MessageEntry) (int, error) {
			var err error
			n, err = (*v).Unmarshal(n, b)
			return n, err
		})
		return n, err
	}); err != nil {
		return
	}
	if n, profile.serverAddr, err = bstd.UnmarshalString(n, b); err != nil {
		return
	}
	if n, profile.serverPEM, err = bstd.UnmarshalString(n, b); err != nil {
		return
	}
	if n, profile.serverEncPEM, err = bstd.UnmarshalString(n, b); err != nil {
		return
	}
	if n, err = profile.userContent.Unmarshal(n, b); err != nil {
		return
	}
	return
}

// Load reads, decrypts, and deserializes a Profile from the given path.
// It verifies the password using the current PBKDF2 iteration count.
func Load(path string, password string) (*Profile, error) {
	p := &Profile{
		filePath: path,
		friends:  make(map[string]Friend),
		groups:   make(map[string]Group),
		history:  make(map[string][]MessageEntry),
		pending:  make(map[string][]MessageEntry),
	}

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return p, nil // Return empty profile for new users
		}
		return nil, err
	}

	if info.Size() > MaxProfileSize {
		return nil, fmt.Errorf("profile file too large: %d bytes (max limit %d bytes)", info.Size(), MaxProfileSize)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if !bytes.HasPrefix(data, []byte(MagicHeader)) {
		return nil, errors.New("invalid profile: file is not encrypted")
	}

	if password == "" {
		return nil, ErrPasswordRequired
	}

	// Explicitly convert to byte slice and wipe it after use to minimize exposure in memory
	pwBytes := []byte(password)
	defer func() {
		for i := range pwBytes {
			pwBytes[i] = 0
		}
	}()

	// Format: [MagicHeader (8)][Salt (16)][Ciphertext...]
	if len(data) < len(MagicHeader)+SaltSize {
		return nil, errors.New("corrupt encrypted file")
	}

	salt := data[len(MagicHeader) : len(MagicHeader)+SaltSize]
	ciphertext := data[len(MagicHeader)+SaltSize:]

	// Attempt decryption with current iteration count
	key := cryptolib.DeriveKeyPBKDF2(pwBytes, salt, IterCurrent)
	plaintext, err := cryptolib.DecryptSymmetric(ciphertext, key, nil)

	if err != nil {
		return nil, ErrInvalidPassword
	}

	data = plaintext
	p.encryptionKey = key
	p.encryptionSalt = salt

	if _, err := p.Unmarshal(0, data); err != nil {
		return nil, err
	}

	// Safety initialization for maps to prevent nil panics
	if p.friends == nil {
		p.friends = make(map[string]Friend)
	}
	if p.groups == nil {
		p.groups = make(map[string]Group)
	}
	if p.history == nil {
		p.history = make(map[string][]MessageEntry)
	}
	if p.pending == nil {
		p.pending = make(map[string][]MessageEntry)
	}

	return p, nil
}

// Save serializes the profile, encrypts it using the cached credentials, and writes it to disk.
// We hold the lock only during serialization (memory copy).
// The heavy Encryption and Disk I/O operations are performed AFTER releasing the lock.
// This prevents the UI from freezing when saving large profiles in the background.
func (p *Profile) Save() error {
	p.mu.Lock()
	buf := make([]byte, p.Size())
	p.Marshal(0, buf)

	// Capture credentials under lock
	var key, salt []byte
	if len(p.encryptionKey) > 0 {
		key = make([]byte, len(p.encryptionKey))
		copy(key, p.encryptionKey)
	}
	if len(p.encryptionSalt) > 0 {
		salt = make([]byte, len(p.encryptionSalt))
		copy(salt, p.encryptionSalt)
	}

	// Allow other goroutines (like the UI thread) to read/write to the profile immediately.
	p.mu.Unlock()

	if len(key) == 0 {
		return ErrPasswordRequired
	}

	encryptedData, err := cryptolib.EncryptSymmetric(buf, key, nil)
	if err != nil {
		return err
	}

	finalBuf := new(bytes.Buffer)
	finalBuf.WriteString(MagicHeader)
	finalBuf.Write(salt)
	finalBuf.Write(encryptedData)

	// Atomic Write: Write to temp file first, then rename to final path.
	// This prevents corruption on crash/power loss.
	dir := filepath.Dir(p.filePath)
	tmpFile, err := os.CreateTemp(dir, "safem_profile_*.tmp")
	if err != nil {
		return err
	}
	
	// Clean up temp file in case of failure before rename
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(finalBuf.Bytes()); err != nil {
		tmpFile.Close()
		return err
	}
	
	// Flush to disk
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}

	if err := tmpFile.Close(); err != nil {
		return err
	}

	// Atomic Move
	return os.Rename(tmpFile.Name(), p.filePath)
}