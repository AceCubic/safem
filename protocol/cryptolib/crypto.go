// Package cryptolib provides the cryptographic primitives for the SAFEM protocol.
//
// It implements a hybrid encryption scheme using:
//   - Ed25519 for Identity and Digital Signatures (Authentication).
//   - X25519 (ECDH) for Key Exchange and Forward Secrecy.
//   - AES-256-GCM for Symmetric Encryption (Data Confidentiality).
//   - SHA-256 / HMAC-SHA-256 for Hashing and Key Derivation.
//   - PBKDF2 for password-based key derivation (Profile encryption).
//
// Security Note: This package relies on crypto/rand for entropy. Failure to read
// from the system CSPRNG will result in a panic to prevent insecure operations.
package cryptolib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sort"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// AESKeySize is the size in bytes for AES-256 keys.
	AESKeySize = 32
	// NonceSize is the size in bytes for AES-GCM standard nonces.
	NonceSize = 12
)

// ReadRandomBytes fills the provided buffer with cryptographically secure random bytes
// from the system's CSPRNG. It returns an error if the random source is unreadable.
func ReadRandomBytes(buf []byte) error {
	_, err := io.ReadFull(rand.Reader, buf)
	return err
}

// Signing Keys (Ed25519)

// GenerateKeyPair creates a new Ed25519 signing key pair using the system's CSPRNG.
// The bits argument is currently ignored as Ed25519 keys have a fixed size.
func GenerateKeyPair(bits int) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// PubKeyToPEM encodes an Ed25519 public key into a standard PEM block.
func PubKeyToPEM(pub ed25519.PublicKey) []byte {
	pubASN1, _ := x509.MarshalPKIXPublicKey(pub)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubASN1})
}

// PEMToPubKey parses a PEM block containing an Ed25519 public key.
func PEMToPubKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 public key")
	}
	return edPub, nil
}

// ParsePrivateKey parses a PEM block containing an Ed25519 private key (PKCS#8).
func ParsePrivateKey(pemStr string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	edPriv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not an Ed25519 private key")
	}
	return edPriv, nil
}

// Fingerprint calculates the SHA-256 hash of the public key and returns it as a hex string.
// This is used as the canonical Peer ID in the SAFEM protocol.
func Fingerprint(pub ed25519.PublicKey) string {
	hash := sha256.Sum256(pub)
	return hex.EncodeToString(hash[:])
}

// Sign calculates the Ed25519 signature of the data using the provided private key.
func Sign(data []byte, privateKey ed25519.PrivateKey) ([]byte, error) {
	return ed25519.Sign(privateKey, data), nil
}

// Verify checks if the signature is valid for the given data and public key.
func Verify(data []byte, signature []byte, publicKey ed25519.PublicKey) error {
	if ed25519.Verify(publicKey, data, signature) {
		return nil
	}
	return errors.New("signature verification failed")
}

// Encryption Keys (X25519 / ECDH)

// GenerateECDH creates a new X25519 key pair for Diffie-Hellman key exchange.
func GenerateECDH() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey(), nil
}

// EncPubKeyToPEM encodes an X25519 public key into a standard PEM block.
func EncPubKeyToPEM(pub *ecdh.PublicKey) []byte {
	pubASN1, _ := x509.MarshalPKIXPublicKey(pub)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubASN1})
}

// PEMToEncPubKey parses a PEM block containing an X25519 public key.
func PEMToEncPubKey(pemBytes []byte) (*ecdh.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecdhPub, ok := pub.(*ecdh.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDH public key")
	}
	return ecdhPub, nil
}

// ParseEncPrivateKey parses a PEM block containing an X25519 private key (PKCS#8).
func ParseEncPrivateKey(pemStr string) (*ecdh.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecdhPriv, ok := key.(*ecdh.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDH private key")
	}
	return ecdhPriv, nil
}

// EncPrivateKeyToPEM encodes an X25519 private key into a standard PEM block.
func EncPrivateKeyToPEM(priv *ecdh.PrivateKey) []byte {
	b, _ := x509.MarshalPKCS8PrivateKey(priv)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})
}

// Hybrid Encryption

// EncryptHybrid performs an ECIES-style hybrid encryption.
//
// Mechanism:
// 1. Generates an ephemeral X25519 key pair.
// 2. Derives a shared secret using Ephemeral_Priv * Recipient_Pub.
// 3. Derives an AES session key from the secret.
// 4. Encrypts the message with AES-256-GCM.
// 5. Returns a blob containing: [Length of Ephemeral PubKey][Ephemeral PubKey][Nonce][Ciphertext].
func EncryptHybrid(msg []byte, recipientEncPub *ecdh.PublicKey, additionalData []byte) ([]byte, error) {
	// Generate Ephemeral Key Pair
	ephemPriv, ephemPub, err := GenerateECDH()
	if err != nil {
		return nil, err
	}
	ephemPubBytes := ephemPub.Bytes()

	// Derive shared secret (Ephemeral Priv + Static Recipient Pub)
	secret, err := ephemPriv.ECDH(recipientEncPub)
	if err != nil {
		return nil, err
	}

	aesKey, err := DeriveSessionKey(secret, []byte("Safem Hybrid Enc"))
	if err != nil {
		return nil, err
	}

	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	aesCiphertext := gcm.Seal(nil, nonce, msg, additionalData)

	out := make([]byte, 0, 2+len(ephemPubBytes)+len(nonce)+len(aesCiphertext))
	out = append(out, byte(len(ephemPubBytes)>>8), byte(len(ephemPubBytes)))
	out = append(out, ephemPubBytes...)
	out = append(out, nonce...)
	out = append(out, aesCiphertext...)
	return out, nil
}

// DecryptHybrid unpacks the ephemeral key from the blob and decrypts the message.
// It requires the recipient's static private encryption key.
func DecryptHybrid(blob []byte, receiverEncPriv *ecdh.PrivateKey, additionalData []byte) ([]byte, error) {
	if len(blob) < 2 {
		return nil, errors.New("blob too short")
	}
	kLen := int(blob[0])<<8 | int(blob[1])
	if len(blob) < 2+kLen+NonceSize {
		return nil, errors.New("malformed ciphertext")
	}

	offset := 2
	ephemPubBytes := blob[offset : offset+kLen]
	offset += kLen
	nonce := blob[offset : offset+NonceSize]
	offset += NonceSize
	aesCiphertext := blob[offset:]

	// Parse ephemeral public key from blob
	ephemPub, err := ecdh.X25519().NewPublicKey(ephemPubBytes)
	if err != nil {
		return nil, err
	}

	// Derive shared secret (Static Receiver Priv + Ephemeral Pub)
	secret, err := receiverEncPriv.ECDH(ephemPub)
	if err != nil {
		return nil, err
	}

	aesKey, err := DeriveSessionKey(secret, []byte("Safem Hybrid Enc"))
	if err != nil {
		return nil, err
	}

	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	return gcm.Open(nil, nonce, aesCiphertext, additionalData)
}

// PackSecure combines a signature and encrypted payload into a single binary format.
// Format: [SigLen uint16][Signature][EncryptedData]
func PackSecure(enc []byte, sig []byte) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint16(len(sig)))
	buf.Write(sig)
	buf.Write(enc)
	return buf.Bytes()
}

// UnpackSecure separates the signature and encrypted payload from the binary format.
func UnpackSecure(data []byte) ([]byte, []byte, error) {
	if len(data) < 2 {
		return nil, nil, errors.New("secure packet too short")
	}
	sigLen := binary.BigEndian.Uint16(data[0:2])
	if len(data) < 2+int(sigLen) {
		return nil, nil, errors.New("secure packet malformed")
	}
	sig := data[2 : 2+sigLen]
	enc := data[2+sigLen:]
	return sig, enc, nil
}

// GenerateRandomBytes returns n bytes of cryptographically secure random data.
// It panics if the system CSPRNG fails, as continuing would be insecure.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	// Use io.ReadFull to guarantee full read of randomness.
	// Failure of the system CSPRNG is fatal.
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic("cryptolib: failed to read random source: " + err.Error())
	}
	return b, nil
}

// GenerateDeterministicNonce generates a unique 12-byte nonce based on a sequence number.
// Structure: [0x00 ... 0x00] [SeqID (8 bytes, BigEndian)]
//
// This guarantees uniqueness as long as the key is unique per session or the
// sequence number is monotonically increasing for a given key.
// It effectively acts as XORing the sequence number into a zero-based IV.
func GenerateDeterministicNonce(seq uint64) []byte {
	nonce := make([]byte, NonceSize)
	// Write SeqID to the last 8 bytes (Big Endian)
	// The first 4 bytes remain 0x00 (padding)
	binary.BigEndian.PutUint64(nonce[NonceSize-8:], seq)
	return nonce
}

// NewAEAD creates a reused cipher.AEAD instance (AES-GCM) from a given key.
// Using this avoids key expansion overhead per packet in high-throughput sessions.
func NewAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// EncryptSymmetric encrypts data using AES-256-GCM with a random nonce.
// It generates a random 12-byte nonce and prepends it to the ciphertext.
//
// Use this for single-shot encryption (e.g., file storage) where a sequence number
// is not available. For streams, use EncryptSymmetricWithNonce.
func EncryptSymmetric(msg []byte, key []byte, additionalData []byte) ([]byte, error) {
	nonce, _ := GenerateRandomBytes(NonceSize)
	return EncryptSymmetricWithNonce(msg, key, nonce, additionalData)
}

// EncryptSymmetricWithNonce encrypts data using AES-256-GCM with a specific nonce.
// It prepends the nonce to the ciphertext [Nonce][Ciphertext][Tag].
func EncryptSymmetricWithNonce(msg []byte, key []byte, nonce []byte, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}

	// Allocate ONE slice for Nonce + Ciphertext + Tag
	// capacity = NonceSize + len(msg) + Overhead
	totalLen := NonceSize + len(msg) + gcm.Overhead()
	final := make([]byte, NonceSize, totalLen)
	copy(final, nonce)

	// Seal appends the ciphertext directly to 'final'
	return gcm.Seal(final, nonce, msg, additionalData), nil
}

// DecryptSymmetric decrypts an AES-256-GCM ciphertext using the provided key.
// It expects the blob to contain [Nonce (12)][Ciphertext][Tag].
func DecryptSymmetric(blob []byte, key []byte, additionalData []byte) ([]byte, error) {
	if len(blob) < NonceSize {
		return nil, errors.New("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, blob[:NonceSize], blob[NonceSize:], additionalData)
}

// DeriveKeyPBKDF2 derives a key from a password and salt using PBKDF2-SHA256.
func DeriveKeyPBKDF2(password, salt []byte, iterations int) []byte {
	return pbkdf2.Key(password, salt, iterations, 32, sha256.New)
}

// DeriveSharedSecret computes the raw ECDH shared secret (Private * RemotePublic).
func DeriveSharedSecret(priv *ecdh.PrivateKey, remotePubBytes []byte) ([]byte, error) {
	curve := ecdh.X25519()
	remotePub, err := curve.NewPublicKey(remotePubBytes)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(remotePub)
}

// DeriveSessionKey derives a 32-byte session key from a master secret and info string.
// It uses HKDF-style expansion (HMAC-SHA256).
func DeriveSessionKey(secret, info []byte) ([]byte, error) {
	hash := sha256.New
	salt := make([]byte, hash().Size()) // Zero salt
	h := hmac.New(hash, salt)
	h.Write(secret)
	prk := h.Sum(nil)

	h2 := hmac.New(hash, prk)
	h2.Write(info)
	h2.Write([]byte{0x01}) // Counter
	okm := h2.Sum(nil)
	return okm[:32], nil
}

// KDF_RK applies the Root Key Derivation Function (KDF).
// It accepts a Root Key (RK) and Diffie-Hellman Output (DH) and returns a (New Root Key, Chain Key) pair.
// This matches the Double Ratchet Specification for the DH Ratchet step.
func KDF_RK(rootKey, dhOut []byte) ([]byte, []byte, error) {
	hash := sha256.New

	// HKDF Extract
	// Salt: rootKey (Use current Root Key as salt)
	// IKM: dhOut (Input Key Material is the DH output)
	h := hmac.New(hash, rootKey)
	h.Write(dhOut)
	prk := h.Sum(nil)

	// HKDF Expand
	// New Root Key (Context 0x01)
	h2 := hmac.New(hash, prk)
	h2.Write([]byte{0x01})
	newRootKey := h2.Sum(nil)

	// Chain Key (Context 0x02)
	h3 := hmac.New(hash, prk)
	h3.Write([]byte{0x02})
	chainKey := h3.Sum(nil)

	return newRootKey[:32], chainKey[:32], nil
}

// KDF_CK applies the Chain Key Derivation Function (Symmetric Ratchet).
// It accepts a Chain Key and returns a (New Chain Key, Message Key) pair.
// This is used for every message sent/received to ensure Forward Secrecy.
func KDF_CK(chainKey []byte) ([]byte, []byte, error) {
	hash := sha256.New

	// HMAC(CK, 0x01) -> New Chain Key
	h := hmac.New(hash, chainKey)
	h.Write([]byte{0x01})
	newChainKey := h.Sum(nil)

	// HMAC(CK, 0x02) -> Message Key
	h2 := hmac.New(hash, chainKey)
	h2.Write([]byte{0x02})
	messageKey := h2.Sum(nil)

	return newChainKey[:32], messageKey[:32], nil
}

// ComputeSafetyNumber generates a numeric fingerprint string from two public keys.
// The keys are sorted to ensure the safety number is the same for both parties.
// Format: XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX (30 digits)
func ComputeSafetyNumber(keyA, keyB ed25519.PublicKey) string {
	// Sort keys byte-wise to ensure consistency regardless of who computes it
	keys := [][]byte{keyA, keyB}
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(keys[i], keys[j]) < 0
	})

	// Hash the sorted keys
	h := sha256.New()
	h.Write(keys[0])
	h.Write(keys[1])
	sum := h.Sum(nil)

	// Convert to numeric blocks
	// We iterate through the hash, taking 5 bytes at a time (approx) to form 5-digit numbers.
	// Since 5 bytes > uint32, we truncate or modulo.
	// To map nicely to 5 digits (00000-99999), we read chunks as uint64 and mod 100000.
	var sb bytes.Buffer
	for i := 0; i < 6; i++ {
		offset := i * 5
		if offset+5 > len(sum) {
			break
		}

		// Use 5 bytes from hash to form a number
		// We use BigEndian to be deterministic
		// Actually, 5 bytes fits in uint64.
		// We pad the slice to 8 bytes to use standard binary.Read, or just manual shift.
		chunk := sum[offset : offset+5]
		val := uint64(chunk[0])<<32 | uint64(chunk[1])<<24 | uint64(chunk[2])<<16 | uint64(chunk[3])<<8 | uint64(chunk[4])

		num := val % 100000

		if i > 0 {
			sb.WriteString(" ")
		}
		fmt.Fprintf(&sb, "%05d", num)
	}

	return sb.String()
}