package cryptolib

import (
	"bytes"
	"crypto/sha256"
)

// MerkleLog represents an append-only Key Transparency Log (RFC 6962 style).
type MerkleLog struct {
	// Leaves stores the raw leaf hashes in order of arrival.
	Leaves [][]byte
}

// NewMerkleLog initializes an empty log.
func NewMerkleLog() *MerkleLog {
	return &MerkleLog{
		Leaves: make([][]byte, 0),
	}
}

// CalculateLeafHash generates the hash for a user entry.
// Note: In a full RFC 6962 implementation, this would be wrapped with 0x00 prefix during tree construction.
// We keep it compatible with the upper layer's expectation of an ID hash.
func CalculateLeafHash(id, signPEM, encPEM string) []byte {
	h := sha256.New()
	h.Write([]byte(id))
	h.Write([]byte(signPEM))
	h.Write([]byte(encPEM))
	return h.Sum(nil)
}

// hashLeafRFC computes the leaf hash node: SHA256(0x00 || data)
func hashLeafRFC(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00}) // Leaf Prefix
	h.Write(data)
	return h.Sum(nil)
}

// hashNodeRFC computes the internal node hash: SHA256(0x01 || left || right)
func hashNodeRFC(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01}) // Node Prefix
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// Append adds a new leaf to the log and returns its index.
// This is an O(1) operation on the storage (O(N) for root calc if done naively, 
// but we only calc root on demand).
func (m *MerkleLog) Append(leafHash []byte) int {
	m.Leaves = append(m.Leaves, leafHash)
	return len(m.Leaves) - 1
}

// Root computes the Merkle Tree Hash (MTH) of the current log.
func (m *MerkleLog) Root() []byte {
	n := len(m.Leaves)
	if n == 0 {
		// Empty tree hash (SHA256(""))
		h := sha256.New()
		return h.Sum(nil)
	}
	return m.subtreeHash(0, n)
}

// subtreeHash recursively computes the hash of the range [start, start+k).
// This structure ensures the tree is consistent for a given size.
func (m *MerkleLog) subtreeHash(start, k int) []byte {
	if k == 0 {
		return nil // Should not happen in recursion logic
	}
	if k == 1 {
		return hashLeafRFC(m.Leaves[start])
	}

	// For a balanced binary tree over a list, split at the largest power of 2 less than k.
	// RFC 6962 definition:
	// let k be the largest power of two smaller than n...
	split := 1
	for split < k {
		split <<= 1
	}
	if split > 1 {
		split >>= 1
	}
	// Note: If k is a power of 2, standard trees split at k/2. 
	// RFC 6962 splits at largest power of 2 < k (e.g. for 5, split at 4).
	// But simple binary construction often just does k/2. 
	// Let's stick to the Largest Power of 2 rule for Append-Only consistency.
	if k > 1 {
		// Optimization: if k is power of 2, split is k/2
		// If k=5, split=4. Left=4, Right=1.
		// If k=13, split=8. Left=8, Right=5.
		
		// Recalculate split precisely
		split = 1
		for (split << 1) < k {
			split <<= 1
		}
	}

	left := m.subtreeHash(start, split)
	right := m.subtreeHash(start+split, k-split)

	return hashNodeRFC(left, right)
}

// Prove generates an inclusion proof for the leaf at index `targetIdx`.
func (m *MerkleLog) Prove(targetIdx int) ([][]byte, bool) {
	n := len(m.Leaves)
	if targetIdx < 0 || targetIdx >= n {
		return nil, false
	}
	
	proof := m.subProof(targetIdx, 0, n)
	return proof, true
}

func (m *MerkleLog) subProof(targetIdx, start, k int) [][]byte {
	if k <= 1 {
		return nil
	}

	// Split logic must match subtreeHash exactly
	split := 1
	for (split << 1) < k {
		split <<= 1
	}

	// Is target in left or right?
	if targetIdx < start+split {
		// Target is in Left. We need Root of Right as sibling.
		path := m.subProof(targetIdx, start, split)
		rightRoot := m.subtreeHash(start+split, k-split)
		return append(path, rightRoot)
	} else {
		// Target is in Right. We need Root of Left as sibling.
		path := m.subProof(targetIdx, start+split, k-split)
		leftRoot := m.subtreeHash(start, split)
		return append(path, leftRoot)
	}
}

// VerifyMerkleProof verifies an RFC 6962 style inclusion proof.
func VerifyMerkleProof(root, leaf []byte, proof [][]byte, index, total int) bool {
	// Reconstruct root from leaf and proof
	computed := hashLeafRFC(leaf)
	
	// We iterate the proof path. But RFC 6962 verification requires knowing
	// the shape of the tree (index and total) to know if sibling is left or right.
	
	currentIdx := index
	currentK := total
	
	// Proof is ordered from bottom (leaves) to top.
	// However, my recursive generation appends (Top-Down recursion returns Bottom-Up list).
	// Let's verify traversal direction.
	// subProof returns [sibling_at_bottom, ..., sibling_at_top].
	
	for _, sibling := range proof {
		if currentK <= 1 {
			break
		}

		split := 1
		for (split << 1) < currentK {
			split <<= 1
		}

		if currentIdx < split {
			// We are in Left. Sibling is Right.
			computed = hashNodeRFC(computed, sibling)
			currentK = split
		} else {
			// We are in Right. Sibling is Left.
			computed = hashNodeRFC(sibling, computed)
			currentIdx -= split
			currentK -= split
		}
	}

	return bytes.Equal(computed, root)
}