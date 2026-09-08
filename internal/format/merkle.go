package format

import "crypto/sha512"

// MerkleRoot computes the RFC 6962 Merkle root over the record hashes using SHA-384
// (SPEC.md 11.8): a leaf is SHA-384(0x00 || recordHash), an interior node is
// SHA-384(0x01 || left || right), and an odd node at a level is promoted unchanged
// rather than duplicated. The empty-tree root is SHA-384 of the empty string. The
// caller supplies the record hashes in canonical record order; the root is therefore
// order-sensitive by construction.
func MerkleRoot(recordHashes [][]byte) []byte {
	if len(recordHashes) == 0 {
		s := sha512.Sum384(nil)
		return s[:]
	}
	level := make([][]byte, len(recordHashes))
	for i, rh := range recordHashes {
		level[i] = leafHash(rh)
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			next = append(next, nodeHash(level[i], level[i+1]))
		}
		level = next
	}
	return level[0]
}

// MerkleAccumulator computes the SPEC.md 11.8 / RFC 6962 Merkle root incrementally as
// record-hash leaves are pushed one at a time, holding only the O(log n) frontier of
// completed perfect-subtree roots (one entry per set bit of the leaf count) rather than
// the whole leaf set. Its Root is byte-identical to what MerkleRoot returns over the same
// leaves in the same order, so a STREAMING verify recomputes the exact signed root that a
// load-all verify does, never materialising every record hash. The zero value is an empty
// accumulator ready to Push.
//
// Equivalence to MerkleRoot's level-by-level "promote an odd node unchanged" tree: the
// frontier holds the binary carry decomposition of n (perfect subtrees of strictly
// decreasing leaf span). Push carries equal-height subtrees into a parent with the EARLIER
// leaves on the left; Root folds the frontier right-to-left with the EARLIER (larger)
// subtree on the left. Both rules place the lone trailing subtree exactly where the
// level-by-level promotion does, so the two roots match for every n (asserted by
// TestMerkleAccumulatorMatchesMerkleRoot over a wide range of n).
type MerkleAccumulator struct {
	// subtrees holds the roots of completed perfect binary subtrees ordered from index 0
	// (largest span, earliest leaves) to the end (smallest span, latest leaves); heights
	// is the parallel log2(span) used to detect when the new subtree meets an equal-height
	// neighbour and the two must merge. Each entry is a freshly allocated 48-byte hash; the
	// pushed leaf slice itself is never retained.
	subtrees [][]byte
	heights  []int
	n        uint64
}

// Push folds one more record-hash leaf into the frontier. It leaf-hashes the input
// (SHA-384(0x00 || recordHash), SPEC.md 11.8) then carries: while the new subtree has the
// same height as the right-most frontier subtree, the two merge into a parent node with
// the existing frontier entry (the EARLIER leaves) as the left child and the newer subtree
// as the right, the identical pairing MerkleRoot forms a level at a time. recordHash is
// read, not retained.
func (m *MerkleAccumulator) Push(recordHash []byte) {
	node := leafHash(recordHash)
	height := 0
	for len(m.heights) > 0 && m.heights[len(m.heights)-1] == height {
		left := m.subtrees[len(m.subtrees)-1]
		m.subtrees = m.subtrees[:len(m.subtrees)-1]
		m.heights = m.heights[:len(m.heights)-1]
		node = nodeHash(left, node)
		height++
	}
	m.subtrees = append(m.subtrees, node)
	m.heights = append(m.heights, height)
	m.n++
}

// Count is the number of leaves pushed so far.
func (m *MerkleAccumulator) Count() uint64 { return m.n }

// Root finalises the frontier into the single Merkle root WITHOUT consuming it: Push may
// continue afterwards and Root may be called again. An empty accumulator returns the
// empty-tree root (SHA-384 of the empty string), matching MerkleRoot(nil). Otherwise the
// frontier subtrees are folded RIGHT TO LEFT, the right-most (smallest, latest) subtree as
// the right child and each earlier subtree to its left, reproducing the RFC 6962 shape
// MerkleRoot builds level by level. The returned slice is a fresh copy the caller may keep.
func (m *MerkleAccumulator) Root() []byte {
	if m.n == 0 {
		s := sha512.Sum384(nil)
		return s[:]
	}
	node := m.subtrees[len(m.subtrees)-1]
	for i := len(m.subtrees) - 2; i >= 0; i-- {
		node = nodeHash(m.subtrees[i], node)
	}
	out := make([]byte, len(node))
	copy(out, node)
	return out
}

func leafHash(data []byte) []byte {
	h := sha512.New384()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

func nodeHash(left, right []byte) []byte {
	h := sha512.New384()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}
