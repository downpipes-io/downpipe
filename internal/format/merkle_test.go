package format

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestMerkleRoot(t *testing.T) {
	a := bytes.Repeat([]byte{0x01}, 48)
	b := bytes.Repeat([]byte{0x02}, 48)
	c := bytes.Repeat([]byte{0x03}, 48)

	if !bytes.Equal(MerkleRoot([][]byte{a, b, c}), MerkleRoot([][]byte{a, b, c})) {
		t.Fatal("the root must be deterministic")
	}
	if bytes.Equal(MerkleRoot([][]byte{a, b, c}), MerkleRoot([][]byte{a, c, b})) {
		t.Fatal("the root must be order-sensitive")
	}
	if !bytes.Equal(MerkleRoot([][]byte{a}), leafHash(a)) {
		t.Fatal("a single-leaf root must equal that leaf hash")
	}

	// The empty-tree root is SHA-384 of the empty string.
	const emptyHex = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
	if got := hex.EncodeToString(MerkleRoot(nil)); got != emptyHex {
		t.Fatalf("empty-tree root = %s, want %s", got, emptyHex)
	}
}

// The two-leaf tree is the smallest interior-node case: an even level with no odd
// promotion, so the root must be exactly nodeHash(leafHash(a), leafHash(b)). This pins
// the RFC 6962 interior-node construction (0x01 || left || right over SHA-384) and is
// the structural counterpart to the single-leaf case, which has no interior node at
// all. The locked hex is a regression vector derived once from this code.
func TestMerkleRootTwoLeaf(t *testing.T) {
	a := bytes.Repeat([]byte{0x0a}, 48)
	b := bytes.Repeat([]byte{0x0b}, 48)

	root := MerkleRoot([][]byte{a, b})

	// Direct node hash over the two leaf hashes, with no odd-node promotion involved.
	if want := nodeHash(leafHash(a), leafHash(b)); !bytes.Equal(root, want) {
		t.Fatalf("two-leaf root = %x, want nodeHash(leaf(a), leaf(b)) = %x", root, want)
	}
	const wantHex = "71e586c1e5a73ca222090fb2909c24e158691fe9d6864286225791be74dd6366ecf7e29835399b5f25d86749fd59df46"
	if got := hex.EncodeToString(root); got != wantHex {
		t.Fatalf("two-leaf root regression: got %s, want locked %s", got, wantHex)
	}
	// A two-leaf root must not collapse to either leaf hash: the interior node mixes both.
	if bytes.Equal(root, leafHash(a)) || bytes.Equal(root, leafHash(b)) {
		t.Fatal("the two-leaf root must be an interior node, not a promoted leaf")
	}
	// The interior node is order-sensitive: 0x01 || a || b differs from 0x01 || b || a.
	if bytes.Equal(root, MerkleRoot([][]byte{b, a})) {
		t.Fatal("the two-leaf interior node must be order-sensitive")
	}
}

// A five-leaf tree forces odd-node promotion at two successive levels: the fifth leaf is
// promoted unchanged from the leaf level to the second level and again to the root join,
// rather than being duplicated. The locked root is the known answer for the explicit
// tree N( N(N(la,lb), N(lc,ld)), le ); it is recomputed here from the leaf and node
// primitives so the test pins the promotion rule, not just a deterministic output, and
// fails if odd promotion ever regresses to RFC-6962-bis-style duplication.
func TestMerkleRootFiveLeafKnownAnswer(t *testing.T) {
	a := bytes.Repeat([]byte{0x0a}, 48)
	b := bytes.Repeat([]byte{0x0b}, 48)
	c := bytes.Repeat([]byte{0x0c}, 48)
	d := bytes.Repeat([]byte{0x0d}, 48)
	e := bytes.Repeat([]byte{0x0e}, 48)

	root := MerkleRoot([][]byte{a, b, c, d, e})

	// Explicit tree with the odd leaf e promoted up two levels, then joined at the top.
	la, lb, lc, ld, le := leafHash(a), leafHash(b), leafHash(c), leafHash(d), leafHash(e)
	want := nodeHash(nodeHash(nodeHash(la, lb), nodeHash(lc, ld)), le)
	if !bytes.Equal(root, want) {
		t.Fatalf("five-leaf root = %x, want explicit promoted tree %x", root, want)
	}
	const wantHex = "5ab01a9736438198e77812f5bf07858e5016de9b3cfae2f3a84f4c1200b00261ceb9b26b21261993429ef38d712a3e80"
	if got := hex.EncodeToString(root); got != wantHex {
		t.Fatalf("five-leaf root regression: got %s, want locked %s", got, wantHex)
	}
	// Promotion, not duplication: if the odd leaf were duplicated (e paired with itself),
	// the root would differ. Asserting the duplicated tree gives a different root proves
	// the production path promotes the lone node unchanged.
	dup := nodeHash(nodeHash(nodeHash(la, lb), nodeHash(lc, ld)), nodeHash(le, le))
	if bytes.Equal(root, dup) {
		t.Fatal("odd nodes must be promoted unchanged, never duplicated")
	}
	// Order sensitivity must hold across the promotion: moving the promoted leaf changes
	// the root.
	if bytes.Equal(root, MerkleRoot([][]byte{a, b, c, e, d})) {
		t.Fatal("the five-leaf root must be order-sensitive")
	}
}

// detLeaf builds a deterministic 48-byte (SHA-384-width) leaf for index i, so the
// equivalence sweep below exercises distinct, well-spread leaves without any randomness
// (a flaky equivalence test would be worthless: the property must hold for EVERY n).
func detLeaf(i int) []byte {
	h := sha512.New384()
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(i))
	h.Write([]byte("merkle-equiv-leaf"))
	h.Write(b[:])
	return h.Sum(nil)
}

// TestMerkleAccumulatorMatchesMerkleRoot is the keystone byte-identity proof for the
// streaming offline restore: the incremental MerkleAccumulator (the frontier the streaming
// verify pushes one record-hash at a time) MUST reproduce the EXACT root the load-all
// MerkleRoot computes over the same leaves, because that root is what the signed archive
// authenticates. A single divergent n would ship a streaming restore that rejects a valid
// signed archive (or, worse, accepts a different leaf set), so this sweeps every n across
// the power-of-two boundaries (0, 1, 2, 3, ... up through 2049) where the RFC 6962 odd-node
// promotion is most likely to diverge from a naive frontier.
func TestMerkleAccumulatorMatchesMerkleRoot(t *testing.T) {
	for n := 0; n <= 2049; n++ {
		leaves := make([][]byte, n)
		for i := range leaves {
			leaves[i] = detLeaf(i)
		}
		want := MerkleRoot(leaves)

		var acc MerkleAccumulator
		for _, l := range leaves {
			acc.Push(l)
		}
		if acc.Count() != uint64(n) {
			t.Fatalf("n=%d: accumulator counted %d leaves", n, acc.Count())
		}
		if got := acc.Root(); !bytes.Equal(got, want) {
			t.Fatalf("n=%d: streaming root %x != load-all root %x", n, got, want)
		}
	}
}

// TestMerkleAccumulatorRootIsNonDestructive proves Root() can be called repeatedly and that
// Push continues correctly afterwards (the streaming verify reads the root only at the end,
// but a defensive caller may peek). Each prefix's streamed root must still equal the
// load-all root over that prefix, so a mid-stream Root() never corrupts the frontier.
func TestMerkleAccumulatorRootIsNonDestructive(t *testing.T) {
	const n = 137 // an arbitrary non-power-of-two with several frontier subtrees
	var acc MerkleAccumulator
	for i := 0; i < n; i++ {
		acc.Push(detLeaf(i))
		// Peek the root twice; it must be stable and must equal the load-all root over the
		// i+1-leaf prefix, proving Root() neither consumes nor mutates the frontier.
		first := acc.Root()
		second := acc.Root()
		if !bytes.Equal(first, second) {
			t.Fatalf("prefix %d: Root() is not idempotent", i+1)
		}
		prefix := make([][]byte, i+1)
		for j := range prefix {
			prefix[j] = detLeaf(j)
		}
		if want := MerkleRoot(prefix); !bytes.Equal(first, want) {
			t.Fatalf("prefix %d: streamed root %x != load-all root %x", i+1, first, want)
		}
	}
}

// TestMerkleAccumulatorEmpty pins the empty-tree root (zero records): the streaming verify
// of an empty run must produce SHA-384 of the empty string, byte-identical to MerkleRoot(nil)
// and to the SPEC.md 11.8 locked constant.
func TestMerkleAccumulatorEmpty(t *testing.T) {
	var acc MerkleAccumulator
	const emptyHex = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
	if got := hex.EncodeToString(acc.Root()); got != emptyHex {
		t.Fatalf("empty accumulator root = %s, want %s", got, emptyHex)
	}
	if !bytes.Equal(acc.Root(), MerkleRoot(nil)) {
		t.Fatal("empty accumulator root must equal MerkleRoot(nil)")
	}
}
