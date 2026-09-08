package crypto

import (
	"bytes"
	"testing"
)

// EncapsulateHybrid takes no caller reader and is always freshly randomised
// from the system CSPRNG. Two encapsulations to the same recipient must therefore
// differ in both the ciphertext and the shared secret, and each must still
// decapsulate to its own secret. This pins the contract that no caller-supplied seed
// governs entropy (the removed randr) and that a byte-pinned encapsulation vector is
// not possible.
func TestEncapsulateHybridFreshlyRandomised(t *testing.T) {
	priv, pub := newRecipient(t)

	ss1, ct1, err := EncapsulateHybrid(pub)
	if err != nil {
		t.Fatal(err)
	}
	ss2, ct2, err := EncapsulateHybrid(pub)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encapsulations produced an identical ciphertext; encapsulation must be freshly randomised")
	}
	if bytes.Equal(ss1, ss2) {
		t.Fatal("two encapsulations produced an identical shared secret; encapsulation must be freshly randomised")
	}

	// Each fresh encapsulation must still round-trip to its own secret.
	got1, err := DecapsulateHybrid(priv, ct1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got1, ss1) {
		t.Fatal("the first encapsulation did not decapsulate to its own shared secret")
	}
	got2, err := DecapsulateHybrid(priv, ct2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got2, ss2) {
		t.Fatal("the second encapsulation did not decapsulate to its own shared secret")
	}
}

// zeroize must overwrite key material with zeros and tolerate the empty and
// nil cases without panicking.
func TestZeroize(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	zeroize(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("zeroize left byte %d = %d, want 0", i, v)
		}
	}

	// A backing array reached through a sub-slice must also be wiped, since OpenCapsule
	// wipes out.Bytes() which aliases the buffer's backing array.
	backing := []byte{9, 9, 9, 9}
	zeroize(backing[:2])
	if backing[0] != 0 || backing[1] != 0 {
		t.Fatalf("zeroize did not wipe the aliased region: %v", backing)
	}
	if backing[2] != 9 || backing[3] != 9 {
		t.Fatalf("zeroize wiped beyond the slice length: %v", backing)
	}

	// Empty and nil must be safe no-ops.
	zeroize(nil)
	zeroize([]byte{})
}

// zeroizeArray must wipe the caller's fixed 32-byte key array through the
// pointer (a copy would leave the original key in memory).
func TestZeroizeArray(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	zeroizeArray(&key)
	if key != ([32]byte{}) {
		t.Fatalf("zeroizeArray left non-zero key material: %v", key)
	}
}

// The deferred zeroization of the KEM shared secret, wrap key and recovered
// master buffer inside openWrap must not corrupt the returned master. Recovery must
// still succeed after the wipes run, including for the break-glass identity. (The
// wipe primitives themselves are pinned by TestZeroize and TestZeroizeArray; Go cannot
// guarantee erasure of every copy, so this asserts the integration stays correct.)
func TestOpenCapsuleRecoversAfterZeroization(t *testing.T) {
	var master [32]byte
	for i := range master {
		master[i] = byte(i*7 + 2)
	}
	bgPriv, bgPub := newRecipient(t)
	opPriv, opPub := newRecipient(t)
	ctx := []byte("downpipe break-glass recovery context")

	wraps, err := SealToRecipients(master, []*HybridKEMPublic{bgPub, opPub}, ctx, deterministicNonceReader())
	if err != nil {
		t.Fatal(err)
	}

	for name, priv := range map[string]*HybridKEMPrivate{"break-glass": bgPriv, "operational": opPriv} {
		got, err := OpenCapsule(wraps, priv, ctx, nil)
		if err != nil {
			t.Fatalf("%s recovery failed after zeroization: %v", name, err)
		}
		if got != master {
			t.Fatalf("%s recovered the wrong master after zeroization", name)
		}
	}
}

// ConstantTimeEqual must be length-safe. A length mismatch must report
// not-equal and must never read as equal, including the case where the shorter slice
// is a prefix of the longer one (the case subtle.ConstantTimeCompare short-circuits on
// by branching on length). Equal-length equal and unequal inputs, the empty case and
// the nil case must all behave.
func TestConstantTimeEqualLengthSafe(t *testing.T) {
	cases := []struct {
		name string
		a, b []byte
		want bool
	}{
		{"both nil", nil, nil, true},
		{"nil vs empty", nil, []byte{}, true},
		{"both empty", []byte{}, []byte{}, true},
		{"equal single", []byte{0x42}, []byte{0x42}, true},
		{"equal multi", []byte{1, 2, 3, 4}, []byte{1, 2, 3, 4}, true},
		{"same length differ first", []byte{1, 2, 3}, []byte{9, 2, 3}, false},
		{"same length differ last", []byte{1, 2, 3}, []byte{1, 2, 9}, false},
		{"shorter is prefix of longer", []byte{1, 2}, []byte{1, 2, 3}, false},
		{"longer has prefix shorter (a longer)", []byte{1, 2, 3}, []byte{1, 2}, false},
		{"empty vs non-empty", []byte{}, []byte{1}, false},
		{"nil vs non-empty", nil, []byte{1}, false},
		{"trailing zero vs shorter", []byte{1, 2, 0}, []byte{1, 2}, false},
	}
	for _, c := range cases {
		if got := ConstantTimeEqual(c.a, c.b); got != c.want {
			t.Errorf("%s: ConstantTimeEqual(%v, %v) = %v, want %v", c.name, c.a, c.b, got, c.want)
		}
		// The relation must be symmetric.
		if got := ConstantTimeEqual(c.b, c.a); got != c.want {
			t.Errorf("%s (swapped): ConstantTimeEqual(%v, %v) = %v, want %v", c.name, c.b, c.a, got, c.want)
		}
	}
}

// ConstantTimeEqual on the fixed-size 48-byte SHA-384 digests it is actually called
// with: equal digests match, a one-bit flip does not.
func TestConstantTimeEqualDigest(t *testing.T) {
	_, a := newRecipient(t)
	_, b := newRecipient(t)
	ha := RecipientSetHash([]*HybridKEMPublic{a, b})
	hb := RecipientSetHash([]*HybridKEMPublic{a, b})
	if !ConstantTimeEqual(ha, hb) {
		t.Fatal("equal recipient-set digests must compare equal")
	}
	flipped := bytes.Clone(ha)
	flipped[0] ^= 0x01
	if ConstantTimeEqual(ha, flipped) {
		t.Fatal("a one-bit-different digest must not compare equal")
	}
}

// deterministicNonceReader returns a reader of fixed bytes for the SealToRecipients
// nonce, so the seal path is exercised without relying on the system CSPRNG for the
// nonce. Encapsulation still draws its own randomness (see EncapsulateHybrid).
func deterministicNonceReader() *bytes.Reader {
	buf := make([]byte, 4096)
	for i := range buf {
		buf[i] = byte(i % 251)
	}
	return bytes.NewReader(buf)
}
