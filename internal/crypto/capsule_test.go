package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func newRecipient(t *testing.T) (*HybridKEMPrivate, *HybridKEMPublic) {
	t.Helper()
	priv, pub, err := GenerateHybridKEM()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// The master wraps to a break-glass and an operational recipient; either private
// identity recovers it, a non-recipient cannot, and a tampered wrap fails.
func TestCapsuleMultiRecipient(t *testing.T) {
	var master [32]byte
	for i := range master {
		master[i] = byte(i*3 + 1)
	}
	bgPriv, bgPub := newRecipient(t)
	opPriv, opPub := newRecipient(t)

	ctx := []byte("downpipe run context")
	wraps, err := SealToRecipients(master, []*HybridKEMPublic{bgPub, opPub}, ctx, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(wraps) != 2 {
		t.Fatalf("want 2 wraps, got %d", len(wraps))
	}

	for name, priv := range map[string]*HybridKEMPrivate{"break-glass": bgPriv, "operational": opPriv} {
		got, err := OpenCapsule(wraps, priv, ctx, nil)
		if err != nil {
			t.Fatalf("%s open: %v", name, err)
		}
		if got != master {
			t.Fatalf("%s recovered the wrong master", name)
		}
	}

	otherPriv, _ := newRecipient(t)
	if _, err := OpenCapsule(wraps, otherPriv, ctx, nil); err == nil {
		t.Fatal("a non-recipient must not open the capsule")
	}

	bad := make([]WrappedKey, len(wraps))
	copy(bad, wraps)
	bad[0].Sealed = bytes.Clone(bad[0].Sealed)
	bad[0].Sealed[len(bad[0].Sealed)-1] ^= 0x01
	if _, err := OpenCapsule(bad, bgPriv, ctx, nil); err == nil {
		t.Fatal("a tampered wrap must fail authentication")
	}

	if _, err := OpenCapsule(wraps, bgPriv, []byte("a different run context"), nil); err == nil {
		t.Fatal("the wrong run context must fail authentication (AAD binding)")
	}
}

// The fingerprint is stable for one identity and distinct across identities.
func TestRecipientFingerprintStableAndDistinct(t *testing.T) {
	_, a := newRecipient(t)
	_, b := newRecipient(t)
	if fp1, fp2 := RecipientFingerprint(a), RecipientFingerprint(a); fp1 != fp2 {
		t.Fatal("the fingerprint must be stable for one recipient")
	}
	if RecipientFingerprint(a) == RecipientFingerprint(b) {
		t.Fatal("the fingerprint must differ across recipients")
	}
}

// The recipient-set hash is independent of listing order and distinct across sets,
// and is a 48-byte SHA-384.
func TestRecipientSetHash(t *testing.T) {
	_, a := newRecipient(t)
	_, b := newRecipient(t)
	_, c := newRecipient(t)

	ab := RecipientSetHash([]*HybridKEMPublic{a, b})
	if len(ab) != 48 {
		t.Fatalf("recipient-set hash is %d bytes, want 48", len(ab))
	}
	if !ConstantTimeEqual(ab, RecipientSetHash([]*HybridKEMPublic{b, a})) {
		t.Fatal("the recipient-set hash must be independent of listing order")
	}
	if ConstantTimeEqual(ab, RecipientSetHash([]*HybridKEMPublic{a, c})) {
		t.Fatal("the recipient-set hash must differ across sets")
	}
}
