package crypto

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// The hybrid KEM must agree on a 32-byte shared secret across encapsulate and
// decapsulate, and a tampered ciphertext must not yield the same secret (ML-KEM
// implicit rejection plus the bound X25519 share).
func TestHybridKEMRoundTrip(t *testing.T) {
	priv, pub, err := GenerateHybridKEM()
	if err != nil {
		t.Fatal(err)
	}
	ss1, ct, err := EncapsulateHybrid(pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(ss1) != 32 {
		t.Fatalf("shared secret is %d bytes, want 32", len(ss1))
	}
	ss2, err := DecapsulateHybrid(priv, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("the hybrid KEM shared secrets disagree")
	}
	bad := bytes.Clone(ct)
	bad[0] ^= 0xff
	// ML-KEM performs implicit rejection: a flipped ciphertext must not error, it must
	// return a pseudorandom secret. Assert the two sub-properties separately so the test
	// fails if a future change makes the function fail-closed (error) instead of implicitly
	// rejecting, which would otherwise pass a combined err==nil && bytes.Equal guard silently.
	ssBad, err := DecapsulateHybrid(priv, bad)
	if err != nil {
		t.Fatalf("a tampered ciphertext must implicitly reject, not error: %v", err)
	}
	if bytes.Equal(ssBad, ss1) {
		t.Fatal("a tampered ciphertext must not recover the same shared secret")
	}
}

// A different recipient's private key must not recover the secret, confirming the
// secret is bound to the recipient identity.
func TestHybridKEMWrongRecipient(t *testing.T) {
	_, pub, err := GenerateHybridKEM()
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := GenerateHybridKEM()
	if err != nil {
		t.Fatal(err)
	}
	ss1, ct, err := EncapsulateHybrid(pub)
	if err != nil {
		t.Fatal(err)
	}
	// As with the tampered-ciphertext case, ML-KEM implicitly rejects: a wrong recipient key
	// must return a pseudorandom secret, not an error. Assert both sub-properties separately.
	ssOther, err := DecapsulateHybrid(other, ct)
	if err != nil {
		t.Fatalf("a different recipient must implicitly reject, not error: %v", err)
	}
	if bytes.Equal(ssOther, ss1) {
		t.Fatal("a different recipient must not recover the shared secret")
	}
}

// A valid hybrid signature verifies; a different message fails; and an Ed25519-only
// signature (the post-quantum half stripped) is rejected, so there is no downgrade.
func TestHybridSignNoDowngrade(t *testing.T) {
	s, v, err := GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("downpipe root manifest canonical bytes")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(msg, sig); err != nil {
		t.Fatalf("a valid hybrid signature was rejected: %v", err)
	}
	if v.Verify([]byte("tampered manifest"), sig) == nil {
		t.Fatal("the signature must not verify for a different message")
	}
	if v.Verify(msg, sig[:ed25519.SignatureSize]) == nil {
		t.Fatal("an Ed25519-only signature must be rejected (no post-quantum downgrade)")
	}
}
