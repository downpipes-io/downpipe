package crypto

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// The round-trip tests prove the happy path. These cover the rejection branches the
// offline reader relies on when it meets a corrupt or wrong-length key, ciphertext or
// segment, so a malformed recovery input fails closed instead of slipping through.

func TestParseVerifierRejectsShort(t *testing.T) {
	// A buffer no longer than the ed25519 prefix has no ML-DSA bytes to parse.
	if _, err := ParseVerifier(make([]byte, ed25519.PublicKeySize)); err == nil {
		t.Fatal("a too-short verifier must be rejected")
	}
	// A long-enough length but rubbish ML-DSA bytes must fail in NewPublicKey.
	if _, err := ParseVerifier(make([]byte, ed25519.PublicKeySize+8)); err == nil {
		t.Fatal("a verifier with invalid ml-dsa bytes must be rejected")
	}
}

func TestParseSignerRejectsShort(t *testing.T) {
	if _, err := ParseSigner(make([]byte, ed25519.SeedSize)); err == nil {
		t.Fatal("a too-short signer must be rejected")
	}
	if _, err := ParseSigner(make([]byte, ed25519.SeedSize+8)); err == nil {
		t.Fatal("a signer with invalid ml-dsa bytes must be rejected")
	}
}

func TestParseKEMPublicRejectsWrongMLKEMLength(t *testing.T) {
	// Right outer length is gated separately; here a too-short ML-KEM half (via
	// NewHybridPublic) must be rejected by NewEncapsulationKey1024.
	_, pub := newRecipient(t)
	if _, err := NewHybridPublic(pub.X25519.Bytes(), make([]byte, 1567)); err == nil {
		t.Fatal("a wrong-length ml-kem encapsulation key must be rejected")
	}
}

func TestNewHybridPublicRejectsBadX25519(t *testing.T) {
	// A wrong-length X25519 public key must be rejected before the ML-KEM half is seen.
	if _, err := NewHybridPublic(make([]byte, 16), make([]byte, 1568)); err == nil {
		t.Fatal("a wrong-length x25519 public key must be rejected")
	}
}

func TestDecapsulateHybridRejectsWrongLength(t *testing.T) {
	priv, _ := newRecipient(t)
	if _, err := DecapsulateHybrid(priv, []byte("short")); err == nil {
		t.Fatal("a wrong-length hybrid ciphertext must be rejected")
	}
}

func TestDecapsulateHybridRejectsBadEphemeralShare(t *testing.T) {
	priv, pub := newRecipient(t)
	_, ct, err := EncapsulateHybrid(pub)
	if err != nil {
		t.Fatal(err)
	}
	// The trailing 32 bytes are the X25519 ephemeral share. A wrong length there is
	// caught by the length guard, so corrupt the ML-KEM half instead: it must surface
	// as a decapsulate-stage rejection rather than a silent wrong secret.
	bad := bytes.Clone(ct)
	bad[0] ^= 0xff
	// ML-KEM decapsulation is designed not to error on a flipped ciphertext (implicit
	// rejection yields a different secret), so this asserts the recovered secret differs
	// from the genuine one rather than expecting an error.
	good, err := DecapsulateHybrid(priv, ct)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecapsulateHybrid(priv, bad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(good, got) {
		t.Fatal("a flipped hybrid ciphertext must not decapsulate to the genuine secret")
	}
}

func TestVerifyRejectsTooShortSignature(t *testing.T) {
	_, verifier, err := GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify([]byte("msg"), make([]byte, ed25519.SignatureSize-1)); err == nil {
		t.Fatal("a signature shorter than the ed25519 half must be rejected")
	}
}

func TestVerifyRejectsTamperedHalves(t *testing.T) {
	signer, verifier, err := GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("a message to sign")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a bit in the ed25519 half: verification must fail on the classical check.
	edBad := bytes.Clone(sig)
	edBad[0] ^= 0x01
	if err := verifier.Verify(msg, edBad); err == nil {
		t.Fatal("a tampered ed25519 half must fail verification")
	}
	// Flip a bit in the ML-DSA half: verification must fail on the post-quantum check.
	mBad := bytes.Clone(sig)
	mBad[ed25519.SignatureSize] ^= 0x01
	if err := verifier.Verify(msg, mBad); err == nil {
		t.Fatal("a tampered ml-dsa half must fail verification")
	}
}

func TestOpenNonSecretSegmentRejectsBadFrame(t *testing.T) {
	master := make([]byte, 32)
	var segID [48]byte
	// Not a valid container frame, so UnframeContainer must reject it.
	if _, err := OpenNonSecretSegment(master, segID, spec.CodecNone, []byte("not a frame")); err == nil {
		t.Fatal("a non-segment frame must be rejected")
	}
}

func TestOpenSecretsSegmentRejectsBadFrame(t *testing.T) {
	master := make([]byte, 32)
	recordID := make([]byte, 16)
	recordSalt := make([]byte, 16)
	runID := make([]byte, 16)
	var segID [48]byte
	if _, err := OpenSecretsSegment(master, segID, SecretsSegmentParams{RecordID: recordID, RecordSalt: recordSalt, RunIDBytes: runID}, []byte("nope")); err == nil {
		t.Fatal("a non-segment frame must be rejected for the secrets class")
	}
}

func TestSealStreamRejectsWrongNonceLength(t *testing.T) {
	var key [32]byte
	// A nonce of the wrong size must be rejected by streamAEAD before any sealing.
	if _, err := SealStream(key, []byte("data"), make([]byte, 8)); err == nil {
		t.Fatal("a wrong-length payload nonce must be rejected on seal")
	}
}

func TestOpenStreamRejectsTruncation(t *testing.T) {
	var key [32]byte
	// Shorter than the payload nonce.
	if _, err := OpenStream(key, []byte{0x01}); err == nil {
		t.Fatal("a payload shorter than the nonce must be rejected")
	}
	// A valid-length nonce but a final chunk shorter than the AEAD tag.
	nonce := make([]byte, spec.StreamNonceSize)
	if _, err := OpenStream(key, nonce); err == nil {
		t.Fatal("a final chunk shorter than the tag must be rejected")
	}
}

func TestOpenStreamRejectsTamperedChunk(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 3)
	}
	nonce := make([]byte, spec.StreamNonceSize)
	sealed, err := SealStream(key, []byte("a chunk of plaintext to tamper with"), nonce)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the ciphertext body: the AEAD tag must reject it.
	sealed[len(sealed)-1] ^= 0x01
	if _, err := OpenStream(key, sealed); err == nil {
		t.Fatal("a tampered final chunk must fail authentication")
	}
}

func TestOpenSegmentRejectsWrongKey(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i)
	}
	nonce := make([]byte, 16)
	id, sealed, err := SealNonSecretSegment(master, "dp-test", spec.AddrSingleNonSecret, spec.CodecNone, []byte("the segment plaintext"), nonce)
	if err != nil {
		t.Fatal(err)
	}
	// Opening with a different master derives a different file key, so the AEAD tag
	// must fail rather than return wrong plaintext.
	otherMaster := make([]byte, 32)
	for i := range otherMaster {
		otherMaster[i] = byte(i + 1)
	}
	if _, err := OpenNonSecretSegment(otherMaster, id, spec.CodecNone, sealed); err == nil {
		t.Fatal("opening a non-secret segment under the wrong master must fail the AEAD tag")
	}
}
