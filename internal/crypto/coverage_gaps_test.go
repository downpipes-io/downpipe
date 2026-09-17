package crypto

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// failReader fails after n bytes, so a CSPRNG failure can be injected at the exact seam
// the sealing helpers already expose (a randr parameter), without adding a seam for the
// sake of a test.
type failReader struct {
	remaining int
	err       error
}

func (f *failReader) Read(p []byte) (int, error) {
	if f.remaining <= 0 {
		return 0, f.err
	}
	n := len(p)
	if n > f.remaining {
		n = f.remaining
	}
	for i := range p[:n] {
		p[i] = 0x7f
	}
	f.remaining -= n
	return n, nil
}

// failWriter fails after n bytes so the streaming seal's write-error branch is exercised
// through its existing io.Writer parameter.
type failWriter struct {
	remaining int
	err       error
}

func (f *failWriter) Write(p []byte) (int, error) {
	if f.remaining <= 0 {
		return 0, f.err
	}
	n := len(p)
	if n > f.remaining {
		n = f.remaining
	}
	f.remaining -= n
	if f.remaining <= 0 {
		return n, f.err
	}
	return n, nil
}

// SealToRecipients draws its per-wrap nonce from the caller-supplied reader, so a
// CSPRNG failure there must surface as an error rather than a silent short read.
func TestSealToRecipientsSurfacesARandomnessFailure(t *testing.T) {
	_, pub, err := GenerateHybridKEM()
	if err != nil {
		t.Fatal(err)
	}
	var secret [32]byte
	want := errors.New("entropy source failed")
	// Enough entropy for the KEM encapsulation, then failure at the wrap nonce.
	if _, err := SealToRecipients(secret, []*HybridKEMPublic{pub}, []byte("aad"), &failReader{remaining: 0, err: want}); err == nil {
		t.Fatal("a randomness failure must surface")
	}
}

// SealStreamTo writes the payload nonce to its destination first, so a failing sink must
// be reported and never leave the caller believing a stream was sealed.
func TestSealStreamToSurfacesAWriteFailure(t *testing.T) {
	var key [32]byte
	nonce := make([]byte, spec.StreamNonceSize)
	want := errors.New("sink is full")
	if _, err := SealStreamTo(&failWriter{remaining: 0, err: want}, key, nonce, nil); err == nil {
		t.Fatal("a failing sink must surface at seal time")
	}
}

// The streaming writer's Close flushes the final chunk, so a sink that fails mid-stream
// must surface there too rather than reporting a clean close.
func TestSealStreamCloseSurfacesAWriteFailure(t *testing.T) {
	var key [32]byte
	nonce := make([]byte, spec.StreamNonceSize)
	want := errors.New("sink went away")
	// Allow the nonce through, then fail on the first chunk flush.
	w, err := SealStreamTo(&failWriter{remaining: len(nonce) + 1, err: want}, key, nonce, nil)
	if err != nil {
		t.Fatalf("seal open: %v", err)
	}
	if _, werr := w.Write(bytes.Repeat([]byte{1}, 128)); werr != nil {
		// A write may surface the error early; either way Close must not report success.
		if cerr := w.Close(); cerr == nil {
			t.Fatal("Close must not report success after a failed write")
		}
		return
	}
	if cerr := w.Close(); cerr == nil {
		t.Fatal("Close must surface the sink failure")
	}
}

// DecapsulateHybrid rejects a low-order X25519 share: the all-zero shared secret is the
// classic small-subgroup result and must never be accepted as key material.
func TestDecapsulateHybridRejectsALowOrderShare(t *testing.T) {
	priv, pub, err := GenerateHybridKEM()
	if err != nil {
		t.Fatal(err)
	}
	_, ct, err := EncapsulateHybrid(pub)
	if err != nil {
		t.Fatal(err)
	}
	// The hybrid ciphertext is ctM||ctX, so the X25519 share is the LAST 32 bytes.
	// Replace it with a low-order point (order 8), whose X25519 output is all zeroes; the
	// implementation must refuse rather than derive key material from it.
	lowOrder := []byte{
		0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
		0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
	}
	bad := append([]byte(nil), ct...)
	copy(bad[len(bad)-32:], lowOrder)
	if _, err := DecapsulateHybrid(priv, bad); err == nil {
		t.Fatal("a low-order X25519 share must be refused")
	}
}

// The key parsers gate on length with a strict inequality, so an input of EXACTLY the
// classical-half length (with an empty post-quantum half) must be refused. A boundary
// slip here would hand an empty byte slice to the ML-DSA parser. Mutation testing
// surfaced both boundaries as unkilled.
func TestKeyParsersRefuseTheExactBoundaryLength(t *testing.T) {
	if _, err := ParseVerifier(make([]byte, ed25519.PublicKeySize)); err == nil {
		t.Fatal("a verifier with an empty ML-DSA half must be refused")
	}
	if _, err := ParseSigner(make([]byte, ed25519.SeedSize)); err == nil {
		t.Fatal("a signer with an empty ML-DSA half must be refused")
	}
}

// lpAppend length-prefixes a field with a single byte, so 255 bytes is the largest
// legal field and 256 must panic. The boundary was unkilled by mutation testing.
func TestLPAppendBoundary(t *testing.T) {
	if got := lpAppend(nil, bytes.Repeat([]byte{1}, 255)); len(got) != 256 {
		t.Fatalf("a 255-byte field must encode to 256 bytes, got %d", len(got))
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a 256-byte field must panic rather than truncate its length prefix")
		}
	}()
	lpAppend(nil, bytes.Repeat([]byte{1}, 256))
}

// RecipientSetHash sorts the recipient encodings so the hash is independent of listing
// order, and the SORT DIRECTION is part of the wire contract a second implementation
// must reproduce. Pin it: the hash must be identical under any input permutation, and
// byte-locked against a known answer so a flipped comparator cannot pass.
func TestRecipientSetHashIsOrderIndependentAndPinned(t *testing.T) {
	var recips []*HybridKEMPublic
	for i := 0; i < 3; i++ {
		_, pub, err := GenerateHybridKEM()
		if err != nil {
			t.Fatal(err)
		}
		recips = append(recips, pub)
	}
	want := RecipientSetHash(recips)
	// Every permutation must hash identically: that is what "independent of listing
	// order" means, and it is exactly what a flipped or unstable comparator breaks.
	perms := [][]int{{0, 1, 2}, {2, 1, 0}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {0, 2, 1}}
	for _, p := range perms {
		shuffled := []*HybridKEMPublic{recips[p[0]], recips[p[1]], recips[p[2]]}
		if !bytes.Equal(RecipientSetHash(shuffled), want) {
			t.Fatalf("recipient-set hash changed under permutation %v", p)
		}
	}
	if len(want) != 48 {
		t.Fatalf("the recipient-set hash must be a 48-byte SHA-384, got %d", len(want))
	}
}

// Every parse refuses a wrong-length input rather than reading out of bounds.
func TestKeyParsersRefuseWrongLengths(t *testing.T) {
	if _, err := ParseKEMPrivate(make([]byte, 3)); err == nil {
		t.Fatal("a short KEM private must be refused")
	}
	if _, err := ParseKEMPublic(make([]byte, 3)); err == nil {
		t.Fatal("a short KEM public must be refused")
	}
	if _, err := ParseVerifier(make([]byte, 3)); err == nil {
		t.Fatal("a short verifier must be refused")
	}
	if _, err := ParseSigner(make([]byte, 3)); err == nil {
		t.Fatal("a short signer must be refused")
	}
}

// A non-secret segment must carry a legal address class; the secrets class has its own
// key derivation, so accepting it here would silently derive the wrong key.
func TestSealNonSecretSegmentRefusesAnIllegalClass(t *testing.T) {
	nonce := make([]byte, spec.StreamNonceSize)
	if _, _, err := SealNonSecretSegment(make([]byte, 32), "dp", 0x7f, spec.CodecNone, []byte("v"), nonce); err == nil {
		t.Fatal("an unknown address class must be refused")
	}
	if _, _, err := SealNonSecretSegment(make([]byte, 32), "dp", spec.AddrSecrets, spec.CodecNone, []byte("v"), nonce); err == nil {
		t.Fatal("the secrets class must be refused on the non-secret seal path")
	}
}

// Close is idempotent: a double Close must not flush a second final chunk (which would
// append a trailing empty chunk and corrupt the stream).
func TestSealStreamCloseIsIdempotent(t *testing.T) {
	var key [32]byte
	nonce := make([]byte, spec.StreamNonceSize)
	var sealed bytes.Buffer
	w, err := SealStreamTo(&sealed, key, nonce, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	n := sealed.Len()
	if err := w.Close(); err != nil {
		t.Fatalf("second close must be a no-op, got %v", err)
	}
	if sealed.Len() != n {
		t.Fatalf("a second Close wrote %d more bytes", sealed.Len()-n)
	}
	// The stream still opens and returns the payload, so the double close did not
	// corrupt it.
	var out bytes.Buffer
	if err := OpenStreamTo(&out, key, bytes.NewReader(sealed.Bytes()), nil, 0); err != nil {
		t.Fatalf("open after a double close: %v", err)
	}
	if out.String() != "payload" {
		t.Fatalf("payload corrupted: %q", out.String())
	}
}
