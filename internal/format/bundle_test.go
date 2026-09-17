package format

import (
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
)

func TestBundleWriteVerify(t *testing.T) {
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	store := memStore{}
	files := map[string][]byte{
		"FORMAT.md":  []byte("the spec"),
		"RECOVER.md": []byte("how to recover"),
	}
	put := func(key string, b []byte) error { store[key] = b; return nil }
	if err := WriteBundle(put, files, signer); err != nil {
		t.Fatal(err)
	}
	if _, ok := store[BundlePrefix+"SHA384SUMS.sig"]; !ok {
		t.Fatal("the bundle must carry a signed SHA384SUMS")
	}
	if err := VerifyBundle(store.Get, verifier); err != nil {
		t.Fatalf("a well-formed bundle must verify: %v", err)
	}

	// Tampering a bundle file must fail.
	store[BundlePrefix+"FORMAT.md"] = []byte("tampered spec")
	if err := VerifyBundle(store.Get, verifier); err == nil {
		t.Fatal("a tampered bundle file must fail verification")
	}

	// A different signer must fail.
	_, other, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	store[BundlePrefix+"FORMAT.md"] = files["FORMAT.md"]
	if err := VerifyBundle(store.Get, other); err == nil {
		t.Fatal("a bundle signed by a different signer must fail")
	}
}

// TestVerifyBundleMalformedSumsLine exercises the strings.Cut failure branch in
// VerifyBundle: a SHA384SUMS line that lacks the required double-space separator must be
// rejected even when the SHA384SUMS signature is valid. Because the signature is checked
// first, the malformed SUMS is re-signed with the same signer so the parse branch, not the
// signature check, is the one under test.
func TestVerifyBundleMalformedSumsLine(t *testing.T) {
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	store := memStore{}
	put := func(key string, b []byte) error { store[key] = b; return nil }
	if err := WriteBundle(put, map[string][]byte{"FORMAT.md": []byte("the spec")}, signer); err != nil {
		t.Fatal(err)
	}

	// Replace SHA384SUMS with a line missing the double-space separator, then re-sign it
	// so the signature check passes and execution reaches the strings.Cut branch.
	malformed := []byte(SHA384Hex([]byte("the spec")) + " FORMAT.md\n")
	store[BundlePrefix+"SHA384SUMS"] = malformed
	sig, err := signer.Sign(malformed)
	if err != nil {
		t.Fatal(err)
	}
	store[BundlePrefix+"SHA384SUMS.sig"] = []byte(B64Encode(sig))

	if err := VerifyBundle(store.Get, verifier); err == nil {
		t.Fatal("a SHA384SUMS line without the double-space separator must fail verification")
	}
}
