package format

import (
	"bytes"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

func sampleRoot() *spec.RootManifest {
	return &spec.RootManifest{
		FormatVersion:       spec.Version,
		RunID:               "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		CreatedAt:           "2026-06-06T12:00:00.000Z",
		DownpipeID:          "dp_1",
		Envelope:            spec.Envelope{AEAD: "AES-256-GCM", KEM: "X25519+ML-KEM-1024", Signature: "Ed25519+ML-DSA-87", KDF: "HKDF-SHA-384", ChunkSize: spec.ChunkSize, Codec: "none"},
		BreakGlassPresent:   true,
		ShardCount:          0,
		DeclaredRecordCount: 3,
		MerkleRoot:          "deadbeef",
	}
}

func TestSignAndVerifyRoot(t *testing.T) {
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	m := sampleRoot()

	canonical, sig, err := SignRoot(m, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRootBytes(canonical, sig, verifier); err != nil {
		t.Fatalf("a valid signature was rejected: %v", err)
	}

	bad := bytes.Clone(canonical)
	bad[10] ^= 0x01
	if err := VerifyRootBytes(bad, sig, verifier); err == nil {
		t.Fatal("a tampered root manifest must fail verification")
	}

	parsed, err := ParseRoot(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.RunID != m.RunID || parsed.Envelope.AEAD != "AES-256-GCM" {
		t.Fatal("the parsed manifest does not match the original")
	}

	// Re-canonicalising the parsed manifest must reproduce the stored bytes, so the
	// reader can verify the signature it was given.
	again, err := MarshalRoot(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, canonical) {
		t.Fatal("re-canonicalised manifest differs from the stored bytes")
	}

	_, otherVerifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRootBytes(canonical, sig, otherVerifier); err == nil {
		t.Fatal("a different signer must fail verification")
	}
}
