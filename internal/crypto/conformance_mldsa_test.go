package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/mldsa"
)

// downpipe-sys-deps-01: the ML-DSA-87 signature primitive is supplied by
// filippo.io/mldsa, pinned to a pre-release pseudo-version on an explicitly-unstable
// API (see go.mod). Until the standard-library crypto/mldsa ships and the wrap moves to
// it, a silent change to that library's signature encoding between pins would let a
// freshly built reader fail to verify an archive a previous build sealed, with no
// compile error to warn us.
//
// This conformance test is the upgrade-time guard. mldsa-frozen.json holds a historical
// ML-DSA-87 public key, message and signature, frozen against the current pin. Because
// the signer key is derived deterministically from a frozen seed and the signature is
// produced by SignDeterministic, every byte is reproducible, so the test asserts two
// independent things against whatever filippo.io/mldsa the build is using:
//
//  1. verification: the frozen signature still verifies under the frozen public key,
//     both through the raw library and through the shipped hybrid verify path; a broken
//     decode or a verification-semantics change fails here.
//  2. reproduction: re-deriving the key and re-signing the message from the frozen seed
//     reproduces the frozen public-key and signature bytes exactly; a signing-encoding
//     change fails here even where verification of the old bytes would still pass.
//
// A deliberate encoding change with a newer pin is then a loud, reviewed diff to the
// fixture in the same commit as the dependency bump, never a silent break.

type mldsaFrozenFixture struct {
	SeedB64      string `json:"seedB64"`
	MessageB64   string `json:"messageB64"`
	PublicKeyB64 string `json:"publicKeyB64"`
	SignatureB64 string `json:"signatureB64"`
}

func decodeB64URL(t *testing.T, what, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("frozen fixture %s is not base64url: %v", what, err)
	}
	return b
}

func loadMLDSAFrozenFixture(t *testing.T) mldsaFrozenFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "mldsa-frozen.json"))
	if err != nil {
		t.Fatalf("read frozen ML-DSA fixture: %v", err)
	}
	var fx mldsaFrozenFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse frozen ML-DSA fixture: %v", err)
	}
	return fx
}

// TestMLDSAFrozenSignatureConformance re-verifies and re-derives the frozen ML-DSA-87
// fixture against the pinned filippo.io/mldsa, so a future encoding change in the
// unstable dependency is caught at upgrade time rather than at recovery time.
func TestMLDSAFrozenSignatureConformance(t *testing.T) {
	fx := loadMLDSAFrozenFixture(t)
	seed := decodeB64URL(t, "seedB64", fx.SeedB64)
	message := decodeB64URL(t, "messageB64", fx.MessageB64)
	pubBytes := decodeB64URL(t, "publicKeyB64", fx.PublicKeyB64)
	sigBytes := decodeB64URL(t, "signatureB64", fx.SignatureB64)

	if len(pubBytes) != mldsa.MLDSA87PublicKeySize {
		t.Fatalf("frozen public key is %d bytes, want %d (the dependency changed its key encoding)", len(pubBytes), mldsa.MLDSA87PublicKeySize)
	}
	if len(sigBytes) != mldsa.MLDSA87SignatureSize {
		t.Fatalf("frozen signature is %d bytes, want %d (the dependency changed its signature encoding)", len(sigBytes), mldsa.MLDSA87SignatureSize)
	}

	// (1) The frozen signature must still verify under the frozen public key with the
	// current pin. This is the core "an archive sealed by an earlier build still
	// verifies" guarantee.
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA87(), pubBytes)
	if err != nil {
		t.Fatalf("the pinned library could not decode the frozen public key: %v", err)
	}
	if err := mldsa.Verify(pub, message, sigBytes, &mldsa.Options{}); err != nil {
		t.Fatalf("the frozen ML-DSA-87 signature no longer verifies under the current pin: %v", err)
	}

	// The same frozen signature must also verify through the shipped hybrid verify path
	// (ParseVerifier + HybridVerifier.Verify), the exact code a recovery runs, by pairing
	// it with a throwaway Ed25519 half over the same message.
	edPub, edPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := ParseVerifier(append(append([]byte(nil), edPub...), pubBytes...))
	if err != nil {
		t.Fatalf("ParseVerifier rejected the frozen ML-DSA public key: %v", err)
	}
	hybridSig := append(append([]byte(nil), ed25519.Sign(edPriv, message)...), sigBytes...)
	if err := verifier.Verify(message, hybridSig); err != nil {
		t.Fatalf("the shipped hybrid verifier rejected the frozen ML-DSA signature: %v", err)
	}

	// (2) Re-deriving the signer from the frozen seed and re-signing the frozen message
	// deterministically must reproduce the frozen public-key and signature bytes exactly.
	// This catches a signing-side encoding change that a verify-only check could miss.
	priv, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), seed)
	if err != nil {
		t.Fatalf("the pinned library could not derive the signer from the frozen seed: %v", err)
	}
	if got := priv.PublicKey().Bytes(); !bytes.Equal(got, pubBytes) {
		t.Fatal("the public key derived from the frozen seed no longer matches the frozen bytes (the dependency changed its key derivation or encoding)")
	}
	resigned, err := priv.SignDeterministic(message, &mldsa.Options{})
	if err != nil {
		t.Fatalf("deterministic re-sign failed: %v", err)
	}
	if !bytes.Equal(resigned, sigBytes) {
		t.Fatal("the deterministic ML-DSA-87 signature over the frozen message no longer matches the frozen bytes (the dependency changed its signature encoding); review the change and regenerate testdata/mldsa-frozen.json in the same commit as the pin bump")
	}
}
