package format

import (
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// TestEnvelopeSuiteIsPinned proves the SPEC.md 5.2 rule on the read side: a root whose
// envelope aead, kem, sig, kdf or chunkSize is not the downpipe/0.1.0 value is refused
// with exit 6 by Open, StreamOpen and Attest. Each mutated root is re-signed by the
// pinned signer, so the signature gate passes and only the envelope gate can refuse it.
// The positive control opens the unmutated archive through all three paths, so a refusal
// below is caused by the mutation and not by the fixture.
func TestEnvelopeSuiteIsPinned(t *testing.T) {
	vs := vectorSpec{dpID: "dp_envsuite", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}}
	rootKey := runKey(vecRunID, "root.manifest.json")
	sigKey := runKey(vecRunID, "root.manifest.json.sig")

	cases := []struct {
		field  string
		mutate func(*spec.Envelope)
	}{
		{"aead", func(e *spec.Envelope) { e.AEAD = "ChaCha20-Poly1305" }},
		{"kem", func(e *spec.Envelope) { e.KEM = "X25519" }},
		{"sig", func(e *spec.Envelope) { e.Signature = "Ed25519" }},
		{"kdf", func(e *spec.Envelope) { e.KDF = "HKDF-SHA-256" }},
		{"chunkSize", func(e *spec.Envelope) { e.ChunkSize = 1 << 20 }},
		{"chunkSize", func(e *spec.Envelope) { e.ChunkSize = 0 }},
	}

	t.Run("control", func(t *testing.T) {
		store, identity, verifier, _ := buildArchiveSpec(t, vs)
		if _, err := Open(store, vecRunID, identity, verifier, Options{}); err != nil {
			t.Fatalf("Open of the unmutated archive: %v", err)
		}
		if _, err := StreamOpen(store, vecRunID, identity, verifier, Options{}); err != nil {
			t.Fatalf("StreamOpen of the unmutated archive: %v", err)
		}
		if _, err := Attest(store, vecRunID, verifier, 0); err != nil {
			t.Fatalf("Attest of the unmutated archive: %v", err)
		}
	})

	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			store, identity, verifier, signer := buildArchiveSpec(t, vs)
			root, err := ParseRoot(store[rootKey])
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(&root.Envelope)
			canonical, sig, err := SignRoot(root, signer)
			if err != nil {
				t.Fatal(err)
			}
			store[rootKey] = canonical
			store[sigKey] = []byte(B64Encode(sig))

			assertRefused := func(path string, err error) {
				t.Helper()
				if err == nil {
					t.Fatalf("%s accepted a root whose envelope %s is not the pinned value", path, tc.field)
				}
				code, ok := exitCodeOf(err)
				if !ok || code != ExitUsage {
					t.Fatalf("%s: want exit %d, got code %d ok=%v: %v", path, ExitUsage, code, ok, err)
				}
				if !strings.Contains(err.Error(), "envelope "+tc.field) {
					t.Fatalf("%s: refused for the wrong reason: %v", path, err)
				}
			}
			_, err = Open(store, vecRunID, identity, verifier, Options{})
			assertRefused("Open", err)
			_, err = StreamOpen(store, vecRunID, identity, verifier, Options{})
			assertRefused("StreamOpen", err)
			_, err = Attest(store, vecRunID, verifier, 0)
			assertRefused("Attest", err)
		})
	}
}
