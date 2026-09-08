package format

import (
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// runRecipients parses the run's signed root from the store and returns its recipient
// list, so a test can assert which fingerprints a wrong-key error should enumerate
// without buildArchive having to expose them.
func runRecipients(t *testing.T, store memStore, runID string) []spec.Recipient {
	t.Helper()
	rootBytes, err := store.Get(runKey(runID, "root.manifest.json"))
	if err != nil {
		t.Fatalf("read root: %v", err)
	}
	root, err := ParseRoot(rootBytes)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	return root.Recipients
}

// Opening a run with an identity that opens none of its wraps must fail loud, and the
// error must enumerate the run's signed recipient fingerprints with their roles, so a
// recoverer holding a rotated key learns which key the run actually needs.
func TestOpenWrongIdentityErrorEnumeratesRecipients(t *testing.T) {
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	store := memStore{}
	_, verifier := buildArchive(t, buildSpec{store: store, runID: runID, dpID: "dp_test", value: []byte("recover me"), secret: false, codec: spec.CodecNameNone})

	recips := runRecipients(t, store, runID)
	if len(recips) != 2 {
		t.Fatalf("fixture should list 2 recipients, got %d", len(recips))
	}

	wrongPriv, _, err := crypto.GenerateHybridKEM()
	if err != nil {
		t.Fatal(err)
	}

	_, err = Open(store, runID, wrongPriv, verifier, Options{})
	if err == nil {
		t.Fatal("opening with a non-recipient identity must fail")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unwrap master capsule") {
		t.Fatalf("error %q should be the unwrap-master failure", msg)
	}
	for _, rc := range recips {
		if !strings.Contains(msg, rc.Role+" "+rc.Fingerprint) {
			t.Fatalf("error %q must name the run's %s recipient %q", msg, rc.Role, rc.Fingerprint)
		}
	}
}

// The wrong-key error must also name the held identity's fingerprint, so the recoverer
// can see both what they hold and what the run wants side by side.
func TestOpenWrongIdentityErrorNamesHeldFingerprint(t *testing.T) {
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	store := memStore{}
	_, verifier := buildArchive(t, buildSpec{store: store, runID: runID, dpID: "dp_test", value: []byte("recover me"), secret: false, codec: spec.CodecNameNone})

	wrongPriv, wrongPub, err := crypto.GenerateHybridKEM()
	if err != nil {
		t.Fatal(err)
	}
	heldFP := crypto.RecipientFingerprint(wrongPub)

	_, err = Open(store, runID, wrongPriv, verifier, Options{})
	if err == nil {
		t.Fatal("opening with a non-recipient identity must fail")
	}
	if !strings.Contains(err.Error(), "no wrap matches the held identity "+heldFP) {
		t.Fatalf("error %q must name the held identity %q", err.Error(), heldFP)
	}
}

// signerMismatchHint must self-gate: it explains a ROTATION only when the archive's declared
// signing-key fingerprint differs from the pinned verifier's, and stays silent (message
// unchanged) for a matching fingerprint (a genuine tamper), an absent field, or unreadable
// root bytes. This keeps the rotation guidance from misfiring on a corrupted-but-same-signer
// archive.
func TestSignerMismatchHintSelfGates(t *testing.T) {
	_, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	pinnedFP := crypto.SignerFingerprint(verifier)

	// matching fingerprint -> no hint (tamper/corruption, not a rotation)
	if h := signerMismatchHint([]byte(`{"signingKeyFingerprint":"`+pinnedFP+`"}`), verifier); h != "" {
		t.Fatalf("a matching fingerprint must yield NO rotation hint, got %q", h)
	}
	// unreadable root -> no hint
	if h := signerMismatchHint([]byte("not json at all"), verifier); h != "" {
		t.Fatalf("unreadable root bytes must yield no hint, got %q", h)
	}
	// absent fingerprint field -> no hint
	if h := signerMismatchHint([]byte(`{"runId":"x"}`), verifier); h != "" {
		t.Fatalf("an absent fingerprint must yield no hint, got %q", h)
	}
	// different fingerprint -> a hint that states this is a REFUSAL (not a transient error),
	// names both fingerprints, and still offers the rotation path with the --signer guidance
	h := signerMismatchHint([]byte(`{"signingKeyFingerprint":"edmldsa1:deadbeefcafe"}`), verifier)
	for _, want := range []string{"refusal to trust", "not a transient error", "--signer", "edmldsa1:deadbeefcafe", pinnedFP} {
		if !strings.Contains(h, want) {
			t.Fatalf("a differing fingerprint must yield a hint containing %q, got %q", want, h)
		}
	}
}

// End-to-end: restoring an archive under a ROTATED pinned signer (the owner's "keys rolled"
// DR case) must fail loud AND the operator-visible error must say this is a refusal to trust,
// not a transient error, while still naming the archive's signing-key fingerprint, the pinned
// one, and the actionable --signer guidance for the genuine-rotation case -- not just the
// opaque "wrong-signer". Mirrors the engine reader's signerMismatchHint so the offline DR
// restore and the online restore agree.
func TestOpenWrongSignerErrorExplainsRotation(t *testing.T) {
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	store := memStore{}
	// buildArchive seals + signs the run with signer A and returns the break-glass KEM key
	// (so the capsule still opens; the signature gate is reached before the unwrap).
	priv, _ := buildArchive(t, buildSpec{store: store, runID: runID, dpID: "dp_test", value: []byte("recover me"), secret: false, codec: spec.CodecNameNone})

	// The archive's declared signer fingerprint, read from its (untrusted) root.
	rootBytes, err := store.Get(runKey(runID, "root.manifest.json"))
	if err != nil {
		t.Fatalf("read root: %v", err)
	}
	root, err := ParseRoot(rootBytes)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	archFP := root.SigningKeyFingerprint
	if archFP == "" {
		t.Fatal("fixture root must carry a signingKeyFingerprint for this test")
	}

	// A DIFFERENT (rotated) signer than the one that sealed the archive.
	_, rotated, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	pinnedFP := crypto.SignerFingerprint(rotated)
	if pinnedFP == archFP {
		t.Fatal("rotated signer must differ from the archive signer")
	}

	_, err = Open(store, runID, priv, rotated, Options{})
	if err == nil {
		t.Fatal("opening an archive under a rotated pinned signer must fail loud")
	}
	msg := err.Error()
	for _, want := range []string{"wrong-signer", "refusal to trust", "not a transient error", "--signer", archFP, pinnedFP} {
		if !strings.Contains(msg, want) {
			t.Fatalf("rotated-signer restore error %q must contain %q", msg, want)
		}
	}
}
