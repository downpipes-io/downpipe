package format

import (
	"sort"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
)

// This file opens the recovery bundle that ships INSIDE every committed archive vector
// (SPEC.md 3, 9) and holds its bytes to the signature they were written under. Without it,
// a corrupted or tampered bundle file inside the shipped conformance corpus would not be
// caught: VerifyBundle is exercised directly by bundle_test.go and by
// cmd/downpipe/bundle_attest_test.go's --check-bundle path, but neither reads the actual
// committed bundle bytes an escrow recoverer or a clean-room re-implementer is pointed at
// (SPEC.md 14.1). A test that exercises the code and a test that exercises the committed
// bytes are different tests.
//
// The four questions, answered for this coverage:
//
// The four questions, answered for this coverage:
//
//  1. Does it run in CI? Yes: it is a t.Run subtest of TestConformance, which the
//     CI-pinned `go test -race -shuffle=on ./...` already runs unconditionally.
//  2. Does it FAIL when it cannot run? Yes. A bundle whose SHA384SUMS or SHA384SUMS.sig
//     is absent fails VerifyBundle, which is a t.Fatalf here for a must-verify vector;
//     an override entry with no Reason is a t.Fatalf regardless of outcome.
//  3. Does it FAIL when there is nothing to check? Yes, twice over. It rides inside
//     replayVector, which TestConformance reaches only once the expectedVectorNames
//     corpus floor is satisfied, so a deleted vector refuses by name before this runs.
//     And within a vector, a SHA384SUMS listing no files would verify happily (a signed
//     empty list is a valid signed list), so the listed set is asserted equal to
//     bundleRequiredFiles rather than merely non-empty.
//  4. What can it fail on? All 49 archive vectors; the four KAT vectors carry no archive
//     and TestConformance routes them elsewhere. 48 are asserted to verify with no
//     override. One, recovery-bundle-tampered, is the deliberate negative and is asserted
//     to FAIL, which is the stronger assertion for it: its expect.json only says the open
//     is refused, and this says the refusal comes from the bundle.
//
// What it structurally CANNOT catch: a bundle whose FORMAT.md and RECOVER.md are wrong
// but internally consistent and correctly signed. This gate binds the bytes to their
// signature, not the prose to the specification. cmd/downpipe/identity_source_test.go
// holds the selftest writer's RECOVER.md to specific claims; nothing holds a committed
// vector's bundle prose, and that is a separate, narrower gap.

// bundleRequiredFiles is the exact set of hashed files SPEC.md 3 and 9 put in a
// downpipe/0.1.0 bundle. Asserting the set, not just its size, means a bundle that hashed
// only one of the two, or hashed some third file, is a failure rather than a pass.
var bundleRequiredFiles = []string{"FORMAT.md", "RECOVER.md"}

// bundleExpectation names a vector whose committed bundle is deliberately NOT expected to
// verify, with the reason. A vector absent from bundleOverrides must verify: it is a
// shipped, signed archive and a recoverer relying on its bundled instructions must be able
// to confirm they were not altered (SPEC.md 8.7 item 4).
type bundleExpectation struct {
	// MustVerify is what VerifyBundle must produce for this vector's committed bundle.
	MustVerify bool
	// MismatchedFiles, on a MustVerify:false vector, is the EXACT set of listed bundle
	// files whose committed bytes must not match their signed SHA-384. It is what stops a
	// negative from passing on the wrong grounds: "the bundle does not verify" is satisfied
	// by a broken signature, a rewritten SHA384SUMS or a corrupted second file just as
	// happily as by the tamper the vector is meant to encode. Naming the set means the
	// SHA384SUMS and its signature must still be sound, and every file NOT named must still
	// match, so three of this vector's four bundle objects are pinned by their signature and
	// the fourth is pinned to being wrong.
	MismatchedFiles []string
	// Reason is mandatory (replayBundle fails the vector if it is empty) and states why
	// this vector's bundle diverges from the corpus-wide expectation.
	Reason string
}

// Derived by measurement, not assumed: with this map empty, the walk flagged exactly ONE
// of the 49 archive vectors, and that one is the deliberate bundle negative. Every other
// negative vector in the corpus (bad-signature, absent-signature, unknown-signer,
// single-half-signature, forged-capsule-wrap and the rest) tampers something other than
// the bundle, so its bundle both does and should still verify against its own signer.pub.
// That is the answer for THIS corpus: one exception, not a class of them.
var bundleOverrides = map[string]bundleExpectation{
	"recovery-bundle-tampered": {
		MustVerify:      false,
		MismatchedFiles: []string{"FORMAT.md"},
		Reason: "this is the corpus's deliberate bundle negative (SPEC.md 14.3): its FORMAT.md " +
			"was altered after signing, so VerifyBundle must reject it and Open with " +
			"CheckRecoveryBundle must exit 2 with recoveryBundleVerified false, which its " +
			"expect.json already asserts. Pinning it here says WHERE the refusal comes from: " +
			"the expect.json assertion alone is satisfied by any unverifiable bundle, so a " +
			"vector whose bundle broke for some unrelated reason would still have passed it.",
	},
}

// bundleExpectFor returns the expectation for the named vector's committed bundle, and
// whether it came from an explicit, reasoned override rather than the corpus-wide default.
func bundleExpectFor(name string) (exp bundleExpectation, overridden bool) {
	if o, ok := bundleOverrides[name]; ok {
		return o, true
	}
	return bundleExpectation{MustVerify: true}, false
}

// replayBundle runs VerifyBundle over one vector's COMMITTED archive objects, against that
// vector's own signer.pub, and asserts the expectation bundleExpectFor computes.
func replayBundle(t *testing.T, name string, store ObjectStore, verifier *crypto.HybridVerifier) {
	t.Helper()
	want, overridden := bundleExpectFor(name)
	if overridden && want.Reason == "" {
		t.Fatalf("bundle override for %q has no Reason: an unexplained divergence is how a real gap hides", name)
	}

	err := VerifyBundle(store.Get, verifier)
	switch {
	case want.MustVerify && err != nil:
		t.Fatalf("vector %s: its committed recovery bundle does not verify against its own signer.pub: %v. "+
			"These are the in-bucket recovery instructions a recoverer holding nothing but the bucket "+
			"reads (SPEC.md 9). Regenerate the vector with `go test ./internal/format -run TestConformance "+
			"-update -update-only %s`; do NOT edit the vector or this expectation to make the failure go away.",
			name, err, name)
	case !want.MustVerify && err == nil:
		t.Fatalf("vector %s: its committed recovery bundle VERIFIES, but this vector is pinned as one that "+
			"must not (%s). The negative has stopped being negative.", name, want.Reason)
	}

	// The bundle's file list is read from the SHA384SUMS bytes either way. On a must-verify
	// vector VerifyBundle has already bound those bytes to the signature; on a negative the
	// binding is re-established below before the list is trusted.
	sums, err := store.Get(BundlePrefix + "SHA384SUMS")
	if err != nil {
		t.Fatalf("vector %s: read the bundle SHA384SUMS: %v", name, err)
	}

	if !want.MustVerify {
		assertBundleNegative(t, name, store, verifier, sums, want)
		return
	}

	// A signed SHA384SUMS listing no files verifies happily, so the signature check alone
	// is not enough: pin the set of files the bundle actually hashes.
	got := bundleListedNames(t, name, string(sums))
	if strings.Join(got, ",") != strings.Join(bundleRequiredFiles, ",") {
		t.Fatalf("vector %s: its bundle SHA384SUMS hashes %v, not the %v SPEC.md 3 and 9 require. "+
			"A bundle that verifies while hashing the wrong set binds nothing a recoverer reads.",
			name, got, bundleRequiredFiles)
	}
}

// assertBundleNegative holds a deliberate bundle negative to the EXACT divergence it
// encodes: the SHA384SUMS and its detached signature must still be sound, the listed set
// must still be the SPEC.md set, and the files whose bytes fail their signed hash must be
// exactly want.MismatchedFiles. Without this a negative vector passes on any breakage,
// which is how a corpus rots quietly behind an assertion that still reads as strict.
func assertBundleNegative(t *testing.T, name string, store ObjectStore, verifier *crypto.HybridVerifier, sums []byte, want bundleExpectation) {
	t.Helper()
	if len(want.MismatchedFiles) == 0 {
		t.Fatalf("bundle override for %q expects a failure but names no MismatchedFiles, so the vector "+
			"would pass on any breakage at all", name)
	}
	sigText, err := store.Get(BundlePrefix + "SHA384SUMS.sig")
	if err != nil {
		t.Fatalf("vector %s: read the bundle SHA384SUMS.sig: %v", name, err)
	}
	sig, err := B64Decode(strings.TrimSpace(string(sigText)))
	if err != nil {
		t.Fatalf("vector %s: its bundle SHA384SUMS.sig does not decode (%v); this negative is meant to "+
			"encode an altered bundle FILE, not a broken signature object", name, err)
	}
	if err := verifier.Verify(sums, sig); err != nil {
		t.Fatalf("vector %s: its bundle SHA384SUMS no longer carries a good signature (%v); this negative "+
			"is meant to encode an altered bundle FILE under an intact signature, so the refusal now comes "+
			"from somewhere other than the tamper it documents", name, err)
	}
	listed := bundleListedNames(t, name, string(sums))
	if strings.Join(listed, ",") != strings.Join(bundleRequiredFiles, ",") {
		t.Fatalf("vector %s: its bundle SHA384SUMS hashes %v, not the %v SPEC.md 3 and 9 require",
			name, listed, bundleRequiredFiles)
	}

	var mismatched []string
	for _, line := range strings.Split(string(sums), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		hash, file, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("vector %s: malformed SHA384SUMS line: %q", name, line)
		}
		data, err := store.Get(BundlePrefix + file)
		if err != nil {
			t.Fatalf("vector %s: read bundle file %s: %v", name, file, err)
		}
		if SHA384Hex(data) != hash {
			mismatched = append(mismatched, file)
		}
	}
	sort.Strings(mismatched)
	wantMismatched := append([]string(nil), want.MismatchedFiles...)
	sort.Strings(wantMismatched)
	if strings.Join(mismatched, ",") != strings.Join(wantMismatched, ",") {
		t.Fatalf("vector %s: the bundle files failing their signed SHA-384 are %v, but this negative "+
			"encodes exactly %v (%s). Every other listed file must still match its signed hash.",
			name, mismatched, wantMismatched, want.Reason)
	}
}

// bundleListedNames returns the sorted file names a verified SHA384SUMS lists. It parses
// the same "hash  name" form WriteBundle emits and VerifyBundle reads.
func bundleListedNames(t *testing.T, vector, sums string) []string {
	t.Helper()
	var names []string
	for _, line := range strings.Split(sums, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		_, name, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("vector %s: malformed SHA384SUMS line after it verified: %q", vector, line)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
