package format

import (
	"errors"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
)

// This file wires format.Attest (SPEC.md 8.8) into the shared conformance corpus that
// already proves Open/StreamOpen agreement (conformance_test.go), replaying every one of
// the 49 archive vectors against Attest, signer-pinned, and asserting either exact
// exit-code parity with Open/verify or a reasoned, named override.
//
// replayAttest runs signer-pinned (the closest analogue to the verify command, which
// mandates --signer) against each vector's PRIMARY run only; a vector's "Also" sub-run (used
// for an allow-stale re-open of an older run under Open's Options) is not replayed against
// Attest, because Attest's API has no allow-stale equivalent at all: a signer-pinned Attest
// unconditionally requires the pinned run be the freshest for its downpipe. That is not a
// gap in this coverage, it is Attest's actual, tested behaviour (see attest_test.go's
// TestAttestFailsOnStaleRunWhenSignerPinned).
//
// The four questions, answered for this specific coverage:
//
//  1. Does it run in CI? Yes: it is a t.Run subtest of TestConformance, which `go test ./...`
//     and the CI-pinned `go test -race -shuffle=on ./...` both already run unconditionally,
//     no new invocation or workflow step needed.
//  2. Does it FAIL when it cannot run? Yes: an unparseable vector directory, a missing
//     signer.pub or a nil ExitError where one was expected all call t.Fatal/t.Fatalf, the
//     same fail-loud convention as replayExpect uses for load-all/streaming.
//  3. Does it FAIL when there is nothing to check? Yes: it rides inside replayVector, which
//     TestConformance only reaches once the corpus floor (expectedVectorNames) is satisfied;
//     an empty or shrunk corpus still refuses before any attest subtest would run.
//  4. How much of the corpus can it fail on at all? All 49 archive vectors (the corpus minus
//     the 4 KAT-only vectors, which carry no run to attest). 33 assert exact exit-code
//     parity with Open/verify with no override. 1 (deleted-shard) is pinned to attest's own
//     correct-but-different exit code (2, not verify's 3). 10 are pinned to an explicit,
//     reasoned override at exit 0 — Attest structurally cannot see the tamper (it needs
//     decryption, the master key, or the recovery-bundle check, none of which Attest
//     performs) — every one of those 10 fails this test loudly if Attest's actual behaviour
//     ever changes out from under its documented scope. What it structurally CANNOT catch,
//     by design or by corpus gap: (a) any defect the 10 overrides above name; (b) a defect
//     that is not represented by any of the 49 vectors at all — for example a duplicate,
//     re-cased JSON key defeating the keyless --min-runlog-index self-consistency check,
//     which no committed corpus vector's RUNLOG contains. Only the narrower unit tests
//     (attest_test.go's TestAttestKeylessRejectsCaseCollidingRunlogIndexEvenWithCanonicalKeyPresent
//     and canonnum_test.go's TestCaseCollidingDuplicateKeyIsRefusedEvenWithCanonicalKeyPresent)
//     catch that class of defect. That is arguably the right home for it regardless — the
//     corpus is meant to be cross-implementation (SPEC.md 14.1), and this defect is an
//     artefact of Go encoding/json's case-insensitive Unmarshal specifically, not a
//     byte-level format property a second, non-Go reader would necessarily reproduce — but
//     it means this conformance coverage is real and load-bearing for the 44 vectors it
//     exercises, and is NOT a substitute for the unit-level regression tests that guard
//     RUNLOG parsing edge cases the corpus does not encode.

// attestParityOverride names a conformance vector whose format.Attest exit code legitimately
// differs from the vector's own ExitCode (0 for a positive vector), together with the reason.
// A vector NOT listed here is asserted at exact exit-code parity with its own outcome: attest
// must fail with exp.ExitCode on a negative vector, and pass clean on a positive one.
type attestParityOverride struct {
	// ExitCode is what format.Attest actually, correctly produces for this vector: 0 means
	// attest passes clean even though the vector is a negative (out of attest's scope).
	ExitCode int
	// Reason is mandatory (replayAttest fails the vector if it is empty) and states, in
	// terms of SPEC.md 8.8's documented scope, WHY attest's outcome differs here.
	Reason string
}

var attestParityOverrides = map[string]attestParityOverride{
	"deleted-shard": {
		ExitCode: ExitUnverified,
		Reason: "verify's exit 3 is the record-level completeness check (declaredRecordCount " +
			"vs the records actually recovered, which needs the master key to open a shard " +
			"manifest); attest's independent keyless shard-hash loop fails first trying to " +
			"fetch the same missing shard OBJECT and reports exit 2. Both correctly refuse the " +
			"run; the code differs because the catching gate differs, not because attest missed " +
			"anything verify caught.",
	},
	"truncated-final-chunk": {
		ExitCode: 0,
		Reason: "the tamper truncates a .seg object's AES-256-GCM tag; attest never fetches or " +
			"decrypts a .seg object, only the shard manifest's already-matching declared hash, " +
			"which the tamper does not touch (SPEC.md 8.8: attest materialises no plaintext).",
	},
	"reordered-chunks": {
		ExitCode: 0,
		Reason: "the tamper swaps STREAM chunk order inside a .seg object; invisible to attest's " +
			"shard-hash-only check for the same reason as truncated-final-chunk.",
	},
	"flipped-tag": {
		ExitCode: 0,
		Reason: "a flipped AEAD tag bit lives inside a .seg object's ciphertext; attest never " +
			"decrypts a segment, so the flip is outside its keyless scope.",
	},
	"reordered-segments": {
		ExitCode: 0,
		Reason: "the record's segment chain is reassembled and its full-record hash checked only " +
			"during RestoreRecord; attest never restores a record (SPEC.md 8.8), so a reversed " +
			"chain is invisible to it even though the root signature and shard hash it DOES " +
			"check both still pass.",
	},
	"incomplete-record-count": {
		ExitCode: 0,
		Reason: "declaredRecordCount vs the count of records actually recovered from an opened " +
			"shard manifest is a record-level completeness check that needs the master key " +
			"(AttestResult.DeclaredRecordCount's own doc comment: 'not record-verified here'); " +
			"the shard OBJECT itself is untouched by this tamper and its hash still matches, so " +
			"attest's keyless completeness check passes.",
	},
	"mixed-codec": {
		ExitCode: 0,
		Reason: "the per-record codec field lives inside the shard manifest, readable only after " +
			"the master-key unwrap; attest never opens a shard manifest, so a per-record codec " +
			"violation is outside its keyless scope.",
	},
	"secrets-with-compression": {
		ExitCode: 0,
		Reason:   "same as mixed-codec: the offending field is a per-record shard-manifest field attest never reads.",
	},
	"unknown-source-type": {
		ExitCode: 0,
		Reason: "sourceType is a per-record shard-manifest field, readable only after the " +
			"master-key unwrap; attest never opens a shard manifest.",
	},
	"wrong-merkle-root": {
		ExitCode: 0,
		Reason: "the Merkle root is recomputed from record hashes read from an opened shard " +
			"manifest; attest hashes the shard OBJECT as one opaque blob against the root's " +
			"per-shard SHA-384 (which this tamper does not touch), so a doctored merkleRoot " +
			"field is outside its keyless scope.",
	},
	"recovery-bundle-tampered": {
		ExitCode: 0,
		Reason: "the recovery-bundle check (SPEC.md 8.7 item 4) is opt-in via " +
			"Options.CheckRecoveryBundle on Open/verify; format.Attest has no equivalent " +
			"parameter and never reads the bundle at all.",
	},
}

// attestExpectFor returns the exit code format.Attest must produce for the named vector's
// primary run, and whether that came from an explicit, reasoned override rather than the
// default parity assumption (attest agrees with the vector's own ExitCode/Mode).
func attestExpectFor(name string, exp vectorExpect) (code int, reason string, overridden bool) {
	if o, ok := attestParityOverrides[name]; ok {
		return o.ExitCode, o.Reason, true
	}
	if exp.Mode == "negative" {
		return exp.ExitCode, "", false
	}
	return 0, "", false
}

// replayAttest runs format.Attest, signer-pinned, over one vector's primary run and asserts
// the exit code attestExpectFor computes: parity with the vector's own outcome by default,
// or the reasoned override. It fails the vector — not skips it — when an override entry is
// missing its Reason, so a divergence can never be encoded silently.
func replayAttest(t *testing.T, name string, store ObjectStore, verifier *crypto.HybridVerifier, exp vectorExpect) {
	t.Helper()
	runID := exp.RunID
	if runID == "" {
		runID = vecRunID
	}
	var minIndex int64
	if exp.Options != nil {
		minIndex = exp.Options.MinRunlogIndex
	}
	wantCode, reason, overridden := attestExpectFor(name, exp)
	if overridden && reason == "" {
		t.Fatalf("attest parity override for %q has no Reason: an unexplained divergence is how a real gap hides", name)
	}

	res, err := Attest(store, runID, verifier, minIndex)
	gotCode := 0
	if err != nil {
		var ee *ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("attest %s: expected a coded ExitError, got %v", name, err)
		}
		gotCode = ee.Code
	}

	if gotCode != wantCode {
		if overridden {
			t.Fatalf("attest %s: documented override expected exit %d (%s), got %d (err=%v)",
				name, wantCode, reason, gotCode, err)
		}
		t.Fatalf("attest %s: expected parity with verify's exit %d, got %d (err=%v); "+
			"if this is a genuine, reasoned scope difference add it to attestParityOverrides "+
			"rather than adjusting this expectation", name, wantCode, gotCode, err)
	}
	// Attest returns a nil result for a handful of early, pre-structural gates (an unparseable
	// runId, an unknown format major or envelope codec): there is no partial AttestResult to
	// report because nothing about the run has been classified yet. A nil result is only valid
	// alongside a failure (gotCode != 0); a nil result on an expected pass would be a real bug.
	if res == nil {
		if wantCode == 0 {
			t.Fatalf("attest %s: Attest returned a nil result on an expected pass", name)
		}
		return
	}
	if res.OK() != (wantCode == 0) {
		t.Fatalf("attest %s: AttestResult.OK()=%v disagrees with its own Code %d", name, res.OK(), res.Code)
	}
}
