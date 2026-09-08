package format

import (
	"bytes"
	"errors"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// Under --allow-unverified the run proceeds, but the Outcome carries the true normative
// exit code so the caller never reports an unverified run as exit 0 (SPEC 8.5).
func TestOutcomeCodeNotLaundered(t *testing.T) {
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

	// A fully verified run: code 0.
	clean := memStore{}
	bg, ver := buildArchive(t, buildSpec{store: clean, runID: runID, dpID: "dp_test", value: []byte("v"), secret: false, codec: spec.CodecNameNone})
	r, err := Open(clean, runID, bg, ver, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Outcome().Verified() || r.Outcome().Code != 0 {
		t.Fatalf("verified run must be code 0, got %d", r.Outcome().Code)
	}

	// A deleted RUNLOG without an allow flag: fails hard with ExitStale (5).
	stale := memStore{}
	bg2, ver2 := buildArchive(t, buildSpec{store: stale, runID: runID, dpID: "dp_test", value: []byte("v"), secret: false, codec: spec.CodecNameNone})
	delete(stale, "_RECOVERY/RUNLOG")
	if _, err := Open(stale, runID, bg2, ver2, Options{}); err == nil {
		t.Fatal("a deleted RUNLOG without --allow-stale must fail")
	} else {
		var ee *ExitError
		if !errors.As(err, &ee) || ee.Code != ExitStale {
			t.Fatalf("a deleted RUNLOG must fail ExitStale (%d), got %v", ExitStale, err)
		}
	}
	// The same run with --allow-unverified-runlog: proceeds and exits 0 (acknowledged), but the
	// outcome records the freshness gap honestly (completeness UNVERIFIED), so it is not
	// laundered as fully verified. It is that flag rather than --allow-stale because a deleted
	// RUNLOG establishes nothing about the run's age, and --allow-stale says only that the age
	// the check reported is acceptable.
	r2, err := Open(stale, runID, bg2, ver2, Options{AllowUnverifiedRunlog: true})
	if err != nil {
		t.Fatalf("allow-unverified-runlog must proceed: %v", err)
	}
	if r2.Outcome().Code != 0 || r2.Outcome().Completeness != "UNVERIFIED" {
		t.Fatalf("acknowledged-stale run must be code 0 with UNVERIFIED completeness, got code %d completeness %s", r2.Outcome().Code, r2.Outcome().Completeness)
	}

	// A tampered signature with --allow-unverified: proceeds but code is ExitUnverified
	// (2) and the signature result is recorded honestly.
	badsig := memStore{}
	bg3, ver3 := buildArchive(t, buildSpec{store: badsig, runID: runID, dpID: "dp_test", value: []byte("v"), secret: false, codec: spec.CodecNameNone})
	sigKey := runKey(runID, "root.manifest.json.sig")
	badsig[sigKey] = bytes.Clone(badsig[sigKey])
	badsig[sigKey][0] ^= 0x01 // corrupt the base64 -> decode or verify fails
	r3, err := Open(badsig, runID, bg3, ver3, Options{AllowUnverified: true})
	if err != nil {
		t.Fatalf("allow-unverified must proceed past a bad signature: %v", err)
	}
	if r3.Outcome().Code != ExitUnverified || r3.Outcome().SignatureResult == "valid" {
		t.Fatalf("bad-signature allow-unverified run must report code %d and a non-valid signature, got code %d sig %s", ExitUnverified, r3.Outcome().Code, r3.Outcome().SignatureResult)
	}
}
