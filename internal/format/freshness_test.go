package format

import (
	"errors"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// An absent or unreadable RUNLOG is a freshness failure (exit 5) in verified mode, and
// --allow-unverified-runlog proceeds despite it while --allow-stale does NOT.
//
// The flag is an age word, and an absent RUNLOG measures no age, so --allow-stale alone must
// not open an archive whose RUNLOG cannot be trusted at all. Nothing must assert that
// --allow-stale opens an archive whose RUNLOG SIGNATURE does not verify, which is the worse
// half of what a combined flag would waive.
func TestFreshnessMissingRunlogRejected(t *testing.T) {
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	store := memStore{}
	bgPriv, verifier := buildArchive(t, buildSpec{store: store, runID: runID, dpID: "dp_test", value: []byte("v"), secret: false, codec: spec.CodecNameNone})
	delete(store, "_RECOVERY/RUNLOG")

	_, err := Open(store, runID, bgPriv, verifier, Options{})
	if err == nil {
		t.Fatal("an absent RUNLOG must fail verified open")
	}
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != ExitStale {
		t.Fatalf("want ExitStale (%d), got %v", ExitStale, err)
	}
	// The age word alone must NOT open it. Asserted before the positive case below, because a
	// test that only proved the new flag works would be green with --allow-stale still waiving
	// everything it used to.
	if _, err := Open(store, runID, bgPriv, verifier, Options{AllowStale: true}); err == nil {
		t.Fatal("--allow-stale opened a run whose RUNLOG is absent, so an age word is still waiving the check that could not be run")
	} else {
		var se *ExitError
		if !errors.As(err, &se) || se.Code != ExitStale {
			t.Fatalf("--allow-stale on an absent RUNLOG must still be ExitStale (%d), got %v", ExitStale, err)
		}
	}
	if _, err := Open(store, runID, bgPriv, verifier, Options{AllowUnverifiedRunlog: true}); err != nil {
		t.Fatalf("--allow-unverified-runlog must proceed despite the absent RUNLOG: %v", err)
	}
}

// CheckFreshness flags a non-latest run, passes the latest, and fails a min-index pin
// above the RUNLOG maximum (the out-of-band rollback signal).
func TestCheckFreshnessStaleAndPin(t *testing.T) {
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	r1 := "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	r2 := "01ARZ3NDEKTSV4RRFFQ69G5FB0"
	runlog, err := MarshalRunlog([]spec.RunlogEntry{
		{Index: 1, RunID: r1, DownpipeID: "dp", Time: "t1", RecordCount: 1, PrevRunID: nil, Status: "superseded"},
		{Index: 2, RunID: r2, DownpipeID: "dp", Time: "t2", RecordCount: 1, PrevRunID: &r1, Status: "active"},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signer.Sign(runlog)
	if err != nil {
		t.Fatal(err)
	}
	sig := []byte(B64Encode(raw))

	rootOld := &spec.RootManifest{DownpipeID: "dp", Freshness: spec.Freshness{PrevRunID: nil, RunlogIndex: 1}}
	if _, err := CheckFreshness(runlog, sig, r1, rootOld, verifier, 0); err == nil {
		t.Fatal("the older run must be flagged stale")
	}

	rootNew := &spec.RootManifest{DownpipeID: "dp", Freshness: spec.Freshness{PrevRunID: &r1, RunlogIndex: 2}}
	if _, err := CheckFreshness(runlog, sig, r2, rootNew, verifier, 0); err != nil {
		t.Fatalf("the latest run must pass: %v", err)
	}
	if _, err := CheckFreshness(runlog, sig, r2, rootNew, verifier, 3); err == nil {
		t.Fatal("a min-index pin above the RUNLOG maximum must fail")
	}
}

// A RUNLOG entry that matches the restored runId but belongs to a different downpipe than
// the signed root must be rejected, and the downpipe-binding check must be the sole reason
// it is rejected. The fixture is constructed so every other gate passes: the entry is the
// only one in the runlog, so the per-downpipe latest check sees downpipeMax == this.Index,
// its index equals the signed root index, its prevRunId (nil) matches the root's, and the
// chain check finds neither a gap nor a dangling pointer. Flipping only the entry's
// downpipeId from the root's to a foreign one is what turns an otherwise-valid freshness
// result into an ExitStale rejection, which proves the guard is load-bearing rather than
// shadowed by the index/prev checks (SPEC.md 10).
func TestCheckFreshnessRejectsCrossDownpipeEntry(t *testing.T) {
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

	// Index 0 with a nil prevRunId is a genesis run: with no entry for the root downpipe,
	// downpipeMax is 0, so this.Index (0) is the latest for the downpipe and the chain
	// check has no indices or pointers to fault. Only the downpipe binding can object.
	makeRunlog := func(entryDownpipe string) ([]byte, []byte) {
		return signedRunlog(t, signer, []spec.RunlogEntry{
			{Index: 0, RunID: runID, DownpipeID: entryDownpipe, Time: "t", RecordCount: 1, PrevRunID: nil, Status: "active"},
		})
	}
	root := &spec.RootManifest{DownpipeID: "dp_root", Freshness: spec.Freshness{PrevRunID: nil, RunlogIndex: 0}}

	// Positive control: the same entry under the root's own downpipe passes cleanly, so the
	// fixture genuinely isolates the downpipe check (every other gate is satisfied).
	runlog, sig := makeRunlog("dp_root")
	if res, err := CheckFreshness(runlog, sig, runID, root, verifier, 0); err != nil {
		t.Fatalf("the same entry under the root downpipe must pass: %v", err)
	} else if res.RollbackWarning {
		t.Fatal("the matching-downpipe control must not raise a rollback warning")
	}

	// The entry under a foreign downpipe must be rejected, and ExitStale is the code.
	runlog, sig = makeRunlog("dp_other")
	_, err = CheckFreshness(runlog, sig, runID, root, verifier, 0)
	if err == nil {
		t.Fatal("a runlog entry from a different downpipe must not satisfy freshness for the root downpipe")
	}
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != ExitStale {
		t.Fatalf("a cross-downpipe entry must be ExitStale (%d): %v", ExitStale, err)
	}
}

// signedRunlog marshals and signs RUNLOG entries with signer, returning the bytes and the
// base64url signature text CheckFreshness expects.
func signedRunlog(t *testing.T, signer *crypto.HybridSigner, entries []spec.RunlogEntry) ([]byte, []byte) {
	t.Helper()
	runlog, err := MarshalRunlog(entries)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signer.Sign(runlog)
	if err != nil {
		t.Fatal(err)
	}
	return runlog, []byte(B64Encode(raw))
}

// A benign allocation gap is ACCEPTED (SPEC.md 10): the writer allocates indices from
// one account-global counter and appends an entry only on successful finalise, so a
// downpipe's index sequence may legitimately hold 1 then 3, either because a failed run
// consumed index 2 without appending an entry or because another downpipe holds it. The
// per-downpipe prevRunId chain is linear in both fixtures, so neither is an anomaly.
func TestCheckFreshnessAllocationGapAccepted(t *testing.T) {
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	r1 := "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	r3 := "01ARZ3NDEKTSV4RRFFQ69G5FB0"
	o2 := "01ARZ3NDEKTSV4RRFFQ69G5FC1"
	rootR3 := &spec.RootManifest{DownpipeID: "dp", Freshness: spec.Freshness{PrevRunID: strPtr(r1), RunlogIndex: 3}}

	// Index 2 consumed by a failed run: no entry carries it for any downpipe.
	hole := []spec.RunlogEntry{
		{Index: 1, RunID: r1, DownpipeID: "dp", Time: "t1", RecordCount: 1, PrevRunID: nil, Status: "superseded"},
		{Index: 3, RunID: r3, DownpipeID: "dp", Time: "t3", RecordCount: 1, PrevRunID: strPtr(r1), Status: "active"},
	}
	runlog, sig := signedRunlog(t, signer, hole)
	res, err := CheckFreshness(runlog, sig, r3, rootR3, verifier, 0)
	if err != nil {
		t.Fatalf("a failed-run allocation gap with a linear prevRunId chain must pass: %v", err)
	}
	if res.RollbackWarning || !res.IsLatestForDownpipe {
		t.Fatalf("a benign allocation gap must not warn: %+v", res)
	}

	// Index 2 held by an interleaving downpipe: dp holds 1 and 3, dp_other holds 2.
	interleaved := []spec.RunlogEntry{
		{Index: 1, RunID: r1, DownpipeID: "dp", Time: "t1", RecordCount: 1, PrevRunID: nil, Status: "superseded"},
		{Index: 2, RunID: o2, DownpipeID: "dp_other", Time: "t2", RecordCount: 1, PrevRunID: nil, Status: "active"},
		{Index: 3, RunID: r3, DownpipeID: "dp", Time: "t3", RecordCount: 1, PrevRunID: strPtr(r1), Status: "active"},
	}
	runlog, sig = signedRunlog(t, signer, interleaved)
	res, err = CheckFreshness(runlog, sig, r3, rootR3, verifier, 0)
	if err != nil {
		t.Fatalf("an interleaved two-downpipe runlog must pass for the latest run of each: %v", err)
	}
	if res.RollbackWarning || !res.IsLatestForDownpipe {
		t.Fatalf("an interleaved allocation gap must not warn: %+v", res)
	}
}

// A correctly signed RUNLOG with a well-linked chain (including a retained superseded
// entry for a pruned predecessor) passes the chain check, while a per-downpipe linearity
// break, a dangling or forked prevRunId, and an index out of append order are each
// rejected as a rollback (SPEC.md 10).
func TestCheckFreshnessChainAnomalies(t *testing.T) {
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	r1 := "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	r2 := "01ARZ3NDEKTSV4RRFFQ69G5FB0"
	r3 := "01ARZ3NDEKTSV4RRFFQ69G5FC1"
	oX := "01ARZ3NDEKTSV4RRFFQ69G5FD2"
	rootR3 := &spec.RootManifest{DownpipeID: "dp", Freshness: spec.Freshness{PrevRunID: strPtr(r2), RunlogIndex: 3}}
	rootR2 := &spec.RootManifest{DownpipeID: "dp", Freshness: spec.Freshness{PrevRunID: strPtr(r1), RunlogIndex: 2}}

	t.Run("good-chain", func(t *testing.T) {
		// A 1->2->3 chain, restoring the latest run, passes with no warning.
		good := []spec.RunlogEntry{
			{Index: 1, RunID: r1, DownpipeID: "dp", Time: "t1", RecordCount: 1, PrevRunID: nil, Status: "superseded"},
			{Index: 2, RunID: r2, DownpipeID: "dp", Time: "t2", RecordCount: 1, PrevRunID: strPtr(r1), Status: "superseded"},
			{Index: 3, RunID: r3, DownpipeID: "dp", Time: "t3", RecordCount: 1, PrevRunID: strPtr(r2), Status: "active"},
		}
		runlog, sig := signedRunlog(t, signer, good)
		res, err := CheckFreshness(runlog, sig, r3, rootR3, verifier, 0)
		if err != nil {
			t.Fatalf("a well-linked chain must pass: %v", err)
		}
		if res.RollbackWarning {
			t.Fatal("a well-linked chain must not raise a rollback warning")
		}
	})

	t.Run("linearity-break", func(t *testing.T) {
		// A linearity break: entry 3's prevRunId names its grandparent r1 while the parent
		// entry r2 remains retained, so an entry was removed from the middle of the chain or
		// the chain was rewritten. The shape is also a fork of r1 (entries 2 and 3 share it),
		// but the linearity pass reports it first; the indices are monotonic and every
		// prevRunId resolves, so neither of the other branches can account for the rejection,
		// and the restored run is still the maximum for its downpipe.
		skipped := []spec.RunlogEntry{
			{Index: 1, RunID: r1, DownpipeID: "dp", Time: "t1", RecordCount: 1, PrevRunID: nil, Status: "superseded"},
			{Index: 2, RunID: r2, DownpipeID: "dp", Time: "t2", RecordCount: 1, PrevRunID: strPtr(r1), Status: "superseded"},
			{Index: 3, RunID: r3, DownpipeID: "dp", Time: "t3", RecordCount: 1, PrevRunID: strPtr(r1), Status: "active"},
		}
		rootSkipped := &spec.RootManifest{DownpipeID: "dp", Freshness: spec.Freshness{PrevRunID: strPtr(r1), RunlogIndex: 3}}
		runlog, sig := signedRunlog(t, signer, skipped)
		res, err := CheckFreshness(runlog, sig, r3, rootSkipped, verifier, 0)
		if err == nil {
			t.Fatal("a linearity break (grandparent link with the parent retained) must be rejected")
		}
		var ee *ExitError
		if !errors.As(err, &ee) || ee.Code != ExitStale {
			t.Fatalf("a linearity break must be ExitStale (%d): %v", ExitStale, err)
		}
		if !res.RollbackWarning {
			t.Fatal("a linearity break must set RollbackWarning")
		}
	})

	t.Run("dangling-prev", func(t *testing.T) {
		// A dangling prevRunId: another downpipe's first retained entry points at oX, a run
		// id no entry of any status carries, so the chain was rewritten. A first entry is
		// exempt from the linearity rule and the indices are monotonic, so only the dangling
		// branch can fire; the restored run's own downpipe chain is clean.
		dangling := []spec.RunlogEntry{
			{Index: 1, RunID: r1, DownpipeID: "dp", Time: "t1", RecordCount: 1, PrevRunID: nil, Status: "superseded"},
			{Index: 2, RunID: r2, DownpipeID: "dp", Time: "t2", RecordCount: 1, PrevRunID: strPtr(r1), Status: "active"},
			{Index: 3, RunID: r3, DownpipeID: "dp_other", Time: "t3", RecordCount: 1, PrevRunID: strPtr(oX), Status: "active"},
		}
		runlog, sig := signedRunlog(t, signer, dangling)
		res, err := CheckFreshness(runlog, sig, r2, rootR2, verifier, 0)
		if err == nil {
			t.Fatal("a dangling prevRunId must be rejected")
		}
		var ee *ExitError
		if !errors.As(err, &ee) || ee.Code != ExitStale {
			t.Fatalf("a dangling prevRunId must be ExitStale (%d): %v", ExitStale, err)
		}
		if !res.RollbackWarning {
			t.Fatal("a dangling prevRunId must set RollbackWarning")
		}
	})

	t.Run("forked-chain", func(t *testing.T) {
		// A forked chain: dp's entry 2 and dp_other's first entry both link back to r1, so
		// two entries share one predecessor. Within a single downpipe any fork is reported by
		// the linearity pass first, so the cross-downpipe shape is what exercises the fork
		// branch itself: each downpipe's own chain is linear, the indices are monotonic and
		// every prevRunId resolves.
		forked := []spec.RunlogEntry{
			{Index: 1, RunID: r1, DownpipeID: "dp", Time: "t1", RecordCount: 1, PrevRunID: nil, Status: "superseded"},
			{Index: 2, RunID: r2, DownpipeID: "dp", Time: "t2", RecordCount: 1, PrevRunID: strPtr(r1), Status: "active"},
			{Index: 3, RunID: r3, DownpipeID: "dp_other", Time: "t3", RecordCount: 1, PrevRunID: strPtr(r1), Status: "active"},
		}
		runlog, sig := signedRunlog(t, signer, forked)
		res, err := CheckFreshness(runlog, sig, r2, rootR2, verifier, 0)
		if err == nil {
			t.Fatal("a forked prevRunId must be rejected")
		}
		var ee *ExitError
		if !errors.As(err, &ee) || ee.Code != ExitStale {
			t.Fatalf("a forked prevRunId must be ExitStale (%d): %v", ExitStale, err)
		}
		if !res.RollbackWarning {
			t.Fatal("a forked prevRunId must set RollbackWarning")
		}
	})

	t.Run("interleaved-order", func(t *testing.T) {
		// INTERLEAVED line order is ACCEPTED (SPEC.md 10, amended after the first
		// production fleet): indices allocate at trigger time but entries land at finalise
		// time, so concurrent runs append out of allocation order as a matter of course.
		// The checks sort by index; the signature anchors the bytes.
		interleaved := []spec.RunlogEntry{
			{Index: 2, RunID: r2, DownpipeID: "dp", Time: "t2", RecordCount: 1, PrevRunID: strPtr(r1), Status: "active"},
			{Index: 1, RunID: r1, DownpipeID: "dp", Time: "t1", RecordCount: 1, PrevRunID: nil, Status: "superseded"},
		}
		runlog, sig := signedRunlog(t, signer, interleaved)
		res, err := CheckFreshness(runlog, sig, r2, rootR2, verifier, 0)
		if err != nil {
			t.Fatalf("interleaved append order must be accepted (the concurrent-fleet shape): %v", err)
		}
		if !res.IsLatestForDownpipe {
			t.Fatal("the restored run is still the latest for its downpipe under interleaved order")
		}
	})

	t.Run("duplicated-index", func(t *testing.T) {
		// A DUPLICATED index is the real corruption signal: the account-global counter
		// never reissues one, so two entries sharing an index mean the log was corrupted
		// or hand-assembled.
		rDup := "01DUPL1CATE000000000000000"
		duplicated := []spec.RunlogEntry{
			{Index: 1, RunID: r1, DownpipeID: "dp", Time: "t1", RecordCount: 1, PrevRunID: nil, Status: "superseded"},
			{Index: 2, RunID: r2, DownpipeID: "dp", Time: "t2", RecordCount: 1, PrevRunID: strPtr(r1), Status: "active"},
			{Index: 2, RunID: rDup, DownpipeID: "dp2", Time: "t3", RecordCount: 1, PrevRunID: nil, Status: "active"},
		}
		runlog, sig := signedRunlog(t, signer, duplicated)
		res, err := CheckFreshness(runlog, sig, r2, rootR2, verifier, 0)
		if err == nil {
			t.Fatal("a duplicated index must be rejected")
		}
		var ee *ExitError
		if !errors.As(err, &ee) || ee.Code != ExitStale {
			t.Fatalf("a duplicated index must be ExitStale (%d): %v", ExitStale, err)
		}
		if !res.RollbackWarning {
			t.Fatal("a duplicated index must set RollbackWarning")
		}
	})
}

// TestOpenMultiRunHistoryWithoutAllowStale proves the offline reader restores a multi-run
// history WITHOUT --allow-stale when the signed root's freshness.prevRunId agrees with the
// chain the RUNLOG records: buildArchiveSpec(runs:2) produces exactly that agreeing shape,
// so the latest run's root and its RUNLOG entry agree on prevRunId. The latest run must
// therefore Open clean (no AllowStale); the older run stays correctly flagged stale until
// AllowStale, which is the genuine anti-rollback behaviour this test protects (integrity !=
// availability).
func TestOpenMultiRunHistoryWithoutAllowStale(t *testing.T) {
	vs := vectorSpec{dpID: "dp_multirun", runs: 2, records: []recordSpec{{name: "k", value: []byte("v")}}}
	store, bgPriv, verifier, _ := buildArchiveSpec(t, vs)

	// The latest run restores WITHOUT --allow-stale: root.prevRunId == the RUNLOG entry's prevRunId.
	r, err := Open(store, vecRunIDB, bgPriv, verifier, Options{})
	if err != nil {
		t.Fatalf("the latest run of a multi-run history must Open WITHOUT --allow-stale: %v", err)
	}
	if !r.Freshness().IsLatestForDownpipe {
		t.Fatal("the latest run must be reported latest-for-downpipe")
	}

	// The OLDER run is genuinely not the latest, so it is rejected without --allow-stale (ExitStale) and
	// restores under it — the real anti-rollback path the fix must leave intact.
	_, err = Open(store, vecRunID, bgPriv, verifier, Options{})
	if err == nil {
		t.Fatal("the older run must be flagged stale without --allow-stale")
	}
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != ExitStale {
		t.Fatalf("older-run rejection must be ExitStale (%d): %v", ExitStale, err)
	}
	if _, err := Open(store, vecRunID, bgPriv, verifier, Options{AllowStale: true}); err != nil {
		t.Fatalf("the older run must restore under --allow-stale: %v", err)
	}
}

// TestCheckFreshnessRunlog1Divergence proves that the freshness check passes ONLY when the
// signed root's freshness.prevRunId matches the RUNLOG entry's prevRunId: a root that
// claims prevRunId=nil while the RUNLOG links a real prior run is rejected ExitStale on an
// otherwise-intact archive, so --allow-stale stays the deliberate waiver for that
// disagreement, not the default.
func TestCheckFreshnessRunlog1Divergence(t *testing.T) {
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	rA := "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	rB := "01ARZ3NDEKTSV4RRFFQ69G5FB0"
	// A correctly chained two-run RUNLOG: B links A (idx 2 after idx 1).
	runlog, sig := signedRunlog(t, signer, []spec.RunlogEntry{
		{Index: 1, RunID: rA, DownpipeID: "dp", Time: "t1", RecordCount: 1, PrevRunID: nil, Status: "superseded"},
		{Index: 2, RunID: rB, DownpipeID: "dp", Time: "t2", RecordCount: 1, PrevRunID: strPtr(rA), Status: "active"},
	})

	// FIXED shape: the signed root agrees with the RUNLOG (prevRunId = A). Freshness passes, no waiver.
	rootFixed := &spec.RootManifest{DownpipeID: "dp", Freshness: spec.Freshness{PrevRunID: strPtr(rA), RunlogIndex: 2}}
	if _, err := CheckFreshness(runlog, sig, rB, rootFixed, verifier, 0); err != nil {
		t.Fatalf("the agreeing (fixed) shape must pass freshness without --allow-stale: %v", err)
	}

	// Divergent shape: the root claims prevRunId=nil while the RUNLOG links A.
	rootBug := &spec.RootManifest{DownpipeID: "dp", Freshness: spec.Freshness{PrevRunID: nil, RunlogIndex: 2}}
	_, err = CheckFreshness(runlog, sig, rB, rootBug, verifier, 0)
	if err == nil {
		t.Fatal("a root/RUNLOG prevRunId divergence must be rejected")
	}
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != ExitStale {
		t.Fatalf("the divergence must be ExitStale (%d): %v", ExitStale, err)
	}
	if !strings.Contains(err.Error(), "prevRunId disagrees with the signed root") {
		t.Fatalf("the divergence error must name the prevRunId disagreement, got: %v", err)
	}
}
