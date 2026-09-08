package format

import (
	"errors"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// TestAllowStaleReachesOnlyTheAgeFindings asserts that --allow-stale acknowledges only the
// two age-related freshness findings (the run is not latest, or below the pinned minimum
// index), and never a finding about the RUNLOG's own trustworthiness (a bad signature, a
// missing or rewritten RUNLOG, or a disagreement between signed documents). Those need the
// stronger --allow-unverified-runlog or --allow-unverified acknowledgement.
//
// The table below is the enumeration, driven rather than read, and it is also the control:
// oldRuleAccepts models the combined condition a single --allow-stale flag would grant if it
// were not split by finding, so comparing it against Options.acknowledges on every row shows
// what the split protects, rather than asserting only that the current rule holds.
func TestAllowStaleReachesOnlyTheAgeFindings(t *testing.T) {
	const (
		thisRun  = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
		nextRun  = "01ARZ3NDEKTSV4RRFFQ69G5FB0"
		thirdRun = "01ARZ3NDEKTSV4RRFFQ69G5FB1"
		otherRun = "01ARZ3NDEKTSV4RRFFQ69G5FB2"
	)
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	root := &spec.RootManifest{DownpipeID: "dp", Freshness: spec.Freshness{PrevRunID: nil, RunlogIndex: 1}}
	entry := spec.RunlogEntry{Index: 1, RunID: thisRun, DownpipeID: "dp", Time: "t1", RecordCount: 1, PrevRunID: nil, Status: "active"}
	withIndex := func(i int64) spec.RunlogEntry { e := entry; e.Index = i; return e }
	withPrev := func(p string) spec.RunlogEntry { e := entry; e.PrevRunID = &p; return e }
	withRun := func(id string) spec.RunlogEntry { e := entry; e.RunID = id; return e }
	withDownpipe := func(d string) spec.RunlogEntry { e := entry; e.DownpipeID = d; return e }
	follower := func(id string, index int64, prev string) spec.RunlogEntry {
		return spec.RunlogEntry{Index: index, RunID: id, DownpipeID: "dp", Time: "t", RecordCount: 1, PrevRunID: &prev, Status: "active"}
	}

	// oldRuleAccepts models a single combined acknowledgement (AllowStale || AllowUnverified)
	// so each row can compare it against the split acknowledgement rule below.
	oldRuleAccepts := func(o Options) bool { return o.AllowStale || o.AllowUnverified }

	cases := []struct {
		name string
		// entries is the RUNLOG this case signs and presents; rawLog overrides it with bytes
		// that are signed as given, for the log that does not parse.
		entries  []spec.RunlogEntry
		rawLog   []byte
		badSig   bool // flip a byte inside the detached signature
		junkSig  bool // present a signature that is not base64 at all
		minIndex int64
		// wantUntrusted is whether this finding is about the RUNLOG's own trustworthiness
		// rather than the run's age, which is what decides which acknowledgement reaches it.
		wantUntrusted bool
		wantCause     string
	}{
		// The RUNLOG's own trustworthiness. --allow-stale must not reach any of these.
		{name: "signature does not verify against the pinned signer", entries: []spec.RunlogEntry{entry}, badSig: true, wantUntrusted: true, wantCause: "verify runlog signature"},
		{name: "signature is not base64", entries: []spec.RunlogEntry{entry}, junkSig: true, wantUntrusted: true, wantCause: "decode runlog signature"},
		{name: "runlog does not parse", rawLog: []byte("{\"index\":\n"), wantUntrusted: true, wantCause: "decode for numeric check"},
		{name: "runlog is empty", entries: nil, wantUntrusted: true, wantCause: "runlog is empty"},
		{name: "run is absent from the runlog", entries: []spec.RunlogEntry{withRun(otherRun)}, wantUntrusted: true, wantCause: "absent from the runlog"},
		{name: "entry belongs to another downpipe", entries: []spec.RunlogEntry{withDownpipe("dp_somebody_else")}, wantUntrusted: true, wantCause: "not the signed root downpipe"},
		{name: "index disagrees with the signed root", entries: []spec.RunlogEntry{withIndex(7)}, wantUntrusted: true, wantCause: "disagrees with the signed root"},
		{name: "prevRunId disagrees with the signed root", entries: []spec.RunlogEntry{withPrev(otherRun)}, wantUntrusted: true, wantCause: "prevRunId disagrees with the signed root"},
		{name: "chain anomaly: an index appears twice", entries: []spec.RunlogEntry{entry, withRun(otherRun)}, wantUntrusted: true, wantCause: "appears twice"},
		{name: "chain anomaly: the chain was rewritten", entries: []spec.RunlogEntry{entry, follower(nextRun, 2, thisRun), follower(thirdRun, 3, thisRun)}, wantUntrusted: true, wantCause: "does not chain to the prior retained entry"},

		// The run's age, from a RUNLOG that verified and is self-consistent. --allow-stale is
		// exactly the acknowledgement for these two, and it is the whole of what it covers.
		{name: "the run is not the latest for its downpipe", entries: []spec.RunlogEntry{entry, follower(nextRun, 2, thisRun)}, wantUntrusted: false, wantCause: "not the latest for its downpipe"},
		{name: "the log maximum is below the operator's pin", entries: []spec.RunlogEntry{entry}, minIndex: 5, wantUntrusted: false, wantCause: "below the pinned minimum"},
	}

	ageRows, untrustedRows := 0, 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logBytes := tc.rawLog
			if logBytes == nil {
				var merr error
				if logBytes, merr = MarshalRunlog(tc.entries); merr != nil {
					t.Fatal(merr)
				}
			}
			raw, serr := signer.Sign(logBytes)
			if serr != nil {
				t.Fatal(serr)
			}
			if tc.badSig {
				raw[len(raw)/2] ^= 0xff
			}
			sigText := []byte(B64Encode(raw))
			if tc.junkSig {
				sigText = []byte("this is not base64 at all")
			}

			fresh, ferr := CheckFreshness(logBytes, sigText, thisRun, root, verifier, tc.minIndex)
			// The control for the row: the input really does fail. A row that passed would
			// make every permission assertion below vacuously true.
			if ferr == nil {
				t.Fatalf("control: %s must fail the freshness check", tc.name)
			}
			if fresh.Reason == "" || !strings.Contains(fresh.Reason, tc.wantCause) {
				t.Errorf("Reason = %q, want it to name %q", fresh.Reason, tc.wantCause)
			}
			if fresh.RunlogUntrusted != tc.wantUntrusted {
				t.Errorf("RunlogUntrusted = %v, want %v (Reason %q)", fresh.RunlogUntrusted, tc.wantUntrusted, fresh.Reason)
			}
			// The error and the result must agree. The CLI is handed only the error when it
			// refuses, and only the result when it proceeds, so the two readings of the same
			// fact live in different code paths and would drift apart silently.
			if got := RunlogUntrustedError(ferr); got != fresh.RunlogUntrusted {
				t.Errorf("RunlogUntrustedError = %v but FreshnessResult.RunlogUntrusted = %v, so the reader would refuse under one rule and explain itself under another", got, fresh.RunlogUntrusted)
			}

			// The permission itself, which is the point of the whole item.
			if (Options{}).acknowledges(fresh) {
				t.Error("no acknowledgement at all must never open a freshness failure")
			}
			if got := (Options{AllowStale: true}).acknowledges(fresh); got == tc.wantUntrusted {
				t.Errorf("--allow-stale accepts = %v on a finding whose RunlogUntrusted is %v; the age word must reach the age findings and nothing else", got, tc.wantUntrusted)
			}
			if !(Options{AllowUnverifiedRunlog: true}).acknowledges(fresh) {
				t.Error("--allow-unverified-runlog is the stronger acknowledgement and must reach every freshness finding, including the age ones")
			}
			if !(Options{AllowUnverified: true}).acknowledges(fresh) {
				t.Error("--allow-unverified subsumes both and must reach every freshness finding")
			}

			// Under a single combined rule, --allow-stale alone would have opened this input; on
			// the untrusted rows that would mean waiving a cryptographic check with an age-only
			// flag.
			if !oldRuleAccepts(Options{AllowStale: true}) {
				t.Fatal("the control does not reproduce the old rule")
			}
			if tc.wantUntrusted {
				untrustedRows++
			} else {
				ageRows++
			}
		})
	}

	// The shape of the table, asserted so a future edit cannot quietly reduce it to the two
	// benign rows and leave every assertion above green.
	if untrustedRows < 10 || ageRows != 2 {
		t.Errorf("the enumeration must keep both sides: %d untrusted rows and %d age rows", untrustedRows, ageRows)
	}

	// THE POSITIVE CONTROL. An intact, agreeing RUNLOG passes with no acknowledgement at
	// all. Without it, a gate hardcoded to refuse would satisfy every assertion above.
	logBytes, merr := MarshalRunlog([]spec.RunlogEntry{entry})
	if merr != nil {
		t.Fatal(merr)
	}
	raw, serr := signer.Sign(logBytes)
	if serr != nil {
		t.Fatal(serr)
	}
	fresh, ferr := CheckFreshness(logBytes, []byte(B64Encode(raw)), thisRun, root, verifier, 0)
	if ferr != nil {
		t.Fatalf("control: an intact runlog must pass with no acknowledgement: %v", ferr)
	}
	if fresh.RunlogUntrusted || fresh.RollbackWarning || fresh.Unchecked {
		t.Errorf("control: a clean check must raise nothing: %+v", fresh)
	}
}

// The two store-level causes, which never reach CheckFreshness at all: the RUNLOG and its
// signature are fetched first, and a fetch that fails is a check that could not be run. They
// are driven through Open rather than the freshness function because that is the only place
// they exist, and because an operator meets them as an exit code rather than as a struct.
func TestAnAbsentRunlogNeedsTheStrongerAcknowledgement(t *testing.T) {
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	for _, missing := range []string{"_RECOVERY/RUNLOG", "_RECOVERY/RUNLOG.sig"} {
		t.Run(missing, func(t *testing.T) {
			store := memStore{}
			bgPriv, verifier := buildArchive(t, buildSpec{store: store, runID: runID, dpID: "dp_test", value: []byte("v"), secret: false, codec: spec.CodecNameNone})
			// The control, run first: this archive opens cleanly before the object is removed,
			// so the refusals below are caused by the removal and not by the fixture.
			if _, err := Open(store, runID, bgPriv, verifier, Options{}); err != nil {
				t.Fatalf("control: the intact archive must open with no acknowledgement: %v", err)
			}
			delete(store, missing)

			_, err := Open(store, runID, bgPriv, verifier, Options{AllowStale: true})
			if err == nil {
				t.Fatalf("--allow-stale opened a run with %s removed, so an age word is still waiving a check that never ran", missing)
			}
			var ee *ExitError
			if !errors.As(err, &ee) || ee.Code != ExitStale {
				t.Errorf("want ExitStale (%d), got %v", ExitStale, err)
			}
			if !errors.Is(err, ErrFreshnessUnchecked) {
				t.Errorf("the error must self-report as a check that could not be run: %v", err)
			}
			r, err := Open(store, runID, bgPriv, verifier, Options{AllowUnverifiedRunlog: true})
			if err != nil {
				t.Fatalf("--allow-unverified-runlog must proceed with %s removed: %v", missing, err)
			}
			defer r.Close()
			if !r.Freshness().RunlogUntrusted || !r.Freshness().Unchecked {
				t.Errorf("the recorded result must still say the RUNLOG could not be trusted: %+v", r.Freshness())
			}
			// And it is still not laundered as a clean run. The acknowledgement changes the
			// exit code, never the labels.
			if r.Outcome().Completeness != "UNVERIFIED" {
				t.Errorf("completeness = %q, want UNVERIFIED", r.Outcome().Completeness)
			}
		})
	}
}
