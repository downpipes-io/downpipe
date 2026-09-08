package main

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// THE OVERRIDE WARNING NAMED A CAUSE IT HAD NOT MEASURED, AND THE HINT THAT SENDS AN
// OPERATOR TO THE OVERRIDE NAMED ONLY BENIGN ONES.
//
// The anti-rollback signal was fixed once already: every early return in the freshness path
// used to hand back a bare FreshnessResult{}, so a forged RUNLOG signature was quieter than
// a benign pin miss. That fix split the warning in two and gave the severe branch its own
// sentence. Two things it did not do, both driven on real archives:
//
//   - the severe sentence ENUMERATED four causes ("absent, unreadable, unparseable, or its
//     signature did not verify"), and that branch also fires for an empty log, a run the log
//     does not carry, and an entry that disagrees with the signed root on downpipe, index or
//     prevRunId. On a validly signed RUNLOG placing the run at index 7 against the signed
//     root's 1, all four named causes were false and the remedy sent the operator to recover
//     a RUNLOG that was intact.
//   - the hint printed at exit 5, BEFORE any override, was one sentence for every cause. A
//     tampered _RECOVERY/RUNLOG.sig printed "re-run with --allow-stale to restore the intact
//     data", advising an operator mid-recovery to waive a signature that did not verify, in
//     the words written for a rapid re-trigger or a demo reset.
//
// The assertions below are on what the operator READS and on the receipt, never on the exit
// code: every state here exits 0 under --allow-stale and 5 without it, before and after, so
// an exit-code assertion would have been green throughout both defects and both fixes.

// freshnessCauseFixture builds a real archive and returns it with its key paths.
func freshnessCauseFixture(t *testing.T) (dir, runID, idPath, signerPath string) {
	t.Helper()
	dir = t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("what the reader says it found"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath = writeArchiveKeys(t, dir, identity, verifier)
	return dir, runID, idPath, signerPath
}

// forgeRunlogSignature flips a byte inside the detached RUNLOG signature, leaving a
// well-formed base64url signature that does not verify against the pinned signer.
func forgeRunlogSignature(t *testing.T, dir string) {
	t.Helper()
	p := filepath.Join(dir, "_RECOVERY", "RUNLOG.sig")
	text, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(text)))
	if err != nil {
		t.Fatalf("decode runlog signature: %v", err)
	}
	raw[len(raw)/2] ^= 0xff
	if err := os.WriteFile(p, []byte(base64.RawURLEncoding.EncodeToString(raw)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestTheOverrideWarningNamesTheCauseTheReaderActuallyFound drives the states the CLI can
// reach and reads the sentence the operator gets, both when the gate refuses and when they
// override it. The below-pin case is the control throughout: it is the benign one, the tool
// always got it right, and without it a change that shouted the same thing at every input
// would satisfy every assertion here.
func TestTheOverrideWarningNamesTheCauseTheReaderActuallyFound(t *testing.T) {
	cases := []struct {
		name string
		// breakIt mutates the archive into the state under test; nil leaves it intact.
		breakIt func(t *testing.T, dir string)
		// ack is the acknowledgement this state needs to reach exit 0. It is per case rather
		// than a shared "--allow-stale" because that is exactly the conflation the split
		// removed: this table used to pass the age word for a forged RUNLOG signature and
		// assert exit 0, which is the product doing the thing this file was written about.
		ack   string
		extra []string
		// wantChecked is whether the freshness check could be RUN at all.
		wantChecked bool
		wantWarning bool
		// wantCause is a fragment of the reader's own error, which the warning must carry
		// instead of a description of the family the fault belongs to.
		wantCause string
	}{
		{
			name:        "forged RUNLOG signature",
			breakIt:     forgeRunlogSignature,
			ack:         "--allow-unverified-runlog",
			extra:       []string{"--acknowledge-no-rollback-pin"},
			wantChecked: false,
			wantWarning: true,
			wantCause:   "verify runlog signature",
		},
		{
			name: "RUNLOG absent",
			breakIt: func(t *testing.T, dir string) {
				if err := os.Remove(filepath.Join(dir, "_RECOVERY", "RUNLOG")); err != nil {
					t.Fatal(err)
				}
			},
			ack:         "--allow-unverified-runlog",
			extra:       []string{"--acknowledge-no-rollback-pin"},
			wantChecked: false,
			wantWarning: true,
			wantCause:   "read runlog",
		},
		{
			name:        "below the pin, the check RAN and found a problem",
			breakIt:     nil,
			ack:         "--allow-stale",
			extra:       []string{"--min-runlog-index", "99"},
			wantChecked: true,
			wantWarning: true,
			wantCause:   "below the pinned minimum 99",
		},
		{
			name:        "intact archive, the check ran and passed",
			breakIt:     nil,
			ack:         "--allow-stale",
			extra:       []string{"--acknowledge-no-rollback-pin"},
			wantChecked: true,
			wantWarning: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, runID, idPath, signerPath := freshnessCauseFixture(t)
			if tc.breakIt != nil {
				tc.breakIt(t, dir)
			}
			out := filepath.Join(t.TempDir(), "r.json")
			args := append([]string{
				"verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath,
				"--receipt", out, tc.ack,
			}, tc.extra...)
			var code int
			_, stderr := captureOutput(t, func() { code = run(args) })
			if code != 0 {
				t.Fatalf("control: %s under %s = %d, want 0", tc.name, tc.ack, code)
			}

			warned := strings.Contains(stderr, "anti-rollback/freshness check")
			if warned != tc.wantWarning {
				t.Errorf("override warning printed = %v, want %v\nstderr:\n%s", warned, tc.wantWarning, stderr)
			}
			if !tc.wantWarning {
				return
			}
			if !strings.Contains(stderr, tc.wantCause) {
				t.Errorf("the warning must name what the reader found (%q), not a family of causes:\n%s", tc.wantCause, stderr)
			}
			// The enumerated guess this replaces. Naming a cause the reader did not measure is
			// the defect, and on the disagreement inputs every item in that list was false.
			if strings.Contains(stderr, "The RUNLOG was absent, unreadable, unparseable") {
				t.Errorf("the warning is enumerating causes again instead of reporting the one it found:\n%s", stderr)
			}
			if !tc.wantChecked {
				if !strings.Contains(stderr, "COULD NOT BE RUN") {
					t.Errorf("a check that could not run must say so:\n%s", stderr)
				}
				if strings.Contains(stderr, "only the freshness guarantee was skipped") {
					t.Errorf("the stale-run reassurance is false when the RUNLOG may have been replaced:\n%s", stderr)
				}
			} else if !strings.Contains(stderr, "did NOT pass") {
				t.Errorf("a check that ran and found a problem must keep its own wording:\n%s", stderr)
			}

			rcpt := readReceiptRaw(t, out)
			fresh, ok := rcpt["freshness"].(map[string]any)
			if !ok {
				t.Fatalf("receipt has no freshness object:\n%v", rcpt)
			}
			if fresh["checked"] != tc.wantChecked {
				t.Errorf("receipt freshness.checked = %v, want %v:\n%v", fresh["checked"], tc.wantChecked, fresh)
			}
			if fresh["rollbackWarning"] != tc.wantWarning {
				t.Errorf("receipt freshness.rollbackWarning = %v, want %v:\n%v", fresh["rollbackWarning"], tc.wantWarning, fresh)
			}
		})
	}
}

// TestAForgedSignatureIsLouderThanABenignPinMiss states the ordering the original defect
// inverted, as a single comparison rather than as two independently asserted states. Both
// runs exit 0, both print a warning, and everything that separates them is in the words.
func TestAForgedSignatureIsLouderThanABenignPinMiss(t *testing.T) {
	warn := func(t *testing.T, forge bool, ack string, extra ...string) (stderr string, checked any) {
		t.Helper()
		dir, runID, idPath, signerPath := freshnessCauseFixture(t)
		if forge {
			forgeRunlogSignature(t, dir)
		}
		out := filepath.Join(t.TempDir(), "r.json")
		args := append([]string{
			"verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath,
			"--receipt", out, ack,
		}, extra...)
		var code int
		_, stderr = captureOutput(t, func() { code = run(args) })
		if code != 0 {
			t.Fatalf("control: both states must exit 0 under their own acknowledgement, %s gave %d", ack, code)
		}
		fresh, ok := readReceiptRaw(t, out)["freshness"].(map[string]any)
		if !ok {
			t.Fatal("receipt has no freshness object")
		}
		return stderr, fresh["checked"]
	}

	// The two acknowledgements are not interchangeable, which is the point of the pair: the
	// forged signature needs the word that says a signature is being waived, and the pin miss
	// needs only the age word.
	forged, forgedChecked := warn(t, true, "--allow-unverified-runlog", "--acknowledge-no-rollback-pin")
	benign, benignChecked := warn(t, false, "--allow-stale", "--min-runlog-index", "99")

	// The receipt: the forged signature established nothing, the pin miss established a
	// finding. A machine consumer reading only rollbackWarning cannot tell them apart, which
	// is what checked is for.
	if forgedChecked != false || benignChecked != true {
		t.Errorf("receipt freshness.checked: forged=%v (want false), below-pin=%v (want true)", forgedChecked, benignChecked)
	}
	// The printed word. The forged case must not borrow the benign case's reassurance, and
	// the benign case must not be shouted at with the severe one's wording, because a warning
	// that fires identically on both is the state this whole item exists to leave behind.
	if !strings.Contains(forged, "COULD NOT BE RUN") || strings.Contains(benign, "COULD NOT BE RUN") {
		t.Errorf("only the forged signature may say COULD NOT BE RUN\nforged:\n%s\nbelow-pin:\n%s", forged, benign)
	}
	if strings.Contains(forged, "still genuinely verified") || !strings.Contains(benign, "still genuinely verified") {
		t.Errorf("only the below-pin case may carry the reassurance\nforged:\n%s\nbelow-pin:\n%s", forged, benign)
	}
}

// TestTheHintThatRecommendsTheOverrideSaysWhichKindOfFailureItIs covers the message printed
// at exit 5, BEFORE the operator overrides anything. It is the message that sends them to
// --allow-stale, and it used to name a rapid re-trigger and a demo reset for a RUNLOG
// signature that did not verify.
func TestTheHintThatRecommendsTheOverrideSaysWhichKindOfFailureItIs(t *testing.T) {
	hint := func(t *testing.T, forge bool, extra ...string) string {
		t.Helper()
		dir, runID, idPath, signerPath := freshnessCauseFixture(t)
		if forge {
			forgeRunlogSignature(t, dir)
		}
		args := append([]string{
			"verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath,
		}, extra...)
		var code int
		_, stderr := captureOutput(t, func() { code = run(args) })
		// The control: with no acknowledgement at all both states really do refuse, so the hint
		// under test is the hint an operator actually meets.
		if code != format.ExitStale {
			t.Fatalf("control: this state must exit %d with no acknowledgement, got %d\n%s", format.ExitStale, code, stderr)
		}
		return stderr
	}

	forged := hint(t, true, "--acknowledge-no-rollback-pin")
	benign := hint(t, false, "--min-runlog-index", "99")

	if strings.Contains(forged, "re-run with --allow-stale to restore the intact data") {
		t.Errorf("a RUNLOG signature that did not verify must not be answered with the benign chain-churn advice:\n%s", forged)
	}
	if !strings.Contains(forged, "waives that check rather than satisfying it") {
		t.Errorf("the hint must say what the acknowledgement would do here, not merely offer it:\n%s", forged)
	}
	// AND IT MUST NAME THE FLAG THAT ACTUALLY WORKS. Saying what --allow-stale would do was
	// only half of it while --allow-stale still did it. Now the age word refuses this state a
	// second time, so a hint that named it would be advice an operator cannot follow, which is
	// the failure mode acceptsFreshnessOverride exists to prevent one command earlier.
	if !strings.Contains(forged, "--allow-unverified-runlog") {
		t.Errorf("the hint must name the acknowledgement that reaches this state:\n%s", forged)
	}
	if !strings.Contains(forged, "--allow-stale does not cover this") {
		t.Errorf("an operator who has already typed --allow-stale must be told why it refused:\n%s", forged)
	}
	// The control: the benign case keeps the advice that is correct for it. Removing the
	// hint everywhere would satisfy the assertion above and strand an operator on a good
	// backup, which is why it was written.
	if !strings.Contains(benign, "re-run with --allow-stale to restore the intact data") {
		t.Errorf("a benign chain difference must keep the advice that recovers it:\n%s", benign)
	}
}

// TestEveryUnrunnableFreshnessInputNamesItselfAndMarksItsError covers the freshness path
// directly, because the CLI reaches only two of its early returns and the three
// disagreement returns are reachable no other way: they need a RUNLOG that is validly
// signed and still contradicts the signed root, which no mutation of a finished archive
// produces. Each input is a different reason the check cannot run.
func TestEveryUnrunnableFreshnessInputNamesItselfAndMarksItsError(t *testing.T) {
	dir := t.TempDir()
	_, _, runID, err := buildSelftestArchive(dir, []byte("a validly signed runlog that contradicts the root"))
	if err != nil {
		t.Fatal(err)
	}
	rootBytes, err := os.ReadFile(filepath.Join(dir, "run", runID, "root.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := format.ParseRoot(rootBytes)
	if err != nil {
		t.Fatal(err)
	}
	// A signer generated here, not the archive's: these inputs must carry a RUNLOG signature
	// that VERIFIES, so that the failure under test is the disagreement and not the signature.
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	sign := func(entries []spec.RunlogEntry) ([]byte, []byte) {
		t.Helper()
		b, merr := format.MarshalRunlog(entries)
		if merr != nil {
			t.Fatal(merr)
		}
		s, serr := signer.Sign(b)
		if serr != nil {
			t.Fatal(serr)
		}
		return b, []byte(format.B64Encode(s))
	}

	const otherRun = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	entry := spec.RunlogEntry{
		Index: root.Freshness.RunlogIndex, RunID: runID, DownpipeID: root.DownpipeID,
		Time: "2026-06-06T12:00:01.000Z", RecordCount: 1, PrevRunID: nil, Status: "active",
	}
	withIndex := func(i int64) spec.RunlogEntry { e := entry; e.Index = i; return e }
	withPrev := func(p string) spec.RunlogEntry { e := entry; e.PrevRunID = &p; return e }
	withRun := func(id string) spec.RunlogEntry { e := entry; e.RunID = id; return e }
	withDownpipe := func(d string) spec.RunlogEntry { e := entry; e.DownpipeID = d; return e }

	cases := []struct {
		name      string
		entries   []spec.RunlogEntry
		wantCause string
	}{
		{"run absent from the runlog", []spec.RunlogEntry{withRun(otherRun)}, "is absent from the runlog"},
		{"index disagrees with the signed root", []spec.RunlogEntry{withIndex(root.Freshness.RunlogIndex + 6)}, "disagrees with the signed root"},
		{"prevRunId disagrees with the signed root", []spec.RunlogEntry{withPrev(otherRun)}, "prevRunId disagrees with the signed root"},
		{"entry belongs to another downpipe", []spec.RunlogEntry{withDownpipe("dp_somebody_else")}, "not the signed root downpipe"},
		{"runlog is empty", nil, "runlog is empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logBytes, sigText := sign(tc.entries)
			fresh, ferr := format.CheckFreshness(logBytes, sigText, runID, root, verifier, 0)
			// The control: each input really does fail the check. An input that passed would
			// make every assertion below vacuous.
			if ferr == nil {
				t.Fatalf("control: %s must fail the freshness check", tc.name)
			}
			if !fresh.Unchecked || !fresh.RollbackWarning {
				t.Errorf("%s: the check could not run, so it did not pass: %+v", tc.name, fresh)
			}
			if !strings.Contains(fresh.Reason, tc.wantCause) {
				t.Errorf("%s: Reason = %q, want it to name %q", tc.name, fresh.Reason, tc.wantCause)
			}
			// The error must self-report as a check that could not run. The CLI has no
			// FreshnessResult on this path (the reader returns none when the operator did not
			// override), so this marker is the only thing telling the two apart there.
			if !errors.Is(ferr, format.ErrFreshnessUnchecked) {
				t.Errorf("%s: the error must carry ErrFreshnessUnchecked, got %v", tc.name, ferr)
			}
			var ee *format.ExitError
			if !errors.As(ferr, &ee) || ee.Code != format.ExitStale {
				t.Errorf("%s: want a coded ExitStale error, got %v", tc.name, ferr)
			}
			_, stderr := captureOutput(t, func() { warnIfRollbackOverridden(fresh) })
			if !strings.Contains(stderr, tc.wantCause) {
				t.Errorf("%s: the operator must be told what was found:\n%s", tc.name, stderr)
			}
		})
	}

	// The control for the whole table: the same call over an intact, agreeing RUNLOG is
	// neither unchecked nor warned and carries no reason. Without it, a result hardcoded to
	// warn always would satisfy every assertion above.
	logBytes, sigText := sign([]spec.RunlogEntry{entry})
	fresh, err := format.CheckFreshness(logBytes, sigText, runID, root, verifier, 0)
	if err != nil {
		t.Fatalf("control: an agreeing runlog must pass its freshness check: %v", err)
	}
	if fresh.Unchecked || fresh.RollbackWarning || fresh.Reason != "" {
		t.Errorf("control: a clean check must be neither unchecked nor warned nor reasoned: %+v", fresh)
	}
}

// TestARanCheckDoesNotClaimItCouldNotRun is the other half of the marker: the three
// findings a check that RAN can report must NOT carry ErrFreshnessUnchecked, or the hint
// keyed on it would send every exit 5 to the severe branch and the split would be
// decorative.
func TestARanCheckDoesNotClaimItCouldNotRun(t *testing.T) {
	dir := t.TempDir()
	_, verifier, runID, err := buildSelftestArchive(dir, []byte("a check that ran"))
	if err != nil {
		t.Fatal(err)
	}
	rootBytes, err := os.ReadFile(filepath.Join(dir, "run", runID, "root.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := format.ParseRoot(rootBytes)
	if err != nil {
		t.Fatal(err)
	}
	logBytes, err := os.ReadFile(filepath.Join(dir, "_RECOVERY", "RUNLOG"))
	if err != nil {
		t.Fatal(err)
	}
	sigText, err := os.ReadFile(filepath.Join(dir, "_RECOVERY", "RUNLOG.sig"))
	if err != nil {
		t.Fatal(err)
	}

	fresh, ferr := format.CheckFreshness(logBytes, sigText, runID, root, verifier, root.Freshness.RunlogIndex+99)
	if ferr == nil {
		t.Fatal("control: a pin above the runlog maximum must fail the check")
	}
	if fresh.Unchecked {
		t.Errorf("a below-pin index is a finding, not an unknown: %+v", fresh)
	}
	if !fresh.RollbackWarning || !strings.Contains(fresh.Reason, "below the pinned minimum") {
		t.Errorf("a below-pin index must warn and say so: %+v", fresh)
	}
	if errors.Is(ferr, format.ErrFreshnessUnchecked) {
		t.Errorf("a check that RAN must not mark its error as one that could not run: %v", ferr)
	}
}

// TestTheWarningSaysSoWhenNoReasonWasRecorded pins the fallback. Every return that raises
// RollbackWarning sets Reason, so this is unreachable through verify and restore today; a
// future path that forgot would otherwise print a sentence with an empty middle clause,
// which reads as the tool having nothing to say rather than as a fault.
func TestTheWarningSaysSoWhenNoReasonWasRecorded(t *testing.T) {
	_, stderr := captureOutput(t, func() {
		warnIfRollbackOverridden(format.FreshnessResult{RollbackWarning: true})
	})
	if !strings.Contains(stderr, "recorded no reason") {
		t.Errorf("a missing reason must be reported as one:\n%s", stderr)
	}
}

// TestAttestDoesNotDescribeARunlogItNeverRead is the other caller of the unchecked flag.
// reportAttest prints under an UNATTESTED label on the failure path, and both of its runlog
// lines described a check that had run: keyless it asserted "present and parsed, listing
// this run" about a RUNLOG that had been deleted, and signer-pinned it printed
// latest-for-downpipe=false as though that had been judged. FreshnessResult.Unchecked was
// set on every one of those returns and no caller read it, so the field could not stop it.
func TestAttestDoesNotDescribeARunlogItNeverRead(t *testing.T) {
	cases := []struct {
		name    string
		breakIt func(t *testing.T, dir string)
		keyless bool
		// wantCause is a fragment of the reader's own error the report must carry.
		wantCause string
	}{
		{
			name: "keyless, RUNLOG deleted",
			breakIt: func(t *testing.T, dir string) {
				if err := os.Remove(filepath.Join(dir, "_RECOVERY", "RUNLOG")); err != nil {
					t.Fatal(err)
				}
			},
			keyless:   true,
			wantCause: "read runlog",
		},
		{
			name:      "signer-pinned, forged RUNLOG signature",
			breakIt:   forgeRunlogSignature,
			wantCause: "verify runlog signature",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, runID, _, signerPath := freshnessCauseFixture(t)
			tc.breakIt(t, dir)
			args := []string{"attest", "--archive", dir, "--run", runID}
			if !tc.keyless {
				args = append(args, "--signer", signerPath, "--acknowledge-no-rollback-pin")
			}
			var code int
			_, stderr := captureOutput(t, func() { code = run(args) })
			// The control: this really is the failure path, so the report under test is the
			// one printed alongside a refusal rather than a passing attestation.
			if code != format.ExitStale {
				t.Fatalf("control: this state must exit %d, got %d\n%s", format.ExitStale, code, stderr)
			}
			if !strings.Contains(stderr, "UNATTESTED") {
				t.Fatalf("control: the report must be printed under an UNATTESTED label:\n%s", stderr)
			}
			if strings.Contains(stderr, "present and parsed, listing this run") {
				t.Errorf("the report claims it read a RUNLOG the check never got through:\n%s", stderr)
			}
			if strings.Contains(stderr, "latest-for-downpipe=") {
				t.Errorf("latest-for-downpipe was never judged here and must not be printed as a verdict:\n%s", stderr)
			}
			if !strings.Contains(stderr, "COULD NOT BE RUN") || !strings.Contains(stderr, tc.wantCause) {
				t.Errorf("the report must say the check could not run and name %q:\n%s", tc.wantCause, stderr)
			}
		})
	}

	// The control for both: an intact archive still gets its measured verdicts. Without it a
	// report that said COULD NOT BE RUN unconditionally would satisfy every assertion above.
	dir, runID, _, signerPath := freshnessCauseFixture(t)
	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{"attest", "--archive", dir, "--run", runID, "--signer", signerPath, "--acknowledge-no-rollback-pin"})
	})
	if code != 0 {
		t.Fatalf("control: an intact archive must attest, got %d\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "latest-for-downpipe=true") || strings.Contains(stderr, "COULD NOT BE RUN") {
		t.Errorf("control: a check that ran must still report what it measured:\n%s", stderr)
	}
}
