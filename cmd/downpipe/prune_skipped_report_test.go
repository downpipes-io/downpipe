package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// "NOTHING WILL BE DELETED" AND "I COULD NOT WORK OUT WHAT WOULD BE DELETED" MUST NOT LOOK ALIKE.
//
// A superseded run that cannot be opened is SKIPPED rather than fatal, which is the right call: its bytes
// stay, and aborting the whole pass because one dead run is unreadable would make the tool useless on
// exactly the estates that most need it. But a skip drops that run out of every count in the report, and
// when every superseded run is unreadable the operator is shown a plan of zeros:
//
//	runs deletable:         0
//	orphan segments:        0
//	would delete segments:  0
//	would delete run-tree objects: 0
//	would delete objects in total: 0
//
// which reads as "your retention policy has nothing to do". The truth is the opposite: the policy
// supersedes three runs, this pass could not read any of them, and their bytes are staying.
//
// The explanation was printed, and in the wrong place under the wrong name. It came AFTER the total, and
// the docs page tells the operator to "read the last line before you arm --apply", so an operator
// following the published instruction read the zero and stopped. It also called those runs "deletable", a
// word the report had already used four lines earlier with a different meaning and a contradictory count.
//
// This drives the real command over an archive whose superseded runs cannot be read, and pins both: the
// caveat comes before the total, and the total is genuinely the last line.
func TestTheReportSaysWhyItWillDeleteNothing(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runs := buildMultiRunArchive(t, dir, []fixtureRun{
		{downpipeID: "dp_alpha", index: 1, records: 2},
		{downpipeID: "dp_alpha", index: 2, records: 3},
		{downpipeID: "dp_beta", index: 3, records: 2},
		{downpipeID: "dp_alpha", index: 4, records: 1},
		{downpipeID: "dp_beta", index: 5, records: 1},
	})
	// Every deletable run made unreadable, by removing the shard manifest its root manifest names. The
	// run stays in the RUNLOG, so the policy still supersedes it; it simply cannot be enumerated, which is
	// what turns it into a skip rather than a deletion.
	dropped := runs[:3]
	for _, r := range dropped {
		if err := os.Remove(filepath.Join(dir, "run", r.runID, "manifest", "00000.dpe")); err != nil {
			t.Fatalf("make run %s unreadable: %v", r.runID, err)
		}
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	var code int
	stdout, stderr := captureOutput(t, func() {
		code = run([]string{
			"prune", "--archive", dir, "--identity", idPath, "--signer", signerPath, "--keep", "1",
		})
	})
	// A skip is not fatal. If this stopped exiting 0 the rest of the test would be asserting against a
	// report that is not printed.
	if code != 0 {
		t.Fatalf("a pass whose superseded runs cannot be read must still report and exit 0, got %d.\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}

	// The premise: the counts really are all zero, so the ambiguity this test is about is present.
	for _, zero := range []string{
		"  runs deletable:         0\n",
		"  orphan segments:        0\n",
		"  would delete objects in total: 0\n",
	} {
		if !strings.Contains(stdout, zero) {
			t.Fatalf("expected the zero plan line %q; the fixture no longer produces the case this test is about.\nstdout:\n%s", zero, stdout)
		}
	}

	const caveat = "  superseded runs this pass will NOT touch (could not be read, so their bytes stay):"
	at := strings.Index(stdout, caveat)
	if at < 0 {
		t.Fatalf("the report is a plan of zeros with nothing saying the policy supersedes %d runs it could not read, so it reads as a no-op.\nstdout:\n%s", len(dropped), stdout)
	}
	// Every run, named. A count alone tells the operator that something was left behind and not which run
	// to repair, and `downpipe verify` needs the run id.
	for _, r := range dropped {
		if !strings.Contains(stdout, r.runID) {
			t.Errorf("superseded run %s was left behind and the report does not name it, so the operator cannot repair it.\nstdout:\n%s", r.runID, stdout)
		}
	}

	// The word "deletable" must belong to one count only. The report says "runs deletable: 0" here, and
	// the old caveat called these same runs "deletable runs SKIPPED: 3": the same word, four lines apart,
	// with contradictory counts.
	caveatLine, _, _ := strings.Cut(stdout[at:], "\n")
	if strings.Contains(caveatLine, "deletable") {
		t.Errorf("the caveat reuses \"deletable\", which the report has already spent on a different count, so the two lines contradict each other: %q", caveatLine)
	}

	// Order, and it is the published instruction that makes this load bearing. The docs page says to read
	// the last line before arming --apply, so a caveat printed after the total is a caveat the documented
	// reading misses.
	total := strings.Index(stdout, "  would delete objects in total:")
	if total < 0 {
		t.Fatalf("no total line, so this ordering check examined nothing.\nstdout:\n%s", stdout)
	}
	if at > total {
		t.Errorf("the reason the plan is empty is printed AFTER the total the docs tell an operator to read before arming --apply, so the documented reading misses it.\nstdout:\n%s", stdout)
	}
	// And the total really is last, which is what makes that instruction true rather than approximately
	// true. A trailing line added here silently demotes the total, so this fails rather than letting the
	// docs go quietly wrong about a destructive command.
	rest := stdout[total:]
	rest = rest[strings.Index(rest, "\n")+1:]
	if strings.TrimSpace(rest) != "" {
		t.Errorf("the dry-run report prints more after the total, so \"read the last line before you arm --apply\" now points at something else:\n%q", rest)
	}
}

// The control. On an archive with nothing to skip the caveat must not appear at all, or it would read as
// a permanent disclaimer and stop meaning anything on the pass where it matters.
func TestThereIsNoSkipCaveatWhenNothingWasSkipped(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, _ := buildMultiRunArchive(t, dir, []fixtureRun{
		{downpipeID: "dp_alpha", index: 1, records: 2},
		{downpipeID: "dp_alpha", index: 2, records: 1},
	})
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	var code int
	stdout, stderr := captureOutput(t, func() {
		code = run([]string{
			"prune", "--archive", dir, "--identity", idPath, "--signer", signerPath, "--keep", "1",
		})
	})
	if code != 0 {
		t.Fatalf("prune dry run = %d, want 0.\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	// The premise: this archive really does have something to delete, so an absent caveat is meaningful
	// rather than the report being empty for another reason.
	if !strings.Contains(stdout, "  runs deletable:         1\n") {
		t.Fatalf("expected one deletable run in this fixture.\nstdout:\n%s", stdout)
	}
	if strings.Contains(stdout, "could not be read") {
		t.Errorf("a pass that read every superseded run printed the skip caveat anyway.\nstdout:\n%s", stdout)
	}
}
