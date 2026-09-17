package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/prune"
)

// The prune dry-run report is a published contract in two directions, and neither of them is a Go
// caller. The docs page prints this block verbatim, down to the column alignment, and tells the
// operator to "read the last line before you arm --apply". Operators also parse it, because prune is
// the one offline command that DELETES and its plan is the thing you check before arming it.
//
// Nothing pinned either. A renamed label leaves the docs quietly wrong about a destructive command,
// and the docs cannot catch that themselves: they live in another repo, so their gate would fire on
// whatever this repo has on its default branch rather than on the change that broke it. The label
// belongs to the repo that prints it, so it is pinned here.
//
// Order is asserted, not just presence. The counts build on each other (segments, then run-tree
// objects, then the total the operator acts on), and a report that lists the total before its parts
// reads as a different claim even though every label is still present.
func TestPruneDryRunPrintsTheDocumentedReport(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, _, err := buildSelftestArchive(dir, []byte("prune report value"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	var code int
	stdout, _ := captureOutput(t, func() {
		code = run([]string{
			"prune",
			"--archive", dir,
			"--identity", idPath,
			"--signer", signerPath,
			"--keep", "30",
		})
	})
	if code != 0 {
		t.Fatalf("prune dry run = %d, want 0. stdout:\n%s", code, stdout)
	}

	// Exactly the lines the docs page reproduces. Trailing spaces are part of the alignment, so they
	// are included: a label whose padding changed would still render a ragged block in the docs.
	want := []string{
		"prune DRY RUN (nothing was deleted; pass --apply to delete)",
		"  runs kept:              ",
		"  runs deletable:         ",
		"  orphan segments:        ",
		"  would delete segments:  ",
		"  would delete run-tree objects: ",
		"  would delete objects in total: ",
	}
	prev := -1
	for _, line := range want {
		at := strings.Index(stdout, line)
		if at < 0 {
			t.Errorf("prune dry run did not print %q; the docs page reproduces this line verbatim.\nstdout:\n%s", line, stdout)
			continue
		}
		if at <= prev {
			t.Errorf("prune dry run printed %q out of order (at %d, previous line at %d).\nstdout:\n%s", line, at, prev, stdout)
		}
		prev = at
	}

	// The dry run must not claim anything was removed. "DRY RUN" in the header is the load-bearing
	// word: an operator reading the apply-mode wording on a run that deleted nothing would either arm
	// a second, real prune believing the first had not taken, or stop believing it had.
	for _, forbidden := range []string{"prune APPLIED", "segments deleted:", "run-tree objects gone:"} {
		if strings.Contains(stdout, forbidden) {
			t.Errorf("a dry run printed apply-mode line %q, which reports deletion that did not happen.\nstdout:\n%s", forbidden, stdout)
		}
	}
}

// THE LABELS WERE PINNED AND THE NUMBERS WERE NOT.
//
// The test above asserts that seven labels are printed and that they are printed in order. It asserts no
// number at all, and it could not: its archive is a single run at --keep 30, so the keep window excludes
// nothing and every count is legitimately 0. Asserting on that fixture would be asserting 0 == 0 + 0.
//
// That left the one line the docs page tells an operator to read immediately before arming an
// IRREVERSIBLE DELETE with nothing pinning it. internal/prune pins Partition and the receipt counts
// exactly, so the arithmetic is guarded where the library computes it. It was not guarded where the
// operator reads it, and those are different things: a report that stopped calling the library, or that
// printed the run-tree count in the segment slot, would leave every unit test in internal/prune green.
//
// So this drives the REAL command over an archive whose counts are non-zero, and asserts the numbers in
// the actual output lines.
//
// WHY THE FIXTURE LOOKS LIKE THIS. Five runs across two downpipes at --keep 1, with a different number of
// records per run, chosen so that every count the operator reads differs from its neighbours:
//
//	runs kept:              2   (the newest run of each of the two downpipes)
//	runs deletable:         3   (the other three)
//	orphan segments:        7   (2 + 3 + 2 records, one segment object each)
//	would delete segments:  7
//	would delete run-tree objects: 9   (three run trees, three objects each)
//	would delete objects in total: 16
//
// Distinctness is the property that makes the assertion mean something. If two counts agreed, a report
// that printed them in the wrong slots would still pass, which is the defect one layer along from the one
// this test closes. The test checks that distinctness itself, so a later change to the fixture that
// collapsed two counts fails here rather than silently weakening every assertion below it.
//
// The one pair that CANNOT be made to differ is "orphan segments" and "would delete segments". They are
// the same value by construction (Result.PlannedSegments is len(plan.OrphanSegments)), and the docs page
// shows 118 on both lines for the same reason. That pair is asserted as equal deliberately rather than
// left as an accident.
//
// The expected numbers are derived from the fixture and from the objects on disk, not copied from a run
// of the code under test. A golden snapshot of whatever the report happened to print would agree with a
// wrong report.
func TestPruneDryRunPrintsTheCountsAnOperatorActsOn(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runs := buildMultiRunArchive(t, dir, []fixtureRun{
		{downpipeID: "dp_alpha", index: 1, records: 2},
		{downpipeID: "dp_alpha", index: 2, records: 3},
		{downpipeID: "dp_beta", index: 3, records: 2},
		{downpipeID: "dp_alpha", index: 4, records: 1},
		{downpipeID: "dp_beta", index: 5, records: 1},
	})
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	// --keep 1 keeps the newest run of EACH downpipe, by the RUNLOG's own index. The three older runs,
	// at indices 1, 2 and 3, are the deletable ones.
	const keepPerDownpipe = 1
	kept, dropped := runs[3:], runs[:3]
	if len(kept) != 2 || len(dropped) != 3 {
		t.Fatalf("the fixture split is wrong: %d kept, %d dropped", len(kept), len(dropped))
	}

	// Ground truth, derived rather than recorded. Segments: one object per record of a deletable run,
	// and none of them shared with a retained run, which is checked below against the objects on disk.
	wantSegments := 0
	for _, r := range dropped {
		wantSegments += r.records
	}
	wantRunObjects := 0
	for _, r := range dropped {
		wantRunObjects += countObjectsUnder(t, dir, "run/"+r.runID+"/")
	}
	if wantRunObjects != runTreeObjectsPerRun*len(dropped) {
		t.Fatalf("a deletable run tree holds %d objects in total across %d runs, expected %d each; the archive layout has moved and the report's run-tree count now means something else",
			wantRunObjects, len(dropped), runTreeObjectsPerRun)
	}
	// Every record in the archive has its own segment object. If two collapsed, the orphan count would
	// silently shrink and this test would be asserting the wrong ground truth rather than failing.
	allRecords := 0
	for _, r := range runs {
		allRecords += r.records
	}
	if got := countObjectsUnder(t, dir, "seg/"); got != allRecords {
		t.Fatalf("the fixture wrote %d segment objects for %d records; segments have collided, so the orphan count no longer means what this test assumes", got, allRecords)
	}

	var code int
	stdout, stderr := captureOutput(t, func() {
		code = run([]string{
			"prune",
			"--archive", dir,
			"--identity", idPath,
			"--signer", signerPath,
			"--keep", strconv.Itoa(keepPerDownpipe),
		})
	})
	if code != 0 {
		t.Fatalf("prune dry run = %d, want 0.\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}

	// The numbers in the lines the operator reads, asserted with their labels attached so a transposition
	// cannot pass. The trailing alignment is part of the published block and is kept.
	wantLines := []struct{ label, line string }{
		{"runs kept", fmt.Sprintf("  runs kept:              %d\n", len(kept))},
		{"runs deletable", fmt.Sprintf("  runs deletable:         %d\n", len(dropped))},
		{"orphan segments", fmt.Sprintf("  orphan segments:        %d\n", wantSegments)},
		{"would delete segments", fmt.Sprintf("  would delete segments:  %d\n", wantSegments)},
		{"would delete run-tree objects", fmt.Sprintf("  would delete run-tree objects: %d\n", wantRunObjects)},
		{"would delete objects in total", fmt.Sprintf("  would delete objects in total: %d\n", wantSegments+wantRunObjects)},
	}
	for _, w := range wantLines {
		if !strings.Contains(stdout, w.line) {
			t.Errorf("the %s line did not carry the count an operator would act on.\nwant the line %q\nstdout:\n%s", w.label, w.line, stdout)
		}
	}

	// The fixture has to keep its discriminating power. Five distinct values across six lines, the one
	// repeat being the definitional segments pair: if a later edit collapsed two of the others, every
	// assertion above would still pass on a report that had transposed them.
	distinct := map[int]bool{}
	for _, n := range []int{len(kept), len(dropped), wantSegments, wantRunObjects, wantSegments + wantRunObjects} {
		if distinct[n] {
			t.Fatalf("two of the report's counts are both %d, so an assertion cannot tell which number landed in which slot: kept=%d deletable=%d segments=%d runObjects=%d total=%d",
				n, len(kept), len(dropped), wantSegments, wantRunObjects, wantSegments+wantRunObjects)
		}
		distinct[n] = true
	}

	// And the arithmetic as the operator checks it, read back out of the printed block rather than from
	// the Result struct. The docs page says the total "is the number that tells you the size of the
	// operation", which is only true while it is the sum of the two parts printed above it.
	got := parsePruneCounts(t, stdout)
	if got["would delete objects in total"] != got["would delete segments"]+got["would delete run-tree objects"] {
		t.Errorf("the total an operator reads before arming --apply is not the sum of the parts printed above it: %d segments + %d run-tree objects, total printed as %d.\nstdout:\n%s",
			got["would delete segments"], got["would delete run-tree objects"], got["would delete objects in total"], stdout)
	}
	if got["orphan segments"] != got["would delete segments"] {
		t.Errorf("orphan segments (%d) and would-delete segments (%d) are the same quantity under two labels and must agree; the docs page prints them as one number twice.\nstdout:\n%s",
			got["orphan segments"], got["would delete segments"], stdout)
	}
	// A parser that matched nothing reads exactly like a report whose numbers are all correct.
	if len(got) != 6 {
		keys := make([]string, 0, len(got))
		for k := range got {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Fatalf("only %d of the 6 counted lines were parsed (%v), so the checks above examined less than the whole report.\nstdout:\n%s", len(got), keys, stdout)
	}
}

// pruneCountLine matches a report line of the form "  <label>: <number>". The label is captured
// separately from the number so the two are asserted together and never independently.
var pruneCountLine = regexp.MustCompile(`(?m)^ {2}([a-z][a-z\- ]*?):\s+(\d+)\s*$`)

// parsePruneCounts reads the counted lines back out of the printed report, mirroring how a
// downstream consumer of this same output parses it.
func parsePruneCounts(t *testing.T, stdout string) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, m := range pruneCountLine.FindAllStringSubmatch(stdout, -1) {
		n, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatalf("count on the %q line is not a number: %q", m[1], m[2])
		}
		if _, seen := out[m[1]]; seen {
			t.Fatalf("the report printed the %q line twice, so an operator reading it cannot tell which count is the plan", m[1])
		}
		out[m[1]] = n
	}
	return out
}

// countObjectsUnder counts the archive objects stored under a key prefix, reading the directory rather
// than asking the code under test how many objects it thinks are there.
func countObjectsUnder(t *testing.T, dir, prefix string) int {
	t.Helper()
	root := filepath.Join(dir, filepath.FromSlash(prefix))
	n := 0
	err := filepath.WalkDir(root, func(_ string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("count objects under %s: %v", prefix, err)
	}
	if n == 0 {
		t.Fatalf("no objects under %s, so this expectation would be zero for the wrong reason", prefix)
	}
	return n
}

// THE RECEIPT AND THE REPORT MUST AGREE, BECAUSE THE DOCS SAY THEY DO.
//
// The docs page says the receipt "carries what the summary prints". That is a claim about two artefacts
// produced by one pass, and nothing checked it. They are computed from the same Result, so agreement is
// cheap today; the point is that it stays true, because the receipt is the durable half and an operator
// reconciling a shrunken corpus reads it long after the terminal output has gone.
func TestTheReceiptCarriesTheSameCountsTheReportPrinted(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runs := buildMultiRunArchive(t, dir, []fixtureRun{
		{downpipeID: "dp_alpha", index: 1, records: 2},
		{downpipeID: "dp_alpha", index: 2, records: 3},
		{downpipeID: "dp_beta", index: 3, records: 2},
		{downpipeID: "dp_alpha", index: 4, records: 1},
		{downpipeID: "dp_beta", index: 5, records: 1},
	})
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)
	receiptPath := filepath.Join(t.TempDir(), "prune-receipt.json")

	var code int
	stdout, stderr := captureOutput(t, func() {
		code = run([]string{
			"prune", "--archive", dir, "--identity", idPath, "--signer", signerPath,
			"--keep", "1", "--receipt", receiptPath,
		})
	})
	if code != 0 {
		t.Fatalf("prune dry run = %d, want 0.\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}

	receipt, err := prune.ReadReceipt(receiptPath)
	if err != nil {
		t.Fatalf("read the receipt the operator keeps: %v", err)
	}
	if receipt.Status != prune.StatusCompleted {
		t.Fatalf("a pass that returned must leave a completed receipt, got %q", receipt.Status)
	}
	if receipt.Mode != "dry-run" {
		t.Errorf("receipt mode = %q, want dry-run: a record that does not say whether anything was deleted is the wrong record", receipt.Mode)
	}

	printed := parsePruneCounts(t, stdout)
	for _, c := range []struct {
		label string
		got   int
	}{
		{"runs kept", receipt.RunsKept},
		{"orphan segments", receipt.PlannedSegments},
		{"would delete segments", receipt.PlannedSegments},
		{"would delete run-tree objects", receipt.PlannedRunObjects},
		{"would delete objects in total", receipt.PlannedSegments + receipt.PlannedRunObjects},
	} {
		if printed[c.label] != c.got {
			t.Errorf("the report printed %d on the %q line and the receipt records %d; the docs page says the receipt carries what the summary prints", printed[c.label], c.label, c.got)
		}
	}
	// The count was taken here, so the record must say so. This is the field that used to read false on
	// the started record for the opposite reason, and it has to keep meaning what it says on both.
	if receipt.RunObjectsUnknown {
		t.Errorf("this destination lists, so the run-object count was measured, and the completed receipt says it was not")
	}
	// The runs the pass covers, named. A count cannot tell an operator reconciling a shrunken corpus
	// which runs went.
	if len(receipt.SupersededRuns) != 3 {
		t.Errorf("the receipt names %d superseded runs, want 3", len(receipt.SupersededRuns))
	}
	for _, r := range runs[:3] {
		if !slices.Contains(receipt.SupersededRuns, r.runID) {
			t.Errorf("deletable run %s is not named in the receipt", r.runID)
		}
	}
}
