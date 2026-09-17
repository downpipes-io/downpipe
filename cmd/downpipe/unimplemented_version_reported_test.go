package main

import (
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
)

// THE PATHS THAT NEVER ASKED THE VERSION QUESTION.
//
// verify, restore, attest and inspect-with-an-identity all reach the format version gate, because all
// four go through format.Open. Driven against the conformance vectors unknown-major (downpipe/9.0.0)
// and unimplemented-minor (downpipe/0.2.0), each of the four exits 6 and restore writes nothing.
//
// keys --which does not go through Open at all. It reads the public root manifests directly, which is
// the whole point of it (it answers "which key opens which runs" with no identity supplied), and so it
// listed a run this reader cannot open at exit 0 with no mention of the version anywhere, with and
// without --signer. That is the command inspect's own usage error names first when somebody does not
// know their run ids, so it is the first thing an operator sees and the last place that should be
// silent about it.
//
// prune does not go through Open in a way that keeps the reason: it opens each run, discards the error
// and abstains. The abstain was safe and measured (exit 2, archive byte-identical before and after
// --apply) but its remedy line asserted a cause the command had never established.
//
// The fixture rewrites one run's root formatVersion and re-signs it, which is what the conformance
// vectors do. It does NOT touch the corpus.

// unreadableVersion is a well-formed version outside this reader's implemented set. It matches the
// unknown-major vector rather than being invented here, so the fixture and the corpus refuse for the
// same reason.
const unreadableVersion = "downpipe/9.0.0"

// TestKeysWhichMarksRunsThisReaderCannotOpen drives keys --which over an archive holding one run this
// reader implements and one it does not, and asserts the unreadable one is LISTED (its key mapping is
// true regardless of this build) and MARKED, while the readable one is listed unmarked.
//
// The mixed archive is the assertion that matters. A fixture with only the unreadable run could be
// satisfied by a change that marked every run in every index.
func TestKeysWhichMarksRunsThisReaderCannotOpen(t *testing.T) {
	dir := t.TempDir()
	_, _, built := buildMultiRunArchive(t, dir, []fixtureRun{
		{downpipeID: "dp_readable", index: 1, records: 1},
		{downpipeID: "dp_future", index: 2, records: 1, formatVersion: unreadableVersion},
	})
	readableRun, futureRun := built[0].runID, built[1].runID

	var code int
	stdout, _ := captureOutput(t, func() {
		code = run([]string{"keys", "--which", "--archive", dir})
	})
	if code != 0 {
		t.Fatalf("keys --which = %d, want 0: a run at a version this reader cannot open is still a run this key opens, and refusing the index dead-ends the step that finds run ids\n%s", code, stdout)
	}
	if !strings.Contains(stdout, futureRun) {
		t.Errorf("the unreadable run must still be listed; dropping it hides the key that opens it\n%s", stdout)
	}
	if !strings.Contains(stdout, readableRun) {
		t.Errorf("the readable run must still be listed\n%s", stdout)
	}
	for _, want := range []string{
		"THIS READER CANNOT OPEN",
		format.ReaderFormatSupport(),
		futureRun + "  (format " + unreadableVersion + ": NOT readable by this reader)",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("keys --which output missing %q\n%s", want, stdout)
		}
	}
	// The readable run must NOT carry the marker. Without this the whole assertion above is satisfied
	// by marking everything, which would tell an operator their working archive needs another reader.
	if strings.Contains(stdout, readableRun+"  (format") {
		t.Errorf("the readable run must not be marked unreadable\n%s", stdout)
	}
}

// TestKeysWhichCleanArchiveCarriesNoVersionWarning is the control. Every assertion in the test above
// is satisfied by a build that prints the warning unconditionally.
func TestKeysWhichCleanArchiveCarriesNoVersionWarning(t *testing.T) {
	dir := t.TempDir()
	runID := selftestArchiveRunID(t, dir, []byte("all runs readable"))

	var code int
	stdout, _ := captureOutput(t, func() {
		code = run([]string{"keys", "--which", "--archive", dir})
	})
	if code != 0 {
		t.Fatalf("keys --which over a readable archive = %d, want 0\n%s", code, stdout)
	}
	if !strings.Contains(stdout, runID) {
		t.Fatalf("the run must be listed\n%s", stdout)
	}
	for _, unwanted := range []string{"THIS READER CANNOT OPEN", "NOT readable by this reader"} {
		if strings.Contains(stdout, unwanted) {
			t.Errorf("an archive this reader can open must carry no version warning, found %q\n%s", unwanted, stdout)
		}
	}
}

// TestKeysWhichMarksUnreadableRunWithSignerToo confirms the mark survives the signer-pinned path, where
// each root's detached signature is verified before it feeds the index. The version is inside the signed
// bytes, so a validly signed root at a version this reader does not implement is the realistic case:
// nothing is tampered, the archive is simply newer than the binary.
func TestKeysWhichMarksUnreadableRunWithSignerToo(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, built := buildMultiRunArchive(t, dir, []fixtureRun{
		{downpipeID: "dp_future", index: 1, records: 1, formatVersion: unreadableVersion},
	})
	_, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	var code int
	stdout, _ := captureOutput(t, func() {
		code = run([]string{"keys", "--which", "--archive", dir, "--signer", signerPath})
	})
	if code != 0 {
		t.Fatalf("keys --which --signer = %d, want 0\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "signer-verified") {
		t.Errorf("the index is signer-verified and must say so; the version is a separate question from the signature\n%s", stdout)
	}
	if !strings.Contains(stdout, built[0].runID+"  (format "+unreadableVersion+": NOT readable by this reader)") {
		t.Errorf("the signer-pinned path must mark the unreadable run too\n%s", stdout)
	}
}

// TestPruneAbstainDoesNotBlameTheIdentityForAVersionRefusal drives prune over an archive whose RETAINED
// run is at a version this reader does not implement.
//
// The abstain itself is correct and stays: an unenumerable retained run means its live segments cannot
// be told from deletable ones, so nothing may be deleted. What was wrong was the sentence after it.
// It read "Check that identity opens the run with downpipe verify before pruning again", and the
// identity was never the problem: Open refuses the version before it looks at a key at all. An operator
// following that line goes and re-derives a break-glass key from custody shares, which on an M-of-N
// ceremony is several people and a room, and learns nothing.
func TestPruneAbstainDoesNotBlameTheIdentityForAVersionRefusal(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, _ := buildMultiRunArchive(t, dir, []fixtureRun{
		{downpipeID: "dp_future", index: 1, records: 1, formatVersion: unreadableVersion},
		{downpipeID: "dp_future", index: 2, records: 1, formatVersion: unreadableVersion},
	})
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	var code int
	stdout, stderr := captureOutput(t, func() {
		code = run([]string{"prune", "--archive", dir, "--identity", idPath, "--signer", signerPath, "--keep", "1"})
	})
	if code != format.ExitUnverified {
		t.Fatalf("prune = %d, want %d (abstain)\n%s\n%s", code, format.ExitUnverified, stdout, stderr)
	}
	if !strings.Contains(stderr, "prune abstained") || !strings.Contains(stderr, "Nothing was deleted") {
		t.Errorf("the abstain must still say plainly that nothing was deleted\n%s", stderr)
	}
	// THE REMEDY MUST NOT NAME THE IDENTITY.
	if strings.Contains(stderr, "Check that identity opens the run") {
		t.Errorf("the remedy blames the identity for a version refusal; the identity was never read\n%s", stderr)
	}
	// The measured cause has to reach the operator, and it carries its own remedy.
	if !strings.Contains(stderr, unreadableVersion) {
		t.Errorf("the abstain must name the formatVersion that actually stopped it\n%s", stderr)
	}
	if !strings.Contains(stderr, format.ReaderFormatSupport()) {
		t.Errorf("the abstain must say what this reader does implement\n%s", stderr)
	}
}

// TestPruneAbstainOnAnUnreadableRetainedRunStillNamesVerify is the control for the test above: removing
// the identity sentence must not remove the next step with it. Whatever refused, verify over that one
// run is the fuller diagnosis, and that instruction is true for every cause rather than one of them.
func TestPruneAbstainOnAnUnreadableRetainedRunStillNamesVerify(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, built := buildMultiRunArchive(t, dir, []fixtureRun{
		{downpipeID: "dp_future", index: 1, records: 1, formatVersion: unreadableVersion},
		{downpipeID: "dp_future", index: 2, records: 1, formatVersion: unreadableVersion},
	})
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	_, stderr := captureOutput(t, func() {
		run([]string{"prune", "--archive", dir, "--identity", idPath, "--signer", signerPath, "--keep", "1"})
	})
	// Compute abstains on the first RETAINED run in run-id order, and --keep 1 retains the newest, so
	// the run named is the one written second.
	if !strings.Contains(stderr, "downpipe verify --run "+built[1].runID) {
		t.Errorf("the abstain must still name the run to diagnose, with its id\n%s", stderr)
	}
}

// TestInspectWithoutIdentityDoesNotSendTheOperatorToACommandItSaysWillRefuse pins the one line of
// inspect's no-identity block that contradicted the rest of it. The format line says verify will refuse
// this run; the closing line said "Run: downpipe verify". Both were printed, six lines apart, in the
// same block, at exit 0.
func TestInspectWithoutIdentityDoesNotSendTheOperatorToACommandItSaysWillRefuse(t *testing.T) {
	dir := t.TempDir()
	_, _, built := buildMultiRunArchive(t, dir, []fixtureRun{
		{downpipeID: "dp_future", index: 1, records: 1, formatVersion: unreadableVersion},
	})

	var code int
	stdout, _ := captureOutput(t, func() {
		code = run([]string{"inspect", "--archive", dir, "--run", built[0].runID})
	})
	// inspect is a diagnostic viewer and deliberately does not refuse. Exit 0 here is the decision,
	// not an oversight: an operator holding an archive nothing else will open still needs to be told
	// what it IS, and refusing destroys the only use this command has left at that moment.
	if code != 0 {
		t.Fatalf("inspect without --identity = %d, want 0: a viewer that refuses the archive being diagnosed is the wrong tool for the moment it is reached for\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "THIS READER CANNOT READ THIS ARCHIVE") {
		t.Fatalf("the format line must carry the reader's verdict\n%s", stdout)
	}
	if strings.Contains(stdout, "checked. Run: downpipe verify)") {
		t.Errorf("the closing line sends the operator to a command this same block says will refuse\n%s", stdout)
	}
	if !strings.Contains(stdout, "Do NOT run downpipe verify on this run with this build") {
		t.Errorf("the closing line must say what to do instead\n%s", stdout)
	}
}

// TestInspectWithoutIdentityStillNamesVerifyOnAReadableRun is the control. The advice to run verify is
// right in the ordinary case and must survive: it is the whole reason the no-identity block exists.
func TestInspectWithoutIdentityStillNamesVerifyOnAReadableRun(t *testing.T) {
	dir := t.TempDir()
	runID := selftestArchiveRunID(t, dir, []byte("readable run"))

	var code int
	stdout, _ := captureOutput(t, func() {
		code = run([]string{"inspect", "--archive", dir, "--run", runID})
	})
	if code != 0 {
		t.Fatalf("inspect = %d, want 0\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "checked. Run: downpipe verify)") {
		t.Errorf("a readable run must still be sent to verify\n%s", stdout)
	}
	if strings.Contains(stdout, "Do NOT run downpipe verify") {
		t.Errorf("a readable run must not be warned off verify\n%s", stdout)
	}
}
