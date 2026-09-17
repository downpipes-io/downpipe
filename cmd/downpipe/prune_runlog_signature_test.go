package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/prune"
)

// ONE EDITED WORD IN THE RUNLOG DELETED THE WHOLE ARCHIVE.
//
// The prune decides what to destroy from the keep window and from each entry's status, because a run the
// engine has already marked "superseded" is deletable whatever --keep says. internal/prune/plan.go gives
// the reason to trust that field in as many words, "because that status is in the signed log, and this
// tool does not second-guess it", and nothing on the prune path verified the signature.
//
// Changing "active" to "superseded" in _RECOVERY/RUNLOG, and leaving _RECOVERY/RUNLOG.sig untouched and
// therefore invalid, turned `prune --keep 30` on a three-run archive from a plan that deletes nothing into
// a plan that deletes every run tree and every segment. Exit 0, nothing on stderr. An operator who read
// that plan and armed --apply lost the archive.
//
// The per-run open verifies each root manifest against --signer, so a forged run's CONTENTS cannot be
// planted, and that is not what this is. The RUNLOG chooses which GENUINE runs get deleted, and enumerate
// opens with AllowStale, which is necessary (a superseded run is by definition not the latest for its
// downpipe) and which makes format.Open tolerate the very freshness failure a bad RUNLOG signature raises.
//
// The read-only `keys --which` has verified this signature since it was written. The command that deletes
// did not.
func TestPruneRefusesARunlogThePinnedSignerDidNotSign(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runs := buildMultiRunArchive(t, dir, []fixtureRun{
		{downpipeID: "dp_alpha", index: 1, records: 2},
		{downpipeID: "dp_alpha", index: 2, records: 3},
		{downpipeID: "dp_beta", index: 3, records: 2},
	})
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)
	argv := []string{"prune", "--archive", dir, "--identity", idPath, "--signer", signerPath, "--keep", "30"}

	// THE CONTROL, RUN FIRST. --keep 30 over three runs supersedes nothing, so the untampered archive
	// must plan to delete nothing. Without this the refusal below could be the archive being unprunable
	// for some other reason, and the test would be passing for a reason that has nothing to do with the
	// signature.
	var code int
	stdout, stderr := captureOutput(t, func() { code = run(argv) })
	if code != 0 {
		t.Fatalf("the untampered archive must prune cleanly, got %d.\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "  runs deletable:         0\n") || !strings.Contains(stdout, "  would delete objects in total: 0\n") {
		t.Fatalf("--keep 30 over three runs must supersede nothing.\nstdout:\n%s", stdout)
	}

	runlogPath := filepath.Join(dir, "_RECOVERY", "RUNLOG")
	original, err := os.ReadFile(runlogPath)
	if err != nil {
		t.Fatalf("read runlog: %v", err)
	}
	tampered := bytes.ReplaceAll(original, []byte(`"status":"active"`), []byte(`"status":"superseded"`))
	if bytes.Equal(tampered, original) {
		t.Fatalf("the status field is not spelled as this test expects, so nothing was tampered with and the refusal below would mean nothing.\nrunlog:\n%s", original)
	}
	if err := os.WriteFile(runlogPath, tampered, 0o644); err != nil {
		t.Fatalf("write tampered runlog: %v", err)
	}
	// The signature file is deliberately left exactly as it was, which is the whole point: it is now a
	// valid signature over bytes that are no longer there.

	// WHAT THE TAMPER IS WORTH TO AN ATTACKER, measured rather than asserted. Partition is the function
	// the command feeds this log to, so this is the plan the command would have built.
	entries, err := format.ParseRunlog(tampered)
	if err != nil {
		t.Fatalf("parse tampered runlog: %v", err)
	}
	keepIDs, dropIDs, err := prune.Partition(entries, 30)
	if err != nil {
		t.Fatalf("partition the tampered runlog: %v", err)
	}
	if len(keepIDs) != 0 || len(dropIDs) != len(runs) {
		t.Fatalf("the tamper does not make every run deletable (%d kept, %d dropped of %d), so this test is not measuring the case it describes", len(keepIDs), len(dropIDs), len(runs))
	}

	stdout, stderr = captureOutput(t, func() { code = run(argv) })
	if code != format.ExitUnverified {
		t.Fatalf("a runlog the pinned signer did not sign steers which runs get deleted, so it must be a tamper verdict (exit %d), got %d.\nstdout:\n%s\nstderr:\n%s",
			format.ExitUnverified, code, stdout, stderr)
	}
	// No plan at all. A report printed alongside the refusal would be a plan built from bytes the tool
	// has just said it cannot trust, and an operator reading a plan tends to act on it.
	if strings.Contains(stdout, "prune DRY RUN") || strings.Contains(stdout, "runs deletable") {
		t.Errorf("a plan was printed from a runlog that failed its signature check.\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, "runlog signature does not verify") {
		t.Errorf("the refusal does not name the signature, so the operator cannot tell it from a corrupt archive.\nstderr:\n%s", stderr)
	}

	// And it is the signature that refused, not the edit. Restoring the original bytes must prune cleanly
	// again, which proves the gate is checking the signature rather than rejecting anything it has not
	// seen before.
	if err := os.WriteFile(runlogPath, original, 0o644); err != nil {
		t.Fatalf("restore runlog: %v", err)
	}
	stdout, stderr = captureOutput(t, func() { code = run(argv) })
	if code != 0 {
		t.Fatalf("the restored archive must prune cleanly again, got %d.\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
}

// An archive with no RUNLOG signature cannot be pruned. That is the intended strictness rather than an
// oversight: --signer is mandatory on this command, so there is no keyless mode to fall back to, and
// deleting on the strength of an unsigned log is the defect above with the tamper step left out.
func TestPruneRefusesAnArchiveWithNoRunlogSignature(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, _ := buildMultiRunArchive(t, dir, []fixtureRun{
		{downpipeID: "dp_alpha", index: 1, records: 2},
		{downpipeID: "dp_alpha", index: 2, records: 1},
	})
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)
	argv := []string{"prune", "--archive", dir, "--identity", idPath, "--signer", signerPath, "--keep", "1"}

	// The control: with the signature present this archive has a run to delete, so the refusal below is
	// caused by removing it rather than by there being nothing to do.
	var code int
	stdout, stderr := captureOutput(t, func() { code = run(argv) })
	if code != 0 || !strings.Contains(stdout, "  runs deletable:         1\n") {
		t.Fatalf("this fixture must prune cleanly with one deletable run first, got %d.\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}

	if err := os.Remove(filepath.Join(dir, "_RECOVERY", "RUNLOG.sig")); err != nil {
		t.Fatalf("remove runlog signature: %v", err)
	}
	stdout, stderr = captureOutput(t, func() { code = run(argv) })
	if code == 0 {
		t.Fatalf("a prune planned deletions from a runlog with no signature at all.\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if strings.Contains(stdout, "prune DRY RUN") {
		t.Errorf("a plan was printed from an unsigned runlog.\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, "runlog signature") {
		t.Errorf("the refusal does not say the signature is missing.\nstderr:\n%s", stderr)
	}
}
