package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/prune"
)

// A prune --apply the destination refused used to exit 0, with the refusal on one line of stdout, and
// every delete error of any kind was printed as "REFUSED by the destination (Object Lock or WORM)". A
// script that ran it believed its retention had taken effect. These tests pin the exit status and the
// words.

func TestPruneApplyExitsFourteenWhenTheDestinationRefuses(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("a read-only directory does not refuse a delete for root, or on Windows")
	}
	dir := t.TempDir()
	identity, verifier, runs := buildMultiRunArchive(t, dir, []fixtureRun{
		{downpipeID: "dp_alpha", index: 1, records: 1},
		{downpipeID: "dp_alpha", index: 2, records: 1},
		{downpipeID: "dp_alpha", index: 3, records: 1},
	})
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	// Every segment directory read-only: the filesystem refuses each orphan segment's delete, which is
	// a refusal (the destination answered no), not a failure.
	var locked []string
	_ = filepath.WalkDir(filepath.Join(dir, "seg"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			locked = append(locked, p)
		}
		return nil
	})
	for _, p := range locked {
		if err := os.Chmod(p, 0o500); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, p := range locked {
			_ = os.Chmod(p, 0o700)
		}
	})

	var code int
	stdout, stderr := captureOutput(t, func() {
		code = run([]string{"prune", "--archive", dir, "--identity", idPath, "--signer", signerPath, "--keep", "1", "--apply"})
	})
	if code != format.ExitPruneIncomplete {
		t.Fatalf("prune --apply over a destination that refused every segment delete exited %d, want %d.\nstdout:\n%s\nstderr:\n%s", code, format.ExitPruneIncomplete, stdout, stderr)
	}
	if !strings.Contains(stdout, "deletes REFUSED by the destination: 2") {
		t.Errorf("the report does not count the two refusals.\nstdout:\n%s", stdout)
	}
	if strings.Contains(stdout, "Object Lock or WORM") {
		t.Errorf("the report calls a permission denial a lock.\nstdout:\n%s", stdout)
	}
	// The superseded runs keep their trees, so a later prune can still find the segments.
	for _, r := range runs[:2] {
		if _, err := os.Stat(filepath.Join(dir, "run", r.runID, "root.manifest.json")); err != nil {
			t.Errorf("run %s lost its tree while its segment is still in the destination: %v", r.runID, err)
		}
	}
	if !strings.Contains(stdout, "run-tree objects KEPT") {
		t.Errorf("the report does not say the run trees were kept.\nstdout:\n%s", stdout)
	}
}

func TestPruneExitIsZeroOnlyWhenTheApplyRemovedEverything(t *testing.T) {
	for _, c := range []struct {
		name    string
		res     *prune.Result
		applied bool
		want    int
	}{
		{"a clean apply", &prune.Result{SegmentsDeleted: 2}, true, 0},
		{"a dry run with nothing possible", &prune.Result{Refused: []string{"x"}}, false, 0},
		{"a refused delete", &prune.Result{Refused: []string{"seg/a"}}, true, format.ExitPruneIncomplete},
		{"a failed delete", &prune.Result{Failed: []string{"seg/a"}}, true, format.ExitPruneIncomplete},
		{"a held run tree", &prune.Result{HeldRunObjects: 3}, true, format.ExitPruneIncomplete},
	} {
		err := pruneExit(c.res, c.applied)
		got := 0
		var ee *format.ExitError
		if errors.As(err, &ee) {
			got = ee.Code
		} else if err != nil {
			got = -1
		}
		if got != c.want {
			t.Errorf("%s: exit %d, want %d (%v)", c.name, got, c.want, err)
		}
	}
}

func TestTheShortfallNeverCallsAFailureALock(t *testing.T) {
	lines := strings.Join(pruneShortfallLines(&prune.Result{Failed: []string{"seg/a"}}), "")
	if strings.Contains(lines, "REFUSED") || strings.Contains(strings.ToLower(lines), "lock") {
		t.Errorf("a failure is reported as a refusal or a lock:\n%s", lines)
	}
	if !strings.Contains(lines, "deletes FAILED") {
		t.Errorf("a failure is not reported as one:\n%s", lines)
	}
	named := strings.Join(pruneShortfallLines(&prune.Result{Refused: []string{"a", "b"}, RefusedLockNamed: 1}), "")
	if !strings.Contains(named, "named an Object Lock, retention or legal hold: 1") {
		t.Errorf("a refusal that named a lock is not counted as one:\n%s", named)
	}
}
