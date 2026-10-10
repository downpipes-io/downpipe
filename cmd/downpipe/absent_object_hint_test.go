package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
)

// The absent-object hint shipped with no test, and driving the built binary found it silent on two of
// the six commands its own readsAnArchive set names.
//
//   - `inspect` reports an absent root manifest as an UNCODED error, so the CLI exits 1 and the hint
//     was never reached: a mistyped --run or a wrong --archive on the diagnostic viewer produced a
//     nested "no such file or directory" and no next step.
//   - `keys --which` reports an absent RUNLOG as ExitStale and exits 5, which is what SPEC.md 8.5 says
//     that code covers. But `keys --which` is the command the hint itself tells the operator to run
//     next, so the one recovery instruction the tool gives was the one whose own failure it did not
//     explain.
//
// Neither exit code moved. Only the explanation did. These cases are pinned here because both were
// invisible to the whole test suite while the hint's text was landed and reviewed.

// captureStderr runs fn with os.Stderr redirected and returns what it wrote.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	os.Stderr = orig
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

func TestAbsentObjectHintCoversEveryCommandThatCanMeetOne(t *testing.T) {
	notFound := fmt.Errorf("read object run/X/root.manifest.json: %w", fs.ErrNotExist)

	cases := []struct {
		name string
		err  error
		code int
		cmd  string
		want bool
	}{
		// The coded paths the hint already covered.
		{"verify on a wrong archive path", notFound, format.ExitUnverified, "verify", true},
		{"attest on a wrong archive path", notFound, format.ExitUnverified, "attest", true},
		{"restore of an archive missing a segment", notFound, format.ExitIncomplete, "restore", true},
		{"a plaintext-coded read failure", notFound, format.ExitPlaintext, "restore", true},

		// The two the drive found silent.
		{"inspect, whose absent manifest is uncoded", notFound, exitUncoded, "inspect", true},
		{"keys --which, whose absent RUNLOG is exit 5", notFound, format.ExitStale, "keys", true},

		{"prune, whose absent RUNLOG is exit 5", notFound, format.ExitStale, "prune", true},

		// It must stay silent where it would mislead.
		{"a genuine integrity failure", errors.New("chunk 0 authentication failed"), format.ExitUnverified, "verify", false},
		{"a genuine stale verdict", errors.New("run is absent from the runlog"), format.ExitStale, "verify", false},
		{"a command that reads no archive", notFound, exitUncoded, "keygen", false},
		{"a usage error", notFound, format.ExitUsage, "verify", false},
		{"an unreachable destination, which has its own text", notFound, format.ExitUnreachable, "verify", false},
	}

	covered := map[string]bool{}
	for _, c := range cases {
		if c.want {
			covered[c.cmd] = true
		}
		got := captureStderr(t, func() { hintAbsentObject(c.err, c.code, c.cmd) })
		printed := strings.Contains(got, "an object this run needs was not found at all")
		if printed != c.want {
			t.Errorf("%s: hint printed = %v, want %v (code %d, command %q)", c.name, printed, c.want, c.code, c.cmd)
		}
		if printed && !strings.Contains(got, fmt.Sprintf("Exit %d is the code", c.code)) {
			t.Errorf("%s: the hint names a different exit code than the one being returned", c.name)
		}
	}
	// The table is named for every command that can meet an absent object, and the set of those
	// commands is readsAnArchive. Nothing tied the two together, so a seventh member could be added
	// with no case asserting the hint fires for it, and the whole package stayed green when one was.
	assertCoversReadsAnArchive(t, covered, "asserted here with want=true")
}

// assertCoversReadsAnArchive checks a test's own coverage against readsAnArchive in both directions.
// A member with no case is the hole; a case naming a command readsAnArchive does not carry is a case
// asserting something the hint will never do.
func assertCoversReadsAnArchive(t *testing.T, covered map[string]bool, how string) {
	t.Helper()
	for cmd := range readsAnArchive {
		if !covered[cmd] {
			t.Errorf("%q is in readsAnArchive, so the absent-object hint is meant to fire for it, but it is not %s", cmd, how)
		}
	}
	for cmd := range covered {
		if !readsAnArchive[cmd] {
			t.Errorf("%q is %s but readsAnArchive does not name it, so the hint can never fire for it", cmd, how)
		}
	}
}

// The table above tests the hint's own logic, and on its own it would have passed against the version
// that was silent for inspect and keys, because the defect was in the WIRING: which code each command
// actually exits with, and whether run() called the hint at all on its uncoded branch. So this drives
// run() end to end against an archive path that does not exist, which is the operator's mistake being
// caught, and asserts the hint on stderr for every command that takes a source.
//
// Run against the version this replaced, inspect fails here with exit 1 and no hint, and keys fails
// with exit 5 and no hint.
// The set it drives is checked against readsAnArchive rather than left as a hand-written list. It was
// a hand-written list of four, and restore and prune were members it never drove: both do print the
// hint, so nothing was broken, but nothing here would have said so. Adding a seventh member to
// readsAnArchive left this test, its unit table, and the whole package green with no case driving it.
func TestRunPrintsTheAbsentObjectHintForEveryCommandThatTakesASource(t *testing.T) {
	silenceOutput(t)
	dir := t.TempDir()
	identity, signer := writeThrowawayKeys(t, dir)
	const missing = "/downpipe-absent-object-hint-no-such-dir"
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

	// wantCode is the status each command exits with on an absent archive, stated per command
	// rather than asserted as "non-zero". The codes genuinely differ, because each command meets
	// the missing object at a different point: inspect and prune report it uncoded (1), keys
	// --which reports an absent RUNLOG as ExitStale (5) per SPEC.md 8.5, and the three that open
	// the run reach it inside verification and report ExitUnverified (2).
	//
	// Stating them is what makes this test say anything. "Non-zero" would stay green if inspect
	// moved from 1 to ExitIncomplete (3), which tells a recovery script that coverage fell below
	// the declared record count: a data-loss verdict read off a mistyped path. It would equally
	// stay green if verify moved from 2 to 5, which sends the operator to --allow-stale, a flag
	// that cannot conjure a directory that is not there.
	//
	// hintAbsentObject fires only for this set of codes, so the stderr assertion below catches a
	// move to ExitUsage (6) and nothing else. These four are the moves it does not catch.
	cases := []struct {
		name     string
		cmd      string
		wantCode int
		args     []string
	}{
		{"inspect", "inspect", exitUncoded, []string{"inspect", "--run", runID, "--archive", missing}},
		{"keys --which", "keys", format.ExitStale, []string{"keys", "--which", "--archive", missing}},
		{"attest", "attest", format.ExitUnverified, []string{"attest", "--run", runID, "--archive", missing}},
		{"verify", "verify", format.ExitUnverified, []string{"verify", "--run", runID, "--archive", missing, "--identity", identity, "--signer", signer}},
		{"restore", "restore", format.ExitUnverified, []string{"restore", "--run", runID, "--archive", missing, "--identity", identity, "--signer", signer, "--out", filepath.Join(dir, "out")}},
		{"prune", "prune", exitUncoded, []string{"prune", "--archive", missing, "--identity", identity, "--signer", signer, "--keep", "1"}},
	}

	driven := map[string]bool{}
	for _, c := range cases {
		driven[c.cmd] = true
		var code int
		out := captureStderr(t, func() { code = run(c.args) })
		if !strings.Contains(out, "an object this run needs was not found at all") {
			t.Errorf("%s against a nonexistent archive exited %d with no absent-object hint, so the operator is left with a nested \"no such file or directory\" and no next step. stderr:\n%s", c.name, code, out)
		}
		if code != c.wantCode {
			t.Errorf("%s against a nonexistent archive exited %d, want %d. The codes a recovery script branches on are not interchangeable, so a move here is a change of verdict and has to be a deliberate one", c.name, code, c.wantCode)
		}
	}
	assertCoversReadsAnArchive(t, driven, "driven end to end here")
}

// writeThrowawayKeys mints an identity and signer pair in dir purely so the commands that require
// them can get past flag validation and reach the archive read this test is about.
func writeThrowawayKeys(t *testing.T, dir string) (identity, signer string) {
	t.Helper()
	out := filepath.Join(dir, "keys")
	if err := cmdKeygen([]string{"--out", out}); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return filepath.Join(out, "identity.key"), filepath.Join(out, "signer.pub")
}
