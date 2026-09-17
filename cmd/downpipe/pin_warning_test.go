package main

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestWarnIfNoRollbackPin locks down the anti-rollback pin reminder: silent when the pin
// is set (minIndex > 0, the same threshold CheckFreshness treats as "pin active" in
// internal/format/freshness.go), silent when the operator explicitly acknowledged the gap
// with --acknowledge-no-rollback-pin, and otherwise a stderr-only warning that names the
// missing flag, why it matters, and the next action. Stdout must stay untouched: the env
// restore sink writes dotenv lines there, and a warning bleeding into it would corrupt
// machine-readable output.
func TestWarnIfNoRollbackPin(t *testing.T) {
	cases := []struct {
		name     string
		minIndex int64
		ackNoPin bool
		wantWarn bool
	}{
		{"pin unset, not acknowledged: warns", 0, false, true},
		{"pin negative (still no pin): warns", -1, false, true},
		{"pin set: silent", 1, false, false},
		{"pin unset, acknowledged: silent", 0, true, false},
		{"pin set and acknowledged: silent", 1, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stdout, stderr := captureOutput(t, func() {
				warnIfNoRollbackPin(c.minIndex, c.ackNoPin)
			})
			if stdout != "" {
				t.Fatalf("stdout must stay clean, got %q", stdout)
			}
			gotWarn := stderr != ""
			if gotWarn != c.wantWarn {
				t.Fatalf("warnIfNoRollbackPin(%d, %v): got warning=%v (stderr=%q), want %v", c.minIndex, c.ackNoPin, gotWarn, stderr, c.wantWarn)
			}
			if gotWarn {
				for _, want := range []string{"--min-runlog-index", "--acknowledge-no-rollback-pin", "rollback"} {
					if !strings.Contains(stderr, want) {
						t.Errorf("warning missing %q: %q", want, stderr)
					}
				}
			}
		})
	}
}

// THE TEST ABOVE PROVES THE HELPER, NOT THE PRODUCT. It calls warnIfNoRollbackPin directly, so
// everything it asserts stays true of a binary that never calls it. Delete the call from
// restore.go, verify.go or attest.go and the operator loses the anti-rollback reminder outright
// while that test, and the whole package, stay green.
//
// The reminder is a PUBLISHED promise, not an internal nicety. docs/RECOVER.md tells a recoverer:
// "Omit it and the reader still runs, but it prints a stderr warning naming the flag and what it
// protects, every time, so the gap cannot pass unnoticed." Nothing drove that sentence. A recoverer
// who never sees the warning restores from a bucket that may have been rolled back to an older,
// validly signed run and is told nothing, which is the whole failure the pin exists to catch.
//
// So this drives run() end to end for every command that offers the pin, and takes the SET OF
// COMMANDS from the source rather than from a list: a fourth command registering
// --min-runlog-index and forgetting the reminder fails here rather than arriving uncovered.

// pinWarningCommands maps the command file that registers --min-runlog-index to a full command
// line for it, against an archive this test builds. The set is checked against the source below in
// both directions, so this table cannot silently stop covering a command.
//
// attest is here with --signer on purpose: it warns only when a signer is pinned, because that is
// the only case where the RUNLOG signature is actually checked and the reminder's wording is true.
// A keyless attest is documented as presence-only and has no lapsed protection to nag about.
func pinWarningCommands(archive, runID, identity, signer, out string) map[string][]string {
	return map[string][]string{
		"verify.go":  {"verify", "--archive", archive, "--run", runID, "--identity", identity, "--signer", signer},
		"restore.go": {"restore", "--archive", archive, "--run", runID, "--identity", identity, "--signer", signer, "--out", out},
		"attest.go":  {"attest", "--archive", archive, "--run", runID, "--signer", signer},
	}
}

const pinFlag = "min-runlog-index"

func TestEveryCommandOfferingThePinWarnsWhenItIsNotSet(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "arc")
	identity, verifier, runID, err := buildSelftestArchive(archive, []byte("rollback pin wiring"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, archive, identity, verifier)
	cmds := pinWarningCommands(archive, runID, idPath, signerPath, filepath.Join(dir, "out"))

	// The set has to match the source in both directions. A command that registers the flag and
	// is not here is the hole; an entry here for a command that no longer registers it is an
	// assertion about something that cannot happen.
	fset, files := commandFiles(t)
	registers := map[string]bool{}
	for name, file := range files {
		flags, unreadable := registeredFlagNames(fset, file)
		if len(unreadable) > 0 {
			t.Fatalf("%s registers a flag whose name this gate cannot read, so it cannot be shown not to be --%s: %s", name, pinFlag, strings.Join(unreadable, ", "))
		}
		for _, f := range flags {
			if f == pinFlag {
				registers[name] = true
			}
		}
	}
	if len(registers) == 0 {
		t.Fatal("no command registers --" + pinFlag + ", so this gate proved nothing; has the flag been renamed?")
	}
	var drift []string
	for name := range registers {
		if _, ok := cmds[name]; !ok {
			drift = append(drift, name+" registers --"+pinFlag+" and is not driven here")
		}
	}
	for name := range cmds {
		if !registers[name] {
			drift = append(drift, name+" is driven here but no longer registers --"+pinFlag)
		}
	}
	if len(drift) > 0 {
		sort.Strings(drift)
		t.Fatalf("the anti-rollback reminder is not covered for every command that offers the pin:\n  %s\n\n"+
			"Add a command line to pinWarningCommands. docs/RECOVER.md promises the warning prints every\n"+
			"time the pin is omitted, and a command outside this table can drop it silently.", strings.Join(drift, "\n  "))
	}

	const marker = "--min-runlog-index was not set"
	for name, base := range cmds {
		t.Run(name, func(t *testing.T) {
			// Omitted: the warning must print, on stderr, naming the flag and the way out.
			stdout, stderr := captureOutput(t, func() { run(base) })
			if !strings.Contains(stderr, marker) {
				t.Errorf("%s runs with no --%s and prints no anti-rollback reminder, so a recoverer restoring from a rolled-back bucket is told nothing. docs/RECOVER.md promises this warning every time.\nargs: %v\nstderr:\n%s", name, pinFlag, base, stderr)
			}
			if strings.Contains(stdout, marker) {
				t.Errorf("%s printed the reminder to STDOUT, which the env restore sink writes dotenv lines to, so machine-readable output is corrupted.\nstdout:\n%s", name, stdout)
			}

			// Acknowledged: silent. This assertion is an ABSENCE, and the run above is its control:
			// the same command line on the same archive has just been shown to produce the marker,
			// so a silent run here is the acknowledgement working and not the check missing.
			ack := append(append([]string{}, base...), "--acknowledge-no-rollback-pin")
			_, ackErr := captureOutput(t, func() { run(ack) })
			if strings.Contains(ackErr, marker) {
				t.Errorf("%s still printed the reminder after --acknowledge-no-rollback-pin, so the flag documented as silencing it does not.\nargs: %v", name, ack)
			}

			// Pinned: silent for the same reason, and with the same control.
			pinned := append(append([]string{}, base...), "--"+pinFlag, "1")
			_, pinErr := captureOutput(t, func() { run(pinned) })
			if strings.Contains(pinErr, marker) {
				t.Errorf("%s printed the missing-pin reminder while the pin WAS set, which teaches an operator to ignore it.\nargs: %v", name, pinned)
			}
		})
	}
}
