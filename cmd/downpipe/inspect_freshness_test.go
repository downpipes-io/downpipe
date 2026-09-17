package main

import (
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
)

// INSPECT HELD THE VERDICT AND PRINTED NOTHING.
//
// format.Open runs the freshness check on every open and hands the result back on the
// reader. inspect opened with AllowStale and never read it, so a forged
// _RECOVERY/RUNLOG.sig produced the same output as an intact archive, at exit 0, with the
// only difference being nothing at all.
//
// Silence about tampering is defensible only if a reader cannot mistake the command for a
// check. A customer who passes --identity and --signer and is shown the decrypted detail
// has just had the root signature, the master capsule, the key commitment, the recipient
// set, the record count and the Merkle root genuinely verified by this command. What they
// conclude from a clean-looking dump at exit 0 is that the archive checked out, and on the
// one thing inspect withheld they would be wrong.
//
// So it says what it found and still shows the run. It is deliberately not made to refuse:
// verify is the command that enforces, and a diagnostic viewer that refuses the archive an
// operator is trying to diagnose is the wrong tool for the moment they reach for it.
func TestInspectSaysWhatTheFreshnessCheckFound(t *testing.T) {
	// ONE archive, inspected twice, forged in between. Two fixtures would carry two run ids
	// and two signers, and the comparison at the end of this test would then be measuring the
	// fixture rather than the finding.
	dir, runID, idPath, signerPath := freshnessCauseFixture(t)
	inspect := func(t *testing.T) (stdout string, code int) {
		t.Helper()
		stdout, _ = captureOutput(t, func() {
			code = run([]string{"inspect", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath})
		})
		return stdout, code
	}

	intact, intactCode := inspect(t)
	forgeRunlogSignature(t, dir)
	forged, forgedCode := inspect(t)

	// The control on the exit code: BOTH are 0, before and after this change. inspect is not
	// a verifier and was not made into one, so an exit-code assertion could never have caught
	// this and cannot be what proves it fixed.
	if intactCode != 0 || forgedCode != 0 {
		t.Fatalf("inspect must still show both runs at exit 0, got intact=%d forged=%d", intactCode, forgedCode)
	}

	if !strings.Contains(intact, "freshness:  checked and passed") {
		t.Errorf("an intact archive must say the check passed, so that its absence elsewhere means something:\n%s", intact)
	}
	if !strings.Contains(forged, "NOT ESTABLISHED") {
		t.Errorf("a forged RUNLOG signature must be reported:\n%s", forged)
	}
	if !strings.Contains(forged, "verify runlog signature") {
		t.Errorf("the line must name what the reader found, not a family of causes:\n%s", forged)
	}
	if !strings.Contains(forged, "Run: downpipe verify") {
		t.Errorf("the line must name the command that enforces what inspect only reports:\n%s", forged)
	}
	// It must not offer an override. inspect has already waived the gate, so there is nothing
	// here for an operator to acknowledge, and naming a waiver in the output of a command that
	// did not stop is how a waiver comes to look like a routine step.
	if strings.Contains(forged, "--allow-stale") || strings.Contains(forged, "--allow-unverified-runlog") {
		t.Errorf("inspect must not offer an override it has already applied:\n%s", forged)
	}

	// AND WHAT THE CHANGE'S ABSENCE LOOKS LIKE, measured rather than asserted. Strip the one
	// line this item adds from each output and the two are identical: a forged signature and
	// an intact archive were the same screen. Every other assertion in this file would pass
	// against a tool that printed the line only on the intact run, so this is the one that
	// pins the pair.
	if withoutFreshness(intact) != withoutFreshness(forged) {
		t.Fatalf("this control assumes the two outputs differ ONLY in the freshness line; they now differ elsewhere, so the measurement below is not the one described:\nintact:\n%s\nforged:\n%s", intact, forged)
	}
	if intact == forged {
		t.Error("a forged RUNLOG signature still produces the same screen as an intact archive")
	}
}

// withoutFreshness drops the freshness line from an inspect dump, so the rest of the two
// outputs can be compared.
func withoutFreshness(out string) string {
	kept := []string{}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "freshness:") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// Without --identity, inspect opens nothing: no signature is verified, no capsule unwrapped
// and no RUNLOG read, so every line it printed is the bucket's own account of itself. The
// signer line already carried that caveat for one field, and an operator mid-recovery reads
// the block rather than one parenthetical inside it.
func TestInspectWithoutAnIdentitySaysNothingWasVerified(t *testing.T) {
	dir, runID, _, _ := freshnessCauseFixture(t)
	var code int
	stdout, _ := captureOutput(t, func() {
		code = run([]string{"inspect", "--archive", dir, "--run", runID})
	})
	if code != 0 {
		t.Fatalf("inspect without --identity must still show the manifest, got %d", code)
	}
	if !strings.Contains(stdout, "nothing above was verified") {
		t.Errorf("a dump with no verification behind it must say so:\n%s", stdout)
	}
	if strings.Contains(stdout, "freshness:") {
		t.Errorf("no run was opened, so there is no freshness verdict to report:\n%s", stdout)
	}
}

// The customer-facing half of the split, driven through the real dispatch on both commands
// that carry the flags: the age word refuses a forged RUNLOG signature, and the word that
// says a signature is being waived opens it.
func TestTheAgeWordNoLongerOpensAForgedRunlogSignature(t *testing.T) {
	for _, cmd := range []string{"verify", "restore"} {
		t.Run(cmd, func(t *testing.T) {
			base := func(dir, runID, idPath, signerPath string) []string {
				args := []string{cmd, "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--acknowledge-no-rollback-pin"}
				if cmd == "restore" {
					args = append(args, "--sink", "discard")
				}
				return args
			}

			// The control, run first: the untampered archive completes under --allow-stale, so
			// the refusal below is caused by the forged signature and not by the fixture or by
			// the flag having stopped working.
			dir, runID, idPath, signerPath := freshnessCauseFixture(t)
			var code int
			_, stderr := captureOutput(t, func() {
				code = run(append(base(dir, runID, idPath, signerPath), "--allow-stale"))
			})
			if code != 0 {
				t.Fatalf("control: an intact archive must still complete under --allow-stale, got %d\n%s", code, stderr)
			}

			dir, runID, idPath, signerPath = freshnessCauseFixture(t)
			forgeRunlogSignature(t, dir)
			_, stderr = captureOutput(t, func() {
				code = run(append(base(dir, runID, idPath, signerPath), "--allow-stale"))
			})
			if code != format.ExitStale {
				t.Errorf("--allow-stale must not open a run whose RUNLOG signature does not verify, got %d\n%s", code, stderr)
			}
			if !strings.Contains(stderr, "--allow-stale does not cover this") {
				t.Errorf("an operator who has already typed --allow-stale must be told why it refused:\n%s", stderr)
			}

			_, stderr = captureOutput(t, func() {
				code = run(append(base(dir, runID, idPath, signerPath), "--allow-unverified-runlog"))
			})
			if code != 0 {
				t.Errorf("--allow-unverified-runlog is the acknowledgement for this state and must open it, got %d\n%s", code, stderr)
			}
			if !strings.Contains(stderr, "COULD NOT BE RUN") {
				t.Errorf("the override warning must still say nothing was established:\n%s", stderr)
			}
			if strings.Contains(stderr, "overridden by --allow-stale or") {
				t.Errorf("the warning must not name a flag that cannot reach this state:\n%s", stderr)
			}
		})
	}
}
