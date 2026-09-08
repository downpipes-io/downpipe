package main

import (
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
)

// TestVerifyShallowReportsStructureNotCompleteness proves the overclaiming-output fix:
// a shallow `verify` over a good archive succeeds but its one-line verdict no
// longer claims `completeness=complete`. It reports `structure=complete` and states
// explicitly that segment bytes were NOT decrypted, pointing the operator at `verify --deep`
// (or `restore --sink discard`) for the real, decrypt-every-record drill.
func TestVerifyShallowReportsStructureNotCompleteness(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("recover me"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{"verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath})
	})
	if code != 0 {
		t.Fatalf("shallow verify over a good archive = %d, want 0\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "structure=complete") {
		t.Fatalf("shallow verify must report structure=, got: %q", stderr)
	}
	if !strings.Contains(stderr, "segment bytes NOT decrypted") {
		t.Fatalf("shallow verify must state segment bytes were not decrypted, got: %q", stderr)
	}
	if !strings.Contains(stderr, "verify --deep") {
		t.Fatalf("shallow verify must point at verify --deep, got: %q", stderr)
	}
	if strings.Contains(stderr, "completeness=complete") {
		t.Fatalf("shallow verify must NOT claim completeness=complete (it never decrypts segments), got: %q", stderr)
	}
}

// TestVerifyDeepCatchesTamperedSegment is the headline regression: against an archive
// whose segment ciphertext has been corrupted, a plain `verify` exits 0 (it reads the signed
// manifests only and never the seg/ data objects), while `verify --deep` decrypts every record
// and catches the AEAD failure, exiting 2 (ExitUnverified). It also confirms deep verify over
// the same-but-good archive exits 0 and reports the records as decrypted+verified.
//
// THE SHALLOW EXIT 0 IS A DECISION, AND IT IS PAID FOR IN THE VERDICT LINE. The reason a
// manifests-only pass is worth having is that it needs no identity and no decrypt, so it is
// the cheap check an operator can run over a whole estate. That is only honest if the pass
// says what it did not read, which is why the shallow arm below asserts the caveat text in the
// same breath as the exit code. Asserting the 0 alone would state, as a requirement, that a
// tampered archive may report a clean exit -- and the earlier wording here ("it still exits 0
// today") was a statement about the present rather than a reason, which is the shape that
// turns a known blindness into a contract. If a future shallow pass DID read segment bytes,
// the right change is to make it exit 2 and delete this arm, not to record the new number.
func TestVerifyDeepCatchesTamperedSegment(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("recover me"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	// Deep verify over the GOOD archive: exit 0, and the verdict says the records were
	// decrypted and verified.
	var deepGoodCode int
	_, deepGoodErr := captureOutput(t, func() {
		deepGoodCode = run([]string{"verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--deep"})
	})
	if deepGoodCode != 0 {
		t.Fatalf("deep verify over a good archive = %d, want 0\nstderr: %s", deepGoodCode, deepGoodErr)
	}
	if !strings.Contains(deepGoodErr, "decrypted+verified") {
		t.Fatalf("deep verify must report records decrypted+verified, got: %q", deepGoodErr)
	}
	if !strings.Contains(deepGoodErr, "restorability attestation") {
		t.Fatalf("deep verify must print the discard attestation, got: %q", deepGoodErr)
	}

	// Now corrupt a segment object: flips a tag byte so AEAD verification fails on decrypt.
	tamperOneSegment(t, dir)

	// Plain verify does not read seg/ bytes, so it cannot see this tamper. The exit is 0 and
	// the verdict must say, in the same line, that segment bytes were not decrypted and which
	// command does read them. The caveat is what makes the 0 an honest answer to a narrower
	// question rather than a clean bill of health, so it is asserted here and not only on the
	// good-archive path: a caveat that appears only when there is nothing to hide is no caveat.
	var shallowCode int
	_, shallowErr := captureOutput(t, func() {
		shallowCode = run([]string{"verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath})
	})
	if shallowCode != 0 {
		t.Fatalf("shallow verify over a tampered segment = %d, want 0 (it never reads seg/ bytes)\nstderr: %s", shallowCode, shallowErr)
	}
	for _, want := range []string{"segment bytes NOT decrypted", "verify --deep"} {
		if !strings.Contains(shallowErr, want) {
			t.Errorf("a shallow pass that exits 0 over a tampered archive must still say %q, or the 0 reads as a clean bill of health:\n%s", want, shallowErr)
		}
	}
	if strings.Contains(shallowErr, "completeness=complete") {
		t.Errorf("a shallow pass must never claim completeness, least of all over a tampered segment:\n%s", shallowErr)
	}

	// Deep verify catches it: the AEAD failure exits ExitUnverified (2), not the swallowed 1.
	var deepCode int
	_, deepErr := captureOutput(t, func() {
		deepCode = run([]string{"verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--deep"})
	})
	if deepCode != format.ExitUnverified {
		t.Fatalf("deep verify over a tampered segment = %d, want %d (ExitUnverified)\nstderr: %s", deepCode, format.ExitUnverified, deepErr)
	}
	if !strings.Contains(deepErr, "failed integrity") {
		t.Fatalf("deep verify must report a failed-integrity record, got: %q", deepErr)
	}
}

// TestRestoreDiscardExitCodeIsCoded proves the swallowed-exit-code fix at the
// restore command: `restore --sink discard` over a byte-flipped segment now exits the coded
// ExitUnverified (2, the AEAD class) rather than the historical generic exit 1.
func TestRestoreDiscardExitCodeIsCoded(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte(sentinelValue))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)
	tamperOneSegment(t, dir)

	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{"restore", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--sink", "discard"})
	})
	if code != format.ExitUnverified {
		t.Fatalf("discard restore over a tampered segment = %d, want %d (ExitUnverified, not the swallowed 1)\nstderr: %s", code, format.ExitUnverified, stderr)
	}
}
