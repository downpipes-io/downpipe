package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
)

// The exit status for a FILE NAMED BY A FLAG THAT CANNOT BE READ is pinned here, for every
// command that takes one.
//
// WHAT WENT WRONG WITHOUT THIS. The contract is ExitUsage (6): the operator named a path and the
// path is wrong, so the fix is on the command line. recombine, setup, and every command reading
// --identity or --signer already coded it that way. unseal-export did not: its --in and --sig
// read errors were returned uncoded and run() gave them exitUncoded (1), which the printed table
// defines as "an I/O or unexpected failure this tool did not otherwise classify". So on the one
// command an operator reaches for after a total account loss, a mistyped path read as something
// having gone wrong INSIDE the tool, and the honest next step (look at what you typed) was the
// one reading the exit code did not suggest.
//
// This drives run() end to end rather than calling the command functions, so what is pinned is
// the process exit status a recovery script branches on, not an intermediate error value. Each
// case asserts the EXACT code. "Non-zero" would pass every one of these while the command exited
// 2, the code that means an archive failed to verify: a wrong path reported as a tamper finding
// is strictly worse than a wrong path reported as an unclassified failure, and a loose assertion
// accepts both.

// inputFileFlags names, per dispatched command, the flags that name a file the command must be
// able to READ. An empty slice states that a command takes none, so the completeness check below
// can tell "accounted for and takes none" from "nobody has looked at this command yet".
var inputFileFlags = map[string][]string{
	"attest":        {"--signer"},
	"help":          {},
	"init":          {},
	"inspect":       {"--identity", "--signer"},
	"keygen":        {},
	"keys":          {"--recipient", "--signer"},
	"preflight":     {},
	"prune":         {"--identity", "--signer"},
	"recombine":     {"--wrapping-key", "--envelope"},
	"restore":       {"--identity", "--signer", "--receipt-signer"},
	"selftest":      {},
	"setup":         {"--config"},
	"spec":          {},
	"unseal-export": {"--in", "--sig", "--signer", "--identity"},
	"update":        {},
	"verify":        {"--identity", "--signer", "--receipt-signer"},
	"version":       {},
}

// noSucceedingBaseLine names the commands with no command line that can succeed offline, so the
// base-line sanity check below skips them rather than being quietly dropped for everyone.
var noSucceedingBaseLine = map[string]bool{"recombine": true, "setup": true}

// baseArgs returns the rest of the command line each command needs to get PAST its required-flag
// check and reach the file read this test is about, with every other path valid.
func baseArgs(cmd, archive, runID, good, out string) []string {
	id := filepath.Join(good, "identity.key")
	signer := filepath.Join(good, "signer.pub")
	switch cmd {
	case "attest":
		return []string{"attest", "--archive", archive, "--run", runID}
	case "inspect":
		return []string{"inspect", "--archive", archive, "--run", runID, "--identity", id, "--signer", signer}
	case "keys":
		return []string{"keys", "--fingerprint", "--recipient", filepath.Join(good, "recipient.pub"), "--signer", signer}
	case "prune":
		return []string{"prune", "--archive", archive, "--identity", id, "--signer", signer, "--keep", "1"}
	case "recombine":
		return []string{"recombine", "--envelope", filepath.Join(good, "no-such-envelope"), "--out", filepath.Join(out, "recombined.key")}
	case "restore":
		return []string{"restore", "--archive", archive, "--run", runID, "--identity", id, "--signer", signer, "--sink", "discard", "--receipt", filepath.Join(out, "r.json")}
	case "setup":
		return []string{"setup", "--config", filepath.Join(good, "no-such-config")}
	case "unseal-export":
		// The engine-produced fixture, so every path but the one under test is genuinely valid and
		// the command reaches the read this case is about. Substituting an arbitrary readable file
		// for --sig instead makes the signature fail to decode, which is a real ExitUnverified and
		// would have this test asserting the wrong thing about the wrong flag.
		fx := filepath.Join("testdata", "sealed-export")
		return []string{"unseal-export", "--in", filepath.Join(fx, "sealed.json"), "--sig", filepath.Join(fx, "sealed.json.sig"), "--signer", filepath.Join(fx, "signer.pub"), "--identity", filepath.Join(fx, "identity.key"), "--out", filepath.Join(out, "recovered.json")}
	case "verify":
		return []string{"verify", "--archive", archive, "--run", runID, "--identity", id, "--signer", signer, "--receipt", filepath.Join(out, "r.json")}
	}
	return nil
}

// replaceFlagValue sets one flag to path, appending the flag if it is not already present.
func replaceFlagValue(args []string, flag, path string) []string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			out := append([]string{}, args...)
			out[i+1] = path
			return out
		}
	}
	return append(append([]string{}, args...), flag, path)
}

func TestUnreadableInputFileIsAUsageError(t *testing.T) {
	silenceOutput(t)
	dir := t.TempDir()
	// The archive's OWN identity and signer, so every base command line below actually succeeds
	// and each case is a one-variable change. With an unrelated keypair the reader-side commands
	// fail on the mismatch before reaching the read under test, and a case could then pass for a
	// reason that has nothing to do with what it claims to assert.
	archive := filepath.Join(dir, "arc")
	identity, verifier, runID, err := buildSelftestArchive(archive, []byte("input file exit contract"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	good := filepath.Join(dir, "keys")
	if err := os.MkdirAll(good, 0o700); err != nil {
		t.Fatalf("mkdir keys: %v", err)
	}
	// The archive's pair goes in `good` as identity.key and signer.pub; keygen supplies the
	// recipient.pub that only `keys --fingerprint` needs, minted into its own directory because
	// writeKeyFile opens with O_EXCL and will not write over what is already there.
	writeArchiveKeys(t, good, identity, verifier)
	minted := filepath.Join(dir, "minted")
	if err := cmdKeygen([]string{"--out", minted}); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := os.Rename(filepath.Join(minted, "recipient.pub"), filepath.Join(good, "recipient.pub")); err != nil {
		t.Fatalf("place recipient.pub: %v", err)
	}
	out := t.TempDir()
	missing := filepath.Join(dir, "no-such-file-anywhere")

	checked := 0
	for _, cmd := range dispatchCases(t) {
		flags, ok := inputFileFlags[cmd]
		if !ok {
			t.Errorf("%q is dispatched but inputFileFlags does not account for it. List the flags that name a file it must read, or an empty slice if it takes none; a new command must not arrive uncovered", cmd)
			continue
		}
		base := baseArgs(cmd, archive, runID, good, out)
		if len(flags) > 0 && base == nil {
			t.Fatalf("%s names input-file flags but baseArgs has no command line for it", cmd)
		}
		// The base line must succeed, or a case below could pass because the command failed for a
		// reason that has nothing to do with the flag it varies. recombine and setup are excluded
		// because neither has a base that can succeed offline: setup would provision against
		// Cloudflare and recombine needs custody artefacts, so their base lines name an absent file
		// deliberately and every case is already the only variable.
		if len(flags) > 0 && !noSucceedingBaseLine[cmd] {
			if got := run(base); got != 0 {
				t.Errorf("the base command line for %s exited %d, want 0, so every case below varies two things and proves nothing about the flag it names.\nargs: %v", cmd, got, base)
				continue
			}
		}
		for _, flag := range flags {
			checked++
			args := replaceFlagValue(base, flag, missing)
			if got := run(args); got != format.ExitUsage {
				t.Errorf("%s with an unreadable %s exited %d, want %d (ExitUsage): the operator named a path that is not there, which is a usage error and not a finding about the archive.\nargs: %v", cmd, flag, got, format.ExitUsage, args)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no command line was driven, so this test proved nothing")
	}
}

// TestBadReceiptSignerDoesNotMaskTheVerdict pins the ORDER, which the code above cannot see: the
// receipt signer is read BEFORE the run, not after it.
//
// WHAT WENT WRONG WITHOUT THIS. --receipt-signer was read only inside emitReceipt, and verify and
// restore both emit the receipt before returning their own verdict. So on a tampered archive the
// command found the tamper, printed it, and then exited 6 because of the flag: a DR script
// branching on the status read "fix your command line" for an archive that had just failed its
// hash check. The records had already been written by then, and on a large archive the operator
// waited out the whole run to be told about a typo.
//
// The assertions are the two halves of the fix and neither implies the other. Exiting 6 is right
// only if nothing ran; running and then exiting 6 is the defect.
//
// THE SECOND HALF IS AN ABSENCE, AND AN ABSENCE NEEDS A CONTROL. "The tamper text is not on
// stderr" was asserted against two hand-written strings that nothing else in the repository
// pinned. Reword either message, which is an ordinary edit to make (the verify line was reworded
// once already, at verify.go:111), and the assertion becomes vacuous: it goes green whether the
// run happened or not, and the defect it stands over can walk back in unnoticed. So each case now
// runs the SAME command line on the SAME tampered archive with the bad flag removed, and requires
// the marker to appear. A silent run is then the fix working rather than the check having stopped
// matching.
func TestBadReceiptSignerDoesNotMaskTheVerdict(t *testing.T) {
	silenceOutput(t)
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("receipt signer ordering"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)
	tamperOneSegment(t, dir)
	missing := filepath.Join(dir, "no-such-receipt-signer.key")

	// ranMarkers are the strings that only appear once a command has actually read the archive
	// and reached its verdict on it. They are what the absence below means, so they are named
	// once and used in both directions.
	ranMarkers := []string{"did NOT decrypt", "unverified:"}
	sawVerdict := func(s string) bool {
		for _, m := range ranMarkers {
			if strings.Contains(s, m) {
				return true
			}
		}
		return false
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		// --deep, because the control proved the shallow form could never fire this assertion.
		// tamperOneSegment flips a byte inside a segment, and a shallow verify checks manifests
		// only: it printed "verified: ... signature=valid structure=complete" and exited 0 on
		// this very archive, so there was no verdict for the flag to mask and the verify half of
		// this test asserted the absence of text that was never going to be there. --deep is what
		// decrypts the segments and reaches the tamper, and it is also the run whose cost is the
		// point: the operator waits out a full decrypt before being told about a typo.
		{"verify", []string{"verify", "--deep", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--receipt", filepath.Join(dir, "r.json")}},
		{"restore", []string{"restore", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--sink", "discard", "--receipt", filepath.Join(dir, "r2.json")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The control. Same command line, same tampered archive, no bad flag: the command
			// runs and reaches its verdict, so the markers the absence assertion looks for are
			// known to be the ones this build actually prints.
			_, control := captureOutput(t, func() { run(tc.args) })
			if !sawVerdict(control) {
				t.Fatalf("%s on a tampered archive printed none of %v, so the absence assertion below would pass whether the run happened or not. Update the markers to whatever this build prints; a control that cannot fire is not a control.\nstderr:\n%s", tc.name, ranMarkers, control)
			}

			args := append(append([]string{}, tc.args...), "--receipt-signer", missing)
			var code int
			_, stderr := captureOutput(t, func() { code = run(args) })
			if code != format.ExitUsage {
				t.Errorf("%s with an unreadable --receipt-signer exited %d, want %d (ExitUsage)", tc.name, code, format.ExitUsage)
			}
			// The run must not have happened. If it had, the tamper would be on stderr and the
			// exit code would be reporting the flag instead of the archive.
			if sawVerdict(stderr) {
				t.Errorf("%s ran the whole archive and THEN failed on the flag, so its integrity verdict was replaced by a usage code. stderr:\n%s", tc.name, stderr)
			}
		})
	}
}
