package main

// Tests for the run() dispatch seam extracted from main(). Each test case asserts
// that the correct exit code is returned without actually calling os.Exit, so the
// suite runs entirely in-process.
//
// Tests that trigger flag.Parse errors (e.g. passing -h to a FlagSet with
// ContinueOnError) may write to stderr; that is expected and harmless.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/source"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// silenceOutput redirects os.Stdout and os.Stderr to /dev/null for the duration
// of the test and restores them on cleanup. This keeps the test log clean when
// subcommands print usage text or version strings.
func silenceOutput(t *testing.T) {
	t.Helper()
	// Open /dev/null write-only: os.Open is O_RDONLY, so writes to the redirected stdout
	// and stderr fds would return EBADF and be silently discarded by fmt rather than
	// correctly written to the null device.
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout = null
	os.Stderr = null
	t.Cleanup(func() {
		os.Stdout = origOut
		os.Stderr = origErr
		_ = null.Close()
	})
}

func TestRunNoArgs(t *testing.T) {
	silenceOutput(t)
	// No arguments: a usage error, code 6, the same as an unrecognised command.
	//
	// It returned 2 until, and the comment here justified that by citing a rule SPEC.md 8.5
	// does not contain. What 8.5 actually says is "`6` a usage or input error", and it reserves `2` for
	// a verdict ABOUT AN ARCHIVE: a missing, invalid, single-half or wrong-signer signature, a failed
	// section 8.3 recomputation, a failed break-glass check or a failed recovery-bundle check. Invoked
	// with no command the tool has opened nothing, so 2 was not a harsh choice, it was a verdict the
	// reader never reached.
	got := run(nil)
	if got != format.ExitUsage {
		t.Fatalf("run(nil) = %d, want %d (ExitUsage)", got, format.ExitUsage)
	}

	got = run([]string{})
	if got != format.ExitUsage {
		t.Fatalf("run([]) = %d, want %d (ExitUsage)", got, format.ExitUsage)
	}

	// The point of the change, asserted rather than described: no-args must not land on the code that
	// means the archive failed to verify. A DR wrapper expanding an unset variable hits this path.
	if format.ExitUsage == format.ExitUnverified {
		t.Fatal("the usage code and the unverified code have become the same value, so this test no longer proves anything")
	}
}

func TestRunUnknownCommand(t *testing.T) {
	silenceOutput(t)
	// An unrecognised command is a usage error: exit code 6 (ExitUsage).
	for _, cmd := range []string{"notacommand", "INSPECT", "Verify", "bogus-sub"} {
		got := run([]string{cmd})
		if got != 6 {
			t.Errorf("run([%q]) = %d, want 6 (ExitUsage)", cmd, got)
		}
	}
}

func TestRunHelpExitsOK(t *testing.T) {
	silenceOutput(t)
	// The three help aliases all succeed with exit code 0.
	for _, cmd := range []string{"help", "-h", "--help"} {
		got := run([]string{cmd})
		if got != 0 {
			t.Errorf("run([%q]) = %d, want 0", cmd, got)
		}
	}
}

func TestRunVersionExitsOK(t *testing.T) {
	silenceOutput(t)
	// All three version forms succeed with exit code 0.
	for _, cmd := range []string{"version", "--version", "-v"} {
		got := run([]string{cmd})
		if got != 0 {
			t.Errorf("run([%q]) = %d, want 0", cmd, got)
		}
	}
}

func TestRunSpecExitsOK(t *testing.T) {
	silenceOutput(t)
	got := run([]string{"spec"})
	if got != 0 {
		t.Fatalf("run([spec]) = %d, want 0", got)
	}
}

// TestRunInspectMissingFlags covers the "inspect needs --run ..." guard: when
// --run is absent the command returns exit 6 (ExitUsage).
func TestRunInspectMissingFlags(t *testing.T) {
	silenceOutput(t)
	// No --run at all.
	got := run([]string{"inspect"})
	if got != 6 {
		t.Fatalf("run([inspect]) = %d, want 6 (ExitUsage, missing --run)", got)
	}
}

// TestRunInspectMissingRunFlag passes a valid source but no --run.
func TestRunInspectMissingRunFlag(t *testing.T) {
	silenceOutput(t)
	got := run([]string{"inspect", "--archive", "/tmp"})
	if got != 6 {
		t.Fatalf("run([inspect --archive /tmp]) = %d, want 6 (ExitUsage, missing --run)", got)
	}
}

// TestRunVerifyMissingFlags covers the "verify needs --run, --identity, --signer ..."
// guard path; missing required flags are usage errors that must exit 6 (ExitUsage).
func TestRunVerifyMissingFlags(t *testing.T) {
	silenceOutput(t)
	// No flags at all.
	got := run([]string{"verify"})
	if got != 6 {
		t.Fatalf("run([verify]) = %d, want 6 (ExitUsage, missing required flags)", got)
	}

	// Only --run supplied; --identity and --signer are absent.
	got = run([]string{"verify", "--archive", "/tmp", "--run", "01JXXXXXXXXXXXXXXXXXXXXXXX"})
	if got != 6 {
		t.Fatalf("run([verify --run only]) = %d, want 6 (ExitUsage, missing --identity and --signer)", got)
	}
}

// TestRunRestoreMissingFlags covers the "restore needs --run, --identity, --signer ..."
// guard path; missing required flags are usage errors that must exit 6 (ExitUsage).
func TestRunRestoreMissingFlags(t *testing.T) {
	silenceOutput(t)
	got := run([]string{"restore"})
	if got != 6 {
		t.Fatalf("run([restore]) = %d, want 6 (ExitUsage, missing required flags)", got)
	}
}

// TestRunRestoreInvalidULID covers the --run ULID guard on the restore path: a
// syntactically invalid --run value is a usage error that exits 6 (ExitUsage) before
// the sink/out guard is ever reached. The sink/out guard itself is covered directly by
// TestRunRestoreMissingSinkOutDirect.
func TestRunRestoreInvalidULID(t *testing.T) {
	silenceOutput(t)
	// Provide the minimum required flags so the guard for --run/--identity/--signer
	// is satisfied, but pass an invalid ULID for --run. We use fake paths; the command
	// validates the flag combination before opening any file so the paths need not
	// exist for this specific guard.
	got := run([]string{
		"restore",
		"--archive", "/tmp",
		"--run", "01JXXXXXXXXXXXXXXXXXXXXXXX",
		"--identity", "/tmp/identity.key",
		"--signer", "/tmp/signer.pub",
		// --sink defaults to "file" and --out is intentionally absent
	})
	// The restore command validates flag combinations in order: --run/--identity/--signer
	// first, then the ULID of --run, then sf.resolve(), then the sink/out combination.
	// Because 01JXXXXXXXXXXXXXXXXXXXXXXX is not a valid ULID the command fails with
	// exit 6 (ExitUsage) at the ULID guard.
	if got != 6 {
		t.Fatalf("run([restore --run invalid-ulid]) = %d, want 6 (ExitUsage)", got)
	}
}

// TestRunInspectInvalidULID confirms that a syntactically invalid --run value is a
// usage/input error that exits 6 (ExitUsage), not a verification failure.
func TestRunInspectInvalidULID(t *testing.T) {
	silenceOutput(t)
	got := run([]string{"inspect", "--archive", "/tmp", "--run", "not-a-ulid"})
	if got != 6 {
		t.Fatalf("run([inspect --run not-a-ulid]) = %d, want 6 (ExitUsage)", got)
	}
}

// TestRunSubcommandFlagHelp verifies that passing -h to a subcommand succeeds, the same as the
// top-level help alias.
//
// It asserted the opposite until, calling a non-zero exit for a printed help a
// "deliberate distinction". It was not a distinction anyone chose: flag.ErrHelp is not an
// ExitError, so it fell through run()'s fallback to exit 1, the code the printed table defines
// as "an I/O or unexpected failure this tool did not otherwise classify". Nothing failed. The
// standard library settles it too: a FlagSet in ExitOnError mode exits 0 on ErrHelp and 2 on a
// parse error, so the two outcomes are distinct everywhere except here, where ContinueOnError
// flattened them into 1.
//
// The old assertion was also weak in a way worth remembering: it only asked for "non-zero", so
// it would have stayed green if a help request had exited 2, the code reserved for a verdict
// that an archive failed to verify. That is the same shape as the no-args defect above.
//
// The whole-dispatch pin lives in flag_parse_exit_test.go; this keeps the single named case.
func TestRunSubcommandFlagHelp(t *testing.T) {
	silenceOutput(t)
	got := run([]string{"inspect", "-h"})
	if got != 0 {
		t.Fatalf("run([inspect -h]) = %d, want 0: the operator asked for the usage and it was printed", got)
	}
}

// TestRunRestoreMissingSinkOutDirect covers the "--sink file needs --out <dir>" guard
// directly. With a non-empty --run, --identity, and --signer the command reaches the
// sink/out check without hitting earlier guards.
func TestRunRestoreMissingSinkOutDirect(t *testing.T) {
	silenceOutput(t)
	got := run([]string{
		"restore",
		"--archive", "/tmp",
		"--run", "ANYRUNID",
		"--identity", "/tmp/identity.key",
		"--signer", "/tmp/signer.pub",
		// --sink defaults to "file" and --out is intentionally absent
	})
	if got != 6 {
		t.Fatalf("run([restore --sink file no --out]) = %d, want 6 (ExitUsage)", got)
	}
}

// TestRunRestoreUnknownSink covers the "unknown --sink" guard: an invalid --sink value
// is a usage error that must exit 6 (ExitUsage).
func TestRunRestoreUnknownSink(t *testing.T) {
	silenceOutput(t)
	got := run([]string{
		"restore",
		"--archive", "/tmp",
		"--run", "ANYRUNID",
		"--identity", "/tmp/identity.key",
		"--signer", "/tmp/signer.pub",
		"--out", "/tmp/out",
		"--sink", "badvalue",
	})
	if got != 6 {
		t.Fatalf("run([restore --sink badvalue]) = %d, want 6 (ExitUsage)", got)
	}
}

// TestRunStoreFlagsMissingSource covers the storeFlags.resolve() usage errors: missing
// --archive and a missing --s3-bucket when --s3-endpoint is supplied. Both are usage
// errors that must exit 6 (ExitUsage).
func TestRunStoreFlagsMissingSource(t *testing.T) {
	silenceOutput(t)
	// No --archive and no --s3-endpoint: the "need --archive ... or --s3-endpoint ..."
	// guard fires via sf.resolve() after the per-subcommand flag checks pass. For inspect
	// that means --run must be present.
	got := run([]string{"inspect", "--run", "ANYRUNID"})
	if got != 6 {
		t.Fatalf("run([inspect --run no-source]) = %d, want 6 (ExitUsage)", got)
	}

	// --s3-endpoint present but no --s3-bucket.
	got = run([]string{"inspect", "--run", "ANYRUNID", "--s3-endpoint", "https://s3.example.com"})
	if got != 6 {
		t.Fatalf("run([inspect --s3-endpoint no --s3-bucket]) = %d, want 6 (ExitUsage)", got)
	}
}

// TestRestoreValueVerified locks in the SPEC.md 12.6 rule: the offline binary
// hash-verifies values written to file and env sinks (via RestoreRecord) so the
// receipt must reflect that. A dry run writes nothing and must report false. A
// secrets-store target cannot be read back by the binary and must also report false.
func TestRestoreValueVerified(t *testing.T) {
	cases := []struct {
		dryRun     bool
		targetKind string
		want       bool
		desc       string
	}{
		{false, "file", true, "real apply to file sink: hash-verified"},
		{false, "env", true, "real apply to env sink: hash-verified"},
		{true, "file", false, "dry run to file sink: nothing written, not verified"},
		{true, "env", false, "dry run to env sink: nothing written, not verified"},
		{false, "secrets-store", false, "secrets-store is write-only: value unverified by offline binary"},
		{true, "secrets-store", false, "dry run to secrets-store: also false"},
	}
	for _, c := range cases {
		got := restoreValueVerified(c.dryRun, c.targetKind)
		if got != c.want {
			t.Errorf("restoreValueVerified(%v, %q) = %v, want %v (%s)", c.dryRun, c.targetKind, got, c.want, c.desc)
		}
	}
}

// TestRunExitCodeConstants locks in the numeric values of the normative exit codes
// (SPEC.md 8.5) so a future edit to format/errors.go that accidentally renumbers
// them fails a test here. The assertions compare the real format.Exit* constants
// against their required numeric values; they cannot pass trivially.
func TestRunExitCodeConstants(t *testing.T) {
	silenceOutput(t)
	check := func(name string, got, want int) {
		t.Helper()
		if got != want {
			t.Errorf("exit constant %s = %d, want %d", name, got, want)
		}
	}
	check("ExitVerified", format.ExitVerified, 0)
	check("ExitUnverified", format.ExitUnverified, 2)
	check("ExitIncomplete", format.ExitIncomplete, 3)
	check("ExitPlaintext", format.ExitPlaintext, 4)
	check("ExitStale", format.ExitStale, 5)
	check("ExitUsage", format.ExitUsage, 6)
}

// TestRunExitCodeMapping exercises the SPEC.md 8.5 exit-code mapping end to end by
// driving run() against a real on-disk archive built with the same public API used by
// selftest. It covers:
//   - ExitUsage (6): a verify invocation with missing required flags
//   - ExitStale (5): verify against an archive whose RUNLOG is absent (freshness failure)
//   - ExitIncomplete (3): verify against an archive with a shard object deleted, so coverage
//     falls below the declared record count
//   - ExitUnverified (2): verify against an archive with a tampered root signature
//
// ExitPlaintext (4) is exercised by TestRestorePlaintextHashMismatchYieldsExitPlaintext.
// Each case here drives run() directly so the mapping is through the real dispatch path, not
// a reimplementation of its logic.
func TestRunExitCodeMapping(t *testing.T) {
	silenceOutput(t)

	// Build a valid one-record archive on disk using the same helper that selftest uses.
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("mapping test value"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}

	// Write the break-glass identity and the operator verifier as key files so run()
	// can read them via identityFlags.loadAndVerifier (same path as a real operator).
	idPath := filepath.Join(dir, "identity.key")
	signerPath := filepath.Join(dir, "signer.pub")
	if err := writeKeyFile(idPath, labelIdentity, crypto.MarshalKEMPrivate(identity)); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	if err := writeKeyFile(signerPath, labelSignerPublic, crypto.MarshalVerifier(verifier)); err != nil {
		t.Fatalf("write signer: %v", err)
	}

	// Baseline: a well-formed archive must verify cleanly (ExitVerified = 0).
	baseArgs := []string{
		"verify",
		"--archive", dir,
		"--run", runID,
		"--identity", idPath,
		"--signer", signerPath,
	}
	if got := run(baseArgs); got != format.ExitVerified {
		t.Fatalf("baseline verify = %d, want %d (ExitVerified)", got, format.ExitVerified)
	}

	// ExitUsage (6): verify with required flags absent. The command guard fires before
	// any I/O, so the archive state is irrelevant.
	if got := run([]string{"verify"}); got != format.ExitUsage {
		t.Errorf("verify no-flags = %d, want %d (ExitUsage)", got, format.ExitUsage)
	}
	if got := run([]string{"verify", "--archive", dir, "--run", runID}); got != format.ExitUsage {
		t.Errorf("verify missing --identity/--signer = %d, want %d (ExitUsage)", got, format.ExitUsage)
	}

	// ExitStale (5): remove the signed RUNLOG so format.Open cannot establish freshness.
	// The freshness check in reader.go line 219 returns a coded ExitStale error when
	// _RECOVERY/RUNLOG is absent; cmdVerify propagates that code to run().
	runlogPath := filepath.Join(dir, "_RECOVERY", "RUNLOG")
	runlogSigPath := filepath.Join(dir, "_RECOVERY", "RUNLOG.sig")
	runlogData, err := os.ReadFile(runlogPath)
	if err != nil {
		t.Fatalf("read RUNLOG: %v", err)
	}
	runlogSigData, err := os.ReadFile(runlogSigPath)
	if err != nil {
		t.Fatalf("read RUNLOG.sig: %v", err)
	}
	if err := os.Remove(runlogPath); err != nil {
		t.Fatalf("remove RUNLOG: %v", err)
	}
	if got := run(baseArgs); got != format.ExitStale {
		t.Errorf("verify absent RUNLOG = %d, want %d (ExitStale)", got, format.ExitStale)
	}
	// Restore the RUNLOG so the tamper case starts from a fresh baseline.
	if err := os.WriteFile(runlogPath, runlogData, 0o644); err != nil {
		t.Fatalf("restore RUNLOG: %v", err)
	}
	if err := os.WriteFile(runlogSigPath, runlogSigData, 0o644); err != nil {
		t.Fatalf("restore RUNLOG.sig: %v", err)
	}

	// ExitIncomplete (3): delete the shard manifest object while leaving the signed root
	// that references it in place. The root signature still verifies, so Open proceeds to
	// open the shards and finds one unreadable; openShards returns a coded ExitIncomplete
	// error (coverage falls below declaredRecordCount, SPEC.md 8.5, 14.3 deleted-shard),
	// which cmdVerify propagates to run(). Restore the shard afterwards so the tamper case
	// below starts from a fresh baseline.
	shardObjPath := filepath.Join(dir, "run", runID, "manifest", "00000.dpe")
	shardData, err := os.ReadFile(shardObjPath)
	if err != nil {
		t.Fatalf("read shard: %v", err)
	}
	if err := os.Remove(shardObjPath); err != nil {
		t.Fatalf("remove shard: %v", err)
	}
	if got := run(baseArgs); got != format.ExitIncomplete {
		t.Errorf("verify deleted shard = %d, want %d (ExitIncomplete)", got, format.ExitIncomplete)
	}
	if err := os.WriteFile(shardObjPath, shardData, 0o644); err != nil {
		t.Fatalf("restore shard: %v", err)
	}

	// ExitUnverified (2): flip the last byte of the root signature so the hybrid
	// verifier rejects it. format.Open returns a coded ExitUnverified error because the
	// signature gate fires before any crypto byte-recovery (reader.go, the switch on
	// the sig file). cmdVerify propagates that code unchanged.
	sigFilePath := filepath.Join(dir, "run", runID, "root.manifest.json.sig")
	sigData, err := os.ReadFile(sigFilePath)
	if err != nil {
		t.Fatalf("read root sig: %v", err)
	}
	tampered := make([]byte, len(sigData))
	copy(tampered, sigData)
	// Flip a byte at the START of the signature, not the end. ML-DSA-87 is randomised and its trailing
	// bytes are the hint encoding, whose final byte is sometimes an insignificant padding zero, so a
	// last-byte flip does not always invalidate the signature (a flaky reject). The first byte is part
	// of a core component (the Ed25519 R / ML-DSA challenge) and is always significant, so flipping it
	// invalidates the hybrid signature deterministically.
	tampered[0] ^= 0x01
	if err := os.WriteFile(sigFilePath, tampered, 0o644); err != nil {
		t.Fatalf("write tampered sig: %v", err)
	}
	if got := run(baseArgs); got != format.ExitUnverified {
		t.Errorf("verify tampered signature = %d, want %d (ExitUnverified)", got, format.ExitUnverified)
	}
}

// TestRunRestorePartialFailureExitsNonZero covers the case where --apply is set and one or
// more record writes fail during restore, the command must exit non-zero rather than
// pretending the partial restore succeeded. The test builds a real one-record archive,
// then sets the output directory read-only so the write fails.
//
// THE CODE IS ASSERTED EXACTLY, and it was "non-zero" until. A write that failed
// because the target was read-only is an uncoded I/O failure, which the printed exit table
// defines as 1: "an I/O or unexpected failure this tool did not otherwise classify. Not a
// verdict on the archive's authenticity". Under "non-zero" this same case could have exited 2
// and stayed green, and 2 is a verdict about the ARCHIVE. An operator whose only fault was a
// read-only directory would have been told their backup failed to verify, which the table
// tells them never to retry and to stop and investigate. The codes here are not
// interchangeable, so the one that is right is the one that is asserted.
func TestRunRestorePartialFailureExitsNonZero(t *testing.T) {
	silenceOutput(t)

	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("partial-restore test value"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}

	idPath := filepath.Join(dir, "identity.key")
	signerPath := filepath.Join(dir, "signer.pub")
	if err := writeKeyFile(idPath, labelIdentity, crypto.MarshalKEMPrivate(identity)); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	if err := writeKeyFile(signerPath, labelSignerPublic, crypto.MarshalVerifier(verifier)); err != nil {
		t.Fatalf("write signer: %v", err)
	}

	// Create the output directory as read-only (0555) so the record write fails with
	// permission denied. The planner sees an empty directory (Existing() returns nothing)
	// and plans the write; Apply then fails the write itself, so result.OK() is false.
	outDir := filepath.Join(dir, "out")
	if err := os.Mkdir(outDir, 0o555); err != nil {
		t.Fatalf("mkdir read-only out: %v", err)
	}
	t.Cleanup(func() {
		// Restore write permission so TempDir cleanup can remove the directory.
		_ = os.Chmod(outDir, 0o755)
	})

	got := run([]string{
		"restore",
		"--archive", dir,
		"--run", runID,
		"--identity", idPath,
		"--signer", signerPath,
		"--out", outDir,
		"--apply",
	})
	if got != exitUncoded {
		t.Fatalf("restore with all writes failing = %d, want %d: a write the target refused is an uncoded I/O failure, and any other code here is a verdict about the archive that this run has no basis for", got, exitUncoded)
	}
}

// TestRestorePlaintextHashMismatchYieldsExitPlaintext exercises the ExitPlaintext (4)
// branch end to end. It builds a one-record archive on disk whose record carries a plaintext
// SHA-384 that does not match its sealed segment, then re-signs the root over the (internally
// consistent) record so the signature and shard-hash gates pass and only the per-record
// plaintext check fails. The mismatch is the writer-bug class SPEC.md 8.5 reserves exit 4
// for, distinct from a tampered-segment AEAD failure (exit 2).
//
// Two assertions are made against the same archive. First, RestoreRecord returns a coded
// ExitPlaintext error: this is the load-bearing exit code consumers read to distinguish a
// hash mismatch from a tampered segment. Second, the restore command surfaces THE SAME CODE,
// which is the half that was not being checked.
//
// WHAT THE LOOSE ASSERTION HID. The command layer asserted only "non-zero", and the comment
// here justified that by stating that the CLI collapses every per-record failure to exit 1 by
// design. restore.go stopped doing that once fixed: it propagates
// result.IntegrityExit, the maximum per-record coded exit, so a plaintext-hash mismatch now
// reaches the operator as 4 and an AEAD failure as 2. The assertion was weak enough to be
// satisfied by both the old behaviour and the new one, so nothing failed when the code moved
// and the comment describing the CLI went stale in place. internal/restore pins IntegrityExit
// exactly, but nothing pinned what the COMMAND does with it, which is the number a DR script
// actually branches on: 4 says the writer produced a record whose bytes do not match their
// recorded hash, and 1 says something unclassified happened and is worth a retry.
func TestRestorePlaintextHashMismatchYieldsExitPlaintext(t *testing.T) {
	silenceOutput(t)

	dir := t.TempDir()
	identity, verifier, runID, err := buildArchiveWrongPlaintextSHA(t, dir, []byte("plaintext-hash test value"))
	if err != nil {
		t.Fatalf("buildArchiveWrongPlaintextSHA: %v", err)
	}

	// Library layer: RestoreRecord must return a coded ExitPlaintext error.
	store := source.NewDirStore(dir)
	r, err := format.Open(store, runID, identity, verifier, format.Options{})
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	recs := r.Records()
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	_, rerr := r.RestoreRecord(recs[0])
	var ee *format.ExitError
	if !errors.As(rerr, &ee) || ee.Code != format.ExitPlaintext {
		t.Fatalf("RestoreRecord plaintext-mismatch error = %v, want a coded ExitPlaintext (%d)", rerr, format.ExitPlaintext)
	}

	// Command layer: restore --apply surfaces the failure as a non-zero exit.
	idPath := filepath.Join(dir, "identity.key")
	signerPath := filepath.Join(dir, "signer.pub")
	if err := writeKeyFile(idPath, labelIdentity, crypto.MarshalKEMPrivate(identity)); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	if err := writeKeyFile(signerPath, labelSignerPublic, crypto.MarshalVerifier(verifier)); err != nil {
		t.Fatalf("write signer: %v", err)
	}
	outDir := filepath.Join(dir, "out")
	if err := os.Mkdir(outDir, 0o755); err != nil {
		t.Fatalf("mkdir out: %v", err)
	}
	if got := run([]string{
		"restore", "--archive", dir, "--run", runID,
		"--identity", idPath, "--signer", signerPath, "--out", outDir, "--apply",
	}); got != format.ExitPlaintext {
		t.Fatalf("restore with a wrong plaintext SHA = %d, want %d (ExitPlaintext): the command must surface the per-record class the library found, not flatten it to a generic failure or report it as a tamper", got, format.ExitPlaintext)
	}
}

// buildArchiveWrongPlaintextSHA assembles a one-record archive on disk exactly like the
// selftest writer except the record's PlaintextSHA is flipped to a wrong digest before the
// record hash is computed. The shard manifest, Merkle root and root signature are all built
// over that record, so the archive verifies cleanly up to RestoreRecord, where the value's
// real SHA-384 fails to match the recorded one (ExitPlaintext). It returns the break-glass
// identity, the signer verifier and the run id.
func buildArchiveWrongPlaintextSHA(t *testing.T, dir string, value []byte) (*crypto.HybridKEMPrivate, *crypto.HybridVerifier, string, error) {
	t.Helper()
	bgPriv, bgPub, err := crypto.GenerateHybridKEM()
	if err != nil {
		return nil, nil, "", err
	}
	_, opPub, err := crypto.GenerateHybridKEM()
	if err != nil {
		return nil, nil, "", err
	}
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		return nil, nil, "", err
	}
	master, err := randomBytes(32)
	if err != nil {
		return nil, nil, "", err
	}
	runRaw, err := randomBytes(16)
	if err != nil {
		return nil, nil, "", err
	}
	runID, err := spec.EncodeULID(runRaw)
	if err != nil {
		return nil, nil, "", err
	}
	runIDBytes, err := spec.DecodeULID(runID)
	if err != nil {
		return nil, nil, "", err
	}
	segNonce, err := randomBytes(spec.StreamNonceSize)
	if err != nil {
		return nil, nil, "", err
	}
	segID, segBytes, err := crypto.SealNonSecretSegment(master, "dp_selftest", spec.AddrSingleNonSecret, spec.CodecNone, value, segNonce)
	if err != nil {
		return nil, nil, "", err
	}
	segHex := crypto.SegIDHex(segID)
	segObj := "seg/" + segHex[:2] + "/" + segHex + ".seg"
	if err := writeObject(dir, segObj, segBytes); err != nil {
		return nil, nil, "", err
	}

	mk := crypto.DeriveMK(master, runIDBytes)
	// A digest that is the correct length but never equals the real plaintext SHA-384, so
	// the per-record check fails without disturbing any other gate.
	wrongSHA := format.SHA384Hex(append([]byte("not-the-value:"), value...))
	keyNameHash := hex.EncodeToString(crypto.NameMAC(crypto.DeriveNameMACKey(mk, runIDBytes), "kv", "greeting"))
	rec := spec.ShardRecord{
		SourceType: "kv", Name: "greeting", KeyNameHash: keyNameHash,
		RecordID:      "recordid00000001",
		PlaintextSize: int64(len(value)), PlaintextSHA: wrongSHA,
		Codec:    spec.CodecNameNone,
		Segments: []spec.Segment{{Object: segObj, ChunkRange: [2]int{0, 1}}},
	}
	rhBytes, err := format.RecordHashOf(rec)
	if err != nil {
		return nil, nil, "", err
	}
	rec.RecordHash = hex.EncodeToString(rhBytes)

	shardNonce, err := randomBytes(spec.StreamNonceSize)
	if err != nil {
		return nil, nil, "", err
	}
	preamble := spec.ShardPreamble{
		FormatVersion: spec.Version, RunID: runID, ShardID: "00000",
		ManifestCodec: spec.CodecNameNone,
		Downpipe:      spec.PreambleDownpipe{Name: "selftest", Cadence: "0 * * * *"},
		Source:        spec.Source{Type: "kv", NamespaceID: "selftest"},
		Window:        spec.Window{Start: "2026-06-06T12:00:00.000Z", End: "2026-06-06T12:00:01.000Z"},
		Consistency:   "crawl",
	}
	shardBytes, shardSHA, err := format.SealShard(preamble, []spec.ShardRecord{rec}, crypto.DeriveManifestWrapKey(mk, runIDBytes, "00000"), shardNonce)
	if err != nil {
		return nil, nil, "", err
	}
	shardObj := "run/" + runID + "/manifest/00000.dpe"
	if err := writeObject(dir, shardObj, shardBytes); err != nil {
		return nil, nil, "", err
	}

	kc := crypto.KeyCommitment(master, runIDBytes)
	wraps, err := crypto.SealToRecipients([32]byte(master), []*crypto.HybridKEMPublic{bgPub, opPub}, kc, rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}
	capsule := make([]spec.CapsuleWrap, len(wraps))
	for i, w := range wraps {
		capsule[i] = spec.CapsuleWrap{Fingerprint: w.Fingerprint, KEMCiphertext: format.B64Encode(w.KEMCiphertext), Sealed: format.B64Encode(w.Sealed)}
	}
	recipients := []spec.Recipient{
		{Fingerprint: crypto.RecipientFingerprint(bgPub), Role: "break-glass", X25519: format.B64Encode(bgPub.X25519.Bytes()), MLKEM: format.B64Encode(bgPub.MLKEM.Bytes())},
		{Fingerprint: crypto.RecipientFingerprint(opPub), Role: "operational", X25519: format.B64Encode(opPub.X25519.Bytes()), MLKEM: format.B64Encode(opPub.MLKEM.Bytes())},
	}
	rhRaw, err := hex.DecodeString(rec.RecordHash)
	if err != nil {
		return nil, nil, "", err
	}
	root := &spec.RootManifest{
		FormatVersion: spec.Version, RunID: runID,
		CreatedAt:  "2026-06-06T12:00:01.000Z",
		DownpipeID: "dp_selftest",
		Envelope:   spec.Envelope{AEAD: "AES-256-GCM", KEM: "X25519+ML-KEM-1024", Signature: "Ed25519+ML-DSA-87", KDF: "HKDF-SHA-384", ChunkSize: spec.ChunkSize, Codec: spec.CodecNameNone},
		Recipients: recipients, MasterCapsule: capsule,
		RecipientSetHash:      hex.EncodeToString(crypto.RecipientSetHash([]*crypto.HybridKEMPublic{bgPub, opPub})),
		KeyCommitment:         hex.EncodeToString(kc),
		BreakGlassPresent:     true,
		Shards:                []spec.ShardRef{{ID: "00000", Object: shardObj, SHA384: shardSHA}},
		ShardCount:            1,
		DeclaredRecordCount:   1,
		MerkleRoot:            hex.EncodeToString(format.MerkleRoot([][]byte{rhRaw})),
		Freshness:             spec.Freshness{PrevRunID: nil, RunlogIndex: 1},
		SigningKeyFingerprint: "edmldsa1:selftest",
	}
	canonical, sig, err := format.SignRoot(root, signer)
	if err != nil {
		return nil, nil, "", err
	}
	if err := writeObject(dir, "run/"+runID+"/root.manifest.json", canonical); err != nil {
		return nil, nil, "", err
	}
	if err := writeObject(dir, "run/"+runID+"/root.manifest.json.sig", []byte(format.B64Encode(sig))); err != nil {
		return nil, nil, "", err
	}

	runlogBytes, err := format.MarshalRunlog([]spec.RunlogEntry{{
		Index: 1, RunID: runID, DownpipeID: "dp_selftest",
		Time: "2026-06-06T12:00:01.000Z", RecordCount: 1, PrevRunID: nil, Status: "active",
	}})
	if err != nil {
		return nil, nil, "", err
	}
	runlogSig, err := signer.Sign(runlogBytes)
	if err != nil {
		return nil, nil, "", err
	}
	if err := writeObject(dir, "_RECOVERY/RUNLOG", runlogBytes); err != nil {
		return nil, nil, "", err
	}
	if err := writeObject(dir, "_RECOVERY/RUNLOG.sig", []byte(format.B64Encode(runlogSig))); err != nil {
		return nil, nil, "", err
	}
	bundle := map[string][]byte{
		"FORMAT.md":  []byte("downpipe/0.1.0 format pointer (test fixture)\n"),
		"RECOVER.md": []byte("recover with the offline break-glass identity and a conformant reader\n"),
	}
	if err := format.WriteBundle(func(key string, b []byte) error { return writeObject(dir, key, b) }, bundle, signer); err != nil {
		return nil, nil, "", err
	}
	return bgPriv, verifier, runID, nil
}

// TestCmdSelftestWriterRoundTrip covers the case where the selftest command exercises the
// selftest writer path (buildSelftestArchive) and then reads the value back through
// format.Open and RestoreRecord, proving the writer and reader interoperate end to end.
// This is a light smoke test: the heavy archive-building logic is already exercised by
// TestRunExitCodeMapping, but that test only calls buildSelftestArchive and not
// cmdSelftest (the full command), so the RestoreRecord round-trip path in selftest.go
// was uncovered by any test that drove run().
func TestCmdSelftestWriterRoundTrip(t *testing.T) {
	silenceOutput(t)
	got := run([]string{"selftest"})
	if got != 0 {
		t.Fatalf("run([selftest]) = %d, want 0", got)
	}
}

// TestMissingReaderInputsNamesOnlyWhatIsMissing keeps the disaster-path usage error honest. The
// message it replaced restated all three inputs plus the source on every failure, so an operator who
// had passed --archive was told they needed a source, which sends them to inspect the one input that
// was already correct.
func TestMissingReaderInputsNamesOnlyWhatIsMissing(t *testing.T) {
	err := missingReaderInputs("restore", "01JXXXXXXXXXXXXXXXXXXXXXXX", true, "", true)
	msg := err.Error()
	if !strings.Contains(msg, "--signer <file>") {
		t.Errorf("the missing input is not named: %q", msg)
	}
	for _, absent := range []string{"--run <runId>", "--identity <file>", "--archive <dir>"} {
		if strings.Contains(msg, absent) {
			t.Errorf("input %q was supplied but the error still asks for it: %q", absent, msg)
		}
	}
	// The whole point: a sheet holder is told signer.pub is a downloaded file, not the fingerprint
	// their sheet prints, and is not in the archive either.
	for _, want := range []string{"downloaded into your recovery kit", "only its fingerprint", "not in the archive"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the signer hint is missing %q: %q", want, msg)
		}
	}
}

// TestReadKeyFileNamesAFingerprintPassedAsAPath is the specific wrong turn a printed recovery sheet
// invites. The sheet lists "signer: edmldsa1:..." under a heading saying these values are safe to
// record, so passing that to --signer is the natural move. The bare os error named the wrong problem
// ("no such file or directory" reads as a typo in a path), which in a real incident, with the console
// gone and no support channel, is the difference between finding the file and giving up.
func TestReadKeyFileNamesAFingerprintPassedAsAPath(t *testing.T) {
	for _, fp := range []string{"edmldsa1:b7813e4697a6c6d6", "dpr1:0cadad822a7eeea4"} {
		_, err := readKeyFile(fp, labelSignerPublic)
		if err == nil {
			t.Fatalf("readKeyFile(%q) succeeded, want an error", fp)
		}
		if !strings.Contains(err.Error(), "is a fingerprint, not a file") {
			t.Errorf("readKeyFile(%q) did not name the value as a fingerprint: %v", fp, err)
		}
	}
}

// TestReadKeyFileKeepsANonExistenceFailureIntact confirms only "does not exist" is reinterpreted. A
// permission problem or a directory is a different fault, and dressing it up as a missing recovery-kit
// file would bury the real cause.
func TestReadKeyFileKeepsANonExistenceFailureIntact(t *testing.T) {
	dir := t.TempDir()
	_, err := readKeyFile(dir, labelSignerPublic)
	if err == nil {
		t.Fatal("readKeyFile on a directory succeeded, want an error")
	}
	if strings.Contains(err.Error(), "downloaded into your recovery kit") {
		t.Errorf("a non-existence read failure was reported as a missing recovery-kit file: %v", err)
	}
}
