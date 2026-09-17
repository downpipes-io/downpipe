package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
)

// TestVerifyCheckBundleSucceeds drives verify with --check-bundle against a real archive
// whose recovery bundle (FORMAT.md, RECOVER.md, signed SHA384SUMS) was written by
// buildSelftestArchive. The bundle is intact and signed by the same signer, so the check
// passes and verify exits 0, reporting bundle=true. This covers the --check-bundle success
// branch of cmdVerify and format.VerifyBundle's happy path through the command.
func TestVerifyCheckBundleSucceeds(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("bundle check value"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{
			"verify",
			"--archive", dir,
			"--run", runID,
			"--identity", idPath,
			"--signer", signerPath,
			"--check-bundle",
		})
	})
	if code != 0 {
		t.Fatalf("verify --check-bundle = %d, want 0 (intact signed bundle)", code)
	}
	if !strings.Contains(stderr, "bundle=verified") {
		t.Errorf("verify --check-bundle should report bundle=verified\n%s", stderr)
	}
}

// TestVerifySummaryDoesNotSayTheBundleFailedWhenItWasNeverChecked pins the distinction the
// summary line used to lose. bundleOK is only true when --check-bundle was given AND passed, and
// the line printed the raw bool, so a clean archive verified WITHOUT --check-bundle (the default)
// ended `bundle=false` beside `signature=valid` and `structure=complete`. Those two are verdicts,
// so the third reads as one, and an operator deciding whether their archive is sound was told the
// signed recovery bundle had failed. It had not been looked at.
func TestVerifySummaryDoesNotSayTheBundleFailedWhenItWasNeverChecked(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("bundle not checked"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{"verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath})
	})
	if code != 0 {
		t.Fatalf("verify = %d, want 0 on an intact archive", code)
	}
	if strings.Contains(stderr, "bundle=false") {
		t.Errorf("verify without --check-bundle reports bundle=false on an intact archive. NOT CHECKED and CHECKED AND BAD are opposite facts and must not share a word\n%s", stderr)
	}
	if !strings.Contains(stderr, "bundle=not-checked") {
		t.Errorf("verify without --check-bundle should say the bundle was not checked, and name the flag that checks it\n%s", stderr)
	}
}

// TestVerifyCheckBundleTamperedFailsClosed drives verify with --check-bundle against an
// archive whose RECOVER.md has been altered after signing, so the bundle no longer matches
// its signed SHA384SUMS. Without --allow-unverified this is fatal: the command must exit
// non-zero (the bundle gate fails closed). This covers the bundle-failure branch.
func TestVerifyCheckBundleTamperedFailsClosed(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("tampered bundle value"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	// Tamper with the bundled RECOVER.md (under the bundle prefix, where VerifyBundle reads
	// it) so it no longer matches the signed SHA384SUMS. SHA384SUMS itself is left intact and
	// validly signed, so the failure is the file-hash mismatch, not a bad signature.
	recoverPath := filepath.Join(dir, filepath.FromSlash(format.BundlePrefix+"RECOVER.md"))
	if err := os.WriteFile(recoverPath, []byte("tampered recovery instructions\n"), 0o644); err != nil {
		t.Fatalf("tamper bundled RECOVER.md: %v", err)
	}

	var code int
	captureOutput(t, func() {
		code = run([]string{
			"verify",
			"--archive", dir,
			"--run", runID,
			"--identity", idPath,
			"--signer", signerPath,
			"--check-bundle",
		})
	})
	// Pinned to the exact code, not to non-zero. The bundle failing its signed hashes is an
	// UNVERIFIED finding (2), and "non-zero" is equally satisfied by ExitUsage (6), which says the
	// command line was wrong and the archive was never judged. An operator who tampered nothing and
	// is reading 6 goes back to their flags; the finding they needed to see is that the recovery
	// instructions shipped inside their archive no longer match what was signed.
	if code != format.ExitUnverified {
		t.Fatalf("verify --check-bundle with a tampered bundle = %d, want %d (ExitUnverified): the bundle gate fails closed and the failure is a verification finding, not a usage error", code, format.ExitUnverified)
	}
}

// TestVerifyCheckBundleTamperedAllowUnverifiedWarns drives the same tampered-bundle case
// but with --allow-unverified, which downgrades the bundle failure to a warning. Because
// the rest of the archive verifies cleanly, the command still surfaces the unverified
// bundle in the exit code (a clean run with a failed bundle becomes ExitUnverified), and
// prints a warning to stderr. This covers the allow-unverified downgrade branch.
func TestVerifyCheckBundleTamperedAllowUnverifiedWarns(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("warn bundle value"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	recoverPath := filepath.Join(dir, filepath.FromSlash(format.BundlePrefix+"RECOVER.md"))
	if err := os.WriteFile(recoverPath, []byte("tampered recovery instructions\n"), 0o644); err != nil {
		t.Fatalf("tamper bundled RECOVER.md: %v", err)
	}

	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{
			"verify",
			"--archive", dir,
			"--run", runID,
			"--identity", idPath,
			"--signer", signerPath,
			"--check-bundle",
			"--allow-unverified",
		})
	})
	// The bundle failure is downgraded to a warning but still reflected in the exit code as
	// unverified, since a clean run with a failed bundle is coded ExitUnverified.
	if code != format.ExitUnverified {
		t.Fatalf("verify --check-bundle --allow-unverified = %d, want %d (ExitUnverified)", code, format.ExitUnverified)
	}
	if !strings.Contains(stderr, "recovery bundle check failed") {
		t.Errorf("expected a bundle-failure warning on stderr\n%s", stderr)
	}
}

// TestRestoreEnvSinkAppliesAndVerifies drives a real --apply restore to the env sink and
// asserts the record value is written to stdout as a dotenv line and the run exits 0. This
// covers the env-sink apply path of cmdRestore (the reportRestore apply branch and the
// env target), which the dry-run and file-sink tests do not.
func TestRestoreEnvSinkAppliesAndVerifies(t *testing.T) {
	dir := t.TempDir()
	value := []byte("env-sink-restored-value")
	identity, verifier, runID, err := buildSelftestArchive(dir, value)
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	var code int
	stdout, stderr := captureOutput(t, func() {
		code = run([]string{
			"restore",
			"--archive", dir,
			"--run", runID,
			"--identity", idPath,
			"--signer", signerPath,
			"--sink", "env",
			"--apply",
		})
	})
	if code != 0 {
		t.Fatalf("restore --sink env --apply = %d, want 0", code)
	}
	// The env sink writes a dotenv line to stdout carrying the restored value; the apply
	// report (records/bytes) goes to stderr.
	if !strings.Contains(stdout, string(value)) {
		t.Errorf("env sink stdout did not carry the restored value\nstdout: %s", stdout)
	}
	if !strings.Contains(stderr, "restored") {
		t.Errorf("env sink apply did not print a restore report to stderr\nstderr: %s", stderr)
	}
}

// TestRestoreCheckBundleSucceeds drives a real --apply restore to a file sink with
// --check-bundle against an archive whose bundle is intact. This covers the --check-bundle
// success branch of cmdRestore (the recovery-bundle binding the recoverer relies on) and
// the bundleOK=true path; the restore itself must also succeed.
func TestRestoreCheckBundleSucceeds(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("restore bundle ok"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)
	outDir := filepath.Join(dir, "out")

	var code int
	captureOutput(t, func() {
		code = run([]string{
			"restore",
			"--archive", dir,
			"--run", runID,
			"--identity", idPath,
			"--signer", signerPath,
			"--out", outDir,
			"--check-bundle",
			"--apply",
		})
	})
	if code != 0 {
		t.Fatalf("restore --check-bundle --apply = %d, want 0 (intact bundle, clean restore)", code)
	}
	// The record must have been written to the output directory.
	entries, err := os.ReadDir(outDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("restore wrote no files to %s (err=%v)", outDir, err)
	}
}

// TestRestoreCheckBundleTamperedFailsClosed drives a restore with --check-bundle against an
// archive whose bundled RECOVER.md was altered after signing. Without --allow-unverified
// the bundle gate is fatal and the command exits non-zero before restoring, covering the
// restore-side bundle-failure branch.
func TestRestoreCheckBundleTamperedFailsClosed(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("restore bundle bad"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)
	outDir := filepath.Join(dir, "out")

	recoverPath := filepath.Join(dir, filepath.FromSlash(format.BundlePrefix+"RECOVER.md"))
	if err := os.WriteFile(recoverPath, []byte("tampered restore instructions\n"), 0o644); err != nil {
		t.Fatalf("tamper bundled RECOVER.md: %v", err)
	}

	var code int
	captureOutput(t, func() {
		code = run([]string{
			"restore",
			"--archive", dir,
			"--run", runID,
			"--identity", idPath,
			"--signer", signerPath,
			"--out", outDir,
			"--check-bundle",
			"--apply",
		})
	})
	if code != format.ExitUnverified {
		t.Fatalf("restore --check-bundle with a tampered bundle = %d, want %d (ExitUnverified): the bundle gate fails closed before restoring, and the failure is a verification finding", code, format.ExitUnverified)
	}
}

// TestRestoreCheckBundleTamperedAllowUnverified drives the tampered-bundle restore with
// --allow-unverified, which downgrades the bundle failure to a warning and proceeds with
// the restore. The exit code reflects the unverified bundle (a clean run with a failed
// bundle is coded ExitUnverified), covering the warn-and-proceed branch of cmdRestore.
func TestRestoreCheckBundleTamperedAllowUnverified(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("restore bundle warn"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)
	outDir := filepath.Join(dir, "out")

	recoverPath := filepath.Join(dir, filepath.FromSlash(format.BundlePrefix+"RECOVER.md"))
	if err := os.WriteFile(recoverPath, []byte("tampered restore instructions\n"), 0o644); err != nil {
		t.Fatalf("tamper bundled RECOVER.md: %v", err)
	}

	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{
			"restore",
			"--archive", dir,
			"--run", runID,
			"--identity", idPath,
			"--signer", signerPath,
			"--out", outDir,
			"--check-bundle",
			"--allow-unverified",
			"--apply",
		})
	})
	if code != format.ExitUnverified {
		t.Fatalf("restore --check-bundle --allow-unverified = %d, want %d (ExitUnverified)", code, format.ExitUnverified)
	}
	if !strings.Contains(stderr, "recovery bundle check failed") {
		t.Errorf("expected a bundle-failure warning on stderr\n%s", stderr)
	}
}

// TestAttestWithSignerPinned drives attest WITH --signer against a real archive, covering
// the signer-pinned branch of cmdAttest (the verifier is parsed and passed to
// format.Attest) and the "signer-pinned" report line. The selftest archive's root and
// RUNLOG are signed by the matching signer, so the attestation succeeds.
func TestAttestWithSignerPinned(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("attest pinned value"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	_, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{
			"attest",
			"--archive", dir,
			"--run", runID,
			"--signer", signerPath,
		})
	})
	if code != 0 {
		t.Fatalf("attest --signer = %d, want 0", code)
	}
	if !strings.Contains(stderr, "signer-pinned") {
		t.Errorf("attest --signer should report a signer-pinned mode\n%s", stderr)
	}
	if !strings.Contains(stderr, "attested") {
		t.Errorf("attest --signer should report an attested outcome\n%s", stderr)
	}
}

// TestAttestBadSignerFileErrors covers the signer-parse error branch of cmdAttest: a
// --signer path that is not a valid signer public-key file is a clean error, not a panic.
func TestAttestBadSignerFileErrors(t *testing.T) {
	dir := t.TempDir()
	runID := selftestArchiveRunID(t, dir, []byte("attest bad signer"))
	// A file that exists with the right label but unparseable bytes.
	badSigner := filepath.Join(dir, "bad-signer.pub")
	if err := writeKeyFile(badSigner, labelSignerPublic, []byte("not-a-verifier")); err != nil {
		t.Fatalf("write bad signer: %v", err)
	}

	var code int
	captureOutput(t, func() {
		code = run([]string{
			"attest",
			"--archive", dir,
			"--run", runID,
			"--signer", badSigner,
		})
	})
	// ExitUsage, not merely non-zero. The operator's signer.pub does not parse, which is a fact
	// about the file they named and not about the archive, and the loose form accepted
	// ExitUnverified (2) reporting the archive as failing its signature check instead.
	if code != format.ExitUsage {
		t.Fatalf("attest with an unparseable --signer = %d, want %d (ExitUsage): the file the operator named is malformed, which says nothing about the archive", code, format.ExitUsage)
	}
}

// TestCmdInspectBadIdentityErrors covers the identityFlags.loadAndVerifier error path inside
// cmdInspect: an --identity file that does not parse is surfaced as an error before any
// shard is opened.
func TestCmdInspectBadIdentityErrors(t *testing.T) {
	dir := t.TempDir()
	_, verifier, runID, err := buildSelftestArchive(dir, []byte("inspect bad id"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	signerPath := filepath.Join(dir, "signer.pub")
	if werr := writeKeyFile(signerPath, labelSignerPublic, crypto.MarshalVerifier(verifier)); werr != nil {
		t.Fatalf("write signer: %v", werr)
	}
	badID := filepath.Join(dir, "bad-identity.key")
	if err := writeKeyFile(badID, labelIdentity, []byte("not-a-kem-private")); err != nil {
		t.Fatalf("write bad identity: %v", err)
	}

	var code int
	captureOutput(t, func() {
		code = run([]string{
			"inspect",
			"--archive", dir,
			"--run", runID,
			"--identity", badID,
			"--signer", signerPath,
		})
	})
	if code != format.ExitUsage {
		t.Fatalf("inspect with an unparseable --identity = %d, want %d (ExitUsage): the file the operator named is malformed, which says nothing about the archive", code, format.ExitUsage)
	}
}
