package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
)

// captureOutput runs fn with os.Stdout and os.Stderr redirected to in-memory pipes and
// returns whatever each stream received. It lets a test assert on the exact bytes a
// subcommand prints, which the discard-sink and attest tests need to prove no plaintext
// leaks and that the attestation lines are emitted.
func captureOutput(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW

	outCh := make(chan string, 1)
	errCh := make(chan string, 1)
	go func() { var b bytes.Buffer; _, _ = io.Copy(&b, outR); outCh <- b.String() }()
	go func() { var b bytes.Buffer; _, _ = io.Copy(&b, errR); errCh <- b.String() }()

	fn()

	// Restore the real streams and close the write ends so the copier goroutines finish.
	os.Stdout, os.Stderr = origOut, origErr
	_ = outW.Close()
	_ = errW.Close()
	return <-outCh, <-errCh
}

// writeArchiveKeys writes the break-glass identity and the operator verifier as key files
// next to an archive built by buildSelftestArchive, returning their paths.
func writeArchiveKeys(t *testing.T, dir string, identity *crypto.HybridKEMPrivate, verifier *crypto.HybridVerifier) (idPath, signerPath string) {
	t.Helper()
	idPath = filepath.Join(dir, "identity.key")
	signerPath = filepath.Join(dir, "signer.pub")
	if err := writeKeyFile(idPath, labelIdentity, crypto.MarshalKEMPrivate(identity)); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	if err := writeKeyFile(signerPath, labelSignerPublic, crypto.MarshalVerifier(verifier)); err != nil {
		t.Fatalf("write signer: %v", err)
	}
	return idPath, signerPath
}

// sentinelValue is a distinctive plaintext the discard tests look for in the output to
// prove it never leaks. It is deliberately unusual so a substring match is meaningful.
const sentinelValue = "TOP-SECRET-PLAINTEXT-SENTINEL-9f3a7c"

// TestRestoreDiscardSinkVerifiesWithoutPlaintext drives the restore command with
// --sink discard against a real sealed archive. It must:
//   - succeed (exit 0),
//   - print an attestation (records, bytes, failures) and a restore digest to stderr,
//   - write the sentinel plaintext NOWHERE: not to stdout, not to stderr, not to any
//     file under the working directory.
func TestRestoreDiscardSinkVerifiesWithoutPlaintext(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte(sentinelValue))
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
			"--sink", "discard",
		})
	})
	if code != 0 {
		t.Fatalf("discard restore over a good archive = %d, want 0\nstderr: %s", code, stderr)
	}

	// The attestation and digest must be on stderr.
	if !strings.Contains(stderr, "restorability attestation") {
		t.Fatalf("stderr must carry the restorability attestation, got: %q", stderr)
	}
	if !strings.Contains(stderr, "restore digest") {
		t.Fatalf("stderr must carry the restore digest, got: %q", stderr)
	}
	if !strings.Contains(stderr, "verified 1 record(s)") {
		t.Fatalf("stderr must report one verified record, got: %q", stderr)
	}
	if !strings.Contains(stderr, "no plaintext was written") {
		t.Fatalf("stderr must state no plaintext was written, got: %q", stderr)
	}

	// The sentinel plaintext must appear in NEITHER stream.
	if strings.Contains(stdout, sentinelValue) {
		t.Fatalf("the discard sink leaked plaintext to stdout: %q", stdout)
	}
	if strings.Contains(stderr, sentinelValue) {
		t.Fatalf("the discard sink leaked plaintext to stderr: %q", stderr)
	}

	// And no file under the archive directory may contain the sentinel: the discard sink
	// writes nothing, so the only place the value lives is inside the encrypted segment.
	assertNoPlaintextInTree(t, dir, sentinelValue)
}

// assertNoPlaintextInTree walks dir and fails if any regular file contains needle as a
// raw substring. The encrypted segment must not (its bytes are ciphertext), so a match
// would mean the sink wrote a decrypted value somewhere.
func assertNoPlaintextInTree(t *testing.T, dir, needle string) {
	t.Helper()
	err := filepath.Walk(dir, func(p string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if info.IsDir() {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if bytes.Contains(b, []byte(needle)) {
			t.Fatalf("plaintext sentinel found on disk at %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// TestRestoreDiscardSinkFailsOnTamperedArchive drives --sink discard against an archive
// whose segment ciphertext has been corrupted. The record fails its AEAD/hash check on
// the full restore path, so the command must exit non-zero and the attestation must
// report the failure, never claiming a verified record.
func TestRestoreDiscardSinkFailsOnTamperedArchive(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte(sentinelValue))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	// Corrupt the on-disk segment object so AEAD verification fails. The segment lives
	// under <dir>/seg/<aa>/<hex>.seg.
	tamperOneSegment(t, dir)

	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{
			"restore",
			"--archive", dir,
			"--run", runID,
			"--identity", idPath,
			"--signer", signerPath,
			"--sink", "discard",
		})
	})
	// The exact code, not non-zero. A segment that fails its AEAD check is ExitUnverified (2), and
	// SPEC.md 8.5 gives distinct codes to distinct findings for the sake of the recovery script
	// that reads them: 4 is a per-record plaintext-hash mismatch, 3 is coverage below the declared
	// record count, 5 is a rollback. "Non-zero" accepts all of them, so this would have stayed
	// green while a tamper reported itself as a rollback and sent the operator to --allow-stale,
	// which would then present the same tampered archive as restorable.
	if code != format.ExitUnverified {
		t.Fatalf("discard restore over a tampered archive = %d, want %d (ExitUnverified): an authentication failure on a segment is a signature-class finding\nstderr: %s", code, format.ExitUnverified, stderr)
	}
	if !strings.Contains(stderr, "verified 0 record(s)") {
		t.Fatalf("a tampered archive must verify zero records, got: %q", stderr)
	}
	if strings.Contains(stderr, sentinelValue) {
		t.Fatalf("tampered discard run leaked plaintext: %q", stderr)
	}
}

// tamperOneSegment flips a byte in the first .seg object found under dir.
func tamperOneSegment(t *testing.T, dir string) {
	t.Helper()
	var segPath string
	err := filepath.Walk(dir, func(p string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if !info.IsDir() && strings.HasSuffix(p, ".seg") && segPath == "" {
			segPath = p
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if segPath == "" {
		t.Fatal("no segment object found to tamper")
	}
	b, err := os.ReadFile(segPath)
	if err != nil {
		t.Fatalf("read seg: %v", err)
	}
	b[len(b)-1] ^= 0x01
	if err := os.WriteFile(segPath, b, 0o644); err != nil {
		t.Fatalf("write seg: %v", err)
	}
}

// TestAttestNeedsNoIdentityPassesOnGoodArchive proves the attest subcommand needs no
// --identity and passes on a good archive, with and without --signer. Without --signer
// the attestation is keyless; with it the signatures are verified. Neither path is given
// the break-glass identity.
func TestAttestNeedsNoIdentityPassesOnGoodArchive(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("attest me"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	// Only the signer is written; the identity is deliberately never passed to attest.
	_, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	// Keyless: no --identity and no --signer.
	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{"attest", "--archive", dir, "--run", runID})
	})
	if code != 0 {
		t.Fatalf("keyless attest over a good archive = %d, want 0\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "attested:") {
		t.Fatalf("attest must print an 'attested' line, got: %q", stderr)
	}
	if !strings.Contains(stderr, "keyless") {
		t.Fatalf("attest with no signer must report keyless mode, got: %q", stderr)
	}

	// Signer-pinned: still no --identity.
	code = 0
	_, stderr2 := captureOutput(t, func() {
		code = run([]string{"attest", "--archive", dir, "--run", runID, "--signer", signerPath})
	})
	if code != 0 {
		t.Fatalf("signer-pinned attest over a good archive = %d, want 0\nstderr: %s", code, stderr2)
	}
	if !strings.Contains(stderr2, "signer-pinned") {
		t.Fatalf("attest with a signer must report signer-pinned mode, got: %q", stderr2)
	}
}

// TestAttestFailsOnTamperedShard proves attest fails (non-zero, ExitUnverified) on a
// tampered archive, keyless: corrupting a shard breaks its signed SHA-384.
func TestAttestFailsOnTamperedShard(t *testing.T) {
	dir := t.TempDir()
	// This keyless path needs only the run ID; the keypair is unused here.
	runID := selftestArchiveRunID(t, dir, []byte("attest me"))

	// Corrupt the shard manifest object so its SHA-384 no longer matches the signed root.
	shardPath := filepath.Join(dir, "run", runID, "manifest", "00000.dpe")
	sb, err := os.ReadFile(shardPath)
	if err != nil {
		t.Fatalf("read shard: %v", err)
	}
	sb[0] ^= 0x01
	if err := os.WriteFile(shardPath, sb, 0o644); err != nil {
		t.Fatalf("write shard: %v", err)
	}

	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{"attest", "--archive", dir, "--run", runID})
	})
	if code != format.ExitUnverified {
		t.Fatalf("attest over a tampered shard = %d, want %d (ExitUnverified)\nstderr: %s", code, format.ExitUnverified, stderr)
	}
	if !strings.Contains(stderr, "UNATTESTED") {
		t.Fatalf("a failed attestation must print UNATTESTED, got: %q", stderr)
	}
}

// TestAttestFailsOnForgedSignature proves a signer-pinned attest fails on a forged or
// tampered root signature, with no identity supplied.
func TestAttestFailsOnForgedSignature(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("attest me"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	_, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	// Flip a byte well inside the root signature so it stays decodable and long enough but
	// no longer verifies under the pinned signer.
	sigPath := filepath.Join(dir, "run", runID, "root.manifest.json.sig")
	sg, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("read sig: %v", err)
	}
	sg[10] ^= 0x01
	if err := os.WriteFile(sigPath, sg, 0o644); err != nil {
		t.Fatalf("write sig: %v", err)
	}

	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{"attest", "--archive", dir, "--run", runID, "--signer", signerPath})
	})
	if code != format.ExitUnverified {
		t.Fatalf("attest over a forged signature = %d, want %d (ExitUnverified)\nstderr: %s", code, format.ExitUnverified, stderr)
	}
}

// TestAttestMissingRunIsUsageError covers the attest flag guard: a missing --run is a
// usage error (exit 6), the same convention as the other subcommands.
func TestAttestMissingRunIsUsageError(t *testing.T) {
	silenceOutput(t)
	if got := run([]string{"attest", "--archive", "/tmp"}); got != format.ExitUsage {
		t.Fatalf("attest with no --run = %d, want %d (ExitUsage)", got, format.ExitUsage)
	}
}
