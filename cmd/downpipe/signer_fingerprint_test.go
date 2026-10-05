package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
)

// These drive --signer-fingerprint (signer_source.go) end to end against a real sealed archive.
//
// The claim under test: a recoverer who holds the bucket, the break-glass identity and the printed
// recovery sheet can verify and restore, because the bundle carries signer.pub and the sheet's
// fingerprint pins it. The trust anchor stays the offline sheet: a bucket copy that does not match
// the pin is refused, whoever wrote it.

// bundledSignerPath is where the bundled signer.pub of an archive under dir lives on disk.
func bundledSignerPath(dir string) string {
	return filepath.Join(dir, filepath.FromSlash(format.BundlePrefix+bundleSignerName))
}

// sealedArchive builds a selftest archive and returns its run id, the identity path and the pinned
// fingerprint a recovery sheet for it would print.
func sealedArchive(t *testing.T, value string) (dir, runID, idPath, signerPath, pin string) {
	t.Helper()
	dir = t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte(value))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath = writeArchiveKeys(t, t.TempDir(), identity, verifier)
	return dir, runID, idPath, signerPath, crypto.SignerFingerprint(verifier)
}

// runCmd runs one reader command and returns its exit code and stderr.
func runCmd(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var code int
	_, stderr := captureOutput(t, func() { code = run(args) })
	return code, stderr
}

// The archive carries the signer public key, and it is the key that sealed the archive.
func TestTheBundleCarriesTheSignerPublicKey(t *testing.T) {
	dir, _, _, signerPath, _ := sealedArchive(t, "bundle carries signer")
	got, err := os.ReadFile(bundledSignerPath(dir))
	if err != nil {
		t.Fatalf("the recovery bundle carries no signer.pub: %v", err)
	}
	want, err := os.ReadFile(signerPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("the bundled signer.pub is not the key that sealed the archive\nbundle: %q\nkit:    %q", got, want)
	}
}

// The claim itself: bucket + identity + the sheet's fingerprint verifies and restores, no kit file.
func TestSignerFingerprintVerifiesAndRestoresWithoutTheKitFile(t *testing.T) {
	dir, runID, idPath, _, pin := sealedArchive(t, "pinned from the sheet")

	code, stderr := runCmd(t, "verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer-fingerprint", pin, "--acknowledge-no-rollback-pin")
	if code != 0 {
		t.Fatalf("verify --signer-fingerprint = %d, want 0\n%s", code, stderr)
	}

	out := filepath.Join(t.TempDir(), "out")
	code, stderr = runCmd(t, "restore", "--archive", dir, "--run", runID, "--identity", idPath, "--signer-fingerprint", pin, "--out", out, "--apply", "--acknowledge-no-rollback-pin")
	if code != 0 {
		t.Fatalf("restore --signer-fingerprint --apply = %d, want 0\n%s", code, stderr)
	}
	if !nonEmptyDir(out) {
		t.Fatalf("restore --signer-fingerprint --apply exited 0 and wrote nothing to %s", out)
	}
}

// A sheet value copied by hand may carry upper-case hex or stray whitespace. Both are the same pin.
func TestSignerFingerprintAcceptsTheSheetValueAsCopiedByHand(t *testing.T) {
	dir, runID, idPath, _, pin := sealedArchive(t, "hand copied pin")
	handCopied := "  edmldsa1:" + strings.ToUpper(strings.TrimPrefix(pin, "edmldsa1:")) + " "
	code, stderr := runCmd(t, "verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer-fingerprint", handCopied, "--acknowledge-no-rollback-pin")
	if code != 0 {
		t.Fatalf("verify with an upper-case, space-padded pin = %d, want 0\n%s", code, stderr)
	}
}

// THE TAMPER CASE. Someone with write access to the bucket replaces signer.pub with their own key.
// The sheet's pin does not name that key, so the reader refuses it before reading anything with it.
func TestSignerFingerprintRefusesAReplacedBundledCopy(t *testing.T) {
	dir, runID, idPath, _, pin := sealedArchive(t, "replaced signer copy")
	_, attacker, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundledSignerPath(dir), []byte(keyFileLine(labelSignerPublic, crypto.MarshalVerifier(attacker))), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range [][]string{
		{"verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer-fingerprint", pin},
		{"restore", "--archive", dir, "--run", runID, "--identity", idPath, "--signer-fingerprint", pin, "--out", filepath.Join(t.TempDir(), "out"), "--apply"},
	} {
		code, stderr := runCmd(t, cmd...)
		if code != format.ExitUnverified {
			t.Errorf("%s with a replaced bundled signer.pub = %d, want %d (ExitUnverified)\n%s", cmd[0], code, format.ExitUnverified, stderr)
		}
		// The refusal names the rotation case too. The bucket keeps only the current signer's copy,
		// so a later sheet cannot stand in for the kit file on a run the earlier signer sealed.
		for _, want := range []string{"refusing the signer public key", crypto.SignerFingerprint(attacker), pin, "--signer", "only the current signer's copy", "only for runs sealed after that rotation"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("%s refusal does not say %q\n%s", cmd[0], want, stderr)
			}
		}
	}
}

// A copy that is not a signer key file at all is refused the same way, not reported as a usage error.
func TestSignerFingerprintRefusesACorruptBundledCopy(t *testing.T) {
	dir, runID, idPath, _, pin := sealedArchive(t, "corrupt signer copy")
	for name, body := range map[string]string{
		"wrong label":       "downpipe-recipient-v1 AAAA\n",
		"truncated payload": labelSignerPublic + " AAAA\n",
		"oversized":         strings.Repeat("A", format.MaxBundledSignerBytes+1),
	} {
		if err := os.WriteFile(bundledSignerPath(dir), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		code, stderr := runCmd(t, "verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer-fingerprint", pin)
		if code != format.ExitUnverified {
			t.Errorf("%s: verify = %d, want %d (ExitUnverified)\n%s", name, code, format.ExitUnverified, stderr)
		}
		if !strings.Contains(stderr, "refusing the signer public key") {
			t.Errorf("%s: the refusal does not name the bundled copy\n%s", name, stderr)
		}
	}
}

// A pin from a different key ceremony does not match the archive's own copy, so it is refused too.
func TestSignerFingerprintRefusesAPinThatNamesAnotherSigner(t *testing.T) {
	dir, runID, idPath, _, _ := sealedArchive(t, "wrong pin")
	_, other, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	code, stderr := runCmd(t, "verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer-fingerprint", crypto.SignerFingerprint(other))
	if code != format.ExitUnverified {
		t.Fatalf("verify with a pin naming another signer = %d, want %d\n%s", code, format.ExitUnverified, stderr)
	}
}

// An archive written before the bundle carried a copy has nothing to pin. The operator is told to
// use the kit file, as a usage error (6): the archive was never judged.
func TestSignerFingerprintOnAnArchiveWithNoBundledCopyNamesTheKitFile(t *testing.T) {
	dir, runID, idPath, _, pin := sealedArchive(t, "no bundled copy")
	if err := os.Remove(bundledSignerPath(dir)); err != nil {
		t.Fatal(err)
	}
	code, stderr := runCmd(t, "verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer-fingerprint", pin)
	if code != format.ExitUsage {
		t.Fatalf("verify --signer-fingerprint on an archive with no bundled signer.pub = %d, want %d (ExitUsage)\n%s", code, format.ExitUsage, stderr)
	}
	for _, want := range []string{"has no", "engine 0.3.7", "--signer"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the message does not say %q\n%s", want, stderr)
		}
	}
}

// A malformed pin is a usage error before any read, so a truncated copy from the sheet is named as
// truncated rather than reported as a mismatch against the archive.
func TestSignerFingerprintRejectsAMalformedPin(t *testing.T) {
	dir, runID, idPath, _, pin := sealedArchive(t, "malformed pin")
	for _, bad := range []string{pin[:40], "dpr1:" + strings.TrimPrefix(pin, "edmldsa1:"), "edmldsa1:zz" + pin[len("edmldsa1:")+2:]} {
		code, stderr := runCmd(t, "verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer-fingerprint", bad)
		if code != format.ExitUsage {
			t.Errorf("verify --signer-fingerprint %q = %d, want %d (ExitUsage)\n%s", bad, code, format.ExitUsage, stderr)
		}
	}
}

// The old route is unchanged: --signer with the kit file verifies, and it does not need the bundled
// copy at all.
func TestSignerFileStillVerifiesWithoutTheBundledCopy(t *testing.T) {
	dir, runID, idPath, signerPath, _ := sealedArchive(t, "kit file route")
	if err := os.Remove(bundledSignerPath(dir)); err != nil {
		t.Fatal(err)
	}
	code, stderr := runCmd(t, "verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--acknowledge-no-rollback-pin")
	if code != 0 {
		t.Fatalf("verify --signer = %d, want 0\n%s", code, stderr)
	}
}

// Both flags: the kit file is checked against the pin. A match verifies; a mismatch is refused.
func TestSignerFileAndPinTogetherCrossCheck(t *testing.T) {
	dir, runID, idPath, signerPath, pin := sealedArchive(t, "cross check")
	code, stderr := runCmd(t, "verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--signer-fingerprint", pin, "--acknowledge-no-rollback-pin")
	if code != 0 {
		t.Fatalf("verify with a matching --signer and --signer-fingerprint = %d, want 0\n%s", code, stderr)
	}
	_, other, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	code, stderr = runCmd(t, "verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--signer-fingerprint", crypto.SignerFingerprint(other))
	if code != format.ExitUsage {
		t.Fatalf("verify with a --signer file that does not match --signer-fingerprint = %d, want %d\n%s", code, format.ExitUsage, stderr)
	}
	if !strings.Contains(stderr, "different key ceremony") {
		t.Errorf("the mismatch does not say the two inputs are from different ceremonies\n%s", stderr)
	}
}

// A signer fingerprint passed to --signer as though it were a path is pointed at the flag that takes it.
func TestAFingerprintPassedToSignerIsPointedAtTheFingerprintFlag(t *testing.T) {
	_, err := readKeyFile("edmldsa1:b7813e4697a6c6d6", labelSignerPublic)
	if err == nil || !strings.Contains(err.Error(), "--signer-fingerprint") {
		t.Fatalf("a signer fingerprint passed as a --signer path is not pointed at --signer-fingerprint: %v", err)
	}
	_, err = readKeyFile("dpr1:0cadad822a7eeea4", labelRecipient)
	if err == nil || strings.Contains(err.Error(), "--signer-fingerprint") {
		t.Fatalf("a recipient fingerprint is pointed at --signer-fingerprint, which cannot take it: %v", err)
	}
}
