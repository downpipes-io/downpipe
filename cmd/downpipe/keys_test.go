package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
)

// TestCmdKeysWhichGroupsRunsByRecipient drives `keys --which` against a real on-disk
// archive and asserts it lists, with no identity supplied, the run grouped under both
// the break-glass and operational recipient fingerprints recorded in the signed root.
// This is the key index that answers "which offline key opens which runs". Without a
// --signer the summary line must say so plainly: the index is unauthenticated
// bucket contents, not a verified result.
func TestCmdKeysWhichGroupsRunsByRecipient(t *testing.T) {
	dir := t.TempDir()
	runID := selftestArchiveRunID(t, dir, []byte("which key opens me"))

	// Learn the run's recipient fingerprints from its public root so the assertion is
	// keyed to the fixture's actual identities.
	store, err := newStoreFlags(dir, "", "", "").resolve()
	if err != nil {
		t.Fatal(err)
	}
	rootBytes, err := store.Get("run/" + runID + "/root.manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	root, err := format.ParseRoot(rootBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(root.Recipients) != 2 {
		t.Fatalf("selftest archive should list 2 recipients, got %d", len(root.Recipients))
	}

	var code int
	stdout, _ := captureOutput(t, func() {
		code = run([]string{"keys", "--which", "--archive", dir})
	})
	if code != 0 {
		t.Fatalf("keys --which = %d, want 0\n%s", code, stdout)
	}
	for _, want := range []string{"1 run(s) across 2 recipient", "break-glass", "operational", runID, "UNVERIFIED: no --signer given"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("keys --which output missing %q\n%s", want, stdout)
		}
	}
	for _, rc := range root.Recipients {
		if !strings.Contains(stdout, rc.Fingerprint) {
			t.Errorf("keys --which output missing recipient fingerprint %q\n%s", rc.Fingerprint, stdout)
		}
	}
	// Break-glass must lead (the recovery-of-last-resort key), before operational.
	if strings.Index(stdout, "break-glass") > strings.Index(stdout, "operational") {
		t.Errorf("break-glass should be listed before operational\n%s", stdout)
	}
}

// TestCmdKeysWithoutWhichIsUsageError confirms `keys` without --which is a clean usage
// error rather than a silent no-op.
func TestCmdKeysWithoutWhichIsUsageError(t *testing.T) {
	silenceOutput(t)
	code := run([]string{"keys", "--archive", t.TempDir()})
	if code != format.ExitUsage {
		t.Fatalf("keys without --which = %d, want %d (ExitUsage)", code, format.ExitUsage)
	}
}

// TestCmdKeysWhichWithSignerIsVerified confirms that pinning the archive's real --signer
// verifies the RUNLOG and the run's root before they feed the index, and the summary line
// reports "signer-verified" rather than the unverified caveat.
func TestCmdKeysWhichWithSignerIsVerified(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("verified which key"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	_, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	var code int
	stdout, _ := captureOutput(t, func() {
		code = run([]string{"keys", "--which", "--archive", dir, "--signer", signerPath})
	})
	if code != 0 {
		t.Fatalf("keys --which --signer = %d, want 0\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "signer-verified") {
		t.Errorf("keys --which --signer output should be tagged signer-verified:\n%s", stdout)
	}
	if strings.Contains(stdout, "UNVERIFIED") {
		t.Errorf("keys --which --signer output must not carry the unverified caveat:\n%s", stdout)
	}
	if !strings.Contains(stdout, runID) {
		t.Errorf("keys --which --signer output missing the run:\n%s", stdout)
	}
}

// TestCmdKeysWhichWithWrongSignerFailsClosed is a regression guard: a --signer that does
// not match the archive's actual signer must fail the whole command (ExitStale, mirroring
// CheckFreshness's treatment of a bad RUNLOG signature) rather than silently print whatever
// the bucket holds. Before the fix `keys --which` had no --signer at all and could not
// reject this: a bucket-write adversary's forged RUNLOG/root would print indistinguishably
// from genuine data.
func TestCmdKeysWhichWithWrongSignerFailsClosed(t *testing.T) {
	dir := t.TempDir()
	runID := selftestArchiveRunID(t, dir, []byte("wrong signer test"))

	_, otherVerifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatalf("GenerateHybridSigner: %v", err)
	}
	wrongSignerPath := filepath.Join(dir, "wrong-signer.pub")
	if err := writeKeyFile(wrongSignerPath, labelSignerPublic, crypto.MarshalVerifier(otherVerifier)); err != nil {
		t.Fatalf("write wrong signer: %v", err)
	}

	var code int
	stdout, _ := captureOutput(t, func() {
		code = run([]string{"keys", "--which", "--archive", dir, "--signer", wrongSignerPath})
	})
	if code != format.ExitStale {
		t.Fatalf("keys --which with a mismatched --signer = %d, want %d (ExitStale)\n%s", code, format.ExitStale, stdout)
	}
	if strings.Contains(stdout, runID) {
		t.Errorf("a mismatched --signer must not print the unauthenticated index:\n%s", stdout)
	}
}

// TestCmdKeysWhichSkipsRunWithForgedRootSignature is the per-run half of the fix: a
// genuinely signed RUNLOG (so the top-level check passes) paired with a run whose root
// signature has been overwritten by a different key must exclude that run from the index.
// The pre-existing "one damaged root doesn't hide the rest" behaviour now also covers a
// forged/wrong-signer root, not just an unreadable one.
func TestCmdKeysWhichSkipsRunWithForgedRootSignature(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("forged root test"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	_, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	// Overwrite the run's root signature with one that is well-formed but signed by a
	// different key, simulating a forged/tampered per-run root without touching the
	// (separately signed) RUNLOG at all.
	forger, _, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatalf("GenerateHybridSigner: %v", err)
	}
	forgedSig, err := forger.Sign([]byte("forged root manifest"))
	if err != nil {
		t.Fatalf("sign forged root: %v", err)
	}
	if err := writeObject(dir, "run/"+runID+"/root.manifest.json.sig", []byte(format.B64Encode(forgedSig))); err != nil {
		t.Fatalf("overwrite root signature: %v", err)
	}

	var code int
	stdout, stderr := captureOutput(t, func() {
		code = run([]string{"keys", "--which", "--archive", dir, "--signer", signerPath})
	})
	if strings.Contains(stdout, runID) {
		t.Errorf("a run with a forged root signature must not appear in the index:\n%s", stdout)
	}
	if !strings.Contains(stdout, "0 run(s)") {
		t.Errorf("keys --which should report 0 runs once the sole run's root is excluded:\n%s", stdout)
	}
	if !strings.Contains(stderr, "skipping run "+runID) {
		t.Errorf("keys --which should warn to stderr about the skipped run:\n%s", stderr)
	}

	// THE SKIP HAS TO REACH STDOUT, AND IT HAS TO REACH THE EXIT CODE.
	//
	// This test used to assert `code != 0 -> fatal`, with the comment "the command still
	// succeeds overall; only the one forged run is excluded". Driven, that meant the entire
	// stdout of a `keys --which --signer` over an archive whose only root had been forged
	// was one line:
	//
	//     0 run(s) across 0 recipient identit(ies) [signer-verified]:
	//
	// at exit 0. The word "verified" next to a count of nothing, and with stderr dropped by
	// a pipe or a log capture there was no trace a run had ever existed. Excluding a forged
	// run from the index is right; presenting the remainder as a verified answer is not, and
	// this same command already fails closed (ExitStale) on a forged RUNLOG signature, so a
	// forged ROOT exiting 0 was the one hole in that posture.
	if !strings.Contains(stdout, "INCOMPLETE") {
		t.Errorf("the summary tag must not read as a clean signer-verified index when a run was skipped:\n%s", stdout)
	}
	if !strings.Contains(stdout, "could NOT be read or verified and are missing from this index") {
		t.Errorf("the skipped count must appear on STDOUT, beside the count it qualifies:\n%s", stdout)
	}
	if code != format.ExitUnverified {
		t.Errorf("keys --which with one forged root = %d, want %d: an index that silently drops a run must not exit 0", code, format.ExitUnverified)
	}
}

// TestCmdKeysWhichCleanArchiveIsNotFlaggedIncomplete is the control for the assertions
// above. Without it, a change that tagged every index INCOMPLETE and exited non-zero
// unconditionally would satisfy every one of them.
func TestCmdKeysWhichCleanArchiveIsNotFlaggedIncomplete(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("nothing forged here"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	_, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	var code int
	stdout, _ := captureOutput(t, func() {
		code = run([]string{"keys", "--which", "--archive", dir, "--signer", signerPath})
	})
	if code != 0 {
		t.Fatalf("keys --which over an intact archive = %d, want 0\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "1 run(s) across 2 recipient identit(ies) [signer-verified]:") {
		t.Errorf("an intact archive must still get the plain signer-verified summary:\n%s", stdout)
	}
	if strings.Contains(stdout, "INCOMPLETE") || strings.Contains(stdout, "could NOT be read or verified") {
		t.Errorf("an intact archive must carry no skipped-run caveat:\n%s", stdout)
	}
	if !strings.Contains(stdout, runID) {
		t.Errorf("the run must be listed:\n%s", stdout)
	}
}

// TestCmdKeysFingerprintNamesTheKeysAnOperatorHolds is the sheet-side check. A printed recovery
// sheet carries FINGERPRINTS, never key files, and the console tells a recovering operator to check
// the files in their recovery kit against them. This asserts the whole chain closes: the identity
// file's fingerprint is the break-glass recipient the archive records, and the signer file's
// fingerprint is the signingKeyFingerprint the run declares. If either link broke, an operator
// comparing their sheet against their files would be told they hold the wrong key when they do not.
func TestCmdKeysFingerprintNamesTheKeysAnOperatorHolds(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("fingerprint the kit"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	kit := t.TempDir()
	idPath := filepath.Join(kit, "identity.key")
	signerPath := filepath.Join(kit, "signer.pub")
	if err := writeKeyFile(idPath, labelIdentity, crypto.MarshalKEMPrivate(identity)); err != nil {
		t.Fatal(err)
	}
	if err := writeKeyFile(signerPath, labelSignerPublic, crypto.MarshalVerifier(verifier)); err != nil {
		t.Fatal(err)
	}

	store, err := newStoreFlags(dir, "", "", "").resolve()
	if err != nil {
		t.Fatal(err)
	}
	rootBytes, err := store.Get("run/" + runID + "/root.manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	root, err := format.ParseRoot(rootBytes)
	if err != nil {
		t.Fatal(err)
	}

	var code int
	stdout, _ := captureOutput(t, func() {
		code = run([]string{"keys", "--fingerprint", "--identity", idPath, "--signer", signerPath})
	})
	if code != 0 {
		t.Fatalf("keys --fingerprint = %d, want 0\n%s", code, stdout)
	}
	var breakGlass string
	for _, rc := range root.Recipients {
		if rc.Role == "break-glass" {
			breakGlass = rc.Fingerprint
		}
	}
	if breakGlass == "" {
		t.Fatal("selftest archive has no break-glass recipient")
	}
	if !strings.Contains(stdout, breakGlass) {
		t.Errorf("identity fingerprint %q not printed, so the sheet comparison cannot be made\n%s", breakGlass, stdout)
	}
	if !strings.Contains(stdout, root.SigningKeyFingerprint) {
		t.Errorf("signer fingerprint %q not printed, so it cannot be checked against the run's declared signer\n%s", root.SigningKeyFingerprint, stdout)
	}
	if root.SigningKeyFingerprint != crypto.SignerFingerprint(verifier) {
		t.Errorf("the run declares signingKeyFingerprint %q but its signer is %q: an operator checking the sheet would be misled",
			root.SigningKeyFingerprint, crypto.SignerFingerprint(verifier))
	}
	// No key material may reach stdout. A fingerprint is a hash of PUBLIC bytes; the identity file's
	// own base64 body must never appear.
	raw, err := os.ReadFile(idPath)
	if err != nil {
		t.Fatal(err)
	}
	secret := string(raw)
	if body := strings.TrimSpace(strings.TrimPrefix(secret, labelIdentity+" ")); strings.Contains(stdout, body) {
		t.Error("keys --fingerprint printed the identity key body")
	}
}

// TestCmdKeysFingerprintWithNoKeyFilesIsUsageError keeps the mode from succeeding vacuously: a bare
// --fingerprint that printed only the explanatory footer would read as a clean run that proved nothing.
func TestCmdKeysFingerprintWithNoKeyFilesIsUsageError(t *testing.T) {
	silenceOutput(t)
	if code := run([]string{"keys", "--fingerprint"}); code != format.ExitUsage {
		t.Fatalf("keys --fingerprint with no key files = %d, want %d (ExitUsage)", code, format.ExitUsage)
	}
}

// TestCmdKeysWhichAndFingerprintTogetherIsUsageError refuses the combination rather than silently
// picking one. The two modes answer different questions and read different things.
func TestCmdKeysWhichAndFingerprintTogetherIsUsageError(t *testing.T) {
	silenceOutput(t)
	if code := run([]string{"keys", "--which", "--fingerprint", "--archive", t.TempDir()}); code != format.ExitUsage {
		t.Fatalf("keys --which --fingerprint = %d, want %d (ExitUsage)", code, format.ExitUsage)
	}
}
