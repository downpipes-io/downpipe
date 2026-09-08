package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
)

// The end-to-end command proof. A real, signed, encrypted
// selftest archive whose single record's value is an incompleteness-marker sentinel is restored
// through the actual `restore` command (StreamOpen + ApplyStreaming, the streaming write path a
// small kv value takes on DirTarget/DiscardTarget). The bug was that this exited 0 as a clean
// full restore; these tests pin the distinct advisory exit and the loud per-record + summary
// WARNING on stderr, while confirming the value STILL restored (the fix stops the false-green, it
// does not drop data). A normal value keeps exit 0 with no warning (backward-compatible).

const markerSentinelValue = `{"_skipped":"the kv namespace was unavailable at backup time"}`

// TestRestoreFileSinkMarkerAdvisoryAndWarning drives `restore --sink file --apply` over a marker
// archive: the command must exit the distinct ExitIncompleteMarkers advisory (not 0, and not a
// hard-failure code), print the per-record and summary warnings naming the kind, and still write
// the value to disk (it genuinely restored).
func TestRestoreFileSinkMarkerAdvisoryAndWarning(t *testing.T) {
	archiveDir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(archiveDir, []byte(markerSentinelValue))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, archiveDir, identity, verifier)
	outDir := filepath.Join(t.TempDir(), "out")

	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{"restore", "--archive", archiveDir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--sink", "file", "--out", outDir, "--apply"})
	})

	if code != format.ExitIncompleteMarkers {
		t.Fatalf("restore of a marker archive = %d, want %d (ExitIncompleteMarkers advisory)\nstderr: %s", code, format.ExitIncompleteMarkers, stderr)
	}
	// The advisory must be SEPARATE from the hard-failure/verification codes, so a script can tell
	// "succeeded-but-partial" apart from "corrupt/failed".
	if code == format.ExitUnverified || code == format.ExitIncomplete || code == format.ExitPlaintext || code == 1 {
		t.Fatalf("the marker advisory must not collide with a hard-failure code, got %d", code)
	}
	if !strings.Contains(stderr, "incompleteness marker") {
		t.Fatalf("stderr must carry the per-record marker warning, got: %q", stderr)
	}
	if !strings.Contains(stderr, "_skipped") {
		t.Fatalf("stderr must name the marker kind, got: %q", stderr)
	}
	if !strings.Contains(stderr, "NOT real data") {
		t.Fatalf("stderr must warn the value is not real data, got: %q", stderr)
	}
	if !strings.Contains(stderr, "incompleteness markers (the source was partially unavailable") {
		t.Fatalf("stderr must carry the summary WARNING, got: %q", stderr)
	}
	// The value genuinely restored: the fix surfaces the marker, it does not drop it. The selftest
	// record is named "greeting".
	got, rerr := os.ReadFile(filepath.Join(outDir, "greeting"))
	if rerr != nil || string(got) != markerSentinelValue {
		t.Fatalf("the marker value must still be written to the file sink, got %q err=%v", got, rerr)
	}
}

// TestRestoreDiscardSinkMarkerAdvisory drives `restore --sink discard` (the restore-drill) over
// the same marker archive: a scheduled restore-test must surface the marker too, exiting the
// advisory and printing the warning, even though the discard sink writes nothing.
func TestRestoreDiscardSinkMarkerAdvisory(t *testing.T) {
	archiveDir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(archiveDir, []byte(markerSentinelValue))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, archiveDir, identity, verifier)

	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{"restore", "--archive", archiveDir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--sink", "discard"})
	})

	if code != format.ExitIncompleteMarkers {
		t.Fatalf("discard drill of a marker archive = %d, want %d (ExitIncompleteMarkers)\nstderr: %s", code, format.ExitIncompleteMarkers, stderr)
	}
	if !strings.Contains(stderr, "incompleteness marker") || !strings.Contains(stderr, "_skipped") {
		t.Fatalf("the discard drill must surface the marker warning, got: %q", stderr)
	}
}

// TestVerifyDeepMarkerAdvisory covers the `verify --deep` restore-drill (the discard sink driven
// by verify): a scheduled deep restore-test over a marker archive must surface the marker and exit
// the advisory, yet keep the one-line summary labelled "verified" (the run IS verified; only its
// content is partial), never mislabelling it UNVERIFIED.
func TestVerifyDeepMarkerAdvisory(t *testing.T) {
	archiveDir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(archiveDir, []byte(markerSentinelValue))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, archiveDir, identity, verifier)

	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{"verify", "--archive", archiveDir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--deep"})
	})
	if code != format.ExitIncompleteMarkers {
		t.Fatalf("verify --deep over a marker archive = %d, want %d (ExitIncompleteMarkers)\nstderr: %s", code, format.ExitIncompleteMarkers, stderr)
	}
	if !strings.Contains(stderr, "incompleteness marker") || !strings.Contains(stderr, "_skipped") {
		t.Fatalf("verify --deep must surface the marker warning, got: %q", stderr)
	}
	if strings.Contains(stderr, "UNVERIFIED") {
		t.Fatalf("a marker run is verified; the deep summary must not say UNVERIFIED, got: %q", stderr)
	}
}

// TestRestoreNormalValueNoMarkerExitZero is the backward-compatible control: an ordinary value
// restores with exit 0 and no marker warning, so the advisory never fires on a clean archive.
func TestRestoreNormalValueNoMarkerExitZero(t *testing.T) {
	archiveDir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(archiveDir, []byte("genuine recovered data, no sentinel"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, archiveDir, identity, verifier)

	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{"restore", "--archive", archiveDir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--sink", "discard"})
	})

	if code != 0 {
		t.Fatalf("a normal archive must restore with exit 0, got %d\nstderr: %s", code, stderr)
	}
	if strings.Contains(stderr, "incompleteness marker") {
		t.Fatalf("a normal archive must not print any marker warning, got: %q", stderr)
	}
}

// The SIGNED restore receipt must surface the incompleteness-marker signal as
// ADDITIVE, machine-readable metadata. The bug was that a consumer of the receipt could NOT tell a fully-real
// restore from one padded with incompleteness-marker stubs: the receipt recorded only the verification
// exitCode (0 = verified), which is identical for both. This drives a real `restore --apply` over a marker
// archive with a SIGNED receipt, then re-opens and VERIFIES the receipt and asserts it carries
// incompleteMarkers>=1 and the per-kind tally -- WITHOUT re-purposing exitCode (which stays the verification
// outcome, 0). RED before the fix: the receipt had no incompleteMarkers field at all.
func TestRestoreReceiptCarriesIncompleteMarkers(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte(markerSentinelValue))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	// A restore-session signer signs the receipt (SPEC.md 8.5); keep its verifier to authenticate the result.
	rsigner, rverifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatalf("GenerateHybridSigner: %v", err)
	}
	rsignerPath := filepath.Join(dir, "receipt-signer.key")
	if err := writeKeyFile(rsignerPath, labelSignerPrivate, crypto.MarshalSigner(rsigner)); err != nil {
		t.Fatalf("write receipt signer key: %v", err)
	}
	outDir := filepath.Join(dir, "out")
	receiptPath := filepath.Join(dir, "receipt.json")

	var code int
	_, _ = captureOutput(t, func() {
		code = run([]string{"restore", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--sink", "file", "--out", outDir, "--apply", "--receipt", receiptPath, "--receipt-signer", rsignerPath})
	})
	// The PROCESS still exits the marker advisory (the CLI behaviour is unchanged).
	if code != format.ExitIncompleteMarkers {
		t.Fatalf("restore of a marker archive = %d, want %d (advisory)", code, format.ExitIncompleteMarkers)
	}

	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	// The SIGNED receipt authenticates: the marker fields are INSIDE the signed pre-image, not cosmetic.
	rcpt, err := format.VerifyReceipt(raw, rverifier)
	if err != nil {
		t.Fatalf("emitted marker receipt failed to verify: %v", err)
	}
	if rcpt.IncompleteMarkers < 1 {
		t.Fatalf("the signed receipt must carry incompleteMarkers>=1 for a marker restore, got %d\nreceipt: %s", rcpt.IncompleteMarkers, raw)
	}
	if rcpt.IncompleteMarkerKinds["_skipped"] < 1 {
		t.Fatalf("the receipt must tally the '_skipped' marker kind, got %v", rcpt.IncompleteMarkerKinds)
	}
	// exitCode is NOT re-purposed: it stays the verification outcome (0 = the marker record itself verified).
	// The marker advisory (8) is the PROCESS exit only; the machine-readable signal rides the additive fields.
	if rcpt.ExitCode != 0 {
		t.Fatalf("the receipt exitCode must stay the verification outcome (0), got %d", rcpt.ExitCode)
	}
}

// TestRestoreReceiptCleanOmitsMarkers is the byte-identical backward-compatible control: a normal-value
// restore emits a receipt that OMITS the marker fields entirely (they are omitempty), so an existing clean
// receipt is byte-for-byte what a pre-marker build produced and existing receipt tooling is unaffected.
func TestRestoreReceiptCleanOmitsMarkers(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("genuine recovered data, no sentinel"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)
	outDir := filepath.Join(dir, "out")
	receiptPath := filepath.Join(dir, "receipt.json")

	var code int
	_, _ = captureOutput(t, func() {
		code = run([]string{"restore", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--sink", "file", "--out", outDir, "--apply", "--receipt", receiptPath})
	})
	if code != 0 {
		t.Fatalf("a normal restore must exit 0, got %d", code)
	}
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	if strings.Contains(string(raw), "incompleteMarker") {
		t.Fatalf("a clean restore's receipt must OMIT the marker fields, got: %s", raw)
	}
}
