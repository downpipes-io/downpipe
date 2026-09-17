package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
)

// THE RECEIPT'S COUNT FIELDS MUST BE MEASURED OR ABSENT, NEVER A SIGNED ZERO.
//
// `vanishedExcluded` and `danglingSegments` were plain int64 with no omitempty and no
// production assignment anywhere in the tool: neither emitRestoreReceipt nor
// emitVerifyReceipt ever set either one. They were also required by
// docs/format/schema.json. So every receipt the reader had ever emitted, signed included,
// carried "vanishedExcluded": 0 and "danglingSegments": 0 about two quantities that no
// code had looked at, and a machine consumer reading either as a finding was reading a
// default.
//
// Driven before the fix on a real on-disk archive whose only seg/ object had been deleted:
// `verify --deep` printed the missing segment as a per-record failure and exited 2 while
// its receipt said "danglingSegments": 0, and the default shallow `verify` exited 0 with
// the same zero. After it, the deep pass reports 1, the shallow pass omits the field, and
// a deep pass over the intact archive reports a measured 0.
//
// The archive is a real tree written by buildSelftestArchive and read back by the real
// run() dispatch, so nothing here asserts against a receipt this file assembled itself.

// readReceiptRaw returns the receipt file as a decoded map, so a test can ask whether a KEY
// is present rather than whether a decoded Go field happens to be zero. That distinction is
// the whole point: a struct field of 0 and an absent key are the same value once decoded
// into a non-pointer field, which is exactly how the old assertion passed for the life of
// the defect.
func readReceiptRaw(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read receipt %s: %v", path, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parse receipt %s: %v\n%s", path, err, b)
	}
	return m
}

// danglingArchive builds a real archive, then deletes its single seg/ object so the run's
// manifest names a segment path the bucket does not hold: a dangling reference in the sense
// of SPEC.md 10.1. It returns the archive directory, the run id and the two key paths.
func danglingArchive(t *testing.T) (dir, runID, idPath, signerPath string) {
	t.Helper()
	dir = t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("this record's segment is about to go missing"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath = writeArchiveKeys(t, dir, identity, verifier)

	segs, err := filepath.Glob(filepath.Join(dir, "seg", "*", "*.seg"))
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 {
		t.Fatalf("fixture control: the selftest archive should hold exactly 1 segment, got %d", len(segs))
	}
	if err := os.Remove(segs[0]); err != nil {
		t.Fatalf("remove segment: %v", err)
	}
	return dir, runID, idPath, signerPath
}

// TestDeepVerifyMeasuresDanglingSegments: the pass that opens every seg/ object reports the
// dangling count SPEC.md 10.1 asks for, and a run over an intact archive reports a measured
// zero. The intact case is the control: without it, a count that simply always said 1 would
// satisfy the first assertion.
func TestDeepVerifyMeasuresDanglingSegments(t *testing.T) {
	dir, runID, idPath, signerPath := danglingArchive(t)
	out := filepath.Join(t.TempDir(), "dangling.json")
	silenceOutput(t)
	code := run([]string{
		"verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath,
		"--deep", "--acknowledge-no-rollback-pin", "--receipt", out,
	})
	// ExitDangling and no longer ExitUnverified. This fixture deletes the segment and
	// changes nothing else, so every byte the pass retrieved checked out; 2 was the tamper
	// verdict being returned over an archive nothing had tampered with.
	if code != format.ExitDangling {
		t.Fatalf("control: a deep verify over an archive missing its only segment = %d, want %d", code, format.ExitDangling)
	}
	rcpt := readReceiptRaw(t, out)
	got, ok := rcpt["danglingSegments"]
	if !ok {
		t.Fatalf("a deep verify read every segment, so it must report the count:\n%v", rcpt)
	}
	if got != float64(1) {
		t.Errorf("danglingSegments: want 1 for a manifest naming one absent seg/ object, got %v", got)
	}

	// The control, on an archive whose segment is still there.
	cleanDir := t.TempDir()
	identity, verifier, cleanRun, err := buildSelftestArchive(cleanDir, []byte("this one keeps its segment"))
	if err != nil {
		t.Fatal(err)
	}
	cleanID, cleanSigner := writeArchiveKeys(t, cleanDir, identity, verifier)
	cleanOut := filepath.Join(t.TempDir(), "clean.json")
	if code := run([]string{
		"verify", "--archive", cleanDir, "--run", cleanRun, "--identity", cleanID, "--signer", cleanSigner,
		"--deep", "--acknowledge-no-rollback-pin", "--receipt", cleanOut,
	}); code != 0 {
		t.Fatalf("control: a deep verify over an intact archive = %d, want 0", code)
	}
	clean := readReceiptRaw(t, cleanOut)
	if got, ok := clean["danglingSegments"]; !ok || got != float64(0) {
		t.Errorf("a deep verify that looked and found none must report a MEASURED 0, got %v (present=%v)", got, ok)
	}
}

// TestShallowVerifyOmitsTheCountItDidNotMeasure is the half an exit-code assertion cannot
// see. The default `verify` reads manifests only and exits 0 over this archive, which is
// correct and documented; what was not correct is that its receipt asserted
// "danglingSegments": 0 about seg/ objects it had never fetched, over an archive whose only
// segment was gone.
func TestShallowVerifyOmitsTheCountItDidNotMeasure(t *testing.T) {
	dir, runID, idPath, signerPath := danglingArchive(t)
	out := filepath.Join(t.TempDir(), "shallow.json")
	silenceOutput(t)
	code := run([]string{
		"verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath,
		"--acknowledge-no-rollback-pin", "--receipt", out,
	})
	// Recorded deliberately: the exit code is 0 both before and after this change, because
	// a shallow verify's verdict over intact manifests is genuinely 0. The defect and the
	// fix are entirely in what the receipt says, so an exit-code assertion is blind to both.
	if code != 0 {
		t.Fatalf("control: a shallow verify over intact manifests = %d, want 0", code)
	}
	rcpt := readReceiptRaw(t, out)
	if got, ok := rcpt["danglingSegments"]; ok {
		t.Errorf("a shallow verify fetched no seg/ object, so it must omit danglingSegments rather than assert %v", got)
	}
	// The control on the same receipt: the fields the shallow pass DID measure are present,
	// so the assertion above is about this one count and not about a receipt that came out
	// empty.
	for _, key := range []string{"recordsVerified", "signatureResult", "exitCode", "freshness"} {
		if _, ok := rcpt[key]; !ok {
			t.Errorf("control: the shallow receipt must still carry %q:\n%v", key, rcpt)
		}
	}
}

// TestNoProductionPathSignsAnUnmeasuredVanishedCount: nothing in the reader can derive
// vanishedExcluded (a vanished record is not emitted as a record line at all, SPEC.md 12.5,
// and neither the signed root nor the shard manifests record the figure), so no command the
// tool offers may put a number against it. This drives the three receipt-emitting paths and
// asserts the key is absent from every one.
func TestNoProductionPathSignsAnUnmeasuredVanishedCount(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("no vanished record here"))
	if err != nil {
		t.Fatal(err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)
	silenceOutput(t)

	base := []string{"--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--acknowledge-no-rollback-pin"}
	cases := []struct {
		name string
		args []string
	}{
		{"shallow verify", append([]string{"verify"}, base...)},
		{"deep verify", append(append([]string{"verify"}, base...), "--deep")},
		{"applied restore to a discard sink", append(append([]string{"restore"}, base...), "--sink", "discard", "--apply")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "r.json")
			if code := run(append(tc.args, "--receipt", out)); code != 0 {
				t.Fatalf("control: %s over an intact archive = %d, want 0", tc.name, code)
			}
			rcpt := readReceiptRaw(t, out)
			if got, ok := rcpt["vanishedExcluded"]; ok {
				t.Errorf("%s cannot know the vanished count, so it must omit the field rather than sign %v", tc.name, got)
			}
			// The control: this receipt is a real one with real content.
			if rcpt["runId"] != runID {
				t.Errorf("control: %s receipt is not for the run under test:\n%v", tc.name, rcpt)
			}
		})
	}
}

// TestDanglingCountIsDistinctPathsNotFailedRecords pins the counting rule. Segments are
// content addressed, so two records holding identical bytes name ONE seg/ object; counting
// failed records instead of distinct paths would report two dangling references where the
// bucket is missing one object, which is the shape of over-claim this whole change exists to
// remove.
func TestDanglingCountIsDistinctPathsNotFailedRecords(t *testing.T) {
	dir := t.TempDir()
	// Two records with identical values collapse to one shared segment.
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("shared bytes"))
	if err != nil {
		t.Fatal(err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)
	segs, err := filepath.Glob(filepath.Join(dir, "seg", "*", "*.seg"))
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 {
		t.Fatalf("fixture control: want 1 segment, got %d", len(segs))
	}
	if err := os.Remove(segs[0]); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "r.json")
	silenceOutput(t)
	if code := run([]string{
		"verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath,
		"--deep", "--acknowledge-no-rollback-pin", "--receipt", out,
	}); code != format.ExitDangling {
		t.Fatalf("control: want %d, got %d", format.ExitDangling, code)
	}
	rcpt := readReceiptRaw(t, out)
	if got := rcpt["danglingSegments"]; got != float64(len(segs)) {
		t.Errorf("danglingSegments must count DISTINCT absent seg/ paths (%d), got %v", len(segs), got)
	}
}

// TestSegmentReadErrorCarriesOnlyFetchFailures: a segment that WAS in the bucket and failed
// its AEAD tag is not a dangling reference, and must never be counted as one. A tampered
// segment is left in place and corrupted, so the fetch succeeds and the open fails.
func TestSegmentReadErrorCarriesOnlyFetchFailures(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("tamper me, do not delete me"))
	if err != nil {
		t.Fatal(err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)
	segs, err := filepath.Glob(filepath.Join(dir, "seg", "*", "*.seg"))
	if err != nil || len(segs) != 1 {
		t.Fatalf("fixture control: want 1 segment, got %d (%v)", len(segs), err)
	}
	sealed, err := os.ReadFile(segs[0])
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte well inside the ciphertext so the object is present, the same length, and
	// fails its authenticated decrypt.
	sealed[len(sealed)/2] ^= 0xff
	if err := os.WriteFile(segs[0], sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "r.json")
	silenceOutput(t)
	code := run([]string{
		"verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath,
		"--deep", "--acknowledge-no-rollback-pin", "--receipt", out,
	})
	// The control that this test is not vacuous: the tamper must actually produce a
	// verdict. A test that "tampered" an archive the reader still accepted would assert
	// against a clean run and pass for the wrong reason.
	if code == 0 {
		t.Fatalf("control: a tampered segment must not verify clean, got exit 0")
	}
	rcpt := readReceiptRaw(t, out)
	if got, ok := rcpt["danglingSegments"]; !ok || got != float64(0) {
		t.Errorf("a segment that was PRESENT and failed its check is not a dangling reference: want a measured 0, got %v (present=%v)", got, ok)
	}
}

// TestReceiptSignatureCoversTheMeasuredCounts confirms the counts ride inside the signature
// rather than beside it: a receipt signed with a measured count still verifies, and the same
// receipt with the count edited does not. Without this, the fields could be reported honestly
// and still be forgeable in transit.
func TestReceiptSignatureCoversTheMeasuredCounts(t *testing.T) {
	dir, runID, idPath, signerPath := danglingArchive(t)
	signerKey := filepath.Join(t.TempDir(), "receipt-signer.key")
	sk, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeKeyFile(signerKey, labelSignerPrivate, crypto.MarshalSigner(sk)); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "signed.json")
	silenceOutput(t)
	if code := run([]string{
		"verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath,
		"--deep", "--acknowledge-no-rollback-pin", "--receipt", out, "--receipt-signer", signerKey,
	}); code != format.ExitDangling {
		t.Fatalf("control: want %d, got %d", format.ExitDangling, code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := format.VerifyReceipt(raw, verifier); err != nil {
		t.Fatalf("control: the receipt as emitted must verify: %v", err)
	}
	if !strings.Contains(string(raw), `"danglingSegments":1`) {
		t.Fatalf("control: the signed receipt must carry the measured count:\n%s", raw)
	}
	edited := strings.Replace(string(raw), `"danglingSegments":1`, `"danglingSegments":0`, 1)
	if _, err := format.VerifyReceipt([]byte(edited), verifier); err == nil {
		t.Error("editing danglingSegments to 0 must break the receipt signature")
	}
}

// TestReceiptCompletenessIsTheVerdictThePassReached is the sixth instance of this bug
// shape, found by driving item 3 rather than by reading: a SIGNED receipt asserting a good
// label over a run that had just failed.
//
// The receipt's completeness came from Outcome.Completeness, which is computed from the
// signed manifests. On a deep verify of an archive whose only segment was gone, the
// manifests were intact, so the receipt said "completeness": "complete" and "mode":
// "verified" while the two lines the tool printed both said
// "completeness=UNVERIFIED (1 of 1 record(s) failed integrity)" and the process exited 2.
//
// SPEC.md 8.5 requires the receipt never to launder an unverified run as verified, and the
// receipt is the machine-parseable artefact a third party reads, so of the two surfaces the
// wrong one was the one that matters. A previous change fixed the PRINTED line and left the
// receipt.
func TestReceiptCompletenessIsTheVerdictThePassReached(t *testing.T) {
	broken, brokenRun, brokenID, brokenSigner := danglingArchive(t)

	intact := t.TempDir()
	identity, verifier, intactRun, err := buildSelftestArchive(intact, []byte("intact"))
	if err != nil {
		t.Fatal(err)
	}
	intactID, intactSigner := writeArchiveKeys(t, intact, identity, verifier)

	silenceOutput(t)
	cases := []struct {
		name     string
		dir, run string
		id, sig  string
		args     []string
		wantCode int
		want     string
	}{
		// "incomplete" and not "UNVERIFIED". danglingArchive breaks the archive by DELETING
		// its only segment, so the honest member of the SPEC.md 8.5 enum is the third one:
		// the manifests verified and the bucket is short an object they name. The receipt
		// carried "UNVERIFIED" here beside its own "danglingSegments": 1, two fields of one
		// signed artefact describing different findings.
		{"deep verify of a broken archive", broken, brokenRun, brokenID, brokenSigner, []string{"--deep"}, format.ExitDangling, "incomplete"},
		{"deep verify of an intact archive", intact, intactRun, intactID, intactSigner, []string{"--deep"}, 0, "complete"},
		{"applied restore of a broken archive", broken, brokenRun, brokenID, brokenSigner, nil, format.ExitDangling, "incomplete"},
		{"applied restore of an intact archive", intact, intactRun, intactID, intactSigner, nil, 0, "complete"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "r.json")
			// Built into one slice rather than appending a verb slice into an args slice.
			// The latter reads as harmless and is not: append may reuse the verb slice's
			// backing array, so two cases sharing a verb literal can write over each other.
			args := make([]string, 0, 12)
			if strings.HasPrefix(tc.name, "applied restore") {
				args = append(args, "restore", "--sink", "discard", "--apply")
			} else {
				args = append(args, "verify")
			}
			args = append(args, "--archive", tc.dir, "--run", tc.run, "--identity", tc.id,
				"--signer", tc.sig, "--acknowledge-no-rollback-pin", "--receipt", out)
			code := run(append(args, tc.args...))
			// The control: the fixture really did reach the verdict the receipt is being
			// judged against. An archive that verified clean when it was meant to be broken
			// would make the UNVERIFIED assertions vacuous.
			if code != tc.wantCode {
				t.Fatalf("control: %s = %d, want %d", tc.name, code, tc.wantCode)
			}
			rcpt := readReceiptRaw(t, out)
			if got := rcpt["completeness"]; got != tc.want {
				t.Errorf("receipt completeness = %v, want %q: the receipt must carry the verdict this pass reached", got, tc.want)
			}
			// The value has to stay inside the SPEC.md 8.5 enum, which docs/format/schema.json
			// pins. A receipt carrying the printed line's "UNVERIFIED (1 of 1 ...)" would read
			// correctly to a human and fail every schema-checking consumer.
			switch rcpt["completeness"] {
			case "complete", "UNVERIFIED", "incomplete":
			default:
				t.Errorf("completeness %v is outside the SPEC.md 8.5 enum", rcpt["completeness"])
			}
		})
	}
}

// TestShallowVerifyKeepsTheReaderCompleteness is the control for the change above: a pass
// that decrypted nothing must not invent a verdict, and keeps the reader's manifests-only
// one. Without it, a fix that hardcoded UNVERIFIED everywhere would pass the test above.
func TestShallowVerifyKeepsTheReaderCompleteness(t *testing.T) {
	dir, runID, idPath, signerPath := danglingArchive(t)
	out := filepath.Join(t.TempDir(), "r.json")
	silenceOutput(t)
	if code := run([]string{
		"verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath,
		"--acknowledge-no-rollback-pin", "--receipt", out,
	}); code != 0 {
		t.Fatalf("control: a shallow verify over intact manifests = %d, want 0", code)
	}
	rcpt := readReceiptRaw(t, out)
	if got := rcpt["completeness"]; got != "complete" {
		t.Errorf("completeness = %v, want \"complete\": a shallow verify checked the manifests and they are intact", got)
	}
	// And the field that makes that honest rather than misleading: the shallow pass did not
	// read a value, so it claims no value verification and omits the count it never took.
	target, _ := rcpt["target"].(map[string]any)
	if target == nil || target["valueVerified"] != false {
		t.Errorf("a shallow verify must record valueVerified false:\n%v", rcpt)
	}
	if _, ok := rcpt["danglingSegments"]; ok {
		t.Errorf("a shallow verify must omit danglingSegments:\n%v", rcpt)
	}
}
