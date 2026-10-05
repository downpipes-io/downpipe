package format

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// A signed receipt must verify: blank the signature field, re-canonicalise with
// Signed=true, and the signature checks against the operator's restore-session signer.
func TestReceiptSignVerify(t *testing.T) {
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	rcpt := &Receipt{
		Kind: "downpipe-restore-receipt", FormatVersion: "downpipe/0.1.0",
		RunID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", DownpipeID: "dp_x",
		Mode: "verified", SignatureResult: "valid", Completeness: "complete",
		BreakGlassVerified: true, DeclaredRecordCount: 3, RecordsVerified: 3,
		Target: ReceiptTarget{Type: "verify"}, ExitCode: 0,
	}
	if err := rcpt.Sign(signer); err != nil {
		t.Fatal(err)
	}
	if !rcpt.Signed || rcpt.ReceiptSignature == "" {
		t.Fatal("a signed receipt must carry a signature")
	}

	sig, err := B64Decode(rcpt.ReceiptSignature)
	if err != nil {
		t.Fatal(err)
	}
	check := *rcpt
	check.ReceiptSignature = ""
	canonical, err := check.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(canonical, sig); err != nil {
		t.Fatalf("receipt signature did not verify: %v", err)
	}

	// A mutated label must break the signature.
	bad := *rcpt
	bad.Completeness = "UNVERIFIED"
	bad.ReceiptSignature = ""
	badCanonical, err := bad.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(badCanonical, sig); err == nil {
		t.Fatal("a mutated receipt must fail signature verification")
	}
}

// VerifyReceipt must authenticate a signed receipt from its emitted JSON bytes (the path
// a third party follows from the bytes on disk), and must reject a receipt whose body was
// tampered after signing as well as an unsigned receipt (SPEC.md 8.5).
func TestVerifyReceiptFromEmittedBytes(t *testing.T) {
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	rcpt := &Receipt{
		Kind: "downpipe-restore-receipt", FormatVersion: "downpipe/0.1.0",
		RunID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", DownpipeID: "dp_x",
		Mode: "verified", SignatureResult: "valid", Completeness: "complete",
		BreakGlassVerified: true, DeclaredRecordCount: 3, RecordsVerified: 3,
		Target: ReceiptTarget{Type: "verify"}, ExitCode: 0,
	}
	if err := rcpt.Sign(signer); err != nil {
		t.Fatal(err)
	}

	// The emitted bytes are what a consumer actually reads.
	emitted, err := rcpt.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	got, err := VerifyReceipt(emitted, verifier)
	if err != nil {
		t.Fatalf("a valid emitted receipt must verify: %v", err)
	}
	if got.RunID != rcpt.RunID || got.Completeness != "complete" {
		t.Fatalf("verified receipt did not round-trip its fields: %+v", got)
	}
	if got.ReceiptSignature != rcpt.ReceiptSignature {
		t.Fatal("VerifyReceipt must return the receipt with its original signature intact")
	}

	// Tamper with a label after signing but keep the original signature: re-emitting and
	// re-verifying from those bytes must fail, because the signed pre-image no longer
	// matches. This is the regression the documented bytes-in path is meant to catch.
	var tampered Receipt
	if err := json.Unmarshal(emitted, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Completeness = "UNVERIFIED"
	tamperedBytes, err := tampered.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReceipt(tamperedBytes, verifier); err == nil {
		t.Fatal("a receipt tampered after signing must fail VerifyReceipt")
	}

	// An unsigned receipt is reported as unsigned, not silently accepted.
	unsigned := &Receipt{
		Kind: "downpipe-restore-receipt", FormatVersion: "downpipe/0.1.0",
		RunID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", DownpipeID: "dp_x",
		Target: ReceiptTarget{Type: "verify"},
	}
	unsignedBytes, err := unsigned.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReceipt(unsignedBytes, verifier); err == nil {
		t.Fatal("an unsigned receipt must not verify")
	}
}

// BuildReceipt must carry the three SPEC 8.5 normative fields: vanishedExcluded,
// danglingSegments, and freshness.rollbackWarning.
func TestBuildReceiptNormativeFields(t *testing.T) {
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

	// A clean archive for the base case: no rollback, no vanished, no dangling.
	clean := memStore{}
	bgPriv, verifier := buildArchive(t, buildSpec{store: clean, runID: runID, dpID: "dp_test", value: []byte("v"), secret: false, codec: spec.CodecNameNone})
	r, err := Open(clean, runID, bgPriv, verifier, Options{})
	if err != nil {
		t.Fatal(err)
	}
	in := ReceiptInput{
		StartedAt:        "2026-06-07T00:00:00.000Z",
		FinishedAt:       "2026-06-07T00:00:01.000Z",
		TargetType:       "verify",
		VanishedExcluded: i64(17),
		DanglingSegments: i64(3),
	}
	rcpt := BuildReceipt(r, in)

	if rcpt.VanishedExcluded == nil || *rcpt.VanishedExcluded != 17 {
		t.Errorf("vanishedExcluded: want 17, got %v", rcpt.VanishedExcluded)
	}
	if rcpt.DanglingSegments == nil || *rcpt.DanglingSegments != 3 {
		t.Errorf("danglingSegments: want 3, got %v", rcpt.DanglingSegments)
	}
	// A clean run is latest for its downpipe: rollbackWarning must be false.
	if rcpt.Freshness.RollbackWarning {
		t.Error("freshness.rollbackWarning: want false for a current run, got true")
	}

	// A stale run (RUNLOG truncated to just a superseded entry) forces RollbackWarning.
	// Use --allow-stale so Open proceeds and we can build the receipt. The stale-run
	// path is built entirely from buildArchiveSpec, which returns the signer needed to
	// re-sign the RUNLOG.
	const runID2 = "01ARZ3NDEKTSV4RRFFQ69G5FB0"
	store2, bgPriv3, verifier3, signer3 := buildArchiveSpec(t, vectorSpec{
		dpID:    "dp_stale",
		records: []recordSpec{{name: "k", value: []byte("w")}},
	})
	const staleRunID = vecRunID
	runlogBytes2, err := MarshalRunlog([]spec.RunlogEntry{
		{Index: 1, RunID: staleRunID, DownpipeID: "dp_stale", Time: "2026-06-07T00:00:00.000Z", RecordCount: 1, PrevRunID: nil, Status: "superseded"},
		{Index: 2, RunID: runID2, DownpipeID: "dp_stale", Time: "2026-06-07T00:01:00.000Z", RecordCount: 1, PrevRunID: strPtr(staleRunID), Status: "active"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rawSig, err := signer3.Sign(runlogBytes2)
	if err != nil {
		t.Fatal(err)
	}
	store2["_RECOVERY/RUNLOG"] = runlogBytes2
	store2["_RECOVERY/RUNLOG.sig"] = []byte(B64Encode(rawSig))

	r2, err := Open(store2, staleRunID, bgPriv3, verifier3, Options{AllowStale: true})
	if err != nil {
		t.Fatalf("allow-stale open: %v", err)
	}
	rcpt2 := BuildReceipt(r2, ReceiptInput{TargetType: "verify"})
	if !rcpt2.Freshness.RollbackWarning {
		t.Error("freshness.rollbackWarning: want true for a superseded run, got false")
	}
	if rcpt2.Freshness.IsLatestForDownpipe {
		t.Error("freshness.isLatestForDownpipe: want false for a superseded run, got true")
	}
	// AN UNSUPPLIED COUNT IS ABSENT, NOT ZERO.
	//
	// This assertion used to read "must be zero when not supplied", and it passed for the
	// whole life of the field precisely because it could not tell the two apart: the input
	// it called "not supplied" was written as VanishedExcluded: 0, which is the same value
	// a caller that HAD measured zero would pass. Nothing in production ever supplied
	// either field, so every signed receipt the tool emitted asserted 0 for two quantities
	// no code had looked at, and this test agreed with it.
	if rcpt2.VanishedExcluded != nil {
		t.Errorf("vanishedExcluded: want absent when nothing measured it, got %d", *rcpt2.VanishedExcluded)
	}
	if rcpt2.DanglingSegments != nil {
		t.Errorf("danglingSegments: want absent when nothing measured it, got %d", *rcpt2.DanglingSegments)
	}
	// The emitted JSON must not carry the keys at all, which is the part a machine consumer
	// reads. A pointer that is nil in Go but serialised as 0 would fail here and pass above.
	b, err := rcpt2.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"vanishedExcluded"`, `"danglingSegments"`} {
		if strings.Contains(string(b), key) {
			t.Errorf("an unmeasured %s must be absent from the signed bytes:\n%s", key, b)
		}
	}
	// The control: a receipt that DID measure them still carries them, so the assertions
	// above are about absence rather than about the fields having been dropped.
	measured, err := BuildReceipt(r2, ReceiptInput{TargetType: "discard", VanishedExcluded: i64(0), DanglingSegments: i64(2)}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(measured), `"vanishedExcluded":0`) {
		t.Errorf("a MEASURED zero must still be carried:\n%s", measured)
	}
	if !strings.Contains(string(measured), `"danglingSegments":2`) {
		t.Errorf("a measured dangling count must be carried:\n%s", measured)
	}
}

// i64 returns a pointer to n, for the receipt's measured-or-absent count fields.
func i64(n int64) *int64 { return &n }

// The incompleteness-marker fields are ADDITIVE receipt metadata (SPEC.md 8.5, 12.1): present only when
// markers were restored, OMITTED (and byte-identical to a pre-marker receipt) when zero, covered by the
// signature, and never a re-purposing of exitCode.
func TestBuildReceiptIncompleteMarkers(t *testing.T) {
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	store := memStore{}
	bgPriv, verifier := buildArchive(t, buildSpec{store: store, runID: runID, dpID: "dp_marker", value: []byte("v"), secret: false, codec: spec.CodecNameNone})
	r, err := Open(store, runID, bgPriv, verifier, Options{})
	if err != nil {
		t.Fatal(err)
	}

	// A clean restore (no markers) OMITS both fields, so its canonical bytes are byte-identical to a
	// pre-marker receipt: the additive change never perturbs an existing clean receipt or its signature.
	clean := BuildReceipt(r, ReceiptInput{TargetType: "file", ExitCode: 0})
	if clean.IncompleteMarkers != 0 || clean.IncompleteMarkerKinds != nil {
		t.Fatalf("a clean receipt must carry zero markers, got %d kinds=%v", clean.IncompleteMarkers, clean.IncompleteMarkerKinds)
	}
	cleanBytes, err := clean.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cleanBytes), "incompleteMarker") {
		t.Fatalf("a clean receipt must OMIT the marker fields (byte-identical backward compatibility), got: %s", cleanBytes)
	}

	// A restore that hit markers carries the count + per-kind tally, and exitCode is UNCHANGED (still the
	// verification outcome, here 0 = verified): the marker signal is additive, not a repurposed exit.
	marked := BuildReceipt(r, ReceiptInput{
		TargetType:            "file",
		ExitCode:              0,
		Restored:              3,
		IncompleteMarkers:     3,
		IncompleteMarkerKinds: map[string]int64{"_skipped": 2, "_unavailable": 1},
	})
	if marked.IncompleteMarkers != 3 {
		t.Fatalf("incompleteMarkers: want 3, got %d", marked.IncompleteMarkers)
	}
	if marked.IncompleteMarkerKinds["_skipped"] != 2 || marked.IncompleteMarkerKinds["_unavailable"] != 1 {
		t.Fatalf("incompleteMarkerKinds tally wrong: %v", marked.IncompleteMarkerKinds)
	}
	if marked.ExitCode != 0 {
		t.Fatalf("exitCode must stay the verification outcome (0), got %d", marked.ExitCode)
	}

	// The emitted JSON carries the count (a machine consumer can read it) and it survives a JSON round-trip.
	markedBytes, err := marked.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(markedBytes), `"incompleteMarkers":3`) {
		t.Fatalf("the emitted receipt must carry the marker count, got: %s", markedBytes)
	}
	var back Receipt
	if err := json.Unmarshal(markedBytes, &back); err != nil {
		t.Fatal(err)
	}
	if back.IncompleteMarkers != 3 || back.IncompleteMarkerKinds["_skipped"] != 2 {
		t.Fatalf("marker fields did not round-trip through JSON: %+v", back)
	}

	// The marker fields are COVERED by the receipt signature: signing then VerifyReceipt authenticates them,
	// and altering the count after signing breaks verification -- they are not un-signed cosmetic add-ons.
	signer, rverifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	if err := marked.Sign(signer); err != nil {
		t.Fatal(err)
	}
	signed, err := marked.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReceipt(signed, rverifier); err != nil {
		t.Fatalf("a signed marker receipt must verify: %v", err)
	}
	var tamper Receipt
	if err := json.Unmarshal(signed, &tamper); err != nil {
		t.Fatal(err)
	}
	tamper.IncompleteMarkers = 99 // lie about the marker count after signing
	tamperBytes, err := tamper.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReceipt(tamperBytes, rverifier); err == nil {
		t.Fatal("a receipt whose marker count was altered after signing must fail verification")
	}
}

// strPtr is a helper for creating *string values in test fixtures.
func strPtr(s string) *string { return &s }

// The receipt has to say WHY a restore fell short of its verified record count, not just that it did.
// Before this it carried "verified 100, restored 98" and nothing else, so a machine consumer auditing a
// recovery could not tell "98 landed and 2 were placeholders" from "98 landed and 2 are still missing".
// Those are different facts about whether the recovery is finished.
func TestBuildReceiptUnwrittenRecords(t *testing.T) {
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	store := memStore{}
	bgPriv, verifier := buildArchive(t, buildSpec{store: store, runID: runID, dpID: "dp_unwritten", value: []byte("v"), secret: false, codec: spec.CodecNameNone})
	r, err := Open(store, runID, bgPriv, verifier, Options{})
	if err != nil {
		t.Fatal(err)
	}

	// A restore that refused nothing OMITS both fields, so its canonical bytes stay byte-identical to a
	// receipt written before they existed and an already-signed clean receipt still verifies.
	clean := BuildReceipt(r, ReceiptInput{TargetType: "file", ExitCode: 0})
	if clean.RecordsUnwritten != 0 || clean.UnwrittenKinds != nil {
		t.Fatalf("a clean receipt must carry no refusals, got %d kinds=%v", clean.RecordsUnwritten, clean.UnwrittenKinds)
	}
	cleanBytes, err := clean.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cleanBytes), "recordsUnwritten") || strings.Contains(string(cleanBytes), "unwrittenKinds") {
		t.Fatalf("a clean receipt must OMIT the refusal fields (byte-identical backward compatibility), got: %s", cleanBytes)
	}

	refused := BuildReceipt(r, ReceiptInput{
		TargetType:       "file",
		ExitCode:         0,
		Restored:         98,
		RecordsUnwritten: 2,
		UnwrittenKinds:   map[string]int64{"unrepresentable": 1, "existing": 1},
	})
	if refused.RecordsUnwritten != 2 {
		t.Fatalf("recordsUnwritten: want 2, got %d", refused.RecordsUnwritten)
	}
	if refused.UnwrittenKinds["unrepresentable"] != 1 || refused.UnwrittenKinds["existing"] != 1 {
		t.Fatalf("unwrittenKinds tally wrong: %v", refused.UnwrittenKinds)
	}
	// Same rule the marker fields follow: the receipt's exitCode stays the VERIFICATION outcome. The
	// unwritten advisory rides on the process exit, not on this field, so a machine consumer reading
	// exitCode still learns whether the run verified and nothing else.
	if refused.ExitCode != 0 {
		t.Fatalf("exitCode must stay the verification outcome (0), got %d", refused.ExitCode)
	}

	// The counts must survive the canonical marshal a signature is computed over, or the evidence is not
	// actually signed evidence.
	b, err := refused.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var round Receipt
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatal(err)
	}
	if round.RecordsUnwritten != 2 || round.UnwrittenKinds["unrepresentable"] != 1 {
		t.Fatalf("the refusal tally did not survive a JSON round-trip: %s", b)
	}
	// Counts and kinds only. A record NAME must never reach the receipt, which is the same contract the
	// failures and marker fields keep.
	if strings.Contains(string(b), "con.") {
		t.Fatalf("a record name leaked into the receipt: %s", b)
	}
}
