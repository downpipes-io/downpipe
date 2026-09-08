package format

import (
	"encoding/json"
	"fmt"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// Receipt is the signed, machine-parseable record a verify or restore emits (SPEC.md
// 8.5): the honest outcome of the run, with the normative exit code and the verification
// labels, so an unverified restore is never presented as verified. It is canonical JSON
// and is signed by the operator's restore-session key when one is supplied.
type Receipt struct {
	Kind                string `json:"kind"`
	FormatVersion       string `json:"formatVersion"`
	RunID               string `json:"runId"`
	DownpipeID          string `json:"downpipeId"`
	StartedAt           string `json:"startedAt"`
	FinishedAt          string `json:"finishedAt"`
	Mode                string `json:"mode"`
	SignerExpected      string `json:"signerExpected"`
	SignatureResult     string `json:"signatureResult"`
	Completeness        string `json:"completeness"`
	BreakGlassVerified  bool   `json:"breakGlassVerified"`
	DeclaredRecordCount int64  `json:"declaredRecordCount"`
	RecordsVerified     int64  `json:"recordsVerified"`
	RecordsRestored     int64  `json:"recordsRestored"`
	// VanishedExcluded is the count of records observed at crawl start but gone before
	// their value could be sealed, excluded from declaredRecordCount (SPEC.md 12.5).
	//
	// A POINTER, AND ABSENT MEANS NOT MEASURED, so that a signed zero is never confused with
	// no production assignment anywhere, so every signed receipt the tool ever emitted
	// asserted `"vanishedExcluded": 0` about a quantity nothing had looked at. A signed
	// zero is a claim; an absent field is the truth, which is that this reader cannot
	// derive the number. Nothing in the signed root or the shard manifests records it (a
	// vanished record is not emitted as a record line at all, SPEC.md 12.5), so only a
	// caller that already holds the figure can fill it in, and none does today.
	VanishedExcluded *int64 `json:"vanishedExcluded,omitempty"`
	// DanglingSegments is the count of DISTINCT seg/ object paths named in the run's
	// manifests that are absent from the bucket (SPEC.md 10.1, 8.5).
	//
	// A POINTER FOR THE SAME REASON, and here the distinction is load-bearing rather than
	// theoretical. A shallow verify never opens a seg/ object, so it cannot answer the
	// question and leaves this absent; a deep verify or an applied restore reads every
	// segment, so it measures the count and a 0 from that pass genuinely means none were
	// missing. Before this, a shallow verify over an archive whose only segment had been
	// deleted emitted `"danglingSegments": 0` at exit 0.
	DanglingSegments *int64 `json:"danglingSegments,omitempty"`
	// IncompleteMarkers is the count of RESTORED records whose value is an incompleteness-marker
	// sentinel, NOT the source's live data (SPEC.md 12.1): the source was only partially available when
	// the run was sealed, so the record restored and hash-verified but its value is a placeholder. It is
	// ADDITIVE metadata that lets a machine consumer of the receipt tell a fully-real restore from one
	// padded with marker stubs; it does NOT change ExitCode (which stays the verification outcome). It is
	// omitempty, so a clean restore (zero markers) omits it and the canonical signed bytes are
	// byte-identical to a pre-marker receipt -- existing clean receipts and their signatures are
	// unaffected. It mirrors the CLI's ExitIncompleteMarkers advisory and the stderr WARNING.
	IncompleteMarkers int64 `json:"incompleteMarkers,omitempty"`
	// IncompleteMarkerKinds is the per-kind tally of IncompleteMarkers (e.g. {"_skipped":2,
	// "_unavailable":1}). The marker KIND is a fixed, engine-authored sentinel label, never a record
	// name, key or value, so the receipt keeps its "counts and fingerprints only" contract. It is also
	// omitempty (nil/empty on a clean restore, so absent and the signed bytes stay byte-identical); the
	// map values sum to IncompleteMarkers.
	IncompleteMarkerKinds map[string]int64 `json:"incompleteMarkerKinds,omitempty"`
	// RecordsUnwritten is the count of records the target REFUSED, and it is additive metadata in exactly
	// the same sense as IncompleteMarkers above and for the same reason. Those two counts describe the two
	// different ways a restore can fall short of its verified record count, and without them the receipt
	// carries only "verified 100, restored 98" and cannot say WHY the two disagree. A machine consumer
	// auditing a recovery needs to tell "98 landed and 2 were placeholders" from "98 landed and 2 are still
	// missing", and a windowed apply from either.
	//
	// It does NOT change ExitCode, which stays the VERIFICATION outcome (the process exit carries the
	// unwritten advisory separately). omitempty, so a restore that refused nothing omits it and the
	// canonical signed bytes stay byte-identical to a pre-existing clean receipt.
	RecordsUnwritten int64 `json:"recordsUnwritten,omitempty"`
	// UnwrittenKinds is the per-kind tally of RecordsUnwritten over the CLOSED conflict vocabulary
	// ("unrepresentable", "existing", "collision"). The kind is a fixed classification, never a record
	// name, key or value, so the receipt keeps its "counts and fingerprints only" contract. Also omitempty;
	// the map values sum to RecordsUnwritten.
	UnwrittenKinds         map[string]int64 `json:"unwrittenKinds,omitempty"`
	RecoveryBundleVerified bool             `json:"recoveryBundleVerified"`
	Freshness              ReceiptFreshness `json:"freshness"`
	Target                 ReceiptTarget    `json:"target"`
	ExitCode               int              `json:"exitCode"`
	Signed                 bool             `json:"signed"`
	ReceiptSignature       string           `json:"receiptSignature,omitempty"`
}

// ReceiptFreshness mirrors the RUNLOG freshness outcome (SPEC.md 8.5, 10).
type ReceiptFreshness struct {
	RunlogIndex         int64 `json:"runlogIndex"`
	IsLatestForDownpipe bool  `json:"isLatestForDownpipe"`
	// RollbackWarning is true when the run is stale, a RUNLOG chain anomaly was
	// detected (SPEC.md 10), or the RUNLOG maximum index is below the operator-pinned
	// minimum (SPEC.md 8.7 item 3).
	RollbackWarning bool  `json:"rollbackWarning"`
	MinIndexPinned  int64 `json:"minIndexPinned"`
	// Checked is false when the freshness check could not be RUN at all: the RUNLOG was
	// absent, unreadable, unparseable or empty, its signature did not verify, or the run
	// was not in it. A machine consumer needs this to tell a check that ran and found a
	// stale run (rollbackWarning true, checked true) from one that established nothing
	// (rollbackWarning true, checked FALSE), because runlogIndex reads 0 in both the
	// unchecked case and a hypothetical index-0 run, and inferring the difference from a
	// zero is exactly the reasoning this receipt exists to make unnecessary.
	Checked bool `json:"checked"`
}

// ReceiptTarget records where a restore wrote and whether the written value was read
// back and hash-checked (SPEC.md 12.6: a write-only Secrets Store target is created but
// value-unverified by the offline tool).
type ReceiptTarget struct {
	Type          string `json:"type"`
	ValueVerified bool   `json:"valueVerified"`
}

// ReceiptInput carries the run-time facts the receipt records beyond the reader's
// verification outcome.
type ReceiptInput struct {
	StartedAt              string
	FinishedAt             string
	SignerExpected         string // crypto.SignerFingerprint of the operator-pinned signer
	TargetType             string // the restore sink, or "verify" for a verify-only run
	Restored               int64
	ExitCode               int
	MinIndexPinned         int64
	RecoveryBundleVerified bool
	// Completeness overrides the reader's manifests-only verdict with the one the pass
	// actually reached. Empty means "use the reader's outcome", which is right for a
	// shallow verify, because manifests are all it read.
	//
	// IT HAS TO BE SUPPLIED BY ANY PASS THAT DECRYPTED RECORDS. Outcome.Completeness is
	// computed from the signed manifests, so it stays "complete" on a deep verify or a
	// restore in which every record failed its plaintext hash check. Driven: `verify --deep`
	// over an archive whose only segment was gone printed
	// "completeness=UNVERIFIED (1 of 1 record(s) failed integrity)" twice, exited 2, and
	// signed a receipt saying "completeness": "complete", "mode": "verified". SPEC.md 8.5
	// requires that the receipt never launder an unverified run as verified, and the signed
	// machine-readable artefact is the surface a third party reads. The value must stay
	// inside the SPEC.md 8.5 enum ("complete", "UNVERIFIED", "incomplete"); the counts the
	// printed line adds belong to the printed line.
	Completeness string
	// VanishedExcluded is the count of records excluded because they vanished mid-crawl
	// (SPEC.md 12.5); the reader cannot derive this from the manifest, so the caller
	// supplies it. Nil means the caller did not measure it, and the receipt then omits the
	// field rather than signing a zero for it.
	VanishedExcluded *int64
	// DanglingSegments is the count of distinct seg/ paths named in the run's manifests
	// that were absent from the bucket during the pass (SPEC.md 10.1, 8.5). Nil means the
	// pass did not read segments (a shallow verify, a dry-run restore), and the receipt
	// omits the field rather than signing a zero it did not measure.
	DanglingSegments *int64
	// IncompleteMarkers is the count of restored incompleteness-marker records
	// (restore.Result.IncompleteMarkers); IncompleteMarkerKinds is their per-kind tally
	// (e.g. {"_skipped":2}). Both are zero/nil on a clean restore, so the receipt omits
	// them (omitempty) and its signed bytes stay byte-identical (SPEC.md 12.1, 8.5).
	IncompleteMarkers     int64
	IncompleteMarkerKinds map[string]int64
	// RecordsUnwritten is the count of records the target REFUSED (restore.Result.SkippedConflicts);
	// UnwrittenKinds is their per-kind tally over the closed conflict vocabulary. Both are zero/nil on a
	// restore that refused nothing, so the receipt omits them and its signed bytes stay byte-identical to
	// one written before these fields existed.
	RecordsUnwritten int64
	UnwrittenKinds   map[string]int64
}

// ReceiptSource is the verified-run view BuildReceipt needs: the signed root, the
// verification outcome, the freshness result, and the verified record count. Both the
// load-all *Reader and the streaming *StreamReader satisfy it, so a restore receipt is
// assembled the same way whichever reader produced the run (the streaming reader supplies
// RecordCount without ever holding the whole record slice).
type ReceiptSource interface {
	Root() *spec.RootManifest
	Outcome() Outcome
	Freshness() FreshnessResult
	RecordCount() int64
}

// BuildReceipt assembles a receipt from a verified run and the run-time input.
func BuildReceipt(r ReceiptSource, in ReceiptInput) *Receipt {
	root := r.Root()
	out := r.Outcome()
	fresh := r.Freshness()
	completeness := out.Completeness
	if in.Completeness != "" {
		completeness = in.Completeness
	}
	return &Receipt{
		Kind:                   "downpipe-restore-receipt",
		FormatVersion:          root.FormatVersion,
		RunID:                  root.RunID,
		DownpipeID:             root.DownpipeID,
		StartedAt:              in.StartedAt,
		FinishedAt:             in.FinishedAt,
		Mode:                   out.Mode,
		SignerExpected:         in.SignerExpected,
		SignatureResult:        out.SignatureResult,
		Completeness:           completeness,
		BreakGlassVerified:     out.BreakGlassVerified,
		DeclaredRecordCount:    root.DeclaredRecordCount,
		RecordsVerified:        r.RecordCount(),
		RecordsRestored:        in.Restored,
		VanishedExcluded:       in.VanishedExcluded,
		DanglingSegments:       in.DanglingSegments,
		IncompleteMarkers:      in.IncompleteMarkers,
		RecordsUnwritten:       in.RecordsUnwritten,
		UnwrittenKinds:         in.UnwrittenKinds,
		IncompleteMarkerKinds:  in.IncompleteMarkerKinds,
		RecoveryBundleVerified: in.RecoveryBundleVerified,
		Freshness: ReceiptFreshness{
			RunlogIndex:         fresh.MaxIndexForDownpipe,
			IsLatestForDownpipe: fresh.IsLatestForDownpipe,
			RollbackWarning:     fresh.RollbackWarning,
			MinIndexPinned:      in.MinIndexPinned,
			Checked:             !fresh.Unchecked,
		},
		Target:   ReceiptTarget{Type: in.TargetType, ValueVerified: false},
		ExitCode: in.ExitCode,
		Signed:   false,
	}
}

// Sign signs the receipt with the operator's restore-session key over the canonical
// bytes of the receipt with Signed=true and the signature field absent, then sets the
// signature. A verifier blanks ReceiptSignature, keeps Signed=true, re-canonicalises
// and verifies.
func (rcpt *Receipt) Sign(signer *crypto.HybridSigner) error {
	rcpt.Signed = true
	rcpt.ReceiptSignature = ""
	canonical, err := CanonicalJSON(rcpt)
	if err != nil {
		return fmt.Errorf("canonicalise receipt: %w", err)
	}
	sig, err := signer.Sign(canonical)
	if err != nil {
		return fmt.Errorf("sign receipt: %w", err)
	}
	rcpt.ReceiptSignature = B64Encode(sig)
	return nil
}

// VerifyReceipt is the canonical implementation of the receipt-verify protocol the
// Sign doc-comment describes: it parses a receipt from its emitted JSON bytes, lifts the
// carried signature, reconstructs the signed pre-image (Signed=true with the signature
// field blanked, re-canonicalised), and checks it against the operator's restore-session
// signer. This is the path a third party follows to confirm an outcome from the bytes on
// disk (SPEC.md 8.5). It returns the parsed receipt so the caller can also read the
// outcome it just authenticated. An unsigned receipt (Signed=false or no signature) is
// reported as such rather than silently accepted.
func VerifyReceipt(receiptJSON []byte, verifier *crypto.HybridVerifier) (*Receipt, error) {
	var rcpt Receipt
	if err := json.Unmarshal(receiptJSON, &rcpt); err != nil {
		return nil, fmt.Errorf("parse receipt: %w", err)
	}
	if !rcpt.Signed || rcpt.ReceiptSignature == "" {
		return &rcpt, fmt.Errorf("receipt is not signed")
	}
	sig, err := B64Decode(rcpt.ReceiptSignature)
	if err != nil {
		return &rcpt, fmt.Errorf("decode receipt signature: %w", err)
	}
	// Reconstruct the exact bytes Sign covered: Signed=true, signature field absent.
	rcpt.Signed = true
	rcpt.ReceiptSignature = ""
	canonical, err := CanonicalJSON(&rcpt)
	if err != nil {
		return &rcpt, fmt.Errorf("canonicalise receipt: %w", err)
	}
	if err := verifier.Verify(canonical, sig); err != nil {
		return &rcpt, fmt.Errorf("verify receipt signature: %w", err)
	}
	// Restore the signature on the returned value so it reflects the input the caller
	// passed in, not the blanked pre-image used for verification.
	rcpt.ReceiptSignature = B64Encode(sig)
	return &rcpt, nil
}

// Marshal returns the canonical JSON bytes of the receipt.
func (rcpt *Receipt) Marshal() ([]byte, error) { return CanonicalJSON(rcpt) }
