package format

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// FreshnessResult is the outcome of the RUNLOG freshness check for a run (SPEC.md 10),
// recorded so a restore receipt can report it.
type FreshnessResult struct {
	IsLatestForDownpipe bool
	MaxIndexForDownpipe int64
	RunlogMaxIndex      int64
	// RollbackWarning is true when the freshness check DID NOT PASS, for any reason: the
	// run is not the latest for its downpipe, a chain anomaly (a duplicated index, a
	// per-downpipe prevRunId linearity break, or a dangling or forked prevRunId) was
	// detected, the RUNLOG maximum index is below the operator-supplied minimum pin
	// (SPEC.md 8.7 item 3, 10), or the check could not be run at all (see Unchecked).
	//
	// This field must be true whenever the freshness check did not pass, regardless of
	// severity: a forged RUNLOG signature or an absent RUNLOG is just as much a reason to
	// warn as a merely below-pin index, and it is the one field both the printed warning
	// and the signed receipt key on.
	RollbackWarning bool
	// Unchecked is true when the freshness check could not be RUN: the RUNLOG was absent or
	// unreadable, its signature failed or was undecodable, it did not parse, it was empty,
	// the run is not in it, or the entry that names the run disagrees with the signed root
	// about its downpipe, its index or its prevRunId. It is a strictly stronger statement
	// than RollbackWarning, which is also true in every one of those cases: a check that
	// found a problem is a finding, and a check that could not run is an unknown, and an
	// operator being told to proceed needs to be told which one they have.
	Unchecked bool
	// RunlogUntrusted is true when the finding is about the RUNLOG's own trustworthiness
	// rather than the run's age: the log could not be verified or read at all (every
	// Unchecked case), or it verified against the pinned signer and is internally
	// contradictory (a chain anomaly: a duplicated index, a per-downpipe prevRunId
	// linearity break, or a dangling or forked prevRunId). It is false for the only two
	// findings that come from a RUNLOG that verified and is self-consistent: the run is
	// not the latest for its downpipe, and the log's maximum index is below the
	// operator's own --min-runlog-index pin.
	//
	// THE PERMISSION BOUNDARY, NOT A LABEL. --allow-stale is an age word: it must not waive
	// a finding about the RUNLOG's own trustworthiness, such as a forged _RECOVERY/RUNLOG.sig
	// or an absent RUNLOG. Options.acknowledges reads this field, so those findings need the
	// stronger --allow-unverified-runlog, which says what it waives.
	//
	// NOT in the receipt: the receipt's checked/rollbackWarning pair is the
	// machine-readable outcome and its schema is vendored by the engine. This decides
	// which acknowledgement the reader will accept and which sentence the operator reads.
	RunlogUntrusted bool
	// Reason is the freshness failure in the reader's own words, empty when the check
	// passed. It is what the operator is shown when they override the gate.
	//
	// Unchecked is also set for an empty log, a run the log does not carry, and an entry
	// disagreeing with the signed root on downpipe, index or prevRunId, so an operator
	// overriding the gate is shown the exact disagreement rather than a generic guess.
	//
	// NOT in the receipt: the receipt's checked/rollbackWarning pair is the machine-readable
	// outcome and its schema is vendored by the engine. This is the human sentence.
	Reason string
}

// uncheckedFreshness is the result every early return in the freshness path carries: the
// check did not run, so it did not pass, and cause is what an operator overriding the gate
// is shown. Named rather than written out at each return because the defect this replaces
// was exactly a bare zero value repeated seven times, and one of them being missed is how
// it comes back.
func uncheckedFreshness(cause error) FreshnessResult {
	return FreshnessResult{RollbackWarning: true, Unchecked: true, RunlogUntrusted: true, Reason: cause.Error()}
}

// ErrFreshnessUnchecked marks a freshness failure where the check could not be RUN at all,
// as distinct from one that ran and found a stale run, a chain anomaly or a below-pin
// index. The CLI keys on it through errors.Is: when the operator did NOT pass --allow-stale
// the reader returns no FreshnessResult, only this error, so without a marker on the error
// the command layer could not tell the two apart and advised --allow-stale in the same
// words for both. Advising an operator mid-recovery to waive a RUNLOG signature that did
// not verify, in the sentence written for a benign chain difference, is the same
// inverted-by-severity defect one message earlier in the same path.
var ErrFreshnessUnchecked = errors.New("the anti-rollback/freshness check could not be run")

// ErrRunlogChainAnomaly marks a freshness failure where the RUNLOG DID verify against the
// pinned signer and is internally contradictory: a duplicated index, a per-downpipe
// prevRunId linearity break, or a dangling or forked prevRunId. The check ran, so
// ErrFreshnessUnchecked does not cover it, and it is not about the run's age either, so
// the CLI must not advise --allow-stale for it. Without this marker the exit-5 hint sent
// an operator with a rewritten chain to a flag that, after the age/integrity split,
// refuses the same way a second time.
var ErrRunlogChainAnomaly = errors.New("the runlog verified but contradicts itself")

// RunlogUntrustedError reports whether err is a freshness refusal about the RUNLOG's own
// trustworthiness rather than the run's age. It is the error-side reading of
// FreshnessResult.RunlogUntrusted, for the CLI, which on a refusal is handed the error and
// no FreshnessResult at all.
//
// The two must agree on every input or the tool refuses under one rule and explains itself
// under another, so TestTheErrorAndTheResultAgreeOnWhichPermissionIsNeeded drives every
// reachable freshness state and compares them.
func RunlogUntrustedError(err error) bool {
	return errors.Is(err, ErrFreshnessUnchecked) || errors.Is(err, ErrRunlogChainAnomaly)
}

// unchecked pairs the FreshnessResult an early return in the freshness path carries with
// the coded ExitStale error that goes with it, so the result and the error cannot drift
// apart on which cause they name or on whether the check ran.
func unchecked(cause error) (FreshnessResult, error) {
	return uncheckedFreshness(cause), staleUnchecked(cause)
}

// staleUnchecked codes cause as the ExitStale error carrying ErrFreshnessUnchecked. Split
// out from unchecked for the two store reads that must keep codedGet's ExitUnreachable
// classification (a RUNLOG that was never retrieved is a transport failure, not a verdict
// about the archive), which construct their own coded error and cannot use the pair.
func staleUnchecked(cause error) error {
	return coded(ExitStale, fmt.Errorf("%w: %w", ErrFreshnessUnchecked, cause))
}

// MarshalRunlog serialises RUNLOG entries as newline-delimited canonical JSON, the
// exact bytes stored as _RECOVERY/RUNLOG and covered by the detached signature.
func MarshalRunlog(entries []spec.RunlogEntry) ([]byte, error) {
	var buf bytes.Buffer
	for _, e := range entries {
		line, err := CanonicalJSON(e)
		if err != nil {
			return nil, fmt.Errorf("canonicalise runlog entry %d: %w", e.Index, err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

// ParseRunlog parses the append-only NDJSON RUNLOG.
func ParseRunlog(b []byte) ([]spec.RunlogEntry, error) {
	var entries []spec.RunlogEntry
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		if err := validateCounts(line, "index", "recordCount"); err != nil {
			return nil, err
		}
		var e spec.RunlogEntry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("parse runlog entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// CheckFreshness verifies the RUNLOG signature against the operator-pinned signer,
// confirms the run is present and agrees with the signed root.freshness, and checks
// that the run is the latest for its downpipe and that the RUNLOG's maximum index is
// not below an out-of-band pin (SPEC.md 8.7, 10). minIndex of 0 means no pin. A
// freshness problem returns an ExitStale error; the caller proceeds only with an
// explicit acknowledgement.
func CheckFreshness(runlogBytes, sigText []byte, runID string, root *spec.RootManifest, signer *crypto.HybridVerifier, minIndex int64) (FreshnessResult, error) {
	sig, err := B64Decode(strings.TrimSpace(string(sigText)))
	if err != nil {
		return unchecked(fmt.Errorf("decode runlog signature: %w", err))
	}
	if err := signer.Verify(runlogBytes, sig); err != nil {
		return unchecked(fmt.Errorf("verify runlog signature: %w", err))
	}
	entries, err := ParseRunlog(runlogBytes)
	if err != nil {
		return unchecked(err)
	}
	if len(entries) == 0 {
		return unchecked(fmt.Errorf("runlog is empty"))
	}

	this, runlogMax, downpipeMax, err := lookupRunEntry(entries, runID, root)
	if err != nil {
		return unchecked(err)
	}

	result := FreshnessResult{
		IsLatestForDownpipe: this.Index == downpipeMax,
		MaxIndexForDownpipe: downpipeMax,
		RunlogMaxIndex:      runlogMax,
	}
	// A signed RUNLOG can still be internally chain-anomalous: a duplicated index, a
	// break in a downpipe's prevRunId linearity, or a dangling or forked
	// prevRunId. The signature gate and the --min-runlog-index pin cover the active
	// bucket-write adversary, but SPEC.md 8.7 item 3 and 10 make the in-bucket chain a
	// verified-mode MUST the reader is the authoritative verifier for, so reject any
	// anomaly as a rollback regardless of whether the restored run is itself the latest
	// (SPEC.md 10). A per-downpipe index gap is NOT an anomaly: indices are allocated
	// account-globally and a failed run consumes one without appending an entry.
	// The three findings below are a check that RAN, so each keeps RollbackWarning without
	// Unchecked, and each records its own reason: the operator who overrides the gate is
	// shown what was found, not a description of the family it belongs to.
	if err := detectChainAnomaly(entries); err != nil {
		result.RollbackWarning = true
		// A chain anomaly is found in a RUNLOG that VERIFIED against the pinned signer, so
		// this is not a check that failed to run. It is still a statement about the log
		// rather than about the run's age: an index the account-global counter never
		// reissues appearing twice, or a chain that forks, means the log was rewritten or
		// hand-assembled. So it sits on the integrity side of the permission boundary with
		// the unchecked cases, not with "this run is old".
		result.RunlogUntrusted = true
		result.Reason = err.Error()
		return result, coded(ExitStale, fmt.Errorf("%w: %w", ErrRunlogChainAnomaly, err))
	}
	if minIndex > 0 && runlogMax < minIndex {
		err := fmt.Errorf("runlog max index %d is below the pinned minimum %d (possible rollback)", runlogMax, minIndex)
		result.RollbackWarning = true
		result.Reason = err.Error()
		return result, coded(ExitStale, err)
	}
	if !result.IsLatestForDownpipe {
		err := fmt.Errorf("run %s is not the latest for its downpipe (index %d, latest %d)", runID, this.Index, downpipeMax)
		result.RollbackWarning = true
		result.Reason = err.Error()
		return result, coded(ExitStale, err)
	}
	return result, nil
}

// lookupRunEntry scans the parsed RUNLOG for the requested run, computes the maximum
// index across the whole log and across the run's downpipe, and binds the matched entry
// to the signed root: it must exist, belong to root's downpipe, and agree with
// root.Freshness on index and prevRunId (SPEC.md 10). It returns the matched entry and
// the two maxima, or a BARE error on the first disagreement: its only caller passes that
// error to unchecked(), which is what codes it ExitStale and marks it as a check that
// could not be run. Coding it here as well would nest one ExitError inside another and
// leave two places deciding the same run's exit status.
func lookupRunEntry(entries []spec.RunlogEntry, runID string, root *spec.RootManifest) (*spec.RunlogEntry, int64, int64, error) {
	var this *spec.RunlogEntry
	var runlogMax, downpipeMax int64
	for i := range entries {
		e := &entries[i]
		if e.Index > runlogMax {
			runlogMax = e.Index
		}
		if e.DownpipeID == root.DownpipeID && e.Index > downpipeMax {
			downpipeMax = e.Index
		}
		if e.RunID == runID {
			this = e
		}
	}
	if this == nil {
		return nil, 0, 0, fmt.Errorf("run %s is absent from the runlog", runID)
	}
	// Bind the matched entry to the signed root's downpipe. The index/prevRunId checks
	// below already pin this entry to root.freshness, but those alone leave the entry's
	// own downpipe membership implicit; an entry from another downpipe that happened to
	// share this runId must not be treated as the run's freshness record (SPEC.md 10).
	if this.DownpipeID != root.DownpipeID {
		return nil, 0, 0, fmt.Errorf("run %s belongs to downpipe %s, not the signed root downpipe %s", runID, this.DownpipeID, root.DownpipeID)
	}
	if this.Index != root.Freshness.RunlogIndex {
		return nil, 0, 0, fmt.Errorf("runlog index %d disagrees with the signed root %d", this.Index, root.Freshness.RunlogIndex)
	}
	if !samePrev(this.PrevRunID, root.Freshness.PrevRunID) {
		return nil, 0, 0, fmt.Errorf("runlog prevRunId disagrees with the signed root")
	}
	return this, runlogMax, downpipeMax, nil
}

func samePrev(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// detectChainAnomaly inspects the signed RUNLOG for the chain anomalies of SPEC.md 10
// (amended: per-downpipe prevRunId linearity replaced index contiguity),
// returning a descriptive error for the first it finds or nil for a well-formed
// document. Index values come from one account-global counter and an entry is appended
// only when a run finalises, so an index gap is NOT an anomaly. The three checks below
// (index uniqueness, per-downpipe prevRunId linearity, dangling or forked prevRunId)
// each carry their own rationale inline; see SPEC.md 10 and 10.1 for the full rules.
func detectChainAnomaly(entries []spec.RunlogEntry) error {
	// LINE ORDER IS NOT LOAD-BEARING: indices are allocated at trigger time but entries land
	// at FINALISE time, so concurrent runs legitimately append out of allocation order. The
	// whole-document signature is the integrity anchor; reordering without re-signing
	// is impossible, so in-document order carries no adversarial signal. The checks
	// below therefore run over a copy sorted by index. The one index fact that IS a
	// corruption signal is a DUPLICATE: the account-global counter never reissues an
	// index, so two entries sharing one means the log was corrupted or hand-assembled.
	sorted := make([]spec.RunlogEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Index < sorted[j].Index })
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Index == sorted[i-1].Index {
			return fmt.Errorf("runlog index %d appears twice (log corrupted or rewritten)", sorted[i].Index)
		}
	}

	// Ascending index order is allocation order, so one pass with a per-downpipe tail
	// implements the prevRunId linearity rule.
	tail := make(map[string]string, len(sorted))
	for i := range sorted {
		e := &sorted[i]
		if last, ok := tail[e.DownpipeID]; ok && (e.PrevRunID == nil || *e.PrevRunID != last) {
			return fmt.Errorf("runlog entry %s for downpipe %s does not chain to the prior retained entry %s (chain rewritten)", e.RunID, e.DownpipeID, last)
		}
		tail[e.DownpipeID] = e.RunID
	}

	ids := make(map[string]struct{}, len(sorted))
	for i := range sorted {
		ids[sorted[i].RunID] = struct{}{}
	}
	prevSeen := make(map[string]string, len(sorted))
	for i := range sorted {
		e := &sorted[i]
		if e.PrevRunID == nil {
			continue
		}
		prev := *e.PrevRunID
		if _, ok := ids[prev]; !ok {
			return fmt.Errorf("runlog entry %s has a dangling prevRunId %s that no entry carries (chain rewritten)", e.RunID, prev)
		}
		if first, ok := prevSeen[prev]; ok {
			return fmt.Errorf("runlog entries %s and %s share prevRunId %s (forked chain)", first, e.RunID, prev)
		}
		prevSeen[prev] = e.RunID
	}
	return nil
}
