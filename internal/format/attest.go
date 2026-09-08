package format

import (
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// AttestResult is the outcome of a keyless attestation over a run (SPEC.md 8.8).
// It reports what a recoverer can establish about a run WITHOUT the break-glass identity:
// the root signature, the structural completeness of the signed root (shard hashes and
// the shard count), and the RUNLOG freshness. It carries no plaintext and no key
// material, only labels, counts and the run identifier.
type AttestResult struct {
	RunID string
	// SignatureResult mirrors Outcome.SignatureResult: "valid" | "invalid" | "absent" |
	// "wrong-signer" when a signer was pinned, or "unchecked" when no signer was supplied
	// and only the signature's presence and structural shape were inspected.
	SignatureResult string
	// SignaturePresent is true when a non-empty root signature object exists, regardless
	// of whether a signer was supplied to verify it.
	SignaturePresent bool
	// SignerPinned is true when a signer verifier was supplied, so SignatureResult is a
	// cryptographic verdict rather than a structural one.
	SignerPinned bool
	// ShardsHashVerified is true when every shard listed in the signed root was present
	// and its bytes matched the root's signed SHA-384, and the shard count was consistent.
	// This is the keyless completeness check: it proves the shard set is intact without
	// decrypting a single record (SPEC.md 8.3).
	ShardsHashVerified bool
	// RecipientSetVerified is true when the signed recipient set passed the same structural
	// gate keyed Open applies (SPEC.md 8.6): a break-glass recipient is declared present,
	// exactly one recipient carries the break-glass role, every listed fingerprint matches
	// its public key, the master-capsule wraps cover the recipient set, and the recipient-set
	// hash matches the listed recipients. It needs no key and no signer, so a keyless attest
	// detects a dropped or role-flipped break-glass recipient rather than green-lighting an
	// archive whose offline recoverability has been stripped.
	RecipientSetVerified bool
	// ShardCount is the number of shards the signed root lists and that were hash-checked.
	ShardCount int
	// DeclaredRecordCount is the run's signed declared record count, surfaced for the
	// report. It is not record-verified here: record-level completeness needs the master
	// key and therefore the identity.
	DeclaredRecordCount int64
	// RunlogVerified is true when the RUNLOG check passed: with a signer that is a verified
	// signature plus a fresh, chain-consistent log; without a signer it is a structural
	// parse and presence check only.
	RunlogVerified bool
	// Freshness is the RUNLOG freshness outcome. With a signer this is the full
	// cryptographically-anchored check (SPEC.md 8.7, 10): the RUNLOG signature is verified
	// before any of these fields are trusted. Without a signer, RunlogMaxIndex and
	// RollbackWarning are still populated (when the caller passed minIndex > 0), but from
	// the UNAUTHENTICATED parsed RUNLOG: nothing anchors those bytes without a signer, so
	// this only catches an accidentally stale or wholesale-replayed bucket, not a targeted
	// bucket-write adversary who also edits the plaintext RUNLOG's stated index.
	// IsLatestForDownpipe and MaxIndexForDownpipe stay at their zero value keyless, because
	// judging "latest" needs the signed root.Freshness cross-check this mode does not
	// attempt. SignerPinned is the field that tells a caller which case applies.
	Freshness FreshnessResult
	// Code is the normative exit code the attestation maps to (SPEC.md 8.5): 0 when every
	// requested check passed, ExitUnverified for a signature or shard-hash failure,
	// ExitStale for a freshness failure.
	Code int
}

// OK reports whether the attestation passed every check it ran (Code 0).
func (a AttestResult) OK() bool { return a.Code == 0 }

// Attest performs a keyless attestation over a run: it verifies the root manifest
// signature, the structural completeness of the signed root (every listed shard is
// present and its bytes match the signed SHA-384, and the shard count is consistent),
// and the RUNLOG freshness, all WITHOUT the break-glass identity. It never unwraps the
// master capsule, opens a shard manifest or decrypts a record, so it materialises no
// plaintext and needs no recipient key (SPEC.md 8.3: the signature and structure checks
// are independent of byte recovery).
//
// signer is optional. When a verifier is supplied the signatures are cryptographically
// verified against it (the operator-pinned recovery-sheet signer). When signer is nil
// the attestation is fully keyless: it checks that a root signature is present and
// structurally well-formed and that the RUNLOG parses and contains the run, and reports
// SignatureResult "unchecked" so the caller never mistakes a structural pass for a
// cryptographic one. Either way a tampered shard or a missing shard fails the
// attestation, as does a forged or absent signature when a signer was supplied to judge
// it against.
//
// minIndex is the operator's out-of-band anti-rollback pin (SPEC.md 10), the same
// --min-runlog-index a caller passes to verify/restore; 0 means no pin. With a signer,
// a RUNLOG whose maximum index is below the pin fails cryptographically anchored,
// exactly as verify/restore already do (a tail rollback: the newer runs were deleted and
// the RUNLOG rolled back to an older, wholesale validly-signed state, which is
// internally self-consistent and has no in-document high-water mark to contradict it).
// Without a signer the same comparison still runs against the parsed RUNLOG's own
// claimed index, but it is a structural self-consistency check like the shard-hash and
// recipient-set checks above it, not a cryptographic one: nothing anchors those bytes
// keyless, so it catches an accidentally stale or wholesale-replayed bucket but not a
// targeted adversary who also edits the RUNLOG's plaintext index. A caller that needs
// the pin to hold against that adversary MUST supply --signer.
func Attest(store ObjectStore, runID string, signer *crypto.HybridVerifier, minIndex int64) (*AttestResult, error) {
	if _, err := spec.DecodeULID(runID); err != nil {
		return nil, coded(ExitUsage, fmt.Errorf("runId: %w", err))
	}
	rootBytes, err := openRootManifest(store, runID)
	if err != nil {
		return nil, err
	}
	res := &AttestResult{RunID: runID, SignatureResult: "valid", SignerPinned: signer != nil}

	// The root signature: a structural object that exists independently of the identity.
	// With a pinned signer this is the cryptographic gate; without one it is a presence and
	// shape check that still rejects an absent or malformed signature. A failure here is
	// recorded and held (sigFailErr) so the structural checks still run and the result is
	// complete; it is returned at the end unless a more specific structural error fires
	// first.
	sigFailErr := res.classifyRootSignature(store, runID, rootBytes, signer)

	root, err := ParseRoot(rootBytes)
	if err != nil {
		return nil, err // already coded (usage); without a parseable root there is nothing to attest
	}
	if err := checkFormatVersion(root.FormatVersion); err != nil {
		return nil, err
	}
	if err := checkEnvelopeCodec(root); err != nil {
		return nil, err
	}
	if root.RunID != runID {
		return nil, coded(ExitUnverified, fmt.Errorf("manifest runId %q does not match the requested run %q", root.RunID, runID))
	}
	res.DeclaredRecordCount = root.DeclaredRecordCount

	// Recipient-set integrity (SPEC.md 8.6): the same structural gate keyed Open applies at
	// reader.go (fatal even under allow-unverified), run here keylessly. A bucket-write
	// Recipient-set integrity (SPEC.md 8.6): the same structural gate keyed Open applies at
	// reader.go (fatal even under allow-unverified), run here keylessly. A bucket-write
	// adversary who drops or role-flips the break-glass recipient strips the archive's
	// offline recoverability; keyed Open catches it (ExitUnverified), and a keyless attest
	// must too rather than returning rc=0 on an archive the break-glass key can no longer
	// open. This needs no master key and no signer: it
	// recipient-set hash. A failure is the operative result and is returned immediately, the
	// same precedence as the shard-hash gate below.
	if err := checkRecipientSet(root); err != nil {
		res.RecipientSetVerified = false
		if res.Code == 0 {
			res.Code = ExitUnverified
		}
		return res, coded(ExitUnverified, err)
	}
	res.RecipientSetVerified = true

	// Keyless completeness: the shard count is consistent and every listed shard is
	// present with bytes that match the signed root SHA-384. This proves the shard set is
	// intact without decrypting a record (record-level Merkle completeness needs the master
	// key and so is left to a full verify/restore with the identity).
	res.ShardCount = root.ShardCount
	if err := res.verifyShardHashes(store, root); err != nil {
		return res, err
	}

	// RUNLOG freshness. With a signer this is the full signed, chain-consistent check;
	// without one the log is parsed and the run's presence confirmed, but it is not
	// cryptographically anchored, so RunlogVerified stays false to report the gap honestly.
	if err := res.checkRunlog(store, runID, root, signer, minIndex); err != nil {
		if res.Code == 0 {
			// checkRunlog's Get failures may now be ExitUnreachable (codedGet); read the
			// code the error actually carries rather than assuming ExitStale, its code
			// before ExitUnreachable existed.
			if code, ok := exitCodeOf(err); ok {
				res.Code = code
			} else {
				res.Code = ExitStale
			}
		}
		return res, err
	}

	// The structural shard and RUNLOG checks passed. If the signature leg failed, that is
	// now the operative failure: surface it so an absent, malformed or wrong-signer
	// signature fails the attestation even when nothing else is wrong.
	if sigFailErr != nil {
		return res, sigFailErr
	}
	return res, nil
}

// verifyShardHashes checks that the signed shard count matches the listed shards and that
// every listed shard is present with bytes that hash to the signed root SHA-384. It sets
// ShardsHashVerified and the exit code on res, and returns a coded error on the first
// mismatch (nil on a clean pass). It reads shard bytes but never decrypts a record.
func (a *AttestResult) verifyShardHashes(store ObjectStore, root *spec.RootManifest) error {
	if root.ShardCount != len(root.Shards) {
		a.ShardsHashVerified = false
		if a.Code == 0 {
			a.Code = ExitUnverified
		}
		return coded(ExitUnverified, fmt.Errorf("shardCount %d does not match the %d listed shards", root.ShardCount, len(root.Shards)))
	}
	for _, sh := range root.Shards {
		shardBytes, gerr := store.Get(sh.Object)
		if gerr != nil {
			a.ShardsHashVerified = false
			cerr := codedGet(ExitUnverified, fmt.Errorf("read shard %s: %w", sh.ID, gerr))
			if a.Code == 0 {
				a.Code = cerr.Code
			}
			return cerr
		}
		if !crypto.ConstantTimeEqual([]byte(SHA384Hex(shardBytes)), []byte(sh.SHA384)) {
			a.ShardsHashVerified = false
			if a.Code == 0 {
				a.Code = ExitUnverified
			}
			return coded(ExitUnverified, fmt.Errorf("shard %s hash does not match the signed root", sh.ID))
		}
	}
	a.ShardsHashVerified = true
	return nil
}

// classifyRootSignature inspects the root signature object the same way Open does, but
// without failing the whole attestation early: it records the result on res, sets the
// exit code, and returns a coded error describing the failure (nil on a pass) so the
// caller can run the structural checks and still surface the signature outcome. With a
// nil signer it can only judge presence and structural shape, reported as "unchecked"
// when the object is present and well-formed (and "unchecked" is a pass: nil error).
func (a *AttestResult) classifyRootSignature(store ObjectStore, runID string, rootBytes []byte, signer *crypto.HybridVerifier) error {
	sigText, sigErr := store.Get(runKey(runID, "root.manifest.json.sig"))
	if sigErr != nil {
		a.SignaturePresent = false
		a.SignatureResult = "absent"
		cerr := codedGet(ExitUnverified, fmt.Errorf("read root signature: %w", sigErr))
		if a.Code == 0 {
			a.Code = cerr.Code
		}
		return cerr
	}
	a.SignaturePresent = true
	sig, derr := B64Decode(strings.TrimSpace(string(sigText)))
	switch {
	case derr != nil:
		// A malformed (undecodable) signature is invalid even without a signer to verify
		// against: the bytes are not a signature at all.
		a.SignatureResult = "invalid"
	case len(sig) <= ed25519.SignatureSize:
		// Too short to hold both hybrid halves (SPEC.md 8.1): structurally invalid.
		a.SignatureResult = "invalid"
	case signer == nil:
		// Keyless: the object is present and the right shape, but no signer was pinned to
		// verify it. Report the honest "unchecked" rather than implying a cryptographic pass.
		// This is a pass: a keyless attestation cannot do better than confirm the shape.
		a.SignatureResult = "unchecked"
		return nil
	case VerifyRootBytes(rootBytes, sig, signer) != nil:
		a.SignatureResult = "wrong-signer"
	default:
		a.SignatureResult = "valid"
		return nil
	}
	a.failSignature()
	return coded(ExitUnverified, fmt.Errorf("verify root signature: %s", a.SignatureResult))
}

// failSignature records that the signature leg failed by setting the unverified exit code
// when no earlier leg has already set one.
func (a *AttestResult) failSignature() {
	if a.Code == 0 {
		a.Code = ExitUnverified
	}
}

// checkRunlog verifies the RUNLOG. With a signer it runs the full signed freshness check
// (rejecting a stale run, a chain anomaly or a below-pin index, minIndex threaded through to
// CheckFreshness exactly as verify/restore's --min-runlog-index does); without a signer it
// parses the log and confirms the run is present, a structural keyless check that still
// rejects an absent, unreadable or run-missing log, and, only when the caller passed
// minIndex > 0, additionally rejects a log whose own claimed maximum index falls below the
// pin. That comparison is UNAUTHENTICATED keyless (see the Attest doc comment): a structural
// self-consistency check, not a cryptographic one.
func (a *AttestResult) checkRunlog(store ObjectStore, runID string, root *spec.RootManifest, signer *crypto.HybridVerifier, minIndex int64) error {
	// Every early return below records uncheckedFreshness(): the check did not run, so it
	// did not pass, and a caller reading a.Freshness must not find a zero value that reads
	// as a clean freshness result. The same bare-zero-value defect lived in CheckFreshness.
	runlogBytes, err := store.Get("_RECOVERY/RUNLOG")
	if err != nil {
		cause := fmt.Errorf("read runlog: %w", err)
		a.Freshness = uncheckedFreshness(cause)
		return codedGet(ExitStale, fmt.Errorf("%w: %w", ErrFreshnessUnchecked, cause))
	}
	if signer != nil {
		sigText, serr := store.Get("_RECOVERY/RUNLOG.sig")
		if serr != nil {
			cause := fmt.Errorf("read runlog signature: %w", serr)
			a.Freshness = uncheckedFreshness(cause)
			return codedGet(ExitStale, fmt.Errorf("%w: %w", ErrFreshnessUnchecked, cause))
		}
		fresh, ferr := CheckFreshness(runlogBytes, sigText, runID, root, signer, minIndex)
		if ferr != nil {
			a.Freshness = fresh
			return ferr // already coded ExitStale
		}
		a.Freshness = fresh
		a.RunlogVerified = true
		return nil
	}
	// Keyless: parse the log and confirm the run is present. The signature is not checked,
	// so RunlogVerified stays false (the log is structurally intact but not anchored).
	entries, perr := ParseRunlog(runlogBytes)
	if perr != nil {
		a.Freshness = uncheckedFreshness(perr)
		return staleUnchecked(perr)
	}
	if len(entries) == 0 {
		empty := fmt.Errorf("runlog is empty")
		a.Freshness = uncheckedFreshness(empty)
		return staleUnchecked(empty)
	}
	present := false
	var runlogMax int64
	for i := range entries {
		if entries[i].RunID == runID {
			present = true
		}
		if entries[i].Index > runlogMax {
			runlogMax = entries[i].Index
		}
	}
	if !present {
		absent := fmt.Errorf("run %s is absent from the runlog", runID)
		a.Freshness = uncheckedFreshness(absent)
		return staleUnchecked(absent)
	}
	a.Freshness.RunlogMaxIndex = runlogMax
	if minIndex > 0 && runlogMax < minIndex {
		// A check that RAN keyless and found a below-pin index: a finding, not an unknown, so
		// it takes RollbackWarning and its own reason and never Unchecked.
		below := fmt.Errorf("runlog max index %d is below the pinned minimum %d (possible rollback; UNAUTHENTICATED without --signer, so this catches an accidentally stale or wholesale-replayed bucket but not a targeted adversary who also edits the unsigned RUNLOG's stated index)", runlogMax, minIndex)
		a.Freshness.RollbackWarning = true
		a.Freshness.Reason = below.Error()
		return coded(ExitStale, below)
	}
	return nil
}
