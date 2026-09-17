package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// cmdAttest runs a keyless attestation over a run: it verifies the root signature, the
// structural completeness of the signed root (shard hashes and shard count) and the
// RUNLOG, WITHOUT the break-glass identity, and prints the outcome. It never unwraps the
// master capsule, opens a shard or decrypts a record, so it needs no --identity and
// materialises no plaintext. A signer is optional: with --signer the signatures are
// cryptographically verified against the operator-pinned signer, and --min-runlog-index
// is honoured as a full anti-rollback pin exactly as verify/restore's; without a signer
// the attestation is fully keyless and reports the signature as "unchecked" while still
// catching a tampered shard, a missing shard or a malformed/absent signature, and, only
// when --min-runlog-index is also given, a RUNLOG whose own claimed index falls below the
// pin — a structural self-consistency check, not a cryptographic one (see
// format.Attest's doc comment). Without --min-runlog-index a keyless attest checks only
// that the run is present in the RUNLOG, never its freshness: a rolled-back RUNLOG that
// still lists the run passes.
func cmdAttest(args []string) error {
	fs := flag.NewFlagSet("attest", flag.ContinueOnError)
	sf := addStoreFlags(fs)
	run := fs.String("run", "", "run id")
	signerPath := fs.String("signer", "", "operator signer public-key file (optional; without it the attestation is keyless)")
	minIndex := fs.Int64("min-runlog-index", 0, "reject a RUNLOG whose maximum index is below this pin; with --signer this is a full cryptographic anti-rollback check (as in verify/restore), without it a structural, unauthenticated one (see --help)")
	ackNoPin := fs.Bool("acknowledge-no-rollback-pin", false, "silence the missing --min-runlog-index warning when --signer is set; rollback protection stays off either way (for a genuine first recovery, before a recovery sheet entry exists)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *run == "" {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("attest needs --run and a source (--archive or --s3-endpoint). To see which runs a source holds, run: downpipe keys --which --archive <dir>")}
	}
	if _, err := spec.DecodeULID(*run); err != nil {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("--run: %w", err)}
	}
	store, err := sf.resolve()
	if err != nil {
		return err
	}
	// The signer is optional: attest never needs the break-glass identity, and it can run
	// with no key at all. When --signer is supplied the signatures are cryptographically
	// verified; otherwise the attestation is keyless.
	var verifier *crypto.HybridVerifier
	if *signerPath != "" {
		signerBytes, rerr := readKeyFile(*signerPath, labelSignerPublic)
		if rerr != nil {
			return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("signer: %w", rerr)}
		}
		verifier, err = crypto.ParseVerifier(signerBytes)
		if err != nil {
			return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("signer: %w", err)}
		}
	}
	// The no-pin nag mirrors verify/restore's warnIfNoRollbackPin, but only when a signer
	// is pinned: that is the only case where the RUNLOG signature is actually checked, so
	// it is the only case where the reminder's wording ("the reader still checks the
	// RUNLOG signature...") is true. A plain keyless attest with no pin at all is the
	// baseline documented behaviour (presence only), not a lapsed protection to nag about.
	if verifier != nil {
		warnIfNoRollbackPin(*minIndex, *ackNoPin)
	}

	res, attestErr := format.Attest(store, *run, verifier, *minIndex)
	if res != nil {
		reportAttest(res, *minIndex)
	}
	if attestErr != nil {
		var ee *format.ExitError
		if errors.As(attestErr, &ee) {
			return attestErr
		}
		return &format.ExitError{Code: format.ExitUnverified, Err: attestErr}
	}
	return nil
}

// reportAttest prints the keyless attestation outcome to stderr (so stdout stays clean):
// the run, the signature verdict, the structural shard-hash completeness, the RUNLOG
// freshness, and the signed declared record count. Every line is a label or a count; no
// plaintext is printed. When minIndex was pinned, the freshness line also says whether
// that pin was honoured cryptographically (a signer was pinned) or only structurally
// (keyless: the RUNLOG's plaintext index, unauthenticated), so the printed report never
// lets a structural pass read like a cryptographic one.
func reportAttest(res *format.AttestResult, minIndex int64) {
	label := "attested"
	if !res.OK() {
		label = "UNATTESTED"
	}
	mode := "keyless"
	if res.SignerPinned {
		mode = "signer-pinned"
	}
	fmt.Fprintf(os.Stderr, "%s: run %s (%s)\n", label, res.RunID, mode)
	fmt.Fprintf(os.Stderr, "  signature:   %s (present=%v)\n", res.SignatureResult, res.SignaturePresent)
	fmt.Fprintf(os.Stderr, "  shards:      %d shard(s), hash-verified=%v\n", res.ShardCount, res.ShardsHashVerified)
	fmt.Fprintf(os.Stderr, "  recipients:  break-glass set verified=%v\n", res.RecipientSetVerified)
	// Keyless, RunlogVerified and IsLatestForDownpipe are false by construction (see
	// internal/format/attest.go: judging either needs the signed root cross-check this mode
	// does not attempt), and a RUNLOG check that genuinely FAILS keyless returns an error and
	// makes the whole attestation UNATTESTED. So on a passing keyless attest those two fields
	// were printing a pair of constants that said nothing about the archive, in the one word
	// an operator mid-recovery reads as a failure. Someone looking at their only surviving
	// backup would see "runlog: verified=false, latest-for-downpipe=false" and conclude the
	// freshness anchor was broken and the run superseded, when neither had been examined.
	//
	// The signature line directly above already draws this distinction correctly, printing
	// "unchecked" rather than "invalid" when there is no signer. This applies the same rule
	// one line down. max-index still prints, because the RUNLOG's own stated index is read
	// keyless and is a real observation, unlike the two verdicts.
	//
	// AND BOTH LINES BELOW DESCRIBE A CHECK THAT RAN. reportAttest is called on the failure
	// path too, which is the whole point of printing a report under an UNATTESTED label, and
	// the keyless line then asserted "present and parsed, listing this run" about a RUNLOG
	// that may not exist. Driven: a keyless attest on an archive with _RECOVERY/RUNLOG
	// DELETED printed exactly that, three claims about an absent object, above an error line
	// naming the absence. The signer-pinned line is the same fault in the other direction,
	// printing verified=false and latest-for-downpipe=false as though they had been measured.
	//
	// AttestResult.Freshness.Unchecked has been set at every one of those returns since the
	// bare-zero-value fix, and nothing read it: the field existed, the report was wrong
	// anyway, and a field no caller consults cannot stop anything. This is the caller.
	switch {
	case res.Freshness.Unchecked:
		fmt.Fprintf(os.Stderr, "  runlog:      the freshness check COULD NOT BE RUN: %s. Nothing was established about this run's recency, and the verdicts this line carries otherwise were not measured\n", freshnessReason(res.Freshness))
	case res.SignerPinned:
		fmt.Fprintf(os.Stderr, "  runlog:      verified=%v, latest-for-downpipe=%v, max-index=%d\n", res.RunlogVerified, res.Freshness.IsLatestForDownpipe, res.Freshness.RunlogMaxIndex)
	default:
		fmt.Fprintf(os.Stderr, "  runlog:      present and parsed, listing this run; signature and freshness unchecked (no --signer), max-index=%d\n", res.Freshness.RunlogMaxIndex)
	}
	if minIndex > 0 {
		anchor := "cryptographically anchored (--signer verified the RUNLOG)"
		if !res.SignerPinned {
			anchor = "UNAUTHENTICATED (no --signer: the RUNLOG's plaintext index only)"
		}
		fmt.Fprintf(os.Stderr, "  min-index:   pinned=%d, %s\n", minIndex, anchor)
	}
	fmt.Fprintf(os.Stderr, "  records:     %d declared (record-level completeness needs the identity; run verify/restore)\n", res.DeclaredRecordCount)
}
