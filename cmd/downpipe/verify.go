package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/restore"
)

func cmdVerify(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	sf := addStoreFlags(fs)
	run := fs.String("run", "", "run id")
	idf := addIdentityFlags(fs, "break-glass identity file")
	signerPath := fs.String("signer", "", "operator signer public-key file")
	allowStale := fs.Bool("allow-stale", false, allowStaleUsage)
	allowUnverifiedRunlog := fs.Bool("allow-unverified-runlog", false, allowUnverifiedRunlogUsage)
	allowUnverified := fs.Bool("allow-unverified", false, "proceed despite a missing/invalid signature, recording the true outcome")
	minIndex := fs.Int64("min-runlog-index", 0, "reject a RUNLOG whose maximum index is below this pin")
	ackNoPin := fs.Bool("acknowledge-no-rollback-pin", false, "silence the missing --min-runlog-index warning; rollback protection stays off, this only suppresses the reminder (for a genuine first recovery, before a recovery sheet entry exists)")
	checkBundle := fs.Bool("check-bundle", false, "verify the in-bucket recovery bundle (FORMAT.md/RECOVER.md) against its signed SHA384SUMS")
	deep := fs.Bool("deep", false, "also decrypt and hash-verify every record's segment bytes (the full restore path, writing nothing); without it verify checks the signed manifests only, not the seg/ data objects")
	fetchConcurrency := fs.Int("fetch-concurrency", 1, "parallel shard prefetch window; 1 = strict sequential bounded-memory")
	receipt := fs.String("receipt", "", "write a signed restore receipt to this path (- for stderr)")
	receiptSigner := fs.String("receipt-signer", "", "sign the receipt with this signer private-key file")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *run == "" || !idf.supplied() || *signerPath == "" {
		return missingReaderInputs("verify", *run, idf.supplied(), *signerPath, sf.supplied())
	}
	if err := checkReceiptSigner(*receiptSigner); err != nil {
		return err
	}
	store, err := sf.resolve()
	if err != nil {
		return err
	}
	identity, verifier, err := idf.loadAndVerifier(*signerPath)
	if err != nil {
		return err
	}
	warnIfNoRollbackPin(*minIndex, *ackNoPin)
	started := nowStamp()
	// The streaming reader runs the identical verification contract as the load-all Open
	// (shared gate helpers; the conformance corpus replays every vector through both), but
	// holds at most one shard's records plus the Merkle frontier, so verifying a very large
	// archive is bounded by its largest shard, not its record count.
	r, err := format.StreamOpenContext(ctx, store, *run, identity, verifier, format.Options{MinRunlogIndex: *minIndex, AllowStale: *allowStale, AllowUnverifiedRunlog: *allowUnverifiedRunlog, AllowUnverified: *allowUnverified, FetchConcurrency: *fetchConcurrency})
	if err != nil {
		return err
	}
	defer r.Close() // wipe the run master when this command is done with it
	bundleOK, err := checkRecoveryBundle(*checkBundle, *allowUnverified, store, verifier)
	if err != nil {
		return err
	}

	out := r.Outcome()
	code := out.Code
	// A bundle failure with everything else sound is its OWN reason, and the closing line has to
	// say so. It did not: the line read "unverified: signature=valid completeness=complete", two
	// good verdicts under an UNVERIFIED label, with nothing naming what actually failed.
	bundleIsTheReason := false
	if *checkBundle && !bundleOK && code == 0 {
		code = format.ExitUnverified
		bundleIsTheReason = true
	}

	// Deep verify runs the same decrypt-and-discard path as `restore --sink discard`: it
	// reassembles every record, AEAD-tag verifies every chunk and checks the per-record
	// plaintext SHA-384, then writes nothing (the discard target streams, so a value larger
	// than memory is verified in bounded memory). A shallow verify reads only the signed
	// root, the shard manifests and the RUNLOG; it never reads a seg/ data object, so a
	// flipped ciphertext byte passes it. Deep verify closes that gap on demand.
	// The apply pass re-walks the shards, so each manifest is fetched twice and a shard
	// mutated between the passes fails its signed hash rather than being trusted.
	var deepResult *restore.Result
	if *deep {
		target := restore.NewDiscardTarget()
		plan, result, derr := restore.ApplyStreaming(r, target, true)
		if derr != nil {
			return derr
		}
		deepResult = result
		reportDiscard(target, plan, result)
		if !result.OK() {
			deepCode := perRecordExit(result)
			// The running maximum stays the rule for the integrity codes, which really are
			// ordered by severity. ExitDangling is not in that order (it is 13 and it is
			// milder than 2), so it is taken only when the run itself reached no verdict of
			// its own. A signature failure and an absent segment in the same pass exits on
			// the signature.
			if code == 0 || (deepCode != format.ExitDangling && deepCode > code) {
				code = deepCode
			}
		}
	}

	emitVerifySummary(*run, r.RecordCount(), out, *deep, deepResult, code, bundleVerdict(*checkBundle, bundleOK))
	warnIfRollbackOverridden(r.Freshness())

	if err := emitVerifyReceipt(r, verifier, started, *deep, deepResult, code, *minIndex, bundleOK, *receipt, *receiptSigner); err != nil {
		return err
	}
	if code != 0 {
		// Report the completeness the run actually established, not the shallow structural one.
		// out.Completeness is the manifests-only verdict, and on a deep verify of a tampered
		// archive it stays "complete" while the drill that just ran found every record failing.
		// The final line printed then read "unverified: signature=valid completeness=complete"
		// directly under a summary line reading "completeness=UNVERIFIED", two adjacent lines
		// contradicting each other on the same field name. The exit code was right in both
		// cases; only the sentence an operator reads last was wrong.
		if bundleIsTheReason {
			return &format.ExitError{Code: code, Err: fmt.Errorf("unverified: the run itself checks out (signature=%s completeness=%s) and the RECOVERY BUNDLE does not match its signed SHA384SUMS, so the in-bucket FORMAT.md or RECOVER.md has been altered since it was written. Do not follow the instructions in the bucket; use a copy of the reader and the guide you already trust", out.SignatureResult, reportedCompleteness(out, *deep, deepResult, r.RecordCount()))}
		}
		// The last line an operator reads is the one they act on, so it carries the same
		// word as the summary above it. "unverified" is this tool's tamper word, and an
		// archive that is merely missing an object has not been found unverified by
		// anything. tagAbsentObject puts fs.ErrNotExist on the chain so the absent-object
		// hint fires for a per-record segment read as it already did for a top-level one.
		return &format.ExitError{Code: code, Err: tagAbsentObject(deepResult, fmt.Errorf("%s: signature=%s completeness=%s", verdictWord(code), out.SignatureResult, reportedCompleteness(out, *deep, deepResult, r.RecordCount())))}
	}
	// A deep drill that decrypted every record cleanly but found incompleteness markers exits the
	// distinct advisory code (kept below the hard-failure codes; a real integrity failure returned
	// above), so a scheduled `verify --deep` restore-test flags a run whose source was partially
	// unavailable at backup time instead of reporting a clean exit 0. reportDiscard already printed
	// the warnings, and the summary/receipt keep the true verification verdict (the run IS
	// verified; only its content is partial).
	if *deep && deepResult != nil && deepResult.IncompleteMarkers > 0 {
		return &format.ExitError{Code: format.ExitIncompleteMarkers, Err: fmt.Errorf("verified, but %d of %d record(s) are incompleteness markers (the source was partially unavailable at backup time), NOT real data", deepResult.IncompleteMarkers, deepResult.Restored)}
	}
	return nil
}

// emitVerifySummary prints the one-line verify verdict to stderr. The shallow line is
// honest about its scope: it never claims `completeness=complete`, because verify reads the
// signed manifests only and never decrypts a seg/ data object, so it prints
// `structure=<...> (manifests only: segment bytes NOT decrypted; run 'verify --deep' or
// 'restore --sink discard')`. The deep line reports the decrypt-and-verify outcome, because
// deep verify did read and authenticate every segment.
// bundleVerdict is the word the summary line uses for the recovery bundle.
//
// It used to be the raw bool, printed as `bundle=%v`. bundleOK is only ever true when
// --check-bundle was given AND the check passed, so a perfectly clean archive verified without
// --check-bundle (the default, and the common case) ended its verdict line with `bundle=false`,
// sitting beside `signature=valid` and `structure=complete`. Those two are verdicts, so the third
// reads as one, and at the moment an operator is deciding whether their archive is sound it says
// the signed recovery bundle failed. It had not been looked at. NOT CHECKED and CHECKED AND BAD
// are opposite facts and must not share a word. The receipt's RecoveryBundleVerified field keeps
// the bool, where false correctly means "not established".
func bundleVerdict(checked, ok bool) string {
	switch {
	case !checked:
		return "not-checked (pass --check-bundle to verify the in-bucket FORMAT.md and RECOVER.md against their signed SHA384SUMS)"
	case ok:
		return "verified"
	default:
		return "FAILED"
	}
}

func emitVerifySummary(run string, n int64, out format.Outcome, deep bool, deepResult *restore.Result, code int, bundle string) {
	label := verdictLabel(code)
	if !deep {
		fmt.Fprintf(os.Stderr, "%s: run %s, %d record(s); signature=%s structure=%s (manifests only: segment bytes NOT decrypted; run 'verify --deep' or 'restore --sink discard') bundle=%s\n",
			label, run, n, out.SignatureResult, out.Completeness, bundle)
		return
	}
	fmt.Fprintf(os.Stderr, "%s: run %s, %d record(s); signature=%s completeness=%s bundle=%s\n",
		label, run, n, out.SignatureResult, reportedCompleteness(out, deep, deepResult, n), bundle)
}

// verdictWord is the verdict this exit status carries, in the running prose of the closing
// line. It exists because "unverified" is this tool's tamper word and it was being printed
// over a run in which nothing failed a check: every record whose segment object was simply
// absent from the archive was announced as unverified, twice, on the way to exit 2.
//
// The word is a function of the CODE and not of the outcome fields, so a status and the
// sentence beside it cannot describe different runs.
func verdictWord(code int) string {
	if code == format.ExitDangling {
		return "incomplete"
	}
	return "unverified"
}

// verdictLabel is the same verdict as the banner the summary line leads with. It is derived
// from verdictWord rather than written out again, so the banner and the closing line can
// never come to disagree about one run: the banner is that word, shouted, and the only case
// it does not cover is exit 0, which has no failure word at all.
func verdictLabel(code int) string {
	if code == 0 {
		return "verified"
	}
	return strings.ToUpper(verdictWord(code))
}

// reportedCompleteness is the single completeness phrase both the summary line and the
// closing error line use, so the two can never again disagree about the same run. Shallow
// verify reports the structural outcome it actually established; deep verify reports the
// decrypt-and-verify outcome, because that is the stronger check it ran. It is stated once
// rather than computed at each print site: the two sites previously derived it separately
// and a deep verify of a tampered archive printed "completeness=UNVERIFIED" on one line
// and "completeness=complete" on the next.
func reportedCompleteness(out format.Outcome, deep bool, deepResult *restore.Result, n int64) string {
	if !deep || deepResult == nil {
		return out.Completeness
	}
	// An absent segment failed no check, so it is never counted as one. The count of
	// OBJECTS is stated beside the count of records because they differ whenever records
	// share a segment by content address, and the object count is what the operator has to
	// go and fetch from another copy.
	if deepResult.DanglingOnly() {
		return fmt.Sprintf("incomplete (%d of %d record(s) could not be read: %d segment object(s) the signed manifests name are not in this archive. No signature, tag or hash failed)",
			len(deepResult.Failed), n, deepResult.DanglingSegments())
	}
	if !deepResult.OK() {
		return fmt.Sprintf("UNVERIFIED (%d of %d record(s) failed integrity)", len(deepResult.Failed), n)
	}
	return fmt.Sprintf("complete (%d record(s) decrypted+verified)", deepResult.Restored)
}

// receiptCompleteness maps a decrypt-and-verify pass (a deep verify, or a restore's apply)
// onto the SPEC.md 8.5 completeness enum for the SIGNED receipt.
//
// The enum is closed: "complete", "UNVERIFIED", "incomplete". The printed summary adds
// counts in brackets, which is right for a line a human reads and wrong for a field a
// machine parses against a schema, so the two are computed separately from the same result
// rather than one being derived by trimming the other.
//
// A pass that decrypted every record and matched every hash is complete. A pass with any
// failed record is UNVERIFIED, and that is the case the receipt used to get wrong: the
// reader's own Outcome.Completeness is computed from the signed manifests, which were
// intact, so it said "complete" over a run where nothing decrypted.
// A pass whose every failure was an absent segment object is "incomplete", the third member
// of that enum, and not "UNVERIFIED": the manifests verified, the bytes that were retrieved
// all checked out, and the archive is short of objects its manifests name. The receipt's
// danglingSegments count already said so beside a completeness of "UNVERIFIED", so the enum
// value now agrees with the count sitting next to it.
func receiptCompleteness(res *restore.Result) string {
	if res == nil {
		return ""
	}
	if res.DanglingOnly() {
		return "incomplete"
	}
	if !res.OK() {
		return "UNVERIFIED"
	}
	return "complete"
}

// emitVerifyReceipt assembles and emits the signed verify receipt. A shallow verify records
// target type "verify" with valueVerified false (no value was decrypted); a deep verify
// records target type "discard" with the verified record count and valueVerified true only
// when every record decrypted and hash-checked, so the receipt never launders a deep run
// that found a tampered segment as value-verified.
func emitVerifyReceipt(r format.ReceiptSource, verifier *crypto.HybridVerifier, started string, deep bool, deepResult *restore.Result, code int, minIndex int64, bundleOK bool, receiptPath, receiptSigner string) error {
	in := format.ReceiptInput{
		StartedAt: started, FinishedAt: nowStamp(),
		SignerExpected:         crypto.SignerFingerprint(verifier),
		TargetType:             "verify",
		Restored:               0,
		ExitCode:               code,
		MinIndexPinned:         minIndex,
		RecoveryBundleVerified: bundleOK,
	}
	valueVerified := false
	if deep {
		in.TargetType = "discard"
		in.Restored = int64(deepResult.Restored)
		valueVerified = deepResult.OK()
		// A deep verify decrypts every record, so it detects incompleteness markers exactly as a restore
		// does. Carry the same ADDITIVE marker signal in the signed verify receipt (omitempty, so it is
		// absent and the bytes stay byte-identical on a clean run); ExitCode still carries the verification
		// outcome. The tally is by marker kind (a fixed sentinel label), never a record name or value.
		in.IncompleteMarkers = int64(deepResult.IncompleteMarkers)
		in.IncompleteMarkerKinds = markerKindTally(deepResult.Markers)
		// A deep verify opens every seg/ object the run's manifests name, so it is the pass
		// that can answer SPEC.md 10.1's dangling-reference question, and a 0 from here means
		// it looked and found none. A SHALLOW verify reads manifests only and never touches a
		// seg/ object, so it leaves this nil and the receipt omits the field rather than
		// signing a zero about segments nothing fetched.
		dangling := deepResult.DanglingSegments()
		in.DanglingSegments = &dangling
		// The receipt's completeness must be the verdict THIS pass reached, not the
		// manifests-only one. Outcome.Completeness stayed "complete" on a deep verify in
		// which every record failed its hash check, so the printed line said
		// "completeness=UNVERIFIED (1 of 1 record(s) failed integrity)" while the SIGNED
		// receipt beside it said "completeness": "complete". Only the enum value goes in the
		// receipt (SPEC.md 8.5); the counts belong to the printed line.
		in.Completeness = receiptCompleteness(deepResult)
	}
	return emitReceipt(r, in, valueVerified, receiptPath, receiptSigner)
}
