package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/restore"
)

// restoreFlags holds the parsed restore command flags, separating flag definition from
// the restore orchestration so cmdRestore stays short.
type restoreFlags struct {
	store      storeFlags
	run        string
	identity   *identityFlags
	signerPath string
	out        string
	sinkKind   string
	apply      bool
	allowStale bool
	// allowUnverifiedRunlog is the separate, stronger acknowledgement for a RUNLOG that
	// could not be verified or read, or that verified and contradicts itself. allowStale
	// is an age word and no longer reaches those; see format.Options.
	allowUnverifiedRunlog bool
	allowUnverified       bool
	minIndex              int64
	ackNoPin              bool
	checkBundle           bool
	receipt               string
	receiptSigner         string
	fetchConcurrency      int
	maxMemory             int64
}

// parseRestoreFlags defines and parses the restore flags and validates the required ones,
// returning a usage error for a missing required flag.
func parseRestoreFlags(args []string) (restoreFlags, error) {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	sf := addStoreFlags(fs)
	run := fs.String("run", "", "run id")
	idf := addIdentityFlags(fs, "break-glass identity file")
	signerPath := fs.String("signer", "", "operator signer public-key file")
	out := fs.String("out", "", "directory to restore record values into (with --sink file)")
	sinkKind := fs.String("sink", "file", "restore target: file, env or discard")
	apply := fs.Bool("apply", false, "write to the target; without it the restore is a dry run that plans only")
	allowStale := fs.Bool("allow-stale", false, allowStaleUsage)
	allowUnverifiedRunlog := fs.Bool("allow-unverified-runlog", false, allowUnverifiedRunlogUsage)
	allowUnverified := fs.Bool("allow-unverified", false, "proceed despite a missing/invalid signature, recording the true outcome")
	minIndex := fs.Int64("min-runlog-index", 0, "reject a RUNLOG whose maximum index is below this pin")
	ackNoPin := fs.Bool("acknowledge-no-rollback-pin", false, "silence the missing --min-runlog-index warning; rollback protection stays off, this only suppresses the reminder (for a genuine first recovery, before a recovery sheet entry exists)")
	checkBundle := fs.Bool("check-bundle", false, "verify the in-bucket recovery bundle (FORMAT.md/RECOVER.md) against its signed SHA384SUMS")
	receipt := fs.String("receipt", "", "write a signed restore receipt to this path (- for stderr)")
	receiptSigner := fs.String("receipt-signer", "", "sign the receipt with this signer private-key file")
	fetchConcurrency := fs.Int("fetch-concurrency", 1, "parallel shard prefetch window; 1 = strict sequential bounded-memory")
	maxMemory := fs.String("max-memory", "0", "cap bytes held in the prefetch buffer (accepts e.g. 512MiB, 1GiB or plain bytes); 0 honours GOMEMLIMIT")
	if err := parseFlags(fs, args); err != nil {
		return restoreFlags{}, err
	}
	if *run == "" || !idf.supplied() || *signerPath == "" {
		return restoreFlags{}, missingReaderInputs("restore", *run, idf.supplied(), *signerPath, sf.supplied())
	}
	if *sinkKind == "file" && *out == "" {
		return restoreFlags{}, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("restore --sink file needs --out <dir>")}
	}
	if err := checkReceiptSigner(*receiptSigner); err != nil {
		return restoreFlags{}, err
	}
	maxMem, err := parseHumanBytes(*maxMemory)
	if err != nil {
		return restoreFlags{}, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("--max-memory: %w", err)}
	}
	return restoreFlags{
		store: sf, run: *run, identity: idf, signerPath: *signerPath, out: *out,
		sinkKind: *sinkKind, apply: *apply, allowStale: *allowStale,
		allowUnverifiedRunlog: *allowUnverifiedRunlog, allowUnverified: *allowUnverified,
		minIndex: *minIndex, ackNoPin: *ackNoPin, checkBundle: *checkBundle, receipt: *receipt, receiptSigner: *receiptSigner,
		fetchConcurrency: *fetchConcurrency, maxMemory: maxMem,
	}, nil
}

// parseHumanBytes parses a byte size as either a plain integer ("536870912") or an integer
// with a binary (KiB/MiB/GiB/TiB, or a bare K/M/G/T) or decimal (KB/MB/GB/TB) unit suffix,
// so an operator can cap --max-memory as "512MiB" rather than counting bytes. An empty
// string or "0" is no cap (0). It rejects a negative or unit-less-garbage input as a usage
// error rather than silently flooring to 0.
func parseHumanBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, fmt.Errorf("invalid size %q: expected a number, optionally with a unit like MiB or GB", s)
	}
	n, err := strconv.ParseInt(s[:i], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", s, err)
	}
	var mult int64
	switch strings.ToLower(strings.TrimSpace(s[i:])) {
	case "", "b":
		mult = 1
	case "k", "kib":
		mult = 1 << 10
	case "kb":
		mult = 1000
	case "m", "mib":
		mult = 1 << 20
	case "mb":
		mult = 1000 * 1000
	case "g", "gib":
		mult = 1 << 30
	case "gb":
		mult = 1000 * 1000 * 1000
	case "t", "tib":
		mult = 1 << 40
	case "tb":
		mult = 1000 * 1000 * 1000 * 1000
	default:
		return 0, fmt.Errorf("invalid size unit in %q (want B, KiB/KB, MiB/MB, GiB/GB or TiB/TB)", s)
	}
	if mult > 1 && n > (int64(1)<<62)/mult {
		return 0, fmt.Errorf("size %q overflows int64", s)
	}
	return n * mult, nil
}

func cmdRestore(ctx context.Context, args []string) error {
	f, err := parseRestoreFlags(args)
	if err != nil {
		return err
	}
	// Validate the sink kind eagerly (before any I/O) so a typo in --sink is a
	// usage error and not a late failure after opening the archive.
	target, err := newRestoreTarget(f.sinkKind, f.out)
	if err != nil {
		return err
	}
	store, err := f.store.resolve()
	if err != nil {
		return err
	}
	identity, verifier, err := f.identity.loadAndVerifier(f.signerPath)
	if err != nil {
		return err
	}
	warnIfNoRollbackPin(f.minIndex, f.ackNoPin)
	started := nowStamp()
	// Streaming, bounded-memory restore: StreamOpen verifies the run (signature, structure,
	// completeness and the Merkle root, recomputed incrementally and byte-identical to the
	// load-all root) without holding every record in RAM, and ApplyStreaming restores it one
	// record at a time. The load-all format.Open + restore.Apply held the record metadata
	// twice and OOM'd a large archive on a commodity DR box; this path is bounded by the shard
	// size and the no-clobber key set, not the record count.
	r, err := format.StreamOpenContext(ctx, store, f.run, identity, verifier, format.Options{MinRunlogIndex: f.minIndex, AllowStale: f.allowStale, AllowUnverifiedRunlog: f.allowUnverifiedRunlog, AllowUnverified: f.allowUnverified, FetchConcurrency: f.fetchConcurrency, MaxMemoryBytes: f.maxMemory})
	if err != nil {
		return err
	}
	defer r.Close() // wipe the run master when this command is done with it
	warnIfRollbackOverridden(r.Freshness())

	bundleOK, err := checkRecoveryBundle(f.checkBundle, f.allowUnverified, store, verifier)
	if err != nil {
		return err
	}

	// The discard sink is a restorability check, not a write: it decrypts and verifies
	// every record through the full restore path and writes nothing. Decryption only
	// happens on an apply (a dry run plans without opening a value), so the discard sink
	// always applies, regardless of --apply, and there is no plaintext to materialise.
	effectiveApply := f.apply || target.Kind() == "discard"

	// Dry run by default: plan only, write nothing. --apply opts in to writing.
	plan, result, err := restore.ApplyStreaming(r, target, effectiveApply)
	if err != nil {
		return err
	}
	reportRestoreOutcome(target, plan, result, effectiveApply)

	out2 := r.Outcome()
	code := out2.Code
	if f.checkBundle && !bundleOK && code == 0 {
		code = format.ExitUnverified
	}

	if err := emitRestoreReceipt(r, result, target, verifier, started, code, bundleOK, f.minIndex, f.receipt, f.receiptSigner); err != nil {
		return err
	}

	if code != 0 {
		return &format.ExitError{Code: code, Err: fmt.Errorf("restored but unverified: signature=%s completeness=%s", out2.SignatureResult, out2.Completeness)}
	}
	// A per-record failure during apply is reported honestly and exits non-zero so a
	// partial restore (or a discard-sink verification with a record that did not decrypt)
	// is never presented as a success. Propagate the maximum per-record coded exit (SPEC.md
	// 8.5: a plaintext-hash mismatch is exit 4, an AEAD/structural failure exit 2) instead
	// of flattening every failure to a generic exit 1: the swallowed code previously made a
	// `restore --sink discard` integrity drill exit 1 regardless of why a record failed
	// A failure that carried no coded exit (an uncoded I/O error such as a
	// missing segment object) keeps the historical generic exit 1.
	if effectiveApply && !result.OK() {
		// Carry fs.ErrNotExist through the aggregate when any record failed because its object
		// was not there at all. The wrapped sentinel is what lets the command boundary tell an
		// incomplete download apart from a tamper finding, and it is what the absent-object
		// hint reads. A partially-downloaded archive is the example the exit-code table itself
		// gives, so this is the case most likely to reach an operator mid-recovery.
		//
		// The count sentence is no longer the same either way. "failed to restore" is true of
		// both, and on its own it left the two states sharing every word a script or a reader
		// could see, so the dangling case now names what is missing and says that nothing
		// failed a check.
		aggregate := fmt.Errorf("%d of %d planned record(s) failed to restore", len(result.Failed), plan.WriteCount)
		if result.DanglingOnly() {
			aggregate = fmt.Errorf("%d of %d planned record(s) could not be restored from this archive: %d segment object(s) the signed manifests name are not here. No signature, tag or hash failed",
				len(result.Failed), plan.WriteCount, result.DanglingSegments())
		}
		return &format.ExitError{Code: perRecordExit(result), Err: tagAbsentObject(result, aggregate)}
	}
	// Records the target could not take are an advisory too, and for a stronger reason than the
	// markers below: those records are in the archive and are not on disk. reportRestoreOutcome
	// has already printed the count and each conflict, but a summary line on stderr is not what a
	// DR script reads, and exiting 0 here contradicted the rule the rest of this function keeps.
	if effectiveApply && result.SkippedConflicts > 0 {
		return &format.ExitError{Code: format.ExitUnwritten, Err: fmt.Errorf("restored %d record(s), but %d were NOT written: the target could not take them (see the conflicts above)", result.Restored, result.SkippedConflicts)}
	}
	// A restore that verified and wrote every record but contains one or more incompleteness
	// markers is a LOUD ADVISORY, not a failure: the records genuinely restored, but their value
	// is a sentinel placeholder the engine wrote when the source was only partially available at
	// backup time. Exit a DISTINCT advisory code (kept separate from and below the hard-failure
	// codes above) so a DR script can tell "succeeded, but some values are placeholders" apart
	// from "corrupt/failed", and never reads the exit-zero as a clean full restore.
	// reportRestoreOutcome already printed the per-record and summary warnings.
	if effectiveApply && result.IncompleteMarkers > 0 {
		return &format.ExitError{Code: format.ExitIncompleteMarkers, Err: fmt.Errorf("restored, but %d of %d record(s) are incompleteness markers (the source was partially unavailable at backup time), NOT real data", result.IncompleteMarkers, result.Restored)}
	}
	// A restore that verified and wrote every record, but wrote one this release cannot render
	// into SQL, is the last and mildest advisory: every byte landed intact, and only this
	// binary's ability to read the body is missing. It comes after the markers check because a
	// placeholder value is a gap in the DATA, while this is a gap in the READER, and a script
	// that can act on only one of them should be handed the data gap.
	//
	// It is here rather than at exit 0 because the alternative was a clean success alongside
	// guidance to feed the written file to sqlite3. reportUnrenderable has already named each
	// record, its file and the label that reads it.
	if effectiveApply && len(result.Unrenderable) > 0 {
		return &format.ExitError{Code: format.ExitUnrenderable, Err: fmt.Errorf("restored, but %d of %d record(s) carry a D1 body format this release cannot render; their verified bytes were written unchanged and are NOT SQL", len(result.Unrenderable), result.Restored)}
	}
	return nil
}

// reportRestoreOutcome prints the restore result: the discard sink prints its attestation
// (counts and a one-way digest only, never a plaintext value) to stderr so stdout stays
// clean; every other sink prints the plan/result summary.
func reportRestoreOutcome(target restore.Target, plan *restore.Plan, result *restore.Result, effectiveApply bool) {
	if dt, ok := target.(*restore.DiscardTarget); ok {
		reportDiscard(dt, plan, result)
		return
	}
	reportRestore(plan, result, effectiveApply)
}

// checkRecoveryBundle binds the in-bucket FORMAT.md and RECOVER.md to their signed
// SHA384SUMS (SPEC.md 8.7 item 4) when the recoverer relies on the bundled instructions.
// When check is false it is a no-op returning (false, nil). A verification failure is
// fatal unless allowUnverified downgrades it to a warning. It returns whether the bundle
// verified.
func checkRecoveryBundle(check, allowUnverified bool, store format.ObjectStore, verifier *crypto.HybridVerifier) (bool, error) {
	if !check {
		return false, nil
	}
	if err := format.VerifyBundle(store.Get, verifier); err != nil {
		if !allowUnverified {
			return false, &format.ExitError{Code: format.ExitUnverified, Err: fmt.Errorf("recovery bundle: %w", err)}
		}
		fmt.Fprintf(os.Stderr, "warning: recovery bundle check failed: %v\n", err)
		return false, nil
	}
	return true, nil
}

// emitRestoreReceipt assembles the signed restore receipt from the run outcome and emits
// it. It reports the restored record count only for a real apply (a dry run restored
// nothing) and carries the exit code, the min-index pin and whether the recovery bundle
// verified. It writes nothing sensitive: the receipt holds counts and fingerprints only.
func emitRestoreReceipt(r format.ReceiptSource, result *restore.Result, target restore.Target, verifier *crypto.HybridVerifier, started string, code int, bundleOK bool, minIndex int64, receiptPath, receiptSigner string) error {
	restored := int64(0)
	if !result.DryRun {
		restored = int64(result.Restored)
	}
	valueVerified := restoreValueVerified(result.DryRun, target.Kind())
	// An APPLIED restore reads every segment, so it can answer SPEC.md 10.1's
	// dangling-reference question and a 0 here means it looked. A dry run decrypts nothing,
	// so it leaves the field absent instead of signing a zero about segments it never
	// fetched: the same distinction the shallow verify makes.
	var dangling *int64
	completeness := ""
	if !result.DryRun {
		n := result.DanglingSegments()
		dangling = &n
		// Same rule as the deep verify: an applied restore decrypted every record, so the
		// receipt's completeness is the verdict THAT pass reached, not the manifests-only
		// one the reader computed before a byte was decrypted. A dry run decrypted nothing
		// and leaves the reader's verdict in place.
		completeness = receiptCompleteness(result)
	}
	// Surface the incompleteness-marker signal in the SIGNED receipt so a machine consumer can tell a
	// fully-real restore from one padded with marker stubs: a marker record restored and hash-verified, but
	// its value is a placeholder sentinel, NOT the source's live data (SPEC.md 12.1). This is ADDITIVE
	// metadata -- ExitCode still carries the verification outcome (0 = verified). Both fields are omitempty,
	// so a clean restore's receipt is byte-identical to a pre-marker one; the tally is by marker KIND (a
	// fixed sentinel label), never a record name or value, keeping the receipt's counts-only contract.
	return emitReceipt(r, format.ReceiptInput{
		StartedAt: started, FinishedAt: nowStamp(),
		SignerExpected:         crypto.SignerFingerprint(verifier),
		TargetType:             target.Kind(),
		Restored:               restored,
		ExitCode:               code,
		MinIndexPinned:         minIndex,
		RecoveryBundleVerified: bundleOK,
		IncompleteMarkers:      int64(result.IncompleteMarkers),
		IncompleteMarkerKinds:  markerKindTally(result.Markers),
		RecordsUnwritten:       int64(result.SkippedConflicts),
		UnwrittenKinds:         conflictKindTally(result.ConflictKinds),
		DanglingSegments:       dangling,
		Completeness:           completeness,
	}, valueVerified, receiptPath, receiptSigner)
}

// conflictKindTally converts the result's per-kind refusal tally into the receipt's string-keyed map.
// It returns nil for no refusals, so the receipt's omitempty keeps a clean restore's signed bytes
// byte-identical to one written before this field existed. Kinds only, never a record name.
func conflictKindTally(kinds map[restore.ConflictKind]int) map[string]int64 {
	if len(kinds) == 0 {
		return nil
	}
	out := make(map[string]int64, len(kinds))
	for k, n := range kinds {
		out[string(k)] = int64(n)
	}
	return out
}

// markerKindTally tallies restored incompleteness-marker records by kind for the receipt, e.g.
// {"_skipped":2,"_unavailable":1}. It returns nil for no markers, so the receipt's omitempty
// incompleteMarkerKinds field is absent on a clean restore and the signed bytes stay byte-identical. It
// carries only the marker KIND (a fixed, engine-authored sentinel label), never a record name, key or value.
func markerKindTally(markers []restore.RecordMarker) map[string]int64 {
	if len(markers) == 0 {
		return nil
	}
	tally := make(map[string]int64, len(markers))
	for _, m := range markers {
		tally[m.Kind]++
	}
	return tally
}

// absentObjectErr tags an aggregate failure whose cause was an object that was not there at
// all, so errors.Is finds fs.ErrNotExist on it while Error() prints only the aggregate's own
// sentence. A plain fmt.Errorf("%w: ...", fs.ErrNotExist) would have prefixed every such line
// with "file does not exist", which is both noise and, for a restore that failed on several
// records for one missing segment, a misleading singular.
type absentObjectErr struct{ error }

func (absentObjectErr) Unwrap() error { return fs.ErrNotExist }

// tagAbsentObject puts the absent-object sentinel on an aggregate error when any record of
// the pass failed because its object was not there at all, and returns err untouched
// otherwise.
//
// It is shared by restore and by verify --deep because the hint was firing for only one of
// them. restore wrapped its aggregate and got the hint; the deep drill built a bare
// ExitError, so the one read failure that matters most, a data segment gone from the bucket,
// reached the operator through the command whose whole purpose is to find it with no hint at
// all. AnyAbsentObject and not DanglingOnly: the hint is guidance rather than a verdict, and
// an operator holding one absent segment beside one failed tag still needs to be told that
// part of what they are looking at is a missing object.
func tagAbsentObject(res *restore.Result, err error) error {
	if res == nil || !res.AnyAbsentObject() {
		return err
	}
	return absentObjectErr{err}
}

// perRecordExit is the exit status a pass's per-record failures produce, stated once because
// restore and verify --deep both derive it and used to derive it separately.
//
// ExitDangling only when EVERY failure was an absent segment object. Otherwise the maximum
// per-record coded exit (SPEC.md 8.5: a plaintext mismatch is 4, an AEAD or structural
// failure 2), so a real integrity finding anywhere in the pass takes precedence over the
// milder verdict. A failure carrying no coded exit at all keeps the historical generic 1.
func perRecordExit(res *restore.Result) int {
	if res.DanglingOnly() {
		return format.ExitDangling
	}
	if res.IntegrityExit != 0 {
		return res.IntegrityExit
	}
	return exitUncoded
}

// reportDiscard prints the discard-sink attestation to stderr (so stdout stays clean):
// the records and bytes verified, the number of failures, and the restore digest over
// the verified plaintext stream. Every line is counts, a one-way hex digest, names and
// failure reasons only; no plaintext value is ever printed or logged.
func reportDiscard(dt *restore.DiscardTarget, plan *restore.Plan, result *restore.Result) {
	fmt.Fprintf(os.Stderr, "restorability attestation: verified %d record(s), %d byte(s); %d failed, %d conflict(s) skipped\n",
		dt.VerifiedRecords(), dt.VerifiedBytes(), len(result.Failed), result.SkippedConflicts)
	// The digest over zero verified records is the SHA-384 of the empty stream, a fixed
	// constant that looks exactly like a real digest on the terminal. An operator whose
	// runbook says "compare the restore digest" would otherwise carry that constant away
	// from a run that verified nothing, so the line says so rather than leaving the reader
	// to recognise 38b060a7... by sight.
	emptyNote := ""
	if dt.VerifiedRecords() == 0 {
		emptyNote = " (no record was verified, so this is the digest of an empty stream, not of your data)"
	}
	fmt.Fprintf(os.Stderr, "restore digest (sha384 over each record's key and plaintext hash): %s%s\n", dt.Digest(), emptyNote)
	for _, f := range result.Failed {
		fmt.Fprintf(os.Stderr, "  failed %q: %s\n", f.Name, f.Reason)
	}
	// The discard sink writes nothing, so its Write never hits the file-sink path collision and
	// never produces a reprovision-only record; the call is a no-op here, kept so both report
	// paths surface a reprovision-only outcome identically if one ever arises.
	reportReprovisionOnly(result)
	reportIncompleteMarkers(result)
	reportReprovision(plan)
	reportD1(plan)
	// The closing line is conditional on the outcome. It used to read "every record was
	// decrypted and verified" unconditionally, which printed that exact sentence three lines
	// below "1 failed" and one line above "UNVERIFIED" on a tampered archive. An operator
	// mid-recovery reads the last line of a report as its verdict, and this one told them the
	// opposite of what the run found. The "no plaintext was written" half is unconditional
	// and true either way, so it is kept in both branches: it is the discard sink's whole
	// safety property.
	//
	// The failure branch also states a CAUSE, and the cause was wrong for the case the
	// operator most needs to read correctly. "did NOT decrypt or did not match their signed
	// hash" was printed over records whose segment object was simply absent: nothing was
	// fetched, so nothing was offered to the decrypt or to the hash, and the sentence
	// accused the bytes of failing a check they were never put to.
	if len(result.Failed) > 0 {
		if result.DanglingOnly() {
			fmt.Fprintf(os.Stderr, "discard sink: %d record(s) could not be read at all because %d segment object(s) are absent from this archive (named above); nothing failed a check, and no plaintext was written.\n", len(result.Failed), result.DanglingSegments())
			return
		}
		fmt.Fprintf(os.Stderr, "discard sink: %d record(s) did NOT decrypt or did not match their signed hash (named above); no plaintext was written.\n", len(result.Failed))
		return
	}
	fmt.Fprintln(os.Stderr, "discard sink: every record was decrypted and verified; no plaintext was written.")
}

// reportReprovision prints the out-of-band re-provision guidance for any reprovision-type
// (workers, cf-config, stream, images, artifacts) records in the plan (SPEC.md 12.1). These
// records are decrypted and hash-verified like
// every other record, and on a file sink their verified bytes are written for the operator,
// but they are never a live re-apply: the operator re-provisions deliberately. The lines
// carry names, keys and guidance only, never a value.
func reportReprovision(plan *restore.Plan) {
	if plan == nil || len(plan.Reprovision) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "%d record(s) restore by re-provisioning, not a live re-apply:\n", len(plan.Reprovision))
	for _, rp := range plan.Reprovision {
		fmt.Fprintf(os.Stderr, "  reprovision [%s] %q -> %q: %s\n", rp.SourceType, rp.Name, rp.Key, rp.Guidance)
	}
}

// reportD1 prints the turnkey apply commands once when the plan writes any d1 record to a
// file sink as a .sql dump. A d1 record is a direct value write (not a reprovision), so its
// guidance is the exact two-command replay to a NEW database (D1ReplayGuidance), surfaced so
// the operator does not have to know to add .sql or guess the sqlite3/wrangler invocation.
// The line carries guidance text only, never a value.
func reportD1(plan *restore.Plan) {
	if plan == nil || !plan.HasD1File {
		return
	}
	fmt.Fprintf(os.Stderr, "d1 dump(s) planned as .sql: %s\n", restore.D1ReplayGuidance())
}

// reportD1Unrenderable prints, at PLAN time, the d1 records whose descriptor names a body
// format this release cannot render. It runs in a dry run as well as an apply, which is the
// point: an operator planning a recovery finds out before they commit to it, not from sqlite3
// afterwards. Each record is named with the label it carries, and none of them is planned to a
// .sql key, so the guidance above is not about them.
func reportD1Unrenderable(plan *restore.Plan, apply bool) {
	if plan == nil || len(plan.D1Unrenderable) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "d1 dump(s) this release cannot render: %s\n", restore.D1UnrenderableGuidance(len(plan.D1Unrenderable), apply))
	for _, u := range plan.D1Unrenderable {
		fmt.Fprintf(os.Stderr, "  unrenderable d1 format %q %q -> %q: written verbatim, NOT SQL; do not apply it with sqlite3\n", u.Format, u.Name, u.Key)
	}
}

// reportUnrenderable prints, after an apply, the d1 records whose verified bytes this release
// could not render. It is separate from reportD1Unrenderable and not a duplicate of it: that
// one reads the descriptor before anything is decrypted, this one reads the body that actually
// arrived, so a record whose writer stamped no descriptor, or stamped one that disagrees with
// its own bytes, is named here and nowhere else.
func reportUnrenderable(result *restore.Result) {
	if result == nil || len(result.Unrenderable) == 0 {
		return
	}
	for _, u := range result.Unrenderable {
		fmt.Fprintf(os.Stderr, "  WARNING unrenderable d1 format %q %q -> %q: the bytes are verified and were written unchanged, and they are NOT SQL; do not apply this file with sqlite3\n", u.Format, u.Name, u.Key)
	}
	fmt.Fprintf(os.Stderr, "WARNING: %d of %d restored record(s) carry a D1 body format this release cannot render. Nothing is corrupt and nothing was lost; use a downpipe release that reads the label named against each record.\n", len(result.Unrenderable), result.Restored)
}

// restoreValueVerified reports whether a restore apply produced a hash-verified value
// for each record handled by the target. The file, env and discard sinks go through
// RestoreRecord (SPEC.md 7.4, 8.3), which decrypts and checks plaintextSHA384, so the
// value is verified; the discard sink verifies the value and then writes nothing. A dry
// run handles no value, so nothing is verified. A secrets-store target is write-only at
// the management API, so value readback requires the engine (SPEC.md 12.6); that sink is
// not implemented in this binary.
func restoreValueVerified(dryRun bool, targetKind string) bool {
	return !dryRun && (targetKind == "file" || targetKind == "env" || targetKind == "discard")
}

// newRestoreTarget builds the offline restore target for the chosen sink. The file
// target writes one file per record under --out; the env target writes dotenv lines to
// stdout, treating the names already in the process environment as occupied so it does
// not redefine a set variable; the discard target verifies every record through the
// full restore path and writes nothing, for a restorability check that must never
// materialise plaintext.
func newRestoreTarget(sinkKind, out string) (restore.Target, error) {
	switch sinkKind {
	case "file":
		return restore.NewDirTarget(out), nil
	case "env":
		return restore.NewEnvTarget(os.Stdout, envNames()), nil
	case "discard":
		return restore.NewDiscardTarget(), nil
	default:
		return nil, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("unknown --sink %q (want file, env or discard)", sinkKind)}
	}
}

// envNames returns the names of the variables in the current process environment, so
// the env target refuses to redefine one. It returns names only, never values.
func envNames() []string {
	env := os.Environ()
	names := make([]string, 0, len(env))
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 {
			names = append(names, kv[:i])
		}
	}
	return names
}

// reportRestore prints the plan, then (on apply) the result, to stderr so stdout stays
// clean for a data sink. It prints counts, names, keys, sizes and reasons only.
func reportRestore(plan *restore.Plan, result *restore.Result, apply bool) {
	// This line runs before the actual outcome is known to the reader (the apply/dry-run
	// result is reported below, or on failure by the caller), so it must never assert a
	// completed write in either mode: "planned" is true regardless of whether the apply
	// below succeeds, partially fails, or never runs. A customer reading this on the
	// offline recovery path, mid-incident, must not be able to mistake this line for a
	// success report. The one line below that is allowed to say "restored" is the one
	// that follows the actual result.
	fmt.Fprintf(os.Stderr, "plan (%s target): %d record(s), %d byte(s) planned, %d conflict(s)\n",
		plan.Kind, plan.WriteCount, plan.TotalBytes, len(plan.Conflicts))
	for _, c := range plan.Conflicts {
		fmt.Fprintf(os.Stderr, "  conflict [%s] %q -> %q: %s\n", c.Kind, c.Name, c.Key, c.Detail)
	}
	reportReprovision(plan)
	reportD1(plan)
	reportD1Unrenderable(plan, apply)
	if !apply {
		fmt.Fprintln(os.Stderr, "dry run: nothing was written. Re-run with --apply to write.")
		return
	}
	fmt.Fprintf(os.Stderr, "restored %d record(s), %d byte(s); %d reprovision-only, %d failed, %d conflict(s) skipped\n",
		result.Restored, result.BytesRestored, len(result.Reprovisioned), len(result.Failed), result.SkippedConflicts)
	for _, f := range result.Failed {
		fmt.Fprintf(os.Stderr, "  failed %q -> %q: %s\n", f.Name, f.Key, f.Reason)
	}
	reportReprovisionOnly(result)
	reportIncompleteMarkers(result)
	reportUnrenderable(result)
}

// reportReprovisionOnly prints the distinct notice for reprovision-type records that were
// decrypted and hash-verified during apply (their recoverability is proven) but whose
// best-effort courtesy file-write could not be laid down as a plain file, most often a
// Worker's content record and its `<id>/settings` and `<id>/versions` siblings, which cannot
// share one path on a filesystem. These are NOT failures: the record restores by deliberate
// re-provisioning from the per-record guidance already printed above. It is shown so an
// operator never reads such a record as a generic failure and so an exit-zero outcome carries
// its explanation. The lines carry names, keys, the source type and the write reason only,
// never a value.
func reportReprovisionOnly(result *restore.Result) {
	if result == nil || len(result.Reprovisioned) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "%d record(s) restore via reprovision, not a plain file write: the verified bytes could not be laid down as a file (a Worker's content and its settings/versions cannot share one path). Re-deploy from the verified snapshot per the reprovision guidance above. This is expected, not a failure.\n", len(result.Reprovisioned))
	for _, rp := range result.Reprovisioned {
		fmt.Fprintf(os.Stderr, "  reprovision-only [%s] %q -> %q: verified, file not written (%s)\n", rp.SourceType, rp.Name, rp.Key, rp.Reason)
	}
}

// reportIncompleteMarkers prints the incompleteness-marker warnings when an apply restored one
// or more marker records: a per-record line naming the destination key and the marker kind, then
// a single summary WARNING. A marker is a record the engine wrote when the source was only
// partially available at backup time, so its value is a sentinel placeholder, not live data. The
// records DID restore (a valid, hash-verifying sentinel), so this is a loud advisory, not a
// failure; it exists so an operator in a DR moment never mistakes a placeholder for the source's
// real data. The lines carry names, keys and the kind only, never a value. Shared by the file/env
// (reportRestore) and discard/drill (reportDiscard) report paths so a marker surfaces on every
// sink.
func reportIncompleteMarkers(result *restore.Result) {
	if result == nil || result.IncompleteMarkers == 0 {
		return
	}
	for _, m := range result.Markers {
		fmt.Fprintf(os.Stderr, "  WARNING incompleteness marker [%s] %q -> %q: the source was partially unavailable at backup time; this value is a sentinel placeholder, NOT real data\n", m.Kind, m.Name, m.Key)
	}
	fmt.Fprintf(os.Stderr, "WARNING: %d of %d restored record(s) are incompleteness markers (the source was partially unavailable at backup time), NOT real data. Their value is a valid, hash-verifying sentinel placeholder; do not treat it as the source's live data.\n", result.IncompleteMarkers, result.Restored)
}
