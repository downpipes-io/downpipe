package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/prune"
)

// cmdPrune is the offline retention prune.
//
// It exists because the ENGINE cannot do this in the break-glass-only posture. Working out which
// segments a superseded run still needs means decrypting that run's shard manifests, and an engine in
// that posture holds no key that can. This tool can, because the operator supplies one. That asymmetry
// is the whole reason the prune belongs here, and until now the documentation promised this command
// while it did not exist.
//
// It is a DRY RUN by default. --apply is required to remove anything, matching the engine's own
// retention default, and no looser.
func cmdPrune(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("prune", flag.ContinueOnError)
	sf := addStoreFlags(fs)
	idf := addIdentityFlags(fs, "break-glass identity file (needed to read which segments each run references)")
	signerPath := fs.String("signer", "", "operator signer public-key file")
	keep := fs.Int("keep", 0, "keep this many most recent runs per downpipe; older runs become deletable")
	apply := fs.Bool("apply", false, "actually delete; without it this is a dry run that removes nothing")
	receiptPath := fs.String("receipt", "", "write a JSON record of this pass to this path (recommended for --apply; it is the only durable account of what was deleted)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if !idf.supplied() || *signerPath == "" || *keep < 1 {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("prune needs an identity (--identity, or --share files with --envelope), --signer, --keep <n>=1 or more, and a source (--archive or --s3-endpoint)")}
	}

	store, err := sf.resolve()
	if err != nil {
		return err
	}
	identity, verifier, err := idf.loadAndVerifier(*signerPath)
	if err != nil {
		return err
	}

	runlogBytes, err := store.Get("_RECOVERY/RUNLOG")
	if err != nil {
		return codedGet(exitUnclassified, fmt.Errorf("read runlog: %w", err))
	}
	if err := verifyRunlogSignature(store, runlogBytes, verifier); err != nil {
		return err
	}
	entries, err := format.ParseRunlog(runlogBytes)
	if err != nil {
		return err
	}
	keepIDs, dropIDs, err := prune.Partition(entries, *keep)
	if err != nil {
		return &format.ExitError{Code: format.ExitUsage, Err: err}
	}

	// Enumerate BOTH partitions. The retained side is not optional and not an optimisation: without it
	// there is nothing to subtract, and every superseded segment would look deletable.
	retained, err := enumerate(store, keepIDs, identity, verifier)
	if err != nil {
		return err
	}
	superseded, err := enumerate(store, dropIDs, identity, verifier)
	if err != nil {
		return err
	}

	plan, err := prune.Compute(retained, superseded)
	if err != nil {
		// An abstain is not a crash and should not read as one. It means the tool could not see enough
		// to be safe, and the honest operator action is to fix the unreadable run, not to force it.
		var ab *prune.Abstain
		if errors.As(err, &ab) {
			// ExitUnverified, not ExitStale. The abstain means a retained run could not be OPENED and
			// verified, which is what a format.Open failure means everywhere else in this tool. Borrowing
			// the freshness code made the top-level handler offer --allow-stale, a flag prune does not
			// have, so an operator following the advice got "flag provided but not defined".
			//
			// THE REMEDY NAMES THE MEASURED CAUSE, NOT THE COMMONEST ONE: it must not assert a cause
			// the command never established. Driven on the conformance vector
			// unknown-major (formatVersion downpipe/9.0.0): prune abstained at exit 2 and deleted
			// nothing, correctly and measurably, and then told the operator to go and check their
			// break-glass identity. The identity was fine. Nothing about it could ever have been the
			// problem, because Open refuses the version before it looks at a key at all. Sending
			// somebody mid-recovery to re-derive a key from custody shares over a version mismatch
			// costs a ceremony and answers nothing.
			//
			// So this block says only what the abstain itself establishes, and the follow-up names
			// verify as the fuller diagnosis without claiming to know what verify will say. The
			// measured cause rides on the returned error, which the top-level handler prints on the
			// line below this one; printing it here as well would repeat a paragraph-long refusal
			// twice in one screen of output.
			fmt.Fprintf(os.Stderr, "prune abstained: retained run %s could not be opened and fully read, so its live segments cannot be told apart from deletable ones. Nothing was deleted.\n", ab.RunID)
			fmt.Fprintf(os.Stderr, "  run `downpipe verify --run %s` for the full diagnosis of that one run, and prune again once it opens. The reason it refused to open is on the next line.\n", ab.RunID)
			return &format.ExitError{Code: format.ExitUnverified, Err: err}
		}
		return err
	}

	mode := "dry-run"
	if *apply {
		mode = "apply"
	}

	// The INTENT is recorded before the first delete, not after the last one. A pass that is interrupted
	// (a closed laptop, a dropped session) returns no Result at all, so a receipt written only on the way
	// out would leave the operator knowing nothing about a pass that had already deleted objects. A receipt
	// left at "started" is precisely the signal that this happened, and it carries the plan that was running.
	res, err := applyWithReceipt(store, plan, !*apply, *receiptPath, func() *prune.Receipt {
		return prune.NewReceipt(sf.describe(), mode, *keep, len(keepIDs), plan, time.Now())
	})
	if err != nil {
		return err
	}

	banner := "DRY RUN (nothing was deleted; pass --apply to delete)"
	if *apply {
		banner = "APPLIED"
	}
	fmt.Printf("prune %s\n", banner)
	fmt.Printf("  runs kept:              %d\n", len(keepIDs))
	fmt.Printf("  runs deletable:         %d\n", len(plan.SupersededRuns))
	fmt.Printf("  orphan segments:        %d\n", len(plan.OrphanSegments))
	if len(plan.SkippedSuperseded) > 0 {
		// A safe leak, and reported rather than hidden: their bytes stay, so an operator who believes the
		// prune was thorough would otherwise be wrong about their storage.
		//
		// PRINTED BEFORE THE TOTALS, AND NOT CALLED "DELETABLE". Both were wrong, and together they made
		// the worst case of this report unreadable. When every superseded run is unreadable the counts are
		// all 0, and the old order put the explanation for those zeros AFTER the line the docs page tells
		// an operator to read before arming --apply ("read the last line"). An operator following that
		// instruction saw a plan of zeros and concluded their retention had nothing to do, when the truth
		// was that it could not work out what to do and their bytes were staying. The old label made it
		// worse by using "deletable" a second time with a different meaning, so the report said "runs
		// deletable: 0" and "deletable runs SKIPPED: 3" four lines apart.
		fmt.Printf("  superseded runs this pass will NOT touch (could not be read, so their bytes stay): %d %v\n", len(plan.SkippedSuperseded), plan.SkippedSuperseded)
	}
	if *apply {
		fmt.Printf("  segments deleted:       %d\n", res.SegmentsDeleted)
		fmt.Printf("  run-tree objects gone:  %d\n", res.RunObjectsDeleted)
		// Planned minus deleted is the shortfall, and it is never silent. A clean exit with a gap here
		// means the destination kept objects the operator believes their retention removed.
		if short := (res.PlannedSegments + res.PlannedRunObjects) - (res.SegmentsDeleted + res.RunObjectsDeleted); short > 0 {
			fmt.Printf("  NOT deleted (planned but kept by the destination): %d\n", short)
		}
	} else {
		for _, line := range pruneDryRunLines(res) {
			fmt.Print(line)
		}
	}
	if len(res.Refused) > 0 {
		// This is what Object Lock looks like, and it is the destination doing its job. Say so, rather
		// than letting the operator read a clean exit as "retention applied".
		fmt.Printf("  deletes REFUSED by the destination (Object Lock or WORM): %d\n", len(res.Refused))
	}
	return nil
}

// verifyRunlogSignature checks the RUNLOG's detached signature against the operator-supplied signer,
// before a single entry of it is read.
//
// WITHOUT THIS, ONE EDITED WORD IN THE RUNLOG DELETED THE WHOLE ARCHIVE. The prune decides what to
// destroy from two things: the keep window, and each entry's status, because a run the engine has already
// marked "superseded" is deletable whatever --keep says. internal/prune/plan.go gives the reason to trust
// that field in as many words, "because that status is in the signed log", and nothing on this path
// verified the signature. Changing "active" to "superseded" in _RECOVERY/RUNLOG, leaving
// _RECOVERY/RUNLOG.sig untouched and therefore invalid, turned `prune --keep 30` on a three-run archive
// from a plan that deletes nothing into a plan that deletes every run tree and every segment, exit 0, with
// nothing on stderr. An operator who then armed --apply lost the archive.
//
// The per-run open does verify each root manifest against --signer, which is why a forged run's CONTENTS
// cannot be planted. It does not help here. The RUNLOG chooses which genuine runs get deleted, and
// enumerate opens runs with AllowStale, which is required (a superseded run is by definition not the
// latest) and which makes format.Open tolerate the very freshness failure a bad RUNLOG signature raises.
//
// The read-only `keys --which` has verified this signature since it was written, and says a forged or
// rolled-back log must fail the whole command. The command that DELETES did not.
//
// ExitUnverified, not ExitStale. A bad signature here is a tamper verdict about the archive, which is what
// 2 is for, and prune has no --allow-stale for the exit-5 hint to offer; that mismatch has already sent an
// operator to a flag this command does not define. Prune always has a verifier, since --signer is
// mandatory, so unlike keys this check is unconditional and an archive with no signature file cannot be
// pruned. That is the intended strictness: deleting on the strength of an unsigned log is the defect.
func verifyRunlogSignature(store format.ObjectStore, runlogBytes []byte, verifier *crypto.HybridVerifier) error {
	sigText, err := store.Get("_RECOVERY/RUNLOG.sig")
	if err != nil {
		return codedGet(format.ExitUnverified, fmt.Errorf("read the runlog signature, which decides which runs this prune may delete: %w", err))
	}
	sig, err := format.B64Decode(strings.TrimSpace(string(sigText)))
	if err != nil {
		return &format.ExitError{Code: format.ExitUnverified, Err: fmt.Errorf("decode the runlog signature: %w", err)}
	}
	if err := verifier.Verify(runlogBytes, sig); err != nil {
		return &format.ExitError{Code: format.ExitUnverified, Err: fmt.Errorf("the runlog signature does not verify against --signer, so which runs your policy supersedes cannot be trusted and nothing was deleted: %w", err)}
	}
	return nil
}

// pruneDryRunLines is the "would delete" block of the dry-run report: what this pass WOULD remove, which
// is the thing the operator decides on. Without it the report gives only the run and orphan counts, and a
// plan that deletes a run's whole manifest tree reads as "nothing will happen".
//
// It is a function rather than four Printf calls inside cmdPrune because one of its two branches cannot be
// reached through the command's own flags. The store comes from --archive or --s3-endpoint, and which
// branch runs is decided by whether that store can LIST, so the uncountable branch has no argv that
// produces it. Left inline it was untestable, and it was wrong.
//
// THE DEFECT THIS SHAPE FIXES. The old block printed
//
//	would delete run-tree objects: unknown (this destination cannot list, so the count needs --apply)
//	would delete objects in total: 118
//
// A definite total, one line after saying the run-object count is not known, immediately before an
// irreversible delete. PlannedRunObjects is 0 in that branch by construction, so the "total" was the
// segment count with the run trees silently missing from it: an UNDERSTATEMENT of a delete, which is the
// direction that matters. It also pointed the operator at --apply for the number, and --apply is precisely
// what cannot run here: prune.Apply refuses a destination it cannot list, before deleting anything.
//
// The branch is LIVE, not latent. The S3 backend this tool ships implements Get and Delete and no List, so
// any dry run against --s3-endpoint takes it. TestTheUncountableRunTreeBranchIsReachableFromAShippedDestination
// pins that.
//
// Lines are returned rather than printed so a test can read them. A caller that printed something else
// would defeat that, which is why TestTheDryRunPlanIsPrintedOnlyFromOnePlace pins the labels to this
// function.
func pruneDryRunLines(res *prune.Result) []string {
	segments := fmt.Sprintf("  would delete segments:  %d\n", res.PlannedSegments)
	if !res.RunObjectsUnknown {
		return []string{
			segments,
			fmt.Sprintf("  would delete run-tree objects: %d\n", res.PlannedRunObjects),
			fmt.Sprintf("  would delete objects in total: %d\n", res.PlannedSegments+res.PlannedRunObjects),
		}
	}
	return []string{
		segments,
		"  would delete run-tree objects: NOT COUNTED (this destination offers no listing)\n",
		// A floor, and marked as one. "at least" is the whole difference between a number an operator can
		// act on and a number that quietly understates what they are about to destroy.
		fmt.Sprintf("  would delete objects in total: at least %d, with the uncounted run trees on top of that\n", res.PlannedSegments),
		// And the fact that decides whether to read any of it: this plan cannot be carried out here. A dry
		// run that looks like every other dry run, against a destination where --apply always fails, is the
		// same report reading as two different things.
		"  a prune cannot be APPLIED to this destination: removing a run tree means listing it first, so an --apply here deletes nothing and fails\n",
	}
}

// enumerate opens each run and collects the segment objects it references. A run that cannot be opened
// or fully walked is returned with Complete=false rather than an empty set, which is the distinction
// prune.Compute depends on: for a retained run it forces an abstain, and for a superseded run it is a
// skip. Reporting a failure as an empty set would let a retained run's live segments be deleted.
func enumerate(store format.ObjectStore, runIDs []string, identity *crypto.HybridKEMPrivate, verifier *crypto.HybridVerifier) ([]prune.RunRefs, error) {
	out := make([]prune.RunRefs, 0, len(runIDs))
	for _, runID := range runIDs {
		refs := prune.RunRefs{RunID: runID, Objects: map[string]struct{}{}}
		// Both acknowledgements, deliberately. AllowStale is what this loop needs (a superseded run
		// is by definition not the latest for its downpipe). AllowUnverifiedRunlog keeps enumerate's
		// behaviour exactly what it was before --allow-stale was narrowed to age alone, and prune
		// does not lose the signature check by setting it: cmdPrune has already run
		// verifyRunlogSignature against --signer over the same bytes and refused the whole command
		// (exit 2) if it did not verify, before any run is opened here.
		r, err := format.Open(store, runID, identity, verifier, format.Options{AllowStale: true, AllowUnverifiedRunlog: true})
		if err != nil {
			// The error is KEPT, not discarded. It was thrown away here, which left the abstain
			// message downstream with nothing to say but the commonest cause, and the commonest
			// cause is not always the cause. Open refuses an unimplemented formatVersion at this
			// exact call with a message that already carries its own remedy, and that message was
			// being replaced by advice to check the identity.
			refs.Reason = err.Error()
			out = append(out, refs) // Complete stays false
			continue
		}
		complete := true
		for _, rec := range r.Records() {
			for _, seg := range rec.Segments {
				refs.Objects[seg.Object] = struct{}{}
			}
		}
		refs.Complete = complete
		out = append(out, refs)
		// Closed HERE, per iteration, not deferred. A defer inside this loop would hold every run's master
		// live until the whole enumeration returned, which on a large archive is one live key per run and
		// the opposite of what closing it is for. Nothing between the open above and this point returns or
		// continues, so the explicit call runs on every path that reached it.
		r.Close()
	}
	return out, nil
}

// applyWithReceipt runs a prune plan with its receipt, and exists as a named function purely so the ORDER
// can be tested. The order is the whole value of the receipt: the intent is recorded and flushed BEFORE
// the first delete, so a pass that is interrupted still leaves an account of what it was doing. Written
// inline in cmdPrune this guarantee was untestable, and a mutation moving the write after Apply passed the
// entire suite.
func applyWithReceipt(store format.ObjectStore, plan *prune.Plan, dryRun bool, receiptPath string, mk func() *prune.Receipt) (*prune.Result, error) {
	var receipt *prune.Receipt
	if receiptPath != "" {
		receipt = mk()
		if err := receipt.Write(receiptPath); err != nil {
			// FATAL. An operator who asked for a receipt and is about to delete archives must not have the
			// deletion proceed with no record of it, and an unwritable path is better found now than after.
			return nil, fmt.Errorf("the prune receipt could not be written, so nothing was deleted: %w", err)
		}
	}

	res, err := prune.Apply(store, plan, dryRun)
	if err != nil {
		return nil, err
	}

	if receipt != nil {
		receipt.Complete(res, time.Now())
		if err := receipt.Write(receiptPath); err != nil {
			// NOT fatal, and the difference from the pre-flight case matters. The deletes have already
			// happened, so failing now would report a prune that did not run when it did. The receipt on
			// disk still says "started" with the plan, which is the honest record of this state.
			fmt.Fprintf(os.Stderr, "warning: the prune ran but its receipt could not be updated at %s: %v\n", receiptPath, err)
			fmt.Fprintf(os.Stderr, "         the receipt still records this pass as started, with the plan it was executing.\n")
		}
	}
	return res, nil
}
