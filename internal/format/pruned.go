package format

import (
	"fmt"
	"strings"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// Telling a pruned run apart from a deleted one.
//
// After `downpipe prune --apply`, a superseded run's tree is gone while its RUNLOG entry remains. Asking
// to open that run then failed with the store's raw error, which for the directory backend reads
//
//	read root manifest: read object run/<id>/root.manifest.json: open <path>: no such file or directory
//
// That is the wording of a corrupted archive, produced by a retention pass that worked exactly as
// designed. It is the wrong answer twice over: it alarms an operator whose archive is healthy, and by
// spending exit 2 on a benign state it teaches them that exit 2 is noise, which is the code that means
// their archive has actually been tampered with.
//
// The honest diagnosis names the condition and refuses to over-claim. A run listed in the RUNLOG whose
// tree is ENTIRELY absent is the post-prune state; it is also exactly what an attacker deleting that run
// would leave behind. Nothing in the archive distinguishes them, for a reason worth stating rather than
// hiding: the offline prune holds only the signer PUBLIC key, so unlike the engine's in-account prune it
// cannot mark the entry superseded and re-sign the log. The entry still reads status="active".
//
// So this does not decide anything and does not soften an exit code. The run still fails to open, still
// at ExitUnverified, because it genuinely cannot be verified. Only the explanation improves, and it
// carries the ambiguity to the operator instead of resolving it for them.

// prunedTreeDiagnosis returns a replacement error when runID looks pruned rather than corrupt, and nil
// when it does not, in which case the caller keeps the store's own error.
//
// "Looks pruned" is deliberately narrow, because a wrong guess here would explain away real damage:
//
//   - the store must be able to LIST, or absence cannot be told from a failed read at all;
//   - the run's prefix must contain ZERO objects. A tree missing SOME of its objects is corruption or a
//     partial delete, never a completed prune, and must keep the raw error;
//   - the run must be LISTED in the RUNLOG. A run absent from the log was never in this archive, which
//     is a different mistake (usually a mistyped run id) and deserves its own wording.
//
// The RUNLOG is read here WITHOUT verifying its signature, and that is safe only because of what the
// result is used for. It selects wording for a failure that has already been decided. It cannot admit a
// run, downgrade a verdict, or suppress a security finding, so an attacker who rewrites the RUNLOG to
// forge this state gains nothing beyond a different sentence on an error they caused anyway.
func prunedTreeDiagnosis(store ObjectStore, runID string) error {
	listed := PrunedRunEntry(store, runID)
	if listed == nil {
		return nil
	}

	status := listed.Status
	if status == "" {
		status = "active"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "run %s is listed in the RUNLOG (index %d, status %q) but its tree is entirely absent, so it cannot be opened.\n", runID, listed.Index, status)
	b.WriteString("This is the expected state after `downpipe prune --apply` removed the run, and it is also what deleting the run would look like.\n")
	b.WriteString("Nothing in the archive tells those apart: the offline prune holds only the signer public key, so it cannot mark the entry superseded and re-sign the log the way the engine's own prune does.\n")
	b.WriteString("If you ran a prune covering this run, this is retention working. If you did not, treat it as data loss and check the rest of the archive with `downpipe keys --which`.")
	return coded(ExitUnverified, fmt.Errorf("%s", b.String()))
}

// PrunedRunEntry reports whether runID is in the pruned-tree state, returning its RUNLOG entry when it
// is and nil when it is not. It is the shared predicate behind both the open-path diagnosis above and
// the `keys --which` walk, which would otherwise print one alarming filesystem error per pruned run: on
// an estate keeping the newest 30 of several hundred runs, that is hundreds of lines of "no such file"
// describing an archive in perfect health.
//
// The narrowness described above is the whole safety argument, so it lives here rather than being
// restated by each caller.
func PrunedRunEntry(store ObjectStore, runID string) *spec.RunlogEntry {
	lister, ok := store.(ListingStore)
	if !ok {
		return nil
	}
	keys, err := lister.List("run/" + runID + "/")
	if err != nil || len(keys) != 0 {
		return nil
	}
	runlogBytes, err := store.Get("_RECOVERY/RUNLOG")
	if err != nil {
		return nil
	}
	entries, err := ParseRunlog(runlogBytes)
	if err != nil {
		return nil
	}
	for i := range entries {
		if entries[i].RunID == runID {
			return &entries[i]
		}
	}
	return nil
}

// openRootManifest reads a run's root manifest, substituting the pruned-run diagnosis when the tree is
// absent. The three open paths (restore, streaming restore and keyless attestation) share it so a run
// pruned from under any of them is explained the same way rather than in whichever one was updated.
func openRootManifest(store ObjectStore, runID string) ([]byte, error) {
	rootBytes, err := store.Get(runKey(runID, "root.manifest.json"))
	if err == nil {
		return rootBytes, nil
	}
	if diag := prunedTreeDiagnosis(store, runID); diag != nil {
		return nil, diag
	}
	return nil, codedGet(ExitUnverified, fmt.Errorf("read root manifest: %w", err))
}
