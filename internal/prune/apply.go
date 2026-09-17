package prune

import (
	"fmt"
	"sort"
	"strings"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// Partition splits the RUNLOG into the runs to keep and the runs whose archives may be removed.
//
// keepPerDownpipe is the retention policy: keep the newest N runs of EACH downpipe. Runs the engine has
// already marked "superseded" are superseded regardless, because that status is in the signed log and
// this tool does not second-guess it.
//
// The newest N is decided by the RUNLOG's own monotonic Index rather than by the Time field. Time is a
// string the writer supplied; Index is the chain's ordering and is what the freshness check anchors. A
// prune must not be steerable by editing a timestamp.
//
// keepPerDownpipe of 0 is refused rather than treated as "keep nothing". A policy that deletes every
// run is not a retention policy, and the likeliest way to arrive at 0 is an unset flag.
func Partition(entries []spec.RunlogEntry, keepPerDownpipe int) (keep, drop []string, err error) {
	if keepPerDownpipe < 1 {
		return nil, nil, fmt.Errorf("keep-per-downpipe must be at least 1, got %d (refusing to treat an unset policy as 'keep nothing')", keepPerDownpipe)
	}

	byDownpipe := make(map[string][]spec.RunlogEntry)
	for _, e := range entries {
		byDownpipe[e.DownpipeID] = append(byDownpipe[e.DownpipeID], e)
	}

	for _, runs := range byDownpipe {
		// Newest first by the chain's own index.
		sort.Slice(runs, func(i, j int) bool { return runs[i].Index > runs[j].Index })
		kept := 0
		for _, e := range runs {
			if e.Status == "superseded" {
				drop = append(drop, e.RunID)
				continue
			}
			if kept < keepPerDownpipe {
				keep = append(keep, e.RunID)
				kept++
				continue
			}
			drop = append(drop, e.RunID)
		}
	}
	sort.Strings(keep)
	sort.Strings(drop)
	return keep, drop, nil
}

// Result is what an apply actually did, as distinct from what the plan proposed.
type Result struct {
	SegmentsDeleted   int
	RunObjectsDeleted int
	// PlannedSegments and PlannedRunObjects count the objects the plan COVERS, whether or not this call
	// deleted them. They exist because a dry run could otherwise not say what it would do: the deleted
	// counters stay at zero by construction when nothing is deleted, so a dry run reporting only those
	// reads as "this would remove nothing" for a plan that is about to remove thousands of objects. That
	// is the worst possible failure of the one offline command that deletes, and the operator arming
	// --apply is precisely the person who needs the number.
	//
	// On an --apply run the pair also exposes shortfall: planned minus deleted is what the destination
	// refused or could not be reached for, which is Object Lock doing its job and must not be silent.
	PlannedSegments   int
	PlannedRunObjects int
	// RunObjectsUnknown marks a dry run against a store that cannot list. The run trees are still deletable
	// (the run ids come from the signed RUNLOG), but their object count cannot be known without a listing,
	// and reporting 0 there would be a lie rather than a measurement.
	RunObjectsUnknown bool
	// Refused counts deletes the destination refused, which is what Object Lock or WORM looks like. It
	// is reported rather than fatal: a destination refusing to delete is doing its job, and an operator
	// needs to see that their retention policy did not take effect rather than be told it did.
	Refused []string
}

// Apply executes a plan. Nothing here decides WHAT to delete; that decision was made by Compute from
// the signed RUNLOG and the decrypted manifests, and this function only carries it out.
//
// Order is load-bearing: orphan SEGMENTS first, then the run TREES that referenced them. A crash between
// the two leaves a run tree pointing at segments already gone, which is detectable and reportable. The
// reverse leaves segments with no manifest naming them, which is unreclaimable by any later pass because
// the only record of which run they belonged to has been destroyed.
func Apply(store format.ObjectStore, plan *Plan, dryRun bool) (*Result, error) {
	mut, ok := store.(format.MutatingStore)
	if !ok && !dryRun {
		return nil, fmt.Errorf("this destination cannot delete objects, so a prune cannot be applied to it")
	}
	lister, canList := store.(format.ListingStore)
	if !canList && !dryRun {
		return nil, fmt.Errorf("this destination cannot list objects, so the run trees to remove cannot be enumerated")
	}

	res := &Result{}

	// del reports whether the object was actually removed. The distinction matters: a refused delete
	// must NOT be counted as a deletion, or the summary tells an operator their retention took effect on
	// objects a WORM bucket still holds, which is the precise dishonesty this tool exists to end.
	del := func(key string) bool {
		if dryRun {
			return false
		}
		if err := mut.Delete(key); err != nil {
			// A refusal is counted, not fatal. Aborting on the first WORM-protected object would leave a
			// partially pruned estate and tell the operator nothing about how much was protected.
			res.Refused = append(res.Refused, key)
			return false
		}
		return true
	}

	res.PlannedSegments = len(plan.OrphanSegments)
	res.RunObjectsUnknown = dryRun && !canList

	for _, seg := range plan.OrphanSegments {
		if del(seg) {
			res.SegmentsDeleted++
		}
	}

	for _, runID := range plan.SupersededRuns {
		prefix := RunTreePrefix(runID)
		var keys []string
		if canList {
			var lerr error
			keys, lerr = lister.List(prefix)
			if lerr != nil {
				return nil, fmt.Errorf("list run tree %s: %w", runID, lerr)
			}
		}
		for _, k := range keys {
			// Defence in depth against a listing that returns more than it should: never delete anything
			// outside the run tree whose removal was decided, even if the store hands it back.
			if !strings.HasPrefix(k, prefix) {
				continue
			}
			// Counted before the delete is attempted, so the planned total is the same number on a dry run
			// and on the --apply that follows it. An operator who saw "42" must not then be deleted 39 and
			// told nothing changed.
			res.PlannedRunObjects++
			if del(k) {
				res.RunObjectsDeleted++
			}
		}
	}
	return res, nil
}

// RunTreePrefix is the object prefix holding one run's manifests and root. Segments live outside it, in
// the flat content-addressed keyspace, which is exactly why the orphan set has to be computed rather
// than derived from this prefix.
func RunTreePrefix(runID string) string {
	return "run/" + runID + "/"
}
