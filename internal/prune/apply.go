package prune

import (
	"errors"
	"fmt"
	"io/fs"
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
	// Refused lists deletes the destination ANSWERED with a refusal: a 4xx status (other than 408 and
	// 429), or a local permission denial. A refusal is either a lock on the object or a permission the
	// credential lacks, and the status alone cannot say which: a plain S3 delete on an Object Lock bucket
	// is not refused at all (it adds a delete marker), so an S3 403 is at least as likely to be a policy.
	// It is reported rather than fatal, and the loop goes on past it.
	Refused []string
	// RefusedLockNamed counts the refusals whose own answer NAMED a lock, a retention or a legal hold
	// (Google Cloud's 403 inside a retention window does). It is a subset of Refused.
	RefusedLockNamed int
	// Failed lists deletes that did not get a usable answer: a network fault, a 5xx, a 408 or 429, or a
	// local error this tool cannot classify. They are not refusals and are never reported as a lock.
	Failed []string
	// HeldRunObjects counts run-tree objects this pass did NOT attempt because a segment of that run was
	// refused or failed. The tree is how a later prune finds that segment again, so it stays until the
	// segment goes. They are included in PlannedRunObjects.
	HeldRunObjects int
}

// Incomplete reports whether an applied pass left any planned object in the destination: a refused or
// failed delete, or a run tree held because of one. cmdPrune turns it into ExitPruneIncomplete.
func (r *Result) Incomplete() bool {
	return len(r.Refused) > 0 || len(r.Failed) > 0 || r.HeldRunObjects > 0
}

// classifyDelete reads a failed Delete through the two optional capabilities format.MutatingStore
// documents. refused is true when the destination answered and said no: a 4xx status other than 408 and
// 429, or a local permission denial. lockNamed is true when that answer named a lock. Anything else is a
// failure, never a refusal and never a lock.
func classifyDelete(err error) (refused, lockNamed bool) {
	var st interface{ DeleteStatus() int }
	if errors.As(err, &st) {
		s := st.DeleteStatus()
		refused = s >= 400 && s < 500 && s != 408 && s != 429
	} else if errors.Is(err, fs.ErrPermission) {
		refused = true
	}
	var ln interface{ LockNamed() bool }
	if refused && errors.As(err, &ln) {
		lockNamed = ln.LockNamed()
	}
	return refused, lockNamed
}

// Apply executes a plan. Nothing here decides WHAT to delete; that decision was made by Compute from
// the signed RUNLOG and the decrypted manifests, and this function only carries it out.
//
// Order is load-bearing: orphan SEGMENTS first, then the run TREES that referenced them. A crash between
// the two leaves a run tree pointing at segments already gone, which is detectable and reportable. The
// reverse leaves segments with no manifest naming them, which is unreclaimable by any later pass because
// the only record of which run they belonged to has been destroyed. For the same reason a run whose
// orphan segment was refused or failed keeps its tree this pass (HeldRunObjects).
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
	// objects the destination still holds, which is the precise dishonesty this tool exists to end.
	del := func(key string) bool {
		if dryRun {
			return false
		}
		if err := mut.Delete(key); err != nil {
			// Counted, not fatal. Aborting on the first refused object would leave a partially pruned
			// estate and tell the operator nothing about how much the destination kept. A refusal and a
			// failure are counted apart: a refusal is the destination saying no, a failure is no answer.
			refused, lockNamed := classifyDelete(err)
			if refused {
				res.Refused = append(res.Refused, key)
				if lockNamed {
					res.RefusedLockNamed++
				}
			} else {
				res.Failed = append(res.Failed, key)
			}
			return false
		}
		return true
	}

	res.PlannedSegments = len(plan.OrphanSegments)
	res.RunObjectsUnknown = dryRun && !canList

	gone := make(map[string]bool, len(plan.OrphanSegments))
	for _, seg := range plan.OrphanSegments {
		if del(seg) {
			res.SegmentsDeleted++
			gone[seg] = true
		}
	}

	for _, runID := range plan.SupersededRuns {
		// A run whose orphan segment was refused or failed keeps its tree, so a later pass can open it
		// and find that segment again. Only an --apply can hold a tree; a dry run deletes nothing.
		held := false
		if !dryRun {
			for _, seg := range plan.OrphansByRun[runID] {
				if !gone[seg] {
					held = true
					break
				}
			}
		}
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
			if held {
				res.HeldRunObjects++
				continue
			}
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
