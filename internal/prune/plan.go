// Package prune computes what an offline prune would delete, and refuses to compute it when it
// cannot see enough to be safe.
//
// Everything in this file is PURE: no I/O, no store, no key. That is deliberate. This is the half of
// the operation that decides whether customer archives get deleted, and pure functions are the half
// that can be exhaustively tested without a destination. The caller does the reading and the deleting;
// this package only ever returns a plan.
//
// The invariants below are ported from the engine's own prune logic rather than
// reinvented, because each one exists for a specific way this operation destroys data.
package prune

import (
	"fmt"
	"sort"
)

// RunRefs is one run's enumerated segment objects, and whether that enumeration COMPLETED.
//
// Complete is the load-bearing field and it is not a detail. A run whose shard manifests could not all
// be decrypted has an incomplete ref set, and an incomplete ref set for a RETAINED run is the single
// most dangerous input this package can receive: its live segments would be missing from the retained
// side, fall out of the subtraction, and be classified as orphans to delete. So an enumeration failure
// must NEVER be reported as an empty-but-complete set. Callers set Complete=false and let Plan abstain.
type RunRefs struct {
	RunID string
	// Objects is the set of segment object keys this run references. Nil or empty is only meaningful
	// alongside Complete=true (a genuinely empty run); with Complete=false it means "unknown".
	Objects map[string]struct{}
	// Complete reports whether every shard manifest of this run was read and decrypted.
	Complete bool
	// Reason is WHY the enumeration did not complete, carried through from whatever refused to open
	// the run. Empty when Complete is true.
	//
	// It exists because the caller discarded the open error and then had to guess at the cause in the
	// message it printed. The guess it made was "check that identity opens the run", which is right
	// for a wrong key and wrong for every other refusal this package can be handed. A format version
	// this reader does not implement abstains here exactly as a wrong key does, and an operator told
	// to check their identity over it goes and re-derives a key that was never the problem, while the
	// archive that needs a different reader sits untouched. A remedy naming the wrong cause is worse
	// than no remedy: it spends the one thing nobody has during a recovery.
	Reason string
}

// Plan is what the caller may delete. Nothing else.
type Plan struct {
	// OrphanSegments are segment objects referenced ONLY by superseded runs, sorted for determinism so
	// two runs of the same plan produce the same output and a support engineer can diff them.
	OrphanSegments []string
	// SupersededRuns are the run ids whose trees may be removed, sorted.
	SupersededRuns []string
	// SkippedSuperseded are superseded runs that could not be enumerated. Their segments stay on the
	// destination: a safe leak, never a reason to abort, but ALWAYS reported rather than hidden, because
	// silently leaking bytes on a prune the operator believes was thorough is its own kind of dishonesty.
	SkippedSuperseded []string
}

// Abstain is returned when the plan cannot be computed safely. It is a distinct type rather than a
// generic error so a caller cannot accidentally treat "I could not see enough to be safe" as "there is
// nothing to do", which is exactly the confusion that would delete live data.
type Abstain struct {
	// RunID is the retained run that could not be fully enumerated.
	RunID string
	// Reason is the enumeration failure carried through from RunRefs, so the message names the cause
	// that actually stopped the pass instead of the commonest one. Empty when the caller supplied none.
	Reason string
}

func (a *Abstain) Error() string {
	msg := fmt.Sprintf("abstained: retained run %s could not be fully enumerated, so its live segments cannot be distinguished from orphans", a.RunID)
	if a.Reason != "" {
		msg += ": " + a.Reason
	}
	return msg
}

// Compute builds the plan, or abstains.
//
// retained and superseded are the two partitions of the RUNLOG. The rule is asymmetric, and the
// asymmetry is the whole safety argument:
//
//   - A RETAINED run that cannot be fully enumerated ABSTAINS the entire pass. Its segments are live,
//     and not knowing which they are means not knowing which of the superseded segments are safe to
//     delete. Abstaining costs storage; guessing costs the customer's backups.
//   - A SUPERSEDED run that cannot be fully enumerated is SKIPPED and counted. Its segments simply stay.
//     There is no danger in leaving bytes behind, only cost, and aborting the whole pass because one
//     dead run is unreadable would make the tool useless on exactly the estates that most need it.
func Compute(retained, superseded []RunRefs) (*Plan, error) {
	// Retained first, and abstain on the first incomplete one. Order matters only for the error message
	// being deterministic, so sort the check rather than trusting caller order.
	sortedRetained := append([]RunRefs(nil), retained...)
	sort.Slice(sortedRetained, func(i, j int) bool { return sortedRetained[i].RunID < sortedRetained[j].RunID })

	live := make(map[string]struct{})
	for _, r := range sortedRetained {
		if !r.Complete {
			return nil, &Abstain{RunID: r.RunID, Reason: r.Reason}
		}
		for obj := range r.Objects {
			live[obj] = struct{}{}
		}
	}

	plan := &Plan{}
	dead := make(map[string]struct{})
	sortedSuperseded := append([]RunRefs(nil), superseded...)
	sort.Slice(sortedSuperseded, func(i, j int) bool { return sortedSuperseded[i].RunID < sortedSuperseded[j].RunID })

	for _, r := range sortedSuperseded {
		if !r.Complete {
			// Safe leak: its bytes stay, and its run tree stays too. Removing the tree while its segments
			// remain would strand those bytes with nothing left to identify them, which is worse than
			// leaving both.
			plan.SkippedSuperseded = append(plan.SkippedSuperseded, r.RunID)
			continue
		}
		plan.SupersededRuns = append(plan.SupersededRuns, r.RunID)
		for obj := range r.Objects {
			dead[obj] = struct{}{}
		}
	}

	// The subtraction. A segment referenced by ANY retained run is never an orphan, even if a superseded
	// run also references it. Content addressing is per-run in the current writer, so cross-run sharing
	// should not occur, but that is a consequence of a writer choice rather than an enforced invariant,
	// and this guard costs nothing.
	for obj := range dead {
		if _, isLive := live[obj]; isLive {
			continue
		}
		plan.OrphanSegments = append(plan.OrphanSegments, obj)
	}
	sort.Strings(plan.OrphanSegments)
	return plan, nil
}
