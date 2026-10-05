package prune

import (
	"errors"
	"reflect"
	"testing"
)

func refs(runID string, complete bool, objs ...string) RunRefs {
	m := make(map[string]struct{}, len(objs))
	for _, o := range objs {
		m[o] = struct{}{}
	}
	return RunRefs{RunID: runID, Objects: m, Complete: complete}
}

// The test that matters most. A retained run whose manifests could not be decrypted must abort the
// whole pass. If this ever regresses, the prune deletes live segments: the unreadable run's objects are
// missing from the live set, so the subtraction classifies them as orphans and they are removed while
// the run is still retained and still expected to restore.
func TestAbstainsWhenARetainedRunCannotBeEnumerated(t *testing.T) {
	retained := []RunRefs{
		refs("run-a", true, "seg/aa/1.seg"),
		refs("run-b", false), // could not decrypt this one's shards
	}
	superseded := []RunRefs{refs("run-old", true, "seg/bb/2.seg")}

	plan, err := Compute(retained, superseded)
	if plan != nil {
		t.Fatalf("expected no plan on abstain, got %+v", plan)
	}
	var ab *Abstain
	if !errors.As(err, &ab) {
		t.Fatalf("expected an *Abstain, got %v", err)
	}
	if ab.RunID != "run-b" {
		t.Fatalf("abstain should name the run that could not be enumerated, got %q", ab.RunID)
	}
}

// The specific way the above goes wrong if Complete is ignored: an unreadable retained run reported as
// an empty set would let its own segments be deleted. Pin that the empty-and-complete case and the
// empty-and-incomplete case are treated differently, because they look identical in the Objects field.
func TestAnIncompleteRetainedRunIsNotTreatedAsAnEmptyOne(t *testing.T) {
	live := "seg/aa/live.seg"
	// Same object appears in a superseded run. If run-b's incompleteness were ignored, this object
	// would look like an orphan and be deleted while run-b still needs it.
	incomplete := []RunRefs{refs("run-b", false)}
	superseded := []RunRefs{refs("run-old", true, live)}

	if _, err := Compute(incomplete, superseded); err == nil {
		t.Fatal("an incomplete retained run must abstain, never fall through to a subtraction")
	}

	// The genuinely-empty case is allowed to proceed: a run with no records is a real thing.
	emptyButComplete := []RunRefs{refs("run-b", true)}
	plan, err := Compute(emptyButComplete, superseded)
	if err != nil {
		t.Fatalf("an empty but COMPLETE retained run is legitimate: %v", err)
	}
	if len(plan.OrphanSegments) != 1 || plan.OrphanSegments[0] != live {
		t.Fatalf("expected the superseded object to be an orphan, got %v", plan.OrphanSegments)
	}
}

// A superseded run that cannot be read is a cost, not a hazard. It must not abort the pass, and its
// run tree must NOT be listed for deletion either: removing the tree while its segments remain would
// strand those bytes with nothing left to identify them.
func TestASupersededRunThatCannotBeEnumeratedIsSkippedAndCounted(t *testing.T) {
	retained := []RunRefs{refs("run-a", true, "seg/aa/1.seg")}
	superseded := []RunRefs{
		refs("run-old", true, "seg/bb/2.seg"),
		refs("run-broken", false),
	}

	plan, err := Compute(retained, superseded)
	if err != nil {
		t.Fatalf("an unreadable SUPERSEDED run must not abort the pass: %v", err)
	}
	if !reflect.DeepEqual(plan.SkippedSuperseded, []string{"run-broken"}) {
		t.Fatalf("the skipped run must be reported, got %v", plan.SkippedSuperseded)
	}
	if !reflect.DeepEqual(plan.SupersededRuns, []string{"run-old"}) {
		t.Fatalf("only the readable superseded run may have its tree removed, got %v", plan.SupersededRuns)
	}
	if !reflect.DeepEqual(plan.OrphanSegments, []string{"seg/bb/2.seg"}) {
		t.Fatalf("only the readable run's segments may be orphaned, got %v", plan.OrphanSegments)
	}
}

// Content addressing is per-run in the current writer, so a shared segment should not arise. The guard
// must hold anyway: that property is a consequence of a writer choice, not an enforced invariant, and
// a future writer that shares segments must not silently start deleting live data.
func TestASegmentSharedWithARetainedRunIsNeverAnOrphan(t *testing.T) {
	shared := "seg/aa/shared.seg"
	retained := []RunRefs{refs("run-a", true, shared, "seg/aa/own.seg")}
	superseded := []RunRefs{refs("run-old", true, shared, "seg/bb/dead.seg")}

	plan, err := Compute(retained, superseded)
	if err != nil {
		t.Fatalf("unexpected abstain: %v", err)
	}
	for _, o := range plan.OrphanSegments {
		if o == shared {
			t.Fatal("a segment a retained run still references must never be listed for deletion")
		}
	}
	if !reflect.DeepEqual(plan.OrphanSegments, []string{"seg/bb/dead.seg"}) {
		t.Fatalf("expected only the unshared dead segment, got %v", plan.OrphanSegments)
	}
}

// Determinism: the same inputs in a different order produce the same plan, so a dry run can be diffed
// against the apply that follows it and a support engineer can reproduce what an operator saw.
func TestThePlanIsDeterministicRegardlessOfInputOrder(t *testing.T) {
	retained := []RunRefs{refs("run-a", true, "seg/aa/1.seg"), refs("run-b", true, "seg/aa/2.seg")}
	superseded := []RunRefs{refs("run-x", true, "seg/cc/9.seg"), refs("run-y", true, "seg/bb/3.seg")}

	a, err := Compute(retained, superseded)
	if err != nil {
		t.Fatalf("unexpected abstain: %v", err)
	}
	rev := func(in []RunRefs) []RunRefs {
		out := make([]RunRefs, 0, len(in))
		for i := len(in) - 1; i >= 0; i-- {
			out = append(out, in[i])
		}
		return out
	}
	b, err := Compute(rev(retained), rev(superseded))
	if err != nil {
		t.Fatalf("unexpected abstain: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("plan is order-dependent:\n%+v\n%+v", a, b)
	}
}

// Nothing superseded means nothing to delete, and that must be an empty plan rather than an error, so
// a scheduled run on an estate with nothing to prune is quiet.
func TestNothingSupersededYieldsAnEmptyPlan(t *testing.T) {
	plan, err := Compute([]RunRefs{refs("run-a", true, "seg/aa/1.seg")}, nil)
	if err != nil {
		t.Fatalf("unexpected abstain: %v", err)
	}
	if len(plan.OrphanSegments) != 0 || len(plan.SupersededRuns) != 0 || len(plan.SkippedSuperseded) != 0 {
		t.Fatalf("expected an empty plan, got %+v", plan)
	}
}
