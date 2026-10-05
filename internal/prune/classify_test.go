package prune

import (
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"testing"
)

// A failed delete is one of two things, and the report and the exit status depend on telling them apart.
// A REFUSAL is the destination answering no: a lock or a permission. A FAILURE is no usable answer. Before
// this split every failed delete was reported as "REFUSED by the destination (Object Lock or WORM)", so a
// network fault read as the destination doing its job.

// errStore refuses or fails the keys it is told to, with the error given.
type errStore struct {
	*fakeStore
	errs map[string]error
}

func (s *errStore) Delete(key string) error {
	if e, ok := s.errs[key]; ok {
		return e
	}
	return s.fakeStore.Delete(key)
}

func TestAFailedDeleteIsNotCountedAsARefusal(t *testing.T) {
	store := &errStore{fakeStore: newFakeStore("seg/aa/a.seg", "seg/bb/b.seg"), errs: map[string]error{
		"seg/aa/a.seg": errors.New("delete seg/aa/a.seg: could not reach the destination: connection refused"),
	}}
	res, err := Apply(store, &Plan{OrphanSegments: []string{"seg/aa/a.seg", "seg/bb/b.seg"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Refused) != 0 {
		t.Errorf("a network failure was counted as a refusal: %v", res.Refused)
	}
	if !reflect.DeepEqual(res.Failed, []string{"seg/aa/a.seg"}) {
		t.Errorf("failed = %v, want the unreachable key", res.Failed)
	}
	if res.SegmentsDeleted != 1 {
		t.Errorf("the loop must go on past a failure: deleted %d, want 1", res.SegmentsDeleted)
	}
	if !res.Incomplete() {
		t.Error("a pass with a failed delete must report itself incomplete")
	}
}

func TestAServerErrorIsAFailureNotARefusal(t *testing.T) {
	store := &errStore{fakeStore: newFakeStore("seg/aa/a.seg"), errs: map[string]error{
		"seg/aa/a.seg": &statusRefusal{msg: "delete seg/aa/a.seg: status 503", status: 503},
	}}
	res, _ := Apply(store, &Plan{OrphanSegments: []string{"seg/aa/a.seg"}}, false)
	if len(res.Refused) != 0 || len(res.Failed) != 1 {
		t.Errorf("a 503 must be a failure: refused %v, failed %v", res.Refused, res.Failed)
	}
}

func TestALocalPermissionDenialIsARefusal(t *testing.T) {
	store := &errStore{fakeStore: newFakeStore("seg/aa/a.seg"), errs: map[string]error{
		"seg/aa/a.seg": fmt.Errorf("delete object seg/aa/a.seg: %w", fs.ErrPermission),
	}}
	res, _ := Apply(store, &Plan{OrphanSegments: []string{"seg/aa/a.seg"}}, false)
	if len(res.Refused) != 1 || len(res.Failed) != 0 {
		t.Errorf("a permission denial must be a refusal: refused %v, failed %v", res.Refused, res.Failed)
	}
	if res.RefusedLockNamed != 0 {
		t.Error("a permission denial names no lock")
	}
}

func TestOnlyARefusalThatNamesALockIsCountedAsOne(t *testing.T) {
	store := &errStore{fakeStore: newFakeStore("seg/aa/a.seg", "seg/bb/b.seg"), errs: map[string]error{
		"seg/aa/a.seg": &statusRefusal{msg: "delete seg/aa/a.seg: status 403", status: 403, lockNamed: true},
		"seg/bb/b.seg": &statusRefusal{msg: "delete seg/bb/b.seg: status 403", status: 403},
	}}
	res, _ := Apply(store, &Plan{OrphanSegments: []string{"seg/aa/a.seg", "seg/bb/b.seg"}}, false)
	if len(res.Refused) != 2 || res.RefusedLockNamed != 1 {
		t.Errorf("refused %v with %d lock-named, want 2 refused and 1 lock-named", res.Refused, res.RefusedLockNamed)
	}
}

// A run's tree is how a later pass finds its segments. If one of them was refused, deleting the tree
// would leave that segment named by no manifest and no later prune could find it.
func TestARunTreeIsKeptWhileOneOfItsSegmentsIsStillThere(t *testing.T) {
	store := &errStore{fakeStore: newFakeStore(
		"seg/aa/locked.seg", "seg/bb/free.seg",
		"run/old/root.manifest.json", "run/old/root.manifest.json.sig",
		"run/older/root.manifest.json",
	), errs: map[string]error{
		"seg/aa/locked.seg": &statusRefusal{msg: "delete seg/aa/locked.seg: status 403", status: 403},
	}}
	plan := &Plan{
		OrphanSegments: []string{"seg/aa/locked.seg", "seg/bb/free.seg"},
		SupersededRuns: []string{"old", "older"},
		OrphansByRun:   map[string][]string{"old": {"seg/aa/locked.seg"}, "older": {"seg/bb/free.seg"}},
	}
	res, err := Apply(store, plan, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, kept := store.objects["run/old/root.manifest.json"]; !kept {
		t.Error("the tree of the run whose segment was refused was deleted, so nothing can find that segment again")
	}
	if res.HeldRunObjects != 2 {
		t.Errorf("held %d run-tree objects, want the 2 of run old", res.HeldRunObjects)
	}
	if _, kept := store.objects["run/older/root.manifest.json"]; kept {
		t.Error("the tree of a run whose segments all went must still be deleted")
	}
	if res.PlannedRunObjects != 3 {
		t.Errorf("planned %d run-tree objects, want 3 (held objects stay in the plan)", res.PlannedRunObjects)
	}
}

// Compute records each superseded run's own orphan segments, so Apply can hold the right trees.
func TestComputeRecordsEachRunsOrphans(t *testing.T) {
	plan, err := Compute(
		[]RunRefs{refs("keep", true, "seg/shared")},
		[]RunRefs{refs("a", true, "seg/shared", "seg/a1"), refs("b", true, "seg/b1")},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.OrphansByRun["a"], []string{"seg/a1"}) || !reflect.DeepEqual(plan.OrphansByRun["b"], []string{"seg/b1"}) {
		t.Errorf("orphans by run = %v, want a -> [seg/a1] (the shared segment is live) and b -> [seg/b1]", plan.OrphansByRun)
	}
}
