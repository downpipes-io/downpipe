package prune

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// fakeStore is a store with the optional delete and list capabilities, plus a set of keys whose delete
// is refused, standing in for a WORM or Object Lock bucket.
type fakeStore struct {
	objects map[string][]byte
	refuse  map[string]bool
	deleted []string
}

func newFakeStore(keys ...string) *fakeStore {
	f := &fakeStore{objects: map[string][]byte{}, refuse: map[string]bool{}}
	for _, k := range keys {
		f.objects[k] = []byte("x")
	}
	return f
}

func (f *fakeStore) Get(key string) ([]byte, error) {
	b, ok := f.objects[key]
	if !ok {
		return nil, fmt.Errorf("object %s is missing", key)
	}
	return b, nil
}

func (f *fakeStore) Delete(key string) error {
	if f.refuse[key] {
		return fmt.Errorf("delete %s: status 403", key)
	}
	delete(f.objects, key)
	f.deleted = append(f.deleted, key)
	return nil
}

func (f *fakeStore) List(prefix string) ([]string, error) {
	var out []string
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

// A dry run must remove nothing at all. It is the default mode, so if this regresses the tool deletes
// customer archives when the operator asked only to be shown what would go.
func TestDryRunDeletesNothing(t *testing.T) {
	store := newFakeStore("seg/aa/dead.seg", "run/old/root.manifest.json")
	plan := &Plan{OrphanSegments: []string{"seg/aa/dead.seg"}, SupersededRuns: []string{"old"}}

	res, err := Apply(store, plan, true)
	if err != nil {
		t.Fatalf("dry run failed: %v", err)
	}
	if len(store.deleted) != 0 {
		t.Fatalf("a dry run deleted objects: %v", store.deleted)
	}
	if res.SegmentsDeleted != 0 || res.RunObjectsDeleted != 0 {
		t.Fatalf("a dry run must report nothing deleted, got %+v", res)
	}
}

// Segments before run trees. A crash between the two must leave a run tree pointing at missing
// segments (detectable) rather than segments with no manifest naming them (unreclaimable, because the
// only record of which run they belonged to is gone).
func TestOrphanSegmentsAreDeletedBeforeRunTrees(t *testing.T) {
	store := newFakeStore("seg/aa/dead.seg", "run/old/root.manifest.json", "run/old/manifest/0.dpe")
	plan := &Plan{OrphanSegments: []string{"seg/aa/dead.seg"}, SupersededRuns: []string{"old"}}

	if _, err := Apply(store, plan, false); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if len(store.deleted) == 0 || store.deleted[0] != "seg/aa/dead.seg" {
		t.Fatalf("the orphan segment must be deleted first, order was %v", store.deleted)
	}
}

// A WORM refusal is counted and does not abort. Aborting on the first protected object would leave a
// partially pruned estate and tell the operator nothing about how much was protected.
func TestARefusedDeleteIsCountedNotFatalAndNotCountedAsDeleted(t *testing.T) {
	store := newFakeStore("seg/aa/locked.seg", "seg/bb/free.seg")
	store.refuse["seg/aa/locked.seg"] = true
	plan := &Plan{OrphanSegments: []string{"seg/aa/locked.seg", "seg/bb/free.seg"}}

	res, err := Apply(store, plan, false)
	if err != nil {
		t.Fatalf("a refusal must not abort the pass: %v", err)
	}
	if !reflect.DeepEqual(res.Refused, []string{"seg/aa/locked.seg"}) {
		t.Fatalf("the refusal must be reported, got %v", res.Refused)
	}
	// The load-bearing half: a refused delete must NOT be counted as a deletion, or the summary claims
	// retention took effect on objects the bucket still holds.
	if res.SegmentsDeleted != 1 {
		t.Fatalf("only the object actually removed may be counted, got %d", res.SegmentsDeleted)
	}
	if _, still := store.objects["seg/aa/locked.seg"]; !still {
		t.Fatal("the refused object should still be present")
	}
}

// The executor must never touch anything outside the run tree whose removal was decided, even if the
// store hands back extra keys.
func TestApplyIgnoresKeysOutsideTheDecidedRunTree(t *testing.T) {
	store := newFakeStore("run/old/root.manifest.json", "run/keepme/root.manifest.json")
	plan := &Plan{SupersededRuns: []string{"old"}}

	if _, err := Apply(store, plan, false); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if _, still := store.objects["run/keepme/root.manifest.json"]; !still {
		t.Fatal("apply deleted an object belonging to a run that was not in the plan")
	}
}

// Partition keeps the newest N per downpipe by the chain's own monotonic index, never by the writer's
// timestamp string, so a prune cannot be steered by editing a Time field.
func TestPartitionKeepsNewestByIndexNotByTime(t *testing.T) {
	entries := []spec.RunlogEntry{
		{Index: 1, RunID: "r1", DownpipeID: "dp", Time: "2099-01-01T00:00:00Z", Status: "active"},
		{Index: 2, RunID: "r2", DownpipeID: "dp", Time: "1990-01-01T00:00:00Z", Status: "active"},
		{Index: 3, RunID: "r3", DownpipeID: "dp", Time: "1990-01-01T00:00:00Z", Status: "active"},
	}
	keep, drop, err := Partition(entries, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// r1 carries a far-future timestamp; index still decides, so it is the one dropped.
	if !reflect.DeepEqual(keep, []string{"r2", "r3"}) {
		t.Fatalf("expected the two highest indices kept, got %v", keep)
	}
	if !reflect.DeepEqual(drop, []string{"r1"}) {
		t.Fatalf("expected the lowest index dropped, got %v", drop)
	}
}

// A run the engine already marked superseded is dropped whatever the count says: that status is in the
// signed log and this tool does not second-guess it.
func TestPartitionAlwaysDropsAnAlreadySupersededRun(t *testing.T) {
	entries := []spec.RunlogEntry{
		{Index: 2, RunID: "r2", DownpipeID: "dp", Status: "superseded"},
		{Index: 1, RunID: "r1", DownpipeID: "dp", Status: "active"},
	}
	keep, drop, err := Partition(entries, 5) // generous policy: would otherwise keep both
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(keep, []string{"r1"}) {
		t.Fatalf("expected only the active run kept, got %v", keep)
	}
	if !reflect.DeepEqual(drop, []string{"r2"}) {
		t.Fatalf("expected the superseded run dropped, got %v", drop)
	}
}

// Retention is per downpipe: a busy downpipe's runs must never push another downpipe's runs out.
func TestPartitionCountsPerDownpipe(t *testing.T) {
	entries := []spec.RunlogEntry{
		{Index: 3, RunID: "a3", DownpipeID: "a", Status: "active"},
		{Index: 2, RunID: "a2", DownpipeID: "a", Status: "active"},
		{Index: 1, RunID: "a1", DownpipeID: "a", Status: "active"},
		{Index: 1, RunID: "b1", DownpipeID: "b", Status: "active"},
	}
	keep, drop, err := Partition(entries, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(keep, []string{"a2", "a3", "b1"}) {
		t.Fatalf("downpipe b's only run must survive, got %v", keep)
	}
	if !reflect.DeepEqual(drop, []string{"a1"}) {
		t.Fatalf("expected only a's oldest dropped, got %v", drop)
	}
}

// An unset policy must not read as "keep nothing". Zero is the value an unset flag lands on, and
// treating it literally would delete every run on the estate.
func TestPartitionRefusesAKeepCountBelowOne(t *testing.T) {
	entries := []spec.RunlogEntry{{Index: 1, RunID: "r1", DownpipeID: "dp", Status: "active"}}
	if _, _, err := Partition(entries, 0); err == nil {
		t.Fatal("a keep count of 0 must be refused, not treated as keep-nothing")
	}
}

// A dry run has to answer "what would this remove?" with a number. The deleted counters cannot serve:
// they are zero by construction when nothing is deleted, so a dry run reporting only those tells an
// operator that a plan about to remove their run trees would remove nothing. The planned counters are
// what the operator reads before arming --apply, and this test is what stops them silently returning to
// zero if the counting is ever moved back inside the delete.
func TestDryRunReportsWhatItWouldDelete(t *testing.T) {
	store := newFakeStore("seg/aa", "seg/bb", "run/r1/root.json", "run/r1/m0.json", "run/r1/m1.json")
	plan := &Plan{OrphanSegments: []string{"seg/aa"}, SupersededRuns: []string{"r1"}}

	res, err := Apply(store, plan, true)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if res.SegmentsDeleted != 0 || res.RunObjectsDeleted != 0 {
		t.Fatalf("a dry run deleted something: segments=%d runObjects=%d", res.SegmentsDeleted, res.RunObjectsDeleted)
	}
	if res.PlannedSegments != 1 {
		t.Errorf("planned segments = %d, want 1", res.PlannedSegments)
	}
	if res.PlannedRunObjects != 3 {
		t.Errorf("planned run objects = %d, want 3 (the whole run tree)", res.PlannedRunObjects)
	}
	if res.RunObjectsUnknown {
		t.Error("a listing store must produce a known run-object count on a dry run")
	}
	if len(store.objects) != 5 {
		t.Errorf("the store changed under a dry run: %d objects left, want 5", len(store.objects))
	}
}

// The prediction has to be the truth. An operator reads the dry run's total, decides on it, and reruns
// with --apply; if the two numbers disagree the dry run was advice about a different operation.
func TestTheDryRunPredictionMatchesWhatApplyActuallyDeletes(t *testing.T) {
	keys := []string{"seg/aa", "seg/bb", "run/r1/root.json", "run/r1/m0.json", "run/r1/m1.json"}
	plan := &Plan{OrphanSegments: []string{"seg/aa"}, SupersededRuns: []string{"r1"}}

	predicted, err := Apply(newFakeStore(keys...), plan, true)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	applied, err := Apply(newFakeStore(keys...), plan, false)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	wantTotal := predicted.PlannedSegments + predicted.PlannedRunObjects
	gotTotal := applied.SegmentsDeleted + applied.RunObjectsDeleted
	if wantTotal != gotTotal {
		t.Fatalf("the dry run predicted %d objects and --apply deleted %d", wantTotal, gotTotal)
	}
	if wantTotal == 0 {
		t.Fatal("the fixture deletes nothing, so this test would pass vacuously")
	}
	// And on the apply side the planned totals must agree with the dry run's, or the two invocations
	// disagree about the plan itself rather than about what was carried out.
	if applied.PlannedSegments != predicted.PlannedSegments || applied.PlannedRunObjects != predicted.PlannedRunObjects {
		t.Errorf("planned counts differ between dry (%d/%d) and apply (%d/%d)",
			predicted.PlannedSegments, predicted.PlannedRunObjects, applied.PlannedSegments, applied.PlannedRunObjects)
	}
}

// A WORM destination that refuses deletes must show up as a shortfall against the plan, never as a clean
// run. This is the counterpart to the refused-delete test above, stated in the terms the CLI prints.
func TestPlannedMinusDeletedExposesARefusingDestination(t *testing.T) {
	store := newFakeStore("seg/aa", "run/r1/root.json")
	store.refuse["seg/aa"] = true
	plan := &Plan{OrphanSegments: []string{"seg/aa"}, SupersededRuns: []string{"r1"}}

	res, err := Apply(store, plan, false)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	shortfall := (res.PlannedSegments + res.PlannedRunObjects) - (res.SegmentsDeleted + res.RunObjectsDeleted)
	if shortfall != 1 {
		t.Fatalf("shortfall = %d, want 1 (the refused segment)", shortfall)
	}
	if len(res.Refused) != 1 || res.Refused[0] != "seg/aa" {
		t.Errorf("refused = %v, want [seg/aa]", res.Refused)
	}
}

// A dry run against a store that cannot list must say the run-object count is unknown rather than print
// a confident zero. Zero is a measurement here, and it would be the wrong one.
func TestDryRunAgainstANonListingStoreReportsUnknownRatherThanZero(t *testing.T) {
	plan := &Plan{OrphanSegments: []string{"seg/aa"}, SupersededRuns: []string{"r1"}}
	res, err := Apply(getOnlyStore{}, plan, true)
	if err != nil {
		t.Fatalf("dry run against a read-only store must not fail: %v", err)
	}
	if !res.RunObjectsUnknown {
		t.Error("want RunObjectsUnknown on a store with no List")
	}
	if res.PlannedRunObjects != 0 {
		t.Errorf("planned run objects = %d; with no listing there is nothing to count", res.PlannedRunObjects)
	}
	if res.PlannedSegments != 1 {
		t.Errorf("planned segments = %d, want 1 (the orphan set comes from the plan, not from a listing)", res.PlannedSegments)
	}
}

// getOnlyStore implements the bare ObjectStore and neither optional capability.
type getOnlyStore struct{}

func (getOnlyStore) Get(string) ([]byte, error) { return nil, fmt.Errorf("not present") }
