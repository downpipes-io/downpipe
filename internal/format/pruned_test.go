package format

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// prunedFake is a store with a listing capability, so the pruned-tree predicate can run against it.
type prunedFake struct{ objects map[string][]byte }

func (f prunedFake) Get(key string) ([]byte, error) {
	b, ok := f.objects[key]
	if !ok {
		return nil, fmt.Errorf("object %s is missing", key)
	}
	return b, nil
}

func (f prunedFake) List(prefix string) ([]string, error) {
	var out []string
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

// getOnly has no List, standing in for a destination whose absence cannot be established. The inner
// store is held in a NAMED field rather than embedded: embedding would promote prunedFake's List method
// onto getOnly, so it would satisfy ListingStore after all and this negative control would assert
// nothing while still reading as though it did.
type getOnly struct{ inner prunedFake }

func (g getOnly) Get(key string) ([]byte, error) { return g.inner.Get(key) }

const twoRunLog = `{"downpipeId":"dp","index":1,"prevRunId":null,"recordCount":1,"runId":"01ARZ3NDEKTSV4RRFFQ69G5FAV","status":"active","time":"2026-06-07T00:00:01.000Z"}
{"downpipeId":"dp","index":2,"prevRunId":"01ARZ3NDEKTSV4RRFFQ69G5FAV","recordCount":1,"runId":"01ARZ3NDEKTSV4RRFFQ69G5FB0","status":"active","time":"2026-06-07T01:00:01.000Z"}`

const prunedRun = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

func prunedStore(extra ...string) prunedFake {
	objects := map[string][]byte{
		"_RECOVERY/RUNLOG": []byte(twoRunLog),
		"run/01ARZ3NDEKTSV4RRFFQ69G5FB0/root.manifest.json": []byte("{}"),
		"seg/64/" + strings.Repeat("a", 96) + ".seg":        []byte("x"),
	}
	for _, k := range extra {
		objects[k] = []byte("x")
	}
	return prunedFake{objects: objects}
}

// The whole point: a run the operator pruned must not be described in the words of a corrupted archive.
func TestAPrunedRunIsDiagnosedRatherThanReportedAsAMissingFile(t *testing.T) {
	err := prunedTreeDiagnosis(prunedStore(), prunedRun)
	if err == nil {
		t.Fatal("want a diagnosis for a run listed in the RUNLOG with an empty tree")
	}
	msg := err.Error()
	for _, want := range []string{prunedRun, "listed in the RUNLOG", "prune", "data loss"} {
		if !strings.Contains(msg, want) {
			t.Errorf("diagnosis does not mention %q: %s", want, msg)
		}
	}
	// It must NOT resolve the ambiguity for the operator. Both readings have to survive into the message,
	// because the archive genuinely cannot tell them apart and claiming otherwise would be the real defect.
	if !strings.Contains(msg, "what deleting the run would look like") {
		t.Error("the diagnosis must state that a deletion looks identical")
	}
	// The exit code is unchanged: the run still cannot be verified, only the wording improves.
	var ce *ExitError
	if !errors.As(err, &ce) || ce.Code != ExitUnverified {
		t.Errorf("want ExitUnverified, got %v", err)
	}
}

// A tree missing SOME of its objects is corruption or a half-finished delete, and must keep the raw
// error. This is the negative control that stops the diagnosis explaining away real damage.
func TestAPartiallyPresentTreeIsNotDiagnosedAsPruned(t *testing.T) {
	store := prunedStore("run/" + prunedRun + "/manifest/00000.dpe")
	if err := prunedTreeDiagnosis(store, prunedRun); err != nil {
		t.Fatalf("a tree with objects still present must not read as pruned: %v", err)
	}
}

// A run that was never in this archive is a different mistake, usually a mistyped run id.
func TestARunAbsentFromTheRunlogIsNotDiagnosedAsPruned(t *testing.T) {
	if err := prunedTreeDiagnosis(prunedStore(), "01ARZ3NDEKTSV4RRFFQ69G5FZZ"); err != nil {
		t.Fatalf("an unlisted run must not read as pruned: %v", err)
	}
}

// Without a listing there is no way to establish that the tree is empty rather than unreadable, so the
// predicate must decline rather than guess.
func TestAStoreThatCannotListNeverDiagnosesAPrune(t *testing.T) {
	// Guard the guard: if getOnly ever gains a List (by embedding, or by the interface growing), this
	// control silently stops testing anything.
	if _, isLister := ObjectStore(getOnly{inner: prunedStore()}).(ListingStore); isLister {
		t.Fatal("getOnly must not satisfy ListingStore, or this negative control is vacuous")
	}
	if err := prunedTreeDiagnosis(getOnly{inner: prunedStore()}, prunedRun); err != nil {
		t.Fatalf("a non-listing store must not produce a prune diagnosis: %v", err)
	}
}

// A run that is present and readable must be untouched by any of this.
func TestAPresentRunIsNotDiagnosedAsPruned(t *testing.T) {
	if e := PrunedRunEntry(prunedStore(), "01ARZ3NDEKTSV4RRFFQ69G5FB0"); e != nil {
		t.Fatalf("a present run must not read as pruned: %+v", e)
	}
}

// openRootManifest is the shared entry point, so the substitution has to happen there rather than only
// in the helper the three open paths do not call directly.
func TestOpenRootManifestSubstitutesTheDiagnosisAndPassesRealReadsThrough(t *testing.T) {
	if _, err := openRootManifest(prunedStore(), prunedRun); err == nil || !strings.Contains(err.Error(), "listed in the RUNLOG") {
		t.Fatalf("want the pruned diagnosis from openRootManifest, got %v", err)
	}
	got, err := openRootManifest(prunedStore(), "01ARZ3NDEKTSV4RRFFQ69G5FB0")
	if err != nil || string(got) != "{}" {
		t.Fatalf("a present root must be returned unchanged: %q %v", got, err)
	}
}
