package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/prune"
	"github.com/downpipes-io/downpipe/internal/source"
)

// A CONFIDENT NUMBER PRINTED NEXT TO AN ADMISSION THAT IT IS NOT KNOWN.
//
// The dry-run report used to print, in this order:
//
//	would delete run-tree objects: unknown (this destination cannot list, so the count needs --apply)
//	would delete objects in total: 118
//
// The second line is a definite total stated one line after saying part of it cannot be known, and the
// docs page tells the operator to read exactly that line before arming an irreversible delete.
// PlannedRunObjects is 0 in that branch by construction, so the total was the segment count with every
// run tree missing from it. An UNDERSTATEMENT of a delete, which is the direction that matters.
//
// These tests drive prune.Apply to set the flag, rather than setting it by hand on a Result. A hand-set
// flag would prove the printing and nothing about when the printing happens.

// countlessStore is a destination that can be read and written but not enumerated: Get and Delete, no
// List. That is the shape of the S3 backend this tool ships, which is why the branch below is live rather
// than hypothetical.
type countlessStore struct{ deleted []string }

func (s *countlessStore) Get(string) ([]byte, error) { return nil, fmt.Errorf("not used") }

func (s *countlessStore) Delete(key string) error {
	s.deleted = append(s.deleted, key)
	return nil
}

// listingStore is the same destination with the listing capability, used as the control.
type listingStore struct {
	countlessStore
	keys []string
}

func (s *listingStore) List(prefix string) ([]string, error) {
	var out []string
	for _, k := range s.keys {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out, nil
}

// uncountablePlan is a plan whose segment and run-tree counts differ, so a total that dropped either part
// is distinguishable from one that did not.
func uncountablePlan() *prune.Plan {
	return &prune.Plan{
		OrphanSegments: []string{"seg/aa/1111.seg", "seg/bb/2222.seg", "seg/cc/3333.seg"},
		SupersededRuns: []string{"01RUNA", "01RUNB"},
	}
}

// definiteTotal matches a total line that states a bare number, which is the form that must NOT appear
// when the run trees could not be counted.
var definiteTotal = regexp.MustCompile(`(?m)^ {2}would delete objects in total:\s+\d+\s*$`)

func TestTheDryRunNeverStatesATotalItHasJustSaidItCannotKnow(t *testing.T) {
	store := &countlessStore{}
	res, err := prune.Apply(store, uncountablePlan(), true)
	if err != nil {
		t.Fatalf("dry run against a destination that cannot list: %v", err)
	}
	// The premise of the whole test. Without this the case below could pass because the flag was never
	// set and the definite branch, which correctly prints a definite total, ran instead.
	if !res.RunObjectsUnknown {
		t.Fatal("a dry run against a destination with no listing must mark the run-object count unknown; this test proved nothing")
	}
	if res.PlannedRunObjects != 0 {
		t.Fatalf("the run-object count is %d, not 0, so the old total was not an understatement and this test is pinned to the wrong shape", res.PlannedRunObjects)
	}
	if len(store.deleted) != 0 {
		t.Fatalf("a dry run deleted %d objects", len(store.deleted))
	}

	block := strings.Join(pruneDryRunLines(res), "")
	if definiteTotal.MatchString(block) {
		t.Errorf("the report states a definite total one line after saying the run-object count cannot be known, immediately before an irreversible delete:\n%s", block)
	}
	// The floor is still given, and marked as a floor. Saying nothing at all would be the opposite
	// failure: an operator with no number cannot size the operation either.
	wantFloor := fmt.Sprintf("at least %d", res.PlannedSegments)
	if !strings.Contains(block, wantFloor) {
		t.Errorf("the report gives no floor for the total, so the operator is left with no number at all; want %q in:\n%s", wantFloor, block)
	}
	if !strings.Contains(block, "with the uncounted run trees on top of that") {
		t.Errorf("the floor is printed without saying what is missing from it, so it reads as the total:\n%s", block)
	}
	// The run-tree line must not carry a number either, or the two lines disagree about whether the
	// count is known.
	for _, line := range pruneDryRunLines(res) {
		if strings.HasPrefix(line, "  would delete run-tree objects:") && regexp.MustCompile(`\d`).MatchString(line) {
			t.Errorf("the run-tree line carries a digit while reporting the count as uncountable: %q", line)
		}
	}
	// And the fact that decides whether any of it matters. prune.Apply refuses this destination outright
	// once --apply is passed, so a dry run that reads like every other dry run is the same block meaning
	// two different things.
	if !strings.Contains(block, "cannot be APPLIED to this destination") {
		t.Errorf("the report does not say that --apply cannot run against this destination, so a plan that can never be carried out reads as an ordinary plan:\n%s", block)
	}
	if _, err := prune.Apply(store, uncountablePlan(), false); err == nil {
		t.Fatal("prune.Apply accepted --apply against a destination it cannot list, so the report's claim that an --apply here fails is now false")
	}
}

// The control. On a destination that CAN be counted the total must stay a plain number, because that is
// what the docs page reproduces and what a downstream consumer parses. A fix that made every
// total non-numeric would pass the test above and break the contract.
func TestTheDryRunTotalIsDefiniteWhenTheRunTreesCanBeCounted(t *testing.T) {
	plan := uncountablePlan()
	store := &listingStore{keys: []string{
		"run/01RUNA/root.manifest.json",
		"run/01RUNA/root.manifest.json.sig",
		"run/01RUNB/root.manifest.json",
	}}
	res, err := prune.Apply(store, plan, true)
	if err != nil {
		t.Fatalf("dry run against a listing destination: %v", err)
	}
	if res.RunObjectsUnknown {
		t.Fatal("a destination that lists must not report the run-object count as unknown")
	}
	block := strings.Join(pruneDryRunLines(res), "")
	want := fmt.Sprintf("  would delete objects in total: %d\n", len(plan.OrphanSegments)+len(store.keys))
	if !strings.Contains(block, want) {
		t.Errorf("a countable destination must still print a plain total; want %q in:\n%s", want, block)
	}
	if strings.Contains(block, "at least") {
		t.Errorf("a countable destination printed a floor rather than a total:\n%s", block)
	}
}

// WHY THE BRANCH IS LIVE RATHER THAN LATENT.
//
// The reader ships two destinations. DirStore lists; the S3 backend implements Get and Delete and no
// List, so every dry run against --s3-endpoint takes the uncountable branch. It is not a shape that needs
// a future store to be reachable.
//
// If this test fails because every shipped destination now lists, that is good news and not a regression.
// The right response is to check whether the uncountable branch has become dead code and remove it with
// its report lines, not to loosen this assertion.
func TestTheUncountableRunTreeBranchIsReachableFromAShippedDestination(t *testing.T) {
	s3, err := source.NewS3Store(source.S3Config{
		Endpoint: "https://example.r2.cloudflarestorage.com", Bucket: "b", Region: "auto",
		AccessKeyID: "id", SecretKey: "secret",
	})
	if err != nil {
		t.Fatalf("build the shipped S3 destination: %v", err)
	}
	shipped := map[string]format.ObjectStore{
		"DirStore": source.NewDirStore(t.TempDir()),
		"S3Store":  s3,
	}
	var countless []string
	for name, store := range shipped {
		if _, ok := store.(format.ListingStore); !ok {
			countless = append(countless, name)
		}
	}
	sort.Strings(countless)
	if len(countless) == 0 {
		t.Fatal("every destination this tool ships can now list objects, so the report's uncountable branch is unreachable: check whether it is dead code and remove it with its lines, rather than weakening this test")
	}
	t.Logf("destinations with no listing, which take the uncountable branch: %s", strings.Join(countless, ", "))
}

// The block above is only worth testing while it is the block the command prints. A test that calls a
// helper leaves the binary free to stop calling it, with the package still green and the report free to
// drift, which is the exact failure this campaign has already found elsewhere.
//
// So the three counted labels of the dry-run plan must appear in exactly one function in this package's
// non-test sources, and that function is the one the tests above drive. It reads the parsed source rather
// than the text, so a label left behind in a comment does not satisfy it.
func TestTheDryRunPlanIsPrintedOnlyFromOnePlace(t *testing.T) {
	const owner = "pruneDryRunLines"
	labels := []string{
		"  would delete segments:  ",
		"  would delete run-tree objects: ",
		"  would delete objects in total: ",
	}

	_, files := commandFiles(t)
	// Which FUNCTIONS print each label: label -> set of "file func". A set, not a list: the countable
	// and uncountable branches of one function each carry the label, and two branches of one function is
	// exactly the shape this gate must allow.
	sites := map[string]map[string]bool{}
	for name, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				text, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				for _, label := range labels {
					if !strings.Contains(text, strings.TrimSpace(label)) {
						continue
					}
					if sites[label] == nil {
						sites[label] = map[string]bool{}
					}
					sites[label][name+" "+fn.Name.Name] = true
				}
				return true
			})
		}
	}

	for _, label := range labels {
		found := make([]string, 0, len(sites[label]))
		for site := range sites[label] {
			found = append(found, site)
		}
		sort.Strings(found)
		if len(found) == 0 {
			t.Fatalf("the label %q is printed nowhere in this package, so the report the docs reproduce is gone or has been renamed", strings.TrimSpace(label))
		}
		if len(found) > 1 {
			t.Errorf("the label %q is printed from %d places (%s); the dry-run plan must come from %s alone, or a test over that function no longer says what the command prints",
				strings.TrimSpace(label), len(found), strings.Join(found, ", "), owner)
			continue
		}
		if !strings.HasSuffix(found[0], " "+owner) {
			t.Errorf("the label %q is printed from %s, not from %s, so the tests over %s no longer cover what the command prints",
				strings.TrimSpace(label), found[0], owner, owner)
		}
	}
}
