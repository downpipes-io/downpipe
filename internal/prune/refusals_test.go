package prune

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This covers the refusal half of prune's behaviour: the part an operator meets only when
// the destination or the receipt path is not what they assumed. This is the one command in
// the repo that deletes a customer's archives, so what it says when it declines to proceed
// is the whole of what the operator has to act on.
//
// Every assertion below is on the SPECIFIC refusal, never on a non-nil error. An error-only
// assertion passes when the command refuses for the wrong reason, and here the wrong reason
// would send an operator to check bucket permissions when their real problem is a receipt path.

// wantRefusal asserts what the operator is told, not merely that they were told something.
func wantRefusal(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no refusal at all, want one saying %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("the refusal reads %q, want it to say %q", err, want)
	}
}

// TestApplyRefusesADestinationThatCannotDelete covers the capability refusal on the arming
// path. A dry run against such a destination is fine and already tested; an --apply is not,
// and the operator has to be told the destination is the reason rather than left to read a
// pass that deleted nothing as a pass that found nothing.
func TestApplyRefusesADestinationThatCannotDelete(t *testing.T) {
	plan := &Plan{OrphanSegments: []string{"seg/aa/dead.seg"}}
	res, err := Apply(getOnlyStore{}, plan, false)
	wantRefusal(t, err, "this destination cannot delete objects, so a prune cannot be applied to it")
	if res != nil {
		t.Fatalf("a refused apply must return no result, got %+v", res)
	}
}

// listErrorStore can delete and can list, but every listing fails. It stands in for a
// destination that is reachable for writes and not for enumeration, which is what a scoped
// credential missing the list permission looks like.
type listErrorStore struct {
	deleted []string
}

func (s *listErrorStore) Get(key string) ([]byte, error) {
	return nil, fmt.Errorf("object %s is missing", key)
}

func (s *listErrorStore) Delete(key string) error {
	s.deleted = append(s.deleted, key)
	return nil
}

func (s *listErrorStore) List(string) ([]string, error) {
	return nil, fmt.Errorf("status 403")
}

// TestApplyStopsWhenARunTreeCannotBeListed covers the listing failure inside the run-tree
// phase, which is a different moment from the capability check above: the store said it could
// list, the segments have already been deleted, and only then does the enumeration fail. The
// refusal names the run so the operator knows which tree was left behind, and the segments
// deleted before it stay deleted, which is safe by the ordering rule (a run tree pointing at
// segments already gone is detectable; the reverse is unreclaimable).
func TestApplyStopsWhenARunTreeCannotBeListed(t *testing.T) {
	store := &listErrorStore{}
	plan := &Plan{
		OrphanSegments: []string{"seg/aa/dead.seg"},
		SupersededRuns: []string{"run-2026-08-04"},
	}
	res, err := Apply(store, plan, false)
	wantRefusal(t, err, "list run tree run-2026-08-04: status 403")
	if res != nil {
		t.Fatalf("a refused apply must return no result, got %+v", res)
	}
	if len(store.deleted) != 1 || store.deleted[0] != "seg/aa/dead.seg" {
		t.Fatalf("the orphan segments deleted before the listing failed = %v, want exactly the one planned segment", store.deleted)
	}
}

// overreachingStore returns a key from OUTSIDE the prefix it was asked for, which is what a
// store with a prefix bug, or one answering a different question than it was asked, looks
// like from here.
type overreachingStore struct {
	extra   string
	deleted []string
}

func (s *overreachingStore) Get(key string) ([]byte, error) {
	return nil, fmt.Errorf("object %s is missing", key)
}

func (s *overreachingStore) Delete(key string) error {
	s.deleted = append(s.deleted, key)
	return nil
}

func (s *overreachingStore) List(prefix string) ([]string, error) {
	return []string{prefix + "root.manifest.json", s.extra}, nil
}

// TestApplyNeverDeletesOutsideTheRunTreeItWasGiven covers the defence in depth against a
// listing that returns more than it should. This is the one uncovered branch in the package
// that is not a message at all: it is a silent skip, and a silent skip is exactly the kind of
// guard that can be deleted by a later refactor without any test going red. The consequence if
// it were absent is the worst this repo has: a store handing back a key belonging to a
// RETAINED run would see that run's archives deleted, and no other check stands between the
// listing and the delete.
func TestApplyNeverDeletesOutsideTheRunTreeItWasGiven(t *testing.T) {
	store := &overreachingStore{extra: "run/keep-me/root.manifest.json"}
	plan := &Plan{SupersededRuns: []string{"drop-me"}}
	res, err := Apply(store, plan, false)
	if err != nil {
		t.Fatalf("an over-returning listing is skipped, not fatal: %v", err)
	}
	for _, k := range store.deleted {
		if !strings.HasPrefix(k, RunTreePrefix("drop-me")) {
			t.Fatalf("deleted %q, which is outside the run tree %q that was planned for removal", k, RunTreePrefix("drop-me"))
		}
	}
	if res.PlannedRunObjects != 1 || res.RunObjectsDeleted != 1 {
		t.Fatalf("planned %d and deleted %d run objects, want 1 and 1: the out-of-prefix key must be counted in neither",
			res.PlannedRunObjects, res.RunObjectsDeleted)
	}
}

// TestAbstainSaysWhyItAbstained covers Abstain's own message. Abstain is a distinct type
// precisely so "I could not see enough to be safe" cannot be read as "there is nothing to do",
// and the message is the only place that distinction is spelled out for the operator reading
// the terminal. It had no test, so the type carried the safety and the sentence carried
// nothing.
func TestAbstainSaysWhyItAbstained(t *testing.T) {
	err := &Abstain{RunID: "run-2026-08-04"}
	wantRefusal(t, err, "abstained: retained run run-2026-08-04 could not be fully enumerated, so its live segments cannot be distinguished from orphans")
}

// TestComputeCarriesTheEnumerationReasonIntoTheAbstain pins the cause reaching the message.
//
// The caller used to discard the error that refused to open the run, so the only thing left to say was
// the commonest cause, and the sentence it printed named the identity. A formatVersion this reader does
// not implement abstains here exactly as a wrong key does, and the identity is never read on that path
// at all. Compute is where the reason has to survive, because it is the boundary between the code that
// knows why and the code that prints.
func TestComputeCarriesTheEnumerationReasonIntoTheAbstain(t *testing.T) {
	const reason = `formatVersion "downpipe/9.0.0": this reader implements downpipe/0.1.x and does not implement 9.0`
	_, err := Compute([]RunRefs{{RunID: "run-keep", Reason: reason}}, nil)
	var ab *Abstain
	if !errors.As(err, &ab) {
		t.Fatalf("Compute over an incomplete retained run = %v, want an *Abstain", err)
	}
	if ab.Reason != reason {
		t.Errorf("Abstain.Reason = %q, want the enumeration reason carried through", ab.Reason)
	}
	if !strings.Contains(ab.Error(), reason) {
		t.Errorf("the abstain message must carry the measured cause, got %q", ab.Error())
	}
}

// TestAbstainWithNoReasonDoesNotInventOne is the control. An abstain whose cause the caller genuinely
// could not determine must read as a plain abstain, not gain a trailing colon or an empty clause.
func TestAbstainWithNoReasonDoesNotInventOne(t *testing.T) {
	msg := (&Abstain{RunID: "run-keep"}).Error()
	if strings.HasSuffix(msg, ":") || strings.Contains(msg, "orphans:") {
		t.Errorf("an abstain with no reason must not trail a colon, got %q", msg)
	}
}

// TestReceiptWriteRefusesAPathItCannotPlaceTheFileAt covers the rename failure, which is what
// an operator pointing the receipt at a directory rather than a file gets. It matters because
// the receipt is written BEFORE the first delete: a failure here must stop the pass with a
// message about the receipt path, not leave the operator hunting the destination.
func TestReceiptWriteRefusesAPathItCannotPlaceTheFileAt(t *testing.T) {
	base := t.TempDir()
	occupied := filepath.Join(base, "receipt.json")
	if err := os.Mkdir(occupied, 0o755); err != nil {
		t.Fatal(err)
	}
	// Non-empty, so the rename fails the same way on every platform this binary ships for.
	if err := os.WriteFile(filepath.Join(occupied, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &Receipt{Version: ReceiptVersion, Status: StatusStarted}
	wantRefusal(t, r.Write(occupied), "place receipt at "+occupied)

	// The temp file is cleaned up on the failure path: a directory an operator is reading
	// during an incident must not fill with half-written receipts.
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".prune-receipt-") {
			t.Fatalf("a failed write left the temp file %q behind", e.Name())
		}
	}
}

// TestReadReceiptRefusesAFileItCannotParse covers the parse failure. A receipt is read to
// answer "did that prune finish?", so a file that is not a receipt has to say so and name
// itself: the likeliest cause is the operator giving the path of a different file, and a
// message that does not name the path leaves them nothing to compare.
func TestReadReceiptRefusesAFileItCannotParse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(path, []byte("this is not a receipt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := ReadReceipt(path)
	wantRefusal(t, err, "parse receipt "+path)
	if r != nil {
		t.Fatalf("a receipt that could not be parsed must be returned as nil, got %+v", r)
	}
}

// SIX REFUSALS IN Receipt.Write REMAIN UNCOVERED AND ARE RECORDED HERE RATHER THAN LEFT AS
// SILENT DEBT. They are the failures of the durable-write sequence itself: the marshal, the
// temp-file write, its Sync, its Close, opening the containing directory, and syncing that
// directory. None can be reached from a test in this process without injecting a filesystem
// seam into Write, and adding one would mean changing the code to make a branch reachable,
// which is not a trade worth making for a sequence whose whole point is to use the real
// syscalls.
//
// One of the six is unreachable for a stronger reason than "hard to induce": the marshal
// cannot fail at all, because every field of Receipt is an int, a string, a bool or a
// []string, and encoding/json has no failure mode over those. That is a property of the
// struct rather than of the test, so it is asserted below: if a later field ever makes the
// receipt unmarshalable, this goes red and the claim above stops being true out loud.
func TestAFullyPopulatedReceiptAlwaysMarshals(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt.json")
	r := &Receipt{
		Version:           ReceiptVersion,
		Status:            StatusCompleted,
		Mode:              "apply",
		Destination:       "s3://bucket/prefix",
		StartedAt:         "2026-08-04T21:00:00Z",
		CompletedAt:       "2026-08-04T21:04:00Z",
		KeepPerDownpipe:   3,
		RunsKept:          3,
		SupersededRuns:    []string{"run-a", "run-b"},
		PlannedSegments:   12,
		PlannedRunObjects: 7,
		RunObjectsUnknown: false,
		SegmentsDeleted:   12,
		RunObjectsDeleted: 7,
		RefusedCount:      2,
		RefusedSample:     []string{"seg/aa/locked.seg", "seg/bb/locked.seg"},
	}
	if err := r.Write(path); err != nil {
		t.Fatalf("a receipt with every field set must write: %v", err)
	}
	back, err := ReadReceipt(path)
	if err != nil {
		t.Fatalf("the receipt just written must read back: %v", err)
	}
	if back.RefusedCount != r.RefusedCount || len(back.RefusedSample) != len(r.RefusedSample) {
		t.Fatalf("the refusal record did not survive the round trip: wrote count %d sample %v, read count %d sample %v",
			r.RefusedCount, r.RefusedSample, back.RefusedCount, back.RefusedSample)
	}
}
