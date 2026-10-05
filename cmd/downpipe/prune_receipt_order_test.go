package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/downpipes-io/downpipe/internal/prune"
)

// THE ORDER IS THE WHOLE VALUE OF THE RECEIPT, so it gets a test that can only pass if the intent reaches
// disk before the first object is deleted.
//
// This file exists because of a measured hole rather than a hunch. The receipt's own unit tests all passed
// while the pre-flight write was mutated away, because they exercise the receipt type directly and never
// the command's ordering. A receipt written only after Apply returns would be absent for exactly the pass
// that needs it: one that was interrupted partway through deleting a customer's archives.

// orderProbeStore is a destination that inspects the receipt at the moment it is first asked to delete.
type orderProbeStore struct {
	receiptPath string
	// seenAtFirstDelete is the receipt status observed when Delete was first called, or "" if no receipt
	// existed at that moment. Recorded once, because it is the first delete that matters.
	seenAtFirstDelete string
	// unknownAtFirstDelete is what that same receipt said about whether its run-object count was measured.
	// Read at this moment on purpose: this is the record an interrupted pass leaves behind, and the count
	// cannot have been taken yet, because Apply computes it and Apply is what is running.
	unknownAtFirstDelete bool
	deletes              int
}

func (s *orderProbeStore) Get(string) ([]byte, error) { return nil, fmt.Errorf("not used") }

func (s *orderProbeStore) List(string) ([]string, error) { return nil, nil }

func (s *orderProbeStore) Delete(string) error {
	if s.deletes == 0 {
		if r, err := prune.ReadReceipt(s.receiptPath); err == nil {
			s.seenAtFirstDelete = r.Status
			s.unknownAtFirstDelete = r.RunObjectsUnknown
		} else {
			s.seenAtFirstDelete = ""
		}
	}
	s.deletes++
	return nil
}

func orderTestPlan() *prune.Plan {
	return &prune.Plan{
		OrphanSegments: []string{"seg/aa/1111.seg", "seg/bb/2222.seg"},
		SupersededRuns: []string{"01RUNA"},
	}
}

func TestTheReceiptIsOnDiskBeforeTheFirstDelete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipt.json")
	store := &orderProbeStore{receiptPath: path}

	res, err := applyWithReceipt(store, orderTestPlan(), false, path, func() *prune.Receipt {
		return prune.NewReceipt("archive /a", "apply", 3, 7, orderTestPlan(), time.Now())
	})
	if err != nil {
		t.Fatalf("applyWithReceipt: %v", err)
	}
	if store.deletes == 0 {
		t.Fatal("the probe never saw a delete, so this test proved nothing about ordering")
	}
	if store.seenAtFirstDelete == "" {
		t.Fatal("no receipt existed when the first object was deleted: an interrupted pass would leave no account of itself")
	}
	if store.seenAtFirstDelete != prune.StatusStarted {
		t.Fatalf("the receipt present at the first delete must be the STARTED record, got %q", store.seenAtFirstDelete)
	}
	// And it must not claim a count it cannot have. plannedRunObjects is computed inside Apply, which is
	// mid-flight at this instant, so a receipt asserting the count was measured is asserting it about
	// work that has not happened. This is the record an interrupted pass leaves, and its whole value is
	// that a reader can tell what was known from what was not.
	if !store.unknownAtFirstDelete {
		t.Fatal("the receipt on disk at the first delete says its run-object count was measured, and Apply had not finished counting")
	}
	if res.SegmentsDeleted != 2 {
		t.Fatalf("segments deleted, got %d", res.SegmentsDeleted)
	}

	// And after the pass it must be completed, or an operator could not tell a finished prune from an
	// abandoned one.
	final, err := prune.ReadReceipt(path)
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	if final.Interrupted() {
		t.Fatalf("a pass that returned must leave a completed receipt, got %q", final.Status)
	}
}

// An unwritable receipt path must stop the pass BEFORE anything is deleted. The operator asked for a
// record; deleting archives without one is not a lesser version of what they asked for.
func TestAnUnwritableReceiptPathDeletesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "no-such-subdir", "receipt.json")
	store := &orderProbeStore{receiptPath: path}

	if _, err := applyWithReceipt(store, orderTestPlan(), false, path, func() *prune.Receipt {
		return prune.NewReceipt("archive /a", "apply", 3, 7, orderTestPlan(), time.Now())
	}); err == nil {
		t.Fatal("an unwritable receipt path must fail the pass")
	}
	if store.deletes != 0 {
		t.Fatalf("nothing may be deleted when the receipt could not be written, got %d deletes", store.deletes)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("no receipt should have been created at an unwritable path")
	}
}

// Without --receipt the command must behave exactly as before. The flag is opt-in, and a prune that ran
// fine yesterday must not start failing because no path was given.
func TestNoReceiptPathStillPrunes(t *testing.T) {
	store := &orderProbeStore{receiptPath: filepath.Join(t.TempDir(), "absent.json")}
	res, err := applyWithReceipt(store, orderTestPlan(), false, "", func() *prune.Receipt {
		t.Fatal("the receipt constructor must not run when no path was given")
		return nil
	})
	if err != nil {
		t.Fatalf("applyWithReceipt: %v", err)
	}
	if res.SegmentsDeleted != 2 {
		t.Fatalf("the prune must still run without a receipt, got %d", res.SegmentsDeleted)
	}
}
