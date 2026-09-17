package prune

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testPlan() *Plan {
	return &Plan{
		OrphanSegments:    []string{"seg/aa/1111.seg", "seg/bb/2222.seg", "seg/cc/3333.seg"},
		SupersededRuns:    []string{"01RUNA", "01RUNB"},
		SkippedSuperseded: []string{"01RUNC"},
	}
}

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// THE TEST THAT MATTERS MOST. A pass that is interrupted returns no Result, so the only account of it is
// whatever was on disk before the deletes began. If the intent were recorded after Apply instead of before
// it, this file would not exist at all and the operator would have no idea which runs were in flight.
func TestInterruptedPassLeavesAStartedReceiptCarryingThePlan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipt.json")

	// Exactly what the command does before deleting anything, and then nothing further: this IS the
	// interruption.
	r := NewReceipt("archive /tmp/arch", "apply", 3, 7, testPlan(), at("2026-07-28T01:02:03Z"))
	if err := r.Write(path); err != nil {
		t.Fatalf("write: %v", err)
	}

	back, err := ReadReceipt(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !back.Interrupted() {
		t.Fatalf("a pass that never completed must read as interrupted, got status %q", back.Status)
	}
	if back.CompletedAt != "" {
		t.Fatalf("an interrupted pass must carry no completion time, got %q", back.CompletedAt)
	}
	// The run ids are the point. A count cannot answer "which runs were being deleted when it stopped".
	if got := strings.Join(back.SupersededRuns, ","); got != "01RUNA,01RUNB" {
		t.Fatalf("the receipt must name the runs the pass was working on, got %q", got)
	}
	if back.PlannedSegments != 3 {
		t.Fatalf("an interrupted receipt must still say how much work was outstanding, got %d", back.PlannedSegments)
	}
	// And it must NOT claim deletions it cannot know about.
	if back.SegmentsDeleted != 0 || back.RunObjectsDeleted != 0 {
		t.Fatalf("an interrupted receipt must not report deletions, got %d/%d", back.SegmentsDeleted, back.RunObjectsDeleted)
	}
}

func TestCompletedPassRecordsWhatApplyActuallyDid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipt.json")

	r := NewReceipt("s3 https://ep/bucket", "apply", 3, 7, testPlan(), at("2026-07-28T01:02:03Z"))
	if err := r.Write(path); err != nil {
		t.Fatalf("write started: %v", err)
	}
	r.Complete(&Result{
		SegmentsDeleted: 2, RunObjectsDeleted: 5,
		PlannedSegments: 3, PlannedRunObjects: 6,
		Refused: []string{"seg/cc/3333.seg"},
	}, at("2026-07-28T01:05:00Z"))
	if err := r.Write(path); err != nil {
		t.Fatalf("write completed: %v", err)
	}

	back, err := ReadReceipt(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if back.Interrupted() || back.Status != StatusCompleted {
		t.Fatalf("status must be completed, got %q", back.Status)
	}
	if back.CompletedAt != "2026-07-28T01:05:00Z" {
		t.Fatalf("completion time, got %q", back.CompletedAt)
	}
	if back.SegmentsDeleted != 2 || back.RunObjectsDeleted != 5 {
		t.Fatalf("deleted counts, got %d/%d", back.SegmentsDeleted, back.RunObjectsDeleted)
	}
	// The shortfall an operator must be able to compute: planned minus deleted is what the destination kept.
	if short := (back.PlannedSegments + back.PlannedRunObjects) - (back.SegmentsDeleted + back.RunObjectsDeleted); short != 2 {
		t.Fatalf("the receipt must let the shortfall be computed, got %d", short)
	}
	if back.RefusedCount != 1 || len(back.RefusedSample) != 1 {
		t.Fatalf("a WORM refusal must be recorded, got count=%d sample=%d", back.RefusedCount, len(back.RefusedSample))
	}
}

// A destination that refuses everything must not produce a receipt that grows without bound, and it must
// still report the true total. Losing the count to keep the file small would be the dishonest half.
func TestRefusalsAreBoundedButTheCountIsNot(t *testing.T) {
	many := make([]string, refusedSample+250)
	for i := range many {
		many[i] = "seg/aa/refused.seg"
	}
	r := NewReceipt("archive /a", "apply", 1, 1, testPlan(), at("2026-07-28T00:00:00Z"))
	r.Complete(&Result{Refused: many}, at("2026-07-28T00:00:01Z"))

	if r.RefusedCount != refusedSample+250 {
		t.Fatalf("the full refusal count must survive, got %d", r.RefusedCount)
	}
	if len(r.RefusedSample) != refusedSample {
		t.Fatalf("the sample must be bounded to %d, got %d", refusedSample, len(r.RefusedSample))
	}
}

// The write must never truncate the target before it has the new bytes. If it did, a failure part-way
// would destroy the "started" record at exactly the moment it is the only account of a pass that has
// already deleted objects.
func TestAFailedWriteLeavesThePreviousReceiptIntact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipt.json")

	r := NewReceipt("archive /a", "apply", 3, 7, testPlan(), at("2026-07-28T01:02:03Z"))
	if err := r.Write(path); err != nil {
		t.Fatalf("write: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}

	// Make the directory unwritable so the temp file cannot be created. This is the closest faithful stand
	// in for a full disk or a revoked permission part-way through a pass.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()

	r.Complete(&Result{SegmentsDeleted: 99}, at("2026-07-28T01:05:00Z"))
	if err := r.Write(path); err == nil {
		t.Skip("this filesystem allowed the write despite a read-only directory, so the failure path cannot be exercised here")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the previous receipt must still be readable after a failed write: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("a failed write must leave the previous receipt byte-identical")
	}
	// And it must still be the STARTED record, not a half-written completed one.
	var parsed Receipt
	if err := json.Unmarshal(after, &parsed); err != nil {
		t.Fatalf("the surviving receipt must still be valid JSON: %v", err)
	}
	if parsed.Status != StatusStarted {
		t.Fatalf("the surviving receipt must still read as started, got %q", parsed.Status)
	}
}

// A receipt from a build that knows more fields must not be read on a best-effort basis: partial data
// producing confident answers is the same class of failure as a dry run reporting zero deletions as a
// completed prune.
func TestAnUnknownVersionIsRefusedRatherThanGuessedAt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipt.json")
	if err := os.WriteFile(path, []byte(`{"version":99,"status":"completed"}`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := ReadReceipt(path); err == nil {
		t.Fatal("a receipt from an unknown version must be refused, not read")
	}
}

// A dry run writes a receipt too. It is the plan the operator is about to arm, and it is the figure they
// need before anything is deleted rather than after.
func TestADryRunReceiptRecordsThePlanAndNoDeletions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipt.json")

	r := NewReceipt("archive /a", "dry-run", 3, 7, testPlan(), at("2026-07-28T01:02:03Z"))
	r.Complete(&Result{PlannedSegments: 3, PlannedRunObjects: 6, RunObjectsUnknown: false}, at("2026-07-28T01:02:04Z"))
	if err := r.Write(path); err != nil {
		t.Fatalf("write: %v", err)
	}
	back, err := ReadReceipt(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if back.Mode != "dry-run" {
		t.Fatalf("mode, got %q", back.Mode)
	}
	if back.SegmentsDeleted != 0 || back.RunObjectsDeleted != 0 {
		t.Fatalf("a dry run must record no deletions, got %d/%d", back.SegmentsDeleted, back.RunObjectsDeleted)
	}
	if back.PlannedSegments != 3 || back.PlannedRunObjects != 6 {
		t.Fatalf("a dry run must record what it WOULD delete, got %d/%d", back.PlannedSegments, back.PlannedRunObjects)
	}
}

// The plan is copied at NewReceipt, so a later mutation of the caller's plan cannot rewrite history.
func TestTheReceiptDoesNotAliasTheCallersPlan(t *testing.T) {
	plan := testPlan()
	r := NewReceipt("archive /a", "apply", 1, 1, plan, at("2026-07-28T00:00:00Z"))
	plan.SupersededRuns[0] = "MUTATED"
	if r.SupersededRuns[0] != "01RUNA" {
		t.Fatalf("the receipt must describe the pass as it began, got %q", r.SupersededRuns[0])
	}
}

// A STARTED RECEIPT MUST NOT CLAIM A COUNT IT COULD NOT HAVE TAKEN.
//
// The started record is written and flushed BEFORE the first delete, and it is the only account of a pass
// that was interrupted partway through deleting a customer's archives. It used to carry
//
//	"plannedSegments": 3, "plannedRunObjects": 0, "runObjectsUnknown": false
//
// where the first is a real plan figure and the second is not. plannedRunObjects is not derivable from the
// plan at all: it needs a listing, and it is only ever computed inside Apply, which has not run. So the
// record positively asserted, via the very flag that exists to carry this distinction, that a count was
// measured on the one record written before anything could have measured it.
//
// The Status doc scoped its caveat to the "deleted" counts, so a reader following it read
// plannedRunObjects as a plan figure.
func TestAStartedReceiptDoesNotClaimItsRunObjectCountWasMeasured(t *testing.T) {
	plan := &Plan{
		OrphanSegments: []string{"seg/aa/1111.seg", "seg/bb/2222.seg", "seg/cc/3333.seg"},
		SupersededRuns: []string{"01RUNA", "01RUNB"},
	}
	started := NewReceipt("archive /a", "apply", 3, 7, plan, time.Now())

	if started.Status != StatusStarted {
		t.Fatalf("this test is about the started record, got %q", started.Status)
	}
	// The premise: the count really is a bare zero at this point, so the flag is the only thing that can
	// tell a reader not to trust it.
	if started.PlannedRunObjects != 0 {
		t.Fatalf("plannedRunObjects is %d before Apply has run; it cannot be known here and this test is pinned to the wrong shape", started.PlannedRunObjects)
	}
	if !started.RunObjectsUnknown {
		t.Error("the started record claims its run-object count was measured, on the record written before anything could have measured it")
	}
	// The segment count IS known from the plan, and must stay known. A fix that marked everything unknown
	// would pass the check above and lose the one planned figure an interrupted pass can report.
	if started.PlannedSegments != len(plan.OrphanSegments) {
		t.Errorf("plannedSegments = %d, want %d: this one does come from the plan", started.PlannedSegments, len(plan.OrphanSegments))
	}

	// Through the file, because the file is what an operator reconciling an interrupted pass reads.
	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := started.Write(path); err != nil {
		t.Fatalf("write: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(raw), `"runObjectsUnknown": true`) {
		t.Errorf("the file an operator opens does not carry the unknown marker:\n%s", raw)
	}

	// The control: Complete must replace the marker with what Apply actually found, or the flag would be
	// pinned true for ever and stop meaning anything on the completed record.
	started.Complete(&Result{PlannedSegments: 3, PlannedRunObjects: 9, SegmentsDeleted: 3, RunObjectsDeleted: 9}, time.Now())
	if started.RunObjectsUnknown {
		t.Error("a completed record whose Apply counted the run objects still says the count is unknown")
	}
	if started.PlannedRunObjects != 9 {
		t.Errorf("plannedRunObjects = %d after Complete, want 9", started.PlannedRunObjects)
	}
	// And the other way: a completed record whose Apply genuinely could not count must keep saying so.
	uncountable := NewReceipt("s3 bucket", "dry-run", 3, 7, plan, time.Now())
	uncountable.Complete(&Result{PlannedSegments: 3, RunObjectsUnknown: true}, time.Now())
	if !uncountable.RunObjectsUnknown {
		t.Error("a completed record whose destination could not list must still say the run-object count is unknown")
	}
}
