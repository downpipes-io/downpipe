package prune

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// The prune receipt: a durable record of what an offline prune intended and what it actually did.
//
// WHY THIS EXISTS. `downpipe prune` is the only command in this repo that deletes a customer's archives,
// and until now it wrote nothing anywhere. Everything it knew went to stdout and died with the terminal.
// Two consequences, and the second is the sharper one.
//
// First, an operator who pruned had no record of it. In the break-glass-only posture, which is now the
// default, the offline prune is the ONLY thing that removes archives, so the estate has no in-account
// account of why its stored corpus shrank. Anything that later notices the shrinkage has nothing to
// reconcile against and must either ignore it or raise a fault the operator cannot answer.
//
// Second, and this is the failure that has no workaround: a prune that is INTERRUPTED reports nothing at
// all. Apply returns its Result only on the way out, so a pass killed midway (a closed laptop, a dropped
// SSH session, an OOM) leaves the operator knowing only that some unknown prefix of the plan ran. The
// deletion order is deliberately recoverable in the sense that it never destroys the record of what a
// segment belonged to, but recoverable is not the same as KNOWN, and nothing on disk said how far it got.
//
// WHY THIS IS NOT A format.Receipt, which is the first thing a reader should wonder. That type is a
// NORMATIVE artefact defined by SPEC.md 8.5: canonical JSON, signed by the operator's restore-session key,
// carrying the format version and the normative exit code. Adding a prune kind to it would be an amendment
// to the published format spec, which is a decision for the owner and not a convenience for this command.
// This record is operator-side only, describes an act rather than an archive, and nothing reads it as
// conformance evidence. The two must stay separate for that reason rather than by accident.
//
// So the receipt is written in two phases. The intent is recorded and flushed BEFORE the first delete, and
// rewritten with the outcome after the last one. A receipt left at StatusStarted is exactly the signal that
// a pass did not finish, and it carries the plan that pass was executing.
const (
	// StatusStarted means the plan was recorded and deletion was about to begin. A receipt still in this
	// state describes a pass that did not reach its end.
	StatusStarted = "started"
	// StatusCompleted means Apply returned and the counts below are what it did.
	StatusCompleted = "completed"
)

// ReceiptVersion is the schema version of the file. It is DELIBERATELY not tied to the archive format
// version: this is an operator-side record, not an archive artefact, and nothing about it is normative.
// Bumping it must never be read as a format change.
const ReceiptVersion = 1

// refusedSample bounds how many refused keys the receipt lists. A WORM destination can refuse every object
// in the plan, and a receipt that grows with the refusal count would be worst exactly when the operator most
// needs to open it. The full count is always recorded; the list is a sample for diagnosis.
const refusedSample = 100

// Receipt is the operator-side record of one prune pass.
type Receipt struct {
	Version int `json:"version"`
	// Status is StatusStarted or StatusCompleted. A reader that finds StatusStarted must treat every
	// "deleted" count below as unknown rather than zero, because the pass was still running when it stopped.
	// The same goes for plannedRunObjects, which is not derivable from the plan and is only computed inside
	// Apply; runObjectsUnknown says so directly and is set on the started record for that reason.
	Status string `json:"status"`
	// Mode is "dry-run" or "apply". A dry run writes a receipt too, because the plan an operator is about
	// to arm is worth keeping, and because it gives them the expected magnitude before anything is deleted.
	Mode        string `json:"mode"`
	Destination string `json:"destination"`
	StartedAt   string `json:"startedAt"`
	CompletedAt string `json:"completedAt,omitempty"`

	KeepPerDownpipe int `json:"keepPerDownpipe"`
	RunsKept        int `json:"runsKept"`
	// SupersededRuns names the runs the plan covers. Names rather than counts, because an interrupted pass
	// leaves the operator needing to know WHICH runs were in flight, and a count cannot answer that.
	SupersededRuns []string `json:"supersededRuns"`

	PlannedSegments int `json:"plannedSegments"`
	// PlannedRunObjects is how many objects the superseded run TREES hold. Unlike plannedSegments it is
	// not derivable from the plan: it needs a listing, so it is only ever computed inside Apply.
	PlannedRunObjects int `json:"plannedRunObjects"`
	// RunObjectsUnknown says that plannedRunObjects above is not a measurement, and it covers BOTH ways
	// that happens. On a completed record it means the destination could not list, so the count could not
	// be taken. On a started record it means the count had not been taken yet, because the record is
	// written before Apply runs. Status tells the two apart.
	//
	// It is set on the started record rather than left at its zero value, which is the bug this comment
	// replaces. A started receipt is the ONLY account of a pass that was interrupted partway through
	// deleting a customer's archives, and it used to read "plannedRunObjects": 0, "runObjectsUnknown":
	// false: a positive claim that the count was measured, on the one record written before anything
	// could have measured it.
	RunObjectsUnknown bool `json:"runObjectsUnknown"`

	SegmentsDeleted   int `json:"segmentsDeleted"`
	RunObjectsDeleted int `json:"runObjectsDeleted"`

	// RefusedCount is the total the destination refused; RefusedSample is a bounded list for diagnosis. A
	// refusal is Object Lock or WORM doing its job, so it is recorded rather than treated as an error, and
	// it must not be silent: it is the difference between retention that took effect and retention that
	// only appeared to.
	RefusedCount  int      `json:"refusedCount"`
	RefusedSample []string `json:"refusedSample,omitempty"`
}

// NewReceipt records the INTENT of a pass, before anything is deleted.
func NewReceipt(destination, mode string, keepPerDownpipe, runsKept int, plan *Plan, now time.Time) *Receipt {
	// Copied rather than aliased. The caller owns the plan and this record must describe the pass as it was
	// begun, not as some later mutation leaves it.
	runs := make([]string, len(plan.SupersededRuns))
	copy(runs, plan.SupersededRuns)
	return &Receipt{
		Version:         ReceiptVersion,
		Status:          StatusStarted,
		Mode:            mode,
		Destination:     destination,
		StartedAt:       now.UTC().Format(time.RFC3339),
		KeepPerDownpipe: keepPerDownpipe,
		RunsKept:        runsKept,
		SupersededRuns:  runs,
		// The segment count comes from the PLAN, so it is known before Apply runs, and it is seeded here so
		// a receipt left at StatusStarted still says how much work was outstanding. Complete overwrites it
		// with Apply's own figure, which is the same number.
		PlannedSegments: len(plan.OrphanSegments),
		// The run-object count does NOT come from the plan. It needs a listing and exists only inside
		// Apply, so at this point it is not merely zero, it is unmeasured, and the record says so rather
		// than leaving a bare 0 to be read as a plan figure. Complete replaces this with what Apply found.
		RunObjectsUnknown: true,
	}
}

// Complete folds an Apply result into the receipt and marks it finished.
func (r *Receipt) Complete(res *Result, now time.Time) {
	r.Status = StatusCompleted
	r.CompletedAt = now.UTC().Format(time.RFC3339)
	r.PlannedSegments = res.PlannedSegments
	r.PlannedRunObjects = res.PlannedRunObjects
	r.RunObjectsUnknown = res.RunObjectsUnknown
	r.SegmentsDeleted = res.SegmentsDeleted
	r.RunObjectsDeleted = res.RunObjectsDeleted
	r.RefusedCount = len(res.Refused)
	if n := len(res.Refused); n > 0 {
		if n > refusedSample {
			n = refusedSample
		}
		r.RefusedSample = append([]string(nil), res.Refused[:n]...)
	}
}

// Write persists the receipt ATOMICALLY: a temporary file in the same directory, flushed to disk, then
// renamed over the target.
//
// The atomicity is not ceremony. This file is written twice, and the second write happens at the end of a
// pass that has already deleted objects. A crash during a plain truncate-and-write would leave a partial
// file, and a partial receipt is worse than none: it would parse as JSON with some fields missing and read
// as a completed pass that deleted less than it did. Rename is atomic on POSIX, so a reader sees either the
// old contents or the new ones.
//
// The directory is synced as well as the file, because a rename that is not durable can be lost by a crash
// even though the file contents were flushed.
func (r *Receipt) Write(path string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".prune-receipt-*")
	if err != nil {
		return fmt.Errorf("create receipt temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup on every failure path below. A left-behind temp file is harmless, but it is
	// untidy in a directory an operator is looking at during an incident.
	defer func() { _ = os.Remove(tmpName) }()

	body, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encode receipt: %w", err)
	}
	body = append(body, '\n')
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write receipt: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("flush receipt: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close receipt: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("place receipt at %s: %w", path, err)
	}
	// Sync the directory so the rename itself survives a crash. Failure here is reported rather than
	// swallowed: the caller is about to delete archives on the strength of this record existing.
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open receipt directory %s: %w", dir, err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("flush receipt directory %s: %w", dir, err)
	}
	return nil
}

// ReadReceipt loads a receipt. It exists so an operator, or a later tool, can answer "did that prune
// finish?" without parsing the file by hand.
func ReadReceipt(path string) (*Receipt, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Receipt
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("parse receipt %s: %w", path, err)
	}
	// An unknown version is refused rather than read on a best-effort basis. Silently reading a future
	// receipt with fields this build does not know about would produce confident answers from partial data,
	// which is the same class of failure as reporting a dry run's zero deletions as a completed prune.
	if r.Version != ReceiptVersion {
		return nil, fmt.Errorf("receipt %s is version %d, this build understands version %d", path, r.Version, ReceiptVersion)
	}
	return &r, nil
}

// Interrupted reports whether this receipt describes a pass that never reached its end.
func (r *Receipt) Interrupted() bool { return r.Status == StatusStarted }
