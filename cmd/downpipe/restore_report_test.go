package main

import (
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/restore"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// TestReportReprovisionAndD1GuidanceOnDiscard exercises the reprovision-guidance and
// D1-replay-guidance output branches that the selftest archive never reaches: that archive
// holds a single kv record, so it produces neither a Reprovision item nor HasD1File. The
// command's reportDiscard fans out to reportReprovision and reportD1, so a Plan carrying a
// workers (reprovision) record and HasD1File must surface both the reprovision line and the
// exact D1 replay command on stderr. A regression in that guidance text would otherwise be
// invisible to the suite.
func TestReportReprovisionAndD1GuidanceOnDiscard(t *testing.T) {
	plan := &restore.Plan{
		Kind: "discard",
		Reprovision: []restore.Reprovision{{
			Name:       "my-worker",
			Key:        "my-worker",
			SourceType: spec.SourceWorkers,
			Guidance:   restore.GuidanceFor(spec.ShardRecord{SourceType: spec.SourceWorkers, Name: "my-worker"}),
		}},
		HasD1File: true,
	}
	result := &restore.Result{Kind: "discard"}
	target := restore.NewDiscardTarget()

	_, stderr := captureOutput(t, func() {
		reportRestoreOutcome(target, plan, result, true)
	})

	if !strings.Contains(stderr, "restore by re-provisioning, not a live re-apply") {
		t.Fatalf("stderr must carry the reprovision header, got: %q", stderr)
	}
	if !strings.Contains(stderr, "reprovision [workers] \"my-worker\"") {
		t.Fatalf("stderr must name the reprovision record, got: %q", stderr)
	}
	if !strings.Contains(stderr, "wrangler deploy") {
		t.Fatalf("stderr must carry the workers reprovision guidance, got: %q", stderr)
	}
	if !strings.Contains(stderr, "d1 dump(s) planned as .sql") {
		t.Fatalf("stderr must carry the D1 dump line, got: %q", stderr)
	}
	if !strings.Contains(stderr, restore.D1ReplayGuidance()) {
		t.Fatalf("stderr must carry the exact D1 replay guidance, got: %q", stderr)
	}
}

// TestReportReprovisionAndD1GuidanceOnFileSink covers the same two branches through the file
// sink path: reportRestore (not reportDiscard) also fans out to reportReprovision and
// reportD1, so the guidance must appear there too.
func TestReportReprovisionAndD1GuidanceOnFileSink(t *testing.T) {
	plan := &restore.Plan{
		Kind: "file",
		Reprovision: []restore.Reprovision{{
			Name:       "config-surface",
			Key:        "config-surface",
			SourceType: spec.SourceCFConfig,
			Guidance:   restore.GuidanceFor(spec.ShardRecord{SourceType: spec.SourceCFConfig, Name: "config-surface"}),
		}},
		HasD1File: true,
	}
	result := &restore.Result{Kind: "file"}
	target := restore.NewDirTarget(t.TempDir())

	_, stderr := captureOutput(t, func() {
		reportRestoreOutcome(target, plan, result, true)
	})

	if !strings.Contains(stderr, "reprovision [cf-config] \"config-surface\"") {
		t.Fatalf("stderr must name the cf-config reprovision record, got: %q", stderr)
	}
	if !strings.Contains(stderr, "d1 dump(s) planned as .sql") {
		t.Fatalf("stderr must carry the D1 dump line on a file sink, got: %q", stderr)
	}
}

// TestReportReprovisionOnlyNoticeOnFileSink proves the EXPLAIN fix: when an apply leaves
// reprovision-only records (verified, but their courtesy file-write could not be laid down,
// the Worker content vs settings/versions path collision), the file-sink report shows a
// DISTINCT notice with per-record guidance rather than counting them as generic failures, so
// an operator reading an exit-zero restore understands why some bytes were not written as
// plain files. It must not present a reprovision-only record under the "failed" wording.
func TestReportReprovisionOnlyNoticeOnFileSink(t *testing.T) {
	plan := &restore.Plan{
		Kind:   "file",
		Writes: []restore.PlannedWrite{{Name: "engine", Key: "engine", Bytes: 6}},
	}
	result := &restore.Result{
		Kind:     "file",
		Restored: 1,
		Reprovisioned: []restore.RecordReprovision{{
			Name:       "engine/settings",
			Key:        "engine/settings",
			SourceType: spec.SourceWorkers,
			Guidance:   restore.GuidanceFor(spec.ShardRecord{SourceType: spec.SourceWorkers, Name: "engine/settings"}),
			Reason:     "create directory for engine/settings: mkdir /out/engine: not a directory",
		}},
	}
	target := restore.NewDirTarget(t.TempDir())

	_, stderr := captureOutput(t, func() {
		reportRestoreOutcome(target, plan, result, true)
	})

	// The summary line counts the reprovision-only records separately from failures.
	if !strings.Contains(stderr, "1 reprovision-only") {
		t.Fatalf("the apply summary must count reprovision-only records distinctly, got: %q", stderr)
	}
	// A distinct headline explains the exit-zero outcome.
	if !strings.Contains(stderr, "restore via reprovision, not a plain file write") {
		t.Fatalf("stderr must carry the distinct reprovision-only notice, got: %q", stderr)
	}
	// The per-record reprovision-only line names the record and says it was verified.
	if !strings.Contains(stderr, "reprovision-only [workers] \"engine/settings\"") {
		t.Fatalf("stderr must name the reprovision-only record, got: %q", stderr)
	}
	if !strings.Contains(stderr, "verified, file not written") {
		t.Fatalf("the reprovision-only line must state the bytes were verified, got: %q", stderr)
	}
	// It must NOT be reported under the generic failure wording.
	if strings.Contains(stderr, "failed \"engine/settings\"") {
		t.Fatalf("a reprovision-only record must not be reported as a failure, got: %q", stderr)
	}
}

// TestReportRestorePlanLineNeverClaimsAWriteBeforeTheOutcomeIsKnown pins the fix:
// the pre-run "plan" line must never assert "wrote" (a completed action) for the planned
// byte count, in either dry-run or apply mode, because it is printed before the actual
// outcome — success or failure — is reported. This reproduces the exact case that exposed
// the defect: an --apply run whose only record fails outright (e.g. a truncated segment),
// so the plan line's old "wrote" wording read as success while the very next line reported
// zero bytes restored and one failure. A customer reading this on the offline recovery
// path, under stress, must never be able to read the first line as a completed write.
func TestReportRestorePlanLineNeverClaimsAWriteBeforeTheOutcomeIsKnown(t *testing.T) {
	plan := &restore.Plan{
		Kind:       "file",
		WriteCount: 1,
		TotalBytes: 196708,
		Writes:     []restore.PlannedWrite{{Name: "object-big", Key: "object-big", Bytes: 196708}},
	}
	result := &restore.Result{
		Kind:   "file",
		Failed: []restore.RecordFailure{{Name: "object-big", Key: "object-big", Reason: "open segment: chunk 3 authentication failed: cipher: message authentication failed"}},
	}
	target := restore.NewDirTarget(t.TempDir())

	_, stderr := captureOutput(t, func() {
		reportRestoreOutcome(target, plan, result, true)
	})

	if strings.Contains(stderr, "wrote") {
		t.Fatalf("the pre-run plan line must never claim a completed write, got: %q", stderr)
	}
	if !strings.Contains(stderr, "plan (file target): 1 record(s), 196708 byte(s) planned, 0 conflict(s)") {
		t.Fatalf("the plan line must state the planned counts without a completion verb, got: %q", stderr)
	}
	if !strings.Contains(stderr, "restored 0 record(s), 0 byte(s); 0 reprovision-only, 1 failed, 0 conflict(s) skipped") {
		t.Fatalf("the post-run summary must still report the true outcome, got: %q", stderr)
	}

	// The dry-run path must not say "wrote" either: "would write" was already gone from
	// the pre-run line's wording after the fix, but pin it directly so a regression that
	// reintroduces a verb here is caught in both modes.
	_, dryStderr := captureOutput(t, func() {
		reportRestoreOutcome(target, plan, &restore.Result{Kind: "file"}, false)
	})
	if strings.Contains(dryStderr, "wrote") || strings.Contains(dryStderr, "would write") {
		t.Fatalf("the dry-run plan line must not use a write-completion verb, got: %q", dryStderr)
	}
	if !strings.Contains(dryStderr, "dry run: nothing was written") {
		t.Fatalf("dry-run must still say nothing was written, got: %q", dryStderr)
	}
}
