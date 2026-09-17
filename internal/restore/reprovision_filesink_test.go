package restore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// workersValues is the three-records-per-script shape the Workers source emits (SPEC.md
// 12.1): the bundle bytes under the bare script name, plus a settings and a versions record
// nested under it. On a file sink the bare name `engine` is written as a file, so its
// `engine/settings` and `engine/versions` siblings cannot also create the directory `engine`:
// a filesystem cannot hold `engine` as both a file and a directory. This is the path collision
// the restore must report as reprovision-only rather than a generic failure.
var workersValues = map[string]string{
	"engine":          "worker-bundle-bytes",
	"engine/settings": `{"bindings":[],"compatibility_date":"2026-06-06"}`,
	"engine/versions": `{"versions":["v1","v2"]}`,
}

// TestWorkersArchiveReprovisionDistinctExitsZero proves the fix for the confirmed bug: a real
// signed, encrypted Workers archive restored to a file sink no longer reports its content vs
// settings/versions path collision as "N planned record(s) failed to restore". The content
// record's verified bytes are written for the operator (so they have the bundle to re-deploy),
// the two siblings that genuinely cannot share that path are recorded distinctly as
// reprovision-only (verified, restore by deliberate re-provisioning), and because no record is
// a real failure the apply is OK() so the command exits zero. This binds the behaviour to the
// real break-glass decrypt and verify path, not a fake reader.
func TestWorkersArchiveReprovisionDistinctExitsZero(t *testing.T) {
	store := memStore{}
	identity, verifier, runID := buildArchive(t, store, "dp_workers", spec.SourceWorkers, workersValues)

	r, err := format.Open(store, runID, identity, verifier, format.Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	dir := t.TempDir()
	plan, res, err := Apply(r, NewDirTarget(dir), true)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	// No genuine failure, so the apply is OK and the command exits zero (cmdRestore returns a
	// non-zero ExitError only when !result.OK()).
	if !res.OK() {
		t.Fatalf("a Workers archive whose only non-written records are reprovision-only must be OK, failed=%+v", res.Failed)
	}
	if len(res.Failed) != 0 {
		t.Fatalf("no record should be a real failure, got %+v", res.Failed)
	}
	if res.IntegrityExit != 0 {
		t.Fatalf("no integrity failure, IntegrityExit=%d", res.IntegrityExit)
	}

	// The content record's verified bytes are on disk for the operator to re-deploy from.
	if res.Restored != 1 {
		t.Fatalf("the content record should be written, Restored=%d", res.Restored)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "engine")); string(got) != workersValues["engine"] {
		t.Fatalf("the verified Worker bundle was not written for the operator: %q", got)
	}

	// The two siblings that cannot share the content record's path are reprovision-only, NOT
	// failures, and each carries non-empty guidance so the operator re-provisions deliberately.
	if len(res.Reprovisioned) != 2 {
		t.Fatalf("settings and versions must be reprovision-only, got %d: %+v", len(res.Reprovisioned), res.Reprovisioned)
	}
	wantNames := map[string]bool{"engine/settings": false, "engine/versions": false}
	for _, rp := range res.Reprovisioned {
		if _, ok := wantNames[rp.Name]; !ok {
			t.Fatalf("unexpected reprovision-only record %q", rp.Name)
		}
		wantNames[rp.Name] = true
		if rp.SourceType != spec.SourceWorkers {
			t.Errorf("reprovision-only %q sourceType = %q, want workers", rp.Name, rp.SourceType)
		}
		if rp.Guidance == "" {
			t.Errorf("reprovision-only %q has no guidance; the operator would see a blank note", rp.Name)
		}
		// The reason is the structural file-sink path collision, not an integrity verdict.
		if !strings.Contains(rp.Reason, "not a directory") {
			t.Errorf("reprovision-only %q reason = %q, want the path-collision reason", rp.Name, rp.Reason)
		}
	}
	for name, seen := range wantNames {
		if !seen {
			t.Errorf("expected %q among the reprovision-only records", name)
		}
	}

	// All three workers records are surfaced with plan-level guidance regardless of whether
	// their bytes landed, so the operator always sees the re-provision instructions.
	if len(plan.Reprovision) != 3 {
		t.Fatalf("all three workers records must carry plan reprovision guidance, got %d", len(plan.Reprovision))
	}
}

// TestCorruptedWorkersRecordStillFailsNonZero is the integrity guard: a corrupted reprovision
// record must STILL fail and exit non-zero, never be laundered into the reprovision-only list.
// It builds the same real Workers archive, corrupts every sealed segment so each record's AEAD
// verification fails, and asserts every record lands in Failed (not Reprovisioned), the apply
// is not OK, and the normative integrity exit is propagated. A reprovision record's verify is
// the integrity gate; only a record that PASSES verify but cannot be file-written is
// reprovision-only.
func TestCorruptedWorkersRecordStillFailsNonZero(t *testing.T) {
	store := memStore{}
	identity, verifier, runID := buildArchive(t, store, "dp_workers_bad", spec.SourceWorkers, workersValues)

	r, err := format.Open(store, runID, identity, verifier, format.Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	// Corrupt every sealed segment's last byte so AEAD verification fails on restore. Open does
	// not decrypt segments, so the corruption surfaces at apply time through RestoreRecord.
	corrupted := 0
	for k := range store {
		if strings.HasSuffix(k, ".seg") {
			b := append([]byte(nil), store[k]...)
			b[len(b)-1] ^= 0xFF
			store[k] = b
			corrupted++
		}
	}
	if corrupted == 0 {
		t.Fatal("no segment objects found to corrupt")
	}

	_, res, err := Apply(r, NewDirTarget(t.TempDir()), true)
	if err != nil {
		t.Fatalf("a per-record decrypt failure must not abort apply: %v", err)
	}
	if res.OK() {
		t.Fatal("a corrupted Workers archive must NOT be OK; it must exit non-zero")
	}
	if len(res.Reprovisioned) != 0 {
		t.Fatalf("a corrupted reprovision record must never be laundered as reprovision-only, got %+v", res.Reprovisioned)
	}
	if len(res.Failed) != len(workersValues) {
		t.Fatalf("every corrupted record must be a real failure, got %d of %d: %+v", len(res.Failed), len(workersValues), res.Failed)
	}
	if res.Restored != 0 {
		t.Fatalf("no corrupted record should count as restored, Restored=%d", res.Restored)
	}
	// Flipping a tag byte fails the AEAD, which the reader codes as the structural exit
	// (SPEC.md 8.5), so the command propagates that integrity class, not a generic exit 1.
	if res.IntegrityExit != format.ExitUnverified {
		t.Fatalf("IntegrityExit = %d, want ExitUnverified (%d) for an AEAD failure", res.IntegrityExit, format.ExitUnverified)
	}
}

// TestReprovisionWriteFailureNotLaunderedAsIntegrity is the sharp coexistence proof: in one
// apply, a healthy content record is written, a CORRUPTED settings record is a real failure
// (its verify returns a coded integrity error), and a healthy versions record that collides on
// the content record's path is reprovision-only. It uses codedFakeReader so the integrity
// verdict is injected precisely (no need to forge an AEAD failure), which isolates the routing:
// verify failure routes to Failed for every source type, while a post-verify courtesy-write
// failure on a reprovision record routes to Reprovisioned.
func TestReprovisionWriteFailureNotLaunderedAsIntegrity(t *testing.T) {
	r := &codedFakeReader{
		recs: []spec.ShardRecord{
			{SourceType: spec.SourceWorkers, Name: "engine", RecordID: "recordid00000000", PlaintextSize: 6},
			{SourceType: spec.SourceWorkers, Name: "engine/settings", RecordID: "recordid00000001", PlaintextSize: 2},
			{SourceType: spec.SourceWorkers, Name: "engine/versions", RecordID: "recordid00000002", PlaintextSize: 2},
		},
		code: map[string]int{"engine/settings": format.ExitPlaintext},
		val:  map[string][]byte{"engine": []byte("bundle"), "engine/versions": []byte("{}")},
	}

	dir := t.TempDir()
	_, res, err := Apply(r, NewDirTarget(dir), true)
	if err != nil {
		t.Fatalf("a per-record failure must not abort apply: %v", err)
	}

	// The corrupted reprovision record is a REAL failure, and never reprovision-only.
	if res.OK() {
		t.Fatal("a corrupted reprovision record must make the apply not OK")
	}
	if len(res.Failed) != 1 || res.Failed[0].Name != "engine/settings" {
		t.Fatalf("the corrupted settings record must be the one real failure, got %+v", res.Failed)
	}
	if res.IntegrityExit != format.ExitPlaintext {
		t.Fatalf("IntegrityExit = %d, want ExitPlaintext (%d)", res.IntegrityExit, format.ExitPlaintext)
	}
	// The healthy content record is written; the healthy versions record (which collides on the
	// content path) is reprovision-only, not a failure.
	if res.Restored != 1 {
		t.Fatalf("the healthy content record should be written, Restored=%d", res.Restored)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "engine")); string(got) != "bundle" {
		t.Fatalf("the content bundle should be on disk, got %q", got)
	}
	if len(res.Reprovisioned) != 1 || res.Reprovisioned[0].Name != "engine/versions" {
		t.Fatalf("the healthy colliding versions record must be reprovision-only, got %+v", res.Reprovisioned)
	}
	// The corrupted record must NOT appear in the reprovision-only list.
	for _, rp := range res.Reprovisioned {
		if rp.Name == "engine/settings" {
			t.Fatal("a corrupted record must never be laundered into the reprovision-only list")
		}
	}
}
