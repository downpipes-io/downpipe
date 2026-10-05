package restore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
)

// TestApplyStreamingEndToEndThroughStreamReader is the bounded-memory restore proof at the
// package level: a REAL encrypted, signed archive is opened with format.StreamOpen (which
// verifies it without materialising the records) and restored with ApplyStreaming straight
// from the streaming reader. It binds ApplyStreaming to the genuine break-glass decrypt +
// streaming-verify path, not a fake, and exercises the per-record streaming WRITE path
// (DirTarget is a StreamTarget and a small kv value is streamable). The dry run must touch
// nothing; the apply must bring every value back byte-for-byte.
func TestApplyStreamingEndToEndThroughStreamReader(t *testing.T) {
	store := memStore{}
	values := map[string]string{
		"greeting":     "recover me without Cloudflare and without the vendor",
		"config/key":   "value-bytes",
		"nested/a/b/c": "deep",
	}
	identity, verifier, runID := buildArchive(t, store, "dp_stream_e2e", "kv", values)

	sr, err := format.StreamOpen(store, runID, identity, verifier, format.Options{})
	if err != nil {
		t.Fatalf("StreamOpen: %v", err)
	}
	if sr.RecordCount() != int64(len(values)) {
		t.Fatalf("streaming record count %d != %d", sr.RecordCount(), len(values))
	}

	dir := t.TempDir()
	target := NewDirTarget(dir)

	// Dry run: classify everything, write nothing.
	plan, res, err := ApplyStreaming(sr, target, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.DryRun || res.Restored != 0 {
		t.Fatalf("dry run wrote something: %+v", res)
	}
	if plan.WriteCount != len(values) {
		t.Fatalf("dry-run plan WriteCount = %d, want %d", plan.WriteCount, len(values))
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("dry run touched the output: %d entries", len(entries))
	}

	// Apply: values come back decrypted and hash-verified through the streaming reader.
	_, res, err = ApplyStreaming(sr, target, true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || res.Restored != len(values) {
		t.Fatalf("apply: restored=%d failed=%+v", res.Restored, res.Failed)
	}
	for name, want := range values {
		got, rerr := os.ReadFile(filepath.Join(dir, filepath.FromSlash(safeKey(name))))
		if rerr != nil {
			t.Fatalf("read restored %s: %v", name, rerr)
		}
		if string(got) != want {
			t.Fatalf("restored %s = %q, want %q", name, got, want)
		}
	}
}

// TestApplyStreamingParityWithApply pins that the streaming apply produces the SAME outcome as
// the load-all apply on the same fixture: identical restored counts and bytes, identical
// conflict handling, and identical files on disk. The only intended difference between the two
// is memory, never behaviour.
func TestApplyStreamingParityWithApply(t *testing.T) {
	mk := func() *fakeReader {
		return rdr(
			[2]string{"a", "alpha"},
			[2]string{"b/c", "bravo"},
			[2]string{"d", "delta"},
		)
	}

	dirA := t.TempDir()
	planA, resA, err := Apply(mk(), NewDirTarget(dirA), true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	dirB := t.TempDir()
	planB, resB, err := ApplyStreaming(mk(), NewDirTarget(dirB), true)
	if err != nil {
		t.Fatalf("ApplyStreaming: %v", err)
	}

	if resA.Restored != resB.Restored || resA.BytesRestored != resB.BytesRestored {
		t.Fatalf("restored mismatch: load-all %d/%d vs streaming %d/%d", resA.Restored, resA.BytesRestored, resB.Restored, resB.BytesRestored)
	}
	if planA.WriteCount != planB.WriteCount || len(planA.Conflicts) != len(planB.Conflicts) || planA.TotalBytes != planB.TotalBytes {
		t.Fatalf("plan mismatch: load-all writes=%d conflicts=%d bytes=%d vs streaming writes=%d conflicts=%d bytes=%d",
			planA.WriteCount, len(planA.Conflicts), planA.TotalBytes, planB.WriteCount, len(planB.Conflicts), planB.TotalBytes)
	}
	// The two output directories must hold byte-identical files.
	for _, name := range []string{"a", "b/c", "d"} {
		ga, _ := os.ReadFile(filepath.Join(dirA, filepath.FromSlash(name)))
		gb, _ := os.ReadFile(filepath.Join(dirB, filepath.FromSlash(name)))
		if string(ga) != string(gb) || len(ga) == 0 {
			t.Fatalf("file %q differs between load-all and streaming apply: %q vs %q", name, ga, gb)
		}
	}
}

// TestApplyStreamingConflictSkipped proves the streaming apply enforces the same no-clobber
// rule as the load-all apply: a record whose destination key already exists is reported as a
// conflict and never written, and the surviving records still restore.
func TestApplyStreamingConflictSkipped(t *testing.T) {
	dir := t.TempDir()
	// Pre-create the file the record "taken" would map to, so it must be refused.
	if err := os.WriteFile(filepath.Join(dir, "taken"), []byte("PRE-EXISTING"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := rdr([2]string{"taken", "would-clobber"}, [2]string{"fresh", "ok"})
	plan, res, err := ApplyStreaming(src, NewDirTarget(dir), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Conflicts) != 1 || plan.Conflicts[0].Name != "taken" || plan.Conflicts[0].Kind != ConflictExisting {
		t.Fatalf("expected one existing-key conflict for 'taken', got %+v", plan.Conflicts)
	}
	if res.Restored != 1 || res.SkippedConflicts != 1 {
		t.Fatalf("expected 1 restored + 1 skipped, got restored=%d skipped=%d", res.Restored, res.SkippedConflicts)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "taken")); string(got) != "PRE-EXISTING" {
		t.Fatalf("the pre-existing file was clobbered: %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "fresh")); string(got) != "ok" {
		t.Fatalf("the fresh record did not restore: %q", got)
	}
}
