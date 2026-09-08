package restore

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// typedReader is a recordReader whose records carry an explicit sourceType, so the
// reprovision handling for workers/cf-config can be exercised without an encrypted archive.
type typedReader struct {
	recs   []spec.ShardRecord
	values map[string][]byte
}

func (r *typedReader) Records() []spec.ShardRecord { return r.recs }

func (r *typedReader) RestoreRecord(rec spec.ShardRecord) ([]byte, error) {
	return r.values[rec.Name], nil
}

func typedRdr(specs ...[3]string) *typedReader {
	r := &typedReader{values: map[string][]byte{}}
	for _, s := range specs {
		srcType, name, val := s[0], s[1], s[2]
		r.recs = append(r.recs, spec.ShardRecord{
			SourceType: srcType, Name: name, PlaintextSize: int64(len(val)),
		})
		r.values[name] = []byte(val)
	}
	return r
}

// GuidanceFor returns out-of-band text for every reprovision source type (workers,
// cf-config, stream, images, artifacts) and "" for a direct-write source, and distinguishes the
// three Workers record kinds. Every spec.ReprovisionSourceType must yield guidance: a
// reprovision record surfaced with empty guidance is a silent gap in the restore report.
func TestGuidanceFor(t *testing.T) {
	cases := []struct {
		srcType, name string
		wantEmpty     bool
		wantContains  string
	}{
		{spec.SourceWorkers, "engine", false, "re-deploy"},
		{spec.SourceWorkers, "engine/settings", false, "secret values were never captured"},
		{spec.SourceWorkers, "engine/versions", false, "informational"},
		{spec.SourceCFConfig, "dns_records", false, "never blindly re-applies"},
		{spec.SourceStream, "01ARZ3NDEKTSV4RRFFQ69G5FAV", false, "re-upload the video binaries"},
		{spec.SourceImages, "img-001", false, "re-upload the image binaries"},
		{spec.SourceImages, "_variants", false, "variant definitions"},
		{spec.SourceArtifacts, "ns/repo", false, "re-push"},
		{spec.SourceKV, "k", true, ""},
		{spec.SourceR2, "obj", true, ""},
		{spec.SourceSecrets, "s", true, ""},
		{spec.SourceD1, "db", true, ""},
	}
	for _, c := range cases {
		got := GuidanceFor(spec.ShardRecord{SourceType: c.srcType, Name: c.name})
		if c.wantEmpty {
			if got != "" {
				t.Errorf("GuidanceFor(%s, %q) = %q, want empty", c.srcType, c.name, got)
			}
			continue
		}
		if got == "" {
			t.Errorf("GuidanceFor(%s, %q) = empty, want guidance", c.srcType, c.name)
		}
		if !strings.Contains(strings.ToLower(got), strings.ToLower(c.wantContains)) {
			t.Errorf("GuidanceFor(%s, %q) = %q, want it to mention %q", c.srcType, c.name, got, c.wantContains)
		}
	}
}

// TestEveryReprovisionTypeHasGuidance is the regression guard for the coupling between
// spec.ReprovisionSourceType (which classifies a record as restore-by-reprovision and so
// puts it in the plan's Reprovision list) and GuidanceFor (which fills that note's text):
// every source type the spec treats as reprovision MUST yield non-empty guidance, or the
// restore report surfaces a reprovision record with a blank line. It drives over
// spec.KnownSourceTypes (the authoritative closed set) so adding a new reprovision type
// without its guidance fails here rather than slipping past a hand-maintained literal.
func TestEveryReprovisionTypeHasGuidance(t *testing.T) {
	for _, srcType := range spec.KnownSourceTypes() {
		got := GuidanceFor(spec.ShardRecord{SourceType: srcType, Name: "x"})
		if spec.ReprovisionSourceType(srcType) {
			if got == "" {
				t.Errorf("reprovision source type %q has no GuidanceFor text; the restore report would show a blank reprovision note", srcType)
			}
			continue
		}
		if got != "" {
			t.Errorf("direct-write source type %q unexpectedly has GuidanceFor text %q", srcType, got)
		}
	}
}

// On a file sink, a reprovision record (workers/cf-config/stream/images) is planned as a
// write (its verified bytes are written out for the operator) AND surfaced as a reprovision
// note with non-empty guidance, so the operator re-provisions deliberately. A plain kv
// record carries no note.
func TestFileSinkWritesAndFlagsReprovision(t *testing.T) {
	dir := t.TempDir()
	r := typedRdr(
		[3]string{spec.SourceWorkers, "engine", "worker-bundle-bytes"},
		[3]string{spec.SourceCFConfig, "dns_records", `{"surface":"dns"}`},
		[3]string{spec.SourceStream, "video-01", `{"uid":"video-01"}`},
		[3]string{spec.SourceImages, "img-01", `{"id":"img-01"}`},
		[3]string{spec.SourceKV, "plainkey", "plainval"},
	)
	target := NewDirTarget(dir)

	plan, res, err := Apply(r, target, true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || res.Restored != 5 {
		t.Fatalf("apply should restore all 5 records, got restored=%d failed=%v", res.Restored, res.Failed)
	}
	// The verified bytes are on disk for the operator to re-provision from.
	if got, _ := os.ReadFile(filepath.Join(dir, "engine")); !bytes.Equal(got, []byte("worker-bundle-bytes")) {
		t.Fatalf("workers bytes not written for the operator: %q", got)
	}
	// Exactly the four reprovision records are flagged with guidance, the kv one is not.
	if len(plan.Reprovision) != 4 {
		t.Fatalf("expected 4 reprovision notes, got %d: %+v", len(plan.Reprovision), plan.Reprovision)
	}
	seen := map[string]string{}
	for _, rp := range plan.Reprovision {
		if rp.Guidance == "" {
			t.Errorf("reprovision note for %q (%s) has no guidance", rp.Name, rp.SourceType)
		}
		seen[rp.Name] = rp.SourceType
	}
	if seen["engine"] != spec.SourceWorkers || seen["dns_records"] != spec.SourceCFConfig ||
		seen["video-01"] != spec.SourceStream || seen["img-01"] != spec.SourceImages {
		t.Fatalf("reprovision notes wrong: %+v", seen)
	}
	if _, ok := seen["plainkey"]; ok {
		t.Fatal("a kv record must not be flagged as reprovision")
	}
}

// The env sink cannot represent a Worker bundle or a config surface as a dotenv value, so
// a reprovision record is refused there (a conflict with guidance) rather than silently
// mis-restored. The note name "dns_records" is a VALID env-var name, so the refusal is the
// source-type guard, not the env-name check.
func TestEnvSinkRefusesReprovisionRecord(t *testing.T) {
	r := typedRdr(
		[3]string{spec.SourceCFConfig, "dns_records", `{"surface":"dns"}`},
		[3]string{spec.SourceKV, "PLAINKEY", "plainval"},
	)
	var buf bytes.Buffer
	target := NewEnvTarget(&buf, nil)

	plan, _, err := Apply(r, target, true)
	if err != nil {
		t.Fatal(err)
	}
	// The cf-config record is a conflict; the kv record writes.
	var cfConflict Conflict
	found := false
	for _, c := range plan.Conflicts {
		if c.Name == "dns_records" {
			cfConflict = c
			found = true
		}
	}
	if !found {
		t.Fatal("env sink must refuse a cf-config record as a conflict")
	}
	if cfConflict.Kind != ConflictUnrepresentable {
		t.Fatalf("cf-config env conflict kind = %q, want %q", cfConflict.Kind, ConflictUnrepresentable)
	}
	// No reprovision note on the env sink (it never wrote the bytes), and the dotenv output
	// must not contain the config-surface value.
	if len(plan.Reprovision) != 0 {
		t.Fatalf("env sink must not record a reprovision write, got %+v", plan.Reprovision)
	}
	if strings.Contains(buf.String(), "surface") {
		t.Fatalf("a cf-config value leaked into the dotenv output: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "PLAINKEY=") {
		t.Fatalf("the plain kv record should still be written to env: %q", buf.String())
	}
}
