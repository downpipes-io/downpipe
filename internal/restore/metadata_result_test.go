package restore

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// metaRdr is rdr with a kv descriptor on the records named in withMeta.
func metaRdr(withMeta map[string]bool, pairs ...[2]string) *fakeReader {
	f := rdr(pairs...)
	for i := range f.recs {
		if withMeta[f.recs[i].Name] {
			f.recs[i].KV = &spec.KVDescriptor{Metadata: json.RawMessage(`{"k":"v"}`), Expiration: 1893456000}
		}
	}
	return f
}

// TestMetadataSidecarCountAndBytes checks the count the summary prints and the exact sidecar
// bytes: the documented field set, and HTML-significant characters kept as they are.
func TestMetadataSidecarCountAndBytes(t *testing.T) {
	f := rdr([2]string{"a", "1"}, [2]string{"b", "2"})
	f.recs[0].SourceType = "r2"
	f.recs[0].Bucket = "media"
	f.recs[0].PlaintextSHA = "00ff"
	f.recs[0].R2 = &spec.R2Descriptor{HTTPMetadata: json.RawMessage(`{"contentDisposition":"attachment; filename=\"a&b<c>.png\""}`)}
	dir := t.TempDir()
	for name, apply := range map[string]func() (*Result, error){
		"load-all": func() (*Result, error) { _, r, e := Apply(f, NewDirTarget(filepath.Join(dir, "a")), true); return r, e },
		"stream": func() (*Result, error) {
			_, r, e := ApplyStreaming(f, NewDirTarget(filepath.Join(dir, "s")), true)
			return r, e
		},
	} {
		res, err := apply()
		if err != nil || !res.OK() {
			t.Fatalf("%s: err=%v failed=%v", name, err, res.Failed)
		}
		if res.MetadataSidecars != 1 || len(res.MetadataUnapplied) != 0 {
			t.Fatalf("%s: sidecars=%d unapplied=%v, want 1 and none", name, res.MetadataSidecars, res.MetadataUnapplied)
		}
	}
	got, err := os.ReadFile(filepath.Join(dir, "a", "a"+wantSidecarSuffix))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"format":"downpipe-restore-metadata/1","sourceType":"r2","bucket":"media","name":"a","plaintextSha384":"00ff","r2":{"httpMetadata":{"contentDisposition":"attachment; filename=\"a&b<c>.png\""}}}` + "\n"
	if string(got) != want {
		t.Fatalf("sidecar bytes:\n got %s\nwant %s", got, want)
	}
	info, err := os.Stat(filepath.Join(dir, "a", "a"+wantSidecarSuffix))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("sidecar mode = %o, want 600 like the value", perm)
	}
}

// TestEnvRestoreReportsMetadataItCannotKeep: the env sink has no place for metadata, so each
// record with metadata must be listed with its fields and the reason. The value line is
// unchanged and the record is not a failure.
func TestEnvRestoreReportsMetadataItCannotKeep(t *testing.T) {
	var buf bytes.Buffer
	f := metaRdr(map[string]bool{"API_TOKEN": true}, [2]string{"API_TOKEN", "s3cr3t"}, [2]string{"DB_URL", "x"})
	_, res, err := ApplyStreaming(f, NewEnvTarget(&buf, nil), true)
	if err != nil || !res.OK() {
		t.Fatalf("err=%v failed=%v", err, res.Failed)
	}
	if got, want := buf.String(), "API_TOKEN='s3cr3t'\nDB_URL='x'\n"; got != want {
		t.Fatalf("env output %q, want %q", got, want)
	}
	if res.MetadataSidecars != 0 || len(res.MetadataUnapplied) != 1 {
		t.Fatalf("sidecars=%d unapplied=%v, want 0 and one", res.MetadataSidecars, res.MetadataUnapplied)
	}
	u := res.MetadataUnapplied[0]
	if u.Name != "API_TOKEN" || u.Key != "API_TOKEN" || u.SourceType != "kv" ||
		!reflect.DeepEqual(u.Fields, []string{"kv.metadata", "kv.expiration"}) || !strings.Contains(u.Reason, "env target has no place to keep metadata") {
		t.Fatalf("unapplied entry = %+v", u)
	}
}

// TestDiscardRestoreHasNoMetadataToLose: the discard drill writes nothing, values included, so
// it lists no metadata as lost.
func TestDiscardRestoreHasNoMetadataToLose(t *testing.T) {
	f := metaRdr(map[string]bool{"a": true}, [2]string{"a", "1"})
	_, res, err := ApplyStreaming(f, NewDiscardTarget(), true)
	if err != nil || !res.OK() {
		t.Fatalf("err=%v failed=%v", err, res.Failed)
	}
	if res.MetadataSidecars != 0 || len(res.MetadataUnapplied) != 0 {
		t.Fatalf("sidecars=%d unapplied=%v, want none", res.MetadataSidecars, res.MetadataUnapplied)
	}
}

// TestMetadataSidecarNeverClobbers: a file already sits at the sidecar path. The value is
// restored, the file is left as it was, and the record is listed as metadata not kept.
func TestMetadataSidecarNeverClobbers(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"+wantSidecarSuffix), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := metaRdr(map[string]bool{"a": true}, [2]string{"a", "1"})
	_, res, err := ApplyStreaming(f, NewDirTarget(dir), true)
	if err != nil || !res.OK() || res.Restored != 1 {
		t.Fatalf("err=%v restored=%d failed=%v", err, res.Restored, res.Failed)
	}
	if len(res.MetadataUnapplied) != 1 || !strings.Contains(res.MetadataUnapplied[0].Reason, "may already exist") {
		t.Fatalf("unapplied = %+v", res.MetadataUnapplied)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "a"+wantSidecarSuffix)); string(got) != "mine" {
		t.Fatalf("existing file was changed: %q", got)
	}
}

// TestMetadataSidecarPathIsClaimedInThePlan: a record whose own key is another record's
// sidecar path is a collision in the plan, on both apply paths, and not a write that fails
// late or a sidecar that overwrites a value.
func TestMetadataSidecarPathIsClaimedInThePlan(t *testing.T) {
	f := metaRdr(map[string]bool{"a": true}, [2]string{"a", "1"}, [2]string{"a" + wantSidecarSuffix, "value"})
	for name, apply := range map[string]func(Target) (*Plan, *Result, error){
		"load-all": func(tg Target) (*Plan, *Result, error) { return Apply(f, tg, true) },
		"stream":   func(tg Target) (*Plan, *Result, error) { return ApplyStreaming(f, tg, true) },
	} {
		dir := t.TempDir()
		plan, res, err := apply(NewDirTarget(dir))
		if err != nil || !res.OK() {
			t.Fatalf("%s: err=%v failed=%v", name, err, res.Failed)
		}
		if len(plan.Conflicts) != 1 || plan.Conflicts[0].Kind != ConflictCollision || plan.Conflicts[0].Name != "a"+wantSidecarSuffix {
			t.Fatalf("%s: conflicts = %+v", name, plan.Conflicts)
		}
		if res.MetadataSidecars != 1 {
			t.Fatalf("%s: sidecars = %d", name, res.MetadataSidecars)
		}
		side := readSidecar(t, dir, "a")
		if !jsonEqual(t, side["name"], `"a"`) {
			t.Fatalf("%s: sidecar = %v", name, side)
		}
	}
}
