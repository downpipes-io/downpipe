package restore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// buildArchiveWithDescriptors is buildArchive with one extra step: decorate sets the kv or r2
// descriptor on each record before the shard is sealed. The descriptor is not a record-hash
// input (SPEC.md 6.5), so the records verify exactly as buildArchive's do.
func buildArchiveWithDescriptors(t *testing.T, store memStore, dpID, sourceType string, values map[string]string, decorate func(*spec.ShardRecord)) (string, archiveKeys) {
	t.Helper()
	k := genArchiveKeys(t)
	records, leaves := sealSegments(t, store, k, dpID, sourceType, values)
	for i := range records {
		decorate(&records[i])
	}
	shardObj, shardSHA := sealShard(t, store, k, records)
	buildRootManifest(t, store, k, dpID, records, leaves, shardObj, shardSHA)
	sealRunlog(t, store, k, dpID, len(records))
	return k.runID, k
}

// The documented sidecar name suffix and format label (docs/format/SPEC.md 6.3). The test pins
// the literal strings, not the package constants, so a rename of either is a visible format change.
const (
	wantSidecarSuffix = ".downpipe-meta.json"
	wantSidecarFormat = "downpipe-restore-metadata/1"
)

// readSidecar reads and decodes the metadata sidecar the file sink writes next to key. It
// fails the test when the sidecar is missing.
func readSidecar(t *testing.T, dir, key string) map[string]json.RawMessage {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(key+wantSidecarSuffix)))
	if err != nil {
		t.Fatalf("metadata sidecar for %q: %v", key, err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("metadata sidecar for %q is not a JSON object: %v\n%s", key, err, b)
	}
	return out
}

// jsonEqual reports whether two JSON texts carry the same value, ignoring key order and
// whitespace.
func jsonEqual(t *testing.T, got json.RawMessage, want string) bool {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("decode %s: %v", got, err)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("decode %s: %v", want, err)
	}
	return reflect.DeepEqual(g, w)
}

// restoreBothPaths applies the archive to a fresh file sink twice: once through the load-all
// Apply and once through the bounded-memory ApplyStreaming that `downpipe restore` uses. It
// returns the two output directories.
func restoreBothPaths(t *testing.T, store memStore, runID string, k archiveKeys) []string {
	t.Helper()
	loadAll, err := format.Open(store, runID, k.bgPriv, k.verifier, format.Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	dirA := t.TempDir()
	if _, res, err := Apply(loadAll, NewDirTarget(dirA), true); err != nil || !res.OK() {
		t.Fatalf("apply: err=%v failed=%v", err, res.Failed)
	}
	streamed, err := format.StreamOpen(store, runID, k.bgPriv, k.verifier, format.Options{})
	if err != nil {
		t.Fatalf("stream open: %v", err)
	}
	defer streamed.Close()
	dirB := t.TempDir()
	if _, res, err := ApplyStreaming(streamed, NewDirTarget(dirB), true); err != nil || !res.OK() {
		t.Fatalf("apply streaming: err=%v failed=%v", err, res.Failed)
	}
	return []string{dirA, dirB}
}

// TestFileRestoreKeepsKVMetadataAndExpiration checks that a restore keeps KV metadata. A KV
// archive whose records carry the engine's kv descriptor (opaque metadata and an absolute
// expiration) restores to the file sink, and the metadata must be on disk afterwards, next
// to the value. A sink that writes the value bytes alone loses the metadata without a word.
func TestFileRestoreKeepsKVMetadataAndExpiration(t *testing.T) {
	store := memStore{}
	values := map[string]string{
		"session/42": "session body",
		"plain":      "no descriptor on this one",
	}
	const meta = `{"owner":"ops","tags":["a","b"],"n":7}`
	runID, k := buildArchiveWithDescriptors(t, store, "dp_kvmeta", "kv", values, func(rec *spec.ShardRecord) {
		rec.Namespace = "sessions"
		if rec.Name == "session/42" {
			rec.KV = &spec.KVDescriptor{Metadata: json.RawMessage(meta), Expiration: 1893456000}
		}
	})

	for _, dir := range restoreBothPaths(t, store, runID, k) {
		side := readSidecar(t, dir, "session/42")
		kv, ok := side["kv"]
		if !ok {
			t.Fatalf("sidecar has no kv object: %v", side)
		}
		var d struct {
			Metadata   json.RawMessage `json:"metadata"`
			Expiration int64           `json:"expiration"`
		}
		if err := json.Unmarshal(kv, &d); err != nil {
			t.Fatal(err)
		}
		if !jsonEqual(t, d.Metadata, meta) {
			t.Fatalf("kv.metadata = %s, want %s", d.Metadata, meta)
		}
		if d.Expiration != 1893456000 {
			t.Fatalf("kv.expiration = %d, want 1893456000", d.Expiration)
		}
		if !jsonEqual(t, side["name"], `"session/42"`) || !jsonEqual(t, side["sourceType"], `"kv"`) || !jsonEqual(t, side["namespace"], `"sessions"`) {
			t.Fatalf("sidecar coordinates wrong: %v", side)
		}
		if !jsonEqual(t, side["format"], `"`+wantSidecarFormat+`"`) {
			t.Fatalf("sidecar format label = %s", side["format"])
		}
		// The value itself is unchanged.
		if got, _ := os.ReadFile(filepath.Join(dir, "session", "42")); string(got) != values["session/42"] {
			t.Fatalf("value = %q", got)
		}
		// A record with no descriptor gets no sidecar: there is nothing to keep.
		if _, err := os.Stat(filepath.Join(dir, "plain"+wantSidecarSuffix)); !os.IsNotExist(err) {
			t.Fatalf("a record without metadata must get no sidecar, stat err=%v", err)
		}
	}
}

// TestFileRestoreKeepsR2HTTPAndCustomMetadata is the R2 half of the red test. It includes one
// value at the streaming threshold, so the bounded-memory write path is covered as well as the
// buffered one.
func TestFileRestoreKeepsR2HTTPAndCustomMetadata(t *testing.T) {
	store := memStore{}
	big := strings.Repeat("x", streamThreshold)
	values := map[string]string{
		"img/logo.png":   "not really a png",
		"backups/big.gz": big,
	}
	const httpMeta = `{"contentType":"image/png","cacheControl":"max-age=60","contentDisposition":"attachment; filename=\"a&b.png\""}`
	const customMeta = `{"uploader":"ci","sha":"abc"}`
	runID, k := buildArchiveWithDescriptors(t, store, "dp_r2meta", "r2", values, func(rec *spec.ShardRecord) {
		rec.Bucket = "media"
		rec.R2 = &spec.R2Descriptor{HTTPMetadata: json.RawMessage(httpMeta), CustomMetadata: json.RawMessage(customMeta)}
	})

	for _, dir := range restoreBothPaths(t, store, runID, k) {
		for name := range values {
			side := readSidecar(t, dir, name)
			var d struct {
				HTTPMetadata   json.RawMessage `json:"httpMetadata"`
				CustomMetadata json.RawMessage `json:"customMetadata"`
			}
			if err := json.Unmarshal(side["r2"], &d); err != nil {
				t.Fatalf("%s: r2 object: %v (%v)", name, err, side)
			}
			if !jsonEqual(t, d.HTTPMetadata, httpMeta) || !jsonEqual(t, d.CustomMetadata, customMeta) {
				t.Fatalf("%s: r2 metadata = %s / %s", name, d.HTTPMetadata, d.CustomMetadata)
			}
			if !jsonEqual(t, side["bucket"], `"media"`) {
				t.Fatalf("%s: bucket = %s", name, side["bucket"])
			}
		}
	}
}
