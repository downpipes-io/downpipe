package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
)

// releasedSidecarSuffix is the documented sidecar suffix (docs/format/SPEC.md 6.3), pinned as a
// literal so a rename is a visible format change.
const releasedSidecarSuffix = ".downpipe-meta.json"

// TestReleasedEngineArchiveKeepsMetadata restores the archive that released engine 0.3.5 sealed
// (internal/format/testdata/released/downpipe-0.1.0) to the file sink, and requires the KV and R2
// metadata the engine wrote to be on disk afterwards, in a sidecar next to each value
// Run 1 holds an incompleteness marker, so its restore exits 8, not 0. The wanted descriptors are the engine's inputs, copied from the sealing
// script (engine test/seal-released-fixture.ts, the KV keys and R2 objects it seeds), so the
// reader is graded against what the writer was given and not against what it read back.
func TestReleasedEngineArchiveKeepsMetadata(t *testing.T) {
	dir := filepath.Join(releasedRoot, "downpipe-0.1.0")
	want := map[string]map[string]string{
		"01K6400000FXTRGEN010000001": {
			"config/feature-flags": `{"metadata":{"owner":"web","revision":14},"expiration":1893456000}`,
			"config/greeting":      `{"metadata":{"note":"quotes \" and unicode é"}}`,
			"docs/report.txt":      `{"httpMetadata":{"contentType":"text/plain","cacheControl":"max-age=3600","cacheExpiry":"2030-01-01T00:00:00.000Z"},"customMetadata":{"team":"ops","origin":"ingest"}}`,
			"media/clip.bin":       `{"httpMetadata":{"contentType":"video/mp4"}}`,
		},
		"01K6400000FXTRGEN010000002": {
			"archive/b.txt":     `{"customMetadata":{"tier":"cold"}}`,
			"archive/large.bin": `{"httpMetadata":{"contentType":"application/octet-stream"}}`,
		},
	}
	for runID, objects := range want {
		t.Run(runID, func(t *testing.T) {
			out := t.TempDir()
			code, log := runReader(t, readerArgs("restore", dir, 2, runID, runID == "01K6400000FXTRGEN010000002", "--apply", "--out", out)...)
			if code != format.ExitVerified && code != format.ExitIncompleteMarkers {
				t.Fatalf("restore --apply = %d\n%s", code, log)
			}
			var found []string
			werr := filepath.WalkDir(out, func(p string, _ os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if strings.HasSuffix(p, releasedSidecarSuffix) {
					rel, rerr := filepath.Rel(out, p)
					if rerr != nil {
						return rerr
					}
					found = append(found, filepath.ToSlash(rel))
				}
				return nil
			})
			if werr != nil {
				t.Fatalf("walk the restore output: %v", werr)
			}
			if len(found) != len(objects) {
				t.Fatalf("found sidecars %v, want one for each of %d records with metadata", found, len(objects))
			}
			for name, descriptor := range objects {
				b, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(name+releasedSidecarSuffix)))
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				var side map[string]json.RawMessage
				if err := json.Unmarshal(b, &side); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				field := "kv"
				if strings.Contains(descriptor, "Metadata") {
					field = "r2"
				}
				var got, exp any
				if err := json.Unmarshal(side[field], &got); err != nil {
					t.Fatalf("%s: %s object: %v in %s", name, field, err, b)
				}
				if err := json.Unmarshal([]byte(descriptor), &exp); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, exp) {
					t.Errorf("%s: %s = %s, want %s", name, field, side[field], descriptor)
				}
			}
			if !strings.Contains(log, "kept the source metadata of") {
				t.Errorf("the summary must say where the metadata went, got:\n%s", log)
			}
		})
	}
}
