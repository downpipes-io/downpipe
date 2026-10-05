package format

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/source"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// These values are MaxRootManifestBytes, MaxRunlogBytes and MaxSignatureBytes. The test
// states them as literals so that it also compiles, and fails, on code without the caps.
const (
	rootCapForTest = 256 << 20
	sigCapForTest  = 64 << 10
)

// sparseObject creates the archive object key under dir as a sparse file of size bytes. It
// costs no disk space, but a reader that reads it whole still allocates size bytes.
func sparseObject(t *testing.T, dir, key string, size int64) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	fh, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := fh.Truncate(size); err != nil {
		_ = fh.Close()
		t.Fatal(err)
	}
	if err := fh.Close(); err != nil {
		t.Fatal(err)
	}
}

// heapAllocatedBy returns the bytes the Go heap allocated while f ran.
func heapAllocatedBy(f func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestReaderRefusesAnOversizedRootObjectBeforeReadingIt proves that the reader refuses a root
// manifest, a root signature or a RUNLOG that is larger than its cap, and that it does so
// before it reads the object. The reader reads these objects before it can check any
// signature, so the general 2 GiB object ceiling let a store writer cost the recovery
// machine gigabytes of heap before the wrong-signer refusal.
func TestReaderRefusesAnOversizedRootObjectBeforeReadingIt(t *testing.T) {
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	// A full read of any object in this table allocates at least its size. The refusal
	// must cost a small fraction of that.
	const allocBound = 16 << 20

	cases := []struct {
		name    string
		key     string
		size    int64
		limit   string
		extra   map[string]int64 // other objects the path reads first
		openRun func(store ObjectStore) error
	}{
		{
			name:  "root manifest",
			key:   runKey(runID, "root.manifest.json"),
			size:  rootCapForTest + 1,
			limit: "exceeds the 268435456-byte limit",
			openRun: func(store ObjectStore) error {
				_, err := StreamOpenContext(context.Background(), store, runID, nil, nil, Options{})
				return err
			},
		},
		{
			name:  "root signature",
			key:   runKey(runID, "root.manifest.json.sig"),
			size:  sigCapForTest + 1,
			limit: "exceeds the 65536-byte limit",
			extra: map[string]int64{runKey(runID, "root.manifest.json"): 64},
			openRun: func(store ObjectStore) error {
				_, err := StreamOpenContext(context.Background(), store, runID, nil, nil, Options{})
				return err
			},
		},
		{
			name:  "RUNLOG",
			key:   "_RECOVERY/RUNLOG",
			size:  rootCapForTest + 1,
			limit: "exceeds the 268435456-byte limit",
			openRun: func(store ObjectStore) error {
				_, err := checkFreshness(store, runID, &spec.RootManifest{}, nil, Options{})
				return err
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sparseObject(t, dir, tc.key, tc.size)
			for k, n := range tc.extra {
				sparseObject(t, dir, k, n)
			}
			store := source.NewDirStore(dir)

			var err error
			allocated := heapAllocatedBy(func() { err = tc.openRun(store) })
			if err == nil {
				t.Fatalf("an oversized %s must be refused", tc.name)
			}
			if !strings.Contains(err.Error(), tc.limit) {
				t.Errorf("the refusal must name the %s cap (%q); got: %v", tc.name, tc.limit, err)
			}
			if allocated > allocBound {
				t.Errorf("the reader allocated %d bytes for a %d-byte %s; it must refuse the object before it reads it (bound %d)", allocated, tc.size, tc.name, allocBound)
			}
		})
	}
}
