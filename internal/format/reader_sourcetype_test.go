package format

import (
	"errors"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// A run carrying a sourceType outside the supported set (SPEC.md 12.1) must be refused
// with ExitUsage, not opened and restored as opaque bytes. The vector is a fully valid,
// signed archive whose only defect is the out-of-set type, so this proves the refusal is
// the source-type gate and not some other failure.
func TestOpenRefusesUnknownSourceType(t *testing.T) {
	store, bgPriv, verifier, _ := buildArchiveSpec(t, vectorSpec{
		dpID:    "dp_unknown_src",
		records: []recordSpec{{name: "a", value: []byte("v"), srcType: "durable_object"}},
	})

	_, err := Open(store, vecRunID, bgPriv, verifier, Options{})
	if err == nil {
		t.Fatal("Open accepted a record with an out-of-set sourceType; it must refuse one (SPEC.md 12.1)")
	}
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != ExitUsage {
		t.Fatalf("unknown sourceType must exit ExitUsage (%d), got %v", ExitUsage, err)
	}
}

// The two reprovision source types the engine writes, workers and cf-config, must OPEN and
// verify end to end exactly like kv/r2/d1: the offline reader models them, decrypts them
// and hash-checks them. (Their out-of-band restore handling is covered in the restore
// package; here we only prove the reader no longer chokes on the type.)
func TestOpenAcceptsWorkersAndCFConfig(t *testing.T) {
	for _, srcType := range []string{spec.SourceWorkers, spec.SourceCFConfig} {
		t.Run(srcType, func(t *testing.T) {
			store, bgPriv, verifier, _ := buildArchiveSpec(t, vectorSpec{
				dpID:    "dp_" + srcType,
				records: []recordSpec{{name: "surface-a", value: []byte("snapshot-bytes"), srcType: srcType}},
			})

			r, err := Open(store, vecRunID, bgPriv, verifier, Options{})
			if err != nil {
				t.Fatalf("Open(%s): %v", srcType, err)
			}
			recs := r.Records()
			if len(recs) != 1 || recs[0].SourceType != srcType {
				t.Fatalf("expected one %s record, got %+v", srcType, recs)
			}
			value, err := r.RestoreRecord(recs[0])
			if err != nil {
				t.Fatalf("RestoreRecord(%s): %v", srcType, err)
			}
			if string(value) != "snapshot-bytes" {
				t.Fatalf("%s value round-trip = %q, want %q", srcType, value, "snapshot-bytes")
			}
		})
	}
}
