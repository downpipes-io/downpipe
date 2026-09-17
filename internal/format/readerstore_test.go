package format

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/downpipes-io/downpipe/internal/source"
)

// Compile-time proof that both shipped backends offer the streamed-read capability the
// reader discovers by type assertion.
var (
	_ ReaderStore = (*source.DirStore)(nil)
	_ ReaderStore = (*source.S3Store)(nil)
)

// readerStoreSpy wraps the in-memory store with the streamed-read capability, counting
// how often the streamed path was chosen, so a test can assert RestoreRecordTo prefers
// the stream over the buffered Get when the store offers it.
type readerStoreSpy struct {
	memStore
	streamedGets int
}

func (s *readerStoreSpy) GetReader(_ context.Context, key string) (io.ReadCloser, int64, error) {
	b, err := s.Get(key) // the promoted buffered Get supplies the bytes
	if err != nil {
		return nil, 0, err
	}
	s.streamedGets++
	return io.NopCloser(bytes.NewReader(b)), int64(len(b)), nil
}

func TestRestoreRecordToUsesStoreStream(t *testing.T) {
	value := bytes.Repeat([]byte("ship it chunk by chunk "), 8192)
	store, bgPriv, verifier, _ := buildArchiveSpec(t, vectorSpec{
		dpID:    "dp_readerstore",
		records: []recordSpec{{name: "blob", value: value, srcType: "r2", segments: 2}},
	})
	spy := &readerStoreSpy{memStore: store}
	r, err := Open(spy, vecRunID, bgPriv, verifier, Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	rec := r.Records()[0]
	var got bytes.Buffer
	if err := r.RestoreRecordTo(rec, &got); err != nil {
		t.Fatalf("streamed restore: %v", err)
	}
	if !bytes.Equal(got.Bytes(), value) {
		t.Fatalf("streamed restore mismatch: got %d bytes, want %d", got.Len(), len(value))
	}
	if spy.streamedGets != 2 {
		t.Fatalf("expected both segments on the streamed path, got %d streamed gets", spy.streamedGets)
	}
}

// A corrupted sealed object must fail identically through the streamed store path: the
// unframe check and the AEAD both sit behind the same gates as the buffered read.
func TestRestoreRecordToStreamedRejectsCorruptSegment(t *testing.T) {
	value := bytes.Repeat([]byte{0x42}, 200000)
	store, bgPriv, verifier, _ := buildArchiveSpec(t, vectorSpec{
		dpID:    "dp_readerstore_bad",
		records: []recordSpec{{name: "blob", value: value, srcType: "r2", segments: 1}},
	})
	for k := range store {
		if len(k) > 4 && k[:4] == "seg/" {
			store[k] = bytes.Clone(store[k])
			store[k][0] ^= 0x01 // break the container magic on the streamed path
		}
	}
	spy := &readerStoreSpy{memStore: store}
	r, err := Open(spy, vecRunID, bgPriv, verifier, Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var dst bytes.Buffer
	if err := r.RestoreRecordTo(r.Records()[0], &dst); err == nil {
		t.Fatal("a corrupt sealed object must fail on the streamed store path")
	}
}
