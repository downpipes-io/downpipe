package format

import (
	"bytes"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// streamRec opens a single-record run built from vs and returns the opened reader and the
// one record, so the streaming tests share one fixture path.
func streamRec(t *testing.T, vs vectorSpec) (*Reader, spec.ShardRecord) {
	t.Helper()
	store, bgPriv, verifier, _ := buildArchiveSpec(t, vs)
	r, err := Open(store, vecRunID, bgPriv, verifier, Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	recs := r.Records()
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	return r, recs[0]
}

// A tampered segment must still be rejected on the streaming path: RestoreRecordTo must
// return an error (the AEAD tag fails inside OpenStreamTo, or the plaintext SHA-384 fails
// afterwards) so streaming never launders a corrupted value. This is the integrity gate the
// streaming path must not weaken; it is written first.
func TestRestoreRecordToTamperedSegmentRejected(t *testing.T) {
	const runID = vecRunID
	value := bytes.Repeat([]byte{0x42}, 3*spec.ChunkSize+7) // multi-segment, multi-chunk
	store, bgPriv, verifier, _ := buildArchiveSpec(t, vectorSpec{
		dpID:    "dp_stream_tamper",
		records: []recordSpec{{name: "blob", value: value, srcType: "r2", segments: 3}},
	})
	// Flip one byte in every seg object so the corruption lands in the record's chain.
	for k := range store {
		if len(k) > 4 && k[:4] == "seg/" {
			store[k] = bytes.Clone(store[k])
			store[k][len(store[k])-1] ^= 0x01
		}
	}
	r, err := Open(store, runID, bgPriv, verifier, Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	rec := r.Records()[0]
	var dst bytes.Buffer
	if err := r.RestoreRecordTo(rec, &dst); err == nil {
		t.Fatal("a tampered segment must fail on the streaming restore path")
	}
}

// The streaming path must produce the exact value bytes and assert the same per-record
// plaintext SHA-384 as the buffering path, for a multi-segment non-gzip record.
func TestRestoreRecordToByteEquality(t *testing.T) {
	value := bytes.Repeat([]byte("stream me across segments "), 4096) // ~100 KiB, multi-chunk
	r, rec := streamRec(t, vectorSpec{
		dpID:    "dp_stream_eq",
		records: []recordSpec{{name: "blob", value: value, srcType: "r2", segments: 3}},
	})

	// Buffering path: the reference value.
	want, err := r.RestoreRecord(rec)
	if err != nil {
		t.Fatalf("buffered restore: %v", err)
	}
	if !bytes.Equal(want, value) {
		t.Fatal("buffered restore mismatch against the source value")
	}

	// Streaming path: must yield byte-identical output.
	var got bytes.Buffer
	if err := r.RestoreRecordTo(rec, &got); err != nil {
		t.Fatalf("streaming restore: %v", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("streaming restore mismatch: got %d bytes, want %d", got.Len(), len(want))
	}

	// The streamed SHA-384 (asserted inside RestoreRecordTo against rec.PlaintextSHA) equals
	// the buffered SHA-384 over the same value: both gate the same hash, so a clean restore
	// through either path proves the same content.
	if SHA384Hex(got.Bytes()) != SHA384Hex(want) {
		t.Fatal("streamed SHA-384 does not equal the buffered SHA-384")
	}
	if SHA384Hex(got.Bytes()) != rec.PlaintextSHA {
		t.Fatal("streamed SHA-384 does not equal the manifest plaintext SHA-384")
	}
}

// A secrets record (single segment, salted file key) must also stream correctly: it is
// non-gzip and non-packed, so it is streamable.
func TestRestoreRecordToSecrets(t *testing.T) {
	value := bytes.Repeat([]byte{0x9c}, spec.ChunkSize+13)
	r, rec := streamRec(t, vectorSpec{
		dpID:    "dp_stream_secret",
		records: []recordSpec{{name: "tok", value: value, secret: true}},
	})
	if rec.SourceType != "secrets" {
		t.Fatalf("expected a secrets record, got %q", rec.SourceType)
	}
	var got bytes.Buffer
	if err := r.RestoreRecordTo(rec, &got); err != nil {
		t.Fatalf("streaming secrets restore: %v", err)
	}
	if !bytes.Equal(got.Bytes(), value) {
		t.Fatal("streamed secrets value mismatch")
	}
}

// A gzip or packed record is not streamable and RestoreRecordTo must refuse it, so the
// caller falls back to RestoreRecord rather than silently skipping the codec or the slice.
func TestRestoreRecordToRejectsNonStreamable(t *testing.T) {
	t.Run("gzip", func(t *testing.T) {
		r, rec := streamRec(t, vectorSpec{
			dpID:    "dp_stream_gzip",
			codec:   spec.CodecNameGzip,
			records: []recordSpec{{name: "doc", value: bytes.Repeat([]byte("z"), 1024), srcType: "r2"}},
		})
		if IsStreamable(rec) {
			t.Fatal("a gzip record must not be streamable")
		}
		var dst bytes.Buffer
		if err := r.RestoreRecordTo(rec, &dst); err == nil {
			t.Fatal("RestoreRecordTo must refuse a gzip record")
		}
	})
	t.Run("packed", func(t *testing.T) {
		store, bgPriv, verifier, _ := buildArchiveSpec(t, vectorSpec{
			dpID: "dp_stream_packed",
			records: []recordSpec{
				{name: "a", value: []byte("alpha"), srcType: "kv", packGroup: 1},
				{name: "b", value: []byte("bravo"), srcType: "kv", packGroup: 1},
			},
		})
		r, err := Open(store, vecRunID, bgPriv, verifier, Options{})
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		for _, rec := range r.Records() {
			if rec.Segments[0].Packed == nil {
				continue
			}
			if IsStreamable(rec) {
				t.Fatal("a packed record must not be streamable")
			}
			var dst bytes.Buffer
			if err := r.RestoreRecordTo(rec, &dst); err == nil {
				t.Fatal("RestoreRecordTo must refuse a packed record")
			}
		}
	})
}

// A chunkRange that under-states the segment's true chunk count must be rejected on the
// streaming path exactly as on the buffering path: the OpenStreamTo maxChunks bound refuses
// to read beyond the declared range, so a segment longer than its declared range fails.
func TestRestoreRecordToBoundsByChunkRange(t *testing.T) {
	value := bytes.Repeat([]byte{0x41}, spec.ChunkSize+1) // two chunks, single segment
	r, rec := streamRec(t, vectorSpec{
		dpID:    "dp_stream_bound",
		records: []recordSpec{{name: "blob", value: value, srcType: "r2"}},
	})
	if segmentStreamChunks(int(rec.PlaintextSize)) != 2 {
		t.Fatalf("fixture must span two chunks")
	}
	var dst bytes.Buffer
	if err := r.RestoreRecordTo(withChunkRange(rec, [2]int{0, 1}), &dst); err == nil {
		t.Fatal("an under-declared chunkRange must be rejected on the streaming path")
	}
	dst.Reset()
	if err := r.RestoreRecordTo(withChunkRange(rec, [2]int{0, 5}), &dst); err == nil {
		t.Fatal("an over-declared chunkRange must be rejected on the streaming path")
	}
}
