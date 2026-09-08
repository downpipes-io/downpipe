package restore

import (
	"fmt"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// codedFakeReader is a recordReader whose RestoreRecord returns a chosen normative coded
// error (a *format.ExitError) per record, so the IntegrityExit propagation — the maximum
// per-record SPEC.md 8.5 code — can be asserted directly without forging a real AEAD or
// plaintext-hash failure for each class. It deliberately does NOT implement streamingReader,
// so Apply takes the buffering path through RestoreRecord.
type codedFakeReader struct {
	recs []spec.ShardRecord
	code map[string]int    // record name -> exit code to return; 0 means succeed
	val  map[string][]byte // record name -> value for the succeeding records
}

func (f *codedFakeReader) Records() []spec.ShardRecord { return f.recs }

func (f *codedFakeReader) RestoreRecord(rec spec.ShardRecord) ([]byte, error) {
	if c := f.code[rec.Name]; c != 0 {
		return nil, &format.ExitError{Code: c, Err: fmt.Errorf("record %s failed with coded exit %d", rec.Name, c)}
	}
	return f.val[rec.Name], nil
}

// TestIntegrityExitPropagatesMaxPerRecordCode proves Result.IntegrityExit is the maximum
// per-record coded exit (SPEC.md 8.5) across the failed records, not a flattened generic 1:
// a plaintext-hash mismatch (4) and an AEAD/structural failure (2) together yield 4, the
// more severe class, so a `restore --sink discard` (or `verify --deep`) drill reports the
// true integrity verdict instead of always exiting 1.
func TestIntegrityExitPropagatesMaxPerRecordCode(t *testing.T) {
	r := &codedFakeReader{
		recs: []spec.ShardRecord{
			{SourceType: "kv", Name: "ok", RecordID: "recordid00000000", PlaintextSize: 2},
			{SourceType: "kv", Name: "aead", RecordID: "recordid00000001", PlaintextSize: 2},
			{SourceType: "kv", Name: "plain", RecordID: "recordid00000002", PlaintextSize: 2},
		},
		code: map[string]int{"aead": format.ExitUnverified, "plain": format.ExitPlaintext},
		val:  map[string][]byte{"ok": []byte("hi")},
	}

	_, res, err := Apply(r, NewDiscardTarget(), true)
	if err != nil {
		t.Fatalf("a per-record failure must not abort apply: %v", err)
	}
	if len(res.Failed) != 2 {
		t.Fatalf("two records failed, got %d: %+v", len(res.Failed), res.Failed)
	}
	if res.Restored != 1 {
		t.Fatalf("one record succeeded, got Restored=%d", res.Restored)
	}
	// Max of ExitPlaintext (4) and ExitUnverified (2) is 4.
	if res.IntegrityExit != format.ExitPlaintext {
		t.Fatalf("IntegrityExit = %d, want %d (ExitPlaintext, the max per-record code)", res.IntegrityExit, format.ExitPlaintext)
	}
}

// TestIntegrityExitIsStructuralWhenOnlyAEAD proves the structural-only case: when the only
// failures are AEAD/structural (a flipped tag), IntegrityExit is ExitUnverified (2), which
// is the verdict a `verify --deep` over a byte-flipped segment must surface, rather than the
// generic exit 1 that collapsing every failure to one code would produce.
func TestIntegrityExitIsStructuralWhenOnlyAEAD(t *testing.T) {
	r := &codedFakeReader{
		recs: []spec.ShardRecord{
			{SourceType: "kv", Name: "aead", RecordID: "recordid00000000", PlaintextSize: 2},
		},
		code: map[string]int{"aead": format.ExitUnverified},
	}
	_, res, err := Apply(r, NewDiscardTarget(), true)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.IntegrityExit != format.ExitUnverified {
		t.Fatalf("IntegrityExit = %d, want %d (ExitUnverified)", res.IntegrityExit, format.ExitUnverified)
	}
}

// TestIntegrityExitZeroForUncodedFailure proves a failure that carries no normative code
// (an uncoded I/O error, e.g. a missing segment object surfaced as a bare error) leaves
// IntegrityExit 0, so the caller falls back to the historical generic exit 1 rather than
// mis-reporting a coded class.
func TestIntegrityExitZeroForUncodedFailure(t *testing.T) {
	// fakeReader.RestoreRecord returns a bare (uncoded) error for a failOn record.
	r := rdr([2]string{"bad", "x"})
	r.failOn["bad"] = true
	_, res, err := Apply(r, NewDiscardTarget(), true)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(res.Failed) != 1 {
		t.Fatalf("the bad record must fail, got %+v", res.Failed)
	}
	if res.IntegrityExit != 0 {
		t.Fatalf("an uncoded failure must leave IntegrityExit 0, got %d", res.IntegrityExit)
	}
}

// bufferOnlyReader wraps a *format.Reader but exposes ONLY the recordReader methods, hiding
// the streaming capability, so Apply is forced onto the buffering path even when the target
// can stream. It lets a test compare the buffered and streamed restore digests over the same
// archive.
type bufferOnlyReader struct{ r *format.Reader }

func (b bufferOnlyReader) Records() []spec.ShardRecord { return b.r.Records() }
func (b bufferOnlyReader) RestoreRecord(rec spec.ShardRecord) ([]byte, error) {
	return b.r.RestoreRecord(rec)
}

// TestDiscardDigestStableBufferedVsStreamed proves the discard restore digest is identical
// whether each record was verified through the buffering path (RestoreRecord + Write) or the
// streaming path (RestoreRecordTo + WriteStream). The streaming discard target was added so
// `verify --deep` checks values larger than memory in bounded memory; this pins that the new
// streaming WriteStream folds a record's contribution byte-identically to Write, so the
// digest an operator pins does not depend on the path the reader happened to take.
func TestDiscardDigestStableBufferedVsStreamed(t *testing.T) {
	store := memStore{}
	values := map[string]string{
		"greeting":   "recover me without Cloudflare and without the vendor",
		"config/key": "value-bytes",
	}
	identity, verifier, runID := buildArchive(t, store, "dp_stream_digest", "kv", values)

	open := func() *format.Reader {
		r, err := format.Open(store, runID, identity, verifier, format.Options{})
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		return r
	}

	// Streamed path: *format.Reader implements streamingReader and DiscardTarget implements
	// StreamTarget, so a streamable kv record is verified through WriteStream.
	streamed := open()
	for _, rec := range streamed.Records() {
		if !format.IsStreamable(rec) {
			t.Fatalf("record %q must be streamable for this test to exercise WriteStream", rec.Name)
		}
	}
	dtStream := NewDiscardTarget()
	if _, res, err := Apply(streamed, dtStream, true); err != nil || !res.OK() {
		t.Fatalf("streamed discard apply: err=%v ok=%v", err, res.OK())
	}

	// Buffered path: the wrapper hides the streaming capability, forcing RestoreRecord+Write.
	dtBuffer := NewDiscardTarget()
	if _, res, err := Apply(bufferOnlyReader{r: open()}, dtBuffer, true); err != nil || !res.OK() {
		t.Fatalf("buffered discard apply: err=%v ok=%v", err, res.OK())
	}

	if dtStream.Digest() != dtBuffer.Digest() {
		t.Fatalf("restore digest must be identical buffered vs streamed, got streamed=%q buffered=%q", dtStream.Digest(), dtBuffer.Digest())
	}
	if dtStream.VerifiedBytes() != dtBuffer.VerifiedBytes() {
		t.Fatalf("verified byte count must match buffered vs streamed, got streamed=%d buffered=%d", dtStream.VerifiedBytes(), dtBuffer.VerifiedBytes())
	}
}
