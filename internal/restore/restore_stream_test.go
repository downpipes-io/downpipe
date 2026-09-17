package restore

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// streamingFakeReader is a recordReader that also implements streamingReader, so the
// streaming Apply path (applyStream + DirTarget.WriteStream) can be exercised without
// standing up a whole encrypted archive (the real end-to-end break-glass stream path is
// covered in internal/format). It produces each record's value through RestoreRecordTo by
// copying the in-memory bytes to the destination, optionally injecting a write error after
// some bytes to mimic a tampered or truncated segment surfacing only after partial output.
type streamingFakeReader struct {
	recs   []spec.ShardRecord
	values map[string][]byte
	// failAfter names records whose RestoreRecordTo writes the value then returns an error,
	// to mimic the integrity verdict arriving after bytes have already streamed to the sink.
	failAfter map[string]bool
	// notStreamable names records IsStreamable reports false for, to force the fallback.
	notStreamable map[string]bool
	streamed      map[string]bool // records that went through the streaming path
}

func newStreamingReader(pairs ...[2]string) *streamingFakeReader {
	f := &streamingFakeReader{
		values:        map[string][]byte{},
		failAfter:     map[string]bool{},
		notStreamable: map[string]bool{},
		streamed:      map[string]bool{},
	}
	for i, p := range pairs {
		name, val := p[0], p[1]
		f.recs = append(f.recs, spec.ShardRecord{
			SourceType: "r2", Name: name, RecordID: fmt.Sprintf("r%015d", i),
			// The fakes model LARGE values (metadata only; the actual bytes stay small) so the
			// size gate in writeOneRecord admits them to the streaming path under test.
			// DirTarget.WriteStream ignores the size parameter, so the mismatch is harmless.
			PlaintextSize: streamThreshold + int64(len(val)),
		})
		f.values[name] = []byte(val)
	}
	return f
}

func (f *streamingFakeReader) Records() []spec.ShardRecord { return f.recs }

func (f *streamingFakeReader) RestoreRecord(rec spec.ShardRecord) ([]byte, error) {
	v, ok := f.values[rec.Name]
	if !ok {
		return nil, fmt.Errorf("no value for %s", rec.Name)
	}
	return v, nil
}

func (f *streamingFakeReader) IsStreamable(rec spec.ShardRecord) bool {
	return !f.notStreamable[rec.Name]
}

func (f *streamingFakeReader) RestoreRecordTo(rec spec.ShardRecord, dst io.Writer) error {
	f.streamed[rec.Name] = true
	v, ok := f.values[rec.Name]
	if !ok {
		return fmt.Errorf("no value for %s", rec.Name)
	}
	if _, err := dst.Write(v); err != nil {
		return err
	}
	if f.failAfter[rec.Name] {
		// The integrity verdict arrives after the bytes have streamed, exactly like the real
		// reader's per-record SHA-384 check, which runs only after the last byte is written.
		return fmt.Errorf("record %s failed its plaintext hash check", rec.Name)
	}
	return nil
}

// A clean streaming Apply must write byte-identical files through the pipe bridge and count
// the restored bytes, proving the writer-to-reader bridge does not corrupt or truncate.
func TestApplyStreamingWritesBytes(t *testing.T) {
	dir := t.TempDir()
	// Repeat enough that the payload spans at least two STREAM chunks regardless of the
	// configured chunk size, so the bridge is exercised across a chunk boundary.
	const payload = "streamed-payload-"
	repeats := (spec.ChunkSize/len(payload) + 1) * 2
	big := bytes.Repeat([]byte(payload), repeats)
	r := newStreamingReader([2]string{"a", "alpha"}, [2]string{"big", string(big)})
	target := NewDirTarget(dir)

	_, res, err := Apply(r, target, true)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !res.OK() || res.Restored != 2 {
		t.Fatalf("expected 2 records restored, got restored=%d failed=%+v", res.Restored, res.Failed)
	}
	if res.BytesRestored != int64(len("alpha")+len(big)) {
		t.Fatalf("byte total wrong: %d", res.BytesRestored)
	}
	// Both records must have gone through the streaming path, not the buffering fallback.
	if !r.streamed["a"] || !r.streamed["big"] {
		t.Fatalf("records did not stream: %v", r.streamed)
	}
	got, err := os.ReadFile(filepath.Join(dir, "a"))
	if err != nil || string(got) != "alpha" {
		t.Fatalf("file a: %q err=%v", got, err)
	}
	got, err = os.ReadFile(filepath.Join(dir, "big"))
	if err != nil {
		t.Fatalf("read big: %v", err)
	}
	if !bytes.Equal(got, big) {
		t.Fatalf("streamed file mismatch: got %d bytes, want %d", len(got), len(big))
	}
}

// A record whose streaming restore fails its integrity check after partial output must be
// recorded as a failure (not laundered as success), and the apply must continue past it.
// This proves the integrity gate survives the streaming Apply path end to end.
func TestApplyStreamingTamperedRecordFails(t *testing.T) {
	dir := t.TempDir()
	r := newStreamingReader([2]string{"good1", "g1"}, [2]string{"bad", "corrupt"}, [2]string{"good2", "g2"})
	r.failAfter["bad"] = true
	target := NewDirTarget(dir)

	_, res, err := Apply(r, target, true)
	if err != nil {
		t.Fatalf("a per-record failure must not abort the apply: %v", err)
	}
	if res.Restored != 2 {
		t.Fatalf("expected 2 records restored around the failure, got %d", res.Restored)
	}
	if len(res.Failed) != 1 || res.Failed[0].Name != "bad" {
		t.Fatalf("expected exactly one failure for 'bad', got %+v", res.Failed)
	}
	if res.OK() {
		t.Fatal("OK must be false when a streamed record failed its integrity check")
	}
	// The two good records were written despite the failure between them.
	for _, name := range []string{"good1", "good2"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("good record %s should have been written: %v", name, err)
		}
	}
	// The tampered record must leave NO partial file at its destination, matching the buffering
	// path's all-or-nothing guarantee: a partial could be mistaken for a good restore.
	if _, err := os.Stat(filepath.Join(dir, "bad")); !os.IsNotExist(err) {
		t.Fatalf("tampered streamed record left a file at its destination (stat err=%v); the partial must be removed", err)
	}
	// No temp/quarantine file may be left behind in the directory either.
	assertNoTempFiles(t, dir)
}

// errAfterReader yields n good bytes and then returns an error mid-stream, mimicking a
// tampered or truncated segment whose integrity verdict arrives after bytes have streamed.
type errAfterReader struct {
	data []byte
	pos  int
	err  error
}

func (r *errAfterReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, r.err
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// assertNoTempFiles fails if any quarantine/temp file from a staged stream write remains in
// dir, so a failed restore cleans up after itself and leaves nothing partial behind.
func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".downpipe-restore-") {
			t.Fatalf("a temp/quarantine file was left behind: %s", e.Name())
		}
	}
}

// WriteStream must leave NO partial file at the destination when the copy errors after some
// bytes have already streamed (the real reader's per-record SHA-384 check fires only after the
// last byte). This exercises DirTarget.WriteStream directly so the temp-then-rename staging is
// proven independent of the pipe bridge, including the cleanup of any temp file.
func TestDirTargetWriteStreamLeavesNoPartialOnError(t *testing.T) {
	dir := t.TempDir()
	d := NewDirTarget(dir)
	src := &errAfterReader{data: []byte("partial-bytes-already-flowed"), err: fmt.Errorf("record failed its plaintext hash check")}

	err := d.WriteStream("k", src, int64(len(src.data)))
	if err == nil {
		t.Fatal("WriteStream must return the mid-stream error")
	}
	// Nothing may be left at the destination path: not the partial, not the reservation.
	if _, statErr := os.Stat(filepath.Join(dir, "k")); !os.IsNotExist(statErr) {
		t.Fatalf("WriteStream left a file at the destination after a mid-stream error (stat err=%v)", statErr)
	}
	assertNoTempFiles(t, dir)
}

// After a clean WriteStream the temp staging file must be gone and only the destination file
// remains, so the happy path also leaves no quarantine litter.
func TestDirTargetWriteStreamCleanLeavesOnlyDestination(t *testing.T) {
	dir := t.TempDir()
	d := NewDirTarget(dir)
	if err := d.WriteStream("k", bytes.NewReader([]byte("verified")), 8); err != nil {
		t.Fatalf("clean WriteStream: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "k"))
	if err != nil || string(got) != "verified" {
		t.Fatalf("destination file wrong after clean write: %q err=%v", got, err)
	}
	assertNoTempFiles(t, dir)
}

// A non-streamable record (gzip/packed in the real reader) must fall back to the buffering
// path (RestoreRecord + Write) even when both sides support streaming, so the codec or slice
// is never skipped.
func TestApplyStreamingFallsBackForNonStreamable(t *testing.T) {
	dir := t.TempDir()
	r := newStreamingReader([2]string{"plain", "p"}, [2]string{"packed", "k"})
	r.notStreamable["packed"] = true
	target := NewDirTarget(dir)

	_, res, err := Apply(r, target, true)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Restored != 2 {
		t.Fatalf("expected 2 restored, got %d", res.Restored)
	}
	if r.streamed["packed"] {
		t.Fatal("a non-streamable record must not go through the streaming path")
	}
	if !r.streamed["plain"] {
		t.Fatal("a streamable record should still stream")
	}
	got, err := os.ReadFile(filepath.Join(dir, "packed"))
	if err != nil || string(got) != "k" {
		t.Fatalf("non-streamable record must still be written via the buffering path: %q err=%v", got, err)
	}
}

// The streaming WriteStream must honour the no-clobber guard exactly as Write does: a
// pre-existing destination file is a planned conflict and is never streamed over.
func TestApplyStreamingNoClobber(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newStreamingReader([2]string{"a", "alpha"}, [2]string{"b", "bravo"})
	target := NewDirTarget(dir)

	plan, res, err := Apply(r, target, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Conflicts) != 1 || plan.Conflicts[0].Name != "a" || plan.Conflicts[0].Kind != ConflictExisting {
		t.Fatalf("expected one existing-file conflict for 'a', got %+v", plan.Conflicts)
	}
	if res.Restored != 1 {
		t.Fatalf("expected 1 restored (b), got %d", res.Restored)
	}
	got, err := os.ReadFile(filepath.Join(dir, "a"))
	if err != nil || string(got) != "ORIGINAL" {
		t.Fatalf("no-clobber violated on the streaming path: file a is now %q (err=%v)", got, err)
	}
}

// DirTarget.WriteStream directly must refuse to overwrite an existing file (O_EXCL), the
// defence-in-depth guard mirroring Write.
func TestDirTargetWriteStreamNoClobberDirect(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "k"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := NewDirTarget(dir)
	err := d.WriteStream("k", bytes.NewReader([]byte("new")), 3)
	if err == nil {
		t.Fatal("WriteStream must refuse to overwrite an existing file")
	}
	got, _ := os.ReadFile(filepath.Join(dir, "k"))
	if string(got) != "x" {
		t.Fatalf("WriteStream clobbered the existing file: %q", got)
	}
}
