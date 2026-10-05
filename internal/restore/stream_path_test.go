package restore

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/source"
)

// spyTarget wraps a real DirTarget and counts which write path each record took, so a
// test can assert the streaming path actually ran rather than inferring it from output
// bytes (both paths produce identical files by design).
type spyTarget struct {
	*DirTarget
	writes       int
	streamWrites int
}

func (s *spyTarget) Write(key string, value []byte) error {
	s.writes++
	return s.DirTarget.Write(key, value)
}

func (s *spyTarget) WriteStream(key string, src io.Reader, size int64) error {
	s.streamWrites++
	return s.DirTarget.WriteStream(key, src, size)
}

// TestStreamingPathSelection pins the path selection against REAL readers on a real
// sealed archive: a streamable record at streamThreshold or above flows through
// WriteStream, a small record keeps the single buffered write, and the restored bytes
// are byte-identical either way. This is the regression guard for the defect where
// *format.Reader lacked the IsStreamable method, so the streamingReader assertion
// always failed and every record silently took the buffered path.
func TestStreamingPathSelection(t *testing.T) {
	big := strings.Repeat("S", streamThreshold)
	values := map[string]string{
		"big/value":   big,
		"small/value": "buffered path stays for small records",
	}
	store := memStore{}
	identity, verifier, runID := buildArchive(t, store, "dp_streampath", "kv", values)

	check := func(t *testing.T, spy *spyTarget, dir string, res *Result) {
		t.Helper()
		if !res.OK() || res.Restored != len(values) {
			t.Fatalf("restore: restored=%d failed=%v", res.Restored, res.Failed)
		}
		if spy.streamWrites != 1 {
			t.Fatalf("expected exactly the big record on the streaming path, got %d stream writes", spy.streamWrites)
		}
		if spy.writes != 1 {
			t.Fatalf("expected exactly the small record on the buffered path, got %d buffered writes", spy.writes)
		}
		for name, want := range values {
			got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(safeKey(name))))
			if err != nil {
				t.Fatalf("read restored %s: %v", name, err)
			}
			if string(got) != want {
				t.Fatalf("restored %s: %d bytes, want %d", name, len(got), len(want))
			}
		}
	}

	t.Run("load-all reader through Apply", func(t *testing.T) {
		r, err := format.Open(store, runID, identity, verifier, format.Options{})
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		dir := t.TempDir()
		spy := &spyTarget{DirTarget: NewDirTarget(dir)}
		_, res, err := Apply(r, spy, true)
		if err != nil {
			t.Fatal(err)
		}
		check(t, spy, dir, res)
	})

	t.Run("streaming reader through ApplyStreaming", func(t *testing.T) {
		r, err := format.StreamOpen(store, runID, identity, verifier, format.Options{})
		if err != nil {
			t.Fatalf("stream open: %v", err)
		}
		dir := t.TempDir()
		spy := &spyTarget{DirTarget: NewDirTarget(dir)}
		_, res, err := ApplyStreaming(r, spy, true)
		if err != nil {
			t.Fatal(err)
		}
		check(t, spy, dir, res)
	})

	// The DirStore offers the streamed-read capability, so this leg proves the whole
	// chain end to end: streamed store read, streamed decrypt, streamed target write.
	t.Run("streaming reader over a DirStore archive", func(t *testing.T) {
		archiveDir := t.TempDir()
		for key, b := range store {
			p := filepath.Join(archiveDir, filepath.FromSlash(key))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		r, err := format.StreamOpen(source.NewDirStore(archiveDir), runID, identity, verifier, format.Options{})
		if err != nil {
			t.Fatalf("stream open: %v", err)
		}
		dir := t.TempDir()
		spy := &spyTarget{DirTarget: NewDirTarget(dir)}
		_, res, err := ApplyStreaming(r, spy, true)
		if err != nil {
			t.Fatal(err)
		}
		check(t, spy, dir, res)
	})
}
