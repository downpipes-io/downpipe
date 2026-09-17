package source

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDirStoreGetReaderStreamsWithSameHardening(t *testing.T) {
	dir := t.TempDir()
	want := strings.Repeat("v", 4096)
	if err := os.WriteFile(filepath.Join(dir, "obj"), []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}
	d := NewDirStore(dir)

	rc, size, err := d.GetReader(context.Background(), "obj")
	if err != nil {
		t.Fatalf("GetReader: %v", err)
	}
	defer func() { _ = rc.Close() }()
	if size != int64(len(want)) {
		t.Fatalf("size hint %d, want %d", size, len(want))
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != want {
		t.Fatalf("streamed bytes differ: %d bytes", len(got))
	}
}

func TestDirStoreGetReaderRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "real"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	d := NewDirStore(dir)
	if _, _, err := d.GetReader(context.Background(), "link"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected the symlink refusal, got %v", err)
	}
}

func TestDirStoreGetReaderBoundsTheStream(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "obj"), []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := NewDirStore(dir)
	d.maxBytes = 4

	// The fd-stat catches the oversize up front (the file has not changed under us).
	if _, _, err := d.GetReader(context.Background(), "obj"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected the size refusal, got %v", err)
	}

	// The mid-stream guard is the hard bound: grow the file AFTER the open so the
	// fd-stat passed, and the bounded reader must abort with an explicit error.
	if err := os.WriteFile(filepath.Join(dir, "grow"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	rc, _, err := d.GetReader(context.Background(), "grow")
	if err != nil {
		t.Fatalf("GetReader: %v", err)
	}
	defer func() { _ = rc.Close() }()
	if err := os.WriteFile(filepath.Join(dir, "grow"), []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, rerr := io.ReadAll(rc)
	if rerr == nil || !strings.Contains(rerr.Error(), "exceeds") {
		t.Fatalf("expected the mid-stream ceiling error, got %v", rerr)
	}
}

// streamTestStore builds an S3Store against an httptest server.
func streamTestStore(t *testing.T, srv *httptest.Server) *S3Store {
	t.Helper()
	s, err := NewS3Store(S3Config{Endpoint: srv.URL, Bucket: "b", Region: "auto", AccessKeyID: "k", SecretKey: "s"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestS3GetReaderStreamsSignedGet(t *testing.T) {
	want := strings.Repeat("z", 200000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" || r.Header.Get("x-amz-date") == "" {
			t.Error("streamed GET must carry the SigV4 headers")
		}
		if r.URL.Path != "/b/seg/ab/abc.seg" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_, _ = io.WriteString(w, want)
	}))
	defer srv.Close()
	s := streamTestStore(t, srv)

	rc, _, err := s.GetReader(context.Background(), "seg/ab/abc.seg")
	if err != nil {
		t.Fatalf("GetReader: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != want {
		t.Fatalf("streamed body differs: %d bytes", len(got))
	}
}

func TestS3GetReaderRejectsNonOKAndOversize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/b/missing":
			http.Error(w, "no", http.StatusNotFound)
		case "/b/huge":
			w.Header().Set("Content-Length", fmt.Sprint(maxObjectBytes+1))
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	s := streamTestStore(t, srv)

	if _, _, err := s.GetReader(context.Background(), "missing"); err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("expected status 404 error, got %v", err)
	}
	if _, _, err := s.GetReader(context.Background(), "huge"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected the size refusal, got %v", err)
	}
}

func TestS3GetReaderAbortsStalledBody(t *testing.T) {
	stall := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "some early bytes")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Stall until released or the client abandons the request. Selecting on the
		// request context is what lets srv.Close() (which waits for handlers) finish:
		// a handler parked on a bare channel would deadlock the shutdown.
		select {
		case <-stall:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(stall) // LIFO: release the handler BEFORE srv.Close waits on it
	s := streamTestStore(t, srv)
	s.idleTimeout = 150 * time.Millisecond

	rc, _, err := s.GetReader(context.Background(), "stalled")
	if err != nil {
		t.Fatalf("GetReader: %v", err)
	}
	defer func() { _ = rc.Close() }()
	start := time.Now()
	_, rerr := io.ReadAll(rc)
	elapsed := time.Since(start)
	if rerr == nil || !strings.Contains(rerr.Error(), "stalled") {
		t.Fatalf("expected the stalled-stream abort, got %v", rerr)
	}
	// The watchdog must fire near the idle bound, never the 60 s whole-request class.
	if elapsed > 5*time.Second {
		t.Fatalf("stalled stream took %s to abort", elapsed)
	}
}
