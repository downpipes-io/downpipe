package source

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// getLimiter is the GetLimit capability the reader discovers by type assertion
// (format.LimitStore). The source package cannot import format, so it states the method.
type getLimiter interface {
	GetLimit(key string, ceiling int64) ([]byte, error)
}

// assertGetLimit checks one backend that serves a 64-byte object at key: a ceiling of 64
// reads it, a ceiling of 8 refuses it, and the store's own smaller limit still applies
// when the caller's ceiling is larger.
func assertGetLimit(t *testing.T, s getLimiter, smaller getLimiter, key string) {
	t.Helper()
	got, err := s.GetLimit(key, 64)
	if err != nil {
		t.Fatalf("an object at the ceiling must read: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("read %d bytes, want 64", len(got))
	}
	if _, err := s.GetLimit(key, 8); err == nil || !strings.Contains(err.Error(), "exceeds the 8-byte limit") {
		t.Fatalf("an object above the ceiling must be refused with the ceiling named, got: %v", err)
	}
	if _, err := smaller.GetLimit(key, 1<<20); err == nil || !strings.Contains(err.Error(), "exceeds the 4-byte limit") {
		t.Fatalf("the store's own limit must still apply under a larger ceiling, got: %v", err)
	}
}

func TestDirStoreGetLimit(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "root.json"), bytes.Repeat([]byte("x"), 64), 0o600); err != nil {
		t.Fatal(err)
	}
	assertGetLimit(t, NewDirStore(dir), &DirStore{baseDir: dir, maxBytes: 4}, "root.json")
}

func TestS3StoreGetLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 64))
	}))
	defer srv.Close()
	newStore := func() *S3Store {
		s, err := NewS3Store(S3Config{Endpoint: srv.URL, Bucket: "bucket", Region: "auto", AccessKeyID: "AKID", SecretKey: "secret"})
		if err != nil {
			t.Fatalf("NewS3Store: %v", err)
		}
		return s
	}
	smaller := newStore()
	smaller.maxBytes = 4
	assertGetLimit(t, newStore(), smaller, "run/abc/root.manifest.json")
}

func TestAzureStoreGetLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 64))
	}))
	defer srv.Close()
	smaller := azureTestStore(t, srv.URL, nil)
	smaller.maxBytes = 4
	assertGetLimit(t, azureTestStore(t, srv.URL, nil), smaller, "run/abc/root.manifest.json")
}
