package source

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDirStore(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "run", "abc"), 0o755); err != nil {
		t.Fatal(err)
	}
	want := []byte("manifest bytes")
	if err := os.WriteFile(filepath.Join(dir, "run", "abc", "root.manifest.json"), want, 0o644); err != nil {
		t.Fatal(err)
	}

	s := NewDirStore(dir)

	got, err := s.Get("run/abc/root.manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("content mismatch: %q", got)
	}

	if _, err := s.Get("run/abc/missing.json"); err == nil {
		t.Fatal("a missing object must error")
	}

	// A traversal key is contained within baseDir, so it cannot read a real file above
	// the root; it simply does not resolve to anything that exists in the temp dir.
	if _, err := s.Get("../../../../etc/hosts"); err == nil {
		t.Fatal("a traversal key must not read a file above the root")
	}
}

// A symlink object in the archive must be refused, not followed: a planted link cannot
// redirect a read to a file outside the recovery directory (or to a device).
func TestDirStoreRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privilege on Windows; the Lstat guard is exercised on unix")
	}
	dir := t.TempDir()
	// A secret outside the archive root the symlink would otherwise expose.
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("escaped"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "object.seg")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	s := NewDirStore(dir)
	if _, err := s.Get("object.seg"); err == nil {
		t.Fatal("a symlink object must be refused, not followed out of the archive root")
	}
}

// An object up to the per-object ceiling reads verbatim; one past it is rejected rather
// than fully buffered. A small injected limit exercises the same guard the 2 GiB default
// enforces in production.
func TestDirStoreSizeLimit(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.seg"), []byte("12345678"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "big.seg"), []byte("123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Limit of 8 bytes: ok.seg (8) reads, big.seg (9) is refused.
	s := &DirStore{baseDir: dir, maxBytes: 8}

	got, err := s.Get("ok.seg")
	if err != nil {
		t.Fatalf("an object at the limit must read: %v", err)
	}
	if string(got) != "12345678" {
		t.Fatalf("at-limit read mismatch: %q", got)
	}
	if _, err := s.Get("big.seg"); err == nil {
		t.Fatal("an object past the limit must be refused, not buffered")
	}
}
