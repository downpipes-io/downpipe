package source

import (
	"os"
	"path/filepath"
	"testing"
)

// The traversal guard matters more on delete than on read. A traversal on a read leaks a file; a
// traversal on a delete destroys one, and the offline prune runs against an operator-supplied archive
// directory whose contents may be corrupt or hostile.
func TestDeleteRefusesToEscapeTheArchiveDirectory(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(t.TempDir(), "precious.txt")
	if err := os.WriteFile(outside, []byte("do not delete me"), 0o600); err != nil {
		t.Fatal(err)
	}

	d := &DirStore{baseDir: base}
	// A key that tries to climb out. Clean+Join roots it inside baseDir, so this must not reach the file.
	_ = d.Delete("../../" + filepath.Base(filepath.Dir(outside)) + "/" + filepath.Base(outside))

	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("a traversing key deleted a file outside the archive directory: %v", err)
	}
}

// os.Remove on a symlink removes the LINK and reports success, leaving the object it pointed at in
// place. That is the wrong outcome twice over: the archive object survives a prune that claimed to
// remove it, and a planted link could aim the delete anywhere. Refuse instead.
func TestDeleteRefusesASymlinkRatherThanUnlinkingIt(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(t.TempDir(), "real.seg")
	if err := os.WriteFile(target, []byte("archive bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "planted.seg")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	d := &DirStore{baseDir: base}
	if err := d.Delete("planted.seg"); err == nil {
		t.Fatal("expected a refusal for a symlink, got success")
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("the symlink itself was removed despite the refusal: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("the symlink target was destroyed: %v", err)
	}
}

// A prune that is interrupted and re-run must not fail on the work it already finished. Without this,
// an operator cannot tell "already done" from "cannot delete".
func TestDeleteIsIdempotent(t *testing.T) {
	base := t.TempDir()
	p := filepath.Join(base, "seg", "aa")
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "1.seg"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	d := &DirStore{baseDir: base}
	if err := d.Delete("seg/aa/1.seg"); err != nil {
		t.Fatalf("first delete failed: %v", err)
	}
	if err := d.Delete("seg/aa/1.seg"); err != nil {
		t.Fatalf("deleting an already-absent object must be a success, got %v", err)
	}
}

// List must return store keys a caller can hand straight back to Get or Delete, not filesystem paths.
func TestListReturnsStoreKeysUnderThePrefix(t *testing.T) {
	base := t.TempDir()
	for _, rel := range []string{"run/r1/root.manifest.json", "run/r1/manifest/0.dpe", "run/r2/root.manifest.json"} {
		full := filepath.Join(base, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	d := &DirStore{baseDir: base}
	keys, err := d.List("run/r1/")
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 objects under run/r1/, got %v", keys)
	}
	for _, k := range keys {
		if _, err := d.Get(k); err != nil {
			t.Fatalf("List returned key %q that Get cannot read: %v", k, err)
		}
	}
}

// An absent prefix is an empty listing rather than an error: a run tree already removed by an earlier,
// interrupted pass must not fail the re-run.
func TestListOfAnAbsentPrefixIsEmptyNotAnError(t *testing.T) {
	d := &DirStore{baseDir: t.TempDir()}
	keys, err := d.List("run/never-existed/")
	if err != nil {
		t.Fatalf("an absent prefix must list empty, got %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected no keys, got %v", keys)
	}
}
