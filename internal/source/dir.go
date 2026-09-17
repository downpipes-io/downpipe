// Package source reads downpipe archives from a backing store. DirStore is the
// local-disk backend (the offline recovery path); a minimal S3 GET backend is added
// alongside it. Neither imports a network, telemetry or vendor package beyond the
// bytes, so the offline reader cannot phone home (CONTRIBUTING).
package source

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// DirStore reads archive objects from a local directory: an object key maps to the
// file at baseDir/<key>. It satisfies the reader's ObjectStore by structural typing,
// so it needs no import of the format package.
type DirStore struct {
	baseDir string
	// maxBytes is the per-object read ceiling; 0 means the package default
	// (maxObjectBytes). It is settable only within the package so the size guard can be
	// exercised with a small limit in tests.
	maxBytes int64
}

// NewDirStore returns a DirStore rooted at baseDir.
func NewDirStore(baseDir string) *DirStore { return &DirStore{baseDir: baseDir} }

// limit returns the effective per-object ceiling for this store.
func (d *DirStore) limit() int64 {
	if d.maxBytes > 0 {
		return d.maxBytes
	}
	return maxObjectBytes
}

// maxObjectBytes bounds a single archive object read so a hostile or corrupt store
// cannot drive an unbounded allocation before any integrity check runs. The spec caps
// a segment at 1 GiB of plaintext (SPEC.md 14.5); this ceiling covers that plus the
// STREAM framing with margin, and is shared by every source backend in this package.
const maxObjectBytes int64 = 2 << 30

// Get reads the object at the given key. The key is cleaned and rooted, so a key
// containing ".." cannot name a file above baseDir.
//
// The read is hardened the same way the S3 backend bounds its body (the offline reader
// runs over an operator-supplied archive that may be corrupt or hostile):
//
//   - A symlink final component is refused (Lstat, which does not follow), so a planted
//     symlink in the archive cannot redirect the read to a file outside baseDir or to a
//     device such as /dev/zero. The earlier path-based os.Stat followed symlinks.
//   - The object is opened ONCE and both the size check and the read operate on that single
//     descriptor, so the size is not re-resolved from the path between the check and the
//     read (the earlier os.Stat-then-os.ReadFile was a time-of-check/time-of-use gap: the
//     file could be swapped after the stat passed).
//   - The read is bounded by io.LimitReader to maxObjectBytes+1 and rejected if it exceeds,
//     so even a descriptor whose true length outgrew the fd-stat is capped rather than fully
//     buffered. This is the hard guard; the fd-stat is only a cheap early exit.
func (d *DirStore) Get(key string) ([]byte, error) {
	rel := filepath.Clean("/" + filepath.FromSlash(key))
	p := filepath.Join(d.baseDir, rel)

	// Lstat (not Stat) so a symlink is detected rather than followed: an archive object
	// must be a regular file, never a link out of the recovery directory.
	if li, err := os.Lstat(p); err == nil && li.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("read object %s: refusing to follow a symlink", key)
	}

	fh, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("read object %s: %w", key, err)
	}
	defer func() { _ = fh.Close() }()

	limit := d.limit()
	// Stat the open descriptor (not the path) so the size check and the read see the same
	// file: a cheap early rejection before reading a clearly oversized object.
	if fi, err := fh.Stat(); err == nil {
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("read object %s: not a regular file", key)
		}
		if fi.Size() > limit {
			return nil, fmt.Errorf("read object %s: %d bytes exceeds the %d-byte limit", key, fi.Size(), limit)
		}
	}

	// The bounded read is the hard guard, mirroring the S3 backend: read at most
	// limit+1 and reject anything that reaches the ceiling.
	b, err := io.ReadAll(io.LimitReader(fh, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read object %s: %w", key, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("read object %s: object exceeds the %d-byte limit", key, limit)
	}
	return b, nil
}

// Delete removes the object at the given key, satisfying format.MutatingStore.
//
// The key is cleaned and rooted exactly as Get does, so a key containing ".." cannot name a file above
// baseDir. That guard matters more here than on the read path: a traversal on a read leaks, a traversal
// on a delete destroys, and the offline prune runs against an operator-supplied archive directory.
//
// A symlink final component is refused rather than followed, so a planted link cannot redirect the
// delete to a file outside the archive. Note that refusing is not merely safer than following, it is
// the only correct behaviour: os.Remove on a symlink removes the LINK, which would leave the archive
// object it pointed at in place and report success.
//
// An already-absent object is a SUCCESS. The prune must be re-runnable after an interruption without
// failing on the work it already completed.
func (d *DirStore) Delete(key string) error {
	rel := filepath.Clean("/" + filepath.FromSlash(key))
	p := filepath.Join(d.baseDir, rel)

	if li, err := os.Lstat(p); err == nil && li.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("delete object %s: refusing to follow a symlink", key)
	}
	if err := os.Remove(p); err != nil {
		if os.IsNotExist(err) {
			return nil // already gone: the desired end state
		}
		return fmt.Errorf("delete object %s: %w", key, err)
	}
	return nil
}

// List returns the object keys under prefix, satisfying format.ListingStore. Keys are returned in the
// store's own slash-separated form, not filesystem paths, so a caller can hand them straight back to
// Get or Delete. Directories are not returned; only files are objects.
func (d *DirStore) List(prefix string) ([]string, error) {
	rel := filepath.Clean("/" + filepath.FromSlash(prefix))
	root := filepath.Join(d.baseDir, rel)

	var keys []string
	err := filepath.WalkDir(root, func(p string, entry os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil // an absent prefix is an empty listing, not a failure
			}
			return err
		}
		if entry.IsDir() {
			return nil
		}
		// Skip symlinks rather than reporting them as objects: a caller would otherwise be handed a key
		// that Get and Delete both refuse, which reads as a store inconsistency.
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		r, relErr := filepath.Rel(d.baseDir, p)
		if relErr != nil {
			return relErr
		}
		keys = append(keys, filepath.ToSlash(r))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list objects under %s: %w", prefix, err)
	}
	return keys, nil
}
