package restore

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// DirTarget restores record values to files under a base directory: a record name maps
// to baseDir/<safeKey>. It is the filesystem directory sink (SPEC.md 12.6), importing
// nothing beyond the standard library so the offline path cannot phone home.
type DirTarget struct{ baseDir string }

// NewDirTarget returns a DirTarget rooted at baseDir.
func NewDirTarget(baseDir string) *DirTarget { return &DirTarget{baseDir: baseDir} }

// Kind reports the file target enum.
func (d *DirTarget) Kind() string { return "file" }

// Key maps a record name to a relative path contained within the base directory: a
// name containing ".." cannot escape it, and an empty result collapses to "_". The
// returned key is the slash form so it is stable across platforms in the plan.
//
// A path element that is a Windows reserved device name (CON, NUL, COM1, ...), with or
// without a trailing extension, is refused rather than written: such a name resolves to
// the device itself rather than a plain file on Windows, and downpipe.goreleaser.yaml
// ships Windows binaries. The check runs on every platform (not just runtime.GOOS ==
// "windows") so a plan produced on Linux/macOS stays valid if later applied on Windows,
// and refusing follows the same "cannot represent this name" idiom as EnvTarget.Key
// rather than silently mangling the filename.
//
// Case-insensitive file systems (macOS APFS, Windows NTFS by default): two record names
// that differ only in case (for example "Foo" and "foo") map to distinct keys here and
// are both planned as writes. The second Write will fail with O_EXCL at apply time and
// appear in Result.Failed. The plan cannot detect this ahead of time without a
// case-folding oracle for the host FS; operators on case-insensitive systems should
// review conflicts in the result rather than relying on the plan alone.
func (d *DirTarget) Key(name string) (string, error) {
	key := safeKey(name)
	if elem, ok := firstReservedWindowsElement(key); ok {
		return "", fmt.Errorf("record name %q contains the Windows reserved device name %q", name, elem)
	}
	return key, nil
}

// Existing walks the base directory and returns the set of slash-form relative paths
// already present, so the planner refuses to clobber a populated output. A missing
// base directory is an empty set, not an error, so a first restore into a fresh path
// plans cleanly.
func (d *DirTarget) Existing() (map[string]struct{}, error) {
	out := make(map[string]struct{})
	info, err := os.Stat(d.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, fmt.Errorf("inspect output directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("output path %s is not a directory", d.baseDir)
	}
	err = filepath.WalkDir(d.baseDir, func(p string, entry os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if entry.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(d.baseDir, p)
		if rerr != nil {
			return rerr
		}
		out[filepath.ToSlash(rel)] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("enumerate output directory: %w", err)
	}
	return out, nil
}

// Write creates baseDir/<key> at owner-only permissions and refuses to overwrite an
// existing file (O_EXCL), so a key that appeared after planning fails loudly rather
// than clobbering. On a write failure (most commonly ENOSPC: the disk filled up
// mid-restore) it removes the file it just created rather than leaving a 0-byte or
// partial file behind. Without this, a disk-full retry after freeing space hit the
// O_EXCL guard as a false "already exists" conflict on the truncated leftover from the
// failed attempt, blocking exactly the retry a customer needs to complete a restore
// once the actual cause (no space) is fixed. WriteStream carries the equivalent
// guarantee for a streamed value.
func (d *DirTarget) Write(key string, value []byte) error {
	root, err := d.openRoot()
	if err != nil {
		return fmt.Errorf("create directory for %s: %w", key, err)
	}
	defer func() { _ = root.Close() }()
	p := filepath.FromSlash(key)
	if err := mkdirAllIn(root, filepath.Dir(p)); err != nil {
		return fmt.Errorf("create directory for %s: %w", key, err)
	}
	fh, err := root.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write %s (it may already exist): %w", key, err)
	}
	if _, err := fh.Write(value); err != nil {
		_ = fh.Close()
		_ = root.Remove(p)
		return fmt.Errorf("write %s: %w", key, err)
	}
	if err := fh.Close(); err != nil {
		_ = root.Remove(p)
		return fmt.Errorf("write %s: %w", key, err)
	}
	return nil
}

// openRoot creates the base directory if it is missing and opens it as an os.Root. Every write
// goes through the root, so no path element can lead out of the base directory: a symlink that
// already sits in the output directory and points outside it is refused, not followed. The
// planner's Existing() does not walk into such a link, so without the root a record under its
// name planned as a clean write and landed wherever the link pointed.
func (d *DirTarget) openRoot() (*os.Root, error) {
	if err := os.MkdirAll(d.baseDir, 0o755); err != nil {
		return nil, err
	}
	return os.OpenRoot(d.baseDir)
}

// WriteStream restores baseDir/<key> from a stream with the same all-or-nothing guarantee
// as Write, refusing to overwrite an existing file (O_EXCL) exactly as Write does. It streams
// via io.Copy so a value larger than memory is restored in bounded memory; size is a hint only
// and the copy runs until src reports EOF.
//
// Because the reader checks a streamed record's plaintext SHA-384 only after the last byte has
// flowed, src can return an integrity error after bytes have already been copied. To avoid
// leaving a partial, untrusted file at the destination path (a partial could be mistaken for a
// good restore), the copy targets a temp file in the same directory and is renamed into place
// ONLY on a clean copy; on any error the temp file is removed so nothing lands at the
// destination. The no-clobber contract is preserved by reserving the destination path up front
// with O_EXCL (a 0-byte placeholder this call owns), so a pre-existing file is still refused
// before any bytes are written, and the rename only ever replaces our own placeholder.
func (d *DirTarget) WriteStream(key string, src io.Reader, _ int64) error {
	root, err := d.openRoot()
	if err != nil {
		return fmt.Errorf("create directory for %s: %w", key, err)
	}
	defer func() { _ = root.Close() }()
	p := filepath.FromSlash(key)
	dir := filepath.Dir(p)
	if err := mkdirAllIn(root, dir); err != nil {
		return fmt.Errorf("create directory for %s: %w", key, err)
	}
	// Reserve the destination atomically with O_EXCL so a pre-existing file is refused exactly
	// as Write does; the rename below only ever replaces this placeholder we just created.
	placeholder, err := root.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write %s (it may already exist): %w", key, err)
	}
	_ = placeholder.Close()
	// Stream into a temp file in the same directory so a failed copy never leaves a partial at
	// the destination; only a clean copy is renamed into place. On any error remove both the
	// temp file and the reserved placeholder so nothing untrusted is left behind.
	tmp, tmpPath, err := createTempIn(root, dir)
	if err != nil {
		_ = root.Remove(p)
		return fmt.Errorf("write %s: %w", key, err)
	}
	if _, err := io.Copy(tmp, src); err != nil {
		_ = tmp.Close()
		_ = root.Remove(tmpPath)
		_ = root.Remove(p)
		return fmt.Errorf("write %s: %w", key, err)
	}
	if err := tmp.Close(); err != nil {
		_ = root.Remove(tmpPath)
		_ = root.Remove(p)
		return fmt.Errorf("write %s: %w", key, err)
	}
	// The copy and integrity check passed: atomically replace our placeholder with the verified
	// bytes. On a rename failure remove the temp file and the placeholder so no partial lands.
	if err := root.Rename(tmpPath, p); err != nil {
		_ = root.Remove(tmpPath)
		_ = root.Remove(p)
		return fmt.Errorf("write %s: %w", key, err)
	}
	return nil
}

// mkdirAllIn creates dir and its parents inside root at 0755. Where a path element already
// exists as a file, os.Root reports EEXIST; os.MkdirAll reported ENOTDIR ("not a directory"),
// which is the reason an operator sees for the Worker content vs settings/versions path
// collision. The error keeps that meaning.
func mkdirAllIn(root *os.Root, dir string) error {
	err := root.MkdirAll(dir, 0o755)
	if errors.Is(err, fs.ErrExist) {
		return &fs.PathError{Op: "mkdir", Path: dir, Err: syscall.ENOTDIR}
	}
	return err
}

// createTempIn creates a new owner-only temp file in dir inside root, as os.CreateTemp does
// for a plain directory. os.Root has no CreateTemp, so it retries O_EXCL on a fresh name. The
// name needs to be unique, not secret: O_EXCL refuses any name that already exists.
func createTempIn(root *os.Root, dir string) (*os.File, string, error) {
	seed := time.Now().UnixNano()
	for i := range int64(100) {
		name := filepath.Join(dir, ".downpipe-restore-"+strconv.Itoa(os.Getpid())+"-"+strconv.FormatInt(seed+i, 36))
		fh, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return fh, name, nil
		}
		if !os.IsExist(err) {
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("create a temp file in %s: too many name collisions", dir)
}

// MetadataKey names the sidecar that holds the source metadata of the value at key: the same
// path with MetadataSidecarSuffix appended, in the same directory (SPEC.md 6.3).
func (d *DirTarget) MetadataKey(key string) string { return key + MetadataSidecarSuffix }

// WriteMetadata writes a record's metadata sidecar next to its value. It goes through Write,
// so it has the same guarantees: owner-only permissions, no path outside the base directory,
// O_EXCL so an existing file is refused and never overwritten, and no partial file on error.
func (d *DirTarget) WriteMetadata(key string, doc []byte) error {
	return d.Write(d.MetadataKey(key), doc)
}

// Close is a no-op; DirTarget writes each value immediately.
func (d *DirTarget) Close() error { return nil }

// safeKey turns an arbitrary record name into a relative path contained within the
// base directory by dropping empty, "." and ".." path elements.
//
// BOTH "/" and "\" are treated as element separators on EVERY platform, not just the
// local one. The record name comes from the backed-up source, so it is archive
// controlled: splitting on the local separator only means a name carrying backslashes
// (`..\..\etc\passwd`, `\\server\share`) is cleaned on Windows but kept as a literal
// file name on Unix, so one archive restores to two different layouts and a file
// restored on Unix carries a name that is a traversal path the moment it reaches
// Windows. Splitting on both makes the mapping deterministic across platforms and
// leaves no separator inside an element, which is the same conservative posture as the
// Windows-reserved-name guard below.
func safeKey(name string) string {
	parts := strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '\\' })
	clean := parts[:0]
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			continue
		}
		clean = append(clean, p)
	}
	if len(clean) == 0 {
		return "_"
	}
	return filepath.ToSlash(filepath.Join(clean...))
}

// windowsReservedNames are the DOS-era device names Windows resolves to an I/O device
// rather than a plain file, at any path depth. This is the same bug class Go's own
// archive/zip patched under GO-2021-0113 / CVE-2021-33196. The table mirrors
// isReservedBaseName in the standard library (internal/filepathlite/path_windows.go)
// exactly, including two forms that are easy to miss because they don't look like the
// ASCII COM1-9/LPT1-9 names: Windows treats the superscript digits U+00B9/U+00B2/U+00B3
// ("¹²³") as equivalent to 1/2/3 in a COM/LPT name unconditionally (not a
// version-dependent case, unlike the trailing-extension rule below), and CONIN$/CONOUT$
// unconditionally open a console handle the same way CON does.
var windowsReservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"COM¹": true, "COM²": true, "COM³": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
	"LPT¹": true, "LPT²": true, "LPT³": true,
	"CONIN$": true, "CONOUT$": true,
}

// firstReservedWindowsElement reports the first slash-separated element of a safeKey
// result that is a Windows reserved device name. It reduces each element to the base name
// Windows actually resolves before the lookup, mirroring the standard library's
// isReservedName (internal/filepathlite/path_windows.go): the base is the substring before
// the element's first "." or ":" (an extension or an NTFS alternate-data-stream suffix is
// ignored, so "COM1.txt" and "CON:bar" both resolve to the device), and any trailing
// spaces are then stripped (Windows ignores them, so "CON " and "CON .txt" also resolve to
// the device). The match on the reduced base is case-insensitive. Refusing regardless of a
// trailing extension is deliberately more conservative than modern Windows 11, where
// "CON.txt" is a valid file name, because the name is still reserved on older versions the
// shipped Windows binaries may run on.
func firstReservedWindowsElement(key string) (elem string, ok bool) {
	for _, part := range strings.Split(key, "/") {
		base := part
		if i := strings.IndexAny(base, ".:"); i >= 0 {
			base = base[:i]
		}
		base = strings.TrimRight(base, " ")
		if windowsReservedNames[strings.ToUpper(base)] {
			return part, true
		}
	}
	return "", false
}
