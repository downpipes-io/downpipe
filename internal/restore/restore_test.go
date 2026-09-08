package restore

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// fakeReader is a recordReader backed by in-memory values, so the plan, no-clobber and
// apply paths can be exercised without standing up a whole encrypted archive. The
// end-to-end break-glass decrypt path is covered separately in e2e_test.go.
type fakeReader struct {
	recs   []spec.ShardRecord
	values map[string][]byte // record name -> plaintext value
	// failOn names records whose RestoreRecord returns an error, to exercise the
	// honest partial-failure path (a hash mismatch or a missing segment in the real
	// reader surfaces the same way).
	failOn map[string]bool
}

func (f *fakeReader) Records() []spec.ShardRecord { return f.recs }

// EachRecord makes fakeReader a restore.StreamSource so the same fixtures drive the
// streaming apply (ApplyStreaming) as well as the load-all Apply, yielding the records in
// the order given (canonical order, as the caller supplies it).
func (f *fakeReader) EachRecord(fn func(spec.ShardRecord) error) error {
	for _, rec := range f.recs {
		if err := fn(rec); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeReader) RestoreRecord(rec spec.ShardRecord) ([]byte, error) {
	if f.failOn[rec.Name] {
		return nil, fmt.Errorf("record %s failed its plaintext hash check", rec.Name)
	}
	v, ok := f.values[rec.Name]
	if !ok {
		return nil, fmt.Errorf("no value for %s", rec.Name)
	}
	return v, nil
}

// rdr builds a fakeReader from name/value pairs. The records are listed in the order
// given (the caller supplies canonical order), and PlaintextSize is the value length so
// the plan's byte total is exercised.
func rdr(pairs ...[2]string) *fakeReader {
	f := &fakeReader{values: map[string][]byte{}, failOn: map[string]bool{}}
	for i, p := range pairs {
		name, val := p[0], p[1]
		f.recs = append(f.recs, spec.ShardRecord{
			SourceType: "kv", Name: name, RecordID: fmt.Sprintf("recordid%08d", i),
			PlaintextSize: int64(len(val)),
		})
		f.values[name] = []byte(val)
	}
	return f
}

func TestPlanDryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	r := rdr([2]string{"a", "alpha"}, [2]string{"b", "bravo"})
	target := NewDirTarget(dir)

	plan, res, err := Apply(r, target, false) // confirm=false: dry run
	if err != nil {
		t.Fatal(err)
	}
	if !res.DryRun {
		t.Fatal("a confirm=false apply must be a dry run")
	}
	if res.Restored != 0 || res.BytesRestored != 0 {
		t.Fatalf("a dry run must write nothing, restored %d (%d bytes)", res.Restored, res.BytesRestored)
	}
	if len(plan.Writes) != 2 {
		t.Fatalf("plan should list 2 writes, got %d", len(plan.Writes))
	}
	if plan.TotalBytes != int64(len("alpha")+len("bravo")) {
		t.Fatalf("plan byte total wrong: %d", plan.TotalBytes)
	}
	if plan.HasConflicts() {
		t.Fatal("a clean plan must report no conflicts")
	}
	// The directory must still be empty: a dry run does not touch the target.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("dry run wrote %d file(s) into the output", len(entries))
	}
}

func TestApplyWritesAndIsLoud(t *testing.T) {
	dir := t.TempDir()
	r := rdr([2]string{"a", "alpha"}, [2]string{"nested/b", "bravo"})
	target := NewDirTarget(dir)

	plan, res, err := Apply(r, target, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.DryRun {
		t.Fatal("a confirm=true apply must not be a dry run")
	}
	if !res.OK() || res.Restored != 2 {
		t.Fatalf("apply should restore 2 records, got restored=%d failed=%d", res.Restored, len(res.Failed))
	}
	if res.BytesRestored != int64(len("alpha")+len("bravo")) {
		t.Fatalf("restored byte total wrong: %d", res.BytesRestored)
	}
	if len(plan.Writes) != 2 {
		t.Fatalf("plan should still list 2 writes, got %d", len(plan.Writes))
	}
	// The values must be on disk under their sanitised keys.
	got, err := os.ReadFile(filepath.Join(dir, "a"))
	if err != nil || string(got) != "alpha" {
		t.Fatalf("file a: %q err=%v", got, err)
	}
	got, err = os.ReadFile(filepath.Join(dir, "nested", "b"))
	if err != nil || string(got) != "bravo" {
		t.Fatalf("file nested/b: %q err=%v", got, err)
	}
}

func TestNoClobberExistingFile(t *testing.T) {
	dir := t.TempDir()
	// Pre-existing target state: a file the restore must not overwrite.
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := rdr([2]string{"a", "alpha"}, [2]string{"b", "bravo"})
	target := NewDirTarget(dir)

	plan, res, err := Apply(r, target, true)
	if err != nil {
		t.Fatal(err)
	}
	// "a" conflicts with the existing file and is skipped; "b" is written.
	if len(plan.Conflicts) != 1 || plan.Conflicts[0].Name != "a" || plan.Conflicts[0].Kind != ConflictExisting {
		t.Fatalf("expected one existing-file conflict for 'a', got %+v", plan.Conflicts)
	}
	if res.SkippedConflicts != 1 {
		t.Fatalf("expected 1 skipped conflict, got %d", res.SkippedConflicts)
	}
	if res.Restored != 1 {
		t.Fatalf("expected 1 record restored (b), got %d", res.Restored)
	}
	// The pre-existing file must be untouched.
	got, err := os.ReadFile(filepath.Join(dir, "a"))
	if err != nil || string(got) != "ORIGINAL" {
		t.Fatalf("no-clobber violated: file a is now %q (err=%v)", got, err)
	}
	// "b" was written.
	got, err = os.ReadFile(filepath.Join(dir, "b"))
	if err != nil || string(got) != "bravo" {
		t.Fatalf("file b: %q err=%v", got, err)
	}
}

func TestNoClobberCollisionWithinRun(t *testing.T) {
	dir := t.TempDir()
	// Two distinct record names that sanitise to the same destination key. The first
	// claims the key and is written; the second is reported as a collision.
	r := rdr([2]string{"x", "first"}, [2]string{"../x", "second"})
	target := NewDirTarget(dir)

	plan, res, err := Apply(r, target, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Conflicts) != 1 || plan.Conflicts[0].Kind != ConflictCollision || plan.Conflicts[0].Name != "../x" {
		t.Fatalf("expected one within-run collision for '../x', got %+v", plan.Conflicts)
	}
	if res.Restored != 1 {
		t.Fatalf("the first of a colliding pair should be written, got restored=%d", res.Restored)
	}
	got, err := os.ReadFile(filepath.Join(dir, "x"))
	if err != nil || string(got) != "first" {
		t.Fatalf("collision must keep the first writer's value, got %q err=%v", got, err)
	}
}

// TestNoClobberCollisionAbsolutePath pins the absolute-path edge of safeKey: a unix
// absolute key ("/etc/x") strips its leading empty segment to "etc/x" rather than escaping
// the DirTarget, so it collides with the canonical "x" only when "x" already implies the
// same path, and never resolves outside the target. DirTarget is the primary barrier
// against path escape during restore, so the behaviour is pinned here.
func TestNoClobberCollisionAbsolutePath(t *testing.T) {
	if got := safeKey("/etc/x"); got != "etc/x" {
		t.Fatalf("an absolute key must strip the leading separator to a contained relative path, got %q", got)
	}
	dir := t.TempDir()
	r := rdr([2]string{"etc/x", "first"}, [2]string{"/etc/x", "second"})
	target := NewDirTarget(dir)

	plan, res, err := Apply(r, target, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Conflicts) != 1 || plan.Conflicts[0].Kind != ConflictCollision || plan.Conflicts[0].Name != "/etc/x" {
		t.Fatalf("expected one within-run collision for '/etc/x', got %+v", plan.Conflicts)
	}
	if res.Restored != 1 {
		t.Fatalf("the first of a colliding pair should be written, got restored=%d", res.Restored)
	}
	got, err := os.ReadFile(filepath.Join(dir, "etc", "x"))
	if err != nil || string(got) != "first" {
		t.Fatalf("the absolute key must resolve inside the target, got %q err=%v", got, err)
	}
}

// TestDirTargetKeyRejectsWindowsReservedNames pins safeKey's Windows-reserved-name gap: a
// record named e.g. "NUL" or "logs/COM1.txt" used to sanitise straight through and would
// resolve to the corresponding I/O device on a Windows restore instead of a file.
// DirTarget.Key must refuse any path element that is a reserved device name, with or
// without a trailing extension, case-insensitively, and at any path depth, while leaving
// a merely similar-looking name (not an exact reserved word) untouched.
//
// The superscript and CONIN$/CONOUT$ cases pin the two forms the standard library's own
// reserved-name table (internal/filepathlite/path_windows.go, isReservedBaseName) treats
// as unconditionally reserved -- not gated behind a Windows-version check the way a
// trailing extension is -- so they must not slip through just because they don't look
// like the ASCII COM1-9/LPT1-9 spelling.
func TestDirTargetKeyRejectsWindowsReservedNames(t *testing.T) {
	target := NewDirTarget(t.TempDir())
	for _, name := range []string{
		"NUL", "nul", "CON", "prn", "AUX", "COM1", "com3", "LPT9",
		"COM1.txt", "logs/com1.txt", "nested/NUL/deep",
		"COM¹", "COM²", "COM³", "LPT¹", "lpt²", // superscript digit forms
		"CONIN$", "conout$", "logs/CONIN$.txt", // console-handle names
		// Sibling forms Windows reduces to the same device before resolving the name:
		// a trailing space is ignored, an NTFS alternate-data-stream ":suffix" is
		// stripped like an extension, and the two combine. All must be refused just as
		// the bare and dotted forms are.
		"CON ", "nul ", "AUX  ", // trailing space(s)
		"CON .txt", "com1 .log", // trailing space before an extension
		"CON:bar", "nul:$DATA", "logs/COM1:stream", // colon / alternate-data-stream suffix
		"nested/PRN /deep", // trailing space in a non-final element
	} {
		if _, err := target.Key(name); err == nil {
			t.Errorf("Key(%q) = nil error, want a reserved-name rejection", name)
		}
	}
	// Lookalikes that are not themselves a reserved word must still pass through: only
	// COM1-9/LPT1-9 (plus their superscript forms) and CONIN$/CONOUT$ are reserved, and
	// the match is on the element's base name (before the first "." or ":", trailing
	// spaces removed). A leading space is NOT stripped by Windows, so " CON" is a distinct
	// file name and must not be rejected, and a reserved word only as a suffix is fine too.
	for _, name := range []string{
		"COM10", "CONSOLE", "NULL", "prn2", "CONIN", "CONOUTS",
		" CON", "myCON", "CONSOLE.txt", "data:CON", "COM10 ",
	} {
		got, err := target.Key(name)
		if err != nil {
			t.Errorf("Key(%q) unexpectedly rejected: %v", name, err)
		}
		if got == "" {
			t.Errorf("Key(%q) returned an empty key", name)
		}
	}
}

// TestApplyRejectsReservedWindowsDeviceName exercises the reserved-name guard through the
// full plan/apply path, not just Key directly: a hostile record name must classify as
// ConflictUnrepresentable -- the same "cannot represent" outcome EnvTarget uses for a bad
// variable name -- and never reach Write, while an unrelated record in the same run still
// restores normally.
func TestApplyRejectsReservedWindowsDeviceName(t *testing.T) {
	dir := t.TempDir()
	r := rdr([2]string{"logs/COM1.txt", "leaked"}, [2]string{"ok", "fine"})
	target := NewDirTarget(dir)

	plan, res, err := Apply(r, target, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Conflicts) != 1 || plan.Conflicts[0].Kind != ConflictUnrepresentable || plan.Conflicts[0].Name != "logs/COM1.txt" {
		t.Fatalf("expected one unrepresentable conflict for the reserved name, got %+v", plan.Conflicts)
	}
	if res.Restored != 1 {
		t.Fatalf("the safe record should still restore, got restored=%d", res.Restored)
	}
	if _, err := os.Stat(filepath.Join(dir, "logs")); !os.IsNotExist(err) {
		t.Fatalf("no path should be created for the rejected record, stat err=%v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "ok"))
	if err != nil || string(got) != "fine" {
		t.Fatalf("file ok: %q err=%v", got, err)
	}
}

func TestApplyPartialFailureIsHonest(t *testing.T) {
	dir := t.TempDir()
	r := rdr([2]string{"good1", "g1"}, [2]string{"bad", "b"}, [2]string{"good2", "g2"})
	r.failOn["bad"] = true // simulate a per-record hash/segment failure
	target := NewDirTarget(dir)

	plan, res, err := Apply(r, target, true)
	if err != nil {
		t.Fatalf("a per-record failure must not abort the apply: %v", err)
	}
	if len(plan.Writes) != 3 {
		t.Fatalf("plan should list 3 writes, got %d", len(plan.Writes))
	}
	if res.Restored != 2 {
		t.Fatalf("expected 2 records restored around the failure, got %d", res.Restored)
	}
	if len(res.Failed) != 1 || res.Failed[0].Name != "bad" {
		t.Fatalf("expected exactly one recorded failure for 'bad', got %+v", res.Failed)
	}
	if res.OK() {
		t.Fatal("OK must be false when a record failed")
	}
	// The two good records were written despite the failure between them.
	for _, name := range []string{"good1", "good2"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("good record %s should have been written: %v", name, err)
		}
	}
	// The failed record left nothing behind.
	if _, err := os.Stat(filepath.Join(dir, "bad")); !os.IsNotExist(err) {
		t.Fatalf("a failed record must not leave a file: %v", err)
	}
}

func TestEnvTargetPlanAndApply(t *testing.T) {
	var buf bytes.Buffer
	r := rdr([2]string{"API_TOKEN", "s3cr3t"}, [2]string{"DB_URL", "postgres://x"})
	// DB_URL is already set in the target environment, so it must conflict, not redefine.
	target := NewEnvTarget(&buf, []string{"DB_URL"})

	plan, res, err := Apply(r, target, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Conflicts) != 1 || plan.Conflicts[0].Name != "DB_URL" || plan.Conflicts[0].Kind != ConflictExisting {
		t.Fatalf("DB_URL should conflict with the set variable, got %+v", plan.Conflicts)
	}
	if res.Restored != 1 {
		t.Fatalf("only API_TOKEN should be written, got restored=%d", res.Restored)
	}
	if got, want := buf.String(), "API_TOKEN='s3cr3t'\n"; got != want {
		t.Fatalf("env output:\n got %q\nwant %q", got, want)
	}
}

func TestEnvTargetRejectsBadName(t *testing.T) {
	var buf bytes.Buffer
	// A record name that is not a valid env var name is unrepresentable, not a write.
	r := rdr([2]string{"not a name", "v"}, [2]string{"OK_NAME", "w"})
	target := NewEnvTarget(&buf, nil)

	plan, res, err := Apply(r, target, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Conflicts) != 1 || plan.Conflicts[0].Kind != ConflictUnrepresentable {
		t.Fatalf("expected an unrepresentable conflict for the bad name, got %+v", plan.Conflicts)
	}
	if res.Restored != 1 {
		t.Fatalf("the valid record should still restore, got restored=%d", res.Restored)
	}
	if got := buf.String(); got != "OK_NAME='w'\n" {
		t.Fatalf("env output: %q", got)
	}
}

func TestDirTargetExistingEnumeratesNested(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a", "b", "c"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "top"), []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := NewDirTarget(dir).Existing()
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"a/b/c", "top"}
	if len(keys) != len(want) || keys[0] != want[0] || keys[1] != want[1] {
		t.Fatalf("existing keys: got %v want %v", keys, want)
	}
}

func TestDirTargetExistingMissingDirIsEmpty(t *testing.T) {
	got, err := NewDirTarget(filepath.Join(t.TempDir(), "does-not-exist")).Existing()
	if err != nil {
		t.Fatalf("a missing output directory must plan cleanly, got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("a missing directory must enumerate to empty, got %v", got)
	}
}

// ----------------------------------------------------------------------------
// fakeTarget exercises the write-time clobber guard and the error-
// surface paths that DirTarget and EnvTarget tests cannot reach because those
// real targets hide their failure modes behind filesystem or buffer I/O.
// ----------------------------------------------------------------------------

// fakeTarget is a Target whose behaviour is controlled entirely by the caller:
// existingKeys drives the no-clobber plan, writeErr injects a Write failure,
// and closeErr injects a Close failure. It records every Write call so tests
// can assert that a clobbered key was never written.
type fakeTarget struct {
	existingKeys map[string]struct{}
	writeErr     error // if non-nil, every Write returns this error
	closeErr     error // if non-nil, Close returns this error
	written      map[string][]byte
}

func newFakeTarget(existing ...string) *fakeTarget {
	ft := &fakeTarget{
		existingKeys: make(map[string]struct{}),
		written:      make(map[string][]byte),
	}
	for _, k := range existing {
		ft.existingKeys[k] = struct{}{}
	}
	return ft
}

func (f *fakeTarget) Kind() string { return "fake" }

func (f *fakeTarget) Key(name string) (string, error) { return name, nil }

func (f *fakeTarget) Existing() (map[string]struct{}, error) {
	out := make(map[string]struct{}, len(f.existingKeys))
	for k := range f.existingKeys {
		out[k] = struct{}{}
	}
	return out, nil
}

func (f *fakeTarget) Write(key string, value []byte) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	f.written[key] = cp
	return nil
}

func (f *fakeTarget) Close() error { return f.closeErr }

// TestFakeTargetClobberGuard verifies that Apply refuses to overwrite a key
// that Existing() reports as already present in the target. The conflict must
// be recorded as ConflictExisting and the key must never be passed to Write.
func TestFakeTargetClobberGuard(t *testing.T) {
	r := rdr([2]string{"taken", "new-value"}, [2]string{"fresh", "other"})
	// "taken" is already present in the fake target.
	ft := newFakeTarget("taken")

	plan, res, err := Apply(r, ft, true)
	if err != nil {
		t.Fatalf("Apply returned an unexpected error: %v", err)
	}

	// The conflict must be reported as ConflictExisting for the pre-existing key.
	if len(plan.Conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d: %+v", len(plan.Conflicts), plan.Conflicts)
	}
	c := plan.Conflicts[0]
	if c.Name != "taken" || c.Kind != ConflictExisting {
		t.Fatalf("expected ConflictExisting for 'taken', got %+v", c)
	}

	// The clobbered key must never have been passed to Write.
	if _, wrote := ft.written["taken"]; wrote {
		t.Fatal("Write must not be called for a key that Existing() reported as present")
	}

	// The non-conflicting record is written and counted.
	if res.Restored != 1 {
		t.Fatalf("expected 1 record restored, got %d", res.Restored)
	}
	if got, ok := ft.written["fresh"]; !ok || string(got) != "other" {
		t.Fatalf("expected 'fresh' to be written with value 'other', written map: %v", ft.written)
	}
}

// TestFakeTargetWriteErrorSurfaced verifies that a Write failure is surfaced as
// a RecordFailure and not silently swallowed. The apply must continue past the
// failing record (it is not aborted) and the error must appear in Result.Failed.
func TestFakeTargetWriteErrorSurfaced(t *testing.T) {
	r := rdr([2]string{"before", "b"}, [2]string{"oops", "o"}, [2]string{"after", "a"})
	ft := newFakeTarget()
	ft.writeErr = fmt.Errorf("simulated disk full")

	_, res, err := Apply(r, ft, true)
	// Apply itself must succeed even though every individual Write failed.
	// (Close returns nil, so there is no top-level error.)
	if err != nil {
		t.Fatalf("Apply must not return a top-level error for per-record Write failures: %v", err)
	}

	// All three records failed at Write, so Restored must be zero.
	if res.Restored != 0 {
		t.Fatalf("expected 0 records restored, got %d", res.Restored)
	}

	// Every record must appear in Failed, not be silently dropped.
	if len(res.Failed) != 3 {
		t.Fatalf("expected 3 failures, got %d: %+v", len(res.Failed), res.Failed)
	}

	// OK must be false.
	if res.OK() {
		t.Fatal("Result.OK() must be false when records failed")
	}

	// The failure reasons must carry the injected error text so the caller can
	// diagnose the problem; if the error were swallowed the reason would be empty.
	for _, f := range res.Failed {
		if f.Reason == "" {
			t.Errorf("failure for %q has an empty Reason; the error was swallowed", f.Name)
		}
	}
}

// TestFakeTargetCloseErrorSurfaced verifies that a Close failure is propagated
// as the top-level error returned by Apply and is not silently discarded.
// Without this guard a flush or sync failure at the end of a restore would be
// invisible to the caller.
func TestFakeTargetCloseErrorSurfaced(t *testing.T) {
	r := rdr([2]string{"key", "val"})
	ft := newFakeTarget()
	ft.closeErr = fmt.Errorf("simulated flush failure")

	_, _, err := Apply(r, ft, true)
	if err == nil {
		t.Fatal("Apply must return an error when Close fails; the caller must be able to detect an incomplete restore")
	}
	if !strings.Contains(err.Error(), "simulated flush failure") {
		t.Fatalf("the Close error must be propagated to the caller, got: %v", err)
	}
}

// TestEnvTargetApplyNeverWritesUnrepresentableKey checks both the plan path (which
// classifies unrepresentable names as ConflictUnrepresentable) and the Write method
// directly (which is the defence-in-depth guard ensuring no code path can bypass the
// planner and write a mangled key). Neither Apply nor a direct Write call may emit an
// env line for a name that is not a valid POSIX environment-variable name.
func TestEnvTargetApplyNeverWritesUnrepresentableKey(t *testing.T) {
	// -- Plan/apply path ----------------------------------------------------------
	// "bad name", "1LEADING_DIGIT" and "" are all unrepresentable; "GOOD" is valid.
	var buf bytes.Buffer
	r := rdr(
		[2]string{"bad name", "should-not-appear"},
		[2]string{"1LEADING_DIGIT", "should-not-appear"},
		[2]string{"", "should-not-appear"},
		[2]string{"GOOD", "written"},
	)
	target := NewEnvTarget(&buf, nil)

	plan, res, err := Apply(r, target, true)
	if err != nil {
		t.Fatalf("unrepresentable names must not abort Apply: %v", err)
	}

	// All three bad names must be classified as ConflictUnrepresentable.
	if got := len(plan.Conflicts); got != 3 {
		t.Fatalf("expected 3 unrepresentable conflicts, got %d: %+v", got, plan.Conflicts)
	}
	for _, c := range plan.Conflicts {
		if c.Kind != ConflictUnrepresentable {
			t.Errorf("conflict for %q has kind %q, want %q", c.Name, c.Kind, ConflictUnrepresentable)
		}
	}

	// Only GOOD must be written.
	if res.Restored != 1 {
		t.Fatalf("expected exactly 1 record restored, got %d", res.Restored)
	}

	// The output must contain exactly the GOOD line and nothing containing the bad names.
	out := buf.String()
	if out != "GOOD='written'\n" {
		t.Fatalf("env output must be exactly the valid record, got %q", out)
	}

	// -- Direct Write path --------------------------------------------------------
	// Write must refuse an unrepresentable key even when called directly, so no
	// code path can bypass the planner and silently emit a malformed env line.
	badNames := []string{"bad name", "1LEADING_DIGIT", "", "KEY=INJECT", "KEY\nINJECT"}
	for _, bad := range badNames {
		var direct bytes.Buffer
		et := NewEnvTarget(&direct, nil)
		werr := et.Write(bad, []byte("value"))
		if werr == nil {
			t.Errorf("Write(%q) must return an error for an unrepresentable key, but it returned nil", bad)
		}
		if direct.Len() != 0 {
			t.Errorf("Write(%q) must not emit any bytes, but wrote: %q", bad, direct.String())
		}
	}
}

// A record name is archive controlled, so a backslash in it must be treated as an
// element separator on EVERY platform, not just Windows. Before this was fixed, safeKey
// split on the local separator only: the same archive restored to a different layout on
// Unix and Windows, and a file restored on Unix could carry a name ("..\..\etc\passwd")
// that becomes a traversal path the moment it reaches Windows. Found by FuzzDirTargetKey.
func TestSafeKeyTreatsBackslashAsASeparatorOnEveryPlatform(t *testing.T) {
	// The traversal elements are dropped and the rest kept, byte for byte what the
	// forward-slash form ("../../etc/passwd") already produced.
	cases := map[string]string{
		`..\..\etc\passwd`: "etc/passwd",
		`\\server\share`:   "server/share",
		`a\b\c`:            "a/b/c",
		`mixed/a\b`:        "mixed/a/b",
		`.\hidden`:         "hidden",
		`..\..`:            "_",
	}
	for name, want := range cases {
		if got := safeKey(name); got != want {
			t.Errorf("safeKey(%q) = %q, want %q", name, got, want)
		}
	}
	// The reserved-name guard still sees each element after the split, so a device name
	// hidden behind a backslash is still refused.
	d := NewDirTarget(t.TempDir())
	if _, err := d.Key(`sub\CON.txt`); err == nil {
		t.Fatal("a reserved device name behind a backslash must still be refused")
	}
}

// The receipt's refusal tally is only as good as what feeds it. recordConflicts derives the per-kind
// counts from the plan's own conflicts, so the count and the tally describe the same refusals; a tally
// recounted separately later could disagree with SkippedConflicts and the receipt would carry both.
func TestConflictKindsTallyMatchesTheSkippedCount(t *testing.T) {
	plan := &Plan{Conflicts: []Conflict{
		{Name: "a", Kind: ConflictUnrepresentable},
		{Name: "b", Kind: ConflictUnrepresentable},
		{Name: "c", Kind: ConflictExisting},
		{Name: "d", Kind: ConflictCollision},
	}}
	res := &Result{}
	recordConflicts(res, plan)

	if res.SkippedConflicts != 4 {
		t.Fatalf("SkippedConflicts = %d, want 4", res.SkippedConflicts)
	}
	sum := 0
	for _, n := range res.ConflictKinds {
		sum += n
	}
	if sum != res.SkippedConflicts {
		t.Fatalf("the per-kind tally sums to %d but SkippedConflicts is %d: the receipt would carry two different answers", sum, res.SkippedConflicts)
	}
	if res.ConflictKinds[ConflictUnrepresentable] != 2 || res.ConflictKinds[ConflictExisting] != 1 || res.ConflictKinds[ConflictCollision] != 1 {
		t.Fatalf("tally wrong: %v", res.ConflictKinds)
	}
}

// No refusals must leave the tally nil, not an empty map, so the receipt's omitempty keeps a clean
// restore's signed bytes byte-identical to one written before the field existed.
func TestNoConflictsLeavesTheTallyNil(t *testing.T) {
	res := &Result{ConflictKinds: map[ConflictKind]int{ConflictExisting: 1}} // a stale tally from a reused result
	recordConflicts(res, &Plan{})
	if res.SkippedConflicts != 0 {
		t.Fatalf("SkippedConflicts = %d, want 0", res.SkippedConflicts)
	}
	if res.ConflictKinds != nil {
		t.Fatalf("ConflictKinds must be nil with no conflicts (omitempty), got %v", res.ConflictKinds)
	}
}
