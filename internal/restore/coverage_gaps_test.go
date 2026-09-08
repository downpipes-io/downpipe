package restore

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// DiscardTarget.WriteStream is the sink verify --deep drills through, so it must fold
// byte-identically to the buffered Write: same digest, same counts, same receipt. It had
// no direct test at all.
func TestDiscardTargetWriteStreamFoldsLikeWrite(t *testing.T) {
	value := bytes.Repeat([]byte("verify me without writing anything "), 4096)

	buffered := NewDiscardTarget()
	if err := buffered.Write("a", value); err != nil {
		t.Fatalf("buffered write: %v", err)
	}
	streamed := NewDiscardTarget()
	if err := streamed.WriteStream("a", bytes.NewReader(value), int64(len(value))); err != nil {
		t.Fatalf("streamed write: %v", err)
	}
	if buffered.VerifiedRecords() != streamed.VerifiedRecords() {
		t.Fatalf("record counts differ: buffered %d, streamed %d", buffered.VerifiedRecords(), streamed.VerifiedRecords())
	}
	if buffered.VerifiedBytes() != streamed.VerifiedBytes() {
		t.Fatalf("verified bytes differ: buffered %d, streamed %d", buffered.VerifiedBytes(), streamed.VerifiedBytes())
	}
	if buffered.Digest() != streamed.Digest() {
		t.Fatal("the streamed fold must produce the identical digest to the buffered fold")
	}
}

// A read error mid-stream must surface, so the discard sink can never report a record
// verified that it did not actually consume.
func TestDiscardTargetWriteStreamPropagatesAReadError(t *testing.T) {
	d := NewDiscardTarget()
	want := errors.New("source went away")
	err := d.WriteStream("a", io.MultiReader(bytes.NewReader([]byte("partial")), errReader{want}), 100)
	if !errors.Is(err, want) {
		t.Fatalf("the read error must surface, got %v", err)
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// DirTarget.WriteStream's failure paths: a mid-stream read error must leave NOTHING at
// the destination (not a partial, not the O_EXCL reservation), and a pre-existing file
// must be refused before any byte is written.
func TestDirTargetWriteStreamCleansUpOnAReadError(t *testing.T) {
	dir := t.TempDir()
	d := NewDirTarget(dir)
	err := d.WriteStream("k", io.MultiReader(bytes.NewReader([]byte("partial")), errReader{errors.New("boom")}), 100)
	if err == nil {
		t.Fatal("a mid-stream read error must fail the write")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "k")); !os.IsNotExist(statErr) {
		t.Fatal("the destination must not exist after a failed stream")
	}
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatal(rerr)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".downpipe-restore-") {
			t.Fatalf("a temp file was left behind: %s", e.Name())
		}
	}
}

func TestDirTargetWriteStreamRefusesAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "k"), []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := NewDirTarget(dir)
	if err := d.WriteStream("k", bytes.NewReader([]byte("REPLACEMENT")), 11); err == nil {
		t.Fatal("an existing destination must be refused")
	}
	got, err := os.ReadFile(filepath.Join(dir, "k"))
	if err != nil || string(got) != "ORIGINAL" {
		t.Fatalf("the existing file was modified: %q", got)
	}
}

// TestD1OutputKeyBranches pins that the .sql rewrite is IDEMPOTENT. "The branches were
// unexercised" is a statement about the suite, not about why the behaviour is right, so here
// is the reason: the suffix exists so the operator can run the written file straight into
// sqlite3, and a record already named db.sql would otherwise become db.sql.sql, which is not
// the name the replay guidance tells them to type.
//
// The table maps two distinct record names, "db" and "db.sql", onto one destination key, and
// that IS a collision -- but it is a reported one rather than a silent overwrite, which is the
// difference that decides whether idempotence is safe. Driven through Apply with both records
// in one run: the first is written, the second is recorded in plan.Conflicts as kind
// "collision" with the detail "another record in this run maps to the same destination key",
// and the existing file is not replaced. That is asserted below, because the safety of this
// function is not a property of this function.
func TestD1OutputKeyBranches(t *testing.T) {
	cases := map[string]string{
		"db":        "db.sql",
		"db.sql":    "db.sql",
		"nested/db": "nested/db.sql",
		"db.sqlite": "db.sqlite.sql",
	}
	for in, want := range cases {
		if got := d1OutputKey(in, ""); got != want {
			t.Errorf("d1OutputKey(%q) = %q, want %q", in, got, want)
		}
		// The same names with a format label this release cannot render: the key is left
		// exactly as it came in, because naming a body the reader could not turn into SQL
		// ".sql" is what sends the operator to sqlite3 in the first place.
		if got := d1OutputKey(in, "downpipe-d1-rows/2"); got != in {
			t.Errorf("d1OutputKey(%q, unrenderable) = %q, want the key unchanged %q", in, got, in)
		}
	}

	// The two names the table collapses onto one key, driven through a real restore.
	dir := t.TempDir()
	r := d1rdr([2]string{"db", "FIRST"}, [2]string{"db.sql", "SECOND"})
	plan, res, err := Apply(r, NewDirTarget(dir), true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(plan.Conflicts) != 1 || plan.Conflicts[0].Kind != "collision" {
		t.Fatalf("two record names mapping to one destination key must be reported as a collision, got %+v", plan.Conflicts)
	}
	if res.Restored != 1 {
		t.Errorf("restored = %d, want 1: the colliding record must not be written over the first", res.Restored)
	}
	got, rerr := os.ReadFile(filepath.Join(dir, "db.sql"))
	if rerr != nil || string(got) != "FIRST" {
		t.Errorf("the first record's bytes must survive the collision, got %q (err %v)", got, rerr)
	}
}
