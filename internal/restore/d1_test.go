package restore

// D1 resumable per-page records (offline-reader behaviour).
//
// A D1 database now backs up as a SEQUENCE of records the engine seals across slices: one header
// record (the table DDL), many row-page records (one keyset page of one table's rows each), then one
// schema record (indexes/triggers/views). The offline reader does NOT replay D1 live: it treats a d1
// record's body as OPAQUE bytes and writes each to a file for the operator to replay against a fresh
// database (SPEC.md 12.1, "restore replays the dump"). These tests pin that the per-page records:
//   - write to DISTINCT files (no two records collide on one destination key, so none is dropped),
//   - sort header -> rows -> schema in name order (the operator's replay order on disk),
//   - are NOT misclassified as reprovision (D1 is a direct value write, unlike workers/cf-config),
//   - and write WITHOUT error through the file sink, the opaque-bytes contract the engine relies on.
// The legacy whole-dump record (one d1 record per database) keeps writing as a single file.

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// d1rdr builds a fakeReader of d1 records from name/body pairs, in the order given. SourceType is
// "d1" (not the kv default of rdr) so the reprovision/classification paths see a real D1 record.
func d1rdr(pairs ...[2]string) *fakeReader {
	f := &fakeReader{values: map[string][]byte{}, failOn: map[string]bool{}}
	for i, p := range pairs {
		name, body := p[0], p[1]
		f.recs = append(f.recs, spec.ShardRecord{
			SourceType: spec.SourceD1, Name: name, RecordID: fmt.Sprintf("recordid%08d", i),
			PlaintextSize: int64(len(body)),
			D1:            &spec.D1Descriptor{Format: "downpipe-d1-rows/1"},
		})
		f.values[name] = []byte(body)
	}
	return f
}

// d1rdrD1 is d1rdr with the D1 DESCRIPTOR under the caller's control: each triple is
// {name, body, descriptor format}. An empty third element leaves the record with NO d1
// descriptor at all, which is what a writer that never stamped one produces and is the case
// where the reader has only the body to go on.
func d1rdrD1(triples ...[3]string) *fakeReader {
	f := &fakeReader{values: map[string][]byte{}, failOn: map[string]bool{}}
	for i, p := range triples {
		name, body, format := p[0], p[1], p[2]
		rec := spec.ShardRecord{
			SourceType: spec.SourceD1, Name: name, RecordID: fmt.Sprintf("recordid%08d", i),
			PlaintextSize: int64(len(body)),
		}
		if format != "" {
			rec.D1 = &spec.D1Descriptor{Format: format}
		}
		f.recs = append(f.recs, rec)
		f.values[name] = []byte(body)
	}
	return f
}

// perPageNames is one database's resumable record names in archive (and replay) order: the header,
// two row pages of one table, a row page of a second table, then the schema. The "<db>/00-header",
// "<db>/10-rows/<ti>-<table>/<page>" and "<db>/20-schema" shape is what the engine emits.
var perPageNames = []string{
	"appdb/00-header",
	"appdb/10-rows/000000-users/000000",
	"appdb/10-rows/000000-users/000001",
	"appdb/10-rows/000001-notes/000000",
	"appdb/20-schema",
}

// TestD1PerPageRecordsWriteDistinctFiles proves the per-page d1 records each write to their own file
// under the file sink, with the exact body bytes, and that none is dropped as a collision. This is
// the core offline-correctness guarantee: a rows-heavy D1 sealed as many records must come back as
// many files, not silently coalesce or conflict on one key (which would lose rows).
func TestD1PerPageRecordsWriteDistinctFiles(t *testing.T) {
	dir := t.TempDir()
	pairs := make([][2]string, len(perPageNames))
	for i, n := range perPageNames {
		pairs[i] = [2]string{n, fmt.Sprintf("body-for-%s", n)} // opaque to the reader; just bytes
	}
	r := d1rdr(pairs...)
	target := NewDirTarget(dir)

	plan, res, err := Apply(r, target, true) // confirm=true: write the files
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if !res.OK() {
		t.Fatalf("apply reported %d failure(s): %+v", len(res.Failed), res.Failed)
	}
	if len(plan.Conflicts) != 0 {
		t.Fatalf("per-page d1 records must not conflict, got %d: %+v", len(plan.Conflicts), plan.Conflicts)
	}
	if res.Restored != len(perPageNames) {
		t.Fatalf("restored %d records, want %d (one file per per-page record)", res.Restored, len(perPageNames))
	}
	// Every record's bytes landed at its own distinct .sql path. The plan resolves a d1
	// record on the file sink to a .sql key (d1OutputKey), so read at the planned key
	// rather than the bare Key (which is the un-suffixed name) and assert the suffix.
	if len(plan.Writes) != len(perPageNames) {
		t.Fatalf("plan has %d writes, want %d", len(plan.Writes), len(perPageNames))
	}
	seen := map[string]struct{}{}
	for _, w := range plan.Writes {
		key := w.Key
		if !strings.HasSuffix(key, ".sql") {
			t.Fatalf("d1 record %q wrote to %q, want a .sql suffix", w.Name, key)
		}
		if _, dup := seen[key]; dup {
			t.Fatalf("two records mapped to the same destination key %q (collision would lose rows)", key)
		}
		seen[key] = struct{}{}
		got, rerr := os.ReadFile(filepath.Join(dir, filepath.FromSlash(key)))
		if rerr != nil {
			t.Fatalf("expected a file at %q: %v", key, rerr)
		}
		want := fmt.Sprintf("body-for-%s", w.Name)
		if string(got) != want {
			t.Fatalf("file %q body = %q, want %q", key, got, want)
		}
	}
}

// TestD1PerPageNamesSortToReplayOrder proves the on-disk file keys sort header -> rows -> schema, so
// an operator replaying the files in name order applies them in the order the database must be
// rebuilt (create tables, insert rows, then build indexes/triggers/views). The numeric 00/10/20
// prefixes and zero-padded page indices are what give this lexicographic ordering.
func TestD1PerPageNamesSortToReplayOrder(t *testing.T) {
	pairs := make([][2]string, len(perPageNames))
	for i, n := range perPageNames {
		pairs[i] = [2]string{n, "b"}
	}
	plan, _, err := Apply(d1rdr(pairs...), NewDirTarget(t.TempDir()), false)
	if err != nil {
		t.Fatalf("plan errored: %v", err)
	}
	// Use the planned destination keys (the .sql-suffixed paths the bytes land at), so the
	// ordering assertion is over what the operator actually replays in name order.
	keys := make([]string, len(plan.Writes))
	for i, w := range plan.Writes {
		keys[i] = w.Key
	}
	// perPageNames is already in replay order; a lexicographic sort of the keys must not reorder it.
	sorted := append([]string(nil), keys...)
	sort.Strings(sorted)
	for i := range keys {
		if keys[i] != sorted[i] {
			t.Fatalf("file keys do not sort to replay order:\n archive %v\n sorted  %v", keys, sorted)
		}
	}
	// The header sorts first and the schema last, the two replay-order anchors. The uniform
	// .sql suffix preserves the relative order of the numeric 00/10/20 prefixes.
	if sorted[0] != "appdb/00-header.sql" {
		t.Fatalf("header must sort first, got %q", sorted[0])
	}
	if sorted[len(sorted)-1] != "appdb/20-schema.sql" {
		t.Fatalf("schema must sort last, got %q", sorted[len(sorted)-1])
	}
}

// TestD1IsNotReprovision pins that a D1 record (whatever its name) is a direct value write, not a
// reprovision/replay-guidance source like workers/cf-config: it carries no Reprovision note and is
// not refused on the env sink for being a reprovision type. This is the classification the offline
// reader relies on to write d1 bytes straight to a file.
func TestD1IsNotReprovision(t *testing.T) {
	if spec.ReprovisionSourceType(spec.SourceD1) {
		t.Fatal("d1 must not be a reprovision source type (it restores by a direct value write)")
	}
	r := d1rdr([2]string{perPageNames[0], "h"}, [2]string{perPageNames[1], "r"})
	plan, _, err := Apply(r, NewDirTarget(t.TempDir()), false)
	if err != nil {
		t.Fatalf("plan errored: %v", err)
	}
	if len(plan.Reprovision) != 0 {
		t.Fatalf("d1 records must carry no reprovision guidance, got %d: %+v", len(plan.Reprovision), plan.Reprovision)
	}
	if GuidanceFor(r.recs[0]) != "" {
		t.Fatalf("d1 records must have no reprovision guidance text, got %q", GuidanceFor(r.recs[0]))
	}
}

// TestABareNamedD1RecordWritesOneWholeDumpFile proves a d1 record whose name carries no slash
// writes as a single <name>.sql file holding the whole database.
//
// A d1 record's name is either a bare database name or a <db>/<page> path, and the slash is
// the only thing that distinguishes a whole-database dump from one page of a paged one. The
// reader keeps both readings live: it is handed whatever is in the archive in front of it, and
// the operator guidance offers both shapes ("each <db>/00-header.sql ... or the single
// <db>.sql for a whole dump"). Dropping the bare-name reading would turn "appdb" into a
// directory-shaped key with nothing after the slash.
//
// The bare name yields exactly one file, named for the database, holding the verified bytes
// unchanged.
func TestABareNamedD1RecordWritesOneWholeDumpFile(t *testing.T) {
	dir := t.TempDir()
	r := d1rdr([2]string{"legacydb", "whole-dump-bytes"})
	plan, res, err := Apply(r, NewDirTarget(dir), true)
	if err != nil {
		t.Fatalf("Apply errored: %v", err)
	}
	if !res.OK() || res.Restored != 1 || len(plan.Conflicts) != 0 {
		t.Fatalf("bare-named whole-dump record did not restore cleanly: restored=%d failed=%+v conflicts=%+v", res.Restored, res.Failed, plan.Conflicts)
	}
	got, rerr := os.ReadFile(filepath.Join(dir, "legacydb.sql"))
	if rerr != nil {
		t.Fatalf("expected a single .sql file named for the database: %v", rerr)
	}
	if string(got) != "whole-dump-bytes" {
		t.Fatalf("whole-dump file body = %q, want %q", got, "whole-dump-bytes")
	}
	// One file, not a directory: a bare name must not be read as a path prefix.
	ents, derr := os.ReadDir(dir)
	if derr != nil || len(ents) != 1 || ents[0].IsDir() {
		t.Fatalf("a bare database name must produce exactly one file, got %v (err %v)", ents, derr)
	}
}

// TestD1RestoresAsReadyToApplySQL proves the offline-apply parity increment (R4): a d1 record
// restores to a <name>.sql file whose bytes are byte-for-byte the verified dump (the reader
// hash-verifies the plaintext before it reaches the target), so the operator can apply it
// turnkey (sqlite3 newdb.sqlite < <name>.sql, then wrangler d1 execute). It also pins that
// the written bytes' plaintext SHA-384 matches the source dump's, and that the plan flags
// HasD1File so the CLI surfaces the apply commands.
func TestD1RestoresAsReadyToApplySQL(t *testing.T) {
	dir := t.TempDir()
	// A SQLite-compatible dump body (the engine captures the d1 export verbatim; the offline
	// reader treats it as opaque bytes).
	dump := "PRAGMA foreign_keys=OFF;\nBEGIN TRANSACTION;\nCREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT);\nINSERT INTO users VALUES(1,'a');\nCOMMIT;\n"
	r := d1rdr([2]string{"appdb/00-header", dump})
	target := NewDirTarget(dir)

	plan, res, err := Apply(r, target, true)
	if err != nil {
		t.Fatalf("Apply errored: %v", err)
	}
	if !res.OK() || res.Restored != 1 {
		t.Fatalf("d1 record did not restore cleanly: restored=%d failed=%+v", res.Restored, res.Failed)
	}
	if !plan.HasD1File {
		t.Fatal("plan must flag HasD1File so the CLI surfaces the apply commands")
	}
	if len(plan.Writes) != 1 || !strings.HasSuffix(plan.Writes[0].Key, ".sql") {
		t.Fatalf("d1 record must be planned to a .sql key, got %+v", plan.Writes)
	}
	key := plan.Writes[0].Key
	if key != "appdb/00-header.sql" {
		t.Fatalf("planned d1 key = %q, want %q", key, "appdb/00-header.sql")
	}

	got, rerr := os.ReadFile(filepath.Join(dir, filepath.FromSlash(key)))
	if rerr != nil {
		t.Fatalf("expected a .sql file at %q: %v", key, rerr)
	}
	// Byte-for-byte equality: the written .sql IS the verified dump, no transformation.
	if string(got) != dump {
		t.Fatalf(".sql file bytes are not the verified dump:\n got %q\nwant %q", got, dump)
	}
	// Plaintext SHA-384 of the written file equals the source dump's, so an operator can
	// pin the dump's hash and confirm the on-disk .sql is exactly what was captured.
	wantHash := sha512.Sum384([]byte(dump))
	gotHash := sha512.Sum384(got)
	if hex.EncodeToString(gotHash[:]) != hex.EncodeToString(wantHash[:]) {
		t.Fatalf(".sql plaintext SHA-384 mismatch:\n got %s\nwant %s", hex.EncodeToString(gotHash[:]), hex.EncodeToString(wantHash[:]))
	}
}

// TestD1ReplayGuidance pins the exact two-command turnkey the CLI surfaces for a d1 dump,
// and that it stays out of the reprovision path: D1ReplayGuidance carries both the sqlite3
// load and the wrangler d1 execute step, while GuidanceFor(d1) is still "" (d1 is a direct
// value write, not a reprovision type).
func TestD1ReplayGuidance(t *testing.T) {
	g := D1ReplayGuidance()
	for _, want := range []string{"sqlite3", "wrangler d1 execute", ".sql"} {
		if !strings.Contains(g, want) {
			t.Fatalf("D1ReplayGuidance() is missing %q:\n%s", want, g)
		}
	}
	rec := spec.ShardRecord{SourceType: spec.SourceD1, Name: "appdb/00-header"}
	if GuidanceFor(rec) != "" {
		t.Fatalf("GuidanceFor(d1) must stay \"\" (d1 is not a reprovision type), got %q", GuidanceFor(rec))
	}
}

// TestNonD1RecordKeepsKeyUnsuffixed proves the .sql suffix is d1-only: a kv record on the
// file sink keeps its bare key (no blind rewrite of other source types).
func TestNonD1RecordKeepsKeyUnsuffixed(t *testing.T) {
	plan, _, err := Apply(rdr([2]string{"config/app", "value"}), NewDirTarget(t.TempDir()), false)
	if err != nil {
		t.Fatalf("plan errored: %v", err)
	}
	if plan.HasD1File {
		t.Fatal("a kv-only plan must not set HasD1File")
	}
	if len(plan.Writes) != 1 || plan.Writes[0].Key != "config/app" {
		t.Fatalf("kv record key must be unsuffixed, got %+v", plan.Writes)
	}
}
