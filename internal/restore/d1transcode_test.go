package restore

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The blob bytes 0x00 0x01 0x02 0xff as base64url (no pad): standard b64 "AAEC/w==" with
// +/ -> -_ and the padding stripped, matching the engine's bytesToB64url.
const d1BlobB64 = "AAEC_w"

// transcodeOrFail runs transcodeD1 and fails unless it recognised and transcoded the body.
func transcodeOrFail(t *testing.T, body string) string {
	t.Helper()
	sql, ok, err := transcodeD1([]byte(body))
	if err != nil {
		t.Fatalf("transcodeD1 error: %v", err)
	}
	if !ok {
		t.Fatalf("transcodeD1 did not recognise the body:\n%s", body)
	}
	return string(sql)
}

// TestTranscodeD1HeaderEmitsCreateTable proves the header record's table DDL becomes a
// terminated CREATE TABLE statement.
func TestTranscodeD1HeaderEmitsCreateTable(t *testing.T) {
	body := `{"format":"downpipe-d1-header/1","tables":[{"name":"users","sql":"CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT)","columns":["id","name"]}]}`
	sql := transcodeOrFail(t, body)
	if !strings.Contains(sql, "CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT);") {
		t.Fatalf("header SQL missing terminated CREATE TABLE:\n%s", sql)
	}
}

// TestTranscodeD1RowsHandlesBlobNullBigint is the cell-encoding proof: a BLOB becomes an
// x'..' hex literal, NULL stays NULL, a bigint over 2^53 becomes a BARE integer literal (not
// a float), a plain integer keeps its token, and a string's embedded quote is doubled.
func TestTranscodeD1RowsHandlesBlobNullBigint(t *testing.T) {
	body := `{"format":"downpipe-d1-rows/1","table":"us\"ers","columns":["id","name","data","big"],` +
		`"rows":[[1,"o'reilly",{"$blob":"` + d1BlobB64 + `"},{"$int":"9223372036854775807"}],` +
		`[2,null,null,42]]}`
	sql := transcodeOrFail(t, body)
	for _, want := range []string{
		`INSERT INTO "us""ers" ("id", "name", "data", "big") VALUES`, // identifier quoting (doubled ")
		`'o''reilly'`,         // string with a doubled single quote
		`x'000102ff'`,         // BLOB as a hex literal
		`9223372036854775807`, // bigint > 2^53 as a bare integer (no float)
		`(2, NULL, NULL, 42)`, // NULL cells and a plain integer
		"BEGIN TRANSACTION;",
		"COMMIT;",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("rows SQL missing %q:\n%s", want, sql)
		}
	}
	// The bigint must never appear in exponent/float form (the failure mode of narrowing a
	// >2^53 integer through a float64).
	if strings.Contains(sql, "9.2233720368547758e+18") || strings.Contains(sql, "9223372036854776000") {
		t.Fatalf("bigint was narrowed through a float:\n%s", sql)
	}
}

// TestTranscodeD1SchemaEmitsCreateIndex proves the schema record's statements are emitted and
// terminated, and that a non-CREATE-INDEX/TRIGGER/VIEW entry is refused (fail loud).
func TestTranscodeD1SchemaEmitsCreateIndex(t *testing.T) {
	sql := transcodeOrFail(t, `{"format":"downpipe-d1-schema/1","schema":["CREATE INDEX idx ON users(name)"]}`)
	if !strings.Contains(sql, "CREATE INDEX idx ON users(name);") {
		t.Fatalf("schema SQL missing terminated CREATE INDEX:\n%s", sql)
	}
	if _, _, err := transcodeD1([]byte(`{"format":"downpipe-d1-schema/1","schema":["DROP TABLE users"]}`)); err == nil {
		t.Fatal("a non-CREATE schema entry must be refused")
	}
}

// TestTranscodeD1Full proves the legacy whole-database body transcodes to CREATE + INSERT +
// schema in that order.
func TestTranscodeD1Full(t *testing.T) {
	body := `{"format":"downpipe-d1-json/1","tables":[{"name":"t","sql":"CREATE TABLE t(a)","columns":["a"],"rows":[[1],[2]]}],"schema":["CREATE INDEX i ON t(a)"]}`
	sql := transcodeOrFail(t, body)
	createAt := strings.Index(sql, "CREATE TABLE t(a)")
	insertAt := strings.Index(sql, `INSERT INTO "t"`)
	indexAt := strings.Index(sql, "CREATE INDEX i ON t(a)")
	if createAt < 0 || insertAt < 0 || indexAt < 0 {
		t.Fatalf("full SQL missing a section:\n%s", sql)
	}
	if createAt >= insertAt || insertAt >= indexAt {
		t.Fatalf("full SQL is out of replay order (create %d, insert %d, index %d):\n%s", createAt, insertAt, indexAt, sql)
	}
}

// TestTranscodeD1VerbatimFallback proves a body that is not a recognised downpipe D1 JSON
// shape is left for the caller to write verbatim (ok=false, no error).
//
// The reader's promise about a record's bytes is that it hands back what the engine put in, having
// hash-verified it. Transcoding is a courtesy laid on top of that promise for the shapes this
// reader can read, so anything else must pass through untouched: refusing an unrecognised body
// would mean a reader that cannot render a dump also refuses to give the operator their own
// verified bytes, in the disaster where those bytes are all they have. The asymmetry with
// TestTranscodeD1MalformedFailsLoud is the whole design: a body that CLAIMS a shape this
// reader knows and then does not hold it is an error, because writing half-built SQL to a file
// the operator is told to pipe into sqlite3 is worse than handing back JSON.
//
// The three inputs below are the three ways a body can fail to claim a known shape, and they
// are the fallback proper. The fourth way is recorded separately, in
// TestAnUnknownD1FormatLabelIsNotDistinguishedFromANonD1Body, because it is not the same
// question.
func TestTranscodeD1VerbatimFallback(t *testing.T) {
	for _, body := range []string{
		"PRAGMA foreign_keys=OFF;\nCREATE TABLE x(a);\n", // raw SQL: not a JSON object at all
		"not json at all", // not parseable as JSON
		`{"no":"format"}`, // JSON object carrying no format tag
	} {
		sql, ok, err := transcodeD1([]byte(body))
		if err != nil {
			t.Fatalf("verbatim body errored: %v (%q)", err, body)
		}
		if ok || sql != nil {
			t.Fatalf("body should be verbatim (ok=false), got ok=%v for %q", ok, body)
		}
	}
}

// TestAnUnknownDownpipeD1LabelIsSeparatedFromAForeignBody pins that a label plainly in the
// downpipe D1 family but not one this release renders is distinguished from a body that was
// never a downpipe D1 dump at all. The two causes have opposite operator responses:
//
//   - a body that was never a downpipe D1 dump, which must be handed back verbatim, and
//   - a body from a NEWER engine, such as downpipe-d1-rows/2, which this reader cannot render
//     and must say so.
//
// The archive-level guard does not separate them and was never going to. formatVersion is
// checked against downpipe/0.1.x (verify.go), the d1 body labels are versioned independently of
// it and are not named in SPEC.md at all, so nothing forces a body-format bump to bump the
// archive minor and a newer archive opens, verifies and reaches this code fully trusted.
//
// Without the separation, a newer-format record would be reported as restored and written to a
// .sql file with sqlite3 replay guidance printed above it, even though the file is not valid
// SQL and piping it into sqlite3 fails -- in a disaster, after the tool had reported success.
//
// The separator is the family prefix downpipe-d1- (d1FormatFamily): a label carrying it that
// this release does not render is the second case, and anything else is the first. This test
// pins BOTH directions, because a fix that flagged the foreign body too would have broken the
// opaque-bytes contract a sibling test argues for at length.
func TestAnUnknownDownpipeD1LabelIsSeparatedFromAForeignBody(t *testing.T) {
	newer := `{"format":"downpipe-d1-rows/2","table":"t","columns":["a"],"rows":[[1]]}`
	foreign := `{"format":"some-other/1","data":1}`

	// Neither transcodes: that much is unchanged, and must stay unchanged. transcodeD1 is
	// deliberately still blind to the difference, because the question is about the record.
	for _, body := range []string{newer, foreign} {
		sql, ok, err := transcodeD1([]byte(body))
		if err != nil || ok || sql != nil {
			t.Fatalf("neither body may transcode, got ok=%v err=%v for %q", ok, err, body)
		}
	}

	// The separation itself, at the label level.
	if got := d1UnrenderableLabel("downpipe-d1-rows/2"); got != "downpipe-d1-rows/2" {
		t.Fatalf("a downpipe D1 label this release does not render must be reported, got %q", got)
	}
	if got := d1UnrenderableLabel("some-other/1"); got != "" {
		t.Fatalf("a label outside the downpipe D1 family is not this reader's to judge, got %q", got)
	}
	if got := d1UnrenderableLabel(d1FormatRows); got != "" {
		t.Fatalf("a label this release renders must not be reported, got %q", got)
	}

	// And end to end. The newer record restores, its bytes are written unchanged, and the
	// three things the operator needs are all present: the record is named in the
	// plan, named in the result, and its file is NOT called .sql.
	dir := t.TempDir()
	r := d1rdrD1([3]string{"appdb", newer, "downpipe-d1-rows/2"})
	plan, res, err := Apply(r, NewDirTarget(dir), true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.OK() || res.Restored != 1 || len(res.Failed) != 0 || len(plan.Conflicts) != 0 {
		t.Fatalf("the bytes must still be restored: OK=%v restored=%d failed=%+v conflicts=%+v",
			res.OK(), res.Restored, res.Failed, plan.Conflicts)
	}
	if len(res.Unrenderable) != 1 || res.Unrenderable[0].Format != "downpipe-d1-rows/2" || res.Unrenderable[0].Name != "appdb" {
		t.Fatalf("the result must name the record and the label it carries, got %+v", res.Unrenderable)
	}
	if len(plan.D1Unrenderable) != 1 || plan.D1Unrenderable[0].Format != "downpipe-d1-rows/2" {
		t.Fatalf("the plan must name it too, so a dry run says so before anything is written, got %+v", plan.D1Unrenderable)
	}
	if plan.HasD1File {
		t.Fatal("a run whose only d1 record is unrenderable must not print the sqlite3 replay guidance")
	}
	if len(plan.Writes) != 1 || plan.Writes[0].Key != "appdb" {
		t.Fatalf("the key must carry no .sql suffix, got %+v", plan.Writes)
	}
	got, rerr := os.ReadFile(filepath.Join(dir, "appdb"))
	if rerr != nil {
		t.Fatalf("expected the verified bytes written to the bare key: %v", rerr)
	}
	if string(got) != newer {
		t.Fatalf("appdb = %q, want the body verbatim %q", got, newer)
	}
	if _, serr := os.Stat(filepath.Join(dir, "appdb.sql")); serr == nil {
		t.Fatal("nothing may be written to appdb.sql: naming JSON .sql is what sends the operator to sqlite3")
	}

	// The control, in the same shape: a foreign body keeps the behaviour the opaque-bytes
	// contract requires, including its .sql key, and is flagged nowhere.
	fdir := t.TempDir()
	fplan, fres, ferr := Apply(d1rdrD1([3]string{"otherdb", foreign, ""}), NewDirTarget(fdir), true)
	if ferr != nil {
		t.Fatalf("Apply (foreign): %v", ferr)
	}
	if len(fres.Unrenderable) != 0 || len(fplan.D1Unrenderable) != 0 {
		t.Fatalf("a foreign body must not be flagged: result %+v plan %+v", fres.Unrenderable, fplan.D1Unrenderable)
	}
	if !fplan.HasD1File || len(fplan.Writes) != 1 || fplan.Writes[0].Key != "otherdb.sql" {
		t.Fatalf("a foreign body keeps the .sql key and the replay guidance, got hasD1File=%v writes=%+v", fplan.HasD1File, fplan.Writes)
	}
	fgot, frerr := os.ReadFile(filepath.Join(fdir, "otherdb.sql"))
	if frerr != nil || string(fgot) != foreign {
		t.Fatalf("a foreign body must be written verbatim to its .sql key, got %q (err %v)", fgot, frerr)
	}
}

// TestTranscodeD1MalformedFailsLoud proves a RECOGNISED format with a malformed body is an
// error (never silently written as broken SQL): a rows record whose row arity does not match
// its columns, a bad $int, and a non-CREATE-TABLE header DDL.
func TestTranscodeD1MalformedFailsLoud(t *testing.T) {
	for _, body := range []string{
		`{"format":"downpipe-d1-rows/1","table":"t","columns":["a","b"],"rows":[[1]]}`,                   // arity mismatch
		`{"format":"downpipe-d1-rows/1","table":"t","columns":["a"],"rows":[[{"$int":"1.5"}]]}`,          // $int not integer
		`{"format":"downpipe-d1-header/1","tables":[{"name":"t","sql":"DROP TABLE t","columns":["a"]}]}`, // not CREATE TABLE
	} {
		if _, _, err := transcodeD1([]byte(body)); err == nil {
			t.Fatalf("malformed recognised body must error: %q", body)
		}
	}
}

// TestTranscodeD1RejectsSmuggledStatement proves a statement-smuggling attempt is refused:
// d1CreateTableRe and d1CreateSchemaRe are prefix matches with no end anchor, so a DDL/schema
// string that STARTS with the right keyword but carries a second statement after it must still
// be refused -- never written verbatim next to the statement it claims to be. Covers all three
// call sites: writeCreateTable (header table DDL), transcodeD1Schema, and transcodeD1Full's
// schema phase.
func TestTranscodeD1RejectsSmuggledStatement(t *testing.T) {
	for _, body := range []string{
		// header table DDL -> writeCreateTable
		`{"format":"downpipe-d1-header/1","tables":[{"name":"users","sql":"CREATE TABLE users(id INTEGER PRIMARY KEY); DROP TABLE IF EXISTS payments; --","columns":["id"]}]}`,
		// schema entry -> transcodeD1Schema
		`{"format":"downpipe-d1-schema/1","schema":["CREATE INDEX idx ON users(name); DROP TABLE payments; --"]}`,
		// legacy whole-database body's schema phase -> transcodeD1Full
		`{"format":"downpipe-d1-json/1","tables":[{"name":"t","sql":"CREATE TABLE t(a)","columns":["a"],"rows":[]}],"schema":["CREATE VIEW v AS SELECT 1; DROP TABLE t; --"]}`,
	} {
		if _, _, err := transcodeD1([]byte(body)); err == nil {
			t.Fatalf("a smuggled second statement must be refused, not written verbatim: %q", body)
		}
	}
}

// TestTranscodeD1SchemaAcceptsRealTrigger proves the single-statement check does not
// mis-truncate or reject a real CREATE TRIGGER: its BEGIN...END body's own internal
// semicolons, and a CASE...END expression nested inside that body, must never be mistaken for
// the statement's terminator or for the trigger's own closing END. Rejecting this would be a
// worse regression than the bug being fixed.
func TestTranscodeD1SchemaAcceptsRealTrigger(t *testing.T) {
	trigger := "CREATE TRIGGER trg AFTER UPDATE ON t BEGIN " +
		"UPDATE t SET y = CASE WHEN new.x IS NULL THEN 0 ELSE new.x END WHERE id = new.id; " +
		"DELETE FROM u WHERE z = 1; " +
		"END"
	body := `{"format":"downpipe-d1-schema/1","schema":["` + trigger + `"]}`
	sql := transcodeOrFail(t, body)
	if !strings.Contains(sql, trigger+";\n") {
		t.Fatalf("a real trigger body was altered or truncated:\n%s", sql)
	}
}

// TestTranscodeD1SchemaAcceptsSemicolonInStringLiteral proves a semicolon that is really just
// part of a quoted string constant (not a statement boundary) is not mistaken for a second
// statement -- the check must be quote-aware, not a naive semicolon count.
func TestTranscodeD1SchemaAcceptsSemicolonInStringLiteral(t *testing.T) {
	body := `{"format":"downpipe-d1-schema/1","schema":["CREATE VIEW v AS SELECT 'a;b' AS x"]}`
	sql := transcodeOrFail(t, body)
	if !strings.Contains(sql, "CREATE VIEW v AS SELECT 'a;b' AS x;\n") {
		t.Fatalf("a semicolon inside a string literal was mistaken for a statement boundary:\n%s", sql)
	}
}

// TestTranscodeD1SchemaRejectsUnterminatedTriggerBody proves a crafted body cannot hide a
// smuggled second statement by opening a BEGIN block it never closes: an unbalanced
// BEGIN/CASE...END depth at end of string is refused, not silently accepted as one statement
// (which would let every semicolon after the fake BEGIN through unchecked).
func TestTranscodeD1SchemaRejectsUnterminatedTriggerBody(t *testing.T) {
	body := `{"format":"downpipe-d1-schema/1","schema":["CREATE TRIGGER t AFTER INSERT ON x BEGIN DELETE FROM a WHERE 1=1"]}`
	if _, _, err := transcodeD1([]byte(body)); err == nil {
		t.Fatal("an unterminated BEGIN block must be refused, not silently accepted as one statement")
	}
}

// TestTranscodeD1RejectsBareKeywordSmuggle proves a bypass of a naive BEGIN/CASE...END depth
// tracker is refused: such a tracker would run for every DDL/schema entry regardless of kind,
// keyed purely on a bare identifier spelled BEGIN/CASE/END with no grammatical context at all.
// So a CREATE TABLE or CREATE INDEX entry -- neither of which can ever legitimately carry a
// BEGIN...END body -- could still open one with an ordinary unquoted column/expression name
// spelled "begin": the real top-level ';' right after it hid behind depth>0, a later bare "END"
// silently rebalanced the counter back to zero, and the smuggled statement in between sailed
// through with no error. Both a CREATE TABLE and a CREATE INDEX variant of this bypass, run
// through the real sqlite3 CLI to confirm the DROP actually executed, must now be refused
// outright.
func TestTranscodeD1RejectsBareKeywordSmuggle(t *testing.T) {
	cases := map[string]string{
		// header table DDL -> writeCreateTable (bare "begin" as a column name)
		"table": `{"format":"downpipe-d1-header/1","tables":[{"name":"users","sql":"CREATE TABLE users(begin INTEGER); DROP TABLE IF EXISTS payments; END","columns":["id"]}]}`,
		// schema entry -> transcodeD1Schema (bare "begin" inside an index expression)
		"index": `{"format":"downpipe-d1-schema/1","schema":["CREATE INDEX idx ON users(begin) ; DROP TABLE payments; END"]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := transcodeD1([]byte(body)); err == nil {
				t.Fatalf("a bare BEGIN/CASE/END token must not be able to hide a smuggled statement: %q", body)
			}
		})
	}
}

// TestTranscodeD1AcceptsLegitimateKeywordColumnNames is the flip side of the bare-keyword bypass
// above: SQLite does not reserve "begin" or "end", so a real single-statement CREATE TABLE
// using either as an ordinary column name (a shift-tracking table, say) is valid DDL --
// confirmed against the installed sqlite3 (3.51.0) -- and must still transcode, not be rejected
// as an "unterminated BEGIN or CASE block" the way a naive unconditional depth tracker would.
// Each keyword is checked on its own (not both in the same table): together in one statement
// they would cancel out in a naive depth counter (one bare "begin" plus one bare "end" nets
// back to a balanced depth of zero) and pass even on buggy code, masking the regression this
// guards against.
func TestTranscodeD1AcceptsLegitimateKeywordColumnNames(t *testing.T) {
	cases := map[string]string{
		"begin": "CREATE TABLE shifts(id INTEGER PRIMARY KEY, begin INTEGER, finish INTEGER)",
		"end":   "CREATE TABLE shifts(id INTEGER PRIMARY KEY, start INTEGER, end INTEGER)",
	}
	for name, createSQL := range cases {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(createSQL)
			if err != nil {
				t.Fatal(err)
			}
			body := `{"format":"downpipe-d1-header/1","tables":[{"name":"shifts","sql":` + string(encoded) + `,"columns":["id"]}]}`
			sql := transcodeOrFail(t, body)
			if !strings.Contains(sql, createSQL+";\n") {
				t.Fatalf("a legitimate %q column name was rejected or mangled:\n%s", name, sql)
			}
		})
	}
}

// TestTranscodeD1RejectsCrossEntryLiteralSplice proves a cross-entry literal-splicing bypass is
// refused: an implementation that validated each JSON array entry in isolation could silently
// accept a quote/bracket/comment that opened but never closed, falling through to end-of-string
// with no error. Since every entry's SQL is concatenated into one buffer with only a plain
// ";\n" written in between (writeCreateTable, transcodeD1Schema, transcodeD1Full), one entry
// could leave an unterminated string literal dangling and a sibling entry could supply the
// closing quote, splicing the two (and the ";\n" between them) into a single attacker-shaped
// string constant and manufacturing a fresh top-level ';' exactly where the injected statement
// should begin. An unterminated span must be refused on its own terms, so it can never reach a
// second entry to be completed by.
func TestTranscodeD1RejectsCrossEntryLiteralSplice(t *testing.T) {
	cases := map[string]string{
		// header: two table entries that only look benign in isolation -- entry 1's leading "'"
		// is meant to close entry 0's dangling, unterminated string literal.
		"header table entries": `{"format":"downpipe-d1-header/1","tables":[` +
			`{"name":"t1","sql":"CREATE TABLE t1(x TEXT DEFAULT '","columns":["x"]},` +
			`{"name":"ignoreme","sql":"CREATE TABLE ignoreme') ; DROP TABLE IF EXISTS payments; --","columns":["y"]}` +
			`]}`,
		// schema: the same splice shape spread across a CREATE INDEX and a CREATE VIEW entry.
		"schema entries": `{"format":"downpipe-d1-schema/1","schema":[` +
			`"CREATE INDEX idx0 ON t(x) WHERE y='",` +
			`"CREATE VIEW v AS SELECT '; DROP TABLE payments; --"` +
			`]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := transcodeD1([]byte(body)); err == nil {
				t.Fatalf("an unterminated literal spliced across two entries must be refused: %q", body)
			}
		})
	}
}

// TestTranscodeD1AcceptsMultilineTrigger is the positive control for both fixes above: a real,
// multi-line CREATE TRIGGER body -- as sqlite_master would actually store one, newlines and all,
// with internal ';'-separated statements and a nested CASE...END expression -- must still
// transcode unchanged. The tightened check must not have overcorrected into rejecting genuine
// trigger DDL just because it now treats CREATE TABLE/INDEX/VIEW so much more strictly.
func TestTranscodeD1AcceptsMultilineTrigger(t *testing.T) {
	trigger := "CREATE TRIGGER users_ai AFTER INSERT ON users\n" +
		"BEGIN\n" +
		"  UPDATE stats SET n = CASE WHEN n IS NULL THEN 1 ELSE n + 1 END;\n" +
		"  INSERT INTO audit(action, table_name) VALUES ('insert', 'users');\n" +
		"END"
	encoded, err := json.Marshal(trigger)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"format":"downpipe-d1-schema/1","schema":[` + string(encoded) + `]}`
	sql := transcodeOrFail(t, body)
	if !strings.Contains(sql, trigger+";\n") {
		t.Fatalf("a real multi-line trigger body was altered or rejected:\n%s", sql)
	}
}

// TestTranscodeD1RejectsTriggerBodyAliasSmuggle proves a further bypass of a bare-spelling
// BEGIN/CASE/END depth counter is refused, even one scoped to CREATE-TRIGGER-only entries: such
// a counter is still fooled inside a trigger body, since SQLite does not reserve "begin"/"end"
// there either. A derived-table column literally aliased "begin" bumps the same counter the
// trigger's own BEGIN needs, so the real closing END is never seen at depth zero and a smuggled
// statement rides through hidden behind it. Confirmed by piping the identical generated text
// into the real, installed sqlite3 per D1ReplayGuidance: an unpatched depth counter accepts the
// body and the smuggled DROP actually executes. Covers both the schema and full-body call
// sites.
func TestTranscodeD1RejectsTriggerBodyAliasSmuggle(t *testing.T) {
	trigger := `CREATE TRIGGER trg AFTER INSERT ON t BEGIN SELECT begin FROM (SELECT 1 AS begin); END; DROP TABLE payments; SELECT end FROM (SELECT 1 AS end)`
	encoded, err := json.Marshal(trigger)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"schema": `{"format":"downpipe-d1-schema/1","schema":[` + string(encoded) + `]}`,
		"full":   `{"format":"downpipe-d1-json/1","tables":[{"name":"t","sql":"CREATE TABLE t(a)","columns":["a"],"rows":[]}],"schema":[` + string(encoded) + `]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := transcodeD1([]byte(body)); err == nil {
				t.Fatalf("a bare BEGIN/END-spelled alias inside a trigger body must not smuggle a statement past the real closing END: %s", trigger)
			}
		})
	}
}

// TestTranscodeD1AcceptsTriggerBodyReferencingBeginEndColumns proves a real, single-statement
// trigger that references a column literally named "begin" or "end" -- not just declares one in
// CREATE TABLE, which is covered separately -- must transcode and not be wrongly rejected as
// "an unterminated BEGIN or CASE block", which a bare-spelling depth counter would do because
// the bare reference bumps its counter with no matching close. Both a bare reference and a
// NEW.-qualified one are covered, for both keywords individually (mirroring the CREATE TABLE
// test's own reasoning: combining both in one body would cancel out in a naive depth counter
// and pass even on buggy code, masking the regression).
func TestTranscodeD1AcceptsTriggerBodyReferencingBeginEndColumns(t *testing.T) {
	cases := map[string]string{
		"begin_bare_and_qualified": "CREATE TRIGGER trg AFTER INSERT ON shifts BEGIN UPDATE shifts SET begin = new.begin WHERE id = new.id; END",
		"end_bare_and_qualified":   "CREATE TRIGGER trg2 AFTER INSERT ON shifts BEGIN UPDATE shifts SET end = new.end WHERE id = new.id; END",
		"select_list_both":         "CREATE TRIGGER trg3 AFTER INSERT ON shifts BEGIN SELECT begin, end FROM shifts; END",
		// a column referenced only via NEW., not declared.
		"new_dot_qualified_only": "CREATE TRIGGER shifts_ai AFTER INSERT ON shifts BEGIN INSERT INTO shift_log(shift_id, started) VALUES (NEW.id, NEW.begin); END",
	}
	for name, trigger := range cases {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(trigger)
			if err != nil {
				t.Fatal(err)
			}
			body := `{"format":"downpipe-d1-schema/1","schema":[` + string(encoded) + `]}`
			sql := transcodeOrFail(t, body)
			if !strings.Contains(sql, trigger+";\n") {
				t.Fatalf("a legitimate trigger referencing a begin/end column was rejected or mangled:\n%s", sql)
			}
		})
	}
}

// TestD1TranscodeRoundTripsThroughSQLite proves the turnkey restore is correct end to end: a
// tiny synthetic D1 archive (header + a rows page carrying BLOB/NULL/bigint > 2^53/quoted-string
// cells + schema), each record a downpipe D1 JSON body, is restored through the real
// ApplyStreaming file path (which transcodes each to .sql), then the .sql files are loaded into
// a fresh database with the local sqlite3 and queried back. The recovered rows must equal what
// was backed up. Skips when sqlite3 is not installed so `go test` stays green on a host without
// it.
func TestD1TranscodeRoundTripsThroughSQLite(t *testing.T) {
	sqlite3, err := exec.LookPath("sqlite3")
	if err != nil {
		t.Skip("sqlite3 not installed; skipping the D1 turnkey round-trip")
	}

	header := `{"format":"downpipe-d1-header/1","tables":[{"name":"users","sql":"CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT, data BLOB, big INTEGER, note TEXT)","columns":["id","name","data","big","note"]}]}`
	rows := `{"format":"downpipe-d1-rows/1","table":"users","columns":["id","name","data","big","note"],` +
		`"rows":[[1,"alice",{"$blob":"` + d1BlobB64 + `"},{"$int":"9223372036854775807"},null],` +
		`[2,"o'reilly",null,{"$int":"-9223372036854775808"},"line1\nline2"]]}`
	schema := `{"format":"downpipe-d1-schema/1","schema":["CREATE INDEX idx_users_name ON users(name)"]}`

	dir := t.TempDir()
	src := d1rdr(
		[2]string{"users/00-header", header},
		[2]string{"users/10-rows/000000-users/000000", rows},
		[2]string{"users/20-schema", schema},
	)
	plan, res, aerr := ApplyStreaming(src, NewDirTarget(dir), true)
	if aerr != nil {
		t.Fatalf("ApplyStreaming: %v", aerr)
	}
	if !res.OK() || res.Restored != 3 {
		t.Fatalf("restore did not complete cleanly: restored=%d failed=%+v", res.Restored, res.Failed)
	}
	if !plan.HasD1File {
		t.Fatal("plan must flag HasD1File for a d1 file restore")
	}

	// Concatenate every restored .sql in name (replay) order: header, then rows, then schema.
	var sqlFiles []string
	if werr := filepath.WalkDir(dir, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() && strings.HasSuffix(p, ".sql") {
			sqlFiles = append(sqlFiles, p)
		}
		return nil
	}); werr != nil {
		t.Fatal(werr)
	}
	sort.Strings(sqlFiles)
	if len(sqlFiles) != 3 {
		t.Fatalf("expected 3 .sql files, got %d: %v", len(sqlFiles), sqlFiles)
	}
	var script strings.Builder
	for _, f := range sqlFiles {
		b, rerr := os.ReadFile(f)
		if rerr != nil {
			t.Fatal(rerr)
		}
		script.Write(b)
		script.WriteByte('\n')
	}

	dbPath := filepath.Join(dir, "restored.sqlite")
	load := exec.Command(sqlite3, dbPath)
	load.Stdin = strings.NewReader(script.String())
	if out, lerr := load.CombinedOutput(); lerr != nil {
		t.Fatalf("sqlite3 load failed: %v\noutput: %s\nscript:\n%s", lerr, out, script.String())
	}

	// Read the rows back, rendering each storage class so BLOB/NULL/bigint are checked exactly.
	// A NULL is distinguished from an empty blob with `IS NULL` (hex(NULL) is '' in SQLite, not
	// NULL, so it cannot tell the two apart on its own).
	query := `SELECT id||'|'||COALESCE(name,'<null>')||'|'||CASE WHEN data IS NULL THEN '<null>' ELSE hex(data) END||'|'||big||'|'||COALESCE(note,'<null>') FROM users ORDER BY id;`
	got, qerr := exec.Command(sqlite3, dbPath, query).Output()
	if qerr != nil {
		t.Fatalf("sqlite3 query failed: %v", qerr)
	}
	gotStr := strings.TrimSpace(string(got))
	want := strings.Join([]string{
		"1|alice|000102FF|9223372036854775807|<null>",
		"2|o'reilly|<null>|-9223372036854775808|line1\nline2",
	}, "\n")
	if gotStr != want {
		t.Fatalf("recovered rows do not match the backup:\n got:\n%s\nwant:\n%s", gotStr, want)
	}

	// The index from the schema record must be present, proving the schema replayed too.
	idx, ierr := exec.Command(sqlite3, dbPath, "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_users_name';").Output()
	if ierr != nil || strings.TrimSpace(string(idx)) != "idx_users_name" {
		t.Fatalf("schema index not restored (got %q, err %v)", strings.TrimSpace(string(idx)), ierr)
	}
}
