package restore

import (
	"encoding/json"
	"strings"
	"testing"
)

// This file directly exercises the transcoder's leaf helpers (writeCreateTable, writeInserts,
// d1Literal, d1TaggedLiteral, d1TriggerActionFollows) rather than only driving transcodeD1
// through a whole JSON body: some refusal branches in those leaves are reachable only when a
// whole-body document happens to hit them, which most never do in the tests in
// d1transcode_test.go alone. These are refusal branches, the half of the transcoder a customer
// meets only when the archive they are restoring in a disaster is not the shape the engine
// promised.
//
// So each test below asserts the SPECIFIC refusal text rather than a non-nil error. A test
// that accepts any error passes when the transcoder refuses for the wrong reason, which
// would leave a customer reading a message about a blob when their problem is a column
// count. The wording is what they get; the wording is what is checked.

// refuseD1 runs transcodeD1 and returns the refusal text, failing unless the body was refused.
// It also holds the contract that a refused body yields no SQL: the caller writes verified
// bytes verbatim on ok=false with no error, so a refusal that leaked a non-nil sql or ok=true
// would be written to the operator's .sql file.
func refuseD1(t *testing.T, body string) string {
	t.Helper()
	sql, ok, err := transcodeD1([]byte(body))
	if err == nil {
		t.Fatalf("body was accepted (ok=%v), want a refusal: %s", ok, body)
	}
	if ok || sql != nil {
		t.Fatalf("a refused body must return ok=false and no SQL, got ok=%v sql=%q", ok, sql)
	}
	return err.Error()
}

// wantRefusal asserts the exact thing the customer is told, not merely that they were told
// something.
func wantRefusal(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("the refusal reads %q, want it to say %q", got, want)
	}
}

// rowsBody wraps a single one-cell row in a rows record, so a cell-level refusal can be
// reached the way a real archive reaches it.
func rowsBody(cell string) string {
	return `{"format":"downpipe-d1-rows/1","table":"t","columns":["a"],"rows":[[` + cell + `]]}`
}

// TestTranscodeD1RefusesAMalformedRecordOfEachFormat covers the per-format json.Unmarshal
// refusal in all four transcoders. These look unreachable and are not: transcodeD1 has
// already unmarshalled the same bytes into a struct carrying only "format", so a reader can
// conclude the body is known-good JSON. It is only known-good against THAT struct. A sibling
// field of the wrong JSON type (an object where an array belongs) parses fine into the
// format-only struct and fails against the richer one, which is exactly the archive an engine
// version mismatch would produce.
func TestTranscodeD1RefusesAMalformedRecordOfEachFormat(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"header": {`{"format":"downpipe-d1-header/1","tables":"users"}`, "d1 header record:"},
		"schema": {`{"format":"downpipe-d1-schema/1","schema":42}`, "d1 schema record:"},
		"rows":   {`{"format":"downpipe-d1-rows/1","rows":{"a":1}}`, "d1 rows record:"},
		"full":   {`{"format":"downpipe-d1-json/1","tables":7}`, "d1 full record:"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			wantRefusal(t, refuseD1(t, tc.body), tc.want)
		})
	}
}

// TestTranscodeD1FullRefusesInEachReplayPhase covers transcodeD1Full's three error returns,
// one per replay phase. The legacy whole-database format had exactly one test and it was a
// happy path, so every way the legacy format can fail was unexercised. The phase matters to
// the customer: the same archive can be wrong in its DDL, its rows, or its indexes, and the
// three refusals name different things to go and look at.
func TestTranscodeD1FullRefusesInEachReplayPhase(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"phase 1 table DDL": {
			`{"format":"downpipe-d1-json/1","tables":[{"name":"t","sql":"DROP TABLE t","columns":["a"],"rows":[]}]}`,
			`d1 table "t" sql is not a CREATE TABLE statement`,
		},
		"phase 2 rows": {
			`{"format":"downpipe-d1-json/1","tables":[{"name":"t","sql":"CREATE TABLE t(a)","columns":["a"],"rows":[[1,2]]}]}`,
			`d1 rows for "t": row 0 has 2 cells, want 1`,
		},
		"phase 3 schema": {
			`{"format":"downpipe-d1-json/1","tables":[],"schema":["DROP TABLE payments"]}`,
			"d1 full schema entry is not a CREATE INDEX/TRIGGER/VIEW statement",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			wantRefusal(t, refuseD1(t, tc.body), tc.want)
		})
	}
}

// TestTranscodeD1RefusesARecordWithNothingToNameIt covers the three "the archive did not tell
// us what this is" refusals in writeCreateTable and writeInserts. A nameless table or a rows
// page with no columns cannot be turned into SQL at all, and the customer needs to be told
// which of the two is missing rather than handed a generic parse failure.
func TestTranscodeD1RefusesARecordWithNothingToNameIt(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"table with no name": {
			`{"format":"downpipe-d1-header/1","tables":[{"name":"","sql":"CREATE TABLE t(a)","columns":["a"]}]}`,
			"d1 table entry has no name",
		},
		"rows with no table name": {
			`{"format":"downpipe-d1-rows/1","table":"","columns":["a"],"rows":[[1]]}`,
			"d1 rows record has no table name",
		},
		"rows with no columns": {
			`{"format":"downpipe-d1-rows/1","table":"t","columns":[],"rows":[[1]]}`,
			`d1 rows for "t" has no columns`,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			wantRefusal(t, refuseD1(t, tc.body), tc.want)
		})
	}
}

// TestTranscodeD1RefusesASpanThatNeverCloses covers the three unterminated-span refusals in
// d1RequireSingleStatement, and with them the two matching early returns in
// d1TriggerActionFollows.
//
// Why none of these had ever run: the scanner stops at the first top-level ';', and every
// existing negative test puts its payload AFTER that ';'. The bracket-identifier and comment
// arms only run on text BEFORE the terminator, which in practice means inside a CREATE TABLE
// column list or a trigger body. Nothing tested either place.
//
// An unterminated span is not cosmetic. Every entry's output is concatenated into one buffer
// with a plain ";\n" between entries, so a span left open at the end of one entry can be
// closed by a character in the next, splicing both entries and the semicolon between them
// into one attacker-shaped literal. The refusals below are what stops that, and each names
// the span that failed to close so an operator can find it in a stored DDL by eye.
func TestTranscodeD1RefusesASpanThatNeverCloses(t *testing.T) {
	cases := map[string]struct{ stmt, want string }{
		"bracket identifier": {
			"CREATE TABLE t([col TEXT)",
			"statement has an unterminated [...] identifier",
		},
		// A trigger entry, so the same truncation is met twice: once by d1TriggerActionFollows
		// looking for the action keyword after BEGIN, and once by the main scan.
		"line comment": {
			"CREATE TRIGGER trg AFTER INSERT ON t BEGIN -- truncated here",
			"statement has an unterminated -- comment (no trailing newline)",
		},
		"block comment": {
			"CREATE TRIGGER trg AFTER INSERT ON t BEGIN /* truncated here",
			"statement has an unterminated /* */ comment",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(tc.stmt)
			if err != nil {
				t.Fatal(err)
			}
			var body string
			if strings.HasPrefix(tc.stmt, "CREATE TABLE") {
				body = `{"format":"downpipe-d1-header/1","tables":[{"name":"t","sql":` + string(encoded) + `,"columns":["col"]}]}`
			} else {
				body = `{"format":"downpipe-d1-schema/1","schema":[` + string(encoded) + `]}`
			}
			wantRefusal(t, refuseD1(t, body), tc.want)
		})
	}
}

// TestTranscodeD1AcceptsSpansThatDoClose is the control for the refusals above, and it is the
// half that would hurt a customer most if it were wrong: a DDL that SQLite itself stores and
// accepts must transcode unchanged. sqlite_master keeps a table's CREATE text verbatim, so a
// bracket-quoted column name, a doubled quote inside a default, and a comment the author left
// in are all ordinary content of a real stored statement. Refusing any of them would fail a
// restore on a database that is not faulty at all.
func TestTranscodeD1AcceptsSpansThatDoClose(t *testing.T) {
	tables := map[string]string{
		"doubled quote in a default": `CREATE TABLE t(x TEXT DEFAULT 'it''s')`,
		"bracket-quoted column":      `CREATE TABLE t([my col] TEXT)`,
		"trailing line comment":      "CREATE TABLE t(a)\n-- kept from the original schema\n",
		"inline block comment":       `CREATE TABLE t(/* the key */ a)`,
	}
	for name, createSQL := range tables {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(createSQL)
			if err != nil {
				t.Fatal(err)
			}
			body := `{"format":"downpipe-d1-header/1","tables":[{"name":"t","sql":` + string(encoded) + `,"columns":["a"]}]}`
			if sql := transcodeOrFail(t, body); !strings.Contains(sql, createSQL+";\n") {
				t.Fatalf("a real stored CREATE TABLE was rejected or altered:\n%s", sql)
			}
		})
	}
	// The trigger equivalents, which additionally prove d1TriggerActionFollows steps over a
	// comment between BEGIN and the first action rather than giving up and leaving the body
	// closed (which would put the body's own semicolons at the top level).
	triggers := map[string]string{
		"line comment before the first action":  "CREATE TRIGGER trg AFTER INSERT ON t BEGIN -- the body starts here\n SELECT 1; END",
		"block comment before the first action": "CREATE TRIGGER trg2 AFTER INSERT ON t BEGIN /* the body starts here */ SELECT 1; END",
	}
	for name, trigger := range triggers {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(trigger)
			if err != nil {
				t.Fatal(err)
			}
			body := `{"format":"downpipe-d1-schema/1","schema":[` + string(encoded) + `]}`
			if sql := transcodeOrFail(t, body); !strings.Contains(sql, trigger+";\n") {
				t.Fatalf("a trigger body opened by a comment was rejected or altered:\n%s", sql)
			}
		})
	}
}

// TestTranscodeD1TriggerBodyOpensOnlyOnARealAction covers the remaining ways
// d1TriggerActionFollows can decline to promote a bare "begin" token into the trigger's own
// body-opening keyword. SQLite does not reserve "begin", so a column called that is legal, and
// the only thing separating the real keyword from a reference to that column is what comes
// immediately after it: a trigger's BEGIN is always followed straight away by INSERT, UPDATE,
// DELETE, SELECT, REPLACE or WITH, and a column reference never is.
//
// The first two cases are the ones that matter, because in each the entry ALSO carries a
// statement smuggled after the trigger's real END. If the bare "begin" had opened the body
// early, the real END would never have been seen at the top level, the smuggled statement's
// semicolon would have been swallowed as body content, and the operator would have been handed
// a .sql file that drops a table when they run it.
func TestTranscodeD1TriggerBodyOpensOnlyOnARealAction(t *testing.T) {
	smuggles := map[string]string{
		// The next byte after "begin" is punctuation, not a bare keyword at all.
		"begin column followed by an operator": `CREATE TRIGGER trg AFTER INSERT ON shifts WHEN NEW.begin > 0 BEGIN SELECT 1; END; DROP TABLE payments`,
		// The next token is a bare keyword, but not one that can start a trigger action.
		"begin column followed by a non-action keyword": `CREATE TRIGGER trg2 AFTER INSERT ON shifts WHEN NEW.begin IS NOT NULL BEGIN SELECT 1; END; DROP TABLE payments`,
	}
	for name, trigger := range smuggles {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(trigger)
			if err != nil {
				t.Fatal(err)
			}
			body := `{"format":"downpipe-d1-schema/1","schema":[` + string(encoded) + `]}`
			wantRefusal(t, refuseD1(t, body), "statement carries content after its terminating ';' (more than one statement)")
		})
	}

	// The boundary of the check, stated rather than left to be discovered. An entry truncated
	// so that a bare "begin" is its last token leaves nothing at all after it, so
	// d1TriggerActionFollows runs off the end of the string and declines to open the body. The
	// entry is then accepted, and that is correct: this function's job is to refuse a SECOND
	// statement, and a truncation has no second statement to refuse. Whether the DDL is
	// runnable SQLite is decided by sqlite3 when the operator replays the file, per
	// D1ReplayGuidance, not here.
	truncated := "CREATE TRIGGER trg3 AFTER UPDATE OF begin"
	encoded, err := json.Marshal(truncated)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"format":"downpipe-d1-schema/1","schema":[` + string(encoded) + `]}`
	if sql := transcodeOrFail(t, body); !strings.Contains(sql, truncated+";\n") {
		t.Fatalf("an entry truncated at a bare begin carries no second statement and must be passed through:\n%s", sql)
	}
}

// TestTranscodeD1RefusesACellItCannotRenderExactly covers every cell-level refusal reachable
// from a real archive. The transcoder's contract is that each storage class survives exactly
// (a BLOB stays bytes, a bigint never goes through a float), so a cell it cannot render
// exactly must stop the restore rather than produce SQL that loads silently-wrong data. Each
// refusal names the cell kind, and writeInserts prefixes the table, row and column, so the
// customer is told which value in which row of which table they need to look at.
func TestTranscodeD1RefusesACellItCannotRenderExactly(t *testing.T) {
	cases := map[string]struct{ cell, want string }{
		"array":              {`[1,2]`, "array cell is not a valid D1 value"},
		"boolean":            {`true`, "boolean cell is not a valid D1 value"},
		"tagged with no tag": {`{}`, "tagged cell must carry exactly one of $blob or $int"},
		"tagged with both":   {`{"$blob":"AA","$int":"1"}`, "tagged cell must carry exactly one of $blob or $int"},
		"blob not a string":  {`{"$blob":1}`, "$blob cell is not a string"},
		"blob not base64url": {`{"$blob":"!!!!"}`, "$blob cell is not valid base64url"},
		"int not a string":   {`{"$int":1}`, "$int cell is not a string"},
		"unknown tag":        {`{"$text":"x"}`, "tagged cell carries an unknown tag"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := refuseD1(t, rowsBody(tc.cell))
			wantRefusal(t, got, tc.want)
			// The locator, which is the part an operator uses on a page of many rows.
			wantRefusal(t, got, `d1 rows for "t" row 0 column 0:`)
		})
	}
}

// TestD1LiteralGuardsNoArchiveBodyCanReach documents that five refusals in d1Literal and
// d1TaggedLiteral cannot be reached through transcodeD1 by any archive body at all. They are
// defence in depth against a future decoder change, exactly as d1NumRe's own comment says, and
// they are worth keeping: the cost is five lines and the thing they stop is a malformed token
// reaching an operator's .sql file as SQL.
//
// The obvious reading is that encoding/json rejects the token while decoding the rows record,
// so the cell renderer never sees it. That is not what happens, and the difference matters to
// a customer. transcodeD1
// sniffs the format by unmarshalling the WHOLE body first, so a body carrying a token
// encoding/json cannot parse fails that sniff and takes the opaque-bytes fallback: no error,
// no transcode, and the verified bytes are written verbatim to the operator's file. So the
// guard is unreachable one step earlier than it looks, and the customer is not refused at all,
// they get their original JSON body back rather than SQL. That is the documented contract for
// anything not recognisably a downpipe D1 body, and it is asserted here so it stays deliberate.
//
// The empty-cell guard is unreachable for a different reason again: a decoded row is a JSON
// array, so a cell cannot be absent, only the row can be short, and the arity check in
// writeInserts reaches that first with a message that names the count.
func TestD1LiteralGuardsNoArchiveBodyCanReach(t *testing.T) {
	// Tokens encoding/json cannot parse: the whole body fails the format sniff and is
	// written verbatim, so no cell is ever rendered and no refusal is ever issued.
	unparseable := map[string]string{
		"n-prefixed but no null": "nope",
		"unparseable string":     `"\q"`,
		"non-JSON number":        "01",
		"unparseable object":     `{"a":}`,
	}
	for name, token := range unparseable {
		t.Run(name+" falls through to verbatim", func(t *testing.T) {
			sql, ok, err := transcodeD1([]byte(rowsBody(token)))
			if err != nil {
				t.Fatalf("an unparseable body must take the verbatim fallback, got error %v", err)
			}
			if ok || sql != nil {
				t.Fatalf("an unparseable body must be left verbatim, got ok=%v sql=%q", ok, sql)
			}
		})
	}

	// An empty cell cannot exist in a decoded row; a short row can, and it is caught by count.
	t.Run("empty cell is a short row instead", func(t *testing.T) {
		wantRefusal(t, refuseD1(t, rowsBody("")), `d1 rows for "t": row 0 has 0 cells, want 1`)
	})

	// Called directly, which is the only way these branches run, and the reason they are here.
	guards := map[string]struct{ token, want string }{
		"empty token":            {"  ", "empty cell"},
		"n-prefixed but no null": {"nope", `unexpected cell token "nope"`},
		"unparseable string":     {`"\q"`, "string cell:"},
		"non-JSON number":        {"01", `malformed numeric cell "01"`},
		"unparseable object":     {`{"a":}`, "tagged cell:"},
	}
	for name, tc := range guards {
		t.Run(name+" is refused at the leaf", func(t *testing.T) {
			lit, err := d1Literal(json.RawMessage(tc.token))
			if err == nil {
				t.Fatalf("d1Literal accepted %q and rendered it as %q", tc.token, lit)
			}
			wantRefusal(t, err.Error(), tc.want)
			if lit != "" {
				t.Fatalf("a refused cell must render nothing, got %q", lit)
			}
		})
	}
}
