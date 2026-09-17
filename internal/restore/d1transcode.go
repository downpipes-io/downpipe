package restore

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// The D1 backup body formats the engine emits (mirrors engine src/sources/d1-format.ts). A
// D1 database is exported as a structured JSON document, NOT raw SQL: a legacy whole-database
// body, or the resumable triple of a header (table DDL), many row pages, and a schema record
// (indexes/triggers/views). transcodeD1 turns any of these into runnable SQLite SQL so the
// .sql file an operator gets on the file sink is turnkey -- sqlite3 newdb.sqlite < file.sql --
// instead of un-runnable JSON (the "D1 not turnkey-restorable" gap). A body that is not one of
// these recognised JSON shapes (a raw-SQL legacy dump, or any other opaque value) is written
// verbatim, preserving the reader's opaque-bytes contract.
//
// A THIRD case sits between those two and is handled separately, by d1FormatFamily below: a
// body whose label is plainly a downpipe D1 label and is one this release does not render. Its
// bytes are still written verbatim, because withholding verified bytes from an operator whose
// only copy is the archive would be worse than any confusion, but the restore reports it and
// the record's file is not named as SQL.
const (
	d1FormatFull   = "downpipe-d1-json/1"
	d1FormatHeader = "downpipe-d1-header/1"
	d1FormatRows   = "downpipe-d1-rows/1"
	d1FormatSchema = "downpipe-d1-schema/1"
)

// d1FormatFamily is the prefix every downpipe D1 format label shares: the four this release
// renders, and every one a later engine adds. It is the whole basis for telling a third case
// apart from the two transcodeD1 already handles.
//
// transcodeD1's default arm reads "a label I do not recognise" as "this was never a downpipe
// D1 body", which is right for a raw-SQL dump or an opaque value and wrong for a body this
// tool plainly recognises as its own and cannot yet render. The two have opposite operator
// responses (write it out and say nothing, against write it out and say it is not SQL), and
// before this prefix existed they shared one arm and one silent outcome.
//
// The label is versioned independently of the archive's formatVersion, which verify.go pins
// to downpipe/0.1.x, so nothing forces a body-format bump to bump the archive version and a
// newer archive reaches this reader fully verified.
const d1FormatFamily = "downpipe-d1-"

// d1KnownFormat reports whether label is a D1 body format this release can render into SQL.
// The set is exactly the four constants above, which mirror the engine's exported
// D1_BACKUP_FORMAT, D1_HEADER_FORMAT, D1_ROWS_FORMAT and D1_SCHEMA_FORMAT.
func d1KnownFormat(label string) bool {
	switch label {
	case d1FormatFull, d1FormatHeader, d1FormatRows, d1FormatSchema:
		return true
	}
	return false
}

// d1UnrenderableLabel returns label when it names a downpipe D1 format this release cannot
// render, and "" otherwise. A label outside the family is not this reader's to judge: a
// foreign or absent label means the body was never a downpipe D1 dump, which is the
// opaque-bytes case and is correct as it stands.
func d1UnrenderableLabel(label string) string {
	label = strings.TrimSpace(label)
	if label == "" || !strings.HasPrefix(label, d1FormatFamily) || d1KnownFormat(label) {
		return ""
	}
	return label
}

// d1DescriptorUnrenderable returns the format label on a record's D1 descriptor when it names
// a downpipe D1 format this release cannot render, and "" otherwise. It reads
// spec.D1Descriptor.Format, which the engine stamps on every per-page D1 record from the same
// constants it writes into the body, so in practice the descriptor and the body agree and the
// descriptor is available a whole decrypt earlier.
//
// This is the plan-time half of the answer, and the only half a plan can have: MakePlan
// resolves every destination key before any byte is decrypted.
func d1DescriptorUnrenderable(rec spec.ShardRecord) string {
	if rec.D1 == nil {
		return ""
	}
	return d1UnrenderableLabel(rec.D1.Format)
}

// d1RecordUnrenderable returns the downpipe D1 format label this release cannot render for a
// record whose verified value is in hand, reading the descriptor first and the body second, or
// "" when neither carries one. It is the apply-time answer, and it is strictly wider than
// d1DescriptorUnrenderable: a body from a writer that stamped no descriptor, or one whose
// descriptor disagrees with its own bytes, is caught here.
func d1RecordUnrenderable(rec spec.ShardRecord, value []byte) string {
	if label := d1DescriptorUnrenderable(rec); label != "" {
		return label
	}
	return d1UnrenderableLabel(d1BodyFormat(value))
}

// d1BodyFormat returns the format label a verified d1 body carries, or "" when the body is
// not a JSON object or carries no format field. It reads the same head struct transcodeD1
// reads, and is called only on the path where transcodeD1 has already declined to transcode,
// so a body is never both fully decoded and head-scanned twice.
func d1BodyFormat(value []byte) string {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return ""
	}
	var head struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(trimmed, &head); err != nil {
		return ""
	}
	return head.Format
}

// d1InsertBatch caps how many rows ride one multi-row INSERT, so the generated statement
// length stays bounded regardless of a page's row count (each rows page is already bounded by
// the engine's page byte guard, but a legacy whole-dump table is not, so this keeps the SQL
// statement size bounded there too).
const d1InsertBatch = 256

var (
	d1CreateTableRe  = regexp.MustCompile(`(?i)^\s*CREATE\s+TABLE\b`)
	d1CreateSchemaRe = regexp.MustCompile(`(?i)^\s*CREATE\s+(INDEX|TRIGGER|VIEW)\b`)
	// d1CreateTriggerRe picks out the one CREATE kind, of the three d1CreateSchemaRe accepts,
	// that legitimately carries a BEGIN...END body. d1RequireSingleStatement only gives bare
	// BEGIN/END tokens any special meaning for an entry that matches this -- see its doc
	// comment for why.
	d1CreateTriggerRe = regexp.MustCompile(`(?i)^\s*CREATE\s+TRIGGER\b`)
	d1IntRe           = regexp.MustCompile(`^-?\d+$`)
	// d1NumRe is the JSON number grammar, used as defence-in-depth before a bare numeric cell
	// is emitted into SQL text (the token already came from a JSON parse, so this only guards
	// against a future decoder change ever letting a non-number through).
	d1NumRe = regexp.MustCompile(`^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$`)
)

// transcodeD1 converts a verified D1 record value into runnable SQL when the value is one of
// the recognised downpipe D1 JSON formats. It returns (sql, true, nil) on a successful
// transcode, (nil, false, nil) when the value is not a downpipe D1 JSON body (the caller then
// writes the verified bytes verbatim), and (nil, false, err) when the body IS a recognised
// format but malformed (fail loud rather than write broken SQL). The input has already passed
// the archive's plaintext-hash check, so this is a shape transform, not a trust boundary.
func transcodeD1(value []byte) ([]byte, bool, error) {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false, nil // not a JSON object: a raw-SQL or opaque body, written verbatim
	}
	var head struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(trimmed, &head); err != nil {
		return nil, false, nil // not parseable as a tagged body: verbatim
	}
	switch head.Format {
	case d1FormatHeader:
		return transcodeD1Header(trimmed)
	case d1FormatRows:
		return transcodeD1Rows(trimmed)
	case d1FormatSchema:
		return transcodeD1Schema(trimmed)
	case d1FormatFull:
		return transcodeD1Full(trimmed)
	default:
		// Unknown or absent format: opaque-bytes fallback. This arm still cannot tell a
		// foreign body from a newer downpipe one, and deliberately does not try: the caller
		// asks d1UnrenderableLabel that question, because it is a question about the record
		// (its descriptor as well as its body) and not about these bytes alone.
		return nil, false, nil
	}
}

type d1TableDDL struct {
	Name    string   `json:"name"`
	SQL     string   `json:"sql"`
	Columns []string `json:"columns"`
}

func transcodeD1Header(b []byte) ([]byte, bool, error) {
	var h struct {
		Tables []d1TableDDL `json:"tables"`
	}
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, false, fmt.Errorf("d1 header record: %w", err)
	}
	var buf bytes.Buffer
	for _, tdef := range h.Tables {
		if err := writeCreateTable(&buf, tdef.Name, tdef.SQL); err != nil {
			return nil, false, err
		}
	}
	return buf.Bytes(), true, nil
}

func transcodeD1Schema(b []byte) ([]byte, bool, error) {
	var s struct {
		Schema []string `json:"schema"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, false, fmt.Errorf("d1 schema record: %w", err)
	}
	var buf bytes.Buffer
	for _, stmt := range s.Schema {
		if !d1CreateSchemaRe.MatchString(stmt) {
			return nil, false, fmt.Errorf("d1 schema entry is not a CREATE INDEX/TRIGGER/VIEW statement")
		}
		if err := d1RequireSingleStatement(stmt, d1CreateTriggerRe.MatchString(stmt)); err != nil {
			return nil, false, fmt.Errorf("d1 schema entry: %w", err)
		}
		buf.WriteString(stmt)
		buf.WriteString(";\n")
	}
	return buf.Bytes(), true, nil
}

func transcodeD1Rows(b []byte) ([]byte, bool, error) {
	var r struct {
		Table   string              `json:"table"`
		Columns []string            `json:"columns"`
		Rows    [][]json.RawMessage `json:"rows"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, false, fmt.Errorf("d1 rows record: %w", err)
	}
	sql, err := writeInserts(r.Table, r.Columns, r.Rows)
	if err != nil {
		return nil, false, err
	}
	return sql, true, nil
}

func transcodeD1Full(b []byte) ([]byte, bool, error) {
	var f struct {
		Tables []struct {
			Name    string              `json:"name"`
			SQL     string              `json:"sql"`
			Columns []string            `json:"columns"`
			Rows    [][]json.RawMessage `json:"rows"`
		} `json:"tables"`
		Schema []string `json:"schema"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, false, fmt.Errorf("d1 full record: %w", err)
	}
	var buf bytes.Buffer
	// Phase 1: every table's DDL, so the rows that follow always have a table to land in.
	for _, t := range f.Tables {
		if err := writeCreateTable(&buf, t.Name, t.SQL); err != nil {
			return nil, false, err
		}
	}
	// Phase 2: each table's rows.
	for _, t := range f.Tables {
		ins, err := writeInserts(t.Name, t.Columns, t.Rows)
		if err != nil {
			return nil, false, err
		}
		buf.Write(ins)
	}
	// Phase 3: the non-table schema (indexes/triggers/views) last, so a trigger never fires
	// on a load row and an index is built once over the final data.
	for _, stmt := range f.Schema {
		if !d1CreateSchemaRe.MatchString(stmt) {
			return nil, false, fmt.Errorf("d1 full schema entry is not a CREATE INDEX/TRIGGER/VIEW statement")
		}
		if err := d1RequireSingleStatement(stmt, d1CreateTriggerRe.MatchString(stmt)); err != nil {
			return nil, false, fmt.Errorf("d1 full schema entry: %w", err)
		}
		buf.WriteString(stmt)
		buf.WriteString(";\n")
	}
	return buf.Bytes(), true, nil
}

// writeCreateTable emits one table's CREATE statement, defending (like the engine decoder)
// that the DDL really is a CREATE TABLE (the type check) and exactly one statement (the
// single-statement check) so a malformed body can never smuggle a different or additional
// statement into the schema-replay path. The sqlite_master CREATE text carries no trailing
// semicolon, so one is appended. A CREATE TABLE statement never carries a BEGIN...END body (only
// CREATE TRIGGER legitimately does), so the single-statement check runs with no trigger-body
// allowance at all.
func writeCreateTable(buf *bytes.Buffer, name, createSQL string) error {
	if name == "" {
		return fmt.Errorf("d1 table entry has no name")
	}
	if !d1CreateTableRe.MatchString(createSQL) {
		return fmt.Errorf("d1 table %q sql is not a CREATE TABLE statement", name)
	}
	if err := d1RequireSingleStatement(createSQL, false); err != nil {
		return fmt.Errorf("d1 table %q sql: %w", name, err)
	}
	buf.WriteString(createSQL)
	buf.WriteString(";\n")
	return nil
}

// d1RequireSingleStatement rejects a DDL/schema string that carries more than one top-level
// statement, closing the gap d1CreateTableRe/d1CreateSchemaRe leave open above: a prefix match
// only proves the string STARTS with the right keyword, not that nothing else follows, so
// "CREATE TABLE t(x); DROP TABLE other; --" passes those regexes unchanged and would otherwise
// be written byte for byte into the generated .sql file the operator is told to run directly
// against a database.
//
// allowTriggerBody must be true only for a CREATE TRIGGER entry, the one DDL kind that
// legitimately carries a BEGIN...END body with its own internal ';'-separated statements (and
// possibly a CASE...END expression nested inside one of them). CREATE TABLE/INDEX/VIEW are, by
// SQLite grammar, always exactly one statement with no legitimate semicolon at all other than an
// optional one right at the very end -- so for those this gives bare identifiers no special
// meaning at all, and simply requires that the first ';' found outside a literal is the only
// content left, whitespace aside.
//
// For a CREATE TRIGGER entry, a bare-token BEGIN/CASE/END depth counter (this function's
// previous approach) is fundamentally unsound: SQLite does not reserve "begin" or "end"
// (confirmed against the installed sqlite3 3.51.0 -- "CREATE TABLE t(begin, end)" and a trigger
// body referencing NEW.begin/NEW.end both work), so a real trigger body can legitimately contain
// a bare column/alias spelled exactly "begin"/"end", and a counter keyed on the bare spelling
// alone cannot tell that apart from the trigger's own structural keywords. An attacker can plant
// an extra unbalanced "begin" so the trigger's REAL closing END is never seen at depth zero,
// hiding a smuggled statement's ';' behind it -- empirically confirmed against the real committed
// depth-tracking fix: it accepted the entry below, and piping the identical generated text into
// the real, installed sqlite3 per D1ReplayGuidance actually executed the smuggled DROP:
//
//	CREATE TRIGGER trg AFTER INSERT ON t BEGIN SELECT begin FROM (SELECT 1 AS begin); END;
//	DROP TABLE payments; SELECT end FROM (SELECT 1 AS end)
//
// So this no longer tracks BEGIN/CASE/END as a bare-token depth counter. Instead it uses two
// SQLite grammar invariants that a same-spelled identifier can never satisfy:
//
//   - The trigger's own opening BEGIN is always immediately followed (whitespace/comments aside)
//     by the keyword starting its first action: INSERT, UPDATE, DELETE, SELECT, or the
//     REPLACE-INTO spelling of INSERT, optionally WITH-CTE-prefixed (confirmed against sqlite3
//     3.51.0 -- a trigger action list only ever begins with one of these). A bare "begin" used as
//     a column/alias/table name is, in any valid SQL, never directly adjacent to one of these
//     keywords with nothing but whitespace/comments between: there is always an intervening
//     comma, operator, parenthesis, or ';'. So a bare "BEGIN" is only ever treated as the real
//     body-opening keyword (d1TriggerActionFollows) when one of those immediately follows it --
//     a signal a same-spelled identifier reference cannot forge.
//   - The trigger's own closing END -- the one that decides where the single statement this
//     function must find really ends -- is always immediately preceded by a ';' (the last action
//     in a ';'-separated body always ends with one before END, per SQLite's trigger_cmd
//     grammar). A CASE...END expression's closing END is never preceded by ';' (its WHEN/THEN
//     /ELSE branches are pure expressions, which cannot contain a bare top-level ';'), and nor is
//     a bare "end" identifier reference (it is always preceded by whatever introduces a value
//     position instead: SET, AS, a dot as in NEW.end, an operator, a comma, and so on). Requiring
//     an "END" token to be immediately preceded by ';' before it can close the trigger body means
//     neither a CASE's own END nor a bare "end" identifier can ever be mistaken for it -- both
//     are simply inert, exactly like INSERT, WHERE, or any other keyword this function does not
//     otherwise track.
//
// A useful consequence: a CASE...END expression nested anywhere in the body needs no tracking at
// all. Its own END can never satisfy the preceded-by-';' test, so it stays inert regardless of
// nesting depth -- this removes the bare-token ambiguity instead of patching around it.
//
// This is a lexical approximation of SQLite's grammar, not a real parser, so it is deliberately
// conservative: anything it cannot positively prove is a single, cleanly-closed statement is
// rejected, never silently accepted. The residual this leaves is a false REJECT, not a bypass --
// an adversarial fragment engineered to make a bare "end" look preceded by ';' can at worst make
// this stop tracking too early and then find genuine trailing body content non-blank, which fails
// closed (an error), never open (content smuggled past it silently). Both directions were
// exercised against the real committed code and the real installed sqlite3 3.51.0 for this
// change: the bypass above is now refused, and a trigger body referencing "begin"/"end" as an
// ordinary column (bare, or NEW./OLD.-qualified) is now accepted.
//
// Whichever mode applies, a quote/backtick/bracket identifier or comment that never closes
// before the string ends is rejected. That matters because a JSON array can carry more than one
// DDL/schema entry, each validated here in isolation, with every entry's output concatenated
// into the same buffer and only a plain ";\n" written in between (see writeCreateTable,
// transcodeD1Schema, transcodeD1Full): an unclosed literal left dangling at the end of one entry
// could otherwise be closed by a character embedded in the NEXT entry's text once concatenated,
// splicing the two entries (and the ";\n" between them) into one attacker-shaped string literal
// and manufacturing a fresh top-level ';' wherever the attacker wants their injected statement to
// begin. Requiring every quote/bracket/comment to close within its own entry means no entry can
// ever leave a dangling span for a sibling entry to complete -- a real single sqlite_master DDL
// statement is, by construction, already fully self-contained, so this never rejects legitimate
// input.
func d1RequireSingleStatement(stmt string, allowTriggerBody bool) error {
	isIdentByte := func(b byte) bool {
		return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
	}
	isSpaceByte := func(b byte) bool {
		switch b {
		case ' ', '\t', '\n', '\r', '\f', '\v':
			return true
		}
		return false
	}
	triggerOpen := false    // true from a verified trigger-body BEGIN until its own matching END
	afterSemicolon := false // true if the last significant token scanned was ';' (whitespace/comments in between do not clear this -- see the preceded-by-';' rule above)
	term := -1
	i, n := 0, len(stmt)
scan:
	for i < n {
		c := stmt[i]
		switch {
		case isSpaceByte(c):
			i++ // whitespace is never "significant": it never clears afterSemicolon
		case c == '\'' || c == '"' || c == '`':
			// String/identifier literal: SQLite treats ', ", and ` alike -- a doubled
			// delimiter is an escaped literal character, a lone one closes the span. It
			// must close within this entry: see the unterminated-span note above.
			start := i
			i++
			closed := false
			for i < n {
				if stmt[i] == c {
					if i+1 < n && stmt[i+1] == c {
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				return fmt.Errorf("statement has an unterminated %c...%c literal starting at byte %d", c, c, start)
			}
			afterSemicolon = false
		case c == '[': // bracket identifier: no escaping, must close at a following ']'
			j := strings.IndexByte(stmt[i+1:], ']')
			if j < 0 {
				return fmt.Errorf("statement has an unterminated [...] identifier")
			}
			i += j + 2
			afterSemicolon = false
		case c == '-' && i+1 < n && stmt[i+1] == '-': // line comment, must end by end of line
			j := strings.IndexByte(stmt[i:], '\n')
			if j < 0 {
				return fmt.Errorf("statement has an unterminated -- comment (no trailing newline)")
			}
			i += j + 1 // a comment is insignificant, like whitespace: it never clears afterSemicolon
		case c == '/' && i+1 < n && stmt[i+1] == '*': // block comment
			j := strings.Index(stmt[i+2:], "*/")
			if j < 0 {
				return fmt.Errorf("statement has an unterminated /* */ comment")
			}
			i += j + 4
		case c == ';':
			if allowTriggerBody && triggerOpen {
				afterSemicolon = true
				i++
				continue
			}
			term = i
			break scan
		case allowTriggerBody && isIdentByte(c):
			// Only a CREATE TRIGGER entry inspects bare identifiers for BEGIN/END at all: for
			// every other kind this branch never runs, so a bare "begin"/"case"/"end" column
			// or identifier name is just skipped like any other token (see doc comment).
			start := i
			for i < n && isIdentByte(stmt[i]) {
				i++
			}
			switch strings.ToUpper(stmt[start:i]) {
			case "BEGIN":
				if !triggerOpen && d1TriggerActionFollows(stmt, i) {
					triggerOpen = true
				}
			case "END":
				if triggerOpen && afterSemicolon {
					triggerOpen = false
				}
				// "CASE" is deliberately not matched here: see the doc comment above for why
				// a CASE...END pair never needs recognising for this check to still find the
				// right statement boundary.
			}
			afterSemicolon = false
		default:
			i++
			afterSemicolon = false
		}
	}
	if allowTriggerBody && triggerOpen {
		return fmt.Errorf("statement's CREATE TRIGGER body never reaches a closing END")
	}
	rest := ""
	if term >= 0 {
		rest = stmt[term+1:]
	}
	if strings.TrimSpace(rest) != "" {
		return fmt.Errorf("statement carries content after its terminating ';' (more than one statement)")
	}
	return nil
}

// d1TriggerActionFollows reports whether the next non-space, non-comment token in stmt at or
// after position i is one of the keywords that can legitimately start a trigger-body action:
// INSERT, UPDATE, DELETE, SELECT (any of which may be WITH-CTE-prefixed), or the REPLACE-INTO
// spelling of INSERT -- confirmed against a real SQLite 3.51.0 trigger_cmd grammar. It is what
// promotes a bare "BEGIN" token from "just another identifier" to "this really is the trigger's
// own body-opening keyword": a column/alias/table name spelled "begin" is, in any valid SQL,
// never immediately adjacent (past whitespace/comments only) to a fresh statement-starting
// keyword like these without an intervening comma, operator, parenthesis, or ';' -- so finding
// one directly after "begin" is a reliable signal a same-spelled identifier cannot forge.
func d1TriggerActionFollows(stmt string, i int) bool {
	n := len(stmt)
	for i < n {
		c := stmt[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '-' && i+1 < n && stmt[i+1] == '-':
			j := strings.IndexByte(stmt[i:], '\n')
			if j < 0 {
				return false
			}
			i += j + 1
		case c == '/' && i+1 < n && stmt[i+1] == '*':
			j := strings.Index(stmt[i+2:], "*/")
			if j < 0 {
				return false
			}
			i += j + 4
		default:
			start := i
			for i < n && (stmt[i] == '_' || (stmt[i] >= 'a' && stmt[i] <= 'z') || (stmt[i] >= 'A' && stmt[i] <= 'Z') || (stmt[i] >= '0' && stmt[i] <= '9')) {
				i++
			}
			if i == start {
				return false // the very next byte is punctuation, not a bare keyword
			}
			switch strings.ToUpper(stmt[start:i]) {
			case "INSERT", "UPDATE", "DELETE", "SELECT", "WITH", "REPLACE":
				return true
			default:
				return false
			}
		}
	}
	return false
}

// writeInserts renders one table's rows as parameter-free, column-named multi-row INSERTs
// inside a single transaction (atomic + fast on apply). The column names are quoted
// identifiers (they cannot be parameters); every value is rendered as a SQL LITERAL by
// d1Literal, which keeps BLOB/NULL/bigint exact. An empty rows set yields no SQL.
func writeInserts(table string, columns []string, rows [][]json.RawMessage) ([]byte, error) {
	if table == "" {
		return nil, fmt.Errorf("d1 rows record has no table name")
	}
	if len(rows) == 0 {
		return nil, nil
	}
	if len(columns) == 0 {
		return nil, fmt.Errorf("d1 rows for %q has no columns", table)
	}
	quotedCols := make([]string, len(columns))
	for i, c := range columns {
		quotedCols[i] = quoteIdent(c)
	}
	colList := strings.Join(quotedCols, ", ")
	qTable := quoteIdent(table)

	var buf bytes.Buffer
	buf.WriteString("BEGIN TRANSACTION;\n")
	for start := 0; start < len(rows); start += d1InsertBatch {
		end := start + d1InsertBatch
		if end > len(rows) {
			end = len(rows)
		}
		fmt.Fprintf(&buf, "INSERT INTO %s (%s) VALUES\n", qTable, colList)
		for i := start; i < end; i++ {
			row := rows[i]
			if len(row) != len(columns) {
				return nil, fmt.Errorf("d1 rows for %q: row %d has %d cells, want %d", table, i, len(row), len(columns))
			}
			buf.WriteByte('(')
			for j, cell := range row {
				if j > 0 {
					buf.WriteString(", ")
				}
				lit, err := d1Literal(cell)
				if err != nil {
					return nil, fmt.Errorf("d1 rows for %q row %d column %d: %w", table, i, j, err)
				}
				buf.WriteString(lit)
			}
			buf.WriteByte(')')
			if i == end-1 {
				buf.WriteString(";\n")
			} else {
				buf.WriteString(",\n")
			}
		}
	}
	buf.WriteString("COMMIT;\n")
	return buf.Bytes(), nil
}

// d1Literal renders one decoded D1 cell as a SQLite literal, keeping each storage class
// exact: NULL stays NULL, a string is single-quoted with internal quotes doubled, a tagged
// BLOB becomes an x'..' hex literal, a tagged out-of-safe-range integer becomes a BARE
// integer literal (never narrowed through a float), and a plain JSON number is emitted as its
// exact token (so an INTEGER up to 2^53 keeps full precision). An array or unrecognised
// object is refused so a malformed cell never produces silently-wrong SQL.
func d1Literal(raw json.RawMessage) (string, error) {
	tok := bytes.TrimSpace(raw)
	if len(tok) == 0 {
		return "", fmt.Errorf("empty cell")
	}
	switch tok[0] {
	case 'n': // null
		if string(tok) != "null" {
			return "", fmt.Errorf("unexpected cell token %q", tok)
		}
		return "NULL", nil
	case '"': // string
		var s string
		if err := json.Unmarshal(tok, &s); err != nil {
			return "", fmt.Errorf("string cell: %w", err)
		}
		return "'" + strings.ReplaceAll(s, "'", "''") + "'", nil
	case '{': // tagged $blob or $int
		return d1TaggedLiteral(tok)
	case '[':
		return "", fmt.Errorf("array cell is not a valid D1 value")
	case 't', 'f':
		return "", fmt.Errorf("boolean cell is not a valid D1 value")
	default: // number
		num := string(tok)
		if !d1NumRe.MatchString(num) {
			return "", fmt.Errorf("malformed numeric cell %q", num)
		}
		return num, nil
	}
}

// d1TaggedLiteral renders the two JSON-untypable cell kinds the engine tags: a base64url
// BLOB ({"$blob":"..."}) as an x'<hex>' literal, and an out-of-safe-range integer
// ({"$int":"<decimal>"}) as a bare integer literal. Exactly one tag must be present.
func d1TaggedLiteral(tok []byte) (string, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(tok, &obj); err != nil {
		return "", fmt.Errorf("tagged cell: %w", err)
	}
	if len(obj) != 1 {
		return "", fmt.Errorf("tagged cell must carry exactly one of $blob or $int")
	}
	if raw, ok := obj["$blob"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", fmt.Errorf("$blob cell is not a string: %w", err)
		}
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
		if err != nil {
			return "", fmt.Errorf("$blob cell is not valid base64url: %w", err)
		}
		return "x'" + hex.EncodeToString(b) + "'", nil
	}
	if raw, ok := obj["$int"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", fmt.Errorf("$int cell is not a string: %w", err)
		}
		if !d1IntRe.MatchString(s) {
			return "", fmt.Errorf("$int cell %q is not a decimal integer", s)
		}
		return s, nil
	}
	return "", fmt.Errorf("tagged cell carries an unknown tag")
}

// quoteIdent wraps a SQLite identifier (table or column name) for safe interpolation into the
// INSERT/CREATE text: wrap in double quotes and double any embedded double quote, so a name
// can never break out of its quotes. Mirrors the engine's quoteIdent.
func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
