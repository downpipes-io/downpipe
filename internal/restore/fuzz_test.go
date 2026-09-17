package restore

import (
	"path/filepath"
	"strings"
	"testing"
)

// FuzzD1Transcode fuzzes the D1 dump transcoder, the largest parser in the reader and
// the only one that runs on SOURCE-CONTROLLED content: integrity proves the bytes are
// what was backed up, not that they are benign, so a hostile or corrupt D1 database
// reaches this statement scanner at restore time with its bytes intact.
//
// Invariants: no panic and no hang (the input is bounded); an error is a clean refusal;
// and an ACCEPTED transcode must emit SQL, never pass a recognised-but-broken dump
// through as if it were opaque bytes. The single-statement rule is the security
// property: a recognised dump must never render into something carrying a second
// statement past the gate.
func FuzzD1Transcode(f *testing.F) {
	f.Add([]byte(`{"downpipeD1Dump":1,"tables":[{"name":"t","rows":[[1,"a"]]}]}`))
	f.Add([]byte(`{"downpipeD1Dump":1,"tables":[]}`))
	f.Add([]byte(`{"downpipeD1Dump":1}`))
	f.Add([]byte(`{"downpipeD1Dump":1,"tables":[{"name":"t; DROP TABLE u","rows":[]}]}`))
	f.Add([]byte(`{"downpipeD1Dump":1,"tables":[{"name":"t","schema":"CREATE TABLE t(a); DROP TABLE u","rows":[]}]}`))
	f.Add([]byte(`{"downpipeD1Dump":1,"tables":[{"name":"t","schema":"CREATE TRIGGER x BEGIN SELECT 1; END","rows":[]}]}`))
	f.Add([]byte(`{"downpipeD1Dump":1,"tables":[{"name":"t","rows":[["'; DROP TABLE u --"]]}]}`))
	f.Add([]byte(`{"downpipeD1Dump":1,"tables":[{"name":"t","rows":[[null,true,1.5,"x"]]}]}`))
	f.Add([]byte(`{"downpipeD1Dump":2,"tables":[]}`))
	f.Add([]byte(`not json at all`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Native Go fuzzing has no per-execution timeout, so a pathological input must
		// not be allowed to run away with the whole budget; the transcoder is a scanner,
		// and a bounded input exercises every state it has.
		if len(data) > 1<<16 {
			return
		}
		sql, ok, err := transcodeD1(data)
		if err != nil {
			if ok {
				t.Fatal("a failed transcode must not also report success")
			}
			if sql != nil {
				t.Fatal("a failed transcode must not return output")
			}
			return
		}
		if !ok {
			// Not a recognised downpipe D1 dump: the caller writes the value verbatim.
			if sql != nil {
				t.Fatal("an unrecognised body must not produce SQL")
			}
			return
		}
		// A recognised dump rendered successfully: it must actually be SQL, and the
		// statement gate must have held (no smuggled second statement outside a
		// quoted literal or a BEGIN...END trigger body).
		if len(sql) == 0 {
			t.Fatal("a recognised dump rendered to empty output")
		}
		// The renderer emits a multi-statement SCRIPT by design (one statement per line),
		// and the transcoder applies the single-statement gate to each statement as it
		// renders. The property under test is that no RENDERED line smuggles a second
		// statement past that gate, so re-apply it line by line. A trigger body is the
		// one legal multi-statement shape (BEGIN ... END), so allow it here exactly as
		// the renderer does.
		for _, line := range strings.Split(string(sql), "\n") {
			line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ";"))
			if line == "" || strings.HasPrefix(line, "--") {
				continue
			}
			if serr := d1RequireSingleStatement(line, true); serr != nil {
				t.Fatalf("a rendered statement fails the single-statement gate: %q (%v)", truncate(line), serr)
			}
		}
	})
}

func truncate(s string) string {
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}

// FuzzDirTargetKey property-fuzzes the archive-controlled path mapping: a record name
// comes from the backed-up source, so it is attacker-influenced in the same way the
// archive bytes are. The mapping must never escape the output directory, never emit an
// absolute path, never keep a traversal element, and never hand the operating system a
// reserved device name (the Windows-reserved guard).
func FuzzDirTargetKey(f *testing.F) {
	for _, seed := range []string{
		"", ".", "..", "/", "//", "a/b", "../../etc/passwd", "/etc/passwd",
		"C:\\Windows\\System32", "CON", "con.txt", "COM1", "CONIN$",
		"COM\u00b9", // the superscript COM1 form the reserved-name guard folds
		"nul", "aux ", "LPT1.txt", "a/../../b", "./x", "x/./y", "a//b",
		"trailing.", "trailing ", "\\\\server\\share", "a\x00b",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, name string) {
		if len(name) > 4096 {
			return
		}
		d := NewDirTarget("/out")
		key, err := d.Key(name)
		if err != nil {
			return // a refused name is a valid outcome
		}
		if key == "" {
			t.Fatalf("accepted %q and mapped it to an empty key", name)
		}
		if filepath.IsAbs(key) || strings.HasPrefix(key, "/") {
			t.Fatalf("key %q from %q is absolute", key, name)
		}
		if strings.HasPrefix(key, "\\") {
			t.Fatalf("key %q from %q is a UNC-style path", key, name)
		}
		for _, elem := range strings.Split(key, "/") {
			if elem == "" || elem == "." || elem == ".." {
				t.Fatalf("key %q from %q keeps the traversal element %q", key, name, elem)
			}
		}
		if elem, bad := firstReservedWindowsElement(key); bad {
			t.Fatalf("key %q from %q keeps the reserved element %q", key, name, elem)
		}
		// Joining under the output root must stay under the output root.
		joined := filepath.Join("/out", filepath.FromSlash(key))
		if !strings.HasPrefix(filepath.ToSlash(joined), "/out/") {
			t.Fatalf("key %q from %q escapes the output root: %q", key, name, joined)
		}
	})
}
