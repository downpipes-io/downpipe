package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The command set is PINNED, because the docs state its size and nothing was checking.
//
// WHAT WENT WRONG WITHOUT THIS. The CLI reference page in the docs site says how many subcommands the
// tool dispatches and lists each one in a table. `prune`, `recombine` and `unseal-export` were added and
// neither the count nor the table moved, so for three weeks the page described the binary as it stood at
// the v0.1.1 tag rather than as it is. A reader following that page would not have known the offline
// prune existed, and `recombine` is the command the M-of-N custody path on that same page depends on.
//
// The docs live in a sibling repository, so a test there cannot see this code and a test here cannot be
// sure the sibling is checked out. This pin is the half that works in a single-repo CI run: it does not
// read the docs, it fails when the SET changes, which is the moment someone must go and update them. The
// failure message says so rather than leaving the next person to guess why a count is in a test.
//
// Adding a command should fail this test. That is the point, not an inconvenience: the fix is one line
// here and one row plus a count in the docs, and doing both is what keeps the page true.

// The fourteen subcommands, as the docs' table describes them.
var wantSubcommands = []string{
	"attest", "init", "inspect", "keygen", "keys", "preflight", "prune",
	"recombine", "restore", "selftest", "setup", "unseal-export", "update", "verify",
}

// The three built-ins, which the docs count separately because they take no archive and do no work.
var wantBuiltins = []string{"help", "spec", "version"}

// dispatchCases reads the switch in main.go rather than a hand-kept list, so the test cannot drift from
// the code it is pinning. A pin copied by hand is a second thing to forget.
//
// It reads the PARSED switch, not the text of the file. The earlier version matched `^\s*case "..."` with
// a regular expression, and that had two holes, both proven against this repository before this was
// rewritten, and both in the direction that leaves the pin green while the truth moves:
//
//   - A case label written as a raw-string literal is not the shape the pattern looked for. Adding
//     `case ` + "`wipe`" + `:` put a new subcommand into the binary and the pin stayed green, so the docs
//     would never have learnt it existed.
//   - A line-oriented pattern cannot see a block comment around it. Wrapping `case "prune":` in a
//     /* */ block took prune out of the binary (`downpipe prune` then answered "unknown command") while
//     the pin stayed green and the docs table kept listing it. That is how a Go command is actually
//     retired, so it is the realistic version of the bug rather than a contrived one.
//
// The parser closes both by construction and closes respellings nobody has thought of yet: a raw string,
// a unicode escape and a concatenation all reduce to the same constant, and a commented-out case is not
// in the tree at all. Accounting is TOTAL: every clause of the dispatch switch must yield a string
// constant, and anything that does not fails the test naming the expression it could not read, rather
// than falling out of a no-match branch and being counted as absent.
func dispatchCases(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("cannot parse main.go, which is where the dispatch lives: %v", err)
	}
	sw := findDispatchSwitch(file)
	if sw == nil {
		t.Fatal("could not find the switch on args[0] inside run() in main.go, so this test proved nothing; has the dispatch moved or been renamed?")
	}
	found := []string{}
	for _, stmt := range sw.Body.List {
		clause, ok := stmt.(*ast.CaseClause)
		if !ok {
			t.Fatalf("the dispatch switch holds a %T where a case clause was expected at %s; this test can no longer account for the whole command set", stmt, fset.Position(stmt.Pos()))
		}
		// A nil List is the default clause. It dispatches no named command, so it contributes nothing,
		// and saying so explicitly keeps it from being mistaken for an unreadable clause below.
		if clause.List == nil {
			continue
		}
		for _, expr := range clause.List {
			name, ok := stringConst(expr)
			if !ok {
				t.Fatalf("case label at %s is not a string constant this test can read (%T); the command set cannot be accounted for while it is there. Write the label as a plain string literal, or teach this test the new form.", fset.Position(expr.Pos()), expr)
			}
			// The aliases are not commands. `-v` and `--help` are spellings of ones already counted.
			if strings.HasPrefix(name, "-") {
				continue
			}
			found = append(found, name)
		}
	}
	if len(found) == 0 {
		t.Fatal("found no dispatch cases in main.go, so this test proved nothing; has the dispatch moved?")
	}
	sort.Strings(found)
	return found
}

// findDispatchSwitch returns the switch statement that dispatches on args[0]. It is identified by its
// tag rather than by being the first switch in the file, because run() holds other switches and adding
// one more must not silently re-point this pin at the wrong statement.
func findDispatchSwitch(file *ast.File) *ast.SwitchStmt {
	var found *ast.SwitchStmt
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Name.Name != "run" || fn.Recv != nil {
			return true
		}
		ast.Inspect(fn, func(inner ast.Node) bool {
			sw, ok := inner.(*ast.SwitchStmt)
			if !ok || sw.Tag == nil {
				return true
			}
			idx, ok := sw.Tag.(*ast.IndexExpr)
			if !ok {
				return true
			}
			ident, ok := idx.X.(*ast.Ident)
			if !ok || ident.Name != "args" {
				return true
			}
			found = sw
			return false
		})
		return false
	})
	return found
}

// stringConst resolves a case label to the string it denotes, so a raw string, an interpreted string
// with escapes, and a concatenation of either all reduce to the same name. Anything else is reported as
// unreadable to the caller rather than skipped, which is what makes the accounting total.
func stringConst(expr ast.Expr) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(e.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.ParenExpr:
		return stringConst(e.X)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		l, lok := stringConst(e.X)
		r, rok := stringConst(e.Y)
		if !lok || !rok {
			return "", false
		}
		return l + r, true
	default:
		return "", false
	}
}

func TestCommandSetMatchesTheDocumentedOne(t *testing.T) {
	got := dispatchCases(t)

	want := append(append([]string{}, wantSubcommands...), wantBuiltins...)
	sort.Strings(want)

	gotSet, wantSet := map[string]bool{}, map[string]bool{}
	for _, c := range got {
		gotSet[c] = true
	}
	for _, c := range want {
		wantSet[c] = true
	}

	added, removed := []string{}, []string{}
	for _, c := range got {
		if !wantSet[c] {
			added = append(added, c)
		}
	}
	for _, c := range want {
		if !gotSet[c] {
			removed = append(removed, c)
		}
	}

	if len(added) > 0 || len(removed) > 0 {
		t.Errorf(
			"the command set has changed and the docs will not know.\n"+
				"  added since the pin:   %s\n"+
				"  gone since the pin:    %s\n"+
				"  Update BOTH: this pin, and docs/src/content/docs/reference/cli/command-reference.mdx, which\n"+
				"  states the subcommand COUNT in prose and lists every command in a table. The count is\n"+
				"  currently %d subcommands plus %d built-ins. Getting this wrong is not cosmetic: the page\n"+
				"  went three weeks describing the v0.1.1 tag instead of the code, so prune, recombine and\n"+
				"  unseal-export were undocumented, and recombine is what the custody path there depends on.",
			strings.Join(added, ", ")+emptyNote(added),
			strings.Join(removed, ", ")+emptyNote(removed),
			len(wantSubcommands), len(wantBuiltins),
		)
	}
}

func emptyNote(s []string) string {
	if len(s) == 0 {
		return "(none)"
	}
	return ""
}
