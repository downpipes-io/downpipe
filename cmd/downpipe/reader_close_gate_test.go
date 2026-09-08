package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Every command that opens a run must close it, so the run master does not outlive the command.
//
// WHY THIS IS A GATE AND NOT JUST A CONVENTION. Five commands open a run today and every one of them was
// missing the close until: the reader held the master for the whole process with nothing to end
// it. That is on the binary a customer runs on their own machine with their break-glass key, and in the
// strict break-glass-only posture, now the default, it is the only thing that can read an archive at all.
// A sixth command added next month would inherit the same gap silently, because nothing failed.
//
// The writing engine enforces the same rule on its own side.
//
// This is a source scan rather than a behavioural test on purpose. The case worth catching is a NEW call
// site, and no behavioural test can see one that does not exist yet.
//
// IT READS THE PARSED SOURCE, NOT THE TEXT. The first version matched the open with one regular expression
// and the close with another, then paired them by the name they bound. Two holes were proven against this
// repository before the rewrite, both leaving the gate green while a run master genuinely leaked:
//
//   - The close was looked for anywhere in the FILE, not in the function that opened. Adding a second
//     helper to restore.go that opened a run into `r` and never closed it passed, because cmdRestore's own
//     `defer r.Close()` was further down the same file and bound the same name. That is exactly the
//     "sixth command added next month" this gate exists for.
//   - A pattern over text cannot tell code from a comment. Replacing verify.go's `defer r.Close()` with
//     the line `// TODO: reinstate r.Close() once the shared teardown lands` left verify genuinely holding
//     the master for the life of the process, and the gate stayed green because the identifier was still
//     in the bytes.
//
// The parser closes both by construction. Accounting is TOTAL: every call to format.Open, StreamOpen or
// StreamOpenContext must bind its reader to a plain identifier this test can follow, and one that does not
// fails the test naming the position, rather than falling out of a no-match branch and being counted as
// absent.

// The constructors that hand back a reader holding a live run master.
var runOpeners = map[string]bool{"Open": true, "StreamOpen": true, "StreamOpenContext": true}

const formatPkgPath = "github.com/downpipes-io/downpipe/internal/format"

// commandFiles parses every non-test Go file of this package. A parse error is fatal rather than skipped:
// a file this test cannot read is a file whose opens it cannot account for.
func commandFiles(t *testing.T) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read command directory: %v", err)
	}
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if perr != nil {
			t.Fatalf("cannot parse %s, so its run opens cannot be accounted for: %v", name, perr)
		}
		files[name] = f
	}
	// A gate that scans nothing reads exactly like a passing gate.
	if len(files) < 10 {
		t.Fatalf("expected this package's command files, found only %d. Has the layout moved?", len(files))
	}
	return fset, files
}

// formatAlias returns the local name the file uses for the format package, so an aliased import does not
// take a command out of this gate's sight. It returns "" when the file does not import format at all,
// which means the file cannot hold an open.
func formatAlias(file *ast.File) string {
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != formatPkgPath {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		return "format"
	}
	return ""
}

// isRunOpen reports whether call is one of the run-opening constructors, under this file's spelling of the
// format package.
func isRunOpen(call *ast.CallExpr, alias string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !runOpeners[sel.Sel.Name] {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == alias
}

// closesBinding reports whether the given function body calls name.Close() anywhere within it, including
// inside a defer or a closure. It is an AST search, so an identifier that only appears in a comment or a
// string does not count as a close.
func closesBinding(body ast.Node, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Close" {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}

func TestEveryCommandThatOpensARunClosesIt(t *testing.T) {
	fset, files := commandFiles(t)

	sites := 0
	var missing []string
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		file := files[name]
		alias := formatAlias(file)
		if alias == "" {
			continue
		}

		// Every open in the file, so one that is not inside a function declaration, or whose reader is
		// not bound to a name, can be reported rather than quietly missed.
		opens := map[*ast.CallExpr]bool{}
		ast.Inspect(file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && isRunOpen(call, alias) {
				opens[call] = true
			}
			return true
		})
		if len(opens) == 0 {
			continue
		}

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				assign, ok := n.(*ast.AssignStmt)
				if !ok || len(assign.Rhs) != 1 {
					return true
				}
				call, ok := assign.Rhs[0].(*ast.CallExpr)
				if !ok || !opens[call] {
					return true
				}
				delete(opens, call)
				sites++
				pos := fset.Position(call.Pos())
				if len(assign.Lhs) == 0 {
					t.Fatalf("%s: a run is opened and its reader is not bound at all, so nothing can close it", pos)
				}
				binding, ok := assign.Lhs[0].(*ast.Ident)
				if !ok {
					t.Fatalf("%s: the reader from this open is bound to a %T rather than a plain name, so this gate cannot follow it. Bind it to a local and close that, or teach this test the new form.", pos, assign.Lhs[0])
				}
				if binding.Name == "_" {
					t.Fatalf("%s: the reader from this open is discarded, so its run master is never wiped", pos)
				}
				// The whole enclosing function, so a close in a defer or a closure counts, and a close in
				// a DIFFERENT function of the same file does not.
				if !closesBinding(fn.Body, binding.Name) {
					missing = append(missing, name+" "+fn.Name.Name+"() ("+binding.Name+")")
				}
				return true
			})
		}

		// Anything left is an open this gate could not attribute to an assignment inside a function.
		for call := range opens {
			t.Fatalf("%s: a run is opened outside any assignment this gate can follow (in %s), so it cannot be shown to be closed", fset.Position(call.Pos()), name)
		}
	}

	// A gate that matched nothing would report clean for ever. The count is asserted so an extractor that
	// silently stopped matching fails here instead of passing quietly.
	if sites < 5 {
		t.Fatalf("expected at least 5 run-open sites in the commands, found %d: the extractor has probably stopped matching", sites)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("these functions open a run and never close it, so the run master outlives them: %s\n"+
			"Add `defer r.Close()` after the error check, or call Close() per iteration when the open is inside a loop.",
			strings.Join(missing, ", "))
	}
}

// A defer inside a loop does not close per iteration: it stacks until the function returns, holding one
// live run master per run. prune's enumerate opens a reader for every run in the archive, so it closes
// explicitly at the end of each iteration instead. This pins that difference, because the obvious "fix" for
// a future reviewer tidying up is to convert it to a defer, which would silently undo it.
//
// It reads the parsed function rather than a slice of the file's text. Sliced by text, a `r.Close()` left
// behind in a comment satisfied the first half of this check, and the `defer` half could be dodged by any
// spelling the exact substring did not cover.
func TestPruneEnumerateDoesNotDeferInsideItsLoop(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "prune.go", nil, 0)
	if err != nil {
		t.Fatalf("cannot parse prune.go: %v", err)
	}

	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		d, ok := decl.(*ast.FuncDecl)
		if ok && d.Recv == nil && d.Name != nil && d.Name.Name == "enumerate" {
			fn = d
			break
		}
	}
	if fn == nil || fn.Body == nil {
		t.Fatal("enumerate not found in prune.go: this gate is pinned to a function that no longer exists")
	}

	// The loop that opens a reader per run. Finding it by the open, rather than by being the first loop,
	// keeps the pin on the right statement if another loop is added.
	alias := formatAlias(file)
	if alias == "" {
		t.Fatal("prune.go no longer imports the format package, so this gate is pinned to code that has moved")
	}
	// The binding comes off the open rather than being assumed to be called r. It was hard-coded, and
	// renaming the reader while keeping the explicit close, which is the tidy-up this gate is here to
	// survive, failed with "must close each one" while the close was right there under the new name. A
	// gate that fails is better than one that passes, but a gate that names a defect that is not there
	// sends the next person hunting for it.
	var loop ast.Node
	binding := ""
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		var body *ast.BlockStmt
		switch l := n.(type) {
		case *ast.RangeStmt:
			body = l.Body
		case *ast.ForStmt:
			body = l.Body
		default:
			return true
		}
		found := ""
		ast.Inspect(body, func(inner ast.Node) bool {
			assign, ok := inner.(*ast.AssignStmt)
			if !ok || len(assign.Rhs) != 1 {
				return true
			}
			call, ok := assign.Rhs[0].(*ast.CallExpr)
			if !ok || !isRunOpen(call, alias) {
				return true
			}
			pos := fset.Position(call.Pos())
			if len(assign.Lhs) == 0 {
				t.Fatalf("%s: a run is opened in enumerate's loop and its reader is not bound at all, so nothing can close it", pos)
			}
			id, ok := assign.Lhs[0].(*ast.Ident)
			if !ok {
				t.Fatalf("%s: the reader from this open is bound to a %T rather than a plain name, so this gate cannot follow it. Bind it to a local and close that, or teach this test the new form.", pos, assign.Lhs[0])
			}
			if id.Name == "_" {
				t.Fatalf("%s: the reader from this open is discarded, so its run master is never wiped", pos)
			}
			found = id.Name
			return false
		})
		if found != "" {
			loop = n
			binding = found
			return false
		}
		return true
	})
	if loop == nil {
		t.Fatal("enumerate no longer opens a run inside a loop, so this gate is pinned to a shape that has gone; has the per-run close moved with it?")
	}

	if !closesBinding(loop, binding) {
		t.Fatalf("enumerate opens a reader per run into %s and must close each one", binding)
	}
	deferred := false
	ast.Inspect(loop, func(n ast.Node) bool {
		d, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		if closesBinding(d, binding) {
			deferred = true
			return false
		}
		return true
	})
	if deferred {
		t.Fatal("enumerate closes inside a per-run loop, so a defer would hold every run's master live until the whole enumeration returned")
	}
}
