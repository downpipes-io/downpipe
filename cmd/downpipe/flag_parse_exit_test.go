package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
)

// The exit status of a FLAG-PARSE outcome is pinned here, for every command in the dispatch.
//
// WHAT WENT WRONG WITHOUT THIS. A flag.FlagSet returns its parse errors uncoded, and every
// subcommand returned that error straight up, where run() gave it exitUncoded (1). The printed
// exit-code table defines 1 as "an I/O or unexpected failure this tool did not otherwise
// classify", so a mistyped flag mid-recovery was reported as an unexpected failure rather than
// as the usage error it is, and "downpipe verify --help" was reported as one too. Thirteen of
// the fourteen commands did this. recombine alone coded its parse error to ExitUsage, which is
// what settled the right answer, and recombine went the other way on help: it exited 6 for a
// help request the tool had just answered.
//
// The no-args case was corrected earlier (run() returns ExitUsage rather than the tamper-class
// 2) and the unknown-command case was already right, so the gap was only ever one layer down,
// inside the subcommands, where nothing was looking.
//
// These are the codes a recovery script branches on: 6 says fix the command line, 1 says
// something unexpected happened and is worth investigating, 0 says nothing is wrong.

// printOnlyBuiltins are the dispatch cases that construct no FlagSet: they print and return.
// They are stated because they are the exception; every other command must satisfy the pin, so
// a NEW command is covered by default rather than needing to be remembered.
var printOnlyBuiltins = map[string]bool{"help": true, "spec": true, "version": true}

// TestFlagParseOutcomesCarryTheRightExitCode drives every dispatched command twice, through the
// same run() that main() calls, so what is pinned is the process exit status and not an
// intermediate error value.
func TestFlagParseOutcomesCarryTheRightExitCode(t *testing.T) {
	cases := dispatchCases(t)
	if len(cases) == 0 {
		t.Fatal("no dispatch cases were read, so this test proved nothing")
	}
	// The subcommands write their usage to stderr on both paths. Silence it so a passing run
	// is readable; a failure reports the command and the codes, which is what is needed.
	silenceOutput(t)

	checked := 0
	for _, cmd := range cases {
		if printOnlyBuiltins[cmd] {
			continue
		}
		checked++
		if got := run([]string{cmd, "--definitely-not-a-flag"}); got != format.ExitUsage {
			t.Errorf("%s with an undefined flag exited %d, want %d (ExitUsage): an unparseable command line is a usage error, not an unclassified failure", cmd, got, format.ExitUsage)
		}
		if got := run([]string{cmd, "--help"}); got != 0 {
			t.Errorf("%s --help exited %d, want 0: the operator asked for the usage and the FlagSet printed it, so nothing failed", cmd, got)
		}
	}
	if checked == 0 {
		t.Fatal("every dispatch case was classified as a print-only builtin, so nothing was driven")
	}
}

// TestEveryFlagSetGoesThroughParseFlags closes the route by which the defect returns: a new
// command calling fs.Parse(args) directly and returning the uncoded error. The pin above would
// catch it, but only for a command that reaches the dispatch, and this says WHERE the fix is.
//
// It reads the parsed syntax tree rather than the text of the files. A commented-out call is not
// in the tree, and a call spelled across lines still reduces to the same node, so neither shape
// can slip past the way a line-oriented search would let it.
func TestEveryFlagSetGoesThroughParseFlags(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("cannot read the command package directory: %v", err)
	}
	var offenders []string
	files := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files++
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("cannot parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok {
				return true
			}
			if fn.Name.Name == "parseFlags" {
				// The one function allowed to call it: it is the fix.
				return false
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Parse" {
					return true
				}
				recv, ok := sel.X.(*ast.Ident)
				if !ok || recv.Name != "fs" {
					return true
				}
				offenders = append(offenders, filepath.Join(name, fn.Name.Name))
				return true
			})
			return false
		})
	}
	if files == 0 {
		t.Fatal("no non-test Go files were parsed in the command package, so this test proved nothing")
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("these functions call fs.Parse directly instead of parseFlags, so their parse errors reach run() uncoded and exit 1: %v", offenders)
	}
}
