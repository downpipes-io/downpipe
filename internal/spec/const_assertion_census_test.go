package spec

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// A CENSUS THAT WAS ONLY A SENTENCE, MADE RE-RUNNABLE.
//
// Commit 5698c6db recorded "2,598 comparisons in assertion position, 11 with both operands constant,
// all 11 read rather than counted" and "1 of 96" for the .mjs gates. Those numbers were true of a
// measurement somebody took once and they were re-derivable by nobody: `git ls-files` finds no census
// script in this repository, so there was no command to re-run, nothing to ratchet, and no way for the
// number to be wrong out loud. It would have rotted in silence the first time anyone added an
// assertion.
//
// RE-DERIVING IT FOUND THE SENTENCE ALREADY SHORT BY ONE. This census reports TWELVE such comparisons.
// The commit accounts for eleven of them, two pinning the container framing constants and nine pinning
// the frozen source-type wire strings. The twelfth is `format.ExitUsage == format.ExitUnverified` in
// cmd/downpipe/main_test.go, which is a good assertion of exactly this kind and was simply not in the
// sentence. That is the whole argument for this file: a number nothing re-derives is a number nobody
// can be told is wrong.
//
// WHY A SET AND NOT A NUMBER. The declaration is a table of sites, each carrying the reason it is
// allowed to compare a constant with a constant. A bare count says something moved; a set says WHICH
// thing moved and in which direction, and it fails just as loudly when a listed site DISAPPEARS as
// when a new one arrives. A disappearing site is the dangerous direction: an assertion that pinned a
// frozen wire string can be deleted and a count would only shrink.
//
// WHY THE DENOMINATOR IS NOT DECLARED. The published 2,598 is not reproduced here and this file does
// not pretend otherwise. Its definition of "assertion position" was not recorded with it, and four
// candidate definitions measured give 4,359 comparisons in all, 3,201 in an if
// condition, 2,947 inside _test.go and 3,029 in assertion position as defined below. None is 2,598, so
// rather than reverse-engineer a definition until a number matched, this file STATES its own
// definition and declares only what that definition settles. The denominator is still measured and
// still asserted, but as a floor rather than as an equality, because its job here is to prove the walk
// visited the corpus rather than to be a fact about it.
//
// WHY NOT A REGULAR-EXPRESSION SCANNER: one could list directories, read bytes and apply a
// pattern, but "both operands are constant" is not a regular expression's answer, it is the type
// checker's: `SourceKV != "kv"` is constant on both sides only because `SourceKV` is a declared
// constant, which is a fact about the package and not about the characters on the line. Declaring the
// number there would have re-derived a different quantity under the same label, which is a control that
// does not match the scheme it checks.
//
// WHAT "ASSERTION POSITION" MEANS HERE, stated because the last one was not: a comparison lying inside
// the condition of an `if` whose body calls a method whose name begins `Error` or `Fatal`, which is the
// Go table-test idiom for an assertion. `runtime.GOOS == "windows"` guarding a `t.Skip` is constant on
// both sides and is deliberately NOT in scope: it selects a build target rather than asserting
// anything, and a census that counted it would be reporting a different property from the one the
// original sentence was about.

// constAssertionSites is the declaration. Key is "<repo-relative file>\t<comparison as written>", so it
// survives the lines around it moving, which a file:line key does not.
var constAssertionSites = map[string]string{
	"cmd/downpipe/main_test.go\tformat.ExitUsage == format.ExitUnverified": "double entry on two exit codes that must stay distinct: a DR wrapper expanding an unset variable lands on the usage path, and if that code ever equalled the unverified code the caller could not tell a misuse from a failed verification. Not in commit 5698c6db's count of eleven.",

	"internal/spec/container_test.go\tContainerHeaderSize != 5":          "double entry on a frozen framing constant (SPEC.md 7.1): the required value is written here independently of the declaration, so an edit to either side is caught.",
	"internal/spec/container_test.go\tContainerVersion != 0x01":          "double entry on the frozen container version (SPEC.md 7.1). A change here is a new format version, not a passing test.",
	"internal/spec/sourcetype_test.go\tSourceKV != \"kv\"":               "double entry on a frozen wire string (SPEC.md 12.1): the literal is written out independently so a rename of the constant cannot silently change the format.",
	"internal/spec/sourcetype_test.go\tSourceR2 != \"r2\"":               "double entry on a frozen wire string (SPEC.md 12.1).",
	"internal/spec/sourcetype_test.go\tSourceSecrets != \"secrets\"":     "double entry on a frozen wire string (SPEC.md 12.1).",
	"internal/spec/sourcetype_test.go\tSourceD1 != \"d1\"":               "double entry on a frozen wire string (SPEC.md 12.1).",
	"internal/spec/sourcetype_test.go\tSourceWorkers != \"workers\"":     "double entry on a frozen wire string (SPEC.md 12.1).",
	"internal/spec/sourcetype_test.go\tSourceCFConfig != \"cf-config\"":  "double entry on a frozen wire string (SPEC.md 12.1).",
	"internal/spec/sourcetype_test.go\tSourceStream != \"stream\"":       "double entry on a frozen wire string (SPEC.md 12.1).",
	"internal/spec/sourcetype_test.go\tSourceImages != \"images\"":       "double entry on a frozen wire string (SPEC.md 12.1).",
	"internal/spec/sourcetype_test.go\tSourceArtifacts != \"artifacts\"": "double entry on a frozen wire string (SPEC.md 12.1).",
}

// comparisonFloor is the walk-visited control rather than a claim about the corpus. A census whose
// walk never arrives files nothing, finds nothing and passes, which is indistinguishable from a clean
// result. The measured figure is 3,029 comparisons in assertion position, so a run
// finding fewer than a third of that has not visited this repository and says so instead of passing.
const comparisonFloor = 1000

func isComparison(op token.Token) bool {
	switch op {
	case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
		return true
	}
	return false
}

type censusResult struct {
	files        int
	packages     int
	comparisons  int
	bothConstant map[string]int
	oneConstant  int
	importErrors int
}

// runConstAssertionCensus type-checks every package in the module and answers, for every comparison in
// assertion position, whether the compiler holds BOTH operands to be constant.
func runConstAssertionCensus(t *testing.T, root string) censusResult {
	t.Helper()

	fset := token.NewFileSet()
	byDir := map[string][]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".worktrees", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".go") {
			byDir[filepath.Dir(p)] = append(byDir[filepath.Dir(p)], p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}

	res := censusResult{bothConstant: map[string]int{}}
	imp := importer.ForCompiler(fset, "source", nil)

	dirs := make([]string, 0, len(byDir))
	for d := range byDir {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)

	for _, dir := range dirs {
		byPkg := map[string][]*ast.File{}
		for _, f := range byDir[dir] {
			af, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parsing %s: %v", f, err)
			}
			byPkg[af.Name.Name] = append(byPkg[af.Name.Name], af)
		}
		names := make([]string, 0, len(byPkg))
		for n := range byPkg {
			names = append(names, n)
		}
		sort.Strings(names)

		for _, name := range names {
			files := byPkg[name]
			res.packages++
			res.files += len(files)

			info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}}
			conf := types.Config{
				Importer:    imp,
				FakeImportC: true,
				// Type errors are collected rather than fatal. A package can fail to check for reasons
				// that have nothing to do with this census, and refusing to report anything because one
				// package did not resolve would be worse than reporting what did. Import failures ARE
				// counted, because they are the one class that silently removes cross-package constants
				// from the answer, and the control below reads that count.
				Error: func(e error) {
					if strings.Contains(e.Error(), "could not import") {
						res.importErrors++
					}
				},
			}
			// The error is deliberately not fatal here; see Error above.
			_, _ = conf.Check(dir, fset, files, info)

			for _, af := range files {
				inAssertion := map[ast.Expr]bool{}
				ast.Inspect(af, func(n ast.Node) bool {
					ifs, ok := n.(*ast.IfStmt)
					if !ok || ifs.Cond == nil {
						return true
					}
					fails := false
					ast.Inspect(ifs.Body, func(m ast.Node) bool {
						call, ok := m.(*ast.CallExpr)
						if !ok {
							return true
						}
						sel, ok := call.Fun.(*ast.SelectorExpr)
						if !ok {
							return true
						}
						if strings.HasPrefix(sel.Sel.Name, "Error") || strings.HasPrefix(sel.Sel.Name, "Fatal") {
							fails = true
						}
						return true
					})
					if fails {
						ast.Inspect(ifs.Cond, func(m ast.Node) bool {
							if e, ok := m.(ast.Expr); ok {
								inAssertion[e] = true
							}
							return true
						})
					}
					return true
				})

				src, err := os.ReadFile(fset.Position(af.Pos()).Filename)
				if err != nil {
					t.Fatalf("reading %s: %v", fset.Position(af.Pos()).Filename, err)
				}
				rel, err := filepath.Rel(root, fset.Position(af.Pos()).Filename)
				if err != nil {
					t.Fatalf("relativising %s: %v", fset.Position(af.Pos()).Filename, err)
				}
				rel = filepath.ToSlash(rel)

				ast.Inspect(af, func(n ast.Node) bool {
					be, ok := n.(*ast.BinaryExpr)
					if !ok || !isComparison(be.Op) || !inAssertion[be] {
						return true
					}
					res.comparisons++
					lhs := info.Types[be.X].Value != nil
					rhs := info.Types[be.Y].Value != nil
					switch {
					case lhs && rhs:
						text := string(src[fset.Position(be.Pos()).Offset:fset.Position(be.End()).Offset])
						res.bothConstant[rel+"\t"+text]++
					case lhs || rhs:
						res.oneConstant++
					}
					return true
				})
			}
		}
	}
	return res
}

// TestConstantAgainstConstantAssertionCensus re-derives the census commit 5698c6db recorded in prose
// and holds it to the declared set above.
func TestConstantAgainstConstantAssertionCensus(t *testing.T) {
	root := repoRoot(t)
	res := runConstAssertionCensus(t, root)

	t.Logf("census: %d file(s) in %d package group(s), %d comparison(s) in assertion position, %d with both operands constant, %d with exactly one",
		res.files, res.packages, res.comparisons, len(res.bothConstant), res.oneConstant)

	// THE WALK-VISITED CONTROL. A census that arrives nowhere reports a clean corpus.
	if res.comparisons < comparisonFloor {
		t.Fatalf("the census found only %d comparison(s) in assertion position, below the floor of %d. It has not visited this repository, so its silence about constant comparisons means nothing. Root walked: %s",
			res.comparisons, comparisonFloor, root)
	}

	// THE TYPE-CHECKER-RAN CONTROL, and it is a different question from the one above. The walk can
	// visit every file and still answer "no constants anywhere" if `info.Types` came back empty,
	// because `Value != nil` is false for an expression the checker never typed. A corpus with
	// constants on one side of a comparison and not the other is what a working checker produces, so a
	// zero here means the instrument, not the code.
	if res.oneConstant == 0 {
		t.Fatal("the census found no comparison with exactly one constant operand, which no real Go corpus produces. The type checker did not resolve constant values, so every 'both operands constant' answer below is an artefact of the instrument rather than a reading of the code")
	}

	// THE IMPORTER-RAN CONTROL, which is the one that decides whether cross-package constants are
	// visible at all. Without it, `format.ExitUsage == format.ExitUnverified` silently drops out of the
	// answer and the census reports eleven sites with no sign that anything went wrong: exactly the
	// number the unrunnable sentence carried, arrived at for the wrong reason.
	if res.importErrors > 0 {
		t.Fatalf("the type checker failed to import %d package reference(s), so constants declared in another package were not resolved and this census cannot see comparisons between them", res.importErrors)
	}

	found := make([]string, 0, len(res.bothConstant))
	for k := range res.bothConstant {
		found = append(found, k)
	}
	sort.Strings(found)

	var undeclared, missing []string
	for _, k := range found {
		if _, ok := constAssertionSites[k]; !ok {
			undeclared = append(undeclared, k)
		}
	}
	for k := range constAssertionSites {
		if _, ok := res.bothConstant[k]; !ok {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)

	show := func(keys []string) string {
		var b strings.Builder
		for _, k := range keys {
			parts := strings.SplitN(k, "\t", 2)
			fmt.Fprintf(&b, "\n    %s: %s", parts[0], parts[1])
		}
		return b.String()
	}

	if len(undeclared) > 0 {
		t.Errorf("%d comparison(s) in assertion position have both operands constant and are not in constAssertionSites.%s\n  Each one is either double entry on a frozen value, which is legitimate and belongs in the table with its reason, or a comparison that cannot fail, which is a control that only looks checked. Read it and then declare or delete it.",
			len(undeclared), show(undeclared))
	}
	if len(missing) > 0 {
		t.Errorf("%d declared site(s) were not found by the census.%s\n  A declared site disappears when the assertion is deleted or rewritten, which is the direction a bare count cannot report: the number simply gets smaller. If the assertion was deliberately removed, remove its row here in the same commit.",
			len(missing), show(missing))
	}
}
