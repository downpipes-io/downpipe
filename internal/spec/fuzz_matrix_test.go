package spec

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The fuzz matrices are hand-maintained lists, in two workflow files, of which package
// runs which Fuzz function. A target that is not listed never runs under -fuzz, and
// nothing said so: CONTRIBUTING once required fuzz targets in internal/crypto that did
// not exist, and the matrices could not show the gap because they list only what
// exists. This test reads the Fuzz functions from the Go source and the matrices from
// the workflows, and requires the two to agree in both directions. It also requires a
// target in each package that reads or seals untrusted bytes, so a package cannot drop
// out of fuzzing by losing its last target.

// fuzzedPackages are the packages that must carry at least one fuzz target: the reader's
// parse and verify paths, the restore transcoders, and the STREAM envelope.
var fuzzedPackages = []string{"./internal/crypto", "./internal/format", "./internal/restore"}

// fuzzWorkflows are the workflows whose matrices must list every target.
var fuzzWorkflows = []string{".github/workflows/ci.yml", ".github/workflows/fuzz-extended.yml"}

var (
	matrixPkg     = regexp.MustCompile(`^\s*-\s*pkg:\s*(\S+)\s*$`)
	matrixTargets = regexp.MustCompile(`^\s*targets:\s*(.+?)\s*$`)
)

func TestFuzzMatricesRunEveryTarget(t *testing.T) {
	root := repoRoot(t)
	inSource := fuzzTargetsInSource(t, root)
	for _, pkg := range fuzzedPackages {
		if len(inSource[pkg]) == 0 {
			t.Errorf("%s has no Fuzz function; it reads or seals untrusted bytes and must carry a fuzz target", pkg)
		}
	}
	for _, wf := range fuzzWorkflows {
		listed := fuzzTargetsInMatrix(t, filepath.Join(root, wf))
		for pkg, targets := range inSource {
			for _, target := range targets {
				if !contains(listed[pkg], target) {
					t.Errorf("%s: %s %s is not in the fuzz matrix, so it never runs under -fuzz", wf, pkg, target)
				}
			}
		}
		for pkg, targets := range listed {
			for _, target := range targets {
				if !contains(inSource[pkg], target) {
					t.Errorf("%s: the fuzz matrix lists %s %s, which is not a Fuzz function in that package", wf, pkg, target)
				}
			}
		}
	}
}

// fuzzTargetsInSource maps each package ("./internal/crypto") to its top-level
// Fuzz functions that take a *testing.F, read from the _test.go files under internal
// and cmd.
func fuzzTargetsInSource(t *testing.T, root string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	fset := token.NewFileSet()
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && d.Name() == "testdata" {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, filepath.Dir(path))
			if err != nil {
				return err
			}
			pkg := "./" + filepath.ToSlash(rel)
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Fuzz") || !takesTestingF(fn) {
					continue
				}
				out[pkg] = append(out[pkg], fn.Name.Name)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", top, err)
		}
	}
	for pkg := range out {
		sort.Strings(out[pkg])
	}
	return out
}

// takesTestingF reports whether fn has the one *testing.F parameter a fuzz target has.
func takesTestingF(fn *ast.FuncDecl) bool {
	params := fn.Type.Params.List
	if len(params) != 1 {
		return false
	}
	star, ok := params[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "F"
}

// fuzzTargetsInMatrix reads the "- pkg:" and "targets:" pairs of a workflow's matrix.
// A pkg line with no targets line after it fails the test, so a malformed matrix cannot
// read as an empty one.
func fuzzTargetsInMatrix(t *testing.T, path string) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out := map[string][]string{}
	pkg := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if m := matrixPkg.FindStringSubmatch(line); m != nil {
			if pkg != "" {
				t.Fatalf("%s: matrix row %s has no targets line", path, pkg)
			}
			pkg = m[1]
			continue
		}
		if m := matrixTargets.FindStringSubmatch(line); m != nil && pkg != "" {
			out[pkg] = append(out[pkg], strings.Fields(m[1])...)
			pkg = ""
		}
	}
	if pkg != "" {
		t.Fatalf("%s: matrix row %s has no targets line", path, pkg)
	}
	if len(out) == 0 {
		t.Fatalf("%s: no fuzz matrix rows found, so nothing was compared", path)
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
