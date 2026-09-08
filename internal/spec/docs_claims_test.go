package spec

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// This test guards against a specific false claim reappearing anywhere this repository publishes
// prose: that recovery is "offline-only". It is not. Verify-at-seal and the hourly canary reach the
// keyed tier from the run's OWN per-run key, so a break-glass-only estate still verifies in-account;
// what an operational key buys is the unattended work (scheduled restore tests, the automated drill,
// in-account retention pruning), not in-account verification itself.
//
// The check runs against this repository's own published prose, so it is gated by this repository's
// own test run rather than depending on another repository's copy.
//
// The rule matches the SHAPE of the claim rather than the token "offline-only", because that token
// is legitimately true of things this repository describes constantly: the reader is offline-only by
// construction and makes no network call. Only the assertion ABOUT RECOVERY is wrong, and the honest
// negated form has to stay clean or the gate would ban the correction it exists to produce.

var recoveryOfflineOnly = regexp.MustCompile(
	`(?i)\b(recovery|restores?|restoring|restore proof)\b(?:\s+\w+){0,3}?\s+(?:is|are|was|were|becomes?|remains?|stays?|happens?)\s+(?:then\s+|therefore\s+|effectively\s+)?(?:not\s+|never\s+)?offline[-\s]?only\b`,
)

var negatedForm = regexp.MustCompile(`(?i)\b(?:not|never)\s+offline[-\s]?only\b`)

// repoRoot walks up from this package to the directory holding go.mod, so the test does not depend on
// where it is invoked from.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the repository root (no go.mod within six levels)")
	return ""
}

// anchorProse is the prose this repository publishes that MUST exist. It is no longer the whole scope
// of the gate, only the set whose disappearance is itself a failure: a renamed or deleted SPEC.md has
// to fail loudly rather than reduce what gets checked. CHANGELOG.md is deliberately here: it is read
// by people deciding whether to upgrade, and a false capability claim there is as costly as one in the
// spec.
var anchorProse = []string{
	"docs/format/SPEC.md",
	"docs/format/CONFORMANCE.md",
	"docs/RECOVER.md",
	"README.md",
	"SECURITY.md",
	"CHANGELOG.md",
	"CONTRIBUTING.md",
}

// skippedDirs are the trees that hold prose this repository did not write.
var skippedDirs = map[string]bool{".git": true, "vendor": true, "node_modules": true}

// publishedProse finds every Markdown file this repository ships, rather than trusting a list.
//
// THE SCOPE IS DISCOVERED, NOT ENUMERATED: a named-path list grows a hole every time the repository
// grows a file, so this walks the whole tree instead.
//
// The archive-embedded RECOVER.md under internal/format/testdata is INCLUDED on purpose. That prose is
// what an operator reads mid-disaster, it is covered by the signed SHA384SUMS, and a false claim there
// is the most expensive place to put one.
func publishedProse(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".md") {
			rel, rerr := filepath.Rel(root, p)
			if rerr != nil {
				return rerr
			}
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		// A walk that stopped early has not checked what it did not reach.
		t.Fatalf("walk the repository for published prose: %v", err)
	}
	sort.Strings(out)
	return out
}

// publishedLiterals returns every string literal in every non-test Go file of this repository, with the
// position it sits at.
//
// PROSE SHIPS IN THE BINARY TOO: cmd/downpipe/selftest.go carries the whole text of the in-bucket
// RECOVER.md as a string literal, so the sentence an operator reads out of a real archive would never
// be caught by a gate that reads only .md files.
//
// It reads the PARSED source and only the literals. Scanning the .go text would fire on this very
// file, which quotes the false sentence in order to explain it, and a gate that cannot tell a quotation
// from a claim is a gate that gets switched off.
func publishedLiterals(t *testing.T, root string) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		src, serr := os.ReadFile(p)
		if serr != nil {
			return serr
		}
		f, perr := parser.ParseFile(fset, filepath.ToSlash(rel), src, parser.SkipObjectResolution)
		if perr != nil {
			// A file this gate cannot parse is a file whose published strings it cannot account for.
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			text, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				// Refuse rather than skip: an unreadable literal is not an absent one.
				t.Fatalf("%s: cannot read a string literal: %v", fset.Position(lit.Pos()), uerr)
			}
			out[fset.Position(lit.Pos()).String()] = text
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk the repository for published strings: %v", err)
	}
	if len(out) < 100 {
		// A gate that scans nothing reads exactly like a passing gate.
		t.Fatalf("found only %d string literals in the repository; the scan has probably stopped seeing them", len(out))
	}
	return out
}

// offlineOnlyClaims reports each banned claim in body, as "line: span".
func offlineOnlyClaims(body []byte) []string {
	var found []string
	for _, m := range recoveryOfflineOnly.FindAllIndex(body, -1) {
		span := string(body[m[0]:m[1]])
		if negatedForm.MatchString(span) {
			continue // "recovery is NOT offline-only" is the corrected form
		}
		found = append(found, strconv.Itoa(1+strings.Count(string(body[:m[0]]), "\n"))+": "+strconv.Quote(span))
	}
	return found
}

const whyItIsFalse = "\n" +
	"  It is not. Verify-at-seal and the hourly canary reach the keyed tier from the run's OWN\n" +
	"  per-run key, so a break-glass-only estate still verifies in-account. What the operational\n" +
	"  key buys is the UNATTENDED work: scheduled restore tests, the automated drill, and\n" +
	"  in-account retention pruning."

func TestPublishedProseDoesNotClaimRecoveryIsOfflineOnly(t *testing.T) {
	root := repoRoot(t)

	prose := publishedProse(t, root)
	have := map[string]bool{}
	for _, rel := range prose {
		have[rel] = true
	}
	// An anchor that has been renamed or removed must FAIL, not quietly shrink the scope. A gate that
	// stops checking when its input moves reads exactly like a passing gate.
	for _, rel := range anchorProse {
		if !have[rel] {
			t.Errorf("%s: the prose this gate exists to check is no longer there; was it renamed or removed?", rel)
		}
	}

	checked := 0
	for _, rel := range prose {
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Errorf("%s: cannot read published prose: %v", rel, err)
			continue
		}
		checked++
		for _, c := range offlineOnlyClaims(body) {
			t.Errorf("%s:%s claims recovery is offline-only%s", rel, c, whyItIsFalse)
		}
	}
	if checked == 0 {
		t.Fatal("no prose files were checked, so this gate proved nothing")
	}

	for pos, text := range publishedLiterals(t, root) {
		if len(offlineOnlyClaims([]byte(text))) > 0 {
			t.Errorf("the string literal at %s claims recovery is offline-only, and string literals in this repository are shipped to operators%s", pos, whyItIsFalse)
		}
	}
}
