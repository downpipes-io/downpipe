package format

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// THE MAPPING THREE MESSAGES POINT AT, AND NOTHING CHECKED IT WAS THERE.
//
// checkFormatVersion's unimplemented-version refusal, inspect's format line and
// keys --which's unreadable-run summary all close by telling the holder of an archive this
// reader cannot open to look up which release reads it, using the "Reads format versions:"
// line in each release's CHANGELOG.md entry. That line was added to every entry by hand.
// Nothing asserted it, so a future release cut without it would leave three messages
// pointing at a mapping that is not there, and the reader would go on printing a remedy
// nobody can act on with every gate green.
//
// The rule is worth having on all three counts:
//
//   - It would have caught the defect that prompted it. Before the line existed the
//     refusal said "install a downpipe release built for 9.0" and named no location at
//     all; this gate is red over every release entry in that state.
//   - A red branch has existed, and can be produced now: deleting the line from any one
//     entry fails this test.
//   - It is expressible without guessing: a release heading with no such line before the
//     next heading.
//
// It is deliberately NOT a check that the version named is correct. Only the release's own
// reader source can say that, and asserting a value here would be asserting a copy against
// a copy.

// changelogReleaseHeading matches a Keep a Changelog release heading, including
// "## [Unreleased]". Unreleased is included on purpose: it is what a maintainer edits, so
// it is where the line is most likely to be forgotten, and it is what the next release
// heading is renamed from.
var changelogReleaseHeading = regexp.MustCompile(`(?m)^## \[[^\]]+\]`)

// TestEveryChangelogReleaseNamesTheFormatVersionsItReads asserts each release entry in
// CHANGELOG.md carries a "Reads format versions:" line before the next entry begins.
func TestEveryChangelogReleaseNamesTheFormatVersionsItReads(t *testing.T) {
	path := filepath.Join("..", "..", "CHANGELOG.md")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	text := string(b)

	headings := changelogReleaseHeading.FindAllStringIndex(text, -1)
	if len(headings) < 2 {
		t.Fatalf("found %d release heading(s) in CHANGELOG.md; the file is meant to hold Unreleased plus every cut release, so a count this low means the heading pattern no longer matches and this gate is asserting nothing", len(headings))
	}

	for i, h := range headings {
		start := h[0]
		end := len(text)
		if i+1 < len(headings) {
			end = headings[i+1][0]
		}
		body := text[start:end]
		title := strings.TrimSpace(text[h[0]:h[1]])
		if !strings.Contains(body, "Reads format versions:") {
			t.Errorf("CHANGELOG.md %s carries no \"Reads format versions:\" line. "+
				"Three of this reader's messages send whoever holds a refused archive to that line to find out which "+
				"release reads their format version (checkFormatVersion's refusal, inspect's format line and "+
				"keys --which's unreadable-run summary). Without it on every entry those messages name a lookup that "+
				"does not exist, which is a remedy nobody can act on.", title)
		}
	}
}

// TestChangelogNamesThisReadersOwnFormatSupport ties the document to the code rather than
// to a literal. The Unreleased entry describes the reader in this tree, so the support
// summary the reader itself builds from ImplementedFormatVersions has to appear in it.
// Widening or narrowing the set without touching the changelog fails here.
func TestChangelogNamesThisReadersOwnFormatSupport(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "CHANGELOG.md"))
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	headings := changelogReleaseHeading.FindAllStringIndex(string(b), -1)
	if len(headings) == 0 {
		t.Fatal("no release headings found in CHANGELOG.md")
	}
	end := len(b)
	if len(headings) > 1 {
		end = headings[1][0]
	}
	unreleased := string(b)[headings[0][0]:end]
	want := ReaderFormatSupport()
	if !strings.Contains(unreleased, "`"+want+"`") {
		t.Errorf("the Unreleased entry must name %q, the support summary this reader builds from ImplementedFormatVersions. "+
			"It describes the reader in this tree, so a set changed without the entry changing leaves the published "+
			"mapping wrong for the release cut from it.", want)
	}
}

// TestChangelogStatesTheObtainabilityDutyOnReleases pins the second half of the mapping.
//
// Naming which release reads a format version is useless if that release cannot be got,
// and measured no released reader could be: the v0.2.0 GitHub Release is a
// draft with no binary, and `go install` at that tag fails 404 at sum.golang.org because
// the repository is private.
//
// The duty is now about ONE format line. The 1.x lineage was retired rather
// than carried, so nothing is owed for it: it was never published and no reader for it is
// obtainable. What is still owed, and still undischarged, is a reader for downpipe/0.1.x
// that somebody outside this organisation can actually obtain, from the first publication
// onwards.
//
// This asserts the duty is STATED, not that it is discharged. Discharging it is an
// owner-level decision about publishing and releases, and a test cannot make it.
func TestChangelogStatesTheObtainabilityDutyOnReleases(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "CHANGELOG.md"))
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	text := string(b)
	for _, want := range []string{
		"RETENTION DUTY",
		"also has to be obtainable",
		"stays obtainable",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("CHANGELOG.md no longer states the retention duty on releases (missing %q). "+
				"The `Reads format versions:` line names which release reads an archive; it does not make that "+
				"release obtainable, and a mapping to a reader nobody can get is a remedy nobody can act on.", want)
		}
	}
}
