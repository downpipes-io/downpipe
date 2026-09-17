package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
)

// The commands the SIGNED, IN-ARCHIVE RECOVER.md prints are driven here.
//
// This is the highest-stakes place in the product where a command line is published. It travels
// inside the archive, it is covered by the signed SHA384SUMS, and it is what an operator reads at
// the moment they have nothing else: no console, no vendor, and possibly no other documentation.
//
// WHAT WENT WRONG WITHOUT IT. The custody example printed two --share files:
//
//	downpipe restore --archive <dir> --run <runId> --signer signer.pub --out <dir> \
//	  --share share-1.txt --share share-3.txt --envelope wrapped-identity.txt
//
// The reader requires one share per custodian in the quorum, read from the labelled shares
// themselves. Driven against this repository's own 3-of-N custody fixture, that line exits
// ExitUsage with "need 3 distinct shares to recombine, got 2". README.md prints the same command
// with three shares and is right; the copy that ships inside the archive was not, and nothing
// compared them. The line also never said the count has to equal the quorum, which is the one fact
// an operator holding a 3-of-5 split needs before they can follow it at all.
//
// The bytes come from a real archive rather than from the string literal, so what is driven is
// what an archive actually carries.

// recoverMdCommands pulls each indented `downpipe ...` command out of the bundled RECOVER.md,
// rejoining backslash continuations.
//
// A leading shell prompt is stripped before the match. It was not, and that was a hole: a line
// written as `$ downpipe verify --archive <dir> --run <runId> --identity identity.key` (missing
// --signer, so a real exit 6) sat in the bundled document and this gate stayed green, because the
// trimmed line did not begin with the word downpipe. A prompt prefix is the most ordinary way
// anyone writes a command into a document, so the shape had to be matched rather than assumed away.
func recoverMdCommands(t *testing.T, text string) []string {
	t.Helper()
	var out []string
	var cur string
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		trimmed = strings.TrimPrefix(trimmed, "$ ")
		switch {
		case cur != "":
			cur += " " + strings.TrimSuffix(trimmed, "\\")
			if !strings.HasSuffix(trimmed, "\\") {
				out = append(out, strings.Join(strings.Fields(cur), " "))
				cur = ""
			}
		case strings.HasPrefix(trimmed, "downpipe "):
			if strings.HasSuffix(trimmed, "\\") {
				cur = strings.TrimSuffix(trimmed, "\\")
				continue
			}
			out = append(out, strings.Join(strings.Fields(trimmed), " "))
		}
	}
	if cur != "" {
		t.Errorf("a command in the bundled RECOVER.md ends on a backslash continuation with no following line: %q", cur)
	}
	return out
}

// nonEmptyDir reports whether anything at all was written under dir. It is how a restore line is
// held to the thing it promises, rather than to its exit code.
func nonEmptyDir(dir string) bool {
	wrote := false
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // an absent output directory is the finding, not an error
		}
		wrote = true
		return filepath.SkipAll
	})
	return wrote
}

func TestBundledRecoverMdCommandsCanBeRun(t *testing.T) {
	silenceOutput(t)
	custody, err := filepath.Abs(filepath.Join("testdata", "custody"))
	if err != nil {
		t.Fatalf("resolving the custody fixture: %v", err)
	}

	dir := t.TempDir()
	archive := filepath.Join(dir, "arc")
	identity, verifier, runID, err := buildSelftestArchive(archive, []byte("bundled recover commands"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, archive, identity, verifier)

	raw, err := os.ReadFile(filepath.Join(archive, filepath.FromSlash(format.BundlePrefix+"RECOVER.md")))
	if err != nil {
		t.Fatalf("the archive carries no bundled RECOVER.md, which is the file this test exists to drive: %v", err)
	}
	cmds := recoverMdCommands(t, string(raw))
	if len(cmds) == 0 {
		t.Fatal("no command was found in the bundled RECOVER.md, so this test proved nothing")
	}

	// Substitutions by the flag each placeholder follows, plus the literal file names the
	// document uses for the recovery-kit and custody artefacts.
	subs := map[string]string{
		"<dir>":                archive, // corrected per flag below
		"<runId>":              runID,
		"identity.key":         idPath,
		"signer.pub":           signerPath,
		"share-1.txt":          filepath.Join(custody, "share-1.txt"),
		"share-2.txt":          filepath.Join(custody, "share-2.txt"),
		"share-3.txt":          filepath.Join(custody, "share-3.txt"),
		"wrapped-identity.txt": filepath.Join(custody, "wrapped-identity.txt"),
	}

	for _, c := range cmds {
		fields := strings.Fields(c)
		args := make([]string, 0, len(fields)-1)
		outDir := ""
		for i := 1; i < len(fields); i++ {
			tok := fields[i]
			switch {
			case tok == "<dir>" && i > 0 && fields[i-1] == "--out":
				outDir = filepath.Join(t.TempDir(), "out")
				args = append(args, outDir)
			case tok == "<dir>" && i > 0 && fields[i-1] == "--archive":
				args = append(args, archive)
			default:
				if v, ok := subs[tok]; ok {
					args = append(args, v)
					continue
				}
				if strings.HasPrefix(tok, "<") {
					t.Errorf("the bundled RECOVER.md prints a placeholder %q this test has no value for, in %q. Add one; an undrivable line inside a signed archive is the worst place in the product to leave a command nobody has run", tok, c)
					args = nil
				}
				if args == nil {
					break
				}
				args = append(args, tok)
			}
		}
		if args == nil {
			continue
		}
		code := run(args)
		// The custody line recombines a DIFFERENT identity from the one this archive is sealed
		// to, so it cannot exit 0 here. What is asserted for every line is that the command line
		// itself is accepted: ExitUsage means the operator is told to fix a command they copied
		// out of their own archive, and there is nothing for them to fix.
		if code == format.ExitUsage {
			t.Errorf("the bundled RECOVER.md prints %q, which exits %d (ExitUsage). An operator reading it mid-recovery is told their command line is wrong, and it is the line their own archive gave them.\nmaterialised as: %v", c, code, args)
		}
		// The identity line names no custody artefact and must work outright.
		if !strings.Contains(c, "--share") && code != 0 {
			t.Errorf("the bundled RECOVER.md prints %q, which exits %d, want 0.\nmaterialised as: %v", c, code, args)
		}
		// AND IT HAS TO HAVE RESTORED SOMETHING. Exit 0 is not the promise a restore line makes.
		//
		// WHAT WENT WRONG WITHOUT THIS. restore is a dry run unless --apply is given, and the
		// bundled document never mentioned --apply anywhere. The line an operator reads at the
		// moment they have nothing else planned the writes, printed "dry run: nothing was written",
		// exited 0 and did not create the --out directory at all. The assertion above was satisfied
		// by exactly that, so the gate built to drive this document stood over a line that returns
		// no data. A restore that writes nowhere is the failure mode this whole document exists to
		// prevent, so the output is looked at rather than the status.
		if strings.HasPrefix(c, "downpipe restore ") && !strings.Contains(c, "--share") && outDir != "" && !nonEmptyDir(outDir) {
			t.Errorf("the bundled RECOVER.md prints %q, which exited %d and wrote NOTHING to --out. An operator following the only instruction they have gets a clean exit and no data; restore plans unless --apply is given.\nmaterialised as: %v", c, code, args)
		}
	}
}
