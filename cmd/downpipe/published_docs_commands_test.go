package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
)

// Every downpipe command README.md and docs/RECOVER.md print is DRIVEN here.
//
// WHAT WENT WRONG WITHOUT THIS. Two gates already drive published command lines: one for llms.txt
// and one for the RECOVER.md that ships inside the archive. Neither covers these two files, and
// nothing else does either: internal/spec/docs_claims_test.go reads the same Markdown but checks
// CLAIMS in prose and never runs a command. So the two largest published command surfaces on the
// recovery path, the file a first-time recoverer reads and the step-by-step guide it points at,
// had every synopsis unexecuted.
//
// It found the defect the llms.txt gate had already found once in a different file. restore plans
// and writes nothing unless --apply is given. README.md's "A real recovery uses your own keys and
// your own bucket" block and docs/RECOVER.md's "Recover end to end" block both printed restore
// without it, so the whole walkthrough a customer follows ended in a clean exit 0 and an --out
// directory that was never created. README.md did not contain the string --apply at all.
//
// So the assertion for a restore line is not its exit code. It is that the output directory has
// something in it afterwards.

// publishedCommandDocs are the files this drives. Named rather than discovered: a file that
// disappears has to fail loudly instead of quietly reducing what is checked.
var publishedCommandDocs = []string{
	filepath.Join("..", "..", "README.md"),
	filepath.Join("..", "..", "docs", "RECOVER.md"),
}

// refusedEndpoint stands in for the `https://<account>.r2.cloudflarestorage.com` placeholder. It
// is a port nothing listens on, so the S3 synopsis is driven through the real destination code
// path with no network call, and the promise it has to keep is the one it can keep offline: that
// it reaches the destination and fails on reachability (exit 11), not on a flag the printed line
// omitted.
const refusedEndpoint = "http://127.0.0.1:1"

type publishedDocsFixture struct {
	archive, runID, identity, signer, custody string
}

// substitute turns one printed command line into a real argv, or says why it cannot. Every token
// that is a placeholder or a relative path has to be accounted for; an unknown one fails rather
// than being passed through, because a line that cannot be materialised is a line nobody drives.
func (f publishedDocsFixture) substitute(t *testing.T, doc, cmd string) (args []string, outDir string, ok bool) {
	t.Helper()
	byToken := map[string]string{
		"./bucket":               f.archive,
		"./keys/identity.key":    f.identity,
		"identity.key":           f.identity,
		"./keys/signer.pub":      f.signer,
		"signer.pub":             f.signer,
		"./share-1.txt":          filepath.Join(f.custody, "share-1.txt"),
		"./share-2.txt":          filepath.Join(f.custody, "share-2.txt"),
		"./share-3.txt":          filepath.Join(f.custody, "share-3.txt"),
		"./wrapped-identity.txt": filepath.Join(f.custody, "wrapped-identity.txt"),
		"<runId>":                f.runID,
		"<run-id>":               f.runID,
		"<n>":                    "1",
		"<bucket>":               "testbucket",
		"<container>":            "testcontainer",
	}
	fields := strings.Fields(cmd)
	args = []string{fields[1]}
	for i := 2; i < len(fields); i++ {
		tok, prev := fields[i], fields[i-1]
		switch prev {
		case "--out":
			// Whatever the document names, the write goes somewhere disposable. The base name is
			// kept so a document that writes a FILE (recombine --out ./identity.key) and one that
			// writes a DIRECTORY (--out ./restored) are both driven as printed.
			outDir = filepath.Join(t.TempDir(), filepath.Base(tok))
			args = append(args, outDir)
		case "--s3-endpoint", "--azure-endpoint":
			args = append(args, refusedEndpoint)
		default:
			v, known := byToken[tok]
			if known {
				args = append(args, v)
				continue
			}
			if strings.HasPrefix(tok, "<") || strings.HasPrefix(tok, "./") {
				t.Errorf("%s prints %q, which names %q, and this test has no value for it. Add one; a published command nobody can materialise is a published command nobody drives", doc, cmd, tok)
				return nil, "", false
			}
			args = append(args, tok)
		}
	}
	return args, outDir, true
}

func TestEveryCommandTheDocsPrintCanBeRun(t *testing.T) {
	silenceOutput(t)
	custody, err := filepath.Abs(filepath.Join("testdata", "custody"))
	if err != nil {
		t.Fatalf("resolving the custody fixture: %v", err)
	}
	// Read every document BEFORE the first t.Chdir below. t.Chdir restores at the end of the test
	// and not at the end of an iteration, so a relative read after it resolved against a scratch
	// directory and the second document was reported missing.
	perDoc := map[string][]string{}
	for _, doc := range publishedCommandDocs {
		raw, rerr := os.ReadFile(doc)
		if rerr != nil {
			t.Fatalf("cannot read %s, which is one of the files this test exists to drive: %v", doc, rerr)
		}
		perDoc[doc] = recoverMdCommands(t, string(raw))
	}

	driven := 0
	for _, doc := range publishedCommandDocs {
		cmds := perDoc[doc]
		if len(cmds) == 0 {
			t.Errorf("no downpipe command line was found in %s, so nothing about it was proved; has its layout changed?", doc)
			continue
		}
		for _, c := range cmds {
			// A scratch working directory per line, because several of these write into it.
			t.Chdir(t.TempDir())
			dir := t.TempDir()
			archive := filepath.Join(dir, "arc")
			identity, verifier, runID, berr := buildSelftestArchive(archive, []byte("published docs commands"))
			if berr != nil {
				t.Fatalf("buildSelftestArchive: %v", berr)
			}
			idPath, signerPath := writeArchiveKeys(t, archive, identity, verifier)
			f := publishedDocsFixture{archive: archive, runID: runID, identity: idPath, signer: signerPath, custody: custody}
			args, outDir, ok := f.substitute(t, doc, c)
			if !ok {
				continue
			}
			driven++

			// A destination line's promise is the one it can keep offline: that it reaches the
			// destination and fails on REACHABILITY, not on a flag the printed line omitted. Both
			// destination protocols are held to it, and the credentials are supplied here because a
			// published command line must never print one.
			if strings.Contains(c, "--s3-endpoint") || strings.Contains(c, "--azure-endpoint") {
				t.Setenv("AWS_ACCESS_KEY_ID", "published-docs-gate")
				t.Setenv("AWS_SECRET_ACCESS_KEY", "published-docs-gate")
				t.Setenv("AZURE_STORAGE_KEY", "cHVibGlzaGVkLWRvY3MtZ2F0ZS1rZXktdmFsdWU=")
				t.Setenv("AZURE_STORAGE_ACCOUNT", "publisheddocsgate")
				if code := run(args); code != format.ExitUnreachable {
					t.Errorf("%s prints %q, which exits %d against an endpoint that refuses the connection, want %d (destination unreachable). Anything else means the line is stopped by something it could have supplied itself.\nmaterialised as: %v", doc, c, code, format.ExitUnreachable, args)
				}
				continue
			}

			code := run(args)
			if code != 0 {
				t.Errorf("%s prints %q, which exits %d, want 0. A published command line is a promise that it works as printed.\nmaterialised as: %v", doc, c, code, args)
				continue
			}
			// A restore line's promise is the data, not the status. Without --apply restore plans,
			// reports, exits 0 and writes nothing, which is how both of these documents came to
			// walk a customer through a recovery that returns no data.
			if strings.HasPrefix(c, "downpipe restore ") && outDir != "" && !nonEmptyDir(outDir) {
				t.Errorf("%s prints %q, which exited 0 and wrote NOTHING to --out. Following it returns no data; restore plans unless --apply is given.\nmaterialised as: %v", doc, c, args)
			}
		}
	}
	if driven == 0 {
		t.Fatal("no published command was driven, so this test proved nothing")
	}
}
