package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every command llms.txt prints is DRIVEN here.
//
// WHAT WENT WRONG WITHOUT THIS. Nothing in the repository referenced llms.txt. The prose gate in
// internal/spec discovers the Markdown this repository ships and llms.txt is not Markdown, so it
// sat outside every check the repository has, and its synopses rotted where nobody was looking.
// Two of them had already been found by hand and corrected, and the correction itself did not
// hold: the restore line was fixed for exactly this defect, and still exited ExitUsage, because
// the commit that fixed it added a flag and never re-drove the line it had just written.
//
// So this drives them rather than reading them. A synopsis is a promise that the command line as
// printed will work, and the only way to keep that promise is to run it.
//
// It found `downpipe preflight`, which cannot be followed: preflight requires --account. README.md
// had the complete form on the same day, which is the half-corrected pattern again at repository
// scope. One published surface was right and the other was not, and nothing compared them.

// synopsisRe matches a backticked span that starts a downpipe command line. The trailing space is
// what keeps `downpipe/0.1.0` and a bare `downpipe` out of the set.
var synopsisRe = regexp.MustCompile("`(downpipe [^`]+)`")

// placeholderValue supplies a real value for each <placeholder>, keyed by THE FLAG IT FOLLOWS
// rather than by the placeholder's own text. `<dir>` means the archive after --archive and the
// output directory after --out, and a table keyed on the token alone would silently conflate them.
type synopsisFixture struct {
	archive, runID, identity, signer, out, sealedIn, sealedSig, sealedSigner, sealedIdentity string
	share1, share2, share3, envelope, wrappingKey                                            string
}

func (f synopsisFixture) valueFor(flag string, nthShare int) (string, bool) {
	switch flag {
	case "--archive":
		return f.archive, true
	case "--run":
		return f.runID, true
	case "--identity":
		return f.identity, true
	case "--signer":
		return f.signer, true
	case "--out":
		return f.out, true
	case "--keep":
		return "1", true
	case "--in":
		return f.sealedIn, true
	case "--sig":
		return f.sealedSig, true
	case "--envelope":
		return f.envelope, true
	case "--wrapping-key":
		return f.wrappingKey, true
	case "--share":
		return [3]string{f.share1, f.share2, f.share3}[nthShare%3], true
	case "--account":
		return "0123456789abcdef0123456789abcdef", true
	case "--domain":
		return "engine.example.com", true
	}
	return "", false
}

// needsAnAccount are the commands with no offline success: they talk to Cloudflare, so the promise
// their synopsis makes is not "exit 0" but "you are not stopped by something the line could have
// told you". They are asserted to fail on the API TOKEN, the prerequisite the line already states,
// and not on a flag the line omitted. That is the assertion that catches the preflight defect.
var needsAnAccount = map[string]bool{"preflight": true, "setup": true}

// unseal-export writes its recovered plaintext somewhere, and the synopsis does not name --out
// because stdout is the default. Driving it as printed is therefore correct.
func newFixture(t *testing.T, testdata string) synopsisFixture {
	t.Helper()
	dir := t.TempDir()
	archive := filepath.Join(dir, "arc")
	identity, verifier, runID, err := buildSelftestArchive(archive, []byte("llms.txt synopsis"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, archive, identity, verifier)
	sealed := filepath.Join(testdata, "sealed-export")
	custody := filepath.Join(testdata, "custody")
	return synopsisFixture{
		archive:        archive,
		runID:          runID,
		identity:       idPath,
		signer:         signerPath,
		out:            filepath.Join(dir, "out"),
		sealedIn:       filepath.Join(sealed, "sealed.json"),
		sealedSig:      filepath.Join(sealed, "sealed.json.sig"),
		sealedSigner:   filepath.Join(sealed, "signer.pub"),
		sealedIdentity: filepath.Join(sealed, "identity.key"),
		share1:         filepath.Join(custody, "share-1.txt"),
		share2:         filepath.Join(custody, "share-2.txt"),
		share3:         filepath.Join(custody, "share-3.txt"),
		envelope:       filepath.Join(custody, "wrapped-identity.txt"),
		wrappingKey:    filepath.Join(custody, "wrapping-key.txt"),
	}
}

// materialise turns one printed synopsis into a real command line, or says why it cannot. Every
// <placeholder> must be accounted for; an unknown one is a failure rather than a skip, so a new
// synopsis cannot arrive undriven.
func materialise(t *testing.T, synopsis string, f synopsisFixture) []string {
	t.Helper()
	fields := strings.Fields(synopsis)
	if len(fields) < 2 || fields[0] != "downpipe" {
		t.Fatalf("materialise called with something that is not a downpipe command line: %q", synopsis)
	}
	cmd := fields[1]
	args := []string{cmd}
	shareCount := 0
	for i := 2; i < len(fields); i++ {
		tok := fields[i]
		if !strings.HasPrefix(tok, "<") {
			args = append(args, tok)
			continue
		}
		if i == 0 || !strings.HasPrefix(fields[i-1], "--") {
			t.Errorf("synopsis %q has a placeholder %q that follows no flag, so no value can be chosen for it", synopsis, tok)
			return nil
		}
		flag := fields[i-1]
		// unseal-export's own signer and identity come from the sealed-export fixture, not from
		// the archive, because they are the recovery kit that sealed export was made for.
		if cmd == "unseal-export" && flag == "--signer" {
			args = append(args, f.sealedSigner)
			continue
		}
		if cmd == "unseal-export" && flag == "--identity" {
			args = append(args, f.sealedIdentity)
			continue
		}
		v, ok := f.valueFor(flag, shareCount)
		if flag == "--share" {
			shareCount++
		}
		if !ok {
			t.Errorf("synopsis %q names %s, which the fixture has no value for. Add one; a synopsis that cannot be materialised is a synopsis nobody drives, which is how this file rotted in the first place", synopsis, flag)
			return nil
		}
		args = append(args, v)
	}
	return args
}

func TestEveryCommandLlmsTxtPrintsCanBeRun(t *testing.T) {
	silenceOutput(t)
	raw, err := os.ReadFile(filepath.Join("..", "..", "llms.txt"))
	if err != nil {
		t.Fatalf("cannot read llms.txt, which is the file this test exists to drive: %v", err)
	}
	// Absolute, because each synopsis below is driven from a scratch working directory.
	testdata, terr := filepath.Abs("testdata")
	if terr != nil {
		t.Fatalf("resolving testdata: %v", terr)
	}
	// Two extractors, because one was not enough. synopsisRe sees only BACKTICKED INLINE spans,
	// which is how every command in llms.txt is written today. Appending an ordinary fenced code
	// block holding `downpipe restore ... --sink nonesuch`, which really exits 6 with `unknown
	// --sink`, left this gate green: the command was on its own line and never inside backticks.
	// A fenced block is the obvious way anyone adds a worked example to this file, so the
	// whole-line form is collected too, by the same reader the bundled RECOVER.md gate uses.
	inline := synopsisRe.FindAllStringSubmatch(string(raw), -1)
	synopses := make([]string, 0, len(inline))
	for _, m := range inline {
		synopses = append(synopses, strings.TrimSpace(m[1]))
	}
	synopses = append(synopses, recoverMdCommands(t, string(raw))...)
	if len(synopses) == 0 {
		t.Fatal("no downpipe command line was found in llms.txt, so this test proved nothing; has the format of the Commands section changed?")
	}

	seen := map[string]bool{}
	driven := 0
	for _, synopsis := range synopses {
		if seen[synopsis] {
			continue // the same line is printed more than once; drive it once
		}
		seen[synopsis] = true
		fields := strings.Fields(synopsis)
		cmd := fields[1]
		if strings.HasPrefix(cmd, "-") {
			continue // `downpipe --version` and friends are aliases, not synopses with inputs
		}
		// Run from a scratch directory. Several synopses default their output to the working
		// directory: keygen writes into ".", and recombine writes identity.key. Driving them AS
		// PRINTED means letting them do that, and from the package directory they wrote three key
		// files into the source tree and the next run then failed because O_EXCL found them.
		t.Chdir(t.TempDir())
		f := newFixture(t, testdata)
		args := materialise(t, synopsis, f)
		if args == nil {
			continue
		}
		driven++
		if needsAnAccount[cmd] {
			// No API token in the environment, so the run must stop at the token and not at
			// anything the printed line could have supplied.
			t.Setenv("CLOUDFLARE_API_TOKEN", "")
			var code int
			_, stderr := captureOutput(t, func() { code = run(args) })
			if code == 0 {
				t.Errorf("%q exited 0 with no API token, which means it did not reach Cloudflare at all", synopsis)
			}
			if !strings.Contains(stderr, "CLOUDFLARE_API_TOKEN") {
				t.Errorf("%q does not get as far as needing a token: it fails on %q, which is something the printed line could have supplied and did not. Print the complete command line", synopsis, strings.TrimSpace(stderr))
			}
			continue
		}
		if code := run(args); code != 0 {
			t.Errorf("%q exited %d, want 0. A synopsis is a promise that the command line as printed will work.\nmaterialised as: %v", synopsis, code, args)
		}
	}
	if driven == 0 {
		t.Fatal("no synopsis was driven, so this test proved nothing")
	}
}
