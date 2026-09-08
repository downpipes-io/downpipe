package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// TestCmdKeygenWritesAllKeyFiles drives the keygen command through run() and asserts it
// writes the four expected key files (the break-glass identity, the recipient public key,
// and the signer keypair) into --out, that each is a labelled, owner-only file, and that
// each round-trips back through the matching crypto parser. keygen is the entrypoint that
// mints the offline recovery material, so a regression here would be a recovery hazard.
func TestCmdKeygenWritesAllKeyFiles(t *testing.T) {
	silenceOutput(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "keys")

	if code := run([]string{"keygen", "--out", out}); code != 0 {
		t.Fatalf("run([keygen --out]) = %d, want 0", code)
	}

	// All four files must exist with owner-only (0600) permissions, written via O_EXCL.
	for _, name := range []string{"identity.key", "recipient.pub", "signer.pub", "signer.key"} {
		p := filepath.Join(out, name)
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("keygen did not write %s: %v", name, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s permissions = %o, want 0600 (owner-only key material)", name, perm)
		}
	}

	// Each file must round-trip through the matching parser, proving the bytes written are
	// the canonical marshalling and not corrupt.
	idBytes, err := readKeyFile(filepath.Join(out, "identity.key"), labelIdentity)
	if err != nil {
		t.Fatalf("read identity.key: %v", err)
	}
	if _, err := crypto.ParseKEMPrivate(idBytes); err != nil {
		t.Errorf("identity.key does not parse as a KEM private key: %v", err)
	}
	signerBytes, err := readKeyFile(filepath.Join(out, "signer.pub"), labelSignerPublic)
	if err != nil {
		t.Fatalf("read signer.pub: %v", err)
	}
	if _, err := crypto.ParseVerifier(signerBytes); err != nil {
		t.Errorf("signer.pub does not parse as a verifier: %v", err)
	}
	privBytes, err := readKeyFile(filepath.Join(out, "signer.key"), labelSignerPrivate)
	if err != nil {
		t.Fatalf("read signer.key: %v", err)
	}
	if _, err := crypto.ParseSigner(privBytes); err != nil {
		t.Errorf("signer.key does not parse as a signer: %v", err)
	}
}

// TestCmdKeygenRefusesOverwrite confirms keygen will not clobber existing key material: a
// second run into the same directory fails because writeKeyFile opens with O_EXCL. This is
// the guard that stops a re-run from silently destroying an existing break-glass key.
func TestCmdKeygenRefusesOverwrite(t *testing.T) {
	silenceOutput(t)
	out := t.TempDir() // already exists and will already hold identity.key after the first run

	if code := run([]string{"keygen", "--out", out}); code != 0 {
		t.Fatalf("first keygen = %d, want 0", code)
	}
	// The second run must fail rather than overwrite the existing identity.key, and it must say
	// so with the code that means "your command line is wrong", which is what it is: the operator
	// named an --out that already holds key material. Pinned to the exact code rather than to
	// non-zero, because "non-zero" is satisfied by ExitUnverified (2), which on this tool means an
	// archive failed its signature or hash check. An operator re-running a key ceremony and
	// reading 2 has been told their archive is bad, and it is the one message that would send
	// them somewhere with no fault in it. recombine codes the identical O_EXCL refusal on its
	// --out to ExitUsage, so this is the same refusal reported the same way.
	if code := run([]string{"keygen", "--out", out}); code != format.ExitUsage {
		t.Fatalf("second keygen into a populated dir = %d, want %d (ExitUsage): O_EXCL must refuse to overwrite, and the refusal is about the path the operator gave", code, format.ExitUsage)
	}
}

// TestCmdKeygenGuidanceKeepsPrivateKeysOffTheSheet drives keygen and gates the guidance it
// prints, because that guidance is the only instruction most operators will ever read about
// where their key files live.
//
// It caught a real defect. keygen used to print "identity.key is the break-glass key: it is
// the only way to recover, so keep it offline and on a printed recovery sheet", which tells
// an operator to copy a KEM private key onto the one artefact the product designs to be safe
// on paper. The console prints fingerprints there under a heading saying those values are
// public and safe to record, so the two halves of the product disagreed about where a private
// key lives, and the reader's half was the unsafe one.
//
// Two gates run here. The first is a leak gate: no byte of any key file may appear in the
// output. The second is the sheet gate: no sentence may name a private key file and the
// recovery sheet together without a negation, which is exactly the shape of the old sentence.
// A literal command in single quotes is stripped before the sentence split, since a command
// naming a path is not prose guidance about where to keep it.
func TestCmdKeygenGuidanceKeepsPrivateKeysOffTheSheet(t *testing.T) {
	out := filepath.Join(t.TempDir(), "keys")
	var code int
	stdout := captureStdout(t, func() {
		code = run([]string{"keygen", "--out", out})
	})
	if code != 0 {
		t.Fatalf("run([keygen --out]) = %d, want 0", code)
	}

	// Leak gate. Not one byte of the material just minted may be echoed to the terminal,
	// whatever the guidance says. A private key on a scrollback buffer is a private key on
	// a shared machine.
	for _, name := range []string{"identity.key", "recipient.pub", "signer.pub", "signer.key"} {
		raw, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		body := strings.TrimSpace(string(raw))
		if _, encoded, ok := strings.Cut(body, " "); ok {
			body = encoded
		}
		if body != "" && strings.Contains(stdout, body) {
			t.Errorf("keygen printed the contents of %s to stdout", name)
		}
	}

	// Sheet gate. Strip the suggested command, unwrap the hard line breaks, then read the
	// guidance a sentence at a time.
	// `openQuote` and `closeQuote` rather than `open` and `close`: `close` is a Go builtin, and
	// revive's redefines-builtin-id rejects shadowing it. `open` is renamed with it so the pair
	// still reads as a pair.
	prose := stdout
	for {
		openQuote := strings.Index(prose, "'")
		if openQuote < 0 {
			break
		}
		closeQuote := strings.Index(prose[openQuote+1:], "'")
		if closeQuote < 0 {
			break
		}
		prose = prose[:openQuote] + prose[openQuote+1+closeQuote+1:]
	}
	prose = strings.ReplaceAll(prose, "\n", " ")
	for _, sentence := range strings.Split(prose, ". ") {
		lower := strings.ToLower(sentence)
		if !strings.Contains(lower, "recovery sheet") {
			continue
		}
		if strings.Contains(lower, "never") || strings.Contains(lower, " not ") {
			continue
		}
		for _, private := range []string{"identity.key", "signer.key"} {
			if strings.Contains(lower, private) {
				t.Errorf("keygen names %s and the recovery sheet in one sentence with no negation, "+
					"which reads as an instruction to write a private key on the sheet: %q", private, sentence)
			}
		}
	}

	// The sheet gate above is satisfied by silence, so pin the statement that has to be
	// present: the operator must be told what the sheet does carry.
	if !strings.Contains(stdout, "fingerprints only") {
		t.Error("keygen never says the recovery sheet carries fingerprints only")
	}
	// A kit built without signer.pub cannot restore: restore requires --signer and the
	// signer public key is not in the archive. keygen must not read as if it leaves.
	if !strings.Contains(stdout, "--signer") {
		t.Error("keygen never warns that restore exits without --signer, so an operator may not keep signer.pub")
	}
}

// TestCmdKeygenBadFlagErrors confirms an unparseable flag is a clean error from the
// keygen FlagSet (ContinueOnError) rather than a panic.
//
// It asserted only non-zero, which is how it stayed green through the whole period in which
// thirteen of the fourteen commands exited 1 for a mistyped flag rather than ExitUsage. It would
// equally have stayed green at 2, the code that means an archive failed to verify, which is
// strictly worse than the defect it was already accepting. TestFlagParseOutcomesCarryTheRightExitCode
// now pins this for every dispatched command; this one keeps its own case because it is what
// somebody reads when keygen changes, and a sibling that disagrees with the pin is how the loose
// form got there in the first place.
func TestCmdKeygenBadFlagErrors(t *testing.T) {
	silenceOutput(t)
	if code := run([]string{"keygen", "--nonexistent-flag"}); code != format.ExitUsage {
		t.Fatalf("keygen with an unknown flag = %d, want %d (ExitUsage)", code, format.ExitUsage)
	}
}

// TestCmdInspectCleartextOnly drives inspect against a real archive WITHOUT an identity and
// asserts the cleartext root fields are printed and that the encrypted-detail hint is shown
// (no identity supplied). This covers the no-identity branch of cmdInspect end to end.
//
// The exit 0 with no identity is a decision: inspect is the command an operator reaches for
// when they do not yet know what they are holding, and refusing to describe an archive because
// no key was supplied would make it useless at exactly that moment. What makes the 0 honest is
// the caveat that nothing on the screen was verified, so that caveat is asserted here and not
// only in its own test: the hint about --identity and --signer is a feature note, and pinning
// the feature note while leaving the caveat to a sibling file is how a permissive exit ends up
// with nothing holding up its half of the bargain.
func TestCmdInspectCleartextOnly(t *testing.T) {
	dir := t.TempDir()
	runID := selftestArchiveRunID(t, dir, []byte("inspect cleartext"))

	var code int
	stdout, _ := captureOutput(t, func() {
		code = run([]string{"inspect", "--archive", dir, "--run", runID})
	})
	if code != 0 {
		t.Fatalf("inspect (cleartext) = %d, want 0", code)
	}
	// The cleartext root fields must appear; the encrypted fields must not be opened.
	for _, want := range []string{"format:", "run:", runID, "downpipe:", "recipients:", "break-glass present: true"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("inspect cleartext output missing %q\n%s", want, stdout)
		}
	}
	if !strings.Contains(stdout, "pass --identity and --signer") {
		t.Errorf("inspect without identity should hint at --identity/--signer\n%s", stdout)
	}
	if !strings.Contains(stdout, "nothing above was verified") {
		t.Errorf("a keyless dump exits 0 only because it admits it checked nothing; without that line the 0 reads as a verdict\n%s", stdout)
	}
}

// TestCmdInspectWithIdentityShowsEncryptedDetail drives inspect WITH the break-glass
// identity and the pinned signer against a real archive and asserts the encrypted preamble
// detail (the downpipe name, cadence, source and window kept out of the cleartext root) is
// decrypted and printed. This covers the --identity branch of cmdInspect, the Preambles()
// loop, and the describeRestoreDescriptor scan.
func TestCmdInspectWithIdentityShowsEncryptedDetail(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("inspect encrypted detail"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	var code int
	stdout, _ := captureOutput(t, func() {
		code = run([]string{
			"inspect",
			"--archive", dir,
			"--run", runID,
			"--identity", idPath,
			"--signer", signerPath,
		})
	})
	if code != 0 {
		t.Fatalf("inspect (with identity) = %d, want 0", code)
	}
	// The encrypted preamble carries the downpipe name "selftest" and cadence, which are not
	// in the cleartext root; seeing them proves the identity opened the shard.
	for _, want := range []string{"encrypted detail", "selftest", "shard 00000"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("inspect encrypted output missing %q\n%s", want, stdout)
		}
	}
}

// TestCmdInspectIdentityWithoutSignerErrors confirms --identity without --signer is a usage
// error: the encrypted detail needs the signer to verify the root before the shard is
// opened, so the command refuses rather than opening unverified.
func TestCmdInspectIdentityWithoutSignerErrors(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("inspect needs signer"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, _ := writeArchiveKeys(t, dir, identity, verifier)

	var code int
	captureOutput(t, func() {
		code = run([]string{
			"inspect",
			"--archive", dir,
			"--run", runID,
			"--identity", idPath,
			// --signer intentionally omitted
		})
	})
	if code != format.ExitUsage {
		t.Fatalf("inspect --identity without --signer = %d, want %d (ExitUsage)", code, format.ExitUsage)
	}
}

// TestDescribeRestoreDescriptor covers describeRestoreDescriptor for every per-source
// descriptor variant and for the empty cases. Exactly one of KV/R2/Secrets/D1 is set on a
// real record; the function renders a short line for a present descriptor and "" when the
// record carries none, which is what inspect uses to decide whether to print the line.
func TestDescribeRestoreDescriptor(t *testing.T) {
	cases := []struct {
		name    string
		rec     spec.ShardRecord
		want    string
		wantSub []string // when set, assert these substrings appear instead of an exact match
	}{
		{
			name: "kv with expiration and metadata",
			rec:  spec.ShardRecord{KV: &spec.KVDescriptor{Expiration: 1700000000, Metadata: json.RawMessage(`{"a":1}`)}},
			want: "kv: expiration=1700000000 metadata",
		},
		{
			name: "kv with expiration only",
			rec:  spec.ShardRecord{KV: &spec.KVDescriptor{Expiration: 42}},
			want: "kv: expiration=42",
		},
		{
			name: "kv with metadata only",
			rec:  spec.ShardRecord{KV: &spec.KVDescriptor{Metadata: json.RawMessage(`{"k":"v"}`)}},
			want: "kv: metadata",
		},
		{
			name: "kv empty descriptor renders nothing",
			rec:  spec.ShardRecord{KV: &spec.KVDescriptor{}},
			want: "",
		},
		{
			name:    "r2 with both metadata kinds",
			rec:     spec.ShardRecord{R2: &spec.R2Descriptor{HTTPMetadata: json.RawMessage(`{}`), CustomMetadata: json.RawMessage(`{}`)}},
			wantSub: []string{"r2:", "httpMetadata", "customMetadata"},
		},
		{
			name: "r2 with http metadata only",
			rec:  spec.ShardRecord{R2: &spec.R2Descriptor{HTTPMetadata: json.RawMessage(`{}`)}},
			want: "r2: httpMetadata",
		},
		{
			name: "r2 empty descriptor renders nothing",
			rec:  spec.ShardRecord{R2: &spec.R2Descriptor{}},
			want: "",
		},
		{
			name:    "secrets descriptor always renders the wiring",
			rec:     spec.ShardRecord{Secrets: &spec.SecretsDescriptor{Store: "s1", Scope: "account", Worker: "w", BindingVar: "B"}},
			wantSub: []string{"secrets:", "store=\"s1\"", "scope=\"account\"", "worker=\"w\"", "binding=\"B\""},
		},
		{
			name: "d1 with a format",
			rec:  spec.ShardRecord{D1: &spec.D1Descriptor{Format: "sql"}},
			want: "d1: format=sql",
		},
		{
			name: "d1 empty descriptor renders nothing",
			rec:  spec.ShardRecord{D1: &spec.D1Descriptor{}},
			want: "",
		},
		{
			name: "no descriptor at all renders nothing",
			rec:  spec.ShardRecord{Name: "plain"},
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := describeRestoreDescriptor(c.rec)
			if len(c.wantSub) > 0 {
				for _, sub := range c.wantSub {
					if !strings.Contains(got, sub) {
						t.Errorf("describeRestoreDescriptor = %q, missing substring %q", got, sub)
					}
				}
				return
			}
			if got != c.want {
				t.Errorf("describeRestoreDescriptor = %q, want %q", got, c.want)
			}
		})
	}
}

// TestDescribeIdentity covers describeIdentity for every top-level self-identification
// coordinate (namespace/bucket pre-existing, database/account new, mirroring the engine's
// manifest annotations 1:1) and for the empty case.
func TestDescribeIdentity(t *testing.T) {
	cases := []struct {
		name string
		rec  spec.ShardRecord
		want string
	}{
		{
			name: "namespace only (KV)",
			rec:  spec.ShardRecord{Namespace: "sessions"},
			want: `identity: namespace="sessions"`,
		},
		{
			name: "bucket only (R2)",
			rec:  spec.ShardRecord{Bucket: "media-prod"},
			want: `identity: bucket="media-prod"`,
		},
		{
			name: "database only (D1 native UUID)",
			rec:  spec.ShardRecord{Database: "db-uuid-abc123"},
			want: `identity: database="db-uuid-abc123"`,
		},
		{
			name: "account only (an API source: workers/cf-config/stream/images/artifacts)",
			rec:  spec.ShardRecord{Account: "acct-xyz"},
			want: `identity: account="acct-xyz"`,
		},
		{
			name: "namespace and account together render both, in field order",
			rec:  spec.ShardRecord{Namespace: "sessions", Account: "acct-xyz"},
			want: `identity: namespace="sessions" account="acct-xyz"`,
		},
		{
			// database and account both set (a real D1 shape: a database lives inside a
			// Cloudflare account, so both are populated together, unlike the other pairings
			// above where one of the two is always empty). This is the case that a
			// database<->account VALUE swap in describeIdentity would NOT be caught by any of
			// the single-field cases above: with only one of the two set, a swap renders the
			// unset field's empty string under the set field's label, which is visibly wrong
			// (an empty quoted string). With both set, a swap prints two plausible non-empty
			// values under the wrong labels and every single-field case above stays green.
			// A prior regression let this exact swap through describeIdentity(); this is the
			// case its own fix needs to catch it (proven: this case alone fails against the
			// swap while every case above it still passes).
			name: "database and account together render both, distinguishable, and are not swapped",
			rec:  spec.ShardRecord{Database: "db-uuid-4f9a2c1e", Account: "acct-d1-identity"},
			want: `identity: database="db-uuid-4f9a2c1e" account="acct-d1-identity"`,
		},
		{
			name: "no identity fields renders nothing",
			rec:  spec.ShardRecord{Name: "plain"},
			want: "",
		},
		{
			name: "a secrets record's store id is NOT rendered here: it lives in the nested descriptor and describeRestoreDescriptor already shows it",
			rec:  spec.ShardRecord{Secrets: &spec.SecretsDescriptor{Store: "store-1"}},
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := describeIdentity(c.rec)
			if got != c.want {
				t.Errorf("describeIdentity = %q, want %q", got, c.want)
			}
		})
	}
}
