package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/source"
)

// ptr is a tiny helper to take the address of a string literal, so a test can build a
// storeFlags by hand without a FlagSet. storeFlags holds *string fields because the real
// values come from flag.String; here we supply them directly.
func ptr(s string) *string { return &s }

// newStoreFlags builds a storeFlags with the given values, mirroring what addStoreFlags
// would produce after parsing.
//
// The Azure pair is filled with empty strings rather than left nil, because addStoreFlags always
// defines both flags and resolve() reads both pointers. A nil here would be a panic in the test
// helper, which is a fault in the double and not in the code under test; newAzureStoreFlags is the
// constructor for the Azure branch.
func newStoreFlags(archive, endpoint, bucket, region string) storeFlags {
	return storeFlags{
		archive:        ptr(archive),
		s3Endpoint:     ptr(endpoint),
		s3Bucket:       ptr(bucket),
		s3Region:       ptr(region),
		azureEndpoint:  ptr(""),
		azureContainer: ptr(""),
	}
}

// newAzureStoreFlags builds a storeFlags naming an Azure Blob destination, with the S3 pair empty.
func newAzureStoreFlags(endpoint, container string) storeFlags {
	sf := newStoreFlags("", "", "", "auto")
	sf.azureEndpoint = ptr(endpoint)
	sf.azureContainer = ptr(container)
	return sf
}

// TestResolveDirStore covers the local-directory branch of storeFlags.resolve: with
// --archive set and no --s3-endpoint, it returns a directory-backed store.
func TestResolveDirStore(t *testing.T) {
	sf := newStoreFlags("/some/dir", "", "", "auto")
	store, err := sf.resolve()
	if err != nil {
		t.Fatalf("resolve(--archive) = %v, want nil", err)
	}
	if _, ok := store.(*source.DirStore); !ok {
		t.Errorf("resolve(--archive) returned %T, want *source.DirStore", store)
	}
}

// TestResolveS3StoreWithCreds covers the S3 branch of storeFlags.resolve: with a valid
// https endpoint, a bucket, and the AWS credentials present in the environment, it builds
// an S3-backed store. NewS3Store performs NO network I/O at construction (it validates the
// endpoint and builds the struct), so this stays fully offline.
func TestResolveS3StoreWithCreds(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIA-test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret-test")
	sf := newStoreFlags("", "https://s3.example.com", "my-bucket", "auto")
	store, err := sf.resolve()
	if err != nil {
		t.Fatalf("resolve(--s3-endpoint) = %v, want nil", err)
	}
	if _, ok := store.(*source.S3Store); !ok {
		t.Errorf("resolve(--s3-endpoint) returned %T, want *source.S3Store", store)
	}
}

// TestResolveS3MissingCredsErrors covers the S3 branch's credential guard: a valid
// endpoint and bucket but absent AWS credentials is a usage error, checked before any
// store is built.
func TestResolveS3MissingCredsErrors(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	sf := newStoreFlags("", "https://s3.example.com", "my-bucket", "auto")
	if _, err := sf.resolve(); err == nil {
		t.Fatal("resolve(--s3-endpoint) with no AWS creds = nil, want a usage error")
	}
}

// TestResolveS3MissingBucketErrors covers the S3 branch's bucket guard: an endpoint with
// no bucket is a usage error.
func TestResolveS3MissingBucketErrors(t *testing.T) {
	sf := newStoreFlags("", "https://s3.example.com", "", "auto")
	if _, err := sf.resolve(); err == nil {
		t.Fatal("resolve(--s3-endpoint) with no --s3-bucket = nil, want a usage error")
	}
}

// TestResolveS3InsecureEndpointErrors covers the S3 branch's NewS3Store error path: an
// http:// (non-localhost) endpoint is rejected by the store constructor and surfaced as a
// usage error, so the SigV4 Authorization header is never sent in clear.
func TestResolveS3InsecureEndpointErrors(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIA-test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret-test")
	sf := newStoreFlags("", "http://insecure.example.com", "my-bucket", "auto")
	if _, err := sf.resolve(); err == nil {
		t.Fatal("resolve with an insecure http endpoint = nil, want a usage error")
	}
}

// TestResolveNoSourceErrors covers the no-source branch: neither --archive nor
// --s3-endpoint set is a usage error.
func TestResolveNoSourceErrors(t *testing.T) {
	sf := newStoreFlags("", "", "", "auto")
	if _, err := sf.resolve(); err == nil {
		t.Fatal("resolve with no source = nil, want a usage error")
	}
}

// TestEnvNamesReturnsNamesOnly covers envNames: it returns the names of the variables in
// the current process environment and never their values. The env sink uses this to refuse
// to redefine an already-set variable, so it must list names but leak no value.
func TestEnvNamesReturnsNamesOnly(t *testing.T) {
	t.Setenv("DOWNPIPE_ENVNAMES_PROBE", "this-value-must-not-appear")
	names := envNames()
	found := false
	for _, n := range names {
		if n == "DOWNPIPE_ENVNAMES_PROBE" {
			found = true
		}
		// A name must never carry the "NAME=value" form; envNames returns the key only.
		if strings.Contains(n, "=") {
			t.Errorf("envNames returned a name with '=' in it: %q (values must not leak)", n)
		}
		if strings.Contains(n, "this-value-must-not-appear") {
			t.Errorf("envNames leaked a value: %q", n)
		}
	}
	if !found {
		t.Error("envNames did not include the probe variable name")
	}
}

// TestNewRestoreTargetEnvAndDiscard covers the env and discard branches of newRestoreTarget
// (the file branch is already covered by the restore command tests). The env target writes
// dotenv lines to stdout treating the current environment as occupied; the discard target
// verifies without writing.
func TestNewRestoreTargetEnvAndDiscard(t *testing.T) {
	envT, err := newRestoreTarget("env", "")
	if err != nil {
		t.Fatalf("newRestoreTarget(env) = %v, want nil", err)
	}
	if envT.Kind() != "env" {
		t.Errorf("env target Kind() = %q, want env", envT.Kind())
	}
	discardT, err := newRestoreTarget("discard", "")
	if err != nil {
		t.Fatalf("newRestoreTarget(discard) = %v, want nil", err)
	}
	if discardT.Kind() != "discard" {
		t.Errorf("discard target Kind() = %q, want discard", discardT.Kind())
	}
	if _, err := newRestoreTarget("bogus", ""); err == nil {
		t.Fatal("newRestoreTarget(bogus) = nil error, want a usage error")
	}
}

// TestLoadIdentityAndSignerErrors covers the error branches of identityFlags.loadAndVerifier: a
// missing identity file, an identity file that does not parse, a missing signer file, and a
// signer file that does not parse. Each must return a wrapped error naming the failing role.
func TestLoadIdentityAndSignerErrors(t *testing.T) {
	dir := t.TempDir()

	// A valid identity and signer to use as the "good" half in each mixed case.
	idPriv, _, err := crypto.GenerateHybridKEM()
	if err != nil {
		t.Fatalf("GenerateHybridKEM: %v", err)
	}
	_, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatalf("GenerateHybridSigner: %v", err)
	}
	goodID := filepath.Join(dir, "identity.key")
	goodSigner := filepath.Join(dir, "signer.pub")
	if err := writeKeyFile(goodID, labelIdentity, crypto.MarshalKEMPrivate(idPriv)); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	if err := writeKeyFile(goodSigner, labelSignerPublic, crypto.MarshalVerifier(verifier)); err != nil {
		t.Fatalf("write signer: %v", err)
	}

	// 1: missing identity file.
	if _, _, err := (&identityFlags{path: filepath.Join(dir, "nope.key")}).loadAndVerifier(goodSigner); err == nil {
		t.Error("loadAndVerifier with a missing identity = nil, want an error")
	}

	// 2: identity file present but unparseable bytes (correct label, junk payload).
	badID := filepath.Join(dir, "bad-identity.key")
	if err := writeKeyFile(badID, labelIdentity, []byte("not-a-real-kem-private")); err != nil {
		t.Fatalf("write bad identity: %v", err)
	}
	if _, _, err := (&identityFlags{path: badID}).loadAndVerifier(goodSigner); err == nil {
		t.Error("loadAndVerifier with an unparseable identity = nil, want an error")
	}

	// 3: missing signer file (identity good).
	if _, _, err := (&identityFlags{path: goodID}).loadAndVerifier(filepath.Join(dir, "nope.pub")); err == nil {
		t.Error("loadAndVerifier with a missing signer = nil, want an error")
	}

	// 4: signer file present but unparseable.
	badSigner := filepath.Join(dir, "bad-signer.pub")
	if err := writeKeyFile(badSigner, labelSignerPublic, []byte("not-a-real-verifier")); err != nil {
		t.Fatalf("write bad signer: %v", err)
	}
	if _, _, err := (&identityFlags{path: goodID}).loadAndVerifier(badSigner); err == nil {
		t.Error("loadAndVerifier with an unparseable signer = nil, want an error")
	}
}

// TestReadKeyFileErrors covers readKeyFile's error branches: a missing file, a file with
// the wrong label, and a file whose payload is not valid base64url.
func TestReadKeyFileErrors(t *testing.T) {
	dir := t.TempDir()

	// Missing file.
	if _, err := readKeyFile(filepath.Join(dir, "absent"), labelIdentity); err == nil {
		t.Error("readKeyFile on a missing file = nil, want an error")
	}

	// Wrong label: the file is a valid two-field line but the label does not match.
	wrongLabel := filepath.Join(dir, "wrong-label")
	if err := os.WriteFile(wrongLabel, []byte("some-other-label AAAA\n"), 0o600); err != nil {
		t.Fatalf("write wrong-label file: %v", err)
	}
	if _, err := readKeyFile(wrongLabel, labelIdentity); err == nil {
		t.Error("readKeyFile with the wrong label = nil, want an error")
	}

	// Wrong field count: only one field on the line.
	oneField := filepath.Join(dir, "one-field")
	if err := os.WriteFile(oneField, []byte("just-one-token\n"), 0o600); err != nil {
		t.Fatalf("write one-field file: %v", err)
	}
	if _, err := readKeyFile(oneField, labelIdentity); err == nil {
		t.Error("readKeyFile with a single field = nil, want an error")
	}

	// Correct label but a payload that is not valid base64url.
	badB64 := filepath.Join(dir, "bad-b64")
	if err := os.WriteFile(badB64, []byte(labelIdentity+" !!!not-base64!!!\n"), 0o600); err != nil {
		t.Fatalf("write bad-b64 file: %v", err)
	}
	if _, err := readKeyFile(badB64, labelIdentity); err == nil {
		t.Error("readKeyFile with a non-base64url payload = nil, want an error")
	}
}

// TestWriteKeyFileRefusesExistingAndBadDir covers writeKeyFile's error branch: O_EXCL means
// a second write to the same path fails rather than clobbering an existing key.
func TestWriteKeyFileRefusesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.key")
	if err := writeKeyFile(path, labelIdentity, []byte("payload-bytes")); err != nil {
		t.Fatalf("first writeKeyFile = %v, want nil", err)
	}
	// A second write to the same path must fail (O_EXCL refuses to overwrite key material).
	if err := writeKeyFile(path, labelIdentity, []byte("other-payload")); err == nil {
		t.Fatal("second writeKeyFile to the same path = nil, want an error (O_EXCL)")
	}
}

// TestCmdSelftestKeepWritesArtifacts covers the --keep branch of cmdSelftest: it builds the
// sample archive into the given directory and keeps the identity and signer key files
// alongside it, printing the follow-up inspect/verify hints. This exercises the
// keep-and-write-keys path that the default (temp, removed) selftest run does not.
func TestCmdSelftestKeepWritesArtifacts(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "kept")

	var code int
	stdout, _ := captureOutput(t, func() {
		code = run([]string{"selftest", "--keep", keep})
	})
	if code != 0 {
		t.Fatalf("selftest --keep = %d, want 0", code)
	}
	// The kept directory must hold the identity and signer key files for a later recovery.
	for _, name := range []string{"identity.key", "signer.pub"} {
		if _, err := os.Stat(filepath.Join(keep, name)); err != nil {
			t.Errorf("selftest --keep did not write %s: %v", name, err)
		}
	}
	// The output should point the operator at the kept artefacts and the follow-up commands.
	if !strings.Contains(stdout, "kept the archive and keys in") {
		t.Errorf("selftest --keep output missing the kept-artefacts hint\n%s", stdout)
	}
}
