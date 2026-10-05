package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// TestCmdInspectPrintsKeyNameHash drives inspect WITH identity against a real archive and
// asserts each record's keyNameHash (SPEC.md 6.5's keyed name MAC over the record's source
// type and name, the field RecordHashOf reads alongside plaintextSha384 and plaintextSize)
// appears in the records detail line.
//
// Before this test, inspect's per-record line carried describeIdentity and
// describeRestoreDescriptor only; an operator with a real archive open and a specific
// keyNameHash from elsewhere (a support ticket, a recovery sheet, a second archive being
// compared record for record) had no command that would print it back. inspect is the one
// place this reader shows per-record detail at all, so that is where it belongs.
func TestCmdInspectPrintsKeyNameHash(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("inspect keyNameHash"))
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

	// The selftest fixture's one record is named "greeting"; if that assumption ever
	// changes, this test should say so plainly rather than pass on the wrong line.
	if !strings.Contains(stdout, "greeting") {
		t.Fatalf("test fixture assumption broken: the selftest record name %q is not in the output:\n%s", "greeting", stdout)
	}

	// keyNameHash is a SHA-384 HMAC (crypto.NameMAC), hex-encoded: 96 lowercase hex
	// characters, never empty (it is not an omitempty field on spec.ShardRecord).
	re := regexp.MustCompile(`keyNameHash=[0-9a-f]{96}\b`)
	if !re.MatchString(stdout) {
		t.Errorf("inspect must print the record's keyNameHash (a full 96-character hex SHA-384 HMAC), got:\n%s", stdout)
	}
}

// TestDescribeKeyNameHash covers describeKeyNameHash directly: it must render the record's
// KeyNameHash field, unconditionally, since (unlike describeIdentity and
// describeRestoreDescriptor) the field is never absent on a real record.
func TestDescribeKeyNameHash(t *testing.T) {
	rec := spec.ShardRecord{Name: "greeting", KeyNameHash: strings.Repeat("ab", 48)}
	want := "keyNameHash=" + rec.KeyNameHash
	if got := describeKeyNameHash(rec); got != want {
		t.Errorf("describeKeyNameHash = %q, want %q", got, want)
	}
}
