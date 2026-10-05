package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
)

// verify-report is driven end to end through run() against the fixture the engine's own report code
// signed (internal/format/testdata/signed-report, written by gen-fixture.mjs there). The rules are
// tested in internal/format/report_test.go; these cases pin the command line and the exit codes.

var reportFixture = filepath.Join("..", "..", "internal", "format", "testdata", "signed-report")

func reportFixturePath(name string) string { return filepath.Join(reportFixture, name) }

func TestVerifyReportCommandExitCodes(t *testing.T) {
	silenceOutput(t)
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	posture, err := os.ReadFile(reportFixturePath("posture.json"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := write("tampered.json", []byte(strings.Replace(string(posture), `"score":87`, `"score":97`, 1)))
	pdf := write("report.pdf", []byte("%PDF-1.4\n"))
	big := filepath.Join(dir, "big.json")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxReportBytes + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	signer := reportFixturePath("signer.pub")
	other := reportFixturePath("other-signer.pub")
	good := reportFixturePath("posture.json")
	pin := signerFingerprintOf(t, signer)

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"the served report", []string{"--signer", signer, "--report", good}, format.ExitVerified},
		{"the console's View JSON", []string{"--signer", signer, "--report", reportFixturePath("posture.pretty.json")}, format.ExitVerified},
		{"a windowed report", []string{"--signer", signer, "--report", reportFixturePath("restore-tests.json")}, format.ExitVerified},
		{"the matching fingerprint", []string{"--signer", signer, "--signer-fingerprint", strings.ToUpper(pin), "--report", good}, format.ExitVerified},
		{"a changed report", []string{"--signer", signer, "--report", tampered}, format.ExitUnverified},
		{"another signer", []string{"--signer", other, "--report", good}, format.ExitUnverified},
		{"an unsigned report", []string{"--signer", signer, "--report", reportFixturePath("unsigned.json")}, format.ExitUnverified},
		{"the PDF", []string{"--signer", signer, "--report", pdf}, format.ExitUsage},
		{"a report over the size limit", []string{"--signer", signer, "--report", big}, format.ExitUsage},
		{"a fingerprint from another ceremony", []string{"--signer", other, "--signer-fingerprint", pin, "--report", good}, format.ExitUsage},
		{"a malformed fingerprint", []string{"--signer", signer, "--signer-fingerprint", "edmldsa1:abc", "--report", good}, format.ExitUsage},
		{"a fingerprint without --signer", []string{"--signer-fingerprint", pin, "--report", good}, format.ExitUsage},
		{"no --report", []string{"--signer", signer}, format.ExitUsage},
		{"no --signer", []string{"--report", good}, format.ExitUsage},
		{"a missing report file", []string{"--signer", signer, "--report", filepath.Join(dir, "absent.json")}, format.ExitUsage},
		{"a missing signer file", []string{"--signer", filepath.Join(dir, "absent.pub"), "--report", good}, format.ExitUsage},
		{"the report as the signer", []string{"--signer", good, "--report", good}, format.ExitUsage},
		{"a positional report", []string{"--signer", signer, good}, format.ExitUsage},
		{"an unknown flag", []string{"--signer", signer, "--report", good, "--json"}, format.ExitUsage},
		{"help", []string{"--help"}, 0},
	}
	for _, c := range cases {
		if got := run(append([]string{"verify-report"}, c.args...)); got != c.want {
			t.Errorf("%s: verify-report exited %d, want %d", c.name, got, c.want)
		}
	}
}

// The success lines name the kind, the time, the window and the signer fingerprint, and a refusal
// names the signer fingerprint so a wrong-key result can be checked against the recovery sheet.
func TestVerifyReportCommandOutput(t *testing.T) {
	signer := reportFixturePath("signer.pub")
	pin := signerFingerprintOf(t, signer)

	var code int
	stderr := captureStderr(t, func() {
		code = run([]string{"verify-report", "--signer", signer, "--report", reportFixturePath("restore-tests.json")})
	})
	if code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
	for _, want := range []string{
		"VERIFIED",
		"kind=restore-tests",
		"generatedAt=2026-09-25T00:00:00.000Z",
		"period=1782432000..1790208000 (2026-06-26T00:00:00Z to 2026-09-24T00:00:00Z)",
		"signer: " + pin,
		"Both signature halves (Ed25519 and ML-DSA-87) verified",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the success output does not contain %q:\n%s", want, stderr)
		}
	}

	stderr = captureStderr(t, func() {
		code = run([]string{"verify-report", "--signer", signer, "--report", reportFixturePath("posture.json")})
	})
	if code != 0 || !strings.Contains(stderr, "period=point-in-time") {
		t.Errorf("a point-in-time report: exit %d, stderr:\n%s", code, stderr)
	}

	stderr = captureStderr(t, func() {
		code = run([]string{"verify-report", "--signer", reportFixturePath("other-signer.pub"), "--report", reportFixturePath("posture.json")})
	})
	if code != format.ExitUnverified || !strings.Contains(stderr, "signer: edmldsa1:") || strings.Contains(stderr, "VERIFIED") {
		t.Errorf("another signer: exit %d, stderr:\n%s", code, stderr)
	}
}

// Standard input is read when --report is "-", so a report can be piped straight from the API.
func TestVerifyReportCommandReadsStandardInput(t *testing.T) {
	silenceOutput(t)
	in, err := os.Open(reportFixturePath("posture.pretty.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	orig := os.Stdin
	os.Stdin = in
	t.Cleanup(func() { os.Stdin = orig })
	if code := run([]string{"verify-report", "--signer", reportFixturePath("signer.pub"), "--report", "-"}); code != 0 {
		t.Fatalf("verify-report --report - exited %d, want 0", code)
	}
}

// A period that is an object without integer bounds is described as such rather than as a window.
func TestDescribeReportPeriod(t *testing.T) {
	if got := describeReportPeriod(&format.VerifiedReport{}); got != "not-a-window" {
		t.Errorf("an object period without bounds: %q", got)
	}
}

func signerFingerprintOf(t *testing.T, path string) string {
	t.Helper()
	v, err := loadSignerFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return crypto.SignerFingerprint(v)
}
