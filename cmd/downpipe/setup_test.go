package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/provision"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what it wrote.
// os.Stderr is sent to /dev/null so plan-apply chatter does not pollute the test log.
// This lets the dry-run tests assert that the plan was printed and nothing was created.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	// Open /dev/null write-only: os.Open is O_RDONLY, so writes to the redirected
	// stderr fd would return EBADF and be silently discarded rather than written to
	// the null device. This matches silenceOutput in main_test.go.
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout = w
	os.Stderr = null
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, readErr := r.Read(buf)
			if n > 0 {
				b.Write(buf[:n])
			}
			if readErr != nil {
				break
			}
		}
		done <- b.String()
	}()
	fn()
	_ = w.Close()
	out := <-done
	os.Stdout, os.Stderr = origOut, origErr
	_ = r.Close()
	_ = null.Close()
	return out
}

// selftestArchiveRunID builds a self-test archive and returns only its run ID, for the
// keyless paths (attest, inspect without a signer) that need the run ID and nothing from
// the keypair. It avoids the blank-identity, blank-verifier discard at each call site.
func selftestArchiveRunID(t *testing.T, dir string, value []byte) string {
	t.Helper()
	_, _, runID, err := buildSelftestArchive(dir, value)
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	return runID
}

// setBaseEnv sets a valid token and account for a setup run. t.Setenv restores them after
// the test, and it fails if the test is parallel, which is correct here.
func setBaseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CLOUDFLARE_API_TOKEN", "test-token-should-not-print")
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "acct-test")
}

// TestSetupMissingTokenExitsUsage covers the clean missing-token failure: no
// CLOUDFLARE_API_TOKEN means a usage exit (6), checked before any network use.
func TestSetupMissingTokenExitsUsage(t *testing.T) {
	silenceOutput(t)
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "acct-test")
	got := run([]string{"setup", "--access-domains", "console.example.com", "--allow-emails", "o@example.com"})
	if got != format.ExitUsage {
		t.Fatalf("setup with no token = %d, want %d (ExitUsage)", got, format.ExitUsage)
	}
}

// TestSetupMissingAccountExitsUsage covers the missing-account failure: a token but no
// CLOUDFLARE_ACCOUNT_ID is a usage exit (6).
func TestSetupMissingAccountExitsUsage(t *testing.T) {
	silenceOutput(t)
	t.Setenv("CLOUDFLARE_API_TOKEN", "test-token")
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "")
	got := run([]string{"setup", "--access-domains", "console.example.com", "--allow-emails", "o@example.com"})
	if got != format.ExitUsage {
		t.Fatalf("setup with no account = %d, want %d (ExitUsage)", got, format.ExitUsage)
	}
}

// TestSetupDryRunPrintsPlanCreatesNothing is the central command test: a dry run (the
// default, no --apply) prints the ordered plan and makes no network call. The command
// never constructs a live client in this path, so the absence of any real call is
// structural; the test asserts the plan was printed and the "nothing was created" line is
// present, and that the token never appears in the output.
func TestSetupDryRunPrintsPlanCreatesNothing(t *testing.T) {
	setBaseEnv(t)
	var code int
	out := captureStdout(t, func() {
		code = run([]string{
			"setup",
			"--app-name", "downpipes prod",
			"--access-domains", "console.example.com,engine.example.com",
			"--allow-email-domains", "example.com",
			"--email-from", "alerts@example.com",
		})
	})
	if code != 0 {
		t.Fatalf("dry-run setup exit = %d, want 0", code)
	}
	if !strings.Contains(out, "plan for account acct-test") {
		t.Errorf("dry-run output missing the plan header:\n%s", out)
	}
	if !strings.Contains(out, "access-app") || !strings.Contains(out, "access-policy") {
		t.Errorf("dry-run output missing the Access actions:\n%s", out)
	}
	if !strings.Contains(out, "dry run: nothing was created") {
		t.Errorf("dry-run output missing the 'nothing was created' notice:\n%s", out)
	}
	if strings.Contains(out, "test-token-should-not-print") {
		t.Errorf("dry-run output leaked the API token:\n%s", out)
	}
}

// TestSetupDryRunFromConfigFile confirms the --config path is parsed and planned, and
// that the secret value never appears in the dry-run plan (the plan holds names only).
func TestSetupDryRunFromConfigFile(t *testing.T) {
	setBaseEnv(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "setup.json")
	cfg := `{
  "AppName": "downpipes prod",
  "AccessDomains": ["console.example.com"],
  "AllowedEmailDomains": ["example.com"],
  "Secrets": [{"Store": "store-1", "Name": "signer-private", "Summary": "engine signer private"}],
  "Sources": [{"Var": "SRC_KV", "Type": "kv", "ID": "kvns-abc"}],
  "Destination": {"Var": "DEST_R2", "Bucket": "downpipes-archives"}
}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	// A secret value in the environment must NOT appear in the dry-run plan.
	t.Setenv("DOWNPIPE_SECRET_SIGNER_PRIVATE", "SENTINEL-SECRET-VALUE")
	var code int
	out := captureStdout(t, func() {
		code = run([]string{"setup", "--config", cfgPath})
	})
	if code != 0 {
		t.Fatalf("dry-run from config exit = %d, want 0", code)
	}
	if !strings.Contains(out, "source-binding") || !strings.Contains(out, "destination-binding") {
		t.Errorf("config plan missing binding actions:\n%s", out)
	}
	if strings.Contains(out, "SENTINEL-SECRET-VALUE") {
		t.Errorf("dry-run plan leaked a secret value:\n%s", out)
	}
}

// TestSetupInvalidConfigExitsUsage confirms a config that fails validation (here a
// workers.dev hostname, which the house rules forbid) is a usage exit, not a crash.
func TestSetupInvalidConfigExitsUsage(t *testing.T) {
	silenceOutput(t)
	setBaseEnv(t)
	got := run([]string{
		"setup",
		"--access-domains", "thing.workers.dev",
		"--allow-emails", "o@example.com",
	})
	if got != format.ExitUsage {
		t.Fatalf("setup with workers.dev hostname = %d, want %d (ExitUsage)", got, format.ExitUsage)
	}
}

// TestSetupMissingConfigFileExitsUsage confirms an unreadable --config path is a usage
// error.
func TestSetupMissingConfigFileExitsUsage(t *testing.T) {
	silenceOutput(t)
	setBaseEnv(t)
	got := run([]string{"setup", "--config", "/no/such/file.json"})
	if got != format.ExitUsage {
		t.Fatalf("setup with missing config = %d, want %d (ExitUsage)", got, format.ExitUsage)
	}
}

// fakeProvisioner is an in-memory Provisioner double for the applyPlan unit test, so the
// apply-reporting path is covered without any network or live client.
type fakeProvisioner struct {
	results []provision.Result
	err     error
	gotPlan provision.Plan
	gotSecs map[string]string
}

func (f *fakeProvisioner) Apply(plan provision.Plan, secrets map[string]string) ([]provision.Result, error) {
	f.gotPlan = plan
	f.gotSecs = secrets
	return f.results, f.err
}

// TestApplyPlanReportsSuccess confirms applyPlan returns nil and reports each result when
// every action succeeded.
func TestApplyPlanReportsSuccess(t *testing.T) {
	silenceOutput(t)
	plan := provision.Plan{AccountID: "acct", Actions: []provision.Action{{Kind: provision.KindAccessApp, Name: "app"}}}
	fp := &fakeProvisioner{results: []provision.Result{{Action: plan.Actions[0], OK: true, ID: "app-1", Detail: "applied"}}}
	if err := applyPlan(fp, plan, nil); err != nil {
		t.Fatalf("applyPlan = %v, want nil", err)
	}
	if fp.gotPlan.AccountID != "acct" {
		t.Errorf("applyPlan did not pass the plan through to the provisioner")
	}
}

// TestApplyPlanReportsFailure confirms applyPlan returns a non-zero ExitError when the
// provisioner reports an error, so a partial provision exits non-zero.
func TestApplyPlanReportsFailure(t *testing.T) {
	silenceOutput(t)
	plan := provision.Plan{AccountID: "acct", Actions: []provision.Action{{Kind: provision.KindAccessApp, Name: "app"}}}
	fp := &fakeProvisioner{
		results: []provision.Result{{Action: plan.Actions[0], OK: false, Detail: "boom"}},
		err:     errors.New("boom"),
	}
	err := applyPlan(fp, plan, nil)
	if err == nil {
		t.Fatal("applyPlan with a provisioner error = nil, want a non-zero ExitError")
	}
	var ee *format.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("applyPlan error is not an ExitError: %v", err)
	}
	if ee.Code != 1 {
		t.Errorf("applyPlan exit code = %d, want 1", ee.Code)
	}
}

// TestSecretEnvVar locks in the secret-name to environment-variable mapping, which is the
// only place secret values come from at apply time.
func TestSecretEnvVar(t *testing.T) {
	cases := map[string]string{
		"signer-private":   "DOWNPIPE_SECRET_SIGNER_PRIVATE",
		"recipient.public": "DOWNPIPE_SECRET_RECIPIENT_PUBLIC",
		"k1":               "DOWNPIPE_SECRET_K1",
		"a b":              "DOWNPIPE_SECRET_A_B",
	}
	for name, want := range cases {
		if got := secretEnvVar(name); got != want {
			t.Errorf("secretEnvVar(%q) = %q, want %q", name, got, want)
		}
	}
}

// TestGatherSecretValuesMissingErrors confirms a declared secret with no environment
// value is a usage error before any call, and that a present value is read.
func TestGatherSecretValuesMissingErrors(t *testing.T) {
	secrets := []provision.SecretEntry{{Store: "s", Name: "k1"}}
	// No env var set: a usage error.
	if _, err := gatherSecretValues(secrets); err == nil {
		t.Fatal("gatherSecretValues with no env value = nil, want a usage error")
	} else {
		var ee *format.ExitError
		if !errors.As(err, &ee) || ee.Code != format.ExitUsage {
			t.Errorf("gatherSecretValues error = %v, want ExitUsage", err)
		}
	}
	// With the value set, it is read.
	t.Setenv("DOWNPIPE_SECRET_K1", "the-value")
	got, err := gatherSecretValues(secrets)
	if err != nil {
		t.Fatalf("gatherSecretValues = %v, want nil", err)
	}
	if got["k1"] != "the-value" {
		t.Errorf("gatherSecretValues[k1] = %q, want the-value", got["k1"])
	}
}

// TestSplitCSV covers the comma-list flag parser.
func TestSplitCSV(t *testing.T) {
	if got := splitCSV(""); got != nil {
		t.Errorf("splitCSV(\"\") = %v, want nil", got)
	}
	got := splitCSV(" a , b ,, c ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("splitCSV = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("splitCSV[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
