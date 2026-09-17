package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/provision"
)

// preflightFakeDoer fakes the Cloudflare API for the cmd-level preflight test: each path
// serves a canned envelope. The zonesBody knob lets a test choose whether the requested
// --domain is covered (verified), missing (failed) or truncated-away (unknown).
type preflightFakeDoer struct {
	zonesBody string
}

func (d *preflightFakeDoer) Do(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet {
		return nil, fmt.Errorf("preflight must be read-only, got %s", req.Method)
	}
	path := req.URL.Path
	switch {
	case strings.HasPrefix(path, "/client/v4/zones"):
		return preflightResp(200, d.zonesBody), nil
	case strings.HasSuffix(path, "/subscriptions"):
		return preflightResp(200, `{"success":true,"errors":[],"result":[{"rate_plan":{"id":"workers_paid","public_name":"Workers Paid"}}]}`), nil
	case strings.HasSuffix(path, "/secrets_store/stores"):
		return preflightResp(200, `{"success":true,"errors":[],"result":[{"id":"st1","name":"default"}]}`), nil
	case strings.Contains(path, "/secrets_store/stores/st1/secrets"):
		return preflightResp(200, `{"success":true,"errors":[],"result":[],"result_info":{"total_count":1}}`), nil
	case strings.HasSuffix(path, "/logpush/jobs"):
		return preflightResp(200, `{"success":true,"errors":[],"result":[{"dataset":"workers_trace_events","enabled":true}]}`), nil
	case strings.HasSuffix(path, "/r2/buckets"):
		return preflightResp(200, `{"success":true,"errors":[],"result":{"buckets":[{"name":"archive"}]}}`), nil
	}
	return preflightResp(404, `{"success":false,"errors":[{"code":404,"message":"no such route"}]}`), nil
}

func preflightResp(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}
}

// withPreflightDoer installs a fake Doer for the duration of the test and restores the
// production nil afterwards, so cmdPreflight drives the canned API instead of the network.
func withPreflightDoer(t *testing.T, d provision.Doer) {
	t.Helper()
	preflightDoer = d
	t.Cleanup(func() { preflightDoer = nil })
}

// A single active zone the deploy-time checks can match a --domain against.
const oneActiveZone = `{"success":true,"errors":[],"result":[{"name":"example.com.au","status":"active"}],"result_info":{"total_count":1}}`

// TestPreflightMissingAccountExitsUsage: no --account is a clean usage error (6), checked
// before any network use.
func TestPreflightMissingAccountExitsUsage(t *testing.T) {
	silenceOutput(t)
	t.Setenv("CLOUDFLARE_API_TOKEN", "tok")
	got := run([]string{"preflight"})
	if got != format.ExitUsage {
		t.Fatalf("preflight with no --account = %d, want %d (ExitUsage)", got, format.ExitUsage)
	}
}

// TestPreflightMissingTokenExitsUsage: an --account but no CLOUDFLARE_API_TOKEN is a
// usage error (6), checked before any network use.
func TestPreflightMissingTokenExitsUsage(t *testing.T) {
	silenceOutput(t)
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	got := run([]string{"preflight", "--account", "acct"})
	if got != format.ExitUsage {
		t.Fatalf("preflight with no token = %d, want %d (ExitUsage)", got, format.ExitUsage)
	}
}

// TestPreflightDomainVerifiedExitsZero: a requested --domain that is covered by an active
// zone, with every other check passing, exits 0.
func TestPreflightDomainVerifiedExitsZero(t *testing.T) {
	silenceOutput(t)
	t.Setenv("CLOUDFLARE_API_TOKEN", "tok")
	withPreflightDoer(t, &preflightFakeDoer{zonesBody: oneActiveZone})
	got := run([]string{"preflight", "--account", "acct", "--domain", "example.com.au"})
	if got != 0 {
		t.Fatalf("preflight with a covered domain = %d, want 0", got)
	}
}

// TestPreflightDomainFailedExitsPreflight: a requested --domain that no active zone
// covers is an observed failure, so the run exits ExitPreflight (7) and never 0; a deploy
// script chained on the exit code must not proceed.
func TestPreflightDomainFailedExitsPreflight(t *testing.T) {
	silenceOutput(t)
	t.Setenv("CLOUDFLARE_API_TOKEN", "tok")
	withPreflightDoer(t, &preflightFakeDoer{zonesBody: oneActiveZone})
	got := run([]string{"preflight", "--account", "acct", "--domain", "nope.example"})
	if got != format.ExitPreflight {
		t.Fatalf("preflight with an uncovered domain = %d, want %d (ExitPreflight)", got, format.ExitPreflight)
	}
}

// TestPreflightDomainUnverifiedExitsPreflight: when the zone list is truncated the domain
// check is StatusUnknown (not failed). The operator asked for the verification, so an
// unanswered question must NOT exit 0; it exits ExitPreflight (7).
func TestPreflightDomainUnverifiedExitsPreflight(t *testing.T) {
	silenceOutput(t)
	t.Setenv("CLOUDFLARE_API_TOKEN", "tok")
	// One listed zone, but the account reports two total: the list is truncated, so a
	// domain that does not match the listed zone is not-observable, not observed-false.
	truncated := `{"success":true,"errors":[],"result":[{"name":"other.example","status":"active"}],"result_info":{"total_count":2}}`
	withPreflightDoer(t, &preflightFakeDoer{zonesBody: truncated})
	got := run([]string{"preflight", "--account", "acct", "--domain", "example.com.au"})
	if got != format.ExitPreflight {
		t.Fatalf("preflight with an unverifiable domain = %d, want %d (ExitPreflight)", got, format.ExitPreflight)
	}
}

// TestPreflightJSONOutput: the --json branch prints a JSON report (accountId and a checks
// array) to stdout and exits 0 when no domain is requested and every check passes.
func TestPreflightJSONOutput(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "tok")
	withPreflightDoer(t, &preflightFakeDoer{zonesBody: oneActiveZone})
	var code int
	out := captureStdout(t, func() {
		code = run([]string{"preflight", "--account", "acct-json", "--json"})
	})
	if code != 0 {
		t.Fatalf("preflight --json (no domain, all pass) = %d, want 0", code)
	}
	if !strings.Contains(out, `"accountId": "acct-json"`) {
		t.Errorf("--json output missing accountId; got:\n%s", out)
	}
	if !strings.Contains(out, `"checks"`) {
		t.Errorf("--json output missing checks array; got:\n%s", out)
	}
	if strings.Contains(out, "tok") {
		t.Errorf("--json output leaked the token; got:\n%s", out)
	}
}

// scopelessDoer refuses every read with a 403, the shape a token minted with none of the
// preflight's read scopes produces. Every check then degrades to StatusUnknown, which is
// the state the two tests below exist for: NOTHING was checked.
type scopelessDoer struct{}

func (d *scopelessDoer) Do(_ *http.Request) (*http.Response, error) {
	// The US spelling is Cloudflare's, not ours. This is their wire text for error 9109,
	// reproduced verbatim so the fixture asserts a message they actually send. Correcting
	// it to Australian spelling would make this test pass against a response that does not
	// exist, which is worse than the house-style breach the linter is reporting.
	//nolint:misspell // verbatim Cloudflare API error body
	return preflightResp(403, `{"success":false,"errors":[{"code":9109,"message":"Unauthorized to access requested resource"}]}`), nil
}

// TestPreflightUncheckedIsNotClearanceToDeploy is the "cannot check is not a pass" gate,
// and it asserts on the CLOSING SENTENCE, not only the exit code.
//
// WHAT WENT WRONG WITHOUT IT. The summary counted StatusFailed and nothing else, so a
// token that could read none of the five sources printed five [?] lines and then
// "no failures: deploy when the todo items you need are in place." at exit 0. The count
// was true and the sentence built on it was not: an operator reads that as clearance and
// a deploy script reads the 0 the same way. That is the one place in this tool where
// being wrong means a deploy.
//
// The exit-code assertion alone could not have caught the printed half, so the printed
// half is asserted first and separately.
func TestPreflightUncheckedIsNotClearanceToDeploy(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "tok")
	withPreflightDoer(t, &scopelessDoer{})
	var code int
	out, _ := captureOutput(t, func() {
		code = run([]string{"preflight", "--account", "acct"})
	})
	// The control: this fixture really does produce a report of nothing but unknowns, so
	// the assertions below are about the summary and not about an accidentally clean run.
	if n := strings.Count(out, "[?   ]"); n != 5 {
		t.Fatalf("fixture control: want 5 unknown checks in the report, got %d\n%s", n, out)
	}
	if strings.Contains(out, "[FAIL]") || strings.Contains(out, "[ok  ]") {
		t.Fatalf("fixture control: a scopeless token must produce no failed and no verified check\n%s", out)
	}
	if strings.Contains(out, "no failures: deploy") {
		t.Errorf("a report of five unanswered checks must NOT print the deploy clearance line:\n%s", out)
	}
	if !strings.Contains(out, "5 check(s) could NOT be checked with this token") {
		t.Errorf("the summary must count the checks that could not run, by name:\n%s", out)
	}
	if !strings.Contains(out, "NOT clearance to deploy") {
		t.Errorf("the summary must say plainly that this is not clearance to deploy:\n%s", out)
	}
	if code != format.ExitPreflight {
		t.Errorf("preflight over an all-unknown report = %d, want %d (ExitPreflight)", code, format.ExitPreflight)
	}
}

// TestPreflightJSONExitsOnFailedCheck: --json and the text report must reach the SAME
// verdict from the same account state.
//
// WHAT WENT WRONG WITHOUT IT. The --json branch was `return enc.Encode(report)`, sitting
// ABOVE both exit gates, so it returned nil whatever the report said. The identical
// account state exited 7 without --json and 0 with it, and the payload the script read at
// exit 0 carried "status": "failed" in it. A script chaining `preflight --json && deploy`
// deployed on a failed check.
//
// The payload is asserted as well as the code, so a "fix" that reached the right exit by
// dropping the report on the floor fails here.
func TestPreflightJSONExitsOnFailedCheck(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "tok")
	withPreflightDoer(t, &preflightFakeDoer{zonesBody: oneActiveZone})

	// The control: the same account state, the same flags bar --json, is a 7. Without
	// this the assertion below could pass against a report that was failing for some
	// reason unrelated to --json.
	var textCode int
	silenceOutput(t)
	textCode = run([]string{"preflight", "--account", "acct", "--domain", "nope.example"})
	if textCode != format.ExitPreflight {
		t.Fatalf("control: the text report over the same state = %d, want %d", textCode, format.ExitPreflight)
	}

	var code int
	out := captureStdout(t, func() {
		code = run([]string{"preflight", "--account", "acct", "--domain", "nope.example", "--json"})
	})
	if !strings.Contains(out, `"status": "failed"`) {
		t.Fatalf("the JSON payload must still be printed in full, carrying the failed check:\n%s", out)
	}
	if code != format.ExitPreflight {
		t.Errorf("preflight --json over a failed check = %d, want %d (ExitPreflight): the exit code is the only part of this a script reads", code, format.ExitPreflight)
	}
}

// TestPreflightJSONMatchesTextExitAcrossReports drives both output formats over the three
// report shapes and asserts they never disagree. The clean case is the control: it proves
// the two agreeing is a fact about the reports rather than about a gate that now refuses
// everything.
func TestPreflightJSONMatchesTextExitAcrossReports(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "tok")
	cases := []struct {
		name string
		doer provision.Doer
		args []string
		want int
	}{
		{"clean", &preflightFakeDoer{zonesBody: oneActiveZone}, []string{"--domain", "example.com.au"}, 0},
		{"failed domain", &preflightFakeDoer{zonesBody: oneActiveZone}, []string{"--domain", "nope.example"}, format.ExitPreflight},
		{"nothing checkable", &scopelessDoer{}, nil, format.ExitPreflight},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			silenceOutput(t)
			withPreflightDoer(t, tc.doer)
			text := run(append([]string{"preflight", "--account", "acct"}, tc.args...))
			asJSON := run(append([]string{"preflight", "--account", "acct", "--json"}, tc.args...))
			if text != tc.want || asJSON != tc.want {
				t.Errorf("text = %d, --json = %d, want %d for both", text, asJSON, tc.want)
			}
		})
	}
}

// TestPreflightVerdictBackstopsAnUnverifiedDomain pins the backstop in judgePreflight's
// err(): the failed and unchecked counts are a whitelist of two statuses, so a domain
// check arriving at any OTHER status must still refuse rather than fall through to 0. No
// live check emits StatusConfigured for a domain today, which is exactly why the branch
// is asserted here directly rather than left to a future report shape to discover.
func TestPreflightVerdictBackstopsAnUnverifiedDomain(t *testing.T) {
	report := &provision.AccountPreflight{
		AccountID: "acct",
		Checks: []provision.PreflightCheck{
			{ID: "domain", Name: "Deployment domain", Status: provision.StatusConfigured, Evidence: "present but unproven"},
		},
	}
	v := judgePreflight(report, "example.com.au")
	if v.failed != 0 || v.unchecked != 0 {
		t.Fatalf("control: this report has no failed and no unknown check, got failed=%d unchecked=%d", v.failed, v.unchecked)
	}
	if v.domainVerified {
		t.Fatal("a domain check that is not StatusVerified must leave domainVerified false")
	}
	err := v.err()
	var ee *format.ExitError
	if !errors.As(err, &ee) || ee.Code != format.ExitPreflight {
		t.Fatalf("an unverified requested domain must exit %d, got %v", format.ExitPreflight, err)
	}
	if !strings.Contains(v.summary(), "still not verified") {
		t.Errorf("the summary must say the domain was not verified:\n%s", v.summary())
	}
}

// TestPreflightCleanReportStillClears is the control for the two gates above: a report
// with nothing failed and nothing unchecked must still print the clearance line and exit
// 0. Without it, a gate that simply refused every report would pass every other
// assertion in this file.
func TestPreflightCleanReportStillClears(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "tok")
	withPreflightDoer(t, &preflightFakeDoer{zonesBody: oneActiveZone})
	var code int
	out, _ := captureOutput(t, func() {
		code = run([]string{"preflight", "--account", "acct", "--domain", "example.com.au"})
	})
	if code != 0 {
		t.Fatalf("a clean report = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "no failures: deploy when the todo items you need are in place.") {
		t.Errorf("a clean report must still clear the operator to deploy:\n%s", out)
	}
	if strings.Contains(out, "NOT clearance to deploy") {
		t.Errorf("a clean report must not carry the unchecked caveat:\n%s", out)
	}
}
