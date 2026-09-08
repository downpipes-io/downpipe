package provision

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// preflightDoer fakes the Cloudflare API for the read-only preflight: each path serves
// a canned envelope; flags exercise the 403-degrade, 401-abort, 5xx-transient,
// pagination and decode-failure paths.
type preflightDoer struct {
	forbidden      map[string]bool // path prefix -> 403
	serverError    map[string]bool // path prefix -> 500 (transient)
	unauthorised   bool            // every call -> 401 (an invalid token)
	manyZones      bool            // zones span two pages (50 filler + the real one)
	garbageZones   bool            // zones result is not an array (decode failure)
	vagueSub       bool            // subscription is workers-shaped but not a known paid id
	r2NotEnabled   bool            // R2 list returns the affirmative 10042 "not entitled" answer
	r2APIError     bool            // R2 list returns a non-transient API error that is NOT 10042
	noSecretsStore bool            // secrets_store/stores returns an empty result (no store yet)
	secretsCount   *int            // override the per-store secret total_count (nil = 97)
	calls          []string
}

func (d *preflightDoer) Do(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet {
		return nil, fmt.Errorf("preflight must be read-only, got %s %s", req.Method, req.URL.Path)
	}
	if req.URL.Host != "api.cloudflare.com" {
		return nil, fmt.Errorf("preflight must talk only to api.cloudflare.com, got %s", req.URL.Host)
	}
	if req.Header.Get("Authorization") != "Bearer tok" {
		return nil, fmt.Errorf("missing bearer")
	}
	path := req.URL.Path
	if req.URL.RawQuery != "" {
		path += "?" + req.URL.RawQuery
	}
	d.calls = append(d.calls, path)
	if d.unauthorised {
		return resp(401, `{"success":false,"errors":[{"code":10000,"message":"authentication error"}]}`), nil
	}
	for prefix := range d.forbidden {
		if strings.HasPrefix(req.URL.Path, prefix) {
			return resp(403, `{"success":false,"errors":[{"code":10000,"message":"forbidden"}]}`), nil
		}
	}
	for prefix := range d.serverError {
		if strings.HasPrefix(req.URL.Path, prefix) {
			return resp(500, `oops`), nil
		}
	}
	switch {
	case strings.HasPrefix(req.URL.Path, "/client/v4/zones"):
		if d.garbageZones {
			return resp(200, `{"success":true,"errors":[],"result":{"not":"an array"}}`), nil
		}
		if d.manyZones {
			// Two pages: 50 filler zones then the real one; total_count reports 51.
			if strings.Contains(req.URL.RawQuery, "page=1") {
				items := make([]string, 0, 50)
				for i := 0; i < 50; i++ {
					items = append(items, fmt.Sprintf(`{"name":"filler-%02d.example","status":"active"}`, i))
				}
				return resp(200, `{"success":true,"errors":[],"result":[`+strings.Join(items, ",")+`],"result_info":{"total_count":51}}`), nil
			}
			return resp(200, `{"success":true,"errors":[],"result":[{"name":"example.com.au","status":"active"}],"result_info":{"total_count":51}}`), nil
		}
		return resp(200, `{"success":true,"errors":[],"result":[{"name":"example.com.au","status":"active"},{"name":"pending.example","status":"pending"}],"result_info":{"total_count":2}}`), nil
	case strings.HasSuffix(req.URL.Path, "/subscriptions"):
		if d.vagueSub {
			return resp(200, `{"success":true,"errors":[],"result":[{"rate_plan":{"id":"biz_workers_bundle","public_name":"Workers Bundle"}}]}`), nil
		}
		return resp(200, `{"success":true,"errors":[],"result":[{"rate_plan":{"id":"workers_paid","public_name":"Workers Paid"}}]}`), nil
	case strings.HasSuffix(req.URL.Path, "/secrets_store/stores"):
		if d.noSecretsStore {
			// A new account that has never added a secret has no Secrets Store yet.
			return resp(200, `{"success":true,"errors":[],"result":[]}`), nil
		}
		return resp(200, `{"success":true,"errors":[],"result":[{"id":"st1","name":"default"}]}`), nil
	case strings.Contains(req.URL.Path, "/secrets_store/stores/st1/secrets"):
		count := 97
		if d.secretsCount != nil {
			count = *d.secretsCount
		}
		return resp(200, fmt.Sprintf(`{"success":true,"errors":[],"result":[],"result_info":{"total_count":%d}}`, count)), nil
	case strings.HasSuffix(req.URL.Path, "/logpush/jobs"):
		return resp(200, `{"success":true,"errors":[],"result":[{"dataset":"workers_trace_events","enabled":true},{"dataset":"http_requests","enabled":true}]}`), nil
	case strings.HasSuffix(req.URL.Path, "/r2/buckets"):
		if d.r2NotEnabled {
			// Cloudflare's affirmative "this account is not entitled to use R2" answer.
			return resp(403, `{"success":false,"errors":[{"code":10042,"message":"Please enable R2 through the Cloudflare Dashboard."}]}`), nil
		}
		if d.r2APIError {
			// A non-transient API failure that is NOT 10042 (a malformed/4xx error). The
			// message embeds the bearer token so the test can prove the evidence is run
			// through redactToken before it reaches the report.
			return resp(400, `{"success":false,"errors":[{"code":7003,"message":"could not route to tok, perhaps your object identifier is invalid?"}]}`), nil
		}
		return resp(200, `{"success":true,"errors":[],"result":{"buckets":[{"name":"archive"},{"name":"media"}]}}`), nil
	}
	return resp(404, `{"success":false,"errors":[{"code":404,"message":"no such route"}]}`), nil
}

func resp(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}
}

func checkByID(t *testing.T, r *AccountPreflight, id string) PreflightCheck {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check %q in %+v", id, r.Checks)
	return PreflightCheck{}
}

func TestPreflightHealthyAccount(t *testing.T) {
	d := &preflightDoer{forbidden: map[string]bool{}}
	c, err := NewClient("acc123", "tok", d)
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Preflight("downpipe-engine.example.com.au")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Zones) != 2 || r.Zones[0].Name != "example.com.au" {
		t.Fatalf("zones not listed: %+v", r.Zones)
	}
	if got := checkByID(t, r, "domain"); got.Status != StatusVerified || !strings.Contains(got.Evidence, "example.com.au") {
		t.Fatalf("domain should verify against the active zone: %+v", got)
	}
	if got := checkByID(t, r, "workers-plan"); got.Status != StatusVerified || !strings.Contains(got.Evidence, "Workers Paid") {
		t.Fatalf("workers plan should be observed: %+v", got)
	}
	// 97 of 100 used leaves 3 free; the threshold is secretsStoreMinFree (6), so 3 < 6 = FAILED.
	if got := checkByID(t, r, "secrets-store"); got.Status != StatusFailed || !strings.Contains(got.Evidence, "97") {
		t.Fatalf("secrets-store headroom should fail at 3 free: %+v", got)
	}
	if got := checkByID(t, r, "logpush"); got.Status != StatusVerified {
		t.Fatalf("logpush job should verify: %+v", got)
	}
	if got := checkByID(t, r, "r2"); got.Status != StatusVerified || len(r.R2Buckets) != 2 {
		t.Fatalf("r2 buckets should list: %+v %v", got, r.R2Buckets)
	}
}

// TestPreflightSecretsStoreHeadroomBoundary pins the headroom threshold: with
// secretsStoreMinFree free slots the check passes, and with one fewer it fails. This
// guards against a silent drift of the secretsStoreMinFree constant.
func TestPreflightSecretsStoreHeadroomBoundary(t *testing.T) {
	pass := secretsStoreDocumentedLimit - secretsStoreMinFree // 6 free
	fail := pass + 1                                          // 5 free
	cases := []struct {
		name string
		used int
		want PreflightStatus
	}{
		{"exactly minimum free passes", pass, StatusVerified},
		{"one below minimum free fails", fail, StatusFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			used := tc.used
			d := &preflightDoer{forbidden: map[string]bool{}, secretsCount: &used}
			c, err := NewClient("acc123", "tok", d)
			if err != nil {
				t.Fatal(err)
			}
			r, err := c.Preflight("downpipe-engine.example.com.au")
			if err != nil {
				t.Fatal(err)
			}
			if got := checkByID(t, r, "secrets-store"); got.Status != tc.want {
				t.Fatalf("used=%d want %s, got %+v", tc.used, tc.want, got)
			}
		})
	}
}

func TestPreflightNoSecretsStoreIsUnconfigured(t *testing.T) {
	// A brand-new account that has never added a secret has no Secrets Store. The
	// preflight must report this distinct first-run state as unconfigured with the
	// actionable remediation, never as a failure or a silent gap.
	d := &preflightDoer{noSecretsStore: true}
	c, _ := NewClient("acc123", "tok", d)
	r, err := c.Preflight("")
	if err != nil {
		t.Fatal(err)
	}
	got := checkByID(t, r, "secrets-store")
	if got.Status != StatusUnconfigured || !strings.Contains(got.Evidence, "no Secrets Store") {
		t.Fatalf("an account with no Secrets Store must be unconfigured: %+v", got)
	}
	if got.Remediation == "" {
		t.Fatalf("the no-store state must carry a non-empty remediation: %+v", got)
	}
}

func TestPreflightDomainNotOnAccount(t *testing.T) {
	d := &preflightDoer{forbidden: map[string]bool{}}
	c, _ := NewClient("acc123", "tok", d)
	r, err := c.Preflight("engine.other-company.net")
	if err != nil {
		t.Fatal(err)
	}
	got := checkByID(t, r, "domain")
	if got.Status != StatusFailed || got.Remediation == "" {
		t.Fatalf("an uncovered domain must FAIL with a remediation: %+v", got)
	}
	// A pending (not active) zone must not cover a domain.
	r2, _ := c.Preflight("x.pending.example")
	if got := checkByID(t, r2, "domain"); got.Status != StatusFailed {
		t.Fatalf("a pending zone must not verify a domain: %+v", got)
	}
}

func TestPreflightScopeDegradesToUnknown(t *testing.T) {
	d := &preflightDoer{forbidden: map[string]bool{"/client/v4/zones": true, "/client/v4/accounts/acc123/logpush": true}}
	c, _ := NewClient("acc123", "tok", d)
	r, err := c.Preflight("")
	if err != nil {
		t.Fatal(err)
	}
	if got := checkByID(t, r, "zones"); got.Status != StatusUnknown || !strings.Contains(got.Remediation, "Zone:Read") {
		t.Fatalf("a forbidden zone read must degrade to unknown with the scope remediation: %+v", got)
	}
	if got := checkByID(t, r, "logpush"); got.Status != StatusUnknown {
		t.Fatalf("a forbidden logpush read must degrade to unknown: %+v", got)
	}
	// The other checks still ran (a scope gap never aborts the preflight).
	if got := checkByID(t, r, "workers-plan"); got.Status != StatusVerified {
		t.Fatalf("other checks must still run: %+v", got)
	}
}

func TestPreflightIsReadOnly(t *testing.T) {
	d := &preflightDoer{forbidden: map[string]bool{}}
	c, _ := NewClient("acc123", "tok", d)
	if _, err := c.Preflight("example.com.au"); err != nil {
		t.Fatal(err)
	}
	for _, call := range d.calls {
		if !strings.HasPrefix(call, "/client/v4/") {
			t.Fatalf("unexpected call target: %s", call)
		}
	}
	// The doer itself rejects any non-GET and any non-api.cloudflare.com host, so
	// reaching here proves read-only against the pinned host.
}

func TestPreflightInvalidTokenAborts(t *testing.T) {
	// A 401 is not a scope gap: the whole preflight must abort with a clear error
	// (six unknowns + exit 0 would let a script deploy on a dead token).
	d := &preflightDoer{unauthorised: true}
	c, _ := NewClient("acc123", "tok", d)
	r, err := c.Preflight("")
	if err == nil || r != nil {
		t.Fatalf("an invalid token must abort the preflight, got report %+v err %v", r, err)
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("the abort must name the 401 cause: %v", err)
	}
}

func TestPreflightDomainCheckSurvivesUnreadableZones(t *testing.T) {
	// --domain was explicitly requested: when zones cannot be read the report must
	// still carry a domain check (unknown), never silently omit the asked question.
	d := &preflightDoer{forbidden: map[string]bool{"/client/v4/zones": true}}
	c, _ := NewClient("acc123", "tok", d)
	r, err := c.Preflight("engine.example.com.au")
	if err != nil {
		t.Fatal(err)
	}
	got := checkByID(t, r, "domain")
	if got.Status != StatusUnknown || !strings.Contains(got.Evidence, "NOT verified") {
		t.Fatalf("an unverifiable requested domain must be reported unknown: %+v", got)
	}
}

func TestPreflightDomainNormalisation(t *testing.T) {
	d := &preflightDoer{}
	c, _ := NewClient("acc123", "tok", d)
	// Mixed case + a trailing dot must match the API's lowercased zone name.
	r, err := c.Preflight("Engine.Example.COM.AU.")
	if err != nil {
		t.Fatal(err)
	}
	if got := checkByID(t, r, "domain"); got.Status != StatusVerified {
		t.Fatalf("case/trailing-dot variants must verify: %+v", got)
	}
	// A Unicode (non-punycode) name is refused with the actionable form, not a false FAIL.
	if _, err := c.Preflight("engine.bücher.example"); err == nil || !strings.Contains(err.Error(), "punycode") {
		t.Fatalf("a non-ASCII domain must be refused with the punycode hint, got %v", err)
	}
}

func TestPreflightZonePagination(t *testing.T) {
	// The matching zone sits on page 2 of 51 zones: pagination must find it rather
	// than failing the domain against a truncated first page.
	d := &preflightDoer{manyZones: true}
	c, _ := NewClient("acc123", "tok", d)
	r, err := c.Preflight("engine.example.com.au")
	if err != nil {
		t.Fatal(err)
	}
	if got := checkByID(t, r, "domain"); got.Status != StatusVerified {
		t.Fatalf("a page-2 zone must still verify the domain: %+v", got)
	}
	if len(r.Zones) != 51 {
		t.Fatalf("all pages must be collected, got %d zones", len(r.Zones))
	}
}

func TestPreflightTransientFaultIsUnknownNotFailed(t *testing.T) {
	// A 5xx means the fact was not observable: the check must degrade to unknown,
	// never assert an account fact (R2 "not enabled", plan "failed").
	d := &preflightDoer{serverError: map[string]bool{
		"/client/v4/accounts/acc123/subscriptions": true,
		"/client/v4/accounts/acc123/r2":            true,
	}}
	c, _ := NewClient("acc123", "tok", d)
	r, err := c.Preflight("")
	if err != nil {
		t.Fatal(err)
	}
	if got := checkByID(t, r, "workers-plan"); got.Status != StatusUnknown || !strings.Contains(got.Evidence, "transient") {
		t.Fatalf("a 5xx on subscriptions must be unknown: %+v", got)
	}
	if got := checkByID(t, r, "r2"); got.Status != StatusUnknown || !strings.Contains(got.Evidence, "not evidence") {
		t.Fatalf("a 5xx on R2 must not claim R2 is absent: %+v", got)
	}
}

func TestPreflightR2NotEnabledIsUnconfigured(t *testing.T) {
	// The ONLY R2 absence: Cloudflare itself reports the account is not entitled to use
	// R2 (code 10042). That affirmative answer reads as unconfigured, with the
	// enable-or-use-S3 remediation.
	d := &preflightDoer{r2NotEnabled: true}
	c, _ := NewClient("acc123", "tok", d)
	r, err := c.Preflight("")
	if err != nil {
		t.Fatal(err)
	}
	got := checkByID(t, r, "r2")
	if got.Status != StatusUnconfigured {
		t.Fatalf("an affirmative R2-not-enabled (10042) must be unconfigured: %+v", got)
	}
	if got.Remediation == "" || !strings.Contains(got.Remediation, "S3-compatible") {
		t.Fatalf("R2-not-enabled must carry the enable-or-S3 remediation: %+v", got)
	}
}

func TestPreflightR2APIErrorIsFailedNotUnconfigured(t *testing.T) {
	// A NON-transient R2 API error that is not the affirmative "not enabled" answer (here
	// a 400/code 7003) must FAIL with the redacted detail, never be mis-attributed as "R2
	// not enabled" (which would mask a real outage as a missing feature). This mirrors the
	// zones/workers-plan/logpush error branches.
	d := &preflightDoer{r2APIError: true}
	c, _ := NewClient("acc123", "tok", d)
	r, err := c.Preflight("")
	if err != nil {
		t.Fatal(err)
	}
	got := checkByID(t, r, "r2")
	if got.Status != StatusFailed {
		t.Fatalf("a non-transient R2 API error must be FAILED, not unconfigured/unknown: %+v", got)
	}
	// The old behaviour asserted absence; the fixed behaviour surfaces the real error.
	if strings.Contains(got.Evidence, "not enabled") || strings.Contains(got.Evidence, "does not appear") {
		t.Fatalf("a real R2 outage must not be reported as 'R2 not enabled': %+v", got)
	}
	// The API detail must reach the evidence (status/code carried through), proving the
	// failure is surfaced rather than swallowed.
	if !strings.Contains(got.Evidence, "7003") {
		t.Fatalf("the API error detail must be surfaced in the evidence: %+v", got)
	}
	// Defence in depth: the bearer token embedded in the error must be redacted out.
	if strings.Contains(got.Evidence, "tok") {
		t.Fatalf("the token must be redacted from the R2 failure evidence: %q", got.Evidence)
	}
	if !strings.Contains(got.Evidence, "[redacted]") {
		t.Fatalf("the redaction marker must be present where the token was: %q", got.Evidence)
	}
}

func TestPreflightVagueSubscriptionIsConfiguredNotVerified(t *testing.T) {
	// A workers-shaped but unrecognised rate plan must not over-claim "verified":
	// the deploy-time [limits] gate is the proof, and the evidence says so.
	d := &preflightDoer{vagueSub: true}
	c, _ := NewClient("acc123", "tok", d)
	r, err := c.Preflight("")
	if err != nil {
		t.Fatal(err)
	}
	got := checkByID(t, r, "workers-plan")
	if got.Status != StatusConfigured || !strings.Contains(got.Evidence, "Workers Bundle") {
		t.Fatalf("an unrecognised workers-shaped plan must be configured (honest), got %+v", got)
	}
}

func TestPreflightZoneDecodeFailureIsPerCheck(t *testing.T) {
	// A malformed zones payload must fail THAT check and keep the run alive (the
	// other checks still report), never abort the whole preflight.
	d := &preflightDoer{garbageZones: true}
	c, _ := NewClient("acc123", "tok", d)
	r, err := c.Preflight("")
	if err != nil {
		t.Fatal(err)
	}
	if got := checkByID(t, r, "zones"); got.Status != StatusFailed || !strings.Contains(got.Evidence, "parsed") {
		t.Fatalf("a garbage zones payload must fail the zones check: %+v", got)
	}
	if got := checkByID(t, r, "workers-plan"); got.Status != StatusVerified {
		t.Fatalf("the other checks must still run after a zones decode failure: %+v", got)
	}
}
