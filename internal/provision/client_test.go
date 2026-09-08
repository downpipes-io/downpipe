package provision

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// recordedRequest is a captured request shape: the fake Doer records method, path,
// the Authorization header, and the decoded JSON body so a test can assert the exact
// requests a real apply would issue, without any network.
type recordedRequest struct {
	method string
	path   string
	auth   string
	body   map[string]any
}

// fakeDoer is an in-memory http.Doer double. It records each request and replies with a
// canned Cloudflare success envelope. responses, when set, supplies a per-call result id
// (used to hand back the created Access application id); otherwise the id is empty.
type fakeDoer struct {
	requests  []recordedRequest
	responses []string // result.id to return for the Nth call
	status    int      // status code to return (0 -> 200)
	failBody  bool     // when true, return a non-success envelope
}

// apiPrefix is the Cloudflare API version path segment that precedes every resource
// path on the wire (apiBase ends in it). Tests assert the resource path after it.
const apiPrefix = "/client/v4"

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	// Record the resource path with the API-version prefix trimmed, so the test asserts
	// the same account-scoped paths the resource builders produce.
	path := strings.TrimPrefix(req.URL.Path, apiPrefix)
	rec := recordedRequest{
		method: req.Method,
		path:   path,
		auth:   req.Header.Get("Authorization"),
	}
	if req.Body != nil {
		raw, _ := io.ReadAll(req.Body)
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &rec.body)
		}
	}
	idx := len(f.requests)
	f.requests = append(f.requests, rec)

	id := ""
	if idx < len(f.responses) {
		id = f.responses[idx]
	}
	env := map[string]any{"success": !f.failBody, "errors": []any{}, "result": map[string]any{"id": id}}
	if f.failBody {
		env["errors"] = []map[string]any{{"code": 1001, "message": "bad request"}}
	}
	buf, _ := json.Marshal(env)
	status := f.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(string(buf))),
		Header:     make(http.Header),
	}, nil
}

const testToken = "test-token-must-not-leak"

func newTestClient(d Doer) *Client {
	c, err := NewClient("acct123", testToken, d)
	if err != nil {
		panic(err)
	}
	return c
}

// TestApplyIssuesExpectedRequests is the core apply-path test: it drives a real plan
// through Client.Apply against a fake Doer and asserts the exact request shapes
// (method, path, key body fields) for each action, that the email note made no request,
// and that the created Access application id was substituted into the policy path.
func TestApplyIssuesExpectedRequests(t *testing.T) {
	plan, err := Planner{}.Plan("acct123", sampleConfig())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// The first call is the Access app create; hand back an id so the policy can bind.
	doer := &fakeDoer{responses: []string{"app-id-xyz"}}
	client := newTestClient(doer)

	secrets := map[string]string{
		"signer-private":   "SECRET-A",
		"recipient-public": "SECRET-B",
	}
	results, err := client.Apply(plan, secrets)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// One result per action; the email note is a manual result, every other action made
	// exactly one request. So requests == actions - manual.
	_, manual := plan.Counts()
	if len(results) != len(plan.Actions) {
		t.Fatalf("results = %d, want %d (one per action)", len(results), len(plan.Actions))
	}
	if len(doer.requests) != len(plan.Actions)-manual {
		t.Fatalf("requests = %d, want %d (actions minus %d manual)", len(doer.requests), len(plan.Actions)-manual, manual)
	}

	// Assert the request shapes by kind. Build a lookup from the request path.
	byPath := map[string]recordedRequest{}
	for _, r := range doer.requests {
		byPath[r.method+" "+r.path] = r
		// The token must be carried as a Bearer header on every request, and only there.
		if r.auth != "Bearer "+testToken {
			t.Errorf("request %s %s Authorization = %q, want Bearer token", r.method, r.path, r.auth)
		}
	}

	want := []struct {
		key       string
		bodyCheck func(map[string]any) bool
	}{
		{"POST /accounts/acct123/access/apps", func(b map[string]any) bool {
			return b["name"] == "downpipes prod" && b["type"] == "self_hosted"
		}},
		// The policy path must carry the substituted app id, not the placeholder.
		{"POST /accounts/acct123/access/apps/app-id-xyz/policies", func(b map[string]any) bool {
			return b["decision"] == "allow"
		}},
		{"PUT /accounts/acct123/secrets_store/stores/store-1/secrets/signer-private", func(b map[string]any) bool {
			return b["name"] == "signer-private" && b["value"] == "SECRET-A"
		}},
		{"PUT /accounts/acct123/secrets_store/stores/store-1/secrets/recipient-public", func(b map[string]any) bool {
			return b["value"] == "SECRET-B"
		}},
		{"PUT /accounts/acct123/workers/scripts/downpipe-engine/bindings/SRC_KV", func(b map[string]any) bool {
			return b["type"] == "kv" && b["id"] == "kvns-abc"
		}},
		{"PUT /accounts/acct123/workers/scripts/downpipe-engine/bindings/SRC_R2", func(b map[string]any) bool {
			return b["type"] == "r2" && b["id"] == "src-bucket"
		}},
		{"PUT /accounts/acct123/workers/scripts/downpipe-engine/bindings/DEST_R2", func(b map[string]any) bool {
			return b["type"] == "r2_bucket" && b["bucket_name"] == "downpipes-archives"
		}},
	}
	for _, w := range want {
		r, ok := byPath[w.key]
		if !ok {
			t.Errorf("expected request not issued: %s", w.key)
			continue
		}
		if !w.bodyCheck(r.body) {
			t.Errorf("request %s body shape wrong: %v", w.key, r.body)
		}
	}

	// The placeholder must never have been sent on the wire.
	for _, r := range doer.requests {
		if strings.Contains(r.path, appIDPlaceholder) {
			t.Errorf("a request carried the unresolved app-id placeholder: %s", r.path)
		}
	}

	// No Result may carry the token, even in a detail string.
	for _, r := range results {
		if strings.Contains(r.Detail, testToken) {
			t.Errorf("result detail leaked the token: %q", r.Detail)
		}
	}
}

// TestApplySecretValueNotInPlan confirms the secret value is added only at call time and
// never lives in the plan: the plan's secret action body has no value, but the issued
// request body does.
func TestApplySecretValueNotInPlan(t *testing.T) {
	c := Config{
		AppName:       "app",
		AccessDomains: []string{"console.example.com"},
		AllowedEmails: []string{"o@example.com"},
		Secrets:       []SecretEntry{{Store: "s1", Name: "k1"}},
	}
	plan, err := Planner{}.Plan("acct123", c)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// Verify the plan holds no value.
	for _, a := range plan.Actions {
		if a.Kind == KindSecret {
			if _, ok := a.Body["value"]; ok {
				t.Fatalf("plan secret action carries a value; it must not")
			}
		}
	}
	doer := &fakeDoer{responses: []string{"app-1"}}
	client := newTestClient(doer)
	if _, err := client.Apply(plan, map[string]string{"k1": "the-value"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var sawValue bool
	for _, r := range doer.requests {
		if strings.HasSuffix(r.path, "/secrets/k1") {
			if r.body["value"] == "the-value" {
				sawValue = true
			}
		}
	}
	if !sawValue {
		t.Error("the secret value was not sent in the PUT request body at apply time")
	}
}

// TestApplyMissingSecretValueFails confirms a secret with no supplied value is an error
// for that action and stops the run, rather than being defaulted to empty.
func TestApplyMissingSecretValueFails(t *testing.T) {
	c := Config{
		AppName:       "app",
		AccessDomains: []string{"console.example.com"},
		AllowedEmails: []string{"o@example.com"},
		Secrets:       []SecretEntry{{Store: "s1", Name: "k1"}},
	}
	plan, err := Planner{}.Plan("acct123", c)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	doer := &fakeDoer{responses: []string{"app-1"}}
	client := newTestClient(doer)
	_, err = client.Apply(plan, map[string]string{}) // no value for k1
	if err == nil {
		t.Fatal("Apply with a missing secret value = nil, want an error")
	}
	if !strings.Contains(err.Error(), "k1") {
		t.Errorf("error %q does not name the missing secret", err.Error())
	}
}

// TestApplyPolicyBeforeAppFails confirms that a policy action whose app-id placeholder is
// unresolved (because no app was created first) is a hard error, not a request with a
// literal placeholder in the path.
func TestApplyPolicyBeforeAppFails(t *testing.T) {
	// A hand-built plan with only the policy action, out of order.
	plan := Plan{AccountID: "acct123", Actions: []Action{
		buildAccessPolicy("acct123", sampleConfig()),
	}}
	doer := &fakeDoer{}
	client := newTestClient(doer)
	_, err := client.Apply(plan, nil)
	if err == nil {
		t.Fatal("Apply with an unresolved app id = nil, want an error")
	}
	if len(doer.requests) != 0 {
		t.Errorf("a request was issued despite the unresolved app id: %d request(s)", len(doer.requests))
	}
}

// TestApplyAPIErrorStopsRun confirms a non-success API response stops the run and is
// reported as a failed result, so a partial provision is never presented as success.
func TestApplyAPIErrorStopsRun(t *testing.T) {
	plan, err := Planner{}.Plan("acct123", sampleConfig())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	doer := &fakeDoer{status: http.StatusBadRequest, failBody: true}
	client := newTestClient(doer)
	results, err := client.Apply(plan, map[string]string{"signer-private": "a", "recipient-public": "b"})
	if err == nil {
		t.Fatal("Apply with an API error = nil, want an error")
	}
	// The first action (the Access app create) fails, so exactly one request was made and
	// the last result is a failure.
	if len(doer.requests) != 1 {
		t.Errorf("requests = %d, want 1 (run stops at the first failure)", len(doer.requests))
	}
	if len(results) == 0 || results[len(results)-1].OK {
		t.Errorf("last result should be a failure, got %v", results)
	}
}

// TestApplyEmailNoteMakesNoRequest confirms the manual email note is recorded as a
// successful result but issues no API call.
func TestApplyEmailNoteMakesNoRequest(t *testing.T) {
	c := Config{
		AppName:       "app",
		AccessDomains: []string{"console.example.com"},
		AllowedEmails: []string{"o@example.com"},
		EmailFrom:     "alerts@example.com",
	}
	plan, err := Planner{}.Plan("acct123", c)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	doer := &fakeDoer{responses: []string{"app-1"}}
	client := newTestClient(doer)
	results, err := client.Apply(plan, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Three actions (app + policy + email note); the email note makes no call, so two
	// requests are issued (the app create and the policy create).
	if len(doer.requests) != 2 {
		t.Errorf("requests = %d, want 2 (the email note makes no call)", len(doer.requests))
	}
	for _, r := range doer.requests {
		if strings.Contains(r.path, "/email") || r.method == "" {
			t.Errorf("an email-note request was issued: %s %s", r.method, r.path)
		}
	}
	var noteResult *Result
	for i := range results {
		if results[i].Action.Kind == KindEmailNote {
			noteResult = &results[i]
		}
	}
	if noteResult == nil || !noteResult.OK {
		t.Errorf("email note result missing or not ok: %v", noteResult)
	}
}

// TestNewClientRejectsEmptyToken confirms the client constructor refuses an empty token
// or account, a defence in depth behind the command's own missing-token guard.
func TestNewClientRejectsEmptyToken(t *testing.T) {
	if _, err := NewClient("acct", "", &fakeDoer{}); err == nil {
		t.Error("NewClient with empty token = nil error, want an error")
	}
	if _, err := NewClient("", "tok", &fakeDoer{}); err == nil {
		t.Error("NewClient with empty account = nil error, want an error")
	}
}

// TestNewClientRejectsUnsafeAccountID confirms the constructor refuses an account id that
// carries a path-traversal segment, as defence in depth behind Planner.Plan. The account
// id is interpolated into every API path, so a "/" or ".." would retarget the call within
// the pinned host (R12).
func TestNewClientRejectsUnsafeAccountID(t *testing.T) {
	for _, bad := range []string{"../../zones/other", "acct/../x", "a:b", "has space"} {
		if _, err := NewClient(bad, "tok", &fakeDoer{}); err == nil {
			t.Errorf("NewClient(%q) = nil error, want a rejection", bad)
		}
	}
	if _, err := NewClient("0123456789abcdef0123456789abcdef", "tok", &fakeDoer{}); err != nil {
		t.Errorf("NewClient with a valid 32-hex account id = %v, want nil", err)
	}
}

// TestClientUsesCloudflareBase confirms the client only ever targets api.cloudflare.com.
// We assert the base constant rather than reaching the network.
func TestClientUsesCloudflareBase(t *testing.T) {
	if !strings.HasPrefix(apiBase, "https://api.cloudflare.com/") {
		t.Fatalf("apiBase = %q, must be https://api.cloudflare.com/...", apiBase)
	}
	c := newTestClient(&fakeDoer{})
	if c.base != apiBase {
		t.Errorf("client base = %q, want %q", c.base, apiBase)
	}
}

// TestRedactToken confirms the redaction helper removes the token from a string.
func TestRedactToken(t *testing.T) {
	got := redactToken("error reaching host with "+testToken+" in it", testToken)
	if strings.Contains(got, testToken) {
		t.Errorf("redactToken left the token in: %q", got)
	}
	if redactToken("no token here", "") != "no token here" {
		t.Error("redactToken with empty token altered the string")
	}
}
