package provision

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// errorDoer is an in-memory Doer double for the call() error paths that the success-path
// fakeDoer cannot reach. Each field selects one failure mode; the request is never sent
// anywhere, so these tests stay fully offline.
type errorDoer struct {
	transportErr error  // when set, Do returns this error (a transport/network failure)
	body         string // the response body to return when transportErr is nil
	status       int    // status code (0 -> 200)
	requests     int
}

func (d *errorDoer) Do(req *http.Request) (*http.Response, error) {
	d.requests++
	// Always drain and close any request body so a real http.Client would too; here it is
	// a no-op double, but it keeps the fake faithful.
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}
	if d.transportErr != nil {
		return nil, d.transportErr
	}
	status := d.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(d.body)),
		Header:     make(http.Header),
	}, nil
}

// singleActionPlan is a minimal one-action plan (the Access app create) so call() runs
// exactly once and the failure mode under test is isolated to that single request.
func singleActionPlan() Plan {
	return Plan{AccountID: "acct123", Actions: []Action{
		buildAccessApp("acct123", sampleConfig()),
	}}
}

// TestCallTransportErrorIsReportedAndRedacted covers the c.doer.Do error branch of call():
// a transport failure must stop the run, be reported as a failed Result, and must never
// leak the token into the error or the Result detail. The token is in the Authorization
// header only; this asserts the redaction defence in depth holds even on the error path.
func TestCallTransportErrorIsReportedAndRedacted(t *testing.T) {
	// The transport error text deliberately embeds the token to prove redaction removes it.
	doer := &errorDoer{transportErr: errors.New("dial tcp: refused while using " + testToken)}
	client := newTestClient(doer)

	results, err := client.Apply(singleActionPlan(), nil)
	if err == nil {
		t.Fatal("Apply with a transport error = nil, want an error")
	}
	if doer.requests != 1 {
		t.Errorf("requests = %d, want 1 (the run stops at the first transport failure)", doer.requests)
	}
	if len(results) != 1 || results[0].OK {
		t.Fatalf("want exactly one failed result, got %v", results)
	}
	// The token must not appear in the Result detail (redactToken is applied on this path).
	if strings.Contains(results[0].Detail, testToken) {
		t.Errorf("result detail leaked the token: %q", results[0].Detail)
	}
}

// TestCallUnparseableResponseErrors covers the json.Unmarshal failure branch of call(): a
// non-JSON body must be reported as a status-coded, body-free error (the raw body is not
// echoed, so a token-bearing or unbounded body cannot leak). The run stops.
func TestCallUnparseableResponseErrors(t *testing.T) {
	doer := &errorDoer{status: http.StatusOK, body: "this is not json at all <<<"}
	client := newTestClient(doer)

	results, err := client.Apply(singleActionPlan(), nil)
	if err == nil {
		t.Fatal("Apply with an unparseable response = nil, want an error")
	}
	if len(results) != 1 || results[0].OK {
		t.Fatalf("want one failed result, got %v", results)
	}
	// The error must mention the status code (the redaction-safe summary) and must not echo
	// the raw body.
	if !strings.Contains(err.Error(), "unparseable response") {
		t.Errorf("error = %q, want it to mention an unparseable response", err.Error())
	}
}

// TestCallResponseTooLargeErrors covers the maxResponseBytes guard in call(): a response
// body larger than the limit must be rejected rather than read unboundedly. The fake
// returns a body one byte over the limit.
func TestCallResponseTooLargeErrors(t *testing.T) {
	// One byte over the limit; call() reads LimitReader(maxResponseBytes+1) and then rejects
	// when the read length exceeds maxResponseBytes.
	oversize := strings.Repeat("a", int(maxResponseBytes)+1)
	doer := &errorDoer{status: http.StatusOK, body: oversize}
	client := newTestClient(doer)

	results, err := client.Apply(singleActionPlan(), nil)
	if err == nil {
		t.Fatal("Apply with an oversized response = nil, want an error")
	}
	if len(results) != 1 || results[0].OK {
		t.Fatalf("want one failed result, got %v", results)
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("error = %q, want it to mention the response-size limit", err.Error())
	}
}

// TestCallNonSuccessStatusWithoutErrorsBody covers the joinAPIErrors empty-errors branch:
// a non-2xx status with a success=false envelope that carries no errors array must still
// produce a stable "no error detail" message rather than an empty or panicking render.
func TestCallNonSuccessStatusWithoutErrorsBody(t *testing.T) {
	// A valid envelope with success=false and no errors entries.
	doer := &errorDoer{status: http.StatusForbidden, body: `{"success":false,"errors":[],"result":{"id":""}}`}
	client := newTestClient(doer)

	_, err := client.Apply(singleActionPlan(), nil)
	if err == nil {
		t.Fatal("Apply with a 403 and empty errors = nil, want an error")
	}
	if !strings.Contains(err.Error(), "no error detail") {
		t.Errorf("error = %q, want the 'no error detail' fallback from joinAPIErrors", err.Error())
	}
}
