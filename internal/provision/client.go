package provision

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// apiBase is the only host this package ever speaks to. The operator's Cloudflare API
// token is sent here over HTTPS and nowhere else: never to the vendor, never to the
// in-account console, and never to any host derived from operator input.
const apiBase = "https://api.cloudflare.com/client/v4"

// maxResponseBytes bounds a single API response read so a hostile or buggy endpoint
// cannot drive an unbounded allocation. Cloudflare API responses are small JSON.
const maxResponseBytes int64 = 4 << 20

// Doer is the minimal HTTP surface the Client needs. *http.Client satisfies it by
// structural typing, and a test injects a fake to assert request shapes without any
// real network call. Keeping the seam this narrow is what lets the apply path be tested
// offline (CONTRIBUTING: the recovery and provisioning paths never phone home in tests).
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Provisioner is the behaviour the command depends on: turn an ordered Plan into a set
// of executed-or-failed results against Cloudflare. The Client is the real
// implementation; a test can supply its own. Apply is taken only at real runtime under
// --apply; a dry run never constructs a live Client.
type Provisioner interface {
	Apply(plan Plan, secrets map[string]string) ([]Result, error)
}

// Result records the outcome of one Action in an apply. ID is the Cloudflare resource id
// returned by a create call when present (for example the new Access application id),
// which later actions in the same run may depend on.
type Result struct {
	Action Action
	OK     bool
	ID     string
	Detail string
}

// Client is the real Cloudflare API provisioner. It holds the operator's token and an
// injectable Doer. The token is read by the command from CLOUDFLARE_API_TOKEN and handed
// in here; it is attached only as the Authorization header on requests to apiBase and is
// never logged, never written to a Result, and never placed in a Plan.
type Client struct {
	token   string
	doer    Doer
	base    string
	account string
}

// NewClient returns a Client for the account, using token for Authorization and doer for
// transport. A nil doer defaults to http.DefaultClient; tests pass a fake. The token is
// required: an empty token is a programming error here, because the command guards the
// missing-token case and exits with a usage code before ever building a Client.
func NewClient(accountID, token string, doer Doer) (*Client, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("a Cloudflare API token is required")
	}
	if strings.TrimSpace(accountID) == "" {
		return nil, errors.New("a Cloudflare account id is required")
	}
	// Defence in depth behind Planner.Plan, which validates the account id before any
	// Client is built: refuse an account id that is not a safe path segment so it cannot
	// retarget a call within the pinned host (a self-inflicted path traversal).
	if err := validateAccountID(accountID); err != nil {
		return nil, err
	}
	if doer == nil {
		doer = http.DefaultClient
	}
	return &Client{token: token, doer: doer, base: apiBase, account: accountID}, nil
}

// cfEnvelope is the standard Cloudflare API response envelope. Only the fields this
// package needs are decoded.
type cfEnvelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result struct {
		ID string `json:"id"`
	} `json:"result"`
}

// Apply executes the plan's actions in order, against Cloudflare. A manual-only action
// (the email note) is recorded as a result and skipped, not called. The created Access
// application id is captured and substituted into any later path carrying the
// appIDPlaceholder, so the policy attaches to the app just created. For a secret action,
// the value is taken from the secrets map keyed by secret name; a missing value is an
// error for that action and is never defaulted to empty.
//
// Apply stops at the first hard failure and returns the results gathered so far plus the
// error, so a half-applied run is reported honestly rather than presented as success.
func (c *Client) Apply(plan Plan, secrets map[string]string) ([]Result, error) {
	results := make([]Result, 0, len(plan.Actions))
	var createdAppID string

	for _, a := range plan.Actions {
		if a.IsManual() {
			results = append(results, Result{Action: a, OK: true, Detail: "manual step: surfaced to the operator, no API call"})
			continue
		}

		path := a.Path
		if strings.Contains(path, appIDPlaceholder) {
			if createdAppID == "" {
				err := fmt.Errorf("action %q references the Access application id before it was created", a.Name)
				results = append(results, Result{Action: a, OK: false, Detail: err.Error()})
				return results, err
			}
			path = strings.ReplaceAll(path, appIDPlaceholder, createdAppID)
		}

		body := a.Body
		if a.Kind == KindSecret {
			val, ok := secrets[a.Name]
			if !ok {
				err := fmt.Errorf("no value supplied for secret %q", a.Name)
				results = append(results, Result{Action: a, OK: false, Detail: err.Error()})
				return results, err
			}
			// Copy the body and add the value at call time only, so the value never
			// lives in the Plan or in a Result. The value goes to api.cloudflare.com and
			// is then dropped.
			body = map[string]any{"name": a.Name, "value": val}
		}

		id, err := c.call(a.Method, path, body)
		if err != nil {
			results = append(results, Result{Action: a, OK: false, Detail: redactToken(err.Error(), c.token)})
			return results, fmt.Errorf("apply %s %q: %w", a.Kind, a.Name, err)
		}
		if a.Kind == KindAccessApp && id != "" {
			createdAppID = id
		}
		results = append(results, Result{Action: a, OK: true, ID: id, Detail: "applied"})
	}
	return results, nil
}

// call issues one Cloudflare API request and returns the result id from the envelope.
// The token is attached only here, as a Bearer Authorization header, on a request to
// c.base; it is never logged. The request URL is c.base + path, where path is built by
// the resource builders from the account id and resource ids, never from a redirect or
// any externally supplied host.
func (c *Client) call(method, path string, body map[string]any) (string, error) {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return "", fmt.Errorf("marshal request body: %w", err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.doer.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("%s %s: read response: %w", method, path, err)
	}
	if int64(len(raw)) > maxResponseBytes {
		return "", fmt.Errorf("%s %s: response exceeds the %d-byte limit", method, path, maxResponseBytes)
	}

	var env cfEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		// Surface the status without echoing an unbounded or token-bearing body.
		return "", fmt.Errorf("%s %s: status %d, unparseable response", method, path, resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !env.Success {
		return "", fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, joinAPIErrors(env))
	}
	return env.Result.ID, nil
}

// joinAPIErrors renders the Cloudflare error array as a short, redaction-safe string.
func joinAPIErrors(env cfEnvelope) string {
	if len(env.Errors) == 0 {
		return "no error detail"
	}
	parts := make([]string, 0, len(env.Errors))
	for _, e := range env.Errors {
		parts = append(parts, fmt.Sprintf("%d %s", e.Code, e.Message))
	}
	return strings.Join(parts, "; ")
}

// redactToken removes the token from a string before it is recorded in a Result, as a
// defence in depth: the token should never reach an error string, but if a future change
// were to interpolate the URL or a header, this stops it leaking into a printed result.
func redactToken(s, token string) string {
	if token == "" {
		return s
	}
	return strings.ReplaceAll(s, token, "[redacted]")
}
