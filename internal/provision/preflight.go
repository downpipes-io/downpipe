package provision

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Deploy-time account preflight: the read-only checks an onboarding needs BEFORE
// deploying the engine, run with the operator's own token on the operator's own machine
// (the same trust shape as the provisioner: the token goes to api.cloudflare.com and
// nowhere else, and the engine itself never holds one). These answer the entitlement
// questions the in-Worker preflight cannot: which domains (zones) the account actually
// has and whether the chosen one is active, how much Secrets Store headroom remains,
// whether a Workers paid subscription is present, whether a Logpush job already ships
// Workers logs to a SIEM, and which R2 buckets exist for the destination choice. Every
// check is a GET; a token without a given read scope degrades that one check to
// "not checkable with this token" rather than failing the run.

// PreflightStatus mirrors the engine's preflight vocabulary so the two reports read as
// one checklist: verified (observed true), configured (present but not proven to the
// full claim), failed (observed false), unconfigured (absent), unknown (not checkable
// with this token's scopes, or not observable through a transient fault).
type PreflightStatus string

// The preflight status vocabulary, shared with the engine so the two reports read as one checklist.
const (
	StatusVerified     PreflightStatus = "verified"
	StatusConfigured   PreflightStatus = "configured"
	StatusFailed       PreflightStatus = "failed"
	StatusUnconfigured PreflightStatus = "unconfigured"
	StatusUnknown      PreflightStatus = "unknown"
)

// PreflightCheck is one account-level finding.
type PreflightCheck struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Requires    string          `json:"requires"`
	Status      PreflightStatus `json:"status"`
	Evidence    string          `json:"evidence"`
	Remediation string          `json:"remediation,omitempty"`
}

// Zone is one account zone (domain) for the operator to choose from.
type Zone struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// AccountPreflight is the full deploy-time report.
type AccountPreflight struct {
	AccountID string           `json:"accountId"`
	Zones     []Zone           `json:"zones"`
	R2Buckets []string         `json:"r2Buckets"`
	Checks    []PreflightCheck `json:"checks"`
}

// secretsStoreDocumentedLimit is the documented per-store secret ceiling the headroom
// note compares against. It is documentation, not an API fact: the limit check reports
// the OBSERVED count and names this figure so the operator sees real headroom.
const secretsStoreDocumentedLimit = 100

// secretsStoreMinFree is the minimum free-slot headroom the preflight wants before it
// reports the Secrets Store as comfortable. It is one slot more than the roughly five
// secrets the engine needs, so a near-full store is flagged before provisioning.
const secretsStoreMinFree = 6

// zonePageBound caps zone pagination (50 per page) so a pathological account cannot
// spin the preflight; past it the domain check degrades honestly instead of failing.
const zonePageBound = 40

// listEnvelope decodes a Cloudflare list response: the result array stays raw so each
// check decodes only the fields it needs, and result_info supplies totals.
type listEnvelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo struct {
		TotalCount int `json:"total_count"`
	} `json:"result_info"`
}

// errInsufficientScope marks a 403: this token lacks ONE read scope, so that one check
// degrades to StatusUnknown and the rest of the preflight proceeds.
var errInsufficientScope = fmt.Errorf("the token lacks the read scope for this check")

// errTokenInvalid marks a 401: the token itself is not valid for ANY check (expired,
// revoked, malformed). That is not a scope gap, so the preflight ABORTS with a clear
// error rather than emitting a page of unknowns and exiting 0; a script chaining
// `downpipe preflight && deploy` must never proceed on a dead token.
var errTokenInvalid = fmt.Errorf("the API token is not valid (401 unauthorised): create a read-scoped token and re-run")

// transientError marks a fault where the fact was NOT OBSERVABLE at all: a network
// failure or a 5xx. That is different from observed-false, so checks degrade to
// StatusUnknown ("could not be read") instead of asserting a failure or an absence the
// account may not have.
type transientError struct{ msg string }

func (e *transientError) Error() string { return e.msg }

func isTransient(err error) bool {
	var t *transientError
	return errors.As(err, &t)
}

// apiError is a non-success Cloudflare envelope (a 4xx or success:false at a status the
// generic path does not special-case). It carries the API error CODES, not just the
// rendered string, so a check can tell an AFFIRMATIVE "feature not enabled" answer (a
// known code) apart from any other API failure. Error() renders the same redaction-safe
// string the generic path always produced, so call sites that only print it are unchanged.
type apiError struct {
	msg   string
	codes []int
}

func (e *apiError) Error() string { return e.msg }

// apiErrorHasCode reports whether err is an apiError carrying the given Cloudflare error
// code. It is the only honest way to read a feature as affirmatively absent: a code the
// API itself returns, never a guess inferred from an unrelated failure.
func apiErrorHasCode(err error, code int) bool {
	var a *apiError
	if !errors.As(err, &a) {
		return false
	}
	for _, c := range a.codes {
		if c == code {
			return true
		}
	}
	return false
}

// r2NotEnabledCode is Cloudflare's affirmative "this account is not entitled to use R2"
// answer (returned by the R2 list-buckets endpoint). Only this code reads as
// StatusUnconfigured; every other R2 API failure is a real failure, not an absence.
const r2NotEnabledCode = 10042

func (c *Client) get(path string) (*listEnvelope, error) {
	req, err := http.NewRequest(http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.doer.Do(req)
	if err != nil {
		return nil, &transientError{msg: fmt.Sprintf("GET %s: %v", path, err)}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, errTokenInvalid
	}
	if resp.StatusCode >= 500 {
		return nil, &transientError{msg: fmt.Sprintf("GET %s: status %d (the API could not answer)", path, resp.StatusCode)}
	}
	var env listEnvelope
	// The same response-size bound as call(): a hostile or buggy endpoint must not
	// balloon memory on this path either.
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes))
	if err := dec.Decode(&env); err != nil {
		// A 403 with an unparseable body is still a scope gap (the body adds nothing);
		// every other unparseable non-2xx is a real, surfaced failure.
		if resp.StatusCode == http.StatusForbidden {
			return nil, errInsufficientScope
		}
		return nil, fmt.Errorf("GET %s: status %d, unparseable response", path, resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !env.Success {
		detail := "no error detail"
		codes := make([]int, 0, len(env.Errors))
		if len(env.Errors) > 0 {
			parts := make([]string, 0, len(env.Errors))
			for _, e := range env.Errors {
				parts = append(parts, fmt.Sprintf("%d %s", e.Code, e.Message))
				codes = append(codes, e.Code)
			}
			detail = strings.Join(parts, "; ")
		}
		apiErr := &apiError{msg: fmt.Sprintf("GET %s: status %d: %s", path, resp.StatusCode, detail), codes: codes}
		// A 403 is normally a scope gap that degrades one check to StatusUnknown. The one
		// exception is an AFFIRMATIVE feature-absence code the API itself returns on a 403
		// (R2-not-enabled, code 10042, which Cloudflare may serve as 403 or another 4xx):
		// that is an account fact, not a missing scope, so it must flow on as the coded
		// apiError for apiErrorHasCode to read. Every other 403 degrades to a scope gap.
		if resp.StatusCode == http.StatusForbidden && !apiErrorHasCode(apiErr, r2NotEnabledCode) {
			return nil, errInsufficientScope
		}
		return nil, apiErr
	}
	return &env, nil
}

// listZones pages through the account's zones (50 per page, server-side filtered to
// this account) so an account with more zones than one page cannot produce a false
// "domain not covered" failure. It returns the collected zones and the API-reported
// total, which exceeds the collected count only past the page bound.
func (c *Client) listZones() ([]Zone, int, error) {
	collected := []Zone{}
	total := 0
	for page := 1; page <= zonePageBound; page++ {
		env, err := c.get(fmt.Sprintf("/zones?per_page=50&page=%d&account.id=%s", page, url.QueryEscape(c.account)))
		if err != nil {
			return nil, 0, err
		}
		var zs []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal(env.Result, &zs); err != nil {
			return nil, 0, fmt.Errorf("the zones response could not be parsed")
		}
		for _, z := range zs {
			collected = append(collected, Zone{Name: z.Name, Status: z.Status})
		}
		total = env.ResultInfo.TotalCount
		if total == 0 {
			total = len(collected)
		}
		if len(zs) == 0 || len(collected) >= total {
			break
		}
	}
	return collected, total, nil
}

// Preflight runs every account-level check. domain, when non-empty, is the custom
// domain the operator intends to serve the engine/console on; the zone check then
// verifies it is covered by an ACTIVE zone on this account (exact zone or a parent of
// the fully-qualified name), which is the "domain is connected to the account"
// validation. It never mutates anything.
func (c *Client) Preflight(domain string) (*AccountPreflight, error) {
	// Normalise the asked domain once: lowercase and strip one trailing dot, because
	// zone names come back lowercased. An internationalised name in Unicode form would
	// never match the API's punycode form, so refuse it with the actionable form
	// instead of reporting a false failure.
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, r := range domain {
		if r > 127 {
			return nil, fmt.Errorf("--domain must be the ASCII/punycode form (xn--...) of an internationalised name")
		}
	}
	report := &AccountPreflight{AccountID: c.account, Zones: []Zone{}, R2Buckets: []string{}, Checks: []PreflightCheck{}}

	// Each check appends its findings to report and returns a non-nil error ONLY for the
	// one abort case shared by all of them: an invalid token (401), which must stop the
	// whole preflight rather than emit a page of unknowns. Every other fault is folded
	// into a check on report by the helper itself.
	for _, check := range []func(*AccountPreflight) error{
		func(r *AccountPreflight) error { return c.checkZones(r, domain) },
		c.checkWorkersSubscription,
		c.checkSecretsStore,
		c.checkLogpush,
		c.checkR2Buckets,
	} {
		if err := check(report); err != nil {
			return nil, err
		}
	}

	return report, nil
}
