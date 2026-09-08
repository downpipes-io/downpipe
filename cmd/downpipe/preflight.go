package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/provision"
)

// preflightDoer, when non-nil, overrides the HTTP transport cmdPreflight uses to reach
// the Cloudflare API. It exists only so a unit test can inject a fake Doer; production
// leaves it nil and cmdPreflight constructs a bounded *http.Client.
var preflightDoer provision.Doer

// cmdPreflight runs the read-only, deploy-time account checks: the entitlement
// questions an onboarding must VALIDATE before the engine is deployed, answered with
// the operator's own token on this machine (the token is read from
// CLOUDFLARE_API_TOKEN, sent only to api.cloudflare.com, and never stored). It lists
// the account's domains so the operator can choose one, verifies a chosen --domain is
// covered by an active zone, reports Secrets Store headroom against the documented
// ceiling, looks for a Workers Paid subscription, reports whether a Logpush job
// already ships Workers logs to a SIEM, and lists R2 buckets for the destination
// choice. Read-only: it provisions nothing (that is `downpipe setup`).
func cmdPreflight(args []string) error {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	account := fs.String("account", "", "Cloudflare account id")
	domain := fs.String("domain", "", "the custom domain you intend to deploy the engine/console on (verified against the account's active zones)")
	asJSON := fs.Bool("json", false, "print the report as JSON (for the console or a script)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *account == "" {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("preflight needs --account <id>")}
	}
	token := os.Getenv("CLOUDFLARE_API_TOKEN")
	if token == "" {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("set CLOUDFLARE_API_TOKEN in your environment (the token stays on this machine and is sent only to api.cloudflare.com)")}
	}
	// A bounded client: a stalled connection must not hang the preflight forever. The
	// Doer is injectable (preflightDoer) so a unit test can drive the account checks with
	// a fake transport; production leaves it nil and gets the bounded HTTP client.
	doer := preflightDoer
	if doer == nil {
		doer = &http.Client{Timeout: 30 * time.Second}
	}
	client, err := provision.NewClient(*account, token, doer)
	if err != nil {
		return &format.ExitError{Code: format.ExitUsage, Err: err}
	}
	report, err := client.Preflight(*domain)
	if err != nil {
		return err
	}
	// The verdict is computed from the report, not from the printing, so BOTH output
	// formats reach the same exit code. It used to be computed inside the text renderer,
	// below a `return enc.Encode(report)` that no gate could see past, so `--json` exited
	// 0 on a report whose own payload carried "status": "failed". The exit code is the
	// only part of this command a `preflight && deploy` script reads.
	verdict := judgePreflight(report, *domain)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
		return verdict.err()
	}

	fmt.Println("downpipe deploy-time preflight (read-only; nothing was changed)")
	fmt.Printf("  account: %s\n\n", report.AccountID)
	if len(report.Zones) > 0 {
		fmt.Println("  available domains on this account:")
		for _, z := range report.Zones {
			fmt.Printf("    %-40s %s\n", z.Name, z.Status)
		}
		fmt.Println()
	}
	if len(report.R2Buckets) > 0 {
		fmt.Println("  R2 buckets (destination candidates):")
		for _, b := range report.R2Buckets {
			fmt.Printf("    %s\n", b)
		}
		fmt.Println()
	}
	fmt.Println("  checks:")
	for _, c := range report.Checks {
		mark := map[provision.PreflightStatus]string{
			provision.StatusVerified:     "ok  ",
			provision.StatusConfigured:   "set ",
			provision.StatusFailed:       "FAIL",
			provision.StatusUnconfigured: "todo",
			provision.StatusUnknown:      "?   ",
		}[c.Status]
		fmt.Printf("    [%s] %-38s %s\n", mark, c.Name, c.Evidence)
		if c.Remediation != "" {
			fmt.Printf("           -> %s\n", c.Remediation)
		}
	}
	fmt.Println()
	fmt.Println(verdict.summary())
	return verdict.err()
}

// preflightVerdict is the deploy-or-not answer read off a finished report, separate from
// how the report is printed. It carries the two numbers that decide it and the one
// question the operator asked for by name.
type preflightVerdict struct {
	failed         int
	unchecked      int
	domain         string
	domainVerified bool
}

// judgePreflight reads the verdict off the report. It counts observed failures and, just
// as importantly, the checks that COULD NOT RUN.
//
// A check that could not run is not a pass. Before this, only StatusFailed was counted,
// so a token missing every read scope produced five [?] lines and the closing sentence
// "no failures: deploy when the todo items you need are in place." at exit 0. Nothing had
// been checked. The word "failures" was accurate and the sentence built on it was not: an
// operator reads that line as clearance to deploy, and a script reads the 0 the same way.
// StatusUnconfigured is different and stays out of the count, because it is an OBSERVED
// absence (no Logpush job exists) rather than an unanswered question, and the closing
// sentence hands that judgement to the operator where it belongs.
func judgePreflight(report *provision.AccountPreflight, domain string) preflightVerdict {
	v := preflightVerdict{domain: domain, domainVerified: domain == ""} // an unrequested domain needs no verdict
	for _, c := range report.Checks {
		switch c.Status {
		case provision.StatusFailed:
			v.failed++
		case provision.StatusUnknown:
			v.unchecked++
		}
		if c.ID == "domain" && c.Status == provision.StatusVerified {
			v.domainVerified = true
		}
	}
	return v
}

// summary is the closing block of the text report, and it says exactly what the verdict
// found. The counts lead, worst first; the domain the operator named by hand is then
// called out on its own line whenever it went unverified, because "1 check could not be
// checked" does not tell the operator WHICH question of theirs went unanswered.
func (v preflightVerdict) summary() string {
	var line string
	switch {
	case v.failed > 0 && v.unchecked > 0:
		line = fmt.Sprintf("  %d check(s) FAILED and %d could NOT be checked with this token: resolve the failures and widen the token's read scopes before deploying.", v.failed, v.unchecked)
	case v.failed > 0:
		line = fmt.Sprintf("  %d check(s) FAILED: resolve them before deploying.", v.failed)
	case v.unchecked > 0:
		line = fmt.Sprintf("  no failures, but %d check(s) could NOT be checked with this token, so this is NOT clearance to deploy: widen the token's read scopes and re-run, or confirm each [?] line in the dashboard yourself.", v.unchecked)
	case !v.domainVerified:
		line = "  the report carries no failure and no unanswered check, yet --domain was still not verified: treat this as unverified and confirm the zone in the dashboard."
	default:
		return "  no failures: deploy when the todo items you need are in place."
	}
	if !v.domainVerified && (v.failed > 0 || v.unchecked > 0) {
		line += fmt.Sprintf("\n  --domain %s was NOT verified, so the one question you asked by name is still open.", v.domain)
	}
	return line
}

// err is the exit code behind the summary. Every non-clean verdict is ExitPreflight, so
// the text report and --json agree and a `downpipe preflight && deploy` script stops on
// any of them.
//
// The domain branch is the backstop, not the usual route: a requested domain that is not
// verified is emitted today as either StatusFailed or StatusUnknown, so one of the two
// counts above already catches it. It stays because the counts are a whitelist of two
// statuses and the domain question is the one an operator asked for by name; a domain
// check that arrived at any OTHER status must not fall through to exit 0.
func (v preflightVerdict) err() error {
	switch {
	case v.failed > 0:
		return &format.ExitError{Code: format.ExitPreflight, Err: fmt.Errorf("%d preflight check(s) failed", v.failed)}
	case v.unchecked > 0:
		return &format.ExitError{Code: format.ExitPreflight, Err: fmt.Errorf("%d preflight check(s) could not be run with this token", v.unchecked)}
	case !v.domainVerified:
		// The operator explicitly asked for this verification; an unanswered question
		// must not exit 0 (a script would deploy on it).
		return &format.ExitError{Code: format.ExitPreflight, Err: fmt.Errorf("--domain %s was not verified", v.domain)}
	default:
		return nil
	}
}
