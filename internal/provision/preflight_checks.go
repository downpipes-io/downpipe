package provision

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// domainUnverified is the check emitted whenever a --domain was REQUESTED but the zone
// list could not be obtained: the answer the operator explicitly asked for must appear
// in the report as not-verified rather than silently vanishing.
func domainUnverified(domain, why string) PreflightCheck {
	return PreflightCheck{
		ID: "domain", Name: "Deployment domain", Requires: "the chosen domain on an ACTIVE zone of this account",
		Status: StatusUnknown, Evidence: fmt.Sprintf("%s was NOT verified: %s", domain, why),
		Remediation: "grant the token Zone:Read (read-only) and re-run, or confirm the zone in the dashboard manually",
	}
}

// checkZones lists the account's domains so deployment can OFFER them, and verifies the
// chosen one. Zone reads need Zone:Read, a different scope family from account reads, so
// this degrades independently; the explicitly-requested domain check is ALWAYS present
// when --domain was given, even when zones were unreadable. It returns errTokenInvalid
// (the only abort) on a 401 and otherwise folds the outcome into report.
func (c *Client) checkZones(report *AccountPreflight, domain string) error {
	zones, total, err := c.listZones()
	switch {
	case errors.Is(err, errTokenInvalid):
		return err
	case errors.Is(err, errInsufficientScope):
		report.Checks = append(report.Checks, PreflightCheck{
			ID: "zones", Name: "Account domains (zones)", Requires: "a zone on the account (Zone:Read scope to check)",
			Status: StatusUnknown, Evidence: "the token cannot read zones",
			Remediation: "grant the token Zone:Read (read-only) to list and verify domains, or check the dashboard manually",
		})
		if domain != "" {
			report.Checks = append(report.Checks, domainUnverified(domain, "the token cannot read zones"))
		}
	case isTransient(err):
		report.Checks = append(report.Checks, PreflightCheck{
			ID: "zones", Name: "Account domains (zones)", Requires: "a zone on the account",
			Status: StatusUnknown, Evidence: "zones could not be read (a transient fault, not an account fact): " + redactToken(err.Error(), c.token),
		})
		if domain != "" {
			report.Checks = append(report.Checks, domainUnverified(domain, "the zone list could not be read"))
		}
	case err != nil:
		report.Checks = append(report.Checks, PreflightCheck{
			ID: "zones", Name: "Account domains (zones)", Requires: "a zone on the account",
			Status: StatusFailed, Evidence: redactToken(err.Error(), c.token),
		})
		if domain != "" {
			report.Checks = append(report.Checks, domainUnverified(domain, "the zone list could not be read"))
		}
	default:
		report.Zones = append(report.Zones, zones...)
		if domain == "" {
			report.Checks = append(report.Checks, PreflightCheck{
				ID: "zones", Name: "Account domains (zones)", Requires: "a zone on the account",
				Status: StatusVerified, Evidence: fmt.Sprintf("%d zone(s) on the account; pass --domain to verify the one you will deploy on", len(zones)),
			})
		} else {
			covered := ""
			for _, z := range zones {
				zname := strings.ToLower(z.Name)
				if z.Status == "active" && (domain == zname || strings.HasSuffix(domain, "."+zname)) {
					covered = zname
					break
				}
			}
			switch {
			case covered != "":
				report.Checks = append(report.Checks, PreflightCheck{
					ID: "domain", Name: "Deployment domain", Requires: "the chosen domain on an ACTIVE zone of this account",
					Status: StatusVerified, Evidence: fmt.Sprintf("%s is covered by the active zone %s", domain, covered),
				})
			case total > len(zones):
				// The page bound truncated the list: the domain MAY be on an
				// unlisted zone, so this is not-observable, not observed-false.
				report.Checks = append(report.Checks, PreflightCheck{
					ID: "domain", Name: "Deployment domain", Requires: "the chosen domain on an ACTIVE zone of this account",
					Status: StatusUnknown, Evidence: fmt.Sprintf("%s did not match the %d zone(s) listed, but the account reports %d total (list truncated)", domain, len(zones), total),
					Remediation: "confirm the zone in the dashboard manually",
				})
			default:
				report.Checks = append(report.Checks, PreflightCheck{
					ID: "domain", Name: "Deployment domain", Requires: "the chosen domain on an ACTIVE zone of this account",
					Status: StatusFailed, Evidence: fmt.Sprintf("%s is not covered by any active zone on this account", domain),
					Remediation: "add the zone to this account (or fix its DNS activation), or choose one of the listed domains",
				})
			}
		}
	}
	return nil
}

// checkWorkersSubscription verifies the paid plan, which is an account subscription. A
// known paid rate-plan id is VERIFIED; a merely workers-shaped plan is reported as
// configured (present, honestly unproven: the deploy-time [limits] gate is the real
// proof). It returns errTokenInvalid (the only abort) on a 401.
func (c *Client) checkWorkersSubscription(report *AccountPreflight) error {
	env, err := c.get("/accounts/" + c.account + "/subscriptions")
	switch {
	case errors.Is(err, errTokenInvalid):
		return err
	case errors.Is(err, errInsufficientScope):
		report.Checks = append(report.Checks, PreflightCheck{
			ID: "workers-plan", Name: "Workers Paid subscription", Requires: "Workers Paid (activate BEFORE deploying; the deploy's [limits] cpu_ms fails without it)",
			Status: StatusUnknown, Evidence: "the token cannot read subscriptions",
			Remediation: "grant the token Account Settings:Read, or rely on the deploy-time gate (wrangler deploy fails on an unpaid account)",
		})
	case isTransient(err):
		report.Checks = append(report.Checks, PreflightCheck{
			ID: "workers-plan", Name: "Workers Paid subscription", Requires: "Workers Paid",
			Status: StatusUnknown, Evidence: "subscriptions could not be read (a transient fault, not an account fact): " + redactToken(err.Error(), c.token),
		})
	case err != nil:
		report.Checks = append(report.Checks, PreflightCheck{
			ID: "workers-plan", Name: "Workers Paid subscription", Requires: "Workers Paid",
			Status: StatusFailed, Evidence: redactToken(err.Error(), c.token),
		})
	default:
		var subs []struct {
			RatePlan struct {
				ID         string `json:"id"`
				PublicName string `json:"public_name"`
			} `json:"rate_plan"`
		}
		if err := json.Unmarshal(env.Result, &subs); err != nil {
			report.Checks = append(report.Checks, PreflightCheck{
				ID: "workers-plan", Name: "Workers Paid subscription", Requires: "Workers Paid",
				Status: StatusUnknown, Evidence: "the subscriptions response could not be parsed",
			})
			return nil
		}
		// Known paid rate-plan ids; anything else workers-shaped is reported but
		// not over-claimed (rate plan naming varies across account vintages).
		paidPlanIDs := map[string]bool{"workers_paid": true, "workers_standard": true, "workers_unbound": true, "workers_enterprise": true}
		exact, shaped := "", ""
		for _, s := range subs {
			display := s.RatePlan.ID
			if s.RatePlan.PublicName != "" {
				display = s.RatePlan.PublicName
			}
			if paidPlanIDs[strings.ToLower(s.RatePlan.ID)] {
				exact = display
				break
			}
			if strings.Contains(strings.ToLower(s.RatePlan.ID+" "+s.RatePlan.PublicName), "workers") && shaped == "" {
				shaped = display
			}
		}
		switch {
		case exact != "":
			report.Checks = append(report.Checks, PreflightCheck{
				ID: "workers-plan", Name: "Workers Paid subscription", Requires: "Workers Paid",
				Status: StatusVerified, Evidence: fmt.Sprintf("a Workers subscription is present (%s)", exact),
			})
		case shaped != "":
			report.Checks = append(report.Checks, PreflightCheck{
				ID: "workers-plan", Name: "Workers Paid subscription", Requires: "Workers Paid",
				Status: StatusConfigured, Evidence: fmt.Sprintf("a workers-shaped subscription is present (%s) but its rate plan is not a known paid id; the deploy-time [limits] gate is the proof", shaped),
			})
		default:
			report.Checks = append(report.Checks, PreflightCheck{
				ID: "workers-plan", Name: "Workers Paid subscription", Requires: "Workers Paid (activate BEFORE deploying)",
				Status: StatusUnconfigured, Evidence: fmt.Sprintf("%d subscription(s) on the account, none workers-shaped", len(subs)),
				Remediation: "activate Workers Paid in the dashboard before deploying; the engine's deploy fails without it and the free 50-subrequest cap would break runs regardless",
			})
		}
	}
	return nil
}

// checkSecretsStore counts the secrets in each store and compares against the documented
// per-store ceiling, so onboarding knows whether the keys it is about to add (signer,
// recipients, destination credentials) actually fit. It returns errTokenInvalid (the
// only abort) on a 401.
func (c *Client) checkSecretsStore(report *AccountPreflight) error {
	env, err := c.get("/accounts/" + c.account + "/secrets_store/stores?per_page=50")
	switch {
	case errors.Is(err, errTokenInvalid):
		return err
	case errors.Is(err, errInsufficientScope):
		report.Checks = append(report.Checks, PreflightCheck{
			ID: "secrets-store", Name: "Secrets Store headroom", Requires: "the account Secrets Store",
			Status: StatusUnknown, Evidence: "the token cannot read the Secrets Store",
			Remediation: "grant the token the Secrets Store read scope to check headroom",
		})
	case isTransient(err):
		report.Checks = append(report.Checks, PreflightCheck{
			ID: "secrets-store", Name: "Secrets Store headroom", Requires: "the account Secrets Store",
			Status: StatusUnknown, Evidence: "the Secrets Store could not be read (a transient fault, not an account fact)",
		})
	case err != nil:
		report.Checks = append(report.Checks, PreflightCheck{
			ID: "secrets-store", Name: "Secrets Store headroom", Requires: "the account Secrets Store",
			Status: StatusFailed, Evidence: redactToken(err.Error(), c.token),
		})
	default:
		var stores []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(env.Result, &stores); err != nil {
			report.Checks = append(report.Checks, PreflightCheck{
				ID: "secrets-store", Name: "Secrets Store headroom", Requires: "the account Secrets Store",
				Status: StatusUnknown, Evidence: "the Secrets Store response could not be parsed",
			})
			return nil
		}
		if len(stores) == 0 {
			report.Checks = append(report.Checks, PreflightCheck{
				ID: "secrets-store", Name: "Secrets Store headroom", Requires: "the account Secrets Store",
				Status: StatusUnconfigured, Evidence: "no Secrets Store exists yet on the account",
				Remediation: "the first store is created when the first secret is added (the engine needs roughly five: signer, break-glass public, optional operational keys, destination credentials)",
			})
		} else {
			// Count usage in the first store (accounts have one default store today).
			st := stores[0]
			countEnv, err := c.get("/accounts/" + c.account + "/secrets_store/stores/" + url.PathEscape(st.ID) + "/secrets?per_page=1")
			switch {
			case errors.Is(err, errTokenInvalid):
				return err
			case errors.Is(err, errInsufficientScope):
				report.Checks = append(report.Checks, PreflightCheck{
					ID: "secrets-store", Name: "Secrets Store headroom", Requires: "the account Secrets Store",
					Status: StatusUnknown, Evidence: "the store exists but its secret count could not be read",
					Remediation: "grant the token the Secrets Store read scope to check headroom",
				})
			case err != nil:
				report.Checks = append(report.Checks, PreflightCheck{
					ID: "secrets-store", Name: "Secrets Store headroom", Requires: "the account Secrets Store",
					Status: StatusUnknown, Evidence: "the store exists but its usage could not be read",
				})
			default:
				used := countEnv.ResultInfo.TotalCount
				free := secretsStoreDocumentedLimit - used
				status := StatusVerified
				remediation := ""
				if free < secretsStoreMinFree {
					status = StatusFailed
					remediation = "free Secrets Store slots are nearly exhausted: remove unused secrets or request a higher limit before onboarding (the engine needs roughly five)"
				}
				report.Checks = append(report.Checks, PreflightCheck{
					ID: "secrets-store", Name: "Secrets Store headroom", Requires: "the account Secrets Store",
					Status: status, Evidence: fmt.Sprintf("store %q holds %d secret(s); the documented per-store ceiling is %d (%d free)", st.Name, used, secretsStoreDocumentedLimit, free),
					Remediation: remediation,
				})
			}
		}
	}
	return nil
}

// checkLogpush reports whether a job already ships Workers logs (the SIEM path for the
// product's mirrored audit lines). Informational: absence is normal pre-onboarding. It
// returns errTokenInvalid (the only abort) on a 401.
func (c *Client) checkLogpush(report *AccountPreflight) error {
	env, err := c.get("/accounts/" + c.account + "/logpush/jobs")
	switch {
	case errors.Is(err, errTokenInvalid):
		return err
	case errors.Is(err, errInsufficientScope):
		report.Checks = append(report.Checks, PreflightCheck{
			ID: "logpush", Name: "Workers logs to a SIEM (Logpush)", Requires: "Workers Paid + a Logpush job for the workers_trace_events dataset",
			Status: StatusUnknown, Evidence: "the token cannot read Logpush jobs",
			Remediation: "grant the token Logs:Read to check, or configure Logpush in the dashboard",
		})
	case isTransient(err):
		report.Checks = append(report.Checks, PreflightCheck{
			ID: "logpush", Name: "Workers logs to a SIEM (Logpush)", Requires: "Workers Paid + a Logpush job",
			Status: StatusUnknown, Evidence: "Logpush jobs could not be read (a transient fault, not an account fact)",
		})
	case err != nil:
		report.Checks = append(report.Checks, PreflightCheck{
			ID: "logpush", Name: "Workers logs to a SIEM (Logpush)", Requires: "Workers Paid + a Logpush job",
			Status: StatusFailed, Evidence: redactToken(err.Error(), c.token),
		})
	default:
		var jobs []struct {
			Dataset string `json:"dataset"`
			Enabled bool   `json:"enabled"`
		}
		if err := json.Unmarshal(env.Result, &jobs); err != nil {
			report.Checks = append(report.Checks, PreflightCheck{
				ID: "logpush", Name: "Workers logs to a SIEM (Logpush)", Requires: "Workers Paid + a Logpush job",
				Status: StatusUnknown, Evidence: "the Logpush response could not be parsed",
			})
			return nil
		}
		n := 0
		for _, j := range jobs {
			if j.Dataset == "workers_trace_events" && j.Enabled {
				n++
			}
		}
		if n > 0 {
			report.Checks = append(report.Checks, PreflightCheck{
				ID: "logpush", Name: "Workers logs to a SIEM (Logpush)", Requires: "Workers Paid + a Logpush job for workers_trace_events",
				Status: StatusVerified, Evidence: fmt.Sprintf("%d enabled workers_trace_events Logpush job(s): the engine's mirrored audit lines will reach the configured destination", n),
			})
		} else {
			report.Checks = append(report.Checks, PreflightCheck{
				ID: "logpush", Name: "Workers logs to a SIEM (Logpush)", Requires: "Workers Paid + a Logpush job for workers_trace_events",
				Status: StatusUnconfigured, Evidence: "no enabled workers_trace_events Logpush job exists",
				Remediation: "optional: create a Logpush job to your SIEM (Splunk HEC, an HTTP collector for Sentinel/Exabeam/InsightIDR/NG-SIEM/Wazuh, or R2/S3); the engine also offers a credentialed pull API",
			})
		}
	}
	return nil
}

// checkR2Buckets lists the destination choice. Absence is fine (S3-compatible
// destinations work too); presence lists the names so onboarding can offer them. Only an
// AFFIRMATIVE API answer is reported as absence; a transient fault is unknown. It returns
// errTokenInvalid (the only abort) on a 401.
func (c *Client) checkR2Buckets(report *AccountPreflight) error {
	env, err := c.get("/accounts/" + c.account + "/r2/buckets")
	switch {
	case errors.Is(err, errTokenInvalid):
		return err
	case errors.Is(err, errInsufficientScope):
		report.Checks = append(report.Checks, PreflightCheck{
			ID: "r2", Name: "R2 buckets (destination choice)", Requires: "R2 enabled (or any S3-compatible bucket elsewhere)",
			Status: StatusUnknown, Evidence: "the token cannot read R2",
			Remediation: "grant the token Workers R2 Storage:Read to list buckets, or use an S3-compatible destination",
		})
	case isTransient(err):
		report.Checks = append(report.Checks, PreflightCheck{
			ID: "r2", Name: "R2 buckets (destination choice)", Requires: "R2 enabled (or any S3-compatible bucket elsewhere)",
			Status: StatusUnknown, Evidence: "R2 could not be read (a transient fault); this is not evidence R2 is absent",
		})
	case apiErrorHasCode(err, r2NotEnabledCode):
		// The ONLY affirmative absence: Cloudflare itself reports the account is not
		// entitled to use R2. Any other API error is a real failure, handled below.
		report.Checks = append(report.Checks, PreflightCheck{
			ID: "r2", Name: "R2 buckets (destination choice)", Requires: "R2 enabled",
			Status: StatusUnconfigured, Evidence: "R2 is not enabled on the account (Cloudflare reports the account is not entitled to use R2)",
			Remediation: "enable R2 (it has a free tier) or use any S3-compatible bucket as the destination",
		})
	case err != nil:
		// A non-transient API error that is NOT the affirmative "not enabled" answer
		// (a malformed request, a 4xx, an unexpected success:false). Reporting this as
		// "R2 not enabled" would mask a real outage as a missing feature, so it FAILS
		// with the redacted detail, matching the zones/workers-plan/logpush checks.
		report.Checks = append(report.Checks, PreflightCheck{
			ID: "r2", Name: "R2 buckets (destination choice)", Requires: "R2 enabled (or any S3-compatible bucket elsewhere)",
			Status: StatusFailed, Evidence: redactToken(err.Error(), c.token),
		})
	default:
		var wrapper struct {
			Buckets []struct {
				Name string `json:"name"`
			} `json:"buckets"`
		}
		if err := json.Unmarshal(env.Result, &wrapper); err != nil {
			report.Checks = append(report.Checks, PreflightCheck{
				ID: "r2", Name: "R2 buckets (destination choice)", Requires: "R2 enabled (or any S3-compatible bucket elsewhere)",
				Status: StatusUnknown, Evidence: "the R2 response could not be parsed",
			})
			return nil
		}
		for _, b := range wrapper.Buckets {
			report.R2Buckets = append(report.R2Buckets, b.Name)
		}
		report.Checks = append(report.Checks, PreflightCheck{
			ID: "r2", Name: "R2 buckets (destination choice)", Requires: "R2 enabled (or any S3-compatible bucket elsewhere)",
			Status: StatusVerified, Evidence: fmt.Sprintf("R2 is enabled (%d bucket(s) listed)", len(wrapper.Buckets)),
		})
	}
	return nil
}
