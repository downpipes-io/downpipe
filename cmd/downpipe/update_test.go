package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
)

// TestUpdatePrintsPlanWithRevokeStep is the central command test: `update` prints the ordered
// scoped-elevate, deploy, verify, rollback, revoke upgrade runbook and exits 0. It asserts the plan
// contains, in order, the version-verify step, the re-elevate (re-create the same scoped token)
// step, the deploy step, the readiness step, and (load-bearing) the final "delete the scoped deploy
// token" revoke step with its dashboard link. It also locks in the #1 update-safety fix: the engine
// deploys via the safe `npm run deploy` (never a bare wrangler deploy, which would silently drop
// console-attached source bindings), the revoke is gated on a SUCCESSFUL post-upgrade run (not just
// ready: true), and a rollback contingency precedes the revoke. It makes no network call: update has
// no live branch at all, so the absence of any call is structural, and this test runs entirely
// in-process with no network double, proving update never reaches the wire.
func TestUpdatePrintsPlanWithRevokeStep(t *testing.T) {
	var code int
	out := captureStdout(t, func() {
		code = run([]string{"update"})
	})
	if code != 0 {
		t.Fatalf("update exit = %d, want 0", code)
	}

	// The ordered runbook must open with its print-only, no-custody framing.
	for _, want := range []string{
		"upgrade runbook",
		"makes no Cloudflare call",
		"holds NO Cloudflare API token",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("update plan missing %q:\n%s", want, out)
		}
	}

	// The ordered runbook step anchors must all be present, in order (the rollback step that now sits
	// between the readiness step and the revoke step is asserted separately below).
	steps := []string{
		"Confirm the available version is signature-verified",
		"Re-create the SAME scoped, short-lived deploy token",
		"Deploy the reviewed new version",
		"Verify readiness",
		"DELETE the scoped deploy token again",
	}
	for _, want := range steps {
		if !strings.Contains(out, want) {
			t.Errorf("update plan missing the step %q:\n%s", want, out)
		}
	}
	// Assert the steps appear in the intended order (each later step after the previous one).
	prev := -1
	for _, want := range steps {
		i := strings.Index(out, want)
		if i <= prev {
			t.Errorf("update plan step %q is out of order (index %d, previous %d):\n%s", want, i, prev, out)
		}
		prev = i
	}

	// Step 1 must point at the pull-reviewed update surfaces: the engine endpoint and the console.
	for _, want := range []string{
		"/admin/updates",
		"pull-reviewed, never vendor-pushed",
		"Licence and updates",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("update plan missing the version-verify reference %q:\n%s", want, out)
		}
	}

	// Step 2 must reference the canonical scopes doc rather than duplicating the full permission
	// list, and must re-create the SAME token (not broaden it).
	if !strings.Contains(out, "https://github.com/downpipes-io/engine/blob/main/docs/CLOUDFLARE-PERMISSIONS.md") {
		t.Errorf("update plan missing the CLOUDFLARE-PERMISSIONS.md reference for the scoped token:\n%s", out)
	}

	// Step 4 must verify readiness via the engine's ready: true status.
	if !strings.Contains(out, "ready: true") {
		t.Errorf("update plan missing the readiness (ready: true) check:\n%s", out)
	}

	// THE #1 UPDATE-SAFETY FIX. Step 3 must deploy the engine via the SAFE wrapper `npm run deploy`,
	// never a bare `wrangler deploy`: a bare deploy resets the engine's binding set to wrangler.toml
	// (which lists ZERO sources) and SILENTLY DROPS every console-attached source binding; npm run
	// deploy reconciles the live bindings via scripts/sync-bindings.mjs so they survive the upgrade.
	if !strings.Contains(out, "cd engine   && npm run deploy") {
		t.Errorf("update plan must deploy the engine with the safe `npm run deploy`, not bare wrangler:\n%s", out)
	}
	if strings.Contains(out, "cd engine   && npx wrangler deploy") {
		t.Errorf("update plan still tells the operator to run a bare engine `wrangler deploy`:\n%s", out)
	}
	// The old, FALSE reassurance that a deploy does not touch source bindings must be gone, replaced
	// by the accurate explanation that the bindings survive ONLY because npm run deploy reconciles them.
	if strings.Contains(out, "NOT touch your keys, secrets or source bindings") {
		t.Errorf("update plan still carries the false 'does not touch source bindings' reassurance:\n%s", out)
	}
	for _, want := range []string{
		"NEVER a bare wrangler deploy",
		"sync-bindings",
		"source binding",
		"is not present",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("update plan missing the binding-preservation explanation %q:\n%s", want, out)
		}
	}

	// The revoke must be gated on a SUCCESSFUL, verified post-upgrade run, not merely on ready: true
	// (which the plan must call out as presence-only, not a health check).
	for _, want := range []string{
		"presence-only",
		"SUCCESSFUL",
		"engine-version-change audit event",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("update plan missing the gate-revoke-on-a-successful-run detail %q:\n%s", want, out)
		}
	}

	// A rollback contingency must be offered and must come BEFORE the revoke step (a rollback needs the
	// still-live scoped deploy token). Rollback is BINDING-SENSITIVE (proven live on a real account): a
	// Worker version is an immutable code+bindings snapshot, so WHICH version is re-activated decides
	// whether the console-attached sources survive. The plan must therefore (1) offer the PREFERRED
	// binding-safe console rollback, (2) give the CLI fallback as a TARGETED re-activation of the Step 3
	// version id (wrangler versions deploy <id>@100%), and (3) warn AGAINST a bare `wrangler rollback`
	// (no version id), which reverts to the previous deployment by recency and can silently drop sources.
	for _, want := range []string{
		"roll back",
		"/admin/update/rollback",          // the preferred, binding-safe console rollback
		"binding-safe",                    // the plan names it as such
		"npx wrangler versions deploy",    // the TARGETED CLI fallback (a specific version id)
		"@100%",                           // re-activate that exact version at 100%
		"Do NOT roll back with a bare",    // the explicit warning against the unsafe form
		"predate your source attachments", // names the mechanism of the loss
	} {
		if !strings.Contains(out, want) {
			t.Errorf("update plan missing the binding-safe rollback contingency %q:\n%s", want, out)
		}
	}
	// The OLD unsafe instruction - a bare, version-less `wrangler rollback` offered as a runnable command -
	// must be gone. Its distinctive parenthetical is asserted absent so a regression that re-adds the
	// command (not just the named-and-warned-against mention) fails this test.
	if strings.Contains(out, "roll the engine Worker back to its prior deployment") {
		t.Errorf("update plan still offers a bare, version-less `wrangler rollback` command (the proven source-loss vector):\n%s", out)
	}
	// Step 3 must tell the operator to RECORD the current live version id first - the precise, binding-safe
	// rollback target the CLI fallback re-activates.
	for _, want := range []string{
		"record the engine's CURRENT live version id",
		"wrangler deployments list",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("update plan missing the Step 3 rollback-target capture %q:\n%s", want, out)
		}
	}
	// After a rollback the plan must tell the operator to CONFIRM the sources survived, reading the engine's
	// LIVE runtime bindings (preflight ground truth), not the lagging dashboard script-settings view.
	for _, want := range []string{
		"/admin/preflight",
		"Source bindings",
		"ground truth",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("update plan missing the post-rollback source-survival confirmation %q:\n%s", want, out)
		}
	}
	if i, j := strings.Index(out, "/admin/update/rollback"), strings.Index(out, "DELETE the scoped deploy token again"); i < 0 || j < 0 || i > j {
		t.Errorf("rollback contingency must appear BEFORE the token-revocation step (rollback %d, revoke %d):\n%s", i, j, out)
	}

	// The load-bearing assertion: the plan ends by telling the operator to DELETE the scoped
	// deploy token again, with the API Tokens dashboard link, so the engine holds no standing token.
	if !strings.Contains(out, "DELETE the scoped deploy token again") {
		t.Errorf("update plan missing the revoke-the-token-again step:\n%s", out)
	}
	if !strings.Contains(out, "dash.cloudflare.com/profile/api-tokens") {
		t.Errorf("update plan missing the API Tokens dashboard link for revocation:\n%s", out)
	}
	if !strings.Contains(out, "no standing deploy credential left to leak") {
		t.Errorf("update plan missing the no-standing-token guarantee:\n%s", out)
	}

	// The bootstrap-token reminder: if an upgrade re-set a bootstrap token (ADMIN_TOKEN), the runbook
	// must remind the operator to retire or delete it again afterwards (same paths as init), and must
	// not leave a deploy-time break-glass token live. Assert it names the RECOVERY CODES break-glass
	// model and both disposal paths: the in-console Security Centre retire affordance and the wrangler
	// secret delete command.
	for _, want := range []string{
		"if this upgrade re-set a bootstrap token (ADMIN_TOKEN)",
		"recovery codes",
		"Retire break-glass token",
		"wrangler secret delete ADMIN_TOKEN",
		"Do not leave a deploy-time break-glass",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("update plan missing the bootstrap-token reminder detail %q:\n%s", want, out)
		}
	}
}

// TestUpdateMakesNoSecretLeakAndNeedsNoToken confirms update runs WITHOUT any Cloudflare token in
// the environment (unlike setup, which requires one), because it never contacts Cloudflare. It also
// confirms the plan carries no secret value: it names scopes, resources, versions and commands only.
func TestUpdateMakesNoSecretLeakAndNeedsNoToken(t *testing.T) {
	// Explicitly clear the credentials setup would need; update must still succeed.
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "")
	t.Setenv("DOWNPIPE_SECRET_SIGNER_PRIVATE", "SENTINEL-SECRET-VALUE")

	var code int
	out := captureStdout(t, func() {
		code = run([]string{"update"})
	})
	if code != 0 {
		t.Fatalf("update with no token exit = %d, want 0 (update makes no Cloudflare call)", code)
	}
	if strings.Contains(out, "SENTINEL-SECRET-VALUE") {
		t.Errorf("update plan leaked a secret value:\n%s", out)
	}
}

// TestUpdateExecuteRefused confirms --execute is a deliberate, safe refusal: it never makes a live
// call and exits with a usage error pointing the operator at the printed steps.
func TestUpdateExecuteRefused(t *testing.T) {
	silenceOutput(t)
	got := run([]string{"update", "--execute"})
	if got != format.ExitUsage {
		t.Fatalf("update --execute = %d, want %d (ExitUsage, not implemented)", got, format.ExitUsage)
	}
}

// TestUpdateRejectsWorkersDevDomain confirms the house rule (custom domains only) is enforced before
// the plan is printed, so the runbook never instructs a deploy onto a workers.dev hostname.
func TestUpdateRejectsWorkersDevDomain(t *testing.T) {
	silenceOutput(t)
	got := run([]string{"update", "--engine-domain", "downpipe-engine.example.workers.dev"})
	if got != format.ExitUsage {
		t.Fatalf("update with a workers.dev domain = %d, want %d (ExitUsage)", got, format.ExitUsage)
	}
}

// TestUpdatePlanThreadsVersionAndDomains confirms the operator-supplied version and domains are
// threaded into the printed plan, so the runbook is concrete to the upgrade.
func TestUpdatePlanThreadsVersionAndDomains(t *testing.T) {
	plan := updatePlan("1.4.2", "eng.acme.example", "con.acme.example")
	for _, want := range []string{"version 1.4.2", "eng.acme.example", "con.acme.example"} {
		if !strings.Contains(plan, want) {
			t.Errorf("updatePlan missing threaded value %q", want)
		}
	}
	// The plan must never be an ExitError-shaped empty string; sanity-check it is substantial.
	if len(plan) < 1000 {
		t.Errorf("updatePlan output is suspiciously short (%d bytes)", len(plan))
	}
}

// TestUpdatePlanWithoutVersionReadsFromChannel confirms that with no --version the plan defers to
// the signature-verified version reported by /admin/updates rather than inventing one.
func TestUpdatePlanWithoutVersionReadsFromChannel(t *testing.T) {
	plan := updatePlan("", "eng.acme.example", "con.acme.example")
	if !strings.Contains(plan, "the signature-verified version reported by /admin/updates") {
		t.Errorf("updatePlan with no version should defer to /admin/updates:\n%s", plan)
	}
}

// TestUpdateExecuteErrorIsExitError locks in that the --execute refusal is a typed ExitError with
// the usage code, so the dispatcher maps it to the right process exit status.
func TestUpdateExecuteErrorIsExitError(t *testing.T) {
	err := cmdUpdate([]string{"--execute"})
	if err == nil {
		t.Fatal("cmdUpdate --execute = nil, want a usage ExitError")
	}
	var ee *format.ExitError
	if !errors.As(err, &ee) || ee.Code != format.ExitUsage {
		t.Fatalf("cmdUpdate --execute error = %v, want ExitUsage", err)
	}
}
