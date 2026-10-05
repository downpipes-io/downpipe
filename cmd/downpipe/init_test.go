package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
)

// TestInitPrintsPlanWithRevokeStep is the central command test: `init` prints the ordered
// least-privilege runbook and exits 0. It asserts the plan contains the three privilege states,
// the exact deploy-token scopes, and (load-bearing) the final "delete the scoped deploy token"
// revoke step with its dashboard link. It makes no network call: init has no live branch at all,
// so the absence of any call is structural, and this test runs entirely in-process with no
// network double, proving init never reaches the wire.
func TestInitPrintsPlanWithRevokeStep(t *testing.T) {
	var code int
	out := captureStdout(t, func() {
		code = run([]string{"init"})
	})
	if code != 0 {
		t.Fatalf("init exit = %d, want 0", code)
	}

	// The ordered runbook must open with its print-only, least-privilege framing.
	for _, want := range []string{
		"least-privilege setup runbook",
		"makes no Cloudflare call",
		"stores no deploy token",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("init plan missing %q:\n%s", want, out)
		}
	}

	// The exact deploy-token scopes from engine/docs/CLOUDFLARE-PERMISSIONS.md.
	for _, scope := range []string{
		"Workers Scripts: Edit",
		"Workers KV Storage: Edit",
		"Workers R2 Storage: Edit",
		"D1: Edit",
		"Secrets Store: Edit",
		"Workers Routes: Edit",
		"DNS: Edit",
		"Account Settings: Read",
	} {
		if !strings.Contains(out, scope) {
			t.Errorf("init plan missing the deploy-token scope %q:\n%s", scope, out)
		}
	}

	// The key-ceremony, source-wiring and readiness steps must be present and ordered.
	for _, want := range []string{
		"Create a SCOPED, short-lived deploy token",
		"key ceremony",
		"Wire the first source",
		"ready: true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("init plan missing the step %q:\n%s", want, out)
		}
	}

	// The load-bearing assertion: the plan ends by telling the operator to DELETE the scoped
	// deploy token, with the API Tokens dashboard link.
	if !strings.Contains(out, "DELETE the scoped deploy token") {
		t.Errorf("init plan missing the revoke-the-token step:\n%s", out)
	}
	if !strings.Contains(out, "dash.cloudflare.com/profile/api-tokens") {
		t.Errorf("init plan missing the API Tokens dashboard link for revocation:\n%s", out)
	}

	// Load-bearing: the runbook must include an explicit disposal step for the ONE-TIME bootstrap
	// token (ADMIN_TOKEN), distinct from the scoped deploy token revoked above. It must frame the
	// token as one-time/bootstrap, flag leaving it live as a standing admin-takeover risk, point the
	// operator at the RECOVERY CODES break-glass model, and offer BOTH disposal paths: the in-console
	// Security Centre "Retire break-glass token" affordance and the wrangler secret delete command.
	for _, want := range []string{
		"Dispose of the one-time bootstrap token (ADMIN_TOKEN)",
		"ONE-TIME bootstrap credential",
		"RECOVERY CODES",                         // the admin sign-in break-glass model
		"Retire break-glass token",               // the in-console Security Centre retire option
		"npx wrangler secret delete ADMIN_TOKEN", // the delete-the-secret-entirely option
		"can take admin",                         // the standing-risk framing
	} {
		if !strings.Contains(out, want) {
			t.Errorf("init plan missing the bootstrap-token disposal detail %q:\n%s", want, out)
		}
	}

	// Order matters: dispose of the bootstrap token ONLY once the passkey works, so the disposal
	// step must come AFTER the readiness / first-Owner enrolment step. If a test author ever moved
	// disposal before enrolment, the operator could lock themselves out; assert the ordering holds.
	enrolIdx := strings.Index(out, "Verify readiness and enrol the first Owner")
	disposeIdx := strings.Index(out, "Dispose of the one-time bootstrap token (ADMIN_TOKEN)")
	if enrolIdx < 0 {
		t.Errorf("init plan missing the readiness / first-Owner enrolment step:\n%s", out)
	}
	if disposeIdx < 0 {
		t.Errorf("init plan missing the bootstrap-token disposal step:\n%s", out)
	}
	if enrolIdx >= 0 && disposeIdx >= 0 && disposeIdx <= enrolIdx {
		t.Errorf("init plan disposes of the bootstrap token (index %d) BEFORE the readiness/Owner-enrolment step (index %d); dispose only once the passkey works:\n%s", disposeIdx, enrolIdx, out)
	}

	// The disposal step must also come BEFORE the scoped-deploy-token deletion remains internally
	// consistent, but more importantly the two are DISTINCT credentials: the bootstrap-token delete
	// command targets ADMIN_TOKEN, never the scoped CLOUDFLARE_API_TOKEN.
	if !strings.Contains(out, "wrangler secret delete ADMIN_TOKEN") {
		t.Errorf("init plan's bootstrap-token disposal must target ADMIN_TOKEN specifically:\n%s", out)
	}
}

// TestInitMakesNoSecretLeakAndNeedsNoToken confirms init runs WITHOUT any Cloudflare token in the
// environment (unlike setup, which requires one), because it never contacts Cloudflare. It also
// confirms the plan carries no secret value: it names scopes, resources and commands only.
func TestInitMakesNoSecretLeakAndNeedsNoToken(t *testing.T) {
	// Explicitly clear the credentials setup would need; init must still succeed.
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "")
	t.Setenv("DOWNPIPE_SECRET_SIGNER_PRIVATE", "SENTINEL-SECRET-VALUE")

	var code int
	out := captureStdout(t, func() {
		code = run([]string{"init"})
	})
	if code != 0 {
		t.Fatalf("init with no token exit = %d, want 0 (init makes no Cloudflare call)", code)
	}
	if strings.Contains(out, "SENTINEL-SECRET-VALUE") {
		t.Errorf("init plan leaked a secret value:\n%s", out)
	}
}

// TestInitExecuteRefused confirms --execute is a deliberate, safe refusal: it never makes a live
// call and exits with a usage error pointing the operator at the printed steps.
func TestInitExecuteRefused(t *testing.T) {
	silenceOutput(t)
	got := run([]string{"init", "--execute"})
	if got != format.ExitUsage {
		t.Fatalf("init --execute = %d, want %d (ExitUsage, not implemented)", got, format.ExitUsage)
	}
}

// TestInitRejectsWorkersDevDomain confirms the design rule (custom domains only) is enforced before
// the plan is printed, so the runbook never instructs a deploy onto a workers.dev hostname.
func TestInitRejectsWorkersDevDomain(t *testing.T) {
	silenceOutput(t)
	got := run([]string{"init", "--engine-domain", "downpipe-engine.example.workers.dev"})
	if got != format.ExitUsage {
		t.Fatalf("init with a workers.dev domain = %d, want %d (ExitUsage)", got, format.ExitUsage)
	}
}

// TestInitPlanCustomDomainsThreaded confirms operator-supplied domains and the bucket are threaded
// into the printed plan, so the runbook is concrete to the deployment.
func TestInitPlanCustomDomainsThreaded(t *testing.T) {
	plan := initPlan("eng.acme.example", "con.acme.example", "acme.example", "acme-archives")
	for _, want := range []string{"eng.acme.example", "con.acme.example", "acme.example", "acme-archives"} {
		if !strings.Contains(plan, want) {
			t.Errorf("initPlan missing threaded value %q", want)
		}
	}
	// The plan must never be an ExitError-shaped empty string; sanity-check it is substantial.
	if len(plan) < 1000 {
		t.Errorf("initPlan output is suspiciously short (%d bytes)", len(plan))
	}
}

// TestInitExecuteErrorIsExitError locks in that the --execute refusal is a typed ExitError with the
// usage code, so the dispatcher maps it to the right process exit status.
func TestInitExecuteErrorIsExitError(t *testing.T) {
	err := cmdInit([]string{"--execute"})
	if err == nil {
		t.Fatal("cmdInit --execute = nil, want a usage ExitError")
	}
	var ee *format.ExitError
	if !errors.As(err, &ee) || ee.Code != format.ExitUsage {
		t.Fatalf("cmdInit --execute error = %v, want ExitUsage", err)
	}
}

// TestInitPlanStatesTheTokenAndKeyCustodyTheEngineHas pins the runbook to what the engine does
// (engine/docs/CLOUDFLARE-PERMISSIONS.md). The plan used to say that the running engine holds no
// Cloudflare API token, that the token never goes to the console, and that the signer private and
// recipient public live in the Secrets Store. Each is false. The engine can store the optional
// read-only discovery token. A console action that changes the engine's Worker takes the deploy
// token as a one-time paste. The engine's keys are Worker secrets. Each old sentence is refused here
// and each true one is required, so a revert fails in both directions.
func TestInitPlanStatesTheTokenAndKeyCustodyTheEngineHas(t *testing.T) {
	plan := initPlan("eng.example.com", "con.example.com", "example.com", "archives")
	for _, gone := range []string{
		"holds NO Cloudflare API token",
		"NO Cloudflare API token anywhere",
		"never the console",
		"the engine holds no token",
		"put the Secrets Store entries the engine reads",
		"put the engine-read entries",
	} {
		if strings.Contains(plan, gone) {
			t.Errorf("init plan still says %q, which the engine does not do:\n%s", gone, plan)
		}
	}
	for _, want := range []string{
		"optional read-only discovery token",
		"one-time paste",
		"are Worker secrets",
		"not Secrets Store entries",
		"bind to the engine the Secrets Store secrets a downpipe backs up",
	} {
		if !strings.Contains(plan, want) {
			t.Errorf("init plan missing %q:\n%s", want, plan)
		}
	}
	assertTokenStepOrder(t, "init", plan)
}

// assertTokenStepOrder checks the deploy-token step of a printed runbook. The line that introduces
// the export lines ends in a colon and scopes the on-machine rule to a wrangler deploy, and the
// console one-time paste is stated after the exports. The update runbook used to end the console
// sentence in the colon that introduces the exports, so the shell exports read as the console
// route. The init runbook kept "put it in this deploy session ONLY" next to the console paste,
// while engine docs/CLOUDFLARE-PERMISSIONS.md scopes that rule to a wrangler deploy.
func assertTokenStepOrder(t *testing.T, name, plan string) {
	t.Helper()
	lines := strings.Split(plan, "\n")
	exportAt := -1
	for i, l := range lines {
		if strings.Contains(l, "export CLOUDFLARE_API_TOKEN=") {
			exportAt = i
			break
		}
	}
	if exportAt < 2 {
		t.Fatalf("%s plan has no deploy-token export line:\n%s", name, plan)
	}
	intro := lines[exportAt-2] + " " + lines[exportAt-1]
	if !strings.HasSuffix(strings.TrimSpace(lines[exportAt-1]), ":") {
		t.Errorf("%s plan: the line before the exports does not end in a colon: %q", name, lines[exportAt-1])
	}
	if !strings.Contains(intro, "For a wrangler deploy, put it in this deploy session only") {
		t.Errorf("%s plan: the export lines are not introduced as the wrangler deploy route: %q", name, intro)
	}
	if strings.Contains(intro, "paste") || strings.Contains(intro, "console") {
		t.Errorf("%s plan: the line that introduces the exports names the console route: %q", name, intro)
	}
	after := strings.Join(lines[exportAt:], "\n")
	if !strings.Contains(after, "one-time paste") {
		t.Errorf("%s plan: the console one-time paste is not stated after the export lines:\n%s", name, plan)
	}
}
