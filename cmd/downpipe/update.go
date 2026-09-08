package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/provision"
)

// cmdUpdate prints the ordered runbook for upgrading an already-deployed engine and console to a
// new, reviewed version, in a customer's own Cloudflare account, and then stops. Like init, it is a
// PLAN PRINTER, a runbook generator, not a live updater: it makes no network call and changes
// nothing. The operator reads the printed plan and runs the steps themselves (the version review,
// the wrangler deploys, and the final token revocation).
//
// This closes the upgrade gap where a long-running engine would otherwise need a standing deploy
// credential to apply a new version. An upgrade re-enters the bootstrap
// privilege state briefly: the operator re-creates the SAME scoped, short-lived deploy token they
// created at init time, deploys the reviewed new version, verifies readiness, and then DELETES the
// scoped token again. Between upgrades the running engine holds ZERO Cloudflare API token and
// reaches data only through bindings (least privilege by construction, the no-custody guarantee).
//
// The available version is pull-reviewed, never vendor-pushed: the engine PULLs a vendor-signed
// recommended-version channel (GET /admin/updates), verifies it against the pinned release-signer
// key, and surfaces it in the console (the Licence and updates screen). The operator reviews and
// approves the signature-verified version before deploying it; the vendor can never push a deploy.
//
// No-custody and safety: update never reads a token, never contacts Cloudflare, and prints no
// secret. The --execute flag is deliberately not implemented; it refuses and points the operator at
// the printed steps, so the command can never make a live call.
func cmdUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	version := fs.String("version", "", "the signature-verified version to deploy (optional; the plan reads it from /admin/updates if empty)")
	engineDomain := fs.String("engine-domain", "downpipe-engine.example.com", "custom domain the engine is reached on (custom domains only; never workers.dev)")
	consoleDomain := fs.String("console-domain", "downpipe-console.example.com", "custom domain the console is reached on")
	execute := fs.Bool("execute", false, "NOT IMPLEMENTED: update only prints the plan; run the printed steps yourself")
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	// The --execute flag is a deliberate refusal, not a live path. update is print-only by
	// construction: there is no branch that contacts Cloudflare, so it can never make a call.
	if *execute {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("update --execute is not implemented; run the printed steps yourself (each step is an explicit wrangler or dashboard action you perform on your own machine)")}
	}

	// Reject a workers.dev domain up front (house rule: custom domains only), so the printed
	// runbook never tells the operator to deploy onto a forbidden hostname.
	for _, h := range []string{*engineDomain, *consoleDomain} {
		if strings.HasSuffix(strings.ToLower(strings.TrimSpace(h)), ".workers.dev") {
			return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("domain %q is a workers.dev address; downpipes uses custom domains only", h)}
		}
	}

	fmt.Print(updatePlan(*version, *engineDomain, *consoleDomain))
	return nil
}

// updatePlan renders the ordered privilege-state-3 upgrade runbook as a single string. It is pure
// (no I/O, no network) so a test can assert its contents directly. The plan is redaction-safe: it
// names scopes, resources, versions and commands only, never a token or a secret value. The exact
// deploy-token scopes are NOT duplicated here; they live in https://github.com/downpipes-io/engine/blob/main/docs/CLOUDFLARE-PERMISSIONS.md
// and the plan points at the SAME token created at init time.
func updatePlan(version, engineDomain, consoleDomain string) string {
	var b strings.Builder

	versionLabel := "the signature-verified version reported by /admin/updates"
	if strings.TrimSpace(version) != "" {
		versionLabel = "version " + version
	}

	fmt.Fprintln(&b, "downpipe update: scoped-elevate, deploy, revoke upgrade runbook (print only; makes no Cloudflare call)")
	fmt.Fprintln(&b, "")
	fmt.Fprintln(&b, "This prints the ordered steps to upgrade your already-deployed engine and console to a new,")
	fmt.Fprintln(&b, "reviewed version, then stops. Nothing here is executed: run each step yourself. An upgrade")
	fmt.Fprintln(&b, "re-enters the bootstrap privilege state only for the deploy: you RE-CREATE the SAME scoped,")
	fmt.Fprintln(&b, "short-lived deploy token, deploy, verify, and then DELETE the token again. Between upgrades the")
	fmt.Fprintln(&b, "running engine holds NO Cloudflare API token and reaches data only through bindings.")
	fmt.Fprintln(&b, "Full reference: https://github.com/downpipes-io/engine/blob/main/docs/CLOUDFLARE-PERMISSIONS.md, https://github.com/downpipes-io/engine/blob/main/docs/UPDATES.md and https://github.com/downpipes-io/engine/blob/main/docs/OPERATIONS.md.")
	fmt.Fprintln(&b, "")
	fmt.Fprintf(&b, "Target: engine %s, console %s, upgrading to %s\n", engineDomain, consoleDomain, versionLabel)
	fmt.Fprintln(&b, "")

	writeUpdateStep1VersionVerify(&b)
	writeUpdateStep2ReElevate(&b)
	writeUpdateStep3Deploy(&b)
	writeUpdateStep4Verify(&b)
	writeUpdateStep5Rollback(&b)
	writeUpdateStep6Revoke(&b)

	fmt.Fprintln(&b, "update printed the plan and made no Cloudflare call. Run the steps above yourself.")

	return b.String()
}

// writeUpdateStep1VersionVerify writes step 1: confirm the available version is
// signature-verified (pull-reviewed, never vendor-pushed).
func writeUpdateStep1VersionVerify(b *strings.Builder) {
	fmt.Fprintln(b, "Step 1. Confirm the available version is signature-verified (pull-reviewed, never vendor-pushed)")
	fmt.Fprintln(b, "  The vendor cannot push a deploy. The engine PULLs a vendor-signed recommended-version channel")
	fmt.Fprintln(b, "  and verifies it against the pinned release-signer key; you review and approve it before")
	fmt.Fprintln(b, "  deploying. Check the version and that its signature verified:")
	fmt.Fprintln(b, "    - In the console, open the Licence and updates screen (the overview also badges when an")
	fmt.Fprintln(b, "      update is available). It shows recommendedVersion and updateAvailable from the engine.")
	fmt.Fprintln(b, "    - Or read it directly: GET /admin/updates on the engine must report configured: true and")
	fmt.Fprintln(b, "      verified: true for the recommendedVersion. A verified: false channel is NOT trusted; do")
	fmt.Fprintln(b, "      not deploy it. Where the artefact lists a sha384, confirm the artefact digest matches.")
	fmt.Fprintln(b, "  Only continue once the version you intend to deploy is the signature-verified one.")
	fmt.Fprintln(b, "")
}

// writeUpdateStep2ReElevate writes step 2: re-create the SAME scoped deploy token,
// referencing the canonical scopes rather than duplicating them.
func writeUpdateStep2ReElevate(b *strings.Builder) {
	fmt.Fprintln(b, "Step 2. Re-create the SAME scoped, short-lived deploy token (privilege state 3: re-elevate)")
	fmt.Fprintln(b, "  At My Profile > API Tokens > Create Token > Create Custom Token, re-create the SAME scoped")
	fmt.Fprintln(b, "  Account API token you used at init time. An in-place version upgrade needs only Workers")
	fmt.Fprintln(b, "  Scripts: Edit (plus Workers Routes: Edit if a route changed); re-create the full init token")
	fmt.Fprintln(b, "  set if this upgrade also adds or rebinds a resource. Do NOT broaden it. The exact scopes are")
	fmt.Fprintln(b, "  the same ones init prints; the canonical list is https://github.com/downpipes-io/engine/blob/main/docs/CLOUDFLARE-PERMISSIONS.md (do")
	fmt.Fprintln(b, "  not invent new permissions here).")
	fmt.Fprintf(b, "  Scope it tightly: limit to THIS one account; where Cloudflare offers a script filter, scope\n")
	fmt.Fprintf(b, "  Workers to the named scripts %s and %s. Set the shortest TTL the workflow allows.\n", provision.EngineScript, "downpipe-console")
	fmt.Fprintln(b, "  Then put it in this deploy session ONLY (never a file that outlives the session, never CI,")
	fmt.Fprintln(b, "  never the console, never the vendor):")
	fmt.Fprintln(b, "      export CLOUDFLARE_API_TOKEN=<the token>")
	fmt.Fprintln(b, "      export CLOUDFLARE_ACCOUNT_ID=<your account id>")
	fmt.Fprintln(b, "")
}

// writeUpdateStep3Deploy writes step 3: deploy the reviewed new version (engine and console). The
// engine MUST deploy via `npm run deploy`, NEVER a bare `wrangler deploy`: a bare deploy resets the
// worker's binding set to wrangler.toml (which deliberately lists ZERO sources) and SILENTLY DROPS
// every console-attached source binding. `npm run deploy` runs scripts/sync-bindings.mjs first to
// reconcile the live source bindings into a superset config, so the upgrade preserves them.
func writeUpdateStep3Deploy(b *strings.Builder) {
	fmt.Fprintln(b, "Step 3. Deploy the reviewed new version (engine and console)")
	fmt.Fprintln(b, "  First, record the engine's CURRENT live version id. This is your precise, binding-safe rollback")
	fmt.Fprintln(b, "  target (Step 5): it is the version that currently carries your console-attached source bindings,")
	fmt.Fprintln(b, "  so re-activating it later preserves them. Note the Active version id from:")
	fmt.Fprintln(b, "      cd engine && npx wrangler deployments list")
	fmt.Fprintln(b, "  Then check out or download the reviewed, signature-verified version, and deploy both Workers in")
	fmt.Fprintln(b, "  place (custom domains only; the existing routes, Durable Object and cron are preserved):")
	fmt.Fprintln(b, "      cd engine   && npm run deploy")
	fmt.Fprintln(b, "      cd console  && npx wrangler deploy")
	fmt.Fprintln(b, "  Deploy the engine with npm run deploy, NEVER a bare wrangler deploy. The engine's wrangler.toml")
	fmt.Fprintln(b, "  deliberately lists ZERO sources, so a bare `wrangler deploy` resets the engine's binding set to")
	fmt.Fprintln(b, "  that file and SILENTLY DROPS every source you attached from the console (each KV, R2, D1 and")
	fmt.Fprintln(b, "  Secrets Store source binding). Your next scheduled run then fails with")
	fmt.Fprintln(b, "  \"source binding ... is not present\". npm run deploy is the safe wrapper that PRESERVES them:")
	fmt.Fprintln(b, "  it runs scripts/sync-bindings.mjs to read the LIVE bindings and regenerate a superset")
	fmt.Fprintln(b, "  wrangler.deploy.toml, then deploys with that config (and refuses to deploy if it cannot prove")
	fmt.Fprintln(b, "  the sources survive). The console has no sources, so it deploys with plain wrangler.")
	fmt.Fprintln(b, "  This replaces the downpipe-engine and downpipe-console script with the new version and does NOT")
	fmt.Fprintln(b, "  touch your keys or secrets: the signer private and the break-glass recipient public are")
	fmt.Fprintln(b, "  unchanged, so no key ceremony is needed.")
	fmt.Fprintln(b, "")
}

// writeUpdateStep4Verify writes step 4: verify the upgrade with a SUCCESSFUL post-upgrade backup
// run, not merely ready: true. ready: true is presence-only (the keys are present and a destination
// resolves), NOT a health check: only a real run that seals every attached source proves the new
// version backs up AND that the source bindings survived the deploy. The revoke (Step 6) is gated
// on this, not on ready: true.
func writeUpdateStep4Verify(b *strings.Builder) {
	fmt.Fprintln(b, "Step 4. Verify readiness with a SUCCESSFUL backup run (not just ready: true)")
	fmt.Fprintln(b, "  Confirm GET /admin/status reports ready: true after the deploy (the signer private is present,")
	fmt.Fprintln(b, "  the recipient public is present, and a destination resolves) and that GET /admin/updates now")
	fmt.Fprintln(b, "  reports the deployed version as current with updateAvailable: false.")
	fmt.Fprintln(b, "  ready: true is presence-only, NOT a health check: it proves the keys and a destination are")
	fmt.Fprintln(b, "  present, not that this version actually backs up your sources. Do NOT gate the revoke (Step 6)")
	fmt.Fprintln(b, "  on it. Instead, watch the next scheduled run land in the run history and SUCCEED end to end, and")
	fmt.Fprintln(b, "  confirm the engine-version-change audit event for this upgrade. A successful run is also what")
	fmt.Fprintln(b, "  proves your console-attached source bindings survived the Step 3 deploy. Until that verified")
	fmt.Fprintln(b, "  run lands the upgrade is NOT confirmed; the engine will not run a backup until ready: true.")
	fmt.Fprintln(b, "")
}

// writeUpdateStep5Rollback writes step 5: the rollback contingency. If the upgrade did not verify
// (Step 4), roll the engine back to the previous version BEFORE the deploy token is revoked in Step
// 6 - a rollback needs that same scoped deploy capability, so it must happen while the token is
// still live. Rollback is binding-sensitive: a Worker version is an immutable code+bindings snapshot,
// so WHICH version you roll back to decides whether the console-attached sources survive. Rolling back
// to the PRE-UPGRADE version (recorded in Step 3) re-activates the snapshot that carried those sources
// and preserves them; a no-arg `wrangler rollback` reverts to the previous DEPLOYMENT chosen by recency,
// which can predate the source attachments and SILENTLY DROP them (the same binding-loss trap as a bare
// `wrangler deploy`, confirmed live). The console rollback is binding-safe by construction - it targets
// the version the engine recorded as live at apply-time - so it is preferred; the CLI fallback must
// target the SPECIFIC Step 3 version id, never a bare rollback.
func writeUpdateStep5Rollback(b *strings.Builder) {
	fmt.Fprintln(b, "Step 5. If the new version is unhealthy, roll back BEFORE you revoke the token")
	fmt.Fprintln(b, "  If Step 4 did not verify - the post-upgrade run failed, or the engine is otherwise unhealthy -")
	fmt.Fprintln(b, "  roll back to the previous version now, while the scoped deploy token from Step 2 is still live.")
	fmt.Fprintln(b, "  A rollback needs that same deploy capability, so it MUST happen before the revoke in Step 6")
	fmt.Fprintln(b, "  (revoke first and you would have to re-create the token just to roll back). A Worker version is")
	fmt.Fprintln(b, "  an immutable code+bindings snapshot, so WHICH version you roll back to decides whether your")
	fmt.Fprintln(b, "  console-attached sources survive - prefer the binding-safe console rollback:")
	fmt.Fprintln(b, "    - PREFERRED, binding-safe: from the console, POST /admin/update/rollback. The engine rolls")
	fmt.Fprintln(b, "      back to the exact version it recorded as live before the upgrade - the one that already")
	fmt.Fprintln(b, "      carried your console-attached source bindings - so they are preserved across the rollback.")
	fmt.Fprintln(b, "    - CLI fallback, TARGETED: re-activate the specific version id you noted in Step 3:")
	fmt.Fprintln(b, "          cd engine && npx wrangler versions deploy <the Step 3 version id>@100%")
	fmt.Fprintln(b, "      That version's binding snapshot (including your sources) becomes live again.")
	fmt.Fprintln(b, "  Do NOT roll back with a bare `npx wrangler rollback` (no version id): it reverts to the previous")
	fmt.Fprintln(b, "  DEPLOYMENT chosen by recency, which can predate your source attachments and SILENTLY DROP every")
	fmt.Fprintln(b, "  console-attached source - the same binding-loss trap as a bare `wrangler deploy`, and confirmed")
	fmt.Fprintln(b, "  on a live account. Always roll back to a known version id, not \"the previous one\".")
	fmt.Fprintln(b, "  After rolling back, CONFIRM your sources survived: re-run Step 4 (a successful backup proves the")
	fmt.Fprintln(b, "  bindings are intact), and check the Source bindings item in GET /admin/preflight - it reads the")
	fmt.Fprintln(b, "  engine's LIVE runtime bindings (ground truth), so it names any source a rollback dropped. Do not")
	fmt.Fprintln(b, "  rely on the dashboard's script-settings view, which can lag the active version after a rollback.")
	fmt.Fprintln(b, "  Only continue to the revoke once a verified-good version is deployed - whether the new one or the")
	fmt.Fprintln(b, "  rolled-back one - AND its source bindings are confirmed present.")
	fmt.Fprintln(b, "")
}

// writeUpdateStep6Revoke writes step 6: delete the scoped deploy token again and the
// bootstrap-token reminder. Gated on a verified-good version: only revoke once a SUCCESSFUL
// post-upgrade run has landed (Step 4) and you are not rolling back (Step 5).
func writeUpdateStep6Revoke(b *strings.Builder) {
	fmt.Fprintln(b, "Step 6. Now DELETE the scoped deploy token again (back to privilege state 2: the no-custody runtime)")
	fmt.Fprintln(b, "  Once the upgrade is verified by a SUCCESSFUL post-upgrade run (Step 4) - not merely ready: true -")
	fmt.Fprintln(b, "  and you are not rolling back (Step 5), revoke the token you re-created in Step 2. After this the")
	fmt.Fprintln(b, "  system is back to running with NO Cloudflare API token anywhere: the engine holds none and")
	fmt.Fprintln(b, "  reaches data only through its bindings (least privilege by construction, the no-custody")
	fmt.Fprintln(b, "  guarantee), and there is no standing deploy credential left to leak. The engine must NEVER hold")
	fmt.Fprintln(b, "  a standing deploy token between upgrades.")
	fmt.Fprintln(b, "      My Profile > API Tokens > the token you re-created in Step 2 > Delete")
	fmt.Fprintln(b, "      https://dash.cloudflare.com/profile/api-tokens")
	fmt.Fprintln(b, "  Also: unset CLOUDFLARE_API_TOKEN in this shell.")
	fmt.Fprintln(b, "  Bootstrap token reminder: if this upgrade re-set a bootstrap token (ADMIN_TOKEN), retire or")
	fmt.Fprintln(b, "  delete it again afterwards the same way init does. Do not leave a deploy-time break-glass")
	fmt.Fprintln(b, "  token live: anyone with the string can take admin. Once your passkey works AND your recovery")
	fmt.Fprintln(b, "  codes are saved, either retire it in the console Security Centre using the")
	fmt.Fprintln(b, "  \"Retire break-glass token\" affordance (immediate, no redeploy), or delete the secret:")
	fmt.Fprintln(b, "      cd engine && npx wrangler secret delete ADMIN_TOKEN")
	fmt.Fprintln(b, "  The engine will refuse to retire until a way back in exists (recovery codes saved or a second")
	fmt.Fprintln(b, "  Owner). The offline break-glass KEY (for DATA recovery) is a separate thing from these admin")
	fmt.Fprintln(b, "  sign-in recovery codes.")
	fmt.Fprintln(b, "")
}
