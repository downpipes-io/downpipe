package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/provision"
)

// cmdInit prints the full least-privilege setup runbook for standing the engine and console
// up in a customer's own Cloudflare account, in order, and then stops. It is a PLAN PRINTER, a
// runbook generator, not a live provisioner: it makes no network call and creates nothing. The
// operator reads the printed plan and runs the steps themselves (the wrangler commands, the
// browser key ceremony, and the final token revocation).
//
// The plan follows the three privilege states documented in https://github.com/downpipes-io/engine/blob/main/docs/CLOUDFLARE-PERMISSIONS.md:
//  1. create a SCOPED, short-lived deploy token (the exact scopes are printed),
//  2. provision resources, deploy, run the key ceremony, wire a source and verify readiness, all of
//     which leave the running engine holding ZERO Cloudflare API token (least privilege by
//     construction: the engine reaches data only through bindings),
//  3. finally DELETE the scoped deploy token, so no standing deploy credential is left behind.
//
// No-custody and safety: init never reads a token, never contacts Cloudflare, and prints no secret.
// The --execute flag is deliberately not implemented; it refuses and points the operator at the
// printed steps, so the command can never make a live call.
func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	engineDomain := fs.String("engine-domain", "downpipe-engine.example.com", "custom domain the engine is reached on (custom domains only; never workers.dev)")
	consoleDomain := fs.String("console-domain", "downpipe-console.example.com", "custom domain the console is reached on")
	zone := fs.String("zone", "example.com", "the Cloudflare zone that hosts the engine and console domains")
	archiveBucket := fs.String("archive-bucket", "downpipe-archives", "R2 bucket name the engine writes archives into")
	execute := fs.Bool("execute", false, "reserved; init is print-only and makes no live call: run the printed steps yourself")
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	// The --execute flag is a deliberate refusal, not a live path. init is print-only by
	// construction: there is no branch that contacts Cloudflare, so it can never make a call.
	if *execute {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("init --execute is not implemented; run the printed steps yourself (each step is an explicit wrangler or dashboard action you perform on your own machine)")}
	}

	// Reject a workers.dev domain up front (house rule: custom domains only), so the printed
	// runbook never tells the operator to deploy onto a forbidden hostname.
	for _, h := range []string{*engineDomain, *consoleDomain} {
		if strings.HasSuffix(strings.ToLower(strings.TrimSpace(h)), ".workers.dev") {
			return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("domain %q is a workers.dev address; downpipes uses custom domains only", h)}
		}
	}

	fmt.Print(initPlan(*engineDomain, *consoleDomain, *zone, *archiveBucket))
	return nil
}

// initPlan renders the ordered, least-privilege setup runbook as a single string. It is pure (no
// I/O, no network) so a test can assert its contents directly. The plan is redaction-safe: it
// names scopes, resources and commands only, never a token or a secret value.
func initPlan(engineDomain, consoleDomain, zone, archiveBucket string) string {
	var b strings.Builder

	fmt.Fprintln(&b, "downpipe init: least-privilege setup runbook (print only; makes no Cloudflare call)")
	fmt.Fprintln(&b, "")
	fmt.Fprintln(&b, "This prints the ordered steps to deploy the engine and console into your own Cloudflare")
	fmt.Fprintln(&b, "account with least privilege, then stops. Nothing here is executed: run each step yourself.")
	fmt.Fprintln(&b, "The deploy capability is a SCOPED, short-lived token you create, use, and then DELETE; the")
	fmt.Fprintln(&b, "running engine holds NO Cloudflare API token and reaches data only through bindings.")
	fmt.Fprintln(&b, "Full reference: https://github.com/downpipes-io/engine/blob/main/docs/CLOUDFLARE-PERMISSIONS.md and https://github.com/downpipes-io/engine/blob/main/docs/OPERATIONS.md.")
	fmt.Fprintln(&b, "")
	fmt.Fprintf(&b, "Target: engine %s, console %s, zone %s, archive bucket %s\n", engineDomain, consoleDomain, zone, archiveBucket)
	fmt.Fprintln(&b, "")

	// Step 1: the scoped deploy token. The scopes printed here are exactly those in
	// https://github.com/downpipes-io/engine/blob/main/docs/CLOUDFLARE-PERMISSIONS.md.
	fmt.Fprintln(&b, "Step 1. Create a SCOPED, short-lived deploy token (privilege state 1: bootstrap)")
	fmt.Fprintln(&b, "  At My Profile > API Tokens > Create Token > Create Custom Token, create an Account API")
	fmt.Fprintln(&b, "  token with EXACTLY these permissions:")
	fmt.Fprintln(&b, "    - Workers Scripts: Edit        (upload the engine and console; covers the cron trigger)")
	fmt.Fprintln(&b, "    - Workers KV Storage: Edit     (create and bind KV source namespaces)")
	fmt.Fprintln(&b, "    - Workers R2 Storage: Edit     (create the archive bucket and any R2 source buckets)")
	fmt.Fprintln(&b, "    - D1: Edit                     (create and bind D1 source databases)")
	fmt.Fprintln(&b, "    - Secrets Store: Edit          (create and put the Secrets Store entries the engine reads)")
	fmt.Fprintln(&b, "    - Workers Routes: Edit         (attach the engine and console custom-domain routes)")
	fmt.Fprintln(&b, "    - DNS: Edit                    (provision the DNS records the routes resolve through)")
	fmt.Fprintln(&b, "    - Account Settings: Read       (resolve the account and its subscriptions at deploy time)")
	fmt.Fprintln(&b, "  Scope it tightly: limit to THIS one account; limit the DNS edit to the one zone")
	fmt.Fprintf(&b, "  (%s); and where Cloudflare offers a script filter, scope Workers to the named scripts\n", zone)
	fmt.Fprintf(&b, "  %s and %s. Set the shortest TTL the workflow allows.\n", provision.EngineScript, provision.ConsoleScript)
	fmt.Fprintln(&b, "  Then put it in this deploy session ONLY (never a file that outlives the session, never CI,")
	fmt.Fprintln(&b, "  never the console, never the vendor):")
	fmt.Fprintln(&b, "      export CLOUDFLARE_API_TOKEN=<the token>")
	fmt.Fprintln(&b, "      export CLOUDFLARE_ACCOUNT_ID=<your account id>")
	fmt.Fprintln(&b, "")

	// Step 2: provision the resources the engine needs.
	fmt.Fprintln(&b, "Step 2. Provision the resources the engine needs (privilege state 1 continues)")
	fmt.Fprintln(&b, "  Create the destination and source resources, then declare them as bindings in")
	fmt.Fprintln(&b, "  engine/wrangler.toml. The binding IS the credential: the engine holds no token, only bindings.")
	fmt.Fprintf(&b, "    - R2 archive bucket (destination):  npx wrangler r2 bucket create %s\n", archiveBucket)
	fmt.Fprintln(&b, "        then in engine/wrangler.toml: [[r2_buckets]] binding=\"DEST_R2\" bucket_name as above")
	fmt.Fprintln(&b, "    - KV source namespace(s):           npx wrangler kv namespace create <NAME>")
	fmt.Fprintln(&b, "        then: [[kv_namespaces]] binding=\"SRC_KV_<name>\" id=<the returned id>")
	fmt.Fprintln(&b, "    - R2 source bucket(s) (optional):   add [[r2_buckets]] binding=\"SRC_R2_<name>\"")
	fmt.Fprintln(&b, "    - D1 source database(s):            npx wrangler d1 create <NAME>")
	fmt.Fprintln(&b, "        then: [[d1_databases]] binding=\"SRC_D1_<name>\" database_id=<the returned id>")
	fmt.Fprintln(&b, "    - Secrets Store + entries:          create a store, then put the engine-read entries")
	fmt.Fprintln(&b, "        (the signer private and recipient public are set in Step 4; provision the store now).")
	fmt.Fprintln(&b, "  The SCHEDULER Durable Object and the */15 reconciliation cron are created automatically by")
	fmt.Fprintln(&b, "  the Step 3 deploy (the v1 SQLite migration in engine/wrangler.toml); no separate step.")
	fmt.Fprintln(&b, "")

	// Step 3: deploy engine + console.
	fmt.Fprintln(&b, "Step 3. Deploy the engine and console")
	fmt.Fprintf(&b, "  Set CONSOLE_ORIGIN in engine/wrangler.toml to https://%s and ALLOWED_ENGINE_ORIGIN in\n", consoleDomain)
	fmt.Fprintf(&b, "  console/wrangler.toml to https://%s, then deploy both (custom domains only):\n", engineDomain)
	fmt.Fprintln(&b, "      cd engine   && npm run deploy")
	fmt.Fprintln(&b, "      cd console  && npx wrangler deploy")
	fmt.Fprintf(&b, "  This creates the %s and %s Workers, the SCHEDULER Durable Object,\n", provision.EngineScript, provision.ConsoleScript)
	fmt.Fprintln(&b, "  the cron, and the custom-domain routes. Always deploy the engine with npm run deploy, never a bare")
	fmt.Fprintln(&b, "  wrangler deploy: it runs scripts/sync-bindings.mjs so a re-deploy can never silently drop a source")
	fmt.Fprintln(&b, "  you attached from the console. Also set the admin token as break-glass administration:")
	fmt.Fprintln(&b, "      cd engine && npx wrangler secret put ADMIN_TOKEN")
	fmt.Fprintln(&b, "")

	// Step 4: the key ceremony (browser; nothing transmitted).
	fmt.Fprintln(&b, "Step 4. Run the key ceremony (in the console, in your browser; nothing is transmitted)")
	fmt.Fprintln(&b, "  Open the console and run the key ceremony. It generates, entirely in your browser, the")
	fmt.Fprintln(&b, "  break-glass key pair (the PRIVATE half is your offline recovery key: it is downloaded to")
	fmt.Fprintln(&b, "  your machine and NEVER sent to the engine or the vendor), the signer key pair, and an")
	fmt.Fprintln(&b, "  optional operational recipient key. The console prints the exact wrangler commands; apply")
	fmt.Fprintln(&b, "  the public recipient key and the signer private out of band:")
	fmt.Fprintln(&b, "      npx wrangler secret put SIGNER_PRIVATE      # the signer private; the engine signs runs with it")
	fmt.Fprintln(&b, "      npx wrangler secret put BREAK_GLASS_PUBLIC  # the recipient public; the break-glass PRIVATE never goes here")
	fmt.Fprintln(&b, "  To generate the keys offline instead (for an air-gapped ceremony) use: downpipe keygen")
	fmt.Fprintln(&b, "  Store the break-glass private offline (consider an M-of-N split); it is the only way to recover.")
	fmt.Fprintln(&b, "")

	// Step 5: wire the first source.
	fmt.Fprintln(&b, "Step 5. Wire the first source and create a downpipe")
	fmt.Fprintln(&b, "  With a source binding declared (Step 2) and the engine ready, create a downpipe in the")
	fmt.Fprintln(&b, "  console: choose the source binding, a schedule, and enable it. The first scheduled run (or a")
	fmt.Fprintln(&b, "  manual trigger) seals that source to the destination bucket.")
	fmt.Fprintln(&b, "")

	// Step 6: verify readiness and enrol the first Owner.
	fmt.Fprintln(&b, "Step 6. Verify readiness and enrol the first Owner")
	fmt.Fprintln(&b, "  Confirm GET /admin/status reports ready: true (the signer private is present, the recipient")
	fmt.Fprintln(&b, "  public is present, and a destination resolves) and watch the first run land in the run history")
	fmt.Fprintln(&b, "  with its throughput. The console drives this check. Until ready: true, the engine will not run")
	fmt.Fprintln(&b, "  a backup. Then claim the first Owner: present the ADMIN_TOKEN once to enrol your Owner passkey")
	fmt.Fprintln(&b, "  in the console, and sign in with that passkey to confirm it works. Enrolling a SECOND Owner now")
	fmt.Fprintln(&b, "  is wise so you are never locked out by a single lost passkey.")
	fmt.Fprintln(&b, "")

	// Step 7: dispose of the one-time bootstrap token (ADMIN_TOKEN) now the Owner passkey works.
	// This is ordered AFTER readiness and first-Owner enrolment on purpose: dispose of the bootstrap
	// credential only once the passkey sign-in works AND the admin recovery codes are saved, so you
	// cannot lock yourself out. It is a SEPARATE credential from the scoped deploy token deleted in the
	// next step. NOTE: the break-glass model is RECOVERY CODES (admin sign-in), distinct from the
	// offline break-glass KEY used for DATA recovery in Step 4.
	fmt.Fprintln(&b, "Step 7. Dispose of the one-time bootstrap token (ADMIN_TOKEN)")
	fmt.Fprintln(&b, "  On first Owner enrolment you are shown RECOVERY CODES; save them offline - they are your")
	fmt.Fprintln(&b, "  break-glass to get back in if you lose your passkey (this is like recovery codes in any")
	fmt.Fprintln(&b, "  normal app).")
	fmt.Fprintln(&b, "  The ADMIN_TOKEN you set in Step 3 is a ONE-TIME bootstrap credential for claiming the first")
	fmt.Fprintln(&b, "  Owner. Once your passkey works AND your recovery codes are saved, dispose of the one-time")
	fmt.Fprintln(&b, "  bootstrap token in one of two ways:")
	fmt.Fprintln(&b, "    (a) In the console Security Centre, use \"Retire break-glass token\". This takes effect")
	fmt.Fprintln(&b, "        immediately, with no redeploy.")
	fmt.Fprintln(&b, "    (b) Or delete the secret entirely:")
	fmt.Fprintln(&b, "        cd engine && npx wrangler secret delete ADMIN_TOKEN")
	fmt.Fprintln(&b, "  Leaving the token live is a standing risk: anyone with the string can take admin. The engine")
	fmt.Fprintln(&b, "  will refuse to retire until a way back in exists (recovery codes saved or a second Owner).")
	fmt.Fprintln(&b, "  The offline break-glass KEY (for DATA recovery, from Step 4) is a SEPARATE thing from these")
	fmt.Fprintln(&b, "  admin sign-in recovery codes; your backups remain recoverable offline via that key regardless.")
	fmt.Fprintln(&b, "")

	// Step 8: now delete the scoped deploy token.
	fmt.Fprintln(&b, "Step 8. Now DELETE the scoped deploy token (privilege state 2: the no-custody runtime)")
	fmt.Fprintln(&b, "  As soon as readiness is confirmed, revoke the token you created in Step 1. After this the")
	fmt.Fprintln(&b, "  system runs with NO Cloudflare API token anywhere: the engine holds none and reaches data only")
	fmt.Fprintln(&b, "  through its bindings (least privilege by construction, the no-custody guarantee), and there is")
	fmt.Fprintln(&b, "  no standing deploy credential left to leak.")
	fmt.Fprintln(&b, "      My Profile > API Tokens > the token you created in Step 1 > Delete")
	fmt.Fprintln(&b, "      https://dash.cloudflare.com/profile/api-tokens")
	fmt.Fprintln(&b, "  Also: unset CLOUDFLARE_API_TOKEN in this shell.")
	fmt.Fprintln(&b, "")
	fmt.Fprintln(&b, "To upgrade later (privilege state 3): re-create the same scoped token, deploy the new version or")
	fmt.Fprintln(&b, "change a binding/secret, then DELETE the token again. The engine never holds a deploy token.")
	fmt.Fprintln(&b, "")
	fmt.Fprintln(&b, "init printed the plan and made no Cloudflare call. Run the steps above yourself.")

	return b.String()
}
