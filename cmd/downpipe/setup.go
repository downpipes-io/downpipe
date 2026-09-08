package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/provision"
)

// cmdSetup is the local Cloudflare provisioner. It runs on
// the operator's own machine with the operator's own Cloudflare API token, read from the
// CLOUDFLARE_API_TOKEN environment variable, and provisions the Access application and
// policies, a note for the manual email sending-domain step, Secrets Store entries, and
// the source and destination bindings via the Cloudflare API.
//
// No-custody: the token is read from the environment, used only against
// api.cloudflare.com via the provisioner, and never printed, never written to the plan,
// and never sent to the vendor or the in-account console. There is no break-glass private
// material here; setup provisions account infrastructure, not keys.
//
// Dry run is the default. Without --apply the command validates the inputs, builds the
// ordered plan, prints exactly what it would create, and makes no network call at all.
// --apply opts in to the live path, which is the only path that contacts Cloudflare.
func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	configPath := fs.String("config", "", "JSON file describing the deployment to provision (Access, email, secrets, bindings)")
	apply := fs.Bool("apply", false, "execute the plan against Cloudflare; without it setup is a dry run that prints the plan and creates nothing")
	appName := fs.String("app-name", "downpipes", "Cloudflare Access application name (when not using --config)")
	accessDomains := fs.String("access-domains", "", "comma-separated console and engine custom hostnames to gate with Access (when not using --config)")
	allowEmails := fs.String("allow-emails", "", "comma-separated allowed email addresses for the Access One-Time PIN policy")
	allowDomains := fs.String("allow-email-domains", "", "comma-separated allowed email domains for the Access One-Time PIN policy")
	emailFrom := fs.String("email-from", "", "outbound sender address on a custom domain (records the manual sending-domain step)")
	script := fs.String("engine-script", provision.EngineScript, "Worker script name the source and destination bindings attach to")
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	// The token is mandatory and comes only from the environment, never a flag, so it is
	// never visible in a process listing or shell history. A missing token is a clean
	// usage error (exit 6), checked before any config parsing or network use.
	token := os.Getenv("CLOUDFLARE_API_TOKEN")
	if strings.TrimSpace(token) == "" {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("set CLOUDFLARE_API_TOKEN in your environment (the token stays on this machine and is sent only to api.cloudflare.com)")}
	}
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	if strings.TrimSpace(accountID) == "" {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("set CLOUDFLARE_ACCOUNT_ID in your environment")}
	}

	cfg, err := loadSetupConfig(*configPath, setupFlags{
		appName:       *appName,
		accessDomains: *accessDomains,
		allowEmails:   *allowEmails,
		allowDomains:  *allowDomains,
		emailFrom:     *emailFrom,
	})
	if err != nil {
		return err
	}

	planner := provision.Planner{ScriptName: *script}
	plan, err := planner.Plan(accountID, cfg)
	if err != nil {
		// A config error is a usage error; anything else is unexpected and exits 1.
		if provision.IsConfigError(err) {
			return &format.ExitError{Code: format.ExitUsage, Err: err}
		}
		return err
	}

	// Always print the plan. In a dry run this is the whole output; under --apply it is
	// the record of what is about to happen. The plan is redaction-safe by construction:
	// it carries no token and no secret value.
	fmt.Print(plan.Describe())

	if !*apply {
		fmt.Println("dry run: nothing was created. Re-run with --apply to provision.")
		fmt.Println("the Cloudflare API token stays on this machine; it is never sent to the vendor or the console.")
		return nil
	}

	return applySetupPlan(accountID, token, cfg, plan)
}

// applySetupPlan runs the live provision path: it gathers secret values from the
// environment (never from flags or the config, so a value never reaches the plan or a
// log), builds the API client, and applies the plan. This is the only path that contacts
// Cloudflare and it runs only under --apply.
func applySetupPlan(accountID, token string, cfg provision.Config, plan provision.Plan) error {
	secrets, err := gatherSecretValues(cfg.Secrets)
	if err != nil {
		return err
	}
	client, err := provision.NewClient(accountID, token, defaultDoer())
	if err != nil {
		return &format.ExitError{Code: format.ExitUsage, Err: err}
	}
	return applyPlan(client, plan, secrets)
}

// applyPlan executes the plan and reports each action's outcome to stderr, returning a
// non-zero ExitError if any action failed so a partial provision is never presented as a
// success. Extracted so a test can drive it with a fake Provisioner.
func applyPlan(p provision.Provisioner, plan provision.Plan, secrets map[string]string) error {
	results, applyErr := p.Apply(plan, secrets)
	for _, r := range results {
		status := "ok"
		if !r.OK {
			status = "FAILED"
		}
		idNote := ""
		if r.ID != "" {
			idNote = " id=" + r.ID
		}
		fmt.Fprintf(os.Stderr, "  %-7s %-22s %s%s: %s\n", status, r.Action.Kind, r.Action.Name, idNote, r.Detail)
	}
	if applyErr != nil {
		return &format.ExitError{Code: 1, Err: fmt.Errorf("provision did not complete: %w", applyErr)}
	}
	fmt.Printf("applied %d action(s) to account %s\n", len(results), plan.AccountID)
	return nil
}

// setupFlags carries the flag-driven inputs used when --config is not supplied.
type setupFlags struct {
	appName       string
	accessDomains string
	allowEmails   string
	allowDomains  string
	emailFrom     string
}

// loadSetupConfig builds the provision.Config either from a JSON file (--config, the full
// shape including secrets and bindings) or from the simple flags. The two are mutually
// exclusive: a --config file is authoritative and the per-field flags are ignored when it
// is present, which keeps the precedence unambiguous.
func loadSetupConfig(path string, f setupFlags) (provision.Config, error) {
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return provision.Config{}, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("read --config: %w", err)}
		}
		var cfg provision.Config
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return provision.Config{}, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("parse --config: %w", err)}
		}
		return cfg, nil
	}
	return provision.Config{
		AppName:             f.appName,
		AccessDomains:       splitCSV(f.accessDomains),
		AllowedEmails:       splitCSV(f.allowEmails),
		AllowedEmailDomains: splitCSV(f.allowDomains),
		EmailFrom:           strings.TrimSpace(f.emailFrom),
	}, nil
}

// gatherSecretValues reads each declared secret's value from the environment, under the
// variable DOWNPIPE_SECRET_<NAME> (the secret name uppercased, with non-alphanumeric
// characters mapped to underscore). Values come only from the environment, never from a
// flag or the config file, so they never appear in a process listing or the plan. A
// missing value is a clean usage error before any call is made.
func gatherSecretValues(secrets []provision.SecretEntry) (map[string]string, error) {
	out := make(map[string]string, len(secrets))
	for _, s := range secrets {
		envName := secretEnvVar(s.Name)
		val := os.Getenv(envName)
		if val == "" {
			return nil, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("set %s to the value for secret %q (secret values come from the environment, never a flag)", envName, s.Name)}
		}
		out[s.Name] = val
	}
	return out, nil
}

// secretEnvVar maps a secret name to its environment variable name. It uppercases the
// name and replaces every byte outside A-Z0-9 with an underscore, so an arbitrary secret
// name maps to a valid, predictable variable.
func secretEnvVar(name string) string {
	var b strings.Builder
	b.WriteString("DOWNPIPE_SECRET_")
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z':
			b.WriteByte(c - ('a' - 'A')) // ASCII lowercase-to-uppercase shift
		case (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'):
			b.WriteByte(c)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// splitCSV splits a comma-separated flag value into trimmed, non-empty parts.
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// defaultDoer is the real HTTP client used for live provisioning. It refuses redirects so
// the Bearer token cannot be replayed to a different host, and carries a bounded timeout.
// It is constructed only on the --apply path; a dry run never builds it.
func defaultDoer() provision.Doer {
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
