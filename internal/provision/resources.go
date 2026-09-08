package provision

import (
	"errors"
	"fmt"
	"strings"
)

// SourceBinding declares one source the engine reads from. The binding is the
// credential (a KV namespace, R2 bucket, D1 database or Secrets Store binding bound to
// the Worker), so this carries identifiers only, never a key or token.
type SourceBinding struct {
	// Var is the binding variable name the engine reads (for example "SRC_KV").
	Var string
	// Type is the source layer: "kv", "r2", "d1" or "secrets".
	Type string
	// ID is the resource identifier the binding points at (a namespace id, bucket
	// name, database id or store id). Never a secret value.
	ID string
}

// DestinationBinding declares where the engine writes archives. The default and best
// path is a native R2 bucket binding, which carries no credential at all.
type DestinationBinding struct {
	// Var is the binding variable name (for example "DEST_R2").
	Var string
	// Bucket is the R2 bucket name the engine writes archive objects into.
	Bucket string
}

// SecretEntry names a Secrets Store entry the deployment needs (for example the engine
// signer private or the recipient public). It carries the store and name only; the
// value is supplied at apply time and is never placed in a Plan or a log. The
// break-glass private is never one of these: it never leaves the operator's browser and
// has no engine binding, by design.
type SecretEntry struct {
	// Store is the Secrets Store id the entry lives in.
	Store string
	// Name is the secret name within the store.
	Name string
	// Summary is a redaction-safe one-liner describing what the entry is for.
	Summary string
}

// Config is the declared shape of the deployment the operator wants provisioned. It is
// the pure input to the Planner: no token, no secret value, no private key. The command
// layer fills it from flags and a config file; the token is held separately and handed
// to the Client, never stored here.
type Config struct {
	// AppName is the label for the Cloudflare Access application.
	AppName string
	// AccessDomains are the console and engine hostnames the Access application gates
	// (for example "console.example.com" and "engine.example.com"). Custom domains
	// only; a workers.dev hostname is rejected by the builder.
	AccessDomains []string
	// AllowedEmails and AllowedEmailDomains drive the default One-Time PIN allow
	// policy. At least one must be set, because an unrestricted OTP allow rule is the
	// documented footgun.
	AllowedEmails       []string
	AllowedEmailDomains []string
	// SessionDuration is the Access session lifetime (for example "24h"). Empty uses
	// the Cloudflare default.
	SessionDuration string

	// EmailFrom is the sender address for outbound email. It must be on a custom
	// domain on the account's Cloudflare zone; its sending-domain onboarding is the one
	// manual step the plan surfaces as a note.
	EmailFrom string

	// Secrets are the Secrets Store entries to provision. Values are not held here.
	Secrets []SecretEntry

	// Sources and Destination declare the engine bindings.
	Sources     []SourceBinding
	Destination *DestinationBinding
}

// errConfig is a typed configuration error so the command layer can map it to a usage
// exit code without depending on string matching.
type errConfig struct{ msg string }

func (e *errConfig) Error() string { return e.msg }

func configErrorf(format string, args ...any) error {
	return &errConfig{msg: fmt.Sprintf(format, args...)}
}

// IsConfigError reports whether err is a provisioner configuration error (a bad or
// missing input), as opposed to an API or transport error. The command maps a config
// error to ExitUsage.
func IsConfigError(err error) bool {
	if err == nil {
		return false
	}
	// errors.As traverses the error chain, so this stays correct if a future caller
	// wraps the *errConfig with fmt.Errorf("%w", ...).
	return errors.As(err, new(*errConfig))
}

// Validate checks the declared Config for the invariants the builders rely on, before
// any plan is produced or any call is made. It enforces custom-domain-only hostnames
// and a restricted Access allow rule (no unrestricted OTP), among others.
func (c Config) Validate() error {
	for _, validate := range []func() error{
		c.validateAccessSection,
		c.validateEmailSection,
		c.validateSecretsSection,
		c.validateSourcesSection,
		c.validateDestinationSection,
	} {
		if err := validate(); err != nil {
			return err
		}
	}
	return nil
}

// validateAccessSection checks the Access application name, the custom-domain-only
// hostnames and the restricted allow rule (no unrestricted OTP).
func (c Config) validateAccessSection() error {
	if strings.TrimSpace(c.AppName) == "" {
		return configErrorf("an Access application name is required")
	}
	if len(c.AccessDomains) == 0 {
		return configErrorf("at least one Access hostname is required (the console and engine custom domains)")
	}
	for _, d := range c.AccessDomains {
		if err := validateCustomHostname(d); err != nil {
			return err
		}
	}
	if len(c.AllowedEmails) == 0 && len(c.AllowedEmailDomains) == 0 {
		return configErrorf("an allowlist is required: set at least one allowed email or email domain (an unrestricted Access allow rule is unsafe)")
	}
	for _, e := range c.AllowedEmails {
		if !strings.Contains(e, "@") || strings.HasPrefix(e, "@") || strings.HasSuffix(e, "@") {
			return configErrorf("allowed email %q is not a valid address", e)
		}
	}
	for _, d := range c.AllowedEmailDomains {
		if strings.Contains(d, "@") || strings.TrimSpace(d) == "" {
			return configErrorf("allowed email domain %q must be a bare domain, not an address", d)
		}
	}
	return nil
}

// validateEmailSection checks the optional sender address and its custom-domain host.
func (c Config) validateEmailSection() error {
	if c.EmailFrom == "" {
		return nil
	}
	if !strings.Contains(c.EmailFrom, "@") {
		return configErrorf("email sender %q is not a valid address", c.EmailFrom)
	}
	host := c.EmailFrom[strings.LastIndexByte(c.EmailFrom, '@')+1:]
	if err := validateCustomHostname(host); err != nil {
		return configErrorf("email sender domain: %v", err)
	}
	return nil
}

// validateSecretsSection checks each declared secret has a path-safe store and name.
func (c Config) validateSecretsSection() error {
	for _, s := range c.Secrets {
		if strings.TrimSpace(s.Store) == "" || strings.TrimSpace(s.Name) == "" {
			return configErrorf("each secret entry needs a store and a name")
		}
		if err := validatePathSegment("secret store", s.Store); err != nil {
			return err
		}
		if err := validatePathSegment("secret name", s.Name); err != nil {
			return err
		}
	}
	return nil
}

// validateSourcesSection checks each source binding has a path-safe variable, a known
// type and a resource id.
func (c Config) validateSourcesSection() error {
	for _, s := range c.Sources {
		if strings.TrimSpace(s.Var) == "" {
			return configErrorf("each source binding needs a variable name")
		}
		if err := validatePathSegment("source binding variable", s.Var); err != nil {
			return err
		}
		switch s.Type {
		case "kv", "r2", "d1", "secrets":
		default:
			return configErrorf("source binding %q has unknown type %q (want kv, r2, d1 or secrets)", s.Var, s.Type)
		}
		if strings.TrimSpace(s.ID) == "" {
			return configErrorf("source binding %q needs a resource id", s.Var)
		}
	}
	return nil
}

// validateDestinationSection checks the optional destination binding's variable and
// bucket.
func (c Config) validateDestinationSection() error {
	if c.Destination == nil {
		return nil
	}
	if strings.TrimSpace(c.Destination.Var) == "" || strings.TrimSpace(c.Destination.Bucket) == "" {
		return configErrorf("the destination binding needs a variable name and a bucket")
	}
	return validatePathSegment("destination binding variable", c.Destination.Var)
}

// validatePathSegment enforces that a value the builders interpolate into a single
// Cloudflare API path segment (a secret store or name, a binding variable, the engine
// script name, the account id) is a safe identifier. The host is already pinned to
// api.cloudflare.com, so this is not an SSRF or token-exfiltration guard: it stops an
// operator-supplied value from carrying "/", ".." or other path-control characters that
// would silently retarget the call at a different resource in the operator's own account
// (a self-inflicted path traversal within the pinned host). The charset is deliberately
// the conservative identifier set Cloudflare resource names use; anything else is a clean
// usage error rather than a surprising API call. label names the field for the message.
func validatePathSegment(label, v string) error {
	if strings.TrimSpace(v) == "" {
		return configErrorf("%s is required", label)
	}
	// Reject the path-traversal tokens outright. "." and ".." are otherwise inside the
	// allowed charset below (which permits "." and "-"), so they must be excluded here.
	if v == "." || v == ".." || strings.Contains(v, "..") {
		return configErrorf("%s %q must not contain path traversal segments", label, v)
	}
	for _, r := range v {
		ok := (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '.' || r == '_' || r == '-'
		if !ok {
			return configErrorf("%s %q must contain only letters, digits, '.', '_' or '-' (no '/', ':' or whitespace)", label, v)
		}
	}
	return nil
}

// validateAccountID enforces that the Cloudflare account id interpolated into every API
// path is a safe identifier. A real account id is 32 lowercase hex characters; the check
// is the same conservative identifier charset used for the other path segments so a test
// or a non-standard id is accepted while "/", ".." and whitespace are rejected. Like
// validatePathSegment this guards against a self-inflicted path traversal, not SSRF: the
// host is already pinned. It returns a config error so the command maps a bad id to a
// usage exit. Callers also handle the empty case with their own message first.
func validateAccountID(accountID string) error {
	return validatePathSegment("account id", accountID)
}

// validateCustomHostname enforces the house rule that hostnames are real custom domains,
// never workers.dev, and are syntactically plausible. It is deliberately strict so a
// misconfiguration is a clean usage error rather than a later API rejection.
func validateCustomHostname(h string) error {
	h = strings.TrimSpace(h)
	if h == "" {
		return configErrorf("a hostname is required")
	}
	if strings.ContainsAny(h, "/:@ ") {
		return configErrorf("hostname %q must be a bare host, not a URL", h)
	}
	if !strings.Contains(h, ".") {
		return configErrorf("hostname %q is not a fully qualified domain", h)
	}
	if strings.HasSuffix(strings.ToLower(h), ".workers.dev") {
		return configErrorf("hostname %q is a workers.dev address; downpipes uses custom domains only", h)
	}
	return nil
}

// buildAccessApp builds the Action that creates the Access self-hosted application.
// Path is the account-scoped Access apps collection; Body is the create payload.
func buildAccessApp(accountID string, c Config) Action {
	body := map[string]any{
		"name":   c.AppName,
		"type":   "self_hosted",
		"domain": c.AccessDomains[0],
	}
	if len(c.AccessDomains) > 1 {
		dests := make([]map[string]any, 0, len(c.AccessDomains))
		for _, d := range c.AccessDomains {
			dests = append(dests, map[string]any{"type": "public", "uri": d})
		}
		body["destinations"] = dests
	}
	if c.SessionDuration != "" {
		body["session_duration"] = c.SessionDuration
	}
	return Action{
		Kind:    KindAccessApp,
		Name:    c.AppName,
		Summary: fmt.Sprintf("Cloudflare Access application gating %s", strings.Join(c.AccessDomains, ", ")),
		Method:  "POST",
		Path:    fmt.Sprintf("/accounts/%s/access/apps", accountID),
		Body:    body,
	}
}

// buildAccessPolicy builds the Action that creates the default One-Time PIN allow
// policy for the application, scoped to the configured email allowlist. The application
// id is unknown until the app is created, so the path carries a placeholder that Apply
// fills from the create response (see Client.Apply); the plan output names it clearly.
func buildAccessPolicy(accountID string, c Config) Action {
	includes := make([]map[string]any, 0, len(c.AllowedEmails)+len(c.AllowedEmailDomains))
	for _, e := range c.AllowedEmails {
		includes = append(includes, map[string]any{"email": map[string]any{"email": e}})
	}
	for _, d := range c.AllowedEmailDomains {
		includes = append(includes, map[string]any{"email_domain": map[string]any{"domain": d}})
	}
	body := map[string]any{
		"name":     "downpipes allowlist (One-Time PIN)",
		"decision": "allow",
		"include":  includes,
	}
	return Action{
		Kind:    KindAccessPolicy,
		Name:    "downpipes allowlist",
		Summary: fmt.Sprintf("allow policy for %d email(s) and %d domain(s) via One-Time PIN", len(c.AllowedEmails), len(c.AllowedEmailDomains)),
		Method:  "POST",
		Path:    fmt.Sprintf("/accounts/%s/access/apps/%s/policies", accountID, appIDPlaceholder),
		Body:    body,
	}
}

// appIDPlaceholder marks where the created Access application id is substituted into the
// policy path at apply time. It is a literal token, never a real id, and is replaced by
// Client.Apply once the app create call returns.
const appIDPlaceholder = "{app_id}"

// buildEmailNote builds the manual-only Action recording the one step the API cannot do:
// outbound sending-domain onboarding (DKIM/SPF/DMARC) is dashboard-only in the email
// beta, although Cloudflare auto-writes the DNS records because the zone is on
// Cloudflare. It is surfaced as an instruction, never an API call.
func buildEmailNote(c Config) Action {
	domain := c.EmailFrom[strings.LastIndexByte(c.EmailFrom, '@')+1:]
	return Action{
		Kind:    KindEmailNote,
		Name:    domain,
		Summary: fmt.Sprintf("onboard the sending domain %q in the Cloudflare dashboard (Email > Sending) so %q can send; the DNS records are written automatically because the zone is on Cloudflare. This step has no API today.", domain, c.EmailFrom),
	}
}

// buildSecret builds the Action that PUTs a Secrets Store entry. Body carries the value
// at apply time, but the value is supplied by the operator and never written into the
// plan (Describe omits every Body), so the plan and any log stay redaction-safe.
func buildSecret(accountID string, s SecretEntry) Action {
	summary := s.Summary
	if summary == "" {
		summary = fmt.Sprintf("Secrets Store entry %q in store %s", s.Name, s.Store)
	}
	return Action{
		Kind:    KindSecret,
		Name:    s.Name,
		Summary: summary,
		Method:  "PUT",
		Path:    fmt.Sprintf("/accounts/%s/secrets_store/stores/%s/secrets/%s", accountID, s.Store, s.Name),
		// The value is filled at apply time from operator-supplied input keyed by
		// secret name; the planner leaves it absent so a dry-run plan holds no value.
		Body: map[string]any{"name": s.Name},
	}
}

// buildSourceBinding builds the Action that declares one source binding on the engine
// Worker. The binding is the credential, so Body carries identifiers only.
func buildSourceBinding(accountID, scriptName string, s SourceBinding) Action {
	return Action{
		Kind:    KindSourceBinding,
		Name:    s.Var,
		Summary: fmt.Sprintf("%s source binding %q -> %s", s.Type, s.Var, s.ID),
		Method:  "PUT",
		Path:    fmt.Sprintf("/accounts/%s/workers/scripts/%s/bindings/%s", accountID, scriptName, s.Var),
		Body:    map[string]any{"name": s.Var, "type": s.Type, "id": s.ID},
	}
}

// buildDestinationBinding builds the Action that declares the destination R2 bucket
// binding on the engine Worker. A native R2 bucket binding carries no credential.
func buildDestinationBinding(accountID, scriptName string, d DestinationBinding) Action {
	return Action{
		Kind:    KindDestinationBinding,
		Name:    d.Var,
		Summary: fmt.Sprintf("destination R2 binding %q -> bucket %s", d.Var, d.Bucket),
		Method:  "PUT",
		Path:    fmt.Sprintf("/accounts/%s/workers/scripts/%s/bindings/%s", accountID, scriptName, d.Var),
		Body:    map[string]any{"name": d.Var, "type": "r2_bucket", "bucket_name": d.Bucket},
	}
}
