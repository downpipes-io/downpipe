package provision

import (
	"strings"
	"testing"
)

type configValidateCase struct {
	name    string
	mutate  func(*Config)
	wantErr bool
}

// runConfigValidateCases applies each mutation to a fresh sampleConfig and asserts
// Validate()'s outcome, mapping an invalid case to a config error (the usage-exit path).
func runConfigValidateCases(t *testing.T, cases []configValidateCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := sampleConfig()
			tc.mutate(&c)
			err := c.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("Validate() = nil, want an error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
			if tc.wantErr && err != nil && !IsConfigError(err) {
				t.Errorf("Validate() error is not a config error: %v", err)
			}
		})
	}
}

// TestConfigValidateRejects covers the invalid input invariants the builders rely on.
func TestConfigValidateRejects(t *testing.T) {
	runConfigValidateCases(t, []configValidateCase{
		{"empty app name", func(c *Config) { c.AppName = "" }, true},
		{"no access domains", func(c *Config) { c.AccessDomains = nil }, true},
		{"workers.dev hostname", func(c *Config) { c.AccessDomains = []string{"thing.workers.dev"} }, true},
		{"url not host", func(c *Config) { c.AccessDomains = []string{"https://console.example.com"} }, true},
		{"bare host no dot", func(c *Config) { c.AccessDomains = []string{"localhost"} }, true},
		{"no allowlist at all", func(c *Config) { c.AllowedEmails = nil; c.AllowedEmailDomains = nil }, true},
		{"bad allowed email", func(c *Config) { c.AllowedEmails = []string{"not-an-email"} }, true},
		{"allowed domain is address", func(c *Config) { c.AllowedEmailDomains = []string{"x@example.com"} }, true},
		{"bad sender address", func(c *Config) { c.EmailFrom = "no-at-sign" }, true},
		{"sender on workers.dev", func(c *Config) { c.EmailFrom = "a@thing.workers.dev" }, true},
		{"secret missing name", func(c *Config) { c.Secrets = []SecretEntry{{Store: "s"}} }, true},
		{"source missing var", func(c *Config) { c.Sources = []SourceBinding{{Type: "kv", ID: "x"}} }, true},
		{"source bad type", func(c *Config) { c.Sources = []SourceBinding{{Var: "V", Type: "queue", ID: "x"}} }, true},
		{"source missing id", func(c *Config) { c.Sources = []SourceBinding{{Var: "V", Type: "kv"}} }, true},
		{"dest missing bucket", func(c *Config) { c.Destination = &DestinationBinding{Var: "V"} }, true},
		// Path-traversal / unsafe-charset guards on the fields interpolated into API paths.
		// These values are non-empty and pass the TrimSpace checks, so only the segment
		// validation catches them.
		{"secret store with slash", func(c *Config) { c.Secrets[0].Store = "../../other-store" }, true},
		{"secret store with dotdot", func(c *Config) { c.Secrets[0].Store = "a..b" }, true},
		{"secret name with slash", func(c *Config) { c.Secrets[0].Name = "a/b" }, true},
		{"secret name dotdot only", func(c *Config) { c.Secrets[0].Name = ".." }, true},
		{"secret name with whitespace", func(c *Config) { c.Secrets[0].Name = "a b" }, true},
		{"source var with slash", func(c *Config) { c.Sources[0].Var = "../bindings/X" }, true},
		{"source var with colon", func(c *Config) { c.Sources[0].Var = "a:b" }, true},
		{"dest var with slash", func(c *Config) { c.Destination.Var = "a/../b" }, true},
	})
}

// TestConfigValidateAccepts covers the valid baseline and boundary inputs that must pass.
//
// An accept case's name is not its reason, so the two that waive a section carry one. The
// allowlist pair is an either/or by design: Access is configured by domain or by address, and
// requiring both would refuse the ordinary single-domain estate. The empty sender is the
// weightier one, because it does not merely skip a validation: Plan appends the email note
// action only when EmailFrom is set, so an absent sender drops a provisioning step. That is
// right rather than merely tolerated -- the dropped step is "onboard the sending domain in the
// dashboard so this address can send", which is work that exists only because an address was
// declared. What would be wrong is dropping the step while a sender IS configured, which is
// why TestPlannerNoEmailNoteWhenNoSender pins the two halves against each other.
func TestConfigValidateAccepts(t *testing.T) {
	runConfigValidateCases(t, []configValidateCase{
		{"valid baseline", func(*Config) {}, false},
		{"safe identifiers pass", func(c *Config) {
			c.Secrets[0].Store = "store_1.A-2"
			c.Secrets[0].Name = "signer.private-key_1"
			c.Sources[0].Var = "SRC_KV.1-a"
			c.Destination.Var = "DEST-R2_1"
		}, false},
		{"allowlist by domain only", func(c *Config) { c.AllowedEmails = nil }, false},
		{"allowlist by email only", func(c *Config) { c.AllowedEmailDomains = nil }, false},
		{"no email sender is fine", func(c *Config) { c.EmailFrom = "" }, false},
	})
}

// TestIsConfigError confirms the predicate distinguishes a config error from a plain
// error, so the command does not map an unexpected error to a usage exit.
func TestIsConfigError(t *testing.T) {
	if IsConfigError(nil) {
		t.Error("IsConfigError(nil) = true, want false")
	}
	if IsConfigError(errPlain{}) {
		t.Error("IsConfigError(plain) = true, want false")
	}
	if !IsConfigError(configErrorf("bad")) {
		t.Error("IsConfigError(configErrorf) = false, want true")
	}
}

type errPlain struct{}

func (errPlain) Error() string { return "plain" }

// TestValidatePathSegmentRejectsTraversal is the direct path-traversal guard: every value the
// builders interpolate into an api.cloudflare.com path segment must reject "/", ":",
// whitespace and ".." (which would silently retarget the call at another resource in the
// operator's own account), while accepting the conservative identifier charset Cloudflare
// resource names use.
func TestValidatePathSegmentRejectsTraversal(t *testing.T) {
	bad := []string{
		"../../other",  // parent traversal
		"a/b",          // embedded slash
		"..",           // bare parent
		".",            // bare current
		"a..b",         // embedded dotdot
		"store:secret", // colon
		"has space",    // whitespace
		"tab\tname",    // tab whitespace
		"new\nline",    // newline whitespace
		"%2e%2e",       // percent (would need decoding to be a segment; rejected anyway)
		"",             // empty
		"   ",          // blank
		"name#frag",    // other punctuation
		"a/b/../../c",  // mixed
	}
	for _, v := range bad {
		if err := validatePathSegment("field", v); err == nil {
			t.Errorf("validatePathSegment(%q) = nil, want a rejection", v)
		} else if !IsConfigError(err) {
			t.Errorf("validatePathSegment(%q) error is not a config error: %v", v, err)
		}
	}
	good := []string{"store-1", "signer-private", "SRC_KV", "a.b.c", "downpipe-engine", "A1_b-2.x", strings.Repeat("a", 64)}
	for _, v := range good {
		if err := validatePathSegment("field", v); err != nil {
			t.Errorf("validatePathSegment(%q) = %v, want nil", v, err)
		}
	}
}

// TestValidateAccountIDRejectsTraversal confirms the account id, interpolated into every
// API path, is held to the same safe-segment rule: a "/" or ".." is rejected, a real
// 32-hex id and the short ids used in tests are accepted.
func TestValidateAccountIDRejectsTraversal(t *testing.T) {
	if err := validateAccountID("../../zones/evil"); err == nil {
		t.Error("validateAccountID with a traversal = nil, want a rejection")
	}
	if err := validateAccountID("acct/../other"); err == nil {
		t.Error("validateAccountID with an embedded traversal = nil, want a rejection")
	}
	if err := validateAccountID(""); err == nil {
		t.Error("validateAccountID(empty) = nil, want a rejection")
	}
	for _, ok := range []string{"acct123", "0123456789abcdef0123456789abcdef"} {
		if err := validateAccountID(ok); err != nil {
			t.Errorf("validateAccountID(%q) = %v, want nil", ok, err)
		}
	}
}

// TestBuildAccessPolicyUsesPlaceholder confirms the policy path carries the app-id
// placeholder, which Apply substitutes from the create response.
func TestBuildAccessPolicyUsesPlaceholder(t *testing.T) {
	a := buildAccessPolicy("acct123", sampleConfig())
	if !strings.Contains(a.Path, appIDPlaceholder) {
		t.Fatalf("policy path %q does not carry the app-id placeholder %q", a.Path, appIDPlaceholder)
	}
}

// TestBuildSecretBodyHasNoValue confirms a freshly built secret action carries no value
// in its Body: the value is supplied only at apply time, so a dry-run plan holds none.
func TestBuildSecretBodyHasNoValue(t *testing.T) {
	a := buildSecret("acct123", SecretEntry{Store: "s", Name: "signer-private"})
	if _, ok := a.Body["value"]; ok {
		t.Fatalf("built secret action carries a value in its body; it must not until apply time")
	}
}

// TestBuildSourceBindingBody confirms the source binding body carries identifiers only
// (name, type, id), never a credential.
func TestBuildSourceBindingBody(t *testing.T) {
	a := buildSourceBinding("acct123", "downpipe-engine", SourceBinding{Var: "SRC_KV", Type: "kv", ID: "kvns-abc"})
	if a.Body["name"] != "SRC_KV" || a.Body["type"] != "kv" || a.Body["id"] != "kvns-abc" {
		t.Fatalf("source binding body = %v, want name/type/id identifiers", a.Body)
	}
}
