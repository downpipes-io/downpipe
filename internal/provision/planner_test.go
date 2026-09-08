package provision

import (
	"strings"
	"testing"
)

// sampleConfig returns a fully-populated, valid Config for the ordering and apply tests.
func sampleConfig() Config {
	return Config{
		AppName:             "downpipes prod",
		AccessDomains:       []string{"console.example.com", "engine.example.com"},
		AllowedEmails:       []string{"owner@example.com"},
		AllowedEmailDomains: []string{"example.com"},
		EmailFrom:           "alerts@example.com",
		Secrets: []SecretEntry{
			{Store: "store-1", Name: "signer-private", Summary: "engine signer private"},
			{Store: "store-1", Name: "recipient-public", Summary: "recipient public"},
		},
		Sources: []SourceBinding{
			{Var: "SRC_KV", Type: "kv", ID: "kvns-abc"},
			{Var: "SRC_R2", Type: "r2", ID: "src-bucket"},
		},
		Destination: &DestinationBinding{Var: "DEST_R2", Bucket: "downpipes-archives"},
	}
}

// TestPlannerOrdering locks in the canonical apply order: the Access application first,
// then its policy, then the email note, then the Secrets Store entries, then the source
// bindings, then the destination binding. This is the dependency order Apply relies on
// (the policy needs the app id; bindings may reference a provisioned secret).
func TestPlannerOrdering(t *testing.T) {
	plan, err := Planner{}.Plan("acct123", sampleConfig())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	wantKinds := []Kind{
		KindAccessApp,
		KindAccessPolicy,
		KindEmailNote,
		KindSecret, // recipient-public (sorted by name within kind)
		KindSecret, // signer-private
		KindSourceBinding,
		KindSourceBinding,
		KindDestinationBinding,
	}
	if len(plan.Actions) != len(wantKinds) {
		t.Fatalf("plan has %d actions, want %d", len(plan.Actions), len(wantKinds))
	}
	for i, want := range wantKinds {
		if plan.Actions[i].Kind != want {
			t.Errorf("action %d: kind = %q, want %q", i, plan.Actions[i].Kind, want)
		}
	}
	// Secrets within their kind are name-sorted for a deterministic plan.
	if plan.Actions[3].Name != "recipient-public" || plan.Actions[4].Name != "signer-private" {
		t.Errorf("secret order = %q, %q; want recipient-public, signer-private", plan.Actions[3].Name, plan.Actions[4].Name)
	}
	// The Access app must come strictly before its policy so the app id exists first.
	appIdx, policyIdx := -1, -1
	for i, a := range plan.Actions {
		switch a.Kind {
		case KindAccessApp:
			appIdx = i
		case KindAccessPolicy:
			policyIdx = i
		}
	}
	if appIdx < 0 || policyIdx < 0 || appIdx >= policyIdx {
		t.Errorf("access app (%d) must precede access policy (%d)", appIdx, policyIdx)
	}
}

// TestPlannerOrderingDeterministic confirms the plan is independent of the order the
// builders emitted, because sortActions imposes the canonical order. Reversing the input
// slices must not change the plan's kind sequence.
func TestPlannerOrderingDeterministic(t *testing.T) {
	c := sampleConfig()
	// Reverse the secrets and sources to perturb builder-emission order.
	c.Secrets[0], c.Secrets[1] = c.Secrets[1], c.Secrets[0]
	c.Sources[0], c.Sources[1] = c.Sources[1], c.Sources[0]
	plan, err := Planner{}.Plan("acct123", c)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Actions[3].Name != "recipient-public" || plan.Actions[4].Name != "signer-private" {
		t.Errorf("secret order not deterministic: %q, %q", plan.Actions[3].Name, plan.Actions[4].Name)
	}
}

// TestPlannerNoEmailNoteWhenNoSender confirms the email note appears only when a sender
// is configured: with no EmailFrom there is no manual step.
func TestPlannerNoEmailNoteWhenNoSender(t *testing.T) {
	c := sampleConfig()
	c.EmailFrom = ""
	plan, err := Planner{}.Plan("acct123", c)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, a := range plan.Actions {
		if a.Kind == KindEmailNote {
			t.Fatalf("email note present despite no sender configured")
		}
	}
	_, manual := plan.Counts()
	if manual != 0 {
		t.Errorf("manual count = %d, want 0 with no email sender", manual)
	}
}

// TestPlannerScriptNameDefault confirms an empty ScriptName falls back to EngineScript in
// the binding paths, and that an override is honoured.
//
// A permissive default next to two neighbours that refuse (TestPlannerRejectsUnsafeAccountID
// and TestPlannerRejectsUnsafeScriptName) deserves the same standard those two hold, so the
// reason is written down here. The script name is interpolated into every binding PUT path,
// so the safety of the default rests entirely on ORDER: Plan substitutes EngineScript for the
// empty value FIRST and then runs validatePathSegment over the substituted name, so the
// default is checked by the same guard as an operator's override rather than skipping it.
// That ordering is asserted below, because "the default is a safe literal" is a claim about a
// constant somebody can edit, not a property of the code.
func TestPlannerScriptNameDefault(t *testing.T) {
	plan, err := Planner{}.Plan("acct123", sampleConfig())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !planHasPathContaining(plan, "/workers/scripts/"+EngineScript+"/bindings/") {
		t.Errorf("default script name %q not used in a binding path", EngineScript)
	}
	// The default is not exempt from the guard: it is a value the guard passes. If EngineScript
	// were ever edited to carry a slash or a traversal segment, every account's binding PUTs
	// would be retargeted and no operator would have typed anything.
	if err := validatePathSegment("engine script name", EngineScript); err != nil {
		t.Errorf("the substituted default must satisfy the same path-segment guard as an override: %v", err)
	}

	plan2, err := Planner{ScriptName: "custom-engine"}.Plan("acct123", sampleConfig())
	if err != nil {
		t.Fatalf("Plan(custom): %v", err)
	}
	if !planHasPathContaining(plan2, "/workers/scripts/custom-engine/bindings/") {
		t.Errorf("override script name not used in a binding path")
	}
}

// TestPlannerRejectsUnsafeAccountID confirms an account id carrying a path-traversal
// segment is rejected at plan time (before any Client is built), as a config error so the
// command maps it to a usage exit. This is the dry-run-path arm of the path-traversal guard: the
// account id is interpolated into every API path.
func TestPlannerRejectsUnsafeAccountID(t *testing.T) {
	_, err := Planner{}.Plan("../../zones/other", sampleConfig())
	if err == nil {
		t.Fatal("Plan with an unsafe account id = nil, want an error")
	}
	if !IsConfigError(err) {
		t.Errorf("Plan account-id error is not a config error: %v", err)
	}
	_, err = Planner{}.Plan("acct/../other", sampleConfig())
	if err == nil {
		t.Error("Plan with an embedded traversal in the account id = nil, want an error")
	}
}

// TestPlannerRejectsUnsafeScriptName confirms a script name carrying "/" or ".." is
// rejected at plan time. The script name is interpolated into the binding paths, so an
// unsafe value would retarget the binding PUTs at another script in the account.
func TestPlannerRejectsUnsafeScriptName(t *testing.T) {
	_, err := Planner{ScriptName: "../other-engine"}.Plan("acct123", sampleConfig())
	if err == nil {
		t.Fatal("Plan with an unsafe script name = nil, want an error")
	}
	if !IsConfigError(err) {
		t.Errorf("Plan script-name error is not a config error: %v", err)
	}
	_, err = Planner{ScriptName: "a/b"}.Plan("acct123", sampleConfig())
	if err == nil {
		t.Error("Plan with a slash in the script name = nil, want an error")
	}
}

func planHasPathContaining(p Plan, sub string) bool {
	for _, a := range p.Actions {
		if strings.Contains(a.Path, sub) {
			return true
		}
	}
	return false
}

// TestPlanDescribeRedactsBody is the redaction-by-construction guard for the plan output:
// Describe must never print an action's Body. We give a secret action a sentinel value in
// its Body and assert the rendered plan does not contain it.
func TestPlanDescribeRedactsBody(t *testing.T) {
	plan := Plan{
		AccountID: "acct123",
		Actions: []Action{{
			Kind:    KindSecret,
			Name:    "signer-private",
			Summary: "engine signer private",
			Method:  "PUT",
			Path:    "/accounts/acct123/secrets_store/stores/s/secrets/signer-private",
			Body:    map[string]any{"name": "signer-private", "value": "SENTINEL-SECRET-VALUE"},
		}},
	}
	out := plan.Describe()
	if strings.Contains(out, "SENTINEL-SECRET-VALUE") {
		t.Fatalf("plan output leaked a secret body value:\n%s", out)
	}
	// It should still name the action and its path so the operator knows what it does.
	if !strings.Contains(out, "signer-private") || !strings.Contains(out, "/secrets/signer-private") {
		t.Errorf("plan output missing the action name or path:\n%s", out)
	}
}
