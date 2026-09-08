package provision

// EngineScript is the default Worker script name the source and destination bindings
// are attached to. The command can override it; the engine deploys under this name in
// the documented setup.
const EngineScript = "downpipe-engine"

// ConsoleScript is the default Worker script name the console deploys under in the
// documented setup. It mirrors EngineScript so a rename stays in one place.
const ConsoleScript = "downpipe-console"

// Planner turns a declared Config into an ordered Plan. It is a pure function: it makes
// no network call, reads no environment, and holds no token or secret value, so the
// dry-run path (the default) can print exactly what an apply would do without any side
// effect. The script name the bindings attach to is configurable; an empty ScriptName
// uses EngineScript.
type Planner struct {
	ScriptName string
}

// Plan builds the ordered Plan for the account and config. The order is the canonical
// dependency order enforced by sortActions: the Access application and its policy first
// (so the deployment is gated before anything else exists), then the email note, then
// the Secrets Store entries, then the source bindings, then the destination binding
// (bindings that may reference a provisioned secret come after the secrets).
//
// Plan validates the config first and returns a config error (IsConfigError) on a bad
// input, so the command can map it to a usage exit without contacting Cloudflare.
func (p Planner) Plan(accountID string, c Config) (Plan, error) {
	if err := validateAccountID(accountID); err != nil {
		return Plan{}, err
	}
	if err := c.Validate(); err != nil {
		return Plan{}, err
	}
	script := p.ScriptName
	if script == "" {
		script = EngineScript
	}
	// The script name is interpolated into the binding paths, so it gets the same
	// safe-identifier check as the other path segments. EngineScript is a safe literal.
	if err := validatePathSegment("engine script name", script); err != nil {
		return Plan{}, err
	}

	actions := make([]Action, 0, 4+len(c.Secrets)+len(c.Sources))
	actions = append(actions, buildAccessApp(accountID, c))
	actions = append(actions, buildAccessPolicy(accountID, c))
	if c.EmailFrom != "" {
		actions = append(actions, buildEmailNote(c))
	}
	for _, s := range c.Secrets {
		actions = append(actions, buildSecret(accountID, s))
	}
	for _, s := range c.Sources {
		actions = append(actions, buildSourceBinding(accountID, script, s))
	}
	if c.Destination != nil {
		actions = append(actions, buildDestinationBinding(accountID, script, *c.Destination))
	}

	sortActions(actions)
	return Plan{AccountID: accountID, Actions: actions}, nil
}
