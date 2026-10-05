package provision

import (
	"fmt"
	"sort"
	"strings"
)

// Kind names the class of Cloudflare resource an Action provisions. The order of the
// constants is the canonical apply order (see Planner.Plan): Access first so the
// deployment is gated before anything else exists, then the email note, then the
// secrets the bindings reference, then the bindings themselves.
type Kind string

const (
	// KindAccessApp creates the Cloudflare Access (Zero Trust) self-hosted application
	// in front of the console and engine hostnames.
	KindAccessApp Kind = "access-app"
	// KindAccessPolicy creates an Access policy attached to the application (for
	// example an allow policy scoped to an email-domain or address list).
	KindAccessPolicy Kind = "access-policy"
	// KindEmailNote records the single step the API cannot do today: outbound
	// sending-domain onboarding (DKIM/SPF/DMARC) is dashboard-only in the beta. It is
	// an instruction the plan surfaces, never an API call, so it has no Method/Path.
	KindEmailNote Kind = "email-note"
	// KindSecret puts a value into Cloudflare Secrets Store. The Action never carries
	// the secret value itself; it carries only the store and name so the plan and any
	// log stay redaction-safe.
	KindSecret Kind = "secret"
	// KindSourceBinding declares a source binding (KV, R2, D1, Secrets) on the engine
	// Worker. The binding is the credential, so nothing sensitive crosses the wire.
	KindSourceBinding Kind = "source-binding"
	// KindDestinationBinding declares a destination binding (an R2 bucket, by default)
	// the engine writes archives to.
	KindDestinationBinding Kind = "destination-binding"
)

// applyRank orders the kinds for a deterministic, dependency-respecting apply. A lower
// rank is applied first. Unknown kinds sort last so a future addition cannot silently
// jump ahead of the gate.
func (k Kind) applyRank() int {
	switch k {
	case KindAccessApp:
		return 0
	case KindAccessPolicy:
		return 1
	case KindEmailNote:
		return 2
	case KindSecret:
		return 3
	case KindSourceBinding:
		return 4
	case KindDestinationBinding:
		return 5
	default:
		return 99
	}
}

// Action is one step the provisioner would take. It is fully described by its Kind, a
// stable Name for the plan output, a human Summary, and (for the API-backed kinds) the
// Method, Path and Body of the request a real apply issues. A manual-only Action (the
// email note) leaves Method and Path empty and is skipped by Apply.
//
// Body never contains a Cloudflare API token, a secret value, or any private key
// material. For a secret, Body carries only the secret name; the planner never sets the
// value. Apply injects the value at call time into a local variable and sends it
// directly to the API, so the Action struct is always redaction-safe. There is no
// break-glass private material in any Action: this package provisions account
// infrastructure only.
type Action struct {
	Kind    Kind
	Name    string
	Summary string
	Method  string
	Path    string
	Body    map[string]any
}

// IsManual reports whether the Action has no API call and is surfaced to the operator
// as an instruction only (the email sending-domain step).
func (a Action) IsManual() bool { return a.Method == "" || a.Path == "" }

// Describe renders a single redaction-safe plan line for the Action. It prints the
// Kind, Name, Summary and, for an API-backed Action, the request Method and Path. It
// deliberately never prints the request Body: a secret PUT body would otherwise leak
// the value, and even non-secret bodies are noise the operator does not need.
func (a Action) Describe() string {
	if a.IsManual() {
		return fmt.Sprintf("  [manual] %-22s %s\n      %s", a.Kind, a.Name, a.Summary)
	}
	return fmt.Sprintf("  [api]    %-22s %s\n      %s %s\n      %s", a.Kind, a.Name, a.Method, a.Path, a.Summary)
}

// Plan is the ordered, deterministic list of Actions a setup run would take. It is
// produced by Planner.Plan, printed by the command in a dry run, and executed in order
// by Apply only under --apply.
type Plan struct {
	AccountID string
	Actions   []Action
}

// sortActions orders actions by their kind's apply rank, then by name within a kind, so
// the plan is deterministic regardless of the order the builders ran. The sort is
// stable to keep the builder-emitted order within an equal (kind, name) pair.
func sortActions(actions []Action) {
	sort.SliceStable(actions, func(i, j int) bool {
		ri, rj := actions[i].Kind.applyRank(), actions[j].Kind.applyRank()
		if ri != rj {
			return ri < rj
		}
		return actions[i].Name < actions[j].Name
	})
}

// Describe renders the whole plan as a redaction-safe, human-readable block. The
// account id is shown (it is not a secret); the API token never appears anywhere in a
// Plan, so it cannot be printed.
func (p Plan) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "plan for account %s: %d action(s)\n", p.AccountID, len(p.Actions))
	api, manual := p.Counts()
	fmt.Fprintf(&b, "  %d API call(s), %d manual step(s)\n\n", api, manual)
	for _, a := range p.Actions {
		b.WriteString(a.Describe())
		b.WriteByte('\n')
	}
	return b.String()
}

// Counts returns the number of API-backed actions and manual-only actions in the plan.
func (p Plan) Counts() (api, manual int) {
	for _, a := range p.Actions {
		if a.IsManual() {
			manual++
		} else {
			api++
		}
	}
	return api, manual
}
