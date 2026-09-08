// Package provision is the local Cloudflare provisioner behind the "downpipe setup"
// subcommand. It runs on the operator's own
// machine with the operator's own Cloudflare API token and provisions the pieces of a
// downpipes deployment that the API can create: the Cloudflare Access application and
// its policies, a note recording the one manual email sending-domain step, Secrets
// Store entries, and the source and destination bindings.
//
// No-custody is the whole point of this path. The token is read from the environment
// by the command layer and handed in here; it is sent only to api.cloudflare.com over
// HTTPS via the Doer, and it is never logged, never written to a plan, and never
// transmitted anywhere else. The vendor and the in-account console never see it: it
// lives and dies on the operator's laptop. There is no break-glass private material
// anywhere near this package; setup provisions account infrastructure, not keys.
//
// The package is built so a test never makes a real network call. The CF client sits
// behind the Provisioner interface and is driven by an injectable Doer (an
// http.Client satisfies it by structural typing), so a fake Doer can assert the exact
// request shapes a real apply would issue. The Planner is a pure function over the
// declared inputs: it produces the ordered list of Actions a run would take, which the
// command prints in a dry run (the default) and which Apply executes only under
// --apply at real runtime.
package provision
