package restore

import (
	"fmt"
	"strings"
)

// EnvTarget restores record values as dotenv KEY='value' lines to a stream, the
// offline secrets-style target for an environment that loads from a file (SPEC.md
// 12.6). The destination key is the record name validated as a POSIX
// environment-variable name; the existing-key set is the names already declared in the
// environment the operator supplied, so a restore refuses to redefine a variable that
// is already set rather than silently shadowing it. A value carrying a NUL byte or an
// embedded CR/LF is refused rather than written, since not every consumer of this sink
// parses a dotenv line with full shell-quoting grammar.
type EnvTarget struct {
	w        envWriter
	existing map[string]struct{}
}

// envWriter is the write side of an EnvTarget, satisfied by an *os.File, a buffer or
// any io.Writer the caller chooses.
type envWriter interface {
	Write(p []byte) (int, error)
}

// NewEnvTarget returns an EnvTarget writing dotenv lines to w. existingNames is the set
// of variable names already present in the target environment (for example the names
// parsed from an existing .env file or the operator's current environment); a nil or
// empty set means a clean environment. The set is the names only, never their values,
// so an EnvTarget never reads a secret value that is already set.
func NewEnvTarget(w envWriter, existingNames []string) *EnvTarget {
	set := make(map[string]struct{}, len(existingNames))
	for _, n := range existingNames {
		set[n] = struct{}{}
	}
	return &EnvTarget{w: w, existing: set}
}

// Kind reports the env target enum.
func (e *EnvTarget) Kind() string { return "env" }

// Key returns the record name as a destination variable name, rejecting any name that
// is not a valid POSIX environment-variable name. Rejecting the name (rather than
// rewriting it) means a crafted record name cannot inject extra dotenv lines, and two
// records with the same valid name collide on one key and are caught as a conflict.
//
// The env sink cannot represent a key for the env target, but Key is a pure function of
// the name and cannot see the record's source type. The reprovision guard for `workers`
// and `cf-config` lives in MakePlan (which has the whole record), so a Worker bundle or a
// configuration surface is never silently emitted as a dotenv value here.
func (e *EnvTarget) Key(name string) (string, error) {
	if !validEnvName(name) {
		return "", fmt.Errorf("record name %q is not a valid environment-variable name for an env target", name)
	}
	return name, nil
}

// Existing returns the set of variable names already declared in the target
// environment, copied so a caller cannot mutate the target's view.
func (e *EnvTarget) Existing() (map[string]struct{}, error) {
	out := make(map[string]struct{}, len(e.existing))
	for k := range e.existing {
		out[k] = struct{}{}
	}
	return out, nil
}

// Write emits one KEY='value' line. The key is re-validated and a value carrying a NUL
// byte or an embedded CR/LF is rejected as unsuitable for a dotenv target: single
// quotes make the line shell-safe for a POSIX-shell `source` consumer, but this sink is
// also documented for line-oriented dotenv consumers (e.g. `docker --env-file`,
// systemd EnvironmentFile) that split on any embedded newline regardless of quoting, so
// a value that would otherwise smuggle a second physical line is refused rather than
// silently emitted. A name already present in the target environment is refused, so a
// write never redefines a variable that another record or the existing environment
// already set.
func (e *EnvTarget) Write(key string, value []byte) error {
	if !validEnvName(key) {
		return fmt.Errorf("record name %q is not a valid environment-variable name for an env target", key)
	}
	if _, taken := e.existing[key]; taken {
		return fmt.Errorf("environment variable %s is already set; refusing to redefine it", key)
	}
	if strings.ContainsAny(string(value), "\x00\r\n") {
		return fmt.Errorf("value for %s contains a NUL byte or a line break and cannot go to a dotenv target", key)
	}
	escaped := strings.ReplaceAll(string(value), "'", `'\''`)
	if _, err := fmt.Fprintf(e.w, "%s='%s'\n", key, escaped); err != nil {
		return fmt.Errorf("write env line for %s: %w", key, err)
	}
	// Record the just-written name so a duplicate within one apply is caught even
	// though it was not in the original environment.
	e.existing[key] = struct{}{}
	return nil
}

// Close is a no-op; EnvTarget holds no resources beyond the stream the caller owns.
func (e *EnvTarget) Close() error { return nil }

// validEnvName reports whether name is a POSIX environment-variable name:
// [A-Za-z_][A-Za-z0-9_]*. This excludes the newline, '=' and space that would let a
// crafted record name inject lines into the dotenv output.
func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
