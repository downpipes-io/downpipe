package restore

import (
	"io"
)

// Target is an offline restore destination the operator controls. A Target maps a
// record name to a stable destination key, enumerates the keys already present so the
// planner can refuse to clobber existing state, and writes a record's value on apply.
//
// The two implementations are the filesystem directory sink and the env/secrets-style
// sink documented in SPEC.md 12.6. A Target holds nothing of the vendor's and learns
// only the customer's own record names and values, which it places into the customer's
// own destination.
type Target interface {
	// Kind is the receipt's target type enum (SPEC.md 8.5), for example "file" or
	// "env". It is a closed label, never a path or a value.
	Kind() string

	// Key maps a record name to the destination key the value would occupy. It is a
	// pure function of the name (it touches no state and writes nothing) so the
	// planner can detect two records that collide on one key, and an error reports a
	// name the target cannot represent (for example a name that is not a valid
	// environment-variable name for the env target).
	Key(name string) (string, error)

	// Existing returns the set of destination keys already present in the target, so
	// the planner can mark a record whose key already exists as a conflict rather than
	// overwrite it. It reads the target but never writes.
	Existing() (map[string]struct{}, error)

	// Write places value under key. It MUST refuse to overwrite an existing key and
	// report that as an error, so a target-state change between Plan and Apply (a key
	// that appeared after planning) is caught at write time and never silently
	// clobbers. The planner only calls Write for records it has cleared of conflicts.
	Write(key string, value []byte) error

	// Close flushes and releases any resources held by the target.
	Close() error
}

// StreamTarget is an optional capability a Target may add to accept a record value as a
// stream rather than a whole []byte, so a value larger than memory can be restored on a
// constrained machine (SPEC.md 1). A target that implements it is offered the streaming
// restore path for streamable records; a target that does not is always written through
// Write. WriteStream carries the same no-clobber contract as Write: it MUST refuse to
// overwrite an existing key. size is the manifest's declared plaintext size, for a
// pre-allocation hint only; the implementation copies until src reports EOF and never
// trusts size as a length.
type StreamTarget interface {
	WriteStream(key string, src io.Reader, size int64) error
}
