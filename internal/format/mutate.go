package format

// MutatingStore is an OPTIONAL ObjectStore capability, discovered by type assertion exactly as
// ReaderStore and ContextStore are: the ability to DELETE an object.
//
// It is deliberately separate from ObjectStore rather than added to it. Every other consumer of this
// package reads, and nothing in this repository has ever deleted anything. Widening the base interface
// would hand a delete method to the restore path, the verifier, the attester and every test double,
// none of which should have one. A caller that needs to delete asks for the capability and handles its
// absence; a caller that does not cannot reach it by accident.
//
// Delete MUST be idempotent: an object that is already gone is a success, not an error. A prune that
// crashes partway through and is re-run would otherwise fail on its own completed work, and the
// operator would have no way to distinguish "already done" from "cannot delete".
//
// Delete MUST report a refusal as an error rather than swallowing it. A destination under Object Lock
// or WORM legitimately refuses, and the prune counts those rather than treating them as done: silently
// reporting a WORM-refused delete as successful would tell an operator their retention policy had been
// applied when nothing was removed.
type MutatingStore interface {
	Delete(key string) error
}

// A Delete error can say more than "it failed", and the prune reads it through two OPTIONAL methods,
// discovered with errors.As so a store backend need not import this package (the same shape as the
// Unreachable capability on a read):
//
//	DeleteStatus() int  the HTTP status the destination ANSWERED the delete with. A 4xx other than
//	                    408 and 429 is a refusal: the destination was reached and said no. A 5xx, a
//	                    408 or a 429 is a failure a later pass may get past.
//	LockNamed() bool    the destination's own refusal named an Object Lock, a retention or a legal
//	                    hold. It is what the store SAID, read as a boolean; no body text rides on it.
//
// An error with neither is a failure this tool cannot classify: a network fault, or a local I/O error
// other than a permission denial. The prune never reports such an error as a lock, because it is not
// evidence of one.

// ListingStore is an OPTIONAL ObjectStore capability: enumerate the object keys under a prefix.
//
// The prune needs it for one thing only, and it is worth being precise about which, because listing is
// exactly the "deletion by listing heuristic" the format spec forbids as a way of deciding WHAT to
// delete. It is not used to decide that. The decision comes from the signed RUNLOG and the decrypted
// shard manifests, as SPEC 10.1 requires. Listing is used only to enumerate a run tree whose deletion
// has ALREADY been decided by that manifest-driven path, so the tree's own objects can be removed.
type ListingStore interface {
	List(prefix string) ([]string, error)
}
