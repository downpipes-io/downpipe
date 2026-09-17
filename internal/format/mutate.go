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
