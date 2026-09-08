package format

import "errors"

// Normative reader exit codes (SPEC.md 8.5). The CLI maps an ExitError's code to its
// process exit status; an unclassified error exits 1.
const (
	ExitVerified   = 0 // verified and complete
	ExitUnverified = 2 // missing/invalid/wrong-signer signature or a failed recompute
	ExitIncomplete = 3 // coverage below the declared record count
	ExitPlaintext  = 4 // a per-record plaintext hash mismatch
	ExitStale      = 5 // a stale run, chain anomaly, below-pin or absent/invalid RUNLOG
	ExitUsage      = 6 // a usage or input error

	// ExitPreflight is OUTSIDE the SPEC-normative reader set above: the deploy-time
	// account preflight found failing checks, or could not verify an explicitly
	// requested --domain. It deliberately does not reuse ExitUnverified (a reader
	// signature/recompute verdict) so exit-status-driven tooling can tell them apart.
	ExitPreflight = 7

	// ExitIncompleteMarkers is OUTSIDE the SPEC-normative reader set above and is an
	// ADVISORY, not a hard failure: the run verified and every restored record's value
	// hash-checked, but one or more of those records is an INCOMPLETENESS MARKER (the source
	// was only partially available when the run was written, so the record's value is a
	// sentinel placeholder, not live data). The data genuinely restored, so this is kept
	// SEPARATE from the hard-failure codes (2-6) and from ExitPreflight, letting a DR script
	// tell "succeeded, but some values are placeholders" apart from "corrupt/failed" and never
	// read an exit-zero as a clean full restore. A hard verification or per-record failure
	// always takes precedence over this advisory.
	ExitIncompleteMarkers = 8

	// ExitUnwritten is OUTSIDE the SPEC-normative reader set and is an ADVISORY in the same
	// family as ExitIncompleteMarkers: the run verified and every record that could be written
	// WAS written and hash-checked, but one or more records were skipped because the target
	// could not take them. The name may be one this target cannot represent (a Windows reserved
	// device name on the file sink), the destination key may already exist, or two records may
	// map to the same key.
	//
	// It exists because the alternative was exit 0. Those records are in the archive and are NOT
	// on the operator's disk, and a summary line on stderr is not something a DR script reads.
	// The surrounding code already holds the line that a script must never read an exit-zero as a
	// clean full restore, and applied it to per-record failures and to incompleteness markers;
	// this closes the one case that was still exiting clean while data did not land.
	//
	// Advisory, so it stays clear of the hard-failure codes: nothing is corrupt and every skip is
	// named on stderr. A hard verification or per-record failure takes precedence, and this takes
	// precedence over ExitIncompleteMarkers, because a record that never landed is a bigger gap
	// than one that landed carrying a placeholder.
	//
	// 10 and not 9: ExitCustody already ships as 9. The two are not merely different, they are
	// opposite readings of the same number. ExitCustody says nothing was recovered because the
	// shares or envelope are wrong; this says the restore ran and verified and some records did
	// not land. They meet on ONE command, because custody artefacts are accepted wherever
	// --identity is, restore included, so a recovery script reading 9 off a `restore --share`
	// could either re-gather correct shares or trust a restore that left records behind.
	ExitUnwritten = 10

	// ExitCustody is OUTSIDE the SPEC-normative reader set above: a custody-integrity
	// failure while recombining the offline break-glass artefacts (the recombined
	// wrapping key fails its public checksum, the authenticated envelope decrypt
	// refuses, or the recovered plaintext is not an identity-key file). It is kept
	// separate from the archive verdicts (2-6) so exit-status-driven recovery tooling
	// can tell "your shares or envelope are wrong" apart from "the archive is bad",
	// and from ExitUsage so a malformed FILE (6) reads differently from a
	// well-formed-but-wrong SET (9).
	ExitCustody = 9

	// ExitUnreachable is OUTSIDE the SPEC-normative reader set above, added following the
	// exact precedent by which 7, 8, 9 and 10 were each added later as the reader grew a
	// distinction the original six-code set had no room for.
	//
	// THE BOUNDARY. It marks an ObjectStore read (root manifest, signature, RUNLOG, shard or
	// segment) that never RETRIEVED bytes at all: a network failure, a DNS failure, a refused
	// connection, or the destination refusing the request outright (403/401/404/5xx) before
	// any body arrived. This is deliberately distinct from ExitUnverified (2), which means
	// bytes WERE retrieved and only then failed a hash, signature or authenticated-decrypt
	// check. A destination read failure and a genuine tamper finding used to share code 2,
	// leaving a recovery script running mid-incident unable to tell "retry once the endpoint
	// or credentials are fixed" from "stop, this archive may be compromised" -- opposite
	// responses the two causes demand.
	//
	// A truncated or partial read -- bytes started arriving and then stopped, or arrived and
	// were rejected for exceeding the per-object byte ceiling -- stays on the ExitUnverified
	// side, not this one. Some bytes were retrieved, so something IS now known about them (an
	// AEAD tag or a signed hash to check them against), and a partial or oversized object is
	// at least as consistent with tampering or corruption as with a network blip. Splitting
	// "some bytes" toward the retry-safe code would soften the exact signal this code exists
	// to keep sharp.
	//
	// 11, NOT 1. Reusing 1 (the crash-path default for a panic or any error this reader did
	// not classify) was considered and rejected: 1 already means "unclassified, maybe safe to
	// retry, maybe not", so formalising it as "safe to retry" would collide with a genuinely
	// unclassified failure that is NOT safe to blindly retry. 11 is a new, unambiguous slot.
	//
	// THE UNCLASSIFIABLE DEFAULT. An error this package cannot positively identify as
	// transport/access layer is NOT reclassified to 11: it keeps whatever code its call site
	// already assigned before this code existed (ExitUnverified for a root/signature/shard/
	// segment read, ExitStale for a RUNLOG read, ExitIncomplete for a missing shard in the
	// streaming walk). That is the deliberately SAFER default -- an unclassifiable Get
	// failure keeps reading as a possible tamper or freshness finding, never as a silent
	// invitation to retry.
	//
	// SCOPE: network stores only. The classification is a capability an ObjectStore's error
	// can implement (see unreachableGetErr below), discovered through errors.As so a store
	// backend need not import this package. internal/source's S3Store implements it for a
	// transport failure and a non-2xx status. internal/source's DirStore deliberately does
	// NOT: a local "no such file" or "permission denied" carries far less signal than a
	// network 403/404 about whether the object was merely inaccessible or genuinely gone, and
	// pruned.go's prunedTreeDiagnosis already reasons through that exact ambiguity for a
	// pruned run's absent tree, choosing to soften only the wording, never the code, because
	// the offline reader cannot tell a completed prune from an attacker's deletion. That
	// reasoning transfers unchanged here: a local read failure stays on whatever code it
	// already carried.
	ExitUnreachable = 11

	// ExitUnrenderable is OUTSIDE the SPEC-normative reader set above and is an ADVISORY in
	// the same family as ExitIncompleteMarkers and ExitUnwritten: the run verified, every
	// planned record was written, and every value hash-checked, but one or more of those
	// records carries a downpipe D1 body-format label this release does not know how to
	// render. The verified bytes were written unchanged, so nothing was lost and nothing is
	// corrupt; what the reader cannot do is turn them into the runnable SQL the D1 replay
	// guidance describes.
	//
	// It exists because the alternative was exit 0 alongside guidance to feed the file to
	// sqlite3. A body-format label is versioned independently of the archive's own
	// formatVersion, so an archive written by a newer engine opens, verifies and restores
	// through a reader that cannot read its D1 bodies, and before this code the operator's
	// only signal was the parse error sqlite3 gave them afterwards.
	//
	// It is the LEAST severe of the three advisories, and a DR script should read it that
	// way rather than reading the numbers as a ranking. ExitUnwritten means records are in
	// the archive and not on disk; ExitIncompleteMarkers means records landed carrying a
	// placeholder instead of the source's data; this means every byte landed intact and one
	// release of this tool cannot render it, which another release can. Both of those take
	// precedence over it, and any hard verification or per-record failure takes precedence
	// over all three.
	//
	// 12 and not a reuse of 8: an incompleteness marker says the SOURCE was partially
	// unavailable when the backup ran, which is a statement about the data. This says
	// nothing about the data at all, only about this reader, so a script that treats the two
	// alike would either chase a backup-time gap that never happened or ignore a file it must
	// not apply.
	ExitUnrenderable = 12

	// ExitDangling is OUTSIDE the SPEC-normative reader set above and marks a run whose
	// signed manifests all verified and whose every per-record failure was a seg/ object
	// those manifests name and this copy of the archive does not hold (SPEC.md 10.1's
	// dangling reference). Nothing was retrieved for those records, so no AEAD tag, no
	// signed hash and no signature failed.
	//
	// THE CONFLATION IT ENDS. An absent segment and a failed authentication tag both
	// reached the operator as ExitUnverified (2) and, worse, as the same sentence:
	// "completeness=UNVERIFIED (1 of 1 record(s) failed integrity)". Driven against a real
	// signed archive, deleting the one seg object and flipping a byte inside it produced
	// byte-identical verdict lines. The two states have opposite remedies. An absent
	// segment means fetch the object from another copy of the bucket, or accept that this
	// copy is incomplete. A failed tag means the bytes were altered and this copy must not
	// be trusted. Telling an operator their data is corrupt when it is merely absent points
	// them away from the replica that would have restored them, which is the more damaging
	// of the two errors.
	//
	// The signed receipt already drew this line: danglingSegments counts distinct absent
	// seg/ paths and reads 1 against an absent segment and 0 against a flipped byte. The
	// exit status and the printed line now agree with it, so the receipt is no longer the
	// only honest surface.
	//
	// PRECEDENCE, because the numbers are not a ranking. Any per-record failure that DID
	// fail a check takes precedence: a pass with one absent segment and one failed tag
	// exits 2 (or 4 for a plaintext mismatch), never this. A signature or structural
	// verdict on the run itself takes precedence too. Against the advisories this one wins:
	// 8, 10 and 12 all describe records that ARE in the archive, and this describes records
	// that are not.
	//
	// 13 and not a reuse of 3: ExitIncomplete is the structural count check, raised before
	// a single segment is fetched, and it says the manifests do not add up. This says the
	// manifests add up exactly and the bucket is missing an object they name, which is a
	// finding about the DESTINATION rather than about the manifest. Nor a reuse of 11:
	// ExitUnreachable means the destination refused the request or could not be reached
	// before any bytes arrived, so nothing at all is known and a retry against the same
	// place may work; here the read was answered and the answer was that the object is not
	// there, so a retry against the same copy will keep failing.
	ExitDangling = 13
)

// ExitError carries a normative exit code alongside an error so the command layer can
// translate a verification outcome into the process exit status.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

// ExitCode returns the normative exit code this error carries (SPEC.md 8.5). It lets a
// caller in another package read the code through a small `interface{ ExitCode() int }`
// without importing the ExitError type, so a per-record failure's true class (a plaintext
// mismatch vs a structural/AEAD failure) survives across a package boundary instead of
// being flattened to a generic exit 1.
func (e *ExitError) ExitCode() int { return e.Code }

// coded wraps err with a normative exit code.
func coded(code int, err error) error {
	if err == nil {
		return nil
	}
	return &ExitError{Code: code, Err: err}
}

// codedIfNot wraps err with code only when err does not already carry an ExitError.
// Use this when a called function may already have classified the error and the
// caller wants to supply a fallback code without overwriting a more specific one.
func codedIfNot(code int, err error) error {
	if err == nil {
		return nil
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		return err
	}
	return &ExitError{Code: code, Err: err}
}

// exitCodeOf reads the normative exit code err carries (most often via coded, codedIfNot
// or codedGet), and reports false when err carries none. A caller that tracks its own
// running exit-code field across several fallible steps (AttestResult.Code) uses this so
// the field agrees with whatever code the step's own error actually carries, rather than
// assuming every step of that kind produces the one code it used to.
func exitCodeOf(err error) (int, bool) {
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code, true
	}
	return 0, false
}

// unreachableGetErr is the OPTIONAL capability an ObjectStore Get/GetContext/GetReader
// error can implement to self-report as transport/access layer (ExitUnreachable's doc
// above states the boundary). It is checked through errors.As, so a store backend in
// another package (internal/source) satisfies it structurally without importing this
// package, the same pattern ExitError.ExitCode() uses in the other direction.
type unreachableGetErr interface{ Unreachable() bool }

// codedGet classifies a store read failure (root, signature, RUNLOG, shard or segment):
// ExitUnreachable when err self-reports transport/access layer, else fallback -- the
// code this call site would have used before ExitUnreachable existed. err is assumed
// non-nil, as at every other call in this file. The concrete *ExitError return (rather
// than error, like coded/codedIfNot) lets a caller that tracks its own running exit code
// outside an error value (AttestResult.Code) read .Code back off the same classification
// the returned error carries, so the two never disagree about which code fired.
func codedGet(fallback int, err error) *ExitError {
	var ue unreachableGetErr
	if errors.As(err, &ue) && ue.Unreachable() {
		return &ExitError{Code: ExitUnreachable, Err: err}
	}
	return &ExitError{Code: fallback, Err: err}
}
