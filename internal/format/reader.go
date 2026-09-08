package format

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// ObjectStore is the read side of a destination: fetch an object's bytes by key under
// the archive root. The offline reader uses local disk or a minimal S3 GET, kept
// behind this interface so the reader core imports no network or vendor package
// (CONTRIBUTING).
type ObjectStore interface {
	Get(key string) ([]byte, error)
}

// ReaderStore is an OPTIONAL ObjectStore capability, discovered by type assertion:
// open one object as a bounded stream instead of a whole buffer, so a large sealed
// segment decrypts chunk by chunk without its ciphertext ever being held in memory.
// The int64 is the store's size hint (negative when unknown); the byte ceiling the
// buffered Get enforces applies identically, enforced on the stream. Only the segment
// reads of RestoreRecordTo use it; manifests, the root, the RUNLOG and the recovery
// bundle stay on Get, whose whole-request bounds suit small objects.
type ReaderStore interface {
	GetReader(ctx context.Context, key string) (io.ReadCloser, int64, error)
}

// ContextStore is an OPTIONAL ObjectStore capability, discovered by type assertion: a
// buffered Get whose blocking wait is bounded by the caller's context. The shard walk
// uses it so an error teardown or an operator interrupt cancels in-flight fetches
// instead of waiting out the store's own timeout. Stores without it fall back to Get.
type ContextStore interface {
	GetContext(ctx context.Context, key string) ([]byte, error)
}

// storeGet fetches one object through the store's context capability when it has one,
// else through the plain Get. Helpers on the fetch path route through this so every
// backend gains cancellation the moment it implements GetContext.
func storeGet(ctx context.Context, store ObjectStore, key string) ([]byte, error) {
	if cs, ok := store.(ContextStore); ok {
		return cs.GetContext(ctx, key)
	}
	return store.Get(key)
}

// Reader is an opened, verified archive run. Open performs the verified-mode checks;
// Records lists the recovered record metadata; RestoreRecord reassembles and verifies
// one record's value.
type Reader struct {
	store ObjectStore
	// ctx is the caller context fetches on this reader observe (StreamOpenContext); a
	// nil ctx means Background (the zero value and the plain Open path).
	ctx        context.Context
	runIDBytes []byte
	master     []byte
	root       *spec.RootManifest
	records    []spec.ShardRecord
	preambles  []spec.ShardPreamble
	freshness  FreshnessResult
	outcome    Outcome
}

// Close wipes the run master this reader holds. Call it with defer as soon as a reader is opened.
//
// WHY IT IS NOT DONE EARLIER. The master must live as long as the reader does: openSegment derives a
// per-segment file key from it on every record it restores, so wiping it at open would break the reader.
// That makes the lifetime the CALLER'S to end, which is what this method is for.
//
// WHY IT MATTERS MORE HERE THAN IN THE ENGINE. This is the binary a customer runs on their own machine
// with their break-glass key, and in the strict break-glass-only posture, now the default, it is the only
// thing that can read an archive at all. crypto.OpenCapsule is already careful: it zeroises the KEM shared
// secret, the wrap key and its own copy of the recovered master as soon as recovery completes. The master
// it RETURNS then lived in this struct for the whole process with nothing to end it.
//
// Best-effort, with the same caveat crypto.Zeroize states: Go's copying collector gives no guarantee that
// every copy of a secret is erased. It is defence in depth, not a promise.
//
// Idempotent, and safe on a zero-value or already-closed reader.
func (r *Reader) Close() {
	crypto.Zeroize(r.master)
}

// context returns the caller context fetches on this reader observe: the one carried
// from StreamOpenContext, or Background for the zero value and the plain Open path.
func (r *Reader) context() context.Context {
	if r.ctx == nil {
		return context.Background()
	}
	return r.ctx
}

// Options controls verified-mode policy for Open (SPEC.md 8.5, 10).
type Options struct {
	// MinRunlogIndex pins the lowest acceptable RUNLOG maximum index out of band, the
	// anti-rollback high-water mark; 0 means no pin.
	MinRunlogIndex int64
	// AllowStale proceeds despite a run's AGE: the RUNLOG verified against the pinned
	// signer and is internally consistent, and what it says is either that this run is
	// not the latest for its downpipe or that the log's maximum index is below the
	// operator's own MinRunlogIndex pin. The outcome is recorded rather than failing.
	//
	// AllowStale must not waive a finding about the RUNLOG's own trustworthiness: a forged
	// _RECOVERY/RUNLOG.sig, a deleted RUNLOG, an unparseable or empty log, a run the log
	// does not carry, an entry contradicting the signed root, or a rewritten chain. Those
	// need the separate, stronger acknowledgement: see AllowUnverifiedRunlog and
	// FreshnessResult.RunlogUntrusted.
	AllowStale bool
	// AllowUnverifiedRunlog proceeds despite the RUNLOG itself being untrustworthy: it
	// could not be read, its signature does not verify against the pinned signer or does
	// not decode, it does not parse, it is empty, it does not carry this run, its entry
	// contradicts the signed root on downpipe, index or prevRunId, or it verified and is
	// internally contradictory (a chain anomaly). It is a strictly stronger statement
	// than AllowStale and subsumes it, because a log that cannot be trusted returns no
	// age verdict to accept separately.
	//
	// It is wanted on its own, which is why it is a flag and not a mode of AllowStale: a
	// bucket copied without its _RECOVERY prefix has no RUNLOG at all, and the operator
	// recovering from it is making no claim about which run is latest.
	AllowUnverifiedRunlog bool
	// AllowUnverified proceeds despite a missing or invalid root signature, recording
	// the true outcome rather than failing (SPEC.md 8.3: present AEAD-authenticated
	// bytes are never gated on the signature). It implies both AllowStale and
	// AllowUnverifiedRunlog: an operator who will proceed on an unsigned root manifest is
	// not being asked again about the RUNLOG that manifest's signature would have
	// anchored. Structural
	// integrity gates (the master capsule, the key commitment, the recipient set,
	// completeness, the Merkle root) still fail hard, because those mean the archive is
	// actually broken, not merely unsigned.
	AllowUnverified bool
	// CheckRecoveryBundle binds the in-bucket recovery bundle on read (SPEC.md 8.7
	// item 4): when the recoverer relies on the bundled FORMAT.md/RECOVER.md rather
	// than an independently trusted spec and reader, recompute their SHA-384 against the
	// bundle's signed SHA384SUMS. A mismatch fails verified restore (exit 2) and records
	// recoveryBundleVerified false. It is off by default because a recoverer who brings
	// a trusted spec MAY skip the comparison; AllowUnverified downgrades a failure here
	// to a recorded outcome, the same as the signature gate.
	CheckRecoveryBundle bool
	// FetchConcurrency is the size of the shard prefetch window: how many shard objects
	// the streaming walk may GET-and-decrypt concurrently while the single-threaded
	// consumer folds their records in canonical order. 0 or 1 is strict sequential
	// bounded-memory (the default, byte-for-byte the original loop); N>1 fetches up to N
	// shards ahead but still DELIVERS them to the consumer in shard-list order, so the
	// folded Merkle root and the restored record stream are byte-identical to the
	// sequential walk. It speeds up restore (better RTO) on a high-latency object store
	// without changing the result. See StreamReader.walkShards.
	FetchConcurrency int
	// MaxMemoryBytes optionally caps the bytes held in the prefetch buffer when
	// FetchConcurrency>1: the prefetcher stops starting a new shard fetch while the
	// fetched-but-not-yet-consumed shards already total at least this many bytes. 0 means
	// no explicit cap (the window size FetchConcurrency is then the only bound, and the
	// process still honours GOMEMLIMIT). The bound is approximate by one window: a shard's
	// size is known only after its GET (a ShardRef carries no pre-fetch size), so up to
	// FetchConcurrency in-flight fetches can overshoot the cap before their sizes register.
	MaxMemoryBytes int64
}

// acknowledges reports whether these options waive the freshness failure recorded in
// fresh, so the reader proceeds and records the gap instead of exiting 5.
//
// IT IS ONE FUNCTION BECAUSE THE GATE IS IN TWO PLACES. Open and StreamOpenContext each
// carry their own copy of the freshness tail, and the condition they used to carry was
// `!opts.AllowStale && !opts.AllowUnverified` written out twice. A permission boundary
// spelled out at each of its sites is one edit away from the two sites disagreeing about
// what a customer consented to, and the whole point of the split is that the word the
// customer typed is the record of that consent.
//
// The order is deliberate. AllowUnverified is checked first because it subsumes both of
// the others; RunlogUntrusted is checked before AllowStale so that the age word can never
// reach a finding about the log itself, which is the inversion this replaces.
func (o Options) acknowledges(fresh FreshnessResult) bool {
	if o.AllowUnverified || o.AllowUnverifiedRunlog {
		return true
	}
	if fresh.RunlogUntrusted {
		return false
	}
	return o.AllowStale
}

// Outcome records the verification result of a run for the restore receipt (SPEC.md
// 8.5). The labels (SignatureResult, Completeness) are honest regardless of the mode and
// never launder a UNVERIFIED run as complete. Code is the exit code this run will produce
// in the current mode: a signature or structural failure always pins it to ExitUnverified,
// but an acknowledged stale-but-validly-signed run exits 0 because AllowStale was set. To
// detect a staleness gap the caller themselves allowed, read Completeness ("UNVERIFIED")
// rather than Code, which by design reports 0 for that acknowledged case.
type Outcome struct {
	SignatureResult    string // "valid" | "invalid" | "absent" | "wrong-signer"
	Completeness       string // "complete" | "UNVERIFIED"
	BreakGlassVerified bool
	// RecoveryBundleVerified is meaningful only when Options.CheckRecoveryBundle was set
	// (SPEC.md 8.7 item 4): true when the bundled FORMAT.md/RECOVER.md matched the
	// signed SHA384SUMS, false when the check was requested and failed. A recoverer that
	// did not request the check brings its own trusted spec and reader and leaves it
	// false, recording the skip rather than a pass.
	RecoveryBundleVerified bool
	Mode                   string // "verified" | "allow-unverified"
	// Code is the exit code this run will produce: 0 when the run is acceptable in the
	// current mode (including a stale run whose AllowStale was acknowledged),
	// ExitUnverified(2) on a signature or structural failure, and ExitStale(5) only when
	// the run is stale and AllowStale was not set. A caller checking for a staleness gap
	// they allowed must read Completeness=="UNVERIFIED", not Code, which reports 0 there.
	Code int
}

// Verified reports whether the run fully verified (the only exit-0 condition).
func (o Outcome) Verified() bool { return o.Code == 0 }

// Open reads and verifies a run: it verifies the root signature against the
// operator-supplied signer (never the manifest's self-asserted fingerprint), unwraps
// the master capsule with the held recipient, checks the key commitment and the
// recipient set including break-glass presence, opens every shard manifest after
// checking its signed hash, and verifies the declared count and the Merkle root over
// the record hashes (SPEC.md 8.3). It returns an error on any mismatch.
func Open(store ObjectStore, runID string, recipient *crypto.HybridKEMPrivate, signer *crypto.HybridVerifier, opts Options) (*Reader, error) {
	runIDBytes, err := spec.DecodeULID(runID)
	if err != nil {
		return nil, coded(ExitUsage, fmt.Errorf("runId: %w", err))
	}
	rootBytes, err := openRootManifest(store, runID)
	if err != nil {
		return nil, err
	}
	outcome := Outcome{SignatureResult: "valid", Completeness: "complete", Mode: "verified"}
	if opts.AllowUnverified {
		outcome.Mode = "allow-unverified"
	}

	if err := verifyRootSignatureGate(store, runID, rootBytes, signer, opts, &outcome); err != nil {
		return nil, err
	}

	root, err := ParseRoot(rootBytes)
	if err != nil {
		return nil, err // already coded (usage), and bytes are unrecoverable without a parseable root
	}
	// Reject any formatVersion this reader does not implement, before any further
	// processing (SPEC.md 13, 14.3 unknown-major and unimplemented-minor). While the major is 0 the MINOR is the
	// compatibility unit, so the reader accepts exactly its own major.minor at any patch.
	// A reader may not interpret a version it does not implement: the format rules, key
	// derivations and field semantics can all differ between compatibility units.
	if err := checkFormatVersion(root.FormatVersion); err != nil {
		return nil, err
	}
	if err := checkEnvelopeCodec(root); err != nil {
		return nil, err
	}
	if root.RunID != runID {
		return nil, coded(ExitUnverified, fmt.Errorf("manifest runId %q does not match the requested run %q", root.RunID, runID))
	}

	// Byte-recovery crypto: fatal regardless of mode, because without it there are no
	// bytes to recover.
	master, err := unwrapMaster(root, recipient)
	if err != nil {
		return nil, coded(ExitUnverified, err)
	}

	// Structural integrity gates: fatal even under allow-unverified (a failure here
	// means the archive is broken, not merely unsigned).
	if err := checkKeyCommitment(root, master, runIDBytes); err != nil {
		return nil, coded(ExitUnverified, err)
	}
	if err := checkRecipientSet(root); err != nil {
		return nil, coded(ExitUnverified, err)
	}
	// breakGlassVerified is true only when the identity that actually opened this run is
	// the signed break-glass recipient (SPEC.md 8.6): an operational-path open proves
	// recoverability for the operational key, not for the offline break-glass key.
	outcome.BreakGlassVerified = identityIsBreakGlass(root, recipient)

	preambles, records, err := openShards(store, root, master, runIDBytes)
	if err != nil {
		// openShards may return a coded error (e.g. ExitUsage for a codec violation);
		// do not overwrite an already-coded exit code with ExitUnverified.
		return nil, codedIfNot(ExitUnverified, err)
	}
	if err := checkCompleteness(root, records); err != nil {
		return nil, err // already coded: count is ExitIncomplete, the rest ExitUnverified
	}

	fresh, ferr := checkFreshness(store, runID, root, signer, opts)
	if ferr != nil {
		outcome.Completeness = "UNVERIFIED"
		if !opts.acknowledges(fresh) {
			return nil, ferr // coded ExitStale: a freshness problem the operator did not acknowledge
		}
		// Acknowledged: proceed and record the freshness gap (the receipt's
		// isLatestForDownpipe tells the truth), but do not force exit 5. A signature
		// failure still sets Code=ExitUnverified above and is never laundered, only an
		// acknowledged stale-but-validly-signed run exits 0. Which acknowledgement was
		// required is Options.acknowledges's decision, not this site's: --allow-stale
		// reaches only the age findings, and everything about the RUNLOG's own
		// trustworthiness needs --allow-unverified-runlog.
	}

	if err := verifyRecoveryBundleGate(store, signer, opts, &outcome); err != nil {
		return nil, err
	}

	return &Reader{store: store, runIDBytes: runIDBytes, master: master, root: root, records: records, preambles: preambles, freshness: fresh, outcome: outcome}, nil
}

// signerMismatchHint makes a "wrong-signer" root-signature failure ACTIONABLE for the most
// common benign cause: the operator pinned a signer key that was rotated AFTER this archive
// was sealed. It reads the archive's declared signingKeyFingerprint (from the already-fetched,
// still-untrusted root bytes) and compares it to the pinned verifier's fingerprint, computed
// with the byte-identical formula the engine writer stamps (crypto.SignerFingerprint =
// "edmldsa1:"+hex(sha384(ed||mldsa))). Reading the unverified field only shapes the error
// message; the signature still fails closed, so this stays a trust-free read. It returns ""
// (message unchanged) when the field is unreadable or the fingerprints MATCH (a genuine
// tamper/corruption, not a rotation). This mirrors the engine reader's signerMismatchHint
// so the offline DR restore and the online restore explain a rolled key the same way.
//
// The wording deliberately does not lead with "most likely a rotation, just retry": a
// wrong-signer result is a REFUSAL to trust the archive under the pinned signer, and an
// operator reading this mid-incident must not treat it as a transient failure worth retrying
// with any key that happens to verify. The rotation path stays offered, but gated on the
// operator confirming it independently (their recovery sheet or rotation record), not on this
// message alone.
func signerMismatchHint(rootBytes []byte, signer *crypto.HybridVerifier) string {
	var m struct {
		SigningKeyFingerprint string `json:"signingKeyFingerprint"`
	}
	if err := json.Unmarshal(rootBytes, &m); err != nil || m.SigningKeyFingerprint == "" {
		return ""
	}
	current := crypto.SignerFingerprint(signer)
	if m.SigningKeyFingerprint == current {
		return ""
	}
	return fmt.Sprintf(" (the archive is signed by %s, not the pinned --signer %s. This is a "+
		"refusal to trust the archive, not a transient error: do not retry with a signer key you "+
		"cannot independently verify. If your recovery sheet or rotation record confirms %s as a "+
		"prior signer, re-run with that signer's public key via --signer; otherwise stop and treat "+
		"this archive as untrusted)", m.SigningKeyFingerprint, current, m.SigningKeyFingerprint)
}

// verifyRootSignatureGate applies the root-signature policy and records its result on
// outcome (SPEC.md 8.3). The signature is a verification gate, not a byte-recovery gate:
// under allow-unverified a missing or invalid signature is recorded and recovery proceeds;
// otherwise it returns a fatal ExitUnverified error. The order and the fail-closed default
// here are the verified-mode security contract, so they live in one named gate.
func verifyRootSignatureGate(store ObjectStore, runID string, rootBytes []byte, signer *crypto.HybridVerifier, opts Options, outcome *Outcome) error {
	switch sigText, sigErr := store.Get(runKey(runID, "root.manifest.json.sig")); {
	case sigErr != nil:
		outcome.SignatureResult = "absent"
		outcome.Completeness = "UNVERIFIED"
		outcome.Code = ExitUnverified
		if !opts.AllowUnverified {
			return codedGet(ExitUnverified, fmt.Errorf("read root signature: %w", sigErr))
		}
	default:
		sig, derr := B64Decode(strings.TrimSpace(string(sigText)))
		switch {
		case derr != nil:
			// A malformed (undecodable) signature is "invalid".
			outcome.SignatureResult = "invalid"
		case len(sig) <= ed25519.SignatureSize:
			// A signature too short to contain both halves (Ed25519 + any ML-DSA-87 bytes)
			// is structurally invalid: one half is absent, not wrong. SPEC.md 8.1 requires
			// both halves and permits no downgrade.
			outcome.SignatureResult = "invalid"
		case VerifyRootBytes(rootBytes, sig, signer) != nil:
			// A well-formed signature that does not verify under the operator-pinned
			// signer is a wrong-signer result (SPEC.md 8.3 vs a forged/garbled one).
			outcome.SignatureResult = "wrong-signer"
		}
		if outcome.SignatureResult != "valid" {
			outcome.Completeness = "UNVERIFIED"
			outcome.Code = ExitUnverified
			if !opts.AllowUnverified {
				// A wrong-signer result is most often a signer rotation, not tampering: enrich the
				// message with the archive-vs-pinned fingerprints + the actionable --signer guidance
				// (the hint self-gates to a true fingerprint mismatch).
				hint := ""
				if outcome.SignatureResult == "wrong-signer" {
					hint = signerMismatchHint(rootBytes, signer)
				}
				return coded(ExitUnverified, fmt.Errorf("verify root signature: %s%s", outcome.SignatureResult, hint))
			}
		}
	}
	return nil
}

// verifyRecoveryBundleGate binds the run to the bundled spec/reader when the recoverer
// relies on them (SPEC.md 8.7 item 4). A tampered FORMAT.md/RECOVER.md fails verified
// restore with a fatal ExitUnverified error; allow-unverified downgrades it to a recorded
// outcome. The gate runs only when CheckRecoveryBundle was set; otherwise the recoverer
// brought their own trusted spec and the result stays the recorded skip.
func verifyRecoveryBundleGate(store ObjectStore, signer *crypto.HybridVerifier, opts Options, outcome *Outcome) error {
	if !opts.CheckRecoveryBundle {
		return nil
	}
	if err := VerifyBundle(store.Get, signer); err != nil {
		outcome.RecoveryBundleVerified = false
		outcome.Completeness = "UNVERIFIED"
		if outcome.Code == 0 {
			outcome.Code = ExitUnverified
		}
		if !opts.AllowUnverified {
			return codedGet(ExitUnverified, fmt.Errorf("recovery bundle: %w", err))
		}
		return nil
	}
	outcome.RecoveryBundleVerified = true
	return nil
}

// Records returns the verified record metadata.
func (r *Reader) Records() []spec.ShardRecord { return r.records }

// RecordCount returns the number of verified records. The streaming reader (StreamReader)
// exposes the same count without materialising the record slice, so the receipt path and
// the verify summary read the count through this accessor rather than len(Records()).
func (r *Reader) RecordCount() int64 { return int64(len(r.records)) }

// Freshness returns the RUNLOG freshness outcome for the run.
func (r *Reader) Freshness() FreshnessResult { return r.freshness }

// Outcome returns the verification outcome for the restore receipt.
func (r *Reader) Outcome() Outcome { return r.outcome }

// Root returns the verified root manifest (for the receipt's run metadata).
func (r *Reader) Root() *spec.RootManifest { return r.root }

// Preambles returns the decrypted shard preambles (the downpipe name, schedule, source
// selectors and window that inspect surfaces only with an identity).
func (r *Reader) Preambles() []spec.ShardPreamble { return r.preambles }

func runKey(runID, name string) string { return "run/" + runID + "/" + name }
