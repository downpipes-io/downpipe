package format

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// checkFreshness fetches and verifies the signed RUNLOG and checks the run's recency
// (SPEC.md 8.7, 10). An absent or unreadable RUNLOG is itself a freshness failure, and it
// returns uncheckedFreshness() rather than a zero value so that a caller proceeding under
// --allow-stale carries "the check did not run" instead of "the check passed". Deleting
// the RUNLOG used to be the quietest way to get a clean-looking verify out of this tool.
func checkFreshness(store ObjectStore, runID string, root *spec.RootManifest, signer *crypto.HybridVerifier, opts Options) (FreshnessResult, error) {
	runlogBytes, err := store.Get("_RECOVERY/RUNLOG")
	if err != nil {
		cause := fmt.Errorf("read runlog: %w", err)
		// codedGet, not staleUnchecked: a RUNLOG whose bytes were never retrieved is a
		// transport or access failure (ExitUnreachable) rather than a verdict about the
		// archive, and that classification must survive. ErrFreshnessUnchecked is wrapped in
		// alongside it, so the error still self-reports as a check that could not be run.
		return uncheckedFreshness(cause), codedGet(ExitStale, fmt.Errorf("%w: %w", ErrFreshnessUnchecked, cause))
	}
	sigText, err := store.Get("_RECOVERY/RUNLOG.sig")
	if err != nil {
		cause := fmt.Errorf("read runlog signature: %w", err)
		return uncheckedFreshness(cause), codedGet(ExitStale, fmt.Errorf("%w: %w", ErrFreshnessUnchecked, cause))
	}
	return CheckFreshness(runlogBytes, sigText, runID, root, signer, opts.MinRunlogIndex)
}

// identityIsBreakGlass reports whether the recovering identity's public fingerprint is
// the run's signed break-glass recipient.
func identityIsBreakGlass(root *spec.RootManifest, recipient *crypto.HybridKEMPrivate) bool {
	idFP := crypto.RecipientFingerprint(&crypto.HybridKEMPublic{
		X25519: recipient.X25519.PublicKey(),
		MLKEM:  recipient.MLKEM.EncapsulationKey(),
	})
	for _, rc := range root.Recipients {
		if rc.Role == "break-glass" && rc.Fingerprint == idFP {
			return true
		}
	}
	return false
}

func unwrapMaster(root *spec.RootManifest, recipient *crypto.HybridKEMPrivate) ([]byte, error) {
	// The capsule DEM is sealed with the run key commitment as AAD (SPEC.md 5.4), so a
	// swapped or forked capsule fails authentication. The reader supplies the signed
	// commitment as the AAD; checkKeyCommitment then binds it to the recovered master.
	capsuleAAD, err := hex.DecodeString(root.KeyCommitment)
	if err != nil {
		return nil, fmt.Errorf("decode key commitment: %w", err)
	}
	wraps := make([]crypto.WrappedKey, 0, len(root.MasterCapsule))
	for _, w := range root.MasterCapsule {
		ct, err := B64Decode(w.KEMCiphertext)
		if err != nil {
			return nil, fmt.Errorf("decode capsule ciphertext: %w", err)
		}
		sealed, err := B64Decode(w.Sealed)
		if err != nil {
			return nil, fmt.Errorf("decode capsule wrap: %w", err)
		}
		wraps = append(wraps, crypto.WrappedKey{Fingerprint: w.Fingerprint, KEMCiphertext: ct, Sealed: sealed})
	}
	// Thread the run's signed recipient list (role + fingerprint) so that a held
	// identity that matches no wrap is told which fingerprints the run actually needs —
	// "this run needs one of: break-glass dpr1:<X>, operational dpr1:<Y>" — not just the
	// one it holds. These come from the root, whose signature is verified before
	// this point on the verified path.
	wanted := wantedRecipients(root)
	master, err := crypto.OpenCapsule(wraps, recipient, capsuleAAD, wanted)
	if err != nil {
		return nil, fmt.Errorf("unwrap master capsule: %w", err)
	}
	return master[:], nil
}

// wantedRecipients maps the run's signed recipient list to the role+fingerprint
// descriptors OpenCapsule uses to name the identities that can open the run when the
// held identity matches none of them.
func wantedRecipients(root *spec.RootManifest) []crypto.RecipientDesc {
	wanted := make([]crypto.RecipientDesc, 0, len(root.Recipients))
	for _, rc := range root.Recipients {
		wanted = append(wanted, crypto.RecipientDesc{Role: rc.Role, Fingerprint: rc.Fingerprint})
	}
	return wanted
}

func checkKeyCommitment(root *spec.RootManifest, master, runIDBytes []byte) error {
	want, err := hex.DecodeString(root.KeyCommitment)
	if err != nil {
		return fmt.Errorf("key commitment: %w", err)
	}
	if !crypto.ConstantTimeEqual(crypto.KeyCommitment(master, runIDBytes), want) {
		return fmt.Errorf("key commitment does not match the run master")
	}
	return nil
}

func checkRecipientSet(root *spec.RootManifest) error {
	if !root.BreakGlassPresent {
		return fmt.Errorf("manifest does not declare a break-glass recipient present")
	}
	pubs, recipientFP, err := validateRecipients(root)
	if err != nil {
		return err
	}
	return verifyWrapCoverage(root, pubs, recipientFP)
}

// validateRecipients decodes each listed recipient public key, confirms its listed
// fingerprint belongs to that key, and confirms exactly one break-glass recipient is
// present. It returns the decoded public keys and the per-fingerprint count map.
func validateRecipients(root *spec.RootManifest) ([]*crypto.HybridKEMPublic, map[string]int, error) {
	pubs := make([]*crypto.HybridKEMPublic, 0, len(root.Recipients))
	recipientFP := make(map[string]int, len(root.Recipients))
	breakGlass := 0
	for _, rc := range root.Recipients {
		x, err := B64Decode(rc.X25519)
		if err != nil {
			return nil, nil, fmt.Errorf("recipient x25519: %w", err)
		}
		m, err := B64Decode(rc.MLKEM)
		if err != nil {
			return nil, nil, fmt.Errorf("recipient mlkem: %w", err)
		}
		pub, err := crypto.NewHybridPublic(x, m)
		if err != nil {
			return nil, nil, err
		}
		// The listed fingerprint must actually belong to the listed public key.
		if crypto.RecipientFingerprint(pub) != rc.Fingerprint {
			return nil, nil, fmt.Errorf("recipient fingerprint does not match its public key")
		}
		pubs = append(pubs, pub)
		recipientFP[rc.Fingerprint]++
		if rc.Role == "break-glass" {
			breakGlass++
		}
	}
	if breakGlass != 1 {
		return nil, nil, fmt.Errorf("expected exactly one break-glass recipient, found %d", breakGlass)
	}
	return pubs, recipientFP, nil
}

// verifyWrapCoverage checks that every master-capsule wrap addresses a signed
// recipient, that the wraps cover the recipient set, and that the signed
// recipient-set hash matches the listed recipients.
func verifyWrapCoverage(root *spec.RootManifest, pubs []*crypto.HybridKEMPublic, recipientFP map[string]int) error {
	// Every master-capsule wrap must address one of the signed recipients, and the
	// wraps must cover the recipient set, so a wrap cannot be added, dropped or
	// retargeted relative to the signed recipients.
	wrapFP := make(map[string]int, len(root.MasterCapsule))
	for _, w := range root.MasterCapsule {
		if _, ok := recipientFP[w.Fingerprint]; !ok {
			return fmt.Errorf("master-capsule wrap addresses an unlisted recipient")
		}
		wrapFP[w.Fingerprint]++
	}
	if len(wrapFP) != len(recipientFP) {
		return fmt.Errorf("master-capsule wraps do not cover the recipient set")
	}

	want, err := hex.DecodeString(root.RecipientSetHash)
	if err != nil {
		return fmt.Errorf("recipient-set hash: %w", err)
	}
	if !crypto.ConstantTimeEqual(crypto.RecipientSetHash(pubs), want) {
		return fmt.Errorf("recipient-set hash does not match the listed recipients")
	}
	return nil
}

// openOneShard fetches, hash-checks against the signed root, and opens one shard manifest,
// returning its preamble and records. It is the single per-shard integrity gate shared by
// the load-all openShards and the streaming shard walk (StreamReader), so the signed
// SHA-384 check and the preamble-binds-the-run check are byte-identical on both paths. mk is
// the run manifest key (crypto.DeriveMK over the master and run id). A missing shard is
// ExitIncomplete (coverage falls below declaredRecordCount, SPEC.md 8.5, 14.3 deleted-shard);
// a hash or preamble mismatch is a bare error the caller codes as ExitUnverified.
func openOneShard(ctx context.Context, store ObjectStore, root *spec.RootManifest, mk, runIDBytes []byte, sh spec.ShardRef) (spec.ShardPreamble, []spec.ShardRecord, error) {
	preamble, recs, _, err := openOneShardSized(ctx, store, root, mk, runIDBytes, sh)
	return preamble, recs, err
}

// openOneShardSized is openOneShard plus the fetched shard's byte size, which the
// concurrent prefetcher (StreamReader.walkShards with FetchConcurrency>1) uses as the
// memory-budget weight for a buffered shard. The size is the FETCHED (sealed) byte
// length, the only size available at fetch time -- a ShardRef carries no pre-fetch size,
// so the weight cannot be known before the GET. The sealed length is a close, slightly
// conservative proxy for the decrypted manifest / parsed-record footprint the shard then
// holds in the prefetch buffer (the sealed bytes add AEAD framing over the plaintext, so
// the budget throttles a touch early, never late -- the safe direction for a cap). Every
// gate is byte-identical to openOneShard, which delegates here, so the sequential and the
// concurrent paths apply the identical signed-SHA-384 and preamble-binding checks.
func openOneShardSized(ctx context.Context, store ObjectStore, root *spec.RootManifest, mk, runIDBytes []byte, sh spec.ShardRef) (spec.ShardPreamble, []spec.ShardRecord, int, error) {
	shardBytes, err := storeGet(ctx, store, sh.Object)
	if err != nil {
		return spec.ShardPreamble{}, nil, 0, codedGet(ExitIncomplete, fmt.Errorf("read shard %s: %w", sh.ID, err))
	}
	if !crypto.ConstantTimeEqual([]byte(SHA384Hex(shardBytes)), []byte(sh.SHA384)) {
		return spec.ShardPreamble{}, nil, 0, fmt.Errorf("shard %s hash does not match the signed root", sh.ID)
	}
	preamble, recs, err := OpenShard(shardBytes, crypto.DeriveManifestWrapKey(mk, runIDBytes, sh.ID))
	if err != nil {
		return spec.ShardPreamble{}, nil, 0, err
	}
	if preamble.RunID != root.RunID || preamble.ShardID != sh.ID || preamble.FormatVersion != root.FormatVersion {
		return spec.ShardPreamble{}, nil, 0, fmt.Errorf("shard %s preamble does not match the signed run", sh.ID)
	}
	// manifestCodec is per shard and independent of the record codec (SPEC.md 7.5): the
	// closed set is enforced here, and gzip, though inside the set, is refused honestly
	// because this reader implements no shard-manifest gunzip (OpenShard decodes the
	// plaintext directly); a gzip manifest would otherwise die obscurely at JSON parse.
	if preamble.ManifestCodec != spec.CodecNameNone {
		if preamble.ManifestCodec == spec.CodecNameGzip {
			return spec.ShardPreamble{}, nil, 0, coded(ExitUsage, fmt.Errorf("shard %s manifestCodec gzip is not implemented by this reader", sh.ID))
		}
		return spec.ShardPreamble{}, nil, 0, coded(ExitUsage, fmt.Errorf("shard %s manifestCodec %q is outside the closed downpipe/0.1.0 set {none, gzip}", sh.ID, preamble.ManifestCodec))
	}
	return preamble, recs, len(shardBytes), nil
}

// knownCodecName reports whether name is inside the closed downpipe/0.1.0 codec set
// {none, gzip} (SPEC.md 5.2, 7.5). Every codec-bearing field is gated on membership up
// front, because the decrypt path otherwise treats an unknown name as codec none.
func knownCodecName(name string) bool {
	return name == spec.CodecNameNone || name == spec.CodecNameGzip
}

// checkEnvelopeCodec refuses a root whose run-wide envelope codec is outside the closed
// set. Without this gate a uniformly relabelled archive (envelope and every record
// agreeing on an unknown codec) passes the per-record equality rule and is then silently
// decrypted as codec none: a fail-open, not even a late failure. A structural format
// violation, exit 6 (SPEC.md 5.2). Shared by Open, StreamOpen and Attest.
func checkEnvelopeCodec(root *spec.RootManifest) error {
	if !knownCodecName(root.Envelope.Codec) {
		return coded(ExitUsage, fmt.Errorf("envelope codec %q is outside the closed downpipe/0.1.0 set {none, gzip} (section 5.2)", root.Envelope.Codec))
	}
	return nil
}

// checkRecordStructural enforces the run-wide per-record structural rules (SPEC.md 12.1,
// 5.2, 7.5, 12.4): the sourceType must be in the supported set (a reserved
// durable_object/vectorize, or anything a later format version adds, is REFUSED
// rather than restored as opaque bytes under a guessed behaviour, because each source
// restores differently), the record codec must match the run-wide envelope codec, and a
// secrets record must never be compressed. All three are structural format violations
// (ExitUsage), not verification failures. Shared by the load-all openShards and the
// streaming verify so the two paths apply the identical gate per record.
func checkRecordStructural(root *spec.RootManifest, rec spec.ShardRecord) error {
	if !spec.IsKnownSourceType(rec.SourceType) {
		return coded(ExitUsage, fmt.Errorf("record %s has sourceType %q, which is outside the supported downpipe/0.1.0 set (section 12.1); a reader refuses an unknown source type", rec.RecordID, rec.SourceType))
	}
	if rec.Codec != root.Envelope.Codec {
		return coded(ExitUsage, fmt.Errorf("record %s codec %q differs from the envelope codec %q", rec.RecordID, rec.Codec, root.Envelope.Codec))
	}
	if !knownCodecName(rec.Codec) {
		// Defence in depth: the envelope gate normally fires first, but a record must
		// never reach key derivation carrying a codec outside the closed set.
		return coded(ExitUsage, fmt.Errorf("record %s codec %q is outside the closed downpipe/0.1.0 set {none, gzip} (section 7.5)", rec.RecordID, rec.Codec))
	}
	if rec.SourceType == spec.SourceSecrets && rec.Codec != spec.CodecNameNone {
		return coded(ExitUsage, fmt.Errorf("secrets record %s must not be compressed (section 5.2, 12.4)", rec.RecordID))
	}
	return nil
}

func openShards(store ObjectStore, root *spec.RootManifest, master, runIDBytes []byte) ([]spec.ShardPreamble, []spec.ShardRecord, error) {
	mk := crypto.DeriveMK(master, runIDBytes)
	var preambles []spec.ShardPreamble
	var records []spec.ShardRecord
	for _, sh := range root.Shards {
		preamble, recs, err := openOneShard(context.Background(), store, root, mk, runIDBytes, sh)
		if err != nil {
			return nil, nil, err
		}
		preambles = append(preambles, preamble)
		records = append(records, recs...)
	}
	for _, rec := range records {
		if err := checkRecordStructural(root, rec); err != nil {
			return nil, nil, err
		}
	}
	return preambles, records, nil
}

func checkCompleteness(root *spec.RootManifest, records []spec.ShardRecord) error {
	if root.ShardCount != len(root.Shards) {
		return coded(ExitUnverified, fmt.Errorf("shardCount %d does not match the %d listed shards", root.ShardCount, len(root.Shards)))
	}
	if int64(len(records)) != root.DeclaredRecordCount {
		return coded(ExitIncomplete, fmt.Errorf("recovered %d records, the root declares %d", len(records), root.DeclaredRecordCount))
	}
	leaves := make([][]byte, len(records))
	for i, rec := range records {
		rh, err := RecordHashOf(rec)
		if err != nil {
			return coded(ExitUnverified, err)
		}
		stated, err := hex.DecodeString(rec.RecordHash)
		if err != nil {
			return coded(ExitUnverified, fmt.Errorf("record %s recordHash: %w", rec.RecordID, err))
		}
		if !crypto.ConstantTimeEqual(rh, stated) {
			return coded(ExitUnverified, fmt.Errorf("record %s hash does not match its fields", rec.RecordID))
		}
		leaves[i] = rh
	}
	want, err := hex.DecodeString(root.MerkleRoot)
	if err != nil {
		return coded(ExitUnverified, fmt.Errorf("merkle root: %w", err))
	}
	if !crypto.ConstantTimeEqual(MerkleRoot(leaves), want) {
		return coded(ExitUnverified, fmt.Errorf("merkle root does not match the recovered records"))
	}
	return nil
}

// ImplementedFormatVersions is the set of format versions this reader implements, as
// "MAJOR.MINOR" compatibility units (SPEC.md 13.1). It is a SET and not a bound: the
// reader reads exactly the units listed here and refuses every other version by name. It
// never reads a version because the major matches, and never because the version sorts
// below its own.
//
// A lower minor is a different, incompatible byte format, not an older dialect of this
// one. Its keys derive under that minor's own HKDF and MAC labels (SPEC.md 11.7), so
// accepting one on ordering alone would decrypt nothing and would surface as an
// authentication failure over the archive's bytes, which reads to the person holding it
// as data loss when nothing has been lost. Reading an older minor is retained code, a
// retained key schedule and a retained conformance corpus, added here deliberately in the
// same change set.
//
// The set is additive FROM THE FIRST PUBLISHED RELEASE: once a release that implements a
// unit is obtainable, no later release may drop it, because the bytes naming it are then in
// somebody's bucket and stored bytes have no deprecation path. Before that point the rule
// has nothing to protect, and treating it as though it did is how a product with no users
// accumulates code for clients that do not exist. the pre-release "1.x"
// lineage was retired under exactly that reading: no release of it was ever published, no
// archive of it was ever held by anyone outside this organisation, and it left the set
// rather than being carried. This is the only unit this format has, and the additive rule
// binds from the first published release of a reader implementing it.
var ImplementedFormatVersions = []string{"0.1"}

// readerSupportSummary renders ImplementedFormatVersions for a refusal message, for
// example "downpipe/0.1.x". It is built from the set rather than written as a literal so
// the message cannot drift from what the reader actually implements.
func readerSupportSummary() string {
	labels := make([]string, len(ImplementedFormatVersions))
	for i, unit := range ImplementedFormatVersions {
		labels[i] = "downpipe/" + unit + ".x"
	}
	return strings.Join(labels, ", ")
}

// ImplementsFormatVersion reports whether this reader implements the archive format
// version v, using the identical gate Open, StreamOpen and Attest apply. It exists so a
// diagnostic command that deliberately never refuses (inspect) can still SAY that the
// reader cannot read what it is showing, instead of printing a version line that looks
// the same whether the archive is readable or not.
func ImplementsFormatVersion(v string) bool { return checkFormatVersion(v) == nil }

// ReaderFormatSupport returns what this reader implements, for example "downpipe/0.1.x".
func ReaderFormatSupport() string { return readerSupportSummary() }

// allCanonicalVersionNumbers reports whether every component is a canonical decimal.
func allCanonicalVersionNumbers(parts []string) bool {
	for _, p := range parts {
		if !isCanonicalVersionNumber(p) {
			return false
		}
	}
	return true
}

// isCanonicalVersionNumber reports whether s is a canonical decimal semver component:
// one or more ASCII digits, no leading zero before another digit (SPEC.md 13).
func isCanonicalVersionNumber(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) == 1 || s[0] != '0'
}

// checkFormatVersion rejects any formatVersion this reader does not implement (SPEC.md
// 13, 13.1, 14.3 unknown-major and unimplemented-minor). The expected form is
// "downpipe/MAJOR.MINOR.PATCH" with each component a canonical decimal integer.
//
// It separates three refusals that mean different things to whoever is holding the archive.
//
//  1. Not a downpipe label at all ("age/1.0.0"): these are not downpipe bytes.
//  2. A MALFORMED label ("downpipe/0.1", "downpipe/0.1.x", a trailing space, a fourth
//     component): the version field is not a version, so no reader anywhere implements it
//     and the archive has been damaged or hand-edited. This message must never send anyone
//     hunting for another build, because there is no build to find.
//  3. A WELL-FORMED version outside the implemented set ("downpipe/0.2.0"): go and get a
//     reader that implements it. The message says where that mapping is published, because
//     the reader's own release number is an independent number space that says nothing
//     about the format (SPEC.md 13.1).
//
// ALL THREE COMPONENTS ARE PART OF THE VERSION, which is why a two-component label is
// case 2 and not case 3, and the arity requirement is load-bearing rather than tidy.
// "downpipe/0.1" carries the same two numbers this reader implements, so a set match on the
// numbers alone would accept it, and it is not this format: the labels of section 11.7 would
// read "downpipe/0.1 <purpose>" and derive every key to different bytes. It would decrypt
// nothing and report an authentication failure over intact bytes, which is the exact failure
// this whole gate exists to prevent.
//
// WHY THERE IS NO BRANCH HERE FOR A MAJOR.MINOR LABEL. That was the identity scheme of a
// pre-release lineage of this format, retired. No release implementing it was
// ever published, no reader for it is obtainable, and the update channel no longer offers a
// writer that stamps one, so nothing a person can get their hands on emits a two-component
// label. A branch that softened case 2 for it would close by naming a different build to go
// and fetch, and that build does not exist and will not be published: a remedy nobody can
// act on is worse mid-recovery than a blunt one, and "damaged or hand-edited, check the
// archive's other copies" is now the true reading of those bytes.
//
// THE ORDERING THIS DEPENDS ON, stated so it cannot be lost. This function is only correct
// while no obtainable writer stamps a two-component label. If one is ever published again,
// this branch is telling the holder of intact bytes that their manifest is damaged, which is
// the most expensive wrong thing it could say.
//
// All three exit ExitUsage (6) rather than an integrity code, so a version refusal is never
// mistaken for a corrupted archive: the bytes are untouched and nothing has been lost.
func checkFormatVersion(v string) error {
	const prefix = "downpipe/"
	if !strings.HasPrefix(v, prefix) {
		return coded(ExitUsage, fmt.Errorf("formatVersion %q is not a downpipe version label", v))
	}
	rest := strings.TrimPrefix(v, prefix)
	// Bounded at three so a fourth component lands INSIDE the third part and is caught as
	// non-canonical rather than discarded. An unbounded split would let "downpipe/0.1.0.0"
	// past the arity check and then past the unit comparison.
	parts := strings.SplitN(rest, ".", 3)
	// The message names both ways this refusal fires, arity and canonicality, because it
	// fires for both: saying only "every component must be a decimal number" would be a
	// false description of "downpipe/0.1", whose components are all decimal numbers.
	if len(parts) != 3 || !allCanonicalVersionNumbers(parts) {
		return coded(ExitUsage, fmt.Errorf("formatVersion %q is not a downpipe version label at all: after %q it must read MAJOR.MINOR.PATCH, with all three components present and each one a canonical decimal number, and this one does not. No downpipe reader implements it, because it does not name a version. Treat this root manifest as damaged or hand-edited, and check the archive's other copies before anything else", v, prefix))
	}
	unit := parts[0] + "." + parts[1]
	for _, implemented := range ImplementedFormatVersions {
		if unit == implemented {
			return nil
		}
	}
	return coded(ExitUsage, fmt.Errorf("formatVersion %q: this reader implements %s and does not implement %s, so it will not read this archive. Nothing is wrong with the bytes and nothing has been lost, and nothing was written. Get a downpipe reader that implements %s: each release's CHANGELOG.md entry names the format versions that release reads (https://github.com/downpipes-io/downpipe). Do NOT re-run with --allow-unverified or any other override; no override reads a format this build does not implement", v, readerSupportSummary(), unit, unit))
}
