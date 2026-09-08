package format

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// attestRunID is a syntactically valid ULID the attest fixtures share.
const attestRunID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

// buildStaleArchive seals attestRunID as a single record, then writes a signed root for it
// and a two-entry RUNLOG in which attestRunID is superseded by a newer run (vecRunIDB) of
// the same downpipe. It returns the pinned operator verifier so a signer-pinned Attest runs
// the full freshness check and rejects the older run with ExitStale. The fixed master 0x7e
// matches the one sealOneRecordShard seals under, so the capsule and key commitment line up.
func buildStaleArchive(t *testing.T, store memStore, dpID string) *crypto.HybridVerifier {
	t.Helper()
	bs := buildSpec{store: store, runID: attestRunID, dpID: dpID, value: []byte("recover me"), secret: false, codec: spec.CodecNameNone}
	rec, shardSHA := sealOneRecordShard(t, bs)

	_, bgPub := newKEM(t)
	_, opPub := newKEM(t)
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	master := bytes.Repeat([]byte{0x7e}, 32)
	runIDBytes, err := spec.DecodeULID(attestRunID)
	if err != nil {
		t.Fatal(err)
	}
	kc := crypto.KeyCommitment(master, runIDBytes)
	wraps, err := crypto.SealToRecipients([32]byte(master), []*crypto.HybridKEMPublic{bgPub, opPub}, kc, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capsule := make([]spec.CapsuleWrap, len(wraps))
	for i, w := range wraps {
		capsule[i] = spec.CapsuleWrap{Fingerprint: w.Fingerprint, KEMCiphertext: B64Encode(w.KEMCiphertext), Sealed: B64Encode(w.Sealed)}
	}
	recipients := []spec.Recipient{
		{Fingerprint: crypto.RecipientFingerprint(bgPub), Role: "break-glass", X25519: B64Encode(bgPub.X25519.Bytes()), MLKEM: B64Encode(bgPub.MLKEM.Bytes())},
		{Fingerprint: crypto.RecipientFingerprint(opPub), Role: "operational", X25519: B64Encode(opPub.X25519.Bytes()), MLKEM: B64Encode(opPub.MLKEM.Bytes())},
	}
	rhRaw, _ := hex.DecodeString(rec.RecordHash)
	root := &spec.RootManifest{
		FormatVersion: spec.Version, RunID: attestRunID,
		CreatedAt:  "2026-06-06T12:00:30.000Z",
		DownpipeID: dpID,
		Envelope:   spec.Envelope{AEAD: "AES-256-GCM", KEM: "X25519+ML-KEM-1024", Signature: "Ed25519+ML-DSA-87", KDF: "HKDF-SHA-384", ChunkSize: spec.ChunkSize, Codec: spec.CodecNameNone},
		Recipients: recipients, MasterCapsule: capsule,
		RecipientSetHash:      hex.EncodeToString(crypto.RecipientSetHash([]*crypto.HybridKEMPublic{bgPub, opPub})),
		KeyCommitment:         hex.EncodeToString(kc),
		BreakGlassPresent:     true,
		Shards:                []spec.ShardRef{{ID: "00000", Object: runKey(attestRunID, "manifest/00000.dpe"), SHA384: shardSHA}},
		ShardCount:            1,
		DeclaredRecordCount:   1,
		MerkleRoot:            hex.EncodeToString(MerkleRoot([][]byte{rhRaw})),
		Freshness:             spec.Freshness{PrevRunID: nil, RunlogIndex: 1},
		SigningKeyFingerprint: "edmldsa1:test",
	}
	canonical, sig, err := SignRoot(root, signer)
	if err != nil {
		t.Fatal(err)
	}
	store[runKey(attestRunID, "root.manifest.json")] = canonical
	store[runKey(attestRunID, "root.manifest.json.sig")] = []byte(B64Encode(sig))

	// A two-entry RUNLOG: attestRunID is superseded by a newer run of the same downpipe,
	// so the tested run is no longer the latest and the freshness check must reject it.
	first := attestRunID
	runlogBytes, err := MarshalRunlog([]spec.RunlogEntry{
		{Index: 1, RunID: attestRunID, DownpipeID: dpID, Time: "2026-06-06T12:00:30.000Z", RecordCount: 1, PrevRunID: nil, Status: "superseded"},
		{Index: 2, RunID: vecRunIDB, DownpipeID: dpID, Time: "2026-06-06T12:01:30.000Z", RecordCount: 1, PrevRunID: &first, Status: "active"},
	})
	if err != nil {
		t.Fatal(err)
	}
	runlogSig, err := signer.Sign(runlogBytes)
	if err != nil {
		t.Fatal(err)
	}
	store["_RECOVERY/RUNLOG"] = runlogBytes
	store["_RECOVERY/RUNLOG.sig"] = []byte(B64Encode(runlogSig))
	return verifier
}

// TestAttestFailsOnStaleRunWhenSignerPinned proves the integration freshness gate: a run
// that is no longer the latest for its downpipe (superseded in a two-entry RUNLOG) fails a
// signer-pinned attestation with ExitStale, and the result reports the run as not the
// latest. This exercises the full Attest path through CheckFreshness, not CheckFreshness in
// isolation.
func TestAttestFailsOnStaleRunWhenSignerPinned(t *testing.T) {
	store := memStore{}
	verifier := buildStaleArchive(t, store, "dp_attest")

	res, err := Attest(store, attestRunID, verifier, 0)
	if err == nil {
		t.Fatal("a superseded (non-latest) run must fail a signer-pinned attestation")
	}
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != ExitStale {
		t.Fatalf("a stale run must fail ExitStale (%d), got %v", ExitStale, err)
	}
	if res == nil || res.RunlogVerified {
		t.Fatal("a stale run must not report RunlogVerified true")
	}
	if res.Freshness.IsLatestForDownpipe {
		t.Fatal("a superseded run must not report IsLatestForDownpipe true")
	}
}

// TestAKeylessAttestPassesOnASupersededRun proves the same superseded run is still keyless
// attestable: with no signer pinned the freshness leg is the structural presence check, which
// confirms the run is in the RUNLOG and passes, so an operator can attest an older run's
// structure on purpose. That is a written decision, not an observation: SPEC.md 8 says a
// keyless attestation with no --min-runlog-index confirms only that the run is PRESENT in the
// RUNLOG and does NOT check freshness, because nothing in keyless mode anchors the RUNLOG's
// bytes. The pass is paid for by the labels asserted below -- SignerPinned false and
// RunlogVerified false -- so a caller cannot read this result as a freshness verdict.
//
// The name used to say WithAllowStale. Attest takes no such option and never has: its
// arguments are the store, the run, an optional signer and a pin. A test name that puts the
// age word on a path that does not have it is how the reader of the next change concludes the
// word reaches further than it does, which is the whole shape --allow-stale was just split
// out of.
func TestAKeylessAttestPassesOnASupersededRun(t *testing.T) {
	store := memStore{}
	_ = buildStaleArchive(t, store, "dp_attest")

	res, err := Attest(store, attestRunID, nil, 0)
	if err != nil {
		t.Fatalf("keyless attest must confirm a superseded run is present in the RUNLOG: %v", err)
	}
	if !res.OK() {
		t.Fatalf("keyless attest over a structurally intact older run must pass, got code %d", res.Code)
	}
	if res.RunlogVerified {
		t.Fatal("a keyless attest must not claim the RUNLOG signature was verified")
	}
}

// TestAttestKeylessPassesOnGoodArchive proves the headline property: a keyless
// attestation (no signer, no break-glass identity) passes on a well-formed archive. It
// verifies the shard hashes against the signed root and confirms the run is in the
// RUNLOG, and it reports the signature as "unchecked" because no signer was pinned, all
// without unwrapping the master capsule or decrypting a record.
func TestAttestKeylessPassesOnGoodArchive(t *testing.T) {
	store := memStore{}
	// The returned identity and verifier are deliberately ignored: attest needs neither.
	_, _ = buildArchive(t, buildSpec{store: store, runID: attestRunID, dpID: "dp_attest", value: []byte("recover me"), secret: false, codec: spec.CodecNameNone})

	res, err := Attest(store, attestRunID, nil, 0)
	if err != nil {
		t.Fatalf("keyless attest must pass on a good archive: %v", err)
	}
	if !res.OK() || res.Code != 0 {
		t.Fatalf("attest result must be OK with code 0, got code %d", res.Code)
	}
	if res.SignerPinned {
		t.Fatal("a nil signer must report SignerPinned false")
	}
	if res.SignatureResult != "unchecked" {
		t.Fatalf("a present, well-formed signature with no signer must be 'unchecked', got %q", res.SignatureResult)
	}
	if !res.SignaturePresent {
		t.Fatal("the root signature is present and must be reported so")
	}
	if !res.ShardsHashVerified {
		t.Fatal("every shard hash matches the signed root, so ShardsHashVerified must be true")
	}
	if res.ShardCount != 1 || res.DeclaredRecordCount != 1 {
		t.Fatalf("expected 1 shard and 1 declared record, got shards=%d records=%d", res.ShardCount, res.DeclaredRecordCount)
	}
	// Keyless: the RUNLOG was parsed and the run confirmed present, but it is not
	// cryptographically anchored, so RunlogVerified is honestly false.
	if res.RunlogVerified {
		t.Fatal("a keyless attest must not claim the RUNLOG signature was verified")
	}
}

// TestAttestWithSignerVerifiesSignatures proves that when a signer is pinned the
// attestation is the full cryptographic check: a valid signature, hash-verified shards,
// and a signed, fresh RUNLOG.
func TestAttestWithSignerVerifiesSignatures(t *testing.T) {
	store := memStore{}
	_, verifier := buildArchive(t, buildSpec{store: store, runID: attestRunID, dpID: "dp_attest", value: []byte("recover me"), secret: false, codec: spec.CodecNameNone})

	res, err := Attest(store, attestRunID, verifier, 0)
	if err != nil {
		t.Fatalf("signer-pinned attest must pass on a good archive: %v", err)
	}
	if !res.OK() {
		t.Fatalf("attest result must be OK, got code %d", res.Code)
	}
	if !res.SignerPinned || res.SignatureResult != "valid" {
		t.Fatalf("a pinned signer must produce a 'valid' signature verdict, got pinned=%v result=%q", res.SignerPinned, res.SignatureResult)
	}
	if !res.RunlogVerified {
		t.Fatal("a signed, fresh RUNLOG must verify under a pinned signer")
	}
	if !res.Freshness.IsLatestForDownpipe {
		t.Fatal("the only run for its downpipe must be the latest")
	}
}

// TestAttestFailsOnTamperedShard proves a tampered archive fails even keyless: flipping a
// byte in a shard breaks its SHA-384 against the signed root, which the keyless shard-hash
// check catches without any key.
func TestAttestFailsOnTamperedShard(t *testing.T) {
	store := memStore{}
	_, _ = buildArchive(t, buildSpec{store: store, runID: attestRunID, dpID: "dp_attest", value: []byte("recover me"), secret: false, codec: spec.CodecNameNone})

	shardKey := runKey(attestRunID, "manifest/00000.dpe")
	tampered := bytes.Clone(store[shardKey])
	tampered[0] ^= 0x01
	store[shardKey] = tampered

	res, err := Attest(store, attestRunID, nil, 0)
	if err == nil {
		t.Fatal("a tampered shard must fail the keyless attestation")
	}
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != ExitUnverified {
		t.Fatalf("a tampered shard must fail ExitUnverified (%d), got %v", ExitUnverified, err)
	}
	if res == nil || res.ShardsHashVerified {
		t.Fatal("the result must report ShardsHashVerified false for a tampered shard")
	}
}

// TestAttestFailsOnForgedSignatureWhenSignerPinned proves a forged or tampered signature
// fails when a signer is pinned: the verifier rejects it as wrong-signer.
func TestAttestFailsOnForgedSignatureWhenSignerPinned(t *testing.T) {
	store := memStore{}
	_, verifier := buildArchive(t, buildSpec{store: store, runID: attestRunID, dpID: "dp_attest", value: []byte("recover me"), secret: false, codec: spec.CodecNameNone})

	sigKey := runKey(attestRunID, "root.manifest.json.sig")
	tampered := bytes.Clone(store[sigKey])
	// Flip a byte well inside the decoded signature (a base64 char early in the string)
	// so it stays decodable and long enough but no longer verifies.
	tampered[10] ^= 0x01
	store[sigKey] = tampered

	res, err := Attest(store, attestRunID, verifier, 0)
	if err == nil {
		t.Fatal("a tampered signature must fail a signer-pinned attestation")
	}
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != ExitUnverified {
		t.Fatalf("a tampered signature must fail ExitUnverified (%d), got %v", ExitUnverified, err)
	}
	if res == nil || res.SignatureResult == "valid" {
		t.Fatalf("the result must not report a 'valid' signature for a tampered sig, got %q", res.SignatureResult)
	}
}

// TestAttestFailsOnAbsentSignatureEvenKeyless proves an absent signature fails even when
// no signer is pinned: a structurally missing signature is never a pass.
func TestAttestFailsOnAbsentSignatureEvenKeyless(t *testing.T) {
	store := memStore{}
	_, _ = buildArchive(t, buildSpec{store: store, runID: attestRunID, dpID: "dp_attest", value: []byte("recover me"), secret: false, codec: spec.CodecNameNone})
	delete(store, runKey(attestRunID, "root.manifest.json.sig"))

	res, err := Attest(store, attestRunID, nil, 0)
	if err == nil {
		t.Fatal("an absent root signature must fail the attestation even keyless")
	}
	if res == nil || res.SignatureResult != "absent" || res.SignaturePresent {
		t.Fatalf("the result must report an absent signature, got present=%v result=%q", res.SignaturePresent, res.SignatureResult)
	}
}

// TestAttestFailsOnMissingShard proves a deleted shard fails: the keyless shard-hash loop
// cannot read it and reports the gap, without any key.
func TestAttestFailsOnMissingShard(t *testing.T) {
	store := memStore{}
	_, _ = buildArchive(t, buildSpec{store: store, runID: attestRunID, dpID: "dp_attest", value: []byte("recover me"), secret: false, codec: spec.CodecNameNone})
	delete(store, runKey(attestRunID, "manifest/00000.dpe"))

	res, err := Attest(store, attestRunID, nil, 0)
	if err == nil {
		t.Fatal("a missing shard must fail the attestation")
	}
	if res == nil || res.ShardsHashVerified {
		t.Fatal("the result must report ShardsHashVerified false for a missing shard")
	}
}

// TestAttestFailsOnMissingRunlog proves an absent RUNLOG fails the freshness leg of the
// attestation with ExitStale, even keyless.
func TestAttestFailsOnMissingRunlog(t *testing.T) {
	store := memStore{}
	_, _ = buildArchive(t, buildSpec{store: store, runID: attestRunID, dpID: "dp_attest", value: []byte("recover me"), secret: false, codec: spec.CodecNameNone})
	delete(store, "_RECOVERY/RUNLOG")

	_, err := Attest(store, attestRunID, nil, 0)
	if err == nil {
		t.Fatal("a missing RUNLOG must fail the attestation")
	}
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != ExitStale {
		t.Fatalf("a missing RUNLOG must fail ExitStale (%d), got %v", ExitStale, err)
	}
}

// TestAttestKeylessCatchesStrippedBreakGlass proves that a keyless attestation runs the same
// recipient-set integrity gate keyed Open applies, so a dropped or role-flipped break-glass
// recipient — which strips the archive's offline recoverability — fails attest with
// ExitUnverified rather than passing. The fixture flips the only break-glass recipient's role
// to "operational" in the signed root and leaves the stale signature in place (a keyless
// attest never checks the signature), modelling a bucket-write adversary. It asserts parity
// with keyed Open under allow-unverified, where the signature is not the gate and Open's
// structural recipient-set check is the one that catches it.
func TestAttestKeylessCatchesStrippedBreakGlass(t *testing.T) {
	store := memStore{}
	bgPriv, verifier := buildArchive(t, buildSpec{store: store, runID: attestRunID, dpID: "dp_attest", value: []byte("recover me"), secret: false, codec: spec.CodecNameNone})

	// Strip break-glass: flip the only break-glass recipient's role to operational so the
	// run declares zero break-glass recipients. The signature is not re-computed; a keyless
	// attest does not check it.
	rootKey := runKey(attestRunID, "root.manifest.json")
	root, err := ParseRoot(store[rootKey])
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	flipped := false
	for i := range root.Recipients {
		if root.Recipients[i].Role == "break-glass" {
			root.Recipients[i].Role = "operational"
			flipped = true
		}
	}
	if !flipped {
		t.Fatal("fixture must contain a break-glass recipient to flip")
	}
	rebytes, err := MarshalRoot(root)
	if err != nil {
		t.Fatalf("marshal root: %v", err)
	}
	store[rootKey] = rebytes

	// Keyless attest must reject a stripped break-glass recipient.
	res, err := Attest(store, attestRunID, nil, 0)
	if err == nil {
		t.Fatal("keyless attest over a stripped-break-glass archive must fail")
	}
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != ExitUnverified {
		t.Fatalf("a stripped break-glass must fail ExitUnverified (%d), got %v", ExitUnverified, err)
	}
	if res == nil || res.RecipientSetVerified {
		t.Fatal("the result must report RecipientSetVerified false for a stripped break-glass")
	}

	// Parity: keyed Open's structural recipient-set gate already rejects the same archive
	// under allow-unverified (where the stale signature is not the gate), with the same code.
	if _, oerr := Open(store, attestRunID, bgPriv, verifier, Options{AllowUnverified: true}); oerr == nil {
		t.Fatal("keyed Open under allow-unverified must also reject a stripped break-glass")
	} else if !errors.As(oerr, &ee) || ee.Code != ExitUnverified {
		t.Fatalf("Open must reject a stripped break-glass with ExitUnverified (%d), got %v", ExitUnverified, oerr)
	}
}

// TestAttestNeedsNoIdentityForCorruptCapsule proves attest never touches the master
// capsule: an archive whose capsule is destroyed (which would break any identity-based
// open) still attests cleanly, because the signature, shard hashes and RUNLOG do not
// depend on the capsule. This is the structural proof that attest is keyless.
func TestAttestNeedsNoIdentityForCorruptCapsule(t *testing.T) {
	store := memStore{}
	_, _ = buildArchive(t, buildSpec{store: store, runID: attestRunID, dpID: "dp_attest", value: []byte("recover me"), secret: false, codec: spec.CodecNameNone})

	// Corrupt the segment object: a real identity-based RestoreRecord would fail to
	// decrypt it, but attest never reads it, so the attestation is unaffected.
	for k := range store {
		if len(k) > 4 && k[len(k)-4:] == ".seg" {
			store[k] = bytes.Repeat([]byte{0x00}, len(store[k]))
		}
	}

	res, err := Attest(store, attestRunID, nil, 0)
	if err != nil {
		t.Fatalf("attest must not depend on the encrypted record bytes: %v", err)
	}
	if !res.OK() {
		t.Fatalf("attest over a structurally intact root/shard/runlog must pass, got code %d", res.Code)
	}
}

// TestAttestSignerPinnedMinIndexCatchesTailRollback proves that a signer-pinned attest
// honours --min-runlog-index exactly as verify/restore do. buildArchive's RUNLOG carries
// exactly one entry (the run itself, index 1): a tail rollback, where an active
// bucket-write adversary deletes the newer runs and rolls the RUNLOG back to an older,
// wholesale validly-signed state, is internally self-consistent (the run IS the latest
// entry the truncated document contains) and has no in-document high-water mark to
// contradict it (SPEC.md 10). Only the out-of-band pin catches it: pinning above the
// log's real maximum index fails cryptographically anchored; pinning at or below it
// passes.
func TestAttestSignerPinnedMinIndexCatchesTailRollback(t *testing.T) {
	store := memStore{}
	_, verifier := buildArchive(t, buildSpec{store: store, runID: attestRunID, dpID: "dp_attest", value: []byte("recover me"), secret: false, codec: spec.CodecNameNone})

	res, err := Attest(store, attestRunID, verifier, 5)
	if err == nil {
		t.Fatal("a RUNLOG whose maximum index (1) is below a signer-pinned --min-runlog-index (5) must fail, a tail rollback the signature alone cannot see")
	}
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != ExitStale {
		t.Fatalf("a below-pin RUNLOG must fail ExitStale (%d), got %v", ExitStale, err)
	}
	if !res.Freshness.RollbackWarning {
		t.Fatal("a below-pin signer-pinned attest must set Freshness.RollbackWarning")
	}

	res, err = Attest(store, attestRunID, verifier, 1)
	if err != nil {
		t.Fatalf("a pin at the RUNLOG's actual maximum index must pass: %v", err)
	}
	if !res.OK() || !res.RunlogVerified {
		t.Fatalf("a satisfied signer-pinned min-index attest must pass with RunlogVerified true, got code %d verified=%v", res.Code, res.RunlogVerified)
	}
}

// TestAttestKeylessMinIndexCatchesTailRollback proves --min-runlog-index also narrows the
// keyless attestation's blind spot, but only structurally: with no signer to anchor the
// RUNLOG bytes, the same tail-rollback shape as the signer-pinned test above still fails
// when a pin is given (it reads the log's own claimed index, which a naive replay of an
// older, untouched bucket state carries honestly), and RunlogVerified stays false either
// way — this is a self-consistency check like the shard-hash gate, not a cryptographic
// one, and the AttestResult never conflates the two (SignerPinned distinguishes them).
func TestAttestKeylessMinIndexCatchesTailRollback(t *testing.T) {
	store := memStore{}
	_, _ = buildArchive(t, buildSpec{store: store, runID: attestRunID, dpID: "dp_attest", value: []byte("recover me"), secret: false, codec: spec.CodecNameNone})

	res, err := Attest(store, attestRunID, nil, 5)
	if err == nil {
		t.Fatal("a keyless attest with a RUNLOG max index (1) below the pin (5) must fail")
	}
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != ExitStale {
		t.Fatalf("a below-pin keyless attest must fail ExitStale (%d), got %v", ExitStale, err)
	}
	if res.RunlogVerified {
		t.Fatal("a failed keyless min-index check must still not claim RunlogVerified true")
	}
	if !res.Freshness.RollbackWarning {
		t.Fatal("a below-pin keyless attest must set Freshness.RollbackWarning")
	}

	res, err = Attest(store, attestRunID, nil, 1)
	if err != nil {
		t.Fatalf("a pin at the RUNLOG's actual maximum index must pass keyless: %v", err)
	}
	if !res.OK() {
		t.Fatalf("a satisfied keyless min-index attest must pass, got code %d", res.Code)
	}
	if res.RunlogVerified {
		t.Fatal("a keyless pass must never claim RunlogVerified true, satisfied pin or not")
	}
	if res.Freshness.RunlogMaxIndex != 1 {
		t.Fatalf("expected RunlogMaxIndex 1, got %d", res.Freshness.RunlogMaxIndex)
	}
}

// TestAttestKeylessRejectsCaseCollidingRunlogIndexEvenWithCanonicalKeyPresent is the
// integration-level companion to the case-collision check in canonnum.go: a keyless
// attest whose RUNLOG line carries both the canonical "index":1 and a re-cased duplicate
// "Index":999999 must fail, not pass with an inflated max-index. The case-collision check
// must fire even when the canonical key is present and validates cleanly, because
// encoding/json binds the LAST-occurring key in the object — the decoy — to
// RunlogEntry.Index.
func TestAttestKeylessRejectsCaseCollidingRunlogIndexEvenWithCanonicalKeyPresent(t *testing.T) {
	store := memStore{}
	_, _ = buildArchive(t, buildSpec{store: store, runID: attestRunID, dpID: "dp_attest", value: []byte("recover me"), secret: false, codec: spec.CodecNameNone})

	// Overwrite the RUNLOG with a hand-crafted line: the canonical "index":1 followed by a
	// re-cased duplicate "Index":999999 (which encoding/json binds last, silently
	// overriding the validated value).
	line := `{"downpipeId":"dp_attest","index":1,"Index":999999,"prevRunId":null,"recordCount":1,"runId":"` + attestRunID + `","status":"active"}` + "\n"
	store["_RECOVERY/RUNLOG"] = []byte(line)

	res, err := Attest(store, attestRunID, nil, 999)
	if err == nil {
		t.Fatalf("a case-colliding duplicate RUNLOG index must not let a keyless attest pass a pin the canonical index (1) does not satisfy; got OK with max-index=%d", res.Freshness.RunlogMaxIndex)
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected a coded ExitError, got %v", err)
	}
	if !strings.Contains(err.Error(), "differs only in case") {
		t.Fatalf("expected a case-collision refusal, got %v (code %d)", err, ee.Code)
	}
	if res != nil && res.Freshness.RunlogMaxIndex == 999999 {
		t.Fatal("the decoy index must never be reported as the runlog's max index")
	}
}
