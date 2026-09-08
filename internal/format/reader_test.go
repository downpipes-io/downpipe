package format

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// memStore is an in-memory ObjectStore for the round-trip test.
type memStore map[string][]byte

func (m memStore) Get(key string) ([]byte, error) {
	v, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("object not found: %s", key)
	}
	return v, nil
}

func newKEM(t *testing.T) (*crypto.HybridKEMPrivate, *crypto.HybridKEMPublic) {
	t.Helper()
	priv, pub, err := crypto.GenerateHybridKEM()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// buildSpec configures buildArchive's minimal one-record archive. It replaces the former
// positional parameter list (which carried a bare boolean and exceeded the four-parameter
// guardrail) so a call site reads as a labelled struct literal.
type buildSpec struct {
	store  memStore
	runID  string
	dpID   string
	value  []byte
	secret bool
	codec  string
}

// archiveKeys holds the freshly generated key material a one-record archive is sealed and
// signed under, threaded between buildArchive's helpers.
type archiveKeys struct {
	bgPub  *crypto.HybridKEMPublic
	opPub  *crypto.HybridKEMPublic
	signer *crypto.HybridSigner
}

// buildArchive assembles a minimal one-record archive into the store and returns the
// break-glass private identity and the operator verifier needed to read it back. It is a
// thin wrapper over sealOneRecordShard (segment plus shard manifest) and
// writeOneRecordRun (capsule, signed root and RUNLOG).
func buildArchive(t *testing.T, bs buildSpec) (*crypto.HybridKEMPrivate, *crypto.HybridVerifier) {
	t.Helper()
	bgPriv, bgPub := newKEM(t)
	_, opPub := newKEM(t)
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	keys := archiveKeys{bgPub: bgPub, opPub: opPub, signer: signer}
	rec, shardSHA := sealOneRecordShard(t, bs)
	writeOneRecordRun(t, bs, keys, rec, shardSHA)
	return bgPriv, verifier
}

// sealOneRecordShard seals the record's value as a single segment and the shard manifest
// into bs.store, returning the record line and the shard SHA-384 the root will reference.
func sealOneRecordShard(t *testing.T, bs buildSpec) (spec.ShardRecord, string) {
	t.Helper()
	master := bytes.Repeat([]byte{0x7e}, 32)
	runIDBytes, err := spec.DecodeULID(bs.runID)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x01}, spec.StreamNonceSize)

	// recordId follows the documented shape (SPEC.md 6.3): "r" then 15 zero-padded
	// digits. The secrets path validates this shape, so the fixture uses a conformant id.
	const recordID = "r000000000000001"
	plainSHA := SHA384Hex(bs.value) // the hash is over the original, decompressed value
	var (
		segID    [48]byte
		segBytes []byte
		recSalt  string
		srcType  = "kv"
		recCodec = bs.codec
	)
	if bs.secret {
		srcType = "secrets"
		recCodec = spec.CodecNameNone
		salt := bytes.Repeat([]byte{0xaa}, 16)
		recSalt = B64Encode(salt)
		segID, segBytes, err = crypto.SealSecretsSegment(master, bs.dpID, crypto.SecretsSegmentParams{RecordID: []byte(recordID), RecordSalt: salt, RunIDBytes: runIDBytes}, bs.value, nonce)
	} else {
		stored := bs.value
		codecID := spec.CodecNone
		if bs.codec == spec.CodecNameGzip {
			var zb bytes.Buffer
			zw := gzip.NewWriter(&zb)
			if _, werr := zw.Write(bs.value); werr != nil {
				t.Fatal(werr)
			}
			if cerr := zw.Close(); cerr != nil {
				t.Fatal(cerr)
			}
			stored = zb.Bytes()
			codecID = spec.CodecGzip
		}
		segID, segBytes, err = crypto.SealNonSecretSegment(master, bs.dpID, spec.AddrSingleNonSecret, codecID, stored, nonce)
	}
	if err != nil {
		t.Fatal(err)
	}
	segHex := crypto.SegIDHex(segID)
	segObj := "seg/" + segHex[:2] + "/" + segHex + ".seg"
	bs.store[segObj] = segBytes

	mk := crypto.DeriveMK(master, runIDBytes)
	keyNameHash := hex.EncodeToString(crypto.NameMAC(crypto.DeriveNameMACKey(mk, runIDBytes), srcType, "greeting"))
	rec := spec.ShardRecord{
		SourceType: srcType, Name: "greeting", KeyNameHash: keyNameHash,
		RecordID:      recordID,
		PlaintextSize: int64(len(bs.value)), PlaintextSHA: plainSHA,
		Codec:      recCodec,
		Segments:   []spec.Segment{{Object: segObj, ChunkRange: [2]int{0, 1}}},
		RecordSalt: recSalt,
	}
	rhBytes, err := RecordHashOf(rec)
	if err != nil {
		t.Fatal(err)
	}
	rec.RecordHash = hex.EncodeToString(rhBytes)

	shardWrap := crypto.DeriveManifestWrapKey(mk, runIDBytes, "00000")
	preamble := spec.ShardPreamble{
		FormatVersion: spec.Version, RunID: bs.runID, ShardID: "00000",
		ManifestCodec: spec.CodecNameNone,
		Downpipe:      spec.PreambleDownpipe{Name: "test", Cadence: "0 * * * *"},
		Source:        spec.Source{Type: srcType, NamespaceID: "ns1"},
		Window:        spec.Window{Start: "2026-06-06T12:00:00.000Z", End: "2026-06-06T12:00:30.000Z"},
		Consistency:   "crawl",
	}
	shardBytes, shardSHA, err := SealShard(preamble, []spec.ShardRecord{rec}, shardWrap, nonce)
	if err != nil {
		t.Fatal(err)
	}
	bs.store[runKey(bs.runID, "manifest/00000.dpe")] = shardBytes
	return rec, shardSHA
}

// writeOneRecordRun signs and writes the master capsule, root manifest and detached
// signature, plus the single-entry RUNLOG, for the record sealed by sealOneRecordShard.
func writeOneRecordRun(t *testing.T, bs buildSpec, keys archiveKeys, rec spec.ShardRecord, shardSHA string) {
	t.Helper()
	master := bytes.Repeat([]byte{0x7e}, 32)
	runIDBytes, err := spec.DecodeULID(bs.runID)
	if err != nil {
		t.Fatal(err)
	}
	bgPub, opPub := keys.bgPub, keys.opPub

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
		FormatVersion: spec.Version, RunID: bs.runID,
		CreatedAt:  "2026-06-06T12:00:30.000Z",
		DownpipeID: bs.dpID,
		Envelope:   spec.Envelope{AEAD: "AES-256-GCM", KEM: "X25519+ML-KEM-1024", Signature: "Ed25519+ML-DSA-87", KDF: "HKDF-SHA-384", ChunkSize: spec.ChunkSize, Codec: bs.codec},
		Recipients: recipients, MasterCapsule: capsule,
		RecipientSetHash:      hex.EncodeToString(crypto.RecipientSetHash([]*crypto.HybridKEMPublic{bgPub, opPub})),
		KeyCommitment:         hex.EncodeToString(kc),
		BreakGlassPresent:     true,
		Shards:                []spec.ShardRef{{ID: "00000", Object: runKey(bs.runID, "manifest/00000.dpe"), SHA384: shardSHA}},
		ShardCount:            1,
		DeclaredRecordCount:   1,
		MerkleRoot:            hex.EncodeToString(MerkleRoot([][]byte{rhRaw})),
		Freshness:             spec.Freshness{PrevRunID: nil, RunlogIndex: 1},
		SigningKeyFingerprint: "edmldsa1:test",
	}
	canonical, sig, err := SignRoot(root, keys.signer)
	if err != nil {
		t.Fatal(err)
	}
	bs.store[runKey(bs.runID, "root.manifest.json")] = canonical
	bs.store[runKey(bs.runID, "root.manifest.json.sig")] = []byte(B64Encode(sig))

	runlogBytes, err := MarshalRunlog([]spec.RunlogEntry{{
		Index: 1, RunID: bs.runID, DownpipeID: bs.dpID, Time: "2026-06-06T12:00:30.000Z",
		RecordCount: 1, PrevRunID: nil, Status: "active",
	}})
	if err != nil {
		t.Fatal(err)
	}
	runlogSig, err := keys.signer.Sign(runlogBytes)
	if err != nil {
		t.Fatal(err)
	}
	bs.store["_RECOVERY/RUNLOG"] = runlogBytes
	bs.store["_RECOVERY/RUNLOG.sig"] = []byte(B64Encode(runlogSig))
}

// The composable builder below generalises buildArchive into the full SPEC-14 breadth
// (multi-record, multi-segment chains, packed shared segments, two runs, the
// break-glass-only posture) so the conformance generator can cut every section 14.2/14.3
// vector from one pinned-input builder. It keeps buildArchive above untouched for the
// existing single-record round-trip tests.

// recordSpec describes one record a vector archive carries. segments forces a non-secret
// codec=none value to be split across that many ordered .seg objects (a segment chain);
// packGroup groups several non-secret records into one shared packed segment (records in
// the same non-zero group share one .seg, each owning a {offset,length} slice).
type recordSpec struct {
	name      string
	value     []byte
	secret    bool
	srcType   string // any source type; defaults to kv for a non-secret record
	segments  int
	packGroup int
	// The optional annotative fields (SPEC.md 6.2): a d1 identity, an API-source
	// account, an incompleteness-marker kind, and the d1 descriptor format hint.
	database string
	account  string
	marker   string
	d1Format string
}

// vectorSpec describes one archive a vector pins. posture is "two" (break-glass plus
// operational, the default) or "bg-only" (the single break-glass recipient). runs is 1
// or 2; a two-run spec shares one seg/ tree and one signed RUNLOG so dedup-same-value
// stores the shared non-secret segment exactly once.
type vectorSpec struct {
	dpID    string
	posture string
	codec   string
	records []recordSpec
	runs    int
}

// the second fixed run id, used only by two-run vectors. Each vector lives in its own
// directory so the two ids never collide with another vector's.
const vecRunIDB = "01ARZ3NDEKTSV4RRFFQ69G5FB0"

// fixedMaster and fixedNonce are the pinned secrets of every vector (SPEC.md 14.1): the
// master from which CAK, MK, every file key and keyCommitment follow, and the single
// STREAM payload nonce. The per-segment file key binds the segId (and so the plaintext),
// so one nonce across distinct segments is not a nonce reuse: each segment seals under a
// distinct AES-256 key.
func fixedMaster() []byte { return bytes.Repeat([]byte{0x7e}, 32) }
func fixedNonce() []byte  { return bytes.Repeat([]byte{0x01}, spec.StreamNonceSize) }

// streamChunkCount returns the number of STREAM chunks SealStream emits for a plaintext
// of n bytes (SPEC.md 7.8): one chunk per 65536 bytes, with an extra chunk for any
// remainder and a single chunk for the empty value. It mirrors crypto.SealStream so a
// vector can set each segment's true chunkRange [0, chunkCount).
func streamChunkCount(n int) int {
	chunks := n / spec.ChunkSize
	if n%spec.ChunkSize != 0 || n == 0 {
		chunks++
	}
	return chunks
}

// orderedRecords returns the record specs in canonical record order (SPEC.md 11.8:
// ascending by sourceType then name) paired with their assigned recordId ordinal "r" +
// 15 digits. The order is independent of input order, matching a conformant writer.
func orderedRecords(recs []recordSpec) ([]recordSpec, []string) {
	out := append([]recordSpec(nil), recs...)
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := recordSourceType(out[i]), recordSourceType(out[j])
		if si != sj {
			return si < sj
		}
		return out[i].name < out[j].name
	})
	ids := make([]string, len(out))
	for i := range out {
		ids[i] = fmt.Sprintf("r%015d", i)
	}
	return out, ids
}

// recordSourceType maps a record spec to its sourceType. The non-secret default is r2
// for a packed or chain record and kv otherwise, so the SPEC-14 names (an r2 multi-chunk,
// kv packed set) come out with the right coordinate field; secrets are explicit.
func recordSourceType(r recordSpec) string {
	if r.secret {
		return "secrets"
	}
	if r.srcType != "" {
		return r.srcType
	}
	return "kv"
}

// builtRun is the output of sealing one run: the records (in canonical order, with their
// segment lists), the shard bytes and hash, and the encrypted preamble inputs.
type builtRun struct {
	runID    string
	prevRun  *string
	index    int64
	records  []spec.ShardRecord
	shardSHA string
}

// buildArchiveSpec assembles a full vector archive into a fresh store and returns the
// break-glass identity and the operator verifier. It seals every run of vs into one
// shared seg/ tree, writes each run's encrypted shard manifest, signs each run's root
// over the pinned recipients and capsule, and writes the signed RUNLOG and the recovery
// bundle. Non-secret content-derived segments dedup across runs by construction.
func buildArchiveSpec(t *testing.T, vs vectorSpec) (memStore, *crypto.HybridKEMPrivate, *crypto.HybridVerifier, *crypto.HybridSigner) {
	t.Helper()
	if vs.posture == "" {
		vs.posture = "two"
	}
	if vs.codec == "" {
		vs.codec = spec.CodecNameNone
	}
	if vs.runs == 0 {
		vs.runs = 1
	}
	store := memStore{}
	bgPriv, bgPub := newKEM(t)
	_, opPub := newKEM(t)
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	master := fixedMaster()

	recipientPubs := []*crypto.HybridKEMPublic{bgPub, opPub}
	recipients := []spec.Recipient{
		recipientJSON(bgPub, "break-glass"),
		recipientJSON(opPub, "operational"),
	}
	if vs.posture == "bg-only" {
		recipientPubs = []*crypto.HybridKEMPublic{bgPub}
		recipients = []spec.Recipient{recipientJSON(bgPub, "break-glass")}
	}

	runIDs := []string{vecRunID}
	if vs.runs == 2 {
		runIDs = []string{vecRunID, vecRunIDB}
	}
	var prev *string
	for i, runID := range runIDs {
		idx := int64(i + 1)
		run := sealRun(t, store, master, vs, runID, prev, idx)
		writeRunRoot(t, store, master, signer, vs, run, recipients, recipientPubs)
		rid := runID
		prev = &rid
	}

	writeRunlog(t, store, signer, vs.dpID, runIDs)
	writeRecoveryBundle(t, store, signer)
	return store, bgPriv, verifier, signer
}

// sealRun seals one run's segments and shard manifest into the shared store and returns
// the run's canonical-order records. Non-secret codec=none segments are content-derived,
// so a second run with the same value reuses the same seg object (stored once).
func sealRun(t *testing.T, store memStore, master []byte, vs vectorSpec, runID string, prev *string, index int64) builtRun {
	t.Helper()
	runIDBytes, err := spec.DecodeULID(runID)
	if err != nil {
		t.Fatal(err)
	}
	nonce := fixedNonce()
	ordered, ids := orderedRecords(vs.records)

	// Seal each packGroup once over the canonical concatenation of its members.
	packSeg := map[int]string{}
	packOffsets := map[int]map[int]spec.Packed{}
	for gi, g := range packGroups(ordered) {
		var concat []byte
		offs := map[int]spec.Packed{}
		for _, idx := range g {
			offs[idx] = spec.Packed{Offset: int64(len(concat)), Length: int64(len(ordered[idx].value))}
			concat = append(concat, ordered[idx].value...)
		}
		segID, segBytes, err := crypto.SealNonSecretSegment(master, vs.dpID, spec.AddrPacked, spec.CodecNone, concat, nonce)
		if err != nil {
			t.Fatal(err)
		}
		obj := segObject(crypto.SegIDHex(segID))
		store[obj] = segBytes
		group := ordered[g[0]].packGroup
		packSeg[group] = obj
		packOffsets[group] = offs
		_ = gi
	}

	sc := sealContext{master: master, vs: vs, runIDBytes: runIDBytes, nonce: nonce, packSeg: packSeg, packOffsets: packOffsets}
	records := make([]spec.ShardRecord, len(ordered))
	for i, rs := range ordered {
		records[i] = sealRecord(t, store, sc, rs, ids[i], i)
	}

	shardBytes, shardSHA := sealShardManifest(t, master, runID, runIDBytes, records, nonce)
	store[runKey(runID, "manifest/00000.dpe")] = shardBytes
	return builtRun{runID: runID, prevRun: prev, index: index, records: records, shardSHA: shardSHA}
}

// sealContext bundles the run-wide inputs shared by every record sealed in one run: the
// master secret, the run's vectorSpec, the decoded run id, the pinned STREAM nonce, and the
// pre-sealed packed-segment lookups. It keeps sealRecord within the four-parameter guardrail
// by carrying these together rather than as eight positional arguments.
type sealContext struct {
	master      []byte
	vs          vectorSpec
	runIDBytes  []byte
	nonce       []byte
	packSeg     map[int]string
	packOffsets map[int]map[int]spec.Packed
}

// sealRecord seals one record's value into the store and returns its manifest line. It
// covers the secrets path (salted, never deduped), the packed-member path (a slice of a
// shared segment), the forced multi-segment chain, and the single non-secret segment
// (codec none or gzip). The per-record inputs (rs, recordID, ordinal) vary per call; the
// run-wide inputs travel in sc.
func sealRecord(t *testing.T, store memStore, sc sealContext, rs recordSpec, recordID string, ordinal int) spec.ShardRecord {
	t.Helper()
	master, vs, runIDBytes, nonce := sc.master, sc.vs, sc.runIDBytes, sc.nonce
	packSeg, packOffsets := sc.packSeg, sc.packOffsets
	srcType := recordSourceType(rs)
	recCodec := vs.codec
	var (
		segs    []spec.Segment
		recSalt string
	)
	switch {
	case rs.secret:
		recCodec = spec.CodecNameNone
		// A distinct per-record salt makes two byte-identical secrets seal to distinct
		// segIds and distinct file keys (SPEC.md 7.2 case 0x03), so secrets never dedup.
		salt := bytes.Repeat([]byte{byte(0xa0 + ordinal)}, 16)
		recSalt = B64Encode(salt)
		segID, segBytes, err := crypto.SealSecretsSegment(master, vs.dpID, crypto.SecretsSegmentParams{RecordID: []byte(recordID), RecordSalt: salt, RunIDBytes: runIDBytes}, rs.value, nonce)
		if err != nil {
			t.Fatal(err)
		}
		obj := segObject(crypto.SegIDHex(segID))
		store[obj] = segBytes
		segs = []spec.Segment{{Object: obj, ChunkRange: [2]int{0, streamChunkCount(len(rs.value))}}}
	case rs.packGroup > 0:
		obj := packSeg[rs.packGroup]
		p := packOffsets[rs.packGroup][ordinal]
		// The packed member owns a byte slice of the shared segment; chunkRange spans the
		// whole shared segment's chunks and packed gives this member's offset and length.
		whole := store[obj]
		body, err := spec.UnframeContainer(spec.MagicSeg, whole)
		if err != nil {
			t.Fatal(err)
		}
		chunks := streamBodyChunkCount(len(body))
		pc := p
		segs = []spec.Segment{{Object: obj, ChunkRange: [2]int{0, chunks}, Packed: &pc}}
	case rs.segments > 1:
		segs = sealSegmentChain(t, store, master, vs.dpID, rs.value, rs.segments, nonce)
	default:
		stored, codecID := encodeForCodec(t, vs.codec, rs.value)
		segID, segBytes, err := crypto.SealNonSecretSegment(master, vs.dpID, spec.AddrSingleNonSecret, codecID, stored, nonce)
		if err != nil {
			t.Fatal(err)
		}
		obj := segObject(crypto.SegIDHex(segID))
		store[obj] = segBytes
		segs = []spec.Segment{{Object: obj, ChunkRange: [2]int{0, streamChunkCount(len(stored))}}}
	}

	mk := crypto.DeriveMK(master, runIDBytes)
	knh := hex.EncodeToString(crypto.NameMAC(crypto.DeriveNameMACKey(mk, runIDBytes), srcType, rs.name))
	rec := spec.ShardRecord{
		SourceType: srcType, Name: rs.name, KeyNameHash: knh, RecordID: recordID,
		PlaintextSize: int64(len(rs.value)), PlaintextSHA: SHA384Hex(rs.value),
		Codec: recCodec, Segments: segs, RecordSalt: recSalt,
		Database: rs.database, Account: rs.account, IncompleteMarker: rs.marker,
	}
	if rs.d1Format != "" {
		rec.D1 = &spec.D1Descriptor{Format: rs.d1Format}
	}
	rhBytes, err := RecordHashOf(rec)
	if err != nil {
		t.Fatal(err)
	}
	rec.RecordHash = hex.EncodeToString(rhBytes)
	return rec
}

// sealSegmentChain splits value into n near-equal pieces and seals each as its own
// non-secret codec=none segment, returning the ordered segments list. It is the
// small-fixture stand-in for the SPEC.md 14.5 segmentation bound (16384 chunks per
// segment): the chain semantics (ordered reassembly, per-segment chunkRange) are
// exercised without a 1 GiB artefact.
func sealSegmentChain(t *testing.T, store memStore, master []byte, dpID string, value []byte, n int, nonce []byte) []spec.Segment {
	t.Helper()
	if n < 2 {
		t.Fatalf("segment chain needs at least 2 pieces, got %d", n)
	}
	pieces := splitN(value, n)
	segs := make([]spec.Segment, 0, n)
	for _, piece := range pieces {
		segID, segBytes, err := crypto.SealNonSecretSegment(master, dpID, spec.AddrSingleNonSecret, spec.CodecNone, piece, nonce)
		if err != nil {
			t.Fatal(err)
		}
		obj := segObject(crypto.SegIDHex(segID))
		store[obj] = segBytes
		segs = append(segs, spec.Segment{Object: obj, ChunkRange: [2]int{0, streamChunkCount(len(piece))}})
	}
	return segs
}

// sealShardManifest seals the shard preamble and records under the per-shard manifest
// wrap key and returns the framed bytes and their SHA-384.
func sealShardManifest(t *testing.T, master []byte, runID string, runIDBytes []byte, records []spec.ShardRecord, nonce []byte) ([]byte, string) {
	t.Helper()
	mk := crypto.DeriveMK(master, runIDBytes)
	srcType := "kv"
	if len(records) > 0 {
		srcType = records[0].SourceType
	}
	preamble := spec.ShardPreamble{
		FormatVersion: spec.Version, RunID: runID, ShardID: "00000",
		ManifestCodec: spec.CodecNameNone,
		Downpipe:      spec.PreambleDownpipe{Name: "test", Cadence: "0 * * * *"},
		Source:        spec.Source{Type: srcType, NamespaceID: "ns1"},
		Window:        spec.Window{Start: "2026-06-06T12:00:00.000Z", End: "2026-06-06T12:00:30.000Z"},
		Consistency:   "crawl",
	}
	shardBytes, shardSHA, err := SealShard(preamble, records, crypto.DeriveManifestWrapKey(mk, runIDBytes, "00000"), nonce)
	if err != nil {
		t.Fatal(err)
	}
	return shardBytes, shardSHA
}

// writeRunRoot signs and writes one run's root manifest and detached signature over the
// pinned recipients and the (non-reproducible) master capsule.
func writeRunRoot(t *testing.T, store memStore, master []byte, signer *crypto.HybridSigner, vs vectorSpec, run builtRun, recipients []spec.Recipient, recipientPubs []*crypto.HybridKEMPublic) {
	t.Helper()
	runIDBytes, err := spec.DecodeULID(run.runID)
	if err != nil {
		t.Fatal(err)
	}
	kc := crypto.KeyCommitment(master, runIDBytes)
	wraps, err := crypto.SealToRecipients([32]byte(master), recipientPubs, kc, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capsule := make([]spec.CapsuleWrap, len(wraps))
	for i, w := range wraps {
		capsule[i] = spec.CapsuleWrap{Fingerprint: w.Fingerprint, KEMCiphertext: B64Encode(w.KEMCiphertext), Sealed: B64Encode(w.Sealed)}
	}
	leaves := make([][]byte, len(run.records))
	for i, rec := range run.records {
		rh, err := hex.DecodeString(rec.RecordHash)
		if err != nil {
			t.Fatal(err)
		}
		leaves[i] = rh
	}
	root := &spec.RootManifest{
		FormatVersion: spec.Version, RunID: run.runID,
		CreatedAt:  "2026-06-06T12:00:30.000Z",
		DownpipeID: vs.dpID,
		Envelope:   spec.Envelope{AEAD: "AES-256-GCM", KEM: "X25519+ML-KEM-1024", Signature: "Ed25519+ML-DSA-87", KDF: "HKDF-SHA-384", ChunkSize: spec.ChunkSize, Codec: vs.codec},
		Recipients: recipients, MasterCapsule: capsule,
		RecipientSetHash:      hex.EncodeToString(crypto.RecipientSetHash(recipientPubs)),
		KeyCommitment:         hex.EncodeToString(kc),
		BreakGlassPresent:     true,
		Shards:                []spec.ShardRef{{ID: "00000", Object: runKey(run.runID, "manifest/00000.dpe"), SHA384: run.shardSHA}},
		ShardCount:            1,
		DeclaredRecordCount:   int64(len(run.records)),
		MerkleRoot:            hex.EncodeToString(MerkleRoot(leaves)),
		Freshness:             spec.Freshness{PrevRunID: run.prevRun, RunlogIndex: run.index},
		SigningKeyFingerprint: crypto.SignerFingerprint(verifierOf(signer)),
	}
	canonical, sig, err := SignRoot(root, signer)
	if err != nil {
		t.Fatal(err)
	}
	store[runKey(run.runID, "root.manifest.json")] = canonical
	store[runKey(run.runID, "root.manifest.json.sig")] = []byte(B64Encode(sig))
}

// writeRunlog writes the signed append-only RUNLOG with one entry per run, chaining each
// run to its predecessor and marking all but the latest superseded (SPEC.md 10).
func writeRunlog(t *testing.T, store memStore, signer *crypto.HybridSigner, dpID string, runIDs []string) {
	t.Helper()
	entries := make([]spec.RunlogEntry, len(runIDs))
	var prev *string
	for i, runID := range runIDs {
		status := "active"
		if i < len(runIDs)-1 {
			status = "superseded"
		}
		entries[i] = spec.RunlogEntry{
			Index: int64(i + 1), RunID: runID, DownpipeID: dpID,
			Time: "2026-06-06T12:00:30.000Z", RecordCount: 1, PrevRunID: prev, Status: status,
		}
		rid := runID
		prev = &rid
	}
	runlogBytes, err := MarshalRunlog(entries)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(runlogBytes)
	if err != nil {
		t.Fatal(err)
	}
	store["_RECOVERY/RUNLOG"] = runlogBytes
	store["_RECOVERY/RUNLOG.sig"] = []byte(B64Encode(sig))
}

// writeRecoveryBundle writes a minimal signed recovery bundle (SPEC.md 9) so a vector can
// exercise the section 8.7 item-4 bundle-binding check. The contents are placeholders;
// the conformance check is over the SHA384SUMS binding, not the prose.
func writeRecoveryBundle(t *testing.T, store memStore, signer *crypto.HybridSigner) {
	t.Helper()
	files := map[string][]byte{
		"FORMAT.md":  []byte("downpipe/0.1.0 format specification (conformance fixture placeholder)\n"),
		"RECOVER.md": []byte("recover with the offline break-glass identity and the vendored reader\n"),
	}
	put := func(key string, data []byte) error { store[key] = data; return nil }
	if err := WriteBundle(put, files, signer); err != nil {
		t.Fatal(err)
	}
}

// packGroups returns the ordinals of each packGroup in canonical order, grouped, for the
// records already in canonical order. A record with packGroup 0 is not packed.
func packGroups(ordered []recordSpec) [][]int {
	seen := map[int]int{}
	var groups [][]int
	for i, r := range ordered {
		if r.packGroup == 0 {
			continue
		}
		if gi, ok := seen[r.packGroup]; ok {
			groups[gi] = append(groups[gi], i)
			continue
		}
		seen[r.packGroup] = len(groups)
		groups = append(groups, []int{i})
	}
	return groups
}

// splitN splits b into n near-equal, non-empty-where-possible pieces in order.
func splitN(b []byte, n int) [][]byte {
	pieces := make([][]byte, 0, n)
	size := (len(b) + n - 1) / n
	for off := 0; off < len(b); off += size {
		end := off + size
		if end > len(b) {
			end = len(b)
		}
		pieces = append(pieces, b[off:end])
	}
	// Pad the slice to exactly n pieces if the value was short, so the chain still has n
	// links (a trailing empty piece is a valid single-empty-chunk segment).
	for len(pieces) < n {
		pieces = append(pieces, []byte{})
	}
	return pieces
}

// encodeForCodec returns the stored bytes and codec id for a non-secret value under the
// run codec: the value verbatim for none, gzip-compressed for gzip.
func encodeForCodec(t *testing.T, codec string, value []byte) ([]byte, byte) {
	t.Helper()
	if codec == spec.CodecNameGzip {
		var zb bytes.Buffer
		zw := gzip.NewWriter(&zb)
		if _, err := zw.Write(value); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return zb.Bytes(), spec.CodecGzip
	}
	return value, spec.CodecNone
}

func recipientJSON(pub *crypto.HybridKEMPublic, role string) spec.Recipient {
	return spec.Recipient{
		Fingerprint: crypto.RecipientFingerprint(pub), Role: role,
		X25519: B64Encode(pub.X25519.Bytes()), MLKEM: B64Encode(pub.MLKEM.Bytes()),
	}
}

func segObject(segHex string) string { return "seg/" + segHex[:2] + "/" + segHex + ".seg" }

// streamBodyChunkCount returns the chunk count implied by a sealed STREAM body length
// (the bytes after the container header), so a packed member's chunkRange spans the whole
// shared segment. The body is the 16-byte payload nonce then ceil-many 65536+16-byte
// chunks with a final possibly-shorter chunk.
func streamBodyChunkCount(bodyLen int) int {
	const fullChunk = spec.ChunkSize + spec.TagSize
	rest := bodyLen - spec.StreamNonceSize
	if rest <= 0 {
		return 1
	}
	chunks := rest / fullChunk
	if rest%fullChunk != 0 {
		chunks++
	}
	return chunks
}

// verifierOf derives the verifier (public halves) for a signer so the root can carry the
// matching edmldsa1: fingerprint. It rebuilds the verifier from the signer's marshalled
// public material.
func verifierOf(s *crypto.HybridSigner) *crypto.HybridVerifier {
	return &crypto.HybridVerifier{Ed: s.Ed.Public().(ed25519.PublicKey), MLDSA: s.MLDSA.PublicKey()}
}

func TestReadArchiveEndToEnd(t *testing.T) {
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	store := memStore{}
	value := []byte("hello, recover me without Cloudflare and without the vendor")
	bgPriv, verifier := buildArchive(t, buildSpec{store: store, runID: runID, dpID: "dp_test", value: value, secret: false, codec: spec.CodecNameNone})

	r, err := Open(store, runID, bgPriv, verifier, Options{})
	if err != nil {
		t.Fatalf("open verified archive: %v", err)
	}
	recs := r.Records()
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	got, err := r.RestoreRecord(recs[0])
	if err != nil {
		t.Fatalf("restore record: %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Fatalf("restored value mismatch:\n got %q\nwant %q", got, value)
	}
}

// A secrets record must round-trip through the secrets file-key path: salted address,
// per-run/record/salt file key, never deduped.
func TestReadSecretsArchiveEndToEnd(t *testing.T) {
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	store := memStore{}
	secretValue := []byte("super-secret-api-token-value")
	bgPriv, verifier := buildArchive(t, buildSpec{store: store, runID: runID, dpID: "dp_secrets", value: secretValue, secret: true, codec: spec.CodecNameNone})

	r, err := Open(store, runID, bgPriv, verifier, Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	recs := r.Records()
	if len(recs) != 1 || recs[0].SourceType != "secrets" {
		t.Fatalf("expected one secrets record, got %+v", recs)
	}
	got, err := r.RestoreRecord(recs[0])
	if err != nil {
		t.Fatalf("restore secret: %v", err)
	}
	if !bytes.Equal(got, secretValue) {
		t.Fatal("restored secret does not match")
	}
}

// A gzip run must round-trip: the reader opens the segment, decompresses the whole
// reassembled value, and checks the hash over the decompressed bytes.
func TestReadGzipArchive(t *testing.T) {
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	store := memStore{}
	value := bytes.Repeat([]byte("compress me, "), 128)
	bgPriv, verifier := buildArchive(t, buildSpec{store: store, runID: runID, dpID: "dp_gzip", value: value, secret: false, codec: spec.CodecNameGzip})

	r, err := Open(store, runID, bgPriv, verifier, Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	got, err := r.RestoreRecord(r.Records()[0])
	if err != nil {
		t.Fatalf("restore gzip: %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Fatal("gzip round-trip mismatch")
	}
}

// A different signer than the one that signed the run must be rejected at open.
func TestReadArchiveWrongSignerRejected(t *testing.T) {
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	store := memStore{}
	bgPriv, _ := buildArchive(t, buildSpec{store: store, runID: runID, dpID: "dp_test", value: []byte("data"), secret: false, codec: spec.CodecNameNone})
	_, wrongVerifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(store, runID, bgPriv, wrongVerifier, Options{}); err == nil {
		t.Fatal("opening with the wrong signer must fail")
	}
}

// Tampering a segment must surface as a failed plaintext hash on restore.
func TestReadArchiveTamperedSegmentRejected(t *testing.T) {
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	store := memStore{}
	bgPriv, verifier := buildArchive(t, buildSpec{store: store, runID: runID, dpID: "dp_test", value: []byte("important data"), secret: false, codec: spec.CodecNameNone})
	for k := range store {
		if len(k) > 4 && k[:4] == "seg/" {
			store[k] = bytes.Clone(store[k])
			store[k][len(store[k])-1] ^= 0x01
		}
	}
	r, err := Open(store, runID, bgPriv, verifier, Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := r.RestoreRecord(r.Records()[0]); err == nil {
		t.Fatal("a tampered segment must fail on restore")
	}
}

// withChunkRange returns a copy of rec whose single segment carries the given chunkRange,
// leaving the stored bytes untouched so only the manifest's declared range changes.
func withChunkRange(rec spec.ShardRecord, cr [2]int) spec.ShardRecord {
	cp := rec
	cp.Segments = append([]spec.Segment(nil), rec.Segments...)
	cp.Segments[0].ChunkRange = cr
	return cp
}

// The reader bounds each segment read by the segment's signed chunkRange and rejects a
// chunkRange that disagrees with the sealed segment. A value spanning two STREAM
// chunks lets the test under-declare the range so the read is bounded below the segment's
// true length, and over-declare it so the segment terminates before lastChunkExclusive.
func TestRestoreRecordBoundsSegmentByChunkRange(t *testing.T) {
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	store := memStore{}
	// ChunkSize+1 bytes seals into two STREAM chunks (one full chunk plus a 1-byte
	// remainder), so the true whole-segment chunkRange is [0, 2).
	value := bytes.Repeat([]byte{0x41}, spec.ChunkSize+1)
	bgPriv, verifier := buildArchive(t, buildSpec{store: store, runID: runID, dpID: "dp_bound", value: value, secret: false, codec: spec.CodecNameNone})

	r, err := Open(store, runID, bgPriv, verifier, Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	rec := r.Records()[0]
	if got := segmentStreamChunks(int(rec.PlaintextSize)); got != 2 {
		t.Fatalf("test fixture must span two chunks, got %d", got)
	}

	// Positive control: the true range [0, 2) restores the value.
	if got, rerr := r.RestoreRecord(withChunkRange(rec, [2]int{0, 2})); rerr != nil {
		t.Fatalf("the true chunkRange must restore: %v", rerr)
	} else if !bytes.Equal(got, value) {
		t.Fatal("restored value mismatch under the true chunkRange")
	}

	t.Run("under-declared range cannot read beyond it", func(t *testing.T) {
		// chunkRange [0, 1) bounds the read to one chunk, but the segment has a second
		// chunk: OpenStreamTo must refuse to open the chunk at index 1.
		if _, rerr := r.RestoreRecord(withChunkRange(rec, [2]int{0, 1})); rerr == nil {
			t.Fatal("a segment longer than its declared chunkRange must be rejected")
		}
	})

	t.Run("over-declared range fails the exact-termination check", func(t *testing.T) {
		// chunkRange [0, 5) over-states the count; the segment terminates after 2 chunks,
		// which must not satisfy a range declaring 5.
		if _, rerr := r.RestoreRecord(withChunkRange(rec, [2]int{0, 5})); rerr == nil {
			t.Fatal("a chunkRange over-stating the segment's chunk count must be rejected")
		}
	})

	t.Run("non-zero firstChunk is rejected", func(t *testing.T) {
		if _, rerr := r.RestoreRecord(withChunkRange(rec, [2]int{1, 2})); rerr == nil {
			t.Fatal("a whole-segment read requires firstChunk 0")
		}
	})

	t.Run("empty range is rejected", func(t *testing.T) {
		if _, rerr := r.RestoreRecord(withChunkRange(rec, [2]int{0, 0})); rerr == nil {
			t.Fatal("an empty chunkRange must be rejected")
		}
	})

	t.Run("range over the per-segment ceiling is rejected", func(t *testing.T) {
		if _, rerr := r.RestoreRecord(withChunkRange(rec, [2]int{0, maxSegmentChunks + 1})); rerr == nil {
			t.Fatal("a chunkRange over the 16384-chunk segment ceiling must be rejected")
		}
	})
}

// The reader enforces the documented recordId shape on the secrets path before it
// derives the secrets file key. A 16-byte but malformed recordId such as
// "recordid00000001" passed the old length-only check; it must now fail with a recordId
// error, not a downstream decryption error.
func TestRestoreRecordRejectsMalformedSecretsRecordID(t *testing.T) {
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	store := memStore{}
	bgPriv, verifier := buildArchive(t, buildSpec{store: store, runID: runID, dpID: "dp_secrets", value: []byte("token"), secret: true, codec: spec.CodecNameNone})

	r, err := Open(store, runID, bgPriv, verifier, Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	bad := r.Records()[0]
	bad.RecordID = "recordid00000001" // 16 bytes, but not "r" + 15 digits
	_, rerr := r.RestoreRecord(bad)
	if rerr == nil {
		t.Fatal("a malformed recordId on a secrets record must be rejected")
	}
	if !strings.Contains(rerr.Error(), "recordId") {
		t.Fatalf("the rejection must name the recordId, got: %v", rerr)
	}
}

// RestoreRecord's segment-reassembly loop must enforce an aggregate ceiling on the
// buffered value as it grows, not only after the whole chain is buffered: nothing else
// caps the number of segments a record's chain declares. restoreRecord takes
// the ceiling as a parameter so this test can drive the check with a tiny value instead
// of allocating real gigabytes.
func TestRestoreRecordEnforcesAggregateCeiling(t *testing.T) {
	value := bytes.Repeat([]byte{0x37}, 300) // 3 segments of 100 bytes each
	r, rec := streamRec(t, vectorSpec{
		dpID:    "dp_agg_ceiling",
		records: []recordSpec{{name: "blob", value: value, srcType: "r2", segments: 3}},
	})

	// A ceiling crossed partway through the chain must reject the record before the codec
	// or plaintext hash is ever consulted.
	if _, rerr := r.restoreRecord(rec, 150); rerr == nil {
		t.Fatal("a chain reassembling past the ceiling must be rejected")
	} else if !strings.Contains(rerr.Error(), "aggregate reassembly ceiling") {
		t.Fatalf("expected an aggregate reassembly ceiling error, got: %v", rerr)
	}

	// A ceiling at the true total must not false-positive: the record still restores.
	got, err := r.restoreRecord(rec, int64(len(value)))
	if err != nil {
		t.Fatalf("a chain within the ceiling must restore: %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Fatal("restored value mismatch under a ceiling equal to the true size")
	}
}
