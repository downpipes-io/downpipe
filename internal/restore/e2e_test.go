package restore

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// memStore is an in-memory ObjectStore, the read side a built archive is opened through.
type memStore map[string][]byte

func (m memStore) Get(key string) ([]byte, error) {
	v, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("object not found: %s", key)
	}
	return v, nil
}

// TestEndToEndApplyThroughReader builds a real encrypted, signed archive with the
// public format and crypto API, opens it with the break-glass identity through
// format.Open, and proves the restore package plans and then applies the decrypted
// values to a directory target. This binds the package to the real break-glass decrypt
// and verify path, not a fake reader.
func TestEndToEndApplyThroughReader(t *testing.T) {
	store := memStore{}
	values := map[string]string{
		"greeting":   "recover me without Cloudflare and without the vendor",
		"config/key": "value-bytes",
	}
	identity, verifier, runID := buildArchive(t, store, "dp_e2e", "kv", values)

	r, err := format.Open(store, runID, identity, verifier, format.Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if len(r.Records()) != len(values) {
		t.Fatalf("expected %d records, got %d", len(values), len(r.Records()))
	}

	dir := t.TempDir()
	target := NewDirTarget(dir)

	// Dry run first: it must plan both records and write nothing.
	plan, res, err := Apply(r, target, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.DryRun || res.Restored != 0 {
		t.Fatalf("dry run wrote something: %+v", res)
	}
	if len(plan.Writes) != len(values) {
		t.Fatalf("plan should list %d writes, got %d", len(values), len(plan.Writes))
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("dry run touched the output: %d entries", len(entries))
	}

	// Apply: the values come back decrypted and hash-verified through the reader.
	_, res, err = Apply(r, target, true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || res.Restored != len(values) {
		t.Fatalf("apply: restored=%d failed=%v", res.Restored, res.Failed)
	}
	for name, want := range values {
		got, rerr := os.ReadFile(filepath.Join(dir, filepath.FromSlash(safeKey(name))))
		if rerr != nil {
			t.Fatalf("read restored %s: %v", name, rerr)
		}
		if string(got) != want {
			t.Fatalf("restored %s = %q, want %q", name, got, want)
		}
	}
}

// archiveKeys carries the identities, master key and run id shared across the build
// stages of buildArchive.
type archiveKeys struct {
	bgPriv     *crypto.HybridKEMPrivate
	bgPub      *crypto.HybridKEMPublic
	opPub      *crypto.HybridKEMPublic
	signer     *crypto.HybridSigner
	verifier   *crypto.HybridVerifier
	master     []byte
	mk         []byte
	nameKey    []byte
	runID      string
	runIDBytes []byte
}

// genArchiveKeys generates the break-glass and operator identities, the signer and the
// master key, then derives the run id and per-run keys.
func genArchiveKeys(t *testing.T) archiveKeys {
	t.Helper()
	bgPriv, bgPub := genKEM(t)
	_, opPub := genKEM(t)
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	master := randBytes(t, 32)
	runID, err := spec.EncodeULID(randBytes(t, 16))
	if err != nil {
		t.Fatal(err)
	}
	runIDBytes, err := spec.DecodeULID(runID)
	if err != nil {
		t.Fatal(err)
	}
	mk := crypto.DeriveMK(master, runIDBytes)
	return archiveKeys{
		bgPriv: bgPriv, bgPub: bgPub, opPub: opPub,
		signer: signer, verifier: verifier,
		master: master, mk: mk, nameKey: crypto.DeriveNameMACKey(mk, runIDBytes),
		runID: runID, runIDBytes: runIDBytes,
	}
}

// sealSegments seals one segment per value into the store and returns the shard records
// and Merkle leaves in canonical order. sourceType is the record sourceType to stamp on
// every record (for example "kv" for a plain value sink test, or "workers" to exercise the
// reprovision path); RecordHashOf covers the sourceType, so the record hash stays consistent.
func sealSegments(t *testing.T, store memStore, k archiveKeys, dpID, sourceType string, values map[string]string) ([]spec.ShardRecord, [][]byte) {
	t.Helper()
	// Canonical record order is ascending by (sourceType, name) (SPEC.md 11.8). Every record
	// here shares one sourceType, so order by name.
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)

	records := make([]spec.ShardRecord, 0, len(names))
	leaves := make([][]byte, 0, len(names))
	for i, name := range names {
		value := []byte(values[name])
		segID, segBytes, serr := crypto.SealNonSecretSegment(k.master, dpID, spec.AddrSingleNonSecret, spec.CodecNone, value, randBytes(t, spec.StreamNonceSize))
		if serr != nil {
			t.Fatal(serr)
		}
		segHex := crypto.SegIDHex(segID)
		segObj := "seg/" + segHex[:2] + "/" + segHex + ".seg"
		store[segObj] = segBytes

		// chunkRange must declare the segment's REAL chunk count (the reader closes the bound
		// in both directions), so compute it exactly as the STREAM does: 64 KiB chunks with a
		// final short chunk, and one empty chunk for an empty value.
		chunks := len(value) / spec.ChunkSize
		if len(value)%spec.ChunkSize != 0 || len(value) == 0 {
			chunks++
		}
		rec := spec.ShardRecord{
			SourceType: sourceType, Name: name,
			KeyNameHash:   hex.EncodeToString(crypto.NameMAC(k.nameKey, sourceType, name)),
			RecordID:      fmt.Sprintf("r%015d", i),
			PlaintextSize: int64(len(value)), PlaintextSHA: format.SHA384Hex(value),
			Codec:    spec.CodecNameNone,
			Segments: []spec.Segment{{Object: segObj, ChunkRange: [2]int{0, chunks}}},
		}
		rhBytes, herr := format.RecordHashOf(rec)
		if herr != nil {
			t.Fatal(herr)
		}
		rec.RecordHash = hex.EncodeToString(rhBytes)
		records = append(records, rec)
		leaves = append(leaves, rhBytes)
	}
	return records, leaves
}

// sealShard seals the single shard manifest for these records into the store and returns
// its object key and hash.
func sealShard(t *testing.T, store memStore, k archiveKeys, records []spec.ShardRecord) (string, string) {
	t.Helper()
	preamble := spec.ShardPreamble{
		FormatVersion: spec.Version, RunID: k.runID, ShardID: "00000",
		ManifestCodec: spec.CodecNameNone,
		Downpipe:      spec.PreambleDownpipe{Name: "e2e", Cadence: "0 * * * *"},
		Source:        spec.Source{Type: "kv", NamespaceID: "e2e"},
		Window:        spec.Window{Start: "2026-06-06T12:00:00.000Z", End: "2026-06-06T12:00:01.000Z"},
		Consistency:   "crawl",
	}
	shardBytes, shardSHA, err := format.SealShard(preamble, records, crypto.DeriveManifestWrapKey(k.mk, k.runIDBytes, "00000"), randBytes(t, spec.StreamNonceSize))
	if err != nil {
		t.Fatal(err)
	}
	shardObj := "run/" + k.runID + "/manifest/00000.dpe"
	store[shardObj] = shardBytes
	return shardObj, shardSHA
}

// sealRecipients seals the master key to the break-glass and operator identities and
// returns the master capsule, the recipient list and the key commitment.
func sealRecipients(t *testing.T, k archiveKeys) ([]spec.CapsuleWrap, []spec.Recipient, []byte) {
	t.Helper()
	kc := crypto.KeyCommitment(k.master, k.runIDBytes)
	wraps, err := crypto.SealToRecipients([32]byte(k.master), []*crypto.HybridKEMPublic{k.bgPub, k.opPub}, kc, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capsule := make([]spec.CapsuleWrap, len(wraps))
	for i, w := range wraps {
		capsule[i] = spec.CapsuleWrap{Fingerprint: w.Fingerprint, KEMCiphertext: format.B64Encode(w.KEMCiphertext), Sealed: format.B64Encode(w.Sealed)}
	}
	recipients := []spec.Recipient{
		{Fingerprint: crypto.RecipientFingerprint(k.bgPub), Role: "break-glass", X25519: format.B64Encode(k.bgPub.X25519.Bytes()), MLKEM: format.B64Encode(k.bgPub.MLKEM.Bytes())},
		{Fingerprint: crypto.RecipientFingerprint(k.opPub), Role: "operational", X25519: format.B64Encode(k.opPub.X25519.Bytes()), MLKEM: format.B64Encode(k.opPub.MLKEM.Bytes())},
	}
	return capsule, recipients, kc
}

// buildRootManifest assembles, signs and stores the root manifest.
func buildRootManifest(t *testing.T, store memStore, k archiveKeys, dpID string, records []spec.ShardRecord, leaves [][]byte, shardObj, shardSHA string) {
	t.Helper()
	capsule, recipients, kc := sealRecipients(t, k)
	root := &spec.RootManifest{
		FormatVersion: spec.Version, RunID: k.runID,
		CreatedAt:  "2026-06-06T12:00:01.000Z",
		DownpipeID: dpID,
		Envelope:   spec.Envelope{AEAD: "AES-256-GCM", KEM: "X25519+ML-KEM-1024", Signature: "Ed25519+ML-DSA-87", KDF: "HKDF-SHA-384", ChunkSize: spec.ChunkSize, Codec: spec.CodecNameNone},
		Recipients: recipients, MasterCapsule: capsule,
		RecipientSetHash:      hex.EncodeToString(crypto.RecipientSetHash([]*crypto.HybridKEMPublic{k.bgPub, k.opPub})),
		KeyCommitment:         hex.EncodeToString(kc),
		BreakGlassPresent:     true,
		Shards:                []spec.ShardRef{{ID: "00000", Object: shardObj, SHA384: shardSHA}},
		ShardCount:            1,
		DeclaredRecordCount:   int64(len(records)),
		MerkleRoot:            hex.EncodeToString(format.MerkleRoot(leaves)),
		Freshness:             spec.Freshness{PrevRunID: nil, RunlogIndex: 1},
		SigningKeyFingerprint: "edmldsa1:e2e",
	}
	canonical, sig, err := format.SignRoot(root, k.signer)
	if err != nil {
		t.Fatal(err)
	}
	store["run/"+k.runID+"/root.manifest.json"] = canonical
	store["run/"+k.runID+"/root.manifest.json.sig"] = []byte(format.B64Encode(sig))
}

// sealRunlog marshals and signs a single-entry RUNLOG for this run into the store.
func sealRunlog(t *testing.T, store memStore, k archiveKeys, dpID string, recordCount int) {
	t.Helper()
	runlogBytes, err := format.MarshalRunlog([]spec.RunlogEntry{{
		Index: 1, RunID: k.runID, DownpipeID: dpID,
		Time: "2026-06-06T12:00:01.000Z", RecordCount: int64(recordCount), PrevRunID: nil, Status: "active",
	}})
	if err != nil {
		t.Fatal(err)
	}
	runlogSig, err := k.signer.Sign(runlogBytes)
	if err != nil {
		t.Fatal(err)
	}
	store["_RECOVERY/RUNLOG"] = runlogBytes
	store["_RECOVERY/RUNLOG.sig"] = []byte(format.B64Encode(runlogSig))
}

// buildArchive assembles a multi-record encrypted, signed archive into the store and
// returns the break-glass identity, the operator verifier and the run id needed to open
// it. It is a test writer built on the public API, not the production engine; it mirrors
// the structure of cmd/downpipe selftest.go.
func buildArchive(t *testing.T, store memStore, dpID, sourceType string, values map[string]string) (*crypto.HybridKEMPrivate, *crypto.HybridVerifier, string) {
	t.Helper()
	k := genArchiveKeys(t)
	records, leaves := sealSegments(t, store, k, dpID, sourceType, values)
	shardObj, shardSHA := sealShard(t, store, k, records)
	buildRootManifest(t, store, k, dpID, records, leaves, shardObj, shardSHA)
	sealRunlog(t, store, k, dpID, len(records))
	return k.bgPriv, k.verifier, k.runID
}

func genKEM(t *testing.T) (*crypto.HybridKEMPrivate, *crypto.HybridKEMPublic) {
	t.Helper()
	priv, pub, err := crypto.GenerateHybridKEM()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatal(err)
	}
	return b
}

// writeStoreToDir spills an in-memory archive to a directory so tests can read it back
// through the real DirStore (which streams sealed objects), rather than through a map.
func writeStoreToDir(t *testing.T, store memStore, dir string) {
	t.Helper()
	for key, b := range store {
		p := filepath.Join(dir, filepath.FromSlash(key))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
