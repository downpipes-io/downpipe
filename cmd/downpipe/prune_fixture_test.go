package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// A MULTI-RUN ARCHIVE, BECAUSE A ONE-RUN ARCHIVE CANNOT TEST A PRUNE.
//
// buildSelftestArchive writes exactly one run, which is right for what it is for: a customer proving they
// can recover without the vendor. It is the wrong fixture for the prune report. With one run and any
// sensible --keep, the keep window excludes nothing, so every count the report prints is legitimately
// zero, and an assertion over those numbers would be asserting 0 == 0 + 0. That is why the report's
// counts went unpinned while its labels were pinned: there was nothing to pin them to.
//
// This writer produces several runs across more than one downpipe, with a chosen number of records each,
// so the keep window genuinely excludes some of them and every count the operator reads is non-zero AND
// different from its neighbours. The differences are the point. A fixture where two of the counts happen
// to agree cannot tell an assertion which number landed in which slot, so a report that transposed two
// lines would still pass.
//
// It duplicates a little of selftest.go rather than reshaping the production writer to take test
// parameters. The archive it builds is checked by format.Open on every run, so a fixture that drifted
// away from what the real writer produces fails loudly here rather than quietly asserting against a
// shape nothing else accepts.

// fixtureRun describes one run to write. downpipeID and index place it in the RUNLOG; records is how many
// records, and therefore how many distinct segment objects, the run owns.
type fixtureRun struct {
	downpipeID string
	index      int64
	records    int
	// formatVersion overrides the root manifest's formatVersion for this run, so a fixture can hold a
	// run at a version this reader does not implement alongside runs it does. Empty means spec.Version.
	//
	// The root alone is rewritten and the root is re-signed, which is exactly what the conformance
	// vector unknown-major does: the version gate fires before anything reads the body (SPEC.md 13,
	// 14.3), so the shard preamble's own version never comes into it and a fixture that also rewrote
	// the preamble would be testing a second refusal rather than this one.
	formatVersion string
	// runID is filled in by buildMultiRunArchive.
	runID string
}

// runTreeObjectsPerRun is how many objects one run's tree holds under run/<id>/: the single shard
// manifest, the root manifest, and its detached signature. Named because the expected run-tree count in
// the report tests is derived from it rather than copied from a run of the code being tested.
const runTreeObjectsPerRun = 3

// buildMultiRunArchive writes the given runs into dir under one break-glass identity and one signer, with
// a single signed RUNLOG covering them all. Runs must be listed in ascending index order; each downpipe's
// entries are chained by prevRunId in that order, which is what the reader's chain-anomaly check requires.
//
// Every run is written as ACTIVE. Nothing here marks a run superseded, so the partition under test is the
// one an operator actually exercises: --keep applied to a live log.
func buildMultiRunArchive(t *testing.T, dir string, runs []fixtureRun) (*crypto.HybridKEMPrivate, *crypto.HybridVerifier, []fixtureRun) {
	t.Helper()
	bgPriv, bgPub, opPub, signer, verifier, err := generateSelftestKeys()
	if err != nil {
		t.Fatalf("generate fixture keys: %v", err)
	}

	built := make([]fixtureRun, len(runs))
	copy(built, runs)

	// The last run written for each downpipe, so the next one chains to it.
	prevByDownpipe := map[string]string{}
	entries := make([]spec.RunlogEntry, 0, len(built))

	for i := range built {
		r := &built[i]
		if r.records < 1 {
			t.Fatalf("fixture run %d asks for %d records; a run with no records has no segments to prune", i, r.records)
		}
		runID, runIDBytes, err := newSelftestRunID()
		if err != nil {
			t.Fatalf("fixture run id: %v", err)
		}
		r.runID = runID

		master, err := randomBytes(32)
		if err != nil {
			t.Fatalf("fixture master: %v", err)
		}
		mk := crypto.DeriveMK(master, runIDBytes)

		recs := make([]spec.ShardRecord, 0, r.records)
		for n := 0; n < r.records; n++ {
			// The plaintext is unique per run and per record. Segment ids are content addressed off the
			// run master and the downpipe id, so two runs never share a segment here, but two records in
			// ONE run carrying identical bytes would collapse to one segment object and quietly reduce the
			// count this fixture exists to control.
			value := []byte(fmt.Sprintf("prune fixture %s record %d", runID, n))
			recs = append(recs, buildFixtureRecord(t, dir, master, r.downpipeID, runIDBytes, mk, n, value))
		}

		shardObj, shardSHA := sealFixtureShard(t, dir, r.downpipeID, runID, mk, runIDBytes, recs)

		var prev *string
		if p, ok := prevByDownpipe[r.downpipeID]; ok {
			prevCopy := p
			prev = &prevCopy
		}
		writeFixtureRoot(t, dir, fixtureRootArgs{
			master: master, runID: runID, runIDBytes: runIDBytes,
			downpipeID: r.downpipeID, records: recs,
			shardObj: shardObj, shardSHA: shardSHA,
			index: r.index, prevRunID: prev,
			bgPub: bgPub, opPub: opPub, signer: signer, verifier: verifier,
			formatVersion: r.formatVersion,
		})

		entries = append(entries, spec.RunlogEntry{
			Index: r.index, RunID: runID, DownpipeID: r.downpipeID,
			Time:        fmt.Sprintf("2026-06-%02dT12:00:01.000Z", 6+i),
			RecordCount: int64(len(recs)), PrevRunID: prev, Status: "active",
		})
		prevByDownpipe[r.downpipeID] = runID
	}

	runlogBytes, err := format.MarshalRunlog(entries)
	if err != nil {
		t.Fatalf("marshal fixture runlog: %v", err)
	}
	runlogSig, err := signer.Sign(runlogBytes)
	if err != nil {
		t.Fatalf("sign fixture runlog: %v", err)
	}
	if err := writeObject(dir, "_RECOVERY/RUNLOG", runlogBytes); err != nil {
		t.Fatalf("write fixture runlog: %v", err)
	}
	if err := writeObject(dir, "_RECOVERY/RUNLOG.sig", []byte(format.B64Encode(runlogSig))); err != nil {
		t.Fatalf("write fixture runlog signature: %v", err)
	}
	if err := writeSelftestBundle(dir, signer); err != nil {
		t.Fatalf("write fixture bundle: %v", err)
	}
	return bgPriv, verifier, built
}

// buildFixtureRecord seals one value into its own segment object and returns the completed shard record
// naming it.
func buildFixtureRecord(t *testing.T, dir string, master []byte, downpipeID string, runIDBytes, mk []byte, n int, value []byte) spec.ShardRecord {
	t.Helper()
	segNonce, err := randomBytes(spec.StreamNonceSize)
	if err != nil {
		t.Fatalf("segment nonce: %v", err)
	}
	segID, segBytes, err := crypto.SealNonSecretSegment(master, downpipeID, spec.AddrSingleNonSecret, spec.CodecNone, value, segNonce)
	if err != nil {
		t.Fatalf("seal segment: %v", err)
	}
	segHex := crypto.SegIDHex(segID)
	segObj := "seg/" + segHex[:2] + "/" + segHex + ".seg"
	if err := writeObject(dir, segObj, segBytes); err != nil {
		t.Fatalf("write segment: %v", err)
	}

	name := fmt.Sprintf("greeting-%d", n)
	rec := spec.ShardRecord{
		SourceType: "kv", Name: name,
		KeyNameHash:   hex.EncodeToString(crypto.NameMAC(crypto.DeriveNameMACKey(mk, runIDBytes), "kv", name)),
		RecordID:      fmt.Sprintf("r%015d", n+1),
		PlaintextSize: int64(len(value)), PlaintextSHA: format.SHA384Hex(value),
		Codec:    spec.CodecNameNone,
		Segments: []spec.Segment{{Object: segObj, ChunkRange: [2]int{0, 1}}},
	}
	rhBytes, err := format.RecordHashOf(rec)
	if err != nil {
		t.Fatalf("record hash: %v", err)
	}
	rec.RecordHash = hex.EncodeToString(rhBytes)
	return rec
}

// sealFixtureShard writes the run's single shard manifest over every record and returns its object key
// and SHA-384.
func sealFixtureShard(t *testing.T, dir, downpipeID, runID string, mk, runIDBytes []byte, recs []spec.ShardRecord) (string, string) {
	t.Helper()
	shardNonce, err := randomBytes(spec.StreamNonceSize)
	if err != nil {
		t.Fatalf("shard nonce: %v", err)
	}
	preamble := spec.ShardPreamble{
		FormatVersion: spec.Version, RunID: runID, ShardID: "00000",
		ManifestCodec: spec.CodecNameNone,
		Downpipe:      spec.PreambleDownpipe{Name: downpipeID, Cadence: "0 * * * *"},
		Source:        spec.Source{Type: "kv", NamespaceID: downpipeID},
		Window:        spec.Window{Start: "2026-06-06T12:00:00.000Z", End: "2026-06-06T12:00:01.000Z"},
		Consistency:   "crawl",
	}
	shardBytes, shardSHA, err := format.SealShard(preamble, recs, crypto.DeriveManifestWrapKey(mk, runIDBytes, "00000"), shardNonce)
	if err != nil {
		t.Fatalf("seal shard: %v", err)
	}
	shardObj := "run/" + runID + "/manifest/00000.dpe"
	if err := writeObject(dir, shardObj, shardBytes); err != nil {
		t.Fatalf("write shard: %v", err)
	}
	return shardObj, shardSHA
}

type fixtureRootArgs struct {
	master     []byte
	runID      string
	runIDBytes []byte
	downpipeID string
	records    []spec.ShardRecord
	shardObj   string
	shardSHA   string
	index      int64
	prevRunID  *string
	bgPub      *crypto.HybridKEMPublic
	opPub      *crypto.HybridKEMPublic
	signer     *crypto.HybridSigner
	verifier   *crypto.HybridVerifier
	// formatVersion overrides spec.Version in the root when non-empty.
	formatVersion string
}

// writeFixtureRoot seals the run master to the two recipients and writes the signed root manifest and its
// detached signature. It differs from writeSelftestRootManifest only in taking many records and a real
// freshness position, which is what a multi-run archive needs and a one-run self test does not.
func writeFixtureRoot(t *testing.T, dir string, a fixtureRootArgs) {
	t.Helper()
	kc := crypto.KeyCommitment(a.master, a.runIDBytes)
	wraps, err := crypto.SealToRecipients([32]byte(a.master), []*crypto.HybridKEMPublic{a.bgPub, a.opPub}, kc, rand.Reader)
	if err != nil {
		t.Fatalf("seal master to recipients: %v", err)
	}
	capsule := make([]spec.CapsuleWrap, len(wraps))
	for i, w := range wraps {
		capsule[i] = spec.CapsuleWrap{Fingerprint: w.Fingerprint, KEMCiphertext: format.B64Encode(w.KEMCiphertext), Sealed: format.B64Encode(w.Sealed)}
	}
	leaves := make([][]byte, len(a.records))
	for i, rec := range a.records {
		raw, derr := hex.DecodeString(rec.RecordHash)
		if derr != nil {
			t.Fatalf("decode record hash: %v", derr)
		}
		leaves[i] = raw
	}

	formatVersion := a.formatVersion
	if formatVersion == "" {
		formatVersion = spec.Version
	}
	root := &spec.RootManifest{
		FormatVersion: formatVersion, RunID: a.runID,
		CreatedAt:  "2026-06-06T12:00:01.000Z",
		DownpipeID: a.downpipeID,
		Envelope:   spec.Envelope{AEAD: "AES-256-GCM", KEM: "X25519+ML-KEM-1024", Signature: "Ed25519+ML-DSA-87", KDF: "HKDF-SHA-384", ChunkSize: spec.ChunkSize, Codec: spec.CodecNameNone},
		Recipients: []spec.Recipient{
			{Fingerprint: crypto.RecipientFingerprint(a.bgPub), Role: "break-glass", X25519: format.B64Encode(a.bgPub.X25519.Bytes()), MLKEM: format.B64Encode(a.bgPub.MLKEM.Bytes())},
			{Fingerprint: crypto.RecipientFingerprint(a.opPub), Role: "operational", X25519: format.B64Encode(a.opPub.X25519.Bytes()), MLKEM: format.B64Encode(a.opPub.MLKEM.Bytes())},
		},
		MasterCapsule:         capsule,
		RecipientSetHash:      hex.EncodeToString(crypto.RecipientSetHash([]*crypto.HybridKEMPublic{a.bgPub, a.opPub})),
		KeyCommitment:         hex.EncodeToString(kc),
		BreakGlassPresent:     true,
		Shards:                []spec.ShardRef{{ID: "00000", Object: a.shardObj, SHA384: a.shardSHA}},
		ShardCount:            1,
		DeclaredRecordCount:   int64(len(a.records)),
		MerkleRoot:            hex.EncodeToString(format.MerkleRoot(leaves)),
		Freshness:             spec.Freshness{PrevRunID: a.prevRunID, RunlogIndex: a.index},
		SigningKeyFingerprint: crypto.SignerFingerprint(a.verifier),
	}
	canonical, sig, err := format.SignRoot(root, a.signer)
	if err != nil {
		t.Fatalf("sign root: %v", err)
	}
	if err := writeObject(dir, "run/"+a.runID+"/root.manifest.json", canonical); err != nil {
		t.Fatalf("write root manifest: %v", err)
	}
	if err := writeObject(dir, "run/"+a.runID+"/root.manifest.json.sig", []byte(format.B64Encode(sig))); err != nil {
		t.Fatalf("write root signature: %v", err)
	}
}
