package format

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// buildMultiShardArchive seals nrec kv records, partitioned into nshard contiguous shards,
// into a fresh store and signs the root over all shards, so the streaming reader's
// shard-walk (and the byte-identical Merkle root across many shards) is exercised on a real
// multi-shard archive rather than the single-shard fixture buildArchiveSpec produces. It
// returns the store, the break-glass identity and the operator verifier. Records are named
// in already-canonical order (kv, ascending name) so input order is canonical order.
func buildMultiShardArchive(t *testing.T, dpID string, nrec, nshard int) (memStore, *crypto.HybridKEMPrivate, *crypto.HybridVerifier, *crypto.HybridSigner) {
	t.Helper()
	if nshard < 1 || nrec < 0 || nshard > nrec && nrec > 0 {
		t.Fatalf("bad fixture shape: nrec=%d nshard=%d", nrec, nshard)
	}
	store := memStore{}
	bgPriv, bgPub := newKEM(t)
	_, opPub := newKEM(t)
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	master := fixedMaster()
	nonce := fixedNonce()
	runID := vecRunID
	runIDBytes, err := spec.DecodeULID(runID)
	if err != nil {
		t.Fatal(err)
	}
	mk := crypto.DeriveMK(master, runIDBytes)

	// Build every record in canonical (kv, ascending name) order with a single non-secret
	// codec=none segment, the same record shape sealRecord's default branch builds.
	recs := make([]spec.ShardRecord, nrec)
	for i := 0; i < nrec; i++ {
		name := fmt.Sprintf("key%06d", i)
		value := []byte(fmt.Sprintf("value-for-%s-%d", name, i))
		segID, segBytes, serr := crypto.SealNonSecretSegment(master, dpID, spec.AddrSingleNonSecret, spec.CodecNone, value, nonce)
		if serr != nil {
			t.Fatal(serr)
		}
		obj := segObject(crypto.SegIDHex(segID))
		store[obj] = segBytes
		knh := hex.EncodeToString(crypto.NameMAC(crypto.DeriveNameMACKey(mk, runIDBytes), "kv", name))
		rec := spec.ShardRecord{
			SourceType: "kv", Name: name, KeyNameHash: knh, RecordID: fmt.Sprintf("r%015d", i),
			PlaintextSize: int64(len(value)), PlaintextSHA: SHA384Hex(value),
			Codec: spec.CodecNameNone, Segments: []spec.Segment{{Object: obj, ChunkRange: [2]int{0, streamChunkCount(len(value))}}},
		}
		rh, herr := RecordHashOf(rec)
		if herr != nil {
			t.Fatal(herr)
		}
		rec.RecordHash = hex.EncodeToString(rh)
		recs[i] = rec
	}

	// Partition into nshard contiguous shards and seal each. The Merkle root is over ALL
	// record hashes in canonical order, independent of how they are grouped into shards.
	shardRefs := make([]spec.ShardRef, 0, nshard)
	per := (nrec + nshard - 1) / nshard
	if per < 1 {
		per = 1
	}
	leaves := make([][]byte, 0, nrec)
	for _, rec := range recs {
		rh, _ := hex.DecodeString(rec.RecordHash)
		leaves = append(leaves, rh)
	}
	for s := 0; s < nshard; s++ {
		lo := s * per
		if lo > nrec {
			lo = nrec
		}
		hi := lo + per
		if hi > nrec {
			hi = nrec
		}
		shardID := fmt.Sprintf("%05d", s)
		preamble := spec.ShardPreamble{
			FormatVersion: spec.Version, RunID: runID, ShardID: shardID,
			ManifestCodec: spec.CodecNameNone,
			Downpipe:      spec.PreambleDownpipe{Name: "test", Cadence: "0 * * * *"},
			Source:        spec.Source{Type: "kv", NamespaceID: "ns1"},
			Window:        spec.Window{Start: "2026-06-06T12:00:00.000Z", End: "2026-06-06T12:00:30.000Z"},
			Consistency:   "crawl",
		}
		shardBytes, shardSHA, serr := SealShard(preamble, recs[lo:hi], crypto.DeriveManifestWrapKey(mk, runIDBytes, shardID), nonce)
		if serr != nil {
			t.Fatal(serr)
		}
		obj := runKey(runID, "manifest/"+shardID+".dpe")
		store[obj] = shardBytes
		shardRefs = append(shardRefs, spec.ShardRef{ID: shardID, Object: obj, SHA384: shardSHA})
	}

	kc := crypto.KeyCommitment(master, runIDBytes)
	recipientPubs := []*crypto.HybridKEMPublic{bgPub, opPub}
	wraps, err := crypto.SealToRecipients([32]byte(master), recipientPubs, kc, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capsule := make([]spec.CapsuleWrap, len(wraps))
	for i, w := range wraps {
		capsule[i] = spec.CapsuleWrap{Fingerprint: w.Fingerprint, KEMCiphertext: B64Encode(w.KEMCiphertext), Sealed: B64Encode(w.Sealed)}
	}
	root := &spec.RootManifest{
		FormatVersion: spec.Version, RunID: runID, CreatedAt: "2026-06-06T12:00:30.000Z", DownpipeID: dpID,
		Envelope:              spec.Envelope{AEAD: "AES-256-GCM", KEM: "X25519+ML-KEM-1024", Signature: "Ed25519+ML-DSA-87", KDF: "HKDF-SHA-384", ChunkSize: spec.ChunkSize, Codec: spec.CodecNameNone},
		Recipients:            []spec.Recipient{recipientJSON(bgPub, "break-glass"), recipientJSON(opPub, "operational")},
		MasterCapsule:         capsule,
		RecipientSetHash:      hex.EncodeToString(crypto.RecipientSetHash(recipientPubs)),
		KeyCommitment:         hex.EncodeToString(kc),
		BreakGlassPresent:     true,
		Shards:                shardRefs,
		ShardCount:            len(shardRefs),
		DeclaredRecordCount:   int64(nrec),
		MerkleRoot:            hex.EncodeToString(MerkleRoot(leaves)),
		Freshness:             spec.Freshness{PrevRunID: nil, RunlogIndex: 1},
		SigningKeyFingerprint: crypto.SignerFingerprint(verifier),
	}
	canonical, sig, err := SignRoot(root, signer)
	if err != nil {
		t.Fatal(err)
	}
	store[runKey(runID, "root.manifest.json")] = canonical
	store[runKey(runID, "root.manifest.json.sig")] = []byte(B64Encode(sig))
	writeRunlog(t, store, signer, dpID, []string{runID})
	writeRecoveryBundle(t, store, signer)
	return store, bgPriv, verifier, signer
}

// TestStreamOpenByteIdenticalRoot is the archive-level keystone proof: the streaming
// reader must recompute the SAME signed Merkle root the load-all reader authenticates. It
// opens one archive both ways and asserts (1) the streaming accumulator over the records'
// hashes equals the signed root, (2) the load-all MerkleRoot equals the signed root, and (3)
// both readers expose the same root string. StreamOpen also only RETURNS successfully when
// its internal streamed root matched the signed root, so a green StreamOpen is itself the
// proof; these explicit checks make the byte-identity unmistakable.
func TestStreamOpenByteIdenticalRoot(t *testing.T) {
	store, bgPriv, verifier, _ := buildArchiveSpec(t, vectorSpec{
		dpID: "dp_stream_root",
		records: []recordSpec{
			{name: "alpha", value: []byte("one"), srcType: "kv"},
			{name: "bravo", value: []byte("two"), srcType: "kv"},
			{name: "charlie", value: []byte("three"), srcType: "kv"},
			{name: "delta", value: bytes.Repeat([]byte("d"), 4096), srcType: "r2", segments: 2},
		},
	})

	open, err := Open(store, vecRunID, bgPriv, verifier, Options{})
	if err != nil {
		t.Fatalf("load-all Open: %v", err)
	}
	sr, err := StreamOpen(store, vecRunID, bgPriv, verifier, Options{})
	if err != nil {
		t.Fatalf("StreamOpen must verify the same archive Open does: %v", err)
	}

	if sr.RecordCount() != open.RecordCount() {
		t.Fatalf("streaming record count %d != load-all %d", sr.RecordCount(), open.RecordCount())
	}

	signedRoot, err := hex.DecodeString(open.Root().MerkleRoot)
	if err != nil {
		t.Fatal(err)
	}
	var acc MerkleAccumulator
	leaves := make([][]byte, 0, len(open.Records()))
	for _, rec := range open.Records() {
		rh, derr := hex.DecodeString(rec.RecordHash)
		if derr != nil {
			t.Fatal(derr)
		}
		leaves = append(leaves, rh)
		acc.Push(rh)
	}
	if !bytes.Equal(acc.Root(), signedRoot) {
		t.Fatalf("streaming accumulator root %x != signed root %x", acc.Root(), signedRoot)
	}
	if !bytes.Equal(MerkleRoot(leaves), signedRoot) {
		t.Fatalf("load-all MerkleRoot %x != signed root %x", MerkleRoot(leaves), signedRoot)
	}
	if open.Root().MerkleRoot != sr.Root().MerkleRoot {
		t.Fatalf("the two readers expose different root strings: %q vs %q", open.Root().MerkleRoot, sr.Root().MerkleRoot)
	}
}

// TestStreamOpenMultiShardYieldsSameRecords proves the streaming shard-walk reads a
// multi-shard archive in the exact canonical record order the load-all reader produces, so a
// streaming restore writes the same records as a load-all restore, and that the signed root
// (over hashes spanning many shards) verifies streaming. This is the multi-shard exercise the
// single-shard fixture cannot give.
func TestStreamOpenMultiShardYieldsSameRecords(t *testing.T) {
	for _, shape := range []struct{ nrec, nshard int }{{0, 1}, {1, 1}, {7, 3}, {64, 9}, {101, 101}, {1500, 150}} {
		name := fmt.Sprintf("nrec=%d/nshard=%d", shape.nrec, shape.nshard)
		t.Run(name, func(t *testing.T) {
			store, bgPriv, verifier, _ := buildMultiShardArchive(t, "dp_multishard", shape.nrec, shape.nshard)

			open, err := Open(store, vecRunID, bgPriv, verifier, Options{})
			if err != nil {
				t.Fatalf("load-all Open: %v", err)
			}
			sr, err := StreamOpen(store, vecRunID, bgPriv, verifier, Options{})
			if err != nil {
				t.Fatalf("StreamOpen: %v", err)
			}
			if sr.RecordCount() != int64(shape.nrec) {
				t.Fatalf("streaming count %d != %d", sr.RecordCount(), shape.nrec)
			}

			want := open.Records()
			var got []spec.ShardRecord
			if err := sr.EachRecord(func(rec spec.ShardRecord) error {
				got = append(got, rec)
				return nil
			}); err != nil {
				t.Fatalf("EachRecord: %v", err)
			}
			if len(got) != len(want) {
				t.Fatalf("EachRecord yielded %d records, Open has %d", len(got), len(want))
			}
			for i := range want {
				if got[i].RecordID != want[i].RecordID || got[i].Name != want[i].Name || got[i].RecordHash != want[i].RecordHash {
					t.Fatalf("record %d differs: stream %s/%s vs load-all %s/%s", i, got[i].RecordID, got[i].Name, want[i].RecordID, want[i].Name)
				}
			}
		})
	}
}

// TestStreamOpenFailsClosed proves the streaming verify fails closed exactly as Open does on
// a tampered Merkle root and a missing shard: a streaming restore must never proceed past a
// structural break. The corruption is introduced after a clean build so the negative is
// precise.
func TestStreamOpenFailsClosed(t *testing.T) {
	t.Run("tampered merkle root", func(t *testing.T) {
		store, bgPriv, verifier, signer := buildMultiShardArchive(t, "dp_badroot", 5, 2)
		// Alter the signed merkleRoot and RE-SIGN with the same signer, so the signature gate
		// passes and the streaming accumulator (over the real records) is what catches the
		// mismatch: a structural ExitUnverified, never a silent accept.
		rootKey := runKey(vecRunID, "root.manifest.json")
		root, err := ParseRoot(store[rootKey])
		if err != nil {
			t.Fatal(err)
		}
		flipped := []rune(root.MerkleRoot)
		if flipped[0] == '0' {
			flipped[0] = '1'
		} else {
			flipped[0] = '0'
		}
		root.MerkleRoot = string(flipped)
		canonical, sig, err := SignRoot(root, signer)
		if err != nil {
			t.Fatal(err)
		}
		store[rootKey] = canonical
		store[runKey(vecRunID, "root.manifest.json.sig")] = []byte(B64Encode(sig))

		_, err = StreamOpen(store, vecRunID, bgPriv, verifier, Options{})
		if err == nil {
			t.Fatal("StreamOpen must reject a run whose streamed Merkle root differs from the signed root")
		}
		var ee *ExitError
		if !errors.As(err, &ee) || ee.Code != ExitUnverified {
			t.Fatalf("a Merkle-root mismatch must be ExitUnverified, got %v", err)
		}
	})
	t.Run("flipped shard byte", func(t *testing.T) {
		store, bgPriv, verifier, _ := buildMultiShardArchive(t, "dp_flipshard", 5, 2)
		shardKey := runKey(vecRunID, "manifest/00000.dpe")
		store[shardKey] = bytes.Clone(store[shardKey])
		store[shardKey][len(store[shardKey])-1] ^= 0x01
		if _, err := StreamOpen(store, vecRunID, bgPriv, verifier, Options{}); err == nil {
			t.Fatal("StreamOpen must reject a shard whose bytes do not match the signed SHA-384")
		}
	})
	t.Run("missing shard", func(t *testing.T) {
		store, bgPriv, verifier, _ := buildMultiShardArchive(t, "dp_missing", 6, 3)
		delete(store, runKey(vecRunID, "manifest/00001.dpe"))
		_, err := StreamOpen(store, vecRunID, bgPriv, verifier, Options{})
		if err == nil {
			t.Fatal("StreamOpen must fail when a signed shard is absent")
		}
		var ee *ExitError
		if !errors.As(err, &ee) || ee.Code != ExitIncomplete {
			t.Fatalf("a missing shard must be ExitIncomplete, got %v", err)
		}
	})
}
