package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/source"
	"github.com/downpipes-io/downpipe/internal/spec"
)

func cmdSelftest(args []string) error {
	fs := flag.NewFlagSet("selftest", flag.ContinueOnError)
	keep := fs.String("keep", "", "write the sample archive and keys to this directory and keep them")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	dir := *keep
	if dir == "" {
		var err error
		dir, err = os.MkdirTemp("", "downpipe-selftest-*")
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(dir) }()
	} else if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	value := []byte("downpipe selftest: recover me without Cloudflare and without the vendor")
	identity, verifier, runID, err := buildSelftestArchive(dir, value)
	if err != nil {
		return fmt.Errorf("build archive: %w", err)
	}

	r, err := format.Open(source.NewDirStore(dir), runID, identity, verifier, format.Options{})
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer r.Close() // wipe the run master when this command is done with it
	recs := r.Records()
	if len(recs) != 1 {
		return fmt.Errorf("expected 1 record, got %d", len(recs))
	}
	got, err := r.RestoreRecord(recs[0])
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	if !bytes.Equal(got, value) {
		return fmt.Errorf("recovered value does not match the original")
	}

	fmt.Println("selftest OK")
	fmt.Printf("  sealed a value with the CNSA 2.0 hybrid envelope, then recovered %d byte(s)\n", len(got))
	fmt.Println("  from disk using only the offline break-glass identity and the pinned signer.")
	fmt.Printf("  recovered: %q\n", string(got))

	if *keep != "" {
		if err := reportSelftest(dir, runID, identity, verifier); err != nil {
			return err
		}
	}
	return nil
}

// reportSelftest writes the kept identity and signer files alongside the sample
// archive and prints the inspect and verify commands the operator can run against it.
func reportSelftest(dir, runID string, identity *crypto.HybridKEMPrivate, verifier *crypto.HybridVerifier) error {
	idFile := filepath.Join(dir, "identity.key")
	signerFile := filepath.Join(dir, "signer.pub")
	if err := writeKeyFile(idFile, labelIdentity, crypto.MarshalKEMPrivate(identity)); err != nil {
		return err
	}
	if err := writeKeyFile(signerFile, labelSignerPublic, crypto.MarshalVerifier(verifier)); err != nil {
		return err
	}
	fmt.Printf("\nkept the archive and keys in %s\n", dir)
	// The identity is a PRIVATE key and it has just been written INSIDE the archive tree, which is
	// the one place a break-glass key must never live: an archive tree is what gets copied to a
	// destination bucket, and a bucket holding both the sealed data and the key that opens it is
	// not sealed at all. keygen says this about the directory it writes; --keep said nothing while
	// doing something worse, so it says it here.
	fmt.Printf("%s is a PRIVATE key and it is inside the archive tree. This is a throwaway sample:\ndelete it when you are done, and never copy this tree to a destination bucket, which would\nput the key that opens the data next to the data.\n", idFile)
	fmt.Printf("try:\n  downpipe inspect --archive %s --run %s\n", dir, runID)
	fmt.Printf("  downpipe verify  --archive %s --run %s --identity %s --signer %s\n", dir, runID, idFile, signerFile)
	return nil
}

// buildSelftestArchive assembles a one-record archive on disk under dir with the public
// format and crypto API, and returns the break-glass identity and signer verifier
// needed to recover it. This is a self-test writer, not the production engine.
func buildSelftestArchive(dir string, value []byte) (*crypto.HybridKEMPrivate, *crypto.HybridVerifier, string, error) {
	// Key generation (SPEC.md 4): the two recipient KEM pairs and the hybrid signer.
	bgPriv, bgPub, opPub, signer, verifier, err := generateSelftestKeys()
	if err != nil {
		return nil, nil, "", err
	}

	// Per-run master and the derived master key. mk is derived from the master and the
	// decoded run id bytes, and every later key (segment, manifest wrap, name MAC) hangs
	// off it.
	master, err := randomBytes(32)
	if err != nil {
		return nil, nil, "", err
	}
	runID, runIDBytes, err := newSelftestRunID()
	if err != nil {
		return nil, nil, "", err
	}
	mk := crypto.DeriveMK(master, runIDBytes)

	// Segment sealing (SPEC.md 7.2) and the shard manifest (SPEC.md 6.4) over the one
	// record. segNonce and shardNonce are independent per-object nonces.
	rec, shardObj, shardSHA, err := buildSelftestSegmentAndShard(dir, master, runID, runIDBytes, mk, value)
	if err != nil {
		return nil, nil, "", err
	}

	// Root signing (SPEC.md 8), the RUNLOG freshness anchor (SPEC.md 10) and the
	// recovery bundle (SPEC.md 9).
	if err := writeSelftestRootManifest(dir, master, runID, runIDBytes, rec, shardObj, shardSHA, bgPub, opPub, signer, verifier); err != nil {
		return nil, nil, "", err
	}
	if err := writeSelftestRunlog(dir, runID, signer); err != nil {
		return nil, nil, "", err
	}
	if err := writeSelftestBundle(dir, signer); err != nil {
		return nil, nil, "", err
	}
	return bgPriv, verifier, runID, nil
}

// newSelftestRunID generates a fresh ULID run id and returns it both as the encoded
// string and as its decoded bytes, which the key-derivation steps need.
func newSelftestRunID() (string, []byte, error) {
	runRaw, err := randomBytes(16)
	if err != nil {
		return "", nil, err
	}
	runID, err := spec.EncodeULID(runRaw)
	if err != nil {
		return "", nil, err
	}
	runIDBytes, err := spec.DecodeULID(runID)
	if err != nil {
		return "", nil, err
	}
	return runID, runIDBytes, nil
}

// buildSelftestSegmentAndShard seals the single record's value into a segment, builds the
// shard record over it, seals and writes the shard manifest, and returns the completed
// record (with its hash), the shard object key and the shard's SHA-384.
func buildSelftestSegmentAndShard(dir string, master []byte, runID string, runIDBytes, mk []byte, value []byte) (spec.ShardRecord, string, string, error) {
	segNonce, err := randomBytes(spec.StreamNonceSize)
	if err != nil {
		return spec.ShardRecord{}, "", "", err
	}
	segID, segBytes, err := crypto.SealNonSecretSegment(master, "dp_selftest", spec.AddrSingleNonSecret, spec.CodecNone, value, segNonce)
	if err != nil {
		return spec.ShardRecord{}, "", "", err
	}
	segHex := crypto.SegIDHex(segID)
	segObj := "seg/" + segHex[:2] + "/" + segHex + ".seg"
	if err := writeObject(dir, segObj, segBytes); err != nil {
		return spec.ShardRecord{}, "", "", err
	}

	keyNameHash := hex.EncodeToString(crypto.NameMAC(crypto.DeriveNameMACKey(mk, runIDBytes), "kv", "greeting"))
	rec := spec.ShardRecord{
		SourceType: "kv", Name: "greeting", KeyNameHash: keyNameHash,
		RecordID:      "r000000000000001",
		PlaintextSize: int64(len(value)), PlaintextSHA: format.SHA384Hex(value),
		Codec:    spec.CodecNameNone,
		Segments: []spec.Segment{{Object: segObj, ChunkRange: [2]int{0, 1}}},
	}
	rhBytes, err := format.RecordHashOf(rec)
	if err != nil {
		return spec.ShardRecord{}, "", "", err
	}
	rec.RecordHash = hex.EncodeToString(rhBytes)

	shardNonce, err := randomBytes(spec.StreamNonceSize)
	if err != nil {
		return spec.ShardRecord{}, "", "", err
	}
	preamble := spec.ShardPreamble{
		FormatVersion: spec.Version, RunID: runID, ShardID: "00000",
		ManifestCodec: spec.CodecNameNone,
		Downpipe:      spec.PreambleDownpipe{Name: "selftest", Cadence: "0 * * * *"},
		Source:        spec.Source{Type: "kv", NamespaceID: "selftest"},
		Window:        spec.Window{Start: "2026-06-06T12:00:00.000Z", End: "2026-06-06T12:00:01.000Z"},
		Consistency:   "crawl",
	}
	shardBytes, shardSHA, err := format.SealShard(preamble, []spec.ShardRecord{rec}, crypto.DeriveManifestWrapKey(mk, runIDBytes, "00000"), shardNonce)
	if err != nil {
		return spec.ShardRecord{}, "", "", err
	}
	shardObj := "run/" + runID + "/manifest/00000.dpe"
	if err := writeObject(dir, shardObj, shardBytes); err != nil {
		return spec.ShardRecord{}, "", "", err
	}
	return rec, shardObj, shardSHA, nil
}

// writeSelftestRootManifest seals the master to the two recipients, assembles the signed
// root manifest over the one shard, and writes the canonical manifest and its detached
// signature.
func writeSelftestRootManifest(dir string, master []byte, runID string, runIDBytes []byte, rec spec.ShardRecord, shardObj, shardSHA string, bgPub, opPub *crypto.HybridKEMPublic, signer *crypto.HybridSigner, verifier *crypto.HybridVerifier) error {
	kc := crypto.KeyCommitment(master, runIDBytes)
	wraps, err := crypto.SealToRecipients([32]byte(master), []*crypto.HybridKEMPublic{bgPub, opPub}, kc, rand.Reader)
	if err != nil {
		return err
	}
	capsule := make([]spec.CapsuleWrap, len(wraps))
	for i, w := range wraps {
		capsule[i] = spec.CapsuleWrap{Fingerprint: w.Fingerprint, KEMCiphertext: format.B64Encode(w.KEMCiphertext), Sealed: format.B64Encode(w.Sealed)}
	}
	recipients := []spec.Recipient{
		{Fingerprint: crypto.RecipientFingerprint(bgPub), Role: "break-glass", X25519: format.B64Encode(bgPub.X25519.Bytes()), MLKEM: format.B64Encode(bgPub.MLKEM.Bytes())},
		{Fingerprint: crypto.RecipientFingerprint(opPub), Role: "operational", X25519: format.B64Encode(opPub.X25519.Bytes()), MLKEM: format.B64Encode(opPub.MLKEM.Bytes())},
	}
	rhRaw, err := hex.DecodeString(rec.RecordHash)
	if err != nil {
		return err
	}

	root := &spec.RootManifest{
		FormatVersion: spec.Version, RunID: runID,
		CreatedAt:  "2026-06-06T12:00:01.000Z",
		DownpipeID: "dp_selftest",
		Envelope:   spec.Envelope{AEAD: "AES-256-GCM", KEM: "X25519+ML-KEM-1024", Signature: "Ed25519+ML-DSA-87", KDF: "HKDF-SHA-384", ChunkSize: spec.ChunkSize, Codec: spec.CodecNameNone},
		Recipients: recipients, MasterCapsule: capsule,
		RecipientSetHash:    hex.EncodeToString(crypto.RecipientSetHash([]*crypto.HybridKEMPublic{bgPub, opPub})),
		KeyCommitment:       hex.EncodeToString(kc),
		BreakGlassPresent:   true,
		Shards:              []spec.ShardRef{{ID: "00000", Object: shardObj, SHA384: shardSHA}},
		ShardCount:          1,
		DeclaredRecordCount: 1,
		MerkleRoot:          hex.EncodeToString(format.MerkleRoot([][]byte{rhRaw})),
		Freshness:           spec.Freshness{PrevRunID: nil, RunlogIndex: 1},
		// The real section-11.4 fingerprint of the signer that signs this manifest, not a
		// placeholder. This is the archive an operator gets from selftest --keep, so it is the
		// one they practise on: a stand-in here would print in inspect as a signer fingerprint
		// that matches no key file and no recovery sheet, teaching the wrong lesson on the
		// exact comparison a real recovery turns on.
		SigningKeyFingerprint: crypto.SignerFingerprint(verifier),
	}
	canonical, sig, err := format.SignRoot(root, signer)
	if err != nil {
		return err
	}
	if err := writeObject(dir, "run/"+runID+"/root.manifest.json", canonical); err != nil {
		return err
	}
	return writeObject(dir, "run/"+runID+"/root.manifest.json.sig", []byte(format.B64Encode(sig)))
}

// generateSelftestKeys mints the three key pairs the self-test archive uses: the
// break-glass and operational recipient KEM pairs and the hybrid signer. It returns the
// break-glass private key, the two recipient public keys, and the signer and its verifier.
func generateSelftestKeys() (bgPriv *crypto.HybridKEMPrivate, bgPub, opPub *crypto.HybridKEMPublic, signer *crypto.HybridSigner, verifier *crypto.HybridVerifier, err error) {
	bgPriv, bgPub, err = crypto.GenerateHybridKEM()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	if _, opPub, err = crypto.GenerateHybridKEM(); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	if signer, verifier, err = crypto.GenerateHybridSigner(); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return bgPriv, bgPub, opPub, signer, verifier, nil
}

// writeSelftestRunlog writes the signed RUNLOG freshness anchor (SPEC.md 10): one active
// entry for this run, index 1 with no predecessor, with a detached signature.
func writeSelftestRunlog(dir, runID string, signer *crypto.HybridSigner) error {
	runlogBytes, err := format.MarshalRunlog([]spec.RunlogEntry{{
		Index: 1, RunID: runID, DownpipeID: "dp_selftest",
		Time: "2026-06-06T12:00:01.000Z", RecordCount: 1, PrevRunID: nil, Status: "active",
	}})
	if err != nil {
		return err
	}
	runlogSig, err := signer.Sign(runlogBytes)
	if err != nil {
		return err
	}
	if err := writeObject(dir, "_RECOVERY/RUNLOG", runlogBytes); err != nil {
		return err
	}
	return writeObject(dir, "_RECOVERY/RUNLOG.sig", []byte(format.B64Encode(runlogSig)))
}

// writeSelftestBundle writes the recovery bundle's versioned, signed instructions
// (SPEC.md 9): a versioned FORMAT.md pointer and RECOVER.md, with a signed SHA384SUMS. It also
// writes the signer public key as signer.pub (SPEC.md 9.1), as the engine does, so the selftest
// archive can be recovered with --signer-fingerprint exactly as a real one can.
func writeSelftestBundle(dir string, signer *crypto.HybridSigner) error {
	verifier := signer.Verifier()
	bundle := map[string][]byte{
		"FORMAT.md": []byte("# downpipe/0.1.0 archive format\n\nThis is a versioned pointer, not the full specification. Recover with the destination bucket bytes, your offline break-glass key, the signer fingerprint from your recovery sheet (or signer.pub from your recovery kit), and a conformant reader of the downpipe/0.1.0 format: use the open-source MIT downpipe tool or build a clean-room reader from docs/format/SPEC.md and the conformance vectors in that project. Neither Cloudflare nor the vendor is involved.\n"),
		// Kept in step with the ENGINE's RECOVER_MD (engine src/format/bundle.ts). The two are separate
		// copies because they are separate repositories and the bundle CONTENT is not normative (each
		// archive verifies its bundle against the SHA384SUMS written in the same run, so the two never need
		// to agree byte for byte). They should still say the same thing: this is the text a customer reads
		// mid-recovery, and a selftest that demonstrates different instructions from the ones real archives
		// carry is teaching the wrong recovery.
		"RECOVER.md": []byte(selftestRecoverMD),
		"signer.pub": []byte(keyFileLine(labelSignerPublic, crypto.MarshalVerifier(verifier))),
	}
	return format.WriteBundle(func(key string, b []byte) error { return writeObject(dir, key, b) }, bundle, signer)
}

// selftestRecoverMD is the selftest archive's RECOVER.md. See writeSelftestBundle for why it is a copy.
const selftestRecoverMD = "# Recovering this archive\n\n" +
	"You need the destination bucket and your offline break-glass identity. You also need to pin the operator signer that signed this archive. Restore and verify refuse to start without a pinned signer. The recovery involves neither Cloudflare nor the vendor.\n\n" +
	"If you do not have the run id to hand, ask the archive. This needs no key of any kind and lists every run the archive holds:\n\n" +
	"    downpipe keys --which --archive <dir>\n\n" +
	"This directory holds signer.pub, the operator signer public key. Anyone who can write to the bucket can replace it, so the reader does not trust it alone. Pass the signer fingerprint from your printed recovery sheet with --signer-fingerprint. The reader uses the copy in this directory only if its fingerprint equals that value:\n\n" +
	"    downpipe restore --archive <dir> --run <runId> --identity identity.key \\\n" +
	"      --signer-fingerprint <signerFingerprint> --out <dir> --apply\n\n" +
	"If you hold signer.pub from your recovery kit, pass it with --signer instead. Do this also for a run sealed before a signer rotation, because this directory holds only the current signer's copy:\n\n" +
	"    downpipe restore --archive <dir> --run <runId> --identity identity.key \\\n" +
	"      --signer signer.pub --out <dir> --apply\n\n" +
	"Without --apply that command plans the restore and writes nothing, which is the safe way to look at an archive before you commit to it. With --apply the recovered records are written under --out.\n\n" +
	"If your reader rejects --signer-fingerprint as an unknown flag, check the copy in this directory yourself. Run downpipe keys --fingerprint --signer with the path to this signer.pub, and compare the fingerprint it prints with your sheet. If they match, pass that file with --signer.\n\n" +
	"If your break-glass key is held as an M-of-N custody quorum rather than as a single file, give the shares to the same command instead of --identity. Pass one --share for each custodian your quorum requires, from any M of the N; they are combined in memory for that one command and wiped, so no complete key is written to disk:\n\n" +
	"    downpipe restore --archive <dir> --run <runId> --signer-fingerprint <signerFingerprint> --out <dir> --apply \\\n" +
	"      --share share-1.txt --share share-2.txt --share share-3.txt --envelope wrapped-identity.txt\n\n" +
	"If a signature check fails, you can add --allow-unverified to the same restore command. This flag skips only the signature checks and the RUNLOG freshness check. The reader still checks the manifests and the record count, and it stops if one of these checks fails. It writes each record that decrypts and matches its hash, and it reports each record that fails. Then it exits with code 2 and the message \"restored but unverified\". This is not a verified restore, because the reader cannot prove that the run is genuine. If you add --receipt <file>, the receipt records the mode allow-unverified and the signature result. The flag does not replace a pinned signer or your break-glass key.\n\n" +
	"The break-glass private key is the only universal way to recover, and it needs a pinned signer: the signer fingerprint on your recovery sheet, or signer.pub from your kit. The format is specified in FORMAT.md and pinned by the conformance vectors it references.\n"

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

func writeObject(baseDir, key string, b []byte) error {
	p := filepath.Join(baseDir, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o644)
}
