package format

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/mldsa"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/source"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// updateVectors regenerates the committed conformance corpus. Run:
//
//	go test ./internal/format -run TestConformance -update
//
// The capsule and signatures use fresh randomness, so a regeneration replaces the
// corpus wholesale; the committed corpus is a fixed snapshot a conformant reader (Go
// or, later, the Workers reader) must recover and reject exactly.
var updateVectors = flag.Bool("update", false, "regenerate the conformance vectors under testdata/vectors")

// updateOnly restricts -update to a comma-separated list of vector names: only those
// directories are regenerated and nothing is deleted, so adding a vector never re-cuts
// the rest of the corpus (regeneration draws fresh randomness, so a wholesale -update
// changes every archive vector's bytes).
var updateOnly = flag.String("update-only", "", "with -update: comma-separated vector names to regenerate; everything else is left untouched")

// vecRunID is the fixed run id used for every single-run vector; each vector lives in its
// own directory, so there is no collision. Two-run vectors add vecRunIDB.
const vecRunID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

// corpusVector is one generated conformance vector: a name, the archive spec that builds
// it (section 14.2 breadth), an optional tamper applied to the stored bytes after build
// (the negative corpus, section 14.3), and the expected reader outcome. The tamper sees
// the signer so it can re-sign an edited root where the spec requires a valid signature
// over a mutated field.
type corpusVector struct {
	name   string
	spec   vectorSpec
	tamper func(t *testing.T, dir string, signer *crypto.HybridSigner)
	expect vectorExpect
}

// vectorExpect is the expect.json contract a replay asserts. A positive vector restores
// every record in Records from the run RunID (default vecRunID); a negative vector fails
// at Phase ("open" or "restore") with ExitCode. Options projects the reader Options the
// vector needs (the stale and bundle gates). The label fields, when set, are asserted
// against the honest Outcome (read through an allow-* re-open for a negative). Also holds
// extra run checks for a two-run vector (for example dedup opening both runs).
type vectorExpect struct {
	Mode     string `json:"mode"`
	RunID    string `json:"runId,omitempty"`
	ExitCode int    `json:"exitCode,omitempty"`
	Phase    string `json:"phase,omitempty"`
	// RecordName, on a restore-phase negative, names the record whose restore must be
	// rejected. When absent the driver restores Records()[0], the right choice for a
	// single-record vector; a multi-record restore-negative sets it so the tampered
	// record is targeted by name rather than position.
	RecordName string         `json:"recordName,omitempty"`
	Records    []vectorRecord `json:"records,omitempty"`
	Options    *expectOptions `json:"options,omitempty"`
	Labels     *expectLabels  `json:"labels,omitempty"`
	// SegCount, when set, asserts the number of .seg objects in the archive: dedup stores
	// a shared non-secret value once, secrets never dedup. It is checked once per vector
	// (on the primary expectation), not per run.
	SegCount *int           `json:"segCount,omitempty"`
	Also     []vectorExpect `json:"also,omitempty"`
}

// expectOptions is the optional reader-Options projection in expect.json. Absent fields
// default to the zero Options (verified mode, no pins, no bundle check).
type expectOptions struct {
	AllowStale bool `json:"allowStale,omitempty"`
	// AllowUnverifiedRunlog is the separate, stronger acknowledgement a vector needs when
	// its RUNLOG cannot be verified or contradicts itself. allowStale is an age word and no
	// longer reaches those; the corpus must be able to express the difference or a vector
	// asserting an ACCEPTANCE on the integrity side could only be written by widening the
	// age word again.
	AllowUnverifiedRunlog bool  `json:"allowUnverifiedRunlog,omitempty"`
	AllowUnverified       bool  `json:"allowUnverified,omitempty"`
	MinRunlogIndex        int64 `json:"minRunlogIndex,omitempty"`
	CheckRecoveryBundle   bool  `json:"checkRecoveryBundle,omitempty"`
}

// expectLabels pins the honest Outcome labels a vector asserts (SPEC.md 8.5, 14.1). A nil
// pointer means do not assert that label; a set pointer is compared exactly.
type expectLabels struct {
	SignatureResult        *string `json:"signatureResult,omitempty"`
	BreakGlassVerified     *bool   `json:"breakGlassVerified,omitempty"`
	RecoveryBundleVerified *bool   `json:"recoveryBundleVerified,omitempty"`
}

type vectorRecord struct {
	Name     string `json:"name"`
	ValueB64 string `json:"valueB64"`
	// The optional annotative fields, asserted against the recovered record's metadata
	// when set, so the corpus PINS them cross-implementation (they are not record-hash
	// inputs, so only an explicit assertion protects them).
	Database         string `json:"database,omitempty"`
	Account          string `json:"account,omitempty"`
	IncompleteMarker string `json:"incompleteMarker,omitempty"`
}

// expectedVectorNames is the corpus floor: every vector directory this test requires
// under testdata/vectors before it will call the corpus non-vacuous. This mechanism does
// nearly all the real cross-implementation work behind the "held to agreement" claim, and
// a corpus that silently shrank — one directory deleted, its
// docs/CONFORMANCE.md entry left in place — would otherwise pass invisibly: Go's testing
// package makes an empty t.Run table indistinguishable from a full one that all passed.
// Add a new vector's name here in the SAME change that adds the vector; this list is a
// floor, not a mirror, so a forgotten addition only fails to raise the floor, it never
// breaks the build.
var expectedVectorNames = []string{
	"absent-runlog", "absent-signature", "bad-signature", "break-glass-only",
	"count-over-2pow53", "crypto-kat", "d1-with-identity", "dedup-same-value-two-runs",
	"deleted-shard", "dropped-break-glass-wrap", "flipped-tag", "forged-capsule-wrap",
	"gzip-codec", "in-range-count-as-string", "incomplete-marker", "incomplete-record-count",
	"kem-combiner-kat", "leading-zero-count", "master-capsule", "missing-break-glass",
	"mixed-codec", "mldsa-kat", "mlkem-kat", "mutated-recipient-fingerprint",
	"negative-count", "non-canonical-json", "non-integer-count", "recovery-bundle-tampered",
	"reordered-chunks", "reordered-segments", "reprovision-workers", "runlog-allocation-gap",
	"runlog-duplicate-index", "runlog-forked-prevrunid", "runlog-interleaved-append",
	"runlog-rollback", "secrets-no-dedup", "secrets-with-compression", "seg-empty",
	"seg-multi-chunk", "seg-multi-segment", "seg-packed", "seg-single-chunk",
	"shard-hash-mismatch", "single-half-signature", "stale-run", "truncated-final-chunk",
	"unimplemented-minor", "unknown-codec", "unknown-major", "unknown-signer",
	"unknown-source-type", "wrong-merkle-root",
}

func TestConformance(t *testing.T) {
	if *updateVectors {
		generateCorpus(t)
	}
	dirs, err := filepath.Glob(filepath.Join("testdata", "vectors", "*"))
	if err != nil {
		t.Fatal(err)
	}
	present := map[string]bool{}
	var runDirs []string
	for _, dir := range dirs {
		fi, err := os.Stat(dir)
		if err != nil || !fi.IsDir() {
			continue // skip the README and any non-vector entry
		}
		present[filepath.Base(dir)] = true
		runDirs = append(runDirs, dir)
	}
	// Refuse rather than skip. An empty or shrunken corpus must fail loudly and name what
	// is missing, not report success having compared nothing.
	var missing []string
	for _, want := range expectedVectorNames {
		if !present[want] {
			missing = append(missing, want)
		}
	}
	if len(runDirs) == 0 {
		t.Fatalf("conformance corpus is EMPTY: testdata/vectors has no vector directories. "+
			"This must never report a pass. All %d expected vectors are missing: %v. "+
			"Restore the corpus from git, or regenerate with -update.", len(expectedVectorNames), expectedVectorNames)
	}
	if len(missing) > 0 {
		t.Fatalf("conformance corpus is missing %d of its %d expected vectors: %v. "+
			"A shrunk-but-nonempty corpus silently loses coverage; restore the missing "+
			"vector directories from git, or regenerate with -update.",
			len(missing), len(expectedVectorNames), missing)
	}
	for _, dir := range runDirs {
		dir := dir
		base := filepath.Base(dir)
		t.Run(base, func(t *testing.T) {
			switch base {
			case "kem-combiner-kat":
				replayCombinerKAT(t, dir)
			case "crypto-kat":
				replayCryptoKAT(t, dir)
			case "mlkem-kat":
				replayMLKEMKAT(t, dir)
			case "mldsa-kat":
				replayMLDSAKAT(t, dir)
			default:
				replayVector(t, dir)
			}
		})
	}
}

// combinerKAT pins fixed inputs and the expected 32-byte output of the hybrid KEM
// combiner (SPEC.md 4.2, 14.6). A second implementation must reproduce it byte-for-byte
// before sealing any object. All fields are base64url no-pad.
type combinerKAT struct {
	SSM    string `json:"ssM"`
	SSX    string `json:"ssX"`
	CTX    string `json:"ctX"`
	PKX    string `json:"pkX"`
	Output string `json:"output"`
}

func hexEncode(b []byte) string { return hex.EncodeToString(b) }

func fixedBytes(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func generateCombinerKAT(t *testing.T) {
	ssM, ssX, ctX, pkX := fixedBytes(0x11, 32), fixedBytes(0x22, 32), fixedBytes(0x33, 32), fixedBytes(0x44, 32)
	kat := combinerKAT{
		SSM: B64Encode(ssM), SSX: B64Encode(ssX), CTX: B64Encode(ctX), PKX: B64Encode(pkX),
		Output: B64Encode(crypto.HybridKEMCombine(ssM, ssX, ctX, pkX)),
	}
	writeVecJSON(t, filepath.Join("testdata", "vectors", "kem-combiner-kat", "kat.json"), kat)
}

func replayCombinerKAT(t *testing.T, dir string) {
	var kat combinerKAT
	if err := json.Unmarshal(readVecFile(t, filepath.Join(dir, "kat.json")), &kat); err != nil {
		t.Fatal(err)
	}
	got := crypto.HybridKEMCombine(mustB64(t, []byte(kat.SSM)), mustB64(t, []byte(kat.SSX)), mustB64(t, []byte(kat.CTX)), mustB64(t, []byte(kat.PKX)))
	if B64Encode(got) != kat.Output {
		t.Fatalf("combiner KAT mismatch:\n got %s\nwant %s", B64Encode(got), kat.Output)
	}
}

// cryptoKAT pins the pure (non-PQ) crypto derivations and a STREAM seal so a second
// implementation can byte-lock derive + stream against Web Crypto alone, before wiring
// the post-quantum library. All binary fields are base64url no-pad; hashes are hex.
type cryptoKAT struct {
	Master        string `json:"master"`        // b64, 32
	DownpipeID    string `json:"downpipeId"`    // utf-8
	RunID         string `json:"runId"`         // ULID text
	Plaintext     string `json:"plaintext"`     // b64, the segment plaintext
	PayloadNonce  string `json:"payloadNonce"`  // b64, 16
	CAK           string `json:"cak"`           // b64, 32
	SegIDHex      string `json:"segIdHex"`      // hex, 48 bytes
	FileKey       string `json:"fileKey"`       // b64, 32
	KeyCommitment string `json:"keyCommitment"` // hex, 48 bytes
	StreamBody    string `json:"streamBody"`    // b64, SealStream output (nonce + chunks)
	Seg           string `json:"seg"`           // b64, the framed .seg (DPS1 + body)
}

func generateCryptoKAT(t *testing.T) {
	master := fixedBytes(0x7e, 32)
	const dpID = "dp_kat"
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	runIDBytes, err := spec.DecodeULID(runID)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("downpipe crypto KAT: derive + STREAM must match across implementations")
	nonce := fixedBytes(0x01, spec.StreamNonceSize)

	cak := crypto.DeriveCAK(master, dpID)
	segID := crypto.SegID(cak, spec.AddrSingleNonSecret, nil, plaintext)
	fileKey := crypto.DeriveNonSecretFileKey(master, segID, spec.CodecNone)
	body, err := crypto.SealStream(fileKey, plaintext, nonce)
	if err != nil {
		t.Fatal(err)
	}
	kat := cryptoKAT{
		Master: B64Encode(master), DownpipeID: dpID, RunID: runID,
		Plaintext: B64Encode(plaintext), PayloadNonce: B64Encode(nonce),
		CAK: B64Encode(cak), SegIDHex: crypto.SegIDHex(segID), FileKey: B64Encode(fileKey[:]),
		KeyCommitment: hexEncode(crypto.KeyCommitment(master, runIDBytes)),
		StreamBody:    B64Encode(body), Seg: B64Encode(spec.FrameContainer(spec.MagicSeg, body)),
	}
	writeVecJSON(t, filepath.Join("testdata", "vectors", "crypto-kat", "kat.json"), kat)
}

func replayCryptoKAT(t *testing.T, dir string) {
	var kat cryptoKAT
	if err := json.Unmarshal(readVecFile(t, filepath.Join(dir, "kat.json")), &kat); err != nil {
		t.Fatal(err)
	}
	master := mustB64(t, []byte(kat.Master))
	runIDBytes, err := spec.DecodeULID(kat.RunID)
	if err != nil {
		t.Fatal(err)
	}
	cak := crypto.DeriveCAK(master, kat.DownpipeID)
	if B64Encode(cak) != kat.CAK {
		t.Fatal("CAK mismatch")
	}
	segID := crypto.SegID(cak, spec.AddrSingleNonSecret, nil, mustB64(t, []byte(kat.Plaintext)))
	if crypto.SegIDHex(segID) != kat.SegIDHex {
		t.Fatal("segId mismatch")
	}
	fileKey := crypto.DeriveNonSecretFileKey(master, segID, spec.CodecNone)
	if B64Encode(fileKey[:]) != kat.FileKey {
		t.Fatal("fileKey mismatch")
	}
	if hexEncode(crypto.KeyCommitment(master, runIDBytes)) != kat.KeyCommitment {
		t.Fatal("keyCommitment mismatch")
	}
	body, err := crypto.SealStream(fileKey, mustB64(t, []byte(kat.Plaintext)), mustB64(t, []byte(kat.PayloadNonce)))
	if err != nil {
		t.Fatal(err)
	}
	if B64Encode(body) != kat.StreamBody {
		t.Fatal("STREAM body mismatch")
	}
}

// mlkemKAT pins an ML-KEM-1024 seed, the encapsulation key it derives, and one
// encapsulation (ciphertext + shared secret), so a second implementation proves it
// derives the same key from the seed and decapsulates to the same secret (SPEC 4.1).
type mlkemKAT struct {
	Seed         string `json:"seed"`         // b64, 64
	EncapKey     string `json:"encapKey"`     // b64, 1568
	CipherText   string `json:"cipherText"`   // b64, 1568
	SharedSecret string `json:"sharedSecret"` // b64, 32
}

func generateMLKEMKAT(t *testing.T) {
	seed := fixedBytes(0x55, 64)
	dk, err := mlkem.NewDecapsulationKey1024(seed)
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	ss, ct := ek.Encapsulate()
	kat := mlkemKAT{Seed: B64Encode(seed), EncapKey: B64Encode(ek.Bytes()), CipherText: B64Encode(ct), SharedSecret: B64Encode(ss)}
	writeVecJSON(t, filepath.Join("testdata", "vectors", "mlkem-kat", "kat.json"), kat)
}

func replayMLKEMKAT(t *testing.T, dir string) {
	var kat mlkemKAT
	if err := json.Unmarshal(readVecFile(t, filepath.Join(dir, "kat.json")), &kat); err != nil {
		t.Fatal(err)
	}
	dk, err := mlkem.NewDecapsulationKey1024(mustB64(t, []byte(kat.Seed)))
	if err != nil {
		t.Fatal(err)
	}
	if B64Encode(dk.EncapsulationKey().Bytes()) != kat.EncapKey {
		t.Fatal("ML-KEM encapsulation key from seed mismatch")
	}
	ss, err := dk.Decapsulate(mustB64(t, []byte(kat.CipherText)))
	if err != nil {
		t.Fatal(err)
	}
	if B64Encode(ss) != kat.SharedSecret {
		t.Fatal("ML-KEM decapsulated secret mismatch")
	}
}

// mldsaKAT pins an ML-DSA-87 public key, a message and a signature so a second
// implementation proves it verifies a reference signature under the reference key
// encoding (SPEC 8.1).
type mldsaKAT struct {
	PublicKey string `json:"publicKey"` // b64, 2592
	Message   string `json:"message"`   // b64
	Signature string `json:"signature"` // b64, 4627
}

func generateMLDSAKAT(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("downpipe ML-DSA-87 cross-implementation KAT")
	sig, err := priv.Sign(rand.Reader, msg, &mldsa.Options{})
	if err != nil {
		t.Fatal(err)
	}
	kat := mldsaKAT{PublicKey: B64Encode(priv.PublicKey().Bytes()), Message: B64Encode(msg), Signature: B64Encode(sig)}
	writeVecJSON(t, filepath.Join("testdata", "vectors", "mldsa-kat", "kat.json"), kat)
}

func replayMLDSAKAT(t *testing.T, dir string) {
	var kat mldsaKAT
	if err := json.Unmarshal(readVecFile(t, filepath.Join(dir, "kat.json")), &kat); err != nil {
		t.Fatal(err)
	}
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA87(), mustB64(t, []byte(kat.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	if err := mldsa.Verify(pub, mustB64(t, []byte(kat.Message)), mustB64(t, []byte(kat.Signature)), &mldsa.Options{}); err != nil {
		t.Fatalf("ML-DSA KAT signature did not verify: %v", err)
	}
}

// katDirs are the deterministic known-answer vectors generated by their own functions
// (not the archive generator) and special-cased in TestConformance; generateCorpus leaves
// them in place and clears every other vector dir before regenerating.
var katDirs = map[string]bool{
	"kem-combiner-kat": true, "crypto-kat": true, "mlkem-kat": true, "mldsa-kat": true,
}

func generateCorpus(t *testing.T) {
	generateCombinerKAT(t)
	if *updateOnly != "" {
		wanted := map[string]bool{}
		for _, n := range strings.Split(*updateOnly, ",") {
			wanted[strings.TrimSpace(n)] = true
		}
		count := 0
		for _, v := range corpusVectors() {
			if wanted[v.name] {
				generateVector(t, v)
				delete(wanted, v.name)
				count++
			}
		}
		if len(wanted) != 0 {
			t.Fatalf("-update-only names not in the corpus: %v", wanted)
		}
		t.Logf("regenerated %d targeted archive conformance vectors; the rest of the corpus is untouched", count)
		return
	}
	generateCryptoKAT(t)
	generateMLKEMKAT(t)
	generateMLDSAKAT(t)

	// Clear every previously generated archive vector so a renamed or retired vector
	// leaves no stale directory; the KATs and the README stay.
	existing, err := filepath.Glob(filepath.Join("testdata", "vectors", "*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range existing {
		base := filepath.Base(dir)
		if katDirs[base] || base == "README.md" {
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
	}

	vectors := corpusVectors()
	for _, v := range vectors {
		generateVector(t, v)
	}
	t.Logf("regenerated %d archive conformance vectors plus %d KATs", len(vectors), len(katDirs))
}

// generateVector builds one vector archive, writes it to its directory with the
// break-glass identity and the signer public key, applies any tamper, and writes
// expect.json.
func generateVector(t *testing.T, v corpusVector) {
	t.Helper()
	dir := filepath.Join("testdata", "vectors", v.name)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	store, bgPriv, verifier, signer := buildArchiveSpec(t, v.spec)
	for k, val := range store {
		writeVecFile(t, filepath.Join(dir, "archive", filepath.FromSlash(k)), val)
	}
	writeVecFile(t, filepath.Join(dir, "identity.key"), []byte(B64Encode(crypto.MarshalKEMPrivate(bgPriv))))
	writeVecFile(t, filepath.Join(dir, "signer.pub"), []byte(B64Encode(crypto.MarshalVerifier(verifier))))
	if v.tamper != nil {
		v.tamper(t, dir, signer)
	}
	writeVecJSON(t, filepath.Join(dir, "expect.json"), v.expect)
}

func replayVector(t *testing.T, dir string) {
	exp := readVecExpect(t, dir)
	identity, err := crypto.ParseKEMPrivate(mustB64(t, readVecFile(t, filepath.Join(dir, "identity.key"))))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := crypto.ParseVerifier(mustB64(t, readVecFile(t, filepath.Join(dir, "signer.pub"))))
	if err != nil {
		t.Fatal(err)
	}
	store := source.NewDirStore(filepath.Join(dir, "archive"))
	if exp.SegCount != nil {
		assertSegCount(t, dir, *exp.SegCount)
	}
	replayExpect(t, store, identity, verifier, exp)
	for _, also := range exp.Also {
		replayExpect(t, store, identity, verifier, also)
	}
	// Attest (SPEC.md 8.8) replays alongside Open/StreamOpen: see conformance_attest_test.go
	// for the parity mechanism and the reasoned scope-boundary overrides.
	t.Run("attest", func(t *testing.T) {
		replayAttest(t, filepath.Base(dir), store, verifier, exp)
	})
	// The committed recovery bundle (SPEC.md 9) is held to its own signature here: see
	// conformance_bundle_test.go for what was and was not covered before it.
	t.Run("bundle", func(t *testing.T) {
		replayBundle(t, filepath.Base(dir), store, verifier)
	})
}

// assertSegCount checks the number of .seg objects under the vector archive, proving the
// dedup (one shared object) and the no-dedup-for-secrets (one object per record)
// invariants of SPEC.md 14.2.
func assertSegCount(t *testing.T, dir string, want int) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "archive", "seg", "*", "*.seg"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != want {
		t.Fatalf("expected %d .seg objects, found %d", want, len(matches))
	}
}

// replayExpect opens one run of the archive under the projected Options and asserts the
// expected outcome THROUGH BOTH READER PATHS: the load-all Open and the bounded-memory
// StreamOpen. The two paths share every gate helper, so a conformance vector must produce
// the identical exit code, labels and values through either; that per-vector parity is
// what lets the verify command run on the streaming reader without weakening the corpus
// contract. The corpus is single-defect by construction: a multi-defect archive could
// legitimately differ in WHICH defect wins, because the two paths order their checks
// differently (load-all checks all shard hashes before any structural check; the walk
// checks structure and hashes per record and the declared count only at the end), so
// equality is asserted per vector here and never claimed for arbitrary archives.
func replayExpect(t *testing.T, store ObjectStore, identity *crypto.HybridKEMPrivate, verifier *crypto.HybridVerifier, exp vectorExpect) {
	t.Helper()
	runID := exp.RunID
	if runID == "" {
		runID = vecRunID
	}
	opts := projectOptions(exp.Options)

	t.Run("load-all", func(t *testing.T) {
		r, openErr := Open(store, runID, identity, verifier, opts)
		var recs []spec.ShardRecord
		if openErr == nil {
			recs = r.Records()
		}
		assertExpect(t, store, identity, verifier, exp, runID, r, recs, openErr)
	})
	t.Run("streaming", func(t *testing.T) {
		sr, openErr := StreamOpen(store, runID, identity, verifier, opts)
		var recs []spec.ShardRecord
		if openErr == nil {
			// The vectors are small, so collecting the walked records lets one assertion
			// helper drive both paths. Restore-phase negatives tamper segment bytes, which
			// the walk never reads, so a walk failure here is a real parity break.
			if werr := sr.EachRecord(func(rec spec.ShardRecord) error {
				recs = append(recs, rec)
				return nil
			}); werr != nil {
				t.Fatalf("streaming walk %s: %v", runID, werr)
			}
		}
		var r replayReader
		if sr != nil {
			r = sr
		}
		assertExpect(t, store, identity, verifier, exp, runID, r, recs, openErr)
	})
}

// replayReader is the slice of reader behaviour the shared expectation assertions need,
// satisfied by both *Reader and *StreamReader.
type replayReader interface {
	RestoreRecord(rec spec.ShardRecord) ([]byte, error)
	Outcome() Outcome
}

// assertExpect asserts one vector expectation against an already-opened reader (either
// path): a positive restores every listed record; a negative fails at the stated phase
// with the stated exit code. Pinned Outcome labels are asserted against the honest
// outcome, reading an allow-* re-open for a negative so the true labels are visible.
func assertExpect(t *testing.T, store ObjectStore, identity *crypto.HybridKEMPrivate, verifier *crypto.HybridVerifier, exp vectorExpect, runID string, r replayReader, recs []spec.ShardRecord, openErr error) {
	t.Helper()
	if exp.Mode == "negative" && exp.Phase == "open" {
		assertExit(t, openErr, exp.ExitCode)
		assertLabels(t, store, runID, identity, verifier, exp.Labels)
		return
	}
	if openErr != nil {
		t.Fatalf("open %s: %v", runID, openErr)
	}
	if exp.Mode == "negative" && exp.Phase == "restore" {
		rec := recs[0]
		if exp.RecordName != "" {
			named, ok := findRecord(recs, exp.RecordName)
			if !ok {
				t.Fatalf("restore-negative vector for run %s names record %q, which is not present", runID, exp.RecordName)
			}
			rec = named
		}
		_, rerr := r.RestoreRecord(rec)
		assertExit(t, rerr, exp.ExitCode)
		assertLabels(t, store, runID, identity, verifier, exp.Labels)
		return
	}
	// A negative vector must declare a phase the driver asserts a rejection for; any other
	// phase would fall through to the positive checks below and silently prove nothing.
	if exp.Mode == "negative" {
		t.Fatalf("negative vector for run %s has unhandled phase %q (want \"open\" or \"restore\")", runID, exp.Phase)
	}
	for _, want := range exp.Records {
		rec, ok := findRecord(recs, want.Name)
		if !ok {
			t.Fatalf("record %q not found in run %s", want.Name, runID)
		}
		got, err := r.RestoreRecord(rec)
		if err != nil {
			t.Fatalf("restore %q: %v", want.Name, err)
		}
		if !bytes.Equal(got, mustB64(t, []byte(want.ValueB64))) {
			t.Fatalf("record %q value mismatch in run %s", want.Name, runID)
		}
		if want.Database != "" && rec.Database != want.Database {
			t.Fatalf("record %q database annotation %q, want %q", want.Name, rec.Database, want.Database)
		}
		if want.Account != "" && rec.Account != want.Account {
			t.Fatalf("record %q account annotation %q, want %q", want.Name, rec.Account, want.Account)
		}
		if want.IncompleteMarker != "" && rec.IncompleteMarker != want.IncompleteMarker {
			t.Fatalf("record %q incompleteMarker %q, want %q", want.Name, rec.IncompleteMarker, want.IncompleteMarker)
		}
	}
	assertOutcomeLabels(t, r.Outcome(), exp.Labels)
}

// projectOptions builds the reader Options from the optional expect.json projection.
func projectOptions(o *expectOptions) Options {
	if o == nil {
		return Options{}
	}
	return Options{
		AllowStale:            o.AllowStale,
		AllowUnverifiedRunlog: o.AllowUnverifiedRunlog,
		AllowUnverified:       o.AllowUnverified,
		MinRunlogIndex:        o.MinRunlogIndex,
		CheckRecoveryBundle:   o.CheckRecoveryBundle,
	}
}

// assertLabels re-opens a rejected run under allow-unverified (and allow-stale, and the
// bundle check when a bundle label is pinned) so the honest Outcome labels are readable,
// then asserts them. A run whose bytes are unrecoverable (the capsule, key commitment or
// recipient set is broken) cannot be re-opened even with allow flags; for those the
// vector pins no labels and this is a no-op.
func assertLabels(t *testing.T, store ObjectStore, runID string, identity *crypto.HybridKEMPrivate, verifier *crypto.HybridVerifier, want *expectLabels) {
	t.Helper()
	if want == nil {
		return
	}
	opts := Options{AllowUnverified: true, AllowStale: true}
	if want.RecoveryBundleVerified != nil {
		opts.CheckRecoveryBundle = true
	}
	r, err := Open(store, runID, identity, verifier, opts)
	if err != nil {
		t.Fatalf("allow-unverified re-open to read labels for %s: %v", runID, err)
	}
	assertOutcomeLabels(t, r.Outcome(), want)
}

func assertOutcomeLabels(t *testing.T, out Outcome, want *expectLabels) {
	t.Helper()
	if want == nil {
		return
	}
	if want.SignatureResult != nil && out.SignatureResult != *want.SignatureResult {
		t.Fatalf("signatureResult: got %q, want %q", out.SignatureResult, *want.SignatureResult)
	}
	if want.BreakGlassVerified != nil && out.BreakGlassVerified != *want.BreakGlassVerified {
		t.Fatalf("breakGlassVerified: got %v, want %v", out.BreakGlassVerified, *want.BreakGlassVerified)
	}
	if want.RecoveryBundleVerified != nil && out.RecoveryBundleVerified != *want.RecoveryBundleVerified {
		t.Fatalf("recoveryBundleVerified: got %v, want %v", out.RecoveryBundleVerified, *want.RecoveryBundleVerified)
	}
}

func assertExit(t *testing.T, err error, code int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a failure with exit code %d, got success", code)
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected an ExitError with code %d, got %v", code, err)
	}
	if ee.Code != code {
		t.Fatalf("expected exit code %d, got %d (%v)", code, ee.Code, err)
	}
}

func findRecord(records []spec.ShardRecord, name string) (spec.ShardRecord, bool) {
	for _, r := range records {
		if r.Name == name {
			return r, true
		}
	}
	return spec.ShardRecord{}, false
}

func writeVecFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func readVecFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeVecJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeVecFile(t, path, append(b, '\n'))
}

func readVecExpect(t *testing.T, dir string) vectorExpect {
	t.Helper()
	var exp vectorExpect
	if err := json.Unmarshal(readVecFile(t, filepath.Join(dir, "expect.json")), &exp); err != nil {
		t.Fatal(err)
	}
	return exp
}

func mustB64(t *testing.T, b []byte) []byte {
	t.Helper()
	out, err := B64Decode(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func tamperLastByte(t *testing.T, path string) {
	t.Helper()
	b := readVecFile(t, path)
	if len(b) == 0 {
		t.Fatalf("cannot tamper empty file %s", path)
	}
	b[len(b)-1] ^= 0x01
	writeVecFile(t, path, b)
}
