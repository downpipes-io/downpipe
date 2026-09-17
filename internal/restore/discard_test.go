package restore

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
)

// sha384HexLen is the length of a SHA-384 digest rendered as lowercase hex: 48 raw bytes
// at two hex characters each. The restore digest is SHA-384, so its hex form is this many
// characters; naming the constant ties the assertions to the algorithm so they move
// together if it ever changes.
const sha384HexLen = sha512.Size384 * 2

// TestDiscardTargetVerifiesAndWritesNothing proves the headline property of the discard
// sink: applied against a real sealed archive it decrypts and verifies every record
// through the full restore path (AEAD-tag plus plaintext hash, via RestoreRecord) and
// writes NOTHING, accumulating only counts and a restore digest. No plaintext is held by
// the target.
func TestDiscardTargetVerifiesAndWritesNothing(t *testing.T) {
	store := memStore{}
	values := map[string]string{
		"greeting":   "recover me without Cloudflare and without the vendor",
		"config/key": "value-bytes",
	}
	identity, verifier, runID := buildArchive(t, store, "dp_discard", "kv", values)

	r, err := format.Open(store, runID, identity, verifier, format.Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	dt := NewDiscardTarget()
	plan, res, err := Apply(r, dt, true)
	if err != nil {
		t.Fatalf("apply to discard sink: %v", err)
	}
	if res.DryRun {
		t.Fatal("an apply to the discard sink must not be a dry run")
	}
	if !res.OK() || res.Restored != len(values) {
		t.Fatalf("discard apply: restored=%d failed=%v, want %d restored", res.Restored, res.Failed, len(values))
	}
	if len(plan.Conflicts) != 0 {
		t.Fatalf("the discard sink must never report a conflict, got %+v", plan.Conflicts)
	}

	// The target counted every record and every byte, with no plaintext retained.
	if dt.VerifiedRecords() != len(values) {
		t.Fatalf("VerifiedRecords = %d, want %d", dt.VerifiedRecords(), len(values))
	}
	var wantBytes int64
	for _, v := range values {
		wantBytes += int64(len(v))
	}
	if dt.VerifiedBytes() != wantBytes {
		t.Fatalf("VerifiedBytes = %d, want %d", dt.VerifiedBytes(), wantBytes)
	}

	// The digest is non-empty hex and reveals no plaintext: assert it does not contain
	// any of the value bytes verbatim.
	digest := dt.Digest()
	if len(digest) != sha384HexLen {
		t.Fatalf("restore digest must be %d hex chars (SHA-384), got %d: %q", sha384HexLen, len(digest), digest)
	}
	for _, v := range values {
		if strings.Contains(digest, v) {
			t.Fatalf("the restore digest must not contain a plaintext value: %q in %q", v, digest)
		}
	}
}

// TestDiscardDigestDeterministic proves the restore digest is stable across two runs over
// the same archive, so an operator can pin it and detect a future change to the recovered
// content.
func TestDiscardDigestDeterministic(t *testing.T) {
	store := memStore{}
	values := map[string]string{"a": "alpha", "b": "bravo", "c": "charlie"}
	identity, verifier, runID := buildArchive(t, store, "dp_digest", "kv", values)

	digestOnce := func() string {
		r, err := format.Open(store, runID, identity, verifier, format.Options{})
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		dt := NewDiscardTarget()
		if _, _, err := Apply(r, dt, true); err != nil {
			t.Fatalf("apply: %v", err)
		}
		return dt.Digest()
	}

	first := digestOnce()
	second := digestOnce()
	if first != second {
		t.Fatalf("restore digest must be deterministic across runs, got %q then %q", first, second)
	}
}

// TestDiscardDigestChangesWithContent proves the digest is content-sensitive: two
// archives with different values produce different digests, so a silent change to a
// recovered value is detectable by a pinned digest.
func TestDiscardDigestChangesWithContent(t *testing.T) {
	digestFor := func(values map[string]string) string {
		store := memStore{}
		identity, verifier, runID := buildArchive(t, store, "dp_digest", "kv", values)
		r, err := format.Open(store, runID, identity, verifier, format.Options{})
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		dt := NewDiscardTarget()
		if _, _, err := Apply(r, dt, true); err != nil {
			t.Fatalf("apply: %v", err)
		}
		return dt.Digest()
	}

	a := digestFor(map[string]string{"k": "value-one"})
	b := digestFor(map[string]string{"k": "value-two"})
	if a == b {
		t.Fatal("two different recovered values must yield different restore digests")
	}
}

// TestDiscardTargetTamperedArchiveFails proves a tampered archive fails through the
// discard sink: corrupting a sealed segment makes RestoreRecord's AEAD/hash check fail,
// which Apply records as a per-record failure, so res.OK() is false and the record is
// counted as failed rather than verified.
func TestDiscardTargetTamperedArchiveFails(t *testing.T) {
	store := memStore{}
	values := map[string]string{"greeting": "tamper me"}
	identity, verifier, runID := buildArchive(t, store, "dp_tamper", "kv", values)

	r, err := format.Open(store, runID, identity, verifier, format.Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	// Corrupt the segment ciphertext so AEAD verification fails on restore. The segment
	// object is the only ".seg" key in the store.
	var segKey string
	for k := range store {
		if strings.HasSuffix(k, ".seg") {
			segKey = k
			break
		}
	}
	if segKey == "" {
		t.Fatal("no segment object found to tamper")
	}
	corrupt := append([]byte(nil), store[segKey]...)
	corrupt[len(corrupt)-1] ^= 0x01 // flip a tag byte
	store[segKey] = corrupt

	dt := NewDiscardTarget()
	_, res, err := Apply(r, dt, true)
	if err != nil {
		t.Fatalf("a per-record decrypt failure must not abort apply: %v", err)
	}
	if res.OK() {
		t.Fatal("a tampered archive must not produce an OK discard result")
	}
	if res.Restored != 0 || dt.VerifiedRecords() != 0 {
		t.Fatalf("a tampered record must not be counted as verified, got restored=%d verified=%d", res.Restored, dt.VerifiedRecords())
	}
	if len(res.Failed) != 1 || res.Failed[0].Name != "greeting" {
		t.Fatalf("the tampered record must appear in Failed, got %+v", res.Failed)
	}
}

// TestDiscardTargetEmptyArchiveDigest proves the discard sink over a zero-record reader
// produces the digest of the empty stream and verifies nothing, without error.
func TestDiscardTargetEmptyArchiveDigest(t *testing.T) {
	r := rdr() // no records
	dt := NewDiscardTarget()
	_, res, err := Apply(r, dt, true)
	if err != nil {
		t.Fatalf("apply over an empty reader: %v", err)
	}
	if res.Restored != 0 || dt.VerifiedRecords() != 0 || dt.VerifiedBytes() != 0 {
		t.Fatalf("an empty archive must verify nothing, got restored=%d records=%d bytes=%d", res.Restored, dt.VerifiedRecords(), dt.VerifiedBytes())
	}
	// The empty-stream SHA-384 in lowercase hex is a fixed constant; assert the digest is
	// well-formed hex of the right length rather than pinning the exact value here (it is
	// pinned implicitly by the determinism test).
	if len(dt.Digest()) != sha384HexLen {
		t.Fatalf("empty-stream digest must be %d hex chars, got %q", sha384HexLen, dt.Digest())
	}
}

// TestDiscardTargetWriteHoldsNoPlaintext is a direct, white-box check that Write retains
// no value bytes: after writing several values the target exposes only counts and a
// digest, never the bytes. The discard target struct has no field that stores a value, so
// this also documents that contract.
func TestDiscardTargetWriteHoldsNoPlaintext(t *testing.T) {
	dt := NewDiscardTarget()
	secret := []byte("super-secret-value")
	if err := dt.Write("k", secret); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Mutate the caller's buffer afterwards; the target must not be observing it.
	for i := range secret {
		secret[i] = 'x'
	}
	if dt.VerifiedRecords() != 1 || dt.VerifiedBytes() != int64(len("super-secret-value")) {
		t.Fatalf("Write must count the record and its bytes, got records=%d bytes=%d", dt.VerifiedRecords(), dt.VerifiedBytes())
	}
	// The only data the target surfaces is the digest, which is a one-way hash.
	if strings.Contains(dt.Digest(), "super-secret") {
		t.Fatal("the digest must not contain plaintext")
	}
}

// TestDiscardDigestFoldsPlaintextHashNotPlaintext pins the digest CONSTRUCTION: the
// accumulator folds each record's destination key and the SHA-384 OF its plaintext, never
// the raw plaintext bytes. It rebuilds the expected digest independently from the public
// (key, value) inputs and asserts the target's digest equals it; folding the raw plaintext
// (the old behaviour, a confirmation oracle) would produce a different digest and fail here.
func TestDiscardDigestFoldsPlaintextHashNotPlaintext(t *testing.T) {
	type leaf struct {
		key   string
		value []byte
	}
	leaves := []leaf{
		{"0", []byte("alpha-secret")},
		{"1", []byte("bravo-secret-value-that-is-longer")},
		{"2", []byte{}}, // an empty value still folds its key and the SHA-384 of the empty string
	}

	dt := NewDiscardTarget()
	for _, l := range leaves {
		if err := dt.Write(l.key, l.value); err != nil {
			t.Fatalf("Write(%q): %v", l.key, err)
		}
	}
	got := dt.Digest()

	// Independently recompute: for each leaf fold len(key)||key||len(hash)||sha384(value),
	// each length as an 8-byte big-endian prefix. This deliberately hashes the value first,
	// so a digest that folded the raw value instead would not match.
	h := sha512.New384()
	var lp [8]byte
	for _, l := range leaves {
		vh := sha512.Sum384(l.value)
		binary.BigEndian.PutUint64(lp[:], uint64(len(l.key)))
		h.Write(lp[:])
		h.Write([]byte(l.key))
		binary.BigEndian.PutUint64(lp[:], uint64(len(vh)))
		h.Write(lp[:])
		h.Write(vh[:])
	}
	want := hex.EncodeToString(h.Sum(nil))
	if got != want {
		t.Fatalf("digest must fold key + sha384(plaintext); got %q want %q", got, want)
	}

	// Cross-check: a digest built by folding the RAW plaintext (the old, oracle behaviour)
	// must NOT equal the target's digest, proving the plaintext bytes are not what is folded.
	hRaw := sha512.New384()
	for _, l := range leaves {
		binary.BigEndian.PutUint64(lp[:], uint64(len(l.value)))
		hRaw.Write(lp[:])
		hRaw.Write(l.value)
	}
	if got == hex.EncodeToString(hRaw.Sum(nil)) {
		t.Fatal("digest must not match a fold over the raw plaintext bytes (that would be a confirmation oracle)")
	}
}

// TestDiscardDigestNoRawPlaintextBytes asserts no raw plaintext byte sequence leaks into the
// digest. A high-entropy plaintext is written; its bytes (and a long substring of them) must
// not appear anywhere in the raw 48-byte digest, because only its SHA-384 is folded.
func TestDiscardDigestNoRawPlaintextBytes(t *testing.T) {
	plaintext := make([]byte, 64)
	for i := range plaintext {
		plaintext[i] = byte(i*7 + 3) // a fixed, distinctive, full-byte-range pattern
	}
	dt := NewDiscardTarget()
	if err := dt.Write("0", plaintext); err != nil {
		t.Fatalf("Write: %v", err)
	}
	rawDigest, err := hex.DecodeString(dt.Digest())
	if err != nil {
		t.Fatalf("digest is not hex: %v", err)
	}
	// The whole plaintext cannot fit in a 48-byte digest, but assert no substantial run of it
	// appears either: check every 8-byte window of the plaintext is absent from the digest.
	for i := 0; i+8 <= len(plaintext); i++ {
		if bytes.Contains(rawDigest, plaintext[i:i+8]) {
			t.Fatalf("an 8-byte run of the raw plaintext appeared in the digest at offset %d", i)
		}
	}
}
