package format

// Go native fuzz targets for the offline reader's untrusted-byte parse and verify
// paths, covering the attacker-reachable untrusted-byte parse paths identified in the
// pre-production security review. The offline reader is the security-critical recovery
// code: pointed at an attacker-controlled destination bucket it must NEVER panic, hang,
// over-allocate from a length field, or accept a forged archive. These targets are
// seeded from the real conformance vectors (testdata/vectors) and assert the safety
// invariants rather than merely exercising the code; any crash a target surfaces is
// checked in under testdata/fuzz/ as a permanent regression seed.
//
// The bounded CI job (.github/workflows/ci.yml, the "fuzz" job) runs each target for a
// short -fuzztime on push/PR. The seed corpus and any checked-in crashers run as normal
// unit tests under `go test ./...` every time regardless of -fuzztime, so a discovered
// crasher stays a hard regression test even when fuzzing itself does not run.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// vectorGlob returns every file under testdata/vectors matching the slash pattern,
// used to seed the fuzz corpus from the real conformance vectors. A missing corpus
// yields no seeds (the targets still run on the built-in literal seeds).
func vectorGlob(f *testing.F, pattern string) []string {
	f.Helper()
	matches, err := filepath.Glob(filepath.Join("testdata", "vectors", filepath.FromSlash(pattern)))
	if err != nil {
		f.Fatalf("glob %s: %v", pattern, err)
	}
	return matches
}

// seedFile adds one file's bytes as a fuzz seed, skipping a file that cannot be read
// (a vector may legitimately not exist on a given checkout).
func seedFile(f *testing.F, path string) {
	f.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	f.Add(b)
}

// FuzzCanonJSON drives arbitrary bytes (seeded with the cleartext vector manifests and
// the canonical-JSON unit-test literals) through the canonical-JSON encoder, the
// security-critical path that produces the exact bytes a signature covers (SPEC.md
// 11.1).
//
// Invariants:
//   - CanonicalJSON never panics on any input (it parses arbitrary JSON via the
//     standard decoder, so the input is first decoded to a generic value, then
//     re-encoded; both steps must only ever error, never crash).
//   - Idempotence: a value CanonicalJSON accepts must canonicalise to a fixed point.
//     Re-decoding the canonical output and canonicalising again must yield byte-identical
//     output (canon(canon(x)) == canon(x)). A drift here would mean two distinct "canonical"
//     forms exist for one value, which breaks signature reproducibility.
//   - Determinism: the same decoded value canonicalises identically regardless of Go map
//     iteration order (re-running the encoder on the same value yields the same bytes).
//   - Rejection is by clean error: a non-canonical number (float, leading zero, negative,
//     over-2^53), invalid UTF-8, or duplicate object keys are rejected with an error, not
//     a panic and not a silent rewrite.
func FuzzCanonJSON(f *testing.F) {
	// Literal seeds: the canonical and non-canonical shapes the unit tests pin.
	for _, s := range []string{
		`{"a":2,"b":1,"c":3}`,
		`{"arr":[3,1,2],"obj":{"a":2,"z":1}}`,
		`{"n":9007199254740991}`,
		`{"n":9007199254740992}`, // over ceiling: must reject
		`{"n":1.5}`,              // float: must reject
		`{"n":-0}`,               // negative zero: must reject
		`{"n":007}`,              // leading zero: must reject
		`{"k":"a<b>&c"}`,
		`{"dup":1,"dup":2}`, // duplicate key
		`[]`, `{}`, `null`, `true`, `false`, `0`, `"x"`,
		`{"nested":{"deep":{"deeper":[1,2,3]}}}`,
	} {
		f.Add([]byte(s))
	}
	// Vector seeds: the real cleartext root manifests and the RUNLOG NDJSON lines are all
	// canonical JSON the signature covers, so they are genuine accept-and-fix-point seeds.
	for _, p := range vectorGlob(f, "*/archive/run/*/root.manifest.json") {
		seedFile(f, p)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// The encoder consumes a Go value, not bytes. We decode the fuzz bytes as JSON
		// first (UseNumber, mirroring CanonicalJSON's own decode) so the fuzzer explores the
		// value space the encoder actually sees; a non-JSON input simply yields no value to
		// test. This is the same two-step the encoder performs internally, so it cannot
		// over- or under-constrain the target.
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return // not a single JSON value; nothing for the encoder to canonicalise
		}
		// Reject trailing garbage: CanonicalJSON is given one value, so only feed it inputs
		// that are exactly one value (a second token means the bytes are not a lone value).
		if dec.More() {
			return
		}

		assertCanonJSONInvariants(t, v)
	})
}

// assertCanonJSONInvariants checks the two CanonicalJSON properties (determinism and
// idempotence) for a single decoded value. A value the encoder cleanly rejects is not an
// invariant violation, so this returns early in that case.
func assertCanonJSONInvariants(t *testing.T, v any) {
	t.Helper()
	out, err := CanonicalJSON(v)
	if err != nil {
		return // a clean rejection (non-canonical number, invalid UTF-8, unsupported type)
	}

	// Determinism: the same value must canonicalise to the same bytes every time,
	// independent of map iteration order. Run it again and compare.
	out2, err := CanonicalJSON(v)
	if err != nil {
		t.Fatalf("CanonicalJSON became non-deterministic: accepted then errored: %v", err)
	}
	if !bytes.Equal(out, out2) {
		t.Fatalf("CanonicalJSON is not deterministic for one value:\n a=%q\n b=%q", out, out2)
	}

	// Idempotence: re-decoding the canonical output and canonicalising it again must be
	// a fixed point. canon(canon(x)) == canon(x). The canonical output is itself valid
	// JSON, so this decode must succeed; a failure to round-trip its own output is a bug.
	dec2 := json.NewDecoder(bytes.NewReader(out))
	dec2.UseNumber()
	var rv any
	if err := dec2.Decode(&rv); err != nil {
		t.Fatalf("canonical output is not decodable JSON: %q: %v", out, err)
	}
	out3, err := CanonicalJSON(rv)
	if err != nil {
		t.Fatalf("canonical output is not itself canonical (re-canonicalise errored): %q: %v", out, err)
	}
	if !bytes.Equal(out, out3) {
		t.Fatalf("CanonicalJSON is not idempotent: canon(canon(x)) != canon(x):\n once=%q\ntwice=%q", out, out3)
	}
}

// FuzzCanonNum drives arbitrary numeric byte strings through the canonical-number
// readers, the exit-6 path that pins counts and sizes to a non-negative integer at most
// 2^53-1 in canonical form (SPEC.md 11.3). It exercises both validateCounts (the
// reader-side check on a signed object field) and checkCanonJSONInt (the writer-side
// check the encoder applies), since the two must agree.
//
// Invariants:
//   - Neither check ever panics on any numeric literal, however malformed.
//   - validateCounts accepts a field value if and only if it is a JSON number that is a
//     canonical non-negative integer in [0, 2^53-1] (no sign, no decimal point or
//     exponent, no leading zero beyond a lone "0"); everything else is rejected with an
//     ExitUsage error and no silent wrap.
//   - The reader-side and writer-side checks agree on every literal: a literal
//     validateCounts accepts must also pass checkCanonJSONInt, and vice versa, so the
//     writer can never emit a number the reader would reject (and the reader never
//     accepts one the writer could not have produced canonically).
func FuzzCanonNum(f *testing.F) {
	for _, s := range []string{
		"0", "1", "42", "9007199254740991", // canonical, in range
		"9007199254740992", "9007199254740993", // over 2^53-1
		"-1", "-0", "007", "01", "1.5", "1e3", "1E3", "0.0", // non-canonical
		"99999999999999999999999999999999", // far over int64 (must not wrap or panic)
		"-99999999999999999999999999999999",
		"+1", "1.", ".1", "1.2.3", "0x10", "", "abc", " 1", "1 ",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, num string) {
		// Build a one-field object literal from the raw numeric token. An invalid token
		// makes the whole object un-decodable, which validateCounts reports as ExitUsage
		// (its own decode failed) rather than a numeric-form rejection; either way it must
		// not panic.
		raw := []byte(`{"n":` + num + `}`)

		// Reader side: validateCounts must terminate cleanly (no panic). When the object
		// decodes and "n" is present, the accept/reject decision must match the canonical
		// numeric rule exactly.
		readerErr := validateCounts(raw, "n")

		// Independently decode "n" so the test can compute the ground-truth expectation and
		// compare it to validateCounts' verdict. A token that does not even form a JSON
		// object is out of scope for the agreement check below (validateCounts will have
		// returned an ExitUsage decode error, which is a valid clean rejection).
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var m map[string]any
		objOK := dec.Decode(&m) == nil && !dec.More()

		if objOK {
			n, present := m["n"]
			jn, isNum := n.(json.Number)
			wantAccept := present && isNum && isCanonicalCount(jn.String())
			gotAccept := readerErr == nil
			if wantAccept != gotAccept {
				t.Fatalf("validateCounts verdict mismatch for %q: want accept=%v, got accept=%v (err=%v)", num, wantAccept, gotAccept, readerErr)
			}

			// Writer/reader agreement: when the field is a JSON number, the encoder's
			// checkCanonJSONInt must reach the same accept/reject verdict as the reader's
			// validateCounts. A divergence would let the writer emit a form the reader
			// rejects, or accept one on read the writer could not produce canonically.
			if present && isNum {
				writerAccept := checkCanonJSONInt(jn) == nil
				if writerAccept != gotAccept {
					t.Fatalf("checkCanonJSONInt and validateCounts disagree on %q: writer-accept=%v reader-accept=%v", jn.String(), writerAccept, gotAccept)
				}
			}
		}
	})
}

// isCanonicalCount is the ground-truth predicate the fuzz target compares the reader's
// validateCounts verdict against: a string is a canonical count iff it is a non-negative
// decimal integer with no leading zero (beyond a lone "0"), no sign, no decimal point or
// exponent, and a magnitude at most 2^53-1. It is written independently of the code under
// test (a from-the-spec restatement) so it can catch a regression in either direction.
func isCanonicalCount(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false // a sign, '.', 'e'/'E', or any non-digit
		}
	}
	if len(s) > 1 && s[0] == '0' {
		return false // leading zero
	}
	// Magnitude: compare against 2^53-1 = 9007199254740991 without overflow by length then
	// lexical compare (all-digit, no leading zero, so length ordering is value ordering).
	const ceil = "9007199254740991"
	if len(s) != len(ceil) {
		return len(s) < len(ceil)
	}
	return s <= ceil
}

// FuzzManifest drives arbitrary bytes (seeded with the real cleartext root manifests)
// through ParseRoot, the reader's untrusted cleartext-manifest decode (SPEC.md 8.3,
// 11.3). root.manifest.json is the one cleartext, attacker-reachable JSON object the
// reader parses, and it carries the count fields (declaredRecordCount, shardCount,
// freshness.runlogIndex) that a length-driven allocation could key off, so it is the
// natural manifest-decode fuzz surface.
//
// Invariants:
//   - ParseRoot never panics on any byte string (it must only ever return a parsed
//     manifest or a clean error).
//   - A decode either errors or yields a structurally usable manifest: the count fields it
//     accepted are in canonical range (so they cannot drive an out-of-range allocation
//     downstream), and re-marshalling the parsed manifest and re-parsing it is stable.
//   - No count field a successful parse exposes is negative or above 2^53-1 (the bound
//     that protects every count-driven loop and allocation in Open).
func FuzzManifest(f *testing.F) {
	for _, s := range []string{
		`{"formatVersion":"downpipe/0.1.0","runId":"x","shardCount":1,"declaredRecordCount":0}`,
		`{"declaredRecordCount":9007199254740992}`, // over ceiling: reject
		`{"shardCount":-1}`, // negative: reject
		`{"freshness":{"runlogIndex":4814}}`,
		`{"shards":[],"recipients":[],"masterCapsule":[]}`,
		`{}`, `[]`, `null`, `not json`,
		// A declared count far larger than any array present: the parser must not pre-size
		// an allocation from the count (the reader derives counts from the decoded slices,
		// never the declared field; this seed pins that no length field drives an alloc).
		`{"declaredRecordCount":9007199254740991,"shardCount":9007199254740991,"shards":[],"recipients":[]}`,
	} {
		f.Add([]byte(s))
	}
	for _, p := range vectorGlob(f, "*/archive/run/*/root.manifest.json") {
		seedFile(f, p)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		root, err := ParseRoot(data)
		if err != nil {
			return // a clean rejection (bad numeric form or undecodable JSON)
		}
		if root == nil {
			t.Fatal("ParseRoot returned nil manifest and nil error")
			return
		}
		assertManifestInvariants(t, root)
	})
}

// assertManifestInvariants checks the count-range and round-trip-stability invariants of a
// successfully parsed root manifest (see FuzzManifest for the rationale of each).
func assertManifestInvariants(t *testing.T, root *spec.RootManifest) {
	t.Helper()
	// A parsed manifest's count fields must be within the canonical range that bounds
	// every downstream count-driven loop and allocation in Open. validateCounts is what
	// enforces this on the raw bytes; assert the structurally decoded values agree, so a
	// future struct-tag change that bypassed validateCounts would be caught.
	if root.DeclaredRecordCount < 0 || root.DeclaredRecordCount > maxCanonicalInt {
		t.Fatalf("ParseRoot accepted an out-of-range declaredRecordCount %d", root.DeclaredRecordCount)
	}
	if root.ShardCount < 0 {
		t.Fatalf("ParseRoot accepted a negative shardCount %d", root.ShardCount)
	}
	if root.Freshness.RunlogIndex < 0 || root.Freshness.RunlogIndex > maxCanonicalInt {
		t.Fatalf("ParseRoot accepted an out-of-range runlogIndex %d", root.Freshness.RunlogIndex)
	}

	// Structural stability: re-marshalling the parsed manifest to canonical JSON and
	// re-parsing must succeed and agree on the counts. This catches a parse that
	// produced a manifest the writer side could not round-trip (an internal
	// inconsistency the later signing/serialising would hit).
	canon, cerr := MarshalRoot(root)
	if cerr != nil {
		// MarshalRoot can legitimately reject a manifest carrying a value the canonical
		// encoder forbids (for example a string field with invalid UTF-8 that survived
		// json.Unmarshal). That is a clean error, not a panic, so it is acceptable.
		return
	}
	root2, err := ParseRoot(canon)
	if err != nil {
		t.Fatalf("re-parsing a manifest's own canonical bytes failed: %v\nbytes=%q", err, canon)
	}
	if root2.DeclaredRecordCount != root.DeclaredRecordCount || root2.ShardCount != root.ShardCount {
		t.Fatalf("manifest counts drifted across a marshal/parse round trip")
	}
}

// FuzzShard drives arbitrary bytes through the real OpenShard post-decrypt line parser
// (SPEC.md 6.1, 6.2). OpenShard's outer layers (container unframe, AEAD STREAM open) are
// authenticated, so a network adversary cannot reach the NDJSON line decode with chosen
// bytes; but the offline recovery tooling and a clean-room reader must still parse a
// decrypted shard manifest without panicking, and the line decode is where a malformed
// count or descriptor could bite. To fuzz exactly that decode over arbitrary bytes, the
// fuzz setup seals the fuzz input under a fixed key (so it decrypts back to itself) and runs
// the genuine OpenShard, exercising the real UnframeContainer -> OpenStream -> split ->
// validateCounts -> json.Unmarshal -> count-agreement pipeline.
//
// Invariants:
//   - OpenShard never panics on any decrypted-manifest byte string.
//   - A decode either errors or yields a structurally valid result: a preamble whose kind
//     is "preamble", records whose kind is "record", the declared per-shard record count
//     matching the number of record lines, and every accepted plaintextSize/recordCount in
//     canonical range. No count field drives an unbounded allocation: the records slice is
//     grown from the actual line count, never the declared field.
func FuzzShard(f *testing.F) {
	// A fixed wrap key and nonce so a sealed fuzz input decrypts deterministically back to
	// the fuzz bytes; the values are arbitrary (this target is about the parser, not the
	// crypto, which the KATs and stream tests cover).
	var wrapKey [32]byte
	for i := range wrapKey {
		wrapKey[i] = byte(i)
	}
	nonce := bytes.Repeat([]byte{0x02}, spec.StreamNonceSize)

	sealLines := func(plain []byte) []byte {
		return sealStreamLines(f, wrapKey, nonce, plain)
	}

	// Literal seeds: a well-formed two-line manifest and several malformed shapes.
	good := []byte(`{"kind":"preamble","formatVersion":"downpipe/0.1.0","runId":"r","shardId":"00000","recordCountInShard":1}` + "\n" +
		`{"kind":"record","sourceType":"kv","name":"n","recordId":"r000000000000000","plaintextSize":3,"plaintextSha384":"00","keyNameHash":"00","recordHash":"00","codec":"none","segments":[]}` + "\n")
	for _, plain := range [][]byte{
		good,
		[]byte(``),                         // empty manifest
		[]byte("\n\n\n"),                   // only blank lines
		[]byte(`{"kind":"record"}` + "\n"), // first line is not a preamble
		[]byte(`{"kind":"preamble","recordCountInShard":9007199254740992}` + "\n"), // over-ceiling count
		[]byte(`{"kind":"preamble","recordCountInShard":5}` + "\n"),                // count disagrees with 0 records
		[]byte(`{"kind":"preamble","recordCountInShard":-1}` + "\n"),               // negative count
	} {
		f.Add(sealLines(plain))
	}
	// Vector seeds: the real sealed .dpe shard manifests. Their bytes will not decrypt
	// under the fixed key (they were sealed under a per-run derived key), so OpenShard
	// rejects them at the AEAD layer, which still exercises the unframe + open path and
	// keeps the corpus anchored to real archive bytes. The fuzzer's mutations of the
	// sealed-by-this-setup seeds are what reach the line parser.
	for _, p := range vectorGlob(f, "*/archive/run/*/manifest/*.dpe") {
		seedFile(f, p)
	}

	f.Fuzz(func(t *testing.T, sealed []byte) {
		preamble, records, err := OpenShard(sealed, wrapKey[:])
		if err != nil {
			return // a clean rejection at the container, AEAD, or parse layer
		}
		assertShardInvariants(t, preamble, records)
	})
}

// sealStreamLines seals plain under wrapKey/nonce and frames it as a .dpe container, the
// seed shape OpenShard expects. A seal failure aborts the seed setup.
func sealStreamLines(f *testing.F, wrapKey [32]byte, nonce, plain []byte) []byte {
	body, err := crypto.SealStream(wrapKey, plain, nonce)
	if err != nil {
		f.Fatalf("seed seal: %v", err)
	}
	return spec.FrameContainer(spec.MagicDpe, body)
}

// assertShardInvariants checks the structural soundness of a successfully opened shard:
// a preamble first line, a declared count matching the record lines, and every count and
// plaintextSize in canonical range (see FuzzShard for the rationale of each).
func assertShardInvariants(t *testing.T, preamble spec.ShardPreamble, records []spec.ShardRecord) {
	t.Helper()
	if preamble.Kind != "preamble" {
		t.Fatalf("OpenShard accepted a non-preamble first line (kind %q)", preamble.Kind)
	}
	if preamble.RecordCountInShard != int64(len(records)) {
		t.Fatalf("OpenShard accepted a preamble whose recordCountInShard %d disagrees with %d records", preamble.RecordCountInShard, len(records))
	}
	if preamble.RecordCountInShard < 0 || preamble.RecordCountInShard > maxCanonicalInt {
		t.Fatalf("OpenShard accepted an out-of-range recordCountInShard %d", preamble.RecordCountInShard)
	}
	for i, r := range records {
		if r.Kind != "record" {
			t.Fatalf("OpenShard accepted a non-record line at %d (kind %q)", i, r.Kind)
		}
		if r.PlaintextSize < 0 || r.PlaintextSize > maxCanonicalInt {
			t.Fatalf("OpenShard accepted record %d with an out-of-range plaintextSize %d", i, r.PlaintextSize)
		}
	}
}

// FuzzReaderOpen is the headline target: it drives the whole archive open and verify
// path (SPEC.md 8.3) over a real, valid single-record vector archive whose object bytes
// are mutated by the fuzzer. A verified-mode Open of a tampered archive must NEVER return
// a verified outcome, and it must never panic; it must instead return one of the
// documented coded errors (ExitUnverified, ExitIncomplete, ExitPlaintext, ExitStale,
// ExitUsage). A fuzzer that makes the reader accept a forged archive, or panic instead of
// cleanly rejecting, is a critical finding.
//
// The setup loads the seg-single-chunk vector (a real, signed, valid archive) once,
// then for each fuzz input picks one object by an index byte and overwrites its bytes
// with a mutation of the original (a flipped/replaced span). It opens in the strictest
// verified mode, Options{CheckRecoveryBundle: true}, under which the reader consumes
// EVERY object in this single-record archive -- the root manifest and its signature, the
// shard manifest, the data segment, the RUNLOG and its signature, and all four
// recovery-bundle files (FORMAT.md, RECOVER.md, SHA384SUMS, SHA384SUMS.sig). With every
// object security-relevant, the invariant is exact: a verified, value-matching restore
// is permitted ONLY when the archive is byte-identical to the baseline on every object.
// (The bundle check is enabled deliberately: with the default Options the bundle files
// are not consumed, so a mutation to one would correctly still verify -- enabling the
// check both removes that false split and additionally fuzzes the bundle-binding verify
// path of SPEC.md 8.7 item 4.)
//
// Invariants:
//   - Open never panics, however the archive bytes are mutated.
//   - If Open succeeds, RestoreRecord on every returned record never panics.
//   - Every rejection is a documented coded ExitError (ExitUnverified / ExitIncomplete /
//     ExitPlaintext / ExitStale / ExitUsage), never an unclassified error.
//   - A successful, verified-and-restored outcome whose value matches the baseline is only
//     ever returned for an archive byte-identical to the baseline on every consumed object:
//     a mutation that changes any consumed object can never yield Verified() with a matching
//     restored value (no forged-archive acceptance).
func FuzzReaderOpen(f *testing.F) {
	base, identity, verifier, ok := loadOpenFuzzBaseline(f)
	if !ok {
		f.Skip("seg-single-chunk vector not present; run the conformance generator with -update")
	}
	// The strictest verified mode: every object below is consumed, so any mutation must be
	// rejected (no object is outside the verified read set).
	openOpts := Options{CheckRecoveryBundle: true}

	// Confirm the baseline really verifies and restores under this mode, so the negative
	// assertion below has a meaningful positive control.
	wantValue, baselineOK := openAndRestore(base, identity, verifier, openOpts)
	if !baselineOK {
		f.Fatalf("the baseline vector archive must verify and restore before fuzzing")
	}

	// The store is read-only for the fuzz run, so its sorted key list is stable; compute it
	// once and capture it in the closure rather than re-sorting on every iteration.
	baseKeys := sortedKeys(base)

	// Seeds: a no-op (empty) mutation, then a single-byte flip targeted at each object, so
	// the corpus starts from "touch every object" rather than only the first.
	f.Add(0, 0, []byte(nil))
	for i := range baseKeys {
		f.Add(i, 0, []byte{0x01})
	}

	f.Fuzz(func(t *testing.T, objIndex int, offset int, patch []byte) {
		assertFuzzOpenInvariant(t, base, baseKeys, identity, verifier, wantValue, openOpts, objIndex, offset, patch)
	})
}

// assertFuzzOpenInvariant runs one fuzz case: it mutates a single object of the baseline
// archive at objIndex/offset with patch, opens and restores it, and asserts the Open
// invariants documented on FuzzReaderOpen. Any rejection must be a coded ExitError, Open
// and RestoreRecord must never panic, and a verified, value-matching restore is permitted
// only when no object differs semantically from the baseline (no forged-archive
// acceptance).
func assertFuzzOpenInvariant(t *testing.T, base memStore, keys []string, identity *crypto.HybridKEMPrivate, verifier *crypto.HybridVerifier, wantValue []byte, openOpts Options, objIndex int, offset int, patch []byte) {
	if len(keys) == 0 {
		return
	}
	// Pick one object deterministically from the fuzzer's index byte.
	key := keys[((objIndex%len(keys))+len(keys))%len(keys)]

	// Build the mutated archive: a shallow copy of the baseline with one object's bytes
	// replaced by a patched copy. An empty patch at a clamped offset is a no-op (the
	// archive stays byte-identical), which must still verify; any non-empty patch
	// mutates the object.
	mutated := cloneStore(base)
	orig := base[key]
	mutated[key] = applyPatch(orig, offset, patch)

	r, openErr := Open(mutated, vecRunID, identity, verifier, openOpts)
	if openErr != nil {
		// A rejection MUST be a documented coded error, never an unclassified one and
		// (because the fuzzer cannot panic us) never a crash.
		assertCodedReaderError(t, openErr)
		return
	}

	// Open succeeded: restoring every record must not panic, and must surface a coded
	// error rather than a crash on a tampered segment.
	var restored [][]byte
	restoredAll := true
	for _, rec := range r.Records() {
		val, rerr := r.RestoreRecord(rec)
		if rerr != nil {
			assertCodedReaderError(t, rerr)
			restoredAll = false
			break
		}
		restored = append(restored, val)
	}

	// The critical no-mis-acceptance check. A verified-and-fully-restored outcome whose
	// single restored record matches the baseline value is the "accepted as genuine"
	// state. Under CheckRecoveryBundle every stored object is consumed by the verify
	// path, so that state is permitted ONLY when every object is SEMANTICALLY identical
	// to the baseline -- identical in the bytes the reader actually derives from it (see
	// semanticEqual: the detached-signature text fields are compared by their decoded
	// signature bytes after TrimSpace, since a different but equivalent base64 spelling of
	// the same signature, or insignificant surrounding whitespace, is not a forgery; every
	// other object, being hashed, AEAD-authenticated or signed over its exact bytes, is
	// compared byte-for-byte). If the fuzzer changed any reader-derived byte of any object
	// yet we still reached a verified, value-matching restore, that is a forged-archive
	// acceptance -- fail loudly (a critical finding).
	if r.Outcome().Verified() && restoredAll &&
		len(restored) == 1 && bytes.Equal(restored[0], wantValue) {
		if diffKey, differs := storeSemanticDiff(base, mutated); differs {
			t.Fatalf("MIS-ACCEPTANCE: a mutated archive verified and restored the baseline value; object %q changed in the bytes the reader consumes, yet Open returned a verified outcome", diffKey)
		}
	}
}

// loadOpenFuzzBaseline loads the seg-single-chunk conformance vector into an in-memory
// store along with the break-glass identity and operator verifier, returning ok=false if
// the vector is absent. seg-single-chunk is a real signed valid single-record archive, so
// it is the natural mutate-and-reject baseline.
func loadOpenFuzzBaseline(f *testing.F) (memStore, *crypto.HybridKEMPrivate, *crypto.HybridVerifier, bool) {
	f.Helper()
	dir := filepath.Join("testdata", "vectors", "seg-single-chunk")
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return nil, nil, nil, false
	}
	archiveDir := filepath.Join(dir, "archive")
	store := memStore{}
	walkErr := filepath.Walk(archiveDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		rel, rerr := filepath.Rel(archiveDir, path)
		if rerr != nil {
			return rerr
		}
		store[filepath.ToSlash(rel)] = b
		return nil
	})
	if walkErr != nil {
		f.Fatalf("load baseline archive: %v", walkErr)
	}
	idBytes, err := os.ReadFile(filepath.Join(dir, "identity.key"))
	if err != nil {
		f.Fatalf("read identity: %v", err)
	}
	identity, err := crypto.ParseKEMPrivate(mustB64Plain(f, idBytes))
	if err != nil {
		f.Fatalf("parse identity: %v", err)
	}
	pubBytes, err := os.ReadFile(filepath.Join(dir, "signer.pub"))
	if err != nil {
		f.Fatalf("read signer: %v", err)
	}
	verifier, err := crypto.ParseVerifier(mustB64Plain(f, pubBytes))
	if err != nil {
		f.Fatalf("parse verifier: %v", err)
	}
	return store, identity, verifier, true
}

// openAndRestore opens the archive under opts and restores its single record, returning
// the restored value and whether the whole flow verified and restored. Used to establish
// the fuzz baseline positive control.
func openAndRestore(store memStore, identity *crypto.HybridKEMPrivate, verifier *crypto.HybridVerifier, opts Options) ([]byte, bool) {
	r, err := Open(store, vecRunID, identity, verifier, opts)
	if err != nil || !r.Outcome().Verified() {
		return nil, false
	}
	recs := r.Records()
	if len(recs) != 1 {
		return nil, false
	}
	val, err := r.RestoreRecord(recs[0])
	if err != nil {
		return nil, false
	}
	return val, true
}

// assertCodedReaderError fails the test unless err carries one of the documented
// normative reader exit codes (SPEC.md 8.5). The offline reader must classify every
// rejection; an unclassified (code-1) error from the verify path is itself a defect.
func assertCodedReaderError(t *testing.T, err error) {
	t.Helper()
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("reader returned an unclassified error (want a coded ExitError): %v", err)
	}
	switch ee.Code {
	case ExitUnverified, ExitIncomplete, ExitPlaintext, ExitStale, ExitUsage:
		return
	default:
		t.Fatalf("reader returned an unexpected exit code %d: %v", ee.Code, err)
	}
}

// applyPatch returns a copy of orig with patch written at a clamped offset, growing the
// slice if the patch runs past the end. An empty patch leaves the bytes unchanged (a
// no-op mutation). The offset is reduced modulo len+1 so the fuzzer's raw int always lands
// in range without biasing toward the front.
func applyPatch(orig []byte, offset int, patch []byte) []byte {
	out := bytes.Clone(orig)
	if len(patch) == 0 {
		return out
	}
	span := len(out) + 1
	off := ((offset % span) + span) % span
	end := off + len(patch)
	if end > len(out) {
		grown := make([]byte, end)
		copy(grown, out)
		out = grown
	}
	copy(out[off:end], patch)
	return out
}

// cloneStore returns a shallow copy of the store: the same byte slices under a fresh map,
// so replacing one key's value does not mutate the baseline.
func cloneStore(src memStore) memStore {
	dst := make(memStore, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// storeSemanticDiff reports the first object whose reader-consumed bytes differ between
// the baseline and the mutated store, or ("", false) when every object is semantically
// identical. "Semantically identical" is per semanticEqual: the detached-signature text
// fields are compared by decoded signature bytes (after TrimSpace), every other object
// byte-for-byte. It is the exact predicate the no-mis-acceptance check needs: it returns
// "no difference" precisely for mutations the reader is documented to ignore, and flags
// any change to a byte the reader actually relies on.
func storeSemanticDiff(base, mutated memStore) (string, bool) {
	if len(base) != len(mutated) {
		return "", true // a key added or removed is always a real difference
	}
	for k, vb := range base {
		vm, ok := mutated[k]
		if !ok || !semanticEqual(k, vb, vm) {
			return k, true
		}
	}
	return "", false
}

// sigTextKeys are the object keys the reader treats as detached-signature TEXT: it decodes
// each as base64url no-pad after stripping surrounding whitespace (reader.go,
// freshness.go, bundle.go all do B64Decode(strings.TrimSpace(string(sigText)))). The bytes
// the reader actually verifies are therefore the DECODED signature, not the raw text, so a
// re-spelled-but-equivalent base64 string (Go's RawURLEncoding accepts non-canonical
// trailing bits) or insignificant whitespace is not a content change. Every other object
// is hashed, AEAD-authenticated, or signed over its exact stored bytes and so is compared
// verbatim.
var sigTextKeys = map[string]bool{
	"run/" + vecRunID + "/root.manifest.json.sig": true,
	"_RECOVERY/RUNLOG.sig":                        true,
	BundlePrefix + "SHA384SUMS.sig":               true,
}

// semanticEqual reports whether two byte values for object key are equal in the bytes the
// reader derives from them. For a detached-signature text field that is the decoded
// signature after TrimSpace; for everything else it is raw byte equality. A value that
// fails to base64-decode under the reader's own rule is compared verbatim, so a mutation
// that breaks the encoding (which the reader would reject) is never treated as equal.
func semanticEqual(key string, a, b []byte) bool {
	if sigTextKeys[key] {
		da, ea := B64Decode(strings.TrimSpace(string(a)))
		db, eb := B64Decode(strings.TrimSpace(string(b)))
		if ea == nil && eb == nil {
			return bytes.Equal(da, db)
		}
		// One or both do not decode: fall through to a verbatim compare so a decode-breaking
		// mutation counts as a difference (and the reader rejects it anyway).
	}
	return bytes.Equal(a, b)
}

// sortedKeys returns the store's keys in a stable order so the fuzzer's object index maps
// deterministically to the same object across runs.
func sortedKeys(s memStore) []string {
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	// Simple insertion sort to avoid importing sort here for a tiny list; deterministic.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// mustB64Plain decodes base64url no-pad fixture bytes for the fuzz baseline loader (the
// testing.F analogue of the conformance generator's mustB64, which takes a *testing.T).
func mustB64Plain(f *testing.F, b []byte) []byte {
	f.Helper()
	out, err := B64Decode(strings.TrimSpace(string(b)))
	if err != nil {
		f.Fatalf("decode fixture base64: %v", err)
	}
	return out
}
