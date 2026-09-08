package format

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// This file enumerates the downpipe/0.1.0 conformance corpus (SPEC.md 14.2 positive/edge
// vectors and 14.3 negative vectors) and the tamper helpers that cut the negatives. The
// generator in conformance_test.go iterates corpusVectors and replays each through
// replayVector. The authority split (SPEC.md 14.1) is preserved by construction: the
// writer-authoritative .seg(codec=none) and .dpe(manifestCodec=none) bytes are stored
// verbatim, while the non-reproducible capsule/root/signature/RUNLOG are reader-corpus
// objects whose outcome (not bytes) the replay asserts.

// Pinned values reused across vectors. The sizes pick the STREAM chunk boundaries
// (SPEC.md 7.8): one short value (single chunk), one spanning four chunks, and small
// values for the packed and dedup cases.
var (
	singleChunkValue = []byte("recover me without Cloudflare and without the vendor")
	multiChunkValue  = bytes.Repeat([]byte("DOWNPIPE-MULTI-CHUNK-"), (3*spec.ChunkSize+100)/21+1)[:3*spec.ChunkSize+100]
	gzipValue        = bytes.Repeat([]byte("compress me, downpipe gzip codec vector, "), 200)
	segmentValue     = []byte(strings.Repeat("alpha-", 40) + strings.Repeat("bravo-", 40) + strings.Repeat("charlie-", 40))
	dedupValue       = []byte("identical-non-secret-value-shared-across-two-runs")
	secretValue      = []byte("super-secret-api-token")
)

func ptrString(s string) *string { return &s }
func ptrBool(b bool) *bool       { return &b }

// corpusVectors is the full archive conformance corpus. The KAT vectors
// (kem-combiner-kat and friends) are generated separately and special-cased in
// TestConformance, so they are not listed here.
func corpusVectors() []corpusVector {
	return append(positiveVectors(), negativeVectors()...)
}

// positiveVectors is the corpus of archives a conformant reader MUST open and recover
// cleanly (SPEC.md 14.2). It is assembled from thematic sub-slices so each stays within the
// per-function length guardrail.
func positiveVectors() []corpusVector {
	// slices.Concat rather than repeated append onto a nil slice: it sizes the result once, and it
	// never writes into a caller's backing array, which repeated append can do when the first
	// argument already has spare capacity.
	return slices.Concat(
		positiveSegmentVectors(),
		positiveDedupCapsuleVectors(),
		positiveRunlogVectors(),
		positiveAnnotationVectors(),
	)
}

// positiveAnnotationVectors pins the OPTIONAL annotative record fields (SPEC.md 6.2,
// section 19) and the reprovision-type record shape: the fields are not record-hash
// inputs, so only these explicit expect assertions protect them cross-implementation.
func positiveAnnotationVectors() []corpusVector {
	d1Dump := []byte(`{"downpipeD1Dump":1,"tables":[{"name":"users","rows":[[1,"ada"]]}]}`)
	sentinel := []byte(`{"_vanished":true,"reason":"the object was deleted between list and read"}`)
	worker := []byte("export default { fetch() { return new Response(\"ok\") } }")
	return []corpusVector{
		{
			name: "d1-with-identity",
			spec: vectorSpec{dpID: "dp_d1id", records: []recordSpec{{
				name: "prod-db", srcType: "d1", value: d1Dump,
				database: "4f9a2c1e-8b3d-4e5f-9a70-1c2d3e4f5a6b", account: "acct-d1-identity",
				d1Format: "downpipe-d1-json-v1",
			}}},
			expect: vectorExpect{Mode: "positive", Records: []vectorRecord{{
				Name: "prod-db", ValueB64: B64Encode(d1Dump),
				Database: "4f9a2c1e-8b3d-4e5f-9a70-1c2d3e4f5a6b", Account: "acct-d1-identity",
			}}},
		},
		{
			name: "incomplete-marker",
			spec: vectorSpec{dpID: "dp_marker", records: []recordSpec{{
				name: "vanished-object", srcType: "r2", value: sentinel, marker: "_vanished",
			}}},
			expect: vectorExpect{Mode: "positive", Records: []vectorRecord{{
				Name: "vanished-object", ValueB64: B64Encode(sentinel), IncompleteMarker: "_vanished",
			}}},
		},
		{
			name: "reprovision-workers",
			spec: vectorSpec{dpID: "dp_workers", records: []recordSpec{{
				name: "api-worker/content", srcType: "workers", value: worker, account: "acct-workers",
			}}},
			expect: vectorExpect{Mode: "positive", Records: []vectorRecord{{
				Name: "api-worker/content", ValueB64: B64Encode(worker), Account: "acct-workers",
			}}},
		},
	}
}

// positiveSegmentVectors pins the basic segment shapes: empty, single-chunk, multi-chunk,
// a multi-segment chain and a packed shared segment.
func positiveSegmentVectors() []corpusVector {
	return []corpusVector{
		{
			name:   "seg-empty",
			spec:   vectorSpec{dpID: "dp_seg_empty", records: []recordSpec{{name: "empty", value: []byte{}}}},
			expect: vectorExpect{Mode: "positive", Records: recs("empty", []byte{})},
		},
		{
			name:   "seg-single-chunk",
			spec:   vectorSpec{dpID: "dp_single", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			expect: vectorExpect{Mode: "positive", Records: recs("object-a", singleChunkValue)},
		},
		{
			name:   "seg-multi-chunk",
			spec:   vectorSpec{dpID: "dp_multi", records: []recordSpec{{name: "object-big", srcType: "r2", value: multiChunkValue}}},
			expect: vectorExpect{Mode: "positive", Records: recs("object-big", multiChunkValue)},
		},
		{
			name:   "seg-multi-segment",
			spec:   vectorSpec{dpID: "dp_chain", records: []recordSpec{{name: "object-chain", srcType: "r2", value: segmentValue, segments: 3}}},
			expect: vectorExpect{Mode: "positive", Records: recs("object-chain", segmentValue)},
		},
		{
			name: "seg-packed",
			spec: vectorSpec{dpID: "dp_packed", records: []recordSpec{
				{name: "k1", value: []byte("first packed value"), packGroup: 1},
				{name: "k2", value: []byte("second packed value, longer"), packGroup: 1},
				{name: "k3", value: []byte("third"), packGroup: 1},
			}},
			expect: vectorExpect{Mode: "positive", Records: []vectorRecord{
				{Name: "k1", ValueB64: B64Encode([]byte("first packed value"))},
				{Name: "k2", ValueB64: B64Encode([]byte("second packed value, longer"))},
				{Name: "k3", ValueB64: B64Encode([]byte("third"))},
			}, SegCount: ptrInt(1)},
		},
	}
}

// positiveDedupCapsuleVectors pins cross-run dedup, the no-dedup secrets rule, the gzip
// codec, the master-capsule unwrap and the break-glass-only posture.
func positiveDedupCapsuleVectors() []corpusVector {
	return []corpusVector{
		{
			name: "dedup-same-value-two-runs",
			spec: vectorSpec{dpID: "dp_dedup", runs: 2, records: []recordSpec{{name: "shared", value: dedupValue}}},
			// One shared non-secret segment stored once (SPEC.md 14.2): both runs re-derive
			// the same content file key and open it. The latest run (B) opens cleanly; the
			// older run (A) opens under allow-stale and recovers the same shared segment.
			expect: vectorExpect{
				Mode: "positive", RunID: vecRunIDB, Records: recs("shared", dedupValue), SegCount: ptrInt(1),
				Also: []vectorExpect{{Mode: "positive", RunID: vecRunID, Records: recs("shared", dedupValue), Options: &expectOptions{AllowStale: true}}},
			},
		},
		{
			name: "secrets-no-dedup",
			spec: vectorSpec{dpID: "dp_secrets", records: []recordSpec{
				{name: "secret-a", value: secretValue, secret: true},
				{name: "secret-b", value: secretValue, secret: true},
			}},
			// Byte-identical secrets with distinct salts seal to distinct segments (SPEC.md
			// 14.2): two .seg objects, never deduped.
			expect: vectorExpect{Mode: "positive", Records: []vectorRecord{
				{Name: "secret-a", ValueB64: B64Encode(secretValue)},
				{Name: "secret-b", ValueB64: B64Encode(secretValue)},
			}, SegCount: ptrInt(2)},
		},
		{
			name:   "gzip-codec",
			spec:   vectorSpec{dpID: "dp_gzip", codec: spec.CodecNameGzip, records: []recordSpec{{name: "object-z", srcType: "r2", value: gzipValue}}},
			expect: vectorExpect{Mode: "positive", Records: recs("object-z", gzipValue)},
		},
		{
			name: "master-capsule",
			spec: vectorSpec{dpID: "dp_capsule", records: []recordSpec{{name: "object-c", srcType: "r2", value: singleChunkValue}}},
			// The reader unwraps the master, derives CAK/MK, and matches keyCommitment and
			// recipientSetHash; a successful open with breakGlassVerified proves section 8.6.
			expect: vectorExpect{Mode: "positive", Records: recs("object-c", singleChunkValue), Labels: &expectLabels{BreakGlassVerified: ptrBool(true)}},
		},
		{
			name: "break-glass-only",
			spec: vectorSpec{dpID: "dp_bg_only", posture: "bg-only", records: []recordSpec{{name: "object-b", value: singleChunkValue}}},
			// The single-recipient posture satisfies the mandatory-break-glass requirement.
			expect: vectorExpect{Mode: "positive", Records: recs("object-b", singleChunkValue), Labels: &expectLabels{BreakGlassVerified: ptrBool(true)}},
		},
	}
}

// positiveRunlogVectors pins the RUNLOG freshness edge cases a conformant reader ACCEPTS: a
// benign allocation gap and interleaved append order.
func positiveRunlogVectors() []corpusVector {
	return []corpusVector{
		{
			// A validly signed RUNLOG with a benign allocation gap: the second run is
			// re-pinned to index 3 (root and RUNLOG agree) and no index-2 entry exists. The
			// writer allocates indices from one account-global counter and appends an entry
			// only on successful finalise, so a failed or interleaving run leaves exactly
			// this hole; the per-downpipe prevRunId chain is linear (1 then 3, chained
			// through the first run) and SPEC.md 10 says an index gap is NOT an anomaly.
			// This vector pins the benign allocation-gap ACCEPTANCE cross-implementation: a
			// reader that still enforces per-downpipe index contiguity (the pre-amendment
			// rule) exits 5 here and fails the corpus. minRunlogIndex 1 is satisfied (the
			// RUNLOG maximum is 3) and keeps the freshness gate active per the projected
			// options on the freshness path rather than skipping it.
			name: "runlog-allocation-gap",
			spec: vectorSpec{dpID: "dp_allocgap", runs: 2, records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) {
				allocationGapRunlog(t, dir, signer, "dp_allocgap")
			},
			expect: vectorExpect{
				Mode: "positive", RunID: vecRunIDB, Records: recs("object-a", singleChunkValue),
				Options: &expectOptions{MinRunlogIndex: 1},
			},
		},
		{
			// A validly signed RUNLOG whose LINES are interleaved relative to index: the
			// index-3 entry precedes the index-1 entry in the document. Entries land at
			// FINALISE time, so concurrent runs interleave as a matter of course (the
			// first production fleet produced this within its first hour); line order
			// carries no signal because the whole-document signature anchors the bytes
			// (SPEC.md 10, amended). A conformant reader sorts by index and
			// ACCEPTS this; a reader that regressed to enforcing append order would
			// reject it with exit 5, so this positive vector fails closed against that.
			name: "runlog-interleaved-append",
			spec: vectorSpec{dpID: "dp_interleave", runs: 2, records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) {
				interleavedRunlog(t, dir, signer, "dp_interleave")
			},
			expect: vectorExpect{
				Mode: "positive", RunID: vecRunIDB, Records: recs("object-a", singleChunkValue),
				Options: &expectOptions{MinRunlogIndex: 1},
			},
		},
	}
}

// negativeVectors is the corpus of archives a conformant reader MUST reject (SPEC.md 14.3).
// It is assembled from thematic sub-slices so each stays within the per-function length
// guardrail.
func negativeVectors() []corpusVector {
	return slices.Concat(
		negativeAEADVectors(),
		negativeCapsuleVectors(),
		negativeSignatureVectors(),
		negativeNumericFormVectors(),
		negativeRunlogVectors(),
		negativeStructuralVectors(),
	)
}

// negativeAEADVectors exercise the per-chunk and per-record integrity gates: a truncated or
// reordered chunk and a flipped tag fail the AEAD (exit 2); a reordered segment chain passes
// the signature but fails the full-record plaintext hash (exit 4).
func negativeAEADVectors() []corpusVector {
	return []corpusVector{
		{
			name: "truncated-final-chunk",
			spec: vectorSpec{dpID: "dp_trunc", records: []recordSpec{{name: "object-big", srcType: "r2", value: multiChunkValue}}},
			tamper: func(t *testing.T, dir string, _ *crypto.HybridSigner) {
				// Truncate half the AES-256-GCM tag: enough to break authentication on the
				// final chunk without disturbing the STREAM nonce or any earlier chunk.
				truncateOneSeg(t, segDir(dir), spec.TagSize/2)
			},
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUnverified, Phase: "restore"},
		},
		{
			name:   "reordered-chunks",
			spec:   vectorSpec{dpID: "dp_reorder", records: []recordSpec{{name: "object-big", srcType: "r2", value: multiChunkValue}}},
			tamper: func(t *testing.T, dir string, _ *crypto.HybridSigner) { swapFirstTwoChunks(t, segDir(dir)) },
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUnverified, Phase: "restore"},
		},
		{
			name:   "flipped-tag",
			spec:   vectorSpec{dpID: "dp_tag", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, _ *crypto.HybridSigner) { flipFinalTagBit(t, segDir(dir)) },
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUnverified, Phase: "restore"},
		},
		{
			// The record's segment chain is sealed and signed in reversed order, so the
			// signature is valid but the reassembled bytes hash to the wrong value: the
			// full-record plaintext check fails (SPEC.md 14.3, the exit-4 branch).
			name:   "reordered-segments",
			spec:   vectorSpec{dpID: "dp_segorder", records: []recordSpec{{name: "object-chain", srcType: "r2", value: segmentValue, segments: 3}}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) { reverseRecordSegments(t, dir, signer) },
			expect: vectorExpect{Mode: "negative", ExitCode: ExitPlaintext, Phase: "restore"},
		},
	}
}

// negativeCapsuleVectors exercise the master-capsule and recipient-set gates: a dropped
// break-glass wrap, a re-signed missing-break-glass posture, a forged wrap to an unlisted
// recipient and a mutated recipient fingerprint.
func negativeCapsuleVectors() []corpusVector {
	return []corpusVector{
		{
			// The break-glass wrap is removed from masterCapsule[] WITHOUT re-signing, so in
			// verified mode Open fails at the signature gate over the mutated root (exit 2)
			// before the capsule is ever unwrapped. The recipient-set gate (SPEC.md 8.6 item
			// 2) is exercised instead by forged-capsule-wrap and missing-break-glass, which
			// re-sign. A hard structural gate, so no honest Outcome is produced to read labels.
			name:   "dropped-break-glass-wrap",
			spec:   vectorSpec{dpID: "dp_dropwrap", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, _ *crypto.HybridSigner) { dropBreakGlassWrap(t, dir) },
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUnverified, Phase: "open"},
		},
		{
			// The break-glass recipient and its wrap are dropped and breakGlassPresent set
			// false, re-signed so the signature is valid; the mandatory-break-glass gate
			// still refuses (SPEC.md 14.3 missing-break-glass).
			name:   "missing-break-glass",
			spec:   vectorSpec{dpID: "dp_nobg", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) { removeBreakGlass(t, dir, signer) },
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUnverified, Phase: "open"},
		},
		{
			// One capsule wrap is re-encapsulated to an attacker recipient and the root is
			// re-signed, so the signature is valid but the wrap addresses an unlisted
			// recipient and recipientSetHash no longer matches (SPEC.md 14.3).
			name:   "forged-capsule-wrap",
			spec:   vectorSpec{dpID: "dp_forge", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) { forgeCapsuleWrap(t, dir, signer) },
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUnverified, Phase: "open"},
		},
		{
			// A signed recipient fingerprint is changed to a different valid dpr1: form
			// without re-signing; the signature over canonical root bytes fails (SPEC.md
			// 14.3 mutated-recipient-fingerprint).
			name:   "mutated-recipient-fingerprint",
			spec:   vectorSpec{dpID: "dp_mutfp", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, _ *crypto.HybridSigner) { mutateRecipientFingerprint(t, dir) },
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUnverified, Phase: "open"},
		},
	}
}

// negativeSignatureVectors exercise the signature and Merkle gates: a tampered shard hash, a
// re-signed wrong Merkle root, an inflated record count, an absent or corrupt signature and a
// well-formed signature by the wrong signer.
func negativeSignatureVectors() []corpusVector {
	return []corpusVector{
		{
			name:   "shard-hash-mismatch",
			spec:   vectorSpec{dpID: "dp_shardhash", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, _ *crypto.HybridSigner) { tamperLastByte(t, shardPath(dir)) },
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUnverified, Phase: "open"},
		},
		{
			// The signed merkleRoot is replaced with a different valid hash and the root is
			// re-signed, so the signature passes and the Merkle recompute is what fails
			// (SPEC.md 8.3 item 2).
			name:   "wrong-merkle-root",
			spec:   vectorSpec{dpID: "dp_merkle", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) { corruptMerkleRoot(t, dir, signer) },
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUnverified, Phase: "open"},
		},
		{
			// declaredRecordCount declares one more record than the archive carries and is
			// re-signed, so readable coverage is below the declared count: this fires the
			// count-mismatch branch of checkCompleteness (SPEC.md 8.5 exit 3). Contrast the
			// separate deleted-shard vector, which exercises the shard-read-failure branch and
			// produces the same exit code by a distinct path.
			name:   "incomplete-record-count",
			spec:   vectorSpec{dpID: "dp_incomplete", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) { inflateDeclaredCount(t, dir, signer) },
			expect: vectorExpect{Mode: "negative", ExitCode: ExitIncomplete, Phase: "open"},
		},
		{
			name:   "absent-signature",
			spec:   vectorSpec{dpID: "dp_nosig", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, _ *crypto.HybridSigner) { removeFile(t, rootSigPath(dir)) },
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUnverified, Phase: "open", Labels: &expectLabels{SignatureResult: ptrString("absent")}},
		},
		{
			name:   "bad-signature",
			spec:   vectorSpec{dpID: "dp_badsig", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, _ *crypto.HybridSigner) { corruptSignatureEncoding(t, dir) },
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUnverified, Phase: "open", Labels: &expectLabels{SignatureResult: ptrString("invalid")}},
		},
		{
			// Validly signed by a different key; the reader is given the original signer, so
			// the signature is well-formed but by the wrong signer (SPEC.md 14.3). The
			// manifest's self-asserted fingerprint must not rescue it.
			name:   "unknown-signer",
			spec:   vectorSpec{dpID: "dp_unknownsigner", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, _ *crypto.HybridSigner) { resignWithForeignSigner(t, dir) },
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUnverified, Phase: "open", Labels: &expectLabels{SignatureResult: ptrString("wrong-signer")}},
		},
	}
}

// negativeNumericFormVectors exercise the canonical-form gates: non-canonical JSON, a count
// above 2^53-1, an in-range count carried as a string and a single-half signature.
func negativeNumericFormVectors() []corpusVector {
	return []corpusVector{
		{
			// The root is re-serialised with reordered keys and added whitespace so it is
			// valid JSON but not RFC 8785 canonical; the signature over canonical bytes
			// fails (SPEC.md 14.3 non-canonical-json).
			name:   "non-canonical-json",
			spec:   vectorSpec{dpID: "dp_noncanon", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, _ *crypto.HybridSigner) { reserializeRootNonCanonical(t, dir) },
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUnverified, Phase: "open"},
		},
		{
			// declaredRecordCount encoded as the JSON number 9007199254740993 (above
			// 2^53-1) and re-signed, so the reader passes the signature gate and rejects the
			// out-of-range numeric form at the count check (SPEC.md 11.3, 14.3). A post-sign
			// flip would fail the signature (exit 2) before the count check, so the edited
			// bytes are re-signed.
			name: "count-over-2pow53",
			spec: vectorSpec{dpID: "dp_bigcount", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) {
				signRawEdited(t, dir, signer, replaceCountForm("9007199254740993"))
			},
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUsage, Phase: "open"},
		},
		{
			// declaredRecordCount encoded as the decimal string "9831242" (the form reserved
			// for values above the ceiling) for an in-range value, re-signed; the reader
			// rejects the non-canonical string form (SPEC.md 11.3, 14.3).
			name: "in-range-count-as-string",
			spec: vectorSpec{dpID: "dp_strcount", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) {
				signRawEdited(t, dir, signer, replaceCountForm(`"9831242"`))
			},
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUsage, Phase: "open"},
		},
		{
			// declaredRecordCount edited to the byte sequence "01" (a leading zero on an
			// otherwise in-range integer) and re-signed. This is SPEC.md 11.3's leading-zero
			// prohibition, but "01" is not valid JSON syntax at all (RFC 8259's int
			// production is "0" or a non-zero digit followed by digits): json.Decoder.Decode
			// refuses it before a json.Number carrying "01" ever exists, so this vector
			// exercises the decode-level rejection in ParseRoot/validateCounts, not
			// checkCanonicalCount's own leading-zero clause specifically (proven live:
			// disabling that clause changes nothing, this vector still correctly rejects).
			// Kept because SPEC 11.3 names the leading-zero form and no other vector pins the
			// reader's outcome for it; the property proved is "the reader rejects this exact
			// byte sequence", true regardless of which layer catches it.
			name: "leading-zero-count",
			spec: vectorSpec{dpID: "dp_leadingzero", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) {
				signRawEdited(t, dir, signer, replaceCountForm("01"))
			},
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUsage, Phase: "open"},
		},
		{
			// declaredRecordCount encoded as the JSON number "-1" (a negative count; the
			// struct path can never produce this since the field is a non-negative int64 in
			// practice, so only a raw edit reaches this guard) and re-signed. This is the one
			// guard clause in checkCanonicalCount proven load-bearing in isolation: disabling
			// only the "-" prefix check flips exactly this vector to a false accept while
			// every other vector, including leading-zero-count and non-integer-count, is
			// unaffected (num.Int64() parses "-1" without error and a negative value is never
			// above the ceiling, so nothing downstream catches it either). SPEC.md 11.3, 14.3.
			name: "negative-count",
			spec: vectorSpec{dpID: "dp_negcount", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) {
				signRawEdited(t, dir, signer, replaceCountForm("-1"))
			},
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUsage, Phase: "open"},
		},
		{
			// declaredRecordCount encoded as the JSON number "1.0" (a decimal-point literal,
			// valid JSON unlike leading-zero-count's "01"); a count is an integer literal
			// only, no decimal point or exponent form is canonical (SPEC.md 11.3). The
			// explicit ".eE" check in checkCanonicalCount is redundant with the num.Int64()
			// parse a few lines below it (strconv.ParseInt rejects "1.0" too, via a different
			// error message but the same exit code), proven live by disabling the ".eE" check
			// alone: this vector still correctly rejects. Kept for the same reason as
			// leading-zero-count: it pins the reader's overall outcome for a form SPEC 11.3
			// names, independent of which internal layer enforces it.
			name: "non-integer-count",
			spec: vectorSpec{dpID: "dp_floatcount", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) {
				signRawEdited(t, dir, signer, replaceCountForm("1.0"))
			},
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUsage, Phase: "open"},
		},
	}
}

// negativeRunlogVectors exercise the freshness and RUNLOG-integrity gates: a stale run, a
// rollback below a pinned index, a forked or duplicated index, an absent RUNLOG and a
// tampered recovery bundle.
func negativeRunlogVectors() []corpusVector {
	return []corpusVector{
		{
			// Two runs in the RUNLOG; opening the older run is stale (not latest) and exits
			// 5 without --allow-stale, and proceeds recording isLatestForDownpipe false with
			// it (SPEC.md 14.3 stale-run). The Also check restores the older run under
			// allow-stale.
			name: "stale-run",
			spec: vectorSpec{dpID: "dp_stale", runs: 2, records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			expect: vectorExpect{
				Mode: "negative", RunID: vecRunID, ExitCode: ExitStale, Phase: "open",
				Also: []vectorExpect{{Mode: "positive", RunID: vecRunID, Records: recs("object-a", singleChunkValue), Options: &expectOptions{AllowStale: true}}},
			},
		},
		{
			// The RUNLOG is truncated back to the single older entry and re-signed (a valid
			// older RUNLOG) while the reader pins --min-runlog-index to the newer index; the
			// RUNLOG maximum index is below the pin (SPEC.md 10, 14.3 runlog-rollback).
			name: "runlog-rollback",
			spec: vectorSpec{dpID: "dp_rollback", runs: 2, records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) {
				rollbackRunlog(t, dir, signer, "dp_rollback")
			},
			expect: vectorExpect{Mode: "negative", RunID: vecRunID, ExitCode: ExitStale, Phase: "open", Options: &expectOptions{MinRunlogIndex: 2}},
		},
		{
			// A validly signed RUNLOG whose restored run skips a link: the restored run
			// (re-pinned to index 3) chains back to the index-1 run while the index-2 entry,
			// its true parent, remains present, so its prevRunId names its grandparent. Under
			// the amended SPEC.md 10 this is the per-downpipe LINEARITY violation (an entry
			// removed from or rewritten in the middle of the chain), and detectChainAnomaly's
			// linearity pass reports it before the fork branch even though entries 2 and 3
			// also share prevRunId; the exit code is what the vector pins, so the firing
			// branch moving from the fork check to the linearity check is fine. The indices
			// are monotonic and every prevRunId resolves, so neither the append-order nor the
			// dangling branch can fire, and the restored run remains the maximum for its
			// downpipe, so the not-latest check is not what rejects it either. This shape IS
			// the skipped-link (grandparent) case, so a separate runlog-skipped-link vector
			// would duplicate it; a rewritten chain (exit 5).
			name: "runlog-forked-prevrunid",
			spec: vectorSpec{dpID: "dp_forkprev", runs: 2, records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) {
				forkRunlog(t, dir, signer, "dp_forkprev")
			},
			expect: vectorExpect{Mode: "negative", RunID: vecRunIDB, ExitCode: ExitStale, Phase: "open"},
		},
		{
			// A validly signed RUNLOG carrying two entries with the SAME index: the
			// account-global counter never reissues one, so a duplicate means the log
			// was corrupted or hand-assembled (SPEC.md 10, amended: the
			// duplicate replaced append-order as the index-axis anomaly). The restored
			// run is the maximum for its downpipe and every prevRunId resolves, so the
			// rejection comes solely from the duplicate-index detector (exit 5).
			name: "runlog-duplicate-index",
			spec: vectorSpec{dpID: "dp_dupindex", runs: 2, records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) {
				duplicateIndexRunlog(t, dir, signer, "dp_dupindex")
			},
			expect: vectorExpect{Mode: "negative", RunID: vecRunIDB, ExitCode: ExitStale, Phase: "open"},
		},
		{
			name: "absent-runlog",
			spec: vectorSpec{dpID: "dp_norunlog", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, _ *crypto.HybridSigner) {
				removeFile(t, filepath.Join(dir, "archive", "_RECOVERY", "RUNLOG"))
			},
			expect: vectorExpect{Mode: "negative", ExitCode: ExitStale, Phase: "open"},
		},
		{
			// The vendored FORMAT.md is altered so its SHA-384 no longer matches the bundle's
			// signed SHA384SUMS; with --check-bundle the section 8.7 item-4 gate fails
			// (SPEC.md 14.3 recovery-bundle-tampered). The label is read through an
			// allow-unverified re-open that still runs the bundle check.
			name:   "recovery-bundle-tampered",
			spec:   vectorSpec{dpID: "dp_bundle", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, _ *crypto.HybridSigner) { tamperBundleFile(t, dir) },
			expect: vectorExpect{
				Mode: "negative", ExitCode: ExitUnverified, Phase: "open",
				Options: &expectOptions{CheckRecoveryBundle: true},
				Labels:  &expectLabels{RecoveryBundleVerified: ptrBool(false)},
			},
		},
	}
}

// negativeStructuralVectors exercise the structural format gates (exit 6 unless noted): a
// single-half signature, a compressed secrets record, a per-record codec that differs from
// the envelope, an unknown major, and a deleted shard (exit 3).
func negativeStructuralVectors() []corpusVector {
	return []corpusVector{
		{
			// The detached signature is replaced with only the Ed25519 half (64 bytes,
			// correctly base64url-encoded). Both halves are required (SPEC.md 8.1); a
			// signature shorter than Ed25519 + 1 byte is structurally invalid rather than a
			// wrong-signer result, so signatureResult is "invalid" not "wrong-signer".
			name:   "single-half-signature",
			spec:   vectorSpec{dpID: "dp_halfhsig", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, _ *crypto.HybridSigner) { writeHalfSignature(t, dir) },
			expect: vectorExpect{
				Mode: "negative", ExitCode: ExitUnverified, Phase: "open",
				Labels: &expectLabels{SignatureResult: ptrString("invalid")},
			},
		},
		{
			// Base secrets-no-dedup: one secret record's codec is set to "gzip" in the
			// shard manifest (re-sealed and re-signed so the signature passes) while the
			// envelope codec remains "none". A secrets record MUST NOT be compressed
			// (SPEC.md 5.2, 12.4); the reader rejects with exit 6.
			name: "secrets-with-compression",
			spec: vectorSpec{dpID: "dp_secretgzip", records: []recordSpec{
				{name: "secret-a", value: secretValue, secret: true},
				{name: "secret-b", value: secretValue, secret: true},
			}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) {
				setFirstRecordCodec(t, dir, signer, "gzip")
			},
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUsage, Phase: "open"},
		},
		{
			// Base seg-multi-segment (envelope codec=none): one record's codec field in the
			// shard manifest is set to "gzip" (re-sealed and re-signed). The codec must be
			// run-wide and uniform (SPEC.md 5.2); a per-record codec that differs from the
			// envelope codec is a format violation; exit 6.
			name: "mixed-codec",
			spec: vectorSpec{dpID: "dp_mixedcodec", records: []recordSpec{{name: "object-chain", srcType: "r2", value: segmentValue, segments: 3}}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) {
				setFirstRecordCodec(t, dir, signer, "gzip")
			},
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUsage, Phase: "open"},
		},
		{
			// A record whose sourceType is outside the supported set must be refused up
			// front (SPEC.md 12.1): each source restores differently, so an unknown type is
			// never restored as opaque bytes under a guessed behaviour. durable_object is
			// the reserved, never-emitted example.
			name:   "unknown-source-type",
			spec:   vectorSpec{dpID: "dp_unksrc", records: []recordSpec{{name: "object-a", srcType: "durable_object", value: singleChunkValue}}},
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUsage, Phase: "open"},
		},
		{
			// An envelope codec outside the closed {none, gzip} set must be refused at open
			// (SPEC.md 5.2): before this gate a uniformly relabelled archive was silently
			// decrypted as codec none. The root is edited and re-signed, so only the
			// membership gate can be the refusal.
			name:   "unknown-codec",
			spec:   vectorSpec{dpID: "dp_unkcodec", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) { setUnknownEnvelopeCodec(t, dir, signer) },
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUsage, Phase: "open"},
		},
		{
			// The root manifest's formatVersion is set to "downpipe/9.0.0" (a version this
			// reader does not implement) and re-signed. The reader MUST refuse it before
			// parsing the body (SPEC.md 13, 14.3); exit 6.
			name:   "unknown-major",
			spec:   vectorSpec{dpID: "dp_unknownmajor", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) { setUnknownMajor(t, dir, signer) },
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUsage, Phase: "open"},
		},
		{
			// formatVersion set to "downpipe/0.2.0": the same major this reader implements
			// and a minor it does not, re-signed so only the version gate can refuse it. The
			// compatibility unit is the MINOR while the major is 0 (SPEC.md 13), so a shared
			// major buys nothing; exit 6, the same as unknown-major. Without this vector the
			// corpus cannot tell a minor-scoped reader from a major-scoped one, which is how
			// an internal policy promising "a reader at major N reads every archive at major
			// N or below" survived unrefuted next to a reader that never did that.
			name:   "unimplemented-minor",
			spec:   vectorSpec{dpID: "dp_unimplminor", records: []recordSpec{{name: "object-a", srcType: "r2", value: singleChunkValue}}},
			tamper: func(t *testing.T, dir string, signer *crypto.HybridSigner) { setUnimplementedMinor(t, dir, signer) },
			expect: vectorExpect{Mode: "negative", ExitCode: ExitUsage, Phase: "open"},
		},
		{
			// A true two-shard archive: records split across shard "00000" and shard "00001".
			// One shard file is removed after the archive is built; readable coverage falls
			// below declaredRecordCount (SPEC.md 8.5, 14.3 deleted-shard); exit 3.
			name:   "deleted-shard",
			spec:   vectorSpec{dpID: "dp_delshard"},
			tamper: buildAndDeleteOneShard,
			expect: vectorExpect{Mode: "negative", ExitCode: ExitIncomplete, Phase: "open"},
		},
	}
}

// recs builds a single-record positive expectation.
func recs(name string, value []byte) []vectorRecord {
	return []vectorRecord{{Name: name, ValueB64: B64Encode(value)}}
}

func ptrInt(n int) *int { return &n }

// --- path helpers ---

func archiveDir(dir string) string { return filepath.Join(dir, "archive") }
func segDir(dir string) string     { return filepath.Join(archiveDir(dir), "seg") }
func runDir(dir, runID string) string {
	return filepath.Join(archiveDir(dir), "run", runID)
}
func rootPath(dir string) string { return filepath.Join(runDir(dir, vecRunID), "root.manifest.json") }
func rootSigPath(dir string) string {
	return filepath.Join(runDir(dir, vecRunID), "root.manifest.json.sig")
}
func shardPath(dir string) string {
	return filepath.Join(runDir(dir, vecRunID), "manifest", "00000.dpe")
}

// --- byte-level tampers ---

func removeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

// truncateOneSeg cuts n bytes from the end of one .seg, so the final STREAM chunk's
// AES-256-GCM tag is incomplete and authentication fails on restore.
func truncateOneSeg(t *testing.T, segRoot string, n int) {
	t.Helper()
	path := firstSeg(t, segRoot)
	b := readVecFile(t, path)
	if len(b) <= n {
		t.Fatalf("segment %s is too short to truncate by %d", path, n)
	}
	writeVecFile(t, path, b[:len(b)-n])
}

// swapFirstTwoChunks swaps the first two full STREAM chunk ciphertexts within one .seg,
// so the chunk counter no longer matches the position and authentication fails.
func swapFirstTwoChunks(t *testing.T, segRoot string) {
	t.Helper()
	path := firstSeg(t, segRoot)
	b := readVecFile(t, path)
	body, err := spec.UnframeContainer(spec.MagicSeg, b)
	if err != nil {
		t.Fatal(err)
	}
	const full = spec.ChunkSize + spec.TagSize
	if len(body) < spec.StreamNonceSize+2*full {
		t.Fatalf("segment %s has fewer than two full chunks to swap", path)
	}
	nonce := body[:spec.StreamNonceSize]
	rest := body[spec.StreamNonceSize:]
	c0 := append([]byte(nil), rest[:full]...)
	c1 := append([]byte(nil), rest[full:2*full]...)
	swapped := make([]byte, 0, len(body))
	swapped = append(swapped, nonce...)
	swapped = append(swapped, c1...)
	swapped = append(swapped, c0...)
	swapped = append(swapped, rest[2*full:]...)
	writeVecFile(t, path, spec.FrameContainer(spec.MagicSeg, swapped))
}

// flipFinalTagBit flips one bit of the last 16 bytes (the AES-256-GCM tag) of a .seg, so
// the chunk fails authentication on restore.
func flipFinalTagBit(t *testing.T, segRoot string) {
	t.Helper()
	path := firstSeg(t, segRoot)
	b := readVecFile(t, path)
	if len(b) < spec.TagSize {
		t.Fatalf("segment %s shorter than a tag", path)
	}
	b[len(b)-1] ^= 0x01
	writeVecFile(t, path, b)
}

func firstSeg(t *testing.T, segRoot string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(segRoot, "*", "*.seg"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("no segment under %s", segRoot)
	}
	return matches[0]
}

// --- root edits without re-signing (the signature gate catches them) ---

// dropBreakGlassWrap removes the break-glass recipient's wrap from masterCapsule[] in the
// stored root, leaving recipients and the envelope intact and not re-signing.
func dropBreakGlassWrap(t *testing.T, dir string) {
	t.Helper()
	root := readRoot(t, dir)
	bgFP := breakGlassFingerprint(t, root)
	kept := root.MasterCapsule[:0]
	for _, w := range root.MasterCapsule {
		if w.Fingerprint != bgFP {
			kept = append(kept, w)
		}
	}
	root.MasterCapsule = kept
	writeRootNoResign(t, dir, root)
}

// mutateRecipientFingerprint changes the break-glass recipient's fingerprint to a
// different but well-formed dpr1: value without re-signing.
func mutateRecipientFingerprint(t *testing.T, dir string) {
	t.Helper()
	root := readRoot(t, dir)
	for i := range root.Recipients {
		if root.Recipients[i].Role == "break-glass" {
			raw, err := hex.DecodeString(strings.TrimPrefix(root.Recipients[i].Fingerprint, "dpr1:"))
			if err != nil {
				t.Fatal(err)
			}
			raw[0] ^= 0x01
			root.Recipients[i].Fingerprint = "dpr1:" + hex.EncodeToString(raw)
			break
		}
	}
	writeRootNoResign(t, dir, root)
}

// corruptSignatureEncoding makes the stored detached signature undecodable as base64url,
// so the reader records signatureResult invalid (SPEC.md 8.3).
func corruptSignatureEncoding(t *testing.T, dir string) {
	t.Helper()
	// A NUL byte is outside the base64url alphabet, so B64Decode fails and the reader
	// classifies the signature as invalid rather than wrong-signer.
	writeVecFile(t, rootSigPath(dir), []byte("@@not-base64@@"))
}

// reserializeRootNonCanonical rewrites root.manifest.json as valid but non-canonical JSON
// (struct field order, indented) so the signature over canonical bytes no longer matches.
func reserializeRootNonCanonical(t *testing.T, dir string) {
	t.Helper()
	root := readRoot(t, dir)
	// json.MarshalIndent emits struct fields in declaration order with whitespace, which
	// is valid JSON but not the RFC 8785 canonical (sorted, minified) form.
	b, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeVecFile(t, rootPath(dir), b)
}

// --- root edits with re-signing (a valid signature over the mutated bytes) ---

// removeBreakGlass drops the break-glass recipient and its wrap, clears breakGlassPresent,
// and re-signs, so only the mandatory-break-glass gate (not the signature) refuses.
func removeBreakGlass(t *testing.T, dir string, signer *crypto.HybridSigner) {
	t.Helper()
	root := readRoot(t, dir)
	bgFP := breakGlassFingerprint(t, root)
	recipients := root.Recipients[:0]
	for _, rc := range root.Recipients {
		if rc.Role != "break-glass" {
			recipients = append(recipients, rc)
		}
	}
	root.Recipients = recipients
	wraps := root.MasterCapsule[:0]
	for _, w := range root.MasterCapsule {
		if w.Fingerprint != bgFP {
			wraps = append(wraps, w)
		}
	}
	root.MasterCapsule = wraps
	root.BreakGlassPresent = false
	resignRoot(t, dir, root, signer)
}

// forgeCapsuleWrap re-encapsulates one wrap to a fresh attacker recipient and re-signs, so
// the signature is valid but the wrap addresses an unlisted recipient and recipientSetHash
// no longer matches.
func forgeCapsuleWrap(t *testing.T, dir string, signer *crypto.HybridSigner) {
	t.Helper()
	root := readRoot(t, dir)
	_, attacker, err := crypto.GenerateHybridKEM()
	if err != nil {
		t.Fatal(err)
	}
	kc, err := hex.DecodeString(root.KeyCommitment)
	if err != nil {
		t.Fatal(err)
	}
	// Wrap an arbitrary 32-byte secret to the attacker; the contents are irrelevant
	// because the recipient-set check rejects the wrap before any unwrap is attempted.
	wraps, err := crypto.SealToRecipients([32]byte(fixedMaster()), []*crypto.HybridKEMPublic{attacker}, kc, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w := wraps[0]
	root.MasterCapsule[len(root.MasterCapsule)-1] = spec.CapsuleWrap{
		Fingerprint: w.Fingerprint, KEMCiphertext: B64Encode(w.KEMCiphertext), Sealed: B64Encode(w.Sealed),
	}
	resignRoot(t, dir, root, signer)
}

// corruptMerkleRoot replaces the signed merkleRoot with a different valid hash and
// re-signs, so the signature passes and the Merkle recompute is the gate that fails.
func corruptMerkleRoot(t *testing.T, dir string, signer *crypto.HybridSigner) {
	t.Helper()
	root := readRoot(t, dir)
	raw, err := hex.DecodeString(root.MerkleRoot)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0x01
	root.MerkleRoot = hex.EncodeToString(raw)
	resignRoot(t, dir, root, signer)
}

// inflateDeclaredCount declares one more record than the archive carries and re-signs, so
// readable coverage falls below the declared count and the reader reports incomplete.
func inflateDeclaredCount(t *testing.T, dir string, signer *crypto.HybridSigner) {
	t.Helper()
	root := readRoot(t, dir)
	root.DeclaredRecordCount++
	resignRoot(t, dir, root, signer)
}

// resignWithForeignSigner re-signs the unchanged root with a freshly generated signer the
// reader was not given, so the signature is well-formed but by the wrong signer.
func resignWithForeignSigner(t *testing.T, dir string) {
	t.Helper()
	foreign, _, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	rootBytes := readVecFile(t, rootPath(dir))
	sig, err := foreign.Sign(rootBytes)
	if err != nil {
		t.Fatal(err)
	}
	writeVecFile(t, rootSigPath(dir), []byte(B64Encode(sig)))
}

// signRawEdited canonicalises the stored root, applies a raw byte edit (a non-canonical
// count form the int64 struct path cannot emit), then signs the EDITED bytes so the
// reader passes the signature gate and reaches the count check (SPEC.md 11.3). It writes
// both the edited root and the matching signature.
func signRawEdited(t *testing.T, dir string, signer *crypto.HybridSigner, edit func([]byte) []byte) {
	t.Helper()
	rootBytes := readVecFile(t, rootPath(dir))
	edited := edit(rootBytes)
	if bytes.Equal(edited, rootBytes) {
		t.Fatal("count-form edit made no change; the replacement target was not found")
	}
	sig, err := signer.Sign(edited)
	if err != nil {
		t.Fatal(err)
	}
	writeVecFile(t, rootPath(dir), edited)
	writeVecFile(t, rootSigPath(dir), []byte(B64Encode(sig)))
}

// replaceCountForm returns an edit that replaces the canonical declaredRecordCount integer
// with a non-canonical form (an over-ceiling number or a string). The canonical root has
// no whitespace, so the target is the literal "declaredRecordCount":<n>.
func replaceCountForm(form string) func([]byte) []byte {
	return func(b []byte) []byte {
		s := string(b)
		const key = `"declaredRecordCount":`
		i := strings.Index(s, key)
		if i < 0 {
			return b
		}
		j := i + len(key)
		k := j
		for k < len(s) && s[k] != ',' && s[k] != '}' {
			k++
		}
		return []byte(s[:j] + form + s[k:])
	}
}

// --- segment-order negative (sealed and signed reversed) ---

// reverseRecordSegments re-seals the run with the record's segment list reversed and
// re-signs, so the archive is internally consistent (valid signature, matching shard hash)
// but reassembles the chain in the wrong order and fails the full-record plaintext check.
func reverseRecordSegments(t *testing.T, dir string, signer *crypto.HybridSigner) {
	t.Helper()
	master := fixedMaster()
	runIDBytes, err := spec.DecodeULID(vecRunID)
	if err != nil {
		t.Fatal(err)
	}
	// Re-open the sealed shard to recover the records, reverse the one record's segments,
	// re-seal the shard, and re-sign the root with the new shard hash.
	mk := crypto.DeriveMK(master, runIDBytes)
	shardBytes := readVecFile(t, shardPath(dir))
	preamble, records, err := OpenShard(shardBytes, crypto.DeriveManifestWrapKey(mk, runIDBytes, "00000"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range records {
		if len(records[i].Segments) > 1 {
			segs := records[i].Segments
			for l, r := 0, len(segs)-1; l < r; l, r = l+1, r-1 {
				segs[l], segs[r] = segs[r], segs[l]
			}
			rh, err := RecordHashOf(records[i])
			if err != nil {
				t.Fatal(err)
			}
			records[i].RecordHash = hex.EncodeToString(rh) // unchanged: recordHash omits segments
		}
	}
	resealed, shardSHA, err := SealShard(preamble, records, crypto.DeriveManifestWrapKey(mk, runIDBytes, "00000"), fixedNonce())
	if err != nil {
		t.Fatal(err)
	}
	writeVecFile(t, shardPath(dir), resealed)
	root := readRoot(t, dir)
	root.Shards[0].SHA384 = shardSHA
	resignRoot(t, dir, root, signer)
}

// --- RUNLOG rollback ---

// rollbackRunlog rewrites the RUNLOG to only the first entry and re-signs it (a valid
// older RUNLOG), so a reader pinning --min-runlog-index to the newer index sees the max
// index below the pin.
func rollbackRunlog(t *testing.T, dir string, signer *crypto.HybridSigner, dpID string) {
	t.Helper()
	entries := []spec.RunlogEntry{{
		Index: 1, RunID: vecRunID, DownpipeID: dpID, Time: "2026-06-06T12:00:30.000Z",
		RecordCount: 1, PrevRunID: nil, Status: "active",
	}}
	runlogBytes, err := MarshalRunlog(entries)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(runlogBytes)
	if err != nil {
		t.Fatal(err)
	}
	writeVecFile(t, filepath.Join(dir, "archive", "_RECOVERY", "RUNLOG"), runlogBytes)
	writeVecFile(t, filepath.Join(dir, "archive", "_RECOVERY", "RUNLOG.sig"), []byte(B64Encode(sig)))
}

// --- RUNLOG chain shapes (SPEC.md 10): the benign allocation gap and the anomalies ---

// vecRunIDC is a third valid ULID used only as a synthetic RUNLOG entry id in the
// skipped-link vector. It need not name an on-disk run: the freshness check resolves the
// archived bytes only for the restored run, and detectChainAnomaly inspects the RUNLOG
// entries as data, so an extra entry can break the chain without a backing run directory
// (freshness.go detectChainAnomaly).
const vecRunIDC = "01ARZ3NDEKTSV4RRFFQ69G5FC1"

// writeSignedRunlog marshals the entries to canonical NDJSON, signs them with the same
// signer the archive root trusts, and writes _RECOVERY/RUNLOG and its detached signature,
// so a reader passes the RUNLOG signature gate and reaches the in-bucket chain check.
func writeSignedRunlog(t *testing.T, dir string, signer *crypto.HybridSigner, entries []spec.RunlogEntry) {
	t.Helper()
	runlogBytes, err := MarshalRunlog(entries)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(runlogBytes)
	if err != nil {
		t.Fatal(err)
	}
	writeVecFile(t, filepath.Join(dir, "archive", "_RECOVERY", "RUNLOG"), runlogBytes)
	writeVecFile(t, filepath.Join(dir, "archive", "_RECOVERY", "RUNLOG.sig"), []byte(B64Encode(sig)))
}

// repinSecondRunRoot rewrites the second run's (vecRunIDB) root freshness to the given
// prevRunId and runlog index and re-signs it, so the restored run's root agrees with the
// re-pinned RUNLOG entry. Without this the run-vs-root index/prevRunId equality checks
// (freshness.go CheckFreshness) would reject first and the chain shape the vector targets
// would never be reached. Only the freshness fields change; the recipients, capsule,
// shards and Merkle root are untouched, so every earlier gate still passes.
func repinSecondRunRoot(t *testing.T, dir string, signer *crypto.HybridSigner, prevRunID string, index int64) {
	t.Helper()
	rootFile := filepath.Join(runDir(dir, vecRunIDB), "root.manifest.json")
	sigFile := filepath.Join(runDir(dir, vecRunIDB), "root.manifest.json.sig")
	root, err := ParseRoot(readVecFile(t, rootFile))
	if err != nil {
		t.Fatal(err)
	}
	prev := prevRunID
	root.Freshness = spec.Freshness{PrevRunID: &prev, RunlogIndex: index}
	canonical, sig, err := SignRoot(root, signer)
	if err != nil {
		t.Fatal(err)
	}
	writeVecFile(t, rootFile, canonical)
	writeVecFile(t, sigFile, []byte(B64Encode(sig)))
}

// allocationGapRunlog re-pins the latest run to index 3 and rewrites the signed RUNLOG so
// the entries for the downpipe are index 1 then index 3 with no index-2 entry, the state
// the account-global allocator leaves after a failed or interleaving run (SPEC.md 10).
// The per-downpipe prevRunId chain is linear (the index-3 entry chains to the index-1
// run) and every index is unique, so a conformant reader accepts it: if
// detectChainAnomaly regressed to per-downpipe index contiguity, this positive vector
// would be rejected with exit 5, so it fails closed against that regression.
func allocationGapRunlog(t *testing.T, dir string, signer *crypto.HybridSigner, dpID string) {
	t.Helper()
	repinSecondRunRoot(t, dir, signer, vecRunID, 3)
	first := vecRunID
	writeSignedRunlog(t, dir, signer, []spec.RunlogEntry{
		{Index: 1, RunID: vecRunID, DownpipeID: dpID, Time: "2026-06-06T12:00:30.000Z", RecordCount: 1, PrevRunID: nil, Status: "superseded"},
		{Index: 3, RunID: vecRunIDB, DownpipeID: dpID, Time: "2026-06-06T12:00:30.000Z", RecordCount: 1, PrevRunID: &first, Status: "active"},
	})
}

// interleavedRunlog re-pins the latest run to index 3 and writes the signed RUNLOG with
// the index-3 line FIRST: the concurrent-fleet shape (entries land at finalise time, not
// allocation time). Both entries are well-formed and the per-downpipe chain is linear;
// only an order-enforcing reader would reject it (SPEC.md 10, amended).
func interleavedRunlog(t *testing.T, dir string, signer *crypto.HybridSigner, dpID string) {
	t.Helper()
	repinSecondRunRoot(t, dir, signer, vecRunID, 3)
	first := vecRunID
	writeSignedRunlog(t, dir, signer, []spec.RunlogEntry{
		{Index: 3, RunID: vecRunIDB, DownpipeID: dpID, Time: "2026-06-06T12:00:30.000Z", RecordCount: 1, PrevRunID: &first, Status: "active"},
		{Index: 1, RunID: vecRunID, DownpipeID: dpID, Time: "2026-06-06T12:00:30.000Z", RecordCount: 1, PrevRunID: nil, Status: "superseded"},
	})
}

// duplicateIndexRunlog re-pins the latest run to index 3 and writes a synthetic THIRD
// entry for another downpipe carrying index 3 as well: a duplicated index, the one
// index-axis fact a reader must reject (the account-global counter never reissues one).
func duplicateIndexRunlog(t *testing.T, dir string, signer *crypto.HybridSigner, dpID string) {
	t.Helper()
	repinSecondRunRoot(t, dir, signer, vecRunID, 3)
	first := vecRunID
	writeSignedRunlog(t, dir, signer, []spec.RunlogEntry{
		{Index: 1, RunID: vecRunID, DownpipeID: dpID, Time: "2026-06-06T12:00:30.000Z", RecordCount: 1, PrevRunID: nil, Status: "superseded"},
		{Index: 3, RunID: vecRunIDB, DownpipeID: dpID, Time: "2026-06-06T12:00:30.000Z", RecordCount: 1, PrevRunID: &first, Status: "active"},
		{Index: 3, RunID: "01DUPL1CATE000000000000000", DownpipeID: dpID + "_other", Time: "2026-06-06T12:00:31.000Z", RecordCount: 1, PrevRunID: nil, Status: "active"},
	})
}

// forkRunlog re-pins the latest run to index 3 and rewrites the signed RUNLOG so the
// restored run chains back to the index-1 run while a synthetic index-2 sibling, the true
// parent, remains present: the restored run's prevRunId names its grandparent. That
// breaks the per-downpipe linearity rule (the sole reason for the rejection,
// detectChainAnomaly's linearity pass; the same shape is also a fork of the index-1 run,
// which the linearity pass reports first). The index sequence is monotonic and every
// prevRunId resolves, so neither the append-order nor the dangling branch can fire, and
// the restored run still has the maximum index, so the not-latest check cannot account
// for it either: if detectChainAnomaly were removed the open would succeed, so this
// vector fails closed against that regression.
func forkRunlog(t *testing.T, dir string, signer *crypto.HybridSigner, dpID string) {
	t.Helper()
	repinSecondRunRoot(t, dir, signer, vecRunID, 3)
	first := vecRunID
	writeSignedRunlog(t, dir, signer, []spec.RunlogEntry{
		{Index: 1, RunID: vecRunID, DownpipeID: dpID, Time: "2026-06-06T12:00:30.000Z", RecordCount: 1, PrevRunID: nil, Status: "superseded"},
		{Index: 2, RunID: vecRunIDC, DownpipeID: dpID, Time: "2026-06-06T12:00:30.000Z", RecordCount: 1, PrevRunID: &first, Status: "superseded"},
		{Index: 3, RunID: vecRunIDB, DownpipeID: dpID, Time: "2026-06-06T12:00:30.000Z", RecordCount: 1, PrevRunID: &first, Status: "active"},
	})
}

// --- single-half-signature ---

// writeHalfSignature replaces the detached root signature with only the Ed25519 half
// (64 bytes, valid for the stored root bytes). The ML-DSA-87 half is absent, so the
// hybrid signature is structurally incomplete and the reader must classify it as
// "invalid" rather than "wrong-signer" (SPEC.md 8.1, 14.3 single-half-signature).
func writeHalfSignature(t *testing.T, dir string) {
	t.Helper()
	// Build a fresh signer whose Ed25519 key we use directly, then sign with Ed25519
	// alone and write the 64-byte result as the detached signature.
	signer, _, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	rootBytes := readVecFile(t, rootPath(dir))
	edSig := ed25519.Sign(signer.Ed, rootBytes)
	writeVecFile(t, rootSigPath(dir), []byte(B64Encode(edSig)))
}

// --- secrets-with-compression and mixed-codec ---

// setFirstRecordCodec re-opens the shard for vecRunID, sets the first record's codec to
// the given value, re-seals the shard under the same wrap key, and re-signs the root
// so the signature passes and the codec gate is what rejects (SPEC.md 5.2, 12.4, 14.3).
func setFirstRecordCodec(t *testing.T, dir string, signer *crypto.HybridSigner, codec string) {
	t.Helper()
	master := fixedMaster()
	runIDBytes, err := spec.DecodeULID(vecRunID)
	if err != nil {
		t.Fatal(err)
	}
	mk := crypto.DeriveMK(master, runIDBytes)
	shardBytes := readVecFile(t, shardPath(dir))
	preamble, records, err := OpenShard(shardBytes, crypto.DeriveManifestWrapKey(mk, runIDBytes, "00000"))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) == 0 {
		t.Fatal("shard has no records to tamper")
	}
	records[0].Codec = codec
	// Recompute the record hash so the Merkle root and shard hash are consistent
	// (the signature is the gate we want to pass here, not the hash).
	rh, err := RecordHashOf(records[0])
	if err != nil {
		t.Fatal(err)
	}
	records[0].RecordHash = hex.EncodeToString(rh)
	resealed, shardSHA, err := SealShard(preamble, records, crypto.DeriveManifestWrapKey(mk, runIDBytes, "00000"), fixedNonce())
	if err != nil {
		t.Fatal(err)
	}
	writeVecFile(t, shardPath(dir), resealed)
	// Re-sign the root with the new shard hash and an updated Merkle root.
	root := readRoot(t, dir)
	root.Shards[0].SHA384 = shardSHA
	leaves := make([][]byte, len(records))
	for i, rec := range records {
		rh, err := hex.DecodeString(rec.RecordHash)
		if err != nil {
			t.Fatal(err)
		}
		leaves[i] = rh
	}
	root.MerkleRoot = hex.EncodeToString(MerkleRoot(leaves))
	resignRoot(t, dir, root, signer)
}

// --- unknown-major ---

// setUnknownMajor replaces formatVersion with "downpipe/9.0.0" and re-signs. The reader
// must refuse a version outside its own major.minor before parsing the body
// (SPEC.md 13, 14.3).
func setUnknownMajor(t *testing.T, dir string, signer *crypto.HybridSigner) {
	t.Helper()
	root := readRoot(t, dir)
	root.FormatVersion = "downpipe/9.0.0"
	resignRoot(t, dir, root, signer)
}

// setUnimplementedMinor replaces formatVersion with "downpipe/0.2.0" and re-signs: the
// SAME major this reader implements, and a minor it does not. This is the vector that
// separates the shipped rule from the discarded one. A reader keyed on the MAJOR would
// accept it, derive every key under the wrong labels (SPEC.md 11.7) and report an
// authentication failure over intact bytes; a reader keyed on the MINOR, which is what
// SPEC.md 13 specifies, refuses it up front with the same exit 6 as unknown-major.
// unknown-major alone cannot make that distinction, because a major-scoped rule and a
// minor-scoped rule both refuse downpipe/9.0.0.
func setUnimplementedMinor(t *testing.T, dir string, signer *crypto.HybridSigner) {
	t.Helper()
	root := readRoot(t, dir)
	root.FormatVersion = "downpipe/0.2.0"
	resignRoot(t, dir, root, signer)
}

// setUnknownEnvelopeCodec replaces the run-wide envelope codec with a name outside the
// closed set and re-signs, so the archive is validly signed and uniformly labelled and
// ONLY the membership gate (SPEC.md 5.2) can refuse it.
func setUnknownEnvelopeCodec(t *testing.T, dir string, signer *crypto.HybridSigner) {
	t.Helper()
	root := readRoot(t, dir)
	root.Envelope.Codec = "zstd"
	resignRoot(t, dir, root, signer)
}

// --- deleted-shard (true two-shard archive) ---

// buildAndDeleteOneShard is a tamper that discards the base single-shard archive and
// replaces it with a two-shard archive where each shard holds one record, then deletes
// one shard file. The result is a structurally complete root (signed, declaredRecordCount
// 2, ShardCount 2, Merkle root over 2 records) with one shard unreadable, so readable
// coverage is 1 of 2 and the reader exits 3 (ExitIncomplete, SPEC.md 8.5, 14.3).
func buildAndDeleteOneShard(t *testing.T, dir string, signer *crypto.HybridSigner) {
	t.Helper()
	// Read back the break-glass identity written by generateVector.
	bgPriv, err := crypto.ParseKEMPrivate(mustB64(t, readVecFile(t, filepath.Join(dir, "identity.key"))))
	if err != nil {
		t.Fatal(err)
	}
	bgPub := &crypto.HybridKEMPublic{X25519: bgPriv.X25519.PublicKey(), MLKEM: bgPriv.MLKEM.EncapsulationKey()}
	_, opPub := newKEM(t)
	master := fixedMaster()
	runIDBytes, err := spec.DecodeULID(vecRunID)
	if err != nil {
		t.Fatal(err)
	}
	mk := crypto.DeriveMK(master, runIDBytes)
	nonce := fixedNonce()
	const dpID = "dp_delshard"

	store := memStore{}
	// Record A goes to shard "00000", record B goes to shard "00001".
	rhA, shardSHAA := sealOneShard(t, store, master, mk, runIDBytes, "00000", "r000000000000000", "record-alpha", []byte("two-shard record alpha"), nonce)
	rhB, shardSHAB := sealOneShard(t, store, master, mk, runIDBytes, "00001", "r000000000000001", "record-bravo", []byte("two-shard record bravo"), nonce)

	root := buildTwoShardRoot(t, master, runIDBytes, dpID, bgPub, opPub, [][]byte{rhA, rhB}, []string{shardSHAA, shardSHAB})
	root.SigningKeyFingerprint = crypto.SignerFingerprint(verifierOf(signer))
	canonical, sig, err := SignRoot(root, signer)
	if err != nil {
		t.Fatal(err)
	}
	store[runKey(vecRunID, "root.manifest.json")] = canonical
	store[runKey(vecRunID, "root.manifest.json.sig")] = []byte(B64Encode(sig))
	writeTwoShardSidecars(t, store, signer, dpID)

	// Flush all objects to disk, replacing the base archive.
	archDir := archiveDir(dir)
	if err := os.RemoveAll(archDir); err != nil {
		t.Fatal(err)
	}
	for k, v := range store {
		writeVecFile(t, filepath.Join(archDir, filepath.FromSlash(k)), v)
	}
	// Delete shard "00001" so readable coverage drops to 1 of 2.
	if err := os.Remove(filepath.Join(archDir, filepath.FromSlash(runKey(vecRunID, "manifest/00001.dpe")))); err != nil {
		t.Fatal(err)
	}
}

// sealOneShard seals one non-secret r2 record as a single segment and a one-record shard
// manifest into store, returning the record hash and the shard SHA-384 the root references.
func sealOneShard(t *testing.T, store memStore, master, mk, runIDBytes []byte, shardID, recordID, name string, value, nonce []byte) ([]byte, string) {
	t.Helper()
	const dpID = "dp_delshard"
	segID, segBytes, err := crypto.SealNonSecretSegment(master, dpID, spec.AddrSingleNonSecret, spec.CodecNone, value, nonce)
	if err != nil {
		t.Fatal(err)
	}
	obj := segObject(crypto.SegIDHex(segID))
	store[obj] = segBytes
	knh := hex.EncodeToString(crypto.NameMAC(crypto.DeriveNameMACKey(mk, runIDBytes), "r2", name))
	rec := spec.ShardRecord{
		SourceType: "r2", Name: name, KeyNameHash: knh,
		RecordID:      recordID,
		PlaintextSize: int64(len(value)), PlaintextSHA: SHA384Hex(value),
		Codec:    spec.CodecNameNone,
		Segments: []spec.Segment{{Object: obj, ChunkRange: [2]int{0, streamChunkCount(len(value))}}},
	}
	rh, err := RecordHashOf(rec)
	if err != nil {
		t.Fatal(err)
	}
	rec.RecordHash = hex.EncodeToString(rh)
	preamble := spec.ShardPreamble{
		FormatVersion: spec.Version, RunID: vecRunID, ShardID: shardID,
		ManifestCodec: spec.CodecNameNone,
		Downpipe:      spec.PreambleDownpipe{Name: "test", Cadence: "0 * * * *"},
		Source:        spec.Source{Type: "r2", NamespaceID: "ns1"},
		Window:        spec.Window{Start: "2026-06-06T12:00:00.000Z", End: "2026-06-06T12:00:30.000Z"},
		Consistency:   "crawl",
	}
	shardBytes, shardSHA, err := SealShard(preamble, []spec.ShardRecord{rec}, crypto.DeriveManifestWrapKey(mk, runIDBytes, shardID), nonce)
	if err != nil {
		t.Fatal(err)
	}
	store[runKey(vecRunID, "manifest/"+shardID+".dpe")] = shardBytes
	return rh, shardSHA
}

// buildTwoShardRoot assembles the (unsigned) root manifest over the two shards: the master
// capsule, the recipient set, the Merkle root over the two record hashes and shardCount 2.
func buildTwoShardRoot(t *testing.T, master, runIDBytes []byte, dpID string, bgPub, opPub *crypto.HybridKEMPublic, recordHashes [][]byte, shardSHAs []string) *spec.RootManifest {
	t.Helper()
	kc := crypto.KeyCommitment(master, runIDBytes)
	recipientPubs := []*crypto.HybridKEMPublic{bgPub, opPub}
	wraps, err := crypto.SealToRecipients([32]byte(master), recipientPubs, kc, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capsule := make([]spec.CapsuleWrap, len(wraps))
	for i, w := range wraps {
		capsule[i] = spec.CapsuleWrap{
			Fingerprint: w.Fingerprint, KEMCiphertext: B64Encode(w.KEMCiphertext), Sealed: B64Encode(w.Sealed),
		}
	}
	return &spec.RootManifest{
		FormatVersion: spec.Version, RunID: vecRunID,
		CreatedAt:         "2026-06-06T12:00:30.000Z",
		DownpipeID:        dpID,
		Envelope:          spec.Envelope{AEAD: "AES-256-GCM", KEM: "X25519+ML-KEM-1024", Signature: "Ed25519+ML-DSA-87", KDF: "HKDF-SHA-384", ChunkSize: spec.ChunkSize, Codec: spec.CodecNameNone},
		Recipients:        []spec.Recipient{recipientJSON(bgPub, "break-glass"), recipientJSON(opPub, "operational")},
		MasterCapsule:     capsule,
		RecipientSetHash:  hex.EncodeToString(crypto.RecipientSetHash(recipientPubs)),
		KeyCommitment:     hex.EncodeToString(kc),
		BreakGlassPresent: true,
		Shards: []spec.ShardRef{
			{ID: "00000", Object: runKey(vecRunID, "manifest/00000.dpe"), SHA384: shardSHAs[0]},
			{ID: "00001", Object: runKey(vecRunID, "manifest/00001.dpe"), SHA384: shardSHAs[1]},
		},
		ShardCount:          2,
		DeclaredRecordCount: 2,
		MerkleRoot:          hex.EncodeToString(MerkleRoot(recordHashes)),
		Freshness:           spec.Freshness{PrevRunID: nil, RunlogIndex: 1},
	}
}

// writeTwoShardSidecars writes the signed RUNLOG and the recovery bundle for the two-shard
// fixture into store.
func writeTwoShardSidecars(t *testing.T, store memStore, signer *crypto.HybridSigner, dpID string) {
	t.Helper()
	runlogBytes, err := MarshalRunlog([]spec.RunlogEntry{{
		Index: 1, RunID: vecRunID, DownpipeID: dpID, Time: "2026-06-06T12:00:30.000Z",
		RecordCount: 2, PrevRunID: nil, Status: "active",
	}})
	if err != nil {
		t.Fatal(err)
	}
	runlogSig, err := signer.Sign(runlogBytes)
	if err != nil {
		t.Fatal(err)
	}
	store["_RECOVERY/RUNLOG"] = runlogBytes
	store["_RECOVERY/RUNLOG.sig"] = []byte(B64Encode(runlogSig))

	files := map[string][]byte{
		"FORMAT.md":  []byte("downpipe/0.1.0 format specification (conformance fixture placeholder)\n"),
		"RECOVER.md": []byte("recover with the offline break-glass identity and the vendored reader\n"),
	}
	put := func(key string, data []byte) error { store[key] = data; return nil }
	if err := WriteBundle(put, files, signer); err != nil {
		t.Fatal(err)
	}
}

// --- recovery bundle ---

// tamperBundleFile alters a bundled file so its SHA-384 no longer matches the signed
// SHA384SUMS (SPEC.md 9, 8.7 item 4).
func tamperBundleFile(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(archiveDir(dir), filepath.FromSlash(BundlePrefix), "FORMAT.md")
	b := readVecFile(t, path)
	writeVecFile(t, path, append(b, []byte("tampered\n")...))
}

// --- shared root read/write/re-sign ---

func readRoot(t *testing.T, dir string) *spec.RootManifest {
	t.Helper()
	root, err := ParseRoot(readVecFile(t, rootPath(dir)))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// writeRootNoResign writes the canonical bytes of an edited root, leaving the existing
// signature in place (it will no longer verify).
func writeRootNoResign(t *testing.T, dir string, root *spec.RootManifest) {
	t.Helper()
	b, err := MarshalRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	writeVecFile(t, rootPath(dir), b)
}

// resignRoot writes the canonical bytes of an edited root and a fresh matching signature.
func resignRoot(t *testing.T, dir string, root *spec.RootManifest, signer *crypto.HybridSigner) {
	t.Helper()
	canonical, sig, err := SignRoot(root, signer)
	if err != nil {
		t.Fatal(err)
	}
	writeVecFile(t, rootPath(dir), canonical)
	writeVecFile(t, rootSigPath(dir), []byte(B64Encode(sig)))
}

func breakGlassFingerprint(t *testing.T, root *spec.RootManifest) string {
	t.Helper()
	for _, rc := range root.Recipients {
		if rc.Role == "break-glass" {
			return rc.Fingerprint
		}
	}
	t.Fatal("root has no break-glass recipient")
	return ""
}
