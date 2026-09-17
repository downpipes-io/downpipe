# downpipe/0.1.0 conformance vectors

These vectors are normative. They live under `internal/format/testdata/vectors/<name>/`
and are the contract a second implementation (for example the engine's TypeScript
reader and writer) proves itself against. The Go reference replays them in
`TestConformance`; regenerate them with `go test ./internal/format -run TestConformance
-update`.

A reader is conformant when it recovers every positive vector with the stated value and
rejects every negative vector with the stated exit code. A writer is conformant when,
for the writer-authoritative object classes, it reproduces the pinned bytes exactly.

## Authority split

The construction is CNSA 2.0 hybrid post-quantum (AES-256-GCM STREAM, hybrid
X25519+ML-KEM-1024 KEM, hybrid Ed25519+ML-DSA-87 signatures, SHA-384). Two facts set
what is byte-reproducible:

- A data segment (`.seg`) under `codec=none` is byte-deterministic from the pinned
  master and the pinned payload nonce, so it is **writer-authoritative**: a second
  writer reproduces it byte-for-byte.
- The master capsule, the root manifest that embeds it, the detached signatures and the
  RUNLOG are **not** byte-reproducible, for two independent reasons: ML-KEM-1024
  encapsulation draws its own randomness with no injected-randomness API in the Go
  standard library, and the Go ML-DSA-87 signer is hedged (randomised) by default. They
  are therefore a **reader corpus**: a second implementation proves conformance by
  recovering and verifying them, not by reproducing their bytes.
- A `gzip` segment is not byte-reproducible across runtimes (DEFLATE differs between Go
  and the Workers runtime), so its sealed bytes are a pinned input artefact and only the
  reader outcome is asserted. A further consequence: two writers compute different
  `segId` values for the same gzipped value, so gzip records do not dedup across
  heterogeneous writers; cross-writer dedup is a `codec=none` property.

The `kem-combiner-kat` vector is the exception that is purely deterministic: it pins the
hybrid KEM combiner inputs and output, so a second implementation MUST reproduce it
byte-for-byte before sealing anything (SPEC.md 4.2, 14.6).

## Vector layout

    <name>/
      archive/        the bucket objects rooted here (run/, seg/, _RECOVERY/)
      identity.key    the break-glass recipient private key (base64url no-pad of
                      x25519(32) || ML-KEM-1024 seed(64))
      signer.pub      the operator signer public key (base64url no-pad of
                      ed25519(32) || ML-DSA-87 public)
      expect.json     the expected outcome

`expect.json` is `{"mode":"positive","records":[{"name","valueB64"}]}` for a vector that
recovers, or `{"mode":"negative","exitCode":N,"phase":"open"|"restore"}` for one that is
rejected. The exit codes are the normative set: 0 verified, 2 unverified, 3 incomplete,
4 plaintext mismatch, 5 stale, 6 usage (SPEC.md 8.5).

`kem-combiner-kat/kat.json` is the standalone combiner vector with `{ssM, ssX, ctX, pkX,
output}`, all base64url no-pad.

## Current corpus

Positive and edge (SPEC.md 14.2): `seg-empty`, `seg-single-chunk`, `seg-multi-chunk`,
`seg-multi-segment`, `seg-packed`, `dedup-same-value-two-runs`, `secrets-no-dedup`,
`gzip-codec`, `master-capsule`, `break-glass-only`, and the annotative-field trio
`d1-with-identity` (the `database`/`account` identity annotations and the d1
descriptor), `incomplete-marker` (a `_vanished` sentinel record whose marker kind the
reader must surface) and `reprovision-workers` (a workers record recovered as verified
bytes). The two benign-acceptance RUNLOG
vectors `runlog-allocation-gap` and `runlog-interleaved-append` are also positive
(SPEC.md 14.3): a per-downpipe `index` gap and an interleaved line order are NOT anomalies,
so a conformant reader accepts both.

Negative (SPEC.md 14.3): `truncated-final-chunk`, `reordered-chunks`, `flipped-tag`,
`reordered-segments` (exit 4, the sealed-reversed-chain branch), `dropped-break-glass-wrap`,
`missing-break-glass`, `forged-capsule-wrap`, `mutated-recipient-fingerprint`,
`shard-hash-mismatch`, `wrong-merkle-root`, `deleted-shard` (exit 3, the missing-shard
read-failure branch), `incomplete-record-count` (exit 3, the count-mismatch branch),
`absent-signature`, `bad-signature`, `single-half-signature`, `unknown-signer`,
`unknown-major` (exit 6), `unimplemented-minor` (exit 6, `downpipe/0.2.0`: the SAME major
this reader implements and a minor it does not, so a shared major buys nothing and the pair
with `unknown-major` is what makes the corpus able to tell a minor-scoped reader from a
major-scoped one), `unknown-source-type` (exit 6, a reserved sourceType is
refused rather than guessed), `unknown-codec` (exit 6, an envelope codec outside the
closed set is refused at open), `mixed-codec` (exit 6), `secrets-with-compression`,
`non-canonical-json`, `count-over-2pow53`, `in-range-count-as-string`, `leading-zero-count`,
`negative-count`, `non-integer-count` (all six exit 6, signed over the edited bytes and
together exhausting SPEC 11.3's canonical-numeric-form rules for a count field: number not
string, integer not decimal/exponent, non-negative, no leading zero, at most 2^53-1),
`stale-run`, `runlog-rollback`, `runlog-duplicate-index`,
`runlog-forked-prevrunid` (both exit 5, RUNLOG chain anomalies), `absent-runlog`,
`recovery-bundle-tampered`.

`leading-zero-count` and `non-integer-count` are two of the six numeric-form vectors, but
worth a specific caveat: their rejection is over-determined in the Go reader.
`leading-zero-count`'s "01" is not valid JSON syntax at all (RFC 8259 forbids a leading
zero in an int production), so `encoding/json` refuses to decode it before the
application-level canonical-form check ever inspects it; `non-integer-count`'s explicit
decimal/exponent check is redundant with the fallback integer parse a few lines later,
which also rejects it. Both vectors still correctly pin the reader's overall outcome for a
form SPEC 11.3 names, and both were proven live to still reject when their own dedicated
guard clause is disabled in isolation, but a second implementation with a laxer JSON
parser, or a different internal check ordering, could in principle diverge on these two in
a way `negative-count` (proven load-bearing on its own single guard clause) cannot.

`deleted-shard` and `incomplete-record-count` are deliberately kept as two distinct exit-3
vectors: `deleted-shard` removes a `manifest/<shardId>.dpe` from a true two-shard archive
(the shard-read-failure branch of completeness), while `incomplete-record-count` inflates
the signed `declaredRecordCount` of a single-shard archive (the count-mismatch branch). A
conformant reader proves both branches.

Deterministic known-answer: `kem-combiner-kat`, `crypto-kat`, `mlkem-kat`, `mldsa-kat`.

The authoritative corpus listing below is machine-checked against the
`internal/format/testdata/vectors/` directory by `scripts/check-vectors-listing.sh` (the
`Vectors listing` CI job): the names enumerated here MUST exactly equal the directory
listing, with no documented vector missing on disk and no on-disk vector left undocumented.

<!-- BEGIN VECTOR CORPUS (machine-checked: equals the testdata/vectors/ directory listing) -->
```
absent-runlog
absent-signature
bad-signature
break-glass-only
count-over-2pow53
crypto-kat
d1-with-identity
dedup-same-value-two-runs
deleted-shard
dropped-break-glass-wrap
flipped-tag
forged-capsule-wrap
gzip-codec
in-range-count-as-string
incomplete-marker
incomplete-record-count
kem-combiner-kat
leading-zero-count
master-capsule
missing-break-glass
mixed-codec
mldsa-kat
mlkem-kat
mutated-recipient-fingerprint
negative-count
non-canonical-json
non-integer-count
recovery-bundle-tampered
reordered-chunks
reordered-segments
reprovision-workers
runlog-allocation-gap
runlog-duplicate-index
runlog-forked-prevrunid
runlog-interleaved-append
runlog-rollback
secrets-no-dedup
secrets-with-compression
seg-empty
seg-multi-chunk
seg-multi-segment
seg-packed
seg-single-chunk
shard-hash-mismatch
single-half-signature
stale-run
truncated-final-chunk
unimplemented-minor
unknown-codec
unknown-major
unknown-signer
unknown-source-type
wrong-merkle-root
```
<!-- END VECTOR CORPUS -->

Every archive vector is generated by one pinned-input harness
(`internal/format/conformance_test.go` plus the corpus list in
`internal/format/conformance_vectors_test.go`). Two-run vectors share one `seg/` tree and
one signed RUNLOG; the count-form negatives re-sign the non-canonical bytes so the reader
reaches the SPEC 11.3 count check rather than failing the signature first; and
`recovery-bundle-tampered` depends on the SPEC 8.7 item-4 bundle-binding check the reader
runs under `--check-bundle`. The break-glass identity fixtures are tracked past the
repository `*.key` ignore by a narrow negation under the corpus path (see the corpus
README); without it a clean checkout would silently lose them.
