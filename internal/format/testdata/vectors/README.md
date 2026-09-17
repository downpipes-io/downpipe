# downpipe conformance vectors

Each subdirectory is one conformance vector for a `downpipe/0.1.0` reader. A conformant
reader (the Go reference reader here, or a second implementation such as the Workers
reader) MUST recover every positive vector and reject every negative one with the
stated exit code (SPEC.md 8.5, 14).

## Layout

    <vector>/
      archive/        the bucket objects, rooted here (run/, seg/, _RECOVERY/)
      identity.key    the break-glass recipient private key: base64url no-pad of
                      x25519(32) || ML-KEM-1024 seed(64)
      signer.pub      the operator signer public key: base64url no-pad of
                      ed25519(32) || ML-DSA-87 public
      expect.json     the expected outcome

The primary run id is the fixed `01ARZ3NDEKTSV4RRFFQ69G5FAV`. A two-run vector (dedup
and the freshness negatives) adds a second run `01ARZ3NDEKTSV4RRFFQ69G5FB0` under the
same `archive/` and one shared `seg/` tree, selected by the `runId` in `expect.json`.
Open the run against `archive/` with the identity and the signer.

## expect.json

    { "mode": "positive", "records": [ { "name": "...", "valueB64": "..." } ] }
    { "mode": "negative", "exitCode": 2, "phase": "open" }

A positive vector opens, and each listed record restores to the bytes in `valueB64`.
A negative vector fails: at `open` the run does not open; at `restore` the run opens
but restoring the record fails. Either way it fails with `exitCode` (2 unverified,
3 incomplete, 4 plaintext, 5 stale, 6 usage).

Optional fields extend this for the broader corpus:

- `runId`: the run to open (defaults to the primary run id).
- `options`: the reader options the vector needs, any of `allowStale`,
  `allowUnverifiedRunlog`, `allowUnverified`, `minRunlogIndex` and
  `checkRecoveryBundle`. Absent means verified mode with no pins and no bundle check.
  `allowStale` acknowledges the run's age only (a non-latest run, or a log maximum below
  `minRunlogIndex`); a RUNLOG that could not be verified or that contradicts itself needs
  `allowUnverifiedRunlog`.
- `labels`: honest restore-receipt labels to assert (`signatureResult`,
  `breakGlassVerified`, `recoveryBundleVerified`); a label is asserted only when present.
- `segCount`: the number of `.seg` objects the archive must contain, proving the dedup
  (one shared non-secret segment) and the secrets-never-dedup (one per record) rules.
- `also`: further per-run checks against the same archive, for example a two-run dedup
  opening both runs, or a stale run that also restores under `allowStale`.

## Regenerating

The master capsule and the signatures use fresh randomness, so the corpus is a fixed
snapshot and is regenerated wholesale:

    go test ./internal/format -run TestConformance -update

The data segments are byte-deterministic from the pinned master and nonces; the root
manifest and the capsule are not, because ML-KEM encapsulation draws its own
randomness, so a second writer cannot reproduce the capsule bytes (SPEC.md 14.1). The
corpus is therefore a reader corpus: a second reader proves conformance by recovering
and rejecting it, not by reproducing it.

## Current corpus

Positive and edge (SPEC.md 14.2): `seg-empty`, `seg-single-chunk`, `seg-multi-chunk`,
`seg-multi-segment`, `seg-packed`, `dedup-same-value-two-runs`, `secrets-no-dedup`,
`gzip-codec`, `master-capsule`, `break-glass-only`.

Negative (SPEC.md 14.3): `truncated-final-chunk`, `reordered-chunks`, `flipped-tag`,
`reordered-segments`, `dropped-break-glass-wrap`, `missing-break-glass`,
`forged-capsule-wrap`, `mutated-recipient-fingerprint`, `shard-hash-mismatch`,
`wrong-merkle-root`, `incomplete-record-count`, `absent-signature`, `bad-signature`,
`unknown-signer`, `non-canonical-json`, `count-over-2pow53`, `in-range-count-as-string`,
`stale-run`, `runlog-rollback`, `absent-runlog`, `recovery-bundle-tampered`.

Deterministic known-answer: `kem-combiner-kat`, `crypto-kat`, `mlkem-kat`, `mldsa-kat`.

## Vectors that yield nothing to the schema checker

`scripts/schema-validate/validate.mjs` walks this directory for `run/<runId>/root.manifest.json`
and `_RECOVERY/RUNLOG`. Some vectors have neither, and which ones is a policy rather than an
observation, because a vector that is empty on purpose and a vector whose directory went missing
look the same from here. Adding a vector that yields no manifest or no RUNLOG therefore needs a
line in `EXPECT_NO_ROOT_MANIFEST`, `EXPECT_NO_RUNLOG` or `EXPECT_RUN_WITHOUT_ROOT_MANIFEST` in
that file, carrying the reason and the rule it rests on. Those tables are what the checker reads:
an undeclared empty refuses at exit 2 naming the vector, and a declaration the corpus no longer
bears out is a failure with the line to delete. The four known-answer vectors are declared there
because they are not archives at all, and `absent-runlog` because its missing log is the defect it
pins.

Three points carry the corpus past easy mistakes:

- Each vector ships a fresh break-glass `identity.key`, and a repository `*.key` ignore
  would otherwise swallow it on a clean checkout while the directory looks complete
  locally. The repository `.gitignore` negates `*.key` (and `*.pem`/`*.age`) under this
  corpus path so a plain `git add` tracks each fixture; real keys elsewhere stay ignored.
- `count-over-2pow53` and `in-range-count-as-string` are signed over the edited bytes,
  not byte-flipped after signing. The signature gate runs before the count check, so a
  post-sign flip would exit 2 instead of the intended 6; the generator emits the
  non-canonical count form and re-signs those exact bytes.
- `recovery-bundle-tampered` exercises the SPEC.md 8.7 item-4 bundle binding: the reader
  recomputes the bundled files against the signed `SHA384SUMS` only when asked
  (`options.checkRecoveryBundle`), failing with exit 2 and `recoveryBundleVerified` false.
