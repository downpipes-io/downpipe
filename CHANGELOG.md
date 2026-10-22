# Changelog

All notable changes to this project are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
This tool follows [0ver](https://0ver.org): its version stays below `1.0`, so the
version number alone makes no stability promise.

The on-disk archive format carries its own version (`downpipe/0.1.0`) that is
independent of this tool's version. A change to a byte-level rule of the archive
format is a new format version (a MINOR bump while the format major is 0), specified in `docs/format/SPEC.md`, not an
entry here. This changelog tracks the reader, the CLI and the library.

Because those two number spaces are independent, **every release below carries a
`Reads format versions:` line naming the format versions that release's reader
implements.** This is the mapping a person holding a refused archive needs: the reader
refuses a format version it does not implement and tells them to get a reader that does
(`docs/format/SPEC.md` 13.1), and without this line there is nowhere to look up which
release that is. The list is additive from the first PUBLISHED release: once a release
implementing a format version is obtainable, no later release may drop that version,
because the bytes naming it are then in somebody's bucket and stored bytes have no
deprecation path. Before that point the rule has nothing to protect.

### One format line

This format has one compatibility unit, `downpipe/0.1`, and the reader implements
exactly it. No published reader implements a two-component `MAJOR.MINOR` label, and no
writer on the update channel stamps one. The reader refuses such a label as MALFORMED
(`internal/format/verify.go`) and does not name a build to fetch, because there is none
to name.

**This is conditional, and the condition is checkable.** It is correct only while no
obtainable engine build stamps a two-component label. If one is ever offered, the reader
would be telling the holder of intact bytes that their root manifest is damaged.

### The retention duty on releases

**Naming the release is half of it. The release also has to be obtainable.**

Every format version a published release has implemented needs a reader that
stays obtainable, for as long as bytes naming it may exist. This is a RETENTION DUTY
on releases: the `Reads format versions:` line below names which release reads an
archive, and that name is only useful while the release itself can still be got.

Every format-version refusal this reader prints ends by telling the holder to get a
reader that implements their version. It points at
`https://github.com/downpipes-io/downpipe` for the mapping. `inspect`, `keys --which`
and the `Open` refusal all carry that same pointer.

## [Unreleased]

Reads format versions: `downpipe/0.1.x`.

- The build and release toolchain is Go 1.26.10. It carries the fix for the Go standard library
  advisory GO-2026-6809 in crypto/x509.

## [0.3.5] - 2026-10-11

Reads format versions: `downpipe/0.1.x`.

### Dependencies

- The ML-DSA library, filippo.io/mldsa, is at 1.0.0. It reads and writes the ML-DSA-87 key and
  signature bytes that `docs/format/SPEC.md` specifies. The bytes are the same: the frozen ML-DSA-87 key and
  signature in the conformance tests verify unchanged.
- The build and release toolchain is Go 1.26.9. It carries the fixes for ten Go standard library
  advisories in net/http, crypto/tls, net/textproto and os.

## [0.3.4] - 2026-10-05

Reads format versions: `downpipe/0.1.x`.

### Added

- `verify-report` verifies the signature on an assurance report the engine generated
  (restore tests, SLA compliance, immutability, posture, evidence pack and change records)
  against `signer.pub`, offline. It reads the report JSON from `--report <file>`, or from
  standard input with `--report -`. It rebuilds the canonical JSON of `{kind, generatedAt,
  period, data}` as the engine does and requires both signature halves to verify. It exits
  `0` when the report verified, `2` when the report is unsigned, changed, signed by another
  signer or carries a damaged signature, and `6` when the input is not a report JSON (the
  PDF, for example) or a flag or key file is wrong. When one signature half verifies and the
  other does not, the message names the failing half and both places it can fail: that part
  of the report's signature member, or that half of the `--signer` file. The command
  prints the signer fingerprint, and `--signer-fingerprint` refuses a `--signer` file with a
  different one. A report file with a repeated member name, an unpaired UTF-16 surrogate, a
  top-level member other than the five the engine writes, or a number the engine cannot
  sign or does not write (a fraction, an exponent or `-0`) exits `2`. The PDF refusal says
  that the PDF carries no signature the tool can check and names the JSON routes, including
  `GET /admin/reports/evidence-pack?framework=<id>` for the evidence pack. A fixture signed by the engine's own report code pins the canonical bytes
  and the signatures, and the `FuzzVerifyReport` target runs in the CI `fuzz` job and in the
  weekly extended job.
- The reader decodes a secret's full wiring (SPEC.md 12.3): its scopes, its comment, every
  Worker that binds it (`{script, binding}`) and `wiring`, which says whether that Worker list
  is complete (`captured`) or could not be read (`unknown`). `inspect` prints them. A record
  from an engine that did not read the wiring prints `wiring=not-recorded`. The single
  `scope` and `worker` members are gone: no engine ever wrote them.
- `verify` and `restore` take `--signer-fingerprint <edmldsa1:...>`, the signer fingerprint
  printed on the recovery sheet. The reader reads the `signer.pub` copy in the archive's
  recovery bundle (`_RECOVERY/downpipe/0.1.0/signer.pub`, SPEC.md 9.1) and uses it only if
  its fingerprint equals the value you pass. So the bucket, the break-glass key and the sheet
  are enough to recover a run, while the signer that sealed it is still the current signer.
  The bucket keeps only the current signer's copy, so after a signer rotation the older runs
  still need the `signer.pub` file from the kit. A replaced or corrupt bucket copy exits `2`
  and names both fingerprints. A bucket with no copy (no engine 0.3.7 or later has written to
  it) exits `6` and names `--signer`, on a local directory, an S3-compatible bucket or an
  Azure container alike. `--signer` is unchanged, and with both flags the file is checked
  against the fingerprint.
- Three conformance vectors pin SPEC.md 9.1: `bundled-signer-pinned`,
  `bundled-signer-replaced` and `bundled-signer-absent`. The corpus replays them through the
  same code the CLI runs.
- The selftest archive's recovery bundle carries `signer.pub`, as an engine archive does.
- Two fuzz targets for the STREAM envelope in `internal/crypto`. `FuzzStreamRoundTrip`
  seals and opens a value of any length up to 196,609 bytes (four chunks).
  `FuzzStreamMalformed` changes a sealed value in one of these ways: it truncates the value
  into or past its final chunk, reorders two chunks, flips a tag bit, re-seals a chunk under
  a wrong counter or last-chunk flag, changes the nonce, flips any chunk bit or replaces the
  chunks. Both readers must refuse the result. Both targets run in the CI `fuzz` job and in
  the weekly extended job. `TestFuzzMatricesRunEveryTarget` fails when a fuzz target is not
  in both job matrices.
- `inspect` prints each record's `keyNameHash` (SPEC.md 6.5's keyed name MAC over the
  record's source type and name), alongside the identity and restore-descriptor detail it
  already showed. It is not an omitempty field, so it always prints, one of the four fields
  `RecordHashOf` binds into the signed Merkle leaf and the one of the three inspect had no
  way to show. `inspect` now prints a line for every record, under the heading
  `records (key hash + identity + restore descriptors):`. A script that parses this output
  must expect the new heading and a line for each record.
- `restore --sink file` keeps the KV metadata and expiration and the R2 HTTP and custom
  metadata that an archive carries. Before, the file sink wrote the value bytes only
  and dropped them without a word. For each record that carries metadata it now writes
  a sidecar next to the value, `<path>.downpipe-meta.json`, labelled
  `downpipe-restore-metadata/1` (`docs/RECOVER.md`, "Source metadata"). The sidecar is
  created with the same no-clobber rule as a value.
- `restore --sink env` prints a `WARNING metadata NOT kept` line for each record whose
  metadata it cannot keep, and a count line. A file-sink sidecar that cannot be written
  gets the same warning. The exit code does not change: the values are restored.

### Changed

- Every command that opens a run refuses a root manifest whose envelope names a different
  suite or chunk size. `verify`, `restore`, `attest` and `inspect` exit `6`. `prune` deletes
  nothing on the evidence of such a run: a retained run stops the pass with exit `2`, and a
  superseded run is skipped and reported. The five fields are `aead` (`AES-256-GCM`), `kem`
  (`X25519+ML-KEM-1024`), `sig` (`Ed25519+ML-DSA-87`), `kdf` (`HKDF-SHA-384`) and
  `chunkSize` (`65536`), as SPEC.md 5.2 pins them. Before, the reader checked only the
  envelope `codec` and read every other root with the pinned suite. The engine writes only
  the pinned values, so no archive it wrote is affected.
- The reader checks the SPEC.md 11.3 number form of each segment's `packed.offset`,
  `packed.length` and `chunkRange` endpoints when it opens a shard manifest. A string, a
  negative value or a value above 2^53 - 1 now exits `6`. Before, a string exited `2` with
  a JSON parse error, and a negative or too-large value was accepted when the shard opened.
  A key that differs from a count field's name only in case is now refused at every level
  of the path, not only at the last one.
- `prune --apply` exits `14` when the pass left any planned object in the destination. Before,
  a prune the destination refused in full exited `0`, with the refusal on one line of stdout.
  A dry run never exits `14`.
- `prune` no longer calls every failed delete an Object Lock refusal. A delete the destination
  REFUSED (it answered and said no: a lock or a missing permission) and a delete that FAILED
  (no usable answer, such as a network fault or a server error) are counted apart. A refusal
  counts as naming a lock only when the destination's own answer names one.
- `prune --apply` keeps a superseded run's tree when one of that run's segments was not
  deleted. The tree is how a later prune finds the segment; deleting it stranded the segment.
- The prune receipt is version 2. It adds `refusedLockNamedCount`, `failedCount`,
  `failedSample` and `heldRunObjects`, and `refusedCount` now counts refusals only. A version 1
  receipt still reads.
- The `--receipt` help on `verify` and `restore` no longer says the receipt is signed. It is
  signed only when `--receipt-signer` names a signer private-key file. The `verify` flag also
  called its receipt a restore receipt.
- `restore` no longer tells an operator to replay the two Cloudflare configuration metadata
  records. `_cf-config-identity` (which account and zone the backup is for) and
  `_cf-config-coverage` (which surfaces the run has no record for, and why) now carry
  informational guidance. Before, both got the surface text "replay it from the verified
  snapshot through the Cloudflare API", although neither is a surface.
- The `selftest` archive's `RECOVER.md` tells a recoverer what `--allow-unverified` does when a
  signature check fails. The flag skips only the signature checks and the RUNLOG freshness check,
  and the restore writes the records and then exits with code 2. It is not a verified restore.
  From engine 0.3.7, the `RECOVER.md` in the engine's recovery bundle carries the same
  paragraph (SPEC section 9).

### Fixed

- The `init` and `update` runbooks state the token and key custody the engine has. They said
  the running engine holds no Cloudflare API token, that the deploy token never goes to the
  console, and that the signer private and the recipient public are Secrets Store entries.
  The engine stores no deploy token, but it can store the optional read-only discovery token.
  A console action that changes the engine's Worker takes the deploy token as a one-time paste
  and does not store it. The engine's keys are Worker secrets, and the Secrets Store scope
  binds the secrets a downpipe backs up.
- The `restore` guidance for `stream`, `images` and `artifacts` records no longer calls the
  files out of `downpipe/0.1.0` scope. When File contents was on for the downpipe, the
  backup holds the video and caption files, the image bytes and the git objects that the run
  captured (SPEC.md 12.1), and the guidance now says so. A file the run could not capture is
  an incompleteness marker, and the guidance says that an applied restore lists each marker.
  When File contents was off, the guidance says the backup holds only the metadata.
- The exit `5` hint that recommends `--allow-stale` names only the two findings that flag
  covers: the run is not the latest for its downpipe, or the RUNLOG's maximum index is below
  the `--min-runlog-index` pin. It used to name a rapid re-trigger and a demo reset. Those
  cause a root and RUNLOG disagreement or a chain anomaly, and `--allow-stale` refuses both.
- When records fail, the restore receipt records the code the process exits with. The
  advisory codes `8`, `10` and `12` are not recorded there. Before, a restore receipt
  recorded only the run-level code, which was `0` when the run itself verified, so an
  applied restore whose records failed (for example exit `2`, `4`, `11` or `13`) wrote
  `exitCode: 0`. `verify --deep` over the same archive recorded the per-record code. Both
  commands now use one rule for the code, and a restore with `--allow-unverified` whose
  records also failed exits with that code, as `verify --deep` does. In that rule, a
  per-record `11` or `13` does not replace a code the run already has (`2` to `6`). Before,
  `verify --deep` let a per-record `11` replace a failed signature's `2`. The schema's receipt
  `exitCode` enum adds `11` and `13`, which SPEC.md 8.5 already said a receipt can record,
  and the uncoded `1`, which a restore records when the target could not write a record.
- The `preflight` Secrets Store check no longer fails with fewer than six free slots, and no
  longer says the engine needs roughly five. The engine's keys are Worker secrets, and the
  engine deploy adds no secret to the store. The check reports the free slots. A full store
  gets a note that it does not block the engine deploy and that you need a free slot for
  each entry in the `secrets` section of a `setup` config, or for a secret you put back
  after a restore. A store that the token cannot read is still a check that could not run,
  and its remediation now says what the free slots are for.
- The `Vectors listing` CI job reads vector names from SPEC.md section 14 only. It read every
  list item of the form `` - `name`: `` in SPEC.md, so the section 12.3 secret descriptor
  members (`store`, `scopes`, `comment`, `workers`, `wiring`) counted as vectors and the job
  failed on main. A new `--self-test` step drives the script over a fixture with such a list.

### Security

- A restore to a directory writes every file through the output directory itself, so a symlink in `--out` that points outside it is refused.
- `recombine` reads a custody artefact only if it is a regular file, so the 1 MiB artefact cap always applies.
- The reader caps the root manifest and the RUNLOG at 256 MiB, and each signature at 64 KiB, before it reads them.

## [0.3.3] - 2026-09-21

Reads format versions: `downpipe/0.1.x`.

The first release built and attested by the public release workflow. The reader is
the 0.3.2 tree unchanged; only the release tooling differs. It carries the 0.3.2 and
0.3.1 changes below.

### Changed

- The release's `checksums.txt` is signed as a Sigstore bundle
  (`checksums.txt.cosign-bundle`), the form cosign 3 produces and the engine and console
  releases already use, in place of the detached signature and certificate.
- The release workflow pins goreleaser and cosign to exact versions.

## [0.3.2] - 2026-09-21

Reads format versions: `downpipe/0.1.x`.

### Changed

- The first public CI run is green on a standalone clone, and the README links the engine and
  console repositories the way theirs link this one.

### Dependencies

- golang.org/x/crypto v0.57.0.
- GitHub Actions pins: step-security/harden-runner 2.21.1, actions/checkout 7.0.1,
  actions/setup-go 7.0.0, actions/setup-node 7.0.0, actions/upload-artifact 7.0.1,
  github/codeql-action 4.38.0.

## [0.3.1] - 2026-09-17

Reads format versions: `downpipe/0.1.x`.

### Changed

- The provisioning client's calls to the Cloudflare API refuse to follow a redirect and
  give up after 30 seconds, so the operator's API token is never carried to another host.

### Dependencies

- golang.org/x/crypto v0.56.0.

## [0.3.0] - 2026-09-06

Reads format versions: `downpipe/0.1.x`.

### Fixed

- `keys --which` no longer lists a run this reader cannot open without saying so.
  Each run at a format version outside this reader's implemented set is now marked
  on its own line and counted in a summary above the listing. The runs stay in the
  index and the command still exits `0`: which key opens which run is a property of
  the archive rather than of this build, and refusing here would dead-end the step
  that finds run ids, which is the step `inspect`'s own usage error sends people to.
- `prune`'s abstain no longer blames the identity for a refusal that had nothing to
  do with it. It abstained safely over a retained run at an unimplemented format
  version, deleting nothing, and then told the operator to check that their identity
  opened the run. The identity is never read on that path. The abstain now carries
  the reason the run refused to open, and points at `verify` for the fuller
  diagnosis without asserting a cause.
- `inspect` without `--identity` no longer closes by telling the operator to run
  `verify` on a run the same block has already said `verify` will refuse.
- A D1 record whose body carries a format label this release does not render no
  longer restores as an unqualified success. It used to write its verified JSON to
  a file named `.sql`, report no failure and exit 0, after which the printed replay
  guidance told the operator to feed that file to `sqlite3`. The reader now tells a
  body from a newer downpipe apart from a body that was never a downpipe D1 dump,
  reading the `d1.format` descriptor the record already carries as well as the body
  itself. Such a record still restores, because the verified bytes may be the only
  copy, and it is now named in the plan and in the result with the format label that
  reads it, is written to a key with no `.sql` suffix, and exits the new advisory
  code `12`. A body that was never a downpipe D1 dump is unaffected and keeps its
  verbatim write and its `.sql` key.

### Added

- Exit code `12`, an advisory alongside `8` and `10`: the run verified and every
  record was written, and one or more of them carries a D1 body format this release
  cannot render. Nothing is corrupt and nothing was lost. `downpipe --help` and
  `docs/RECOVER.md` describe the whole advisory family.

- Azure Blob Storage as a destination this reader can open, through `--azure-endpoint`
  with `--azure-container`. Credentials come from `AZURE_STORAGE_KEY` (a storage account
  access key) or `AZURE_STORAGE_SAS_TOKEN` (a shared access signature), with
  `AZURE_STORAGE_ACCOUNT` for an account name that is not the endpoint's first label, and
  never from a flag.

  This closes a gap in the break-glass promise rather than adding a convenience. Azure Blob
  does not speak the S3 API: it has its own wire protocol, its own authentication and its
  own listing document, so `--s3-endpoint` could not reach an Azure container at any value,
  measured against a real storage account. An estate whose only destination was Azure could
  therefore have archives written, sealed and verified, and opened only through the engine,
  which is the one thing this reader exists to make unnecessary. Cloudflare R2, Amazon S3
  and Google Cloud Storage were and remain reachable through `--s3-endpoint`.

  The reader is READ-ONLY on Azure: it gets an object, checks one exists and lists a
  prefix. It carries no delete, so `prune --apply` against an Azure container refuses. That
  is deliberate: a break-glass tool that can delete from a destination can destroy the last
  copy of the data it exists to recover.

## [0.2.0] - 2026-08-03

Reads format versions: `downpipe/0.1.x`.

### Changed

- The archive format is identified as `downpipe/0.1.0` and versioned by semver:
  while the major is 0, a byte-level rule change bumps the MINOR and is a new,
  incompatible format identity, and a patch changes no byte-level rule. The
  reader accepts exactly `downpipe/0.1.x`. The version string participates in
  every HKDF and MAC info string, the hybrid-KEM and key-commitment labels and
  the recovery-bundle path, so a version it does not implement is refused rather
  than guessed at.
- The reader refuses a codec name outside the closed `{none, gzip}` set up front
  (envelope, per record and per-shard `manifestCodec`), exit 6; previously a
  uniformly relabelled archive was silently decrypted as codec `none`.
- `verify` and `verify --deep` run on the streaming reader: memory is bounded by
  the largest shard, not the record count, and the record summary, receipts and
  exit codes are unchanged. `verify` gains `--fetch-concurrency`.
- Restore streams large records end to end: the per-record streaming path
  activates for records of 8 MiB and above, and both store backends can serve
  sealed objects as bounded streams, so peak memory is independent of the
  largest record in the archive.
- An interrupt (Ctrl-C) now cancels in-flight fetches and stops verify and
  restore promptly with a real error.

### Fixed

- A record name carrying backslashes is now sanitised the same way on every platform.
  `safeKey` split on the LOCAL separator only, so an archive-controlled name such as
  `..\..\etc\passwd` was cleaned on Windows but kept as a literal file name on Unix:
  one archive restored to two different layouts, and a file restored on Unix carried a
  name that becomes a traversal path the moment it reaches Windows. Found by the new
  path-mapping fuzz target.

### Added

- Statement coverage is now GATED in CI, per package: internal/crypto at 90%, every
  other package at 85% (`scripts/coverage-gate.sh`, `make cover-gate`). The gate
  aggregates the profile's statement blocks and fails loudly on a package that is
  absent from the profile entirely, so a package with no tests cannot pass silently.
- Memory tripwires for the streaming restore path (`make memcheck`): peak heap must
  not scale with the largest record in the archive. A 32 MiB record costs no
  measurable additional heap; the tripwire is proven to go red when a record is
  forced back onto the buffered path.
- Four fuzz targets over the parsers that had none: the D1 dump transcoder (the largest
  parser in the reader, and the only one that runs on source-controlled content), the
  keyless RUNLOG parse reachable before any signature check, the RUNLOG chain-anomaly
  detector over arbitrary entry sets, and the archive-controlled restore path mapping.
  All nine targets now run in CI as a per-package matrix, with a weekly long-budget
  workflow and committed seed corpora so a discovered input is pinned rather than
  rediscovered.
- `recombine`: rebuild `identity.key` offline from the break-glass custody
  artefacts. It accepts the labelled share files, the bare base64url share bodies
  custodians receive by email (saved to files), or the whole wrapping-key file,
  together with the wrapped-identity envelope, and verifies the recombined key
  against its public checksum before the authenticated decrypt. Previously the
  M-of-N custody posture could only be recombined in the console, so a customer
  holding shares and the ciphertext could not rebuild their key with this tool
  alone. Custody-integrity failures exit 9, distinct from the archive verdicts.
- `prune`: an offline, manifest-driven retention prune. It exists because a
  break-glass-only estate's engine holds no key that can decrypt a superseded
  run's shard manifests to work out which segments are still referenced, and
  this tool can, because the operator supplies one. Dry run by default; `--apply`
  is required to delete anything, matching the engine's own retention default.
  The runs to drop come from the signed RUNLOG and the segments to delete come
  from the decrypted manifests; a run this tool cannot open is reported
  incomplete rather than as an empty (and so falsely prunable) set. Proven
  against the dedup-same-value-two-runs conformance vector, the case where two
  runs share a segment: the shared segment survives and the retained run still
  restores and verifies afterwards.
- `unseal-export`: open a SEALED control-plane export offline with the
  break-glass identity and signer, and write the recovered plaintext export
  JSON, so `identity.key` never has to reach a browser. It shares the archive
  reader's own crypto (`OpenCapsule` / `OpenStreamTo`) and its two domain-
  separated AADs are pinned against an engine-produced fixture by a cross-impl
  conformance test, so the sealed export and an archive share one trust
  surface and cannot silently drift apart.
- `ExitUnwritten` (exit 10): an advisory, alongside `ExitIncompleteMarkers`,
  for a restore that verified and wrote every record it could but skipped one
  or more because the target could not take them (an unrepresentable name, an
  existing destination key, or two records mapping to the same key). Previously
  those skips exited 0, which a DR script reads as a clean full restore; now
  the gap is on the exit code, not only on stderr.
- Three OPTIONAL annotative record fields are normative in `downpipe/0.1.0`:
  `database`, `account` and `incompleteMarker` (schema.json pins their shapes;
  they are omitted when empty and are not record-hash inputs).

### Install

- **The `v0.1.1` tag predates this release and is a trap, not a shortcut.**
  `go install .../downpipe@v0.1.1` resolves to a reader missing `prune`,
  `recombine` and `unseal-export`, one of which the M-of-N custody path
  depends on. `v0.2.0` carries the full command set, and `@latest` resolves to it.

## [0.1.0] - 2026-06-17

Reads format versions: none. This release's reader accepts only `downpipe/1.<minor>`
labels. No writer on the update channel stamps one, so this release reads no archive
that a published engine writes.

First public release of the offline reader, the recovery CLI and the library.

### Added

- The `downpipe/0.1.0` archive format, specified normatively in
  `docs/format/SPEC.md` and pinned by the conformance vectors under
  `internal/format/testdata/vectors/` (see `docs/format/CONFORMANCE.md`). Any
  change to a byte-level rule is a new format version, not an erratum.
- The offline recovery path: `keygen`, `inspect`, `verify`, `attest`, `restore`
  and `selftest`. It imports no telemetry and no vendor SDK and makes no network
  call to Cloudflare or to Maelstrom AI, so a holder of the destination bucket
  bytes and the offline break-glass key can recover with no vendor in the loop.
- `verify`: end-to-end verification against an operator-pinned signer, the
  recipient set, the key commitment, every shard hash, the declared record count,
  the Merkle root and each record's hash, with freshness enforced against the
  signed RUNLOG (`--allow-stale`, `--allow-unverified-runlog`,
  `--min-runlog-index`) and the opt-in recovery-bundle hash binding
  (`--check-bundle`). `--allow-stale` acknowledges this run's age and nothing
  else; a RUNLOG that could not be verified or that contradicts itself needs
  `--allow-unverified-runlog`, so an age word never waives a signature check.
- `attest`: a keyless attestation that verifies the root signature, the shard
  hashes and the RUNLOG without the break-glass identity and materialises no
  plaintext. With `--signer` the signatures are cryptographically verified;
  without it the attestation is fully keyless.
- `restore`: a dry run by default that plans the writes and reports conflicts;
  `--apply` writes. Targets are `file` (one file per record), `env` (dotenv lines
  to stdout) and `discard` (a restorability check that decrypts and verifies every
  record and writes nothing). Restore never overwrites existing target state.
- Signed restore and verify receipts (`--receipt`, `--receipt-signer`).
- The post-quantum, CNSA 2.0, hybrid envelope: X25519 + ML-KEM-1024 (FIPS 203)
  confidentiality with AES-256-GCM in a 64 KiB STREAM, Ed25519 + ML-DSA-87
  (FIPS 204) signatures with both halves required and no downgrade, and
  HKDF-SHA-384 / SHA-384 throughout. The hybrid KEM combiner is pinned by a
  known-answer vector.
- Reading archives from a local directory (`--archive`) or an S3-compatible
  bucket (`--s3-endpoint`, `--s3-bucket`; R2, Backblaze B2, Wasabi, MinIO, AWS S3),
  with credentials from `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` and S3
  redirects refused.
- The provisioner path used to stand up or upgrade the engine: `setup`,
  `preflight`, `init` and `update`. `setup` and `preflight` make read-only calls
  to `api.cloudflare.com` with an operator-supplied token; `init` and `update`
  are plan printers that make no network call. None are on the recovery path.
- `version`, `--version` and `-v` report the build version, injected at release
  time and reported as `dev` for an unstamped local build.

[0.3.5]: https://github.com/downpipes-io/downpipe/releases/tag/v0.3.5
[0.3.4]: https://github.com/downpipes-io/downpipe/releases/tag/v0.3.4
[0.3.3]: https://github.com/downpipes-io/downpipe/releases/tag/v0.3.3
[0.3.2]: https://github.com/downpipes-io/downpipe/releases/tag/v0.3.2
[0.3.1]: https://github.com/downpipes-io/downpipe/releases/tag/v0.3.1
[0.3.0]: https://github.com/downpipes-io/downpipe/releases/tag/v0.3.0
[0.1.0]: https://github.com/downpipes-io/downpipe/releases/tag/v0.1.0
