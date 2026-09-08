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

### One format line, and why there is only one

This format has one compatibility unit, `downpipe/0.1`, and the reader implements exactly
it. A `1.x` lineage existed in pre-release form and was RETIRED on 2026-08-08 rather than
carried. The reasoning is the reasoning behind the additive rule, applied honestly rather
than by reflex: nothing implementing `1.x` was ever published, no reader for it is
obtainable, no archive of it is held by anyone outside this organisation, and no writer
offered on the update channel stamps one. There were no stored bytes for the rule to
protect, so retiring the unit cost nobody anything, and carrying it would have meant
shipping a branch, a message and a second reader for clients that do not exist.

What that decision buys in the reader is stated where it bites, in
`internal/format/verify.go`: a two-component label is now MALFORMED, and the refusal no
longer closes by naming a build to go and fetch. That is the only honest ending once the
build in question will not be published.

**The decision is conditional and the condition is checkable.** It is correct only while
no obtainable engine build stamps a two-component label. If one is ever offered again, the
reader is telling the holder of intact bytes that their root manifest is damaged. A
release-tooling census check fails when the update channel offers a writer whose format
label no reader ref implements.

### The retention duty that line does not discharge

**Naming the release is half of it. The release also has to be obtainable.**

Measured on 2026-08-06, no released reader is obtainable by anyone outside this
organisation:

- The `v0.2.0` GitHub Release is a maintainer-reviewed draft, so no binary is downloadable
  for any platform.
- `go install github.com/downpipes/downpipe/cmd/downpipe@v0.2.0` fails: `404 Not Found`
  from `sum.golang.org`, then `git ls-remote` on the repository failing to authenticate.
  The repository is private, so the module proxy cannot read it, and `@latest` and
  `git clone` fail for the same reason. Both acquisition paths README and the docs site
  give a recovering customer are paths only a member of this organisation can walk.

Every format-version refusal this reader prints ends by telling the holder to go and get a
reader that implements their version, and points at `https://github.com/downpipes/downpipe`
for the mapping. While the repository is private that URL is a 404 for the person the
message is written for, so the remedy names an action they cannot perform. `inspect`,
`keys --which` and the `Open` refusal all carry that same pointer.

This is a RETENTION DUTY on releases, and it is live rather than theoretical. Stated
plainly, so it can be accepted or rejected: **every format version that any published
release has implemented needs a reader that stays obtainable, for as long as bytes naming
that version may exist.** Discharging it could mean publishing the repository, attaching
signed binaries to the release, or something else again. Which of those, and when, is the
owner's decision and not a maintainer's. Nothing is owed for `1.x`, because nothing
implementing it was ever published; the duty attaches on the first publication, which is
why the ordering below matters.

**The retirement is not complete until three things are done together**, and only the first
is in this repository:

1. The reader stops implementing and stops naming `1.x`. That is this change.
2. The `v0.1.1` tag, whose reader implements `downpipe/1.x` and nothing else, is deleted,
   so no build of that lineage can be resolved by tag.
3. The stable update channel stops offering an engine artefact that stamps `downpipe/1.0`.
   Until it does, a person can still install a writer whose archives this reader now calls
   damaged.

## [Unreleased]

Reads format versions: `downpipe/0.1.x`.

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

- **The `v0.1.1` tag (cut 2026-07-05) predates this release and is a trap, not
  a shortcut.** It was the only tag in this repository for four weeks while
  `origin/main` moved 51 commits ahead of it, so `go install
  .../downpipe@latest` resolved silently to a reader missing `prune`,
  `recombine` and `unseal-export` (one of which the M-of-N custody path
  depends on), with no error and nothing in CI to flag the divergence.
  `v0.2.0` carries the full command set; `@latest` now resolves to it. The tag is
  additionally scheduled for deletion as part of the 2026-08-08 retirement of the
  `1.x` format lineage its reader implemented; the trap is recorded here so the
  failure mode outlives the tag, and `.github/workflows/tag-drift.yml` is the gate
  that catches the next one.

## [0.1.0] - 2026-06-17

Reads format versions: none. **This entry is RETIRED, and it is kept as history rather
than as a mapping.** It predates the 2026-07-12 semver cutover and describes a reader
that keyed on the MAJOR component alone and accepted any `downpipe/1.<minor>`, which is
what the format identity was before the cutover. That lineage was retired on 2026-08-08:
it was never published, no reader for it is obtainable, and no writer offered on the
update channel stamps a `downpipe/1.0` label. Nothing here names a reader to go and
fetch, because there is none, and pointing a person mid-recovery at a binary that will
not be published is worse than telling them plainly that this line ended.

Pending the signed `v0.1.0` tag: the contents below are frozen for the first
public release, but the tag and the GitHub release are cut by the owner-only
signing step, so the Release and Scorecard badges report no release and no data
until that step runs.

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

[Unreleased]: https://github.com/downpipes-io/downpipe/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/downpipes-io/downpipe/releases/tag/v0.3.0
[0.1.0]: https://github.com/downpipes-io/downpipe/releases/tag/v0.1.0
