# downpipe

[![CI](https://github.com/downpipes-io/downpipe/actions/workflows/ci.yml/badge.svg)](https://github.com/downpipes-io/downpipe/actions/workflows/ci.yml)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/downpipes-io/downpipe?display_name=tag&sort=semver)](https://github.com/downpipes-io/downpipe/releases)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/downpipes-io/downpipe/badge)](https://scorecard.dev/viewer/?uri=github.com/downpipes-io/downpipe)

`downpipe` is the standalone, offline reader for downpipe archives. It verifies
and restores encrypted Cloudflare backups from the destination bucket bytes plus
your own keys, with neither Cloudflare nor any vendor service in the loop.

This repository is the open core of the product: the offline reader and the
archive format it reads. The format is the moat. Because the format is documented
in full (see [`docs/format/SPEC.md`](docs/format/SPEC.md)) and shipped inside
every archive next to the data, a holder of the destination bytes and the
offline break-glass key can always recover, even if the vendor disappears and
even if the Cloudflare account is gone. The paid, proprietary assurance plane
that schedules and writes archives is a separate component, and nothing here
depends on it to read, verify or restore.

## Status

The archive format is `downpipe/0.1.0`, versioned by semver: while the major is 0,
any byte-level rule change is a new MINOR (an incompatible format identity) and a
patch changes no byte-level rule. The normative
contract is [`docs/format/SPEC.md`](docs/format/SPEC.md) and ships with cut
conformance vectors (see [`docs/format/CONFORMANCE.md`](docs/format/CONFORMANCE.md));
a byte-level rule change is never an erratum. The
reader, the recovery CLI and the post-quantum envelope are implemented and
tested end to end against those vectors. The engine that writes archives from a
live Cloudflare account is a separate component.

## Install

```
go install github.com/downpipes-io/downpipe/cmd/downpipe@latest
```

`@latest` resolves to the `v0.3.0` tag, which carries the full command set,
including `prune`, `recombine` and `unseal-export`. A binary installed this way
reports `downpipe dev`: `go install` does not run this repository's release
pipeline, so the version-injection ldflag is never set. That is cosmetic, not a
functional gap; the command set is complete either way.

From source (requires Go 1.26 or newer), for the version-stamped binary, offline
builds, or to build against an unreleased commit:

```
git clone https://github.com/downpipes-io/downpipe
cd downpipe
go build ./cmd/downpipe
```

Or download a prebuilt binary from the [v0.3.0 release](https://github.com/downpipes-io/downpipe/releases/tag/v0.3.0):
reproducible, SBOM-attested and cosign-signed for linux, darwin and windows (amd64 and arm64).
`downpipe version` prints the version a binary was built from (`dev` for `go install` or a plain
local build, the tag for a release-pipeline build). See [VERIFY.md](VERIFY.md) to check a
downloaded binary against its checksum and signature before you run it.

**There is one archive format line and one reader.** The format is
`downpipe/0.1.x` and this reader implements exactly it; a `1.x` lineage existed in
pre-release form and was retired without ever being published, so no
build of it is offered and none will be. A label outside the
`downpipe/MAJOR.MINOR.PATCH` shape, two components included, is refused as
malformed rather than as a version somebody could go and find a reader for.

Every format-version refusal this tool prints tells the holder to go and get a
reader that implements their version, and points here. See
[CHANGELOG.md](CHANGELOG.md), "The retention duty that line does not discharge",
for what that refusal costs a holder who cannot yet get the right reader.

**Before `v0.2.0`:** a `v0.1.1` tag was cut, before `prune`,
`recombine` and `unseal-export` existed, so `@latest` silently resolved to an
incomplete reader for four weeks with nothing to flag it: no error, no gate,
no warning from the tool itself. `v0.2.0` closes that gap, and the tag is
scheduled for deletion with the rest of the retired `1.x` lineage; the trap is
recorded here so the failure mode outlives the tag. See
[CHANGELOG.md](CHANGELOG.md) `## [0.2.0]` for what shipped.

See [CHANGELOG.md](CHANGELOG.md) for releases and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for the community standards.

## Try it

Build the tool, then prove the whole round trip end to end:

```
go build ./cmd/downpipe
./downpipe selftest
```

`selftest` seals a value with the post-quantum envelope and recovers it from disk
using only an offline key, with nothing else in the loop.

A real recovery uses your own keys and your own bucket:

```
downpipe keygen  --out ./keys
downpipe inspect --archive ./bucket --run <runId>
downpipe verify  --archive ./bucket --run <runId> \
    --identity ./keys/identity.key --signer ./keys/signer.pub \
    --min-runlog-index <n>
downpipe restore --apply --archive ./bucket --run <runId> \
    --identity ./keys/identity.key --signer ./keys/signer.pub \
    --min-runlog-index <n> --out ./restored
```

`--apply` is what writes. Without it `restore` plans, reports the writes it would
make, exits 0 and leaves `--out` untouched, which is the right default for a
rehearsal and the wrong one for a recovery. Drop the flag to read the plan first.

`--min-runlog-index <n>` is the anti-rollback pin: the latest trusted RUNLOG index
off your recovery sheet, out-of-band proof that the bucket has not been served
back to you as an older, validly signed run. It defaults to off, and `verify` and
`restore` warn on stderr every time it is left off; see
[docs/RECOVER.md](docs/RECOVER.md#the-anti-rollback-pin-defaults-to-off-and-says-so).

Read straight from the destination instead of a local directory. There are two
flag pairs, because there are two wire protocols:

- `--s3-endpoint` with `--s3-bucket` for any S3-compatible bucket: R2, Amazon S3,
  Google Cloud Storage (endpoint `https://storage.googleapis.com` with an HMAC
  interoperability key pair), Backblaze B2, Wasabi, MinIO. Credentials come from
  `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.
- `--azure-endpoint` with `--azure-container` for Azure Blob Storage, which is not
  an S3-compatible store and is not reachable through `--s3-endpoint` at any value.
  Credentials come from `AZURE_STORAGE_KEY` (a storage account access key) or
  `AZURE_STORAGE_SAS_TOKEN` (a shared access signature); set
  `AZURE_STORAGE_ACCOUNT` as well only when the account name is not the endpoint's
  first label.

No credential is read from a flag on either destination, so none reaches a shell
history or a process listing.

## What it does

A downpipe archive is encrypted, content-addressed and self-describing. The tool
reads that archive and:

- restores records to local files, to dotenv lines, or to a discard sink that decrypts
  and verifies every record while writing nothing. A large record streams straight from
  the store to its destination, so peak memory does not scale with the biggest value in
  the archive
- verifies the hybrid signature against an operator-pinned signer, the recipient
  set, the key commitment, every shard's hash, the declared count, the Merkle root
  and each record's hash on restore
- attests an archive keylessly, confirming the root signature, the shard hashes
  and the RUNLOG without the break-glass identity and without producing plaintext
- inspects an archive so you can see what it holds before restoring anything

verify and restore enforce freshness against the signed RUNLOG (SPEC.md 10), and
a failure exits 5 until you acknowledge it. The two acknowledgements are separate
on purpose: `--allow-stale` covers this run's AGE, and nothing else, from a RUNLOG
that verified against your `--signer` and is internally consistent, while
`--allow-unverified-runlog` covers a RUNLOG that is absent, unreadable, fails its
signature, or contradicts the signed root manifest. `--min-runlog-index` pins the
anti-rollback high-water mark out of band. The
recovery-bundle hash binding (SPEC.md 8.7) is verified on the opt-in
`--check-bundle` path, which checks the in-bucket spec and reader copy against the
bundle's signed `SHA384SUMS`.

Restore is offline by design. The keys are yours, the format is documented in the
bucket next to the data, and the recovery path (`keygen`, `inspect`, `verify`,
`attest`, `restore`, `recombine` and `selftest`) imports no telemetry or vendor SDK and
makes no network call, so it cannot call home.

If your break-glass key is held under an M-of-N custodian split, rebuild it first with
`recombine`, then restore as above:

```
downpipe recombine --share ./share-1.txt --share ./share-2.txt --share ./share-3.txt \
    --envelope ./wrapped-identity.txt --out ./identity.key
```

A `--share` file is either the labelled share download or a file holding the bare share
body a custodian received by email. With the whole wrapping key instead of shares, pass
`--wrapping-key` in their place. The command reads local files only and writes the key
with owner-only permissions; it never prints key material.

The binary also carries a separate provisioner path (`setup`, `preflight`,
`init` and `update`) used when standing up or upgrading the engine in a
Cloudflare account. Of these, `setup` and `preflight` make read-only
(GET-only) calls to `api.cloudflare.com` using a token you supply in
`CLOUDFLARE_API_TOKEN`; the token stays on this machine and nothing is created
or changed. `init` and `update` are plan printers that emit a runbook and make
no network call. None of the provisioner commands touch any Maelstrom AI or
Downpipes service, and none are on the recovery path above.

## Deploy-time preflight

`downpipe preflight --account <id> [--domain engine.example.com] [--json]` runs the
read-only account checks an onboarding needs BEFORE deploying the engine: the
account's zones (and whether a chosen `--domain` sits on an active one), Secrets
Store headroom, a Workers paid subscription, Logpush coverage for SIEM delivery,
and the R2 buckets available as destinations. The token is read from
`CLOUDFLARE_API_TOKEN`, sent only to `api.cloudflare.com`, and used for GETs only;
nothing is created or changed. A check the token cannot read degrades to
"unknown" and the rest of the preflight still runs, but an invalid token (401)
aborts loudly.

A check that could not run is not a pass, so an unknown does not clear the
deploy. Exit codes: 0 only when every check ran and none failed (and any
requested `--domain` verified), 7 when a check failed, a check could not be run
with this token, or a requested `--domain` could not be verified (deliberately
distinct from the normative reader exit codes), 6 for usage errors. `--json`
prints the report and then exits on the same verdict as the text output, so
`downpipe preflight --json && deploy` stops on a report it could not clear.

## Recover without the vendor

This is the one promise the format exists to keep: a holder of the destination
bucket bytes and the customer's own offline break-glass key can recover the data
with neither Cloudflare nor the vendor available.

Everything needed to decrypt, verify and reassemble the data lives in the
destination bucket, alongside a signed recovery bundle (a versioned FORMAT.md
pointer and RECOVER.md). The authoritative specification, the conformance vectors
and the MIT reader are this open-source project, kept by the recoverer or
re-implemented clean-room. The run master is wrapped to every recipient, including a
mandatory break-glass recipient whose private key is held offline by the customer
and never reaches the vendor or Cloudflare. The writing engine can wrap to that
recipient but can never unwrap it, which is what keeps recovery in the customer's
hands alone.

[`docs/RECOVER.md`](docs/RECOVER.md) walks through recovering from the bucket
bytes and the break-glass key end to end, including the high-assurance posture in
which the break-glass key is the only key that can open the archive.

## Cryptography

The construction is post-quantum at CNSA 2.0 parameters and hybrid, so an archive
stays safe if either the classical or the post-quantum half is later broken. It is
not claimed to be "quantum-proof": the hybrid design is a hedge against one half
falling, not a guarantee that neither will.

- confidentiality: X25519 + ML-KEM-1024 (FIPS 203), AES-256-GCM payloads in a
  64 KiB STREAM
- signatures: Ed25519 + ML-DSA-87 (FIPS 204), both halves required, no downgrade
- key derivation and hashing: HKDF-SHA-384 and SHA-384 throughout
- recipient wrapping: every run master is wrapped to each recipient, including a
  mandatory offline break-glass recipient the writing engine can never unwrap

The hybrid KEM combiner binds the X25519 ephemeral share and the recipient's
public key into the shared secret (SPEC.md 4.2) and is pinned by a known-answer
vector, so a second implementation reproduces it byte for byte. The envelope is
not an `age` file and is interoperable with nothing off the shelf, which is why
recovery is delivered by a documented, audited reader of the downpipe format
rather than a third-party tool.

## Conformance

The format ships with normative conformance vectors under
`internal/format/testdata/vectors/`, described in
[`docs/format/CONFORMANCE.md`](docs/format/CONFORMANCE.md). They are the contract
a second implementation proves itself against, so the format is defined by tested
behaviour and not by prose alone.

- A reader is conformant when it recovers every positive vector with the stated
  value and rejects every negative vector with the stated exit code.
- A writer is conformant when, for the writer-authoritative object classes, it
  reproduces the pinned bytes exactly. A `codec=none` data segment is
  byte-deterministic and so is writer-authoritative; the master capsule, the root
  manifest and the detached signatures are not byte-reproducible (ML-KEM
  encapsulation and the ML-DSA signer draw their own randomness) and so are a
  reader corpus, proven by recovering and verifying rather than by reproducing.

The Go reference reader replays the corpus in `TestConformance`. Recovery and
verification are delivered by a conformant reader of the downpipe format: the
open-source MIT reader in this project (keep a copy alongside your recovery key),
or a clean-room re-implementation from the spec and the vectors.

## Layout

```
cmd/downpipe        command line: keygen, inspect, verify, attest, restore,
                    selftest (recovery/reader path); setup, preflight, init,
                    update (provisioner path); version, spec, help
internal/crypto     CNSA 2.0 hybrid post-quantum envelope and key handling
internal/spec       on-disk format constants, ULIDs and manifest types
internal/format     archive reader: manifests, signing, shards, segments, verify
internal/source     read archives from a local directory, an S3-compatible bucket
                    or an Azure Blob container
internal/restore    write restored records to a target (file directory or env stream)
internal/provision  read-only Cloudflare account checks for the provisioner path
docs/format/SPEC.md the archive format specification
docs/RECOVER.md     offline recovery walkthrough
```

## Development

```
go build ./...
go test ./...
gofmt -s -w .
go vet ./...
```

Requires Go 1.26 or newer.

## Building offline from source

Every dependency this reader needs, including the post-quantum signature module
(`filippo.io/mldsa`), is vendored into `./vendor`. The reader therefore builds,
tests and runs from the checked-out source with no module download, and with no
network access at all provided the machine's own Go already satisfies the
`toolchain go1.26.6` pin in `go.mod`. That is what underpins the offline-recovery
promise above: if the vendor and Cloudflare are both gone, you can still rebuild
the recovery tool from this repository alone.

```
go build -mod=vendor ./...
go test  -mod=vendor ./...
```

The toolchain pin is the one thing the checked-out source cannot supply. Under
Go's default `GOTOOLCHAIN=auto`, a machine whose installed `go` is older than the
pin, and whose module cache does not already hold `go1.26.6`, fetches that
toolchain from the module proxy before it compiles anything; with no proxy
reachable the build exits 1 with `toolchain not available` rather than quietly
falling back to the older Go. Driven against a clean module cache
with `GOPROXY=off` on a machine running go1.26.1: `GOTOOLCHAIN=auto` exits 1,
`GOTOOLCHAIN=local` exits 0 and the binary reports `downpipe dev`, and the same
`auto` build exits 0 against a cache that already holds the pinned toolchain,
which is why a machine that has built this repository before will not show the
gap. `GOTOOLCHAIN=local` gives up the pin's security-patch guarantee, so keep a
`go` meeting the pin alongside the source rather than reaching for `local` during
a recovery.

Set `GOFLAGS=-mod=vendor` (or `GOPROXY=off`) to force the vendored build. A
`GOPROXY=off` build that exits 0 is a proof that no network was touched, since
the toolchain is fetched from that same proxy; a `GOPROXY=off` build that exits 1
on the toolchain is the gap above rather than a fault in the source. This covers
the from-source path only. It is not a claim of reproducible or signed builds;
for verified release binaries (which are reproducible and ship an SBOM) see
Install above.

## Docs, support and security

Full documentation, including the guided deploy path, lives at
[docs.downpipes.io](https://docs.downpipes.io). General support: support@downpipes.io. Report a
vulnerability by email rather than a public issue; see [SECURITY.md](SECURITY.md) for the address
and what to include.

## Licence

MIT. See [LICENSE](LICENSE).
