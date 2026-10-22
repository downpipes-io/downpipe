# downpipe

[![CI](https://github.com/downpipes-io/downpipe/actions/workflows/ci.yml/badge.svg)](https://github.com/downpipes-io/downpipe/actions/workflows/ci.yml)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/downpipes-io/downpipe?display_name=tag&sort=semver)](https://github.com/downpipes-io/downpipe/releases)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/downpipes-io/downpipe/badge)](https://scorecard.dev/viewer/?uri=github.com/downpipes-io/downpipe)

`downpipe` is the standalone, offline reader for downpipe archives. It verifies
and restores encrypted Cloudflare backups from the destination bucket bytes plus
your own keys, with neither Cloudflare nor any vendor service in the loop.

This repository is the open core of the product: the offline reader and the
archive format it reads. The format is the moat. The format is documented in
full (see [`docs/format/SPEC.md`](docs/format/SPEC.md)), and every archive carries
a signed pointer naming the format version it was written under. So a holder of
the destination bytes, the offline break-glass key and a pinned signer can always
recover, even if the vendor disappears and even if the Cloudflare account is gone.
The pinned signer is the signer public key (`signer.pub`) from the recovery kit.
From reader 0.3.4 it can instead be the signer fingerprint on the printed recovery
sheet, which pins the `signer.pub` copy that the bucket carries from engine 0.3.7. That
copy is the current signer's, so after a signer rotation the older runs still need the
kit file. The engine that schedules and writes archives is a
separate, source-available component (Elastic License 2.0), and nothing here
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

`@latest` resolves to the newest release tag, which carries the full command set,
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

Or download a prebuilt binary from the [releases page](https://github.com/downpipes-io/downpipe/releases):
each tagged release ships reproducible binaries for linux, darwin and windows (amd64 and arm64), a CycloneDX SBOM for each archive and a cosign-signed checksums file.
`downpipe version` prints the version a binary was built from (`dev` for `go install` or a plain
local build, the tag for a release-pipeline build). See [VERIFY.md](VERIFY.md) to check a
downloaded binary against its checksum and signature before you run it.

**On macOS**, the release binaries are signed ad hoc and are not notarised by Apple. An
archive you download with a web browser is quarantined, and so is the binary you unpack
from it. When you run that binary, macOS blocks it. To run it:

1. Verify the archive first, as [VERIFY.md](VERIFY.md) describes.
2. Remove the quarantine attribute from the unpacked binary with
   `xattr -d com.apple.quarantine ./downpipe`.

An archive you download with `curl` is not quarantined, so its binary runs without this step.

**There is one archive format line and one reader.** The format is
`downpipe/0.1.x` and this reader implements exactly it. A label outside the
`downpipe/MAJOR.MINOR.PATCH` shape, two components included, is refused as
malformed rather than as a version somebody could go and find a reader for.

When this tool refuses a well-formed format version that it does not implement, it
tells the holder to get a reader that implements that version, and points here. See
[CHANGELOG.md](CHANGELOG.md), "The retention duty on releases", for what a reader
owes once it names a format version it does not implement.

See [CHANGELOG.md](CHANGELOG.md) for releases and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for the community standards.

## Try it

Build the tool, then prove the whole round trip end to end:

```
go build ./cmd/downpipe
./downpipe selftest
```

`selftest` seals a value with the post-quantum envelope and recovers it from disk
using only the offline break-glass identity and the pinned signer, with nothing else in the loop.

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
`restore` warn on stderr when it is left off, unless you pass
`--acknowledge-no-rollback-pin`; see
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
  and verifies every record while writing nothing. A large record that is not
  gzip-compressed streams straight from the store to a file or discard sink, so peak
  memory does not scale with it. A gzip record is decompressed in memory, up to its signed
  plaintext size
- verifies the hybrid signature against an operator-pinned signer, the recipient
  set, the key commitment, every shard's hash, the declared count, the Merkle root
  and each record's hash on restore
- attests an archive without the break-glass identity and without producing plaintext,
  confirming the shard hashes and the RUNLOG, and the root signature when you pin
  `--signer`
- inspects an archive so you can see what it holds before restoring anything
- verifies the signature on an assurance report the engine generated, against your
  signer, with no archive and no identity needed

verify and restore enforce freshness against the signed RUNLOG (SPEC.md 10), and
a failure exits 5 until you acknowledge it. The two acknowledgements are separate
on purpose: `--allow-stale` covers this run's AGE, and nothing else, from a RUNLOG
that verified against your `--signer` and is internally consistent, while
`--allow-unverified-runlog` covers a RUNLOG that is absent, unreadable, fails its
signature, or contradicts the signed root manifest. `--min-runlog-index` pins the
anti-rollback high-water mark out of band. The
recovery-bundle hash binding (SPEC.md 8.7) is verified on the opt-in
`--check-bundle` path, which checks the in-bucket `FORMAT.md` and `RECOVER.md`
against the bundle's signed `SHA384SUMS`.

Restore is offline by design. The keys are yours, the format version is named in
the bucket next to the data, and the recovery path (`keygen`, `inspect`, `verify`,
`attest`, `restore`, `recombine` and `selftest`) imports no telemetry or vendor SDK.
It makes no network call other than to a destination endpoint you name with
`--s3-endpoint` or `--azure-endpoint`, so it cannot call home.

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
Cloudflare account. `preflight` makes read-only (GET-only) calls to
`api.cloudflare.com` using a token you supply in `CLOUDFLARE_API_TOKEN`; the token
stays on this machine and nothing is created or changed. `setup` prints its plan and
makes no network call. With `--apply`, it creates the planned Access, Secrets Store
and binding resources through `api.cloudflare.com` with the same token.
`init` and `update` are plan printers that emit a runbook and make
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
bucket bytes, the customer's own offline break-glass key and a pinned signer can
recover the data with neither Cloudflare nor the vendor available. The pinned signer
is `signer.pub` from the recovery kit, or (from reader 0.3.4) the signer fingerprint
on the printed recovery sheet. With `--signer-fingerprint`, the reader uses the bucket's
copy of `signer.pub` only if its fingerprint equals the one on the sheet, so the trust
anchor stays offline. An engine writes that copy from 0.3.7, and every run overwrites it
with the current signer's key. So the fingerprint route covers a run only while the
signer that sealed it is still the current signer. Keep the kit file for every other run.

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
bytes, the break-glass key and a pinned signer end to end, including the high-assurance
posture in which the break-glass key is the only key that can open the archive.

## Verify a signed report

When the engine has a signer configured, it signs the assurance reports it generates
(restore tests, SLA compliance, immutability, posture, the compliance evidence pack and
change records) with that signer, the same key pair that signs your archives.
`verify-report` checks a report's signature offline against the signer public key file:

```
downpipe verify-report --signer ./keys/signer.pub --report ./posture-report.json
```

Give it the report JSON: the body of `GET /admin/reports/<kind>`, or the console's View JSON
saved to a file. The console offers the compliance evidence pack as a PDF only, so take its
JSON from `GET /admin/reports/evidence-pack?framework=<id>`. `--report -` reads the JSON
from standard input. The signature covers the JSON. The PDF does not carry a signature this
tool can check, and each request generates a new report, so a JSON you fetch after the PDF
is a separately generated report, not the one the PDF shows. The signature is over the
canonical JSON of the report's `kind`, `generatedAt`, `period` and `data`, and both halves,
Ed25519 and ML-DSA-87, must verify. The command prints the signer fingerprint. Compare it
with the one on your recovery sheet, or pass that value as `--signer-fingerprint`, and the
command refuses a `--signer` file with a different fingerprint.

Exit 0 means the report verified. Exit 2 means it did not: the report is unsigned, it was
changed after signing, a different signer signed it, its signature is damaged, or the file
holds something the engine does not write, such as a repeated member name. When one
signature half verifies and the other does not, the message names that half and both places
it can fail: that part of the report's signature member (edited or badly copied), or that
half of the `--signer` file (damaged, or from a partial signer rotation). Take the report JSON
again from the engine first, then another copy of `signer.pub` from your recovery kit, and
do not rely on the report until both halves verify. Exit 6 means the input is not a report
JSON, for example the PDF, or a flag or key file is wrong.

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
recovery is delivered by a documented reader of the downpipe format
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
cmd/downpipe        command line: keygen, inspect, keys, verify, attest, restore,
                    recombine, selftest (recovery/reader path); verify-report
                    (signed assurance reports); prune,
                    unseal-export; setup, preflight, init, update (provisioner
                    path); version, spec, help
internal/crypto     CNSA 2.0 hybrid post-quantum envelope and key handling
internal/spec       on-disk format constants, ULIDs and manifest types
internal/format     archive reader: manifests, signing, shards, segments, verify
internal/source     read archives from a local directory, an S3-compatible bucket
                    or an Azure Blob container
internal/restore    write restored records to a target (file directory, env stream or discard)
internal/custody    rebuild the break-glass identity from M-of-N custody artefacts
internal/prune      plan and apply the deletion of superseded runs
internal/provision  Cloudflare account checks and the setup plan and apply for the
                    provisioner path
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
`toolchain go1.26.10` pin in `go.mod`. That is what underpins the offline-recovery
promise above: if the vendor and Cloudflare are both gone, you can still rebuild
the recovery tool from this repository alone.

```
go build -mod=vendor ./...
go test  -mod=vendor ./...
```

The toolchain pin is the one thing the checked-out source cannot supply. Under
Go's default `GOTOOLCHAIN=auto`, a machine whose installed `go` is older than the
pin, and whose module cache does not already hold `go1.26.10`, fetches that
toolchain from the module proxy before it compiles anything; with no proxy
reachable the build exits 1 with `toolchain not available` rather than quietly
falling back to the older Go. Driven against a clean module cache
with `GOPROXY=off` on a machine running go1.26.1: `GOTOOLCHAIN=auto` exits 1,
`GOTOOLCHAIN=local` exits 0 and the binary reports `downpipe dev`, and the same
`auto` build exits 0 against a cache that already holds the pinned toolchain,
which is why a machine that has built this repository before will not show the
gap. `GOTOOLCHAIN=local` gives up the security fixes the pinned toolchain carries, so keep a
`go` meeting the pin alongside the source rather than reaching for `local` during
a recovery.

Set `GOFLAGS=-mod=vendor` (or `GOPROXY=off`) to force the vendored build. A
`GOPROXY=off` build that exits 0 is a proof that no network was touched, since
the toolchain is fetched from that same proxy; a `GOPROXY=off` build that exits 1
on the toolchain is the gap above rather than a fault in the source. This covers
the from-source path only. It is not a claim of reproducible or signed builds;
for verified release binaries (which are reproducible and ship an SBOM) see
Install above.

## The downpipes family

| Repository | What it is | Licence |
|------------|-----------|---------|
| [`engine`](https://github.com/downpipes-io/engine) | The in-account backup Worker: capture, seal, schedule, restore | Elastic 2.0 |
| [`console`](https://github.com/downpipes-io/console) | The in-account management console; every action in the browser | Elastic 2.0 |
| `downpipe` (this repo) | The offline Go reader: verify and recover archives with no vendor | MIT |

Docs live at [docs.downpipes.io](https://docs.downpipes.io), and you can mount them in your AI tooling: [use the docs in your agent](https://docs.downpipes.io/reference/connect-docs-to-ai). The product site is [downpipes.io](https://downpipes.io).

## Docs, support and security

Full documentation, including the guided deploy path, lives at
[docs.downpipes.io](https://docs.downpipes.io). General support: support@downpipes.io. Report a
vulnerability by email rather than a public issue; see [SECURITY.md](SECURITY.md) for the address
and what to include.

## Licence

MIT. See [LICENSE](LICENSE).
