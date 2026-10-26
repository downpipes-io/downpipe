# Security policy for downpipes-io/downpipe

The downpipe binary is a Go offline CLI that reads, verifies, and
restores downpipe/0.1.0 archives without any network call to Maelstrom AI or
to the engine. It operates entirely within the operator's own environment
(laptop, air-gapped workstation, or automation runner). Because it holds no
server-side state and makes no inbound connections, its attack surface is
confined to: the archive files it reads, the S3-compatible or Azure Blob source it
can read from, the Cloudflare API answers that the provisioner commands read, and the
operator-supplied flags.

---

## Reporting a vulnerability

**Please do not open a public GitHub issue for security findings.**

Report via email to:

    security@maelstrom.au

Include:

- a description of the vulnerability and the affected component;
- reproduction steps, a proof-of-concept, or a test vector if you have one;
- the potential impact as you understand it;
- your preferred contact for follow-up.

We will acknowledge your report within **2 business days** and keep you informed
throughout remediation. We will coordinate public disclosure with you and credit you
by name (or anonymously, if you prefer) once the fix is shipped.

We do not operate a bug-bounty programme at this time.

### Encrypted reporting

If a finding is sensitive enough that plain email is not appropriate, encrypt it
with our OpenPGP key: https://maelstrom.au/.well-known/security.asc (fingerprint
3AFA 3933 B25B 53B9 DBFA 1464 B047 75F6 8767 EF48).
GitHub private vulnerability reporting is not turned on for this repository, so use
email.

### Coordinated-disclosure window

We follow a **90-day coordinated-disclosure window**. Give us up to 90 days from
the date of your report before any public disclosure. This gives us time to prepare
a fix and an advisory. We will work to disclose sooner where a
fix ships earlier, and we will agree any extension with you in writing if a
coordinated cross-component release needs more time (the exception path below).
We will not request silence beyond what is needed to protect operators.

### Safe harbour

If you report a vulnerability in good faith and in line with this policy, we will
not take or support legal action against you. We treat such research as authorised,
and we do not consider it a breach of computer-misuse terms or our terms of
service. If a third party raises a concern about your research under this policy, we will
say so on your behalf. We work with you to understand and fix the issue quickly.

Good-faith research means that you:

- avoid privacy violations, data destruction, and any interruption or degradation
  of services or systems;
- interact only with accounts that you own or have explicit permission to test;
- do not access any data beyond the minimum needed to show the finding, and do
  not change or keep customer data beyond that minimum;
- never use, store, share or exfiltrate any data that you access beyond what the
  report needs;
- do not exploit a finding beyond what you need to confirm it;
- report the finding to us promptly;
- give us reasonable time to fix the issue before you disclose it publicly.

If you are not sure whether we allow an action, ask us at
security@maelstrom.au before you proceed.

This safe harbour does not cover a breach of the law. It does not cover tests
against any system that you do not control.

---

## Risk-based remediation SLA

These timeframes run from the date we become aware of the finding.

| Severity  | Definition (examples)                                           | Target remediation  |
|-----------|---------------------------------------------------------------|---------------------|
| Critical  | RCE via malicious archive, private-key exfiltration             | 2 business days     |
| High      | Archive-verification bypass, AEAD forgery, path traversal       | 7 calendar days     |
| Medium    | Defence-in-depth bypass, redirect-following SSRF, decompression abuse | 30 calendar days |
| Low       | Missing documentation, informational finding                    | 90 calendar days    |

**Exception path.** Where the fix requires a coordinated release with the engine
(for example a breaking change to the downpipe/0.1.0 archive format or the
hybrid-signature scheme), the target may be extended by up to 30 days with a written
internal risk-acceptance record. No extension applies to Critical or High findings.

**Severity assignment** follows the CVSS 4.0 base score. Because the CLI runs
offline in the operator's own environment, privilege escalation and lateral movement
within the Cloudflare account are not reachable from this component alone.

---

## Supported versions and branches

Fixes ship only in the next release; the vendor does not backport them.

| Release | Status | Notes |
|-------------|------------------|------------------------------------------|
| `main`      | Supported        | All security fixes land here first       |
| Latest release | Supported | It has no successor, so it has no end-of-support date |
| An earlier release | Supported until 90 days after its successor ships | Upgrade to the latest release |
| A release past that date | End of life | No fixes of any kind |

The release workflow builds each release only from a signed tag. There is no automatic update mechanism
in the CLI itself; operators are responsible for pulling and deploying fixes within
the SLA window above.

---

## Dependency vulnerability handling

### Detection

Several automated mechanisms detect vulnerable dependencies. Items 1 and 2 run on every
push and pull request against `main` (`.github/workflows/ci.yml`):

1. **`govulncheck ./...`** (the `govulncheck` job) runs the Go vulnerability
   database check against all transitive dependencies and fails the build on any
   reachable advisory. This is a blocking gate; the `ci-success` sentinel will not
   pass if `govulncheck` reports a finding.

2. **`go test -race ./...`** (the `build-test` job) runs the full test suite with
   the Go race detector, catching concurrency bugs that could affect archive
   integrity.

3. **Dependabot** (`.github/dependabot.yml`) opens weekly pull requests for both
   `gomod` packages and GitHub Actions pins.

4. **Pinned, hardened workflows.** The `step-security/harden-runner` action is
   pinned to a full commit SHA in every workflow job that checks out the
   repository, and `actions/checkout` is run with `persist-credentials: false`.

The CI and release toolchain is pinned via `GO_VERSION=1.26.10`
(`.github/workflows/ci.yml`) and the `toolchain go1.26.10` directive in `go.mod`;
the `go.mod` `go` directive (the minimum supported floor) is `go 1.26.0`. The
1.26.10 toolchain was chosen specifically because it incorporates stdlib
advisories tracked by `govulncheck` that earlier patch releases did not carry:
GO-2026-5856 (crypto/tls ECH privacy leak, missing before 1.26.5) and
GO-2026-6218, GO-2026-6090, GO-2026-6088, GO-2026-5972 and GO-2026-5026
(net/url, crypto/tls, encoding/xml, encoding/asn1 and net/http, all missing
before 1.26.6) and GO-2026-6603, GO-2026-6604, GO-2026-6605,
GO-2026-6607, GO-2026-6608, GO-2026-6610, GO-2026-6611, GO-2026-6612, GO-2026-6613 and GO-2026-6617
(net/http, crypto/tls, net/textproto and os, all missing before 1.26.9) and GO-2026-6809
(crypto/x509 distrust of compromised intermediate certificates, missing before 1.26.10); the comment in `go.mod` records this rationale.

### Response

- A `govulncheck` finding fails the `govulncheck` job, which is in the
  `CI Success` needs list, so `CI Success` goes red with it, and that blocks the
  merge. `main` in this repository is protected by an active repository ruleset
  with no bypass actors. It requires a pull request (no approving review is
  required) and a passing `CI Success` status check on a branch that is up to date
  with `main`. It also blocks force pushes to `main` and deletion of `main`. The
  finding must be resolved (module upgrade, patch, or justified override with a
  risk-acceptance comment) before the pull request can merge.
- Dependabot PRs for security advisories are reviewed and merged within the
  applicable SLA window. Non-security version bumps are reviewed weekly.

### Crypto dependencies

The Go module (`go.mod`) has two direct dependencies:

- `golang.org/x/crypto v0.57.0` supplies HKDF (`golang.org/x/crypto/hkdf`).
- `filippo.io/mldsa v1.0.0` supplies ML-DSA-87 (FIPS-204). This is pinned to
  that exact release, and `go.sum` records its hash. The committed `vendor/` tree is
  what the reader is built from, and CI re-derives it from the pinned modules and fails
  on any byte difference.

The Go 1.26 standard library supplies `crypto/mlkem` (ML-KEM-1024, FIPS-203),
`crypto/ecdh` (X25519) and `crypto/ed25519`. Together these implement the mandatory PQ-hybrid envelope:
X25519 + ML-KEM-1024 KEM and Ed25519 + ML-DSA-87 signatures, with AES-256-GCM
(from stdlib) and SHA-384 / HKDF-SHA-384.

Advisories against any of these are treated as **at least High** regardless of the
CVSS base score, because a break directly affects the confidentiality and integrity
of the archives the CLI reads.

---

## Security architecture summary

This section records the controls that are actually implemented, so that a
security review can quickly locate the relevant source.

**Archive verification before any output.** The CLI verifies the hybrid signature
(Ed25519 + ML-DSA-87, both halves) and the Merkle root against the signed root
manifest before decrypting a single record. A forged root manifest is rejected before
any plaintext is produced, unless the operator passes `--allow-unverified`. A tampered
shard manifest always fails its signed SHA-384 check. A tampered segment fails its
record's AEAD or SHA-384 check, and the CLI does not write that record.

**Decompression bounds.** Gzip-encoded record values are decompressed bounded by the
size declared in the signed manifest (the `gunzip` function in
`internal/format/restore.go`), mitigating decompression-bomb attacks. Object reads from
disk are bounded by the `maxObjectBytes` constant (`internal/source/dir.go`), set to
2 GiB. The reader reads the root manifest, the RUNLOG and their signatures before it
checks a signature, so these objects have smaller caps: 256 MiB for the root manifest
and the RUNLOG, and 64 KiB for a signature (`internal/format/reader.go`). The disk, S3
and Azure stores refuse an object above its cap from its size, before they read it.

**No hard-coded keys or credentials.** Private key material is never embedded in
the binary. `keygen`, `recombine` and `selftest --keep` (which keeps a throwaway
sample key) write private key files, with owner-only permissions, and refuse to
overwrite an existing file (`writeKeyFile` in `cmd/downpipe/main.go`,
`cmd/downpipe/recombine.go`). Every other command reads keys from files the operator
supplies and never writes them.

**S3 source authentication.** When reading from an S3-compatible source, the CLI
sends credentials only in a SigV4 `Authorization` header, never in URLs or query
strings (`internal/source/s3.go`).

**Cloudflare API redirects are refused.** Every credentialed call to the Cloudflare API, the
provisioning apply, the preflight account checks and the provisioning client's own fallback
transport, uses `provision.NoRedirectClient` (`internal/provision/client.go`), an `http.Client`
with a bounded timeout and a `CheckRedirect` policy that returns `http.ErrUseLastResponse`.
`http.DefaultClient`, which follows up to ten redirects and would carry the Bearer token with
it, is never used for a credentialed call. `TestNoRedirectClientRefusesRedirect` and
`TestNewClientNilDoerRefusesRedirect` pin both.

**S3 redirects are refused.** The S3 `http.Client` sets a `CheckRedirect` policy
that returns `http.ErrUseLastResponse` (the `CheckRedirect` policy in
`NewS3Store`, `internal/source/s3.go`), so no redirect
is ever followed. A redirect from the storage service to a different host could
otherwise expose the SigV4 `Authorization` header or steer archive bytes to an
attacker-controlled endpoint; the redirect response is instead surfaced as a
non-200 status and the read fails closed
(`TestS3StoreNoFollowRedirect`, `internal/source/s3_test.go`).

**No network calls to Maelstrom AI.** The CLI makes no calls to any Maelstrom AI
or Downpipes service. All archive data is read from operator-supplied paths or
endpoints.

**Cross-implementation test vectors.** The Go CLI and the TypeScript engine share
the conformance vectors in `internal/format/testdata/vectors`. The engine's CI, in
the engine repository, checks out this public repository at a pinned release tag.
It runs `npm run validate` (which includes `validate-reader.ts`) to confirm that the
TypeScript reader accepts and rejects the Go-produced vectors as they require. Its
writer-to-reader job has the engine seal a real archive that this reader verifies
and restores, and checks that this reader rejects a tampered copy. This repository's
own CI does not run the engine.

---

## Known open findings

This policy lists no open finding for the downpipe CLI. The file-handling policy that
covers the CLI, including the 2 GiB object cap in `internal/source/dir.go` and the
manifest-bounded decompression in `internal/format/restore.go`, is part of the engine's published security documentation.

The normative behaviour of the format itself, including the verification and
rejection rules a conformant reader must enforce, is specified in
[`docs/format/SPEC.md`](docs/format/SPEC.md) and pinned by the conformance
vectors described in [`docs/format/CONFORMANCE.md`](docs/format/CONFORMANCE.md);
those vectors are the contract any second implementation proves itself against.

If you believe you have found an exploitable path that builds on the controls above,
please report it privately (see *Reporting a vulnerability*) rather than assuming
it is already known.
