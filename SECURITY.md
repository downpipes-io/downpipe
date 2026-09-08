# Security policy for downpipes-io/downpipe

The downpipe binary is a Go offline CLI (and library) that reads, verifies, and
restores downpipe/0.1.0 archives without any network call to Maelstrom AI or
to the engine. It operates entirely within the operator's own environment
(laptop, air-gapped workstation, or automation runner). Because it holds no
server-side state and makes no inbound connections, its attack surface is
confined to: the archive files it reads, the S3/R2 source it can pull from,
and the operator-supplied flags.

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

If a finding is sensitive enough that plain email is not appropriate, request our
PGP key by emailing security@maelstrom.au with the subject `pgp-key request`, or
use GitHub's private vulnerability reporting on this repository
(https://github.com/downpipes-io/downpipe/security/advisories/new), which keeps the
report and the exchange confidential until a fix is published.

### Coordinated-disclosure window

We follow a **90-day coordinated-disclosure window**: we ask that you give us up
to 90 days from the date we acknowledge your report before any public disclosure,
so a fix and an advisory can be prepared. We will work to disclose sooner where a
fix ships earlier, and we will agree any extension with you in writing if a
coordinated cross-component release needs more time (the exception path below).
We will not request silence beyond what is needed to protect operators.

### Safe harbour

We will not pursue or support legal action against you for security research
conducted in good faith under this policy. Activity is in good faith when you:

- make a genuine effort to avoid privacy violations, data destruction, and any
  interruption or degradation of services or systems;
- access only the minimum data needed to demonstrate a finding, and never use,
  store, share or exfiltrate that data beyond what the report requires;
- report promptly and give us a reasonable time to remediate before disclosing;
- do not exploit a finding beyond what is necessary to confirm it.

If you are unsure whether a specific action is authorised, contact us at
security@maelstrom.au and ask before you proceed. We will not consider research
that complies with this policy to be a breach of any applicable computer-misuse
or anti-circumvention terms, and we will say so on your behalf if a third party
raises a concern about work conducted under it.

---

## Risk-based remediation SLA

These timeframes run from the date a finding is confirmed (that is, triaged and
reproduced, not merely reported).

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

| Branch / tag | Status           | Notes                                       |
|-------------|------------------|---------------------------------------------|
| `main`      | Supported        | All security fixes land here first           |
| Tagged releases | Supported for 90 days after tag | Fixes backported on request for Critical/High |
| Older releases | Not supported  | Upgrade to the latest tag                   |

Releases are dispatch-only signed builds. There is no automatic update mechanism
in the CLI itself; operators are responsible for pulling and deploying fixes within
the SLA window above.

---

## Dependency vulnerability handling

### Detection

Several automated mechanisms run on every push and pull request against `main`
(`.github/workflows/ci.yml`):

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
   pinned to a full commit SHA in every workflow job, and `actions/checkout` is
   run with `persist-credentials: false`.

The CI and release toolchain is pinned via `GO_VERSION=1.26.6`
(`.github/workflows/ci.yml`) and the `toolchain go1.26.6` directive in `go.mod`;
the `go.mod` `go` directive (the minimum supported floor) is `go 1.26`. The
1.26.6 toolchain was chosen specifically because it incorporates stdlib
advisories tracked by `govulncheck` that earlier patch releases did not carry:
GO-2026-5856 (crypto/tls ECH privacy leak, missing before 1.26.5) and
GO-2026-6218, GO-2026-6090, GO-2026-6088, GO-2026-5972 and GO-2026-5026
(net/url, crypto/tls, encoding/xml, encoding/asn1 and net/http, all missing
before 1.26.6); the comment in `go.mod` records this rationale.

### Response

- A `govulncheck` finding fails the `govulncheck` job, which is in the
  `CI Success` needs list, so `CI Success` goes red with it. It does not
  mechanically block a merge: `main` in this repository carries no branch
  protection and no repository ruleset, so no status check is required and nothing
  stops a merge or a direct push over a red run. The finding must still be resolved
  (module upgrade, patch, or justified override with a risk-acceptance comment)
  before any code lands; that is a rule people follow, not one the platform
  enforces.
- Dependabot PRs for security advisories are reviewed and merged within the
  applicable SLA window. Non-security version bumps are reviewed weekly.

### Crypto dependencies

The Go module (`go.mod`) has two direct dependencies:

- `golang.org/x/crypto v0.54.0` supplies X25519 and related primitives.
- `filippo.io/mldsa v0.0.0-20260215214346-43d0283efc3e` supplies ML-DSA-87
  (FIPS-204). This is pinned to a full commit hash.

The Go 1.26 standard library supplies `crypto/mlkem` (ML-KEM-1024, FIPS-203) and
`crypto/ed25519`. All four together implement the mandatory PQ-hybrid envelope:
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
(Ed25519 + ML-DSA-87, both halves) and the Merkle root against the sealed header
before decrypting a single record. A forged or tampered archive is rejected before
any plaintext is produced.

**Decompression bounds.** Gzip-encoded record values are decompressed bounded by the
size declared in the signed manifest (the `gunzip` function in
`internal/format/restore.go`), mitigating decompression-bomb attacks. Object reads from
disk are bounded by the `maxObjectBytes` constant (`internal/source/dir.go`), set to
2 GiB.

**No hard-coded keys or credentials.** Private key material is always supplied by
the operator at runtime (flag or environment variable) and is never embedded in the
binary or written to disk by the CLI itself.

**S3 source authentication.** When reading from an S3-compatible source, the CLI
sends credentials only in a SigV4 `Authorization` header, never in URLs or query
strings (`internal/source/s3.go`).

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
cross-implementation test vectors for the cryptographic primitives. The engine CI
runs `npm run validate` (which includes `validate-reader.ts`) to confirm that the
Go-produced vectors are accepted by the TypeScript decoder, and vice versa.

---

## Known open findings

These are the open items most relevant to the downpipe CLI. They are tracked
internally and being addressed:

- **No documented file-handling policy (medium).** The mitigating controls exist
  in source (the 2 GiB object cap in `internal/source/dir.go` and
  manifest-bounded decompression in `internal/format/restore.go`) but are not yet
  published as a single auditable policy.

The normative behaviour of the format itself, including the verification and
rejection rules a conformant reader must enforce, is specified in
[`docs/format/SPEC.md`](docs/format/SPEC.md) and pinned by the conformance
vectors described in [`docs/format/CONFORMANCE.md`](docs/format/CONFORMANCE.md);
those vectors are the contract any second implementation proves itself against.

If you believe you have found an exploitable path that builds on the items above,
please report it privately (see *Reporting a vulnerability*) rather than assuming
it is already known.
