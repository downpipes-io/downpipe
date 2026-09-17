# Contributing

These are the standards every change holds to. They are deliberately light on
process and heavy on craft. CI, secret scanning, dependency review, static
analysis and supply-chain checks already run on every push and pull request
against `main` (see `.github/workflows/`); a contributor sees the same gates a
maintainer does.

## Contributor Licence Agreement

Pull requests are accepted only from contributors who have signed the
[Contributor Licence Agreement](CLA.md). The CLA Assistant bot checks this automatically on your
first pull request and posts a comment with a sign-off link if you have not signed yet; signing
takes one comment and you only do it once.

## Style

- Australian English (organise, authorise, behaviour, colour, centre, licence the
  noun, licensed the verb).
- Comments explain why, not what; the code already says what.
- Keep internal references out of shipped code and comments.

## Go code standards

- `gofmt -s` clean and `go vet ./...` clean. No exceptions committed.
- Library code returns errors; it does not `panic`. Reserve `panic` for truly
  unreachable invariants, and never for input handling.
- Wrap errors with context using `fmt.Errorf("...: %w", err)`.
- Compare secret material in constant time with `crypto/subtle`. Never use a
  byte-by-byte loop or `==` on keys, tags, signatures or other secrets.
- Tests are table-driven where it helps, and run under `-race`.
- The crypto and format packages carry known-answer tests and fuzz targets, and
  the archive round-trip is proven byte-for-byte against the conformance vectors.
- No new dependency without a reason. Prefer the standard library.

## The format is the contract

`docs/format/SPEC.md` is the single source of truth for the on-disk archive. Code
must write exactly what the spec describes, the spec must describe exactly what
the code writes, and CI proves it with a backup-to-restore round-trip over the
conformance vectors. A change to the format is a deliberate, versioned decision,
never an accident.

## Cryptography and archive-format rules (downpipe/0.1.0)

These rules are normative for any change to the crypto, format, restore or
offline-tool packages. They implement decisions D9 and D10 of the format review
and back the guarantees of `docs/format/SPEC.md`.

### The envelope is the pinned CNSA 2.0 construction; do not invent your own

The on-disk envelope is the construction pinned in `docs/format/SPEC.md`: AES-256-GCM
in the downpipe STREAM (a per-file payload nonce, 64 KiB chunks, an 11-byte
big-endian counter and a 1-byte last-chunk flag, the payload key derived by
HKDF-SHA-384 of the file key salted by the nonce), a hybrid X25519 + ML-KEM-1024 key
encapsulation whose combiner is X-Wing's binding generalised to ML-KEM-1024 over
HKDF-SHA-384, the per-run master capsule that wraps the master to every recipient by
KEM-DEM, and a hybrid Ed25519 + ML-DSA-87 signature with both halves required. Do not
invent a different AEAD, chunking, key encapsulation, combiner or signature. Any
deviation is a versioned spec change (a major bump), never a quiet patch, and the
conformance vectors move with it.

The library boundary is deliberate. ML-KEM, the X25519 exchange, AES-256-GCM and the
SHA-384 family come from the Go standard library; ML-DSA comes from `filippo.io/mldsa`
until the stdlib `crypto/mldsa` lands in Go 1.27. The hybrid KEM combiner and the
master capsule are assembled from these vetted primitives, which is implementing the
pinned construction, not hand-rolling a new one. The whole-buffer seal and open are
used only for small bounded inputs (the master capsule and the conformance vectors);
arbitrary-size segments use the streaming seal and open with a chunk bound, so a value
is never held whole in memory.

### Crypto-dependency allowlist

Crypto comes from a short vetted allowlist only:

- The Go standard library: `crypto/mlkem` (ML-KEM-1024, FIPS 203), `crypto/ecdh`
  (X25519), `crypto/ed25519`, `crypto/aes` and `crypto/cipher` (AES-256-GCM),
  `crypto/sha512` (SHA-384), `crypto/hmac`, `crypto/subtle` and `crypto/rand`.
- `golang.org/x/crypto/hkdf` (HKDF-SHA-384).
- `filippo.io/mldsa` (ML-DSA-87, FIPS 204) until the stdlib `crypto/mldsa` lands
  in Go 1.27, at which point the dependency is dropped for the stdlib package.

The post-quantum posture is hybrid on both axes and at CNSA 2.0 parameters:
confidentiality is X25519 plus ML-KEM-1024 combined with an X-Wing-derived combiner,
and signatures are Ed25519 plus ML-DSA-87 with both halves required, so an archive
stays confidential and tamper-evident if either the classical or the post-quantum
half is later broken. The hash and KDF layer is SHA-384. The exact wire format is
pinned in `docs/format/SPEC.md`.

No ad-hoc third-party crypto. Adding any other cryptographic dependency, or
re-implementing a primitive that the allowlist provides, requires a format-review
sign-off and is presumptively rejected. `TestCryptoFormatImportAllowlist` in
`internal/crypto` fails the build, on every change, if the import graph of
`internal/crypto` or `internal/format` reaches any external dependency outside the
allowlist (stdlib crypto plus `golang.org/x/crypto/hkdf` and `filippo.io/mldsa`). It
runs under `go test ./...`, which CI executes as a required job.

### Leaf types package (no crypto to format import cycle)

The on-disk types live in a single leaf package, `internal/spec`, together with the
algorithm and codec identifier constants and the HKDF and MAC info-string constants
of SPEC.md section 11.7. `internal/spec` imports none of the crypto, format, restore or
offline packages; those packages import `internal/spec`. This breaks the import
cycle and keeps the frozen byte-level constants in one place that the conformance
vectors and both the writer and the reader share. A change to a constant in
`internal/spec` that is a frozen SPEC value is a major bump (SPEC.md section 13).

### CI fuzz targets

The crypto and format packages MUST carry CI fuzz targets, run on every change to
those packages:

- An envelope round-trip target: seal then open a value through the pinned STREAM
  construction and assert the recovered plaintext and its `plaintextSha256` match.
- A malformed-input target over the negative-shape space: a truncated final chunk,
  reordered chunks, a flipped GCM tag, a wrong chunk counter or last-chunk flag, a
  tampered payload nonce, and a forged or replayed capsule wrap. A conformant reader
  MUST reject each without panicking and with a non-zero outcome.

These complement, and do not replace, the normative conformance corpus under
`testdata/vectors/` (SPEC.md section 14, `docs/format/CONFORMANCE.md`).

### The offline binary imports no network, telemetry or vendor SDK

The offline tool and its ENTIRE import graph MUST NOT import any network, telemetry
or vendor-SDK package. Archive bytes are read through a narrow storage interface:
local disk, plus a minimal S3 GET that carries no analytics and no metrics and no
vendor client beyond the bytes. `TestOfflineImportGraphHasNoVendorSDK` in
`cmd/downpipe` asserts that `go list -deps` over the command contains none of the
forbidden packages (the test carries the explicit denylist: the Cloudflare SDK, any
analytics or telemetry client, and any general HTTP server or RUM package; a plain S3
GET via the standard HTTP client is permitted). It runs under `go test ./...`, which
CI executes as a required job. This is what keeps recover-without-vendor true at the
binary level: the bytes-recovery path cannot phone home and cannot depend on the
vendor.

### What a reader MUST enforce in verified mode

When touching the restore or verify path, preserve the verified-mode reader
contract of SPEC.md section 8: operator-pinned `--signer` (never the manifest's
self-asserted `signingKeyFingerprint`); recompute and constant-time-compare each
shard hash, the Merkle root, the key commitment and the recipient-set hash against
the signed values; re-derive each segment and shard file key from the committed
master and reject a stanza wrapping a different file key; confirm each relied-upon
sealed unit actually carries a well-formed break-glass stanza matching the signed
recipient; verify the signed RUNLOG and, when relying on the bundled spec or reader,
the recovery-bundle hashes. A change that weakens any of these from a MUST to a
softer check is a security regression and requires format-review sign-off.

All hash comparisons use `crypto/subtle.ConstantTimeCompare` on decoded bytes, never
a string compare. All binary in downpipe JSON is base64url no-pad; hashes are bare
lowercase hex; key fingerprints carry a type prefix.

## Commits

Short, imperative, scoped: `crypto: add streaming AEAD frame sealing`. Describe
the change and the reason, not the process that produced it.
