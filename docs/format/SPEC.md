# Downpipe archive format

- Identifier: `downpipe/0.1.0`
- Document version: 1.0
- Status: Stable. The format is frozen and the conformance vectors are cut.
- Date:
- Authors: The downpipe project (Maelstrom AI), and the open-source MIT downpipe contributors.
- Licence: This specification and the reference reader are published under the MIT licence.

The identifier `downpipe/0.1.0` is the frozen format version string. It is never renamed:
while the major is 0 a change to any byte-level rule is a new MINOR version, not an erratum
to this document (section 13).

## Abstract

A downpipe archive stores Cloudflare data on an S3-compatible destination as an encrypted,
content-addressed, self-describing tree of objects. It exists to make one promise true: a
holder of the destination bucket bytes and the customer's own offline key can fully recover
the data with neither Cloudflare nor any vendor available. This document is the normative
contract for that on-disk format: its object layout, its CNSA 2.0-grade hybrid
post-quantum cryptographic construction (AES-256-GCM STREAM, a hybrid X25519 + ML-KEM-1024
KEM-DEM capsule, hybrid Ed25519 + ML-DSA-87 signatures and SHA-384 throughout), its
cleartext bootstrap manifest and encrypted shard manifests, its signed freshness anchor and
recovery bundle, and the verified, complete-or-loud restore a conformant reader performs.
The downpipe envelope is not an age file and is interoperable with no off-the-shelf tool;
recovery is by a conformant reader of this format, kept by the recoverer or re-implemented
clean-room from this specification and the normative conformance vectors. A companion
machine-readable JSON Schema for the cleartext and decrypted JSON shapes lives at
`docs/format/schema.json`; where the schema and this document disagree, this document and
the conformance vectors govern.

## Requirements language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED,
MAY and OPTIONAL in this document are to be interpreted as described in BCP 14
(RFC 2119 and RFC 8174) when, and only when, they appear in all capitals, as shown here.

Status: stable, `downpipe/0.1.0`, versioned by semver. This document is the
normative design contract for the format. The version string `downpipe/0.1.0` is
byte-identical wherever it appears: this header, the `.seg` and `.dpe` containers
(section 7.1), the root manifest, the encrypted shard manifests, the compatibility
section, the HKDF and MAC info strings that carry a version, and the hybrid-KEM and
key-commitment labels. While the major is 0, any change to a byte-level rule in this
document is a new MINOR version (a different, incompatible format identity), never an
erratum; a patch bump changes no byte-level rule.

The conformance vectors under `testdata/vectors/` are part of this
specification. A reader is conformant when it accepts every positive and edge
vector and rejects every negative vector. A writer is conformant when its sealed
bytes match the writer-authoritative vectors byte-for-byte for the object
classes those vectors pin (section 14 names exactly which object classes are
writer-authoritative and which are not). Section 14 specifies the vectors.

The format is frozen and the conformance vectors are cut. The downpipe envelope
is NOT an age file and is not interoperable with the `age` tool; the second
independent reader is a separate, audited reader of the downpipe `.dpe`/`.seg`
format (Go or Workers) vendored in the recovery bundle, not `age` (sections 4,
9, 15).

Reference implementation status. The Go reference implementation is complete.
The reader (`internal/format`) implements this contract in full. It anchors trust
in the operator-pinned signer and recomputes the recipient set and
`recipientSetHash` from the manifest's signed inline recipient public keys, rather
than from a separately operator-supplied recipient set. It enforces the read-side
canonical-numeric form (section 11.3, exit 6 on a non-canonical count,
`internal/format/canonnum.go`). It emits the restore receipt (section 8.5,
`internal/format/receipt.go`). It verifies the recovery-bundle hash binding
(section 8.7, `internal/format/bundle.go`, enabled via
`Options.CheckRecoveryBundle`). Break-glass recoverability is proven by the held
identity opening the master capsule; a full offline drill uses the break-glass
private key and the conformant reader as described in section 8.6. The offline
restore package (`internal/restore`) is complete, including the no-clobber
planner and all target implementations. The conformance corpus pins the format
byte-for-byte for the writer-authoritative object classes and is the authority for
interoperability.

## 1. Purpose and guarantees

A downpipe archive stores Cloudflare data on an S3-compatible destination as an
encrypted, content-addressed, self-describing tree of objects. The format exists
to make one promise true: a holder of the destination bucket bytes and the
customer's own offline key can fully recover the data with neither Cloudflare nor
the vendor available.

The format preserves these properties.

- Recover without Cloudflare and without the vendor. Everything required to
  decrypt, verify and reassemble the data is in the destination bucket, alongside a
  signed recovery bundle (a versioned FORMAT.md pointer and RECOVER.md, section 9).
  The conformant reader is the open-source MIT downpipe project, kept by the
  recoverer or re-implemented from this specification and the conformance vectors,
  never the vendor. The break-glass identity that unlocks the archive is held by the
  customer offline and never reaches the vendor or Cloudflare.
- Opaque transfer. Values are treated as opaque byte strings. The format never
  parses, transforms, interprets or indexes a payload. The only operations
  applied to a value are an optional closed-set compression codec and the
  downpipe envelope (AES-256-GCM STREAM under a key derived from the run master,
  section 7).
- A second independent reader for the format. The sealed payload is the downpipe
  STREAM body (AES-256-GCM in fixed chunks, section 7.8) and the per-run master
  is wrapped to the recipients by the downpipe hybrid KEM-DEM capsule (section
  5.4). Recover-without-vendor is delivered by a conformant reader of this format,
  NOT by any third-party tool: the construction is post-quantum hybrid and is
  interoperable with nothing off the shelf. That reader is the open-source MIT
  downpipe project (the offline tool, this specification and the conformance
  vectors); a recoverer keeps a copy or re-implements a clean-room reader from the
  spec and the vectors, then recovers and verifies the archive end to end with the
  bucket bytes and the offline key.
- Tamper-evident and complete-or-loud. The manifests are signed against an
  operator-supplied signer fingerprint, every segment is bound to its own
  identity and position, the recipient set of every sealed unit is bound under
  the signature, and verified restore (the default) refuses to present a partial
  archive as whole.
- Streamable. Large values are sealed in downpipe STREAM chunks (AES-256-GCM, 64
  KiB plaintext per chunk), so neither the in-account writer nor the offline
  reader holds a whole value in memory.

The paid, proprietary assurance plane is a separate component. Nothing in this
format and nothing in the offline tool that implements it may require the vendor
to read, verify or restore an archive.

### 1.1 Threat model and what confidentiality actually holds

The break-glass private key is held offline by the customer and never reaches
Cloudflare or the vendor. The operational private key is an in-account identity:
it is the in-account read-back and verification path, and it is present in the
live Cloudflare account by design.

State the confidentiality property precisely, because the difference is
load-bearing for the secrets source (section 12.4).

- Destination bucket alone. An adversary who holds only the destination bucket
  bytes, without the in-account operational private key and without the offline
  break-glass key, recovers nothing but ciphertext. This is the offsite
  confidentiality guarantee and it is the property the offsite, cross-cloud
  destination delivers.
- Full Cloudflare account plus destination bucket. An adversary who fully
  compromises the live Cloudflare account obtains the in-account operational
  private key. Combined with the destination ciphertext, that key recovers the
  master from the capsule and so decrypts every sealed unit, including secrets,
  through the operational recipient path. The format does not defend this
  scenario in its default two-recipient posture.
- Break-glass-only high-assurance posture. A downpipe MAY be configured with no
  operational recipient, so the only recipient besides break-glass is omitted and
  the capsule is wrapped to the break-glass identity alone (the break-glass key
  MAY be Shamir-split across several offline holders). In that posture a full
  account compromise yields no key that opens the capsule, because the only
  decrypting key lives offline and every other unit is opened only by a
  master-derived file key. The cost is narrower than it once was, and is
  about what runs UNATTENDED rather than about verification (section 12.4). The
  writer verifies each run at seal, and the hourly canary reads its own cell back,
  from the run's OWN per-run master, which the seal path holds while it finalises;
  neither needs a standing in-account decrypting key, so both still run in-account
  in this posture. What stops is the work that needs a key present with nobody
  there: scheduled restore tests, the automated drill, and in-account retention
  pruning, which moves offline to the reader's prune. An in-console restore also
  still works, attended, because the operator's break-glass key opens the capsule
  in their browser. The break-glass requirement (section 5.2, D5) is satisfied either
  way, since break-glass is always present.

A reader and the recovery sheet make the active posture explicit, so an operator
relying on the secrets moat knows whether an operational key exists that could
decrypt under account compromise.

## 2. Terminology and key roles

- Downpipe. One route: a single source with an include and exclude selector, an
  envelope, a destination and a schedule. A house runs many independent
  downpipes over one bucket. The unit of scheduling and the unit of backup are
  the same.
- Run. One execution of one downpipe. A run is identified by a `runId` and is
  the unit a restore selects.
- Record. One backed-up item: a KV key and its value, an R2 object, a secret, or
  a database dump. A record has a stable per-run identity and a `plaintextSha384`
  over its full reassembled value.
- Segment. One content-addressed `.seg` object holding sealed bytes. A record is
  carried by one or more segments; a small record may share a segment with other
  records of the same downpipe (packing).
- File key. The 32-byte (AES-256) file key for one sealed unit. It is NOT
  wrapped per unit: only the master capsule carries per-recipient wraps (section
  5.4). Every sealed unit's file key is the key the STREAM payload key is derived
  from and is itself derived deterministically from the recovered master. For
  data segments the file key is derived per section 7.4; for the shard manifests
  it is derived per section 6.3. There are no 16-byte age file keys in this
  format.
- Master. A per-downpipe 32-byte secret, freshly generated per run and wrapped to
  the run's recipient set in the master capsule (section 5.4), from which the
  content-addressing key, the manifest subkey and every per-unit file key are
  derived by HKDF-SHA-384. The master is never written in the clear.
- Recipients. The recipient set the master capsule is wrapped to (section 5.4); a
  `.seg` and a shard `.dpe` carry no per-unit recipients. Every recipient is a
  hybrid X25519 + ML-KEM-1024 identity. Every run carries, at minimum, the
  break-glass recipient (a hybrid identity whose private half is attestably
  offline). The default posture additionally carries an operational recipient (an
  in-account hybrid identity); the break-glass-only posture omits it (section
  1.1). There is no passphrase or scrypt recipient.
- Signer. The hybrid Ed25519 + ML-DSA-87 keypair that signs the root manifest and
  the RUNLOG, both halves required with no downgrade (section 8). Customer-
  generated and escrowed; the vendor never holds it. Verified restore checks the
  hybrid signature against an operator-supplied expected signer public key, not
  the manifest's self-asserted fingerprint hint.

The break-glass private key, the operational private key (when used) and the
signer private key are generated on the customer side and recorded on a printed
recovery sheet in the same ceremony, before any backup runs.

## 3. Object layout

Every object lives under a caller-chosen root prefix `<root>/`.

```
<root>/
  run/<runId>/root.manifest.json           cleartext bootstrap manifest (section 5)
  run/<runId>/root.manifest.json.sig        detached hybrid signature (section 8)
  run/<runId>/manifest/<shardId>.dpe        encrypted shard manifest (section 6)
  seg/<aa>/<segId>.seg                       content-addressed sealed segment (section 7)
  _RECOVERY/downpipe/0.1.0/FORMAT.md           versioned format pointer (section 9)
  _RECOVERY/downpipe/0.1.0/RECOVER.md          bucket-only recovery instructions
  _RECOVERY/downpipe/0.1.0/SHA384SUMS          hashes of the versioned bundle
  _RECOVERY/RUNLOG                           append-only signed freshness anchor (section 10)
  _RECOVERY/RUNLOG.sig
  index.json                                 optional convenience catalogue, never required
```

`runId` is a canonical 26-character uppercase Crockford base32 ULID (section
11.6). It is never lowercased in an object path. `segId` is the keyed content
address of the segment (section 7.2), lowercase hex. `<aa>` is the first two
lowercase hex characters of `segId`, a fan-out prefix only and never a security
boundary. `shardId` is a zero-padded decimal ordinal of at least five digits, for
example `00000`.

`<formatVersion>` in the recovery path is the version string substituted
literally, including its `/` character, so `_RECOVERY/<formatVersion>/` is the
two-level prefix `_RECOVERY/downpipe/0.1.0/`. A reader enumerating versions lists
under `_RECOVERY/` with the `/` delimiter applied at `_RECOVERY/downpipe/`; the
segment that comes back is the whole `MAJOR.MINOR.PATCH`, here `0.1.0`, so what a
listing enumerates is format versions and not majors.

The `seg/` tree is shared per downpipe only. Two downpipes never share a `seg/`
object even on identical content (section 7.3). A reader never depends on
`index.json`; it discovers runs by listing `run/` and discovers an archive's
segments from the decrypted shard manifests.
## 4. Cryptographic construction overview

The downpipe envelope is a CNSA 2.0-grade construction built directly on the
primitives in `internal/crypto`; it is NOT age and is NOT interoperable with the
`age` tool. The tool does not invent a bespoke AEAD or a bespoke key-wrap in the
sense forbidden by D9: the symmetric layer is AES-256-GCM (NIST SP 800-38D)
applied in a standard STREAM; the asymmetric layer is a hybrid KEM whose combiner
mirrors the binding set of X-Wing (draft-connolly-cfrg-xwing-kem) generalised to
ML-KEM-1024 over HKDF-SHA-384; the signature is a hybrid of two NIST/FIPS schemes
with both halves required. These are assembled from the blessed allowlist
(CONTRIBUTING) and pinned byte-for-byte here, with a known-answer test vector for
the combiner (section 14.6).

A sealed unit is the downpipe STREAM payload of section 7.8: a 16-byte payload
nonce followed by AES-256-GCM chunks. Unlike the previous major there is no
per-unit recipient header on a `.seg` or a shard `.dpe`; the only object that
carries per-recipient wraps is the master capsule (section 5.4). Every other unit
is opened by re-deriving its 32-byte file key from the run master (sections 6.3,
7.4), which the holder of a recipient identity recovers once from the capsule.

Several things are wrapped or derived.

- The per-run master (32 random bytes) is wrapped to the run's recipient set by
  the hybrid KEM-DEM capsule (section 5.4). One wrap per recipient: a hybrid KEM
  ciphertext plus the master sealed under a DEM key derived from the KEM shared
  secret. Unwrapping any one wrap with the matching recipient identity yields the
  32-byte master.
- From the master, HKDF-SHA-384 derives the content-addressing key `CAK` (section
  7.2), the manifest subkey `MK` (section 6), and from `MK` the name-MAC key and
  the per-shard manifest-wrap key (section 11.7).
- Each `.seg` and each shard `.dpe` is sealed under a file key that is itself
  HKDF-SHA-384-derived from the master (sections 7.4, 6.3), so a reader re-derives
  every file key deterministically from the one recovered master and never
  unwraps a per-unit stanza.

The fixed primitives for `downpipe/0.1.0` are:

- Confidentiality KEM: hybrid X25519 + ML-KEM-1024 (FIPS 203). Component secrets
  are combined by the downpipe combiner of section 4.2 over HKDF-SHA-384. The
  hybrid KEM ciphertext is `ct_M || ct_X` (1568 + 32 = 1600 bytes).
- Symmetric AEAD: AES-256-GCM (FIPS 197 + SP 800-38D) in the downpipe STREAM
  (section 7.8).
- Signatures: hybrid Ed25519 + ML-DSA-87 (FIPS 204), both halves required, no
  downgrade (section 8). The hybrid signature is `edSig(64) || mldsaSig(4627) =
  4691 bytes`.
- KDF / MAC / hash: SHA-384 throughout. HKDF-SHA-384 for all key derivation,
  HMAC-SHA-384 for the keyed segment address, the keyed name MAC and the key
  commitment, and SHA-384 for content, segment, shard, record, recipient-set and
  Merkle hashes.
- Symmetric key and hash sizes: derived symmetric keys (file keys, the master, the
  capsule DEM key) are 32 bytes (AES-256); SHA-384 and HMAC-SHA-384 outputs are 48
  bytes; segId is 48 bytes; the STREAM payload nonce is 16 bytes; the AES-256-GCM
  tag is 16 bytes.

These are frozen for the major version; a new primitive requires a major bump
(section 13, D8 M9). There is no scrypt, no ChaCha20-Poly1305, no X25519-only wrap
and no SHA-256 in this major.

Implementation note on the ML-DSA dependency. The Go reference reader currently
takes ML-DSA-87 from the vendored `filippo.io/mldsa` module, pinned by hash in
`go.sum` to an untagged pseudo-version (there is no upstream tagged release yet).
The release pipeline vendors the pinned commit so a reader build does not depend on
the commit remaining reachable upstream; track upstream for a tagged release and
move to it when available. Run outside the Go standard-library FIPS boundary, the
vendored module's FIPS-140 pairwise consistency test on key generation and its
algorithm self-test are no-ops, so a key produced by a faulty RNG or CPU path is
not caught by a generation-time self-test. This does not weaken the ML-DSA-87
mathematics; the conformance vectors (section 14) and the post-generation
sign-then-verify use of the key are the practical consistency checks. A future move
to the standard-library `crypto/mldsa`, once it lands, restores the FIPS self-tests
and removes the untagged-dependency consideration.

### 4.1 X25519 and ML-KEM hardening (normative)

The X25519 half of the hybrid KEM MUST be performed with an implementation that
aborts on an all-zero (non-contributory) shared secret (RFC 7748). Both the
encapsulator and the decapsulator MUST abort if the X25519 exchange yields an
all-zero shared secret; Go's `crypto/ecdh` returns an error in exactly this case
and satisfies the requirement, and an independent implementation MUST replicate
the abort. A decapsulator MUST reject a hybrid ciphertext whose length is not
exactly 1600 bytes (`ct_M` 1568 || `ct_X` 32) before any decapsulation, and MUST
parse `ct_X` as a valid 32-byte X25519 public point (rejecting a malformed point).

The ML-KEM-1024 half uses the FIPS 203 implicit-rejection behaviour unchanged: a
tampered `ct_M` yields a deterministic pseudo-random `ss_M` rather than an error,
and the binding of the combiner (section 4.2) plus the AES-256-GCM authentication
of the DEM then reject the wrap. Recipient identities are addressed by the
fingerprint of section 7.6.1, not by a recipient string; there is no Bech32
`age1...` recipient and no recipient-string canonicalisation in this major. Every
equality comparison of key-derived material that a reader performs (the key
commitment of 8.4, the recipient-set hash of 7.6.1, a re-derived file key) MUST
use `crypto/subtle.ConstantTimeCompare` over the decoded bytes, never a string
compare.

### 4.2 Hybrid KEM combiner (normative)

The 32-byte hybrid shared secret is derived from the two component shared secrets,
binding the X25519 ephemeral share and the recipient X25519 public key so the
secret is tied to this encapsulation:

```
ss = HKDF-SHA-384(
        ikm  = ss_M || ss_X,
        salt = (empty),
        info = "downpipe/0.1.0 hybrid-kem" || 0x00 || ct_X || pk_X,
        L    = 32 )
```

where `ss_M` is the ML-KEM-1024 shared secret, `ss_X` is the X25519 shared
secret, `ct_X` is the 32-byte X25519 ephemeral public share (which is also the
trailing 32 bytes of the hybrid ciphertext), and `pk_X` is the recipient's static
32-byte X25519 public key. The hybrid ciphertext transmitted and stored is `ct_M
|| ct_X`. `ct_M` is NOT included in `info` because ML-KEM-1024's FO transform
already binds `ct_M` and the encapsulation key into `ss_M` under IND-CCA2 (the
same property X-Wing relies on to omit it).

This is the downpipe combiner. It mirrors X-Wing's bound value set (`ss_M, ss_X,
ct_X, pk_X`) but X-Wing is fixed to ML-KEM-768 with a SHA3-256 hash, whereas this
construction is ML-KEM-1024 over HKDF-SHA-384 with the label as HKDF `info`. It is
therefore NOT covered verbatim by the X-Wing / draft-ietf-hpke-pq security theorem
and is interoperable with neither X-Wing nor HPKE-PQ. A second implementer MUST
reproduce it byte-for-byte; the combiner output is pinned by a known-answer vector
(section 14.6) so the construction is byte-locked.
## 5. Root manifest (cleartext bootstrap)

`root.manifest.json` is the only cleartext manifest. It carries the minimum a
bucket-only reader needs to find and decrypt everything else, and nothing that
would hand a bucket-read adversary a reconnaissance dossier. Source selectors,
secret descriptors, key names, per-record sizes and KV metadata are NOT here;
they live encrypted in the shard manifests (section 6) and are bound by the
signature.

It is serialised as RFC 8785 JCS canonical JSON (section 11.1). The detached
signature in `root.manifest.json.sig` is over the exact stored bytes of this
file, and is the hybrid Ed25519 + ML-DSA-87 signature of section 8.1.

### 5.1 Cleartext fields

```jsonc
{
  "formatVersion": "downpipe/0.1.0",
  "runId": "01J9Z3K7M0QABCDEFGHJKMNPQR",
  "createdAt": "2026-06-06T12:07:33.000Z",
  "downpipeId": "dp_7f3a9c",              // opaque, the ONLY downpipe field in the clear

  "envelope": {
    "aead": "AES-256-GCM",
    "kem": "X25519+ML-KEM-1024",
    "sig": "Ed25519+ML-DSA-87",
    "kdf": "HKDF-SHA-384",
    "chunkSize": 65536,
    "codec": "none"                        // run-wide codec, section 5.2
  },

  "recipients": [                          // recipient PUBLIC keys, inline in the signed root
    { "fingerprint": "dpr1:…",             // section 7.6.1
      "role": "break-glass",
      "x25519": "…",                       // base64url no-pad, 32-byte X25519 public point
      "mlkem": "…" },                      // base64url no-pad, 1568-byte ML-KEM-1024 enc key
    { "fingerprint": "dpr1:…",
      "role": "operational",
      "x25519": "…", "mlkem": "…" }
  ],

  "masterCapsule": [                       // section 5.4, a BARE ARRAY of wraps, not an object
    { "fingerprint": "dpr1:…",             // section 7.6.1, the field is "fingerprint"
      "kemCiphertext": "…",                // base64url no-pad, 1600 bytes (ct_M||ct_X)
      "sealed": "…" }                      // base64url no-pad, STREAM-sealed 32-byte master
  ],

  "recipientSetHash": "8a4d…",             // top-level, lowercase hex, 96 chars (SHA-384), section 7.6.1
  "keyCommitment": "1f0c…",                // top-level, lowercase hex, 96 chars (SHA-384), section 8.4
  "breakGlassPresent": true,

  "shards": [
    { "id": "00000", "object": "manifest/00000.dpe",
      "sha384": "9b2c…" }                  // SHA-384 of the stored .dpe bytes, 96 hex chars
  ],
  "shardCount": 1,

  "declaredRecordCount": 9831242,
  "merkleRoot": "4af1…",                   // section 11.8, SHA-384, lowercase hex (96 chars)
  "freshness": { "prevRunId": "01J9Z2…", "runlogIndex": 4814 },

  "signingKeyFingerprint": "edmldsa1:Mxq8…" // a HINT only, section 8.3
}
```

### 5.2 Field rules

- `formatVersion` MUST be the byte string `downpipe/0.1.0`. A reader accepts exactly
  the `major.minor` it implements at any patch, refuses a well-formed version it does
  not implement with a clear message rather than guessing, and refuses a label outside
  the `downpipe/MAJOR.MINOR.PATCH` shape as malformed (section 13). The reader's patch
  tolerance is deliberately wider than this writer rule and no wider than section 13's
  shape: `docs/format/schema.json` pins the writer rule with `const`, so a conformant
  writer emits this exact byte string and nothing else.
- `runId` MUST be a canonical ULID per section 11.6 and MUST equal the `<runId>`
  in this object's path.
- `createdAt` is an RFC 3339 UTC timestamp with literal `Z` and exactly three
  fractional digits (section 11.5). It is emission-canonical and advisory;
  freshness ordering is by the signed RUNLOG (section 10), never by this field,
  so a reader MUST NOT make any decision from it.
- `downpipeId` scopes dedup and the `seg/` boundary (section 7.3). It is an
  opaque identifier and is the ONLY downpipe field carried in the clear; it is
  not, on its own, sensitive. The human name, the cadence and the selectors live
  encrypted in the shard preamble (section 6.1), never here.
- `envelope.aead` MUST be `AES-256-GCM`, `envelope.kem` MUST be
  `X25519+ML-KEM-1024`, `envelope.sig` MUST be `Ed25519+ML-DSA-87` and
  `envelope.kdf` MUST be `HKDF-SHA-384`. `chunkSize` MUST be `65536`. `codec` is
  the run-wide codec and is one of the closed lowercase set `{none, gzip}`
  (section 7.5); every record's `codec` MUST equal `envelope.codec`, so a run
  does not mix codecs and a reader MUST reject a run any of whose records' `codec`
  differs from `envelope.codec`. The envelope carries exactly these six fields and
  no others: `keyCommitment` and `recipientSetHash` are top-level fields (below),
  not nested under `envelope`, and there is no run-wide secrets-compression flag in
  the format at all. The secrets-no-compression rule is enforced through each
  `secrets` record's own `codec`, which MUST be `none` and which the reader checks
  (section 12.4, D8 M4).
- `recipients` is a top-level array listing each recipient as
  `{fingerprint, role, x25519, mlkem}`, carrying the recipient PUBLIC key material
  inline in the signed root: `x25519` is the base64url no-pad 32-byte X25519 public
  point and `mlkem` is the base64url no-pad 1568-byte ML-KEM-1024 encapsulation key,
  and `fingerprint` is the `dpr1:`-prefixed fingerprint of section 7.6.1 over those
  two keys. The private halves are never here (the break-glass private key is
  offline, section 7.6). A reader recomputes each `fingerprint` from the inline
  `x25519` and `mlkem` and rejects a mismatch. The set MUST include exactly one
  `break-glass` entry, and `breakGlassPresent` MUST be `true`. The set MAY
  additionally include at most one `operational` entry (the default posture); the
  break-glass-only posture omits it (section 1.1). The entries are listed
  break-glass first, then operational; this order is the recipient listing order,
  while the recipient-set hash of section 7.6.1 is order-independent (it sorts the
  recipient encodings by raw bytes). Each capsule wrap's `fingerprint` MUST be the
  `fingerprint` of one of these recipients and the wrap set MUST cover the recipient
  set, and a reader MUST reject a manifest where the recipient list and the capsule
  wrap set disagree (section 8.6). Each `fingerprint` mirrors the recovery sheet
  (section 9, D8 M5).
- `masterCapsule` is a top-level BARE ARRAY of wraps,
  `[ { fingerprint, kemCiphertext, sealed }, ... ]` (section 5.4), one wrap per
  recipient in canonical recipient order. The wrap selector field is `fingerprint`
  (the same `dpr1:` value as the matching `recipients[]` entry). `masterCapsule` is
  a plain array: it is NOT an enclosing object with a member array, NOT a base64url
  blob and NOT an age file.
- `recipientSetHash` is a top-level field (NOT nested under `envelope`): the
  recipient-set hash (section 7.6.1), lowercase hex of a 48-byte SHA-384 (96 hex
  chars). It binds the exact hybrid recipient public keys (both halves) of the
  run's recipient set into the signed root.
- `keyCommitment` is a top-level field (NOT nested under `envelope`): the
  key-commitment value (section 8.4), lowercase hex of a 48-byte HMAC-SHA-384 (96
  hex chars).
- `breakGlassPresent` MUST be `true`. The engine refuses any route whose
  recipient set lacks an attestably-offline recipient, for every source type, not
  only `secrets` (D5). A reader in verified mode refuses a manifest with
  `breakGlassPresent` other than `true` or with no `break-glass` recipient, and
  additionally enforces the capsule break-glass checks of section 8.6.
- `shards` lists each encrypted shard manifest `{id, object, sha384}` where
  `object` matches `manifest/<shardId>.dpe` and `sha384` is the lowercase hex
  SHA-384 of the stored `.dpe` bytes of that shard (96 hex chars). `shardCount`
  MUST equal the length of `shards`.
- `declaredRecordCount` is the count of records the run intends the reader to
  find across all shards, excluding vanished-mid-crawl records (section 12.5). It
  is a count field per section 11.3: a JSON number when it is at most 2^53 - 1,
  and a decimal string when it is larger; a reader MUST reject a number above
  2^53 - 1 and MUST reject a string form for an in-range value.
- `merkleRoot` is the RFC 6962 Merkle root over per-record hashes in canonical
  record order using SHA-384 (section 11.8), lowercase hex (96 chars).
- `freshness.prevRunId` is the previous run's `runId` for this downpipe, or the
  JSON null literal for the first run. `runlogIndex` is this run's append index in
  the RUNLOG (section 10).
- `signingKeyFingerprint` is a HINT and is NOT used to decide trust. It carries
  the `edmldsa1:` prefix of section 11.4. Verified restore checks the signature
  against the operator-supplied `--signer` full public key and hard-fails on
  disagreement (section 8.3).

### 5.3 What is NOT in the cleartext manifest

The cleartext root manifest MUST NOT contain: the source block (`source.type`,
`source.namespaceId`, `source.bucket`, `source.label` and the include and exclude
selectors), the crawl `window`, the `consistency` mode, the downpipe human `name`,
the `cadence`, secret descriptors, key names, per-record names, per-record sizes,
per-record hashes other than as aggregated into `merkleRoot`, or KV metadata. The
source block, the window, the consistency mode and the downpipe name and cadence
moved out of the root and now live in the ENCRYPTED shard preamble (section 6.1);
the per-record fields live in the encrypted record lines (section 6.2). All of it
is sealed under the manifest subkey and bound by the signature through each shard's
stored-byte hash (D3). The only downpipe-identifying field in the clear is the
opaque `downpipeId`. `plaintextSha384` and `keyNameHash` never appear as a
cleartext object name or a cleartext manifest field; they live only inside the
encrypted and signed region (D2). The cleartext manifest does NOT carry the
recovery-bundle hashes; those are bound under the signer through the per-run RUNLOG
entry only (section 9, section 10).

### 5.4 The master capsule

The master is generated fresh per run as 32 random bytes. The writer wraps it to
the run's recipient set by the hybrid KEM-DEM capsule, one wrap per recipient.
For each recipient, in canonical recipient order:

```
(ss, kemCt) = EncapsulateHybrid(recipientPublic)         // section 4, kemCt = ct_M(1568) || ct_X(32) = 1600 bytes
wrapKey     = HKDF-SHA-384(ikm = ss, salt = (empty),
                           info = "downpipe/0.1.0 capsule-dem", L = 32)
sealed      = STREAM-seal(fileKey = wrapKey, plaintext = master[32],
                          payloadNonce = fresh 16 random bytes,
                          aad = keyCommitment(master, runId))   // section 7.8, AAD per below
wrap        = { fingerprint, kemCiphertext = base64url(kemCt),
                sealed = base64url(sealed) }
```

The capsule is the JSON BARE ARRAY `[ wrap, ... ]` stored inline in the cleartext
root under `masterCapsule` (section 5.1); it is not wrapped in an enclosing object
and has no `wraps` member, and each wrap's selector field is `fingerprint`. It is
NOT an age file and cannot be opened by any third-party tool; in particular the
`age` tool cannot read it.

A bucket-only reader recovers the master by selecting the wrap whose
`fingerprint` matches a held identity, decapsulating `kemCiphertext` to
the hybrid shared secret `ss`, deriving `wrapKey`, and STREAM-opening `sealed`
with the same AAD to the 32-byte master. Because the master is recovered ONCE and
every other file key is derived from it (section 4), the capsule is the only place
a recipient identity is used. The reader then derives `CAK` and `MK` (section
11.7).

Key-commitment of the capsule (normative): the DEM (AES-256-GCM STREAM) is not
key-committing, so on the `--allow-unverified` path a bucket-write adversary who
can rewrite the capsule is not, by AEAD alone, bound to a single master. To bind
it independently of the signature, the writer MUST pass the run key commitment as
the AES-256-GCM additional data of every capsule chunk: the STREAM-seal of
`sealed` uses `aad = keyCommitment(master, runId)` (section 8.4) and the reader
MUST STREAM-open with the same AAD, so a swapped or forked capsule fails AEAD
authentication even in unverified mode. This makes OpenCapsule self-checking.

The master capsule's recipient set is bound into the signature through the signed
`recipients` set, the signed `recipientSetHash` (section 7.6.1, which the reader
recomputes over the operator-supplied recipient public keys) and the signed
`masterCapsule` bytes (section 8.2), so a substituted capsule with a different
recipient set fails verified restore.

The master capsule is the only sealed unit that carries per-recipient wraps and
has no object path. Its bytes are NOT byte-reproducible, even with a pinned X25519
ephemeral and payload nonce, because the ML-KEM-1024 encapsulation that produces
`ct_M` draws its own randomness and the reference implementation exposes no
caller-supplied-coins variant. The capsule, and therefore the root manifest that
embeds it and the detached signature over the root, are reader-authoritative in the
conformance corpus (section 14.1): a second implementation proves conformance by
recovering and verifying them, not by reproducing their bytes.
## 6. Shard manifests (encrypted)

Each shard manifest is a complete downpipe envelope file stored at
`run/<runId>/manifest/<shardId>.dpe`. Its plaintext payload, before sealing, is
newline-delimited JSON (NDJSON): one canonical JSON object per record (section
6.2), each object on its own line terminated by a single LF (0x0A), no trailing
blank line. The payload is sealed by STREAM-seal (section 7.8) under a file key
derived from `MK` as specified in section 6.3; there is NO recipient header on a
shard. Only a holder of the master (recovered from the capsule with a recipient
identity) can derive the shard file key and read the shard manifests.

The downpipe STREAM payload is the NDJSON bytes. Compression of the manifest
payload is allowed only as `gzip` and is governed by the determinism note of
section 7.5; the chosen manifest codec is recorded inside the manifest preamble
line (section 6.1), not in the cleartext root. A shard manifest is never
content-addressed and never shared across runs, so its non-deterministic gzip
bytes are not a cross-writer interop concern; the cleartext root pins each
shard's stored-byte SHA-384, which is what the signature covers.

### 6.1 The encrypted preamble line

The first NDJSON line of every shard is a kind-tagged preamble object, not a
record. It carries the reconnaissance metadata that was deliberately kept out of
the cleartext root (the downpipe name and cadence, the source block, the crawl
window and the consistency mode) plus the per-shard record count, all sealed under
the manifest subkey with the record lines and bound by the signature through the
shard's stored-byte hash:

```jsonc
{ "kind": "preamble", "formatVersion": "downpipe/0.1.0",
  "runId": "01J9Z3K7M0QABCDEFGHJKMNPQR", "shardId": "00000",
  "manifestCodec": "none",
  "downpipe": { "name": "uploads-hourly", "cadence": "0 * * * *" },
  "source": {
    "type": "r2", "bucket": "media-prod", "label": "media",
    "include": ["uploads/", "media/"], "exclude": ["uploads/tmp/"]
  },
  "window": { "start": "2026-06-06T11:00:00.000Z", "end": "2026-06-06T12:00:00.000Z" },
  "consistency": "crawl",
  "recordCountInShard": 50000 }
```

- `kind` MUST be `preamble`. `formatVersion`, `runId` and `shardId` MUST match the
  cleartext root and the object path; a reader rejects a preamble that disagrees.
- `manifestCodec` is `none` or `gzip` and describes the manifest payload codec for
  THIS shard. It is independent of `envelope.codec` (which constrains record
  payloads, not the manifest's own framing).
- `downpipe` carries the human `name` and the `cadence`. These are sensitive
  reconnaissance fields and live here, encrypted, not in the cleartext root (D3).
- `source` carries `type` and, where the source class has them, the optional
  `namespaceId`, `bucket`, `label` and the ordered `include` and `exclude`
  selectors (section 12); the optional members are omitted when empty. The whole
  source block moved out of the cleartext root into this encrypted preamble.
- `window` is the crawl window of the run, `{start, end}` as RFC 3339 UTC
  timestamps with milliseconds (section 11.5). It moved out of the cleartext root
  into this encrypted preamble.
- `consistency` records the source's consistency mode for the run (for example a
  live `crawl` for KV, which has no point-in-time snapshot, section 12.5). It moved
  out of the cleartext root into this encrypted preamble.
- `recordCountInShard` is the number of record lines that follow in this shard,
  excluding the preamble; a reader rejects a shard whose actual record-line count
  disagrees with it.

### 6.2 Record line shape

Each subsequent NDJSON line is one record object (D6). The ordered `segments`
list expresses a single segment, a multi-segment chain, or a packed share of a
segment.

A record carries flat source coordinates (`namespace` for a namespaced source like
KV, `bucket` for a bucketed source like R2) plus a per-source descriptor object that
reconstructs configuration on restore beyond the value bytes: `kv` `{metadata,
expiration}`, `r2` `{httpMetadata, customMetadata}`, `secrets` `{store, scope,
comment, worker, bindingVar}` (section 12.3), or `d1` `{format}`. The descriptor's
opaque metadata is carried as raw JSON the reader never interprets; it only restores
it. Exactly the descriptor matching `sourceType` is present. The record fields are
`kind`, `sourceType`, `namespace`/`bucket` (as applicable), `name`, `keyNameHash`,
`recordId`, `plaintextSize`, `plaintextSha384`, `recordHash`, `codec`, `segments`,
`recordSalt` (present only for `secrets`) and the matching descriptor object. The
source-native name (KV key, R2 object key, secret name) is the `name` field.

A record MAY additionally carry three OPTIONAL annotative fields, each omitted when
empty: `database` (a `d1` record only: the native database UUID
this backup is OF, where `name` carries only the binding name), `account` (an
API-discovery record: the Cloudflare account this backup is OF) and
`incompleteMarker` (this record's value is an incompleteness SENTINEL the writer
emitted in place of real bytes; the value is the marker kind, one of the closed set
`_truncated`, `_unavailable`, `_skipped`, `_pending`, `_refused`, `_vanished`). A
reader MUST accept a record carrying any of them and MAY surface them. None of the
three is an input to the record hash (section 6.5) or to any key derivation, so
their presence changes no recomputed root and no verification outcome.

```jsonc
{ "kind": "record",
  "sourceType": "kv",
  "namespace": "sessions",                // present for a namespaced source (KV)
  "name": "user:42",
  "keyNameHash": "ab39…",                 // keyed MAC, section 6.4, lowercase hex
  "recordId": "r000000000000042",         // r + 15 zero-padded digits, section 6.3
  "plaintextSize": 318,
  "plaintextSha384": "7c1e…",             // over the FULL reassembled value, lowercase hex
  "recordHash": "0d4a…",                  // section 6.5, the Merkle leaf preimage source
  "codec": "none",
  "segments": [
    { "object": "seg/ab/ab39c4…f0.seg", "chunkRange": [0, 1], "packed": null }
  ],
  "kv": { "metadata": { /* opaque JSON, restored verbatim */ },
          "expiration": 1717680000 }       // present for an expiring KV key, else 0/omitted
}
```

Packed record (shares one segment with others of the same downpipe):

```jsonc
{ "kind": "record", "sourceType": "kv", "namespace": "sessions",
  "name": "user:43", "keyNameHash": "…", "recordId": "r000000000000043",
  "plaintextSize": 12, "plaintextSha384": "…", "recordHash": "…", "codec": "none",
  "segments": [
    { "object": "seg/c2/c2aa…e1.seg", "chunkRange": [0, 1],
      "packed": { "offset": 318, "length": 12 } } ] }
```

Multi-segment chain (one large value across an ordered list of segments):

```jsonc
{ "kind": "record", "sourceType": "r2", "bucket": "media-prod",
  "name": "uploads/2026/big.tar", "keyNameHash": "…",
  "recordId": "r000000000000044",
  "plaintextSize": 5368709120, "plaintextSha384": "…", "recordHash": "…",
  "codec": "none",
  "segments": [
    { "object": "seg/0a/0a11…b2.seg", "chunkRange": [0, 16384], "packed": null },
    { "object": "seg/9f/9f22…c3.seg", "chunkRange": [0, 16384], "packed": null },
    { "object": "seg/5d/5d33…d4.seg", "chunkRange": [0, 12288], "packed": null } ] }
```

A `secrets` record additionally carries a per-record `recordSalt` (base64url
no-pad, 16 bytes, section 7.2 / 12.4); a non-secret record omits `recordSalt`.

### 6.3 Record line rules

- `recordId` is stable within a run and is the per-record identity referenced by
  the manifest. It is a per-run ordinal string `r` followed by 15 zero-padded
  decimal digits, assigned `0`, `1`, `2`, … in canonical record order (section
  11.8), which is defined independently of `recordId` itself (it is ascending by
  `(sourceType, name)`). Cross-record splicing and cross-segment reordering are
  caught by the layered binding of section 7.4 (the data-segment file key binds
  `segId`, the `segments` list and `recordHash` are signed, and the full-record
  `plaintextSha384` is a normative MUST).
- `sourceType` is one of the supported values in section 12.
- `name` is the source-native name (KV key, R2 object key, secret name). It is
  sensitive and lives only here.
- `keyNameHash` is the keyed name MAC of section 6.4, lowercase hex.
- `plaintextSize` is the byte length of the full reassembled value. It is a count
  field per section 11.3 (JSON number when at most 2^53 - 1, decimal string when
  larger).
- `plaintextSha384` is the lowercase hex SHA-384 over the FULL reassembled record
  value (after decrypt and, if `codec` is `gzip`, after decompression). The reader
  MUST verify this over the full record as a normative end-to-end check (D6). The
  reader verifies plaintext, never byte-reproduction of a compressed segment (D8
  M4).
- `recordHash` is the record hash of section 6.5. Note that `recordHash` binds
  `recordId`, `plaintextSha384`, `keyNameHash` and `plaintextSize` only;
  `recordSalt` is NOT an input to the record hash (section 6.5).
- `recordSalt` is 16 random bytes, base64url no-pad (22 characters), and is present
  ONLY on a `secrets` record. It is mixed into the segment address derivation AND
  the segment file-key derivation for `secrets` records (section 7.2 case 0x03,
  section 7.4), where it guarantees that identical secret values never collide on
  disk and that each secrets segment has a unique file key; a reader requires
  exactly 16 decoded bytes (reader.go) and otherwise errors. For a non-secret
  record `recordSalt` is OMITTED entirely (the field is `omitempty` and is not
  emitted): there is no all-zero placeholder value, and a reader never reads
  `recordSalt` for a non-secret record. Omitting it keeps a non-secret segment's
  address a function of content alone (a run-independent `addrInput`); whether the
  same content then yields the same `segId` across runs, and so whether cross-run
  dedup occurs, depends on the writer's master scope (section 7.3).
- `namespace` is present only for a namespaced source (for example KV) and `bucket`
  only for a bucketed source (for example R2); both are flat top-level coordinate
  fields, omitted otherwise.
- The per-source descriptor object carries the configuration restored beyond the
  bytes: `kv.expiration` is the KV key's expiry as a count field (section 11.3),
  present only on an expiring KV record; `kv.metadata`, `r2.httpMetadata` and
  `r2.customMetadata` are opaque JSON restored verbatim; `d1.format` records the dump
  format. Exactly the descriptor matching `sourceType` is present.
- `codec` is `none` or `gzip` and MUST equal both `envelope.codec` (section 5.2)
  and the codec used to produce the sealed bytes for this record; a reader rejects
  a record whose `codec` differs from `envelope.codec`. For `secrets`, `codec` MUST
  be `none`, which a reader enforces (D8 M4).
- `segments` is an ordered, non-empty list. Each entry is `{object, chunkRange,
  packed}` where `object` is the `seg/<aa>/<segId>.seg` path, `chunkRange` is the
  half-open downpipe STREAM chunk index range `[firstChunk, lastChunkExclusive)`
  this record occupies in that segment, and `packed` is either the JSON null
  literal (the record owns the decrypted stream of the listed chunks) or an object
  `{offset, length}` giving the record's byte offset and length within the
  decrypted concatenation of the listed chunks. The reader reassembles a record by
  decrypting the listed chunk ranges of each segment in order, concatenating, then
  for a packed record taking `[offset, offset+length)`. For a whole-segment entry
  `lastChunkExclusive` MUST equal the segment's true chunk count and the reader
  MUST verify the segment's downpipe STREAM terminates (last-chunk flag 0x01,
  section 7.8) exactly at `lastChunkExclusive`, erroring otherwise.
- The per-source descriptor is a nested object keyed by source type (`kv`, `r2`,
  `secrets` or `d1`, section 12); the flat `namespace`/`bucket` coordinates sit
  alongside it. The reader MUST treat any source-native metadata it restores as
  opaque and never act on its contents beyond restoring it.
- A vanished-mid-crawl record is NOT emitted as a record line in this format: a
  record observed to exist at crawl start but gone before its value could be sealed
  is simply excluded from the shard's record lines, from `declaredRecordCount` and
  from the readable-coverage denominator (section 12.5). The record line shape
  carries no `vanished` field; every emitted record line is a present, readable
  record with a non-empty `segments` list.

The shard file key is derived from the master through the manifest subkey `MK`;
there is no per-shard recipient stanza to unwrap:

```
fileKey = HKDF-SHA-384(ikm = MK, salt = runId-bytes,
                       info = "downpipe/0.1.0 manifest-wrap" || 0x00 || shardId-ascii, L = 32)
```

and the shard is STREAM-sealed under it (section 7.8). `MK = HKDF-SHA-384(ikm =
master, salt = runId-bytes, info = "downpipe/0.1.0 manifest-key")` (section 11.7).
`fileKey` is 32 bytes (AES-256).

### 6.4 Keyed name MAC

`keyNameHash = HMAC-SHA-384(K_name, sourceType || 0x00 || name)` where `K_name =
HKDF-SHA-384(ikm = MK, salt = runId-bytes, info = "downpipe/0.1.0 name-mac")`,
`name` is the UTF-8 source name, and the result is lowercase hex (96 chars).
`runId-bytes` is the 16-byte binary form of the ULID (section 11.6). This is a
keyed MAC, not a bare hash, so a bucket-read adversary cannot dictionary-confirm a
guessed name (D2). Producers MUST emit a `name` that is valid UTF-8; a writer MUST
reject a record whose name is not valid UTF-8 (the canonical-JSON layer must not
silently transcode it, section 11.1).

### 6.5 Record hash (Merkle leaf source)

`recordHash = SHA-384(domain || recordId-bytes || plaintextSha384-bytes ||
keyNameHash-bytes || plaintextSize-u64be)` where `domain` is the ASCII bytes
`downpipe/0.1.0 record-hash`, `recordId-bytes` is the 16 ASCII bytes of the
`recordId` field, `plaintextSha384-bytes` and `keyNameHash-bytes` are the 48 raw
bytes each (hex-decoded), and `plaintextSize-u64be` is the size as an unsigned
64-bit big-endian integer. The result is lowercase hex (96 chars). `recordSalt`
is not an input to the record hash. In verified mode the reader recomputes each
record's `recordHash` from its fields and constant-time-compares it to the
manifest's `recordHash` BEFORE building the Merkle tree, rejecting any record whose
recomputed hash disagrees (exit 2). The Merkle tree of section 11.8 is then built
over the `recordHash` values in canonical record order, and its root is the signed
`merkleRoot`. Because `recordHash` binds `plaintextSha384` and `keyNameHash`, the
signature transitively covers the integrity of every record's value and name (D4). The empty-value hash is the
SHA-384 of the empty string
`38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b`.
## 7. Data segments and the envelope

### 7.1 The `.seg` container

A `.seg` object is a downpipe envelope file: a 4-byte magic, a 1-byte container
version, then the downpipe STREAM payload (section 7.8). It is NOT an age file,
there is no age header and no age stanzas, and no third-party tool reads it; in
particular the `age` tool cannot open it. The container carries no recipient
header: the segment file key is derived from the run master (section 7.4), so a
reader needs only the recovered master, the segment's signed `segId` and its
`codec` to open it.

```
offset  bytes                         meaning
0x00    44 50 53 31                   magic "DPS1" (downpipe segment v1)
0x04    01                            container version 0x01
0x05    <16 bytes>                    STREAM payload nonce (section 7.8)
0x15    <chunk 0> <chunk 1> …         AES-256-GCM STREAM chunks (section 7.8)
```

The shard manifest container `.dpe` is byte-identical except the magic is `DPE1`
("DPS1" becomes "DPE1"). Neither container is an `.age` file. The byte layout of
the payload is pinned in section 7.8 with a worked hex example in section 7.9.

The address `segId` and the fan-out `<aa>` are computed from the plaintext
(section 7.2), not from the container bytes, so a segment's name is stable under
the per-file random payload nonce and under gzip.

The magic and version are container framing only and are NOT folded into any AEAD
additional data; the file key already binds `segId`, `codecId` and `chunkSize` by
derivation (section 7.4). A build MAY carry the magic and version as the AAD of
chunk 0 for defence in depth; the reference does not, and a second implementer
MUST match whichever the vectors pin.

### 7.2 Keyed addressing

`segId` is the keyed content address of the segment plaintext:

```
CAK   = HKDF-SHA-384(ikm = master, salt = downpipeId-utf8,
                     info = "downpipe/0.1.0 content-address", L = 32)
segId = HMAC-SHA-384(CAK, addrInput)    // 48 raw bytes; segIdHex is the lowercase hex object-name form
```

where `addrInput` depends on the source class and carries a one-byte domain
separator so the three classes never collide on one address.

Single-record non-secret segment (carries exactly one record's chunk range):
`addrInput = 0x01 || segmentPlaintext`. The segment plaintext is the exact bytes
sealed into this segment's STREAM payload (after any `gzip`, since that is what is
stored), so intra-downpipe dedup is by stored content (section 7.3).

Packed non-secret segment (carries several small records of one downpipe and one
trust origin): `addrInput = 0x02 || segmentPlaintext`. The packed segment's
plaintext is the deterministic concatenation of its members in canonical record
order (section 7.3, D8 M4).

Secrets segment (any `secrets` record): `addrInput = 0x03 || recordSalt-bytes ||
segmentPlaintext`, where `recordSalt-bytes` is the 16 raw bytes of the record's
`recordSalt`. A writer MUST pass a 16-byte `recordSalt`; a reader or writer MUST
treat any other length as an error, since the address concatenation is
unambiguous only at the fixed 16-byte salt width (the salt is not length-prefixed
in the address input). Because `recordSalt` is fresh random per secret record,
identical secret values never collide on disk and no dedup occurs for secrets
(D2).

`recordSalt` participates in the address ONLY for the secrets class (0x03). For
the non-secret classes (0x01, 0x02) the `addrInput` is a function of the plaintext
alone, so it is run-independent; whether the derived `segId` then repeats across
runs (and so whether cross-run dedup occurs) depends on the scope of `CAK`, and so
of the writer's `master` (section 7.3).

`CAK` is derived from the master, which is wrapped to the recipients only in the
master capsule (section 5.4), so the address is keyed: a bucket-read adversary
without a recipient identity cannot recover the master and therefore cannot
compute `segId` from a guessed plaintext, which closes the plaintext
content-addressing oracle (D2 B1).

### 7.3 Dedup scope and the `seg/` boundary

Dedup is intra-downpipe across that one downpipe's runs only, and never
cross-downpipe or cross-tenant (D2). The `seg/` namespace is logically scoped per
downpipe: an engine MUST NOT let two downpipes write or read the same `seg/`
object even on identical content, achieved by either a per-downpipe `seg/`
subtree or a per-downpipe destination, and the chosen boundary is recorded by the
engine and is outside the offline reader's trust (the reader only ever follows the
`object` paths named in a run's shard manifests).

Cross-run dedup is an OPTIONAL writer optimisation, not a format guarantee. Whether
an unchanged non-secret value reuses one stored segment across runs depends on the
scope of the writer's `master`, because `segId` and the non-secret file key are both
functions of `master` (sections 7.2, 7.4):

- A writer using a STABLE PER-DOWNPIPE master derives the same `CAK`, the same
  `segId` and the same non-secret file key for unchanged content across runs, so that
  content is sealed once and is openable by every run that references it: cross-run
  dedup holds. This is the per-downpipe-keyed model that resolves the cross-run-dedup
  versus per-run-key tension (D1, D2, B2).
- A writer using a FRESH PER-RUN master derives a different `CAK` (and so a different
  `segId` and file key) each run, so unchanged content is sealed afresh each run and
  cross-run dedup does NOT occur: each run stores a full snapshot. This trades the
  dedup saving for per-run key independence, since one run's master opens no other run.

The current reference engine (downpipe-engine) uses a fresh per-run master
(see the engine repository's `src/seal/runstate.ts`), so it is the snapshot case and does NOT perform
cross-run dedup. In BOTH cases dedup still holds WITHIN one run (identical content in a
run shares one segment), and for `secrets` there is no dedup at all (section 7.2 case
0x03). A reader is agnostic to the writer's choice: it follows the `object` paths named
in each run's shard manifests and MUST open both shared and unshared segments (the
section 14.2 vector `dedup-same-value-two-runs` pins the shared case).

A writer that compresses (run-wide `codec` is `gzip`) computes `segId` over the
compressed plaintext, which is not byte-deterministic across heterogeneous
implementations (section 7.5). Two different writers can therefore assign
different `segId` values to the same source value under gzip, so cross-writer
dedup interoperability is guaranteed only for `codec = none`. Within one writer
implementation gzip dedup still holds because that writer's compressed output is
stable for fixed inputs.

### 7.4 Per-segment file-key derivation and the AEAD-bound context

Each segment is sealed under its own 32-byte (AES-256) file key derived from the
committed master. The file key is NOT raw random; it is derived from the master
so that a reader can re-derive it deterministically and never unwraps any
per-unit stanza (the key-confusion defence reduces to the single key-commitment
check on the master, section 8.4 and D8 M1), and, for a writer using a stable
per-downpipe master, so that the same content yields a re-derivable key across
runs for dedup (section 7.3).

The derivation depends on the source class, because the non-secret classes are
content-addressed and run-independent while the secrets class is per-record and
never shared.

Non-secret single-record (0x01) and packed (0x02) segments:

```
fileKey = HKDF-SHA-384(
    ikm  = master,
    salt = zero-length salt,
    info = "downpipe/0.1.0 seg-key" || 0x00 || ctxNonSecret,
    L    = 32 )
```

`ctxNonSecret` is the canonical concatenation, each field length-prefixed by a
single unsigned byte giving the field's length in bytes followed by the field
bytes:

1. `segId-bytes`: the 48 raw bytes of `segId`.
2. `codecId`: one byte, `0x00` for `none`, `0x01` for `gzip`.
3. `chunkSize-u32be`: `65536` as a 4-byte big-endian integer.

The non-secret file key derivation takes no run, record or salt identity beyond
`master`; its inputs are `master`, `segId`, `codecId` and `chunkSize`. A writer using
a stable per-downpipe master therefore derives the same `fileKey` for the same content
in every run, so a shared dedup segment opens under the re-derived key of any run that
references it (section 7.3); a writer using a per-run master derives a per-run file key
and shares no segment across runs. In either case the section 8.4 re-derive-and-reject
defence holds for the run that wrote the segment, without falling back to trusting any
stanza.

Secrets segments (0x03):

```
fileKey = HKDF-SHA-384(
    ikm  = master,
    salt = runId-bytes (16 bytes),
    info = "downpipe/0.1.0 seg-key" || 0x00 || ctxSecret,
    L    = 32 )
```

`ctxSecret` is the canonical concatenation under the same single-byte
length-prefix rule:

1. `segId-bytes`: the 48 raw bytes of `segId`.
2. `recordId-bytes`: the 16 ASCII bytes of the owning record's `recordId`.
3. `recordSalt-bytes`: the 16 raw bytes of the record's `recordSalt`.
4. `codecId`: one byte, always `0x00` (secrets are never compressed, section
   12.4).
5. `chunkSize-u32be`: `65536` as a 4-byte big-endian integer.

Secrets segments are never shared across runs or records (a fresh `recordSalt`
gives each a unique `segId`), so binding `runId`, `recordId` and `recordSalt` into
the file key is safe and adds defence in depth.

Cross-segment reordering and truncation and splicing are all caught by these
layers together: the downpipe STREAM last-chunk flag and counter catch truncation
and reordering within a segment by failing authentication; the per-segment file
key binds `segId`, so a swapped or substituted segment body authenticates under
the wrong derived key and fails; the signed `segments` list and `recordHash`
catch a substituted `object` path or a reordered `segments` list; and the
per-record `plaintextSha384` over the full reassembled value catches any wrong,
reordered or spliced segment because the value changes. A reader MUST perform the
full-record `plaintextSha384` check, MUST recompute the run key commitment over
the recovered master and constant-time-compare it to the signed top-level
`keyCommitment` before trusting any derived key (section 8.4), MUST
re-derive each segment's file key from the committed master, and MUST verify, in
verified mode, that the `segments` list and `recordHash` are the signed ones (D6).
The old per-unit "unwrap the stanza and compare the file key" check is gone: there
are no per-unit stanzas, and the equivalent defence is the single key-commitment
check on the master plus deterministic re-derivation.

Note on packing: a packed segment has no single owning record, so its file key is
derived under the non-secret 0x02 path from `segId` alone (the content of the
concatenation). Each member is bound to the segment through the signed manifest
(each member's `segments[0].object` is the packed `segId`, each member's
`plaintextSha384` is checked over its own `[offset, offset+length)` slice, and
each member's `recordHash` is in `merkleRoot`). A writer MUST NOT pack records of
different trust origins into one segment (section 7.3, section 12.4), so a packed
segment never mixes secrets with non-secrets and never co-packs secrets at all.

### 7.5 Compression codec

`codec` is the closed lowercase set `{none, gzip}` (D8 M4) and is run-wide: a run
uses one codec for all its records (section 5.2). Compression is applied to the
plaintext before sealing. The reader's contract is decrypt then, if `codec` is
`gzip`, decompress, then check `plaintextSha384` over the decompressed bytes. The
reader MUST NOT require byte-reproduction of the compressed segment, because gzip
is not byte-deterministic across the Go and Workers runtimes (D8 M4). For the same
reason a `gzip` segment is NOT writer-authoritative in the conformance corpus: the
gzip vector pins the already-compressed segment bytes as a fixed input artefact
produced once by the reference generator, and only the reader outcome is asserted
(section 14.2). An independent WRITER is not required to reproduce gzip segment
bytes, and the writer gate asserts byte-equality only for `codec = none` segments
and for the non-payload bytes of the pinned vectors (the canonical JSON, the
detached hybrid signature, and the `.seg`/`.dpe` container framing of magic plus
version).

`codec` MUST be `none` for any `secrets` record (section 5.2), and the reader
rejects a `secrets` record whose `codec` is not `none`. There is no separate
run-wide secrets-compression flag in the envelope; the rule is carried entirely by
each secrets record's `codec`. The writer MUST NOT co-pack records of different
trust origins into one segment (section 7.3, D8 M4).

Where the manifest payload itself is gzipped (`manifestCodec` is `gzip`, section
6.1) the same non-determinism applies, but a shard manifest is content-addressed
by neither path and the signature binds its stored-byte hash, so it raises no
cross-writer interop concern.

### 7.6 Recipients

The run has a recipient set, carried only by the master capsule (section 5.4): a
`.seg` and a shard `.dpe` carry NO per-unit recipients and NO recipient stanzas.
The master capsule is wrapped to the run's recipient set in canonical recipient
order (break-glass first, then operational when present), and the capsule wrap
order MUST equal that order so the writer-authoritative byte check is
deterministic. The canonical archive's capsule wraps to two hybrid recipients:
the mandatory break-glass identity and an in-account operational identity. A
high-assurance downpipe MAY instead wrap the capsule to the break-glass identity
alone (section 1.1).

There is no `scrypt` passphrase recipient and no passphrase operational variant
in this major. Every recipient is a hybrid X25519 + ML-KEM-1024 identity. A run
that does not carry the mandatory break-glass recipient (every archive carries
it, per D5) is refused. The break-glass identity is the firewall: the in-account
operational key satisfies the break-glass requirement on nothing, and a manifest
that records only an in-account recipient is refused in verified mode (D5).

The writer can wrap the master to the break-glass recipient but can never unwrap
it: the running engine holds only the break-glass public hybrid key (the 32-byte
X25519 public point and the 1568-byte ML-KEM-1024 encapsulation key), so a live
Worker cannot recover the master through the break-glass path. Because every other
unit is opened only by deriving its file key from the master, an engine that
cannot recover the master through break-glass cannot read any past archive through
the break-glass path. This is what makes a destination-bucket-alone compromise
unable to yield plaintext; section 1.1 states precisely which compromise scenarios
this does and does not defend.

### 7.6.1 Recipient fingerprint and recipient-set hash

A recipient is identified by its fingerprint, carried in the manifest as the
`fingerprint` field of each `recipients[]` entry and each `masterCapsule[]` wrap:

```
fingerprint = "dpr1:" || lowercase_hex( SHA-384( pk_X25519(32) || ek_MLKEM1024(1568) ) )
```

where `pk_X25519` is the recipient's 32-byte X25519 public point and
`ek_MLKEM1024` is the recipient's 1568-byte ML-KEM-1024 encapsulation key. There
is no `x25519:`, `age1...` or Bech32 recipient string and no recipient-string
canonicalisation in this major. The fingerprint is a wrap selector and a
recovery-sheet label only; a forged fingerprint with a mismatched KEM ciphertext
simply fails the capsule DEM authentication, so the fingerprint is not itself a
security gate.

`recipientSetHash` binds the exact hybrid recipient public keys of the run into
the signed root, so an attacker who swaps or substitutes the capsule's recipient
set is caught when the reader checks the recomputed hash against the signed value
(section 8.6):

```
recipientSetHash = lowercase_hex( SHA-384( "downpipe/0.1.0 recipient-set" ||
                                           0x00 || rpk_sorted ) )
```

where each recipient contributes the byte string `pk_X25519(32) ||
ek_MLKEM1024(1568)` (1600 bytes), and `rpk_sorted` is the concatenation of those
1600-byte recipient encodings sorted ascending by their raw bytes (so the hash is
independent of listing order and of any encoding). Every wrap of a run's capsule
is to this same recipient set, so one `recipientSetHash` covers the whole run. The
signed root also carries each recipient's PUBLIC keys inline (`recipients[].x25519`
and `recipients[].mlkem`, section 5.1), so the reader can recompute each recipient
fingerprint and the recipient-set hash from the manifest itself, while the trust
anchor remains the operator-supplied recipient set. The reader recomputes
`recipientSetHash` over those operator-supplied recipient public keys,
constant-time-compares it to the signed top-level `recipientSetHash`, and
independently confirms that each capsule wrap's `fingerprint` is the fingerprint of
one of those supplied recipients (section 8.6).

### 7.7 (removed)

The age header byte layout that previously occupied this subsection is removed.
There is no age header, no age intro line, no age stanzas and no header MAC line
in this major; the container framing is now the 4-byte magic plus 1-byte version
of section 7.1. The subsection number is retained as reserved so the later
numbering is stable.

### 7.8 downpipe STREAM payload byte layout (pinned)

Immediately after the container magic and version (section 7.1), the payload
begins:

- A 16-byte payload nonce, generated fresh per sealed unit (per `.seg`, per
  `.dpe`, per capsule wrap), or pinned by the vector for writer-authoritative
  vectors (section 14.1).
- The per-file payload key is `payloadKey = HKDF-SHA-384(ikm = fileKey, salt = the
  16-byte payload nonce, info = "downpipe/0.1.0 payload", L = 32)`. Because the
  payload nonce is the HKDF salt, every sealed unit gets a fresh AES-256 key; the
  per-file chunk counter restarting at 0 is therefore the standard re-keyed-STREAM
  pattern, not nonce reuse.
- The STREAM body: AES-256-GCM over the plaintext in chunks of exactly 65536
  plaintext bytes, except the last chunk which may be shorter. Each chunk's nonce
  is 12 bytes: an 11-byte big-endian counter field followed by a 1-byte last-chunk
  flag that is 0x01 only for the final chunk and 0x00 otherwise. The counter
  field's low 8 bytes carry a uint64 chunk index starting at 0 and incrementing by
  1 per chunk; the top 3 bytes are reserved and MUST be zero. A real backup never
  approaches 2^64 chunks, let alone the 2^88 a full 11-byte counter could hold;
  the zero-fill of the top 3 bytes is part of the wire format and a second
  implementer MUST reproduce it. Each chunk ciphertext is its plaintext length
  plus a 16-byte GCM tag. The chunk AAD is empty for data and shard units; the
  capsule DEM uses the run key commitment as AAD (section 5.4).
- The last chunk MUST NOT be empty unless the entire payload is empty (the
  empty-value encoding, section 12.5: a single final chunk of zero plaintext bytes
  with flag 0x01). A reader MUST error if it reaches end of file without a valid
  final chunk (a flag-0x01 chunk that authenticates).

AES-256-GCM is not a committing AEAD; the security argument relies on the reader
deriving exactly one file key per unit (re-derived deterministically from the
committed master) and never searching a key space, so there is no key-confusion
oracle. The downpipe STREAM chunk index referenced by a record's `chunkRange` is
this chunk counter: chunk 0 is the first 65536 plaintext bytes, and `chunkRange =
[first, lastExclusive)` selects a contiguous run of chunks. For a record that owns
a whole segment the range is `[0, totalChunks)`.

### 7.9 Worked `.seg` hex example

This example is normative for byte layout and appears as a pinned positive vector
(section 14.2, vectors `seg-empty` and `seg-single-chunk`). All randomness is
pinned by the vector. The structure, with the actual hex provided in
`testdata/vectors/seg-single-chunk/`, is:

```
offset  bytes                                   meaning
0x00    44 50 53 31                             magic "DPS1"
0x04    01                                      container version 0x01
0x05    <16 raw bytes>                          STREAM payload nonce
0x15    <ciphertext chunk 0: len(pt)+16 bytes>  AES-256-GCM, nonce 00..00||01
```

The vector directory pins the master (from which the file key is derived per
section 7.4, so it is fixed once the master and plaintext are fixed) and the
16-byte payload nonce, and it pins the plaintext, so the entire `.seg` byte string
is reproducible and the writer is authoritative for it (D8 M10, section 14.1).
There is no X25519 ephemeral on a `.seg` because segments carry no recipients; the
only ephemerals pinned by a vector are the capsule's, under the synthetic
`masterCapsule` key.
## 8. Signatures, operator-pinned verification and key commitment

### 8.1 Signature object

`run/<runId>/root.manifest.json.sig` is a detached HYBRID signature over the
exact stored bytes of `run/<runId>/root.manifest.json`. The signature is a hybrid
of Ed25519 and ML-DSA-87 (FIPS 204) with both halves required and no downgrade.
The signature file contains `edSig(64) || mldsaSig(4627)` (4691 raw bytes)
encoded as base64url no-pad, with no other framing. The same hybrid signature
scheme signs the RUNLOG (section 10) and the restore receipt (section 8.5).

### 8.2 What the signature covers

Because the cleartext root manifest carries `shards[].sha384` (each encrypted
shard's stored-byte hash), the `recipients` set (each recipient's inline `x25519`
and `mlkem` public keys, `fingerprint` and `role`), the top-level
`recipientSetHash`, the `masterCapsule` bare array (each wrap's `fingerprint`,
`kemCiphertext` and `sealed`), the envelope parameters (including `envelope.kem`,
`envelope.sig` and `envelope.kdf`), the top-level `keyCommitment`, `merkleRoot`,
`declaredRecordCount`, `runId` and `formatVersion`,
a single hybrid signature over the canonical root bytes transitively covers: each
shard's content (via its hash), the recipient set (via the listed fingerprints and
the recipient-set hash), the master capsule, the envelope and codec parameters,
the Merkle root over every record hash, and the declared count, all bound to
`runId` and `formatVersion` (D4). A change to any sealed shard, any recipient, the
master capsule, the envelope, the codec, the declared count or the Merkle root
changes the root bytes and breaks the signature.

The transitive coverage is only real if the reader recomputes the covered values
and compares them; section 8.3 makes those recomputations normative reader MUSTs.

### 8.3 Non-advisory completeness and operator-pinned signer

AEAD decryption of present bytes is never gated on the signature: a lost signing
key never blocks reading bytes that are physically present and AEAD-authenticated.
This keeps a key-management slip from becoming total data loss.

Verified and complete restore is the DEFAULT mode, and it REQUIRES a valid
manifest signature over the canonical stored bytes, verified against an
OPERATOR-SUPPLIED FULL signer public key passed as `--signer <hybrid-public-key>`
or read from the recovery sheet (D4). The reader cannot reconstruct a public key
from a fingerprint, so it verifies both halves of the hybrid signature against the
operator-supplied Ed25519 and ML-DSA-87 public keys directly. The verifier MUST
NOT trust the manifest's own `signingKeyFingerprint`; that field is a hint only. If
the operator-supplied key disagrees with the key that actually produced a valid
signature, the reader hard-fails. A missing signature, an invalid signature, a
signature that verifies under only one of the two halves, or a signature by a
signer other than the operator-supplied one is labelled `completeness UNVERIFIED`,
the reader exits non-zero, and presenting the archive requires an explicit
`--allow-unverified` acknowledgement (section 8.5 records which path was taken).
This closes the advisory-signature completeness collapse (D4, B3).

In verified mode the reader MUST additionally perform each of these recomputations
and constant-time comparisons, and MUST fail verified restore (the stated exit
code) on any mismatch:

1. Recompute SHA-384 over each shard's stored `.dpe` bytes and compare to that
   shard's signed `shards[].sha384`. A mismatch is exit 2.
2. Recompute `merkleRoot` (RFC 6962 over SHA-384, section 11.8) over the decrypted
   `recordHash` set in canonical record order and compare to the signed
   `merkleRoot`. A mismatch is exit 2.
3. Recompute `keyCommitment` from the recovered master (section 8.4), HMAC-SHA-384,
   and compare to the signed top-level `keyCommitment`. A mismatch is exit 2.
4. Recompute `recipientSetHash` (SHA-384 over the sorted 1600-byte hybrid recipient
   encodings, section 7.6.1) over the recipient public keys the operator supplied,
   confirm every capsule wrap's `fingerprint` is the fingerprint of one of those
   recipients (section 8.6), and compare to the signed top-level
   `recipientSetHash`. A mismatch is exit 2.
5. Verify the RUNLOG and the recovery-bundle binding per section 8.7.
6. Verify that every readable record's reassembled value matches its signed
   `plaintextSha384` (section 6.3). A mismatch is exit 4.
7. Verify coverage against `declaredRecordCount` (section 12.5). Coverage below
   the declared count is exit 3.

A reader that trusts the signed fields without these recomputations obtains no
transitive guarantee and is not conformant.

### 8.4 Key commitment

The capsule DEM is AES-256-GCM, which is not key-committing on its own, so a
rewritten capsule could in principle decrypt to two different masters under two
wraps. To prevent key confusion across the recipient set (D8 M1), the run carries
a committing value:

```
keyCommitment = lowercase_hex( HMAC-SHA-384( key = master, msg = "downpipe/0.1.0 key-commit" || runId-bytes ) )
```

The reader, after recovering the master from any wrap, recomputes `keyCommitment`
and constant-time-compares it against the signed top-level `keyCommitment` (section
8.3 item 3). Because `keyCommitment` is a deterministic function of the single
master and is signed, every recipient path that yields a valid master yields the
same commitment, so a recipient-specific master substitution is detected in
verified mode.

Additionally (section 5.4), `keyCommitment(master, runId)` is the AES-256-GCM
additional data of the capsule DEM, so a swapped or forked capsule fails AEAD
authentication even on the `--allow-unverified` path; OpenCapsule MUST open with
this AAD.

Key commitment commits the master, not each derived file key. The per-file-key
layer is protected because every file key is a deterministic HKDF-SHA-384 function
of that committed master (sections 6.3 and 7.4): after recovering and committing
the master, the reader re-derives each `.seg` and shard file key from that master,
so a per-recipient or per-file file-key substitution cannot occur without changing
the master and failing the commitment. This holds independently of the plaintext
check, so it is decided before the full-record `plaintextSha384` is computed. There
are no per-unit stanzas to compare against; this is the post-PQ replacement for the
old per-unit unwrap-and-compare-file-key MUST.

### 8.5 Restore receipt

The restore receipt is a normative, machine-parseable, signed artefact and is the
load-bearing fails-loudly UX (D8 MISSED). The offline tool emits it on every
restore and verify. It is canonical JSON (section 11.1) and is signed by the
operator's restore-session key (the hybrid scheme of section 8.1) if one is
supplied, otherwise emitted unsigned with `signed: false`.

```jsonc
{ "kind": "downpipe-restore-receipt", "formatVersion": "downpipe/0.1.0",
  "runId": "01J9Z3K7M0QABCDEFGHJKMNPQR", "downpipeId": "dp_7f3a9c",
  "startedAt": "2026-06-06T13:00:00.000Z", "finishedAt": "2026-06-06T13:04:11.000Z",
  "mode": "verified",                         // "verified" | "allow-unverified"
  "signerExpected": "edmldsa1:Mxq8…",
  "signatureResult": "valid",                 // "valid" | "invalid" | "absent" | "wrong-signer"
  "completeness": "complete",                 // "complete" | "UNVERIFIED" | "incomplete"
  "breakGlassVerified": true,                 // section 8.6
  "declaredRecordCount": 9831242,
  "recordsVerified": 9831242,
  "recordsRestored": 9831242,
  "vanishedExcluded": 17,                     // OPTIONAL; ABSENT when nothing measured it (section 12.5). The offline
                                              // reader cannot derive it, so only a caller holding the figure supplies it
  "danglingSegments": 0,                      // OPTIONAL; ABSENT when the pass read no seg/ object. A deep verify or an
                                              // applied restore measures it, so a 0 from those means it looked (section 10.1)
  "incompleteMarkers": 2,                     // OPTIONAL; omitted when 0. Count of restored records whose value is an
                                              // incompleteness-marker sentinel (section 12.1), NOT the source's live data
  "incompleteMarkerKinds": { "_skipped": 2 }, // OPTIONAL; omitted when empty. Per-kind tally of incompleteMarkers
  "freshness": { "runlogIndex": 4814, "isLatestForDownpipe": true,
                 "rollbackWarning": false, "checked": true, "minIndexPinned": 4814 },
                                              // checked is false when the freshness check could not RUN at all (the RUNLOG
                                              // was absent, unreadable, unparseable or empty, its signature did not verify,
                                              // the run was not in it, or its entry disagreed with the signed root on the
                                              // run's downpipe, index or prevRunId). rollbackWarning is then also true: a
                                              // check that could not run did not pass
  "recoveryBundleVerified": true,             // section 8.7
  "target": { "type": "file", "valueVerified": true },  // "file" | "env" | "discard" | "verify" (the offline tool's sinks)
  "exitCode": 0,
  "signed": true,
  "receiptSignature": "…"                      // base64url no-pad hybrid signature over the canonical receipt minus this field
}
```

Exit codes are normative: `0` verified and complete; `2` completeness UNVERIFIED
(missing, invalid, single-half, or wrong-signer signature, or a failed section 8.3
recomputation other than coverage or plaintext, or a failed break-glass check of
section 8.6, or a failed recovery-bundle check of section 8.7) and
`--allow-unverified` was not given; `3` incomplete coverage below
`declaredRecordCount`; `4` a per-record `plaintextSha384` mismatch; `5` a freshness
problem (a non-latest run, a section 10 chain anomaly, a below-pin index, or an
absent or truncated RUNLOG) was detected and not acknowledged; `6` a usage or input
error. When `--allow-unverified` is given the
tool proceeds, sets `mode` to `allow-unverified`, and still records the true
`signatureResult`, `completeness`, `breakGlassVerified` and `recoveryBundleVerified`
so the receipt never launders an unverified restore as verified. Code 5 takes one of
two acknowledgements, and neither suppresses code 2, 3 or 4. `--allow-stale`
acknowledges the run's AGE and covers exactly the two findings a RUNLOG that verified
against `--signer` and is internally consistent can report: a non-latest run and a
below-pin index. `--allow-unverified-runlog` acknowledges the RUNLOG itself being
untrustworthy (absent, truncated, unparseable, empty, not carrying the run, failing its
signature, disagreeing with the signed root, or internally contradictory) and subsumes
`--allow-stale`, because a log that cannot be trusted reports no age. `--allow-unverified`
subsumes both.

A destination read failure -- a network or DNS failure, a refused connection, or the
destination returning a non-2xx status (403/404/5xx) before any bytes came back -- is
kept apart from code 2 by a CLI-level exit code, `11`, outside this normative reader
set (the same footing as the advisory codes above): the bytes were never RETRIEVED, so
nothing is yet known about the archive's integrity, which is a different condition
from code 2's "bytes were retrieved and failed to verify". A read failure the reader
cannot positively attribute to the destination (a local filesystem error on `--archive`,
or any error it does not otherwise recognise) is NOT reclassified to `11`; it keeps
whichever code the failing check already carries (most often `2`), the deliberately
safer default, since an unclassified failure is closer in kind to a tamper finding than
to a resolvable access problem. Code `11` never appears in `exitCode` above: it can only
occur before a run is opened far enough to produce a receipt at all.

`incompleteMarkers` and `incompleteMarkerKinds` are OPTIONAL and additive. They are
present only when the restore (or a deep verify) surfaced at least one incompleteness
marker: a record whose value is a sentinel placeholder because the source was only
partially available when the run was sealed (section 12.1), NOT the source's live
data. `incompleteMarkers` is the count and `incompleteMarkerKinds` its per-kind tally
(the kind is a fixed sentinel label, never a record name, key or value). They let a
machine consumer of the receipt distinguish a fully-real restore from one padded with
marker stubs. They do NOT change `exitCode`, which continues to carry the verification
outcome above (the CLI additionally signals the marker case with a distinct advisory
exit code, outside this normative reader set). Both fields are omitted when zero or
empty, so a clean restore's receipt is byte-for-byte identical to one produced before
these fields existed and existing receipt verification is unaffected.

### 8.6 Capsule break-glass and recipient-set enforcement

The break-glass requirement (D5) is the moat: recovery with only the offline key.
In the previous major every sealed unit carried recipient stanzas that a
bucket-write adversary could strip, so the reader had to re-check stanzas per unit.
In this major a `.seg` and a shard `.dpe` carry NO recipients; the only object that
carries recipient wraps is the master capsule (section 5.4), and every other unit
is openable only by a file key derived from the master. Stripping break-glass from
a unit is therefore impossible, because there is nothing per-unit to strip. The
break-glass property reduces to a property of the capsule, which is fully covered by
the signature.

In verified mode the reader MUST:

1. Confirm `breakGlassPresent` is `true` and that the signed `recipients` set
   contains exactly one `break-glass` entry.
2. Confirm the `masterCapsule[]` wraps cover the signed recipient set: every wrap
   addresses a listed recipient and the set of distinct wrap `fingerprint` values
   equals the set of `recipients[].fingerprint` (so no recipient is dropped and no
   wrap targets an unlisted recipient), and that each is the `dpr1:` fingerprint of a recipient
   public key the operator supplied (constant-time compare over the decoded
   fingerprint bytes).
3. Recompute `recipientSetHash` (section 7.6.1) over the operator-supplied recipient
   public keys and constant-time-compare to the signed top-level `recipientSetHash`;
   a mismatch fails verified restore (exit 2) and sets `breakGlassVerified: false`.
4. Confirm the signed `recipients` carries a `break-glass` entry whose fingerprint
   matches the operator's break-glass recipient public key (constant-time compare
   over the decoded 1600-byte hybrid key, `pk_X25519(32) || ek_MLKEM1024(1568)`);
   absence or mismatch fails verified restore (exit 2) and sets
   `breakGlassVerified: false`.

This makes the break-glass property a signed, capsule-bound property rather than a
per-unit byte check: a run is not complete unless the signed capsule actually wraps
the master to the operator's break-glass recipient and the recipient set recomputes.

Because the engine holds only the break-glass public hybrid key and cannot itself
recover the master through break-glass (section 7.6), the structural check above is
the strongest test the in-account engine can perform. A full proof that the
break-glass private key opens the archive is an OFFLINE drill: the offline holder
periodically recovers the master from a sampled capsule with the break-glass
identity using a conformant downpipe reader and records the outcome in the drill's
receipt. An operational-path verify does NOT prove break-glass recoverability and a
receipt from one MUST NOT claim it does; `breakGlassVerified` reflects only the
structural checks above unless the run was performed with the break-glass identity.
The conformance vectors replace the old `stripped-break-glass-stanza` vector with
`dropped-break-glass-wrap` and `forged-capsule-wrap` (section 14.3).

### 8.7 Recovery-bundle and freshness binding on read

The recovery bundle (section 9) and the freshness anchor (section 10) are bound
under the operator's signer through the RUNLOG, but that binding protects a
recoverer only if the reader verifies it. In verified mode the reader MUST:

1. Verify `_RECOVERY/RUNLOG.sig` as a valid hybrid signature (section 8.1) over the
   exact stored `_RECOVERY/RUNLOG` bytes, against the operator-supplied `--signer`
   full signer public key. An absent or truncated RUNLOG, or a RUNLOG signature that
   is invalid, single-half, or by a different signer, fails with exit 5 unless
   `--allow-unverified-runlog` (or `--allow-unverified`) is given. `--allow-stale` does
   NOT cover this: no age was measured, so there is no age to acknowledge.
2. Locate the RUNLOG entry whose `runId` equals the run being restored and confirm
   its `index` and `prevRunId` agree with the root manifest's
   `freshness.runlogIndex` and `freshness.prevRunId`.
3. Determine whether the run is the latest for its downpipe, and detect the chain
   anomalies of section 10: a duplicated `index`, a break in the
   per-downpipe `prevRunId` linearity, or a dangling or forked `prevRunId`. An
   `index` gap is NOT an anomaly (indices are account-globally allocated and a
   failed run consumes one without appending an entry, section 10). A non-latest
   run or a maximum `index` below an operator-supplied minimum
   (`--min-runlog-index`, section 10) exits 5 unless `--allow-stale`. A detected chain
   anomaly exits 5 unless `--allow-unverified-runlog`: the RUNLOG verified, so the check
   ran, but a log that contradicts itself was rewritten or hand-assembled and reports no
   trustworthy age. A disagreement found in step 2 takes `--allow-unverified-runlog` for
   the same reason. The receipt records `isLatestForDownpipe`, `rollbackWarning` and
   `minIndexPinned`.
4. When the recoverer relies on the bundled `FORMAT.md`, `RECOVER.md` or the
   vendored audited reader (rather than an independently trusted reader and spec),
   recompute their SHA-384 against the bundle's `SHA384SUMS` (section 9) and
   confirm `SHA384SUMS` itself matches the value the operator pinned out of band on
   the recovery sheet; a mismatch fails verified restore (exit 2) and sets
   `recoveryBundleVerified: false`. The RUNLOG entry carries no `recoveryBundle`
   field (section 10), so this check is against the bundle's own `SHA384SUMS` and
   the out-of-band pin, not against a RUNLOG entry field. The second independent
   reader is this vendored, audited reader of the downpipe format, not any
   third-party tool. A recoverer that brings its own trusted reader and spec MAY
   skip this comparison and records `recoveryBundleVerified` accordingly, but MUST
   still verify the RUNLOG signature of item 1.

### 8.8 Keyless attestation

`attest` is a distinct, non-normative-restore check: it verifies the root
signature, the structural completeness of the signed root (every listed shard
present with bytes matching the signed SHA-384, and the shard count consistent)
and, on request, the RUNLOG, all WITHOUT the break-glass identity. It never
unwraps the master capsule, opens a shard manifest or decrypts a record, so it
needs no recipient key and materialises no plaintext. `--signer` is optional.

With `--signer`, the root and RUNLOG signatures are the same cryptographic
verification section 8.3 and 8.7 describe, and `--min-runlog-index` is the same
out-of-band anti-rollback pin (section 10): a RUNLOG whose maximum index falls
below the pin fails (`RunlogVerified: false`), exactly as verify/restore already
enforce. This is a full, cryptographically-anchored rollback check.

Without `--signer` the attestation is fully keyless. It reports the root
signature's presence and structural shape only (`unchecked`, never `valid`), so a
caller cannot mistake a structural pass for a cryptographic one. The RUNLOG check
without a signer is a STRUCTURAL check, not a cryptographic one, because nothing
in this mode anchors the RUNLOG's bytes:

- With no `--min-runlog-index`, a keyless attestation confirms only that the
  requested run is PRESENT in the RUNLOG. It does NOT check freshness. A RUNLOG
  that has been rolled back to an older, wholesale validly-signed state (section
  10's tail-rollback case) still lists the run and passes.
- With `--min-runlog-index`, a keyless attestation additionally compares the
  RUNLOG's own claimed maximum index against the pin, the same comparison the
  signed path makes. This catches an accidentally stale or naively/wholesale
  replayed bucket (the RUNLOG bytes genuinely reflect an older state and nobody
  edited them). It does NOT catch a targeted bucket-write adversary who, having
  already rolled the archive back, also edits the unsigned RUNLOG's plaintext
  index to claim a higher one: nothing in keyless mode would detect that edit.
  A recoverer who needs the pin to hold against that adversary MUST supply
  `--signer`.

A tampered shard, a missing shard, a stripped break-glass recipient (section
8.6) or a malformed/absent root signature fails a keyless attestation
regardless of a signer or a pin, because those checks are self-consistency
checks over the signed root's own claimed values, not checks that need an
external anchor.

## 9. Recovery bundle and versioning of the bundle

On every run the writer refreshes `_RECOVERY/downpipe/0.1.0/` so the bucket carries
signed, versioned recovery instructions (D8 M6). The bundle is versioned by
`formatVersion` (the path substitutes the version literally, including its `/`,
section 3), so a bucket that has carried more than one format version keeps each
version's bundle. The compatibility unit while the major is 0 is the minor
(section 13), so that is one bundle per minor line, not one per major.

- `_RECOVERY/downpipe/0.1.0/FORMAT.md`: a versioned pointer for the format in use. It
  names the format version and states that the authoritative specification and the
  normative conformance vectors are the open-source MIT downpipe project. It is a
  pointer, not a verbatim copy of this specification: by F16 the full spec and the
  reader source are deliberately kept out of the writer's bundle to stay within the
  Worker module-size budget.
- `_RECOVERY/downpipe/0.1.0/RECOVER.md`: instructions to recover using only the
  bucket bytes, the offline break-glass key and a conformant reader. Because the
  downpipe envelope is NOT an age file and no third-party tool reads it (sections 4,
  7.1), there is no external command line that unwraps a `.seg`; recovery is
  performed by a conformant reader of this format, which is the open-source MIT
  downpipe tool (kept by the recoverer) or a clean-room re-implementation from this
  spec and the vectors. The reader recovers the master from the capsule with the
  break-glass identity, derives every file key and reads and verifies the archive
  end to end. `RECOVER.md` states explicitly that an unverified byte-only recovery
  (the `--allow-unverified` path) recovers bytes but is not verified restore
  (section 1).
- `_RECOVERY/downpipe/0.1.0/SHA384SUMS`: the lowercase hex SHA-384 of every file in
  the versioned bundle, with a detached hybrid signature `SHA384SUMS.sig` over it,
  so a recoverer can confirm the `FORMAT.md` and `RECOVER.md` instructions were not
  altered.

The integrity of `FORMAT.md` and `RECOVER.md` is anchored by the bundle's own
`SHA384SUMS`, which lists the lowercase hex SHA-384 of every file in the versioned
bundle. Neither the root manifest nor the per-run RUNLOG entry carries a
`recoveryBundle` field: the root manifest carries no recovery-bundle hashes
(section 5.3) and the RUNLOG entry carries exactly the seven fields of section 10.
A recoverer confirms the bundle was not altered by verifying `SHA384SUMS.sig`
against the operator-pinned signer, or by recomputing `SHA384SUMS` and comparing it
to the value pinned out of band on the recovery sheet.

Writing the recovery bundle is a precondition of the first segment write of a run:
the engine MUST write and read back `_RECOVERY/downpipe/0.1.0/` and confirm the
`SHA384SUMS` matches the bundle it is about to publish before sealing any `seg/`
object, so a bucket never contains data without its signed recovery instructions.

The bucket then carries the data, the encrypted manifests, the per-recipient master
capsule, the freshness anchor and the signed recovery bundle. Reading it needs a
conformant reader of the downpipe `.dpe`/`.seg` format, which is the open-source MIT
downpipe project (the offline tool, this specification and the conformance vectors),
kept by the recoverer or re-implemented clean-room; no vendor and no Cloudflare are
involved. Shipping the verbatim specification and a buildable reader INSIDE the
bundle, so the bucket is self-sufficient with no external copy at all, is a planned
strengthening of this section, gated on a per-writer embed strategy.

## 10. Freshness anchor

A stale but validly-signed run MUST NOT be silently restored as current (D8 M2).
The writer maintains `_RECOVERY/RUNLOG`, an append-only, signed log of run headers,
one canonical JSON object per line terminated by LF:

```jsonc
{ "index": 4814, "runId": "01J9Z3K7M0QABCDEFGHJKMNPQR", "downpipeId": "dp_7f3a9c",
  "time": "2026-06-06T12:07:33.000Z", "recordCount": 9831242,
  "prevRunId": "01J9Z2…", "status": "active" }
```

A RUNLOG entry carries exactly these seven fields: `index`, `runId`, `downpipeId`,
`time`, `recordCount`, `prevRunId` (the JSON null literal for a downpipe's first
run) and `status`. `time` is an RFC 3339 UTC timestamp (section 11.5) and
`recordCount` is a count field (section 11.3). The entry carries no `recoveryBundle`
object; the recovery bundle's integrity is anchored by its own `SHA384SUMS` within
the versioned bundle (section 9), not by a per-entry RUNLOG field.

`_RECOVERY/RUNLOG.sig` is a detached hybrid Ed25519 + ML-DSA-87 signature
(`edSig(64) || mldsaSig(4627)` = 4691 raw bytes, base64url no-pad, section 8.1) over
the exact stored RUNLOG bytes, by the same signer as the root manifests. Both halves
are required; a RUNLOG signature that verifies under only one half is invalid. The
whole-document signature is the document-integrity anchor: any edit to the stored
RUNLOG bytes, anywhere in the log, invalidates it.

`index` values are allocated from one account-global counter shared by every
downpipe of the account, and an entry is appended only when a run finalises
successfully: a failed or abandoned run consumes its allocated `index` without ever
appending an entry. `index` values therefore MAY be non-contiguous, both within a
downpipe and across the document. A downpipe interleaved with another holds a
strided subsequence of the account counter (say 1, 3, 5), and a failed run leaves a
hole in the account-wide sequence; an `index` gap is NOT an anomaly. Nor is LINE
ORDER: an entry is appended when its run FINALISES, and concurrent runs finalise
out of allocation order as a matter of course, so a conformant log's lines MAY be
interleaved relative to `index` (a writer MAY additionally canonicalise the line
order to ascending `index` on a rewrite; readers MUST NOT rely on either order).
What the document MUST satisfy is: every entry carries a UNIQUE `index` (the
account-global counter never reissues one), and it chains each downpipe's runs
through `prevRunId` per the linearity rule below, evaluated in ascending `index`
order. The root
manifest's `freshness.runlogIndex` and `freshness.prevRunId` MUST agree with the
RUNLOG entry of the same `runId`. `status` is `active` for a live run and
`superseded` for a run whose `run/<runId>/` tree has been pruned (section 10.1).

A reader in verified mode MUST consult the RUNLOG (section 8.7) and MUST detect
these chain anomalies:

1. Duplicated `index`: two entries carrying the same `index`. The account-global
   counter never reissues an index, so a duplicate means the log was corrupted or
   hand-assembled. Line order itself carries no signal (the whole-document
   signature is the integrity anchor; reordering without re-signing is
   impossible), so a reader MUST sort by `index` before evaluating the rules
   below and MUST NOT reject an interleaved line order.
2. Per-downpipe `prevRunId` linearity: taking each downpipe's entries in ascending
   `index` order, the first entry's `prevRunId` is the JSON null literal (a
   downpipe's first run) or, if non-null, names an existing entry of any status
   (rule 3 covers a pointer that resolves nowhere); every subsequent entry's
   `prevRunId` MUST equal the immediately prior retained entry's `runId` for that
   downpipe. A break in linearity means an entry was removed from the middle of
   the chain or the chain was rewritten. The after-prune state does not trip this
   rule, because pruned entries are retained marked `superseded` (section 10.1).
3. Dangling or forked `prevRunId`: a non-null `prevRunId` that no entry of any
   status carries is a dangling pointer, and two entries sharing one `prevRunId`
   are a fork; either means the chain was rewritten.

An `index` gap is NOT among these anomalies, for the allocation reason above; a
reader MUST NOT reject a per-downpipe or document-wide `index` gap as a rollback.
If the run being restored is not the latest for its downpipe, or a chain anomaly
above is detected, or the RUNLOG's maximum `index` is below an operator-supplied
`--min-runlog-index`, the reader warns and records
`freshness.isLatestForDownpipe`, `freshness.rollbackWarning` and
`freshness.minIndexPinned` in the receipt, and exits non-zero (code 5) unless the
operator acknowledges it. The acknowledgement is `--allow-stale` for a non-latest run
and a below-pin index, and `--allow-unverified-runlog` for a chain anomaly, because an
internally contradictory log reports no trustworthy age. An absent or truncated RUNLOG is
itself a code-5 condition in verified mode (section 8.7), taking
`--allow-unverified-runlog`.

The in-bucket RUNLOG defends against accidental staleness and naive replay: a stale
validly-signed run is observable rather than silent. It does not, on its own, defend
against an active bucket-write adversary who deletes the newer run AND rolls the
RUNLOG back to an older validly-signed state, which is internally self-consistent
and has no in-bucket high-water mark to contradict it. To make that observable, the
operator pins the last-known maximum index out of band: the recovery sheet records
it, and `--min-runlog-index` causes the reader to exit non-zero in verified mode if
the RUNLOG's maximum index is below the pin or the RUNLOG is absent. Replay is
therefore observable to a reader that pins a minimum `runlogIndex` out of band. The
division of labour is deliberate: the whole-document signature catches any rewrite
of the stored bytes, the chain anomalies above catch a removal or rewrite within an
otherwise-signed document, and a tail rollback (substituting an older validly
signed RUNLOG and signature pair wholesale) is caught only by the out-of-band pin,
not by any in-document check.

The recovery bundle (section 9) is kept out of the per-run RUNLOG entry to keep
both the entry and the root manifest small. The bundle's own `SHA384SUMS`
(section 9) is the integrity anchor over `FORMAT.md`, `RECOVER.md` and the vendored
reader; a recoverer who pins the expected `SHA384SUMS` out of band, on the recovery
sheet, confirms the bundle was not altered.

### 10.1 Lifecycle and manifest-driven deletion

Object-store lifecycle and expiry rules MUST NOT be applied to the `seg/` and
`run/` trees (D8 M8). A bucket lifecycle policy that expires objects by age would
silently break completeness: a segment that looks unreferenced by age may still be
the only copy a retained run depends on (and, for a writer that performs cross-run
dedup per section 7.3, one segment may back several runs at once). Deletion of archive
objects is the engine's manifest-driven prune alone, never the object store's clock.
The engine configures no such rule, and a deployment that adds one is misconfigured.

Deletion is manifest-driven only. A `seg/<aa>/<segId>.seg` object is deletable only
when no retained run's shard manifests reference that content id. Pruning a run
means deleting its `run/<runId>/` tree and then deleting any `seg/` object that no
remaining retained run references, computed from the retained runs' decrypted shard
manifests, never by age or by a listing heuristic. The pruned run is NOT erased from
the RUNLOG: its entry is retained with `status` set to `superseded` so each
downpipe's `prevRunId` chain stays linear.

A reader walking `prevRunId` backward MAY encounter a `prevRunId` whose
`run/<runId>/` tree has been pruned. That is the expected after-prune state and is
NOT a rollback: the chain anomalies of section 10 are checked against the RUNLOG
entries themselves (which retain pruned entries, marked `superseded`), never
against the presence of each previous run's tree. A removed RUNLOG entry, by
contrast (a break in the per-downpipe `prevRunId` linearity, or a `prevRunId` that
no RUNLOG entry of any status carries), is a rollback and triggers code 5. An
`index` gap is not a removal signal, because `index` values are account-globally
allocated and a failed run consumes one without appending an entry (section 10).

The `verify` command reports dangling references: a `seg/` object path named by a
retained manifest that is absent from the bucket is a dangling reference and counts
against completeness, and a `seg/` object present in the bucket that no retained
manifest references is reported as an orphan candidate for manifest-driven deletion.
The receipt carries `danglingSegments` (section 8.5), counting DISTINCT `seg/` paths,
because segments are content addressed and two records may name one object.

A pass that reads no `seg/` object cannot answer this question and MUST omit the field
rather than report `0`. A shallow `verify` reads manifests only and omits it; `verify
--deep` and an applied `restore` open every segment, so they report the count and a `0`
from them means the check ran and found none. The orphan half of this paragraph is not
implemented by the reader and no receipt field carries it.

## 11. Byte-level encodings

Every encoding below is pinned so the conformance vectors are cuttable (D7).

### 11.1 Canonical JSON

Signed and MAC'd JSON uses RFC 8785 JSON Canonicalisation Scheme: object keys
sorted by UTF-16 code unit, no insignificant whitespace, shortest-round-trip number
form, UTF-8 output. Equivalently stated for implementers without an RFC 8785
library: sorted keys, no insignificant whitespace, minimal number form, UTF-8. The
NDJSON manifest payloads are a sequence of canonical JSON objects each on one line;
canonicalisation applies per object.

### 11.2 No NaN, no infinities

Signed JSON MUST NOT contain NaN, Infinity or -Infinity. Numbers are finite.

### 11.3 Integer ceiling and the canonical numeric form

A signed field that is a count or size (`declaredRecordCount`, `plaintextSize`,
`recordCountInShard`, `shardCount`, `runlogIndex`, `recordCount`, the receipt count
fields, packed `offset`/`length`, `chunkRange` endpoints) has exactly one canonical
representation for a given value:

- A value at most 2^53 - 1 (`9007199254740991`) MUST be a JSON number, never a
  string.
- A value greater than 2^53 - 1 MUST be a decimal string of ASCII digits, never a
  JSON number.

A reader MUST reject the wrong form in a signed field: a JSON number above 2^53 - 1
is rejected (exit 6), and a string form for a value that is at most 2^53 - 1 is
rejected as non-canonical (exit 6). This removes the number-versus-string ambiguity
that would otherwise let two writers produce different RFC 8785 canonical bytes for
the same value and so produce incompatible signatures.

### 11.4 Base64 for binary-in-JSON

All binary carried inside downpipe JSON uses base64url with no padding (Go
`base64.RawURLEncoding`). This is the only base64 variant in downpipe JSON; there is
no age-header base64 in this major. The base64url no-pad JSON fields are the inline
recipient public keys (`recipients[].x25519`, 32 bytes, and `recipients[].mlkem`,
1568 bytes), each capsule wrap's `kemCiphertext` (1600 bytes) and `sealed`, and a
`secrets` record's `recordSalt` (16 bytes); the hashes and MAC outputs are bare
lowercase hex (section 11.8), not base64. The detached signature files
(`root.manifest.json.sig` and `_RECOVERY/RUNLOG.sig`) are base64url no-pad of the
4691-byte hybrid signature `edSig(64) || mldsaSig(4627)` (section 8.1), and a `.seg`
or `.dpe` is raw bytes on disk, not base64. Key fingerprints carry a type prefix:
`dpr1:` for a hybrid X25519 + ML-KEM-1024 recipient fingerprint (section 7.6.1),
`edmldsa1:` for a hybrid Ed25519 + ML-DSA-87 signer fingerprint. A signer
fingerprint is `"edmldsa1:" || lowercase_hex( SHA-384( ed25519Pub(32) ||
mldsa87Pub(2592) ) )`. Other binary fields carry no prefix.

### 11.5 Timestamps

Timestamps are RFC 3339 in UTC with a literal `Z`, exactly three fractional digits,
for example `2026-06-06T12:07:33.000Z`. No other offset and no other fractional
precision is permitted in a signed field. Timestamp fields are emission-canonical
only; a reader MUST NOT make any decision from a timestamp (freshness is from the
RUNLOG `index`, section 10), so the semantic validity of the instant is immaterial
to a reader and a reader need not range-check it.

### 11.6 ULID

`runId` is a 26-character uppercase Crockford base32 ULID. Its binary form
(`runId-bytes`, used in HKDF salts and MACs) is the 16-byte ULID: a 48-bit
big-endian millisecond timestamp followed by 80 bits of randomness. The canonical
text form is never lowercased in an object path or a signed field. Crockford base32
excludes I, L, O and U; the alphabet is `0123456789ABCDEFGHJKMNPQRSTVWXYZ`.

### 11.7 HKDF info strings (frozen)

The HKDF and MAC labels for `downpipe/0.1.0`, as exact ASCII byte strings (all KDFs
are HKDF-SHA-384; all keyed MACs are HMAC-SHA-384):

- Content-addressing key `CAK`: info `downpipe/0.1.0 content-address`, salt =
  `downpipeId` UTF-8, ikm = master.
- Manifest subkey `MK`: info `downpipe/0.1.0 manifest-key`, salt = `runId-bytes`, ikm
  = master.
- Shard file key: info `downpipe/0.1.0 manifest-wrap` || 0x00 || shardId-ascii, salt
  = `runId-bytes`, ikm = `MK` (section 6.3).
- Name MAC key: info `downpipe/0.1.0 name-mac`, salt = `runId-bytes`, ikm = `MK`.
- Non-secret segment file key: info `downpipe/0.1.0 seg-key` || 0x00 ||
  ctxNonSecret, salt = zero-length, ikm = master (section 7.4).
- Secrets segment file key: info `downpipe/0.1.0 seg-key` || 0x00 || ctxSecret, salt
  = `runId-bytes`, ikm = master (section 7.4).
- STREAM payload key: info `downpipe/0.1.0 payload`, salt = the 16-byte payload
  nonce, ikm = fileKey (section 7.8).
- Capsule DEM wrap key: info `downpipe/0.1.0 capsule-dem`, salt = zero-length, ikm =
  the hybrid KEM shared secret (section 5.4).
- Hybrid KEM combiner: info `downpipe/0.1.0 hybrid-kem` || 0x00 || ct_X || pk_X, salt
  = zero-length, ikm = ss_M || ss_X (section 4.2).
- Key commitment: HMAC-SHA-384 with key = master and message `downpipe/0.1.0
  key-commit` || `runId-bytes` (section 8.4).
- Recipient-set hash: SHA-384 over `downpipe/0.1.0 recipient-set` || 0x00 ||
  rpk_sorted (section 7.6.1).

There are no age-internal labels in this major. These labels are frozen for the
format version; a change to any label is a byte-level rule change and therefore a
MINOR bump while the major is 0 (section 13, D8 M9, D7). The string each label
carries is the minor line's identifier at its `.0` patch, which is why a patch bump
leaves every label above untouched: a patch that moved a label would change key
derivation and would not be a patch.

### 11.8 Hash, Merkle and canonical record order

Content, plaintext, segment, shard, record, recipient-set and Merkle hashes are
SHA-384 rendered as bare lowercase hex (96 chars) with no prefix; the keyed-MAC
outputs (segId, keyNameHash, keyCommitment) are HMAC-SHA-384, 48 bytes, lowercase
hex. A reader hex-decodes then compares with `crypto/subtle.ConstantTimeCompare`,
never a string compare. Key fingerprints carry a type prefix (section 11.4).

Canonical record order is defined independently of `recordId` so that two writers
crawling the same source assign the same order. Records are ordered ascending by the
pair `(sourceType, name)`: first by `sourceType` compared as the byte string of its
lowercase ASCII value, then for equal `sourceType` by `name` compared as the
byte-wise lexicographic order of its UTF-8 encoding. Each record's `recordId`
r-ordinal is then assigned `0`, `1`, `2`, … in this order. A vanished-mid-crawl
record (section 12.5) takes its position in this same order by `(sourceType, name)`,
so the Merkle leaf set and `declaredRecordCount` are writer-independent for the same
source data. A source MUST NOT present two records with the same `(sourceType,
name)` in one run; if the source could (it cannot for KV, R2, secrets or a single
D1 dump as defined here), the writer fails the run rather than emit an ambiguous
order.

The Merkle tree is RFC 6962: leaf hash = `SHA-384(0x00 || recordHash-bytes)`,
interior node = `SHA-384(0x01 || left || right)`, over `recordHash` values (section
6.5) in canonical record order. An odd node at a level is promoted unchanged to the
next level, never duplicated. The empty-tree root (zero records) is `SHA-384` of the
empty string, lowercase hex
(`38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b`).
`merkleRoot` is the resulting root, lowercase hex.

### 11.9 `.seg` magic and codec identifiers

The `.seg` object's magic is the 4 ASCII bytes `DPS1` (44 50 53 31) followed by a
1-byte container version `0x01` (section 7.1); it is NOT an age file and carries no
age intro line. The shard manifest container `.dpe` is identical except the magic is
`DPE1`. The codec identifier byte used in the file-key context (section 7.4) is
`0x00` for `none` and `0x01` for `gzip`. The textual codec name in JSON is the
lowercase set `{none, gzip}`.
## 12. Source types and per-source rules

A downpipe reads exactly one source type per route. Every source reduces to the
ordered-segments record shape, so adding a source is an adapter, never a format
change. Many small records pack into shared segments; a large opaque blob becomes a
one-or-more segment chain.

### 12.1 Supported and reserved `sourceType`

- `kv` (supported): Workers KV. Name and opaque value. Small values pack.
- `r2` (supported): R2 objects. Large opaque blobs, a segment chain per object.
- `secrets` (supported, high-assurance, possibly load-bearing): account Secrets
  Store and per-Worker secrets. Name and opaque secret value, read at runtime
  through a Worker binding with `await env.BINDING.get()` because secret values
  cannot be read back through any management surface. Subject to section 12.4.
- `d1` (supported): a D1 database exported as a structured, replayable dump: a header
  record with each table's CREATE DDL and column names, many keyset-paged row records, and a
  schema record for indexes, triggers and views, carried with a `format` hint. Restore replays
  the dump by re-creating the schema and re-inserting every row with parameterised statements
  into a fresh database.
- `workers` (supported, reprovision restore): deployed Worker scripts, snapshotted as
  the script code, a settings record (bindings, compatibility date and flags,
  observability, limits) and a small versions inventory, one record per aspect,
  name-prefixed by the script id. Unlike a binding source it is read account-scoped
  through the Cloudflare REST API with a read-only token. Restore is REPROVISION, never a
  blind redeploy: the offline reader verifies the snapshot and surfaces the verified
  bytes plus re-deploy guidance, and the operator re-deploys deliberately, because a
  blind redeploy from a backup could brick a live service. A `secrets`/`secret_key`
  binding's VALUE is never captured (it cannot be read back); only a checklist of its
  name and type is recorded, to be re-provisioned.
- `cf-config` (supported, replay restore): Cloudflare configuration surfaces (DNS, zone
  settings, rulesets and WAF, page rules, Access, load balancers, and so on), one
  canonical-JSON record per surface, read through the Cloudflare REST API with a
  read-only token. Restore is tiered replay: an idempotent surface can be re-applied
  additively with an edit-scoped token, while ordered and write-only surfaces stay out of
  band with guidance. The offline reader verifies the snapshot and surfaces it; it never
  blindly re-applies a configuration surface.
- `stream` (supported, reprovision restore): Cloudflare Stream videos, snapshotted as a
  video-inventory, one canonical-JSON record per video carrying its metadata (uid, name,
  duration, playback ids, status, `requireSignedURLs`, allowed origins, created/modified,
  user `meta`), read account-scoped through the Cloudflare REST API with a read-only token.
  When the downpipe enables content capture, the writer ALSO emits the video bytes
  (`<uid>/video.mp4`, size-gated) and caption tracks (`<uid>/captions/<lang>.vtt`) as extra
  records of this same type; a video whose async download is not yet rendered carries an honest
  pending marker captured on a later run. Restore is REPROVISION, like `workers`: the offline
  reader verifies the snapshot and surfaces the inventory (and, when present, the files) plus
  re-upload guidance. No secret value transits (signing keys are a separate resource, not captured).
- `images` (supported, reprovision restore): Cloudflare Images, snapshotted as an inventory, one
  canonical-JSON record per image carrying its metadata (id, filename, uploaded,
  `requireSignedURLs`, variants, user `meta`) plus one account-level variant-definitions record,
  read account-scoped through the Cloudflare REST API with a read-only token. When the downpipe
  enables content capture, the writer ALSO emits each image's bytes (`<id>/blob`, size-gated) as
  extra records of this same type. Restore is REPROVISION, like `stream`/`workers`: the offline
  reader verifies the snapshot and surfaces the inventory (and, when present, the files) plus
  re-upload guidance. No secret value transits (signing keys are a separate resource, not captured).
- `artifacts` (supported, reprovision restore): Cloudflare Artifact Registry, snapshotted as an
  inventory, one canonical-JSON record per repository carrying its namespace + repo metadata, read
  account-scoped through the Cloudflare REST API with a read-only token. When the downpipe enables
  content capture, the writer ALSO walks the repo's git objects across the full history (the commit
  log, every commit and reachable tree as metadata records, and each reachable file blob's bytes,
  `<ns>/<repo>/blob/<hash>`, size-gated and deduped) as extra records of this same type. Restore is
  REPROVISION, like `stream`/`images`: the offline reader verifies the snapshot and surfaces the
  namespace/repo inventory (and, when present, the objects) plus re-create guidance. Per-repo push
  tokens are not captured.
- `durable_object`, `vectorize` (reserved, later): both need cooperative in-account
  enumeration and have native point-in-time recovery, so they sit outside
  `downpipe/0.1.0` scope. A `sourceType` outside the supported set (the nine types above) is
  refused by a `downpipe/0.1.0` reader.

### 12.2 Selectors

`source.include` and `source.exclude` are ordered lists of prefixes in the
source-native key space: an R2 object-key prefix, a KV key prefix within a
namespace. A record is in scope when it matches at least one include prefix and no
exclude prefix. The selectors live in the encrypted preamble (section 6.1), so an
audit can prove the running selector matched the committed one without exposing it in
the clear.

### 12.3 Secret descriptors

For `secrets`, the descriptor needed to reconstruct configuration and not only the
bytes (the store, scope, comment and per-Worker binding wiring) is carried inside the
encrypted shard manifest, never in the cleartext root. It is the per-source `secrets`
descriptor object on the record line (section 6.2): `{store, scope, comment, worker,
bindingVar}`, exactly the descriptor matching `sourceType` and present only for a
`secrets` record. The secret name itself is the record's `name` field (section 6.2) and
the source context is the encrypted preamble's `source` block (section 6.1), not part of
the descriptor object. A reader treats the restored descriptor as opaque configuration;
any additional per-record secret configuration a future minor adds is carried as further
members of this descriptor object and a reader still treats them as opaque. None of this
descriptor material is in the cleartext root.

### 12.4 The secrets rule (non-negotiable)

A `secrets` downpipe carries the highest-value data in the account, including the
keys that protect every other backup. Losing the Secrets Store loses the keys to
everything, permanently, so this source is the high-assurance, possibly load-bearing
source.

- The recipient set MUST include the offline break-glass hybrid X25519+ML-KEM-1024
  recipient, the same mandatory requirement as every other source (D5). A `secrets`
  downpipe additionally MUST NOT rely on a wrapping key held inside the store being
  backed up, because that is a circular dependency: losing the store would lose the
  key to its own backup.
- Compression is FORCED OFF: `codec` is `none` for every secrets record, which the
  reader enforces (section 5.2, 7.5, D8 M4). The rule is carried by the per-record
  `codec`; there is no separate run-wide secrets-compression flag in the envelope.
  Secrets of different trust origins are never co-packed into one segment (section
  7.3).
- The read-and-seal path runs only in the customer account on the inspectable
  engine. Plaintext secrets are sealed in isolate memory and are never written to a
  log, a manifest, an intermediate object or any orchestration state.
- Each secrets record carries a fresh random `recordSalt` mixed into its segment
  address and its segment file key (section 7.2 case 0x03, section 7.4), so identical
  secret values never collide on disk and no dedup occurs for secrets (D2).

The confidentiality property is precisely the one stated in section 1.1, not a
stronger one. Compromise of the destination bucket ALONE does not yield the secret
values, because the operational private key lives in the (separate) Cloudflare
account and the break-glass private key lives offline. A simultaneous full compromise
of the live Cloudflare account AND the destination CAN decrypt the secrets through
the in-account operational key, unless the downpipe runs in the break-glass-only
posture (no operational recipient, section 1.1), where the only decrypting key is
offline. A secrets downpipe that must withstand full account compromise MUST use the
break-glass-only posture and accept the loss of in-account read-back. Because the
break-glass key lives offline, losing it makes the backup unrecoverable, so the data
is wrapped to more than one offline holder where break-glass-only is used (the
offline key MAY be Shamir-split) and every recipient `fingerprint` is captured on
the printed recovery sheet.

### 12.5 Vanished-mid-crawl, empty value, absent value

KV has no point-in-time snapshot and is a crawl over a live namespace. To stop a live
crawl false-positiving the completeness gate (D8 M7):

- A record observed at crawl start but gone before its value could be sealed is a
  vanished-mid-crawl record. It is NOT emitted as a record line (section 6.3 is
  normative): it is excluded from the shard's record lines, from `declaredRecordCount`
  and from the readable-coverage denominator, and the record line shape carries no
  `vanished` field. It still takes its canonical-order position by `(sourceType, name)`
  (section 11.8) but contributes no Merkle leaf and no coverage obligation. The receipt
  reports `vanishedExcluded` when its emitter holds the figure. Nothing in the signed root
  or in the shard manifests records it, so the offline reader cannot derive it and omits
  the field; an emitter that has the count MUST NOT be inferred to have measured zero from
  its absence.
- An empty value (a present key whose value is zero bytes) is encoded as a record with
  `plaintextSize: 0`, `plaintextSha384` of the empty string
  (`38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b`),
  and a segment whose downpipe STREAM payload is empty: a single final chunk of zero
  plaintext bytes with the last-chunk flag 0x01 (the only case where the final chunk
  may be empty, section 7.8). This is distinct from an absent value: an absent key is
  simply not a record.

### 12.6 Restoring a secrets downpipe

Restore is the point and it runs offline. The break-glass private hybrid key decrypts
the archive on the operator's own machine, recovering plaintext with neither Cloudflare
nor the vendor in the loop. The operator chooses a sink:

- Back into a fresh Cloudflare Secrets Store, to recover after an attacker or an
  accident wipes the store. Restore creates each secret fresh, never `duplicate` (which
  produces a Worker-unreadable secret), and recreating under the original names lets
  existing Workers resolve the restored secret by binding name without a redeploy.
- Into another secrets manager such as Vault, AWS Secrets Manager or Azure Key Vault,
  to move off Cloudflare entirely.
- Out to a plain `.env` file, for an environment that loads secrets from a file.
- To stdout, for piping into the operator's own loader.

Verification adapts to the write-only model. A non-Cloudflare target is read back and
hash-checked directly against the signed manifest. A restore back into Secrets Store
cannot read the value through the management API, so value verification binds the
restored secret to a throwaway Worker, reads it with `.get()`, and checks its hash.
That bind-and-get check is an engine feature, not something the offline binary can do,
so the offline tool records a Secrets Store target as created but value-unverified
(`target.valueVerified: false`) unless the verifier runs. Recovery remains fully
offline; only the post-restore value check on a write-only store needs the engine,
which is a documentation and honesty point, not a custody or moat concession. The
receipt records which verification was used and the backup window, since a restore
reintroduces values as of that window and may carry credentials that have since been
rotated.

## 13. Versioning

`formatVersion` is the byte string `downpipe/0.1.0`, versioned by semver
(`downpipe/MAJOR.MINOR.PATCH`). While the major is 0, the MINOR is the compatibility
unit: a reader accepts exactly the `major.minor` it implements (`downpipe/0.1.x`, any
patch) and refuses every other version with a clear message rather than guessing. The
cryptographic primitives (section 4) are fixed for a minor; a new primitive, a new
HKDF or MAC label, a changed chunk size, a changed canonicalisation, or a changed
byte layout is a minor bump while the major is 0 (D8 M9, D7), and a patch bump
changes no byte-level rule. The recovery bundle is versioned by `formatVersion`
(section 9), so a bucket can carry more than one format version's bundle side by
side.

`MAJOR`, `MINOR` and `PATCH` are each a canonical decimal integer: one or more ASCII
digits, and no leading zero before another digit. A reader MUST refuse a
`formatVersion` whose components are not canonical decimals as a MALFORMED label
rather than as an unimplemented version, because the two say different things to
whoever is holding the archive: one means these bytes are not a downpipe version
string and no reader anywhere will help, the other means go and get a different
reader. `downpipe/0.1.0 ` with a trailing space, `downpipe/0.1.x` and
`downpipe/00.01.0` are all malformed, none of them is `downpipe/0.1` at some patch,
and a reader that accepted any of them would be reading a version no conformant
writer emits (section 5.2).

All three components are part of the version. A `downpipe/MAJOR.MINOR` label is
MALFORMED and MUST be refused as such: no conformant writer emits one, no reader
implements one, and the refusal MUST NOT close by naming a build to go and fetch,
because there is none to name. A two-component label MUST NOT match a reader's
implemented set on its numbers: `downpipe/0.1` carries the same two numbers as
`downpipe/0.1.0` and is a different format, because its section 11.7 labels read
`downpipe/0.1 <purpose>` and every key derives to different bytes. A reader that
matched on the numbers alone would decrypt nothing and report an authentication
failure over intact bytes, which reads as data loss when nothing has been lost.

Because this refusal fires on arity as well as on canonicality, the message MUST name
the shape rather than blaming non-decimal components alone: every component of
`downpipe/0.1` IS a decimal number, and a message saying otherwise misdescribes the
bytes to the one person who has to act on them.

A `MAJOR.MINOR` label was the identity scheme of a pre-release lineage of this format,
retired. No release implementing it was ever published, no reader for it
is obtainable, and no writer offered on the update channel stamps one. This rule is
correct only while that stays true: a published writer emitting a two-component label
would make the malformed refusal tell the holder of intact bytes that their manifest is
damaged, which is the most expensive wrong thing a reader can say mid-recovery.

### 13.1 What a reader implements, and what it owes

A reader implements a SET of format versions, and the set is stated by the release,
not inferred from a comparison. It reads exactly the versions in its set and refuses
every other one by name. It does not read a version because that version's major
matches its own, and it does not read a version because that version sorts below its
own: a lower minor is a different, incompatible byte format, so accepting it on
ordering alone would derive every key under the wrong labels (section 11.7) and the
failure would surface as an authentication failure over the archive's bytes, which
reads as data loss when nothing has been lost. Refusing is the safe outcome and the
honest one: the refusal happens before any target is written, so a refused restore
writes nothing and destroys nothing.

The set is additive FROM THE FIRST PUBLISHED RELEASE. Once a release implementing a
format version is obtainable, no later release may remove that version, because the
bytes that name it are then sitting in somebody's bucket and there is no deprecation
path for stored bytes. Adding a minor to a reader is therefore real retained code, a
retained key schedule and a retained conformance corpus for the older minor, not a
widened version comparison. Whoever cuts the second minor owes that work in the same
change set.

The rule binds on what was PUBLISHED, not on what was written down. Before the first
obtainable release there are no stored bytes to protect, and treating the rule as
though there were is how a format accumulates units for readers nobody holds. The
`1.x`lineage was retired on that reading: it had no published release,
no obtainable reader and no writer offered on the update channel, so it left the set
rather than being carried. `0.1` is the only unit this format has, and the additive
rule binds on it from the first published release of a reader that implements it.

Two duties follow, and both bind the project rather than the bytes:

- A reader release that implements a given format version MUST stay obtainable for as
  long as any stored bytes name that version. Stored bytes have no deprecation path, so
  that is indefinite.
- Each reader release MUST state the format versions it implements, in a place
  somebody holding a refused archive can reach. This repository states it in
  `CHANGELOG.md` under each release. Without that, the refusal names a remedy
  (get a reader for this version) that nobody can act on, because the reader's own
  version number is an independent number space and says nothing about the format.

## 14. Conformance vectors

The vectors under `testdata/vectors/` are normative (D8 M10). Each vector directory
contains the pinned inputs, the writer-authoritative stored bytes for the object
classes that are writer-authoritative, and an `expect.json` describing the expected
reader outcome.

### 14.1 Authority split and what is writer-authoritative

For a positive or edge vector, randomness is pinned so that a defined set of object
classes is reproducible byte-for-byte. A vector pins: a fixed master (from which `CAK`,
`MK`, the non-secret content-derived file keys, the secrets file keys and
`keyCommitment` follow deterministically, so they are not separately pinned); a fixed
X25519 ephemeral secret per capsule wrap, indexed for the inline master capsule by the
synthetic key `masterCapsule` keyed by recipient fingerprint (there are no per-unit
stanzas to pin, since only the capsule carries recipient wraps); the fixed hybrid
X25519+ML-KEM-1024 public recipients and their identities; a fixed 16-byte STREAM
payload nonce per sealed unit, indexed by object path and, for each capsule wrap, under
the synthetic `masterCapsule` key by recipient fingerprint; the hybrid Ed25519+ML-DSA-87
signer private key and its `edmldsa1:` fingerprint; and the per-run identifiers.

With that pinning the WRITER is authoritative for these object classes, which a
conformant writer MUST reproduce byte-for-byte:

- every `.seg` whose `codec` is `none`;
- every `manifest/<shardId>.dpe` whose `manifestCodec` is `none`;
- the deterministic `kem-combiner-kat` (section 14.6).

The WRITER is NOT authoritative for, and a second writer is NOT required to reproduce:

- the `masterCapsule`, and therefore the `root.manifest.json` that embeds it and the
  detached `root.manifest.json.sig`: ML-KEM-1024 encapsulation draws its own randomness
  with no caller-supplied-coins variant in the reference, so `ct_M` (and thus the
  capsule and root bytes) cannot be pinned; and the ML-DSA-87 signer is hedged
  (randomised), so a signature is not reproducible either. These are reader-authoritative
  (the reader recovers and verifies them);
- the RUNLOG and its signature, for the same signing reason;
- any `.seg` whose `codec` is `gzip` (cross-runtime DEFLATE non-determinism, section
  7.5): the compressed segment bytes are pinned as a fixed input artefact produced once
  by the reference generator, and only the reader outcome is asserted;
- any `manifest/<shardId>.dpe` whose `manifestCodec` is `gzip`, for the same reason.

The READER asserts, for every positive and edge vector: it recovers each listed
record's bytes, the recovered bytes hash to the pinned `plaintextSha384`, the hybrid
signature verifies against the pinned signer, every section 8.3 recomputation passes,
the break-glass and recipient-set checks of section 8.6 pass, and the run reaches the
pinned receipt outcome.

For negative vectors the READER is authoritative for the OUTCOME: a conformant reader
MUST reject the vector with the specified exit code and `signatureResult` /
`completeness` labels. Negative vectors do not require byte-reproduction.

### 14.2 Positive vectors

Each pins all randomness as in section 14.1.

- `seg-empty`: one `kv` record, empty value, `codec` none. A single empty final chunk,
  last-chunk flag 0x01. Reader recovers zero bytes, `plaintextSha384` of empty, receipt
  exit 0. Writer-authoritative for the `.seg`, the shard `.dpe` and the root.
- `seg-single-chunk`: one `r2` record, value smaller than 65536 bytes, `codec` none. One
  chunk, flag 0x01. Worked hex of section 7.9 lives here. Writer-authoritative.
- `seg-multi-chunk`: one `r2` record larger than 65536 bytes, several chunks, only the
  last with flag 0x01, `codec` none. Writer-authoritative.
- `seg-multi-segment`: one large `r2` record across an ordered `segments[]` chain at the
  pinned segmentation bound (section 14.5), reassembled in order, full-record
  `plaintextSha384` checked, `codec` none. Writer-authoritative.
- `seg-packed`: several small `kv` records of one downpipe sharing one segment, `codec`
  none, each with a `packed {offset, length}`, each member's slice hash checked.
  Writer-authoritative.
- `dedup-same-value-two-runs`: two runs of one downpipe with an identical unchanged
  non-secret value, `codec` none, written by a stable-per-downpipe-master writer (the
  OPTIONAL cross-run-dedup case, section 7.3). Both runs reference the same
  `seg/<aa>/<segId>.seg` object, stored once, and the reader restoring EITHER run
  re-derives the same content file key and opens it. The vector tree contains exactly
  one copy of that segment. Both runs' roots and signatures verify. A reader MUST open
  this shape; a per-run-master writer (the reference engine) instead writes two
  distinct segments for the two runs and is equally conformant. The shared `.seg` here
  is a pinned input artefact, not reference-writer output.
- `secrets-no-dedup`: one run, source `secrets`, two secret records with byte-identical
  values, distinct `recordSalt`, distinct `segId`, distinct per-segment file keys,
  each record's `codec` none. Two distinct `.seg` objects. Writer-authoritative.
- `gzip-codec`: one `r2` record with run-wide `codec` gzip and a value chosen to
  compress. The compressed `.seg` bytes are a PINNED INPUT ARTEFACT (not writer-
  authoritative). The reader's assertion is decrypt then decompress then
  `plaintextSha384` over the decompressed bytes; it MUST NOT require byte-reproduction
  of the compressed segment. The root and shard `.dpe` (with `manifestCodec` none) stay
  writer-authoritative.
- `master-capsule`: the cleartext root with a pinned `masterCapsule` (each wrap's
  ephemeral and STREAM payload nonce pinned under the synthetic key `masterCapsule` by
  recipient fingerprint). The reader unwraps the master, derives `CAK` and `MK`,
  recomputes `keyCommitment` and `recipientSetHash`, and matches them in constant time
  against the signed envelope. Writer-authoritative for the root.
- `break-glass-only`: one run in the break-glass-only posture (recipients are the
  break-glass identity alone), `codec` none. Demonstrates that the single-recipient
  posture satisfies the break-glass requirement and that section 8.6 passes with one
  recipient. Writer-authoritative.

- `d1-with-identity`: one `d1` record carrying the OPTIONAL annotative fields
  `database` (the native database UUID) and `account`, plus the `d1` descriptor;
  recovery returns the dump bytes and the reader must surface the annotations
  (section 6.2, 19). Pins the annotative fields, which are not record-hash inputs.
- `incomplete-marker`: one `r2` record stamped `incompleteMarker: "_vanished"` whose
  value is the sentinel JSON the writer emits in place of real bytes; recovery
  returns the sentinel value and the reader must surface the marker kind rather than
  presenting the record as real data (section 6.2).
- `reprovision-workers`: one `workers` record (an API-discovery source, carrying
  `account`); recovery returns the verified bytes (a reprovision-type source
  restores by deliberate re-provisioning, section 12.1).

### 14.3 Negative and tamper corpus

A conformant reader MUST reject each, with the noted outcome.

- `truncated-final-chunk`: base `seg-multi-chunk`, the last STREAM chunk cut by 8 bytes;
  AES-256-GCM authentication of the final chunk fails; completeness not satisfied; exit
  non-zero (a decrypt failure, not a clean partial). The receipt records the failing
  record.
- `reordered-chunks`: base `seg-multi-chunk`, the two chunk ciphertexts swapped on disk;
  AES-256-GCM authentication fails because the chunk counter no longer matches; exit
  non-zero.
- `reordered-segments`: base `seg-multi-segment`, the two entries of the record's
  `segments` list swapped in the manifest without re-signing; the hybrid signature over
  canonical bytes fails first (exit 2), and absent the signature the full-record
  `plaintextSha384` fails (exit 4); the vector fixes the expected exit.
- `flipped-tag`: base `seg-single-chunk`, one bit of the single chunk's AES-256-GCM tag
  flipped; authentication fails; exit non-zero.
- `mutated-recipient-fingerprint`: base `seg-single-chunk`, the break-glass
  recipient's `fingerprint` in the signed root is altered to a different valid `dpr1:`
  fingerprint without re-signing; the hybrid signature over canonical root bytes fails;
  `signatureResult` invalid; exit 2. (This mutates a SIGNED field, so the signature
  detects it.)
- `dropped-break-glass-wrap`: base `seg-single-chunk` in the default two-recipient
  posture, the break-glass wrap is removed from the `masterCapsule[]` array in the
  stored root while the `recipients` list and the signed envelope are left otherwise
  intact. The signature no longer verifies over the mutated canonical root bytes;
  failing that, the section 8.6 item-2 check finds the capsule wrap set no longer
  covers the signed `recipients[].fingerprint` set and no longer
  carries the break-glass fingerprint; verified restore refuses with exit 2 and
  `breakGlassVerified: false`. This proves break-glass is bound through the signed capsule,
  not a free-standing claim.
- `forged-capsule-wrap`: base `seg-single-chunk`, a capsule wrap re-encapsulated to an
  attacker-controlled recipient and re-signed by the pinned signer so the signature is
  valid, but the wrap's `fingerprint` is not the `dpr1:` fingerprint of any
  recipient public key the operator supplied. The section 8.6 item-2 check fails (an
  unrecognised capsule wrap fingerprint) and `recipientSetHash` recomputed over the
  operator-supplied recipients no longer equals the signed value; verified restore refuses
  with exit 2 and `breakGlassVerified: false`. This proves the recipient-set binding is
  checked against the operator's keys, not self-asserted by the capsule.
- `deleted-shard`: base a true two-shard positive archive whose records are split across
  shard `00000` and shard `00001`, one `manifest/<shardId>.dpe` removed after the archive
  is built; readable coverage falls below `declaredRecordCount` through the
  shard-read-failure branch of completeness; completeness incomplete; exit 3.
- `incomplete-record-count`: base `seg-single-chunk`, `declaredRecordCount` inflated to
  declare one more record than the archive carries and re-signed by the pinned signer, so
  readable coverage is below the declared count through the count-mismatch branch of
  completeness. This reaches the same exit 3 as `deleted-shard` but by a distinct path:
  `deleted-shard` exercises the missing-shard read failure, `incomplete-record-count`
  exercises the count comparison alone (SPEC.md 8.5 exit 3). Both vectors are retained so a
  conformant reader proves both completeness branches.
- `wrong-merkle-root`: base `seg-packed`, one record's `plaintextSha384` altered in the
  manifest so its `recordHash` no longer rolls up to the signed `merkleRoot`. The vector
  pins which check fails first: either the recomputed Merkle root disagrees with the
  signed root under the section 8.3 item-2 recomputation (exit 2) or, if the writer left
  the root consistent and only the value diverges, the per-record plaintext check fails
  (exit 4). The vector fixes the expected exit.
- `shard-hash-mismatch`: base `seg-single-chunk`, the stored `manifest/00000.dpe` bytes
  are altered after the root was signed so `shards[0].sha384` no longer matches; the
  section 8.3 item-1 recomputation fails; exit 2.
- `bad-signature`: base `seg-single-chunk`, the bytes in `root.manifest.json.sig`
  corrupted; `signatureResult` invalid; `completeness` UNVERIFIED; exit 2 without
  `--allow-unverified`. With `--allow-unverified` the reader proceeds, sets `mode` to
  `allow-unverified`, still reports `signatureResult` invalid, and exits 0 only if every
  other check passes.
- `absent-signature`: base `seg-single-chunk`, `root.manifest.json.sig` removed;
  `signatureResult` absent; `completeness` UNVERIFIED; exit 2.
- `single-half-signature`: base `seg-single-chunk`, the detached signature truncated to a
  valid Ed25519 half with the ML-DSA-87 half removed (or one half corrupted) so only one
  half of the hybrid signature verifies; both halves are required and no downgrade is
  permitted (section 8.1), so `signatureResult` invalid; `completeness` UNVERIFIED; exit 2.
- `unknown-signer`: base `seg-single-chunk`, validly signed by a key K2, reader given
  `--signer` of a different key K1; `signatureResult` wrong-signer; exit 2; the
  manifest's self-asserted `signingKeyFingerprint` (set to K2) MUST NOT rescue it.
- `unknown-major`: base `seg-single-chunk`, `formatVersion` set to `downpipe/9.0.0` (a version
  the reader does not implement); reader refuses it with a clear message; exit 6; it does
  not parse the body.
- `unimplemented-minor`: base `seg-single-chunk`, `formatVersion` set to `downpipe/0.2.0`,
  the SAME major as the reader implements and a minor it does not; reader refuses it with
  the same clear message and the same exit 6, because the compatibility unit is the minor
  and not the major (section 13). This is the vector that separates the shipped rule from
  the discarded one: a reader that read every archive sharing its major would accept this
  archive, derive every key under the wrong labels and report an authentication failure
  over intact bytes. `unknown-major` alone cannot make that distinction, because a
  major-scoped rule and a minor-scoped rule both refuse `downpipe/9.0.0`.
- `unknown-source-type`: a natively built archive whose single record carries
  `sourceType: "durable_object"` (reserved, never emitted); the reader refuses the
  run up front with exit 6 rather than restoring an unknown type under a guessed
  behaviour (section 12.1).
- `unknown-codec`: base `seg-single-chunk`, the run-wide `envelope.codec` set to
  `zstd` and re-signed by the pinned signer; the closed-set membership gate
  (section 5.2) refuses the run at open with exit 6. Before this gate a uniformly
  relabelled archive was decrypted as codec `none`.
- `non-canonical-json`: base `seg-single-chunk`, `root.manifest.json` re-serialised with
  reordered keys and added whitespace so it is valid JSON but not RFC 8785 canonical; the
  hybrid signature over canonical bytes fails; `signatureResult` invalid; exit 2.
- `count-over-2pow53`: base `seg-single-chunk`, `declaredRecordCount` encoded as the JSON
  number `9007199254740993` (above 2^53 - 1); reader rejects the out-of-range number
  form; exit 6.
- `in-range-count-as-string`: base `seg-single-chunk`, `declaredRecordCount` encoded as
  the decimal string `"9831242"` for an in-range value; reader rejects the
  non-canonical string form (section 11.3); exit 6.
- `leading-zero-count`: base `seg-single-chunk`, `declaredRecordCount` edited to the byte
  sequence `01` and re-signed; not valid JSON syntax (a leading zero is not a legal int
  production), so the reader refuses to decode the manifest at all; exit 6 (section 11.3).
- `negative-count`: base `seg-single-chunk`, `declaredRecordCount` encoded as the JSON
  number `-1` and re-signed; a count is non-negative by definition, no leading sign is
  canonical; exit 6 (section 11.3).
- `non-integer-count`: base `seg-single-chunk`, `declaredRecordCount` encoded as the JSON
  number `1.0` and re-signed; a count is an integer literal only, no decimal point or
  exponent form is canonical; exit 6 (section 11.3).
- `secrets-with-compression`: base `secrets-no-dedup`, one secret record set to `codec`
  gzip while a secrets record is present; the reader rejects the forbidden
  secrets-with-compression combination (a `secrets` record MUST have `codec` none,
  section 5.2, 12.4).
- `mixed-codec`: base `seg-multi-segment`, one record's `codec` set to differ from
  `envelope.codec`; reader rejects the codec mismatch (section 5.2); exit 6.
- `missing-break-glass`: base `seg-single-chunk`, the `recipients` set edited to drop the
  break-glass entry (and its capsule wrap) and `breakGlassPresent` set false, re-signed by
  the pinned signer so the signature itself is valid; verified restore still refuses,
  because the break-glass requirement is independent of the signature; exit 2. This proves
  the mandatory-break-glass gate is not merely a signed-claim check.
- `stale-run`: two runs of one downpipe in the RUNLOG, reader pointed at the older run
  which is validly signed and complete but not the latest; reader warns and exits 5
  without `--allow-stale`; with `--allow-stale` it proceeds and records
  `isLatestForDownpipe: false`.
- `runlog-rollback`: two runs in the RUNLOG, then the RUNLOG truncated back to the older
  state and re-signed (a valid older RUNLOG) while the operator supplies
  `--min-runlog-index` equal to the newer index; the RUNLOG maximum index is below the
  pin; reader exits 5 without `--allow-stale` (section 10).
- `runlog-duplicate-index`: a validly signed RUNLOG carrying two entries with the same
  `index` (a hand-assembled log; the account-global counter never reissues an index,
  section 10 anomaly 1). The reader sorts by `index`, detects the duplicate and exits 5
  without `--allow-unverified-runlog`. The duplicated entry uses a synthetic placeholder `runId` that
  is not a canonical ULID, so it also exercises the reader's per-entry `runId` rejection.
- `runlog-forked-prevrunid`: a validly signed RUNLOG where two entries of one downpipe
  carry the same `prevRunId`, a fork that means the chain was rewritten (section 10 anomaly
  3). The reader detects the forked pointer and exits 5 without
  `--allow-unverified-runlog`.
- `runlog-allocation-gap`: a POSITIVE vector. Two runs of one downpipe hold a strided
  account-counter subsequence (`index` 1 then 3) because a failed run of another downpipe
  consumed the intervening `index` without appending an entry. An `index` gap is NOT an
  anomaly (section 10), so the per-downpipe `prevRunId` chain stays linear and a conformant
  reader ACCEPTS the run; `--min-runlog-index 1` is satisfied. A reader that regressed to
  enforcing per-downpipe `index` contiguity would wrongly exit 5, so this vector pins the
  benign-acceptance behaviour.
- `runlog-interleaved-append`: a POSITIVE vector. A validly signed RUNLOG whose lines are
  interleaved relative to `index` (the index-3 entry precedes the index-1 entry), because
  entries land at finalise time and concurrent runs finalise out of allocation order
  (section 10). Line order carries no signal, since the whole-document signature anchors the
  bytes, so a conformant reader sorts by `index` and ACCEPTS the run; a reader that enforced
  append order would wrongly exit 5, which this vector fails closed against.
- `absent-runlog`: base `seg-single-chunk` with `_RECOVERY/RUNLOG` removed; verified mode
  treats the absent RUNLOG as a code-5 condition unless `--allow-unverified-runlog`
  (section 8.7).
- `recovery-bundle-tampered`: base `seg-single-chunk`, the vendored `FORMAT.md` in
  `_RECOVERY/downpipe/0.1.0/` altered so its SHA-384 no longer matches the bundle's
  own `SHA384SUMS` (section 9); a reader relying on the bundled spec/reader fails the
  section 8.7 item-4 check; exit 2 with `recoveryBundleVerified: false`.

### 14.4 Edge vectors

`seg-empty`, `seg-single-chunk`, `seg-multi-chunk`, `seg-multi-segment`, `seg-packed`,
`dedup-same-value-two-runs` and `break-glass-only` from section 14.2 are also the edge
set (empty value, single chunk, multi chunk, multi-segment chain, packed shared frame,
dedup-same-value-across-two-runs-of-one-downpipe, single-recipient posture). The
empty-value versus absent-value distinction (section 12.5) is covered by `seg-empty`
together with the absence of a record for an absent key.

### 14.5 Pinned segmentation bound

So that two independent writers produce identical segment chains for the same large
value under `codec = none`, the segmentation bound is fixed for the major version: a
record is split into segments of at most 16384 downpipe STREAM chunks each
(16384 * 65536 = 1 GiB of plaintext per segment), and the final segment of a record
carries the remainder. A whole-segment `chunkRange` therefore has `lastChunkExclusive`
at most 16384, and a record larger than 1 GiB of stored payload occupies a chain of
segments in order. This bound governs only `codec = none` interop; under `codec = gzip`
segment boundaries fall on the compressed stream and are not cross-writer reproducible
(section 7.5).

### 14.6 Hybrid KEM combiner known-answer vector

`kem-combiner-kat` is a normative known-answer vector that byte-locks the hybrid KEM
combiner of section 4.2 independently of any sealed object, so a second implementer can
validate the combiner before recovering a single archive. It pins the component inputs
and asserts the 32-byte combiner output exactly:

- pinned inputs: the ML-KEM-1024 shared secret `ss_M`, the X25519 shared secret `ss_X`,
  the 32-byte X25519 ephemeral share `ct_X` and the recipient's static 32-byte X25519
  public key `pk_X` (all as raw byte strings);
- the asserted output is the 32-byte hybrid shared secret
  `ss = HKDF-SHA-384(ikm = ss_M || ss_X, salt = (empty), info = "downpipe/0.1.0 hybrid-kem" || 0x00 || ct_X || pk_X, L = 32)`;
- `ct_M` is deliberately NOT a combiner input, since ML-KEM-1024's FO transform already
  binds `ct_M` and the encapsulation key into `ss_M`, so the vector does not pin it.

A conformant implementation MUST reproduce the asserted `ss` byte-for-byte. Because this
construction is ML-KEM-1024 over HKDF-SHA-384 rather than X-Wing's ML-KEM-768 over
SHA3-256, it is interoperable with neither X-Wing nor HPKE-PQ, and this vector is the
authority that pins the difference.

### 14.7 Primitive known-answer vectors

Alongside `kem-combiner-kat`, the corpus pins deterministic primitive known-answer vectors
that byte-lock the underlying algorithms independently of any sealed object, so a second
implementer validates each primitive before recovering an archive:

- `mlkem-kat`: ML-KEM-1024 (FIPS 203) encapsulation and decapsulation against pinned
  inputs, asserting the shared secret and ciphertext byte-for-byte.
- `mldsa-kat`: ML-DSA-87 (FIPS 204) signing and verification against a pinned key and
  message, asserting the verification outcome.
- `crypto-kat`: the SHA-384, HKDF-SHA-384 and HMAC-SHA-384 primitives (section 4) against
  pinned inputs, asserting each digest and derived key byte-for-byte.
- `kem-combiner-kat`: the hybrid KEM combiner of section 4.2 and 14.6, listed here for
  completeness as the fourth deterministic primitive vector.

Each is purely deterministic and a conformant implementation MUST reproduce its asserted
outputs byte-for-byte.

## 15. Compatibility section

This archive is `downpipe/0.1.0`. A reader that implements `downpipe/0.1` reads it at any
patch; a reader that does not implement `0.1` refuses it by name rather than guessing, and
no reader reads it on the strength of a shared major (section 13). The sealed
segments and shard manifests are downpipe envelope files (AES-256-GCM STREAM, sections
7.1 and 7.8), and the per-run master is wrapped to the recipients by the downpipe hybrid
X25519+ML-KEM-1024 KEM-DEM capsule (section 5.4); NONE of these is an age file, and none
is readable by the `age` command line tool or any other off-the-shelf tool, because no
shipping tool offers this post-quantum hybrid suite. The second independent reader that
strengthens recover-without-vendor (D1) is a self-contained, audited reader of the
downpipe `.dpe`/`.seg` format from the open-source MIT downpipe project, alongside this
specification and the normative conformance vectors. Recovery and verification, namely
the manifest hybrid signature, the key commitment, the recipient-set binding,
completeness, freshness and the break-glass requirement, require a conformant downpipe
reader in verified mode (section 8). A recoverer with the bucket bytes and the
offline key uses that reader, or re-implements one from this spec and the
conformance vectors, and recovers and verifies the archive end to end. The frozen version
string `downpipe/0.1.0` appears byte-identically in this header, the cleartext root manifest
`formatVersion`, every encrypted preamble `formatVersion`, the HKDF and MAC labels that
carry a version, and the hybrid-KEM and key-commitment labels.

## 16. Privacy considerations

This section states what the on-disk format exposes to a party who holds only the
destination bucket bytes, and what it deliberately keeps confidential. It complements the
threat model of section 1.1, which states which key-compromise scenarios the format does
and does not defend.

### 16.1 What a bucket-only observer can see

A party with read access to the destination bucket, but without any recipient private key
and without the offline break-glass key, observes only the following.

- The object layout of section 3: the existence of `seg/` objects, the `run/<runId>/`
  trees, the shard `.dpe` objects, the signed root manifests, the recovery bundle and the
  RUNLOG.
- The COUNT and approximate aggregate SIZE of those objects, which are inherent to any
  object-store backup and are not concealed by the format.
- The cleartext root manifest fields of section 5.1, which are deliberately minimal: the
  `formatVersion`, the `runId`, the advisory `createdAt`, the opaque `downpipeId`, the
  envelope algorithm identifiers, the inline recipient PUBLIC keys and their `dpr1:`
  fingerprints and roles, the master capsule wraps, the `recipientSetHash`, the
  `keyCommitment`, the shard hashes, the `declaredRecordCount`, the `merkleRoot` and the
  freshness pointer. None of these is plaintext data.
- The RUNLOG entries of section 10: per-run `index`, `runId`, opaque `downpipeId`, advisory
  `time`, `recordCount`, `prevRunId` and `status`. This reveals backup CADENCE and per-run
  record COUNTS for each opaque downpipe, which is reconnaissance an operator should weigh.

### 16.2 What the format keeps confidential

The reconnaissance metadata that a backup of sensitive infrastructure would otherwise leak
is kept out of the clear and sealed under the manifest subkey, bound by the signature
(sections 5.3, 6.1, 6.2).

- The source block (`source.type`, `namespaceId`, `bucket`, `label` and the include and
  exclude selectors), the crawl `window`, the `consistency` mode, the human downpipe `name`
  and the `cadence` live ENCRYPTED in the shard preamble, never in the cleartext root.
- Every per-record field, the source-native `name`, the `keyNameHash`, the
  `plaintextSize`, the `plaintextSha384`, the per-source descriptor and the segment map,
  lives only inside the encrypted, signed shard manifest.
- `keyNameHash` is a KEYED MAC (HMAC-SHA-384 under a master-derived key, section 6.4), not a
  bare hash, so a bucket-read adversary cannot dictionary-confirm a guessed record name.
- `segId` is a KEYED content address (section 7.2), so a bucket-read adversary without a
  recipient identity cannot compute a segment address from a guessed plaintext, which
  closes the plaintext content-addressing oracle.

### 16.3 Residual privacy exposure and dedup

Some exposure is inherent and is stated honestly rather than hidden.

- The opaque `downpipeId` correlates all runs of one downpipe, which is necessary to scope
  dedup and the `seg/` boundary (section 7.3). It is not, on its own, a human-meaningful
  name.
- Non-secret dedup (section 7.3) is observable where it occurs: repeated content WITHIN a
  run shares one `seg/` object, and for a writer using a stable per-downpipe master an
  unchanged value across runs also maps to one shared object, so an observer can infer that
  some content repeated, without learning what it is. A per-run-master writer (the
  reference engine) shares nothing across runs and does not expose this cross-run inference.
- Secrets never dedup (a fresh `recordSalt` per record, section 7.2 case 0x03), so a
  `secrets` downpipe leaks no equality signal across its records or across runs.
- Object sizes leak an upper bound on plaintext sizes (modulo the GCM tag, the chunk
  framing and any compression). The format does not pad to a fixed size; an operator who
  needs size-obfuscation must arrange it above this layer.

## 17. Reader state diagram

This section is INFORMATIVE. It summarises the verified-restore decision flow that
sections 8.3, 8.6, 8.7, 11.3, 12.5 and 6.3 specify normatively. The exit codes are the
normative set of section 8.5; where this diagram and the body disagree, the body governs.

### 17.1 Verified-restore flow

```
                       +-------------------------------+
   open archive  --->  | parse cleartext root manifest |
                       +-------------------------------+
                                     |
              version not implemented (not downpipe/0.1.x) ----> EXIT 6
              non-canonical count form (SPEC 11.3) ------------> EXIT 6
              codec mismatch / forbidden secrets gzip ---------> EXIT 6
                                     | well-formed downpipe/0.1.0
                                     v
                       +-------------------------------+
                       | verify hybrid signature over  |
                       | canonical root bytes against  |
                       | the operator-supplied --signer|
                       +-------------------------------+
                                     |
              missing / invalid / single-half / wrong-signer:
                   completeness UNVERIFIED -----> EXIT 2
                   (unless --allow-unverified, which proceeds and
                    records the true labels, never laundering them)
                                     | both halves verify
                                     v
                       +-------------------------------+
                       | recompute and constant-time   |
                       | compare the signed values:    |
                       |  - shard stored-byte SHA-384   |
                       |  - merkleRoot (RFC 6962)       |
                       |  - keyCommitment from master   |
                       |  - recipientSetHash + capsule  |
                       |    break-glass binding (8.6)   |
                       +-------------------------------+
                                     |
              any recomputation mismatch / break-glass fail ---> EXIT 2
                                     | all match
                                     v
                       +-------------------------------+
                       | verify the RUNLOG signature   |
                       | and freshness (section 8.7,10)|
                       +-------------------------------+
                                     |
              non-latest, or max index below --min-runlog-index:
                   ----> EXIT 5 (unless --allow-stale)
              absent/truncated/unverifiable RUNLOG, or chain anomaly:
                   ----> EXIT 5 (unless --allow-unverified-runlog)
              (a benign index gap or interleaved line order is
               NOT an anomaly and does not exit)
                                     | fresh and signed
                                     v
                       +-------------------------------+
                       | reassemble each record and    |
                       | verify full-record            |
                       | plaintextSha384, then coverage |
                       | against declaredRecordCount    |
                       +-------------------------------+
                                     |
              a per-record plaintextSha384 mismatch ----------> EXIT 4
              readable coverage below declaredRecordCount ----> EXIT 3
                   (vanished-mid-crawl records are excluded
                    from the denominator, section 12.5)
                                     | complete and verified
                                     v
                                  EXIT 0
                          (signed restore receipt, section 8.5)
```

### 17.2 RUNLOG entry status

A RUNLOG entry's `status` (section 10, 10.1) moves in one direction only.

```
   active  -- run/<runId>/ tree pruned (manifest-driven, section 10.1) -->  superseded
```

A `superseded` entry is RETAINED in the RUNLOG so each downpipe's `prevRunId` chain stays
linear; it is never deleted, so a reader walking the chain past a pruned run does not see a
false rollback.

## 18. References

### 18.1 Normative references

These define behaviour a conformant implementation MUST follow.

- [BCP 14] RFC 2119 and RFC 8174, the requirements-language key words used in this document.
- [RFC 8785] JSON Canonicalisation Scheme (JCS), the canonical-JSON encoding of section 11.1.
- [RFC 3339] Date and Time on the Internet, the UTC timestamp form of section 11.5.
- [RFC 7748] Elliptic Curves for Security (X25519), with the all-zero shared-secret abort of
  section 4.1.
- [RFC 6962] Certificate Transparency, the Merkle leaf and node hashing of section 11.8.
- [RFC 5869] HKDF, the HKDF-SHA-384 key derivation used throughout (section 4, 11.7).
- [RFC 2104] HMAC, the HMAC-SHA-384 keyed MAC and key commitment (sections 6.4, 7.2, 8.4).
- [FIPS 180-4] Secure Hash Standard, SHA-384.
- [FIPS 197] and [NIST SP 800-38D] AES and GCM, the AES-256-GCM AEAD of section 7.8.
- [FIPS 203] ML-KEM, the ML-KEM-1024 half of the hybrid KEM (section 4).
- [FIPS 204] ML-DSA, the ML-DSA-87 half of the hybrid signature (section 8).
- [Crockford base32] the ULID text alphabet of section 11.6.
- The downpipe conformance vectors under `internal/format/testdata/vectors/` (section 14),
  which are themselves normative.

### 18.2 Informative references

These give context and do not constrain a conformant implementation.

- [X-Wing] draft-connolly-cfrg-xwing-kem, whose bound value set the downpipe combiner of
  section 4.2 mirrors. The downpipe combiner is NOT X-Wing (it is ML-KEM-1024 over
  HKDF-SHA-384, not ML-KEM-768 over SHA3-256) and is interoperable with neither X-Wing nor
  draft-ietf-hpke-pq.
- [CNSA 2.0] the NSA Commercial National Security Algorithm Suite 2.0, the post-quantum
  algorithm-selection guidance the construction of section 4 is described as grade-aligned
  with. It is context only and constrains nothing in this document.
- [age] the `age` file-encryption tool. The downpipe envelope is explicitly NOT an age file
  and is not readable by `age`; the references here are only to state that non-relationship.
- `docs/format/schema.json`, the informative machine-readable JSON Schema for the cleartext
  and decrypted JSON shapes; this document and the vectors govern on any disagreement.
