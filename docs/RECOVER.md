# Recovering a downpipe archive offline

This is the recovery walkthrough for the holder of a downpipe destination bucket
and the offline break-glass key. It covers the case the format is built for:
recovering the data with neither Cloudflare nor the vendor available.

It is the operator-facing companion to the in-bucket recovery sheet. Every archive
also ships a versioned `_RECOVERY/<formatVersion>/FORMAT.md` pointer and a short
`RECOVER.md` next to the data, with a signed `SHA384SUMS` so you can confirm the
instructions were not altered. The authoritative specification, the conformance
vectors and the MIT reader are this open-source project; keep a copy alongside your
recovery key, or re-implement a clean-room reader from the spec and the vectors.

## What you need

Recovery needs the bucket bytes, the break-glass key and a pinned signer.

- The destination bucket bytes. This is the whole `<root>/` tree on the
  destination (an S3-compatible bucket such as R2, Amazon S3, Google Cloud
  Storage, Backblaze B2, Wasabi or MinIO, or an Azure Blob container) or a copy
  of it on local disk. It already contains the encrypted data, the encrypted
  manifests, the per-recipient master capsule, the freshness anchor, and the signed
  recovery bundle (the versioned FORMAT.md pointer and RECOVER.md). From engine 0.3.7
  the bundle also carries `signer.pub`, the public key of the current operator signer.
  Every run overwrites it.
- `identity.key`, the offline break-glass private key, from wherever you keep it.
  It never reaches the vendor or Cloudflare. If you hold it as an M-of-N custody
  quorum instead, the shares go straight to the same command (`--share` with
  `--envelope`) and no complete key is written to disk.
- A pinned signer. The reader verifies every signature against an operator signer
  that you pin. It never uses the manifest's own self-asserted hint. You pin the signer
  in one of two ways:
  - `--signer-fingerprint` with the `signer:` fingerprint from your printed recovery
    sheet (from reader 0.3.4). The reader reads the `signer.pub` copy in the bucket's
    recovery bundle and uses it only if its fingerprint equals the value you pass. The
    trust anchor is your offline sheet, not the bucket. A copy that someone replaced
    has a different fingerprint, and the reader refuses it (exit 2).
  - `--signer` with `signer.pub`, the file the key ceremony downloaded into your
    recovery kit. This works with every archive and every reader release.

**The printed recovery sheet carries fingerprints, not keys.** It lists the
`edmldsa1:` signer fingerprint, the `dpr1:` break-glass and operational recipient
fingerprints, the custody sign-off, and the anti-rollback high-water mark you fill in
by hand. A signer public key is about 3.5 KB of base64, so nobody retypes one off
paper. The signer fingerprint is short enough to copy, and `--signer-fingerprint`
makes it a usable input when the bucket carries the right `signer.pub`.

The bucket keeps one copy, the current signer's. So the fingerprint route does not
work in two cases:

- No engine 0.3.7 or later has written to the bucket. Then the bucket has no copy, and
  the reader exits 6.
- The run was sealed by a signer that you have since rotated (a re-key). Then the copy
  is the new signer's. Your old sheet's fingerprint refuses it (exit 2), and the new
  sheet's fingerprint accepts it but the old run then fails verification.

**In those cases, a kit holding only the printed sheet and `identity.key` cannot
verify or restore**, because `verify` and `restore` refuse to run without a pinned
signer (exit 6). Keep `signer.pub` from the key ceremony with your kit, and keep the
old one after a re-key, so that every archive stays recoverable.

What the sheet is for is confirming that the files you hold are the right ones. Ask
the reader to fingerprint them and compare each line against the sheet:

```
downpipe keys --fingerprint --identity ./keys/identity.key --signer ./keys/signer.pub
```

That reads no archive and makes no network call, so it works with the kit alone. The
identity's fingerprint should also appear in `downpipe keys --which` for the archive
you are recovering, and the signer's should match the `signer:` line `downpipe
inspect` prints for the run. A mismatch means the file is from a different ceremony.

You do not need the vendor, the Cloudflare account, the live engine or any
network service. The reader imports no telemetry and no vendor SDK, so the
recovery path cannot call home.

## Get a reader you trust

The downpipe envelope is post-quantum hybrid and is interoperable with nothing
off the shelf, so there is no third-party command line that opens a `.seg`. You
recover with a conformant reader of the downpipe format. There are two ways to
obtain one, and either is enough.

- Use the open-source MIT reader. This tool (`downpipe`) is MIT-licensed and
  public; keep a copy alongside your recovery key so a reader is always to hand.
  The bundle's `SHA384SUMS` is signed (`SHA384SUMS.sig`), so before you trust the
  in-bucket FORMAT.md and RECOVER.md you can confirm them against your pinned signer
  with `verify --check-bundle`. The recovery sheet does not carry a bundle hash, so
  this check needs a pinned signer: `--signer` with your `signer.pub`, or
  `--signer-fingerprint` with the fingerprint from your sheet.
- Re-implement from the specification and the vectors. The format is defined by
  [`docs/format/SPEC.md`](format/SPEC.md) and the normative conformance vectors
  described in [`docs/format/CONFORMANCE.md`](format/CONFORMANCE.md). A second
  implementation that recovers every positive vector and rejects every negative
  vector is a conformant reader, so the bucket is recoverable with a clean-room
  reader built from the open spec and vectors, with no vendor and no Cloudflare.

The remainder of this walkthrough uses the reader in this repository.

```
go build ./cmd/downpipe
```

Every dependency is vendored, so that build downloads no module. The one thing it
needs of the outside world is the toolchain: `go.mod` pins `toolchain go1.26.6`,
and under Go's default `GOTOOLCHAIN=auto` a machine whose installed `go` is older
than the pin fetches that toolchain before it compiles anything. On a disconnected
machine that download fails, and the build exits 1. Check `go version` against the
pin before you need it. If the machine you are recovering on cannot meet the pin and
cannot reach a proxy, `GOTOOLCHAIN=local` builds with the Go you have, if it is
go1.26.0 or later (the `go` line in `go.mod`). You then lose the pin's
security-patch guarantee.

## Recover end to end

Point the reader at the bucket bytes and at the run you want back. A `runId` is
the canonical 26-character identifier of one backup run. Ask the archive which runs
it holds, which needs no key of any kind:

```
downpipe keys --which --archive ./bucket
```

That lists every run in the archive, grouped by the recipient identity that opens
it, so it answers "which runs are here" and "which of my key files opens them" in
one step. Listing the `run/` prefix on the destination gives the same run ids if you
would rather read them off the bucket directly. `inspect` below does not answer this
question, because it takes a `runId` as input.

If a run's root manifest cannot be read, or you passed `--signer` and its signature
does not verify, that run is left out of the index and the summary line says so:

```
0 run(s) across 0 recipient identit(ies) [signer-verified, INCOMPLETE]:
(1 further run(s) in the RUNLOG could NOT be read or verified and are missing from
this index; the reason for each is on stderr. ...)
```

The command exits `2` in that case. Treat the listing as a partial answer: a key
that opens only the excluded runs will not appear at all, so do not conclude from
an incomplete index that a key file you hold is unnecessary.

Before you run `verify` or `restore`, read the latest trusted RUNLOG index off
your recovery sheet's anti-rollback line and pass it as `--min-runlog-index <n>`.
Without it, a bucket that has been rolled back to an older, validly signed run
still verifies and restores cleanly: `--min-runlog-index` is the out-of-band
reference point that catches a tail rollback the archive cannot flag on its own.
Omit it and the reader still runs, but it prints a stderr warning naming the flag
and what it protects, every time, so the gap cannot pass unnoticed; see
"Freshness / rollback (exit 5)" below.

Reading from a local copy of the bucket tree:

```
downpipe inspect --archive ./bucket --run <runId>

downpipe verify  --archive ./bucket --run <runId> \
    --identity ./keys/identity.key --signer ./keys/signer.pub \
    --min-runlog-index <n>

downpipe restore --apply --archive ./bucket --run <runId> \
    --identity ./keys/identity.key --signer ./keys/signer.pub \
    --min-runlog-index <n> --out ./restored
```

If you do not hold `signer.pub`, pin the bundled copy with the fingerprint from your
sheet instead. This needs reader 0.3.4 or later, and a bucket that an engine 0.3.7 or
later has written to since the signer that sealed the run became current.
`<signerFingerprint>` is the whole `signer:` value on your sheet, starting
`edmldsa1:`:

```
downpipe verify  --archive ./bucket --run <runId> \
    --identity ./keys/identity.key --signer-fingerprint <signerFingerprint> \
    --min-runlog-index <n>

downpipe restore --apply --archive ./bucket --run <runId> \
    --identity ./keys/identity.key --signer-fingerprint <signerFingerprint> \
    --min-runlog-index <n> --out ./restored
```

`--apply` is the flag that writes. Leave it off and `restore` plans the writes,
reports any conflict with what is already in the target, exits 0 and creates
nothing, so run it once without `--apply` to read the plan and again with it to
get your data back.

Reading straight from an S3-compatible destination instead of a local copy, with
credentials in `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`:

```
downpipe restore --apply --s3-endpoint https://<account>.r2.cloudflarestorage.com \
    --s3-bucket <bucket> --run <runId> \
    --identity ./keys/identity.key --signer ./keys/signer.pub \
    --min-runlog-index <n> --out ./restored
```

Azure Blob Storage is not an S3-compatible store: it has its own wire protocol and
its own authentication, so `--s3-endpoint` cannot reach an Azure container at any
value. It has its own flag pair, and credentials come from `AZURE_STORAGE_KEY` (a
storage account access key) or `AZURE_STORAGE_SAS_TOKEN` (a shared access
signature):

```
downpipe restore --apply --azure-endpoint https://<account>.blob.core.windows.net \
    --azure-container <container> --run <runId> \
    --identity ./keys/identity.key --signer ./keys/signer.pub \
    --min-runlog-index <n> --out ./restored
```

The account name is read from the endpoint's first label. Set
`AZURE_STORAGE_ACCOUNT` as well only when it is not, which is the case for a
custom domain in front of the account. Set exactly one of the two credentials: the
reader refuses both at once rather than choosing between them, because an operator
who has set two has one of them wrong.

What each step does.

- `inspect` reads the cleartext bootstrap manifest and shows what the run holds.
  It needs no identity, so it is a safe first look before you decrypt anything.
- `verify` recovers the run master from the master capsule using the break-glass
  identity, derives every file key from it, and checks the signed metadata: the
  hybrid signature against the supplied signer, every shard's hash, the recipient
  set and the break-glass binding, the key commitment, the Merkle root over every
  record hash, the declared record count and the RUNLOG freshness. This proves the
  signed manifests are authentic and internally consistent: the manifest set
  commits to each record's plaintext hash and nothing has been added, dropped or
  re-ordered. It does **not** read or decrypt the `seg/` data objects, so a plain
  `verify` will **not** detect a corrupted or tampered data segment: the bytes in
  the bucket are checked only on the decrypt path. To prove the data bytes
  themselves still recover, add `--deep` (or run `restore --sink discard`), which
  decrypts and hash-verifies every record and writes nothing. Treat
  `verify --deep` / `restore --sink discard` as the canonical offline integrity
  drill: it is the only check that authenticates the segment bytes without
  materialising a single plaintext value, so it is safe to run on a machine that
  must not hold the recovered secrets.
- `verify --deep` does everything `verify` does and then runs the full decrypt path
  over every record (the same path `restore` uses), streaming each value so a value
  larger than memory is verified in bounded memory. It writes nothing. A tampered
  segment fails its AEAD tag here and the command exits with the per-record code
  (2 for an AEAD/structural failure, 4 for a plaintext-hash mismatch).
- `restore` runs the same checks and then reassembles each record's value and
  verifies it against its signed plaintext hash as it writes the values out, so a
  per-record mismatch is caught here and exits 4. It writes only with `--apply`.
  Without it, the manifest checks still run, but no value is decrypted, so the
  per-record hash check does not run and the result is a plan rather than a
  restore. With `--sink file` (the default) an applied restore writes to `--out`;
  `--sink env` is available for scripted recovery, and `--sink discard` decrypts
  and verifies every record while writing nothing (the restorability drill).

## What restores turnkey offline, and what needs re-provisioning

Offline restore always writes verified bytes for every record. The reader decrypts
each value, checks it against its signed plaintext hash, and writes the result out.
That is true for all source types, including the ones below that you cannot blindly
re-apply.

What differs is what those verified bytes are. For some source types the bytes are
the live value and writing them is the restore. For others the bytes are a snapshot
you re-provision deliberately, because a blind re-apply from a backup could brick a
live service or silently diverge from it. The reader never re-applies those itself;
it surfaces the verified bytes and the re-provision guidance and leaves the live
change to you. For three source types the backup is an inventory by default: the
per-item metadata recovers. The binaries recover only when the downpipe's File contents
option is on, and only up to its size limit.

The table is keyed on the source type recorded in each record. The first group is a
direct value write; the second is re-provision; the third recovers an inventory, plus
the binaries when File contents is on.

| Source type | Offline restore | What you get back |
| --- | --- | --- |
| `kv` | Turnkey. Direct value write. | The verified value, written to the file or env target ready to re-apply. On the file sink, a key's metadata and expiration go in a sidecar next to the value (see [Source metadata](#source-metadata-kv-and-r2)). The env sink cannot keep them, and the restore prints a WARNING for each key that carries them. |
| `r2` | Turnkey. Direct value write, streamed for large values. | The verified object bytes. A value larger than memory is written through the streaming sink, so a large object restores in bounded memory on a constrained machine. On the file sink, the object's HTTP metadata (for example its content type) and its custom metadata go in a sidecar next to the bytes (see [Source metadata](#source-metadata-kv-and-r2)). Set them from the sidecar when you upload the object. |
| `secrets` | Turnkey. Direct value write. | The verified secret value, written to the file or env target. Per-Worker secret values that were never captured (only their names and types) are re-provisioned under the `workers` row. |
| `d1` | Turnkey bytes, manual replay. | A verified SQLite-compatible dump (`wrangler d1 export` format). On the file sink the reader writes each d1 record with a `.sql` suffix so you can apply it turnkey: `sqlite3 restored.sqlite < <db>/00-header.sql` (then each `10-rows/*` page and `20-schema.sql` in name order, or the single `<db>.sql` for a legacy whole-dump), then `wrangler d1 execute <DB_NAME> --file=<file>.sql`. Apply to a NEW database and cut over deliberately; it is not an automatic in-place database rebuild. |
| `workers` | Re-provision. | Re-deploy the script from the verified content snapshot (wrangler deploy or the Workers API), then apply its settings record. The offline tool never blind-redeploys a Worker. A `secrets` binding's value was never captured; the settings checklist lists the names and types to re-provision. |
| `cf-config` | Re-provision. | Replay the surface from the verified snapshot through the Cloudflare API, or re-apply an idempotent surface in the console with an edit-scoped token. The offline tool never blindly re-applies a configuration surface. |
| `stream` | Inventory, plus binaries with File contents on. | The verified per-video metadata (name, requireSignedURLs, allowed origins, user meta) recovers. With File contents on, the video files and caption tracks also recover as verified bytes. Re-upload the binaries from those files or from your source of truth, then replay each video's verified configuration through the Stream API. |
| `images` | Inventory, plus binaries with File contents on. | The verified per-image metadata and the account-level variant definitions recover. With File contents on, the image files also recover as verified bytes. Re-upload the binaries from those files or from your source of truth, then replay the metadata and variants through the Images API. |
| `artifacts` | Inventory, plus binaries with File contents on. | The verified namespace and repository inventory recovers. With File contents on, the git commits, trees and file blobs also recover as verified bytes. Re-create the namespaces and repositories, then re-push the contents from your source of truth. |

The distinction is whether the verified bytes are a live re-apply or a snapshot you
re-provision. It is never a difference in what was proven: every type's bytes are
decrypted and hash-verified the same way.

### Source metadata (KV and R2)

A `kv` record can carry the key's metadata and its expiration. An `r2` record can carry
the object's HTTP metadata and its custom metadata. The archive holds them in the
record's `kv` or `r2` descriptor (`docs/format/SPEC.md` 6.2). The offline reader does not
write to KV or R2, so it cannot apply them to a live binding. It keeps them for you
instead:

- **File sink.** For each restored record that carries metadata, the reader writes a
  sidecar file next to the value. Its name is the value's path plus
  `.downpipe-meta.json`. For example, `img/logo.png` gets `img/logo.png.downpipe-meta.json`.
  A record without metadata gets no sidecar. The restore summary prints how many
  sidecars it wrote.
- **Env sink.** A dotenv line has no place for metadata. The restore prints a
  `WARNING metadata NOT kept` line for each record that carries metadata, and a
  `WARNING:` count line. The values are still restored.
- **Discard sink.** It writes nothing, so there is no metadata to keep or lose.

A sidecar is one JSON object on one line, followed by a newline. Its fields are:

| Field | Meaning |
| --- | --- |
| `format` | Always `downpipe-restore-metadata/1`. Check it before you read the rest. A new shape gets a new label. |
| `sourceType` | `kv` or `r2`. |
| `namespace` | The KV namespace, for a `kv` record. |
| `bucket` | The R2 bucket, for an `r2` record. |
| `name` | The source-native name: the KV key or the R2 object key. Use it when you put the value back. The file path can differ, because the reader drops empty, `.` and `..` path elements. |
| `plaintextSha384` | The SHA-384 of the value, as the signed manifest records it. Check it against the file next to the sidecar. |
| `kv` | `{metadata, expiration}` exactly as the record carries them. `metadata` is opaque JSON. `expiration` is an absolute Unix time in seconds, present only for an expiring key. |
| `r2` | `{httpMetadata, customMetadata}` exactly as the record carries them. |

Example, for an R2 object:

```json
{"format":"downpipe-restore-metadata/1","sourceType":"r2","bucket":"media","name":"docs/report.txt","plaintextSha384":"36ca…","r2":{"httpMetadata":{"contentType":"text/plain","cacheControl":"max-age=3600"},"customMetadata":{"team":"ops"}}}
```

Apply the metadata unchanged when you put the value back, for example as the
`metadata` and `expiration` of a KV `put`, or the `httpMetadata` and `customMetadata`
of an R2 `put`. KV refuses an expiration that has already passed; drop it or choose a
new one. The reader never acts on the contents of the metadata.

A sidecar follows the same no-clobber rule as a value. The reader creates it with
owner-only permissions and never overwrites a file that is already there. If it cannot
write a sidecar (for example because a file already sits at that path), it still
restores the value, and it prints the `WARNING metadata NOT kept` line with the reason.
In the plan, a record whose own path is another record's sidecar path is a
`collision`, so one never overwrites the other.

An archive does not change. The metadata stays in the archive, and a later restore can
write it again.

## How the master capsule lets break-glass alone recover

The run master is a fresh per-run secret from which every file key is derived. It
is wrapped to each recipient once, in the master capsule in the cleartext root
manifest. The break-glass recipient is always one of them. Decapsulating the
break-glass wrap with the offline break-glass identity yields the master, and from
the master the reader derives the keys for the manifests and every data segment.
No other key and no vendor step is involved.

Two postures exist, and your recovery sheet records which one a downpipe uses.

- Default posture. The run is wrapped to both an in-account operational recipient
  and the offline break-glass recipient. Either opens the capsule. The operational
  key gives the live account a read-back and verification path; the break-glass key
  is the offsite, vendor-independent path.
- Break-glass-only posture. The run is wrapped to the break-glass recipient alone.
  Only the offline key can open the archive, so even a full compromise of the
  Cloudflare account yields no key that decrypts the data. The break-glass key may
  be split across several offline holders. What this posture removes is the engine's
  ability to reopen a sealed run on its own, so the unattended work stops: scheduled
  restore tests, the automated drill, and in-account retention pruning. Verification at
  seal and the hourly canary keep running, because both use that run's own single-run
  key rather than a stored one. Recovery itself has two paths. The console's break-glass
  restore takes your key in the browser and derives that run's key there. Only that one
  run's key goes to the engine. Your break-glass key never leaves the browser, and the
  browser clears both keys when you leave the panel. This walkthrough is the other path,
  and the one that still works when the platform itself is unreachable.

## Reading the result

`verify` and `restore` finish with an exit code that says exactly what was proven.
The normative set is:

- `0`: verified and complete.
- `2`: completeness unverified (a missing, invalid, single-half or wrong-signer
  signature, a failed integrity recomputation, or a failed break-glass or
  recovery-bundle check) and `--allow-unverified` was not given.
- `3`: incomplete coverage below the run's declared record count.
- `4`: a per-record plaintext hash mismatch.
- `5`: a freshness problem, and the acknowledgement it needs was not given. A
  stale run or an index below your `--min-runlog-index` pin needs `--allow-stale`.
  A RUNLOG that is absent, truncated, unparseable, fails its signature, does not
  carry this run, contradicts the signed root manifest or contradicts itself needs
  `--allow-unverified-runlog`, because none of those established an age for
  `--allow-stale` to acknowledge.
- `6`: a usage or input error.

Outside that normative set there is an ADVISORY family. Each one means the restore ran
and fell short of a clean full restore, so a script must not read a non-zero exit as
failure without reading which code it was. `10` means one or more records were not
written because the target could not take them, so they are in the archive and not on
your disk. `8` means one or more records landed carrying an incompleteness-marker
placeholder rather than the source's data, because the source was only partly available
when the backup ran. `12` means one or more D1 records carry a body format this release
cannot render: the verified bytes were written unchanged and are NOT SQL, so the `sqlite3`
replay step does not apply to those files, and a downpipe release that reads the label
named against each record renders them. They are not ranked by their numbers, and `10` is
the largest gap of the three. `9` is a custody failure rather than a restore shortfall:
the shares or envelope are wrong, so no key was recovered and nothing was read. `7` is the
provisioner's preflight and does not arise on a recovery.

Also outside that normative set, `13` means this copy of the archive is short of data
objects its own signed manifests name. The manifests all verified, and one or more of the
`seg/` objects they point at are not in the bucket tree, so nothing was retrieved for
those records and no signature, authentication tag or hash failed anywhere. It is kept
apart from `2` because the two ask opposite things of you: `13` says fetch the named
objects from another copy of the bucket, or accept that this copy is incomplete, while `2`
says the bytes you already hold were altered and this copy must not be trusted. Being told
the data is corrupt when it is merely absent is the worse of the two mistakes, because it
points you away from the replica that would have restored you. `13` is returned only when
EVERY per-record failure was an absent object; one altered record alongside them returns
`2` or `4`, because a real integrity finding always takes precedence. The receipt
carries the same finding as a count, `danglingSegments`, alongside a completeness of
`incomplete`.

Also outside that normative set, `11` means the destination could not be reached at all: a
network or DNS failure, a refused connection, or the destination returning a non-2xx
status (403/404/5xx) before any bytes came back. This is deliberately kept apart from
`2`: code `2` means the bytes were retrieved and then failed to verify (a real reason to
stop and treat the archive as suspect); code `11` means the bytes were never retrieved at
all, so nothing is yet known about the archive, and the right response is to check the
endpoint, bucket and credentials and retry, not to escalate. A read failure the tool
cannot positively attribute to the destination keeps whichever code it already carried
(most often `2`), the safer default when it is genuinely unclear which case applies.

`inspect`, `keys` and `prune` read the same `--s3-endpoint` and `--azure-endpoint`
destinations and honour exit
`11` on the same boundary: a network or DNS failure or a non-2xx status before any bytes
arrived exits `11` there too. They are diagnostic and retention commands rather than
verifiers, and none of them writes the signed restore receipt. Their other exit codes:

- `inspect` exits `1` (unclassified) or `6` (usage). With `--identity` and `--signer` it
  opens the run, and a run that does not open exits with the code of that failure, such
  as `2`.
- `keys` exits `1` or `6` on the same terms. With `--which` it exits `5` when it cannot
  read or parse the RUNLOG, or, with `--signer`, cannot verify it. It exits `2` when one
  or more runs could not be read or verified.
- `prune` exits `1` or `6` on the same terms. It exits `2` when the RUNLOG signature does
  not verify against `--signer`, or when it abstains from deleting because a retained run
  could not be opened and fully read.

`prune --apply` exits `14` when the pass ran and one or more objects it planned to delete
are still in the destination. The report says why, and counts two cases apart. A delete the
destination REFUSED means it answered and said no. The cause is a lock on the object or a
permission the credential lacks. The tool names a lock only when the destination's own answer
names one. A delete that FAILED got no usable answer, such as a network fault or a server
error, and running prune again retries it. A run whose segment was not deleted keeps its run
tree for that pass, because the tree is how a later prune finds the segment. A dry run never
exits `14`. The receipt carries the same counts as `refusedCount`, `refusedLockNamedCount`,
`failedCount` and `heldRunObjects`.

A signed, machine-readable restore receipt records the same outcome in detail;
write one with `--receipt <path>` and, if you hold a signer private-key file, sign it
with `--receipt-signer <path>`.

## Recovering bytes when something is wrong

Verified, complete restore is the default and is what you should rely on. If a
signature does not check out, or the run is signed by a key you cannot reconcile
with your recovery sheet, you can still pull the physically present, authenticated
bytes back with `--allow-unverified`. This
keeps a key-management slip from becoming total data loss, but it is not verified
restore: the bytes are decrypted and authenticated by the envelope, yet the run is
not proven whole or genuine, and the receipt records the true unverified outcome
rather than presenting it as verified. Treat an `--allow-unverified` recovery as
a salvage path, not as a clean restore.

It is not a way around a missing kit file, and it must not be reached for as one.
`--allow-unverified` does not waive the pinned signer: with neither `--signer` nor
`--signer-fingerprint`, `restore` and `verify` still exit 6 with it passed, because
the flag relaxes the VERDICT on an archive that was read, not the inputs needed to
read one. It does not accept a bundled `signer.pub` that fails the fingerprint check
either. It does not waive
`--identity` either, since nothing decrypts without the break-glass key. Nor does
it rescue a tampered data segment: a flipped ciphertext byte fails its AEAD tag on
the decrypt path, so the record is reported as failed, nothing is written for it,
and the command still exits 2.

`--allow-stale` is the matching acknowledgement for this run's AGE alone. It lets
you restore a run the RUNLOG flags as not the latest, or one whose log maximum is
below your `--min-runlog-index` pin, which is sometimes exactly what you want,
while still surfacing that the run is not current. It does not suppress an
integrity, completeness or plaintext failure.

It also does not waive anything about the RUNLOG itself. The word means "I know
this run is old, proceed anyway". An old run and an untrusted RUNLOG need two
different permissions, so they have two different flags. `--allow-unverified-runlog`
is the one that waives the RUNLOG's signature, presence and self-consistency, and
it says so in its own help text. When the reader refuses at exit `5` over a RUNLOG
it could read, it names which of the two reaches the state you are in.

### The anti-rollback pin defaults to off, and says so

`--min-runlog-index` defaults to `0`, which means no pin: `verify` and `restore`
still check the RUNLOG signature and that the restored run is the latest entry the
RUNLOG itself contains, but they have no external reference point, so a bucket
that has been wholesale-replaced with an older, validly signed, internally
consistent RUNLOG (a tail rollback) verifies and restores cleanly. This is not an
error; a first recovery, before any recovery sheet
entry exists to pin against, is a real case the tool must not block. Instead, every
`verify` and `restore` run without `--min-runlog-index` prints a one-line warning
to stderr naming the missing flag, why it matters, and what to pass instead;
stdout, and the receipt's `minIndexPinned` field, are unaffected. If you are
certain this is a genuine first recovery with no recovery sheet entry yet, pass
`--acknowledge-no-rollback-pin` to silence the reminder; it silences the stderr
line only, it does not turn the check on, and the receipt still records the pin as
unset.

### Freshness / rollback (exit 5)

An exit `5` is the **anti-rollback freshness check**, not a decryption or integrity
failure. The bytes are intact. The check compares this run with the account-wide
RUNLOG, and each kind of finding below needs its own acknowledgement.

**The run is not the latest.** The RUNLOG verified against your pinned signer and is
consistent. It says that this run is not the latest for its downpipe, or that the log's
maximum index is below your `--min-runlog-index` pin. This is the expected result when
you ask for an older run on purpose. The run still **decrypts, authenticates and
verifies**; the freshness check is the only thing complaining. The intended recovery is
to **re-run with `--allow-stale`**:

```
downpipe restore --run <run-id> --identity identity.key --signer signer.pub \
  --archive ./bucket --sink file --out ./restored --apply --allow-stale
```

`--allow-stale` deliberately waives the anti-rollback guarantee for this one restore and
records that it did, so the receipt stays honest. Use it for a known multi-run history.
If you cannot explain why the run is not the latest, treat the exit `5` as a real
rollback signal and investigate before waiving it.

**A second cause is not benign, and it reads differently.** The first is a check that
RAN and found an older run. The second is a check that could not run at all, so nothing
was established about this run's recency, and `--allow-stale` does not reach it: the flag
above acknowledges an age, and here no age was measured. The acknowledgement for this
family is `--allow-unverified-runlog`. It covers a `_RECOVERY/RUNLOG` that is absent,
unreadable, unparseable or empty, one whose detached signature does not verify against
your pinned signer, and one that is validly signed and still does not carry this run or
disagrees with the signed root about the run's downpipe, index or `prevRunId`.

You do not have to work out which of those you have. The tool names the one it found, in
its own words, on both paths. Without an override, at exit `5`:

```
downpipe: the anti-rollback/freshness check could not be run: runlog index 7 disagrees
with the signed root 1
downpipe: this is the anti-rollback freshness check, and the line above says it could not
be run at all, so nothing was established about this run's recency. --allow-stale does not
cover this and will refuse again: it is an age word, and no age was measured. The
acknowledgement here is --allow-unverified-runlog, which waives that check rather than
satisfying it, ...
```

and with `--allow-unverified-runlog` or `--allow-unverified`, at exit `0`:

```
warning: this run's anti-rollback/freshness check COULD NOT BE RUN and was overridden
by --allow-unverified-runlog or --allow-unverified: runlog index 7 disagrees with the
signed root 1. Nothing was established about this run's recency, ...
```

**And a third, between the two.** A RUNLOG can verify against your pinned signer and still
contradict itself: an index the account-global counter never reissues appearing twice, a
break in a downpipe's `prevRunId` linearity, or a dangling or forked `prevRunId`. The check
RAN, so this is not the second case, and it says nothing about the run's age, so
`--allow-stale` does not reach it either. Either someone rewrote or hand-assembled the log,
or the engine's run state was reset while the bucket kept its RUNLOG, so new runs reused
its indices. Which run is latest cannot be read from it. `--allow-unverified-runlog` is the
acknowledgement, and compare the log against a copy you trust before you act on the
outcome.

The receipt records `"freshness": { "checked": false, "rollbackWarning": true, ... }`, and
`checked` is the field that separates the second case from a check that ran and found a
stale run.
A bucket someone has rolled back or replaced wholesale looks exactly like this. Re-check
the run against a RUNLOG and signature from a copy you trust before you act on the
outcome. If you must proceed regardless, note in your records that the run's recency is
unestablished rather than confirmed.

## Confirming the bucket can be read

The promise is only worth anything if it is exercised. Run an offline drill on a
schedule: recover the master from a run with the break-glass identity on an
isolated machine and verify the run end to end with `verify --deep` (or
`restore --sink discard`), which decrypts and hash-verifies **every** record's
segment bytes and writes nothing, then keep the receipt (add `--receipt-signer` with the
signer private-key file to sign it). A plain `verify`
is not a sufficient drill: it authenticates the signed manifests but never reads
the `seg/` data objects, so it cannot detect a corrupted or tampered data segment
only the deep decrypt path does. A drill that uses the operational key does not
prove break-glass recoverability, so a genuine drill uses the break-glass
identity. This is the only test that proves, rather than assumes, that the bucket
bytes and the offline key are enough on their own.
