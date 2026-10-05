# Released generation `downpipe/0.1.0`

Directories here only accumulate: never delete one, never regenerate one.

This directory holds one archive in the `downpipe/0.1.0` format, sealed by engine 0.3.5, the engine release published as tag `v0.3.5` (commit `de281e6b` in the public engine repository). The sealing checkout was the engine's own history at that release. Its `src/` tree matches the tag line for line, apart from comments.

The archive is a statement about what a released writer put on disk. Every later reader must open it, so the bytes stay exactly as they were sealed.

## What it holds

- `archive/` is the destination bucket as the engine left it: `run/`, `seg/` and `_RECOVERY/`, including the signed RUNLOG and the recovery bundle.
- `identity.key` is the break-glass identity and `signer.pub` is the signer public key, in the reader's labelled key-file format. Both are throwaway keys minted for this fixture. They protect nothing else.
- `expected.json` lists every record the engine sealed: its source type, name, size and plaintext SHA-384. The values come from the source data before sealing, so a reader is graded against the writer's input and never against what it read back.

One downpipe, two runs, chained through the RUNLOG and each run's signed `prevRunId`:

- Run `01K6400000FXTRGEN010000001` (index 1, 18 records) was sealed by the buffered pipeline. It holds KV records with metadata and an expiry, R2 objects with HTTP and custom metadata, one R2 object sealed as a single streamed segment, a D1 database as header, row-page and schema records, a salted secrets record with its wiring, one record for each API source type (`cf-config`, `workers`, `stream`, `images`, `artifacts`) and a `_vanished` incompleteness marker.
- Run `01K6400000FXTRGEN010000002` (index 2, 4 records, the latest) was sealed by the sliced seal, the engine's default path. It has two manifest shards, and its largest R2 object is a chained record of four segments.

## How it was sealed

From the engine release checkout, with Node 26:

```
node test/seal-released-fixture.ts <this directory>
```

The script is `test/seal-released-fixture.ts` in the engine repository, SHA-256 `c48c9a1ee010a733fdb4c601df4d3cf327201a440e0609ba33ca194cabeee552`, and it refuses to write into a directory that already exists.

## What reads it

- `go test ./cmd/downpipe -run TestReleasedGenerations` walks every directory under `released/` and runs `verify --deep --check-bundle` and `restore --apply` on each run. A copy with one flipped byte must be refused.
- The engine's `test/validate-backcompat-archives.ts` reads the same directories through the engine's own reader.

A new format generation adds a sibling directory beside this one. Neither test needs a code change to pick it up.
