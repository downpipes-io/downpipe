# Verify that a release is what it claims to be

You do not have to trust us. This document lets you confirm, yourself, that a `downpipe` binary
was built by CI from the tagged source in this repository.

## What this proves, and what it does not

- It PROVES the binary you downloaded matches the checksum published in `checksums.txt`, and that
  `checksums.txt` itself was signed by this repository's release workflow: a keyless cosign
  signature whose certificate is logged in the public Sigstore Rekor transparency log, so a
  signature served to you and hidden from everyone else is detectable.
- It PROVES the tag the release was cut from carries a valid SSH signature from a key on the
  maintainer's roster: before any of the steps above run, the release workflow's verify-tag job
  checks the tag against `.github/allowed_signers` as committed on `main` (never the tag's own
  tree, so a pushed tag can never vouch for itself) and fails closed if the tag is unsigned or
  signed by a key not on that roster. Check a clone of the tag yourself with:

  ```bash
  git -c gpg.ssh.allowedSignersFile=.github/allowed_signers verify-tag <the release tag, e.g. v0.3.1>
  ```

- It does NOT prove the source is benign. Read the source (it is the whole point of an offline,
  MIT-licensed reader) for that separate assurance.

## Release integrity

This repository's own source-control and build gates sit upstream of everything above: every
change reaches `main` through a pull request and a green CI check, `main` and release tags
require signatures, and the release workflow checks a tag's signature against this repository's
allowed-signers file before it builds. See [What protects the release
path](https://docs.downpipes.io/operations/verify-a-release/#what-protects-the-release-path) for
the full picture, including reproducible builds. `downpipe` itself ships as a tagged GitHub
release rather than through the engine's update channel; that page's update-channel section
describes the engine's separate distribution path.

## Step 1: check the checksum

```bash
sha256sum --check --ignore-missing checksums.txt
```

## Step 2: verify the checksum file's signature

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github.com/downpipes-io/downpipe/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

The keyless signature and its certificate are logged in the public Sigstore Rekor transparency
log, so a signature served to you and hidden from everyone else is detectable.

## Step 3: check the SBOM

Each platform archive ships a matching `.cdx.json` CycloneDX software bill of materials, listing
every Go module the binary was built against, for anyone who needs to check a dependency's
version against a vulnerability advisory.

## Step 4: verify the SLSA build provenance (releases from v0.3.1 onward)

From v0.3.1, every release also carries `downpipe.intoto.jsonl`, a SLSA Build L3 provenance
statement produced by the `slsa-framework/slsa-github-generator` reusable workflow. It proves
which workflow run, on which commit, produced `checksums.txt` (and, transitively, the archives
it checksums), independent of the cosign signature above.

Install [`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier), then:

```bash
slsa-verifier verify-artifact checksums.txt \
  --provenance-path downpipe.intoto.jsonl \
  --source-uri github.com/downpipes-io/downpipe \
  --source-tag <the release tag, e.g. v0.3.1>
```

A release before v0.3.1 carries no `downpipe.intoto.jsonl`; verify it with steps 1-2 above only.

## Step 5: prove the round trip yourself

```bash
./downpipe selftest
```

This seals a value with the post-quantum envelope and recovers it from disk using only an offline
key, with nothing else in the loop. It does not depend on any of the steps above; it is a
functional proof, not a provenance one.
