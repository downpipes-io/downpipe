#!/usr/bin/env bash
# Generate a CycloneDX 1.6 SBOM for the downpipe Go repo.
#
# Output: sbom.cdx.json in the repo root.
#
# Requires:
#   Go >= 1.26 (matching the go directive in go.mod)
#   cyclonedx-gomod
#
# Install cyclonedx-gomod if missing:
#   go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
#
# This script only generates the SBOM; it does not run go mod download or
# modify any files other than sbom.cdx.json.
#
# See engine/docs/security/sbom.md for the dependency inventory.
# The Go modules (golang.org/x/crypto v0.52.0 and filippo.io/mldsa
# v0.0.0-20260215214346-43d0283efc3e) are exactly pinned in go.mod and
# hash-verified in go.sum; the caret-range concern documented for the
# TypeScript repos does not apply here.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Sourcing this ARMS the completion guard. A generator is graded the same way a gate is: its exit code
# is the only thing its caller reads, and "exited 0 having written nothing" is the same false green.
. "${SCRIPT_DIR}/lib/verdict-guard.sh"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

if ! command -v cyclonedx-gomod >/dev/null 2>&1; then
  echo "error: cyclonedx-gomod not found" >&2
  echo "install with: go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest" >&2
  # Mandatory: the caller asked for an SBOM and there is none, so this must not read as a quiet skip.
  verdict_skipped "cyclonedx-gomod is not installed, so no SBOM was produced" require
  exit 1
fi

cyclonedx-gomod mod \
  -json \
  -output sbom.cdx.json \
  "${REPO_ROOT}"

# The count is the number of components the SBOM actually names. A run that wrote a file with no
# component in it produced nothing useful, and exited 0 while doing so, which is the shape the guard
# exists for reached through a generator rather than through a gate.
components="$(grep -c '"bom-ref"' "${REPO_ROOT}/sbom.cdx.json" || true)"
echo "SBOM written to ${REPO_ROOT}/sbom.cdx.json (${components} component(s))"
verdict_reached 0 "${components}"
