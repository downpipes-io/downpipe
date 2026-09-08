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
# The Go modules (golang.org/x/crypto and filippo.io/mldsa) are exactly
# pinned in go.mod and hash-verified in go.sum.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

if ! command -v cyclonedx-gomod >/dev/null 2>&1; then
  echo "error: cyclonedx-gomod not found" >&2
  echo "install with: go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest" >&2
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
if [ "${components}" -eq 0 ]; then
  echo "error: sbom.cdx.json names no component; nothing useful was produced" >&2
  exit 1
fi
