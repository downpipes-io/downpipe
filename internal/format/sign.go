package format

import (
	"encoding/json"
	"fmt"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// MarshalRoot returns the canonical JSON bytes of the root manifest, the exact bytes
// stored as root.manifest.json and covered by the signature (SPEC.md 8, 11.1).
func MarshalRoot(m *spec.RootManifest) ([]byte, error) {
	return CanonicalJSON(m)
}

// SignRoot returns the canonical root-manifest bytes and the detached hybrid signature
// over those exact bytes (SPEC.md 8). The caller stores the bytes as
// root.manifest.json and the signature as root.manifest.json.sig.
func SignRoot(m *spec.RootManifest, signer *crypto.HybridSigner) (canonical, signature []byte, err error) {
	canonical, err = CanonicalJSON(m)
	if err != nil {
		return nil, nil, fmt.Errorf("canonicalise root manifest: %w", err)
	}
	signature, err = signer.Sign(canonical)
	if err != nil {
		return nil, nil, fmt.Errorf("sign root manifest: %w", err)
	}
	return canonical, signature, nil
}

// VerifyRootBytes verifies the detached signature over the exact stored root-manifest
// bytes against an operator-supplied verifier, which is the recovery-sheet signer and
// never the manifest's self-asserted fingerprint. Both signature halves must pass, and
// the reader verifies before trusting any field (SPEC.md 8.3).
func VerifyRootBytes(storedBytes, signature []byte, verifier *crypto.HybridVerifier) error {
	return verifier.Verify(storedBytes, signature)
}

// ParseRoot parses stored root-manifest bytes into a RootManifest, enforcing the
// canonical numeric form of the signed count fields (SPEC.md 11.3). In verified mode
// the caller verifies the bytes with VerifyRootBytes before trusting the result.
func ParseRoot(storedBytes []byte) (*spec.RootManifest, error) {
	if err := validateCounts(storedBytes, "declaredRecordCount", "shardCount", "freshness.runlogIndex"); err != nil {
		return nil, err
	}
	var m spec.RootManifest
	if err := json.Unmarshal(storedBytes, &m); err != nil {
		return nil, coded(ExitUsage, fmt.Errorf("parse root manifest: %w", err))
	}
	return &m, nil
}
