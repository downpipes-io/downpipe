package crypto_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestCryptoFormatImportAllowlist enforces the supply-chain control CONTRIBUTING.md asserts
// ("No ad-hoc third-party crypto"): the import graph of internal/crypto and internal/format
// MUST import only the named stdlib crypto packages plus golang.org/x/crypto/hkdf and the
// filippo.io/mldsa packages. Any other external (non-stdlib, non-internal-module)
// cryptographic dependency fails the build. This is the CI check the doc describes; it runs
// under `go test ./...`, which CI already executes.
func TestCryptoFormatImportAllowlist(t *testing.T) {
	// allowedExternalPrefixes are the only non-stdlib, non-downpipe module paths the crypto
	// and format packages may reach: the post-quantum signature library and the x/crypto HKDF
	// implementation. Everything else with a dot in its first path element is a third-party
	// import and is rejected.
	allowedExternalPrefixes := []string{
		"filippo.io/mldsa",
		"golang.org/x/crypto/hkdf",
	}

	for _, pkg := range []string{"github.com/downpipes-io/downpipe/internal/crypto", "github.com/downpipes-io/downpipe/internal/format", "github.com/downpipes-io/downpipe/internal/custody"} {
		out, err := exec.Command("go", "list", "-deps", pkg).Output()
		if err != nil {
			t.Fatalf("go list -deps %s: %v", pkg, err)
		}
		for _, dep := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if !isExternal(dep) {
				continue // stdlib or this module: not subject to the allowlist
			}
			if allowed(dep, allowedExternalPrefixes) {
				continue
			}
			t.Errorf("%s reaches external dependency %q, which is outside the crypto/format import allowlist (stdlib + golang.org/x/crypto/hkdf + filippo.io/mldsa)", pkg, dep)
		}
	}
}

// isExternal reports whether an import path is a third-party module rather than the standard
// library or this module. A stdlib path has no dot in its first path segment (for example
// "crypto/sha512"); a module path does (for example "filippo.io/mldsa"). Vendored copies are
// matched on the path that follows the "vendor/" prefix.
func isExternal(dep string) bool {
	dep = strings.TrimPrefix(dep, "vendor/")
	if strings.HasPrefix(dep, "github.com/downpipes-io/downpipe/") {
		return false
	}
	first, _, _ := strings.Cut(dep, "/")
	return strings.Contains(first, ".")
}

// allowed reports whether dep (with any "vendor/" prefix removed) lies under one of the
// allowed external prefixes.
func allowed(dep string, prefixes []string) bool {
	dep = strings.TrimPrefix(dep, "vendor/")
	for _, p := range prefixes {
		if dep == p || strings.HasPrefix(dep, p+"/") {
			return true
		}
	}
	return false
}
