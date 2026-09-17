package crypto_test

import (
	"os/exec"
	"path/filepath"
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

// cryptoImportAllowlist is the committed discovery manifest for ASVS V11.1.3: every package in
// this module that imports crypto/*, golang.org/x/crypto/* or filippo.io/*, mapped to exactly
// the crypto-shaped import paths TestCryptoDiscovery finds it importing today. It is a
// completeness census over the WHOLE module (every package, whatever it does), not the
// supply-chain allowlist above (three named packages' external dependencies only) -- a package
// can appear here with only stdlib crypto/* imports and no third-party dependency at all, and
// four of these six do.
var cryptoImportAllowlist = map[string][]string{
	"github.com/downpipes-io/downpipe/cmd/downpipe":     {"crypto/rand"},
	"github.com/downpipes-io/downpipe/internal/crypto":  {"crypto/aes", "crypto/cipher", "crypto/ecdh", "crypto/ed25519", "crypto/hmac", "crypto/mlkem", "crypto/rand", "crypto/sha512", "crypto/subtle", "filippo.io/mldsa", "golang.org/x/crypto/hkdf"},
	"github.com/downpipes-io/downpipe/internal/custody": {"crypto/aes", "crypto/cipher", "crypto/sha256", "crypto/subtle"},
	"github.com/downpipes-io/downpipe/internal/format":  {"crypto/ed25519", "crypto/sha512"},
	"github.com/downpipes-io/downpipe/internal/restore": {"crypto/sha512"},
	"github.com/downpipes-io/downpipe/internal/source":  {"crypto/hmac", "crypto/sha256"},
}

// isCryptoImport reports whether dep (with any "vendor/" prefix removed) is one of the three
// shapes TestCryptoDiscovery treats as cryptographic: a stdlib crypto/* subpackage, an
// x/crypto/* extension, or a filippo.io/* signature library.
func isCryptoImport(dep string) bool {
	dep = strings.TrimPrefix(dep, "vendor/")
	return dep == "crypto" || strings.HasPrefix(dep, "crypto/") ||
		strings.HasPrefix(dep, "golang.org/x/crypto/") ||
		strings.HasPrefix(dep, "filippo.io/")
}

// TestCryptoDiscovery is the module-wide discovery mechanism ASVS V11.1.3 asks for: it does not
// trust a hand-picked list of "the crypto packages" the way TestCryptoFormatImportAllowlist
// above does, it asks every package in the module what it imports and fails on anything the
// committed manifest does not already name.
//
//	(a) UNLISTED. A package importing a crypto-shaped dependency that cryptoImportAllowlist does
//	    not carry fails -- a new package reaching for crypto/* needs a reviewed manifest entry.
//	(b) STALE. A manifest entry for a package that no longer imports anything crypto-shaped
//	    fails, so a refactor that removes a dependency is required to remove its row too.
//	(c) ANTI-VACUITY. Finding zero crypto-importing packages fails outright: a broken `go list`
//	    invocation or an empty module must not read as a clean discovery pass.
//
// Run: go test ./internal/crypto/ -run TestCryptoDiscovery -v
func TestCryptoDiscovery(t *testing.T) {
	// `go list ./...` resolves package patterns relative to the COMMAND's working directory, which
	// is this test binary's own package directory (internal/crypto), not the module root -- so
	// without this the walk silently covered only internal/crypto and its subdirectories. `go env
	// GOMOD` names the module's go.mod file regardless of where the test runs from; its directory
	// is the module root the walk needs.
	gomodOut, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	moduleRoot := filepath.Dir(strings.TrimSpace(string(gomodOut)))

	listCmd := exec.Command("go", "list", "-f", "{{.ImportPath}} {{.Imports}}", "./...")
	listCmd.Dir = moduleRoot
	out, err := listCmd.Output()
	if err != nil {
		t.Fatalf("go list -f '{{.ImportPath}} {{.Imports}}' ./... (in %s): %v", moduleRoot, err)
	}

	discovered := map[string][]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		pkg, rest, ok := strings.Cut(line, " ")
		if !ok {
			t.Fatalf("go list line has no import list: %q", line)
		}
		// .Imports prints as a Go slice literal, "[a b c]"; strip the brackets and split on
		// whitespace to recover the individual import paths.
		rest = strings.TrimPrefix(strings.TrimSuffix(rest, "]"), "[")
		var crypto []string
		for _, dep := range strings.Fields(rest) {
			if isCryptoImport(dep) {
				crypto = append(crypto, strings.TrimPrefix(dep, "vendor/"))
			}
		}
		if len(crypto) > 0 {
			discovered[pkg] = crypto
		}
	}

	if len(discovered) == 0 {
		t.Fatal("discovered zero packages importing crypto/*, golang.org/x/crypto/* or filippo.io/*; the walk is misrooted or `go list` failed silently")
	}

	for pkg, imports := range discovered {
		want, known := cryptoImportAllowlist[pkg]
		if !known {
			t.Errorf("%s imports %v but is not in cryptoImportAllowlist; add it with the crypto-shaped imports it actually uses", pkg, imports)
			continue
		}
		for _, dep := range imports {
			if !containsExact(want, dep) {
				t.Errorf("%s imports %s, which is not in its cryptoImportAllowlist entry %v; widen the entry", pkg, dep, want)
			}
		}
	}

	for pkg, want := range cryptoImportAllowlist {
		if _, found := discovered[pkg]; !found {
			t.Errorf("cryptoImportAllowlist lists %s (expected imports %v) but it no longer imports anything crypto-shaped; remove its entry", pkg, want)
		}
	}
}

// containsExact reports whether dep is exactly one of prefixes (allowed() also accepts a
// "prefix/" match, which is right for the third-party allowlist above but would let
// cryptoImportAllowlist's exact stdlib entries silently cover unrelated siblings, e.g. an entry
// for "crypto/sha512" matching a future "crypto/sha512/dummy" package).
func containsExact(prefixes []string, dep string) bool {
	for _, p := range prefixes {
		if dep == p {
			return true
		}
	}
	return false
}
