module github.com/downpipes-io/downpipe

go 1.26.0

// Pin the build toolchain to the patched 1.26.10 (GO-2026 stdlib advisories: x509 parsing DoS,
// HTTP/2 SETTINGS infinite loop, net/textproto, and GO-2026-5856 Encrypted Client Hello privacy
// leak in crypto/tls; GO-2026-6218 net/url quadratic resolvePath,
// GO-2026-6090 crypto/tls post-handshake message limit, GO-2026-6088 encoding/xml recursion depth,
// GO-2026-5972 encoding/asn1 recursion depth and GO-2026-5026 net/http Punycode label rejection
// (via the vendored golang.org/x/net/idna); GO-2026-6603, -6604, -6605, -6607, -6608, -6610, -6611,
// -6612, -6613 and -6617 in net/http, crypto/tls, net/textproto and os; and GO-2026-6809 crypto/x509
// distrust of compromised intermediate certificates). CI/release set
// GO_VERSION to match; this forces dev/customer source builds to the same patched toolchain
// (GOTOOLCHAIN=auto), so a stale local Go can't produce a vulnerable reader. Verified by
// govulncheck (ASVS V15.2.1).
toolchain go1.26.10

require golang.org/x/crypto v0.57.0

// downpipe-sys-deps-01: the ML-DSA-87 signature primitive comes from filippo.io/mldsa,
// pinned to the tagged release v1.0.0. The pin is exact ON PURPOSE: a silent change to the
// signature encoding would let a freshly built reader fail to verify an archive an earlier
// build sealed, so the version must not float. Built with Go 1.26, the toolchain pinned
// above, the module compiles its own ML-DSA implementation; built with Go 1.27 or later
// (outside the v1.0 FIPS module) it wraps the standard-library crypto/mldsa (FIPS 204).
// MIGRATION: move the wrap in internal/crypto to crypto/mldsa once this module targets
// Go 1.27, then drop this dependency. Until then, the frozen-fixture guard
// TestMLDSAFrozenSignatureConformance (internal/crypto) re-verifies a historical signature
// against whatever pin and toolchain are in use, so any encoding change is caught at the
// moment this line is bumped rather than at recovery time; bump the fixture in the same commit.
require filippo.io/mldsa v1.0.0
