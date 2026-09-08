module github.com/downpipes-io/downpipe

go 1.26.0

// Pin the build toolchain to the patched 1.26.6 (GO-2026 stdlib advisories: x509 parsing DoS,
// HTTP/2 SETTINGS infinite loop, net/textproto, and GO-2026-5856 Encrypted Client Hello privacy
// leak in crypto/tls, which 1.26.4 did NOT carry; and GO-2026-6218 net/url quadratic resolvePath,
// GO-2026-6090 crypto/tls post-handshake message limit, GO-2026-6088 encoding/xml recursion depth,
// GO-2026-5972 encoding/asn1 recursion depth and GO-2026-5026 net/http Punycode label rejection
// (via the vendored golang.org/x/net/idna), which 1.26.5 did NOT carry). CI/release set
// GO_VERSION to match; this forces dev/customer source builds to the same patched toolchain
// (GOTOOLCHAIN=auto), so a stale local Go can't produce a vulnerable reader. Verified by
// govulncheck (ASVS V15.2.1).
toolchain go1.26.6

require golang.org/x/crypto v0.56.0

// The ML-DSA-87 signature primitive is pinned to a pre-release
// pseudo-version of filippo.io/mldsa, whose API the upstream still marks unstable. The
// pin is exact ON PURPOSE: a silent change to the signature encoding would let a freshly
// built reader fail to verify an archive an earlier build sealed, so the version must not
// float. MIGRATION: move the wrap in internal/crypto to the standard-library crypto/mldsa
// once it ships (FIPS 204), then drop this dependency. Until then, the frozen-fixture
// guard TestMLDSAFrozenSignatureConformance (internal/crypto) re-verifies a historical
// signature against whatever pin is in use, so any encoding change is caught at the moment
// this line is bumped rather than at recovery time; bump the fixture in the same commit.
require filippo.io/mldsa v0.0.0-20260215214346-43d0283efc3e
