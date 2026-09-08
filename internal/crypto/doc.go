// Package crypto implements the downpipe CNSA 2.0 post-quantum envelope: a hybrid
// X25519 + ML-KEM-1024 key encapsulation (the combiner is derived from X-Wing,
// generalised to ML-KEM-1024 over HKDF-SHA-384), a hybrid Ed25519 + ML-DSA-87
// signature with both halves required, AES-256-GCM segment sealing in a STREAM
// construction, and the per-run master capsule that wraps the master to every
// recipient by KEM-DEM. The mandatory break-glass recipient is held offline, so the
// running engine can wrap to it but never unwrap, which is what lets a customer
// recover without Cloudflare and without the vendor. Key derivation, addressing and
// the key commitment are HKDF and HMAC over SHA-384.
//
// The normative format lives in docs/format/SPEC.md.
package crypto
