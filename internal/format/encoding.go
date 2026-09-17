package format

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
)

// B64Encode renders binary as base64url no-pad, the encoding for binary fields in
// downpipe JSON (SPEC.md 11.4).
func B64Encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// B64Decode parses base64url no-pad.
func B64Decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// SHA384Hex is the bare lowercase hex SHA-384 of b (SPEC.md 11.8).
func SHA384Hex(b []byte) string {
	sum := sha512.Sum384(b)
	return hex.EncodeToString(sum[:])
}
