package spec

import (
	"encoding/binary"
	"fmt"
)

const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// EncodeULID renders 16 raw bytes as a canonical 26-character uppercase Crockford
// base32 ULID (SPEC.md 11.6). It is the form used for runId in object paths and
// manifests, and is never lowercased.
func EncodeULID(b []byte) (string, error) {
	if len(b) != 16 {
		return "", fmt.Errorf("a ULID is 16 bytes, got %d", len(b))
	}
	hi := binary.BigEndian.Uint64(b[0:8])
	lo := binary.BigEndian.Uint64(b[8:16])
	var out [26]byte
	for i := 25; i >= 0; i-- {
		out[i] = crockfordAlphabet[lo&0x1f]
		lo = (lo >> 5) | (hi << 59)
		hi >>= 5
	}
	return string(out[:]), nil
}

// DecodeULID parses a canonical 26-character uppercase Crockford base32 ULID into its
// 16 raw bytes (SPEC.md 11.6). It rejects a non-canonical encoding: the wrong length,
// a lowercase or out-of-alphabet character (the excluded letters I, L, O and U
// included), or a first character above '7', which would overflow 128 bits.
func DecodeULID(s string) ([]byte, error) {
	if len(s) != 26 {
		return nil, fmt.Errorf("a ULID is 26 characters, got %d", len(s))
	}
	var hi, lo uint64
	for i := 0; i < 26; i++ {
		v := crockfordValue(s[i])
		if v < 0 {
			return nil, fmt.Errorf("invalid ULID character %q at position %d", s[i], i)
		}
		if i == 0 && v > 7 {
			return nil, fmt.Errorf("ULID first character %q overflows 128 bits", s[i])
		}
		hi = (hi << 5) | (lo >> 59)
		lo = (lo << 5) | uint64(v)
	}
	out := make([]byte, 16)
	binary.BigEndian.PutUint64(out[0:8], hi)
	binary.BigEndian.PutUint64(out[8:16], lo)
	return out, nil
}

// crockfordValue decodes one canonical uppercase Crockford base32 character, or -1.
// It deliberately does not accept the lenient aliases (lowercase, or I/L as 1 and O
// as 0), because the format requires the canonical encoding.
func crockfordValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'H':
		return int(c-'A') + 10
	case c == 'J' || c == 'K':
		return int(c-'J') + 18
	case c == 'M' || c == 'N':
		return int(c-'M') + 20
	case c >= 'P' && c <= 'T':
		return int(c-'P') + 22
	case c >= 'V' && c <= 'Z':
		return int(c-'V') + 27
	default:
		return -1
	}
}
