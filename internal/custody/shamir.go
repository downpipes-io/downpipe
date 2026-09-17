// Package custody recombines the offline break-glass custody artefacts the Downpipes
// console emits: an AES-256-GCM envelope over the identity.key file, whose 256-bit
// wrapping key is either stored whole (a labelled wrapping-key file) or Shamir-split
// M-of-N (labelled share files, or the bare share bodies custodians receive by email).
// Everything here is offline and byte-compatible with the console's artefacts, proven
// by fixtures generated from the console's own code; the authoritative acceptance check
// is always the authenticated GCM decrypt.
//
// The package is deliberately stdlib-only (the import-allowlist test pins it), reads no
// file and prints nothing: callers hand it parsed bytes and map its error classes to
// exit codes.
package custody

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

// SecretBytes is the wrapping-key length the scheme is built for: 32 bytes.
const SecretBytes = 32

// ShareBytes is one Shamir share: a non-zero index byte then SecretBytes y-bytes.
const ShareBytes = 1 + SecretBytes

// ChecksumBytes is the PUBLIC truncated wrapping-key checksum length carried in share
// files: an early "one of your shares is incorrect" signal, never the authoritative
// check (the authenticated decrypt is).
const ChecksumBytes = 4

// checksumDomain binds the public checksum to its purpose; it matches the console's
// domain label byte for byte.
const checksumDomain = "downpipes:break-glass:wrapping-key-checksum:v1"

// The field is GF(2^8) with the AES reduction polynomial 0x11b and generator 0x03,
// matching the console's tables, so a share set recombines identically on either side.
// Side channels are out of scope for this offline, one-shot recovery path (the console
// makes the same call); the table lookups are not constant-time.
var gfExp [512]byte
var gfLog [256]byte

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = byte(i)
		x ^= gfXtime(byte(x))
		x &= 0xff
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfXtime(a byte) int {
	shifted := int(a) << 1
	if shifted&0x100 != 0 {
		shifted ^= 0x11b
	}
	return shifted & 0xff
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func gfInv(a byte) byte {
	// a^-1 = g^(255 - log a); a is never zero on the combine path (indices are non-zero
	// and denominators are XORs of distinct indices).
	return gfExp[255-int(gfLog[a])]
}

// Combine recovers the secret from the given shares by Lagrange interpolation at x = 0.
// It enforces structure (length, non-zero distinct indices) but is threshold-unaware:
// with fewer than the original threshold of shares it returns a WRONG value with no
// signal, which is the Shamir security property. Callers MUST verify the result, first
// against the public checksum when one is known, then authoritatively by the
// authenticated envelope decrypt.
func Combine(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, &ArtefactError{Msg: "need at least 2 shares to recombine"}
	}
	xs := make([]byte, len(shares))
	seen := map[byte]bool{}
	for i, sh := range shares {
		if len(sh) != ShareBytes {
			return nil, &ArtefactError{Msg: fmt.Sprintf("share %d is %d bytes, want %d", i+1, len(sh), ShareBytes)}
		}
		x := sh[0]
		if x == 0 {
			return nil, &ArtefactError{Msg: fmt.Sprintf("share %d has a zero index; indices are 1..255", i+1)}
		}
		if seen[x] {
			return nil, &ArtefactError{Msg: fmt.Sprintf("two shares carry index %d with different bodies; one is corrupt", x)}
		}
		seen[x] = true
		xs[i] = x
	}
	// Lagrange basis weights at x=0: L_i(0) = prod_{j!=i} x_j / (x_j XOR x_i); the
	// weights depend only on the indices, so they are shared across all secret bytes.
	weights := make([]byte, len(xs))
	for i := range xs {
		num, den := byte(1), byte(1)
		for j := range xs {
			if j == i {
				continue
			}
			num = gfMul(num, xs[j])
			den = gfMul(den, xs[i]^xs[j])
		}
		weights[i] = gfMul(num, gfInv(den))
	}
	out := make([]byte, SecretBytes)
	for b := 0; b < SecretBytes; b++ {
		var acc byte
		for i, sh := range shares {
			acc ^= gfMul(sh[1+b], weights[i])
		}
		out[b] = acc
	}
	return out, nil
}

// Checksum returns the PUBLIC 4-byte wrapping-key checksum the share files carry:
// SHA-256 over the domain label and the key, truncated. It reveals nothing usable
// about the 256-bit key and exists so a wrong or mis-transcribed share set is reported
// clearly before the decrypt.
func Checksum(wrappingKey []byte) ([]byte, error) {
	if len(wrappingKey) != SecretBytes {
		return nil, &ArtefactError{Msg: fmt.Sprintf("wrapping key is %d bytes, want %d", len(wrappingKey), SecretBytes)}
	}
	h := sha256.New()
	h.Write([]byte(checksumDomain))
	h.Write(wrappingKey)
	return h.Sum(nil)[:ChecksumBytes], nil
}

// VerifyChecksum reports whether the recombined key matches the expected public
// checksum. Total: any length mismatch is simply "does not verify".
func VerifyChecksum(wrappingKey, expected []byte) bool {
	if len(expected) != ChecksumBytes {
		return false
	}
	got, err := Checksum(wrappingKey)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, expected) == 1
}

// Wipe zeroes b in place. Go strings parsed from artefact files are immutable and
// cannot be wiped; only the decoded byte slices, the combined key and the plaintext
// can, and callers wipe exactly those.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
