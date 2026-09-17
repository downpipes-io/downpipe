package spec

import "testing"

// TestCrockfordValueAcceptsEveryAlphabetChar drives DecodeULID with each of the 32
// canonical Crockford characters so every arm of crockfordValue's switch is exercised
// (0-9, A-H, J/K, M/N, P-T, V-Z), not just the subset a random round-trip happens to hit.
// Each character is placed at a non-first position (a '0' leads so the first-character
// 128-bit overflow guard never fires), so the only thing under test is that the character
// is accepted. A rejected canonical character would fail the decode here.
func TestCrockfordValueAcceptsEveryAlphabetChar(t *testing.T) {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for i := 0; i < len(alphabet); i++ {
		c := alphabet[i]
		// 26 characters: a leading '0' (value 0, safely below the first-char limit) then the
		// character under test repeated to fill the ULID. All characters here are canonical, so
		// the decode must succeed.
		s := "0"
		for j := 0; j < 25; j++ {
			s += string(c)
		}
		if _, err := DecodeULID(s); err != nil {
			t.Errorf("DecodeULID with canonical character %q = %v, want a successful decode", string(c), err)
		}
	}
}

// TestCrockfordValueRejectsExcludedAndLowercase confirms the deliberately excluded letters
// (I, L, O, U) and any lowercase letter fall through to the default (-1) arm and are
// rejected. The format requires the canonical uppercase encoding with no lenient aliases.
func TestCrockfordValueRejectsExcludedAndLowercase(t *testing.T) {
	bad := []byte{'I', 'L', 'O', 'U', 'i', 'l', 'o', 'u', 'a', 'z', '-', ' ', '@', 0x00}
	for _, c := range bad {
		// Place the bad character at position 1 (not 0) so the rejection is the
		// out-of-alphabet check, not the first-character overflow guard.
		s := "0" + string(c)
		for j := 0; j < 24; j++ {
			s += "0"
		}
		if _, err := DecodeULID(s); err == nil {
			t.Errorf("DecodeULID with non-canonical character %q = nil error, want a rejection", string(rune(c)))
		}
	}
}
