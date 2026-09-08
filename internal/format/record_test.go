package format

import "testing"

// ValidateRecordID enforces the documented recordId shape (SPEC.md 6.3): the letter "r"
// then exactly 15 zero-padded decimal digits, 16 ASCII bytes in total. This pins both
// the accepted form and the malformed forms, including "recordid00000001" which is also
// 16 bytes and so passed the old length-only check.
func TestValidateRecordID(t *testing.T) {
	valid := []string{
		"r000000000000000",
		"r000000000000001",
		"r000000000000042",
		"r999999999999999",
	}
	for _, id := range valid {
		if err := ValidateRecordID(id); err != nil {
			t.Errorf("recordId %q should be valid: %v", id, err)
		}
	}

	invalid := []struct {
		name string
		id   string
	}{
		{"old length-only-valid alphanumeric form", "recordid00000001"},
		{"wrong prefix letter", "x000000000000001"},
		{"uppercase prefix", "R000000000000001"},
		{"missing prefix, 16 digits", "0000000000000001"},
		{"too short by one digit", "r00000000000001"},
		{"too long by one digit", "r0000000000000001"},
		{"empty", ""},
		{"prefix only", "r"},
		{"non-digit in the body", "r00000000000000a"},
		{"sign in the body", "r-00000000000001"},
		{"space padding", "r 00000000000001"},
		{"unicode digit lookalike", "r00000000000000٠"},
	}
	for _, c := range invalid {
		t.Run(c.name, func(t *testing.T) {
			if err := ValidateRecordID(c.id); err == nil {
				t.Fatalf("recordId %q must be rejected", c.id)
			}
		})
	}
}
