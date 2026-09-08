package main

import "testing"

// TestParseHumanBytes locks down the --max-memory size parser: plain bytes, binary and decimal
// unit suffixes, the no-cap zero, and the rejected garbage. The prefetch memory cap rides on
// this, so a misparsed "512MiB" must fail loudly, never silently floor to 0.
func TestParseHumanBytes(t *testing.T) {
	ok := []struct {
		in   string
		want int64
	}{
		{"", 0},
		{"0", 0},
		{"1024", 1024},
		{"512B", 512},
		{"1K", 1 << 10},
		{"1KiB", 1 << 10},
		{"1KB", 1000},
		{"512MiB", 512 << 20},
		{"512MB", 512 * 1000 * 1000},
		{"1GiB", 1 << 30},
		{"2GB", 2 * 1000 * 1000 * 1000},
		{"1TiB", 1 << 40},
		{"  256MiB  ", 256 << 20},
		{"4gib", 4 << 30}, // case-insensitive unit
	}
	for _, c := range ok {
		got, err := parseHumanBytes(c.in)
		if err != nil {
			t.Errorf("parseHumanBytes(%q) errored: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseHumanBytes(%q) = %d, want %d", c.in, got, c.want)
		}
	}

	bad := []string{"MiB", "-1", "12 quatloos", "1.5GiB", "0x10", "abc"}
	for _, in := range bad {
		if got, err := parseHumanBytes(in); err == nil {
			t.Errorf("parseHumanBytes(%q) = %d, want an error", in, got)
		}
	}
}
