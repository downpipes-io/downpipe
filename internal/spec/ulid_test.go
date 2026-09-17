package spec

import (
	"bytes"
	"strings"
	"testing"
)

func TestULIDRoundTrip(t *testing.T) {
	cases := [][]byte{
		bytes.Repeat([]byte{0x00}, 16),
		bytes.Repeat([]byte{0xff}, 16),
		{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
	}
	for _, b := range cases {
		s, err := EncodeULID(b)
		if err != nil {
			t.Fatalf("encode %x: %v", b, err)
		}
		if len(s) != 26 {
			t.Fatalf("encoded length %d, want 26", len(s))
		}
		got, err := DecodeULID(s)
		if err != nil {
			t.Fatalf("decode %q: %v", s, err)
		}
		if !bytes.Equal(got, b) {
			t.Fatalf("round-trip mismatch: %x -> %q -> %x", b, s, got)
		}
	}
}

// EncodeULID guards its input length directly: only exactly 16 bytes encode, and any
// other length is an error rather than a silent truncation or panic (SPEC.md 11.6).
func TestEncodeULIDRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 15, 17} {
		if _, err := EncodeULID(make([]byte, n)); err == nil {
			t.Fatalf("EncodeULID(%d bytes) must return an error", n)
		}
	}
	if _, err := EncodeULID(make([]byte, 16)); err != nil {
		t.Fatalf("EncodeULID(16 bytes) must succeed: %v", err)
	}
}

func TestDecodeULIDRejectsNonCanonical(t *testing.T) {
	valid, err := EncodeULID(bytes.Repeat([]byte{0x11}, 16))
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"too short":         valid[:25],
		"lowercase":         strings.ToLower(valid),
		"excluded letter I": "I" + valid[1:],
		"first char over 7": "8" + strings.Repeat("0", 25),
	}
	for name, s := range bad {
		if _, err := DecodeULID(s); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
}
