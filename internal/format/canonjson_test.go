package format

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalJSON(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{
			name: "keys are sorted and output is compact",
			in:   map[string]any{"b": 1, "a": 2, "c": 3},
			want: `{"a":2,"b":1,"c":3}`,
		},
		{
			name: "html characters are not escaped",
			in:   map[string]any{"k": "a<b>&c"},
			want: `{"k":"a<b>&c"}`,
		},
		{
			name: "nested objects and arrays canonicalise recursively",
			in:   map[string]any{"arr": []any{3, 1, 2}, "obj": map[string]any{"z": 1, "a": 2}},
			want: `{"arr":[3,1,2],"obj":{"a":2,"z":1}}`,
		},
		{
			name: "quote, backslash and control characters escape minimally",
			in:   map[string]any{"s": "x\"y\\z\n\t"},
			want: `{"s":"x\"y\\z\n\t"}`,
		},
	}
	for _, c := range cases {
		got, err := CanonicalJSON(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if string(got) != c.want {
			t.Fatalf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
}

// The same object always serialises to the same bytes regardless of map iteration
// order, which is what makes a signature reproducible.
func TestCanonicalJSONDeterministic(t *testing.T) {
	a, err := CanonicalJSON(map[string]any{"one": 1, "two": 2, "three": 3, "four": 4})
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalJSON(map[string]any{"four": 4, "three": 3, "two": 2, "one": 1})
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("canonical output must be order-independent:\n%s\n%s", a, b)
	}
}

// Object keys sort by UTF-16 code unit, not UTF-8 bytes. U+1F600 is a surrogate pair
// whose first code unit (0xD83D) is below U+E000, so it sorts first in UTF-16; in
// UTF-8 byte order U+E000 (0xEE...) sorts before U+1F600 (0xF0...). RFC 8785 requires
// the UTF-16 order, and it is what keeps a manifest signature reproducible.
func TestCanonicalJSONUTF16KeyOrder(t *testing.T) {
	emoji := "\U0001F600"       // UTF-16 first code unit 0xD83D
	pua := string(rune(0xE000)) // UTF-16 code unit 0xE000
	got, err := CanonicalJSON(map[string]any{emoji: 1, pua: 2})
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"" + emoji + "\":1,\"" + pua + "\":2}"
	if string(got) != want {
		t.Fatalf("UTF-16 key order:\n got %q\nwant %q", got, want)
	}
}

// A non-integer number must be rejected: floats are not allowed in signed objects.
func TestCanonicalJSONRejectsFloat(t *testing.T) {
	if _, err := CanonicalJSON(map[string]any{"f": 1.5}); err == nil {
		t.Fatal("a floating-point value must be rejected")
	}
}

// A whole-number float (for example float64(2.0)) must be rejected, not silently
// coerced to an integer. Go marshals float64(2.0) to the text "2", so the
// lexical .eE guard never sees a float here; the type-level pre-pass is what enforces
// the integer-only contract (SPEC.md 11.3). This pins the previously-leaking case where
// CanonicalJSON returned {"n":2} with no error.
func TestCanonicalJSONRejectsWholeNumberFloat(t *testing.T) {
	cases := []struct {
		name string
		in   any
	}{
		{"top-level float64 whole number", map[string]any{"n": float64(2.0)}},
		{"top-level float32 whole number", map[string]any{"n": float32(2)}},
		{"float zero", map[string]any{"n": float64(0)}},
		{"float inside a slice", map[string]any{"arr": []any{int64(1), float64(3.0)}}},
		{"float nested in an inner object", map[string]any{"outer": map[string]any{"inner": float64(7.0)}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, err := CanonicalJSON(c.in); err == nil {
				t.Fatalf("a whole-number float must be rejected, got %s", got)
			}
		})
	}
}

// A float carried on a struct field (the shape a real signed object takes) must also be
// rejected, including when the value is integral. This exercises the reflective walk
// over exported struct fields, pointers and embedded structs.
func TestCanonicalJSONRejectsFloatStructField(t *testing.T) {
	type inner struct {
		Ratio float64 `json:"ratio"`
	}
	type outer struct {
		Name  string `json:"name"`
		Inner inner  `json:"inner"`
	}
	if _, err := CanonicalJSON(outer{Name: "x", Inner: inner{Ratio: 4.0}}); err == nil {
		t.Fatal("a whole-number float on a nested struct field must be rejected")
	}
	if _, err := CanonicalJSON(&outer{Name: "x", Inner: inner{Ratio: 4.0}}); err == nil {
		t.Fatal("a whole-number float reached through a pointer must be rejected")
	}
}

// An all-integer object that resembles the float cases must still canonicalise, so the
// float pre-pass does not over-reject genuine integer counts and sizes.
func TestCanonicalJSONAcceptsIntegersAlongsideFloatGuard(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{"n": int64(2), "arr": []any{int64(0), int64(7)}})
	if err != nil {
		t.Fatalf("integers must be accepted: %v", err)
	}
	if want := `{"arr":[0,7],"n":2}`; string(got) != want {
		t.Fatalf("unexpected output:\n got %s\nwant %s", got, want)
	}
}

// TestCanonicalJSONNumericConstraints exercises the SPEC 11.3 boundaries enforced by
// CanonicalJSON on integer values: the inclusive ceiling at 2^53-1, the rejection of
// values above the ceiling, and the rejection of negative values. It uses raw
// json.Number inputs (via a map decoded with UseNumber) to exercise the check directly
// without going through Go's type system, which would prevent the bad values from
// appearing in practice.
func TestCanonicalJSONNumericConstraints(t *testing.T) {
	// Helper that builds a one-field object from a raw JSON number literal and runs
	// CanonicalJSON on it, returning the output or the error.
	runWith := func(raw string) (string, error) {
		// Decode via UseNumber so json.Number preserves the raw literal.
		dec := json.NewDecoder(strings.NewReader(`{"n":` + raw + `}`))
		dec.UseNumber()
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			return "", err
		}
		out, err := CanonicalJSON(m)
		return string(out), err
	}

	t.Run("max ok (2^53-1)", func(t *testing.T) {
		got, err := runWith("9007199254740991")
		if err != nil {
			t.Fatalf("2^53-1 must be accepted: %v", err)
		}
		if got != `{"n":9007199254740991}` {
			t.Fatalf("unexpected output: %s", got)
		}
	})

	t.Run("over ceiling (2^53) rejected", func(t *testing.T) {
		if _, err := runWith("9007199254740992"); err == nil {
			t.Fatal("2^53 must be rejected (exceeds canonical ceiling)")
		}
	})

	t.Run("well over ceiling rejected", func(t *testing.T) {
		if _, err := runWith("9007199254740993"); err == nil {
			t.Fatal("9007199254740993 must be rejected (exceeds canonical ceiling)")
		}
	})

	t.Run("negative rejected", func(t *testing.T) {
		if _, err := runWith("-1"); err == nil {
			t.Fatal("negative integer must be rejected")
		}
	})

	t.Run("negative zero rejected", func(t *testing.T) {
		// -0 is the non-canonical signed-zero form; it must be rejected regardless
		// of the ceiling check.
		if _, err := runWith("-0"); err == nil {
			t.Fatal("negative zero (-0) must be rejected as non-canonical")
		}
	})

	t.Run("leading zero rejected", func(t *testing.T) {
		if _, err := runWith("007"); err == nil {
			t.Fatal("leading-zero integer must be rejected as non-canonical")
		}
	})

	t.Run("zero ok", func(t *testing.T) {
		got, err := runWith("0")
		if err != nil {
			t.Fatalf("zero must be accepted: %v", err)
		}
		if got != `{"n":0}` {
			t.Fatalf("unexpected output: %s", got)
		}
	})

	t.Run("one ok", func(t *testing.T) {
		got, err := runWith("1")
		if err != nil {
			t.Fatalf("one must be accepted: %v", err)
		}
		if got != `{"n":1}` {
			t.Fatalf("unexpected output: %s", got)
		}
	})
}
