package format

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// CanonicalJSON serialises v to canonical JSON for signing (SPEC.md 11.1): object
// keys sorted, no insignificant whitespace, UTF-8 output, integers as plain decimal,
// and no HTML escaping. It is a constrained RFC 8785 profile. The format forbids
// floating-point and NaN in signed objects (counts and sizes are integers or, above
// 2^53, strings), so only integers, strings, booleans, null, arrays and objects
// appear, which removes the hard number-canonicalisation cases. A value that arrived
// as a float, or a non-integer number literal, is rejected rather than canonicalised.
func CanonicalJSON(v any) ([]byte, error) {
	// Reject any value that arrived as a Go floating-point type before the json.Marshal
	// round-trip below, which would silently drop the fractional part of a whole-number
	// float (float64(2.0) marshals to "2"). The lexical guard in checkCanonJSONInt only
	// ever sees the post-marshal text, so a 2.0 never reaches it as a float; this pre-pass
	// is what enforces the integer-only contract at the type level (SPEC.md 11.3).
	if err := rejectFloatKinds(reflect.ValueOf(v)); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	var out bytes.Buffer
	if err := canonValue(&out, generic); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func canonValue(out *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if t {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case json.Number:
		if err := checkCanonJSONInt(t); err != nil {
			return err
		}
		out.WriteString(t.String())
	case string:
		// Reject invalid UTF-8 rather than silently transcoding it to U+FFFD, so a
		// signature stays reproducible and a name cannot be quietly rewritten (SPEC.md
		// 11.1, 6.4).
		if !utf8.ValidString(t) {
			return fmt.Errorf("string is not valid UTF-8; canonical JSON must not transcode it")
		}
		writeJSONString(out, t)
	case []any:
		return canonArray(out, t)
	case map[string]any:
		return canonObject(out, t)
	default:
		return fmt.Errorf("unsupported type %T in canonical JSON", v)
	}
	return nil
}

// canonArray writes a JSON array with no inter-element whitespace, recursing into each
// element via canonValue.
func canonArray(out *bytes.Buffer, arr []any) error {
	out.WriteByte('[')
	for i, e := range arr {
		if i > 0 {
			out.WriteByte(',')
		}
		if err := canonValue(out, e); err != nil {
			return err
		}
	}
	out.WriteByte(']')
	return nil
}

// canonObject writes a JSON object with keys sorted by UTF-16 code unit and no
// inter-member whitespace, recursing into each value via canonValue.
func canonObject(out *bytes.Buffer, obj map[string]any) error {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
	out.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			out.WriteByte(',')
		}
		writeJSONString(out, k)
		out.WriteByte(':')
		if err := canonValue(out, obj[k]); err != nil {
			return err
		}
	}
	out.WriteByte('}')
	return nil
}

// rejectFloatKinds walks v and returns an error if any value reachable through it is a
// Go floating-point kind (float32 or float64), regardless of whether the value happens
// to be integral. It runs before json.Marshal so a whole-number float such as
// float64(2.0), which Go marshals to the integer text "2", is caught at the type level
// rather than coerced silently (SPEC.md 11.3 forbids floating-point in signed objects).
// It descends through pointers, interfaces, maps, slices, arrays and struct fields,
// which covers every shape a signed object in this format takes (all the signed structs
// are plain integer/string/bool/slice/struct compositions; none defines its own
// json.Marshaler or carries a float field today). json.Number is a string kind, so it
// is handled by the lexical check in checkCanonJSONInt, not here.
func rejectFloatKinds(v reflect.Value) error {
	if !v.IsValid() {
		return nil
	}
	switch v.Kind() {
	case reflect.Float32, reflect.Float64:
		return fmt.Errorf("floating-point value %v is not allowed in a signed object", v.Interface())
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return nil
		}
		return rejectFloatKinds(v.Elem())
	case reflect.Map:
		for _, k := range v.MapKeys() {
			if err := rejectFloatKinds(v.MapIndex(k)); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if err := rejectFloatKinds(v.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			// Only exported fields are marshalled, so only they can reach the output.
			if t.Field(i).PkgPath != "" {
				continue
			}
			if err := rejectFloatKinds(v.Field(i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkCanonJSONInt enforces the SPEC 11.3 numeric constraints on a json.Number that
// appears inside a signed object:
//   - Must be an integer (no decimal point, no exponent).
//   - Must be non-negative (no leading minus, including the non-canonical "-0").
//   - Must be at most 2^53-1; a larger value must be a decimal string, not a number.
//   - Must have no leading zeros (e.g. "007" is non-canonical; only "0" may start
//     with the digit zero).
//
// These are the same constraints that validateCounts applies on the reader side.
// Enforcing them here means the writer and reader agree: CanonicalJSON will never
// silently emit a form that the reader would reject as non-canonical. A value that
// arrived as a Go float is rejected earlier by rejectFloatKinds; this lexical guard
// additionally catches a float that arrives as a raw json.Number literal (for example
// "2.0" decoded with UseNumber).
func checkCanonJSONInt(num json.Number) error {
	s := num.String()
	// Floats (decimal point or exponent notation) are not permitted in signed objects.
	if strings.ContainsAny(s, ".eE") {
		return fmt.Errorf("non-integer number %q is not allowed in a signed object", s)
	}
	// Non-negative: reject any leading minus, which also catches the non-canonical "-0".
	if strings.HasPrefix(s, "-") {
		return fmt.Errorf("number %q must be a non-negative integer in a signed object", s)
	}
	// No leading zeros: "0" is fine; "007" and "01" are non-canonical.
	if len(s) > 1 && s[0] == '0' {
		return fmt.Errorf("number %q has a leading zero and is not in canonical form", s)
	}
	// Ceiling: a value above 2^53-1 must be encoded as a decimal string, not a number.
	n, err := num.Int64()
	if err != nil {
		return fmt.Errorf("number %q exceeds the canonical integer ceiling 2^53-1 and must be a decimal string", s)
	}
	if n > maxCanonicalInt {
		return fmt.Errorf("number %d exceeds the canonical integer ceiling 2^53-1 and must be a decimal string", n)
	}
	return nil
}

// lessUTF16 orders two strings by their UTF-16 code units, as RFC 8785 requires for
// object key sorting (SPEC.md 11.1). This differs from Go's byte-order string compare
// for supplementary-plane characters, and getting it right is what makes a signature
// over a manifest reproducible across the Go and the Workers implementations.
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for x := 0; x < len(ua) && x < len(ub); x++ {
		if ua[x] != ub[x] {
			return ua[x] < ub[x]
		}
	}
	return len(ua) < len(ub)
}

// writeJSONString writes a JSON string with the RFC 8785 minimal escaping: the quote,
// the backslash, the short forms for the common control characters and \u00xx for the
// remaining control characters. It does not HTML-escape, and it emits non-ASCII as
// UTF-8 rather than \u escapes.
func writeJSONString(out *bytes.Buffer, s string) {
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}
