package format

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// maxCanonicalInt is the inclusive ceiling for a count or size carried as a JSON number
// (SPEC.md 11.3): a value at most 2^53-1 is a number, a larger value is a decimal
// string. The reference structs hold these fields as int64, which cannot represent the
// string form, so in practice every value the reader accepts is at or below this
// ceiling; the check rejects a number above it and a string used where a number is
// canonical.
const maxCanonicalInt int64 = 1<<53 - 1

// validateCounts enforces the SPEC 11.3 canonical numeric form for the named dotted
// fields of a signed JSON object. A field encoded as a JSON number must be a
// non-negative integer at most 2^53-1; a field encoded as a string (the form reserved
// for values above the ceiling, which this reader does not accept) is rejected. A
// missing field is permitted (it may be omitempty). Every violation is a usage error
// (exit 6).
func validateCounts(raw []byte, paths ...string) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return coded(ExitUsage, fmt.Errorf("decode for numeric check: %w", err))
	}
	for _, p := range paths {
		parts := strings.Split(p, ".")
		// The case-collision check runs UNCONDITIONALLY, before the absence check below, not
		// only when the exact key is missing. This matters when BOTH the canonical key and a
		// re-cased duplicate are present in the same object: resolvePath's exact-name lookup
		// would find and validate only the canonical key, while encoding/json.Unmarshal walks
		// the raw object key-by-key and binds whichever of the two keys appears LAST in the
		// byte stream — attacker-controlled order, not spelling. So {"index":1,"Index":999999}
		// would validate the harmless "index":1 while RunlogEntry.Index ends up 999999,
		// silently defeating the keyless --min-runlog-index self-consistency check the RUNLOG
		// index guards. A key that case-collides with a normative field is ambiguous input to
		// a format whose field names are canonical, so it is refused regardless of whether the
		// canonical spelling is ALSO present.
		if collides, found := caseCollidingKey(generic, parts); collides {
			return coded(ExitUsage, fmt.Errorf("field %q appears as %q, which differs only in case: canonical field names are exact", p, found))
		}
		v, ok := resolvePath(generic, parts)
		if !ok || v == nil {
			// The field is genuinely absent under its exact name and no case-colliding
			// duplicate exists either (the check above would have returned): nothing to
			// validate.
			continue
		}
		if err := checkCanonicalCount(p, v); err != nil {
			return coded(ExitUsage, err)
		}
	}
	return nil
}

// caseCollidingKey reports whether the object that WOULD have held the final path segment carries a
// key equal to it apart from case. Only the final segment matters: an intermediate segment that is
// mis-cased leaves the whole path unresolvable for encoding/json too, so nothing is reinterpreted.
func caseCollidingKey(v any, parts []string) (bool, string) {
	if len(parts) == 0 {
		return false, ""
	}
	cur := v
	for _, p := range parts[:len(parts)-1] {
		m, ok := cur.(map[string]any)
		if !ok {
			return false, ""
		}
		cur, ok = m[p]
		if !ok {
			return false, ""
		}
	}
	m, ok := cur.(map[string]any)
	if !ok {
		return false, ""
	}
	want := parts[len(parts)-1]
	for k := range m {
		if k != want && strings.EqualFold(k, want) {
			return true, k
		}
	}
	return false, ""
}

// checkCanonicalCount enforces the SPEC 11.3 canonical numeric form. Each check below is
// commented with whether it is the ONLY thing standing between an out-of-form value and
// acceptance, or whether a later check in this same function would also catch the value
// (redundant, defence in depth). This was established empirically: each guard was
// disabled in isolation and every conformance vector re-run, so the claim below is
// proven, not assumed.
func checkCanonicalCount(path string, v any) error {
	num, ok := v.(json.Number)
	if !ok {
		return fmt.Errorf("field %q must be a canonical integer, not %T (a string form is reserved for values above 2^53-1, which this reader does not accept)", path, v)
	}
	s := num.String()
	// A decimal point or exponent is REDUNDANT with the num.Int64() parse below:
	// strconv.ParseInt (which json.Number.Int64 calls) rejects any non-digit character
	// including '.', 'e' and 'E', so disabling this line alone changes nothing observable
	// — the value is still refused, just via the "out of canonical range" branch below
	// instead of this one. Kept for a precise error message, not because removing it
	// would open a hole.
	if strings.ContainsAny(s, ".eE") {
		return fmt.Errorf("field %q is not an integer: %s", path, s)
	}
	// Counts are non-negative; reject any sign, including the non-canonical "-0". This IS
	// load-bearing: strconv.ParseInt accepts a leading '-', so a negative value survives
	// num.Int64() intact and is not caught by the ceiling check either (a negative number
	// is never > maxCanonicalInt). Disabling this line alone lets "-1" and "-0" through.
	if strings.HasPrefix(s, "-") {
		return fmt.Errorf("field %q must be a non-negative integer: %s", path, s)
	}
	// No leading zeros: "0" is fine; "007" and "01" are non-canonical (matches the lexical
	// guard in checkCanonJSONInt so the writer and reader reject identical forms). This
	// line is UNREACHABLE via any genuinely JSON-decoded value: RFC 8259's int production
	// is "0" or a non-zero digit followed by digits, so "007"/"01" is a syntax error at
	// json.Decoder.Decode itself (proven live: {"n":01} fails to decode at all, before a
	// json.Number ever exists to inspect). Every caller of checkCanonicalCount reaches it
	// only after a full json.Decoder.Decode of the surrounding bytes, so no live archive
	// can exercise this exact line; it is kept as defence in depth against a future caller
	// that constructs a json.Number without going through json.Decoder.
	if len(s) > 1 && s[0] == '0' {
		return fmt.Errorf("field %q has a leading zero and is not in canonical form: %s", path, s)
	}
	n, err := num.Int64()
	if err != nil {
		return fmt.Errorf("field %q is out of canonical range (>2^53-1): %s", path, s)
	}
	if n > maxCanonicalInt {
		return fmt.Errorf("field %q is out of canonical range [0, 2^53-1]: %d", path, n)
	}
	return nil
}

// resolvePath walks a dotted path through decoded JSON objects.
func resolvePath(v any, parts []string) (any, bool) {
	cur := v
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}
