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

// validateCounts enforces the SPEC 11.3 canonical numeric form for the named fields of a
// signed JSON object. A field encoded as a JSON number must be a non-negative integer at
// most 2^53-1; a field encoded as a string (the form reserved for values above the
// ceiling, which this reader does not accept) is rejected. A missing field is permitted
// (it may be omitempty). Every violation is a usage error (exit 6).
//
// A path is dotted. A segment that ends in "[]" names an array, and the rest of the path
// applies to each element: "segments[].packed?.offset" is the packed offset of every
// segment, and "segments[].chunkRange[]" is every chunkRange endpoint. A segment that ends
// in "?" names an object the format allows to be null; any other null on a path is refused. Before, a path
// could name only an object field, so the shard parse checked plaintextSize and nothing
// under segments. A string packed.offset then failed later in encoding/json as an
// uncoded error (exit 2), and a negative offset or a chunkRange endpoint above 2^53-1
// decoded without an error at all (SPEC 11.3 says exit 6 for both).
func validateCounts(raw []byte, paths ...string) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return coded(ExitUsage, fmt.Errorf("decode for numeric check: %w", err))
	}
	for _, p := range paths {
		var sites []countSite
		if err := collectCounts(generic, strings.Split(p, "."), "", &sites); err != nil {
			return coded(ExitUsage, err)
		}
		for _, site := range sites {
			if err := checkCanonicalCount(site.path, site.value); err != nil {
				return coded(ExitUsage, err)
			}
		}
	}
	return nil
}

// countSite is one value a count path resolved to, with its concrete path (array
// indices filled in) for the error message.
type countSite struct {
	path  string
	value any
}

// collectCounts walks parts through v and appends every value the path reaches to out. A
// field that is absent under its exact name adds nothing, and so does a step into a value
// that is not an object: encoding/json then fails on the shape itself. A count that is
// present as null is an error.
//
// The case-collision check runs at EVERY object on the path, before the absence check,
// not only when the exact key is missing. It used to run only in the "absent" branch, on
// the assumption that a case-colliding key only mattered when it was the SOLE way
// encoding/json's later, case-insensitive Unmarshal could reach the field. That missed
// the case where BOTH the canonical key and a re-cased duplicate are present in the same
// object: the exact-name lookup finds and validates the canonical key, while
// encoding/json.Unmarshal walks the raw object key-by-key and binds whichever of the two
// keys appears LAST in the byte stream (attacker-controlled order, not spelling). So
// {"index":1,"Index":999999} passed this check (validating the harmless "index":1) while
// RunlogEntry.Index ended up 999999, silently defeating the keyless --min-runlog-index
// self-consistency check the RUNLOG index guards (reproduced live: attest
// --min-runlog-index 999 against exactly that RUNLOG line reported max-index=999999 and
// exited 0). A key that case-collides with a normative field is ambiguous input to a
// format whose field names are canonical, so it is refused regardless of whether the
// canonical spelling is ALSO present.
//
// It runs at the intermediate objects too, because encoding/json matches every level
// case-insensitively, not only the last one. Measured: Unmarshal of
// {"freshness":{"runlogIndex":1},"Freshness":{"runlogIndex":-5}} yields runlogIndex -5
// with no error, while a check of the final segment alone validated the 1.
func collectCounts(v any, parts []string, prefix string, out *[]countSite) error {
	if len(parts) == 0 {
		*out = append(*out, countSite{path: prefix, value: v})
		return nil
	}
	seg, each := strings.CutSuffix(parts[0], "[]")
	key, nullable := strings.CutSuffix(seg, "?")
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	path := key
	if prefix != "" {
		path = prefix + "." + key
	}
	if found, collides := caseCollidingKey(m, key); collides {
		return fmt.Errorf("field %q appears as %q, which differs only in case: canonical field names are exact", path, found)
	}
	child, ok := m[key]
	if !ok {
		return nil
	}
	// A null on the path is present and is not the shape the format gives that field, so it
	// is refused (SPEC 11.3), not read as absent: a null count, a null array, and a null
	// object the count sits in all decode to zero values otherwise. Only a step marked "?"
	// may be null (packed, SPEC 6.3: null means the record owns the listed chunks), and a
	// null there adds nothing.
	if child == nil {
		switch {
		case nullable:
			return nil
		case len(parts) == 1 && !each:
			return fmt.Errorf("field %q must be a canonical integer, not null", path)
		case each:
			return fmt.Errorf("field %q must be an array, not null", path)
		default:
			return fmt.Errorf("field %q must be an object, not null", path)
		}
	}
	if !each {
		return collectCounts(child, parts[1:], path, out)
	}
	arr, ok := child.([]any)
	if !ok {
		return fmt.Errorf("field %q must be an array, not %T", path, child)
	}
	for i, el := range arr {
		elPath := fmt.Sprintf("%s[%d]", path, i)
		if el == nil && len(parts) > 1 {
			return fmt.Errorf("field %q must be an object, not null", elPath)
		}
		if err := collectCounts(el, parts[1:], elPath, out); err != nil {
			return err
		}
	}
	return nil
}

// caseCollidingKey reports a key of m that equals want apart from case, if there is one.
func caseCollidingKey(m map[string]any, want string) (string, bool) {
	for k := range m {
		if k != want && strings.EqualFold(k, want) {
			return k, true
		}
	}
	return "", false
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
