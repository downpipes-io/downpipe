package format

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/downpipes-io/downpipe/internal/crypto"
)

// Signed assurance reports.
//
// The engine generates a report over the account's own state and signs it with the operator signer,
// the same Ed25519 + ML-DSA-87 key pair that signs the archive (engine src/admin/reports.ts, signReport).
// A report is a JSON object with five members:
//
//	{"kind": ..., "generatedAt": ..., "period": ..., "data": ..., "signature": "edmldsa1:<base64url>"}
//
// The signature covers the canonical JSON of the other four members only, {kind, generatedAt, period,
// data}, with no domain-separation prefix: the signed bytes are exactly that canonical JSON. The value
// after "edmldsa1:" is unpadded base64url of edSig(64) || mldsaSig(4627), the same detached layout as a
// root-manifest signature, and both halves must verify.
//
// The canonical form is the engine's canonicalJSON (src/format/canonjson.ts): keys sorted by UTF-16 code
// unit, no whitespace, no HTML escaping, the short escapes for \b \t \n \f \r and \u00xx for the other
// control characters, and integers only. It differs from the archive's CanonicalJSON in one place that
// matters here: a report may carry a negative integer, which the archive's SPEC.md 11.3 form refuses. So
// a report is canonicalised by its own writer below, which reuses the archive's string escaping and key
// order and follows the engine on numbers.
//
// The file is parsed strictly, because a verifier that reads a file one way while another tool reads it
// another way can print "verified" over content the signer never saw. A duplicated key, a lone UTF-16
// surrogate, bytes that are not UTF-8, a number not written as a plain integer and trailing content after
// the object are all refused.

// ReportSignaturePrefix is the scheme tag on a report signature, the same tag a signer fingerprint
// carries.
const ReportSignaturePrefix = "edmldsa1:"

// reportSignatureLen is the byte length of a decoded report signature: Ed25519 (64) + ML-DSA-87 (4627).
const reportSignatureLen = 64 + 4627

// maxReportDepth bounds how deeply the report's JSON may nest. Real reports nest a few levels.
const maxReportDepth = 256

// maxSafeInteger is 2^53 - 1, JavaScript's Number.MAX_SAFE_INTEGER, the ceiling the engine's
// canonicalJSON enforces in both directions.
const maxSafeInteger = 1<<53 - 1

// ReportPeriod is a time-bounded report's window, in epoch seconds.
type ReportPeriod struct {
	FromSeconds int64
	ToSeconds   int64
}

// VerifiedReport describes a report whose signature verified.
type VerifiedReport struct {
	Kind        string
	GeneratedAt string
	// PointInTime is true when period is null. Period is set when period is a {fromSeconds, toSeconds}
	// window of integers.
	PointInTime bool
	Period      *ReportPeriod
	// SignedBytes is the canonical JSON the signature covers.
	SignedBytes []byte
}

// reportSignedMembers are the members the signature covers, in the order the refusals name them.
var reportSignedMembers = []string{"kind", "generatedAt", "period", "data"}

// VerifyReport verifies a signed report file against the operator signer. It returns the report's
// kind, time and period when both signature halves verify.
//
// The error is an *ExitError. ExitUsage (6) means the input is not a report JSON this tool can read: a
// PDF, a UTF-16 file, a syntax error, or a JSON value that is not a report object. ExitUnverified (2)
// means it is a report and it did not verify: no signature, an unrecognised scheme, a malformed
// signature, content the engine cannot have signed, or a signature that fails under this signer.
func VerifyReport(raw []byte, verifier *crypto.HybridVerifier) (*VerifiedReport, error) {
	obj, err := parseReportObject(raw)
	if err != nil {
		return nil, err
	}
	sigText, err := reportSignature(obj)
	if err != nil {
		return nil, err
	}
	for _, k := range obj.keys {
		if k != "signature" && !isReportSignedMember(k) {
			return nil, coded(ExitUnverified, fmt.Errorf("the report has a top-level member %q that the signature does not cover. The engine emits only kind, generatedAt, period, data and signature, so this file is not the report as the engine emitted it", k))
		}
	}
	for _, k := range reportSignedMembers {
		if _, ok := obj.vals[k]; !ok {
			return nil, coded(ExitUnverified, fmt.Errorf("the report has no %q member, so the signed content cannot be rebuilt. The engine always emits kind, generatedAt, period and data", k))
		}
	}
	sig, err := decodeReportSignature(sigText)
	if err != nil {
		return nil, err
	}
	view := &reportObject{vals: map[string]any{}}
	for _, k := range reportSignedMembers {
		view.keys = append(view.keys, k)
		view.vals[k] = obj.vals[k]
	}
	var signed bytes.Buffer
	writeReportCanonical(&signed, view)

	edOK, mldsaOK := verifier.VerifyEach(signed.Bytes(), sig)
	switch {
	case edOK && mldsaOK:
	case !edOK && !mldsaOK:
		return nil, coded(ExitUnverified, errors.New("the report signature did not verify: neither the Ed25519 half nor the ML-DSA-87 half verified under this signer. Either the report was changed after it was signed, or a different signer signed it. Check the signer fingerprint against your recovery sheet"))
	case mldsaOK:
		return nil, coded(ExitUnverified, errors.New("the report signature did not verify: the ML-DSA-87 half verified and the Ed25519 half did not. The Ed25519 part of the report's signature member may be damaged (an edited or badly copied signature), or the Ed25519 half of the --signer file may be damaged or come from a partial signer rotation. Take the report JSON again from the engine and, if it still fails, take another copy of the signer public key (signer.pub) from your recovery kit. Do not rely on the report until both halves verify"))
	default:
		return nil, coded(ExitUnverified, errors.New("the report signature did not verify: the Ed25519 half verified and the ML-DSA-87 half did not. The ML-DSA-87 part of the report's signature member may be damaged (an edited or badly copied signature), or the ML-DSA-87 half of the --signer file may be damaged or come from a partial signer rotation. Take the report JSON again from the engine and, if it still fails, take another copy of the signer public key (signer.pub) from your recovery kit. Do not rely on the report until both halves verify"))
	}

	out := &VerifiedReport{SignedBytes: signed.Bytes()}
	out.Kind, _ = obj.vals["kind"].(string)
	out.GeneratedAt, _ = obj.vals["generatedAt"].(string)
	out.PointInTime = obj.vals["period"] == nil
	if p, ok := obj.vals["period"].(*reportObject); ok {
		from, fok := p.vals["fromSeconds"].(int64)
		to, tok := p.vals["toSeconds"].(int64)
		if fok && tok {
			out.Period = &ReportPeriod{FromSeconds: from, ToSeconds: to}
		}
	}
	return out, nil
}

func isReportSignedMember(k string) bool {
	for _, m := range reportSignedMembers {
		if k == m {
			return true
		}
	}
	return false
}

// reportSignature returns the signature member's text, refusing a report that has none.
func reportSignature(obj *reportObject) (string, error) {
	v, ok := obj.vals["signature"]
	if !ok || v == nil {
		return "", coded(ExitUnverified, errors.New("the report has no signature, so nothing in it can be verified. The engine returns a report unsigned when it has no signer configured or when signing fails. Treat its figures as informational only"))
	}
	s, ok := v.(string)
	if !ok {
		return "", coded(ExitUnverified, errors.New("the report's signature member is not a string, so it is not a signature the engine wrote"))
	}
	return s, nil
}

// decodeReportSignature strips the scheme tag and decodes the detached hybrid signature.
func decodeReportSignature(s string) ([]byte, error) {
	if !strings.HasPrefix(s, ReportSignaturePrefix) {
		shown := s
		if i := strings.IndexByte(s, ':'); i >= 0 {
			shown = s[:i+1]
		} else if len(shown) > 16 {
			shown = shown[:16] + "..."
		}
		return nil, coded(ExitUnverified, fmt.Errorf("the report signature does not carry the %q scheme tag (it starts %q), so this tool cannot verify it", ReportSignaturePrefix, shown))
	}
	sig, err := B64Decode(strings.TrimPrefix(s, ReportSignaturePrefix))
	if err != nil {
		return nil, coded(ExitUnverified, fmt.Errorf("the report signature is not valid unpadded base64url: %w", err))
	}
	if len(sig) != reportSignatureLen {
		return nil, coded(ExitUnverified, fmt.Errorf("the report signature decodes to %d bytes, and an %s signature is %d bytes (Ed25519 64 + ML-DSA-87 4627). It is truncated or damaged, which is often a copy that lost its end", len(sig), strings.TrimSuffix(ReportSignaturePrefix, ":"), reportSignatureLen))
	}
	return sig, nil
}

// reportObject is a parsed JSON object that remembers its members' order for error messages.
type reportObject struct {
	keys []string
	vals map[string]any
}

// parseReportObject reads the whole file as one strict JSON object.
func parseReportObject(raw []byte) (*reportObject, error) {
	switch {
	case bytes.HasPrefix(raw, []byte("%PDF-")):
		return nil, coded(ExitUsage, errors.New("this is the report PDF, and the PDF does not carry a signature this tool can check: its Signature line states only that the report was signed and with which scheme. The signature covers the report JSON. Each request to the engine generates a new report, so a JSON you fetch now is a separately generated report, not the one this PDF shows, and that JSON can be verified. Take it from the report card's View JSON in the console, or from GET /admin/reports/<kind>. The console offers a compliance evidence pack as a PDF only, so for its JSON fetch GET /admin/reports/evidence-pack?framework=<id>"))
	case bytes.HasPrefix(raw, []byte{0xFF, 0xFE}), bytes.HasPrefix(raw, []byte{0xFE, 0xFF}):
		return nil, coded(ExitUsage, errors.New("the report file is UTF-16 text. Save it as UTF-8 and run the command again (a PowerShell > redirect writes UTF-16; use Out-File -Encoding utf8, or Invoke-RestMethod -OutFile)"))
	}
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	if !utf8.Valid(raw) {
		return nil, coded(ExitUnverified, errors.New("the report file is not valid UTF-8, so it is not the JSON the engine emitted"))
	}
	p := &reportParser{b: raw}
	p.skipSpace()
	if p.i >= len(p.b) {
		return nil, coded(ExitUsage, errors.New("the report file is empty"))
	}
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.i != len(p.b) {
		return nil, coded(ExitUsage, fmt.Errorf("the report file has content after the JSON value, at byte %d. It holds more than one report, or the copy picked up extra text", p.i))
	}
	obj, ok := v.(*reportObject)
	if !ok {
		return nil, coded(ExitUsage, errors.New("the report file holds a JSON value that is not an object, so it is not a report"))
	}
	if _, hasKind := obj.vals["kind"]; !hasKind {
		if _, hasSig := obj.vals["signature"]; !hasSig {
			return nil, coded(ExitUsage, errors.New("the report file is a JSON object with neither a kind nor a signature member, so it is not a report"))
		}
	}
	return obj, nil
}

// reportParser is a strict RFC 8259 parser. It keeps integers as int64 and refuses what the engine
// cannot have signed.
type reportParser struct {
	b []byte
	i int
}

func (p *reportParser) syntax(what string) error {
	return coded(ExitUsage, fmt.Errorf("the report file is not valid JSON: %s at byte %d", what, p.i))
}

func (p *reportParser) skipSpace() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *reportParser) value(depth int) (any, error) {
	if depth > maxReportDepth {
		return nil, coded(ExitUsage, fmt.Errorf("the report file nests deeper than %d levels", maxReportDepth))
	}
	p.skipSpace()
	if p.i >= len(p.b) {
		return nil, p.syntax("unexpected end of input")
	}
	switch c := p.b[p.i]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		return p.str()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	case p.literal("true"):
		return true, nil
	case p.literal("false"):
		return false, nil
	case p.literal("null"):
		return nil, nil
	default:
		return nil, p.syntax(fmt.Sprintf("unexpected character %q", rune(c)))
	}
}

func (p *reportParser) literal(word string) bool {
	if bytes.HasPrefix(p.b[p.i:], []byte(word)) {
		p.i += len(word)
		return true
	}
	return false
}

func (p *reportParser) object(depth int) (any, error) {
	p.i++ // {
	obj := &reportObject{vals: map[string]any{}}
	p.skipSpace()
	if p.i < len(p.b) && p.b[p.i] == '}' {
		p.i++
		return obj, nil
	}
	for {
		p.skipSpace()
		if p.i >= len(p.b) || p.b[p.i] != '"' {
			return nil, p.syntax("expected a member name")
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		if _, dup := obj.vals[k]; dup {
			return nil, coded(ExitUnverified, fmt.Errorf("the report repeats the member name %q in one object. Two readers can take different values from such a file, and the engine never writes one", k))
		}
		p.skipSpace()
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			return nil, p.syntax("expected ':'")
		}
		p.i++
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		obj.keys = append(obj.keys, k)
		obj.vals[k] = v
		p.skipSpace()
		if p.i >= len(p.b) {
			return nil, p.syntax("unexpected end of input in an object")
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return obj, nil
		default:
			return nil, p.syntax("expected ',' or '}'")
		}
	}
}

func (p *reportParser) array(depth int) (any, error) {
	p.i++ // [
	arr := []any{}
	p.skipSpace()
	if p.i < len(p.b) && p.b[p.i] == ']' {
		p.i++
		return arr, nil
	}
	for {
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
		p.skipSpace()
		if p.i >= len(p.b) {
			return nil, p.syntax("unexpected end of input in an array")
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return arr, nil
		default:
			return nil, p.syntax("expected ',' or ']'")
		}
	}
}

// number reads an RFC 8259 number and returns it as int64. It accepts only the spelling the engine
// writes. The engine signs a number only when it is an integer within 2^53 - 1, and it serves the report
// with JSON.stringify, which writes such an integer in plain decimal without a fraction or an exponent
// (and writes -0 as 0). A spelling such as 1.0000000000000001 rounds to the same JavaScript double as 1,
// but a decimal-exact JSON reader shows it as a different value, so it is refused.
func (p *reportParser) number() (any, error) {
	start := p.i
	if p.b[p.i] == '-' {
		p.i++
	}
	switch {
	case p.i < len(p.b) && p.b[p.i] == '0':
		p.i++
	case p.i < len(p.b) && p.b[p.i] >= '1' && p.b[p.i] <= '9':
		p.digits()
	default:
		return nil, p.syntax("malformed number")
	}
	plain := true
	if p.i < len(p.b) && p.b[p.i] == '.' {
		p.i++
		if p.digits() == 0 {
			return nil, p.syntax("malformed number")
		}
		plain = false
	}
	if p.i < len(p.b) && (p.b[p.i] == 'e' || p.b[p.i] == 'E') {
		p.i++
		if p.i < len(p.b) && (p.b[p.i] == '+' || p.b[p.i] == '-') {
			p.i++
		}
		if p.digits() == 0 {
			return nil, p.syntax("malformed number")
		}
		plain = false
	}
	lit := string(p.b[start:p.i])
	if !plain || lit == "-0" {
		return nil, coded(ExitUnverified, fmt.Errorf("the report holds the number %s, which is not written as a plain integer. The engine writes integers only, in plain decimal, so it did not write this report", lit))
	}
	n, err := strconv.ParseInt(lit, 10, 64)
	if err != nil || n > maxSafeInteger || n < -maxSafeInteger {
		return nil, coded(ExitUnverified, fmt.Errorf("the report holds the integer %s, whose magnitude is over 2^53 - 1. The engine signs integers up to that magnitude only, so it cannot have signed this report", lit))
	}
	return n, nil
}

func (p *reportParser) digits() int {
	n := 0
	for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
		p.i++
		n++
	}
	return n
}

// str reads a JSON string. A \u escape that leaves a UTF-16 surrogate unpaired is refused: the engine
// refuses to sign such a string, and a Go reader would otherwise turn it into U+FFFD silently.
func (p *reportParser) str() (string, error) {
	p.i++ // opening quote
	var sb strings.Builder
	for {
		if p.i >= len(p.b) {
			return "", p.syntax("unterminated string")
		}
		c := p.b[p.i]
		switch {
		case c == '"':
			p.i++
			return sb.String(), nil
		case c < 0x20:
			return "", p.syntax("unescaped control character in a string")
		case c == '\\':
			r, err := p.escape()
			if err != nil {
				return "", err
			}
			sb.WriteRune(r)
		default:
			r, size := utf8.DecodeRune(p.b[p.i:])
			sb.WriteRune(r)
			p.i += size
		}
	}
}

// escape reads one escape sequence, joining a \u surrogate pair into one rune.
func (p *reportParser) escape() (rune, error) {
	p.i++ // backslash
	if p.i >= len(p.b) {
		return 0, p.syntax("unterminated escape")
	}
	c := p.b[p.i]
	p.i++
	switch c {
	case '"':
		return '"', nil
	case '\\':
		return '\\', nil
	case '/':
		return '/', nil
	case 'b':
		return '\b', nil
	case 'f':
		return '\f', nil
	case 'n':
		return '\n', nil
	case 'r':
		return '\r', nil
	case 't':
		return '\t', nil
	case 'u':
	default:
		return 0, p.syntax(fmt.Sprintf("invalid escape \\%c", c))
	}
	hi, err := p.hex4()
	if err != nil {
		return 0, err
	}
	if !utf16.IsSurrogate(hi) {
		return hi, nil
	}
	if hi >= 0xDC00 || !bytes.HasPrefix(p.b[p.i:], []byte(`\u`)) {
		return 0, p.loneSurrogate(hi)
	}
	p.i += 2
	lo, err := p.hex4()
	if err != nil {
		return 0, err
	}
	r := utf16.DecodeRune(hi, lo)
	if r == utf8.RuneError {
		return 0, p.loneSurrogate(hi)
	}
	return r, nil
}

func (p *reportParser) loneSurrogate(r rune) error {
	return coded(ExitUnverified, fmt.Errorf("the report holds an unpaired UTF-16 surrogate (\\u%04x) before byte %d. The engine refuses to sign such a string, so it cannot have signed this report", r, p.i))
}

func (p *reportParser) hex4() (rune, error) {
	if p.i+4 > len(p.b) {
		return 0, p.syntax("short \\u escape")
	}
	n, err := strconv.ParseUint(string(p.b[p.i:p.i+4]), 16, 32)
	if err != nil {
		return 0, p.syntax("malformed \\u escape")
	}
	p.i += 4
	return rune(n), nil
}

// writeReportCanonical writes v in the engine's canonical JSON form. Strings use the archive's
// escaping and objects the archive's UTF-16 key order; integers may be negative, as in the engine.
func writeReportCanonical(out *bytes.Buffer, v any) {
	switch t := v.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		out.WriteString(strconv.FormatBool(t))
	case int64:
		out.WriteString(strconv.FormatInt(t, 10))
	case string:
		writeJSONString(out, t)
	case []any:
		out.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				out.WriteByte(',')
			}
			writeReportCanonical(out, e)
		}
		out.WriteByte(']')
	case *reportObject:
		keys := append([]string(nil), t.keys...)
		sortUTF16(keys)
		out.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			writeJSONString(out, k)
			out.WriteByte(':')
			writeReportCanonical(out, t.vals[k])
		}
		out.WriteByte('}')
	}
}

// sortUTF16 sorts keys by UTF-16 code unit, the order the engine's canonicalJSON uses.
func sortUTF16(keys []string) {
	sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
}
