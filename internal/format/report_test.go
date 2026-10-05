package format

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
)

// The fixture under testdata/signed-report is written by the engine's own report code (makeReport and
// signReport in engine src/admin/reports.ts) through gen-fixture.mjs. These tests are the agreement gate
// between the two implementations: the Go canonical form must equal the bytes the engine signed, and the
// engine's signatures must verify here. Regenerate with the command in gen-fixture.mjs.

const reportFixtureDir = "testdata/signed-report"

func readReportFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(reportFixtureDir, name))
	if err != nil {
		t.Fatalf("reading the engine report fixture %s: %v", name, err)
	}
	return b
}

// reportFixtureSigner parses a labelled signer.pub file from the fixture.
func reportFixtureSigner(t *testing.T, name string) *crypto.HybridVerifier {
	t.Helper()
	fields := strings.Fields(string(readReportFixture(t, name)))
	if len(fields) != 2 || fields[0] != "downpipe-signer-public-v1" {
		t.Fatalf("%s is not a downpipe-signer-public-v1 file", name)
	}
	raw, err := B64Decode(fields[1])
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	v, err := crypto.ParseVerifier(raw)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return v
}

func wantReportCode(t *testing.T, name string, err error, code int, mention string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: verified, want exit %d", name, code)
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("%s: uncoded error %v, want exit %d", name, err, code)
	}
	if ee.Code != code {
		t.Fatalf("%s: exit %d (%v), want %d", name, ee.Code, err, code)
	}
	if mention != "" && !strings.Contains(err.Error(), mention) {
		t.Fatalf("%s: the message %q does not mention %q", name, err.Error(), mention)
	}
}

// The known answers: the canonical bytes Go rebuilds from each served report equal the bytes the engine
// signed, and the engine's signature verifies over them. restore-tests carries the strings and keys that
// separate a correct canonical form from a near miss (HTML characters, control characters, U+2028 and
// U+2029, a non-BMP character, UTF-16 key order and a negative integer).
func TestVerifyReportEngineKnownAnswers(t *testing.T) {
	v := reportFixtureSigner(t, "signer.pub")
	cases := []struct {
		file, canonical, kind string
		period                *ReportPeriod
	}{
		{"posture.json", "posture.canonical", "posture", nil},
		{"posture.pretty.json", "posture.canonical", "posture", nil},
		{"restore-tests.json", "restore-tests.canonical", "restore-tests", &ReportPeriod{FromSeconds: 1782432000, ToSeconds: 1790208000}},
	}
	for _, c := range cases {
		got, err := VerifyReport(readReportFixture(t, c.file), v)
		if err != nil {
			t.Fatalf("%s: the engine-signed report did not verify: %v", c.file, err)
		}
		if want := readReportFixture(t, c.canonical); !bytes.Equal(got.SignedBytes, want) {
			t.Fatalf("%s: the Go canonical form differs from the bytes the engine signed\n got: %s\nwant: %s", c.file, got.SignedBytes, want)
		}
		if got.Kind != c.kind || got.GeneratedAt != "2026-09-25T00:00:00.000Z" {
			t.Errorf("%s: kind %q generatedAt %q", c.file, got.Kind, got.GeneratedAt)
		}
		if (got.Period == nil) != (c.period == nil) || (c.period != nil && *got.Period != *c.period) {
			t.Errorf("%s: period %+v, want %+v", c.file, got.Period, c.period)
		}
	}
}

// The canonical form must not depend on the file's member order or whitespace: a report re-serialised
// with its members reversed and extra spacing still verifies.
func TestVerifyReportIgnoresLayout(t *testing.T) {
	v := reportFixtureSigner(t, "signer.pub")
	obj, err := parseReportObject(readReportFixture(t, "restore-tests.json"))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	b.WriteString("\ufeff{ \n")
	for i := len(obj.keys) - 1; i >= 0; i-- {
		k := obj.keys[i]
		writeJSONString(&b, k)
		b.WriteString(" :\t")
		writeReportCanonical(&b, obj.vals[k])
		if i > 0 {
			b.WriteString(",\r\n")
		}
	}
	b.WriteString("\n}\n")
	if _, err := VerifyReport(b.Bytes(), v); err != nil {
		t.Fatalf("a reordered, re-spaced report did not verify: %v", err)
	}
}

// Equivalent spellings of the same JSON string canonicalise the same way, as the engine reads them:
// escaped and literal characters. Numbers have no equivalent spellings here, because the engine writes
// only plain decimal integers; TestVerifyReportRefusals refuses the other forms.
func TestVerifyReportEquivalentSpellings(t *testing.T) {
	v := reportFixtureSigner(t, "signer.pub")
	raw := string(readReportFixture(t, "restore-tests.json"))
	for _, sub := range []struct{ from, to string }{
		{`"passed / ok"`, `"passed \/ ok"`},
		{`"kind":"restore-tests"`, `"kind":"restore\u002dtests"`},
		{"\U0001F600", `\ud83d\ude00`},
	} {
		if !strings.Contains(raw, sub.from) {
			t.Fatalf("the fixture no longer holds %q", sub.from)
		}
		if _, err := VerifyReport([]byte(strings.Replace(raw, sub.from, sub.to, 1)), v); err != nil {
			t.Errorf("respelling %q as %q broke verification: %v", sub.from, sub.to, err)
		}
	}
}

// Every change to signed content fails, and each refusal carries the exit code the reader's contract
// gives it.
func TestVerifyReportRefusals(t *testing.T) {
	v := reportFixtureSigner(t, "signer.pub")
	posture := string(readReportFixture(t, "posture.json"))
	restore := string(readReportFixture(t, "restore-tests.json"))
	replace := func(s, from, to string) []byte {
		t.Helper()
		if !strings.Contains(s, from) {
			t.Fatalf("the fixture no longer holds %q", from)
		}
		return []byte(strings.Replace(s, from, to, 1))
	}
	sigStart := strings.Index(posture, `"signature":"edmldsa1:`) + len(`"signature":"edmldsa1:`)
	sigEnd := strings.LastIndex(posture, `"`)
	sigText := posture[sigStart:sigEnd]
	withSig := func(sig string) []byte { return []byte(posture[:sigStart] + sig + posture[sigEnd:]) }
	sigBytes, err := B64Decode(sigText)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(i int) []byte {
		b := bytes.Clone(sigBytes)
		b[i] ^= 0x01
		return withSig(B64Encode(b))
	}
	// swapChar changes one base64url character of the signature member, as an edit or a bad copy of
	// the report file would. The Ed25519 half is the first 64 bytes, so characters before index 85
	// fall in it and characters from index 86 on fall in the ML-DSA-87 half.
	swapChar := func(i int) []byte {
		c := byte('A')
		if sigText[i] == 'A' {
			c = 'B'
		}
		return withSig(sigText[:i] + string(c) + sigText[i+1:])
	}
	const edFails = "the ML-DSA-87 half verified and the Ed25519 half did not. The Ed25519 part of the report's signature member may be damaged"
	const mldsaFails = "the Ed25519 half verified and the ML-DSA-87 half did not. The ML-DSA-87 part of the report's signature member may be damaged"

	cases := []struct {
		name    string
		raw     []byte
		code    int
		mention string
	}{
		{"a changed score", replace(posture, `"score":87`, `"score":97`), ExitUnverified, "neither the Ed25519 half nor the ML-DSA-87 half"},
		{"a changed kind", replace(posture, `"kind":"posture"`, `"kind":"immutability"`), ExitUnverified, "neither"},
		{"a changed time", replace(posture, `2026-09-25T00:00:00.000Z`, `2026-09-26T00:00:00.000Z`), ExitUnverified, "neither"},
		{"a period added", replace(posture, `"period":null`, `"period":{"fromSeconds":0,"toSeconds":1}`), ExitUnverified, "neither"},
		{"a changed window", replace(restore, `"fromSeconds":1782432000`, `"fromSeconds":1782431999`), ExitUnverified, "neither"},
		{"a changed U+2028", replace(restore, "\u2028", "\u2029"), ExitUnverified, "neither"},
		{"a flipped Ed25519 byte", flip(0), ExitUnverified, edFails},
		{"a flipped ML-DSA-87 byte", flip(len(sigBytes) - 1), ExitUnverified, mldsaFails},
		{"one changed character in the Ed25519 part", swapChar(10), ExitUnverified, edFails},
		{"one changed character in the ML-DSA-87 part", swapChar(len(sigText) / 2), ExitUnverified, mldsaFails},
		{"the Ed25519 half alone", withSig(B64Encode(sigBytes[:64])), ExitUnverified, "decodes to 64 bytes"},
		{"the ML-DSA-87 half alone", withSig(B64Encode(sigBytes[64:])), ExitUnverified, "decodes to 4627 bytes"},
		{"a truncated signature", withSig(sigText[:len(sigText)-8]), ExitUnverified, "truncated or damaged"},
		{"padded base64", withSig(sigText + "="), ExitUnverified, "base64url"},
		{"another scheme", replace(posture, `"edmldsa1:`, `"ed25519:`), ExitUnverified, `"ed25519:"`},
		{"no signature", readReportFixture(t, "unsigned.json"), ExitUnverified, "no signature"},
		{"a null signature", withSigMember(posture, `null`), ExitUnverified, "no signature"},
		{"a numeric signature", withSigMember(posture, `7`), ExitUnverified, "not a string"},
		{"an extra member", replace(posture, `"kind":"posture"`, `"kind":"posture","verified":true`), ExitUnverified, `"verified"`},
		{"no period member", replace(posture, `"period":null,`, ``), ExitUnverified, `"period"`},
		{"a duplicated member", replace(posture, `"kind":"posture"`, `"kind":"posture","kind":"posture"`), ExitUnverified, "repeats the member name"},
		{"a duplicated nested member", replace(posture, `"score":87`, `"score":87,"score":87`), ExitUnverified, "repeats"},
		{"a fraction", replace(posture, `"score":87`, `"score":87.5`), ExitUnverified, "not written as a plain integer"},
		{"an integer with a zero fraction", replace(posture, `"score":87`, `"score":87.000`), ExitUnverified, "not written as a plain integer"},
		{"an integer with an exponent", replace(posture, `"score":87`, `"score":8.7e1`), ExitUnverified, "not written as a plain integer"},
		{"a fraction that rounds to the signed double", replace(posture, `"score":87`, `"score":87.00000000000001`), ExitUnverified, "not written as a plain integer"},
		{"a fraction that rounds up to the signed double", replace(posture, `"score":87`, `"score":86.99999999999999999999`), ExitUnverified, "not written as a plain integer"},
		{"a negative zero", replace(posture, `"score":87`, `"score":-0`), ExitUnverified, "not written as a plain integer"},
		{"an unsafe integer", replace(posture, `"score":87`, `"score":9007199254740992`), ExitUnverified, "magnitude is over 2^53 - 1"},
		{"an unsafe negative integer", replace(posture, `"score":87`, `"score":-9007199254740992`), ExitUnverified, "magnitude is over 2^53 - 1"},
		{"an integer beyond int64", replace(posture, `"score":87`, `"score":99999999999999999999`), ExitUnverified, "magnitude is over 2^53 - 1"},
		{"an infinite number", replace(posture, `"score":87`, `"score":1e999`), ExitUnverified, "not written as a plain integer"},
		{"a lone high surrogate", replace(posture, `"break-glass-recipient"`, `"break-glass\ud800"`), ExitUnverified, "unpaired"},
		{"a lone low surrogate", replace(posture, `"break-glass-recipient"`, `"break-glass\udc00"`), ExitUnverified, "unpaired"},
		{"a high surrogate before a letter", replace(posture, `"break-glass-recipient"`, `"\ud800A"`), ExitUnverified, "unpaired"},
		{"invalid UTF-8", replace(posture, `recipient`, "recipi\xffnt"), ExitUnverified, "not valid UTF-8"},
		{"the PDF", []byte("%PDF-1.4\n..."), ExitUsage, "the PDF does not carry a signature this tool can check"},
		{"UTF-16", append([]byte{0xFF, 0xFE}, []byte(posture)...), ExitUsage, "UTF-16"},
		{"an empty file", []byte(" \n"), ExitUsage, "empty"},
		{"two reports", []byte(posture + posture), ExitUsage, "content after the JSON value"},
		{"an array", []byte(`[` + posture + `]`), ExitUsage, "not an object"},
		{"an unrelated object", []byte(`{"hello":"world"}`), ExitUsage, "not a report"},
		{"a truncated file", []byte(posture[:len(posture)/2]), ExitUsage, "not valid JSON"},
		{"a raw control character", replace(posture, `"posture"`, "\"post\x01ure\""), ExitUsage, "control character"},
		{"a bad escape", replace(posture, `"posture"`, `"post\xure"`), ExitUsage, "invalid escape"},
		{"a short unicode escape", replace(posture, `"posture"`, `"post\u00"`), ExitUsage, "escape"},
		{"a leading plus", replace(posture, `"score":87`, `"score":+87`), ExitUsage, "unexpected character"},
		{"a bare minus", replace(posture, `"score":87`, `"score":-`), ExitUsage, "malformed number"},
		{"a bare point", replace(posture, `"score":87`, `"score":87.`), ExitUsage, "malformed number"},
		{"a bare exponent", replace(posture, `"score":87`, `"score":87e`), ExitUsage, "malformed number"},
		{"a missing colon", replace(posture, `"score":87`, `"score" 87`), ExitUsage, "expected ':'"},
		{"a missing comma", replace(posture, `"score":87,`, `"score":87 `), ExitUsage, "expected ','"},
		{"an unquoted name", replace(posture, `"score":87`, `score:87`), ExitUsage, "member name"},
		{"a bad array", replace(posture, `"checks":[`, `"checks":[1 2,`), ExitUsage, "expected ',' or ']'"},
		{"too deep", []byte(strings.Repeat("[", maxReportDepth+2) + strings.Repeat("]", maxReportDepth+2)), ExitUsage, "nests deeper"},
	}
	for _, c := range cases {
		_, err := VerifyReport(c.raw, v)
		wantReportCode(t, c.name, err, c.code, c.mention)
	}
}

// withSigMember replaces the whole signature member's value.
func withSigMember(report, value string) []byte {
	i := strings.Index(report, `"signature":`) + len(`"signature":`)
	return []byte(report[:i] + value + "}")
}

// The report verifies only under the signer that signed it, and both halves of the verifier matter.
func TestVerifyReportSignerHalves(t *testing.T) {
	good := reportFixtureSigner(t, "signer.pub")
	other := reportFixtureSigner(t, "other-signer.pub")
	raw := readReportFixture(t, "posture.json")

	_, err := VerifyReport(raw, other)
	wantReportCode(t, "another signer", err, ExitUnverified, "neither")

	_, err = VerifyReport(raw, &crypto.HybridVerifier{Ed: other.Ed, MLDSA: good.MLDSA})
	wantReportCode(t, "a foreign Ed25519 half", err, ExitUnverified, "or the Ed25519 half of the --signer file may be damaged or come from a partial signer rotation")

	_, err = VerifyReport(raw, &crypto.HybridVerifier{Ed: good.Ed, MLDSA: other.MLDSA})
	wantReportCode(t, "a foreign ML-DSA-87 half", err, ExitUnverified, "or the ML-DSA-87 half of the --signer file may be damaged or come from a partial signer rotation")
}

// A report the Go side signs the way the engine does verifies, including a negative integer and every
// JSON value type. This is the round trip the fixture pins from the engine side.
func TestVerifyReportRoundTrip(t *testing.T) {
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	body := `{"kind":"sla-compliance","generatedAt":"2026-09-25T00:00:00.000Z","period":{"fromSeconds":1,"toSeconds":2},"data":{"b":[true,false,null,-9007199254740991,0,"x"],"a":{},"s":"\b\f\n\r\t\"\\\/\u0041\u00e9"}}`
	obj, err := parseReportObject([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	var canon bytes.Buffer
	writeReportCanonical(&canon, obj)
	if want := `{"data":{"a":{},"b":[true,false,null,-9007199254740991,0,"x"],"s":"\b\f\n\r\t\"\\/A` + "\u00e9" + `"},"generatedAt":"2026-09-25T00:00:00.000Z","kind":"sla-compliance","period":{"fromSeconds":1,"toSeconds":2}}`; canon.String() != want {
		t.Fatalf("canonical form\n got: %s\nwant: %s", canon.String(), want)
	}
	sig, err := signer.Sign(canon.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	signed := strings.TrimSuffix(body, "}") + `,"signature":"` + ReportSignaturePrefix + B64Encode(sig) + `"}`
	got, err := VerifyReport([]byte(signed), verifier)
	if err != nil {
		t.Fatalf("a report signed as the engine signs did not verify: %v", err)
	}
	if got.Kind != "sla-compliance" || got.Period == nil || got.Period.FromSeconds != 1 || got.Period.ToSeconds != 2 {
		t.Errorf("unexpected verdict %+v", got)
	}

	// -0 canonicalises to the same bytes as 0, so the signature would verify over it. The engine writes
	// the JavaScript -0 as 0, and a decimal-exact reader shows -0 as a different value, so it is refused.
	zero := strings.Replace(signed, `,0,"x"]`, `,-0,"x"]`, 1)
	_, err = VerifyReport([]byte(zero), verifier)
	wantReportCode(t, "-0 over a signature on 0", err, ExitUnverified, "not written as a plain integer")
}

// FuzzVerifyReport feeds arbitrary bytes to the report parser. It must never panic, and any refusal
// must be a coded exit 2 or 6.
func FuzzVerifyReport(f *testing.F) {
	for _, name := range []string{"posture.json", "posture.pretty.json", "restore-tests.json", "unsigned.json"} {
		b, err := os.ReadFile(filepath.Join(reportFixtureDir, name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(`{"kind":"x","signature":"edmldsa1:"}`))
	f.Add([]byte(`"😀"`))
	f.Add([]byte(`-0.5e-7`))
	_, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, err := VerifyReport(raw, verifier)
		if err == nil {
			return
		}
		var ee *ExitError
		if !errors.As(err, &ee) || (ee.Code != ExitUnverified && ee.Code != ExitUsage) {
			t.Fatalf("refusal %v is not a coded exit 2 or 6", err)
		}
	})
}

// The PDF refusal says that a fresh JSON fetch is a separately generated report, and names the JSON
// route for the evidence pack, which the console offers as a PDF only.
func TestVerifyReportPDFRefusalNamesTheJSONSources(t *testing.T) {
	v := reportFixtureSigner(t, "signer.pub")
	_, err := VerifyReport([]byte("%PDF-1.7\n"), v)
	for _, want := range []string{
		"separately generated report, not the one this PDF shows",
		"GET /admin/reports/<kind>",
		"GET /admin/reports/evidence-pack?framework=<id>",
	} {
		wantReportCode(t, "the PDF", err, ExitUsage, want)
	}
}
