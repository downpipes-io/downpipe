package format

// Direct unit tests for the primitives in encoding.go, the
// FrameContainer/UnframeContainer framing in spec, the RootManifest JSON
// round-trip, and the coded/ExitError helpers in errors.go.
//
// These cases fill the gaps left by the existing test suite: SHA384Hex against
// a known vector, B64 edge cases (empty input, invalid input), container
// framing in isolation, manifest canonical-JSON determinism, and the error
// helper paths.

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// ---------------------------------------------------------------------------
// B64 encoding (encoding.go)
// ---------------------------------------------------------------------------

// TestB64RoundTripEdgeCases extends the brief shard_test.go smoke-test with
// additional inputs: the empty slice, a single byte, and a value whose
// base64url-no-pad length has no trailing padding.
func TestB64RoundTripEdgeCases(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", []byte{}},
		{"single zero byte", []byte{0x00}},
		{"single 0xff", []byte{0xff}},
		{"two bytes", []byte{0x00, 0xff}},
		{"three bytes", []byte{0xde, 0xad, 0xbe}},
		{"four bytes crosses padding boundary", []byte{0x01, 0x02, 0x03, 0x04}},
		{"16-byte nonce-sized block", bytes.Repeat([]byte{0xab}, 16)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			enc := B64Encode(c.in)
			// Must not contain padding or standard-alphabet + chars.
			for _, ch := range enc {
				if ch == '=' || ch == '+' || ch == '/' {
					t.Fatalf("B64Encode produced a forbidden character %q in %q", ch, enc)
				}
			}
			got, err := B64Decode(enc)
			if err != nil {
				t.Fatalf("B64Decode(%q): %v", enc, err)
			}
			if !bytes.Equal(got, c.in) {
				t.Fatalf("round-trip mismatch: got %x, want %x", got, c.in)
			}
		})
	}
}

// TestB64DecodeInvalidInput checks that B64Decode rejects inputs that are not
// valid base64url-no-pad: a standard-alphabet '+', a '/', and a pad '='.
func TestB64DecodeInvalidInput(t *testing.T) {
	cases := []struct {
		name string
		s    string
	}{
		{"standard alphabet plus", "ab+c"},
		{"standard alphabet slash", "ab/c"},
		{"with padding", "YWJj="},
		{"clearly garbage", "!!!"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := B64Decode(c.s); err == nil {
				t.Fatalf("B64Decode(%q) unexpectedly succeeded", c.s)
			}
		})
	}
}

// TestSHA384HexKnownVector checks SHA384Hex against the well-known SHA-384 of
// the empty string, independently derivable from any reference implementation.
// The hex is the canonical NIST value.
func TestSHA384HexKnownVector(t *testing.T) {
	// SHA-384("") from NIST FIPS 180-4 test vectors.
	const emptyHex = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
	if got := SHA384Hex([]byte{}); got != emptyHex {
		t.Fatalf("SHA384Hex(empty): got %s, want %s", got, emptyHex)
	}
	// SHA-384("abc") from NIST.
	const abcHex = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
	if got := SHA384Hex([]byte("abc")); got != abcHex {
		t.Fatalf("SHA384Hex(\"abc\"): got %s, want %s", got, abcHex)
	}
}

// TestSHA384HexIsDeterministic confirms the same input always produces the
// same output (property test over a non-trivial payload).
func TestSHA384HexIsDeterministic(t *testing.T) {
	payload := bytes.Repeat([]byte{0x55}, 200)
	a := SHA384Hex(payload)
	b := SHA384Hex(payload)
	if a != b {
		t.Fatal("SHA384Hex is not deterministic")
	}
}

// TestSHA384HexOutputLength confirms the output is always 96 hex characters
// (48 bytes * 2 hex digits).
func TestSHA384HexOutputLength(t *testing.T) {
	inputs := [][]byte{
		{},
		{0x00},
		bytes.Repeat([]byte{0xff}, 64),
	}
	for _, in := range inputs {
		got := SHA384Hex(in)
		if len(got) != 96 {
			t.Fatalf("SHA384Hex output length: got %d, want 96 (input len %d)", len(got), len(in))
		}
		// All characters must be lowercase hex.
		for _, ch := range got {
			if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
				t.Fatalf("SHA384Hex output contains non-lowercase-hex character %q", ch)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Container framing (spec.FrameContainer / spec.UnframeContainer)
// ---------------------------------------------------------------------------

// TestFrameUnframeRoundTrip verifies FrameContainer/UnframeContainer for both
// magic values (DPE1 and DPS1) with representative payloads.
func TestFrameUnframeRoundTrip(t *testing.T) {
	magics := []struct {
		name  string
		magic [4]byte
	}{
		{"MagicDpe", spec.MagicDpe},
		{"MagicSeg", spec.MagicSeg},
	}
	payloads := [][]byte{
		{},
		{0x00},
		bytes.Repeat([]byte{0xca, 0xfe}, 50),
	}
	for _, m := range magics {
		for _, payload := range payloads {
			framed := spec.FrameContainer(m.magic, payload)
			// Header must be exactly ContainerHeaderSize bytes prepended.
			if len(framed) != spec.ContainerHeaderSize+len(payload) {
				t.Fatalf("%s: framed length %d, want %d", m.name, len(framed), spec.ContainerHeaderSize+len(payload))
			}
			// The version byte must match.
			if framed[4] != spec.ContainerVersion {
				t.Fatalf("%s: container version byte %x, want %x", m.name, framed[4], spec.ContainerVersion)
			}
			got, err := spec.UnframeContainer(m.magic, framed)
			if err != nil {
				t.Fatalf("%s: UnframeContainer: %v", m.name, err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("%s: payload mismatch: got %x, want %x", m.name, got, payload)
			}
		}
	}
}

// TestUnframeContainerBadMagic verifies that a wrong magic is rejected.
func TestUnframeContainerBadMagic(t *testing.T) {
	// Frame with DPE1, try to unframe expecting DPS1.
	framed := spec.FrameContainer(spec.MagicDpe, []byte("payload"))
	if _, err := spec.UnframeContainer(spec.MagicSeg, framed); err == nil {
		t.Fatal("UnframeContainer must reject mismatched magic")
	}
}

// TestUnframeContainerTruncatedInput verifies that inputs shorter than the
// ContainerHeaderSize are rejected.
func TestUnframeContainerTruncatedInput(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"one byte", []byte{spec.MagicDpe[0]}},
		{"four bytes (magic only, no version)", append([]byte(nil), spec.MagicDpe[:]...)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := spec.UnframeContainer(spec.MagicDpe, c.input); err == nil {
				t.Fatalf("UnframeContainer must reject %s input", c.name)
			}
		})
	}
}

// TestUnframeContainerWrongVersion verifies that an unsupported version byte is
// rejected while the magic is correct.
func TestUnframeContainerWrongVersion(t *testing.T) {
	// Construct a container whose version byte is not ContainerVersion.
	framed := spec.FrameContainer(spec.MagicDpe, []byte("data"))
	framed[4] ^= 0x01 // flip the version byte
	if _, err := spec.UnframeContainer(spec.MagicDpe, framed); err == nil {
		t.Fatal("UnframeContainer must reject an unsupported container version")
	}
}

// TestFrameContainerHeaderBytes confirms the exact byte layout: 4 magic bytes
// followed by ContainerVersion (0x01) then the payload.
func TestFrameContainerHeaderBytes(t *testing.T) {
	payload := []byte{0xde, 0xad}
	framed := spec.FrameContainer(spec.MagicDpe, payload)
	// Bytes 0-3: magic.
	if !bytes.Equal(framed[:4], spec.MagicDpe[:]) {
		t.Fatalf("DPE1 magic bytes wrong: %x", framed[:4])
	}
	// Byte 4: version.
	if framed[4] != spec.ContainerVersion {
		t.Fatalf("version byte: got %x, want %x", framed[4], spec.ContainerVersion)
	}
	// Bytes 5-: payload.
	if !bytes.Equal(framed[5:], payload) {
		t.Fatalf("payload bytes wrong: got %x, want %x", framed[5:], payload)
	}
}

// ---------------------------------------------------------------------------
// RootManifest JSON round-trip
// ---------------------------------------------------------------------------

// TestRootManifestJSONRoundTrip confirms that a RootManifest marshals to
// canonical JSON and that ParseRoot reproduces the original field values, so
// a verifier can re-canonicalise stored bytes and get an identical digest.
func TestRootManifestJSONRoundTrip(t *testing.T) {
	prevID := "01ARZ3NDEKTSV4RRFFQ69G5FAU"
	m := &spec.RootManifest{
		FormatVersion:       spec.Version,
		RunID:               "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		CreatedAt:           "2026-06-06T12:00:00.000Z",
		DownpipeID:          "dp_test",
		Envelope:            spec.Envelope{AEAD: "AES-256-GCM", KEM: "X25519+ML-KEM-1024", Signature: "Ed25519+ML-DSA-87", KDF: "HKDF-SHA-384", ChunkSize: spec.ChunkSize, Codec: "none"},
		BreakGlassPresent:   true,
		ShardCount:          2,
		DeclaredRecordCount: 42,
		MerkleRoot:          "deadbeef1234",
		Freshness:           spec.Freshness{PrevRunID: &prevID, RunlogIndex: 7},
	}
	canonical, err := MarshalRoot(m)
	if err != nil {
		t.Fatalf("MarshalRoot: %v", err)
	}
	if len(canonical) == 0 {
		t.Fatal("MarshalRoot returned empty bytes")
	}

	parsed, err := ParseRoot(canonical)
	if err != nil {
		t.Fatalf("ParseRoot: %v", err)
	}

	// Field-level checks that the round-trip preserved values.
	if parsed.RunID != m.RunID {
		t.Errorf("RunID: got %q, want %q", parsed.RunID, m.RunID)
	}
	if parsed.DeclaredRecordCount != m.DeclaredRecordCount {
		t.Errorf("DeclaredRecordCount: got %d, want %d", parsed.DeclaredRecordCount, m.DeclaredRecordCount)
	}
	if parsed.ShardCount != m.ShardCount {
		t.Errorf("ShardCount: got %d, want %d", parsed.ShardCount, m.ShardCount)
	}
	if parsed.MerkleRoot != m.MerkleRoot {
		t.Errorf("MerkleRoot: got %q, want %q", parsed.MerkleRoot, m.MerkleRoot)
	}
	if parsed.Freshness.RunlogIndex != m.Freshness.RunlogIndex {
		t.Errorf("Freshness.RunlogIndex: got %d, want %d", parsed.Freshness.RunlogIndex, m.Freshness.RunlogIndex)
	}
	if parsed.Freshness.PrevRunID == nil || *parsed.Freshness.PrevRunID != prevID {
		t.Errorf("Freshness.PrevRunID: got %v, want %q", parsed.Freshness.PrevRunID, prevID)
	}
	if parsed.Envelope.AEAD != m.Envelope.AEAD {
		t.Errorf("Envelope.AEAD: got %q, want %q", parsed.Envelope.AEAD, m.Envelope.AEAD)
	}

	// Re-canonicalise the parsed manifest: the bytes must be identical, which is
	// what lets a verifier hash the stored bytes and reproduce a consistent digest.
	again, err := MarshalRoot(parsed)
	if err != nil {
		t.Fatalf("second MarshalRoot: %v", err)
	}
	if !bytes.Equal(canonical, again) {
		t.Fatalf("re-canonicalised manifest differs from first canonical bytes:\nfirst:  %s\nsecond: %s", canonical, again)
	}
}

// TestRootManifestJSONDeterministic confirms that MarshalRoot is deterministic:
// the same manifest always produces the same bytes.
func TestRootManifestJSONDeterministic(t *testing.T) {
	m := sampleRoot() // defined in sign_test.go
	a, err := MarshalRoot(m)
	if err != nil {
		t.Fatal(err)
	}
	b, err := MarshalRoot(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("MarshalRoot is not deterministic")
	}
}

// TestRootManifestFirstRunNullPrev checks that a first-run manifest (PrevRunID
// nil) marshals prevRunId as the JSON null literal and parses back correctly.
func TestRootManifestFirstRunNullPrev(t *testing.T) {
	m := &spec.RootManifest{
		FormatVersion:       spec.Version,
		RunID:               "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		CreatedAt:           "2026-06-06T00:00:00.000Z",
		DeclaredRecordCount: 1,
		ShardCount:          1,
		Freshness:           spec.Freshness{PrevRunID: nil, RunlogIndex: 1},
	}
	canonical, err := MarshalRoot(m)
	if err != nil {
		t.Fatalf("MarshalRoot: %v", err)
	}
	// The JSON must contain the null literal for prevRunId.
	if !bytes.Contains(canonical, []byte(`"prevRunId":null`)) {
		t.Fatalf("first-run manifest must carry prevRunId:null, got: %s", canonical)
	}
	parsed, err := ParseRoot(canonical)
	if err != nil {
		t.Fatalf("ParseRoot: %v", err)
	}
	if parsed.Freshness.PrevRunID != nil {
		t.Fatalf("parsed PrevRunID: want nil, got %q", *parsed.Freshness.PrevRunID)
	}
}

// TestParseRootRejectsInvalidJSON confirms that ParseRoot returns an error on
// malformed JSON.
func TestParseRootRejectsInvalidJSON(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", []byte{}},
		{"truncated", []byte(`{"runId":`)},
		{"not JSON", []byte(`not json at all`)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseRoot(c.in); err == nil {
				t.Fatalf("ParseRoot(%q) must fail", c.in)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ExitError and coded helpers (errors.go)
// ---------------------------------------------------------------------------

// TestCodedNilReturnsNil verifies that coded(code, nil) returns nil so callers
// can write "return coded(ExitUsage, err)" unconditionally without nil-wrapping.
func TestCodedNilReturnsNil(t *testing.T) {
	if got := coded(ExitUsage, nil); got != nil {
		t.Fatalf("coded(ExitUsage, nil) must return nil, got %v", got)
	}
	if got := coded(ExitStale, nil); got != nil {
		t.Fatalf("coded(ExitStale, nil) must return nil, got %v", got)
	}
}

// TestExitErrorInterface verifies the ExitError.Error() message and Unwrap()
// chain so errors.As and errors.Is work correctly through the wrapper.
func TestExitErrorInterface(t *testing.T) {
	sentinel := errors.New("underlying cause")
	ee := &ExitError{Code: ExitUnverified, Err: sentinel}

	// Error() must return the underlying message.
	if got := ee.Error(); got != "underlying cause" {
		t.Fatalf("ExitError.Error(): got %q, want %q", got, "underlying cause")
	}

	// Unwrap() must return the wrapped error, enabling errors.Is.
	if !errors.Is(ee, sentinel) {
		t.Fatal("errors.Is must find the sentinel through ExitError")
	}
}

// TestCodedWrapsError confirms that coded(code, err) produces an *ExitError
// carrying the right code and that errors.As extracts it correctly.
func TestCodedWrapsError(t *testing.T) {
	inner := errors.New("inner")
	for _, tc := range []struct {
		code int
	}{
		{ExitVerified},
		{ExitUnverified},
		{ExitIncomplete},
		{ExitPlaintext},
		{ExitStale},
		{ExitUsage},
	} {
		err := coded(tc.code, inner)
		if err == nil {
			t.Fatalf("coded(%d, non-nil) must not return nil", tc.code)
		}
		var ee *ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("coded(%d, err): result is not *ExitError", tc.code)
		}
		if ee.Code != tc.code {
			t.Fatalf("ExitError.Code: got %d, want %d", ee.Code, tc.code)
		}
	}
}

// exitCodePins is the pinned exit-code contract, and the ONLY copy of it. Both tests below read this
// one slice. It used to be a local table in TestExitCodeConstants with a second, hand-maintained list
// of the same names in the coverage test, and that duplication was itself a hole: retiring a row by
// commenting it out, which is how a row actually gets retired, dropped the constant from every value
// and distinctness check while the hand-maintained list still swore it was pinned. Proven against this
// repository by commenting out the ExitUnwritten row and setting ExitUnwritten to 9 in errors.go; the
// whole package stayed green with ExitUnwritten and ExitCustody colliding on 9, which is the precise
// defect the distinctness check below was written after.
var exitCodePins = []struct {
	name string
	got  int
	want int
}{
	{"ExitVerified", ExitVerified, 0},
	{"ExitUnverified", ExitUnverified, 2},
	{"ExitIncomplete", ExitIncomplete, 3},
	{"ExitPlaintext", ExitPlaintext, 4},
	{"ExitStale", ExitStale, 5},
	{"ExitUsage", ExitUsage, 6},
	// The two advisory codes are outside the SPEC-normative set but are just as much a contract
	// with a DR script, and a refactor that renumbered them would silently change what an
	// operator's automation concludes from a restore.
	{"ExitPreflight", ExitPreflight, 7},
	{"ExitIncompleteMarkers", ExitIncompleteMarkers, 8},
	{"ExitCustody", ExitCustody, 9},
	{"ExitUnwritten", ExitUnwritten, 10},
	{"ExitUnreachable", ExitUnreachable, 11},
	{"ExitUnrenderable", ExitUnrenderable, 12},
	{"ExitDangling", ExitDangling, 13},
}

// TestExitCodeConstants verifies the normative exit code values from SPEC.md
// 8.5 are not accidentally changed by a refactor.
func TestExitCodeConstants(t *testing.T) {
	for _, c := range exitCodePins {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// exitConstant is one Exit* constant as the compiler would see it, recovered from the parsed source.
type exitConstant struct {
	name  string
	value int
	pos   string
}

// declaredExitConstants parses every non-test Go file of this package and returns every constant whose
// name begins with Exit, with its value resolved.
//
// ACCOUNTING IS TOTAL. Anything this function cannot resolve to an integer fails the test naming the
// file and line, rather than being skipped and counted as absent. That is the whole difference from the
// regular expression it replaces, which looked for `Exit<name> = <digits>` and treated everything else
// as nothing to see. Two evasions were proven against this repository before the rewrite:
//
//   - `ExitTruncated = ExitCustody`, a new code given an existing code's value by name rather than by
//     digits, matched no pattern and so was never reported as unpinned. A new constant silently sharing
//     a number with an old one is exactly what the distinctness check exists to stop, and this is the
//     shortest way to write it.
//   - The scan was pinned to errors.go by filename, so the same declaration in any other file of the
//     package was invisible. It now reads the package.
//
// A constant is resolved from an integer literal, or from a reference to another Exit constant, which
// is followed. iota, arithmetic, and implicit repetition of a previous spec's value are all refused
// loudly: they are not used here, and a gate that guessed at them would be guessing at the number a
// disaster-recovery script branches on.
func declaredExitConstants(t *testing.T) []exitConstant {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read format package directory: %v", err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("cannot parse %s, so its exit codes cannot be accounted for: %v", name, perr)
		}
		files = append(files, f)
	}
	// A gate that scans nothing reads exactly like a passing gate.
	if len(files) < 10 {
		t.Fatalf("expected this package's source files, found only %d. Has the layout moved?", len(files))
	}

	byName := map[string]int{}
	var out []exitConstant
	// Two passes: the first takes literal values, the second follows references to them, so the
	// order of declaration within the package cannot decide whether a reference resolves.
	type pending struct {
		name, ref, pos string
	}
	var refs []pending
	for _, f := range files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, s := range gd.Specs {
				vs, ok := s.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, id := range vs.Names {
					if !strings.HasPrefix(id.Name, "Exit") {
						continue
					}
					pos := fset.Position(id.Pos()).String()
					if i >= len(vs.Values) {
						t.Fatalf("%s at %s has no value of its own (iota or an implicit repeat); this gate will not guess the number a DR script branches on", id.Name, pos)
					}
					switch v := vs.Values[i].(type) {
					case *ast.BasicLit:
						if v.Kind != token.INT {
							t.Fatalf("%s at %s is a %s literal, not an integer", id.Name, pos, v.Kind)
						}
						n, cerr := strconv.Atoi(v.Value)
						if cerr != nil {
							t.Fatalf("%s at %s has unreadable value %q: %v", id.Name, pos, v.Value, cerr)
						}
						byName[id.Name] = n
						out = append(out, exitConstant{name: id.Name, value: n, pos: pos})
					case *ast.Ident:
						refs = append(refs, pending{name: id.Name, ref: v.Name, pos: pos})
					default:
						t.Fatalf("%s at %s is set from an expression this gate cannot resolve to a number; write it as an integer literal or as another Exit constant", id.Name, pos)
					}
				}
			}
		}
	}
	for _, r := range refs {
		n, ok := byName[r.ref]
		if !ok {
			t.Fatalf("%s at %s is set from %s, which is not an Exit constant with a literal value in this package", r.name, r.pos, r.ref)
		}
		out = append(out, exitConstant{name: r.name, value: n, pos: r.pos})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// TestExitCodeTableCoversEveryConstant keeps the pinned table honest against the source. The collision
// it checks for went unnoticed because ExitCustody was not in the table at all, so a distinctness check
// would have had nothing to compare. Pinning values is worth little if a new constant can be added
// without appearing here, so the constants are read from the parsed package rather than trusted to be
// listed, and the distinctness check runs over what is DECLARED rather than over what is pinned.
func TestExitCodeTableCoversEveryConstant(t *testing.T) {
	declared := declaredExitConstants(t)
	if len(declared) < len(exitCodePins) {
		t.Fatalf("found only %d Exit constants in the package but %d are pinned; the scan has probably stopped seeing them", len(declared), len(exitCodePins))
	}

	pinned := map[string]int{}
	for _, c := range exitCodePins {
		pinned[c.name] = c.want
	}
	seen := map[string]bool{}
	for _, d := range declared {
		seen[d.name] = true
		want, ok := pinned[d.name]
		if !ok {
			t.Errorf("%s = %d is declared at %s but is not pinned in exitCodePins, so nothing checks its value or that it does not collide", d.name, d.value, d.pos)
			continue
		}
		if want != d.value {
			t.Errorf("%s is declared as %d at %s but pinned as %d", d.name, d.value, d.pos, want)
		}
	}
	// The other direction: a pin whose constant was renamed or deleted would otherwise sit there
	// pinning nothing, and the count check above cannot see a swap.
	for _, c := range exitCodePins {
		if !seen[c.name] {
			t.Errorf("%s is pinned but no longer declared in the package; was it renamed or removed?", c.name)
		}
	}

	// Distinct values, over the declared set rather than the pinned one. Pinning every code it listed
	// still let two constants collide on 9, because pinning each one individually cannot see a pair,
	// and a pinned list cannot see a constant that never reached it. ExitCustody says nothing was
	// recovered (your shares or envelope are wrong); ExitUnwritten says the restore ran and verified
	// and some records did not land. They are opposite readings, and they meet on one command, since
	// custody artefacts are accepted wherever --identity is, restore included.
	byValue := map[int]string{}
	for _, d := range declared {
		if prev, dup := byValue[d.value]; dup {
			t.Errorf("exit code %d is used by BOTH %s and %s; a script cannot tell them apart", d.value, prev, d.name)
		}
		byValue[d.value] = d.name
	}
}
