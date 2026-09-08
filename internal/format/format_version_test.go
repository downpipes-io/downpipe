package format

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/source"
)

// The version gate had no direct test of its own before this file. Its only coverage was
// the single conformance vector `unknown-major` (formatVersion downpipe/9.0.0), and that
// vector cannot tell the shipped rule apart from the discarded one: a reader keyed on the
// MAJOR and a reader keyed on the MINOR both refuse 9.0.0. So every branch that separates
// them, a lower minor and a higher minor at the reader's own major, ran unasserted, and an
// internal compatibility policy went on promising that a reader reads every archive at its
// own major or below for as long as nothing here contradicted it.
//
// This table asserts the decision for each version RELATION the reader can meet, and the
// two conformance vectors (`unknown-major`, `unimplemented-minor`) pin the two that a
// second implementation must also reproduce.

// TestFormatVersionDecisionTable pins the accept/refuse decision for every version
// relation, so widening or narrowing the gate cannot happen silently (SPEC.md 13, 13.1).
func TestFormatVersionDecisionTable(t *testing.T) {
	const (
		accept     = "accept"
		malformed  = "malformed"
		unimplem   = "unimplemented"
		notALabel  = "not-a-label"
		implemLine = "downpipe/0.1.x"
	)
	cases := []struct {
		version string
		want    string
		why     string
	}{
		{"downpipe/0.1.0", accept, "the reader's own version"},
		{"downpipe/0.1.1", accept, "a patch bump changes no byte-level rule (SPEC.md 13)"},
		{"downpipe/0.1.99", accept, "any patch on the implemented minor"},

		{"downpipe/0.0.9", unimplem, "a LOWER minor is a different, incompatible format, not an older dialect"},
		{"downpipe/0.2.0", unimplem, "a HIGHER minor at the same major; the vector unimplemented-minor pins this"},
		{"downpipe/1.0.0", unimplem, "a different major"},
		{"downpipe/9.0.0", unimplem, "the vector unknown-major pins this"},

		// A two-component label is MALFORMED: all three components are part of the version,
		// nothing obtainable writes a MAJOR.MINOR label, and no reader implements one. The
		// refusal must not name another build to go and fetch, because there is none.
		// downpipe/0.1 is the trap in this shape: the same two numbers this reader
		// implements, a different format, and it must not be accepted on the numbers.
		{"downpipe/1.0", malformed, "two components are not a version; the retired pre-release lineage has no reader to send anyone to"},
		{"downpipe/0.1", malformed, "two components carrying the reader's own numbers; a set match on numbers alone would wrongly ACCEPT this"},
		{"downpipe/2.0", malformed, "any other two-component label"},

		{"downpipe/0.1.", malformed, "empty patch"},
		{"downpipe/0.1.0.1", malformed, "a fourth component leaves the patch as \"0.1\""},
		{"downpipe/0.1.0-rc1", malformed, "a pre-release suffix is not a decimal patch"},
		{"downpipe/0.1.x", malformed, "the support summary is not itself a version"},
		{"downpipe/0.1.0 ", malformed, "a trailing space is not the frozen byte string (SPEC.md 5.2)"},
		{"downpipe/0.1.0\n", malformed, "a trailing newline, the shape a hand-edited manifest produces"},
		{"downpipe/ 0.1.0", malformed, "a leading space in the major"},
		{"downpipe/00.01.0", malformed, "zero-padded components are not canonical decimals"},

		{"age/1.0.0", notALabel, "a different format entirely"},
		{"", notALabel, "an absent formatVersion"},
		// The prefix alone carries the label, so it is malformed rather than foreign:
		// there is no version to go and find a reader for.
		{"downpipe/", malformed, "the prefix alone splits to one empty component"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.version, func(t *testing.T) {
			err := checkFormatVersion(tc.version)
			if tc.want == accept {
				if err != nil {
					t.Fatalf("%q must be accepted (%s), got: %v", tc.version, tc.why, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("%q must be refused (%s), it was accepted", tc.version, tc.why)
			}
			code, ok := exitCodeOf(err)
			if !ok || code != ExitUsage {
				t.Fatalf("%q must refuse with ExitUsage (%d) so a version refusal is never read as a corrupted archive; got code %d ok=%v", tc.version, ExitUsage, code, ok)
			}
			msg := err.Error()
			switch tc.want {
			case notALabel:
				if !strings.Contains(msg, "is not a downpipe version label") {
					t.Fatalf("%q (%s) must be refused as not a downpipe label; got: %v", tc.version, tc.why, err)
				}
			case malformed:
				// A malformed label must NOT tell anyone to go and fetch another reader:
				// no reader implements a version string that is not a version string, so
				// that remedy would name an action nobody can perform.
				if !strings.Contains(msg, "is not a downpipe version label at all") {
					t.Fatalf("%q (%s) must be refused as MALFORMED, not as unimplemented; got: %v", tc.version, tc.why, err)
				}
				if strings.Contains(msg, "Get a downpipe reader") {
					t.Fatalf("%q (%s) is malformed, so the message must not send anyone looking for a reader that implements it; got: %v", tc.version, tc.why, err)
				}
				// The refusal fires on arity as well as on canonicality, so it has to name
				// the shape. A message that says only "every component must be a decimal
				// number" is a false description of "downpipe/0.1", whose components are
				// all decimal numbers, and whoever reads it goes looking for the wrong
				// thing in an already bad hour.
				if !strings.Contains(msg, "MAJOR.MINOR.PATCH") || !strings.Contains(msg, "all three components present") {
					t.Fatalf("%q (%s) must be refused with a message that names the MAJOR.MINOR.PATCH shape and the requirement that all three components are present, because arity is one of the two ways this refusal fires; got: %v", tc.version, tc.why, err)
				}
			case unimplem:
				if !strings.Contains(msg, "does not implement") {
					t.Fatalf("%q (%s) must be refused as an unimplemented version; got: %v", tc.version, tc.why, err)
				}
				if !strings.Contains(msg, implemLine) {
					t.Fatalf("%q must name what this reader DOES implement (%s); got: %v", tc.version, implemLine, err)
				}
				if !strings.Contains(msg, "CHANGELOG.md") || !strings.Contains(msg, "github.com/downpipes-io/downpipe") {
					t.Fatalf("%q must name where the format-version-to-release mapping is published, or the remedy is one nobody can act on; got: %v", tc.version, err)
				}
				if !strings.Contains(msg, "nothing has been lost") {
					t.Fatalf("%q must say the bytes are intact: a version refusal mid-recovery must not read as data loss; got: %v", tc.version, err)
				}
			}
		})
	}
}

// TestTwoComponentVersionIsRefusedAndNeverMatchesOnItsNumbers pins the arity requirement,
// which is the part of this gate that costs the most to get wrong in the accepting
// direction.
//
// "downpipe/0.1" holds exactly the two numbers this reader implements, so a set match on
// the numbers alone would ACCEPT it, and it is not this format: its section 11.7 labels
// would read "downpipe/0.1 <purpose>", every key derives to different bytes, and the reader
// would report an authentication failure over bytes that are perfectly intact. That is the
// failure the whole gate exists to prevent, so the refusal is asserted here and not left to
// the decision table alone.
//
// The refusal is MALFORMED, and must not name another build to go and fetch. A MAJOR.MINOR
// label was the identity of a pre-release lineage retired: no release of it
// was published, no reader for it is obtainable, and the update channel no longer offers a
// writer that stamps one. A message closing with "get a reader that implements 1.0" would
// name a binary that does not exist, and mid-recovery a remedy nobody can act on is worse
// than a blunt one.
//
// THIS TEST IS ONLY TRUE WHILE THAT RETIREMENT HOLDS. If an obtainable writer ever
// stamps a two-component label again, this expectation inverts and the reader is telling
// the holder of intact bytes that their manifest is damaged.
func TestTwoComponentVersionIsRefusedAndNeverMatchesOnItsNumbers(t *testing.T) {
	for _, v := range []string{"downpipe/0.1", "downpipe/1.0", "downpipe/2.0"} {
		err := checkFormatVersion(v)
		if err == nil {
			t.Fatalf("%q must be refused: all three components are part of the version, and %q in particular must not be accepted on the strength of carrying the same numbers this reader implements", v, "downpipe/0.1")
		}
		msg := err.Error()
		if !strings.Contains(msg, "is not a downpipe version label at all") {
			t.Fatalf("%q must be refused as MALFORMED: a two-component label is not a version, and there is no reader implementing one to send anyone to; got: %v", v, err)
		}
		if strings.Contains(msg, "Get a downpipe reader") {
			t.Fatalf("%q must not close by naming a reader to go and fetch. No release implementing a MAJOR.MINOR lineage was ever published, so that remedy names a binary nobody can obtain; got: %v", v, err)
		}
		if !strings.Contains(msg, "MAJOR.MINOR.PATCH") || !strings.Contains(msg, "all three components present") {
			t.Fatalf("%q is refused on ARITY, so the message must say the shape is MAJOR.MINOR.PATCH and that all three components must be present. Every component of %q is a decimal number, so a message blaming non-decimal components would be false; got: %v", v, v, err)
		}
	}
}

// TestImplementedFormatVersionsIsSingletonAndCanonical guards the SET the reader claims.
// It is additive from the first PUBLISHED release (SPEC.md 13.1): once a release
// implementing a unit is obtainable, no later release may drop it, because the bytes naming
// it are then in somebody's bucket and stored bytes have no deprecation path. Adding a unit
// here without the retained key schedule and the retained corpus for that minor would make
// the reader accept an archive it cannot decrypt and report an authentication failure over
// intact bytes, so this fails loudly on a bare addition.
func TestImplementedFormatVersionsIsSingletonAndCanonical(t *testing.T) {
	if len(ImplementedFormatVersions) != 1 || ImplementedFormatVersions[0] != "0.1" {
		t.Fatalf("this reader implements exactly the compatibility unit 0.1; ImplementedFormatVersions is %v. "+
			"Adding a unit is not a version-comparison change: it needs that minor's key schedule, its byte rules "+
			"and its conformance vectors retained in the same change set (SPEC.md 13.1). Update this test in that "+
			"change set, never ahead of it.", ImplementedFormatVersions)
	}
	if got := readerSupportSummary(); got != "downpipe/0.1.x" {
		t.Fatalf("readerSupportSummary() = %q, want %q; the refusal message is built from the set so it cannot drift", got, "downpipe/0.1.x")
	}
}

// TestFormatVersionRefusalIsNotOverridable proves the claim the refusal message makes:
// no reader Option reads a format this build does not implement. The message tells an
// operator not to reach for --allow-unverified, and a message that said that while an
// override existed would be worse than silence.
//
// It runs the real unimplemented-minor vector (downpipe/0.2.0, validly signed) through
// both reader paths under the WIDEST Options a caller can express. The conformance replay
// exercises the same vector under the zero Options; this asserts the acknowledgement flags
// do not open a door, which is the specific thing the message promises.
func TestFormatVersionRefusalIsNotOverridable(t *testing.T) {
	dir := filepath.Join("testdata", "vectors", "unimplemented-minor")
	identity, err := crypto.ParseKEMPrivate(mustB64(t, readVecFile(t, filepath.Join(dir, "identity.key"))))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := crypto.ParseVerifier(mustB64(t, readVecFile(t, filepath.Join(dir, "signer.pub"))))
	if err != nil {
		t.Fatal(err)
	}
	store := source.NewDirStore(filepath.Join(dir, "archive"))
	widest := Options{AllowStale: true, AllowUnverified: true, AllowUnverifiedRunlog: true}

	assertRefused := func(t *testing.T, path string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: downpipe/0.2.0 was READ under the widest Options; the refusal message tells an operator no override exists, so an override that exists makes that message a lie", path)
		}
		code, ok := exitCodeOf(err)
		if !ok || code != ExitUsage {
			t.Fatalf("%s: want ExitUsage (%d), got code %d ok=%v: %v", path, ExitUsage, code, ok, err)
		}
		if !strings.Contains(err.Error(), "does not implement") {
			t.Fatalf("%s: refused for the wrong reason: %v", path, err)
		}
	}
	_, err = Open(store, vecRunID, identity, verifier, widest)
	assertRefused(t, "Open", err)
	_, err = StreamOpen(store, vecRunID, identity, verifier, widest)
	assertRefused(t, "StreamOpen", err)
	_, err = Attest(store, vecRunID, verifier, 0)
	assertRefused(t, "Attest", err)
}
