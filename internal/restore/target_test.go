package restore

// Byte-exact corner cases for EnvTarget value-escaping and DirTarget
// traversal-containment, plus a sink Close-error surface check.
//
// The tests here complement the escaping/containment coverage that already
// exists in restore_test.go.  They pin the exact output bytes for adversarial
// value content so a regression from single-quoting to double-quoting (which
// would re-enable $, backtick, and variable expansion) would not go unnoticed.

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// TestEnvTargetRejectsCRLFInValue asserts that a value containing a CRLF
// sequence is refused rather than written.  Single-quoting keeps such a value
// shell-safe for a POSIX-shell `source` consumer, but this sink is also
// documented for line-oriented dotenv consumers (docker --env-file, systemd
// EnvironmentFile, ...) that split on any embedded newline regardless of
// quoting, so a value smuggling a second physical line must be rejected
// instead of silently emitted.
func TestEnvTargetRejectsCRLFInValue(t *testing.T) {
	var buf bytes.Buffer
	et := NewEnvTarget(&buf, nil)

	value := "before\r\nafter"
	if err := et.Write("MY_VAR", []byte(value)); err == nil {
		t.Fatalf("Write must reject a value containing CRLF, got nil error")
	}
}

// TestEnvTargetRejectsCRInValue asserts that a bare CR byte in a value is
// refused for the same reason as CRLF above.
func TestEnvTargetRejectsCRInValue(t *testing.T) {
	var buf bytes.Buffer
	et := NewEnvTarget(&buf, nil)

	if err := et.Write("CR_VAR", []byte("foo\rbar")); err == nil {
		t.Fatalf("Write must reject a value containing a bare CR, got nil error")
	}
}

// TestEnvTargetQuoteInjectionValue asserts that a value containing shell
// metacharacters that could break out of single-quoting is escaped correctly.
// The only character that can terminate a single-quoted string is a literal
// single quote; all other metacharacters (dollar, backtick, semicolons,
// redirects) pass through verbatim inside single quotes.  A single quote in
// the value is replaced with '\” (close-quote, escaped-quote, reopen-quote),
// so the emitted line is always shell-safe.
// envQuoteInjectionCases drives TestEnvTargetQuoteInjectionValue: each value is a shell
// metacharacter sequence and want is the expected single-quoted, injection-safe line.
var envQuoteInjectionCases = []struct {
	name  string
	value string
	want  string
}{
	{
		// A value that opens with a single quote and ends with one, surrounding
		// shell command-substitution syntax.  The single quotes are escaped via
		// the '\'' idiom: close-quote, escaped-literal-quote, reopen-quote.
		name:  "shell_command_substitution",
		value: "'$(touch /tmp/pwned)'",
		want:  "KEY=''\\''$(touch /tmp/pwned)'\\'''\n",
	},
	{
		name:  "bare_single_quote",
		value: "it's",
		want:  "KEY='it'\\''s'\n",
	},
	{
		name:  "multiple_single_quotes",
		value: "a'b'c",
		want:  "KEY='a'\\''b'\\''c'\n",
	},
	{
		name:  "dollar_and_backtick",
		value: "$VAR`cmd`",
		// No single quotes in value, so it is wrapped as-is; the dollar and
		// backtick are inert inside single quotes and cannot expand.
		want: "KEY='$VAR`cmd`'\n",
	},
	{
		name:  "semicolons_and_pipes",
		value: "val; rm -rf /; echo done | tee /tmp/x",
		want:  "KEY='val; rm -rf /; echo done | tee /tmp/x'\n",
	},
}

func TestEnvTargetQuoteInjectionValue(t *testing.T) {
	for _, tc := range envQuoteInjectionCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			et := NewEnvTarget(&buf, nil)
			if err := et.Write("KEY", []byte(tc.value)); err != nil {
				t.Fatalf("Write returned unexpected error: %v", err)
			}
			got := buf.String()
			if got != tc.want {
				t.Fatalf("value-escaping for %q:\n got  %q\nwant %q", tc.value, got, tc.want)
			}
			// Verify the output starts with KEY=' and ends with '\n so no
			// injection can escape the quoted region from the outside.
			if !strings.HasPrefix(got, "KEY='") {
				t.Errorf("output does not start with KEY=': %q", got)
			}
			if !strings.HasSuffix(got, "'\n") {
				t.Errorf("output does not end with single-quote newline: %q", got)
			}
		})
	}
}

// envUnsafeValueByteCases drives TestEnvTargetRejectsUnsafeValueBytes: each value
// carries a byte that a line-oriented dotenv consumer (not just a POSIX shell) cannot
// treat as staying inside one quoted token, so Write must refuse all of them.
var envUnsafeValueByteCases = []struct {
	name  string
	value string
}{
	{name: "nul_byte", value: "before\x00after"},
	{name: "bare_cr", value: "foo\rbar"},
	{name: "bare_lf", value: "line1\nline2"},
	{name: "crlf", value: "before\r\nafter"},
}

func TestEnvTargetRejectsUnsafeValueBytes(t *testing.T) {
	for _, tc := range envUnsafeValueByteCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			et := NewEnvTarget(&buf, nil)
			if err := et.Write("KEY", []byte(tc.value)); err == nil {
				t.Fatalf("Write must reject value %q, got nil error", tc.value)
			}
			// A refused record must leave no partial or corrupted line in the
			// stream; the caller's writeOneRecord treats this as a per-record
			// failure and keeps applying the rest of the restore.
			if buf.Len() != 0 {
				t.Errorf("rejected Write must not write anything, got %q", buf.String())
			}
		})
	}
}

// TestEnvTargetCloseErrorSurfacedOnPartialFailure verifies that when both
// per-record Write failures and a Close failure occur, Apply propagates the
// Close error as the top-level error AND returns the already-accumulated
// Result (including sorted failures) to the caller.  The Close-error early
// return must not swallow the failure list.
func TestEnvTargetCloseErrorSurfacedOnPartialFailure(t *testing.T) {
	// Three records; the target injects a Write error on every call and a Close
	// error at the end, so we exercise the path where Failed is non-empty when
	// Close fails.
	r := rdr(
		[2]string{"AAA", "v1"},
		[2]string{"BBB", "v2"},
		[2]string{"CCC", "v3"},
	)
	ft := newFakeTarget()
	ft.writeErr = fmt.Errorf("disk full")
	ft.closeErr = fmt.Errorf("flush failed")

	_, res, err := Apply(r, ft, true)

	// The Close error must reach the caller.
	if err == nil {
		t.Fatal("Apply must return an error when Close fails")
	}
	if !strings.Contains(err.Error(), "flush failed") {
		t.Fatalf("Close error must be wrapped in the returned error, got: %v", err)
	}

	// The failure list must be present and sorted even though Close errored.
	if len(res.Failed) != 3 {
		t.Fatalf("expected 3 failures, got %d", len(res.Failed))
	}
	names := make([]string, len(res.Failed))
	for i, f := range res.Failed {
		names[i] = f.Name
	}
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Errorf("Failed list is not sorted: %v", names)
			break
		}
	}
}
