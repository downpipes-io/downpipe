package format

// Focused unit tests for the codedIfNot helper in errors.go.
//
// coded, ExitError.Error/Unwrap, the exit-code constants, and the simple
// coded(nil) path are already exercised by encoding_test.go. The remaining
// uncovered error path is codedIfNot, whose whole point is that it must not
// overwrite a code a callee has already classified. These cases pin that
// behaviour: a nil error passes through, an unclassified error is wrapped with
// the fallback code, and an error that already carries an ExitError is returned
// unchanged so the more specific code wins.

import (
	"errors"
	"fmt"
	"testing"
)

// TestCodedIfNotNilReturnsNil verifies codedIfNot(code, nil) returns nil, so a
// caller can write "return codedIfNot(ExitUnverified, err)" unconditionally.
func TestCodedIfNotNilReturnsNil(t *testing.T) {
	if got := codedIfNot(ExitUnverified, nil); got != nil {
		t.Fatalf("codedIfNot(ExitUnverified, nil) must return nil, got %v", got)
	}
	if got := codedIfNot(ExitStale, nil); got != nil {
		t.Fatalf("codedIfNot(ExitStale, nil) must return nil, got %v", got)
	}
}

// TestCodedIfNotWrapsUnclassifiedError verifies that an error not already
// carrying an ExitError is wrapped with the supplied fallback code, and that
// errors.As extracts that code while the underlying error stays reachable.
func TestCodedIfNotWrapsUnclassifiedError(t *testing.T) {
	for _, tc := range []struct {
		code int
	}{
		{ExitUnverified},
		{ExitIncomplete},
		{ExitPlaintext},
		{ExitStale},
		{ExitUsage},
	} {
		inner := errors.New("unclassified cause")
		err := codedIfNot(tc.code, inner)
		if err == nil {
			t.Fatalf("codedIfNot(%d, non-nil) must not return nil", tc.code)
		}
		var ee *ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("codedIfNot(%d, err): result is not *ExitError", tc.code)
		}
		if ee.Code != tc.code {
			t.Fatalf("codedIfNot(%d): ExitError.Code = %d, want %d", tc.code, ee.Code, tc.code)
		}
		// The original error must remain reachable through the wrapper.
		if !errors.Is(err, inner) {
			t.Fatalf("codedIfNot(%d): wrapped result lost the underlying error", tc.code)
		}
	}
}

// TestCodedIfNotPreservesExistingCode verifies the defining behaviour: when the
// error already carries an ExitError, codedIfNot returns it untouched and does
// not overwrite the already-classified code with the fallback. This is what lets
// a caller supply a default code without clobbering a callee's more specific one.
func TestCodedIfNotPreservesExistingCode(t *testing.T) {
	// An error already classified as ExitStale, handed a different fallback.
	already := coded(ExitStale, errors.New("freshness rollback"))
	got := codedIfNot(ExitUnverified, already)

	var ee *ExitError
	if !errors.As(got, &ee) {
		t.Fatalf("result is not *ExitError: %v", got)
	}
	if ee.Code != ExitStale {
		t.Fatalf("codedIfNot must not overwrite an existing code: got %d, want %d (ExitStale)", ee.Code, ExitStale)
	}
	// It must return the same value it was given, not a re-wrapped copy.
	if got != already {
		t.Fatal("codedIfNot must return the already-classified error unchanged")
	}
}

// TestCodedIfNotFindsWrappedExitError verifies that codedIfNot honours an
// ExitError buried deeper in the chain (reached via errors.As, not just a
// top-level type assertion), so a fallback code is not applied when a specific
// code is already present several %w layers down.
func TestCodedIfNotFindsWrappedExitError(t *testing.T) {
	deep := coded(ExitPlaintext, errors.New("plaintext hash mismatch"))
	// Wrap the classified error twice more with plain fmt.Errorf %w layers.
	wrapped := fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", deep))

	got := codedIfNot(ExitUsage, wrapped)

	var ee *ExitError
	if !errors.As(got, &ee) {
		t.Fatalf("result must still surface an *ExitError: %v", got)
	}
	if ee.Code != ExitPlaintext {
		t.Fatalf("codedIfNot must keep the deeply-wrapped code: got %d, want %d (ExitPlaintext)", ee.Code, ExitPlaintext)
	}
	// Because an ExitError was found, the input must be returned verbatim.
	if got != wrapped {
		t.Fatal("codedIfNot must return the input unchanged when an ExitError is already present in the chain")
	}
}
