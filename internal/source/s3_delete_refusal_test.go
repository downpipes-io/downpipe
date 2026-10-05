package source

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The prune classifies a failed delete through two optional capabilities on the error:
// DeleteStatus() int and LockNamed() bool (internal/format/mutate.go). These tests pin that the S3
// store carries them, so a refusal reaches the prune as a refusal and a transport fault does not.

type deleteStatusCap interface{ DeleteStatus() int }
type lockNamedCap interface{ LockNamed() bool }

func deleteWith(t *testing.T, status int, body string) error {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	return streamTestStore(t, srv).Delete("seg/aa/obj.seg")
}

// A refused delete carries the status it was refused with, so the prune can count it as a refusal
// rather than as a failure.
func TestS3DeleteRefusalCarriesItsStatus(t *testing.T) {
	err := deleteWith(t, http.StatusForbidden, `<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`)
	var st deleteStatusCap
	if !errors.As(err, &st) || st.DeleteStatus() != http.StatusForbidden {
		t.Fatalf("a 403 delete returned %v, want an error carrying DeleteStatus 403", err)
	}
	var ln lockNamedCap
	if errors.As(err, &ln) && ln.LockNamed() {
		t.Error("a bare AccessDenied names no lock, and the error says it does")
	}
	if strings.Contains(err.Error(), "Access Denied") {
		t.Errorf("the error carries body text: %q", err)
	}
	if strings.Contains(err.Error(), "read access") {
		t.Errorf("a refused DELETE is told to check read access, which is the wrong permission: %q", err)
	}
}

// Google Cloud's S3-interoperable endpoint refuses a delete inside a per-object retention window with a
// 403 whose body names the retention. That is the destination's own statement of a lock, and it is the
// only case this tool calls a lock.
func TestS3DeleteRefusalThatNamesARetentionSaysSo(t *testing.T) {
	err := deleteWith(t, http.StatusForbidden, `<Error><Code>AccessDenied</Code><Message>Object 'seg/aa/obj.seg' is subject to object retention and cannot be deleted</Message></Error>`)
	var ln lockNamedCap
	if !errors.As(err, &ln) || !ln.LockNamed() {
		t.Fatalf("a refusal naming the retention returned %v, want LockNamed true", err)
	}
	if strings.Contains(err.Error(), "subject to object retention") {
		t.Errorf("the body text rides on the error: %q", err)
	}
}

// A transport failure carries no status, so the prune counts it as a failure and never as a refusal.
func TestS3DeleteTransportFailureCarriesNoStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	store := streamTestStore(t, srv)
	srv.Close()
	err := store.Delete("seg/aa/obj.seg")
	var st deleteStatusCap
	if err == nil || errors.As(err, &st) {
		t.Fatalf("an unreachable endpoint returned %v, want an error with no DeleteStatus", err)
	}
}
