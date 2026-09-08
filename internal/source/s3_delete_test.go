package source

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Delete is the only code in this repository that removes an object, and it shipped with no test at
// all. What is covered here is not the happy path so much as the three status codes whose handling is
// a deliberate decision, because getting any of them wrong is silent and expensive.

// 204 is the ordinary success, and the request itself must be a signed DELETE at the bucket-qualified
// path. An unsigned or misrouted delete would fail against a real endpoint in a way no local test of the
// return value alone would notice.
func TestS3DeleteSendsASignedDeleteAndAcceptsNoContent(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotSha string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.EscapedPath()
		gotAuth = r.Header.Get("Authorization")
		gotSha = r.Header.Get("x-amz-content-sha256")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := streamTestStore(t, srv).Delete("seg/ab/cd.seg"); err != nil {
		t.Fatalf("Delete on 204 = %v, want nil", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	if gotPath != "/b/seg/ab/cd.seg" {
		t.Errorf("path = %q, want the key under the bucket", gotPath)
	}
	if !strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256 ") {
		t.Errorf("Authorization = %q, want a SigV4 signature; an unsigned delete is refused by a real endpoint", gotAuth)
	}
	if gotSha != emptyPayloadHash {
		t.Errorf("x-amz-content-sha256 = %q, want the empty-payload hash that the signature was computed over", gotSha)
	}
}

// 404 is success on purpose: the desired end state is that the object is gone. Without this a prune
// interrupted part-way could never be re-run, because every already-deleted key would fail the retry.
func TestS3DeleteTreatsAlreadyAbsentAsDone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if err := streamTestStore(t, srv).Delete("seg/gone.seg"); err != nil {
		t.Fatalf("Delete on 404 = %v, want nil so an interrupted prune stays re-runnable", err)
	}
}

// 403 is what Object Lock looks like, and it must NOT be swallowed. The prune counts refusals and
// reports them; an error that went missing here would tell an operator their retention had been applied
// while the bucket still held everything, which is the exact failure this tool exists to prevent.
func TestS3DeleteSurfacesAWormRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	err := streamTestStore(t, srv).Delete("seg/locked.seg")
	if err == nil {
		t.Fatal("a 403 must be an error; swallowing a WORM refusal reports retention as applied when nothing was removed")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error = %q, want the status in the message so the refusal is diagnosable", err)
	}
	if !strings.Contains(err.Error(), "seg/locked.seg") {
		t.Errorf("error = %q, want the key named", err)
	}
}

// A 500 is not a refusal and not a success. It is included because the 404-is-success rule makes it
// tempting to broaden "not 2xx" handling, and a server fault must stay an error.
func TestS3DeleteSurfacesAServerFault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if err := streamTestStore(t, srv).Delete("seg/x.seg"); err == nil {
		t.Fatal("a 500 must be an error, not treated as done")
	}
}

// A transport failure (endpoint unreachable) must be an error naming the key, not a nil that would let
// the caller record the object as removed.
func TestS3DeleteSurfacesATransportFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	store := streamTestStore(t, srv)
	srv.Close() // nothing is listening now

	err := store.Delete("seg/unreachable.seg")
	if err == nil {
		t.Fatal("an unreachable endpoint must be an error, not a silent success")
	}
	if !strings.Contains(err.Error(), "seg/unreachable.seg") {
		t.Errorf("error = %q, want the key named", err)
	}
}
