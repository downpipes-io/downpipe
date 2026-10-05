package source

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The address an operator reads in an S3 failure is pinned here.
//
// WHAT WENT WRONG WITHOUT THIS. signedGetRequest sets req.URL.Opaque to the canonical
// bucket/key path, which is right on the wire: net/http then transmits the request target
// byte-for-byte as SigV4 signed it. url.URL.String() renders an opaque URL as scheme + ":" +
// opaque, dropping the host, and net/http puts that rendering into the *url.Error of every
// transport failure. So a wrong --s3-endpoint produced
//
//	could not reach the destination: Get "https:/mybucket/run/…": dial tcp: lookup …
//
// The address on screen was malformed, was not the address that had been dialled, and did not
// contain the host the operator had typed, so the error could not answer the only question the
// operator had. The request was always correct; only the message was wrong.
//
// These assert the WHOLE address (scheme, host, bucket, key), not that the message is non-empty
// and not that it contains the host. A message that names the host but still carries the
// hostless rendering beside it is the same defect half-fixed, and "contains the host" would pass
// it.

// wantAddress is the address every message below must carry, built from the test server's own
// origin so the assertion cannot drift from what was dialled.
func wantAddress(origin string) string {
	return origin + "/mybucket/run/01ARZ3NDEKTSV4RRFFQ69G5FAV/root.json"
}

const addrKey = "run/01ARZ3NDEKTSV4RRFFQ69G5FAV/root.json"

// hostlessPrefix is the rendering the defect produced. Asserting its ABSENCE is what stops the
// half-fix: appending the real address while leaving the malformed one in place.
const hostlessPrefix = "\"http:/mybucket/"

func TestS3TransportErrorNamesTheAddressItDialled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	origin := srv.URL
	srv.Close() // closed, so the next request fails below the HTTP layer, exactly as a wrong endpoint does

	s, err := NewS3Store(S3Config{Endpoint: origin, Bucket: "mybucket", Region: "auto", AccessKeyID: "AKID", SecretKey: "secret"})
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"Get", func() error { _, err := s.Get(addrKey); return err }},
		{"GetReader", func() error { _, _, err := s.GetReader(context.Background(), addrKey); return err }},
		{"Delete", func() error { return s.Delete(addrKey) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("a request to a closed server succeeded, so this proved nothing")
			}
			msg := err.Error()
			if !strings.Contains(msg, wantAddress(origin)) {
				t.Errorf("%s transport error does not name the address it dialled.\nwant it to contain: %s\ngot: %s", tc.name, wantAddress(origin), msg)
			}
			if strings.Contains(msg, hostlessPrefix) {
				t.Errorf("%s transport error still carries the hostless opaque rendering, which is the malformed address the operator cannot act on: %s", tc.name, msg)
			}
		})
	}
}

func TestS3StatusErrorNamesTheAddressItReached(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	s, err := NewS3Store(S3Config{Endpoint: srv.URL, Bucket: "mybucket", Region: "auto", AccessKeyID: "AKID", SecretKey: "secret"})
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"Get", func() error { _, err := s.Get(addrKey); return err }},
		{"GetReader", func() error { _, _, err := s.GetReader(context.Background(), addrKey); return err }},
		{"Delete", func() error { return s.Delete(addrKey) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("a 403 was reported as success, so this proved nothing")
			}
			msg := err.Error()
			if !strings.Contains(msg, wantAddress(srv.URL)) {
				t.Errorf("%s status error tells the operator to check --s3-endpoint without saying which one was used.\nwant it to contain: %s\ngot: %s", tc.name, wantAddress(srv.URL), msg)
			}
		})
	}
}

// TestObjectAddressIsNotUsedToBuildRequests states the boundary in a form a compiler cannot:
// objectAddress renders for MESSAGES and the request target stays the opaque canonical path. If
// the two ever converged, a signed path and a sent path could drift and every read would fail as
// a signature error, which reads to an operator as a permissions problem.
func TestObjectAddressIsNotUsedToBuildRequests(t *testing.T) {
	s, err := NewS3Store(S3Config{Endpoint: "https://s3.example.com:9000", Bucket: "mybucket", Region: "auto", AccessKeyID: "AKID", SecretKey: "secret"})
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}
	req, err := s.signedGetRequest(addrKey)
	if err != nil {
		t.Fatalf("signedGetRequest: %v", err)
	}
	if got, want := req.URL.Opaque, "/mybucket/"+addrKey; got != want {
		t.Errorf("request target = %q, want the canonical path %q: the signed path and the sent path must stay identical", got, want)
	}
	if got, want := s.objectAddress(addrKey), "https://s3.example.com:9000/mybucket/"+addrKey; got != want {
		t.Errorf("objectAddress = %q, want %q", got, want)
	}
}
