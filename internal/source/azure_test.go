package source

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The Azure Blob source, driven against an in-process server that speaks the real Azure shapes: a 404
// with x-ms-error-code for an absent blob, a 200 with an ETag for one that is there, and a List Blobs
// EnumerationResults document paged by NextMarker.
//
// The shapes matter more than they would for a store this repository invented, because Azure's are
// not the S3 ones the rest of this package assumes: a listing is XML with a marker rather than a
// continuation token, the error code arrives in a header rather than a body, and the request target
// is percent-encoded while the signed string is not. A double that answered generic HTTP would let
// every one of those be wrong.

// testAzureKey is a syntactically valid base64 account key that is NOT a credential.
const testAzureKey = "ZmFrZS1rZXktZm9yLXN0cmluZy10by1zaWduLW9ubHk="

// azureTestStore builds a store pointed at an httptest server. srv.URL is http://127.0.0.1:... which
// isPermittedEndpoint allows by exact host, exactly as the S3 tests rely on.
func azureTestStore(t *testing.T, srvURL string, cfg func(*AzureConfig)) *AzureStore {
	t.Helper()
	c := AzureConfig{
		Endpoint:   srvURL,
		Container:  "breakglass",
		Account:    "myaccount",
		AccountKey: testAzureKey,
	}
	if cfg != nil {
		cfg(&c)
	}
	store, err := NewAzureStore(c)
	if err != nil {
		t.Fatalf("NewAzureStore: %v", err)
	}
	return store
}

// enumerationResults renders a List Blobs page in Azure's own document shape.
//
// The names are XML-ESCAPED here, because that is what Azure sends: a blob named with an ampersand
// arrives as &amp; and has to be decoded before the key can be used. A fixture that wrote the raw
// character would be a fixture the reader never has to decode, so the decoding assertion would prove
// nothing.
func enumerationResults(nextMarker string, names ...string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><EnumerationResults ContainerName="https://myaccount.blob.core.windows.net/breakglass"><Blobs>`)
	for _, n := range names {
		var escaped bytes.Buffer
		if err := xml.EscapeText(&escaped, []byte(n)); err != nil {
			panic("the fixture could not escape a blob name: " + err.Error())
		}
		fmt.Fprintf(&b, `<Blob><Name>%s</Name><Properties><Content-Length>7</Content-Length><Etag>0x8D</Etag></Properties></Blob>`, escaped.String())
	}
	b.WriteString(`</Blobs><NextMarker>` + nextMarker + `</NextMarker></EnumerationResults>`)
	return b.String()
}

// TestAzureStoreGet drives the read path against the real Azure answers for a blob that is there and
// one that is not, and checks that the request carried what Azure requires.
func TestAzureStoreGet(t *testing.T) {
	want := []byte("archive object bytes")
	var gotAuth, gotVersion, gotDate, gotTarget string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotVersion = r.Header.Get("x-ms-version")
		gotDate = r.Header.Get("x-ms-date")
		gotTarget = r.URL.RequestURI()
		if r.URL.Path == "/breakglass/run/abc/root.manifest.json" {
			w.Header().Set("ETag", `"0x8DA1B2C3D4E5F60"`)
			_, _ = w.Write(want)
			return
		}
		// Azure's absent-blob answer, with its own error code in the header where Azure puts it.
		w.Header().Set("x-ms-error-code", "BlobNotFound")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	s := azureTestStore(t, srv.URL, nil)
	got, err := s.Get("run/abc/root.manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("body mismatch: %q", got)
	}
	if !strings.HasPrefix(gotAuth, "SharedKey myaccount:") {
		t.Errorf("request lacked a Shared Key Authorization header: %q", gotAuth)
	}
	if gotVersion != azureAPIVersion {
		t.Errorf("request declared x-ms-version %q, want %q; Azure refuses an unversioned authorised request", gotVersion, azureAPIVersion)
	}
	if gotDate == "" {
		t.Error("request carried no x-ms-date, which is the instant the Shared Key signature is bound to")
	}
	if gotTarget != "/breakglass/run/abc/root.manifest.json" {
		t.Errorf("request target is %q, want the container-rooted blob path", gotTarget)
	}

	// An absent blob is an error, and the message must carry the status, Azure's own error code
	// and the address, or an operator cannot tell a wrong container from a short archive.
	_, err = s.Get("run/abc/missing")
	if err == nil {
		t.Fatal("a 404 must return an error")
	}
	for _, want := range []string{"404", "BlobNotFound", "--azure-container", srv.URL + "/breakglass/run/abc/missing"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the 404 error does not mention %q: %v", want, err)
		}
	}
}

// TestAzureStoreStatuses drives the statuses an operator meets mid-recovery, and pins that each one
// is an error carrying its status and self-reports as transport/access layer so the CLI exits 11
// rather than reporting a verdict about the archive.
func TestAzureStoreStatuses(t *testing.T) {
	cases := []struct {
		status    int
		errorCode string
		wantsHint string
	}{
		{http.StatusUnauthorized, "NoAuthenticationInformation", "authentication failed"},
		{http.StatusForbidden, "AuthenticationFailed", "access denied"},
		{http.StatusNotFound, "ContainerNotFound", "not found"},
		{http.StatusConflict, "ContainerBeingDeleted", ""},
		{http.StatusTooManyRequests, "", ""},
		{http.StatusInternalServerError, "InternalError", ""},
		{http.StatusServiceUnavailable, "ServerBusy", ""},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("status %d", tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.errorCode != "" {
					w.Header().Set("x-ms-error-code", tc.errorCode)
				}
				w.WriteHeader(tc.status)
			}))
			t.Cleanup(srv.Close)

			s := azureTestStore(t, srv.URL, nil)
			_, err := s.Get("run/abc/object")
			if err == nil {
				t.Fatalf("status %d returned no error", tc.status)
			}
			if !strings.Contains(err.Error(), fmt.Sprintf("%d", tc.status)) {
				t.Errorf("the error does not carry the status %d: %v", tc.status, err)
			}
			if tc.errorCode != "" && !strings.Contains(err.Error(), tc.errorCode) {
				t.Errorf("the error does not carry Azure's own code %q: %v", tc.errorCode, err)
			}
			if tc.wantsHint != "" && !strings.Contains(err.Error(), tc.wantsHint) {
				t.Errorf("the error carries no hint mentioning %q: %v", tc.wantsHint, err)
			}
			// The capability internal/format and cmd/downpipe both read through errors.As to
			// classify this as exit 11: the bytes were never retrieved, so nothing is yet known
			// about the archive.
			var ue interface{ Unreachable() bool }
			if !errors.As(err, &ue) || !ue.Unreachable() {
				t.Errorf("status %d did not self-report as unreachable, so the CLI would report a verdict about the archive instead of exit 11: %v", tc.status, err)
			}
		})
	}
}

// TestAzureStoreExists drives HEAD.
//
// The 403 row is the one that matters. A writing client collapses a non-200, non-404 HEAD to "absent"
// and re-uploads; a READER that did the same would tell an operator their archive is short of an
// object when the truth is that their credential was refused.
func TestAzureStoreExists(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		wantExists bool
		wantErr    bool
	}{
		{"a blob that is there", http.StatusOK, true, false},
		{"a blob that is not", http.StatusNotFound, false, false},
		{"a credential that was refused is an ERROR, never an absence", http.StatusForbidden, false, true},
		{"a wobbling store is an ERROR, never an absence", http.StatusServiceUnavailable, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotMethod string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod = r.Method
				w.WriteHeader(tc.status)
			}))
			t.Cleanup(srv.Close)

			s := azureTestStore(t, srv.URL, nil)
			exists, err := s.Exists("run/abc/object")
			if tc.wantErr && err == nil {
				t.Fatalf("status %d returned no error", tc.status)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("status %d returned an unexpected error: %v", tc.status, err)
			}
			if exists != tc.wantExists {
				t.Errorf("Exists = %v, want %v", exists, tc.wantExists)
			}
			if gotMethod != http.MethodHead {
				t.Errorf("Exists sent %s, want HEAD: a GET would pull the whole object to answer a yes or no", gotMethod)
			}
		})
	}
}

// TestAzureStoreListPagesByNextMarker drives the listing, including the paging Azure does with
// NextMarker rather than with a continuation token, and the XML entity a regex-based reader would
// hand back in a form no later request could address.
func TestAzureStoreListPagesByNextMarker(t *testing.T) {
	var markers []string
	var prefixes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		markers = append(markers, q.Get("marker"))
		prefixes = append(prefixes, q.Get("prefix"))
		if q.Get("restype") != "container" || q.Get("comp") != "list" {
			t.Errorf("a listing request must carry restype=container and comp=list, got %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/xml")
		switch q.Get("marker") {
		case "":
			_, _ = io.WriteString(w, enumerationResults("page-two", "run/abc/root.manifest.json", "run/abc/shard-0.dp"))
		case "page-two":
			// A key carrying an XML entity. encoding/xml decodes it; the key must come back in
			// the form Get can address.
			_, _ = io.WriteString(w, enumerationResults("", "run/abc/a&b.dp"))
		default:
			t.Errorf("unexpected marker %q", q.Get("marker"))
		}
	}))
	defer srv.Close()

	s := azureTestStore(t, srv.URL, nil)
	keys, err := s.List("run/abc/")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"run/abc/root.manifest.json", "run/abc/shard-0.dp", "run/abc/a&b.dp"}
	if len(keys) != len(want) {
		t.Fatalf("List returned %d keys, want %d: %q", len(keys), len(want), keys)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Errorf("key %d is %q, want %q", i, keys[i], want[i])
		}
	}
	if len(markers) != 2 || markers[0] != "" || markers[1] != "page-two" {
		t.Errorf("the walk sent markers %q, want the first page unmarked and the second carrying NextMarker", markers)
	}
	for i, p := range prefixes {
		if p != "run/abc/" {
			t.Errorf("page %d asked for prefix %q, want %q carried on every page", i, p, "run/abc/")
		}
	}
}

// TestAzureStoreListRefusals pins the listing's two refusals: a page that is not a List Blobs
// document, and a marker walk that never terminates.
func TestAzureStoreListRefusals(t *testing.T) {
	t.Run("a response that is not a List Blobs document", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "this is not xml at all")
		}))
		t.Cleanup(srv.Close)
		s := azureTestStore(t, srv.URL, nil)
		if _, err := s.List("run/"); err == nil || !strings.Contains(err.Error(), "not a List Blobs document") {
			t.Fatalf("a non-XML page must be refused by name, got: %v", err)
		}
	})

	t.Run("a marker that never terminates", func(t *testing.T) {
		pages := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			pages++
			// The same marker every time: a walk that follows it runs for ever while
			// allocating too little to trip any other guard.
			_, _ = io.WriteString(w, enumerationResults("always-the-same", "run/abc/object"))
		}))
		t.Cleanup(srv.Close)
		s := azureTestStore(t, srv.URL, nil)
		_, err := s.List("run/")
		if err == nil || !strings.Contains(err.Error(), "pages of results") {
			t.Fatalf("a non-terminating marker walk must be stopped by name, got: %v", err)
		}
		if pages != maxListPages {
			t.Errorf("the walk made %d requests, want it stopped at maxListPages (%d)", pages, maxListPages)
		}
	})
}

// TestAzureStoreGetReader drives the streamed read, which is what keeps a large sealed segment out of
// memory, and its byte ceiling.
func TestAzureStoreGetReader(t *testing.T) {
	want := []byte("streamed archive object bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(want)
	}))
	defer srv.Close()

	s := azureTestStore(t, srv.URL, nil)
	rc, size, err := s.GetReader(context.Background(), "seg/abc/0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("streamed body mismatch: %q", got)
	}
	if size != int64(len(want)) {
		t.Errorf("size hint is %d, want %d", size, len(want))
	}

	// The ceiling is enforced ON the stream, not only on the declared length, so an object that
	// outgrows its Content-Length still aborts rather than being consumed.
	small := azureTestStore(t, srv.URL, nil)
	small.maxBytes = 4
	rc2, _, err := small.GetReader(context.Background(), "seg/abc/0")
	if err != nil {
		// Rejected on the declared length, which is the cheap early exit and also correct.
		if !strings.Contains(err.Error(), "exceeds the 4-byte limit") {
			t.Fatalf("an oversized object must be refused by the byte ceiling, got: %v", err)
		}
		return
	}
	defer func() { _ = rc2.Close() }()
	if _, err := io.ReadAll(rc2); err == nil || !strings.Contains(err.Error(), "exceeds the 4-byte limit") {
		t.Fatalf("the streamed byte ceiling did not fire, got: %v", err)
	}
}

// TestAzureStoreBufferedByteCeiling pins the buffered path's ceiling on both routes: the declared
// Content-Length and, for a server that under-declares it, the bytes actually read.
func TestAzureStoreBufferedByteCeiling(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 64))
	}))
	defer srv.Close()

	s := azureTestStore(t, srv.URL, nil)
	s.maxBytes = 8
	if _, err := s.Get("run/abc/object"); err == nil || !strings.Contains(err.Error(), "8-byte limit") {
		t.Fatalf("an oversized object must be refused by the byte ceiling, got: %v", err)
	}
}

// TestAzureStoreGetContextCancels pins that GetContext's request is genuinely bound to the caller's
// context, so an operator interrupt stops an in-flight fetch instead of waiting out the whole-request
// timeout.
func TestAzureStoreGetContextCancels(t *testing.T) {
	released := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-released
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer close(released)

	s := azureTestStore(t, srv.URL, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.GetContext(ctx, "run/abc/object"); err == nil {
		t.Fatal("GetContext with a cancelled context returned no error, so the fetch was not bound to it")
	}
}

// TestAzureStoreRefusesRedirects pins that neither client follows a redirect. If one did, a
// misconfigured or hostile endpoint could steer archive bytes, the Shared Key Authorization header or
// a SAS token (which IS the credential, in full) to an unintended host.
func TestAzureStoreRefusesRedirects(t *testing.T) {
	const target = "/redirected"
	redirected := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == target {
			redirected = true
			_, _ = w.Write([]byte("should not reach here"))
			return
		}
		http.Redirect(w, r, target, http.StatusFound)
	}))
	defer srv.Close()

	s := azureTestStore(t, srv.URL, nil)
	if _, err := s.Get("run/abc/object"); err == nil {
		t.Fatal("a redirect must not be followed into a success")
	}
	if redirected {
		t.Fatal("the client followed a redirect; the CheckRedirect policy was not applied")
	}
}

// TestAzureStoreSASSendsNoAuthorizationHeader pins the SAS path, which is the cheaper credential
// precisely because nothing here signs anything: the token is a query string somebody else already
// signed. A request carrying BOTH a SAS and an Authorization header is refused by Azure rather than
// treated as belt and braces, so the absence of that header is the assertion.
func TestAzureStoreSASSendsNoAuthorizationHeader(t *testing.T) {
	const token = "sv=2022-11-02&ss=b&srt=o&sp=r&sig=abc%2Bdef%2F123%3D"
	var gotAuth, gotQuery, gotDate string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotDate = r.Header.Get("x-ms-date")
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("bytes"))
	}))
	defer srv.Close()

	s := azureTestStore(t, srv.URL, func(c *AzureConfig) {
		c.AccountKey = ""
		c.SASToken = "?" + token
	})
	if _, err := s.Get("run/abc/object"); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "" {
		t.Errorf("a SAS request carried an Authorization header %q; Azure refuses a request carrying both", gotAuth)
	}
	if gotDate != "" {
		t.Errorf("a SAS request carried x-ms-date %q; it exists to bind a Shared Key signature, and nothing signs here", gotDate)
	}
	if gotQuery != token {
		t.Errorf("the SAS reached the wire as %q, want %q unchanged: re-encoding it would corrupt the sig parameter", gotQuery, token)
	}

	// And a listing merges its own parameters with the token rather than replacing either.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = io.WriteString(w, enumerationResults("", "run/abc/object"))
	}))
	defer srv2.Close()
	s2 := azureTestStore(t, srv2.URL, func(c *AzureConfig) {
		c.AccountKey = ""
		c.SASToken = token
	})
	if _, err := s2.List("run/"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, "comp=list") || !strings.HasSuffix(gotQuery, token) {
		t.Errorf("a SAS listing sent %q, want the operation's own parameters followed by the token", gotQuery)
	}
}

// TestNewAzureStoreRefusals pins every construction refusal. Each one exists because the failure it
// prevents arrives on the wire as a 403 or a 404, which mid-recovery reads as a permissions problem on
// the container rather than as a command line the operator can fix.
func TestNewAzureStoreRefusals(t *testing.T) {
	base := func() AzureConfig {
		return AzureConfig{
			Endpoint:   "https://myaccount.blob.core.windows.net",
			Container:  "breakglass",
			AccountKey: testAzureKey,
			Now:        func() time.Time { return time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC) },
		}
	}
	cases := []struct {
		name    string
		mutate  func(*AzureConfig)
		wantErr error
	}{
		{"plain http to a remote host", func(c *AzureConfig) { c.Endpoint = "http://myaccount.blob.core.windows.net" }, ErrInsecureAzureEndpoint},
		{"a host that merely starts with localhost", func(c *AzureConfig) { c.Endpoint = "http://localhost.attacker.com" }, ErrInsecureAzureEndpoint},
		{"a private but off-host address", func(c *AzureConfig) { c.Endpoint = "http://192.168.1.1" }, ErrInsecureAzureEndpoint},
		{"a scheme that is neither", func(c *AzureConfig) { c.Endpoint = "ftp://myaccount.blob.core.windows.net" }, ErrInsecureAzureEndpoint},
		{"no container", func(c *AzureConfig) { c.Container = "" }, ErrAzureNoContainer},
		{"no credential at all", func(c *AzureConfig) { c.AccountKey = "" }, ErrAzureNoCredential},
		{"both a key and a SAS", func(c *AzureConfig) { c.SASToken = "sv=2022-11-02&sig=abc" }, ErrAzureTwoCredentials},
		{"a key that is not base64", func(c *AzureConfig) { c.AccountKey = "not base64!!" }, ErrAzureKeyNotBase64},
		{
			"an account name that is neither given nor derivable",
			func(c *AzureConfig) { c.Endpoint = "https://storage"; c.Account = "" },
			ErrAzureNoAccount,
		},
		{"a SAS with no signature", func(c *AzureConfig) { c.AccountKey = ""; c.SASToken = "sv=2022-11-02&ss=b" }, ErrAzureSASNoSignature},
		{
			"a SAS that has expired",
			func(c *AzureConfig) { c.AccountKey = ""; c.SASToken = "sv=2022-11-02&se=2026-08-24T00:00:00Z&sig=abc" },
			ErrAzureSASExpired,
		},
		{
			"a SAS whose expiry is present and unreadable",
			func(c *AzureConfig) { c.AccountKey = ""; c.SASToken = "sv=2022-11-02&se=next+tuesday&sig=abc" },
			ErrAzureSASBadExpiry,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mutate(&cfg)
			_, err := NewAzureStore(cfg)
			if err == nil {
				t.Fatalf("NewAzureStore returned no error, want %v", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("NewAzureStore error is %v, want it to wrap %v", err, tc.wantErr)
			}
			// The refusal must never echo the credential: a SAS IS the credential in full, and
			// an error message reaches the terminal, a run log and whatever an operator pastes
			// into a ticket.
			if cfg.SASToken != "" && strings.Contains(err.Error(), "sig=abc") {
				t.Errorf("the refusal echoed the SAS token: %v", err)
			}
		})
	}
}

// TestNewAzureStoreAccepts is the positive control for the table above: without it, every refusal
// would pass on a constructor that refused everything.
func TestNewAzureStoreAccepts(t *testing.T) {
	fixed := func() time.Time { return time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC) }
	cases := []struct {
		name string
		cfg  AzureConfig
	}{
		{"https with an account key", AzureConfig{Endpoint: "https://myaccount.blob.core.windows.net", Container: "c", AccountKey: testAzureKey, Now: fixed}},
		{"a SAS with no expiry, which is legal", AzureConfig{Endpoint: "https://myaccount.blob.core.windows.net", Container: "c", SASToken: "sv=2022-11-02&sig=abc", Now: fixed}},
		{"a SAS whose expiry is still ahead", AzureConfig{Endpoint: "https://myaccount.blob.core.windows.net", Container: "c", SASToken: "sv=2022-11-02&se=2026-12-31T23:59:59Z&sig=abc", Now: fixed}},
		{"a SAS whose expiry is written to the minute", AzureConfig{Endpoint: "https://myaccount.blob.core.windows.net", Container: "c", SASToken: "sv=2022-11-02&se=2026-12-31T23:59Z&sig=abc", Now: fixed}},
		{"a SAS whose expiry is a bare date", AzureConfig{Endpoint: "https://myaccount.blob.core.windows.net", Container: "c", SASToken: "sv=2022-11-02&se=2026-12-31&sig=abc", Now: fixed}},
		{"an exactly-loopback http endpoint, for a local emulator", AzureConfig{Endpoint: "http://127.0.0.1:10000", Container: "c", Account: "devstoreaccount1", AccountKey: testAzureKey, Now: fixed}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewAzureStore(tc.cfg); err != nil {
				t.Fatalf("NewAzureStore refused a valid configuration: %v", err)
			}
		})
	}
}

// TestAzureAccountFromHost pins where the account name comes from when none was supplied.
func TestAzureAccountFromHost(t *testing.T) {
	cases := map[string]string{
		"myaccount.blob.core.windows.net": "myaccount",
		"other.blob.core.windows.net":     "other",
		// No dot means no label to read, and returning "" is what makes AZURE_STORAGE_ACCOUNT a
		// required input there rather than a guessed one: a guessed account name signs into the
		// canonicalised resource and answers 403, indistinguishable from a wrong key.
		"localhost": "",
		"127.0.0.1": "127",
	}
	for host, want := range cases {
		if got := azureAccountFromHost(host); got != want {
			t.Errorf("azureAccountFromHost(%q) = %q, want %q", host, got, want)
		}
	}
}

// TestAzureStoreSignsWhatItSends is the assertion that would have caught the whole class of
// encode-versus-sign faults: the wire path is percent-encoded, the signed resource is not, and a key
// carrying characters that need escaping must still authenticate.
//
// The server re-derives the string to sign from the request it received and compares signatures, so
// this proves the two agree rather than proving each is individually plausible.
func TestAzureStoreSignsWhatItSends(t *testing.T) {
	creds, err := newAzureSharedKeyCreds("myaccount", testAzureKey)
	if err != nil {
		t.Fatalf("newAzureSharedKeyCreds: %v", err)
	}
	const key = "run/a b+c/root=1.json"

	var mismatch string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Rebuild the canonical string from the DECODED path, exactly as Azure does.
		decoded, decErr := decodeRequestPath(r.URL)
		if decErr != nil {
			mismatch = fmt.Sprintf("the request target does not decode: %v", decErr)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		headers := map[string]string{"x-ms-date": r.Header.Get("x-ms-date"), "x-ms-version": r.Header.Get("x-ms-version")}
		_, want := signAzureSharedKey(azureSignRequest{Method: r.Method, Path: decoded, Headers: headers}, creds)
		if got := r.Header.Get("Authorization"); got != want {
			mismatch = fmt.Sprintf("the signature does not cover the path that was sent\n sent path: %q\n      got: %q\n     want: %q", decoded, got, want)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	s := azureTestStore(t, srv.URL, nil)
	if _, err := s.Get(key); err != nil {
		t.Fatalf("a key with characters that need escaping did not authenticate: %v", err)
	}
	if mismatch != "" {
		t.Fatal(mismatch)
	}
}

// decodeRequestPath returns the request target's path with its percent-escapes resolved, which is the
// form Azure builds its canonicalised resource from. url.URL.Path already holds the decoded form for a
// target net/http parsed, so this is a named accessor rather than a decoder, and it fails loudly on the
// one shape that would not have been parsed.
func decodeRequestPath(u *url.URL) (string, error) {
	if u.Path == "" {
		return "", errors.New("the request carried no path")
	}
	return u.Path, nil
}
