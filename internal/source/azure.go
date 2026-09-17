package source

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The Azure Blob Storage source: the READ half of an Azure container, for the offline reader.
//
// IT IS READ-ONLY ON PURPOSE, and the omission is not an unfinished piece. DirStore and S3Store both
// carry Delete because the offline prune runs against them. Nothing here does: the reader's job on an
// Azure container is to open an archive somebody else sealed, and a break-glass tool that can delete
// from a destination is a break-glass tool that can destroy the last copy of the data it exists to
// recover. AzureStore therefore satisfies format.ObjectStore, ContextStore, ReaderStore and
// ListingStore, and deliberately not MutatingStore, so `prune --apply` against an Azure container
// refuses by the capability it cannot find rather than by a check somebody has to remember to write.
//
// WHAT MAPS FROM THE S3 BACKEND, which is most of it: the https-or-exact-loopback endpoint rule, the
// refusal to follow redirects, the whole-request bound on the buffered path, the phase bounds plus
// idle watchdog on the streamed path, the per-object byte ceiling, and the unreachableErr
// classification that turns a transport failure or a non-2xx into SPEC.md 8.5's exit 11. Those are
// properties of reading an archive over HTTPS, not of the S3 protocol, so they are held identically
// here.
//
// WHAT DOES NOT MAP: the authentication (see azuresharedkey.go), the listing document (Azure answers
// an EnumerationResults XML page walked by NextMarker, not a continuation token), and the request
// target, where the wire path is percent-encoded while the string that is signed is the decoded one.

// defaultAzureTimeout bounds a single blob fetch, on the same terms and for the same reason as
// defaultS3Timeout: generous enough to transfer a large archive object over a slow link, finite so a
// hung storage service cannot block the offline restore indefinitely. Stated separately rather than
// shared with the S3 constant so a future change to one destination's patience does not silently
// change the other's.
const defaultAzureTimeout = 60 * time.Second

// maxListBodyBytes bounds one List Blobs page. A page carries at most 5,000 entries by Azure's own
// cap and each entry is a few hundred bytes of XML, so this is roomy for a legitimate page and finite
// against a hostile or broken endpoint that would otherwise stream XML until the reader ran out of
// memory, before any signature has been checked.
const maxListBodyBytes int64 = 16 << 20

// maxListPages bounds the NextMarker walk. Azure returns a marker to continue with and an empty one
// to stop, so an endpoint that returns the SAME marker for ever is an infinite loop that never
// allocates enough to trip any other guard. At 5,000 blobs a page this still enumerates ten million
// objects, which is far above any archive this reader opens.
const maxListPages = 2000

var (
	// ErrInsecureAzureEndpoint is returned by NewAzureStore when the endpoint scheme is not https
	// (or http:// on an exactly-loopback host, for tests and local emulators). The exact-host
	// discipline is isPermittedEndpoint's, shared with the S3 backend: see its doc for why the
	// loopback exemption is three exact names and never a prefix match.
	ErrInsecureAzureEndpoint = errors.New("azure endpoint must use https")
	// ErrAzureNoContainer is returned when no container was named. An Azure blob endpoint alone
	// addresses an account, not an archive.
	ErrAzureNoContainer = errors.New("azure needs a container name")
	// ErrAzureNoAccount is returned when the storage account name is neither supplied nor derivable
	// from the endpoint host. Shared Key signs the account name into the canonicalised resource, so
	// a wrong or absent one is a 403 rather than a 404.
	ErrAzureNoAccount = errors.New("azure needs a storage account name")
	// ErrAzureNoCredential is returned when neither an account key nor a SAS token was supplied.
	ErrAzureNoCredential = errors.New("azure needs a storage account key or a SAS token")
	// ErrAzureTwoCredentials is returned when BOTH were supplied. Refused rather than resolved by
	// precedence: an operator mid-recovery who has set two credentials has one of them wrong, and
	// silently picking the other means the run that succeeds proves nothing about the one they
	// meant to use.
	ErrAzureTwoCredentials = errors.New("azure was given both a storage account key and a SAS token")
	// ErrAzureSASNoSignature is returned when the SAS token carries no sig parameter, so it holds
	// no signature and could not authenticate any request. This is the paste-the-wrong-thing case:
	// a connection string, a container URL or an account key in the SAS slot.
	ErrAzureSASNoSignature = errors.New("the azure SAS token has no sig parameter")
	// ErrAzureSASExpired is returned when the token's se parameter is in the past. Refused at
	// construction so the cause is named, rather than arriving as a 403 on the first read.
	ErrAzureSASExpired = errors.New("the azure SAS token has expired")
	// ErrAzureSASBadExpiry is returned when a PRESENT se parameter is not a date. A token with no
	// se at all is legal and accepted (a service SAS can take its expiry from a stored access
	// policy), so the absence is not an error; a present-and-unreadable one is a malformed token,
	// and demoting it to "no expiry" would invent the one fact that can be seen to be wrong.
	ErrAzureSASBadExpiry = errors.New("the azure SAS token's se parameter is not a date this reader can read")
)

// azureCredential is the ONE place the two credential kinds differ, resolved once at construction so
// no request path has to re-decide it and no two of them can be armed at once.
//
// A SHARED KEY signs: the canonical string covers the method, the eleven standard fields, every
// x-ms-* header and the canonicalised resource INCLUDING its query, so the query the signature covers
// and the query on the URL have to be the same one.
//
// A SAS DOES NOT SIGN, AND MUST NOT SEND AN AUTHORIZATION HEADER. The signature is already inside the
// token; a request carrying both a SAS and an Authorization header is refused by Azure rather than
// treated as belt and braces. x-ms-version is still sent, because it is required on every authorised
// request and governs the response shape this client parses. x-ms-date is not sent: it exists so a
// Shared Key signature can be bound to an instant, and nothing signs it on this path.
type azureCredential interface {
	// authorise returns the headers to put on the request and the RAW query string for the URL.
	authorise(req azureSignRequest) (headers map[string]string, rawQuery string)
}

// azureSharedKeyCredential signs each request with the storage account key.
type azureSharedKeyCredential struct {
	creds azureSharedKeyCreds
	now   func() time.Time
}

func (c azureSharedKeyCredential) authorise(req azureSignRequest) (map[string]string, string) {
	headers := make(map[string]string, len(req.Headers)+3)
	for k, v := range req.Headers {
		headers[k] = v
	}
	// http.TimeFormat is RFC 1123 in GMT, which is the form Azure reads and the form the writing
	// engine sends.
	headers["x-ms-date"] = c.now().UTC().Format(http.TimeFormat)
	headers["x-ms-version"] = azureAPIVersion
	req.Headers = headers
	_, authorization := signAzureSharedKey(req, c.creds)
	// Set AFTER signing. Authorization is never part of the string to sign, and adding it before
	// would make no difference (it is not an x-ms-* header and occupies no standard slot), but
	// setting it here says so rather than leaving a reader to work it out.
	headers["Authorization"] = authorization
	return headers, azureEncodeQuery(req.Query)
}

// azureSASCredential carries a shared access signature somebody else already signed.
type azureSASCredential struct {
	// query is the token as query parameters, with no leading "?" and NOTHING re-encoded. A SAS
	// arrives already percent-encoded, and re-encoding it would corrupt the sig parameter, whose
	// base64 carries "+", "/" and "=".
	query string
}

func (c azureSASCredential) authorise(req azureSignRequest) (map[string]string, string) {
	headers := make(map[string]string, len(req.Headers)+1)
	for k, v := range req.Headers {
		headers[k] = v
	}
	headers["x-ms-version"] = azureAPIVersion
	own := azureEncodeQuery(req.Query)
	if own == "" {
		return headers, c.query
	}
	// The request's own parameters go first and the token after, which is cosmetic (a SAS is
	// verified over named fields, not over parameter order) and keeps a logged URL readable, with
	// the operation up front and the credential trailing where a reader expects it.
	return headers, own + "&" + c.query
}

// azureEncodeQuery renders the request's own query parameters for the wire. url.Values.Encode sorts
// by name and percent-encodes both halves, which is what Azure receives and decodes back into the
// values azureCanonicalResource signed raw.
func azureEncodeQuery(q map[string]string) string {
	if len(q) == 0 {
		return ""
	}
	v := make(url.Values, len(q))
	for k, s := range q {
		v.Set(k, s)
	}
	return v.Encode()
}

// AzureStore reads archive objects from one Azure Blob Storage container over HTTPS. It is a
// GET/HEAD/LIST-only client carrying no analytics, telemetry or vendor SDK, only the bytes, so the
// recovery path reaches the customer's own container and nothing else (CONTRIBUTING).
type AzureStore struct {
	origin    string // scheme://host, with no path and no trailing slash
	container string
	creds     azureCredential
	client    *http.Client
	// streamClient serves GetReader: no whole-request timeout (a large object may stream for
	// minutes), with the connect, TLS and first-byte phases bounded by the shared transport and the
	// body bounded by the idle watchdog. Exactly S3Store's split, for exactly its reason.
	streamClient *http.Client
	idleTimeout  time.Duration
	// maxBytes is the per-object read ceiling; 0 means the package default (maxObjectBytes).
	// Settable only within the package, as DirStore.maxBytes and S3Store.maxBytes are, so the
	// body-size guard can be exercised with a small limit instead of moving 2 GiB through a test
	// server.
	maxBytes int64
	now      func() time.Time
}

// limit returns the effective per-object ceiling for this store.
func (a *AzureStore) limit() int64 {
	if a.maxBytes > 0 {
		return a.maxBytes
	}
	return maxObjectBytes
}

// AzureConfig groups the inputs to NewAzureStore so the call site names each field rather than
// relying on positional order, which made transposing two plain strings a silent compile-time
// hazard. It mirrors S3Config for the same reason.
type AzureConfig struct {
	// Endpoint is the account's blob endpoint, for example
	// https://<account>.blob.core.windows.net.
	Endpoint string
	// Container is the container the archive lives in.
	Container string
	// Account is the storage account name. When empty it is taken from the endpoint's first host
	// label, which is where Azure's own endpoint form puts it.
	Account string
	// AccountKey is one of the account's access keys, base64 exactly as the portal prints it.
	AccountKey string
	// SASToken is a shared access signature supplied INSTEAD of the account key, with or without a
	// leading "?". It needs no signing at all: the signature is already inside it.
	SASToken string
	// Now is the clock, injectable so a test can pin the x-ms-date it signs and the instant a SAS
	// expiry is compared against. Nil means time.Now.
	Now func() time.Time
}

// NewAzureStore returns an AzureStore for the given endpoint, container and credential. It returns an
// error if the endpoint scheme is not https (local test addresses http://localhost and
// http://127.0.0.1 are also accepted), if no container was named, or if the credential is absent,
// doubled or malformed. Every one of those is refused HERE rather than at the first read, because
// each of them otherwise arrives mid-recovery as a 403 or a 404 that names nothing.
func NewAzureStore(cfg AzureConfig) (*AzureStore, error) {
	if !isPermittedEndpoint(cfg.Endpoint) {
		return nil, fmt.Errorf("%w: got %q", ErrInsecureAzureEndpoint, cfg.Endpoint)
	}
	u, err := url.Parse(strings.TrimSpace(cfg.Endpoint))
	if err != nil || u.Host == "" {
		// isPermittedEndpoint already parsed this successfully, so reaching here means the
		// endpoint has no host at all.
		return nil, fmt.Errorf("%w: got %q", ErrInsecureAzureEndpoint, cfg.Endpoint)
	}
	if strings.TrimSpace(cfg.Container) == "" {
		return nil, ErrAzureNoContainer
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	creds, err := newAzureCredential(cfg, u, now)
	if err != nil {
		return nil, err
	}

	// One transport serves both clients (one connection pool), with the connect, TLS and
	// first-byte phases bounded so even the un-timeout-ed stream client cannot hang before a body
	// exists. The pool settings mirror net/http's DefaultTransport, as S3Store's do.
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: defaultAzureTimeout,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	// Refuse all redirects on both clients. A redirect from the storage service to a different host
	// could expose the Shared Key Authorization header or the SAS token, which IS the credential in
	// full, or steer archive bytes to an attacker-controlled endpoint.
	refuseRedirects := func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &AzureStore{
		origin:    u.Scheme + "://" + u.Host,
		container: strings.Trim(strings.TrimSpace(cfg.Container), "/"),
		creds:     creds,
		client: &http.Client{
			Timeout:       defaultAzureTimeout,
			Transport:     transport,
			CheckRedirect: refuseRedirects,
		},
		streamClient: &http.Client{
			Transport:     transport,
			CheckRedirect: refuseRedirects,
		},
		idleTimeout: defaultStreamIdleTimeout,
		now:         now,
	}, nil
}

// newAzureCredential resolves EXACTLY ONE credential from the configuration, or refuses.
func newAzureCredential(cfg AzureConfig, u *url.URL, now func() time.Time) (azureCredential, error) {
	key := strings.TrimSpace(cfg.AccountKey)
	sas := strings.TrimSpace(cfg.SASToken)
	switch {
	case key == "" && sas == "":
		return nil, ErrAzureNoCredential
	case key != "" && sas != "":
		return nil, ErrAzureTwoCredentials
	case sas != "":
		parsed, err := parseAzureSASToken(sas, now())
		if err != nil {
			return nil, err
		}
		return azureSASCredential{query: parsed}, nil
	}
	account := strings.TrimSpace(cfg.Account)
	if account == "" {
		account = azureAccountFromHost(u.Hostname())
	}
	if account == "" {
		return nil, ErrAzureNoAccount
	}
	shared, err := newAzureSharedKeyCreds(account, key)
	if err != nil {
		return nil, err
	}
	return azureSharedKeyCredential{creds: shared, now: now}, nil
}

// azureAccountFromHost reads the storage account out of an endpoint host, which for Azure's own
// endpoint form is the first label: <account>.blob.core.windows.net.
//
// It returns "" for a host with no dot in it, which is every loopback test address and would also be
// a custom domain fronting the account. Returning "" rather than guessing is what makes the account
// name a REQUIRED input in those cases: Shared Key signs the account into the canonicalised resource,
// so a guessed one is a 403 with no way to tell it from a wrong key.
func azureAccountFromHost(host string) string {
	label, _, found := strings.Cut(host, ".")
	if !found {
		return ""
	}
	return label
}

// parseAzureSASToken validates an operator-supplied shared access signature and returns it normalised
// for appending to a URL. It refuses the three broken shapes by name rather than reporting a generic
// bad credential; see the Err values above for what each one means.
//
// WHAT IT DOES NOT CHECK, on purpose: sp (the permission letters), sr and srt (the resource scope)
// and ss (the service). Those spell differently across account, service and user delegation tokens,
// and a rule written from one shape would reject working tokens of another. What a token is ALLOWED
// to do is answered by the first read, and a refusal there is reported with the status Azure gave.
func parseAzureSASToken(raw string, now time.Time) (string, error) {
	query := strings.TrimPrefix(strings.TrimSpace(raw), "?")
	params, err := url.ParseQuery(query)
	if err != nil {
		// The message never quotes the token. A SAS IS a credential, in full, and one echoed into
		// an error reaches the terminal, the run log and whatever an operator pastes into a ticket.
		return "", fmt.Errorf("%w: it is not a readable query string", ErrAzureSASNoSignature)
	}
	if params.Get("sig") == "" {
		return "", ErrAzureSASNoSignature
	}
	se := params.Get("se")
	if se == "" {
		return query, nil
	}
	at, ok := parseAzureSASExpiry(se)
	if !ok {
		return "", ErrAzureSASBadExpiry
	}
	if !at.After(now) {
		// The DATE rides in the message and the token does not. The date is the operator's own
		// configuration and is the fact that makes this refusal actionable: it separates "expired
		// last night" from "expired in March and nobody noticed".
		return "", fmt.Errorf("%w at %s, so every request made with it would be refused", ErrAzureSASExpired, at.UTC().Format(time.RFC3339))
	}
	return query, nil
}

// azureSASExpiryLayouts are the ISO 8601 forms Azure writes into a SAS `se` parameter. Azure lets the
// minting caller truncate the instant, so all three are legitimate tokens and a reader that accepted
// only the full form would refuse working credentials mid-recovery. Anything outside this set is a
// malformed token rather than a shape we have not met: see ErrAzureSASBadExpiry for why that is
// refused rather than demoted to "no expiry".
var azureSASExpiryLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04Z07:00",
	"2006-01-02",
}

// parseAzureSASExpiry reads the `se` parameter as an instant, reporting whether any known layout
// matched.
func parseAzureSASExpiry(se string) (time.Time, bool) {
	for _, layout := range azureSASExpiryLayouts {
		if at, err := time.Parse(layout, se); err == nil {
			return at, true
		}
	}
	return time.Time{}, false
}

// blobPath is the resource path Azure SIGNS: decoded, container-rooted, no account. Kept in one place
// because the signer and the request must agree exactly, and a path encoded for the URL but signed
// raw (or the other way about) authenticates nothing while looking correct in every log.
func (a *AzureStore) blobPath(key string) string {
	return "/" + a.container + "/" + key
}

// containerPath is the resource path for a container-scoped operation, which is the listing.
func (a *AzureStore) containerPath() string {
	return "/" + a.container
}

// newRequest builds one authorised request against a decoded resource path.
//
// The path goes on the wire percent-encoded and into the signature raw. encodePath is the S3
// backend's own per-segment encoder, shared rather than re-written: it escapes everything outside
// A-Za-z0-9-._~ and preserves the slashes, which is stricter than Azure requires and decodes to
// exactly the path that was signed, so the canonicalised resource Azure rebuilds matches ours.
//
// req.URL.Opaque carries the encoded path so net/http transmits it byte for byte rather than
// re-normalising it, the same reason S3Store sets it. RawQuery is still appended by
// url.URL.RequestURI when Opaque is set, so a listing's parameters and a SAS both reach the wire.
func (a *AzureStore) newRequest(method, path string, query map[string]string) (*http.Request, error) {
	req, err := http.NewRequest(method, a.origin, nil)
	if err != nil {
		return nil, fmt.Errorf("object url for %s: %w", path, err)
	}
	headers, rawQuery := a.creds.authorise(azureSignRequest{
		Method:  method,
		Path:    path,
		Query:   query,
		Headers: map[string]string{},
	})
	req.URL.Opaque = encodePath(path)
	req.URL.RawQuery = rawQuery
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

// objectAddress renders the address one request was actually sent to: the configured endpoint's
// scheme and host, then the encoded resource path. It exists for MESSAGES only, for the same reason
// S3Store.objectAddress does, and must never be used to build a request or the sent and signed paths
// could drift. The query is deliberately omitted: on a SAS destination it IS the credential.
func (a *AzureStore) objectAddress(path string) string {
	return a.origin + encodePath(path)
}

// sentTo restates a transport failure with the address the request was sent to.
//
// Setting req.URL.Opaque is correct on the wire and wrong in an error message: url.URL.String
// renders an opaque URL as scheme + ":" + opaque and so DROPS THE HOST, and net/http carries that
// rendering into the *url.Error of every transport failure. An operator whose --azure-endpoint was
// wrong would read an address that is malformed and is not the one that was dialled, so the one
// question they had could not be answered from the error. See S3Store.sentTo, which this mirrors; the
// cause below is preserved verbatim and still unwraps.
func (a *AzureStore) sentTo(path string, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s %q: %w", ue.Op, a.objectAddress(path), ue.Err)
	}
	return err
}

// azureErrorCode pulls Azure's own closed error code out of the response HEADER, which is where Azure
// puts it. Reading the header rather than parsing the XML body means no byte of the body is ever
// carried into a message an operator may paste into a ticket.
func azureErrorCode(resp *http.Response) string {
	return resp.Header.Get("x-ms-error-code")
}

// azureStatusDetail renders the parenthetical for a status this reader cannot use: Azure's own error
// code where the response carried one, then a short actionable hint for the statuses an operator is
// most likely to hit mid-recovery.
//
// It exists for the reason httpStatusHint exists on the S3 side: "status 403" and "status 404" on
// their own read exactly like a verification failure (the archive is bad), when the far more common
// cause is a destination misconfiguration the operator can fix by checking a flag or a credential,
// and is no reason to distrust the archive.
func azureStatusDetail(status int, errorCode string) string {
	parts := make([]string, 0, 2)
	if errorCode != "" {
		parts = append(parts, errorCode)
	}
	if hint := azureStatusHint(status); hint != "" {
		parts = append(parts, hint)
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

// azureStatusHint returns the hint text for one status, or "" for a status with no specific and
// reliable interpretation, so the caller falls back to the bare status code rather than guessing.
func azureStatusHint(status int) string {
	switch status {
	case http.StatusForbidden:
		return "access denied: check AZURE_STORAGE_KEY or AZURE_STORAGE_SAS_TOKEN, that the credential has read access to the container, and that AZURE_STORAGE_ACCOUNT names the account in --azure-endpoint. A SAS that has expired also answers 403"
	case http.StatusUnauthorized:
		return "authentication failed: check AZURE_STORAGE_KEY or AZURE_STORAGE_SAS_TOKEN"
	case http.StatusNotFound:
		return "not found: check --azure-container and --azure-endpoint point at the right destination, and that --run names a run that exists there"
	default:
		return ""
	}
}

// Get fetches the object at the given archive key from the container.
func (a *AzureStore) Get(key string) ([]byte, error) {
	req, err := a.newRequest(http.MethodGet, a.blobPath(key), nil)
	if err != nil {
		return nil, err
	}
	return a.doBufferedGet(key, req)
}

// GetContext is Get bounded by the caller's context: identical signing, gates and byte ceiling, with
// the request cancellable so an error teardown or an operator interrupt stops an in-flight fetch
// instead of waiting out the whole-request timeout.
func (a *AzureStore) GetContext(ctx context.Context, key string) ([]byte, error) {
	req, err := a.newRequest(http.MethodGet, a.blobPath(key), nil)
	if err != nil {
		return nil, err
	}
	return a.doBufferedGet(key, req.WithContext(ctx))
}

// doBufferedGet sends one authorised GET on the buffered client and consumes the response under the
// shared status, Content-Length and byte-ceiling gates.
func (a *AzureStore) doBufferedGet(key string, req *http.Request) ([]byte, error) {
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, &unreachableErr{err: fmt.Errorf("get %s: could not reach the destination: %w", key, a.sentTo(a.blobPath(key), err))}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, &unreachableErr{err: fmt.Errorf("get %s: %s returned status %d%s", key, a.objectAddress(a.blobPath(key)), resp.StatusCode, azureStatusDetail(resp.StatusCode, azureErrorCode(resp)))}
	}
	limit := a.limit()
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("get %s: %d bytes exceeds the %d-byte limit", key, resp.ContentLength, limit)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", key, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("get %s: object exceeds the %d-byte limit", key, limit)
	}
	return b, nil
}

// GetReader fetches the object as a stream, so a large sealed segment decrypts chunk by chunk without
// its ciphertext ever being buffered whole. The buffered Get keeps its whole-request client (right
// for small manifest objects); this path instead bounds each PHASE: connect, TLS and first byte
// through the shared transport, and the body through the idle watchdog that aborts the request when
// no bytes arrive for the store's idle bound. Redirects are refused identically, the status and
// Content-Length gates match Get, and the per-object byte ceiling is enforced on the stream.
func (a *AzureStore) GetReader(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	req, err := a.newRequest(http.MethodGet, a.blobPath(key), nil)
	if err != nil {
		return nil, 0, err
	}
	wctx, cancel := context.WithCancel(ctx)
	req = req.WithContext(wctx)
	resp, err := a.streamClient.Do(req)
	if err != nil {
		cancel()
		return nil, 0, &unreachableErr{err: fmt.Errorf("get %s: could not reach the destination: %w", key, a.sentTo(a.blobPath(key), err))}
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		cancel()
		return nil, 0, &unreachableErr{err: fmt.Errorf("get %s: %s returned status %d%s", key, a.objectAddress(a.blobPath(key)), resp.StatusCode, azureStatusDetail(resp.StatusCode, azureErrorCode(resp)))}
	}
	limit := a.limit()
	if resp.ContentLength > limit {
		_ = resp.Body.Close()
		cancel()
		return nil, 0, fmt.Errorf("get %s: %d bytes exceeds the %d-byte limit", key, resp.ContentLength, limit)
	}
	w := &idleWatchdogBody{key: key, idle: a.idleTimeout, body: resp.Body, cancel: cancel}
	w.timer = time.AfterFunc(a.idleTimeout, func() {
		w.timedOut.Store(true)
		cancel()
	})
	return &boundedReadCloser{prefix: "get", key: key, src: w, closer: w, limit: limit}, resp.ContentLength, nil
}

// Exists reports whether the container holds the object, by HEAD.
//
// A NON-200, NON-404 STATUS IS AN ERROR HERE AND NOT AN ABSENCE, which is the opposite of what a
// writing client does with the same call. A writer collapses a 403 or a 5xx to "absent" and re-uploads,
// which costs bandwidth; a READER that collapsed them would tell an operator mid-recovery that an
// object is missing from their archive when the truth is that their credential was refused, and
// "your backup is short of an object" is the most expensive wrong answer this tool could give.
//
// No interface in internal/format consumes this today: the reader opens objects rather than probing
// for them. It is here because "is this key in the container" is the question an operator asks when a
// restore reports a dangling segment, and answering it required a HEAD that nothing else exposes.
func (a *AzureStore) Exists(key string) (bool, error) {
	req, err := a.newRequest(http.MethodHead, a.blobPath(key), nil)
	if err != nil {
		return false, err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return false, &unreachableErr{err: fmt.Errorf("head %s: could not reach the destination: %w", key, a.sentTo(a.blobPath(key), err))}
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, &unreachableErr{err: fmt.Errorf("head %s: %s returned status %d%s", key, a.objectAddress(a.blobPath(key)), resp.StatusCode, azureStatusDetail(resp.StatusCode, azureErrorCode(resp)))}
	}
}

// azureListBlobsResult is the shape of Azure's List Blobs response, read with encoding/xml rather
// than with a regular expression.
//
// The stdlib parser is the reason a key carrying an XML entity comes back usable: a blob named with
// an ampersand arrives as &amp; and is decoded here, where a regex would return a name no later
// request could address. It also addresses Blobs>Blob>Name specifically, so a BlobPrefix element
// (which a delimited listing returns, and which is a folder rather than an object) can never be
// mistaken for a key.
type azureListBlobsResult struct {
	XMLName xml.Name `xml:"EnumerationResults"`
	Blobs   struct {
		Blob []struct {
			Name string `xml:"Name"`
		} `xml:"Blob"`
	} `xml:"Blobs"`
	NextMarker string `xml:"NextMarker"`
}

// List returns the object keys under prefix, satisfying format.ListingStore. Keys come back as blob
// names, which for a container-rooted archive ARE the store's keys, so a caller can hand them straight
// back to Get.
//
// Azure pages a listing with NextMarker rather than with a continuation token: a non-empty marker in
// the response is the value to send as the next request's marker parameter, and an empty one means
// the listing is complete. The walk is bounded (maxListPages), because an endpoint returning the same
// marker for ever is a loop that allocates too little to trip any other guard.
func (a *AzureStore) List(prefix string) ([]string, error) {
	var keys []string
	marker := ""
	for page := 0; ; page++ {
		if page >= maxListPages {
			return nil, fmt.Errorf("list objects under %s: the destination returned more than %d pages of results, so the listing was stopped rather than followed further", prefix, maxListPages)
		}
		batch, next, err := a.listPage(prefix, marker)
		if err != nil {
			return nil, err
		}
		keys = append(keys, batch...)
		if next == "" {
			return keys, nil
		}
		marker = next
	}
}

// listPage fetches one List Blobs page and returns its keys and the marker to continue with ("" when
// the listing is complete).
func (a *AzureStore) listPage(prefix, marker string) ([]string, string, error) {
	query := map[string]string{"restype": "container", "comp": "list", "prefix": prefix}
	if marker != "" {
		query["marker"] = marker
	}
	req, err := a.newRequest(http.MethodGet, a.containerPath(), query)
	if err != nil {
		return nil, "", err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, "", &unreachableErr{err: fmt.Errorf("list objects under %s: could not reach the destination: %w", prefix, a.sentTo(a.containerPath(), err))}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, "", &unreachableErr{err: fmt.Errorf("list objects under %s: %s returned status %d%s", prefix, a.objectAddress(a.containerPath()), resp.StatusCode, azureStatusDetail(resp.StatusCode, azureErrorCode(resp)))}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBodyBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("list objects under %s: %w", prefix, err)
	}
	if int64(len(body)) > maxListBodyBytes {
		return nil, "", fmt.Errorf("list objects under %s: one page of results exceeds the %d-byte limit", prefix, maxListBodyBytes)
	}
	var parsed azureListBlobsResult
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return nil, "", fmt.Errorf("list objects under %s: the destination's response is not a List Blobs document: %w", prefix, err)
	}
	keys := make([]string, 0, len(parsed.Blobs.Blob))
	for _, b := range parsed.Blobs.Blob {
		keys = append(keys, b.Name)
	}
	return keys, strings.TrimSpace(parsed.NextMarker), nil
}
