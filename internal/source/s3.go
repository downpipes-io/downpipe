package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultS3Timeout bounds a single object fetch. It is generous enough to transfer a
// large archive object over a slow link, yet finite so a hung storage service cannot
// block the offline restore indefinitely.
const defaultS3Timeout = 60 * time.Second

// defaultStreamIdleTimeout bounds the gap between successive body bytes on the
// STREAMED read path (GetReader). A streamed object may legitimately take longer than
// defaultS3Timeout in total, so the stream has no whole-request bound; instead a body
// that delivers nothing for this long is aborted, so a stalled storage service still
// cannot hang a restore.
const defaultStreamIdleTimeout = 30 * time.Second

// S3Store reads archive objects from an S3-compatible bucket (R2, Backblaze B2,
// Wasabi, MinIO, AWS S3) over HTTPS with SigV4 auth. It is a GET-only client carrying
// no analytics, telemetry or vendor SDK, only the bytes, so the recovery path reaches
// the customer's own bucket and nothing else.
type S3Store struct {
	endpoint string
	bucket   string
	creds    sigV4Creds
	client   *http.Client
	// streamClient serves GetReader: no whole-request timeout (a large object may
	// stream for minutes), with the connect, TLS and first-byte phases bounded by the
	// shared transport and the body bounded by the idle watchdog.
	streamClient *http.Client
	// idleTimeout is the streamed-body idle bound; a field (not a package variable) so
	// a test can shorten it on one store without racing others.
	idleTimeout time.Duration
	// maxBytes is the per-object read ceiling; 0 means the package default
	// (maxObjectBytes). Settable only within the package, exactly as DirStore.maxBytes
	// is, so the body-size guard can be exercised with a small limit instead of moving
	// 2 GiB through a test server. The guard proved is the same one either way, and the
	// large form was costing more than the coverage was worth.
	maxBytes int64
	now      func() time.Time
}

// unreachableErr marks a Get/GetContext/GetReader failure as TRANSPORT/ACCESS layer: the
// object's bytes were never retrieved, either because the request never reached the
// destination (a dial, DNS or TLS failure below the HTTP layer) or because the destination
// refused it outright with a non-2xx status before any body arrived. It is the store-side
// half of internal/format's ExitUnreachable split (see that constant's doc for the
// boundary): this package need not import internal/format to participate, because the
// capability is a plain `Unreachable() bool` method, checked there through errors.As, the
// same pattern *format.ExitError's ExitCode() uses in the other direction.
//
// Error() delegates verbatim to the wrapped error, so a caller or test that inspects the
// message (for example checking it mentions "403" or "status 404") sees exactly the text
// it saw before this type existed.
type unreachableErr struct{ err error }

func (e *unreachableErr) Error() string     { return e.err.Error() }
func (e *unreachableErr) Unwrap() error     { return e.err }
func (e *unreachableErr) Unreachable() bool { return true }

// limit returns the effective per-object ceiling for this store.
func (s *S3Store) limit() int64 {
	if s.maxBytes > 0 {
		return s.maxBytes
	}
	return maxObjectBytes
}

// ErrInsecureEndpoint is returned by NewS3Store when the endpoint scheme is not
// https (or http://localhost / http://127.0.0.1 for local testing).
var ErrInsecureEndpoint = errors.New("s3 endpoint must use https")

// isPermittedEndpoint reports whether ep is allowed. HTTPS is always accepted.
// Plain HTTP is permitted only when the host is EXACTLY localhost, 127.0.0.1 or
// ::1, which allows httptest servers used in tests and local MinIO instances.
//
// The host is matched by exact equality after parsing, never by string prefix:
// a prefix match on "http://localhost" / "http://127.0.0.1" would also admit a
// hostile name such as http://localhost.attacker.com or http://127.0.0.1.evil.example,
// sending the SigV4 Authorization credential and archive bytes in CLEARTEXT to an
// attacker-controlled off-host endpoint (ASVS V12.2.1). Mirrors the exact-hostname
// discipline the engine's own HTTPS-endpoint validation applies.
func isPermittedEndpoint(ep string) bool {
	u, err := url.Parse(strings.TrimSpace(ep))
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" {
		host := strings.ToLower(u.Hostname())
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}
	return false
}

// S3Config groups the inputs to NewS3Store so the call site names each field rather than
// relying on positional order, which made transposing two of the five plain strings (for
// example AccessKeyID and SecretKey) a silent compile-time hazard.
type S3Config struct {
	Endpoint    string
	Bucket      string
	Region      string
	AccessKeyID string
	SecretKey   string
}

// NewS3Store returns an S3Store for the given endpoint (for example
// https://<account>.r2.cloudflarestorage.com), bucket and credentials.
// It returns an error if the endpoint scheme is not https (local test addresses
// http://localhost and http://127.0.0.1 are also accepted).
func NewS3Store(cfg S3Config) (*S3Store, error) {
	if !isPermittedEndpoint(cfg.Endpoint) {
		return nil, fmt.Errorf("%w: got %q", ErrInsecureEndpoint, cfg.Endpoint)
	}
	// One transport serves both clients (one connection pool), with the connect, TLS and
	// first-byte phases bounded so even the un-timeout-ed stream client cannot hang before
	// a body exists. The pool settings mirror net/http's DefaultTransport.
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: defaultS3Timeout,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	// Refuse all redirects on both clients. A redirect from the storage service to a
	// different host could silently expose the SigV4 Authorization header or steer
	// archive bytes to an attacker-controlled endpoint.
	refuseRedirects := func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &S3Store{
		endpoint: strings.TrimRight(cfg.Endpoint, "/"),
		bucket:   cfg.Bucket,
		creds:    sigV4Creds{accessKeyID: cfg.AccessKeyID, secretKey: cfg.SecretKey, region: cfg.Region, service: "s3"},
		client: &http.Client{
			Timeout:       defaultS3Timeout,
			Transport:     transport,
			CheckRedirect: refuseRedirects,
		},
		streamClient: &http.Client{
			Transport:     transport,
			CheckRedirect: refuseRedirects,
		},
		idleTimeout: defaultStreamIdleTimeout,
		now:         time.Now,
	}, nil
}

// signedGetRequest builds the SigV4-signed GET for one object key, shared by the
// buffered Get and the streamed GetReader so the two paths cannot drift on signing.
func (s *S3Store) signedGetRequest(key string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, s.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("object url for %s: %w", key, err)
	}
	// Sign and send the exact same canonical path. The path is AWS-UriEncoded per
	// segment and carried as the opaque request target so net/http transmits it
	// byte-for-byte rather than re-normalising it away from what was signed.
	canonicalPath := "/" + s.bucket + "/" + encodePath(key)
	req.URL.Opaque = canonicalPath
	amzDate := s.now().UTC().Format("20060102T150405Z")
	headers := map[string]string{
		"host":                 req.URL.Host,
		"x-amz-date":           amzDate,
		"x-amz-content-sha256": emptyPayloadHash,
	}
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", emptyPayloadHash)
	req.Header.Set("Authorization", signV4(sigV4Request{
		Method:       http.MethodGet,
		CanonicalURI: canonicalPath,
		Query:        "",
		Headers:      headers,
		PayloadHash:  emptyPayloadHash,
		AmzDate:      amzDate,
	}, s.creds))
	return req, nil
}

// Get fetches the object at the given archive key from the bucket.
func (s *S3Store) Get(key string) ([]byte, error) {
	req, err := s.signedGetRequest(key)
	if err != nil {
		return nil, err
	}
	return s.doBufferedGet(key, req)
}

// GetContext is Get bounded by the caller's context: identical signing, gates and byte
// ceiling, with the request cancellable so an error teardown or an operator interrupt
// stops an in-flight fetch instead of waiting out the whole-request timeout.
func (s *S3Store) GetContext(ctx context.Context, key string) ([]byte, error) {
	req, err := s.signedGetRequest(key)
	if err != nil {
		return nil, err
	}
	return s.doBufferedGet(key, req.WithContext(ctx))
}

// doBufferedGet sends one signed GET on the buffered 60 s client and consumes the
// response under the shared status, Content-Length and byte-ceiling gates.
func (s *S3Store) doBufferedGet(key string, req *http.Request) ([]byte, error) {
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, &unreachableErr{err: fmt.Errorf("get %s: could not reach the destination: %w", key, s.sentTo(key, err))}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, &unreachableErr{err: fmt.Errorf("get %s: %s returned status %d%s", key, s.objectAddress(key), resp.StatusCode, httpStatusHint(resp.StatusCode))}
	}
	limit := s.limit()
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

// objectAddress renders the address one object request was actually sent to: the configured
// endpoint's scheme and host, then the canonical bucket/key path. It exists for MESSAGES only.
// The request itself carries that path in req.URL.Opaque, because net/http must transmit the
// request target byte-for-byte as SigV4 signed it, and this function must never be used to
// build a request or the two paths could drift.
func (s *S3Store) objectAddress(key string) string {
	canonicalPath := "/" + s.bucket + "/" + encodePath(key)
	u, err := url.Parse(s.endpoint)
	if err != nil || u.Host == "" {
		// NewS3Store already rejected an endpoint this cannot parse, so this is unreachable in
		// practice; falling back to the raw endpoint keeps a message honest rather than empty.
		return strings.TrimSuffix(s.endpoint, "/") + canonicalPath
	}
	return u.Scheme + "://" + u.Host + canonicalPath
}

// sentTo restates a transport failure with the address the request was sent to.
//
// WHAT WENT WRONG WITHOUT IT. signedGetRequest and signedRequest set req.URL.Opaque, which is
// correct on the wire: net/http then sends the canonical path exactly as it was signed instead
// of re-normalising it. But url.URL.String() renders an opaque URL as scheme + ":" + opaque and
// so DROPS THE HOST, and net/http carries that rendering into the *url.Error of every transport
// failure. An operator whose --s3-endpoint was wrong read
//
//	get run/…/root.json: could not reach the destination: Get "https:/my-bucket/run/…": dial tcp: lookup …: no such host
//
// where the only address on screen is malformed and is not the one that was dialled, so the one
// question they had (is my endpoint wrong?) could not be answered from the error. Unwrapping the
// *url.Error drops that rendering and puts the real address in its place; the cause below it is
// preserved verbatim and still unwraps, so net.Error and tls checks upstream are unaffected.
func (s *S3Store) sentTo(key string, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s %q: %w", ue.Op, s.objectAddress(key), ue.Err)
	}
	return err
}

// httpStatusHint returns a short, actionable parenthetical for the S3 status codes an
// operator is most likely to hit mid-recovery: wrong or expired credentials, a
// credential without permission on this bucket, or a wrong bucket/endpoint/key. It
// exists because "status 403" and "status 404" on their own read exactly like a
// verification failure (the archive is bad), when the far more common cause is a
// destination misconfiguration the operator can fix by checking a flag or a
// credential, not a reason to distrust the archive. Returns "" for a status with no
// specific, reliable interpretation, so the caller falls back to the bare status code
// rather than guessing.
func httpStatusHint(status int) string {
	switch status {
	case http.StatusForbidden:
		return " (access denied: check AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY and that this credential has read access to the bucket)"
	case http.StatusUnauthorized:
		return " (authentication failed: check AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)"
	case http.StatusNotFound:
		return " (not found: check --s3-bucket and --s3-endpoint point at the right destination, and that --run names a run that exists there)"
	default:
		return ""
	}
}

// encodePath AWS-UriEncodes each path segment of an object key, preserving the
// slashes. AWS SigV4 and S3 leave only A-Za-z0-9-._~ unescaped and percent-encode
// every other byte with uppercase hex; url.PathEscape does not, leaving bytes such as
// + : = & $ @ that are legal in object keys and would then fail signature matching.
func encodePath(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = awsURIEncode(p)
	}
	return strings.Join(parts, "/")
}

func awsURIEncode(s string) string {
	const upperhex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(upperhex[c>>4])
			b.WriteByte(upperhex[c&0x0f])
		}
	}
	return b.String()
}

// signedRequest builds a signed request for an arbitrary method against one object key, sharing the
// exact canonical-path and SigV4 construction Get uses. Factored out rather than duplicated because a
// delete that signs a different canonical path than it sends is a signature failure the operator would
// read as a permissions problem.
func (s *S3Store) signedRequest(method, key string) (*http.Request, error) {
	req, err := http.NewRequest(method, s.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("object url for %s: %w", key, err)
	}
	canonicalPath := "/" + s.bucket + "/" + encodePath(key)
	req.URL.Opaque = canonicalPath
	amzDate := s.now().UTC().Format("20060102T150405Z")
	headers := map[string]string{
		"host":                 req.URL.Host,
		"x-amz-date":           amzDate,
		"x-amz-content-sha256": emptyPayloadHash,
	}
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", emptyPayloadHash)
	req.Header.Set("Authorization", signV4(sigV4Request{
		Method:       method,
		CanonicalURI: canonicalPath,
		Query:        "",
		Headers:      headers,
		PayloadHash:  emptyPayloadHash,
		AmzDate:      amzDate,
	}, s.creds))
	return req, nil
}

// Delete removes one object, satisfying format.MutatingStore.
//
// 404 and 204 are both success: S3 DeleteObject returns 204 for a delete it performed and, for a key
// that was already absent, still returns 204 rather than 404. Treating both as success keeps the prune
// re-runnable after an interruption.
//
// Every other non-2xx is an ERROR carrying its status, and that matters specifically for 403. A bucket
// under Object Lock refuses deletes with 403, and the prune counts those refusals rather than treating
// them as done. Swallowing a WORM refusal would tell an operator their retention had been applied when
// nothing was removed, which is the failure this whole tool exists to stop being possible.
func (s *S3Store) Delete(key string) error {
	req, err := s.signedRequest(http.MethodDelete, key)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("delete %s: could not reach the destination: %w", key, s.sentTo(key, err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil // already gone: the desired end state
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("delete %s: %s returned status %d%s", key, s.objectAddress(key), resp.StatusCode, httpStatusHint(resp.StatusCode))
	}
	return nil
}
