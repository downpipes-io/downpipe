package source

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Azure Storage Shared Key authentication, for the Azure Blob source.
//
// WHY THIS EXISTS AT ALL, when every other destination this reader reaches is signed with SigV4.
// Azure Blob Storage does not speak the S3 API. It is not an S3-compatible store behind a different
// host, the way Cloudflare R2 and Google Cloud Storage are: it is a different wire protocol with a
// different authentication scheme, a different request shape and a different listing document. So
// --s3-endpoint cannot reach an Azure container at any value, and an estate whose only destination is
// Azure had no offline break-glass path until this file and azure.go existed. That is the whole
// reason for them: the reader is what makes "you can always recover without us" true, and a
// destination the reader cannot open is a destination that claim does not cover.
//
// THE SCHEME. Azure builds a canonical string from a FIXED-POSITION list of eleven standard headers,
// then every x-ms-* header sorted, then a canonicalised resource path with its query parameters
// sorted. The signature is HMAC-SHA256 over that string, keyed by the account key, which is base64
// and must be DECODED before use rather than hashed as text. The result rides in
// `Authorization: SharedKey <account>:<signature>`.
//
// THE TRAP THAT MAKES THIS WORTH KNOWN-ANSWER VECTORS. The eleven standard fields are POSITIONAL: an
// absent Content-Length is an empty LINE, not an omitted one, so a signer that skips empty headers
// produces a string of the right shape and the wrong length, and every request fails with a 403 that
// says nothing about which line was dropped. Microsoft publishes worked examples of the
// string-to-sign, and azuresharedkey_test.go grades this implementation against them character for
// character rather than checking that some signature was produced.
//
// CONTENT-LENGTH IS THE SPECIFIC ONE. Azure's own rule changed with the API version: a
// zero content length signs as an EMPTY string, never as "0". A signer that writes "0" authenticates
// every body-bearing request correctly and fails every GET, HEAD and LIST, which is every request
// this reader makes, and it fails them as a permission error rather than as a signing one.

// azureAPIVersion is the Storage service version every request declares in x-ms-version. It is not a
// cosmetic header: the empty-string rule for a zero Content-Length below is specific to
// and later, so moving this constant without re-reading that rule silently breaks every body-less
// call. It matches the version the writing engine signs for, so a container written by the engine and
// read by this tool are addressed through one service contract.
const azureAPIVersion = "2021-12-02"

// azureStandardFields are the ELEVEN positional header slots of the string to sign, in Azure's own
// order. It is an ARRAY rather than a slice so its length is fixed at compile time, and the length is
// load-bearing: the VERB is followed by exactly these eleven lines whether or not a request carries
// the headers, because an absent header contributes an empty line rather than disappearing.
var azureStandardFields = [...]string{
	"content-encoding",
	"content-language",
	"content-length",
	"content-md5",
	"content-type",
	"date",
	"if-modified-since",
	"if-match",
	"if-none-match",
	"if-unmodified-since",
	"range",
}

// ErrAzureKeyNotBase64 is returned when the storage account key cannot be decoded. The key is
// STANDARD base64, not base64url: an account key contains "+" and "/", and a url-safe decoder would
// produce different key bytes and a 403 that names nothing.
var ErrAzureKeyNotBase64 = errors.New("the azure storage account key is not valid base64")

// ErrAzureKeyEmpty is returned when the account key decodes to no bytes at all. Refused here rather
// than at the first request, because an empty key does not fail: it produces a valid HMAC under a
// zero-length key and a 403 AuthenticationFailed on every call, which sends an operator to audit the
// container's permissions for what is a missing credential.
var ErrAzureKeyEmpty = errors.New("the azure storage account key decodes to no bytes")

// azureSharedKeyCreds is the storage account and its DECODED key. The key is decoded once at
// construction so no request path can decode it again differently, and so a malformed key is a
// construction failure rather than a per-request one.
type azureSharedKeyCreds struct {
	account string
	key     []byte
}

// newAzureSharedKeyCreds decodes the account key exactly as the Azure portal prints it.
func newAzureSharedKeyCreds(account, keyBase64 string) (azureSharedKeyCreds, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(keyBase64))
	if err != nil {
		return azureSharedKeyCreds{}, fmt.Errorf("%w: %v", ErrAzureKeyNotBase64, err)
	}
	if len(key) == 0 {
		return azureSharedKeyCreds{}, ErrAzureKeyEmpty
	}
	return azureSharedKeyCreds{account: account, key: key}, nil
}

// azureSignRequest groups the per-request inputs to signAzureSharedKey so the call site reads by
// field name rather than by positional string order, exactly as sigV4Request does for the S3 side.
//
// Path is the resource path WITHOUT the account and DECODED, because Azure's canonicalised resource
// is built from the decoded path while the wire carries the encoded one. Query is the request's own
// parameters, unsorted and unencoded. Headers are the headers to sign and send; every x-ms-* one is
// signed, and the eleven standard slots are read from here where present.
type azureSignRequest struct {
	Method  string
	Path    string
	Query   map[string]string
	Headers map[string]string
	// ContentLength is the request body length, signed as an EMPTY line when zero. This reader
	// never sends a body, so it is always zero here; the field exists because the rule is the one
	// most likely to be got wrong and it is graded by a known-answer vector rather than assumed.
	ContentLength int64
}

// signAzureSharedKey builds the Shared Key Authorization header for one request.
//
// It returns the string it signed as well as the header, because a signature that disagrees is
// undiagnosable without it: two signers differing by one empty line produce two opaque base64 strings
// and no way to see which line moved. Every vector in azuresharedkey_test.go grades the string.
func signAzureSharedKey(req azureSignRequest, creds azureSharedKeyCreds) (stringToSign, authorization string) {
	fields := make([]string, 0, len(azureStandardFields))
	for _, f := range azureStandardFields {
		switch f {
		case "content-length":
			// The rule: a zero length signs as EMPTY, never "0". See this file's
			// header for why getting this wrong looks exactly like a permission problem.
			if req.ContentLength == 0 {
				fields = append(fields, "")
				continue
			}
			fields = append(fields, strconv.FormatInt(req.ContentLength, 10))
		case "date":
			// Deliberately always empty: x-ms-date carries the timestamp and is signed among the
			// x-ms-* headers instead. Azure accepts either, but signing both binds the request to
			// two instants, and any skew between them is a 403 nothing explains.
			fields = append(fields, "")
		default:
			fields = append(fields, azureHeaderValue(req.Headers, f))
		}
	}

	var b strings.Builder
	b.WriteString(strings.ToUpper(req.Method))
	b.WriteByte('\n')
	b.WriteString(strings.Join(fields, "\n"))
	b.WriteByte('\n')
	b.WriteString(azureCanonicalHeaders(req.Headers))
	b.WriteString(azureCanonicalResource(creds.account, req.Path, req.Query))
	stringToSign = b.String()

	// hmacSHA256 is sigv4.go's own helper, shared rather than re-written: the two schemes differ in
	// what they canonicalise, not in the primitive that keys the result.
	authorization = "SharedKey " + creds.account + ":" + base64.StdEncoding.EncodeToString(hmacSHA256(creds.key, []byte(stringToSign)))
	return stringToSign, authorization
}

// azureHeaderValue reads one standard-slot header by its lower-cased name, returning "" when the
// request does not carry it. The value is returned VERBATIM: only the x-ms-* lines are
// whitespace-collapsed, which is Azure's own division rather than an oversight here.
func azureHeaderValue(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// azureCanonicalHeaders builds the x-ms-* half of the string to sign: every header whose name begins
// "x-ms-", lower-cased, sorted by name, one "name:value" line each, with internal whitespace
// collapsed to single spaces and the ends trimmed.
//
// The sort is ORDINAL on the lower-cased name, which is what sort.Strings does on Go strings. A
// locale-aware comparison orders some characters differently from Azure's own and produces a
// canonical string that differs only in line order, which is invisible in a diff and fatal on the
// wire.
func azureCanonicalHeaders(headers map[string]string) string {
	values := make(map[string]string, len(headers))
	for k, v := range headers {
		lk := strings.ToLower(k)
		if !strings.HasPrefix(lk, "x-ms-") {
			continue
		}
		// strings.Fields splits on any run of whitespace and drops the ends, so the join is the
		// trim and the collapse in one pass.
		values[lk] = strings.Join(strings.Fields(v), " ")
	}
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(values[n])
		b.WriteByte('\n')
	}
	return b.String()
}

// azureCanonicalResource builds the resource half: "/<account><path>", then one line per query
// parameter as "name:value", lower-cased by name and sorted.
//
// The path is the DECODED one. The wire carries a percent-encoded path (azure.go encodes it), and
// signing the encoded form authenticates nothing: Azure builds its own canonical string from the
// path it decoded.
//
// A parameter with an empty value still contributes its line, for the same positional reason the
// eleven standard fields do.
func azureCanonicalResource(account, path string, query map[string]string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	base := "/" + account + path
	if len(query) == 0 {
		return base
	}
	values := make(map[string]string, len(query))
	for k, v := range query {
		values[strings.ToLower(k)] = v
	}
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString(base)
	for _, n := range names {
		b.WriteByte('\n')
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(values[n])
	}
	return b.String()
}
