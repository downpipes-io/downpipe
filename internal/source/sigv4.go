package source

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

const (
	sigV4Algorithm = "AWS4-HMAC-SHA256"
	// emptyPayloadHash is SHA-256 of the empty string, the payload hash for a GET.
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

type sigV4Creds struct {
	accessKeyID string
	secretKey   string
	region      string
	service     string
}

// sigV4Request groups the per-request inputs to signV4 so the signing call site reads by
// field name rather than by positional string order. Headers must include the host and
// x-amz-date (and, for S3, x-amz-content-sha256); AmzDate is the ISO basic form
// YYYYMMDDTHHMMSSZ.
type sigV4Request struct {
	Method       string
	CanonicalURI string
	Query        string
	Headers      map[string]string
	PayloadHash  string
	AmzDate      string
}

// signV4 builds the AWS Signature Version 4 Authorization header for a request. It is
// a minimal, dependency-free implementation, validated against the AWS SigV4 test suite.
func signV4(req sigV4Request, creds sigV4Creds) string {
	method := req.Method
	canonicalURI := req.CanonicalURI
	canonicalQuery := req.Query
	headers := req.Headers
	payloadHash := req.PayloadHash
	amzDate := req.AmzDate
	dateStamp := amzDate[:8]

	lower := make(map[string]string, len(headers))
	keys := make([]string, 0, len(headers))
	for k, v := range headers {
		lk := strings.ToLower(k)
		// AWS SigV4 spec requires leading/trailing whitespace stripped AND
		// consecutive internal whitespace collapsed to a single space.
		lower[lk] = collapseSpaces(v)
		keys = append(keys, lk)
	}
	sort.Strings(keys)

	var canonicalHeaders strings.Builder
	for _, k := range keys {
		canonicalHeaders.WriteString(k)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(lower[k])
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(keys, ";")

	canonicalRequest := strings.Join([]string{
		method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := dateStamp + "/" + creds.region + "/" + creds.service + "/aws4_request"
	stringToSign := strings.Join([]string{
		sigV4Algorithm,
		amzDate,
		scope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	signingKey := hmacChain([]byte("AWS4"+creds.secretKey), dateStamp, creds.region, creds.service, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	return sigV4Algorithm +
		" Credential=" + creds.accessKeyID + "/" + scope +
		", SignedHeaders=" + signedHeaders +
		", Signature=" + signature
}

// collapseSpaces trims leading and trailing whitespace and collapses every
// interior run of whitespace characters to a single ASCII space, as required by
// the AWS SigV4 canonical-header normalisation rules.
func collapseSpaces(s string) string {
	s = strings.TrimSpace(s)
	// Fast path: no run of two or more whitespace characters.
	prev := false
	for _, r := range s {
		isSpace := r == ' ' || r == '\t'
		if isSpace && prev {
			goto slow
		}
		prev = isSpace
	}
	return s
slow:
	var b strings.Builder
	b.Grow(len(s))
	inSpace := false
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if !inSpace {
				b.WriteByte(' ')
			}
			inSpace = true
		} else {
			b.WriteRune(r)
			inSpace = false
		}
	}
	return b.String()
}

func hexSHA256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func hmacChain(key []byte, parts ...string) []byte {
	for _, p := range parts {
		key = hmacSHA256(key, []byte(p))
	}
	return key
}
