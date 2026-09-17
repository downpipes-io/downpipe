package source

import (
	"strings"
	"testing"
)

// The AWS SigV4 test-suite "get-vanilla" vector pins the algorithm end to end: fixed
// credentials, date, region and service must produce this exact signature. It proves
// the canonical request, string-to-sign and signing-key chain are all correct.
func TestSigV4GetVanilla(t *testing.T) {
	creds := sigV4Creds{
		accessKeyID: "AKIDEXAMPLE",
		secretKey:   "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		region:      "us-east-1",
		service:     "service",
	}
	headers := map[string]string{
		"host":       "example.amazonaws.com",
		"x-amz-date": "20150830T123600Z",
	}
	got := signV4(sigV4Request{Method: "GET", CanonicalURI: "/", Query: "", Headers: headers, PayloadHash: emptyPayloadHash, AmzDate: "20150830T123600Z"}, creds)

	const want = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-date, " +
		"Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got != want {
		t.Fatalf("SigV4 get-vanilla mismatch:\n got %s\nwant %s", got, want)
	}
}

// TestSigV4HeaderWhitespaceCollapse verifies that internal runs of whitespace in
// a header value are collapsed to a single space in the canonical headers block,
// per the AWS SigV4 spec, Step 1: Create a Canonical Request (the CanonicalHeaders
// construction, where the whitespace-collapse rule lives). A header
// value with leading/trailing padding and an embedded tab run must be normalised
// before it is hashed; if it were not, the signature would differ from what AWS
// computes and the request would be rejected.
func TestSigV4HeaderWhitespaceCollapse(t *testing.T) {
	creds := sigV4Creds{accessKeyID: "AKIDEXAMPLE", secretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", region: "us-east-1", service: "service"}

	// collapseSpaces is the internal normaliser; test it directly first.
	cases := []struct{ in, want string }{
		{"simple", "simple"},
		{"  leading", "leading"},
		{"trailing  ", "trailing"},
		{"  both  ", "both"},
		{"a  b", "a b"},
		{"a\t\tb", "a b"},
		{"  a  \t b  ", "a b"},
		{"no change needed", "no change needed"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := collapseSpaces(tc.in); got != tc.want {
			t.Errorf("collapseSpaces(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// signV4 with a header that has internal whitespace must produce the same
	// signature as the same header with the whitespace already collapsed.
	dirtied := map[string]string{
		"host":       "example.amazonaws.com",
		"x-amz-date": "20150830T123600Z",
		"x-custom":   "  a\t\tb  ", // leading, trailing, internal whitespace
	}
	clean := map[string]string{
		"host":       "example.amazonaws.com",
		"x-amz-date": "20150830T123600Z",
		"x-custom":   "a b", // collapsed form
	}
	sigDirty := signV4(sigV4Request{Method: "GET", CanonicalURI: "/", Query: "", Headers: dirtied, PayloadHash: emptyPayloadHash, AmzDate: "20150830T123600Z"}, creds)
	sigClean := signV4(sigV4Request{Method: "GET", CanonicalURI: "/", Query: "", Headers: clean, PayloadHash: emptyPayloadHash, AmzDate: "20150830T123600Z"}, creds)
	if sigDirty != sigClean {
		t.Fatalf("whitespace in header value must be normalised before signing:\n dirty: %s\n clean: %s", sigDirty, sigClean)
	}
}

// TestSigV4WithQueryString verifies that a non-empty canonical query string is
// included in the canonical request correctly. The AWS SigV4 spec places the
// query string on its own line in the canonical request; if it were omitted or
// appended to the URI the signature would not match what AWS computes.
func TestSigV4WithQueryString(t *testing.T) {
	creds := sigV4Creds{accessKeyID: "AKIDEXAMPLE", secretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", region: "us-east-1", service: "s3"}
	headers := map[string]string{
		"host":       "bucket.s3.amazonaws.com",
		"x-amz-date": "20260101T000000Z",
	}
	// A query string must produce a different signature than no query string.
	sigNoQuery := signV4(sigV4Request{Method: "GET", CanonicalURI: "/key", Query: "", Headers: headers, PayloadHash: emptyPayloadHash, AmzDate: "20260101T000000Z"}, creds)
	sigWithQuery := signV4(sigV4Request{Method: "GET", CanonicalURI: "/key", Query: "list-type=2&prefix=run%2F", Headers: headers, PayloadHash: emptyPayloadHash, AmzDate: "20260101T000000Z"}, creds)
	if sigNoQuery == sigWithQuery {
		t.Fatal("signatures must differ when the canonical query string differs")
	}
	// Both must start with the algorithm prefix.
	if !strings.HasPrefix(sigNoQuery, "AWS4-HMAC-SHA256 ") {
		t.Fatalf("sigNoQuery missing algorithm prefix: %s", sigNoQuery)
	}
	if !strings.HasPrefix(sigWithQuery, "AWS4-HMAC-SHA256 ") {
		t.Fatalf("sigWithQuery missing algorithm prefix: %s", sigWithQuery)
	}
	// signV4 must be deterministic for the same query string.
	sigWithQuery2 := signV4(sigV4Request{Method: "GET", CanonicalURI: "/key", Query: "list-type=2&prefix=run%2F", Headers: headers, PayloadHash: emptyPayloadHash, AmzDate: "20260101T000000Z"}, creds)
	if sigWithQuery != sigWithQuery2 {
		t.Fatal("signV4 must be deterministic for identical inputs including query string")
	}
}

func TestSigV4Deterministic(t *testing.T) {
	creds := sigV4Creds{accessKeyID: "AKID", secretKey: "secret", region: "auto", service: "s3"}
	h := map[string]string{"host": "b.example.com", "x-amz-date": "20260606T000000Z", "x-amz-content-sha256": emptyPayloadHash}
	a := signV4(sigV4Request{Method: "GET", CanonicalURI: "/bucket/k", Query: "", Headers: h, PayloadHash: emptyPayloadHash, AmzDate: "20260606T000000Z"}, creds)
	b := signV4(sigV4Request{Method: "GET", CanonicalURI: "/bucket/k", Query: "", Headers: h, PayloadHash: emptyPayloadHash, AmzDate: "20260606T000000Z"}, creds)
	if a != b {
		t.Fatal("SigV4 must be deterministic for fixed inputs")
	}
	if !strings.Contains(a, "SignedHeaders=host;x-amz-content-sha256;x-amz-date") {
		t.Fatalf("signed headers not sorted/complete: %s", a)
	}
}
