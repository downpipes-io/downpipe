package source

import (
	"regexp"
	"strings"
	"testing"
)

// Known-answer vectors for the Azure Shared Key signer.
//
// THESE GRADE THE STRING TO SIGN, CHARACTER FOR CHARACTER, not merely that a signature came out. Two
// signers that differ by one empty line both produce a plausible base64 signature and a 403 that names
// nothing, so a test asserting only "a signature was produced" would pass on a signer that cannot
// authenticate a single request, and the first person to find out would be somebody mid-recovery.
//
// The first two vectors are Microsoft's own published worked examples. Their expected strings are
// INLINE here as this repository's own fixtures rather than read from another repository at test time:
// a fixture that resolves somewhere else is a fixture that can go stale without this repository's own
// run noticing. They are the same two the writing engine's signer is graded against, so the reader and
// the writer are held to one published answer rather than to each other.
//
// The remaining vectors pin the rules this implementation is most likely to get wrong, each of which
// fails in a way that reads like a permission problem:
//
//	the eleven standard fields are POSITIONAL, so an absent header is an empty LINE and not an omitted one
// a zero Content-Length signs as EMPTY, never as "0" (the rule)
//	the x-ms-* lines are lower-cased, whitespace-collapsed and ORDINAL-sorted

// testCreds is a syntactically valid base64 key that is NOT a credential. The string-to-sign vectors
// do not depend on the key at all (they grade the canonical string), and the signature vectors below
// need it only to decode.
func testCreds(t *testing.T) azureSharedKeyCreds {
	t.Helper()
	creds, err := newAzureSharedKeyCreds("myaccount", "ZmFrZS1rZXktZm9yLXN0cmluZy10by1zaWduLW9ubHk=")
	if err != nil {
		t.Fatalf("newAzureSharedKeyCreds: %v", err)
	}
	return creds
}

// msDate is the timestamp Microsoft's published examples use, so the expected strings below can be
// transcribed verbatim.
const msDate = "Fri, 26 Jun 2015 23:39:12 GMT"

// TestAzureStandardFieldsAreEleven pins the count on its own. The VERB is followed by exactly eleven
// lines, and a twelfth or a tenth would move every canonical string this file grades while leaving
// each individual assertion below looking locally sensible.
func TestAzureStandardFieldsAreEleven(t *testing.T) {
	if got := len(azureStandardFields); got != 11 {
		t.Fatalf("azureStandardFields holds %d slots, want 11: the string to sign is the verb plus exactly eleven positional lines", got)
	}
}

// TestAzureSharedKeyMicrosoftWorkedExamples grades the signer against Microsoft's two published
// worked examples, character for character.
func TestAzureSharedKeyMicrosoftWorkedExamples(t *testing.T) {
	creds := testCreds(t)
	cases := []struct {
		name string
		req  azureSignRequest
		want string
	}{
		{
			name: "GET container metadata with three query parameters",
			req: azureSignRequest{
				Method:  "GET",
				Path:    "/mycontainer",
				Query:   map[string]string{"restype": "container", "comp": "metadata", "timeout": "20"},
				Headers: map[string]string{"x-ms-date": msDate, "x-ms-version": "2015-02-21"},
			},
			want: "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:Fri, 26 Jun 2015 23:39:12 GMT\nx-ms-version:2015-02-21\n/myaccount/mycontainer\ncomp:metadata\nrestype:container\ntimeout:20",
		},
		{
			// A comma-joined multi-value parameter is ONE line, unsplit. A signer that split it
			// on the comma would produce a string differing only in line count.
			name: "list blobs with a multi-value include parameter",
			req: azureSignRequest{
				Method:  "GET",
				Path:    "/mycontainer",
				Query:   map[string]string{"restype": "container", "comp": "list", "include": "metadata,snapshots,uncommittedblobs"},
				Headers: map[string]string{"x-ms-date": msDate, "x-ms-version": "2015-02-21"},
			},
			want: "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:Fri, 26 Jun 2015 23:39:12 GMT\nx-ms-version:2015-02-21\n/myaccount/mycontainer\ncomp:list\ninclude:metadata,snapshots,uncommittedblobs\nrestype:container",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := signAzureSharedKey(tc.req, creds)
			if got != tc.want {
				t.Fatalf("string to sign does not match Microsoft's published example\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}

// TestAzureSharedKeyStandardFieldsArePositional pins the trap that fails like a permission error: an
// absent header is an empty LINE, and a present one lands in its own slot rather than anywhere else.
func TestAzureSharedKeyStandardFieldsArePositional(t *testing.T) {
	creds := testCreds(t)

	bare, _ := signAzureSharedKey(azureSignRequest{
		Method:  "HEAD",
		Path:    "/c/blob",
		Headers: map[string]string{"x-ms-date": msDate, "x-ms-version": azureAPIVersion},
	}, creds)
	head := strings.Split(bare, "\n")[:12]
	if head[0] != "HEAD" {
		t.Fatalf("line 0 is %q, want the verb HEAD", head[0])
	}
	for i, line := range head[1:] {
		if line != "" {
			t.Fatalf("standard slot %d is %q, want empty: no such header was supplied, and an absent header is an empty line", i, line)
		}
	}

	// The other direction: a header that IS present must land in its own slot.
	//
	// A `Date` header is supplied here DELIBERATELY, and its slot must stay empty anyway. Without a
	// fixture that supplies one, "the Date slot is empty" is satisfied by any implementation at all,
	// because nothing would have put anything there: the assertion would be vacuous. It is not a
	// hypothetical, either. x-ms-date already carries the timestamp, and signing both binds the
	// request to two instants; any skew between them is a 403 AuthenticationFailed that names
	// nothing, which is the same undiagnosable failure every other rule in this file guards.
	withType, _ := signAzureSharedKey(azureSignRequest{
		Method:        "PUT",
		Path:          "/c/blob",
		Headers:       map[string]string{"content-type": "application/octet-stream", "Date": "Sat, 27 Jun 2015 00:00:00 GMT", "x-ms-date": msDate, "x-ms-version": azureAPIVersion},
		ContentLength: 7,
	}, creds)
	lines := strings.Split(withType, "\n")
	slots := []struct {
		index int
		want  string
		what  string
	}{
		{3, "7", "Content-Length"},
		{5, "application/octet-stream", "Content-Type, two lines below Content-MD5"},
		{6, "", "the Date slot, which stays empty because x-ms-date carries the timestamp, even though this request supplied a Date header"},
	}
	for _, s := range slots {
		if lines[s.index] != s.want {
			t.Errorf("slot %d (%s) is %q, want %q; first seven lines: %q", s.index, s.what, lines[s.index], s.want, lines[:7])
		}
	}
}

// TestAzureSharedKeyZeroContentLengthSignsEmpty pins the rule. A signer that writes "0"
// authenticates every body-bearing request and fails every GET, HEAD and LIST, which is every request
// this reader makes.
func TestAzureSharedKeyZeroContentLengthSignsEmpty(t *testing.T) {
	creds := testCreds(t)
	headers := map[string]string{"x-ms-date": msDate, "x-ms-version": azureAPIVersion}

	explicitZero, _ := signAzureSharedKey(azureSignRequest{Method: "GET", Path: "/c/blob", Headers: headers, ContentLength: 0}, creds)
	if got := strings.Split(explicitZero, "\n")[3]; got != "" {
		t.Fatalf("an explicit zero Content-Length signed as %q, want the empty string", got)
	}
	omitted, _ := signAzureSharedKey(azureSignRequest{Method: "GET", Path: "/c/blob", Headers: headers}, creds)
	if omitted != explicitZero {
		t.Fatalf("an omitted ContentLength must be byte-identical to an explicit zero\n omitted: %q\nexplicit: %q", omitted, explicitZero)
	}
	// THE POSITIVE CONTROL. Without it, the assertions above would pass on a signer that dropped
	// the Content-Length field entirely, which is the other way to break the same slot.
	seven, _ := signAzureSharedKey(azureSignRequest{Method: "PUT", Path: "/c/blob", Headers: headers, ContentLength: 7}, creds)
	if got := strings.Split(seven, "\n")[3]; got != "7" {
		t.Fatalf("CONTROL: a non-zero Content-Length signed as %q, want %q", got, "7")
	}
}

// TestAzureSharedKeyCanonicalHeaders pins the x-ms-* half: lower-cased, whitespace-collapsed and
// ordinal-sorted, with non-x-ms headers excluded.
func TestAzureSharedKeyCanonicalHeaders(t *testing.T) {
	creds := testCreds(t)
	signed, _ := signAzureSharedKey(azureSignRequest{
		Method: "PUT",
		Path:   "/c/blob",
		Headers: map[string]string{
			"X-MS-Meta-Zebra": "z",
			"x-ms-blob-type":  "BlockBlob",
			"X-Ms-Date":       msDate,
			"x-ms-version":    azureAPIVersion,
			// A value with a run of interior whitespace and untrimmed ends, which Azure's rule
			// collapses to single spaces.
			"x-ms-meta-note": "  two   words  ",
			// A non-x-ms header, which must be signed in its positional slot and must NOT appear
			// among the x-ms lines.
			"content-type": "text/plain",
		},
	}, creds)

	canon := strings.Split(signed, "\n")[12:]
	// Ordinal by the lower-cased name: blob-type < date < meta-note < meta-zebra < version.
	// Written out in full rather than computed with a sort, because computing the expected order
	// the same way the implementation does would assert only that the code agrees with itself.
	want := []string{
		"x-ms-blob-type:BlockBlob",
		"x-ms-date:" + msDate,
		"x-ms-meta-note:two words",
		"x-ms-meta-zebra:z",
		"x-ms-version:" + azureAPIVersion,
		"/myaccount/c/blob",
	}
	if len(canon) != len(want) {
		t.Fatalf("canonical tail has %d lines, want %d: %q", len(canon), len(want), canon)
	}
	for i := range want {
		if canon[i] != want[i] {
			t.Errorf("canonical line %d is %q, want %q", i, canon[i], want[i])
		}
	}
	for _, line := range canon {
		if strings.HasPrefix(line, "content-type") {
			t.Errorf("content-type appears among the x-ms lines as %q; it belongs in its positional slot only", line)
		}
	}
	if got := strings.Split(signed, "\n")[5]; got != "text/plain" {
		t.Errorf("CONTROL: content-type is %q in its positional slot, want %q, so its absence above is an exclusion and not a dropped header", got, "text/plain")
	}
}

// TestAzureSharedKeyCanonicalResource pins the resource half, including the empty-value parameter
// that still contributes its line.
func TestAzureSharedKeyCanonicalResource(t *testing.T) {
	cases := []struct {
		name    string
		account string
		path    string
		query   map[string]string
		want    string
	}{
		{
			name:    "no query is the bare account-rooted path",
			account: "myaccount",
			path:    "/c/blob",
			want:    "/myaccount/c/blob",
		},
		{
			name:    "a path with no leading slash is rooted anyway",
			account: "myaccount",
			path:    "c/blob",
			want:    "/myaccount/c/blob",
		},
		{
			name:    "parameters are lower-cased by name and sorted",
			account: "myaccount",
			path:    "/c",
			query:   map[string]string{"Restype": "container", "comp": "list"},
			want:    "/myaccount/c\ncomp:list\nrestype:container",
		},
		{
			// A parameter with an empty value still contributes its line, for the same positional
			// reason the standard fields do.
			name:    "an empty value still contributes its line",
			account: "myaccount",
			path:    "/c",
			query:   map[string]string{"comp": "list", "prefix": ""},
			want:    "/myaccount/c\ncomp:list\nprefix:",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := azureCanonicalResource(tc.account, tc.path, tc.query); got != tc.want {
				t.Fatalf("azureCanonicalResource = %q, want %q", got, tc.want)
			}
		})
	}
}

// authorizationShape is the SharedKey header form: the scheme, the account, then standard base64.
var authorizationShape = regexp.MustCompile(`^SharedKey myaccount:[A-Za-z0-9+/]+=*$`)

// TestAzureSharedKeyAuthorizationHeader pins the header's shape and, through two controls, that the
// signature is genuinely a function of the request and of the key. Without the controls, a signer
// that ignored its inputs and returned a constant would satisfy every assertion above.
func TestAzureSharedKeyAuthorizationHeader(t *testing.T) {
	creds := testCreds(t)
	_, auth := signAzureSharedKey(azureSignRequest{Method: "GET", Path: "/c/blob", Headers: map[string]string{"x-ms-date": msDate}}, creds)
	if !authorizationShape.MatchString(auth) {
		t.Fatalf("Authorization is %q, want SharedKey <account>:<base64>", auth)
	}

	_, other := signAzureSharedKey(azureSignRequest{Method: "PUT", Path: "/c/blob", Headers: map[string]string{"x-ms-date": msDate}}, creds)
	if other == auth {
		t.Error("CONTROL: a different request signed identically, so the signature is not a function of the request")
	}

	otherKey, err := newAzureSharedKeyCreds("myaccount", "YW5vdGhlci1mYWtlLWtleS12YWx1ZS1oZXJlLW9r")
	if err != nil {
		t.Fatalf("newAzureSharedKeyCreds: %v", err)
	}
	_, underOtherKey := signAzureSharedKey(azureSignRequest{Method: "GET", Path: "/c/blob", Headers: map[string]string{"x-ms-date": msDate}}, otherKey)
	if underOtherKey == auth {
		t.Error("CONTROL: a different account key signed identically, so the key is not keying the HMAC")
	}
}

// TestAzureSharedKeyCredsRefuseBadKeys pins the two construction refusals. Both exist because the
// failure they prevent is a 403 AuthenticationFailed on every call, which reads as a permissions
// problem on the container rather than as a malformed credential.
func TestAzureSharedKeyCredsRefuseBadKeys(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		wantErr error
	}{
		{"not base64 at all", "this is not base64!!", ErrAzureKeyNotBase64},
		{"base64url rather than standard", "a-b_c-d_e-f_g-h_", ErrAzureKeyNotBase64},
		{"empty", "", ErrAzureKeyEmpty},
		{"whitespace only", "   ", ErrAzureKeyEmpty},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newAzureSharedKeyCreds("myaccount", tc.key)
			if err == nil {
				t.Fatalf("newAzureSharedKeyCreds(%q) returned no error, want %v", tc.key, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr.Error()) {
				t.Fatalf("newAzureSharedKeyCreds(%q) error is %v, want it to carry %v", tc.key, err, tc.wantErr)
			}
		})
	}
	// CONTROL: the key every other vector uses must still be accepted, or the table above would
	// pass on a constructor that refused everything.
	if _, err := newAzureSharedKeyCreds("myaccount", "ZmFrZS1rZXktZm9yLXN0cmluZy10by1zaWduLW9ubHk="); err != nil {
		t.Fatalf("CONTROL: a well-formed key was refused: %v", err)
	}
}

// TestAzureSharedKeySignatureIsKnownAnswer pins the SIGNATURE BYTES, which nothing else here does.
//
// Every other assertion about the Authorization header is relational or structural:
// TestAzureSharedKeyAuthorizationHeader checks a shape regex, that a different request signs
// differently, and that a different key signs differently, and a consistently corrupted input
// satisfies all three. TestAzureSharedKeyMicrosoftWorkedExamples takes
// "got, _ :=" and grades the string to sign alone, discarding the authorization it is handed.
//
// So the canonicalisation is graded character for character and the HMAC over it is graded only for
// varying. What that combination misses is a signer that is well shaped, request dependent, key
// dependent and wrong, which reaches an operator as 403 AuthenticationFailed on every call. On an
// Azure-only estate that is the break-glass path, so it fails at the moment it is needed and reads
// as a container permissions problem rather than as a signing fault.
//
// THE EXPECTED VALUE WAS COMPUTED INDEPENDENTLY, by a separate HMAC-SHA256 implementation over the same
// key and the string to sign that Microsoft publishes for this request, NOT by calling signAzureSharedKey
// and recording what it returned. A value taken from the code under test pins the current behaviour
// including its bugs, which is a ratchet rather than an oracle.
func TestAzureSharedKeySignatureIsKnownAnswer(t *testing.T) {
	creds := testCreds(t)
	req := azureSignRequest{
		Method:  "GET",
		Path:    "/mycontainer",
		Query:   map[string]string{"restype": "container", "comp": "metadata", "timeout": "20"},
		Headers: map[string]string{"x-ms-date": msDate, "x-ms-version": "2015-02-21"},
	}
	const wantSignature = "Eyq+9Glv4SxYroGFuBfjFYRVuvcbVQXTxuc+kvQZMdg="
	const wantAuthorization = "SharedKey myaccount:" + wantSignature

	sts, auth := signAzureSharedKey(req, creds)
	if auth != wantAuthorization {
		t.Fatalf("Authorization does not match the independently computed HMAC\n got: %q\nwant: %q\nstring to sign was %q", auth, wantAuthorization, sts)
	}
}
