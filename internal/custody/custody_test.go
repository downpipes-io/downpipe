package custody

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

// testSplit is a test-only Shamir split mirroring the console's: per secret byte an
// independent degree-(threshold-1) polynomial with the secret as the constant term,
// evaluated at indices 1..n. It exists so Combine is proven against genuine splits at
// several geometries, not just the committed fixtures.
func testSplit(t *testing.T, secret []byte, n, threshold int) [][]byte {
	t.Helper()
	shares := make([][]byte, n)
	for i := range shares {
		shares[i] = make([]byte, ShareBytes)
		shares[i][0] = byte(i + 1)
	}
	coeffs := make([]byte, threshold)
	for b := 0; b < SecretBytes; b++ {
		coeffs[0] = secret[b]
		if _, err := rand.Read(coeffs[1:]); err != nil {
			t.Fatal(err)
		}
		for i := range shares {
			x := shares[i][0]
			var acc byte
			for c := len(coeffs) - 1; c >= 0; c-- {
				acc = gfMul(acc, x) ^ coeffs[c]
			}
			shares[i][1+b] = acc
		}
	}
	return shares
}

func TestCombineRecoversAcrossGeometries(t *testing.T) {
	secret := make([]byte, SecretBytes)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ n, threshold int }{{2, 2}, {4, 3}, {16, 5}, {255, 2}} {
		shares := testSplit(t, secret, tc.n, tc.threshold)
		// Any threshold-sized subset recovers; use the LAST threshold shares so the
		// subset is never just the first indices.
		got, err := Combine(shares[tc.n-tc.threshold:])
		if err != nil {
			t.Fatalf("%d-of-%d: %v", tc.threshold, tc.n, err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("%d-of-%d did not recover the secret", tc.threshold, tc.n)
		}
		// Below the threshold the result is WRONG (never an error): the checksum is
		// what reports it.
		if tc.threshold > 2 {
			wrong, err := Combine(shares[:tc.threshold-1])
			if err != nil {
				t.Fatalf("below-threshold combine errored: %v", err)
			}
			if bytes.Equal(wrong, secret) {
				t.Fatal("below-threshold combine must not recover the secret")
			}
			if VerifyChecksum(wrong, mustChecksum(t, secret)) {
				t.Fatal("the checksum must reject a below-threshold combine")
			}
		}
	}
}

func mustChecksum(t *testing.T, key []byte) []byte {
	t.Helper()
	c, err := Checksum(key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCombineRefusesStructuralDefects(t *testing.T) {
	secret := make([]byte, SecretBytes)
	shares := testSplit(t, secret, 3, 2)
	if _, err := Combine(shares[:1]); err == nil {
		t.Fatal("one share must be refused")
	}
	short := append([]byte(nil), shares[0][:ShareBytes-1]...)
	if _, err := Combine([][]byte{short, shares[1]}); err == nil {
		t.Fatal("a short share must be refused")
	}
	zero := append([]byte(nil), shares[0]...)
	zero[0] = 0
	if _, err := Combine([][]byte{zero, shares[1]}); err == nil {
		t.Fatal("a zero index must be refused")
	}
	dup := append([]byte(nil), shares[0]...)
	dup[5] ^= 0x01
	if _, err := Combine([][]byte{shares[0], dup}); err == nil {
		t.Fatal("same index with different bodies must be refused")
	}
}

func TestParseShareFileSemantics(t *testing.T) {
	share := make([]byte, ShareBytes)
	share[0] = 2
	checksum := []byte{1, 2, 3, 4}
	text := "# a leading comment before the magic is legal\n\n" +
		ShareFileMagic + "\r\n" +
		"# Custodian 2 of 4.\n" +
		"a free-text-banner-line-with-no-space\n" +
		"index 2\n" +
		"n 4\n" +
		"threshold 3\n" +
		"checksum " + encodeB64(checksum) + "\n" +
		"share " + encodeB64(share) + "  \n"
	sf, err := ParseShareFile(text)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sf.Index != 2 || sf.N != 4 || sf.Threshold != 3 || !bytes.Equal(sf.Share, share) {
		t.Fatalf("fields wrong: %+v", sf)
	}

	for name, mutate := range map[string]func(string) string{
		"wrong magic":       func(s string) string { return strings.Replace(s, ShareFileMagic, WrappingKeyFileMagic, 1) },
		"duplicate label":   func(s string) string { return s + "index 2\n" },
		"index mismatch":    func(s string) string { return strings.Replace(s, "index 2", "index 3", 1) },
		"threshold too low": func(s string) string { return strings.Replace(s, "threshold 3", "threshold 1", 1) },
		"n below threshold": func(s string) string { return strings.Replace(s, "n 4", "n 2", 1) },
		"non-numeric":       func(s string) string { return strings.Replace(s, "n 4", "n four", 1) },
	} {
		if _, err := ParseShareFile(mutate(text)); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
}

func TestDecodeB64Rules(t *testing.T) {
	// The console never emits padding, but a hand-mangled artefact may carry it; a
	// well-formed pad to a 4-char boundary is tolerated (1 or 2 '=' at the end).
	for _, ok := range []string{"AA==", "AAA=", "AAAA"} {
		if _, err := DecodeB64(ok); err != nil {
			t.Fatalf("%q is well formed and must be accepted: %v", ok, err)
		}
	}
	// Padding in the middle, the standard (non-url) alphabet, whitespace, and a pad
	// that does not land on a 4-char boundary are all refused.
	for _, bad := range []string{"AA=B", "A+AA", "A/AA", "AA A", "AAAAA=", "AA="} {
		if _, err := DecodeB64(bad); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
}

func TestOpenEnvelopeRefusesTamperAndWrongKey(t *testing.T) {
	// Round trip through the real cipher: seal locally, then break each input.
	key := make([]byte, SecretBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	env := sealTestEnvelope(t, key, []byte("downpipe-identity-v1 payload\n"))
	if _, err := OpenEnvelope(env, key); err != nil {
		t.Fatalf("clean open: %v", err)
	}
	tampered := &EnvelopeFile{IV: env.IV, Ciphertext: append([]byte(nil), env.Ciphertext...)}
	tampered.Ciphertext[0] ^= 0x01
	if _, err := OpenEnvelope(tampered, key); err == nil {
		t.Fatal("a tampered ciphertext must refuse")
	}
	wrong := make([]byte, SecretBytes)
	if _, err := OpenEnvelope(env, wrong); err == nil {
		t.Fatal("a wrong key must refuse")
	}
}

// The artefact parsers must refuse a wrong-length or wrong-kind payload rather than
// hand a short key or IV to the cipher. These are the branches the CLI conformance
// tests reach only indirectly.
func TestArtefactParsersRefuseBadPayloads(t *testing.T) {
	// A wrapping-key file whose key is the wrong length.
	short := WrappingKeyFileMagic + "\nkey " + encodeB64(make([]byte, 8)) + "\n"
	if _, err := ParseWrappingKeyFile(short); err == nil {
		t.Fatal("a short wrapping key must be refused")
	}
	if _, err := ParseWrappingKeyFile(WrappingKeyFileMagic + "\n"); err == nil {
		t.Fatal("a wrapping-key file with no key line must be refused")
	}

	// An envelope with a wrong-length IV, and one whose ciphertext is shorter than the tag.
	badIV := EnvelopeFileMagic + "\niv " + encodeB64(make([]byte, 5)) +
		"\nciphertext " + encodeB64(make([]byte, 32)) + "\n"
	if _, err := ParseEnvelopeFile(badIV); err == nil {
		t.Fatal("a wrong-length IV must be refused")
	}
	shortCT := EnvelopeFileMagic + "\niv " + encodeB64(make([]byte, GCMIVBytes)) +
		"\nciphertext " + encodeB64(make([]byte, 4)) + "\n"
	if _, err := ParseEnvelopeFile(shortCT); err == nil {
		t.Fatal("a ciphertext shorter than the tag must be refused")
	}
	if _, err := ParseEnvelopeFile(EnvelopeFileMagic + "\niv " + encodeB64(make([]byte, GCMIVBytes)) + "\n"); err == nil {
		t.Fatal("an envelope with no ciphertext line must be refused")
	}

	// A credential-id envelope parses, carrying the PUBLIC handle through.
	withCred := EnvelopeFileMagic + "\niv " + encodeB64(make([]byte, GCMIVBytes)) +
		"\nciphertext " + encodeB64(make([]byte, 32)) +
		"\ncredential-id " + encodeB64([]byte{1, 2, 3}) + "\n"
	env, err := ParseEnvelopeFile(withCred)
	if err != nil {
		t.Fatalf("a credential-id envelope must parse: %v", err)
	}
	if len(env.CredentialID) != 3 {
		t.Fatal("the credential id must be carried through")
	}
}

func TestParseRawShareRules(t *testing.T) {
	good := make([]byte, ShareBytes)
	good[0] = 7
	if _, err := ParseRawShare("# a comment\n\n" + encodeB64(good) + "\n"); err != nil {
		t.Fatalf("a bare emailed share must parse: %v", err)
	}
	for name, text := range map[string]string{
		"empty":         "\n\n",
		"two tokens":    encodeB64(good) + "\n" + encodeB64(good) + "\n",
		"wrong length":  encodeB64(make([]byte, 8)) + "\n",
		"zero index":    encodeB64(make([]byte, ShareBytes)) + "\n",
		"not base64url": "not+valid/base64\n",
	} {
		if _, err := ParseRawShare(text); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
}

// Recombine's own guards: no envelope, no shares, and shares mixed with a wrapping key.
func TestRecombineInputGuards(t *testing.T) {
	if _, _, err := Recombine(Inputs{}); err == nil {
		t.Fatal("a missing envelope must be refused")
	}
	env := &EnvelopeFile{IV: make([]byte, GCMIVBytes), Ciphertext: make([]byte, 32)}
	if _, _, err := Recombine(Inputs{Envelope: env}); err == nil {
		t.Fatal("no key source must be refused")
	}
	share := make([]byte, ShareBytes)
	share[0] = 1
	if _, _, err := Recombine(Inputs{Envelope: env, Raw: [][]byte{share}, WrappingKey: make([]byte, SecretBytes)}); err == nil {
		t.Fatal("shares plus a wrapping key must be refused")
	}
}

func TestChecksumRefusesAWrongLengthKey(t *testing.T) {
	if _, err := Checksum(make([]byte, 8)); err == nil {
		t.Fatal("a wrong-length key must be refused")
	}
	if VerifyChecksum(make([]byte, 8), []byte{0, 0, 0, 0}) {
		t.Fatal("a wrong-length key must not verify")
	}
	if VerifyChecksum(make([]byte, SecretBytes), []byte{0, 0}) {
		t.Fatal("a wrong-length checksum must not verify")
	}
}

// TestParseErrorsNeverEchoTheRejectedFile is the standing guard on the one leak these
// parsers can commit. Every one of them is fed a file the OPERATOR chose, so the file
// each rejects is, by definition, the file they got wrong, and the file they got wrong
// is routinely a secret: a bare wrapping key is one line of 43 base64url characters, an
// emailed share body is one token, an identity.key is a label and a private key. A
// parser that quotes the rejected input back to explain itself quotes a key, onto a
// terminal, into scrollback, and from there into the support ticket the operator opens
// because recovery is not working.
//
// This test feeds each parser the WRONG SECRET FILE and asserts the error carries no
// fragment of it. A CLAMP DOES NOT PASS, which is the point: the header error used to
// quote the first 40 characters of the offending line, and 40 characters of a
// 43-character wrapping key is about 30 of its 32 bytes. Bounding the length of a leak
// is not redacting it.
func TestParseErrorsNeverEchoTheRejectedFile(t *testing.T) {
	key := make([]byte, SecretBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	share := make([]byte, ShareBytes)
	if _, err := rand.Read(share); err != nil {
		t.Fatalf("rand: %v", err)
	}
	share[0] = 1
	identity := "SENTINEL_BREAKGLASS_PRIVATE_IDENTITY_B64_never_echoed"

	keyB64, shareB64 := encodeB64(key), encodeB64(share)
	secrets := []string{keyB64, shareB64, identity}

	// The wrong-file-for-the-flag cases an operator actually hits, each one a SECRET.
	bareKey := keyB64 + "\n"                                  // the emailed or transcribed key: no magic at all
	bareShare := shareB64 + "\n"                              // what an emailed custodian holds: the bare body
	identityFile := "downpipe-identity-v1 " + identity + "\n" // the plaintext key file itself

	// A WELL-FORMED-ENOUGH share file whose numeric field carries a secret. This reaches intField, the
	// sibling site the first no-echo pass missed: an operator who pasted a wrapping key where the index
	// belongs would otherwise get the whole key back. And a share file whose base64 body is mangled reaches
	// DecodeB64, whose Go error carries a byte offset (a position fingerprint of the secret).
	shareKeyAsIndex := ShareFileMagic + "\nindex " + keyB64 + "\nn 3\nthreshold 2\nchecksum " + encodeB64(make([]byte, ChecksumBytes)) + "\nshare " + shareB64 + "\n"
	shareBadBody := ShareFileMagic + "\nindex 1\nn 3\nthreshold 2\nchecksum " + encodeB64(make([]byte, ChecksumBytes)) + "\nshare " + keyB64 + "!!bad\n"

	cases := map[string]func() error{
		"ParseWrappingKeyFile fed a bare wrapping key": func() error { _, err := ParseWrappingKeyFile(bareKey); return err },
		"ParseWrappingKeyFile fed a bare share body":   func() error { _, err := ParseWrappingKeyFile(bareShare); return err },
		"ParseWrappingKeyFile fed an identity.key":     func() error { _, err := ParseWrappingKeyFile(identityFile); return err },
		"ParseShareFile fed a bare wrapping key":       func() error { _, err := ParseShareFile(bareKey); return err },
		"ParseShareFile fed an identity.key":           func() error { _, err := ParseShareFile(identityFile); return err },
		"ParseShareFile with a secret in the index":    func() error { _, err := ParseShareFile(shareKeyAsIndex); return err },
		"ParseShareFile with a mangled base64 body":    func() error { _, err := ParseShareFile(shareBadBody); return err },
		"ParseEnvelopeFile fed a bare wrapping key":    func() error { _, err := ParseEnvelopeFile(bareKey); return err },
		"ParseEnvelopeFile fed an identity.key":        func() error { _, err := ParseEnvelopeFile(identityFile); return err },
	}

	for name, run := range cases {
		err := run()
		if err == nil {
			t.Fatalf("%s: must be refused", name)
		}
		msg := err.Error()
		// Any fragment is a leak, so hunt substrings rather than equality. Eight
		// characters of base64url is six bytes of key: far past defensible.
		for _, secret := range secrets {
			for n := len(secret); n >= 8; n-- {
				if strings.Contains(msg, secret[:n]) {
					t.Fatalf("%s: error echoed %d characters of the rejected file: %q", name, n, msg)
				}
			}
		}
	}
}
