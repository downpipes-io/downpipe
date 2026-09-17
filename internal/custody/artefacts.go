package custody

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"strings"
)

// The artefact file magics, byte-for-byte what the console writes as the first
// non-comment line of each download.
const (
	ShareFileMagic       = "downpipe-shamir-share-v1"
	EnvelopeFileMagic    = "downpipe-wrapped-identity-v1"
	WrappingKeyFileMagic = "downpipe-wrapping-key-v1"
)

// GCMIVBytes and GCMTagBytes pin the envelope's AES-256-GCM parameters: a 96-bit IV
// and the full 128-bit tag, which the console's WebCrypto appends to the ciphertext.
const (
	GCMIVBytes  = 12
	GCMTagBytes = 16
)

// ArtefactError is a malformed or mis-paired input file: a usage-class failure the
// caller maps to the usage exit code.
type ArtefactError struct{ Msg string }

func (e *ArtefactError) Error() string { return e.Msg }

// IntegrityError is a custody-integrity failure: the shares recombine to the wrong key
// (public checksum mismatch) or the authenticated decrypt refuses. Callers map it to
// the custody-integrity exit code, distinct from the archive-verdict codes.
type IntegrityError struct{ Msg string }

func (e *IntegrityError) Error() string { return e.Msg }

// DecodeB64 decodes a base64url body the way the console's decoder does: unpadded
// primary, strict alphabet (no +, / or embedded =), with well-formed trailing padding
// tolerated for hand-mangled input. The console's own encoder never emits padding.
func DecodeB64(s string) ([]byte, error) {
	if strings.ContainsAny(s, "+/ \t") {
		return nil, &ArtefactError{Msg: "not base64url: contains a character outside the url-safe alphabet"}
	}
	if i := strings.IndexByte(s, '='); i >= 0 {
		pad := s[i:]
		if pad != strings.Repeat("=", len(pad)) || len(pad) > 2 || len(s)%4 != 0 {
			return nil, &ArtefactError{Msg: "not base64url: malformed padding"}
		}
		s = s[:i]
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		// Go's base64 error carries the byte OFFSET at which decoding failed, which is a position
		// fingerprint of the rejected material. Drop it: a closed fault class, matching the console's
		// b64urlDecode, which never surfaces the offending character or its position.
		return nil, &ArtefactError{Msg: "not base64url: the material is not valid url-safe base64"}
	}
	return b, nil
}

// artefactLabels is the CLOSED set of label names each artefact kind legally carries.
// It exists so a duplicate label can be NAMED in an error without echoing file content:
// a label matched against this set is one of our own constants, not a string read out of
// the operator's file. Anything else is reported only as unrecognised.
var artefactLabels = map[string][]string{
	EnvelopeFileMagic:    {"iv", "ciphertext", "credential-id"},
	WrappingKeyFileMagic: {"key"},
	ShareFileMagic:       {"index", "n", "threshold", "checksum", "share"},
}

// knownLabel reports whether label is one of the artefact kind's own labels.
func knownLabel(magic, label string) bool {
	for _, l := range artefactLabels[magic] {
		if l == label {
			return true
		}
	}
	return false
}

// parseLabelledLines mirrors the console's artefact parser exactly: the first
// non-blank, non-comment line must equal magic; each later non-comment line is
// "label value" (the value is everything after the FIRST space, trimmed); duplicate
// labels are rejected; comment lines start with '#'; blank lines and free-text lines
// with no space (the KEEP OFFLINE banner) are ignored; every line is right-trimmed so
// CRLF files parse.
//
// NO-CUSTODY, and the reason these messages look sparse. This parser is fed a file the
// operator CHOSE, and the point of --wrapping-key, --share and --envelope is that the
// file they choose may be the wrong one. The wrong one is routinely a SECRET: a bare
// wrapping key is 43 base64url characters on one line, an emailed share body is one
// token, an identity.key is one label and a private key. A parser that quotes the input
// back to explain the failure quotes a key, onto a terminal, into scrollback, and from
// there into the support ticket the operator opens because recovery is not working.
//
// This used to quote the first 40 characters of the header line, which for a bare
// wrapping key is about 30 of its 32 bytes. A clamp is not a redaction. The message now
// names only the KIND of file expected (one of three constants) and the KIND of fault.
// The accept/reject boundary is unchanged: the same files parse and the same files are
// rejected, so the console and this reader stay pinned to each other.
func parseLabelledLines(text, magic string) (map[string]string, error) {
	out := map[string]string{}
	sawMagic := false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !sawMagic {
			// The header did not match. `line` is the first meaningful line of a file of
			// the WRONG KIND, which is exactly when it is most likely to be a bare key or
			// a bare share body. It is not echoed, clamped or hinted at.
			if line != magic {
				return nil, &ArtefactError{Msg: fmt.Sprintf("this is not a %s file", magic)}
			}
			sawMagic = true
			continue
		}
		sp := strings.IndexByte(line, ' ')
		if sp < 0 {
			continue
		}
		label := line[:sp]
		if _, dup := out[label]; dup {
			// A label is file content. It is named only when it is one of this artefact's
			// own labels, in which case the string in the message is our constant.
			if knownLabel(magic, label) {
				return nil, &ArtefactError{Msg: fmt.Sprintf("duplicate %q line in a %s file", label, magic)}
			}
			return nil, &ArtefactError{Msg: fmt.Sprintf("duplicate unrecognised label in a %s file", magic)}
		}
		out[label] = strings.TrimSpace(line[sp+1:])
	}
	if !sawMagic {
		return nil, &ArtefactError{Msg: fmt.Sprintf("missing the %s header", magic)}
	}
	return out, nil
}

// ShareFile is one custodian's parsed labelled share artefact.
type ShareFile struct {
	Index     int
	N         int
	Threshold int
	Checksum  []byte
	Share     []byte
}

// ParseShareFile parses a labelled downpipe-shamir-share-v1 artefact, enforcing the
// bounds the format defines (not the console UI's tighter operational caps): share
// exactly ShareBytes with a non-zero index equal to the header's index line,
// 2 <= threshold <= n <= 255, checksum exactly ChecksumBytes.
func ParseShareFile(text string) (*ShareFile, error) {
	fields, err := parseLabelledLines(text, ShareFileMagic)
	if err != nil {
		return nil, err
	}
	idx, err := intField(fields, "index")
	if err != nil {
		return nil, err
	}
	n, err := intField(fields, "n")
	if err != nil {
		return nil, err
	}
	threshold, err := intField(fields, "threshold")
	if err != nil {
		return nil, err
	}
	checksum, err := bytesField(fields, "checksum")
	if err != nil {
		return nil, err
	}
	share, err := bytesField(fields, "share")
	if err != nil {
		return nil, err
	}
	if len(checksum) != ChecksumBytes {
		return nil, &ArtefactError{Msg: fmt.Sprintf("checksum is %d bytes, want %d", len(checksum), ChecksumBytes)}
	}
	if len(share) != ShareBytes {
		return nil, &ArtefactError{Msg: fmt.Sprintf("share body is %d bytes, want %d", len(share), ShareBytes)}
	}
	if threshold < 2 || n < threshold || n > 255 {
		return nil, &ArtefactError{Msg: fmt.Sprintf("parameters out of range: need 2 <= threshold (%d) <= n (%d) <= 255", threshold, n)}
	}
	if idx < 1 || idx > 255 {
		return nil, &ArtefactError{Msg: fmt.Sprintf("index %d out of range 1..255", idx)}
	}
	if int(share[0]) != idx {
		return nil, &ArtefactError{Msg: fmt.Sprintf("the index line says %d but the share body carries index %d; the file is corrupt or mis-assembled", idx, share[0])}
	}
	return &ShareFile{Index: idx, N: n, Threshold: threshold, Checksum: checksum, Share: share}, nil
}

// ParseRawShare parses the EMAILED form of a share: a file holding exactly one
// non-blank, non-comment token, the bare base64url share body (33 bytes decoded). This
// is what a custodian possesses after the share email, which carries no labelled file,
// no checksum and no threshold.
func ParseRawShare(text string) ([]byte, error) {
	token := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if token != "" {
			return nil, &ArtefactError{Msg: "a raw share file must hold exactly one base64url token"}
		}
		token = line
	}
	if token == "" {
		return nil, &ArtefactError{Msg: "the file holds no share token"}
	}
	share, err := DecodeB64(token)
	if err != nil {
		return nil, err
	}
	if len(share) != ShareBytes {
		return nil, &ArtefactError{Msg: fmt.Sprintf("the decoded share is %d bytes, want %d", len(share), ShareBytes)}
	}
	if share[0] == 0 {
		return nil, &ArtefactError{Msg: "the share carries a zero index; indices are 1..255"}
	}
	return share, nil
}

// EnvelopeFile is the parsed downpipe-wrapped-identity-v1 artefact: the PUBLIC IV, the
// ciphertext with its GCM tag appended, and the optional PUBLIC credential id present
// only when the wrapping key derives from a security key rather than shares.
type EnvelopeFile struct {
	IV           []byte
	Ciphertext   []byte
	CredentialID []byte
}

// ParseEnvelopeFile parses the envelope artefact and enforces the GCM shapes: a 12-byte
// IV and a ciphertext at least one tag long.
func ParseEnvelopeFile(text string) (*EnvelopeFile, error) {
	fields, err := parseLabelledLines(text, EnvelopeFileMagic)
	if err != nil {
		return nil, err
	}
	iv, err := bytesField(fields, "iv")
	if err != nil {
		return nil, err
	}
	ct, err := bytesField(fields, "ciphertext")
	if err != nil {
		return nil, err
	}
	if len(iv) != GCMIVBytes {
		return nil, &ArtefactError{Msg: fmt.Sprintf("iv is %d bytes, want %d", len(iv), GCMIVBytes)}
	}
	if len(ct) < GCMTagBytes {
		return nil, &ArtefactError{Msg: fmt.Sprintf("ciphertext is %d bytes, shorter than the %d-byte tag", len(ct), GCMTagBytes)}
	}
	out := &EnvelopeFile{IV: iv, Ciphertext: ct}
	if cred, ok := fields["credential-id"]; ok {
		b, err := DecodeB64(cred)
		if err != nil {
			return nil, err
		}
		out.CredentialID = b
	}
	return out, nil
}

// ParseWrappingKeyFile parses the downpipe-wrapping-key-v1 artefact (Tier 1/2: the
// whole key stored offline instead of split).
func ParseWrappingKeyFile(text string) ([]byte, error) {
	fields, err := parseLabelledLines(text, WrappingKeyFileMagic)
	if err != nil {
		return nil, err
	}
	key, err := bytesField(fields, "key")
	if err != nil {
		return nil, err
	}
	if len(key) != SecretBytes {
		return nil, &ArtefactError{Msg: fmt.Sprintf("wrapping key is %d bytes, want %d", len(key), SecretBytes)}
	}
	return key, nil
}

// OpenEnvelope performs the authoritative decrypt: AES-256-GCM with the 12-byte IV,
// the tag appended to the ciphertext, and no additional data, exactly as the console
// seals it. A wrong key or any tampering refuses; nothing partial is ever returned.
func OpenEnvelope(env *EnvelopeFile, wrappingKey []byte) ([]byte, error) {
	if len(wrappingKey) != SecretBytes {
		return nil, &ArtefactError{Msg: fmt.Sprintf("wrapping key is %d bytes, want %d", len(wrappingKey), SecretBytes)}
	}
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, env.IV, env.Ciphertext, nil)
	if err != nil {
		return nil, &IntegrityError{Msg: "the envelope failed to decrypt: below the share threshold, a mis-transcribed share, shares from different ceremonies, or the wrong envelope file"}
	}
	return pt, nil
}

func intField(fields map[string]string, label string) (int, error) {
	raw, ok := fields[label]
	if !ok {
		return 0, &ArtefactError{Msg: fmt.Sprintf("missing the %q line", label)}
	}
	v := 0
	// The raw value is NEVER echoed: an operator who fed a wrapping key where an index was expected would
	// otherwise see the whole key in the error. `label` is a caller-supplied constant, so it is safe. This
	// matches the console's parseIntField, which suppresses the value for the same reason.
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, &ArtefactError{Msg: fmt.Sprintf("%q must be a non-negative integer", label)}
		}
		v = v*10 + int(c-'0')
		if v > 1<<20 {
			return 0, &ArtefactError{Msg: fmt.Sprintf("%q is out of range", label)}
		}
	}
	if raw == "" {
		return 0, &ArtefactError{Msg: fmt.Sprintf("%q must be a non-negative integer, got an empty value", label)}
	}
	return v, nil
}

func bytesField(fields map[string]string, label string) ([]byte, error) {
	raw, ok := fields[label]
	if !ok {
		return nil, &ArtefactError{Msg: fmt.Sprintf("missing the %q line", label)}
	}
	b, err := DecodeB64(raw)
	if err != nil {
		return nil, &ArtefactError{Msg: fmt.Sprintf("%q line: %v", label, err)}
	}
	return b, nil
}
