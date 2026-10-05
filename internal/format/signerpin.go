package format

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/downpipes-io/downpipe/internal/crypto"
)

// The bundled signer public key and its fingerprint pin (SPEC.md 9.1).
//
// The signer public key is the trust anchor of a verified restore (SPEC.md 8.3). The printed
// recovery sheet carries only the signer FINGERPRINT, and a fingerprint cannot verify a signature.
// So the writer also puts signer.pub in the recovery bundle. The bucket is not a trust anchor:
// anyone with write access to it can replace that file. So a reader uses the bucket copy ONLY when
// the operator pins it with the fingerprint from the offline sheet. BundledSigner recomputes the
// fingerprint of the bucket copy in the sheet's own construction (crypto.SignerFingerprint, SPEC.md
// 11.4) and refuses the copy unless the two are equal. The anchor stays offline; the bucket only
// supplies the bytes that the anchor names.
//
// This lives here, not in the CLI, so the conformance corpus replays the same code the CLI runs
// (the bundled-signer-* vectors).

// BundleSignerName is the file name of the bundled signer public key under BundlePrefix.
const BundleSignerName = "signer.pub"

// SignerFingerprintPrefix is the scheme tag of a hybrid signer fingerprint (SPEC.md 11.4).
const SignerFingerprintPrefix = "edmldsa1:"

// SignerPublicLabel is the label of a signer.pub key file, in the kit and in the bundle alike.
const SignerPublicLabel = "downpipe-signer-public-v1"

// MaxBundledSignerBytes bounds the bundled signer.pub a reader will parse. The real file is one
// "downpipe-signer-public-v1 <base64url>" line over 32 + 2592 key bytes, about 3.5 KiB.
const MaxBundledSignerBytes = 16 << 10

// SignerKeyFile renders a verifier as a signer.pub file: one "<label> <base64url>" line and a LF.
func SignerKeyFile(v *crypto.HybridVerifier) []byte {
	return []byte(SignerPublicLabel + " " + base64.RawURLEncoding.EncodeToString(crypto.MarshalVerifier(v)) + "\n")
}

// ParseSignerFingerprint normalises a fingerprint copied from a recovery sheet. It accepts the
// value with surrounding whitespace and upper-case hex, because people copy it by hand. It refuses
// anything that is not the scheme tag and 96 hex digits (a SHA-384), so a truncated copy is a usage
// error here and not a confusing mismatch later.
func ParseSignerFingerprint(s string) (string, error) {
	v := strings.TrimSpace(s)
	if !strings.HasPrefix(strings.ToLower(v), SignerFingerprintPrefix) {
		return "", usagef("--signer-fingerprint %q is not a signer fingerprint: it must start with %s, as the signer line on your recovery sheet does", s, SignerFingerprintPrefix)
	}
	digest := strings.ToLower(v[len(SignerFingerprintPrefix):])
	raw, err := hex.DecodeString(digest)
	if err != nil || len(raw) != 48 {
		return "", usagef("--signer-fingerprint %q is not a complete signer fingerprint: after %s it must be 96 hexadecimal characters. Copy the whole signer line from your recovery sheet", s, SignerFingerprintPrefix)
	}
	return SignerFingerprintPrefix + digest, nil
}

// SameSignerFingerprint compares two normalised fingerprints. The values are public, so constant
// time is not needed for secrecy; it is used for the same reason the rest of the reader uses it on
// digests.
func SameSignerFingerprint(a, b string) bool {
	return crypto.ConstantTimeEqual([]byte(a), []byte(b))
}

// BundledSigner reads the signer public key from the recovery bundle and accepts it only if its
// fingerprint equals pin, a value ParseSignerFingerprint returned. Nothing about the bucket copy is
// trusted before that comparison: not the SHA384SUMS entry (its signature is by the key under
// test), and not the root manifest's signingKeyFingerprint (a hint the bucket also controls,
// SPEC.md 8.3).
//
// The copy is destination-wide: every run overwrites it with the signer of that run. So it names
// the CURRENT signer. After a signer rotation, a run sealed by the earlier signer cannot use it, and
// the refusal says so.
//
// Exit codes: 2 for a copy that fails the pin (a wrong-signer outcome), 6 for an absent copy, 11
// for a destination that could not be read. Any other read failure carries no code.
func BundledSigner(store ObjectStore, pin string) (*crypto.HybridVerifier, error) {
	key := BundlePrefix + BundleSignerName
	raw, err := store.Get(key)
	if err != nil {
		if bundledSignerAbsent(err) {
			return nil, usagef("the destination has no %s, so --signer-fingerprint has nothing to check. An engine writes this copy from engine 0.3.7, so a bucket that no such engine has written to has none. Pass --signer with signer.pub from your recovery kit", key)
		}
		// A destination that could not be read exits 11 (ExitUnreachable), not as a verdict on the
		// archive. The store's own error says which it was.
		read := fmt.Errorf("read the bundled signer public key %s: %w", key, err)
		var ue unreachableGetErr
		if errors.As(err, &ue) && ue.Unreachable() {
			return nil, &ExitError{Code: ExitUnreachable, Err: read}
		}
		return nil, read
	}
	// A signer.pub line is about 3.5 KiB. The store bounds every read already; this bound stops a
	// hostile bucket from handing the key-file parser an object far larger than any key file.
	if len(raw) > MaxBundledSignerBytes {
		return nil, bundledSignerRefused(key, fmt.Sprintf("it is %d bytes, larger than any signer public-key file", len(raw)))
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 2 || fields[0] != SignerPublicLabel {
		return nil, bundledSignerRefused(key, "it is not a "+SignerPublicLabel+" file")
	}
	payload, err := base64.RawURLEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, bundledSignerRefused(key, "it is not a "+SignerPublicLabel+" file")
	}
	verifier, err := crypto.ParseVerifier(payload)
	if err != nil {
		return nil, bundledSignerRefused(key, fmt.Sprintf("it does not parse as a signer public key (%v)", err))
	}
	if got := crypto.SignerFingerprint(verifier); !SameSignerFingerprint(got, pin) {
		return nil, bundledSignerRefused(key, fmt.Sprintf("its fingerprint is %s, and your recovery sheet pins %s", got, pin))
	}
	return verifier, nil
}

// bundledSignerRefused is the refusal for a bucket copy that fails the pin. It exits 2
// (ExitUnverified), the reader's wrong-signer code: the bucket offered a signer the operator did not
// pin. It names the two causes the reader cannot tell apart, and the route that still works. A later
// sheet is NOT offered as a general route: its pin matches the current copy, but a run sealed by the
// earlier signer then fails verification.
func bundledSignerRefused(key, why string) error {
	return &ExitError{Code: ExitUnverified, Err: fmt.Errorf("refusing the signer public key in %s: %s. Either the bucket copy was altered, or the signer was rotated after your sheet was printed. The bucket keeps only the current signer's copy. Nothing was read with it. Pass --signer with the signer.pub file that matches your sheet. A later sheet's fingerprint helps only for runs sealed after that rotation", key, why)}
}

// objectAbsent is the store capability that marks a 404 for the object itself (internal/source
// S3 and Azure stores). A 404 for the bucket or container does not carry it.
type objectAbsent interface{ ObjectAbsent() bool }

// bundledSignerAbsent reports whether a failed read of the bundled copy means the copy is not
// there. A directory store says so with fs.ErrNotExist. An S3 or Azure store says so with a 404
// that names the object. Any other failure, such as a 403 or a wrong bucket, stays an error of the
// destination and keeps its own exit code (11).
func bundledSignerAbsent(err error) bool {
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	var oa objectAbsent
	return errors.As(err, &oa) && oa.ObjectAbsent()
}

// usagef is a usage error (exit 6) with a formatted message.
func usagef(msg string, args ...any) error {
	return &ExitError{Code: ExitUsage, Err: fmt.Errorf(msg, args...)}
}
