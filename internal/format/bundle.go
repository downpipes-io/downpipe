package format

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// BundlePrefix is the versioned recovery-bundle key prefix (SPEC.md 3, 9):
// _RECOVERY/downpipe/0.1.0/. The version string carries its own slash.
const BundlePrefix = "_RECOVERY/" + spec.Version + "/"

// The recovery bundle makes the destination self-sufficient: a verbatim copy of the
// specification, plain recovery instructions, and a SHA384SUMS over them, with a
// detached hybrid signature over SHA384SUMS so a recoverer who relies on the bundled
// spec can confirm it was not altered (SPEC.md 9, 8.7). A recoverer who brings an
// independently trusted spec and reader MAY skip the check.

// WriteBundle writes each named file under the bundle prefix, a SHA384SUMS over them in
// sorted order, and a base64url detached hybrid signature over the SHA384SUMS bytes.
func WriteBundle(put func(key string, data []byte) error, files map[string][]byte, signer *crypto.HybridSigner) error {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)

	var sums bytes.Buffer
	for _, n := range names {
		if err := put(BundlePrefix+n, files[n]); err != nil {
			return fmt.Errorf("write bundle file %s: %w", n, err)
		}
		fmt.Fprintf(&sums, "%s  %s\n", SHA384Hex(files[n]), n)
	}
	if err := put(BundlePrefix+"SHA384SUMS", sums.Bytes()); err != nil {
		return fmt.Errorf("write SHA384SUMS: %w", err)
	}
	sig, err := signer.Sign(sums.Bytes())
	if err != nil {
		return fmt.Errorf("sign SHA384SUMS: %w", err)
	}
	if err := put(BundlePrefix+"SHA384SUMS.sig", []byte(B64Encode(sig))); err != nil {
		return fmt.Errorf("write SHA384SUMS.sig: %w", err)
	}
	return nil
}

// VerifyBundle verifies the bundle's SHA384SUMS signature against the operator-pinned
// signer, then confirms every listed file's SHA-384 matches. A mismatch or a bad
// signature is a verification failure (the caller maps it to exit 2).
func VerifyBundle(get func(key string) ([]byte, error), verifier *crypto.HybridVerifier) error {
	sums, err := get(BundlePrefix + "SHA384SUMS")
	if err != nil {
		return fmt.Errorf("read SHA384SUMS: %w", err)
	}
	sigText, err := get(BundlePrefix + "SHA384SUMS.sig")
	if err != nil {
		return fmt.Errorf("read SHA384SUMS.sig: %w", err)
	}
	sig, err := B64Decode(strings.TrimSpace(string(sigText)))
	if err != nil {
		return fmt.Errorf("decode SHA384SUMS.sig: %w", err)
	}
	if err := verifier.Verify(sums, sig); err != nil {
		return fmt.Errorf("verify SHA384SUMS signature: %w", err)
	}
	for _, line := range strings.Split(string(sums), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		hash, name, ok := strings.Cut(line, "  ")
		if !ok {
			return fmt.Errorf("malformed SHA384SUMS line: %q", line)
		}
		// Defence in depth: the SHA384SUMS bytes are signature-verified above, so a
		// traversal name cannot enter without forging the signer, but pin the path
		// contract here so a malformed-but-signed line cannot read a sibling key.
		if name == "" || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
			return fmt.Errorf("bundle file name not a flat relative name: %q", name)
		}
		data, err := get(BundlePrefix + name)
		if err != nil {
			return fmt.Errorf("read bundle file %s: %w", name, err)
		}
		if !crypto.ConstantTimeEqual([]byte(SHA384Hex(data)), []byte(hash)) {
			return fmt.Errorf("bundle file %s does not match its signed SHA-384", name)
		}
	}
	return nil
}
