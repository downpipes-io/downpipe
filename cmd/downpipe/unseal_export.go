package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
)

// unseal-export opens a SEALED control-plane export offline, using the break-glass identity and signer.pub
// from the recovery kit, and writes the recovered plaintext export JSON. It is the offline bridge that keeps
// identity.key out of the browser: after a total account loss the operator seals-nothing and unseals HERE, then
// pastes the recovered plaintext export into the console estate-import form. It uses the SAME crypto the reader
// uses for archives (OpenCapsule / OpenStreamTo), so a sealed export and an archive share one trust surface.
//
// The sealed artefact and its two domain-separated AADs are authored by the engine
// (src/admin/control-plane-seal.ts); this command MUST byte-match those AADs and that JSON shape, which the
// cross-impl conformance test (unseal_export_test.go) pins against an engine-produced fixture.

// The AADs. These MUST equal the engine's EXPORT_CAPSULE_AAD / EXPORT_BODY_AAD byte-for-byte; the conformance
// test fails if they drift.
var (
	exportCapsuleAAD = []byte("downpipes/control-plane-export/capsule/v1")
	exportBodyAAD    = []byte("downpipes/control-plane-export/body/v1")
)

// sealedCapsuleWrap mirrors the engine's SealedCapsuleWrapJSON (a recipient's KEM-DEM wrap of the content key).
type sealedCapsuleWrap struct {
	Fingerprint   string `json:"fingerprint"`
	KEMCiphertext string `json:"kemCiphertext"`
	Sealed        string `json:"sealed"`
}

// sealedRecipientDesc mirrors the engine's SealedRecipientDesc (a recipient's role + fingerprint; public).
type sealedRecipientDesc struct {
	Role        string `json:"role"`
	Fingerprint string `json:"fingerprint"`
}

// sealedControlPlaneExport mirrors the engine's SealedControlPlaneExport: a small plaintext header, the capsule
// (the content key sealed to each recipient), and the sealed body.
type sealedControlPlaneExport struct {
	V               int                   `json:"v"`
	ExportedAt      string                `json:"exportedAt"`
	ConfigVersion   int64                 `json:"configVersion"`
	EngineAccountID *string               `json:"engineAccountId"`
	Recipients      []sealedRecipientDesc `json:"recipients"`
	Capsule         []sealedCapsuleWrap   `json:"capsule"`
	Body            string                `json:"body"`
}

func cmdUnsealExport(args []string) error {
	fs := flag.NewFlagSet("unseal-export", flag.ContinueOnError)
	inPath := fs.String("in", "", "the sealed control-plane export file (…-.sealed.json)")
	sigPath := fs.String("sig", "", "the detached signature file (…-.sealed.json.sig)")
	idf := addIdentityFlags(fs, "your recovery-kit break-glass identity.key")
	signerPath := fs.String("signer", "", "your recovery-kit signer.pub")
	outPath := fs.String("out", "", "where to write the recovered plaintext export JSON (default: stdout)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *inPath == "" || *sigPath == "" || !idf.supplied() || *signerPath == "" {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("unseal-export needs --in, --sig, --signer and an identity source (--identity, or --envelope with --share)")}
	}

	// A file named by a required flag that cannot be read is a USAGE error (6), the code every
	// other command in this tool gives for the same shape: recombine's --envelope and --share,
	// setup's --config, and --identity and --signer everywhere through readKeyFile. These two
	// returned the read error uncoded, so run() gave them 1, "an I/O or unexpected failure this
	// tool did not otherwise classify", and a mistyped path on the one command an operator
	// reaches for after a total account loss read as something having gone wrong inside the tool.
	sealedBytes, err := os.ReadFile(*inPath)
	if err != nil {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("reading the sealed export named by --in: %w", err)}
	}
	sigText, err := os.ReadFile(*sigPath)
	if err != nil {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("reading the signature named by --sig: %w", err)}
	}
	sig, err := format.B64Decode(strings.TrimSpace(string(sigText)))
	if err != nil {
		return &format.ExitError{Code: format.ExitUnverified, Err: fmt.Errorf("the signature is not valid base64url: %w", err)}
	}

	// 1. VERIFY the detached signature over the RAW sealed bytes (verify precedes decrypt), mirroring
	//    VerifyRootBytes for archives -- the file bytes are the exact canonical bytes the engine signed.
	signerBytes, err := readKeyFile(*signerPath, labelSignerPublic)
	if err != nil {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("signer: %w", err)}
	}
	verifier, err := crypto.ParseVerifier(signerBytes)
	if err != nil {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("signer: %w", err)}
	}
	if verr := format.VerifyRootBytes(sealedBytes, sig, verifier); verr != nil {
		return &format.ExitError{Code: format.ExitUnverified, Err: fmt.Errorf("the sealed export signature did not verify against signer.pub (wrong key, or the export was modified): %w", verr)}
	}

	// 2. Parse the (now-verified) sealed artefact and open the capsule with the held identity.
	var sealed sealedControlPlaneExport
	if jerr := json.Unmarshal(sealedBytes, &sealed); jerr != nil {
		return fmt.Errorf("the sealed export is not valid JSON: %w", jerr)
	}
	if sealed.V != 1 || len(sealed.Capsule) == 0 || sealed.Body == "" {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("the file is not a v1 sealed control-plane export")}
	}
	// The identity comes from the shared resolver, so a split-custody holder can unseal from a quorum
	// without first writing the reconstructed key to disk. This command needs that more than any other:
	// it is the total-account-loss bridge, and an organisation that split its break-glass key precisely
	// to survive a disaster is the operator most likely to be standing here.
	priv, err := idf.resolve()
	if err != nil {
		return err
	}
	wraps := make([]crypto.WrappedKey, 0, len(sealed.Capsule))
	for _, w := range sealed.Capsule {
		ct, e1 := format.B64Decode(w.KEMCiphertext)
		s, e2 := format.B64Decode(w.Sealed)
		if e1 != nil || e2 != nil {
			return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("a capsule wrap is malformed base64url")}
		}
		wraps = append(wraps, crypto.WrappedKey{Fingerprint: w.Fingerprint, KEMCiphertext: ct, Sealed: s})
	}
	wanted := make([]crypto.RecipientDesc, 0, len(sealed.Recipients))
	for _, r := range sealed.Recipients {
		wanted = append(wanted, crypto.RecipientDesc{Role: r.Role, Fingerprint: r.Fingerprint})
	}
	contentKey, err := crypto.OpenCapsule(wraps, priv, exportCapsuleAAD, wanted)
	if err != nil {
		return &format.ExitError{Code: format.ExitUnverified, Err: fmt.Errorf("no recipient wrap matches your identity, or the capsule is corrupt: %w", err)}
	}

	// 3. Decrypt the body with the recovered content key. The whole sealed object was already authenticated by
	//    the signature above, so an unbounded read is safe (the input is trusted at this point).
	body, err := format.B64Decode(sealed.Body)
	if err != nil {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("the sealed body is not valid base64url: %w", err)}
	}
	var inner bytes.Buffer
	if oerr := crypto.OpenStreamTo(&inner, contentKey, bytes.NewReader(body), exportBodyAAD, 0); oerr != nil {
		return &format.ExitError{Code: format.ExitUnverified, Err: fmt.Errorf("the sealed export body failed to decrypt: %w", oerr)}
	}

	// 4. Write the recovered plaintext export.
	if *outPath == "" {
		_, err = os.Stdout.Write(inner.Bytes())
		return err
	}
	if werr := os.WriteFile(*outPath, inner.Bytes(), 0o600); werr != nil {
		return fmt.Errorf("writing the recovered export: %w", werr)
	}
	fmt.Fprintf(os.Stderr, "recovered the plaintext control-plane export to %s (%d bytes)\n", *outPath, inner.Len())
	return nil
}
