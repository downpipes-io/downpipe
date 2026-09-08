package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/custody"
	"github.com/downpipes-io/downpipe/internal/format"
)

// recombine rebuilds identity.key from the offline break-glass custody artefacts the
// console emits: the wrapped-identity envelope plus either M labelled share files, the
// bare base64url share bodies custodians receive by email (saved to files), or the
// whole wrapping-key file. Everything is local: no store flags, no network. Key
// material is never accepted on the command line (argv leaks into process listings and
// shell history) and never printed.

// maxArtefactBytes caps one artefact file read; a share file is under a kilobyte, so a
// mistakenly supplied huge file is refused rather than buffered.
const maxArtefactBytes = 1 << 20

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func cmdRecombine(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("recombine", flag.ContinueOnError)
	var shares stringList
	fs.Var(&shares, "share", "a share file (repeatable): the labelled downpipe-shamir-share-v1 download, or a file holding the bare emailed share body")
	wkPath := fs.String("wrapping-key", "", "the downpipe-wrapping-key-v1 file (instead of shares)")
	envPath := fs.String("envelope", "", "the downpipe-wrapped-identity-v1 file (the ciphertext the console offered for download)")
	outPath := fs.String("out", "identity.key", "where to write the recovered identity key (refuses to overwrite)")
	threshold := fs.Int("threshold", 0, "the ceremony's M (share threshold); only needed when every supplied share is the bare emailed form, which carries no threshold")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *envPath == "" {
		return usageErr("recombine needs --envelope (the wrapped-identity file) plus --share files or --wrapping-key")
	}
	if len(shares) == 0 && *wkPath == "" {
		return usageErr("recombine needs a key source: repeatable --share files, or --wrapping-key")
	}
	if len(shares) > 0 && *wkPath != "" {
		return usageErr("supply --share files or --wrapping-key, not both")
	}

	in, err := loadCustodyInputs(shares, *wkPath, *envPath, *threshold)
	if err != nil {
		return err
	}

	plaintext, notices, err := custody.Recombine(*in)
	printCustodyNotices(notices)
	if err != nil {
		return custodyErr("recombine", err)
	}
	defer custody.Wipe(plaintext)

	// Validate the plaintext is a usable identity-key file BEFORE writing: the right
	// label and a key that parses. This catches a wrong-artefact pairing that
	// nonetheless decrypted (possible only with a mismatched envelope for the same key).
	idBytes, err := parseKeyFileBytes(plaintext, labelIdentity)
	if err != nil {
		return &format.ExitError{Code: format.ExitCustody, Err: fmt.Errorf("the decrypted payload is not an identity-key file: %v", err)}
	}
	if _, err := crypto.ParseKEMPrivate(idBytes); err != nil {
		custody.Wipe(idBytes)
		return &format.ExitError{Code: format.ExitCustody, Err: fmt.Errorf("the decrypted payload does not parse as a break-glass identity key: %v", err)}
	}
	custody.Wipe(idBytes)

	f, err := os.OpenFile(*outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return usageErr(fmt.Sprintf("write %s (it may already exist): %v", *outPath, err))
	}
	if _, err := f.Write(plaintext); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", *outPath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", *outPath, err)
	}
	// --apply is in the printed line because this hint is read at the moment the operator is about
	// to restore, and restore plans without it. The same omission shipped in the archive-bundled
	// RECOVER.md and in both published walkthroughs, where following the printed line exited 0 and
	// wrote nothing.
	fmt.Fprintf(os.Stderr, "recovered the break-glass identity to %s\nnext: downpipe restore --apply --archive <bucket> --run <runId> --identity %s --signer <signer.pub> --out <dir>\n", *outPath, *outPath)
	return nil
}

// isLabelledShare reports whether the file's first meaningful line is the labelled
// share magic; anything else is treated as the raw emailed form and parsed as such.
func isLabelledShare(text string) bool {
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line == custody.ShareFileMagic
	}
	return false
}

// readArtefact reads one custody artefact file under the size cap.
func readArtefact(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", usageErr(fmt.Sprintf("read %s: %v", path, err))
	}
	if fi.Size() > maxArtefactBytes {
		return "", usageErr(fmt.Sprintf("read %s: %d bytes is far larger than any custody artefact; refusing", path, fi.Size()))
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", usageErr(fmt.Sprintf("read %s: %v", path, err))
	}
	return string(b), nil
}

// custodyErr maps the custody package's error classes to exit codes: a malformed
// artefact is usage (6), a well-formed set that fails its checksum or decrypt is the
// custody-integrity code (9). Error text never echoes share or key bytes.
func custodyErr(where string, err error) error {
	var integrity *custody.IntegrityError
	if errors.As(err, &integrity) {
		return &format.ExitError{Code: format.ExitCustody, Err: fmt.Errorf("%s: %v", where, err)}
	}
	return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("%s: %v", where, err)}
}

func usageErr(msg string) error {
	return &format.ExitError{Code: format.ExitUsage, Err: errors.New(msg)}
}

// parseKeyFileBytes is the bytes-level form of readKeyFile: the "<label> <base64url>"
// shape validated and decoded without touching the filesystem, so recombine can prove
// the decrypted payload is a usable key file before anything lands on disk.
func parseKeyFileBytes(content []byte, label string) ([]byte, error) {
	fields := strings.Fields(string(content))
	if len(fields) != 2 || fields[0] != label {
		return nil, fmt.Errorf("not a %s file", label)
	}
	return base64.RawURLEncoding.DecodeString(fields[1])
}

// loadCustodyInputs reads the share, wrapping-key and envelope files into custody.Inputs.
//
// It is shared by `recombine` and by the in-memory identity source, deliberately. The two differ only in
// what they do with the recovered plaintext (one writes it, one uses it and wipes it), so if the reading
// and parsing of the artefacts lived in both, a fix to share parsing could land in the path an operator
// is not using and be reported as working.
func loadCustodyInputs(shares stringList, wrappingKeyPath, envelopePath string, threshold int) (*custody.Inputs, error) {
	envText, err := readArtefact(envelopePath)
	if err != nil {
		return nil, err
	}
	env, err := custody.ParseEnvelopeFile(envText)
	if err != nil {
		return nil, custodyErr(envelopePath, err)
	}
	if env.CredentialID != nil {
		// A credential-id envelope derives its wrapping key from an enrolled security key via WebAuthn,
		// which needs a browser and the hardware. It is not recoverable offline at all, so say that here
		// rather than failing later inside the recombine with a decrypt error.
		return nil, usageErr("this envelope's wrapping key derives from a security key (it carries a credential-id); it is not recoverable offline from shares. Use the console's security-key flow, or the share or wrapping-key artefacts of a share-based ceremony")
	}
	if len(shares) > 0 && wrappingKeyPath != "" {
		return nil, usageErr("supply --share files or --wrapping-key, not both")
	}
	if len(shares) == 0 && wrappingKeyPath == "" {
		return nil, usageErr("recovering the identity needs a key source: repeatable --share files, or --wrapping-key")
	}

	in := &custody.Inputs{Envelope: env, ThresholdHint: threshold}
	for _, p := range shares {
		text, rerr := readArtefact(p)
		if rerr != nil {
			return nil, rerr
		}
		if isLabelledShare(text) {
			sf, perr := custody.ParseShareFile(text)
			if perr != nil {
				return nil, custodyErr(p, perr)
			}
			in.Labelled = append(in.Labelled, sf)
			continue
		}
		raw, perr := custody.ParseRawShare(text)
		if perr != nil {
			return nil, custodyErr(p, perr)
		}
		in.Raw = append(in.Raw, raw)
	}
	if wrappingKeyPath != "" {
		text, rerr := readArtefact(wrappingKeyPath)
		if rerr != nil {
			return nil, rerr
		}
		wk, perr := custody.ParseWrappingKeyFile(text)
		if perr != nil {
			return nil, custodyErr(wrappingKeyPath, perr)
		}
		in.WrappingKey = wk
	}
	return in, nil
}

// printCustodyNotices reports the recombine's own notices (a dropped duplicate share, a threshold
// inferred from the labelled set). They go to stderr so a command writing data to stdout stays clean.
func printCustodyNotices(notices []string) {
	for _, n := range notices {
		fmt.Fprintln(os.Stderr, "note: "+n)
	}
}
