package main

import (
	"flag"
	"fmt"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/custody"
	"github.com/downpipes-io/downpipe/internal/format"
)

// Where a command gets the break-glass identity from.
//
// Split custody is an internal-controls arrangement: an organisation that wants M-of-N sign-off before
// anyone can read an archive holds the identity as Shamir shares rather than as one file. Supporting it
// used to mean a detour. `recombine` reassembled the shares and WROTE the reconstructed private key to
// identity.key, and every command that needed a key took a path to one, so the operator's only route was
// to materialise the break-glass key as a plaintext file, use it, and remember to destroy it. The tool
// even printed the next command with --identity identity.key in it, so the natural reading was to leave
// it there.
//
// That is a poor trade for a control meant to raise the bar. It converts an M-of-N arrangement into a
// single file on one operator's disk for as long as they forget about it, and on a copy-on-write or
// journalled filesystem the bytes outlive the unlink. The whole point of holding the key in shares is
// that a complete key should not exist anywhere except for the moment it is being used.
//
// So the artefacts are accepted DIRECTLY wherever an identity is accepted. The shares are combined in
// memory, the identity is parsed from the plaintext, and both are wiped before the command does its
// work. Nothing reaches the disk, and no step depends on the operator remembering to clean up.
//
// --identity is unchanged and is still the right answer for a single-file custody arrangement. This adds
// a second source, it does not replace the first.

// identityFlags holds the identity-source flags shared by every command that needs to decrypt. Commands
// register it once rather than declaring --share/--envelope themselves, so a new command cannot
// accidentally support only half of the sources and leave split-custody operators back on the disk path.
type identityFlags struct {
	path        string
	shares      stringList
	wrappingKey string
	envelope    string
	threshold   int
}

// addIdentityFlags registers --identity plus the custody artefact flags on fs. identityHelp describes
// what the command needs the key FOR, which differs enough between reading a run and planning a prune to
// be worth saying at the flag.
func addIdentityFlags(fs *flag.FlagSet, identityHelp string) *identityFlags {
	f := &identityFlags{}
	fs.StringVar(&f.path, "identity", "", identityHelp)
	fs.Var(&f.shares, "share", "a custody share file (repeatable): use M of them instead of --identity to combine the key in memory for this command only, never writing it to disk")
	fs.StringVar(&f.wrappingKey, "wrapping-key", "", "the downpipe-wrapping-key-v1 file, used with --envelope instead of --share")
	fs.StringVar(&f.envelope, "envelope", "", "the downpipe-wrapped-identity-v1 file, required when recovering the key from --share or --wrapping-key")
	fs.IntVar(&f.threshold, "threshold", 0, "the ceremony's M, needed only when every supplied share is the bare emailed form, which carries no threshold")
	return f
}

// supplied reports whether any identity source was given at all, so a command can produce its own
// "needs an identity" usage message rather than this package guessing at the command's other requirements.
func (f *identityFlags) supplied() bool {
	return f.path != "" || f.envelope != "" || len(f.shares) > 0 || f.wrappingKey != ""
}

// fromCustody reports whether the custody artefacts, rather than a key file, are the source.
func (f *identityFlags) fromCustody() bool {
	return len(f.shares) > 0 || f.wrappingKey != ""
}

// resolve produces the identity. The returned key is parsed; every intermediate buffer holding key
// material is wiped before returning, on the success path and on every failure path after the bytes
// exist. Go cannot guarantee erasure (a copying collector may have moved the backing array), which is
// why internal/crypto documents its own wipes as best effort, and the same caveat applies here: this
// removes the routine, long-lived copy, not every trace a determined memory forensic could find.
func (f *identityFlags) resolve() (*crypto.HybridKEMPrivate, error) {
	switch {
	case !f.supplied():
		return nil, usageErr("no identity source: pass --identity <file>, or --envelope with repeatable --share files (or --wrapping-key)")
	case f.path != "" && f.fromCustody():
		// Refused rather than picking one. An operator who passes both has a belief about which key is
		// being used, and a silent precedence rule would be right only half the time.
		return nil, usageErr("supply either --identity or the custody artefacts (--share/--wrapping-key with --envelope), not both")
	case f.path != "":
		idBytes, err := readKeyFile(f.path, labelIdentity)
		if err != nil {
			return nil, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("identity: %w", err)}
		}
		defer custody.Wipe(idBytes)
		identity, err := crypto.ParseKEMPrivate(idBytes)
		if err != nil {
			return nil, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("identity: %w", err)}
		}
		return identity, nil
	case f.envelope == "":
		return nil, usageErr("recovering the identity from shares needs --envelope (the wrapped-identity file the console offered for download)")
	}

	in, err := loadCustodyInputs(f.shares, f.wrappingKey, f.envelope, f.threshold)
	if err != nil {
		return nil, err
	}
	plaintext, notices, err := custody.Recombine(*in)
	printCustodyNotices(notices)
	if err != nil {
		return nil, custodyErr("recombine", err)
	}
	defer custody.Wipe(plaintext)

	idBytes, err := parseKeyFileBytes(plaintext, labelIdentity)
	if err != nil {
		return nil, &format.ExitError{Code: format.ExitCustody, Err: fmt.Errorf("the recovered payload is not an identity-key file: %v", err)}
	}
	defer custody.Wipe(idBytes)
	identity, err := crypto.ParseKEMPrivate(idBytes)
	if err != nil {
		return nil, &format.ExitError{Code: format.ExitCustody, Err: fmt.Errorf("the recovered payload does not parse as a break-glass identity key: %v", err)}
	}
	return identity, nil
}

// loadAndVerifier resolves the identity and the operator signer together, which is what every reading
// command needs. It exists so the identity is never resolved without the verifier that bounds what the
// resulting key is allowed to trust.
func (f *identityFlags) loadAndVerifier(signerPath string) (*crypto.HybridKEMPrivate, *crypto.HybridVerifier, error) {
	identity, err := f.resolve()
	if err != nil {
		return nil, nil, err
	}
	signerBytes, err := readKeyFile(signerPath, labelSignerPublic)
	if err != nil {
		return nil, nil, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("signer: %w", err)}
	}
	verifier, err := crypto.ParseVerifier(signerBytes)
	if err != nil {
		return nil, nil, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("signer: %w", err)}
	}
	return identity, verifier, nil
}
