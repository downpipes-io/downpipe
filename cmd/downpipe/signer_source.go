package main

import (
	"flag"
	"fmt"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
)

// Where verify and restore get the operator signer they verify against.
//
// The signer public key is the trust anchor of a verified restore (SPEC.md 8.3). Until the bundled
// copy existed, the only source was --signer <file>: signer.pub from the recovery kit. The printed
// recovery sheet carries only the signer FINGERPRINT, and a fingerprint cannot verify a signature.
// So a recoverer holding the bucket, the break-glass key and the sheet could not start a restore.
//
// The writer now also puts signer.pub in the recovery bundle (SPEC.md 9.1). The bucket copy is used
// ONLY when the operator pins it with --signer-fingerprint, the value printed on the offline sheet.
// format.BundledSigner does the pin, so the conformance corpus replays the same code this runs.
//
// --signer is unchanged. When both flags are given, the kit file is checked against the pin, so an
// operator who holds both gets a cross-check rather than a silent precedence rule.

// bundleSignerName is the file name of the bundled signer public key under format.BundlePrefix.
const bundleSignerName = format.BundleSignerName

// signerFingerprintPrefix is the scheme tag of a hybrid signer fingerprint (SPEC.md 11.4).
const signerFingerprintPrefix = format.SignerFingerprintPrefix

// signerFlags holds the two ways verify and restore can be given the operator signer.
type signerFlags struct {
	path        string
	fingerprint string
}

// addSignerFlags registers --signer and --signer-fingerprint on fs.
func addSignerFlags(fs *flag.FlagSet) *signerFlags {
	f := &signerFlags{}
	fs.StringVar(&f.path, "signer", "", "operator signer public-key file (signer.pub from your recovery kit)")
	fs.StringVar(&f.fingerprint, "signer-fingerprint", "", "the signer fingerprint (edmldsa1:...) from your printed recovery sheet: use the signer.pub copy in the archive's recovery bundle, but only if its fingerprint equals this value")
	return f
}

// supplied reports whether any signer source was given.
func (f *signerFlags) supplied() bool {
	return f.path != "" || f.fingerprint != ""
}

// resolve returns the verifier this command pins. store is the archive source; it is read only
// when --signer-fingerprint is given without --signer.
func (f *signerFlags) resolve(store format.ObjectStore) (*crypto.HybridVerifier, error) {
	pin := ""
	if f.fingerprint != "" {
		p, err := format.ParseSignerFingerprint(f.fingerprint)
		if err != nil {
			return nil, err
		}
		pin = p
	}
	if f.path != "" {
		verifier, err := loadSignerFile(f.path)
		if err != nil {
			return nil, err
		}
		if pin != "" {
			if got := crypto.SignerFingerprint(verifier); !format.SameSignerFingerprint(got, pin) {
				return nil, usageErr(fmt.Sprintf("the --signer file %s has fingerprint %s, which is not the --signer-fingerprint you gave (%s). One of the two is from a different key ceremony. Check which signer your recovery sheet names", f.path, got, pin))
			}
		}
		return verifier, nil
	}
	if pin == "" {
		return nil, usageErr("no signer: pass --signer <file>, or --signer-fingerprint <fingerprint from your recovery sheet>")
	}
	return format.BundledSigner(store, pin)
}

// loadSignerFile reads and parses a signer.pub file named by --signer.
func loadSignerFile(path string) (*crypto.HybridVerifier, error) {
	signerBytes, err := readKeyFile(path, labelSignerPublic)
	if err != nil {
		return nil, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("signer: %w", err)}
	}
	verifier, err := crypto.ParseVerifier(signerBytes)
	if err != nil {
		return nil, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("signer: %w", err)}
	}
	return verifier, nil
}

// loadWithSigner resolves the signer first and then the identity. The signer comes first so a
// refused bucket copy stops the command before any private key material is read or recombined.
func (f *identityFlags) loadWithSigner(sig *signerFlags, store format.ObjectStore) (*crypto.HybridKEMPrivate, *crypto.HybridVerifier, error) {
	verifier, err := sig.resolve(store)
	if err != nil {
		return nil, nil, err
	}
	identity, err := f.resolve()
	if err != nil {
		return nil, nil, err
	}
	return identity, verifier, nil
}
