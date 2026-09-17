package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/downpipes-io/downpipe/internal/crypto"
)

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", ".", "directory to write the key files into")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	priv, pub, err := crypto.GenerateHybridKEM()
	if err != nil {
		return fmt.Errorf("generate recipient identity: %w", err)
	}
	signer, verifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		return fmt.Errorf("generate signer: %w", err)
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	files := []struct {
		name, label string
		raw         []byte
	}{
		{"identity.key", labelIdentity, crypto.MarshalKEMPrivate(priv)},
		{"recipient.pub", labelRecipient, crypto.MarshalKEMPublic(pub)},
		{"signer.pub", labelSignerPublic, crypto.MarshalVerifier(verifier)},
		{"signer.key", labelSignerPrivate, crypto.MarshalSigner(signer)},
	}
	// Write the full set or none of it: if a later write fails (disk full, permissions)
	// remove the files already written so the directory is left clean and a re-run is
	// safe. writeKeyFile uses O_EXCL, so a leftover partial set would otherwise block a
	// re-run with a "file exists" error.
	written := make([]string, 0, len(files))
	for _, f := range files {
		path := filepath.Join(*out, f.name)
		if err := writeKeyFile(path, f.label, f.raw); err != nil {
			for _, w := range written {
				_ = os.Remove(w)
			}
			return err
		}
		written = append(written, path)
	}
	fmt.Printf("wrote identity.key, recipient.pub, signer.pub and signer.key to %s\n", *out)
	fmt.Println("identity.key and signer.key are private key files. Never print them and never copy")
	fmt.Println("them onto the recovery sheet, which carries fingerprints only. Keep this directory")
	fmt.Println("offline on media you control, and keep a second copy in another location.")
	fmt.Println("recipient.pub and signer.pub go to the writer, and signer.key signs runs and stays")
	fmt.Println("with the writer. Keep your own copy of signer.pub here too: restore needs")
	fmt.Println("identity.key and signer.pub together and exits without --signer, so identity.key on")
	fmt.Println("its own will not recover an archive.")
	fmt.Printf("Run 'downpipe keys --fingerprint --identity %s --recipient %s --signer %s'\n",
		filepath.Join(*out, "identity.key"), filepath.Join(*out, "recipient.pub"), filepath.Join(*out, "signer.pub"))
	fmt.Println("to print the fingerprints your recovery sheet should record.")
	return nil
}
