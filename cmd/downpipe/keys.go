package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// cmdKeys groups an archive's runs by the recipient identities that can open them,
// answering "which offline key opens which runs / date range" across key rotations.
// It is a diagnostic over the public signed root manifests and the RUNLOG and
// needs no identity: the recipient fingerprints and roles are recorded in the clear in
// each signed root, so an operator holding several rotated keys can build the index of
// which key opens which window without unwrapping anything. A signer is optional, as in
// attest: with --signer the RUNLOG and every run's root are cryptographically verified
// before they feed the index; without one a bucket-write adversary could plant a forged
// recipient mapping, so the keyless index is printed labelled UNVERIFIED rather than
// presented as authenticated.
//
// --fingerprint is the second mode, and it touches no archive at all. The printed recovery
// sheet records the break-glass, operational and signer FINGERPRINTS, never the key files
// themselves (a signer public key is about 3.5 KB of base64, so it is not a thing anyone
// retypes off paper). The console tells a recovering operator to check the files in their
// recovery kit against those printed fingerprints, and until this mode existed there was no
// command that could do it: the tool could consume a key file but never say which key it was.
// So an operator with two identity.key files from two ceremonies, or unsure whether the
// signer.pub they found is the one that signed this archive, had no way to tell before
// running the real command and reading a decryption failure.
func cmdKeys(args []string) error {
	fs := flag.NewFlagSet("keys", flag.ContinueOnError)
	sf := addStoreFlags(fs)
	which := fs.Bool("which", false, "group runs by the recipient identity that opens them")
	fingerprint := fs.Bool("fingerprint", false, "print the fingerprint of the key files you hold, to check them against the fingerprints on your printed recovery sheet (reads no archive)")
	idf := addIdentityFlags(fs, "the break-glass identity file (identity.key) to fingerprint, with --fingerprint")
	recipientPath := fs.String("recipient", "", "a recipient public-key file (recipient.pub) to fingerprint, with --fingerprint")
	signerPath := fs.String("signer", "", "operator signer public-key file (optional; without it the key index is unverified)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *which && *fingerprint {
		return usageErr("keys takes --which or --fingerprint, not both: --which reads an archive, --fingerprint reads only the key files you hold")
	}
	if *fingerprint {
		return reportKeyFingerprints(idf, *recipientPath, *signerPath)
	}
	if !*which {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("keys needs --which and a source (--archive or --s3-endpoint), or --fingerprint with the key files you hold")}
	}
	if idf.supplied() || *recipientPath != "" {
		return usageErr("keys --which reads only the archive's public manifests, so it takes no identity or recipient key. Use --fingerprint to check those files against your recovery sheet")
	}
	store, err := sf.resolve()
	if err != nil {
		return err
	}
	// The signer is optional, mirroring attest: with --signer the RUNLOG and each run's
	// root are cryptographically verified before they feed the index; without one the
	// index is built from whatever the bucket currently holds.
	var verifier *crypto.HybridVerifier
	if *signerPath != "" {
		signerBytes, rerr := readKeyFile(*signerPath, labelSignerPublic)
		if rerr != nil {
			return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("signer: %w", rerr)}
		}
		verifier, err = crypto.ParseVerifier(signerBytes)
		if err != nil {
			return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("signer: %w", err)}
		}
	}
	return reportKeysWhich(store, verifier)
}

// sheetFingerprint is one line of the --fingerprint report: the recovery sheet's own name for
// this kind of key, and the fingerprint computed from the file the operator actually holds.
type sheetFingerprint struct {
	label string
	value string
}

// reportKeyFingerprints prints the fingerprint of each key file supplied, in the form the printed
// recovery sheet records them. It reads no archive, opens no network connection and needs no run
// id, so it works with nothing but the files in the recovery kit and the sheet in the operator's
// hand. That is the whole point: it is the one check a recovering operator can make before they
// know anything else is intact.
//
// The identity arrives through the shared identity source, so a split-custody holder can
// fingerprint the key their shares rebuild without ever writing a complete key to disk.
//
// NO KEY MATERIAL IS PRINTED. A private identity is fingerprinted through its public half
// (crypto.PublicOf), and a fingerprint is a SHA-384 of public key bytes. There is no path here
// from a private key to stdout.
func reportKeyFingerprints(idf *identityFlags, recipientPath, signerPath string) error {
	if !idf.supplied() && recipientPath == "" && signerPath == "" {
		return usageErr("keys --fingerprint needs at least one key file to fingerprint: --identity identity.key (or --share files with --envelope), --recipient recipient.pub, or --signer signer.pub")
	}
	var lines []sheetFingerprint
	if idf.supplied() {
		identity, err := idf.resolve()
		if err != nil {
			return err
		}
		lines = append(lines, sheetFingerprint{"identity", crypto.RecipientFingerprint(crypto.PublicOf(identity))})
	}
	if recipientPath != "" {
		b, err := readKeyFile(recipientPath, labelRecipient)
		if err != nil {
			return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("recipient: %w", err)}
		}
		pub, perr := crypto.ParseKEMPublic(b)
		if perr != nil {
			return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("recipient: %w", perr)}
		}
		lines = append(lines, sheetFingerprint{"recipient", crypto.RecipientFingerprint(pub)})
	}
	if signerPath != "" {
		b, err := readKeyFile(signerPath, labelSignerPublic)
		if err != nil {
			return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("signer: %w", err)}
		}
		v, perr := crypto.ParseVerifier(b)
		if perr != nil {
			return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("signer: %w", perr)}
		}
		lines = append(lines, sheetFingerprint{"signer", crypto.SignerFingerprint(v)})
	}
	for _, l := range lines {
		fmt.Printf("%-12s %s\n", l.label, l.value)
	}
	fmt.Println("\nCompare each of these against the matching fingerprint printed on your recovery sheet.")
	fmt.Println("An identity fingerprint should also appear in downpipe keys --which for the archive you")
	fmt.Println("are recovering; a signer fingerprint should match the run's signingKeyFingerprint in")
	fmt.Println("downpipe inspect. A mismatch means this is a key from a different ceremony.")
	return nil
}

// keyGroup accumulates the runs one recipient identity can open, with the role it plays
// and the time window those runs span.
type keyGroup struct {
	fingerprint string
	role        string
	runIDs      []string
	firstTime   string
	lastTime    string
}

// unreadableVersions maps a run id to the formatVersion this reader does not implement, for the runs
// the index lists but this build cannot open.
//
// WHY THE INDEX STILL LISTS THEM, AND WHY THIS COMMAND STILL EXITS 0.
//
// keys --which answers "which offline key opens which runs", and that answer is a property of the
// ARCHIVE, not of this binary: the recipient fingerprints sit in the clear in each signed root and are
// true whatever version the run is written at. A run at a formatVersion this reader does not implement
// is still opened by the key named beside it, by the reader that does implement that version. Dropping
// it from the index, or refusing the whole command over it, would take away the one thing an operator
// holding such an archive still needs, which is knowing WHICH key and WHICH runs before they go and
// fetch the right reader. This command is also where inspect's own usage error sends somebody who does
// not yet know their run ids, so a refusal here dead-ends the first step of a recovery.
//
// What was wrong was the silence. Driven on the conformance vector unknown-major (formatVersion
// downpipe/9.0.0, refused at exit 6 by verify, restore, attest and by inspect once an identity is
// supplied): keys --which listed the run under both recipients at exit 0, with and without --signer,
// and said nothing anywhere about the version. An operator reads that as an archive this tool can
// recover, picks a run id off it, and finds out otherwise one command later. So the runs are listed,
// and each one carries this reader's verdict beside it, the same rule inspect's format line follows.
type unreadableVersions map[string]string

// reportKeysWhich reads the RUNLOG to enumerate the archive's runs, reads each run's
// public root to learn its recipients, and prints the runs grouped by recipient
// fingerprint. With a signer pinned, the RUNLOG signature is verified before the log is
// parsed at all (a forged or rolled-back log fails the whole command, matching
// CheckFreshness's treatment of a bad RUNLOG signature) and each run's root is verified
// before its recipients are trusted; without a signer the index is built from whatever
// the bucket currently holds. A run whose root cannot be read or verified is reported to
// stderr and skipped, so one damaged or forged root does not hide the rest of the index.
func reportKeysWhich(store format.ObjectStore, verifier *crypto.HybridVerifier) error {
	runlogBytes, err := store.Get("_RECOVERY/RUNLOG")
	if err != nil {
		return codedGet(format.ExitStale, fmt.Errorf("read runlog: %w", err))
	}
	if verifier != nil {
		sigText, serr := store.Get("_RECOVERY/RUNLOG.sig")
		if serr != nil {
			return codedGet(format.ExitStale, fmt.Errorf("read runlog signature: %w", serr))
		}
		sig, derr := format.B64Decode(strings.TrimSpace(string(sigText)))
		if derr != nil {
			return &format.ExitError{Code: format.ExitStale, Err: fmt.Errorf("decode runlog signature: %w", derr)}
		}
		if verr := verifier.Verify(runlogBytes, sig); verr != nil {
			return &format.ExitError{Code: format.ExitStale, Err: fmt.Errorf("verify runlog signature: %w", verr)}
		}
	}
	entries, err := format.ParseRunlog(runlogBytes)
	if err != nil {
		return &format.ExitError{Code: format.ExitStale, Err: fmt.Errorf("parse runlog: %w", err)}
	}

	groups := map[string]*keyGroup{}
	unreadable := unreadableVersions{}
	runs := 0
	pruned := 0
	skipped := 0
	for _, e := range entries {
		// A run whose tree has been pruned away is listed here but cannot be read, and it is the normal
		// state of a healthy archive under retention rather than something to warn about once per run.
		// Counting them and saying so once keeps the per-run warnings meaning what they say.
		if format.PrunedRunEntry(store, e.RunID) != nil {
			pruned++
			continue
		}
		root, rerr := readRunRoot(store, e.RunID, verifier)
		if rerr != nil {
			// COUNTED, not only printed. The per-run detail belongs on stderr, but a
			// skipped run is missing from the index and the index's own summary line has to
			// say so, because stderr is exactly what a pipe, a log capture or a support
			// pack transcript drops.
			skipped++
			fmt.Fprintf(os.Stderr, "downpipe: skipping run %s: %v\n", e.RunID, rerr)
			continue
		}
		runs++
		// The same gate Open, StreamOpen and Attest apply, asked here rather than acted on. This
		// command reads only the public root and never calls Open, so nothing else in this loop
		// would ever have noticed.
		if !format.ImplementsFormatVersion(root.FormatVersion) {
			unreadable[e.RunID] = root.FormatVersion
		}
		for _, rc := range root.Recipients {
			g := groups[rc.Fingerprint]
			if g == nil {
				g = &keyGroup{fingerprint: rc.Fingerprint, role: rc.Role}
				groups[rc.Fingerprint] = g
			}
			g.runIDs = append(g.runIDs, e.RunID)
			if g.firstTime == "" || e.Time < g.firstTime {
				g.firstTime = e.Time
			}
			if e.Time > g.lastTime {
				g.lastTime = e.Time
			}
		}
	}

	printKeyGroups(groups, runs, pruned, skipped, verifier != nil, unreadable)
	if skipped > 0 {
		// A skipped run is a run this index CANNOT account for, and the command must not
		// exit 0 over it. The same command already fails closed on a forged RUNLOG
		// signature (ExitStale); a forged or unreadable ROOT signature exiting 0 was the
		// one hole left in that posture, and it is the hole an adversary would use, since
		// removing a run from the index is exactly what makes a key look unnecessary.
		//
		// The index is printed in full first. An operator recovering from a disaster needs
		// the runs that DID read, and the exit code is what tells them it is not the whole
		// picture.
		return &format.ExitError{Code: format.ExitUnverified, Err: fmt.Errorf("%d run(s) could not be read or verified, so this key index is INCOMPLETE: the runs above are the ones that read, not all the runs in this archive", skipped)}
	}
	return nil
}

// readRunRoot fetches and parses one run's public root manifest. It is the per-run unit
// reportKeysWhich loops over. With a signer pinned, the detached root signature
// (SPEC.md 8.3) is verified before ParseRoot's result is trusted; without one the caller
// treats the result as unverified.
func readRunRoot(store format.ObjectStore, runID string, verifier *crypto.HybridVerifier) (*spec.RootManifest, error) {
	b, err := store.Get("run/" + runID + "/root.manifest.json")
	if err != nil {
		return nil, err
	}
	if verifier != nil {
		sigText, serr := store.Get("run/" + runID + "/root.manifest.json.sig")
		if serr != nil {
			return nil, fmt.Errorf("read root signature: %w", serr)
		}
		sig, derr := format.B64Decode(strings.TrimSpace(string(sigText)))
		if derr != nil {
			return nil, fmt.Errorf("decode root signature: %w", derr)
		}
		if verr := format.VerifyRootBytes(b, sig, verifier); verr != nil {
			return nil, fmt.Errorf("verify root signature: %w", verr)
		}
	}
	return format.ParseRoot(b)
}

// printKeyGroups renders the recipient -> runs index, break-glass first then by
// fingerprint, with each identity's run count and time window and the run ids it opens.
// verified is false when no --signer was pinned: the summary line then carries an
// explicit UNVERIFIED tag (mirroring attest's keyless/signer-pinned mode tag) so forged
// bucket contents are never presented as an authenticated key index.
func printKeyGroups(groups map[string]*keyGroup, runs, pruned, skipped int, verified bool, unreadable unreadableVersions) {
	ordered := make([]*keyGroup, 0, len(groups))
	for _, g := range groups {
		ordered = append(ordered, g)
	}
	sort.Slice(ordered, func(i, j int) bool {
		// Break-glass first (the recovery-of-last-resort key), then by fingerprint, so
		// the listing is stable and leads with the key that matters most in a disaster.
		bgI, bgJ := ordered[i].role == "break-glass", ordered[j].role == "break-glass"
		if bgI != bgJ {
			return bgI
		}
		if ordered[i].role != ordered[j].role {
			return ordered[i].role < ordered[j].role
		}
		return ordered[i].fingerprint < ordered[j].fingerprint
	})

	mode := "UNVERIFIED: no --signer given"
	if verified {
		mode = "signer-verified"
	}
	if skipped > 0 {
		// The tag must not read "signer-verified" over a count that silently excludes runs.
		// Driven before this changed: one archive, one run, its root signature tampered, and
		// the whole of stdout was "0 run(s) across 0 recipient identit(ies) [signer-verified]:"
		// at exit 0. The word verified sat next to a count of nothing.
		mode += ", INCOMPLETE"
	}
	fmt.Printf("%d run(s) across %d recipient identit(ies) [%s]:\n", runs, len(ordered), mode)
	if skipped > 0 {
		// On STDOUT, alongside the count it qualifies. The per-run reasons are on stderr,
		// and stderr is what a pipe drops.
		fmt.Printf("(%d further run(s) in the RUNLOG could NOT be read or verified and are missing from this index; the reason for each is on stderr. A key that opens only those runs will not appear here at all)\n", skipped)
	}
	if pruned > 0 {
		// Reported, not hidden. An operator comparing this count against their retention policy is the
		// only person who can tell a prune they ran from runs that went missing on them.
		fmt.Printf("(%d further run(s) are listed in the RUNLOG with their trees removed, which is what a prune leaves behind)\n", pruned)
	}
	if len(unreadable) > 0 {
		// On STDOUT and above the listing, because the listing is what an operator copies a run id
		// out of and this changes which reader they should be running against it.
		fmt.Printf("(%d of the run(s) below are at a format version THIS READER CANNOT OPEN: it implements %s. They are listed because the archive records which key opens them and that is still true, but verify, restore and attest will refuse them, and each is marked below. Get a downpipe reader that implements the version marked, using the 'Reads format versions' line in each release's CHANGELOG.md at https://github.com/downpipes-io/downpipe)\n", len(unreadable), format.ReaderFormatSupport())
	}
	for _, g := range ordered {
		role := g.role
		if role == "" {
			role = "(unlabelled)"
		}
		fmt.Printf("\n%-12s %s\n", role, g.fingerprint)
		fmt.Printf("  opens %d run(s)  %s .. %s\n", len(g.runIDs), g.firstTime, g.lastTime)
		for _, id := range g.runIDs {
			// Marked on the run id itself, not only in the summary above it. An archive under
			// retention lists many runs and only some of them need another reader, so a count at the
			// top cannot tell an operator WHICH run id they are about to use.
			if v, bad := unreadable[id]; bad {
				fmt.Printf("    %s  (format %s: NOT readable by this reader)\n", id, v)
				continue
			}
			fmt.Printf("    %s\n", id)
		}
	}
}
