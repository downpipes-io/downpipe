package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// cmdInspect is a diagnostic viewer, not a verifier: it waives the freshness and rollback
// gate by design, so it SHOWS a rolled-back or unverifiable run instead of refusing it.
// Use verify when freshness enforcement is required.
//
// SILENCE ABOUT WHAT HAS ALREADY BEEN MEASURED IS NOT SAFE HERE. It opens with AllowStale, and
// format.Open runs the freshness check on every open and hands the result back on the
// reader, so inspect held the verdict and printed nothing: a forged _RECOVERY/RUNLOG.sig
// produced the same output, at exit 0, as an intact archive. Silence is defensible only if
// a reader cannot mistake this command for a check, and a customer who passes --identity
// and --signer and is shown the decrypted detail has just had the root signature, the
// master capsule, the key commitment, the recipient set, the record count and the Merkle
// root all genuinely verified. What they conclude from a clean-looking dump at exit 0 is
// that the archive checked out, and on the one thing inspect withheld they would be wrong.
//
// So it is not made to refuse, which is what verify is for. It prints the freshness line it
// already has, on every open, passing or not: a line that appears only on trouble is one
// whose absence an operator cannot rely on.
func cmdInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	sf := addStoreFlags(fs)
	run := fs.String("run", "", "run id")
	idf := addIdentityFlags(fs, "open the encrypted preamble with this identity (optional; inspect reports the freshness check but never enforces it, so use verify when a rolled-back run must be refused)")
	signerPath := fs.String("signer", "", "operator signer public-key file (with --identity)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *run == "" {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("inspect needs --run and a source (--archive or --s3-endpoint). To see which runs a source holds, run: downpipe keys --which --archive <dir>")}
	}
	if _, err := spec.DecodeULID(*run); err != nil {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("--run: %w", err)}
	}
	store, err := sf.resolve()
	if err != nil {
		return err
	}
	b, err := store.Get("run/" + *run + "/root.manifest.json")
	if err != nil {
		return codedGet(exitUnclassified, err)
	}
	m, err := format.ParseRoot(b)
	if err != nil {
		return err
	}
	fmt.Println(formatVersionLine(m.FormatVersion))
	fmt.Printf("run:        %s\n", m.RunID)
	fmt.Printf("created:    %s\n", m.CreatedAt)
	fmt.Printf("downpipe:   %s\n", m.DownpipeID)
	fmt.Printf("envelope:   %s | %s | %s | %s\n", m.Envelope.AEAD, m.Envelope.KEM, m.Envelope.Signature, m.Envelope.KDF)
	fmt.Printf("records:    %d declared across %d shard(s); break-glass present: %v\n", m.DeclaredRecordCount, m.ShardCount, m.BreakGlassPresent)
	// The signer this run DECLARES it was signed by. Printed because it is the only thing in the
	// archive an operator can hold their recovery sheet's signer fingerprint up against, and
	// --signer wants a 3.5 KB key file the sheet does not carry. It is a claim by the bucket, not
	// proof: the manifest is only signed under the very key this line names, so a bucket-write
	// adversary can rewrite the pair together. It answers "is this the ceremony my sheet
	// describes", never "is this archive authentic", and the label says which.
	fmt.Printf("signer:     %s (declared by the run; verify with --signer signer.pub)\n", m.SigningKeyFingerprint)
	fmt.Println("recipients:")
	for _, rc := range m.Recipients {
		fmt.Printf("  - %-12s %s\n", rc.Role, rc.Fingerprint)
	}
	if !idf.supplied() {
		fmt.Println("(the downpipe name, schedule, sources and window are encrypted; pass --identity and --signer to show them)")
		// And what has NOT happened, said plainly. Without --identity this command never opened the
		// run: no signature was verified, no capsule unwrapped and no RUNLOG read, so every line
		// above is the bucket's own account of itself. The signer line already carries that caveat
		// for one field; an operator mid-recovery reads the block, not one parenthetical in it.
		// The closing instruction is CONDITIONAL, because on a run this reader cannot open it
		// contradicted the format line six lines above it. Driven on the unknown-major vector, the
		// block said "verify and restore will refuse this run" at the top and "Run: downpipe verify"
		// at the bottom, and an operator following the last line got exit 6. Naming a next step that
		// this same output has already said will fail is not a next step.
		if format.ImplementsFormatVersion(m.FormatVersion) {
			fmt.Println("(nothing above was verified: without --identity this run was not opened, so no signature, no record hash and no RUNLOG was checked. Run: downpipe verify)")
		} else {
			fmt.Println("(nothing above was verified: without --identity this run was not opened, so no signature, no record hash and no RUNLOG was checked. Do NOT run downpipe verify on this run with this build; it will refuse the version, as the format line above says. Get a reader that implements this format version first)")
		}
		return nil
	}
	if *signerPath == "" {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("inspect --identity also needs --signer")}
	}
	identity, verifier, err := idf.loadAndVerifier(*signerPath)
	if err != nil {
		return err
	}
	// Both acknowledgements, so this command still opens every run it can read rather than
	// refusing one. AllowStale alone no longer covers a RUNLOG that could not be verified, and a
	// diagnostic viewer that refuses the archive an operator is trying to diagnose is the wrong
	// tool for the moment they reach for it.
	r, err := format.Open(store, *run, identity, verifier, format.Options{AllowStale: true, AllowUnverifiedRunlog: true})
	if err != nil {
		return err
	}
	defer r.Close() // wipe the run master when this command is done with it
	fmt.Println(freshnessLine(r.Freshness()))
	fmt.Println("encrypted detail (opened with the identity):")
	for _, p := range r.Preambles() {
		fmt.Printf("  shard %s: downpipe %q cadence %q, source %s, window %s..%s, %d record(s)\n",
			p.ShardID, p.Downpipe.Name, p.Downpipe.Cadence, p.Source.Type, p.Window.Start, p.Window.End, p.RecordCountInShard)
		if len(p.Source.Include) > 0 || len(p.Source.Exclude) > 0 {
			fmt.Printf("    include=%v exclude=%v\n", p.Source.Include, p.Source.Exclude)
		}
	}
	// Surface each record's self-identifying source coordinates (namespace/bucket/database/account,
	// mirroring the engine's manifest annotations 1:1, SPEC.md 6.2) alongside the per-source restore
	// descriptor it carries beyond its value bytes (KV expiration/metadata, R2 http/custom metadata,
	// the secret binding wiring including its Secrets Store id, the D1 format). Together these show
	// what account/namespace/bucket/database an archive is a backup OF and what the engine's
	// in-account restore reapplies; showing them here proves an archive is full-fidelity rather than
	// value-only, and the offline reader can report what it would carry.
	shownDetail := false
	for _, rec := range r.Records() {
		ident := describeIdentity(rec)
		desc := describeRestoreDescriptor(rec)
		if ident == "" && desc == "" {
			continue
		}
		parts := make([]string, 0, 2)
		if ident != "" {
			parts = append(parts, ident)
		}
		if desc != "" {
			parts = append(parts, desc)
		}
		if !shownDetail {
			fmt.Println("records (identity + restore descriptors):")
			shownDetail = true
		}
		fmt.Printf("  %-40s %s\n", rec.Name, strings.Join(parts, "  "))
	}
	return nil
}

// describeIdentity renders the present top-level self-identification coordinates on a record as a
// short line, or "" when the record carries none: namespace for a namespaced source (KV), bucket
// for a bucketed source (R2), database for D1's native database UUID, and account for an API source
// (workers, cf-config, stream, images, artifacts) naming the Cloudflare account the backup is OF.
// These mirror the engine's manifest annotations 1:1 (SPEC.md 6.2) and are omitempty. Database and
// account are NOT mutually exclusive: a D1 database lives inside a Cloudflare account, so a D1
// record's Database and Account are both set together (see the corpus's d1-with-identity vector and
// TestDescribeIdentity's "database and account together" case); a prior version of this comment
// claimed at most one field is set per record, which was false and left a database<->account value
// swap here undetected until a dedicated both-set test case was added.
// A secrets record's identity (its Secrets Store id) is not here: it lives in the nested descriptor
// and describeRestoreDescriptor already shows it.
// formatVersionLine renders inspect's format line with this reader's own verdict on the
// version, on EVERY run rather than only on trouble.
//
// Without it the line was the archive's self-description and nothing else, and it printed
// identically whether the reader could read the archive or not. Driven before this
// changed: the conformance vector unknown-major (formatVersion downpipe/9.0.0, a version
// this reader refuses at exit 6) produced a full, clean-looking inspect block at EXIT 0
// with no mention anywhere that the reader cannot read it, closing on a line telling the
// operator to run downpipe verify, which then refuses. inspect is a diagnostic viewer and
// is deliberately not made to refuse, which is the right call; the fix is that it says
// what it already knows. This is the same rule the freshness line above follows: a line
// that appears only on trouble is one whose absence an operator cannot rely on, so the
// reader's support is stated on the readable case too.
func formatVersionLine(v string) string {
	if format.ImplementsFormatVersion(v) {
		return fmt.Sprintf("format:     %s  (this reader implements %s)", v, format.ReaderFormatSupport())
	}
	return fmt.Sprintf("format:     %s  (THIS READER CANNOT READ THIS ARCHIVE: it implements %s. "+
		"verify and restore will refuse this run. Nothing is wrong with the bytes and nothing has been lost; "+
		"get a downpipe reader that implements this format version, using the 'Reads format versions' line in "+
		"each release's CHANGELOG.md at https://github.com/downpipes-io/downpipe)", v, format.ReaderFormatSupport())
}

func describeIdentity(rec spec.ShardRecord) string {
	parts := []string{}
	if rec.Namespace != "" {
		parts = append(parts, fmt.Sprintf("namespace=%q", rec.Namespace))
	}
	if rec.Bucket != "" {
		parts = append(parts, fmt.Sprintf("bucket=%q", rec.Bucket))
	}
	if rec.Database != "" {
		parts = append(parts, fmt.Sprintf("database=%q", rec.Database))
	}
	if rec.Account != "" {
		parts = append(parts, fmt.Sprintf("account=%q", rec.Account))
	}
	if len(parts) == 0 {
		return ""
	}
	return "identity: " + strings.Join(parts, " ")
}

// describeRestoreDescriptor renders the present per-source descriptor on a record as a short line, or
// "" when the record carries none. At most one of KV/R2/Secrets/D1 is set (the direct-write source
// types); reprovision-type records (workers, cf-config, stream, images, artifacts) carry none.
func describeRestoreDescriptor(rec spec.ShardRecord) string {
	switch {
	case rec.KV != nil:
		parts := []string{}
		if rec.KV.Expiration != 0 {
			parts = append(parts, fmt.Sprintf("expiration=%d", rec.KV.Expiration))
		}
		if len(rec.KV.Metadata) > 0 {
			parts = append(parts, "metadata")
		}
		if len(parts) == 0 {
			return ""
		}
		return "kv: " + strings.Join(parts, " ")
	case rec.R2 != nil:
		parts := []string{}
		if len(rec.R2.HTTPMetadata) > 0 {
			parts = append(parts, "httpMetadata")
		}
		if len(rec.R2.CustomMetadata) > 0 {
			parts = append(parts, "customMetadata")
		}
		if len(parts) == 0 {
			return ""
		}
		return "r2: " + strings.Join(parts, " ")
	case rec.Secrets != nil:
		s := rec.Secrets
		return fmt.Sprintf("secrets: store=%q scope=%q worker=%q binding=%q", s.Store, s.Scope, s.Worker, s.BindingVar)
	case rec.D1 != nil:
		if rec.D1.Format == "" {
			return ""
		}
		return "d1: format=" + rec.D1.Format
	}
	return ""
}

// freshnessLine renders the anti-rollback/freshness verdict inspect already holds as one line, in
// the same label column as the rest of the dump. It never returns "", because the case that matters
// most is the one where the check could not run, and a viewer that prints a line only when it has
// something to say is a viewer whose silence means two different things.
//
// It states the verdict and the command that ENFORCES it, and it does not offer --allow-stale or
// --allow-unverified-runlog: inspect has already waived the gate, so there is nothing here for an
// operator to override, and naming an override in the output of a command that did not stop is how
// a waiver comes to look like a routine step.
func freshnessLine(fresh format.FreshnessResult) string {
	switch {
	case fresh.Unchecked:
		return fmt.Sprintf("freshness:  NOT ESTABLISHED, the check could not be run: %s. inspect showed this run anyway; nothing above says whether the bucket was rolled back or replaced. Run: downpipe verify", fresh.Reason)
	case fresh.RunlogUntrusted:
		return fmt.Sprintf("freshness:  the RUNLOG verified against --signer and contradicts itself: %s. inspect showed this run anyway; which run is latest cannot be read from that log. Run: downpipe verify", fresh.Reason)
	case fresh.RollbackWarning:
		return fmt.Sprintf("freshness:  checked, and it did NOT pass: %s. inspect showed this run anyway. Run: downpipe verify", fresh.Reason)
	default:
		return fmt.Sprintf("freshness:  checked and passed: this run is the latest for its downpipe (runlog index %d, log maximum %d)", fresh.MaxIndexForDownpipe, fresh.RunlogMaxIndex)
	}
}
