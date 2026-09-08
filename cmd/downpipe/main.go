// Command downpipe is the standalone, offline recovery tool for downpipe archives. It
// verifies and restores encrypted Cloudflare backups from the destination bucket
// bytes plus the customer-held offline keys, with neither Cloudflare nor any vendor
// service in the loop. See docs/format/SPEC.md for the archive format.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/source"
)

// version is the release version, set at build time by the release pipeline via
// -ldflags "-X main.version=<tag>" (see .goreleaser.yaml and the Makefile). A plain
// "go build" leaves it at "dev", so an unstamped local build reports "downpipe dev".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

// errHelpRequested marks the one flag-parse outcome that is not a failure: the operator asked
// for a subcommand's help and the FlagSet printed it. It is unexported and compared by identity
// in run(), so no other error can be mistaken for it.
var errHelpRequested = errors.New("help requested")

// parseFlags parses a subcommand's flags and gives the outcome the exit status it deserves.
//
// A FlagSet returns its parse errors uncoded, and an uncoded error falls through run() to
// exitUncoded (1), which the printed exit-code table defines as "an I/O or unexpected failure
// this tool did not otherwise classify". So a mistyped flag mid-recovery reported an unexpected
// failure instead of a usage error, and "downpipe verify --help" reported one too, for the
// operator who asked the tool a question and got an answer. Every subcommand had the defect
// except recombine, which coded its parse error to ExitUsage and settled what the right answer
// is; recombine went the other way on help, exiting 6 for a help request that succeeded.
//
// Both routes matter to a recovery script that branches on the status: 6 says fix the command
// line, 1 says something went wrong that is worth investigating, and 0 says nothing is wrong
// at all.
func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return errHelpRequested
		}
		return &format.ExitError{Code: format.ExitUsage, Err: err}
	}
	return nil
}

// run dispatches args to the appropriate subcommand and returns the process exit code.
// Extracting this from main() allows tests to call it directly without exec.
func run(args []string) int {
	if len(args) == 0 {
		// A usage error, code 6, and not the tamper-class code 2 this used to return. SPEC.md 8.5
		// reserves 2 for a verdict ABOUT AN ARCHIVE: a missing, invalid, single-half or wrong-signer
		// signature, a failed section 8.3 recomputation, a failed break-glass check or a failed
		// recovery-bundle check. Invoked with no command the tool has opened nothing, so 2 asserted a
		// verification failure that was never reached. The realistic way this is hit is a DR wrapper
		// expanding an unset variable, and telling a recoverer mid-incident that their archive failed
		// to verify, when the truth is that a shell variable was empty, is the most frightening thing
		// this tool can say and the least true.
		usage()
		return format.ExitUsage
	}
	// One signal-aware context for the long-running commands: an interrupt cancels the
	// shard walk and every in-flight fetch, so the run stops promptly with a real error
	// and can never be recorded as a success.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch args[0] {
	case "keygen":
		err = cmdKeygen(args[1:])
	case "inspect":
		err = cmdInspect(args[1:])
	case "keys":
		err = cmdKeys(args[1:])
	case "verify":
		err = cmdVerify(ctx, args[1:])
	case "attest":
		err = cmdAttest(args[1:])
	case "restore":
		err = cmdRestore(ctx, args[1:])
	case "prune":
		err = cmdPrune(ctx, args[1:])
	case "recombine":
		err = cmdRecombine(ctx, args[1:])
	case "unseal-export":
		err = cmdUnsealExport(args[1:])
	case "selftest":
		err = cmdSelftest(args[1:])
	case "setup":
		err = cmdSetup(args[1:])
	case "preflight":
		err = cmdPreflight(args[1:])
	case "init":
		err = cmdInit(args[1:])
	case "update":
		err = cmdUpdate(args[1:])
	case "version", "--version", "-v":
		fmt.Println("downpipe", version)
	case "spec":
		fmt.Println("the archive format is specified in docs/format/SPEC.md")
	case "help", "-h", "--help":
		usage()
	default:
		err = &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("unknown command %q, run 'downpipe help'", args[0])}
	}
	if errors.Is(err, errHelpRequested) {
		// The FlagSet has already printed the subcommand's usage. Asking for it is not a
		// failure, so it is not announced as one and the status is 0.
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "downpipe:", err)
		var ee *format.ExitError
		if errors.As(err, &ee) {
			// A freshness/rollback rejection (exit 5) is frequently a BENIGN chain churn — a rapid
			// re-trigger or a demo reset left the signed root and the RUNLOG disagreeing on prevRunId —
			// not a real rollback: the data is intact and --allow-stale restores it. Surface the intended
			// recovery at the point of failure so an operator mid-DR is not stuck on a rollback alarm over
			// a good backup. (The genuine anti-rollback guarantee is what --allow-stale waives, so it is a
			// deliberate, recorded acknowledgement; see docs/RECOVER.md "Freshness / rollback (exit 5)".)
			// Gated on the command actually HAVING --allow-stale. The hint used to fire on every exit 5,
			// so a command without the flag advised an operator to re-run with it, and doing as they were
			// told produced "flag provided but not defined". Advice that cannot be followed is worse than
			// none, because it spends the operator's trust in the next hint the tool gives them.
			// Also gated on the RUNLOG having been read at all. An absent RUNLOG is an exit 5 by
			// SPEC.md 8.5, and --allow-stale cannot conjure a file that is not there, so on a wrong
			// --archive path this advised re-running with a flag that would fail the same way. The
			// absent-object hint below covers that case with the instruction that does help.
			// And gated on the check having RUN. This hint recommends the override, and it
			// named only benign causes while doing so, in exactly the same words for a RUNLOG
			// signature that did not verify against the pinned signer. Driven: a tampered
			// _RECOVERY/RUNLOG.sig printed "re-run with --allow-stale to restore the intact
			// data" with nothing said about a bucket that may have been replaced. The message
			// AFTER the override was split by severity; this is the message BEFORE it, and it
			// is the one that sends the operator there.
			if ee.Code == format.ExitStale && acceptsFreshnessOverride[args[0]] && !errors.Is(err, fs.ErrNotExist) {
				switch {
				case errors.Is(err, format.ErrFreshnessUnchecked):
					fmt.Fprintln(os.Stderr, "downpipe: this is the anti-rollback freshness check, and the line above says it could not be run at all, so nothing was established about this run's recency. --allow-stale does not cover this and will refuse again: it is an age word, and no age was measured. The acknowledgement here is --allow-unverified-runlog, which waives that check rather than satisfying it, and a bucket someone has rolled back or replaced looks exactly like this. Fetch the RUNLOG and its signature from a copy you trust and re-run first; see docs/RECOVER.md \"Freshness / rollback (exit 5)\".")
				case errors.Is(err, format.ErrRunlogChainAnomaly):
					// The chain anomaly is the case a marker on the error exists for. The check RAN, so
					// the unchecked branch above does not cover it, and it is not about this run's age,
					// so the benign branch below must not offer --allow-stale for it: after the split
					// that flag refuses a second time, and advice that cannot be followed spends the
					// operator's trust in the next hint the tool gives them.
					fmt.Fprintln(os.Stderr, "downpipe: this is the anti-rollback freshness check. The RUNLOG verified against --signer, and the line above says the log contradicts itself, which means it was rewritten or hand-assembled rather than appended to by the engine. --allow-stale does not cover this and will refuse again; the acknowledgement is --allow-unverified-runlog. Compare this log against a copy you trust before you act on the outcome; see docs/RECOVER.md \"Freshness / rollback (exit 5)\".")
				default:
					fmt.Fprintln(os.Stderr, "downpipe: this is the anti-rollback freshness check, not a decryption failure. The check ran, and the line above says what it found. If you expected a multi-run history (or this archive saw a rapid re-trigger or a demo reset), re-run with --allow-stale to restore the intact data; see docs/RECOVER.md \"Freshness / rollback (exit 5)\".")
				}
			}
			hintAbsentObject(err, ee.Code, args[0])
			hintIdentityMismatch(ee)
			return ee.Code
		}
		// An uncoded error still gets the absent-object hint. inspect reports an absent root
		// manifest this way, and a mistyped --run on the diagnostic viewer is one of the likeliest
		// wrong turns in a recovery.
		hintAbsentObject(err, exitUncoded, args[0])
		return exitUncoded
	}
	return 0
}

type storeFlags struct {
	archive    *string
	s3Endpoint *string
	s3Bucket   *string
	s3Region   *string
	// The Azure Blob pair is separate from the S3 pair rather than folded into it, because Azure
	// Blob is not an S3-compatible store: it has its own wire protocol, its own authentication and
	// its own listing document, so --s3-endpoint cannot reach an Azure container at any value.
	// Cloudflare R2, Amazon S3 and Google Cloud Storage all ARE reachable through --s3-endpoint,
	// which is why one generic pair covers three destinations and Azure needs a second.
	azureEndpoint  *string
	azureContainer *string
}

// acceptsFreshnessOverride is the set of commands that define BOTH --allow-stale and
// --allow-unverified-runlog, the two acknowledgements the exit-5 hint below can offer. It is stated
// here rather than inferred, because the cost of it being wrong is asymmetric: a missing entry loses a
// useful hint, while a spurious one sends an operator mid-recovery to a flag that does not exist.
//
// Both flags, not either: the hint chooses between them by what the reader actually found, so a command
// carrying only one of the pair would still be handed the sentence naming the other.
var acceptsFreshnessOverride = map[string]bool{"verify": true, "restore": true}

// allowStaleUsage and allowUnverifiedRunlogUsage are the help text for the two freshness
// acknowledgements, written once and shared by verify and restore so the two commands cannot come to
// describe the same permission differently.
//
// THE FLAG'S OWN HELP NOW STATES WHAT IT WAIVES AND WHAT IT DOES NOT. --allow-stale was one word
// granting two permissions: a customer in a disaster reached for a word meaning "I know this run is old,
// proceed anyway" and, on the evidence of that word, the RUNLOG's signature check was waived.
const allowStaleUsage = "proceed despite this run's AGE and nothing else: the RUNLOG verified against --signer, is internally consistent, and says either that this run is not the latest for its downpipe or that its maximum index is below your --min-runlog-index pin. It does NOT waive the RUNLOG's signature, presence or self-consistency; that is --allow-unverified-runlog. See docs/RECOVER.md"

const allowUnverifiedRunlogUsage = "proceed despite the RUNLOG itself being untrustworthy: absent, unreadable, unparseable, empty, not carrying this run, failing to verify against --signer, disagreeing with the signed root manifest, or internally contradictory. Nothing is then established about this run's recency, and a bucket someone has rolled back or replaced looks exactly like this. See docs/RECOVER.md"

// exitUncoded is the CLI's fallback status for an error carrying no ExitError. It is not one of
// SPEC.md 8.5's normative reader codes, which is why it lives here rather than in internal/format,
// and the help table describes it as "an I/O or unexpected failure this tool did not otherwise
// classify".
const exitUncoded = 1

// readsAnArchive is the set of commands that open an archive, so the absent-object hint below is
// never printed by a command that was not reading one. Stated rather than inferred, for the same
// asymmetry acceptsAllowStale records.
var readsAnArchive = map[string]bool{"inspect": true, "keys": true, "verify": true, "attest": true, "restore": true, "prune": true}

// hintAbsentObject explains an exit whose real cause was an archive object that was not there at all.
//
// ExitUnreachable (11) marks this case for a NETWORK destination, and internal/source's
// httpStatusHint already turns a 401, 403 or 404 into an actionable parenthetical. The LOCAL
// --archive path has neither. internal/format's ExitUnreachable doc records why, and that reasoning
// stands: a local read failure keeps whichever code its check already carried, because the reader
// cannot safely reclassify it. So the code is deliberately unchanged here.
//
// What it leaves behind is the experience problem this hint closes. RECOVER.md's primary path is a
// copy of the bucket tree on local disk, so the likeliest cause of an absent object mid-recovery is a
// wrong --archive path, a wrong --run, an unmounted drive or a copy that did not finish. Every one of
// those exits 2, 3 or 4, and the tool's own exit-code table says of 2 to 5: "stop and investigate, and
// never retry on a different key or file just to make the error go away". That is the correct
// instruction for a tamper finding and the wrong one for a typo, and the operator has nothing on
// screen to tell the two apart beyond a nested "no such file or directory".
//
// Gated on fs.ErrNotExist, which a signature, hash or authenticated-decrypt failure never carries, so
// the hint cannot soften a genuine integrity verdict. It states what is and is not known and stops
// short of telling anyone to ignore the exit code.
// It takes the raw error and the code the command is about to exit with, rather than an ExitError,
// because the two commands most likely to meet a wrong path do not produce one. Driving the built
// binary found both. `inspect` reports an absent root manifest as an UNCODED error and exits 1, so
// while it is named in readsAnArchive above, the hint could never fire for it: a mistyped --run or a
// wrong --archive on the diagnostic viewer got a nested "no such file or directory" and no next step.
// `keys --which` reports an absent RUNLOG as ExitStale and exits 5, which is what SPEC.md 8.5 says
// that code covers, so the code stays; but `keys --which` is the command this very hint tells the
// operator to run next, and answering "stale" for a directory that does not exist was the one
// recovery instruction the tool gives whose own failure it did not explain.
func hintAbsentObject(err error, code int, cmd string) {
	if !readsAnArchive[cmd] || !errors.Is(err, fs.ErrNotExist) {
		return
	}
	switch code {
	case exitUncoded, format.ExitUnverified, format.ExitIncomplete, format.ExitPlaintext, format.ExitStale, format.ExitDangling:
	default:
		return
	}
	// The middle sentence differs by code, because it is a claim about the number and one
	// version of it is false for ExitDangling. Every other code here was assigned by some
	// other check and merely kept through the read failure, which is what "the code that read
	// failure kept" says. 13 was assigned by this exact finding, so saying the same of it
	// would be describing a code the tool no longer produces that way. Both spellings keep
	// the phrase "Exit <n> is the code", so a reader and the gate below meet the same shape
	// whichever branch printed.
	kept := fmt.Sprintf("Exit %d is the code that read failure kept, not a finding against the archive: no signature or hash failed here.", code)
	if code == format.ExitDangling {
		kept = fmt.Sprintf("Exit %d is the code for exactly this: the run's signed manifests all verified and name an object the archive does not hold. It is not a finding against the archive's authenticity, and no signature, tag or hash failed here.", code)
	}
	fmt.Fprintf(os.Stderr, "downpipe: an object this run needs was not found at all, so nothing was retrieved to check. %s Check that --archive points at the whole bucket tree (it must hold run/, seg/ and _RECOVERY/ together), that the copy or download finished, and that --run names a run present there. Run 'downpipe keys --which --archive <dir>' to list the runs the archive actually holds, then retry. If the path and the run are right and the object is genuinely gone from the destination, that is a real gap in the archive and is worth investigating as one.\n", kept)
}

// hintIdentityMismatch adds the next step to "the key you supplied is not one this run was
// sealed to".
//
// The message this follows is already good on the facts: it prints the fingerprint of the key
// the operator holds and the fingerprints of the keys that would open the run. What it lacked
// was the instruction. The wrong-SIGNER message a few checks earlier does exactly this, and
// says plainly what to do and what not to do; the wrong-IDENTITY message stopped at the facts
// and left an operator holding two fingerprints and no sentence telling them to go and find
// the matching key file.
//
// The gap mattered more than a missing sentence usually does, because the exit code argues
// against the correct action here. This is an exit 2, and the exit-code table says of 2 to 5:
// never retry on a different key or file just to make the error go away. That rule is right
// for a tamper finding and wrong for this, where a different key file is precisely the fix.
func hintIdentityMismatch(ee *format.ExitError) {
	if !errors.Is(ee, crypto.ErrIdentityMismatch) {
		return
	}
	fmt.Fprintln(os.Stderr, "downpipe: this is a key mismatch, not a finding against the archive. The archive is intact and sealed to the identities named above; the key the command held is a different one. Find the key file whose fingerprint matches one of them (your recovery sheet records which identity is which) and re-run with that file as --identity. If you recovered from an M-of-N custody quorum and passed --share with --envelope rather than a key file, you hold no key file to swap and the same conclusion applies to the quorum: those shares and that envelope rebuild a key this run was not sealed to, so they are from a different ceremony or a different split, and the fix is the right custody artefacts rather than more shares from the same set. Retrying with the correct key is the right response here, and is the exception to the exit-code table's rule about not retrying on a different key. Run 'downpipe keys --which' against the archive to see every identity that opens a run in it.")
}

// describe names the destination in a form fit for an operator-side record. It is deliberately the
// endpoint and bucket rather than any credential, because the prune receipt it feeds is a plain file an
// operator may keep, attach to a ticket or hand to an auditor.
func (sf storeFlags) describe() string {
	if sf.s3Endpoint != nil && *sf.s3Endpoint != "" {
		bucket := ""
		if sf.s3Bucket != nil {
			bucket = *sf.s3Bucket
		}
		return fmt.Sprintf("s3 %s/%s", *sf.s3Endpoint, bucket)
	}
	if sf.azureEndpoint != nil && *sf.azureEndpoint != "" {
		container := ""
		if sf.azureContainer != nil {
			container = *sf.azureContainer
		}
		return fmt.Sprintf("azure %s/%s", *sf.azureEndpoint, container)
	}
	if sf.archive != nil && *sf.archive != "" {
		return "archive " + *sf.archive
	}
	return "unknown destination"
}

func addStoreFlags(fs *flag.FlagSet) storeFlags {
	return storeFlags{
		archive:    fs.String("archive", "", "local archive directory"),
		s3Endpoint: fs.String("s3-endpoint", "", "S3-compatible endpoint instead of --archive"),
		s3Bucket:   fs.String("s3-bucket", "", "S3 bucket name (with --s3-endpoint)"),
		s3Region:   fs.String("s3-region", "auto", "S3 region (with --s3-endpoint)"),
		// No --azure-region: Azure carries the region in the endpoint host and signs no scope
		// line, so there is nothing for a region flag to set. No --azure-account either: the
		// account name is the endpoint's first label, and AZURE_STORAGE_ACCOUNT overrides it for a
		// custom domain, alongside the credential it belongs with.
		azureEndpoint:  fs.String("azure-endpoint", "", "Azure Blob endpoint instead of --archive, for example https://<account>.blob.core.windows.net"),
		azureContainer: fs.String("azure-container", "", "Azure Blob container name (with --azure-endpoint)"),
	}
}

// supplied reports whether a source was named at all, so a usage error can list the source only when
// it is one of the things actually missing. Listing every requirement on every failure is how the old
// message told an operator who had passed --archive that they needed a source, which invites them to
// go looking at the one input that was already right.
func (sf storeFlags) supplied() bool {
	return *sf.archive != "" || *sf.s3Endpoint != "" || *sf.azureEndpoint != ""
}

// resolve picks the local-directory, the S3 or the Azure Blob backend. Every credential comes from
// the environment and never from a flag: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY for S3, and
// AZURE_STORAGE_KEY or AZURE_STORAGE_SAS_TOKEN (with AZURE_STORAGE_ACCOUNT where the account name is
// not the endpoint's first label) for Azure. Those are the names the vendors' own tools read, so an
// operator who can already reach the destination from a shell can reach it from here with no new
// secret to place.
func (sf storeFlags) resolve() (format.ObjectStore, error) {
	// TWO ENDPOINTS IS A REFUSAL, not a precedence. An operator who has named both has one of them
	// wrong, and quietly reading the other means the run that succeeds says nothing about the
	// destination they meant. Checked before either branch so the message names the conflict rather
	// than a missing bucket or container.
	if *sf.s3Endpoint != "" && *sf.azureEndpoint != "" {
		return nil, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("--s3-endpoint and --azure-endpoint name two different destinations; pass one")}
	}
	if *sf.azureEndpoint != "" {
		return sf.resolveAzure()
	}
	if *sf.s3Endpoint != "" {
		if *sf.s3Bucket == "" {
			return nil, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("--s3-bucket is required with --s3-endpoint")}
		}
		ak, sk := os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY")
		if ak == "" || sk == "" {
			return nil, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to read from S3")}
		}
		store, err := source.NewS3Store(source.S3Config{
			Endpoint:    *sf.s3Endpoint,
			Bucket:      *sf.s3Bucket,
			Region:      *sf.s3Region,
			AccessKeyID: ak,
			SecretKey:   sk,
		})
		if err != nil {
			return nil, &format.ExitError{Code: format.ExitUsage, Err: err}
		}
		return store, nil
	}
	if *sf.archive == "" {
		return nil, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("need --archive <dir>, --s3-endpoint <url> --s3-bucket <name>, or --azure-endpoint <url> --azure-container <name>")}
	}
	return source.NewDirStore(*sf.archive), nil
}

// resolveAzure builds the Azure Blob backend. Split out rather than inlined into resolve, so the two
// network backends read as two branches of the same length rather than one long one with the other
// nested inside it.
//
// EVERY REFUSAL HERE IS A USAGE ERROR (exit 6), and that is the whole point of refusing here rather
// than at the first read. A missing container, an absent credential, two credentials, a key that is
// not base64 and a SAS that expired last week all answer 403 or 404 on the wire, and a 403
// mid-recovery reads as "your credential lacks permission on this container", which sends an operator
// to the Azure portal to audit access for what is a command line they can fix in one keystroke.
func (sf storeFlags) resolveAzure() (format.ObjectStore, error) {
	if *sf.azureContainer == "" {
		return nil, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("--azure-container is required with --azure-endpoint")}
	}
	key, sas := os.Getenv("AZURE_STORAGE_KEY"), os.Getenv("AZURE_STORAGE_SAS_TOKEN")
	if key == "" && sas == "" {
		return nil, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("set AZURE_STORAGE_KEY (a storage account access key) or AZURE_STORAGE_SAS_TOKEN (a shared access signature) to read from Azure Blob")}
	}
	store, err := source.NewAzureStore(source.AzureConfig{
		Endpoint:   *sf.azureEndpoint,
		Container:  *sf.azureContainer,
		Account:    os.Getenv("AZURE_STORAGE_ACCOUNT"),
		AccountKey: key,
		SASToken:   sas,
	})
	if err != nil {
		return nil, &format.ExitError{Code: format.ExitUsage, Err: err}
	}
	return store, nil
}

// exitUnclassified is the implicit unclassified-error fallback run() applies to any error that
// carries no *format.ExitError (see run()'s final `return 1` above): named here, not just
// literal, so a codedGet fallback that means "keep exiting 1 exactly as before" reads as a
// deliberate choice rather than a stray magic number.
const exitUnclassified = 1

// unreachableGetErr is the capability a store.Get error can implement to self-report as
// transport/access layer: the object's bytes were never retrieved (SPEC.md 8.5's ExitUnreachable
// boundary, documented in full on that constant in internal/format/errors.go). Checked through
// errors.As, mirroring internal/format's own unreachableGetErr/codedGet exactly, so
// internal/source's S3Store is classified here without cmd/downpipe importing internal/format's
// unexported type or internal/format importing cmd/downpipe.
type unreachableGetErr interface{ Unreachable() bool }

// codedGet classifies a direct store.Get failure made outside internal/format (inspect, keys and
// prune each hold their own): ExitUnreachable when err self-reports transport/access layer, else
// fallback, the code this call site used before ExitUnreachable existed. Same boundary, same
// unclassifiable-default rule, same mechanism as internal/format/errors.go's codedGet; duplicated
// rather than exported across the package boundary because it is four lines and the alternative is
// a new exported format API surface for a single internal helper shape.
func codedGet(fallback int, err error) *format.ExitError {
	var ue unreachableGetErr
	if errors.As(err, &ue) && ue.Unreachable() {
		return &format.ExitError{Code: format.ExitUnreachable, Err: err}
	}
	return &format.ExitError{Code: fallback, Err: err}
}

const (
	labelIdentity      = "downpipe-identity-v1"
	labelRecipient     = "downpipe-recipient-v1"
	labelSignerPublic  = "downpipe-signer-public-v1"
	labelSignerPrivate = "downpipe-signer-private-v1"
)

// nowStamp is the RFC 3339 UTC millisecond timestamp used in receipts (SPEC.md 11.5).
func nowStamp() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000Z") }

// warnIfNoRollbackPin prints a one-line stderr warning when verify or restore runs
// without --min-runlog-index. minIndex <= 0 is exactly the condition CheckFreshness
// (internal/format/freshness.go) treats as "no pin": the reader still checks the RUNLOG
// signature and that the restored run is the latest entry it can see, but it has no
// out-of-band reference point, so a bucket wholesale-replaced with an older, validly
// signed, internally self-consistent RUNLOG (a tail rollback) verifies clean. Printed to
// stderr, never stdout, so a machine consumer piping or parsing stdout (the env sink
// writes dotenv lines there) never sees it mixed into that output. ackNoPin suppresses
// the reminder for a deliberate first recovery, before a recovery sheet's anti-rollback
// line has ever been filled in; it does not change MinIndexPinned in the signed receipt,
// which still records 0, so the absence of the pin stays visible in the machine-readable
// outcome even when the printed reminder is silenced.
func warnIfNoRollbackPin(minIndex int64, ackNoPin bool) {
	if minIndex > 0 || ackNoPin {
		return
	}
	fmt.Fprintln(os.Stderr, "warning: --min-runlog-index was not set, so a rollback to an older, validly signed run will not be detected. Read the latest trusted RUNLOG index off your recovery sheet's anti-rollback line and pass --min-runlog-index <n>. If this is a genuine first recovery with no recovery sheet entry yet, pass --acknowledge-no-rollback-pin to silence this reminder; rollback protection stays off either way.")
}

// warnIfRollbackOverridden prints a one-line stderr warning when a run completed (exit 0)
// despite a failed anti-rollback/freshness check, because the operator passed --allow-stale
// or --allow-unverified. Without this, a successful verify or restore gives no signal that
// the check was skipped: the shallow verify summary line already carries a Completeness of
// "UNVERIFIED" in this case, but that field is shared with two unrelated causes (a shallow,
// manifests-only verify, and an allowed signature failure) and prints a hint about
// 'verify --deep' that has nothing to do with the actual cause, and restore prints no
// completeness field at all. FreshnessResult.RollbackWarning is the one signal that is
// true precisely when a rollback, a chain anomaly or a below-pin index was found, whether or
// not the run was allowed to proceed, so it is what both commands key this warning on.
func warnIfRollbackOverridden(fresh format.FreshnessResult) {
	if !fresh.RollbackWarning {
		return
	}
	if fresh.Unchecked {
		// A check that could not RUN is not the same event as a check that ran and found a
		// stale run, and the two must not share a sentence. The reassurance in the message
		// below ("only the freshness guarantee was skipped") is true of a known-stale run and
		// false here: an absent RUNLOG or one whose signature does not verify is consistent
		// with someone having replaced the bucket, and the reader cannot tell that from an
		// operator who deleted the log. So this case gets its own line and no reassurance.
		//
		// The cause comes from fresh.Reason and is no longer a four-item list of the causes
		// this branch was written for. That list named an absent, unreadable, unparseable or
		// unsigned RUNLOG, and this branch also fires for an empty log, a run the log does not
		// carry, and an entry that disagrees with the signed root on downpipe, index or
		// prevRunId. Driven on an archive whose validly signed RUNLOG put the run at index 7
		// against the signed root's 1, all four named causes were false and the remedy sent
		// the operator to recover a RUNLOG that was intact.
		fmt.Fprintf(os.Stderr, "warning: this run's anti-rollback/freshness check COULD NOT BE RUN and was overridden by --allow-unverified-runlog or --allow-unverified: %s. Nothing was established about this run's recency, and a rolled-back or replaced bucket would look exactly like this. Re-check this run against a RUNLOG and signature from a copy you trust before you act on the outcome. See docs/RECOVER.md %q.\n", freshnessReason(fresh), "Freshness / rollback (exit 5)")
		return
	}
	if fresh.RunlogUntrusted {
		// The chain anomaly: the check RAN and the RUNLOG verified against the pinned signer, so
		// neither the sentence above nor the one below fits. The reassurance below ("only the
		// freshness guarantee was skipped") is true of a run that is merely old and false of a log
		// whose chain forks, and the sentence above would tell an operator the check could not run
		// when it ran and found something.
		fmt.Fprintf(os.Stderr, "warning: this run's anti-rollback/freshness check found the RUNLOG contradicts itself, and that was overridden by --allow-unverified-runlog or --allow-unverified: %s. The log verified against the pinned signer, so the contradiction means it was rewritten or hand-assembled rather than appended to by the engine, and which run is latest cannot be read from it. Compare it against a copy you trust before you act on the outcome. See docs/RECOVER.md %q.\n", freshnessReason(fresh), "Freshness / rollback (exit 5)")
		return
	}
	fmt.Fprintf(os.Stderr, "warning: this run's anti-rollback/freshness check did NOT pass and was overridden by --allow-stale, --allow-unverified-runlog or --allow-unverified: %s. The signature and manifests are still genuinely verified; only the freshness guarantee was skipped for this run. See docs/RECOVER.md %q.\n", freshnessReason(fresh), "Freshness / rollback (exit 5)")
}

// freshnessReason is the cause sentence the two warnings above interpolate. Reason is set
// at every return in the freshness path that raises RollbackWarning, so the fallback is
// unreachable through verify and restore; it exists because a warning whose middle clause
// silently became "warning: ... overridden by --allow-stale or --allow-unverified: ." on
// some future path would be worse than one that says it does not know.
func freshnessReason(fresh format.FreshnessResult) string {
	if fresh.Reason == "" {
		return "the reader recorded no reason, which is itself a fault worth reporting"
	}
	return fresh.Reason
}

// checkReceiptSigner reads and parses --receipt-signer BEFORE the run starts, so a mistyped path
// is reported as the usage error it is at the moment the operator can still fix it.
//
// WHAT WENT WRONG WITHOUT IT. The key was read only inside emitReceipt, which runs AFTER the whole
// verify or restore. Both commands emit the receipt before returning their own verdict, so the
// usage error REPLACED that verdict: a restore that found a tampered record and would have exited
// 4 exited 6 instead, and 6 says "fix your command line", not "this archive failed its hash
// check". The records had already been written by then. On a large archive the operator also
// waited out the entire run to be told about a flag that could have been checked in a millisecond.
//
// It is a fail-fast guard, not the authority: emitReceipt still reads and parses the file it
// signs with, so nothing here is trusted to have stayed true.
func checkReceiptSigner(path string) error {
	if path == "" {
		return nil
	}
	raw, err := readKeyFile(path, labelSignerPrivate)
	if err != nil {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("receipt signer: %w", err)}
	}
	if _, err := crypto.ParseSigner(raw); err != nil {
		return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("receipt signer: %w", err)}
	}
	return nil
}

// emitReceipt builds, optionally signs, and writes a restore/verify receipt. A path of
// "" skips emission; "-" writes to stderr so stdout stays clean for data sinks.
// valueVerified must be true only when the offline binary has hash-checked the written
// value against the signed manifest (SPEC.md 12.6): this is the case for the file and
// env sinks on a real apply, not for a dry run and not for a verify-only run.
func emitReceipt(r format.ReceiptSource, in format.ReceiptInput, valueVerified bool, path, signerKeyPath string) error {
	if path == "" {
		return nil
	}
	rcpt := format.BuildReceipt(r, in)
	rcpt.Target.ValueVerified = valueVerified
	if signerKeyPath != "" {
		raw, err := readKeyFile(signerKeyPath, labelSignerPrivate)
		if err != nil {
			return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("receipt signer: %w", err)}
		}
		signer, err := crypto.ParseSigner(raw)
		if err != nil {
			return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("receipt signer: %w", err)}
		}
		if err := rcpt.Sign(signer); err != nil {
			return err
		}
	}
	b, err := rcpt.Marshal()
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if path == "-" {
		_, err := os.Stderr.Write(b)
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func writeKeyFile(path, label string, raw []byte) error {
	line := label + " " + base64.RawURLEncoding.EncodeToString(raw) + "\n"
	// O_EXCL with 0600: create key material at owner-only permissions and refuse to
	// silently overwrite an existing key file (an existing break-glass key must not be
	// clobbered by a re-run).
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			// The refusal is DELIBERATE and it is about the path the operator gave, so it is a
			// usage error (6), exactly as recombine codes the identical O_EXCL refusal on its
			// --out. Uncoded, it exited 1, and the printed table defines 1 as "an I/O or
			// unexpected failure this tool did not otherwise classify": on a key ceremony that
			// told the operator something had gone wrong inside the tool at the moment the tool
			// had just done the right thing and protected an existing break-glass key.
			return &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("%s already exists and this refuses to overwrite key material: choose an empty --out directory, or move the existing files aside first if you are certain they are not needed", path)}
		}
		return fmt.Errorf("write key file %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("write key file %s: %w", path, err)
	}
	return nil
}

func readKeyFile(path, label string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, missingKeyFile(path, label, err)
	}
	key, err := parseKeyFileBytes(b, label)
	if err != nil {
		return nil, fmt.Errorf("%s is %v", path, err)
	}
	return key, nil
}

// missingReaderInputs is the usage error verify and restore raise when one of their three required
// inputs is absent. It names the ones actually missing and says where each comes from.
//
// The message it replaced listed all three every time and then offered keys --which, which helps only
// when the missing input is the run id. A holder of the printed recovery sheet who is missing
// signer.pub was told "--signer" and nothing else, and the sheet in their hand has a line reading
// "signer: edmldsa1:...", so the natural reading is that they already have it. They do not: the sheet
// carries a fingerprint and --signer wants a file that is neither on the sheet nor in the archive.
// Saying so at the moment of failure is the difference between finding the file and concluding the
// data is unrecoverable.
func missingReaderInputs(cmd, run string, identitySupplied bool, signerPath string, sourceSupplied bool) error {
	var missing []string
	if run == "" {
		missing = append(missing, "--run <runId>")
	}
	if !identitySupplied {
		missing = append(missing, "an identity (--identity <file>, or --share files with --envelope)")
	}
	if signerPath == "" {
		missing = append(missing, "--signer <file>")
	}
	if !sourceSupplied {
		missing = append(missing, "a source (--archive <dir>, --s3-endpoint <url> or --azure-endpoint <url>)")
	}
	msg := cmd + " needs " + strings.Join(missing, ", ") + "."
	if run == "" {
		msg += " To list the runs a source holds, which needs no run id and no keys, run: downpipe keys --which --archive <dir>."
	}
	if !identitySupplied {
		msg += " " + keyFileOrigin(labelIdentity) + "."
	}
	if signerPath == "" {
		msg += " " + keyFileOrigin(labelSignerPublic) + ". Check a candidate against your sheet with: downpipe keys --fingerprint --signer <file>."
	}
	return &format.ExitError{Code: format.ExitUsage, Err: errors.New(msg)}
}

// fingerprintPrefixes are the two forms a recovery sheet prints: a recipient fingerprint
// (SPEC.md 7.6.1) and a hybrid signer fingerprint (SPEC.md 11.4). A path that starts with one
// of them is not a path at all.
var fingerprintPrefixes = []string{"dpr1:", "edmldsa1:"}

// missingKeyFile turns a failed key-file read into something a person recovering from a printed
// sheet can act on, and it is the message that decides whether they get their data back.
//
// The default was the bare os error. A holder of the printed recovery sheet reads "--signer" on
// the sheet's own restore command, looks at the sheet, and finds "signer: edmldsa1:..." under a
// heading that says these values are safe to record here. Passing that to --signer produced
// "open edmldsa1:3f2a...: no such file or directory", which names the wrong problem entirely: it
// reads as a typo in a path rather than as "that is a fingerprint, and the file it fingerprints
// is a separate download you need to go and find". At that point the console is gone, there is no
// support channel, and the archive is intact and unreadable.
//
// So a value carrying a fingerprint prefix is called out as a fingerprint, and every missing key
// file says where that file comes from. A read failure that is not "does not exist" (a permission
// problem, a directory) is passed through untouched: it is a different problem and guessing at it
// would bury the real cause.
func missingKeyFile(path, label string, err error) error {
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	origin := keyFileOrigin(label)
	for _, p := range fingerprintPrefixes {
		if strings.HasPrefix(path, p) {
			return fmt.Errorf("%q is a fingerprint, not a file. %s. To check a file you already hold against the fingerprint on your sheet, run: downpipe keys --fingerprint", path, origin)
		}
	}
	return fmt.Errorf("%w. %s", err, origin)
}

// keyFileOrigin says where a recovery kit's key file came from, per label. The printed sheet
// names only identity.key, so the other two are the ones an operator is most likely not to have
// kept, and saying "it is a download from the key ceremony" is the difference between looking in
// the right place and concluding the data is gone.
func keyFileOrigin(label string) string {
	switch label {
	case labelSignerPublic:
		return "signer.pub is the operator signer PUBLIC key, a file the key ceremony downloaded into your recovery kit. It is not printed on the recovery sheet (the sheet carries only its fingerprint) and it is not in the archive, so it has to come from your kit"
	case labelRecipient:
		return "recipient.pub is the break-glass PUBLIC key, a file the key ceremony downloaded into your recovery kit. The recovery sheet carries only its fingerprint"
	case labelIdentity:
		return "identity.key is the break-glass PRIVATE key from your offline storage. If you hold it as custody shares instead, pass --envelope with M --share files rather than --identity"
	case labelSignerPrivate:
		return "the signer private key is held by the writing engine and is not part of a recovery kit"
	}
	return "check the path"
}

func usage() {
	fmt.Println(`downpipe recovers downpipe archives offline.

Usage:
  downpipe <command> [flags]

Commands:
  keygen    Generate a break-glass identity and a signer keypair
  inspect   Show a run's cleartext root manifest (no identity needed)
  keys      With --which, group runs by the recipient identity that opens them (no identity needed)
  verify    Verify a run end to end against an identity and a signer
  attest    Keyless: verify the signature, shard hashes and RUNLOG without an identity
  restore   Plan, and with --apply write, a run's records to a target
  prune     Plan, and with --apply delete, the runs your retention policy has superseded
  recombine Rebuild identity.key from custody artefacts: M share files (or bare
            emailed share bodies saved to files) plus the wrapped-identity envelope,
            or the wrapping-key file
  unseal-export  Open a sealed control-plane export offline with your recovery kit
  selftest  Build and recover a sample archive, end to end
  preflight Read-only deploy-time account checks (domains, Secrets Store headroom, plan, Logpush, R2)
  setup     Provision Cloudflare (Access, email note, secrets, bindings) on your machine
  init      Print the ordered least-privilege deploy runbook (print only; no live call)
  update    Print the scoped-elevate, deploy, revoke upgrade runbook (print only; no live call)
  version   Print the tool version

inspect, verify, attest and restore read from --archive <dir> or straight from the
destination the archive was written to. Two destination flag pairs, because there are two
wire protocols:

  --s3-endpoint <url> --s3-bucket <name>
      Any S3-compatible bucket: Cloudflare R2, Amazon S3, Google Cloud Storage (endpoint
      https://storage.googleapis.com with an HMAC interoperability key pair), Backblaze
      B2, Wasabi, MinIO. Credentials from AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.

  --azure-endpoint <url> --azure-container <name>
      Azure Blob Storage, which is not an S3-compatible store and is not reachable
      through --s3-endpoint at any value. Endpoint is the account's blob endpoint, for
      example https://myaccount.blob.core.windows.net. Credentials from AZURE_STORAGE_KEY
      (a storage account access key) or AZURE_STORAGE_SAS_TOKEN (a shared access
      signature); set AZURE_STORAGE_ACCOUNT as well only when the account name is not the
      endpoint's first label.

No credential is ever read from a flag, on either destination, so none reaches a shell
history or a process listing. verify and restore also take --run, --identity and --signer.

Every command that takes --identity also accepts the custody artefacts directly, for an
organisation holding the break-glass key as M-of-N shares rather than as one file:

  downpipe prune --archive <dir> --signer signer.pub --keep 30 \
    --share share-1.txt --share share-3.txt --share share-4.txt \
    --envelope wrapped-identity.txt

The shares are combined in memory, used for that command, and wiped. No complete copy of
the key is written anywhere, so the M-of-N control holds for the whole operation instead
of ending at the first recombine. Use the recombine command when you deliberately want a key
file on disk; use the flags above when you do not.

Exit codes, for a recovery script. This tool exists for the case where the platform is
unreachable, so the codes are listed here rather than only in the online documentation:

  0   verified and complete
  1   an I/O or unexpected failure this tool did not otherwise classify. Not a verdict on
      the archive's authenticity: read the message above, fix the underlying problem, and
      retry. An archive object that was ABSENT does not reliably land here; see 2 below.
  2   unverified: a missing, invalid or wrong-signer signature, or a failed recompute.
      Two causes of a 2 are NOT findings against the archive: an object that could not
      be read at all from a local --archive path (a local read failure carries too little
      signal to reclassify safely; a network destination has its own code, 11, and an
      absent per-record data segment has its own code, 13), and an --identity that is not
      one the run was sealed to. The tool names either one explicitly on the line after
      the error and says what to do. Absent such a line, treat a 2 as the hard failure
      described below.
  3   incomplete: verified coverage is below the run's declared record count
  4   a per-record plaintext hash mismatch
  5   stale: a rolled-back or forked RUNLOG, or a run below your --min-runlog-index pin
  6   a usage or input error
  7   preflight found failing account checks (the provisioner commands only)
  8   restored, but one or more records are incompleteness-marker placeholders, not live data
  9   custody integrity: the shares or envelope are wrong, so no key was recovered
  10  restored, but one or more records were NOT written: the target could not take them
  11  the destination could not be reached: a network or DNS failure, a refused
      connection, or the destination returned a 403/404/5xx before any bytes came back.
      Not a verdict on the archive: nothing about it is yet known. Check the endpoint,
      bucket and credentials, and retry.
  12  restored, but one or more D1 records carry a body format this release cannot render.
      The verified bytes were written unchanged and are NOT SQL, so the sqlite3 replay step
      does not apply to those files. Nothing is corrupt and nothing was lost; the record is
      named with the format label that reads it, and a downpipe release carrying that label
      renders it.
  13  incomplete: the run's signed manifests all verified, and one or more of the seg/ data
      objects they name are not in this copy of the archive. Nothing was retrieved for
      those records, so no signature, tag or hash failed. Fetch the named objects from
      another copy of the bucket, or accept that this copy is short of them. This code is
      returned only when EVERY per-record failure was an absent object; one altered record
      alongside them returns 2 or 4 instead.

  0 and 6 mean what they say. 1 and 11 are both worth a retry once the underlying problem
  is fixed, and differ in what is known: 1 is an I/O or internal fault this tool could not
  otherwise classify; 11 specifically means the destination refused the request or could
  not be reached before any bytes arrived, so the archive itself was never examined. 2 to
  5 are hard failures: stop and investigate, and never retry on a different key or file
  just to make the error go away. The one exception is the absent-local-object case noted
  under 2, which the tool calls out explicitly when it happens and which IS worth a retry
  once the path, the run id or the copy is corrected. 9 is a hard failure too, of the
  custody artefacts rather
  than the archive. 7, 8, 10 and 12 are ADVISORY, and 8, 10 and 12 all mean the restore
  ran and fell short of a clean full restore, so a script must not treat a non-zero exit
  as failure without reading which code it was. They are not ranked by their numbers: 10
  is the largest gap (records in the archive that are not on disk), then 8 (records on
  disk whose value is a placeholder), then 12 (records on disk, intact, that this release
  cannot render). The signed receipt carries the same shortfall as counts
  (incompleteMarkers, recordsUnwritten) for a script that would rather parse than branch
  on the exit status.

  13 is not ranked by its number either, and it is not an advisory: those records did not
  restore. It sits below 2 and 4, which always take precedence when any record in the same
  pass failed a check, and above 8, 10 and 12, because those three describe records that
  ARE in the archive while 13 describes records that are not. Against 2 the practical
  difference is the remedy: 13 says fetch the object from another copy, and 2 says the
  bytes you have were altered and this copy must not be trusted. The signed receipt
  carries the same finding as a count, danglingSegments, alongside a completeness of
  "incomplete".

attest needs neither --identity nor a written target: it verifies the root signature,
the shard hashes and the RUNLOG and prints the outcome. --signer is optional; without it
the attestation is keyless and reports the signature as unchecked while still catching a
tampered or missing shard and a malformed or absent signature. A plain keyless attest
with no --min-runlog-index only confirms the run is present in the RUNLOG, never its
freshness: a rolled-back RUNLOG that still lists the run passes. Pass --min-runlog-index
to also check the log's own claimed index against your pin; with --signer that check is
cryptographically anchored, exactly as verify/restore's pin already is, and a rolled-back
RUNLOG fails it (exit 5). Without --signer the same check still runs, but structurally
only: nothing anchors the RUNLOG bytes keyless, so it catches an accidentally stale or
wholesale-replayed bucket, not a targeted bucket-write adversary who also edits the
unsigned RUNLOG's stated index. For that guarantee, supply --signer.

restore is a dry run by default: it plans the writes and reports any conflict with
state already present in the target, writing nothing. Pass --apply to write. The
target is --sink file (one file per record under --out), --sink env (dotenv lines to
stdout), or --sink discard. The discard sink is a restorability check: it decrypts and
verifies every record through the full restore path and writes NOTHING, printing an
attestation (records, bytes, failures) and a restore digest with no plaintext in any
output. restore never overwrites existing target state.

setup provisions your Cloudflare account from this machine using your own API token,
read from CLOUDFLARE_API_TOKEN (with CLOUDFLARE_ACCOUNT_ID). The token stays on your
machine and is sent only to api.cloudflare.com; the vendor and the in-account console
never see it. setup is a dry run by default: it prints the ordered plan and creates
nothing. Pass --apply to provision. Secret values are read from the environment
(DOWNPIPE_SECRET_<NAME>), never from a flag, so they never appear in the plan.

init prints the full least-privilege deploy runbook in order: create a scoped,
short-lived deploy token (the exact Cloudflare scopes), provision the engine's
resources, deploy the engine and console, run the key ceremony, wire the first
source, verify readiness, and finally DELETE the scoped token. It is print-only:
it makes no Cloudflare call and creates nothing; you run the printed steps
yourself. The running engine holds no Cloudflare API token and reaches data only
through bindings. See https://github.com/downpipes-io/engine/blob/main/docs/CLOUDFLARE-PERMISSIONS.md.

update prints the ordered upgrade runbook for an already-deployed stack: confirm the
available version is signature-verified (pull-reviewed via /admin/updates and the
console; the vendor cannot push), RE-CREATE the same scoped, short-lived deploy token
(the same scopes init prints; see https://github.com/downpipes-io/engine/blob/main/docs/CLOUDFLARE-PERMISSIONS.md), deploy the
reviewed new version (engine and console), verify readiness (ready: true), and finally
DELETE the scoped token again so the engine never holds a standing deploy credential. It
is print-only: it makes no Cloudflare call and changes nothing; you run the printed steps
yourself. See https://github.com/downpipes-io/engine/blob/main/docs/UPDATES.md.`)
}
