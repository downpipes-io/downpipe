package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
)

// verify-report checks the signature on an assurance report the engine generated (the restore-tests,
// SLA, immutability, posture, evidence-pack and change-records reports). The engine signs each report
// with the operator signer, the same key pair that signs the archive, and this command verifies the
// report JSON against that signer's public key file. It is offline: it reads two local files, or the
// report from standard input, and makes no network call.
//
// The verdict is the reader's exit-code contract: 0 when both signature halves verify, 2 when the
// report is unsigned, altered, damaged or signed by another signer, and 6 when the input is not a
// report JSON or a flag or key file is wrong. format.VerifyReport holds the rules.

// maxReportBytes bounds the report read, so a wrong --report (a disk image, a log) fails quickly
// instead of filling memory.
const maxReportBytes = 64 << 20

func cmdVerifyReport(args []string) error {
	fs := flag.NewFlagSet("verify-report", flag.ContinueOnError)
	reportPath := fs.String("report", "", "the report JSON: the body of GET /admin/reports/<kind> (for the evidence pack, GET /admin/reports/evidence-pack?framework=<id>), or the console's View JSON saved to a file. - reads standard input")
	signerPath := fs.String("signer", "", "your signer public-key file (signer.pub from the key ceremony or your recovery kit)")
	pin := fs.String("signer-fingerprint", "", "optional: the signer fingerprint (edmldsa1:...) printed on your recovery sheet. The --signer file must have this fingerprint")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return usageErr(fmt.Sprintf("verify-report takes no positional arguments (got %q); name the report with --report", fs.Arg(0)))
	}
	if *reportPath == "" {
		return usageErr("verify-report needs --report <file>, the report JSON (or - for standard input)")
	}
	if *signerPath == "" {
		msg := "verify-report needs --signer <file>, the signer.pub public-key file"
		if *pin != "" {
			msg += ". A fingerprint identifies a signer but cannot verify a signature, so --signer-fingerprint is a check on the --signer file, not a replacement for it"
		}
		return usageErr(msg)
	}

	verifier, err := loadSignerFile(*signerPath)
	if err != nil {
		return err
	}
	fingerprint := crypto.SignerFingerprint(verifier)
	if *pin != "" {
		want, perr := format.ParseSignerFingerprint(*pin)
		if perr != nil {
			return perr
		}
		if !format.SameSignerFingerprint(fingerprint, want) {
			return usageErr(fmt.Sprintf("the --signer file %s has fingerprint %s, which is not the --signer-fingerprint you gave (%s). One of the two is from a different key ceremony. Check which signer your recovery sheet names", *signerPath, fingerprint, want))
		}
	}

	raw, err := readReportInput(*reportPath)
	if err != nil {
		return err
	}
	got, err := format.VerifyReport(raw, verifier)
	if err != nil {
		return fmt.Errorf("%w\nsigner: %s", err, fingerprint)
	}
	fmt.Fprintf(os.Stderr, "verify-report: VERIFIED. kind=%s generatedAt=%s period=%s\n", got.Kind, got.GeneratedAt, describeReportPeriod(got))
	fmt.Fprintf(os.Stderr, "signer: %s\n", fingerprint)
	fmt.Fprintln(os.Stderr, "Both signature halves (Ed25519 and ML-DSA-87) verified over the canonical {kind, generatedAt, period, data}. Compare the signer fingerprint with the one on your recovery sheet.")
	return nil
}

// readReportInput reads the report file, or standard input for "-", within maxReportBytes.
func readReportInput(path string) ([]byte, error) {
	var r io.Reader
	name := path
	if path == "-" {
		r, name = os.Stdin, "standard input"
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("reading the report named by --report: %w", err)}
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxReportBytes+1))
	if err != nil {
		return nil, &format.ExitError{Code: format.ExitUsage, Err: fmt.Errorf("reading the report from %s: %w", name, err)}
	}
	if len(raw) > maxReportBytes {
		return nil, &format.ExitError{Code: format.ExitUsage, Err: errors.New("the file named by --report is larger than 64 MiB, the most verify-report reads, so it is not a report JSON")}
	}
	return raw, nil
}

// describeReportPeriod prints a report window as epoch seconds and UTC times, or point-in-time.
func describeReportPeriod(r *format.VerifiedReport) string {
	p := r.Period
	switch {
	case r.PointInTime:
		return "point-in-time"
	case p == nil:
		return "not-a-window"
	}
	utc := func(s int64) string { return time.Unix(s, 0).UTC().Format(time.RFC3339) }
	return fmt.Sprintf("%d..%d (%s to %s)", p.FromSeconds, p.ToSeconds, utc(p.FromSeconds), utc(p.ToSeconds))
}
