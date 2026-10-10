package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/restore"
)

// AN ABSENT SEGMENT AND AN ALTERED ONE ARE OPPOSITE FINDINGS AND USED TO SHARE EVERY WORD.
//
// Driven against a real archive from the selftest writer, copied twice: one copy with its
// single seg object deleted, the other with a byte of that same object flipped. `verify
// --deep` printed the same two lines over both, character for character, and exited 2 for
// both:
//
//	UNVERIFIED: run ...; signature=valid completeness=UNVERIFIED (1 of 1 record(s) failed
//	integrity) bundle=not-checked
//	downpipe: unverified: signature=valid completeness=UNVERIFIED (1 of 1 record(s) failed
//	integrity)
//
// Both also printed "discard sink: 1 record(s) did NOT decrypt or did not match their signed
// hash", which for the deleted segment names a check the bytes were never put to, because
// there were no bytes. And neither printed the absent-object hint: it fired on a top-level
// read failure and not on a per-record segment read, so the one read failure that matters
// most reached the operator with no next step.
//
// The remedies are opposite. An absent segment means fetch the object from another copy of
// the bucket, or accept that this copy is incomplete. An altered segment means the bytes were
// changed and this copy must not be trusted. The signed receipt had drawn the line already
// (danglingSegments 1 against the deleted segment, 0 against the flipped byte); the exit
// status and the printed line now agree with it.

// alteredArchive builds a real archive and flips a byte well inside its single seg object, so
// the object is present and the same length and fails its authenticated decrypt. It is the
// exact counterpart of danglingArchive, which deletes that same object, and the two are the
// pair this file exists to keep apart.
func alteredArchive(t *testing.T) (dir, runID, idPath, signerPath string) {
	t.Helper()
	dir = t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("this record's segment is about to be altered"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath = writeArchiveKeys(t, dir, identity, verifier)

	segs, err := filepath.Glob(filepath.Join(dir, "seg", "*", "*.seg"))
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 {
		t.Fatalf("fixture control: the selftest archive should hold exactly 1 segment, got %d", len(segs))
	}
	sealed, err := os.ReadFile(segs[0])
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)/2] ^= 0xff
	if err := os.WriteFile(segs[0], sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, runID, idPath, signerPath
}

// TestAbsentSegmentAndAlteredSegmentDoNotShareAVerdict drives the two commands that read
// every segment against the two fixtures, and asserts on the exit status a recovery script
// branches on AND on the sentences the operator reads. Both halves are needed: the codes
// could be split while the prose still told everyone their data had failed integrity, and the
// prose could be split while a script still could not tell the two apart.
func TestAbsentSegmentAndAlteredSegmentDoNotShareAVerdict(t *testing.T) {
	silenceOutput(t)
	absentDir, absentRun, absentID, absentSigner := danglingArchive(t)
	alteredDir, alteredRun, alteredID, alteredSigner := alteredArchive(t)

	// absentSays and alteredSays are the sentence each command reaches for in each state.
	// They are stated per command rather than shared, because the two commands close with
	// different sentences and a shared phrase would be vacuous for one of them: "failed
	// integrity" belongs to verify's completeness line and restore never prints it, so
	// asserting its absence from restore's output would assert nothing at all. Each output is
	// then checked against BOTH, so the sentence for one state has to be present and the
	// sentence for the other has to be gone.
	commands := []struct {
		name        string
		verb        []string
		absentSays  string
		alteredSays string
	}{
		{
			name:        "verify --deep",
			verb:        []string{"verify", "--deep"},
			absentSays:  "completeness=incomplete",
			alteredSays: "failed integrity",
		},
		{
			name:        "restore --apply to a discard sink",
			verb:        []string{"restore", "--sink", "discard", "--apply"},
			absentSays:  "could not be restored from this archive",
			alteredSays: "failed to restore",
		},
	}
	for _, c := range commands {
		t.Run(c.name, func(t *testing.T) {
			drive := func(dir, runID, id, signer string) (int, string) {
				args := append(append([]string{}, c.verb...),
					"--archive", dir, "--run", runID, "--identity", id, "--signer", signer,
					"--acknowledge-no-rollback-pin")
				var code int
				out := captureStderr(t, func() { code = run(args) })
				return code, out
			}
			absentCode, absentOut := drive(absentDir, absentRun, absentID, absentSigner)
			alteredCode, alteredOut := drive(alteredDir, alteredRun, alteredID, alteredSigner)

			// The status a DR script branches on.
			if absentCode != format.ExitDangling {
				t.Errorf("%s over an archive whose segment is GONE exited %d, want %d. A missing object is not a finding against the archive, and the code is what a recovery script reads:\n%s", c.name, absentCode, format.ExitDangling, absentOut)
			}
			if alteredCode != format.ExitUnverified {
				t.Errorf("%s over an archive whose segment was ALTERED exited %d, want %d. An authenticated decrypt that refused is the tamper verdict and must keep it:\n%s", c.name, alteredCode, format.ExitUnverified, alteredOut)
			}
			// Stated separately from the two above, because that is the property: a later
			// change that mapped both onto one new code would satisfy neither of the pins
			// above and this says why it must not.
			if absentCode == alteredCode {
				t.Errorf("%s gave an absent segment and an altered segment the same exit status (%d), so a recovery script cannot tell 'fetch this object from another copy' from 'these bytes were altered, do not trust this copy'", c.name, absentCode)
			}

			// What the operator reads about the archive that is merely incomplete.
			if !strings.Contains(absentOut, c.absentSays) {
				t.Errorf("%s over an archive whose segment is GONE never says %q, so nothing on screen distinguishes it from an altered one:\n%s", c.name, c.absentSays, absentOut)
			}
			if strings.Contains(absentOut, c.alteredSays) {
				t.Errorf("%s told an operator whose segment is merely absent that %q. Nothing failed a check; nothing was retrieved to check:\n%s", c.name, c.alteredSays, absentOut)
			}
			if !strings.Contains(absentOut, "segment object(s)") {
				t.Errorf("%s did not name what is actually missing, so the operator cannot tell how much of the archive is short:\n%s", c.name, absentOut)
			}
			if !strings.Contains(absentOut, "No signature, tag or hash failed") {
				t.Errorf("%s did not say that nothing failed a check, which is the fact that sends the operator to another copy rather than away from it:\n%s", c.name, absentOut)
			}
			if strings.Contains(absentOut, "did NOT decrypt or did not match their signed hash") {
				t.Errorf("%s named a check the bytes were never put to: the object was not fetched, so nothing was offered to the decrypt or to the hash:\n%s", c.name, absentOut)
			}
			if !strings.Contains(absentOut, "an object this run needs was not found at all") {
				t.Errorf("%s printed no absent-object hint on a per-record segment read, so the operator is left with a nested \"no such file or directory\" and no next step:\n%s", c.name, absentOut)
			}
			// The hint's middle sentence is a claim ABOUT the number, and it has two
			// spellings. Every other code it fires for was assigned by some other check and
			// merely kept through the read failure, which is what "the code that read
			// failure kept" says. 13 was assigned by this exact finding, so that sentence
			// is false of it. This survived the first mutation round: deleting the
			// 13-specific branch left the whole suite green, because nothing looked at what
			// the sentence told the operator.
			if strings.Contains(absentOut, "is the code that read failure kept") {
				t.Errorf("%s told the operator that 13 was a code some other check assigned and this read failure merely kept. It is the code for this finding:\n%s", c.name, absentOut)
			}
			if !strings.Contains(absentOut, "is the code for exactly this") {
				t.Errorf("%s did not say that the exit status names this finding, leaving the operator to work out whether 13 is a verdict or a leftover:\n%s", c.name, absentOut)
			}

			// And what the operator reads about the archive that really was altered, so the
			// fix above cannot have been made by softening both.
			if !strings.Contains(alteredOut, c.alteredSays) {
				t.Errorf("%s stopped saying %q over an altered segment, which is exactly what happened to it:\n%s", c.name, c.alteredSays, alteredOut)
			}
			if strings.Contains(alteredOut, c.absentSays) {
				t.Errorf("%s described an altered segment as %q, which sends the operator looking for a copy of an object that is right there and was changed:\n%s", c.name, c.absentSays, alteredOut)
			}
			if !strings.Contains(alteredOut, "did NOT decrypt or did not match their signed hash") {
				t.Errorf("%s stopped naming the check an altered segment actually failed:\n%s", c.name, alteredOut)
			}
			if strings.Contains(alteredOut, "an object this run needs was not found at all") {
				t.Errorf("%s offered the absent-object hint over an archive whose object was present and failed its authentication tag, which reads as an invitation to retry a tamper finding:\n%s", c.name, alteredOut)
			}
			if strings.Contains(alteredOut, "No signature, tag or hash failed") {
				t.Errorf("%s said nothing failed a check over a run in which an authentication tag did:\n%s", c.name, alteredOut)
			}
		})
	}
}

// TestVerifySummaryLineStopsCallingAnAbsentSegmentUnverified pins the two words the operator
// actually acts on, which live on separate lines and were computed separately until they were
// tied together. "unverified" is this tool's tamper word, and it was the banner AND the
// closing word over a run in which nothing had been found unverified by anything.
func TestVerifySummaryLineStopsCallingAnAbsentSegmentUnverified(t *testing.T) {
	silenceOutput(t)
	dir, runID, idPath, signerPath := danglingArchive(t)
	var code int
	out := captureStderr(t, func() {
		code = run([]string{"verify", "--deep", "--archive", dir, "--run", runID,
			"--identity", idPath, "--signer", signerPath, "--acknowledge-no-rollback-pin"})
	})
	if code != format.ExitDangling {
		t.Fatalf("control: the fixture must reach the dangling verdict, got exit %d:\n%s", code, out)
	}
	if strings.Contains(out, "UNVERIFIED:") {
		t.Errorf("the summary banner still shouts UNVERIFIED over a run whose manifests all verified and whose bytes all checked out:\n%s", out)
	}
	if !strings.Contains(out, "INCOMPLETE:") {
		t.Errorf("the summary banner does not say what the run actually is, which is incomplete:\n%s", out)
	}
	if !strings.Contains(out, "completeness=incomplete") {
		t.Errorf("the completeness field must carry the third member of the SPEC.md 8.5 enum here, not the tamper one:\n%s", out)
	}
	// The count of OBJECTS, asserted as part of the completeness phrase itself rather than
	// anywhere in the output. A looser assertion survived the first mutation round: the
	// discard sink prints "segment object(s)" on its own line, so the completeness phrase
	// could drop the count entirely and every check stayed green. The object count is what
	// the operator has to go and find, and it differs from the record count whenever records
	// share a segment by content address.
	if !strings.Contains(out, "completeness=incomplete (1 of 1 record(s) could not be read: 1 segment object(s)") {
		t.Errorf("the completeness phrase does not name how many objects are missing, which is the number the operator has to act on:\n%s", out)
	}
	if strings.Contains(out, "downpipe: unverified:") {
		t.Errorf("the closing line, which is the line an operator acts on, still calls the run unverified:\n%s", out)
	}
	if !strings.Contains(out, "downpipe: incomplete:") {
		t.Errorf("the closing line does not carry the same verdict as the banner above it:\n%s", out)
	}
}

// TestASignatureVerdictBesideAnAbsentSegmentKeepsTheSignatureVerdict drives the precedence
// rule at the OTHER site, where the run itself already reached a verdict before a segment was
// ever fetched. perRecordExit decides between the per-record failures; this decides between
// those and the run's own outcome, and the two rules live apart.
//
// It was a mutant that survived the first round. The site folds the deep drill's status into
// the run's with a running maximum, and 13 is numerically larger than 2 while being a milder
// finding, so the plain comparison handed an operator whose root signature does not verify an
// exit that says "go and fetch a copy of this object". The signature is the reason to stop.
func TestASignatureVerdictBesideAnAbsentSegmentKeepsTheSignatureVerdict(t *testing.T) {
	silenceOutput(t)
	dir, runID, idPath, signerPath := danglingArchive(t)
	sig := filepath.Join(dir, "run", runID, "root.manifest.json.sig")
	if _, err := os.Stat(sig); err != nil {
		t.Fatalf("fixture control: the archive must carry a root signature to break: %v", err)
	}
	if err := os.WriteFile(sig, []byte("not a signature at all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	out := captureStderr(t, func() {
		// --allow-unverified is what lets the run open at all with a broken signature, so
		// the deep drill runs and both findings are in play at once. Without it the reader
		// refuses at the signature gate and the segment is never reached.
		code = run([]string{"verify", "--deep", "--allow-unverified", "--archive", dir, "--run", runID,
			"--identity", idPath, "--signer", signerPath, "--acknowledge-no-rollback-pin"})
	})
	if code != format.ExitUnverified {
		t.Errorf("a run whose root signature does not verify AND whose segment is absent exited %d, want %d. The signature is the reason to stop, and %d would send the operator looking for a copy of an object while the archive it came from cannot be trusted:\n%s", code, format.ExitUnverified, format.ExitDangling, out)
	}
	// The control: the fixture really is carrying both findings at once, so the assertion
	// above is about precedence and not about an archive that only ever had one problem.
	if !strings.Contains(out, "signature=invalid") && !strings.Contains(out, "signature=wrong-signer") {
		t.Errorf("control: the signature was meant to be broken:\n%s", out)
	}
	if !strings.Contains(out, "an object this run needs was not found at all") {
		t.Errorf("control: the segment was meant to be absent, and the operator is still told so even though the verdict is the signature's:\n%s", out)
	}
}

// TestPerRecordExitGivesPrecedenceToARealIntegrityFinding is the rule a table over whole
// archives cannot reach cheaply: what happens when ONE pass holds both kinds of failure. The
// milder verdict must never swallow the harder one, because a script reading 13 would go
// looking for a copy of an object while a record it already holds has been altered.
func TestPerRecordExitGivesPrecedenceToARealIntegrityFinding(t *testing.T) {
	absent := func(object string) restore.RecordFailure {
		err := &format.SegmentReadError{Object: object, Err: fmt.Errorf("read object %s: %w", object, fs.ErrNotExist)}
		return restore.RecordFailure{Name: "absent-" + object, Err: err}
	}
	coded := func(code int, msg string) restore.RecordFailure {
		return restore.RecordFailure{Name: msg, Err: &format.ExitError{Code: code, Err: errors.New(msg)}}
	}
	cases := []struct {
		name          string
		failed        []restore.RecordFailure
		integrityExit int
		want          int
	}{
		{"every failure was an absent segment", []restore.RecordFailure{absent("seg/aa/aaaa.seg")}, format.ExitUnverified, format.ExitDangling},
		{"two records, two absent segments", []restore.RecordFailure{absent("seg/aa/aaaa.seg"), absent("seg/bb/bbbb.seg")}, format.ExitUnverified, format.ExitDangling},
		{
			name:          "one absent segment beside one failed authentication tag",
			failed:        []restore.RecordFailure{absent("seg/aa/aaaa.seg"), coded(format.ExitUnverified, "chunk 0 authentication failed")},
			integrityExit: format.ExitUnverified,
			want:          format.ExitUnverified,
		},
		{
			name:          "one absent segment beside one plaintext hash mismatch",
			failed:        []restore.RecordFailure{absent("seg/aa/aaaa.seg"), coded(format.ExitPlaintext, "failed its plaintext hash check")},
			integrityExit: format.ExitPlaintext,
			want:          format.ExitPlaintext,
		},
		{"only an altered segment", []restore.RecordFailure{coded(format.ExitUnverified, "chunk 0 authentication failed")}, format.ExitUnverified, format.ExitUnverified},
		{
			name:   "an absent object that is not a segment read keeps the generic status",
			failed: []restore.RecordFailure{{Name: "shard", Err: fmt.Errorf("read shard s0: %w", fs.ErrNotExist)}},
			want:   exitUncoded,
		},
		{
			// A network destination that answered 404 keeps ExitUnreachable, and this must
			// not quietly take it over. internal/source's S3Store reports a non-2xx as an
			// unreachable error and deliberately does NOT wrap fs.ErrNotExist, because a
			// 404 from a bucket says as much about the endpoint and the credentials as
			// about the object. ExitDangling is the verdict for a read that was ANSWERED
			// with the object's absence, so the two stay apart at the boundary
			// ExitUnreachable's own doc draws.
			name: "a destination that refused the segment read keeps its unreachable status",
			failed: []restore.RecordFailure{{Name: "a", Err: &format.ExitError{
				Code: format.ExitUnreachable,
				Err:  &format.SegmentReadError{Object: "seg/aa/aaaa.seg", Err: errors.New("GET seg/aa/aaaa.seg: status 404")},
			}}},
			integrityExit: format.ExitUnreachable,
			want:          format.ExitUnreachable,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := &restore.Result{Failed: tc.failed, IntegrityExit: tc.integrityExit}
			if got := perRecordExit(res); got != tc.want {
				t.Errorf("perRecordExit = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestAbsentObjectHintIsOfferedWheneverAnObjectWasAbsent covers the half the verdict rule
// deliberately does not: the hint is guidance and not a verdict, so a pass holding one absent
// segment beside one altered one still exits on the tamper finding AND still tells the
// operator that part of what they are looking at is a missing object.
func TestAbsentObjectHintIsOfferedWheneverAnObjectWasAbsent(t *testing.T) {
	absent := restore.RecordFailure{Name: "a", Err: &format.SegmentReadError{
		Object: "seg/aa/aaaa.seg",
		Err:    fmt.Errorf("read object seg/aa/aaaa.seg: %w", fs.ErrNotExist),
	}}
	altered := restore.RecordFailure{Name: "b", Err: &format.ExitError{Code: format.ExitUnverified, Err: errors.New("chunk 0 authentication failed")}}
	mixed := &restore.Result{Failed: []restore.RecordFailure{absent, altered}, IntegrityExit: format.ExitUnverified}

	if got := perRecordExit(mixed); got != format.ExitUnverified {
		t.Errorf("a mixed pass must exit on the tamper finding, got %d", got)
	}
	if !errors.Is(tagAbsentObject(mixed, errors.New("aggregate")), fs.ErrNotExist) {
		t.Error("a mixed pass carries an absent object, so the aggregate must still reach the hint: the operator needs to know part of this is a missing file even though the verdict is a tamper one")
	}
	onlyAltered := &restore.Result{Failed: []restore.RecordFailure{altered}, IntegrityExit: format.ExitUnverified}
	if errors.Is(tagAbsentObject(onlyAltered, errors.New("aggregate")), fs.ErrNotExist) {
		t.Error("a pass with no absent object must not be tagged as one: the hint would soften a genuine integrity verdict")
	}
}

// TestHelpTellsAScriptWhenExitDanglingIsNotReturned. TestHelpListsEveryExitCode already
// refuses a code the help does not describe, and a description is not the same as a contract:
// the load-bearing part of a new code is the boundary, because a script that reads 13 as
// "nothing is wrong with any record" would be wrong the moment one record was altered too.
// The numbers are not an ordering, so the ranking is stated as well.
func TestHelpTellsAScriptWhenExitDanglingIsNotReturned(t *testing.T) {
	help := captureUsage(t)
	line := exitCodeLine(help, format.ExitDangling)
	if line == "" {
		t.Fatalf("the help does not list exit %d at all", format.ExitDangling)
	}
	// Matched against the help with its line wrapping collapsed, so a sentence that is true
	// and merely folded across two lines is not read as missing.
	flat := strings.Join(strings.Fields(help), " ")
	for _, want := range []string{
		"EVERY per-record failure was an absent object",
		"one altered record alongside them returns 2 or 4",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("the help does not state the boundary a script needs (%q), so a reader can only guess when 13 is returned", want)
		}
	}
	if !strings.Contains(flat, "13 is not ranked by its number") {
		t.Error("the help ranks the other codes explicitly and says the numbers are not an ordering; a new code that leaves its own place unstated is the one a script will misplace")
	}
}

// captureUsage runs usage() with stdout redirected and returns what it printed.
func captureUsage(t *testing.T) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	usage()
	os.Stdout = orig
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// TestRecoverGuideDescribesEveryExitCode. The help has had a gate reading the format
// package's own source since ExitCustody was found to be returned and undocumented, and
// docs/RECOVER.md is the surface the same argument applies to hardest: it is the guide a
// customer opens when the platform is unreachable, it ships INSIDE the archive, and it is
// where a code they are staring at either is explained or is not.
//
// The codes come from the parsed source rather than a list written here, for the reason that
// gate records: a hand list repeats the failure the day someone adds a code and does not
// think of the document.
func TestRecoverGuideDescribesEveryExitCode(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "docs", "RECOVER.md"))
	if err != nil {
		t.Fatalf("read the recovery guide: %v", err)
	}
	const heading = "## Reading the result"
	start := strings.Index(string(body), heading)
	if start < 0 {
		t.Fatalf("the recovery guide has no %q section at all, so nothing below is checking anything", heading)
	}
	rest := string(body)[start+len(heading):]
	if next := strings.Index(rest, "\n## "); next > 0 {
		rest = rest[:next]
	}
	codes := declaredExitCodesFromFormat(t)
	if len(codes) < 12 {
		t.Fatalf("found only %d exit codes in the format package; the scan has probably stopped seeing them", len(codes))
	}
	for name, code := range codes {
		if !strings.Contains(rest, fmt.Sprintf("`%d`", code)) {
			t.Errorf("the recovery guide's result section never mentions exit %d (%s). It ships inside the archive and is read when nothing else is available, so a code it does not explain is a code nobody can act on", code, name)
		}
	}
	// The section has to say what to DO about 13, not merely that it exists, because the
	// remedy is the whole reason it is not a 2.
	for _, want := range []string{
		"fetch the named objects from another copy",
		"EVERY per-record failure was an absent object",
	} {
		if !strings.Contains(strings.Join(strings.Fields(rest), " "), want) {
			t.Errorf("the recovery guide does not tell a recoverer %q, which is the difference between 13 and 2", want)
		}
	}
}
