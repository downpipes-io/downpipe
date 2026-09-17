package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
)

// THE FRESHNESS SIGNAL WAS INVERTED BY SEVERITY.
//
// CheckFreshness returned a bare FreshnessResult{} from every one of its early returns,
// and checkFreshness did the same for both of its store reads. RollbackWarning is the ONE
// field that warnIfRollbackOverridden and the signed receipt both key on, so the worse the
// fault, the quieter the tool got:
//
//   - a tampered _RECOVERY/RUNLOG.sig under --allow-stale: exit 0, no warning, receipt
//     rollbackWarning false
//   - _RECOVERY/RUNLOG deleted entirely: byte-identical, exit 0, no warning, false
//   - the SAME archive merely below a --min-runlog-index pin, the least severe of the
//     three: warning printed, rollbackWarning true
//
// All three were driven on real archives before the fix. The two severe cases now set both
// RollbackWarning and Unchecked, and Unchecked gets its own warning, because "only the
// freshness guarantee was skipped for this run" is true of a known-stale run and false of
// a RUNLOG that may have been replaced.
//
// Every assertion here is on the WARNING TEXT and the RECEIPT, never on the exit code. The
// exit code is 0 before and after in all three cases, which is correct: the acknowledgement
// is the operator saying "proceed anyway". A test that asserted on the exit code would have
// been green throughout the defect and green throughout the fix.
//
// THE ACKNOWLEDGEMENT EACH CASE PASSES IS NOT THE SAME ONE ANY MORE. The two severe cases
// used to be driven with --allow-stale, and asserting exit 0 there was this file stating, as
// a requirement, that an age word opens an archive whose RUNLOG signature does not verify.
// They now pass --allow-unverified-runlog; the below-pin control still passes --allow-stale,
// so the pair still proves the tool measures rather than shouting at everything.

// freshnessFixture builds a real archive and returns it with its key paths.
func freshnessFixture(t *testing.T) (dir, runID, idPath, signerPath string) {
	t.Helper()
	dir = t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("freshness under a broken runlog"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath = writeArchiveKeys(t, dir, identity, verifier)
	return dir, runID, idPath, signerPath
}

// tamperRunlogSignature flips a byte inside the detached RUNLOG signature, leaving a
// well-formed base64url signature that does not verify. This is the shape a bucket-write
// adversary leaves, and it is the case the reader was quietest about.
func tamperRunlogSignature(t *testing.T, dir string) {
	t.Helper()
	p := filepath.Join(dir, "_RECOVERY", "RUNLOG.sig")
	text, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(text)))
	if err != nil {
		t.Fatalf("decode runlog signature: %v", err)
	}
	raw[len(raw)/2] ^= 0xff
	if err := os.WriteFile(p, []byte(base64.RawURLEncoding.EncodeToString(raw)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestUnrunnableFreshnessCheckIsLoudAndRecorded drives the three states side by side and
// asserts that the two severe ones are at least as loud as the benign one. The below-pin
// case is the control: it is what the tool always got right, and without it a fix that
// simply warned on everything would be indistinguishable from one that measures.
func TestUnrunnableFreshnessCheckIsLoudAndRecorded(t *testing.T) {
	cases := []struct {
		name string
		// breakIt mutates the archive into the state under test; nil leaves it intact.
		breakIt func(t *testing.T, dir string)
		extra   []string
		// wantChecked is whether the freshness check could be RUN at all.
		wantChecked bool
		wantWarning bool
	}{
		{
			name:        "tampered RUNLOG signature",
			breakIt:     tamperRunlogSignature,
			extra:       []string{"--allow-unverified-runlog"},
			wantChecked: false,
			wantWarning: true,
		},
		{
			name: "RUNLOG absent",
			breakIt: func(t *testing.T, dir string) {
				if err := os.Remove(filepath.Join(dir, "_RECOVERY", "RUNLOG")); err != nil {
					t.Fatal(err)
				}
			},
			extra:       []string{"--allow-unverified-runlog"},
			wantChecked: false,
			wantWarning: true,
		},
		{
			name:        "below the pin, the check RAN and found a problem",
			breakIt:     nil,
			extra:       []string{"--allow-stale", "--min-runlog-index", "99"},
			wantChecked: true,
			wantWarning: true,
		},
		{
			name:        "intact archive, the check ran and passed",
			breakIt:     nil,
			extra:       []string{"--acknowledge-no-rollback-pin"},
			wantChecked: true,
			wantWarning: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, runID, idPath, signerPath := freshnessFixture(t)
			if tc.breakIt != nil {
				tc.breakIt(t, dir)
			}
			out := filepath.Join(t.TempDir(), "r.json")
			args := append([]string{
				"verify", "--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath,
				"--receipt", out,
			}, tc.extra...)
			var code int
			_, stderr := captureOutput(t, func() { code = run(args) })

			// Recorded, not asserted as the finding: the exit code is 0 in all four cases,
			// before and after this change. --allow-stale is the operator overriding the
			// gate, so 0 is right; the defect and the fix live entirely in what the tool
			// says while exiting 0.
			if code != 0 {
				t.Fatalf("control: %s = %d, want 0 (all four states exit 0 by design)", tc.name, code)
			}

			warned := strings.Contains(stderr, "anti-rollback/freshness check")
			if warned != tc.wantWarning {
				t.Errorf("anti-rollback override warning printed = %v, want %v\nstderr:\n%s", warned, tc.wantWarning, stderr)
			}
			if tc.wantWarning && !tc.wantChecked {
				if !strings.Contains(stderr, "COULD NOT BE RUN") {
					t.Errorf("a check that could not run must say so, not borrow the stale-run sentence:\n%s", stderr)
				}
				if strings.Contains(stderr, "only the freshness guarantee was skipped") {
					t.Errorf("the stale-run reassurance is false when the RUNLOG may have been replaced:\n%s", stderr)
				}
			}
			if tc.wantWarning && tc.wantChecked && !strings.Contains(stderr, "did NOT pass") {
				t.Errorf("a check that ran and found a problem must keep its own wording:\n%s", stderr)
			}

			rcpt := readReceiptRaw(t, out)
			fresh, ok := rcpt["freshness"].(map[string]any)
			if !ok {
				t.Fatalf("receipt has no freshness object:\n%v", rcpt)
			}
			if fresh["checked"] != tc.wantChecked {
				t.Errorf("receipt freshness.checked = %v, want %v:\n%v", fresh["checked"], tc.wantChecked, fresh)
			}
			// rollbackWarning must be true whenever the check did not pass, INCLUDING when
			// it could not run. This is the assertion the whole item turns on.
			if fresh["rollbackWarning"] != tc.wantWarning {
				t.Errorf("receipt freshness.rollbackWarning = %v, want %v:\n%v", fresh["rollbackWarning"], tc.wantWarning, fresh)
			}
		})
	}
}

// TestUncheckedFreshnessIsNotAPassAtEveryEarlyReturn covers the freshness path's early
// returns directly, because the CLI reaches only two of them and one bare zero value left
// behind is how this defect returns. Each input is a different reason the check cannot run.
func TestUncheckedFreshnessIsNotAPassAtEveryEarlyReturn(t *testing.T) {
	dir, runID, _, signerPath := freshnessFixture(t)
	signerBytes, err := readKeyFile(signerPath, labelSignerPublic)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := crypto.ParseVerifier(signerBytes)
	if err != nil {
		t.Fatal(err)
	}
	rootBytes, err := os.ReadFile(filepath.Join(dir, "run", runID, "root.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := format.ParseRoot(rootBytes)
	if err != nil {
		t.Fatal(err)
	}
	goodLog, err := os.ReadFile(filepath.Join(dir, "_RECOVERY", "RUNLOG"))
	if err != nil {
		t.Fatal(err)
	}
	goodSig, err := os.ReadFile(filepath.Join(dir, "_RECOVERY", "RUNLOG.sig"))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		runlog  []byte
		sigText []byte
		runID   string
	}{
		{"undecodable signature", goodLog, []byte("not base64url!!"), runID},
		{"signature does not verify", goodLog, []byte("AAAA"), runID},
		{"runlog does not parse", []byte("{not json}\n"), goodSig, runID},
		{"runlog is empty", []byte(""), goodSig, runID},
		{"run absent from the runlog", goodLog, goodSig, "01ARZ3NDEKTSV4RRFFQ69G5FAV"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fresh, err := format.CheckFreshness(tc.runlog, tc.sigText, tc.runID, root, verifier, 0)
			// The control: each input really does fail the check. An input that passed
			// would make the assertions below vacuous.
			if err == nil {
				t.Fatalf("control: %s must fail the freshness check", tc.name)
			}
			if !fresh.Unchecked {
				t.Errorf("%s: the check could not run, so Unchecked must be true", tc.name)
			}
			if !fresh.RollbackWarning {
				t.Errorf("%s: a check that could not run did not pass, so RollbackWarning must be true", tc.name)
			}
		})
	}

	// The control for the whole table: the same call over the intact inputs is neither
	// unchecked nor warned. Without it, a FreshnessResult hardcoded to warn always would
	// satisfy every assertion above.
	fresh, err := format.CheckFreshness(goodLog, goodSig, runID, root, verifier, 0)
	if err != nil {
		t.Fatalf("control: the intact archive must pass its freshness check: %v", err)
	}
	if fresh.Unchecked || fresh.RollbackWarning {
		t.Errorf("control: a clean check must be neither unchecked nor warned: %+v", fresh)
	}
}
