package main

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/restore"
)

// releasedRoot holds one sealed fixture archive per archive-format generation a released engine has
// written. Directories only accumulate: a generation is never deleted and never regenerated, so every
// reader built from this tree has to open every one of them.
const releasedRoot = "../../internal/format/testdata/released"

// releasedExpected is the expected.json the sealing engine wrote beside each archive. Every value in it
// was taken from the source data before sealing, so the reader is graded against the writer's inputs
// and never against anything it read out of the archive itself.
type releasedExpected struct {
	Generation    string        `json:"generation"`
	FormatVersion string        `json:"formatVersion"`
	EngineVersion string        `json:"engineVersion"`
	Runs          []releasedRun `json:"runs"`
}

type releasedRun struct {
	RunID       string           `json:"runId"`
	RunlogIndex int64            `json:"runlogIndex"`
	Latest      bool             `json:"latest"`
	Records     []releasedRecord `json:"records"`
}

type releasedRecord struct {
	SourceType       string `json:"sourceType"`
	Name             string `json:"name"`
	Size             int64  `json:"size"`
	PlaintextSha384  string `json:"plaintextSha384"`
	IncompleteMarker string `json:"incompleteMarker"`
}

// releasedGenerations lists every generation directory under releasedRoot. A directory added there is
// picked up with no change to this file.
func releasedGenerations(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(releasedRoot)
	if err != nil {
		t.Fatalf("read %s: %v", releasedRoot, err)
	}
	var gens []string
	for _, e := range entries {
		if e.IsDir() {
			gens = append(gens, e.Name())
		}
	}
	if len(gens) == 0 {
		t.Fatalf("no generation directory under %s, so the read-them-all gate has nothing to read", releasedRoot)
	}
	return gens
}

func loadReleasedExpected(t *testing.T, dir string) releasedExpected {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		t.Fatalf("read expected.json: %v", err)
	}
	var exp releasedExpected
	if err := json.Unmarshal(raw, &exp); err != nil {
		t.Fatalf("parse expected.json: %v", err)
	}
	if exp.Generation != filepath.Base(dir) {
		t.Fatalf("expected.json names generation %q but sits in %q", exp.Generation, filepath.Base(dir))
	}
	if len(exp.Runs) == 0 {
		t.Fatalf("expected.json lists no runs")
	}
	return exp
}

// runReader drives the real command dispatcher and returns its exit code and combined output.
func runReader(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var code int
	stdout, stderr := captureOutput(t, func() { code = run(args) })
	return code, stdout + stderr
}

// readerArgs is the common flag set for one run of one generation. The RUNLOG pin is the highest index
// the fixture holds, so the anti-rollback comparison runs rather than being waived. An older run in the
// chain is opened with --allow-stale, which is the documented way to restore a run that is not the latest.
func readerArgs(cmd, dir string, maxIndex int64, runID string, latest bool, extra ...string) []string {
	args := []string{
		cmd,
		"--archive", filepath.Join(dir, "archive"),
		"--run", runID,
		"--identity", filepath.Join(dir, "identity.key"),
		"--signer", filepath.Join(dir, "signer.pub"),
		"--min-runlog-index", strconv.FormatInt(maxIndex, 10),
		"--check-bundle",
	}
	if !latest {
		args = append(args, "--allow-stale")
	}
	return append(args, extra...)
}

func sha384Hex(b []byte) string {
	sum := sha512.Sum384(b)
	return hex.EncodeToString(sum[:])
}

// TestReleasedGenerationsVerifyAndRestore is the read-them-all gate. For every released generation and
// every run in it, the reader's own verify (deep, with the recovery bundle checked) and its applied
// restore must succeed, the restored bytes must hash to the values the sealing engine recorded, and the
// restore receipt must count exactly the records the engine sealed.
func TestReleasedGenerationsVerifyAndRestore(t *testing.T) {
	for _, gen := range releasedGenerations(t) {
		t.Run(gen, func(t *testing.T) {
			dir := filepath.Join(releasedRoot, gen)
			exp := loadReleasedExpected(t, dir)
			var maxIndex int64
			for _, r := range exp.Runs {
				if r.RunlogIndex > maxIndex {
					maxIndex = r.RunlogIndex
				}
			}
			for _, r := range exp.Runs {
				t.Run(r.RunID, func(t *testing.T) {
					markers := 0
					for _, rec := range r.Records {
						if rec.IncompleteMarker != "" {
							markers++
						}
					}
					want := format.ExitVerified
					if markers > 0 {
						want = format.ExitIncompleteMarkers
					}

					if !r.Latest {
						code, out := runReader(t, readerArgs("verify", dir, maxIndex, r.RunID, true)...)
						if code != format.ExitStale {
							t.Errorf("verify of an older run without --allow-stale = %d, want %d (the RUNLOG chain names a later run)\n%s", code, format.ExitStale, out)
						}
					}

					code, out := runReader(t, readerArgs("verify", dir, maxIndex, r.RunID, r.Latest, "--deep")...)
					if code != want {
						t.Fatalf("verify --deep = %d, want %d\n%s", code, want, out)
					}
					if !strings.Contains(out, "signature=valid") || !strings.Contains(out, "bundle=verified") {
						t.Errorf("verify did not report a valid signature and a verified bundle\n%s", out)
					}

					restored := t.TempDir()
					receipt := filepath.Join(t.TempDir(), "receipt.json")
					code, out = runReader(t, readerArgs("restore", dir, maxIndex, r.RunID, r.Latest, "--apply", "--out", restored, "--receipt", receipt)...)
					if code != want {
						t.Fatalf("restore --apply = %d, want %d\n%s", code, want, out)
					}
					checkRestoredValues(t, restored, r.Records)
					checkReceipt(t, receipt, len(r.Records), markers)
				})
			}
		})
	}
}

// checkRestoredValues requires every non-D1 record's plaintext hash to appear among the restored files,
// once per record, and one .sql file per D1 record. A schema record with nothing beyond the tables renders
// as an empty file, so only the D1 output as a whole must be non-empty. A D1 record is written out as SQL rather
// than as its sealed bytes, so its plaintext hash is proven by the deep verify and the restore itself,
// both of which hash-check every record against the signed manifest before writing anything.
func checkRestoredValues(t *testing.T, restored string, records []releasedRecord) {
	t.Helper()
	got := map[string]int{}
	sqlFiles, sqlBytes := 0, 0
	err := filepath.WalkDir(restored, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil || d.IsDir() {
			return werr
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if strings.HasSuffix(p, restore.MetadataSidecarSuffix) {
			checkSidecar(t, p, b, records)
			return nil
		}
		if strings.HasSuffix(p, ".sql") {
			sqlFiles++
			sqlBytes += len(b)
			return nil
		}
		got[sha384Hex(b)]++
		return nil
	})
	if err != nil {
		t.Fatalf("walk the restore output: %v", err)
	}
	wantSQL := 0
	var missing []string
	for _, rec := range records {
		if rec.SourceType == "d1" {
			wantSQL++
			continue
		}
		if got[rec.PlaintextSha384] == 0 {
			missing = append(missing, rec.SourceType+" "+rec.Name)
			continue
		}
		got[rec.PlaintextSha384]--
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("no restored file carries the sealed plaintext of: %s", strings.Join(missing, ", "))
	}
	for h, n := range got {
		if n > 0 {
			t.Errorf("restored %d file(s) with hash %s that match no sealed record", n, h)
		}
	}
	if sqlFiles != wantSQL {
		t.Errorf("restored %d D1 .sql file(s), want %d", sqlFiles, wantSQL)
	}
	if wantSQL > 0 && sqlBytes == 0 {
		t.Errorf("every restored D1 .sql file is empty")
	}
}

// checkSidecar grades one metadata sidecar the file sink wrote (docs/format/SPEC.md 6.3). It is
// not a value, so checkRestoredValues does not count it as one. Instead it must carry the
// documented format label, name a kv or r2 record the engine sealed by source type, name and
// plaintext hash, and sit next to the restored file that holds exactly that plaintext.
func checkSidecar(t *testing.T, path string, b []byte, records []releasedRecord) {
	t.Helper()
	var side struct {
		Format       string `json:"format"`
		SourceType   string `json:"sourceType"`
		Name         string `json:"name"`
		PlaintextSHA string `json:"plaintextSha384"`
	}
	if err := json.Unmarshal(b, &side); err != nil {
		t.Errorf("sidecar %s is not JSON: %v", path, err)
		return
	}
	if side.Format != restore.MetadataSidecarFormat {
		t.Errorf("sidecar %s format = %q, want %q", path, side.Format, restore.MetadataSidecarFormat)
	}
	found := false
	for _, rec := range records {
		if rec.SourceType == side.SourceType && rec.Name == side.Name && rec.PlaintextSha384 == side.PlaintextSHA && (rec.SourceType == "kv" || rec.SourceType == "r2") {
			found = true
		}
	}
	if !found {
		t.Errorf("sidecar %s names %s %q, which is no sealed kv or r2 record", path, side.SourceType, side.Name)
	}
	value, err := os.ReadFile(strings.TrimSuffix(path, restore.MetadataSidecarSuffix))
	if err != nil {
		t.Errorf("sidecar %s has no value next to it: %v", path, err)
		return
	}
	if sha384Hex(value) != side.PlaintextSHA {
		t.Errorf("sidecar %s sits next to a value that is not the record it names", path)
	}
}

func checkReceipt(t *testing.T, path string, records, markers int) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the restore receipt: %v", err)
	}
	var rc struct {
		SignatureResult     string `json:"signatureResult"`
		Completeness        string `json:"completeness"`
		DeclaredRecordCount int64  `json:"declaredRecordCount"`
		RecordsVerified     int64  `json:"recordsVerified"`
		RecordsRestored     int64  `json:"recordsRestored"`
		IncompleteMarkers   int64  `json:"incompleteMarkers"`
	}
	if err := json.Unmarshal(raw, &rc); err != nil {
		t.Fatalf("parse the restore receipt: %v", err)
	}
	n := int64(records)
	if rc.SignatureResult != "valid" || rc.Completeness != "complete" {
		t.Errorf("receipt signatureResult=%q completeness=%q, want valid and complete", rc.SignatureResult, rc.Completeness)
	}
	if rc.DeclaredRecordCount != n || rc.RecordsVerified != n || rc.RecordsRestored != n {
		t.Errorf("receipt counts declared=%d verified=%d restored=%d, want %d each (the records the engine sealed)", rc.DeclaredRecordCount, rc.RecordsVerified, rc.RecordsRestored, n)
	}
	if rc.IncompleteMarkers != int64(markers) {
		t.Errorf("receipt incompleteMarkers=%d, want %d", rc.IncompleteMarkers, markers)
	}
}

// copyGeneration copies one generation directory into a temp dir, so a negative control can damage the
// copy and never the committed fixture.
func copyGeneration(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		return os.WriteFile(target, b, 0o600)
	})
	if err != nil {
		t.Fatalf("copy %s: %v", src, err)
	}
	return dst
}

func flipByte(t *testing.T, path string, offset int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if offset >= len(b) {
		t.Fatalf("%s is %d bytes, too short to flip byte %d", path, len(b), offset)
	}
	b[offset] ^= 0x01
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestReleasedGenerationsRefuseOneFlippedByte is the negative control for the gate above: the same reader
// over a copy with one byte changed must refuse. Two places are damaged, one per copy. A byte in the middle
// of the largest data segment, past its container header, must fail the per-record authentication on a deep
// verify of whichever run owns it. A byte of the latest run's root signature must fail verify outright.
func TestReleasedGenerationsRefuseOneFlippedByte(t *testing.T) {
	for _, gen := range releasedGenerations(t) {
		t.Run(gen, func(t *testing.T) {
			src := filepath.Join(releasedRoot, gen)
			exp := loadReleasedExpected(t, src)
			var maxIndex int64
			latest := exp.Runs[0].RunID
			for _, r := range exp.Runs {
				if r.RunlogIndex > maxIndex {
					maxIndex = r.RunlogIndex
				}
				if r.Latest {
					latest = r.RunID
				}
			}

			t.Run("segment", func(t *testing.T) {
				dir := copyGeneration(t, src)
				var victim string
				var victimSize int64
				segRoot := filepath.Join(dir, "archive", "seg")
				err := filepath.WalkDir(segRoot, func(p string, d fs.DirEntry, werr error) error {
					if werr != nil || d.IsDir() {
						return werr
					}
					info, ierr := d.Info()
					if ierr != nil {
						return ierr
					}
					if info.Size() > victimSize {
						victim, victimSize = p, info.Size()
					}
					return nil
				})
				if err != nil || victim == "" {
					t.Fatalf("find a data segment under %s: %v", segRoot, err)
				}
				flipByte(t, victim, int(victimSize/2))
				refused := 0
				for _, r := range exp.Runs {
					code, out := runReader(t, readerArgs("verify", dir, maxIndex, r.RunID, r.Latest, "--deep")...)
					switch code {
					case format.ExitVerified, format.ExitIncompleteMarkers:
					default:
						refused++
						if !strings.Contains(out, "authentication failed") {
							t.Errorf("run %s refused with exit %d but not on the chunk authentication\n%s", r.RunID, code, out)
						}
					}
				}
				if refused != 1 {
					t.Errorf("a flipped byte in %s was refused by %d run(s), want exactly the 1 run that owns it", filepath.Base(victim), refused)
				}
			})

			t.Run("root-signature", func(t *testing.T) {
				dir := copyGeneration(t, src)
				flipByte(t, filepath.Join(dir, "archive", "run", latest, "root.manifest.json.sig"), 0)
				code, out := runReader(t, readerArgs("verify", dir, maxIndex, latest, true)...)
				if code != format.ExitUnverified {
					t.Errorf("verify with a flipped root-signature byte = %d, want %d\n%s", code, format.ExitUnverified, out)
				}
			})
		})
	}
}
