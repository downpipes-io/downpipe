package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// The end-to-end command proof for a D1 body this release cannot render.
//
// Before the fix, driven against the built binary: a record whose body carried
// downpipe-d1-rows/2 restored with "0 failed", exit 0, its verified JSON written to
// <name>.sql, and D1ReplayGuidance printed above telling the operator to run
// `sqlite3 restored.sqlite < <db>.sql`. Running that guidance for real on the file the tool
// had just written gave a "Parse error near line 1" over the JSON's opening brace, and exit 1.
//
// These tests drive the actual restore command over a real signed archive and pin what
// replaced it: the distinct advisory exit, the plan-time and apply-time reports, a
// destination key with no .sql suffix, and the bytes still on disk. A d1 record this release
// DOES render keeps exit 0 with no warning, which is the control that stops the fix widening
// into every d1 record.

const (
	newerD1Body = `{"format":"downpipe-d1-rows/2","table":"t","columns":["a"],"rows":[[1]]}`
	knownD1Body = `{"format":"downpipe-d1-rows/1","table":"t","columns":["a"],"rows":[[1]]}`
	d1RecName   = "appdb"
)

// buildD1SelftestArchive writes a real, signed, encrypted one-record archive whose single
// record is a d1 record carrying the given body and D1 descriptor format. It mirrors
// buildSelftestArchive, which builds a kv record and cannot express a source type or a
// descriptor, and it reuses that builder's key, root, RUNLOG and bundle steps unchanged so
// the archive this produces is opened by the same reader path as any other.
//
// An empty descriptorFormat leaves the record with no D1 descriptor at all, which is what a
// writer that never stamped one produces.
func buildD1SelftestArchive(t *testing.T, dir, body, descriptorFormat string) (*crypto.HybridKEMPrivate, *crypto.HybridVerifier, string) {
	t.Helper()
	value := []byte(body)
	bgPriv, bgPub, opPub, signer, verifier, err := generateSelftestKeys()
	if err != nil {
		t.Fatalf("generateSelftestKeys: %v", err)
	}
	master, err := randomBytes(32)
	if err != nil {
		t.Fatalf("master: %v", err)
	}
	runID, runIDBytes, err := newSelftestRunID()
	if err != nil {
		t.Fatalf("newSelftestRunID: %v", err)
	}
	mk := crypto.DeriveMK(master, runIDBytes)

	segNonce, err := randomBytes(spec.StreamNonceSize)
	if err != nil {
		t.Fatalf("segNonce: %v", err)
	}
	segID, segBytes, err := crypto.SealNonSecretSegment(master, "dp_selftest", spec.AddrSingleNonSecret, spec.CodecNone, value, segNonce)
	if err != nil {
		t.Fatalf("SealNonSecretSegment: %v", err)
	}
	segHex := crypto.SegIDHex(segID)
	segObj := "seg/" + segHex[:2] + "/" + segHex + ".seg"
	if werr := writeObject(dir, segObj, segBytes); werr != nil {
		t.Fatalf("write segment: %v", werr)
	}

	rec := spec.ShardRecord{
		SourceType: spec.SourceD1, Name: d1RecName,
		KeyNameHash:   hex.EncodeToString(crypto.NameMAC(crypto.DeriveNameMACKey(mk, runIDBytes), spec.SourceD1, d1RecName)),
		RecordID:      "r000000000000001",
		PlaintextSize: int64(len(value)), PlaintextSHA: format.SHA384Hex(value),
		Codec:    spec.CodecNameNone,
		Segments: []spec.Segment{{Object: segObj, ChunkRange: [2]int{0, 1}}},
	}
	if descriptorFormat != "" {
		rec.D1 = &spec.D1Descriptor{Format: descriptorFormat}
	}
	rhBytes, err := format.RecordHashOf(rec)
	if err != nil {
		t.Fatalf("RecordHashOf: %v", err)
	}
	rec.RecordHash = hex.EncodeToString(rhBytes)

	shardNonce, err := randomBytes(spec.StreamNonceSize)
	if err != nil {
		t.Fatalf("shardNonce: %v", err)
	}
	preamble := spec.ShardPreamble{
		FormatVersion: spec.Version, RunID: runID, ShardID: "00000",
		ManifestCodec: spec.CodecNameNone,
		Downpipe:      spec.PreambleDownpipe{Name: "selftest", Cadence: "0 * * * *"},
		Source:        spec.Source{Type: spec.SourceD1, NamespaceID: "selftest"},
		Window:        spec.Window{Start: "2026-06-06T12:00:00.000Z", End: "2026-06-06T12:00:01.000Z"},
		Consistency:   "crawl",
	}
	shardBytes, shardSHA, err := format.SealShard(preamble, []spec.ShardRecord{rec}, crypto.DeriveManifestWrapKey(mk, runIDBytes, "00000"), shardNonce)
	if err != nil {
		t.Fatalf("SealShard: %v", err)
	}
	shardObj := "run/" + runID + "/manifest/00000.dpe"
	if werr := writeObject(dir, shardObj, shardBytes); werr != nil {
		t.Fatalf("write shard: %v", werr)
	}
	if rerr := writeSelftestRootManifest(dir, master, runID, runIDBytes, rec, shardObj, shardSHA, bgPub, opPub, signer, verifier); rerr != nil {
		t.Fatalf("writeSelftestRootManifest: %v", rerr)
	}
	if rerr := writeSelftestRunlog(dir, runID, signer); rerr != nil {
		t.Fatalf("writeSelftestRunlog: %v", rerr)
	}
	if berr := writeSelftestBundle(dir, signer); berr != nil {
		t.Fatalf("writeSelftestBundle: %v", berr)
	}
	return bgPriv, verifier, runID
}

// TestRestoreOfANewerD1BodyExitsTheAdvisoryAndNamesTheLabel drives `restore --sink file
// --apply` over an archive whose one d1 record carries a format label from a newer engine. It
// pins the four things that were all absent before: a non-zero, distinct advisory exit, a
// stderr report naming the record and the label it carries, a destination file that is NOT
// named .sql, and the verified bytes still on disk unchanged.
func TestRestoreOfANewerD1BodyExitsTheAdvisoryAndNamesTheLabel(t *testing.T) {
	archiveDir := t.TempDir()
	identity, verifier, runID := buildD1SelftestArchive(t, archiveDir, newerD1Body, "downpipe-d1-rows/2")
	idPath, signerPath := writeArchiveKeys(t, archiveDir, identity, verifier)
	outDir := filepath.Join(t.TempDir(), "out")

	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{"restore", "--archive", archiveDir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--sink", "file", "--out", outDir, "--apply"})
	})

	if code != format.ExitUnrenderable {
		t.Fatalf("restore of a newer-format d1 archive = %d, want %d (the unrenderable advisory)\nstderr: %s", code, format.ExitUnrenderable, stderr)
	}
	// It must not be read as a clean restore, and it must not be read as corruption either.
	if code == 0 || code == format.ExitUnverified || code == format.ExitPlaintext || code == format.ExitIncomplete || code == 1 {
		t.Fatalf("the advisory must be distinct from success and from every hard-failure code, got %d", code)
	}
	if code == format.ExitIncompleteMarkers {
		t.Fatal("this is not an incompleteness marker: the source was fully available, the reader is what cannot read it")
	}
	for _, want := range []string{"downpipe-d1-rows/2", "NOT SQL", "sqlite3", d1RecName} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr must carry %q so the operator knows which file and which release, got: %q", want, stderr)
		}
	}
	// The APPLY-time report specifically, not the plan-time one. Both name the record and
	// the label, so an assertion on those alone is satisfied by either: deleting the
	// apply-time call entirely left this test green until these two lines were added.
	if !strings.Contains(stderr, "WARNING unrenderable d1 format") {
		t.Fatalf("stderr must carry the per-record apply-time WARNING, got: %q", stderr)
	}
	if !strings.Contains(stderr, "carry a D1 body format this release cannot render. Nothing is corrupt") {
		t.Fatalf("stderr must carry the apply-time summary WARNING, got: %q", stderr)
	}
	// The output key. This is the half that makes the guidance harmful rather than merely
	// unhelpful: an operator reaches for sqlite3 on the strength of the extension.
	if _, err := os.Stat(filepath.Join(outDir, d1RecName+".sql")); err == nil {
		t.Fatal("a body this release could not render must not be written to a .sql path")
	}
	got, rerr := os.ReadFile(filepath.Join(outDir, d1RecName))
	if rerr != nil {
		t.Fatalf("the verified bytes must still be on disk at the bare key: %v", rerr)
	}
	if string(got) != newerD1Body {
		t.Fatalf("the bytes must be written unchanged, got %q", got)
	}
	// And the replay guidance must not be printed for a run that has no renderable dump: it
	// is the sentence that sends the operator to sqlite3.
	if strings.Contains(stderr, "d1 dump(s) planned as .sql") {
		t.Fatalf("the sqlite3 replay guidance must not print when no d1 record is renderable, got: %q", stderr)
	}
}

// TestRestoreOfANewerD1BodySaysSoOnTheDryRun proves the operator finds out BEFORE committing
// to the recovery, not after. A dry run decrypts nothing, so this is what the descriptor is
// for: it is the only thing that can answer the question at plan time.
func TestRestoreOfANewerD1BodySaysSoOnTheDryRun(t *testing.T) {
	archiveDir := t.TempDir()
	identity, verifier, runID := buildD1SelftestArchive(t, archiveDir, newerD1Body, "downpipe-d1-rows/2")
	idPath, signerPath := writeArchiveKeys(t, archiveDir, identity, verifier)
	outDir := filepath.Join(t.TempDir(), "out")

	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{"restore", "--archive", archiveDir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--sink", "file", "--out", outDir})
	})

	// A dry run wrote nothing, so it is not the advisory: nothing fell short of anything yet.
	if code != 0 {
		t.Fatalf("a dry run = %d, want 0: it planned, it did not restore\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "cannot render") || !strings.Contains(stderr, "downpipe-d1-rows/2") {
		t.Fatalf("the dry run must name the unrenderable record and its label, got: %q", stderr)
	}
	if strings.Contains(stderr, "d1 dump(s) planned as .sql") {
		t.Fatalf("the dry run must not print the sqlite3 replay guidance for a record it cannot render, got: %q", stderr)
	}
}

// TestRestoreOfAnUndeclaredNewerBodyStillWarns is the case only the apply-time report can
// reach. The record carries NO D1 descriptor, so the plan has nothing to go on and says
// nothing, the key keeps its .sql suffix, and the only thing standing between the operator
// and sqlite3 is the warning printed after the bytes were read.
//
// It is also the case that proves the two reports are not duplicates of each other.
func TestRestoreOfAnUndeclaredNewerBodyStillWarns(t *testing.T) {
	archiveDir := t.TempDir()
	identity, verifier, runID := buildD1SelftestArchive(t, archiveDir, newerD1Body, "")
	idPath, signerPath := writeArchiveKeys(t, archiveDir, identity, verifier)
	outDir := filepath.Join(t.TempDir(), "out")

	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{"restore", "--archive", archiveDir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--sink", "file", "--out", outDir, "--apply"})
	})

	if code != format.ExitUnrenderable {
		t.Fatalf("an undeclared newer body = %d, want %d\nstderr: %s", code, format.ExitUnrenderable, stderr)
	}
	if !strings.Contains(stderr, "WARNING unrenderable d1 format") || !strings.Contains(stderr, "downpipe-d1-rows/2") {
		t.Fatalf("the apply-time warning is the only report that can fire here, got: %q", stderr)
	}
	// The plan could not know, so it said nothing. That is recorded, not required: see
	// TestADisagreeingBodyStillLandsAtADotSQLKey in internal/restore for why the key cannot
	// move once the plan has committed to it.
	if strings.Contains(stderr, "d1 dump(s) this release cannot render") {
		t.Fatalf("the plan cannot know this without the body; if it now does, promote the record that says so: %q", stderr)
	}
	if _, err := os.Stat(filepath.Join(outDir, d1RecName+".sql")); err != nil {
		t.Fatalf("current behaviour has changed: the undeclared body no longer lands at a .sql key (%v); "+
			"promote the record of that behaviour to a requirement rather than deleting it", err)
	}
}

// TestRestoreOfAKnownD1BodyStaysCleanIsTheControl is the control that keeps the fix from
// widening: a d1 record this release DOES render restores to a .sql file, prints the replay
// guidance, exits 0 and warns about nothing.
func TestRestoreOfAKnownD1BodyStaysCleanIsTheControl(t *testing.T) {
	archiveDir := t.TempDir()
	identity, verifier, runID := buildD1SelftestArchive(t, archiveDir, knownD1Body, "downpipe-d1-rows/1")
	idPath, signerPath := writeArchiveKeys(t, archiveDir, identity, verifier)
	outDir := filepath.Join(t.TempDir(), "out")

	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{"restore", "--archive", archiveDir, "--run", runID, "--identity", idPath, "--signer", signerPath, "--sink", "file", "--out", outDir, "--apply"})
	})

	if code != 0 {
		t.Fatalf("a d1 record this release renders = %d, want 0\nstderr: %s", code, stderr)
	}
	if strings.Contains(stderr, "cannot render") {
		t.Fatalf("nothing may be flagged for a renderable record, got: %q", stderr)
	}
	if !strings.Contains(stderr, "d1 dump(s) planned as .sql") {
		t.Fatalf("the replay guidance must still print for a renderable dump, got: %q", stderr)
	}
	sql, rerr := os.ReadFile(filepath.Join(outDir, d1RecName+".sql"))
	if rerr != nil {
		t.Fatalf("a renderable record must land at its .sql key: %v", rerr)
	}
	if !strings.Contains(string(sql), `INSERT INTO "t"`) {
		t.Fatalf("the .sql file must hold the transcoded SQL, got %q", sql)
	}
}
