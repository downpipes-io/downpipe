package restore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// The D1 format descriptor, and what it is read for.
//
// spec.D1Descriptor.Format rides on every per-page D1 record the engine writes, and is pinned
// in the conformance corpus. These tests pin the decision it makes: the destination key is
// resolved by MakePlan before a single byte is decrypted, so the descriptor is the only thing
// that can stop a body the reader cannot render being planned to a .sql path.

// TestTheD1DescriptorDecidesTheKeyBeforeAnyByteIsDecrypted proves the descriptor alone, with a
// body that says nothing at all, moves the destination key and the plan report. It is the
// clearest statement that the field is now load-bearing: change nothing but the descriptor and
// the plan changes.
func TestTheD1DescriptorDecidesTheKeyBeforeAnyByteIsDecrypted(t *testing.T) {
	// A body with no format field whatsoever. The transcoder declines it either way, so
	// every difference below is the descriptor's doing and nothing else's.
	body := `{"tables":[{"name":"users","rows":[[1,"ada"]]}]}`

	known, err := MakePlan(d1rdrD1([3]string{"db", body, "downpipe-d1-json/1"}), NewDirTarget(t.TempDir()))
	if err != nil {
		t.Fatalf("MakePlan (known descriptor): %v", err)
	}
	if len(known.Writes) != 1 || known.Writes[0].Key != "db.sql" || !known.HasD1File || len(known.D1Unrenderable) != 0 {
		t.Fatalf("a descriptor this release knows must plan a .sql key and no finding, got writes=%+v hasD1File=%v unrenderable=%+v",
			known.Writes, known.HasD1File, known.D1Unrenderable)
	}

	unknown, err := MakePlan(d1rdrD1([3]string{"db", body, "downpipe-d1-rows/2"}), NewDirTarget(t.TempDir()))
	if err != nil {
		t.Fatalf("MakePlan (unknown descriptor): %v", err)
	}
	if len(unknown.Writes) != 1 || unknown.Writes[0].Key != "db" {
		t.Fatalf("a descriptor this release does not know must plan a BARE key, got %+v", unknown.Writes)
	}
	if unknown.HasD1File {
		t.Fatal("a descriptor this release does not know must not put the sqlite3 guidance on the plan")
	}
	if len(unknown.D1Unrenderable) != 1 || unknown.D1Unrenderable[0].Format != "downpipe-d1-rows/2" || unknown.D1Unrenderable[0].Key != "db" {
		t.Fatalf("the plan must name the record, its bare key and its label, got %+v", unknown.D1Unrenderable)
	}
	// A plan decrypts nothing, so this held without the body ever being read. That is the
	// whole reason the descriptor is worth carrying.
	if _, statErr := os.Stat(filepath.Join(t.TempDir(), "db")); statErr == nil {
		t.Fatal("MakePlan must not have written anything")
	}
}

// TestAMixedRunKeepsTheGuidanceForTheRecordsItIsAbout proves the two reports coexist: one
// renderable record and one unrenderable record in the same run give both the sqlite3 replay
// guidance and the finding, each about only its own records. A fix that suppressed the
// guidance whenever anything was unrenderable would strand the records that are fine.
func TestAMixedRunKeepsTheGuidanceForTheRecordsItIsAbout(t *testing.T) {
	dir := t.TempDir()
	r := d1rdrD1(
		[3]string{"gooddb", `{"format":"downpipe-d1-rows/1","table":"t","columns":["a"],"rows":[[1]]}`, "downpipe-d1-rows/1"},
		[3]string{"newerdb", `{"format":"downpipe-d1-rows/2","table":"t","columns":["a"],"rows":[[1]]}`, "downpipe-d1-rows/2"},
	)
	plan, res, err := Apply(r, NewDirTarget(dir), true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !plan.HasD1File {
		t.Fatal("the renderable record must still carry the sqlite3 replay guidance")
	}
	if len(plan.D1Unrenderable) != 1 || plan.D1Unrenderable[0].Name != "newerdb" {
		t.Fatalf("the finding must name only the unrenderable record, got %+v", plan.D1Unrenderable)
	}
	if len(res.Unrenderable) != 1 || res.Unrenderable[0].Name != "newerdb" {
		t.Fatalf("the result must name only the unrenderable record, got %+v", res.Unrenderable)
	}
	if res.Restored != 2 || !res.OK() {
		t.Fatalf("both records restore: restored=%d ok=%v failed=%+v", res.Restored, res.OK(), res.Failed)
	}
	sql, rerr := os.ReadFile(filepath.Join(dir, "gooddb.sql"))
	if rerr != nil || !strings.Contains(string(sql), `INSERT INTO "t"`) {
		t.Fatalf("the renderable record must still transcode to its .sql file, got %q (err %v)", sql, rerr)
	}
	if _, serr := os.Stat(filepath.Join(dir, "newerdb")); serr != nil {
		t.Fatalf("the unrenderable record's bytes must be on disk at its bare key: %v", serr)
	}
}

// TestABodyThatDisagreesWithItsDescriptorIsStillCaught proves the apply-time check is strictly
// wider than the plan-time one. A writer that stamped no descriptor, or stamped one this
// release knows over a body it does not, is caught by reading the verified bytes.
//
// The KEY in these two cases keeps its .sql suffix, because the plan resolved it before the
// body existed. That part is recorded rather than required: see the record below.
func TestABodyThatDisagreesWithItsDescriptorIsStillCaught(t *testing.T) {
	newer := `{"format":"downpipe-d1-rows/2","table":"t","columns":["a"],"rows":[[1]]}`
	for name, descriptor := range map[string]string{
		"no descriptor at all":           "",
		"a descriptor this reader knows": "downpipe-d1-rows/1",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			_, res, err := Apply(d1rdrD1([3]string{"db", newer, descriptor}), NewDirTarget(dir), true)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if len(res.Unrenderable) != 1 || res.Unrenderable[0].Format != "downpipe-d1-rows/2" {
				t.Fatalf("the body's own label must be read when the descriptor does not answer, got %+v", res.Unrenderable)
			}
			if res.Restored != 1 || !res.OK() {
				t.Fatalf("the bytes must still restore: restored=%d ok=%v", res.Restored, res.OK())
			}
		})
	}
}

// TestADisagreeingBodyStillLandsAtADotSQLKey RECORDS CURRENT BEHAVIOUR. It is not a
// requirement, and if the reader ever stops needing this compromise the record should be
// PROMOTED to a requirement that says so, not deleted.
//
// The destination key is resolved by MakePlan, which decrypts nothing, so the only input it
// has for this decision is the descriptor. When the descriptor is absent or disagrees with the
// body, the key is already committed by the time the body is read, and the record's within-run
// no-clobber claim is committed with it, so changing the key at write time would make the plan
// and the bytes disagree about where a record went.
//
// The residual is narrow by construction rather than by luck: the engine stamps the descriptor
// from the same constants it writes into the body, so a body and its descriptor disagree only
// for a writer that is not the engine. And the finding still fires:
// the operator is told the file is not SQL and told not to apply it, which is the part that
// matters. What they do not get is a file name that also says so.
func TestADisagreeingBodyStillLandsAtADotSQLKey(t *testing.T) {
	newer := `{"format":"downpipe-d1-rows/2","table":"t","columns":["a"],"rows":[[1]]}`
	dir := t.TempDir()
	plan, res, err := Apply(d1rdrD1([3]string{"db", newer, ""}), NewDirTarget(dir), true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(plan.Writes) != 1 || plan.Writes[0].Key != "db.sql" {
		t.Fatalf("current behaviour has changed: the key is now %+v. If the reader can now resolve this "+
			"key from the body as well as the descriptor, promote this record to a requirement that says "+
			"the key follows the bytes, rather than deleting it", plan.Writes)
	}
	if _, rerr := os.ReadFile(filepath.Join(dir, "db.sql")); rerr != nil {
		t.Fatalf("current behaviour has changed: nothing at db.sql (%v); promote this record rather than deleting it", rerr)
	}
	// The half that IS a requirement: the operator is still told, and told which label.
	if len(res.Unrenderable) != 1 || res.Unrenderable[0].Key != "db.sql" {
		t.Fatalf("the finding must fire and must name the file it is about, got %+v", res.Unrenderable)
	}
}

// TestTheStreamingApplyReachesTheSameVerdict proves the bounded-memory path is not a hole. The
// two apply paths annotate the plan through one function and write records through one
// function, and this is what proves it rather than asserting it.
func TestTheStreamingApplyReachesTheSameVerdict(t *testing.T) {
	newer := `{"format":"downpipe-d1-rows/2","table":"t","columns":["a"],"rows":[[1]]}`
	dir := t.TempDir()
	plan, res, err := ApplyStreaming(d1rdrD1([3]string{"db", newer, "downpipe-d1-rows/2"}), NewDirTarget(dir), true)
	if err != nil {
		t.Fatalf("ApplyStreaming: %v", err)
	}
	if len(plan.D1Unrenderable) != 1 || plan.HasD1File {
		t.Fatalf("the streaming plan must reach the same verdict, got unrenderable=%+v hasD1File=%v", plan.D1Unrenderable, plan.HasD1File)
	}
	if len(res.Unrenderable) != 1 || res.Unrenderable[0].Key != "db" {
		t.Fatalf("the streaming result must reach the same verdict, got %+v", res.Unrenderable)
	}
	if _, serr := os.Stat(filepath.Join(dir, "db.sql")); serr == nil {
		t.Fatal("the streaming path must not write a .sql file for a body it could not render either")
	}
}

// TestTheAuthoritativeD1FormatSpellingIsTheEngines pins WHICH spelling of the D1 format label
// is authoritative: the slash form ("downpipe-d1-json/1" and its header/rows/schema
// siblings) is what a real writer stamps on both the body and the record descriptor, so it is
// the form this reader matches on.
//
// A second spelling, "downpipe-d1-json-v1", appears once in this repository's conformance
// corpus as a fixture value that no writer emits. This test names it explicitly so the reader's
// treatment of it is deliberate: it carries the family prefix and is not one of the four known
// labels, so it is reported as a format this reader cannot render.
func TestTheAuthoritativeD1FormatSpellingIsTheEngines(t *testing.T) {
	for _, label := range []string{
		"downpipe-d1-json/1", "downpipe-d1-header/1", "downpipe-d1-rows/1", "downpipe-d1-schema/1",
	} {
		if !d1KnownFormat(label) {
			t.Errorf("the engine emits %q; this reader must render it", label)
		}
		if got := d1UnrenderableLabel(label); got != "" {
			t.Errorf("%q is renderable and must not be reported, got %q", label, got)
		}
	}
	// The corpus fixture spelling, which no writer emits.
	const corpusSpelling = "downpipe-d1-json-v1"
	if d1KnownFormat(corpusSpelling) {
		t.Errorf("%q is not a format this reader renders; only the four the engine emits are", corpusSpelling)
	}
	if got := d1UnrenderableLabel(corpusSpelling); got != corpusSpelling {
		t.Errorf("%q carries the downpipe D1 family prefix and is not one this reader renders, so it must be reported, got %q", corpusSpelling, got)
	}
	// Whitespace around a label must not smuggle it past the check: " downpipe-d1-rows/2 "
	// is the same claim, and a reader that missed it would go back to silent success.
	if got := d1UnrenderableLabel("  downpipe-d1-rows/2\n"); got != "downpipe-d1-rows/2" {
		t.Errorf("a padded label must still be read, got %q", got)
	}
	// An absent descriptor answers nothing, and must not be mistaken for an answer.
	if got := d1DescriptorUnrenderable(spec.ShardRecord{}); got != "" {
		t.Errorf("a record with no D1 descriptor must report nothing, got %q", got)
	}
	if got := d1DescriptorUnrenderable(spec.ShardRecord{D1: &spec.D1Descriptor{}}); got != "" {
		t.Errorf("an empty descriptor format must report nothing, got %q", got)
	}
}

// TestTheUnrenderableGuidanceSaysTheFileIsNotSQLAndKeepsIt pins the guidance sentence itself,
// which is the text an operator acts on mid-recovery: it must say the file is not SQL and must
// never tell the operator to delete verified bytes.
//
// It also pins the tense. The plan report prints on a dry run, which writes nothing, so a
// sentence saying bytes "were written" there would be the same kind of imprecision this whole
// change exists to remove.
func TestTheUnrenderableGuidanceSaysTheFileIsNotSQLAndKeepsIt(t *testing.T) {
	applied := D1UnrenderableGuidance(2, true)
	planned := D1UnrenderableGuidance(2, false)

	for _, want := range []string{"NOT SQL", "sqlite3", "cannot render", "2 D1 record(s)"} {
		if !strings.Contains(applied, want) {
			t.Errorf("the guidance must say %q, got:\n%s", want, applied)
		}
	}
	// It must never send the operator to delete verified bytes. That is the one instruction
	// that would turn a recoverable situation into data loss.
	for _, banned := range []string{"delete", "discard", "ignore"} {
		if strings.Contains(strings.ToLower(applied), banned) {
			t.Errorf("the guidance must never tell an operator to %s verified bytes, got:\n%s", banned, applied)
		}
	}
	if !strings.Contains(applied, "were written unchanged") {
		t.Errorf("an applied restore has written the bytes, and must say so, got:\n%s", applied)
	}
	if !strings.Contains(planned, "will be written unchanged") || strings.Contains(planned, "were written") {
		t.Errorf("a dry run wrote nothing and must not claim it did, got:\n%s", planned)
	}
	// And the count is the record count, not a constant.
	if strings.Contains(D1UnrenderableGuidance(1, true), "2 D1 record(s)") {
		t.Error("the guidance must report the real count")
	}
}

// TestAMarkerAndAnUnknownFormatAreBothReported proves the two findings are independent. A
// record can be a sentinel placeholder AND carry a label this release cannot render, and the
// operator needs both facts: one says the source was partly unavailable at backup time, the
// other says this binary cannot read what did arrive.
func TestAMarkerAndAnUnknownFormatAreBothReported(t *testing.T) {
	r := d1rdrD1([3]string{"db", `{"_skipped":"the database was unavailable at backup time"}`, "downpipe-d1-rows/2"})
	r.recs[0].IncompleteMarker = "_skipped"
	dir := t.TempDir()
	_, res, err := Apply(r, NewDirTarget(dir), true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.IncompleteMarkers != 1 {
		t.Fatalf("the marker must still be reported, got %d", res.IncompleteMarkers)
	}
	if len(res.Unrenderable) != 1 || res.Unrenderable[0].Format != "downpipe-d1-rows/2" {
		t.Fatalf("the unrenderable label must be reported alongside it, got %+v", res.Unrenderable)
	}
}
