package format

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateCounts(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		ok   bool
	}{
		{"in-range number", `{"declaredRecordCount":9831242,"shardCount":1}`, true},
		{"zero", `{"declaredRecordCount":0,"shardCount":0}`, true},
		{"nested ok", `{"freshness":{"runlogIndex":4814}}`, true},
		{"missing is fine", `{"shardCount":1}`, true},
		{"over 2^53", `{"declaredRecordCount":9007199254740993}`, false},
		{"in-range as string", `{"declaredRecordCount":"9831242"}`, false},
		{"non-integer", `{"declaredRecordCount":1.5}`, false},
		{"negative", `{"shardCount":-1}`, false},
		// "-0" is valid JSON and numerically zero, so a naive parse to int64 would accept
		// it; the canonical form forbids a leading sign, so the guard must reject it.
		{"negative zero", `{"shardCount":-0}`, false},
	}
	for _, c := range cases {
		err := validateCounts([]byte(c.raw), "declaredRecordCount", "shardCount", "freshness.runlogIndex")
		if c.ok && err != nil {
			t.Fatalf("%s: unexpected error %v", c.name, err)
		}
		if !c.ok {
			if err == nil {
				t.Fatalf("%s: expected rejection", c.name)
			}
			var ee *ExitError
			if !errors.As(err, &ee) || ee.Code != ExitUsage {
				t.Fatalf("%s: want ExitUsage, got %v", c.name, err)
			}
		}
	}
}

// A key differing only in case must not slip past the numeric checks. encoding/json matches struct
// fields case-insensitively, so a caller that validates the raw bytes here and then unmarshals them
// gets the worst of both: this function saw no "index" and skipped every check, while the unmarshal
// happily filled Index from "indeX". Found by FuzzRunlogKeyless on the input {"indeX":-1}, which is
// the RUNLOG index the KEYLESS attestation path relies on to detect a rollback without a signature.
//
// The same function guards declaredRecordCount, shardCount, recordCountInShard and plaintextSize at
// three other call sites, so the bypass was not specific to the RUNLOG.
func TestCaseVariantKeyIsRefusedNotSkipped(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		path string
	}{
		{"runlog index", `{"indeX":-1}`, "index"},
		{"runlog recordCount", `{"recordcount":-5}`, "recordCount"},
		{"root declaredRecordCount", `{"DeclaredRecordCount":-1}`, "declaredRecordCount"},
		{"shard plaintextSize", `{"PLAINTEXTSIZE":-2}`, "plaintextSize"},
	}
	for _, c := range cases {
		err := validateCounts([]byte(c.raw), c.path)
		if err == nil {
			t.Errorf("%s: %s was accepted; a case-variant key must be refused, not skipped", c.name, c.raw)
			continue
		}
		if !strings.Contains(err.Error(), "differs only in case") {
			t.Errorf("%s: want a case-collision refusal, got %v", c.name, err)
		}
	}
	// The exact name still validates normally, and a genuinely absent field is still fine.
	if err := validateCounts([]byte(`{"index":-1}`), "index"); err == nil {
		t.Error("an exact key with a negative value must still be refused")
	}
	if err := validateCounts([]byte(`{"other":1}`), "index"); err != nil {
		t.Errorf("an absent field must remain acceptable, got %v", err)
	}
}

// TestCaseCollidingDuplicateKeyIsRefusedEvenWithCanonicalKeyPresent proves the second,
// deeper layer of the case-collision bug TestCaseVariantKeyIsRefusedNotSkipped fixed:
// caseCollidingKey used to run only when the exact-name lookup found nothing, so an
// object carrying BOTH the canonical key and a re-cased duplicate slipped through
// untouched — resolvePath found and validated the harmless canonical key, and the
// collision branch never ran because the exact key was not "absent". encoding/json's
// Unmarshal, walking the same raw bytes independently, binds whichever of the two keys
// appears LAST in the object (attacker-controlled byte order, not spelling), so
// {"index":1,"Index":999999} passed this validator while the field it protects ended up
// holding 999999. Reproduced live against the compiled binary: a keyless attest whose RUNLOG carried
// exactly this line reported max-index=999999 and exited 0 under
// --min-runlog-index 999, defeating the keyless freshness self-consistency check with
// no signature to forge. Key order is what flips it: canonical-first,-decoy-last wins
// for the attacker; the reverse order already failed the pre-fix code by coincidence
// (the canonical key, appearing last, is what encoding/json bound), which is why this
// needs its own case rather than being implied by the "absent" test above.
func TestCaseCollidingDuplicateKeyIsRefusedEvenWithCanonicalKeyPresent(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		path string
	}{
		{"canonical first, decoy last (the exploitable order)", `{"index":1,"Index":999999}`, "index"},
		{"decoy first, canonical last", `{"Index":999999,"index":1}`, "index"},
		{"three-way spread", `{"recordCount":1,"RecordCount":9007199254740993,"recordcount":-1}`, "recordCount"},
	}
	for _, c := range cases {
		err := validateCounts([]byte(c.raw), c.path)
		if err == nil {
			t.Errorf("%s: %s was accepted; a case-colliding duplicate must be refused even when the canonical key is also present", c.name, c.raw)
			continue
		}
		if !strings.Contains(err.Error(), "differs only in case") {
			t.Errorf("%s: want a case-collision refusal, got %v", c.name, err)
		}
	}
}

// TestValidateCountsRefusesNull checks that a count written as JSON null is refused with
// ExitUsage for every count field the reader checks, and is not read as absent (zero).
func TestValidateCountsRefusesNull(t *testing.T) {
	cases := []struct {
		name  string
		raw   string
		paths []string
	}{
		{"root declaredRecordCount", `{"declaredRecordCount":null}`, []string{"declaredRecordCount", "shardCount", "freshness.runlogIndex"}},
		{"root shardCount", `{"shardCount":null}`, []string{"declaredRecordCount", "shardCount", "freshness.runlogIndex"}},
		{"root freshness.runlogIndex", `{"freshness":{"runlogIndex":null}}`, []string{"declaredRecordCount", "shardCount", "freshness.runlogIndex"}},
		{"runlog index", `{"index":null}`, []string{"index", "recordCount"}},
		{"runlog recordCount", `{"recordCount":null}`, []string{"index", "recordCount"}},
		{"preamble recordCountInShard", `{"recordCountInShard":null}`, []string{"recordCountInShard"}},
		{"record plaintextSize", `{"plaintextSize":null}`, recordCountPaths},
		{"record packed.offset", `{"segments":[{"packed":{"offset":null,"length":1}}]}`, recordCountPaths},
		{"record packed.length", `{"segments":[{"packed":{"offset":0,"length":null}}]}`, recordCountPaths},
		{"record chunkRange element", `{"segments":[{"chunkRange":[0,null]}]}`, recordCountPaths},
	}
	for _, c := range cases {
		err := validateCounts([]byte(c.raw), c.paths...)
		if err == nil {
			t.Errorf("%s: null count was accepted", c.name)
			continue
		}
		var ee *ExitError
		if !errors.As(err, &ee) || ee.Code != ExitUsage {
			t.Errorf("%s: want ExitUsage, got %v", c.name, err)
		}
	}
}

func TestValidateCountsRefusesNullParent(t *testing.T) {
	rootPaths := []string{"declaredRecordCount", "shardCount", "freshness.runlogIndex"}
	cases := []struct {
		name  string
		raw   string
		paths []string
	}{
		{"root freshness", `{"freshness":null}`, rootPaths},
		{"record segments", `{"segments":null}`, recordCountPaths},
		{"record segment element", `{"segments":[null]}`, recordCountPaths},
		{"record chunkRange", `{"segments":[{"chunkRange":null,"packed":null}]}`, recordCountPaths},
	}
	for _, c := range cases {
		err := validateCounts([]byte(c.raw), c.paths...)
		if err == nil {
			t.Errorf("%s: null parent was accepted", c.name)
			continue
		}
		var ee *ExitError
		if !errors.As(err, &ee) || ee.Code != ExitUsage {
			t.Errorf("%s: want ExitUsage, got %v", c.name, err)
		}
	}
}

func TestValidateCountsAllowsNullPackedAndAbsent(t *testing.T) {
	cases := []struct {
		name  string
		raw   string
		paths []string
	}{
		{"whole-segment record", `{"plaintextSize":5,"segments":[{"chunkRange":[0,1],"packed":null}]}`, recordCountPaths},
		{"packed record", `{"plaintextSize":5,"segments":[{"chunkRange":[0,1],"packed":{"offset":0,"length":5}}]}`, recordCountPaths},
		{"absent freshness", `{"declaredRecordCount":1,"shardCount":1}`, []string{"declaredRecordCount", "shardCount", "freshness.runlogIndex"}},
		{"absent segments", `{"plaintextSize":5}`, recordCountPaths},
	}
	for _, c := range cases {
		if err := validateCounts([]byte(c.raw), c.paths...); err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
	}
}
