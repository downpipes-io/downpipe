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

// TestCaseCollidingDuplicateKeyIsRefusedEvenWithCanonicalKeyPresent proves the
// case-collision check fires even when the canonical key is ALSO present: an object
// carrying BOTH the canonical key and a re-cased duplicate must still be refused, not
// slip through because resolvePath's exact-name lookup finds and validates only the
// harmless canonical key. encoding/json's Unmarshal, walking the same raw bytes
// independently, binds whichever of the two keys appears LAST in the object
// (attacker-controlled byte order, not spelling), so {"index":1,"Index":999999} would
// otherwise validate the harmless "index":1 while the field it protects ends up holding
// 999999, defeating the keyless freshness self-consistency check with no signature to
// forge. Key order is what flips it: canonical-first, decoy-last is the exploitable
// order, which is why this needs its own case rather than being implied by the "absent"
// test above.
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
