package format

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// schemaPath is docs/format/schema.json relative to this package (internal/format).
const schemaPath = "../../docs/format/schema.json"

// loadSchema parses the on-disk JSON schema so a test can read an enum out of it and
// confirm it agrees with what the binary emits. The validate.js harness validates the
// cleartext root manifest and the RUNLOG, but NOT the receipt or the (encrypted) shard
// record; those shapes are the Go reader's contract, so the schema-vs-code reconciliation
// for them is asserted here, with no third-party JSON-schema dependency.
func loadSchema(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(schemaPath))
	if err != nil {
		t.Fatalf("read schema.json: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse schema.json: %v", err)
	}
	return doc
}

// enumAt walks a dotted path of object keys from the schema root to an "enum" array and
// returns it as a set of strings. It fails the test if any step is missing, so a renamed
// or removed schema node is caught rather than silently skipped.
func enumAt(t *testing.T, doc map[string]any, path ...string) map[string]struct{} {
	t.Helper()
	cur := any(doc)
	walked := ""
	for _, key := range path {
		walked += "/" + key
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("schema path %s: parent is not an object", walked)
		}
		cur, ok = m[key]
		if !ok {
			t.Fatalf("schema path %s: key missing", walked)
		}
	}
	arr, ok := cur.([]any)
	if !ok {
		t.Fatalf("schema path %s is not an array", "/"+joinPath(path))
	}
	set := make(map[string]struct{}, len(arr))
	for _, v := range arr {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("schema enum %s has a non-string member %v", "/"+joinPath(path), v)
		}
		set[s] = struct{}{}
	}
	return set
}

func joinPath(path []string) string {
	out := ""
	for i, p := range path {
		if i > 0 {
			out += "/"
		}
		out += p
	}
	return out
}

func sortedSetKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The schema's sourceType enum must equal EXACTLY the supported set the reader enforces
// (SPEC.md 12.1): no emitted/accepted type missing from the schema, and no dead enum value
// the reader would refuse. This is the drift that previously left workers and cf-config out
// of the schema even though the engine writes them and the reader now accepts them.
func TestSchemaSourceTypeEnumMatchesReader(t *testing.T) {
	doc := loadSchema(t)
	schemaEnum := enumAt(t, doc, "$defs", "sourceType", "enum")

	want := map[string]struct{}{
		spec.SourceKV:        {},
		spec.SourceR2:        {},
		spec.SourceSecrets:   {},
		spec.SourceD1:        {},
		spec.SourceWorkers:   {},
		spec.SourceCFConfig:  {},
		spec.SourceStream:    {},
		spec.SourceImages:    {},
		spec.SourceArtifacts: {},
	}

	for s := range want {
		if _, ok := schemaEnum[s]; !ok {
			t.Errorf("schema sourceType enum is missing %q, which the reader accepts (SPEC.md 12.1)", s)
		}
		if !spec.IsKnownSourceType(s) {
			t.Errorf("internal inconsistency: %q is in the want set but IsKnownSourceType is false", s)
		}
	}
	for s := range schemaEnum {
		if _, ok := want[s]; !ok {
			t.Errorf("schema sourceType enum has %q, which the reader does not accept (a dead/drifted enum value)", s)
		}
		if !spec.IsKnownSourceType(s) {
			t.Errorf("schema sourceType enum has %q, which IsKnownSourceType refuses", s)
		}
	}
	if t.Failed() {
		t.Logf("schema enum: %v; reader set: %v", sortedSetKeys(schemaEnum), sortedSetKeys(want))
	}
}

// The schema's RestoreReceipt target.type enum must equal EXACTLY the set of target types
// the binary actually emits: the three restore sinks (file, env, discard) and "verify" for
// a verify-only run. Previously the schema listed secrets-store/secrets-manager/env-file/
// s3/kv/stdout, NONE of which this offline tool emits, while the values it does emit were
// absent, so a real receipt would have failed its own schema.
func TestSchemaReceiptTargetTypeEnumMatchesEmitted(t *testing.T) {
	doc := loadSchema(t)
	schemaEnum := enumAt(t, doc, "$defs", "RestoreReceipt", "properties", "target", "properties", "type", "enum")

	// The exhaustive set of target.type values BuildReceipt/emitReceipt can carry: the
	// restore Target.Kind() values plus the verify path's literal "verify".
	emitted := map[string]struct{}{
		"file":    {}, // restore.DirTarget.Kind()
		"env":     {}, // restore.EnvTarget.Kind()
		"discard": {}, // restore.DiscardTarget.Kind()
		"verify":  {}, // cmd/downpipe verify.go
	}

	for s := range emitted {
		if _, ok := schemaEnum[s]; !ok {
			t.Errorf("schema receipt target.type enum is missing %q, which the binary emits", s)
		}
	}
	for s := range schemaEnum {
		if _, ok := emitted[s]; !ok {
			t.Errorf("schema receipt target.type enum has %q, which the binary never emits (a dead/drifted enum value)", s)
		}
	}
	if t.Failed() {
		t.Logf("schema enum: %v; emitted set: %v", sortedSetKeys(schemaEnum), sortedSetKeys(emitted))
	}
}

// A real receipt built for each emitted target type must carry a target.type the schema's
// enum admits. This binds the actual emitted bytes (not just a hand-listed set) to the
// schema, so a future change to either side that desynchronises them fails here. It is the
// receipt-schema validation the production review asked for; the validate.js harness does
// not cover the receipt.
func TestReceiptTargetTypeIsSchemaValid(t *testing.T) {
	const runID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	store := memStore{}
	bgPriv, verifier := buildArchive(t, buildSpec{store: store, runID: runID, dpID: "dp_schema", value: []byte("v"), secret: false, codec: spec.CodecNameNone})
	r, err := Open(store, runID, bgPriv, verifier, Options{})
	if err != nil {
		t.Fatal(err)
	}

	doc := loadSchema(t)
	schemaEnum := enumAt(t, doc, "$defs", "RestoreReceipt", "properties", "target", "properties", "type", "enum")

	for _, targetType := range []string{"verify", "file", "env", "discard"} {
		rcpt := BuildReceipt(r, ReceiptInput{
			StartedAt: "2026-06-07T00:00:00.000Z", FinishedAt: "2026-06-07T00:00:01.000Z",
			TargetType: targetType,
		})
		emitted, err := rcpt.Marshal()
		if err != nil {
			t.Fatalf("marshal receipt (%s): %v", targetType, err)
		}
		// Parse the emitted bytes back and read target.type out, the field a consumer sees.
		var parsed struct {
			Target struct {
				Type string `json:"type"`
			} `json:"target"`
		}
		if err := json.Unmarshal(emitted, &parsed); err != nil {
			t.Fatalf("parse emitted receipt (%s): %v", targetType, err)
		}
		if parsed.Target.Type != targetType {
			t.Fatalf("emitted target.type = %q, want %q", parsed.Target.Type, targetType)
		}
		if _, ok := schemaEnum[parsed.Target.Type]; !ok {
			t.Fatalf("emitted target.type %q is not admitted by the schema enum %v", parsed.Target.Type, sortedSetKeys(schemaEnum))
		}
	}
}
