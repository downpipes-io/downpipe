package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
)

// THE RESTORE RECEIPT RECORDED 0 FOR A RESTORE THAT EXITED NON-ZERO.
//
// emitRestoreReceipt was handed the run-level code alone. A restore whose records failed with a
// per-record code (2 or 4 for a failed tag or hash, 11 for an unreachable segment, 13 when every
// failure was an absent segment) exited with that code and signed a receipt reading exitCode 0.
// verify --deep over the same archive folded the per-record code in, so its receipt disagreed
// with the restore receipt about one archive. A machine consumer reads the receipt, not the
// process status, so the restore receipt told it the restore was clean.
//
// This drives both commands over the two fixtures that fail per record, an absent segment and
// an altered one, and asserts that each receipt records the code its process exited with.

// receiptExitCode reads the exitCode member of an emitted receipt.
func receiptExitCode(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	var r struct {
		ExitCode *int `json:"exitCode"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("parse receipt: %v\n%s", err, raw)
	}
	if r.ExitCode == nil {
		t.Fatalf("receipt carries no exitCode:\n%s", raw)
	}
	return *r.ExitCode
}

func TestTheRestoreReceiptRecordsThePerRecordExitCode(t *testing.T) {
	silenceOutput(t)
	fixtures := []struct {
		name  string
		build func(t *testing.T) (dir, runID, idPath, signerPath string)
		want  int
	}{
		{"absent segment", danglingArchive, format.ExitDangling},
		{"altered segment", alteredArchive, format.ExitUnverified},
	}
	commands := []struct {
		name string
		verb []string
	}{
		{"verify --deep", []string{"verify", "--deep"}},
		{"restore --apply to a discard sink", []string{"restore", "--sink", "discard", "--apply"}},
	}
	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			dir, runID, idPath, signerPath := fx.build(t)
			for _, c := range commands {
				receiptPath := filepath.Join(t.TempDir(), "receipt.json")
				args := append(append([]string{}, c.verb...),
					"--archive", dir, "--run", runID, "--identity", idPath, "--signer", signerPath,
					"--acknowledge-no-rollback-pin", "--receipt", receiptPath)
				var code int
				_ = captureStderr(t, func() { code = run(args) })
				// The control: the process exit is the per-record code, so the fixture really does
				// fail per record and the receipt has something to disagree with.
				if code != fx.want {
					t.Fatalf("control: %s over an archive with an %s exited %d, want %d", c.name, fx.name, code, fx.want)
				}
				if got := receiptExitCode(t, receiptPath); got != code {
					t.Errorf("%s over an archive with an %s exited %d and its receipt records exitCode %d. The receipt is what a machine consumer reads, so it must record the same code", c.name, fx.name, code, got)
				}
			}
		})
	}
}

// TestFoldPerRecordExitKeepsTheSeverityOrder pins the precedence restore and verify --deep share.
// A per-record integrity code wins over a milder run-level one and loses to a more severe one.
// ExitDangling is taken only when the run reached no verdict of its own, because 13 is milder
// than 2 although it is the larger number.
func TestFoldPerRecordExitKeepsTheSeverityOrder(t *testing.T) {
	cases := []struct {
		code, record, want int
	}{
		{0, format.ExitDangling, format.ExitDangling},
		{0, format.ExitUnverified, format.ExitUnverified},
		{format.ExitUnverified, format.ExitDangling, format.ExitUnverified},
		{format.ExitUnverified, format.ExitPlaintext, format.ExitPlaintext},
		{format.ExitPlaintext, format.ExitUnverified, format.ExitPlaintext},
		// ExitUnreachable is 11, larger than every run-level code, and it says less than any of
		// them: the read got no bytes. A failed signature with an unreachable segment exits 2.
		{0, format.ExitUnreachable, format.ExitUnreachable},
		{format.ExitUnverified, format.ExitUnreachable, format.ExitUnverified},
		{format.ExitStale, format.ExitUnreachable, format.ExitStale},
		{format.ExitStale, format.ExitDangling, format.ExitStale},
		// The uncoded 1 is taken only when the run has no code of its own.
		{0, exitUncoded, exitUncoded},
		{format.ExitUnverified, exitUncoded, format.ExitUnverified},
	}
	for _, c := range cases {
		if got := foldPerRecordExit(c.code, c.record); got != c.want {
			t.Errorf("foldPerRecordExit(%d, %d) = %d, want %d", c.code, c.record, got, c.want)
		}
	}
}

// THE RESTORE RECEIPT FOR A REFUSED WRITE WAS OUTSIDE THE SCHEMA.
//
// When restore began to record the per-record code, a restore into a directory it could not
// write exited the uncoded 1 and signed a receipt reading exitCode 1. The schema's exitCode
// enum did not list 1, so every consumer that validates the receipt refused the one the reader
// wrote for the most common local restore failure. This drives that restore and validates the
// whole receipt against docs/format/schema.json, not only the exit code.
func TestTheReceiptForARefusedWriteIsSchemaValid(t *testing.T) {
	silenceOutput(t)
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory, so the write this test needs to fail succeeds")
	}
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("refused write receipt value"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath := filepath.Join(dir, "identity.key")
	signerPath := filepath.Join(dir, "signer.pub")
	if err := writeKeyFile(idPath, labelIdentity, crypto.MarshalKEMPrivate(identity)); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	if err := writeKeyFile(signerPath, labelSignerPublic, crypto.MarshalVerifier(verifier)); err != nil {
		t.Fatalf("write signer: %v", err)
	}
	outDir := filepath.Join(dir, "out")
	if err := os.Mkdir(outDir, 0o555); err != nil {
		t.Fatalf("mkdir read-only out: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(outDir, 0o755) })

	receiptPath := filepath.Join(t.TempDir(), "receipt.json")
	code := run([]string{"restore", "--archive", dir, "--run", runID, "--identity", idPath,
		"--signer", signerPath, "--out", outDir, "--apply", "--acknowledge-no-rollback-pin",
		"--receipt", receiptPath})
	// The control: the write really was refused, so the receipt carries the uncoded 1.
	if code != exitUncoded {
		t.Fatalf("control: restore into a read-only directory = %d, want %d", code, exitUncoded)
	}
	if got := receiptExitCode(t, receiptPath); got != code {
		t.Fatalf("the process exited %d and the receipt records exitCode %d", code, got)
	}
	schema := loadReceiptSchema(t)
	receipt := readReceiptRaw(t, receiptPath)
	if errs := schemaErrors(schema, schemaDef(t, schema, "RestoreReceipt"), receipt, "receipt"); len(errs) > 0 {
		t.Errorf("the receipt for a refused write is not valid against docs/format/schema.json:\n  %s", strings.Join(errs, "\n  "))
	}

	// The negative controls: the validator rejects a code outside the enum and a member the
	// schema does not name, so the pass above is not a validator that accepts everything.
	for name, mutate := range map[string]func(map[string]any){
		"an exitCode outside the enum":      func(r map[string]any) { r["exitCode"] = float64(7) },
		"a member the schema does not name": func(r map[string]any) { r["notInTheSchema"] = true },
		"a target type outside the enum": func(r map[string]any) {
			r["target"] = map[string]any{"type": "s3", "valueVerified": false}
		},
	} {
		bad := readReceiptRaw(t, receiptPath)
		mutate(bad)
		if errs := schemaErrors(schema, schemaDef(t, schema, "RestoreReceipt"), bad, "receipt"); len(errs) == 0 {
			t.Errorf("negative control: the validator accepted a receipt with %s", name)
		}
	}
}

// loadReceiptSchema parses docs/format/schema.json from this package's directory.
func loadReceiptSchema(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "format", "schema.json"))
	if err != nil {
		t.Fatalf("read schema.json: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse schema.json: %v", err)
	}
	return doc
}

func schemaDef(t *testing.T, root map[string]any, name string) map[string]any {
	t.Helper()
	defs, _ := root["$defs"].(map[string]any)
	def, ok := defs[name].(map[string]any)
	if !ok {
		t.Fatalf("schema.json has no $defs.%s", name)
	}
	return def
}

// schemaErrors checks v against a JSON Schema node for the keywords the receipt schema uses.
// The module takes no JSON Schema dependency, so this is a small validator. It reports any
// keyword it does not implement as an error, so a later schema change that it cannot check
// turns this test red instead of passing it without a check.
func schemaErrors(root, node map[string]any, v any, at string) []string {
	var errs []string
	keys := make([]string, 0, len(node))
	for k := range node {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch k {
		case "$ref":
			ref, _ := node[k].(string)
			name, ok := strings.CutPrefix(ref, "#/$defs/")
			defs, _ := root["$defs"].(map[string]any)
			def, found := defs[name].(map[string]any)
			if !ok || !found {
				errs = append(errs, fmt.Sprintf("%s: unresolvable $ref %q", at, ref))
				continue
			}
			errs = append(errs, schemaErrors(root, def, v, at)...)
		case "oneOf":
			alts, _ := node[k].([]any)
			matched := 0
			for _, a := range alts {
				if sub, ok := a.(map[string]any); ok && len(schemaErrors(root, sub, v, at)) == 0 {
					matched++
				}
			}
			if matched != 1 {
				errs = append(errs, fmt.Sprintf("%s: %d oneOf branches match, want 1", at, matched))
			}
		case "type":
			if !schemaTypeMatches(node[k].(string), v) {
				errs = append(errs, fmt.Sprintf("%s: %v is not of type %s", at, v, node[k]))
			}
		case "const":
			if !reflect.DeepEqual(v, node[k]) {
				errs = append(errs, fmt.Sprintf("%s: %v is not the const %v", at, v, node[k]))
			}
		case "enum":
			found := false
			for _, e := range node[k].([]any) {
				if reflect.DeepEqual(v, e) {
					found = true
				}
			}
			if !found {
				errs = append(errs, fmt.Sprintf("%s: %v is not in the enum %v", at, v, node[k]))
			}
		case "pattern":
			if s, ok := v.(string); ok && !regexp.MustCompile(node[k].(string)).MatchString(s) {
				errs = append(errs, fmt.Sprintf("%s: %q does not match %s", at, s, node[k]))
			}
		case "minLength":
			if s, ok := v.(string); ok && float64(len([]rune(s))) < node[k].(float64) {
				errs = append(errs, fmt.Sprintf("%s: %q is shorter than %v", at, s, node[k]))
			}
		case "minimum":
			if n, ok := v.(float64); ok && n < node[k].(float64) {
				errs = append(errs, fmt.Sprintf("%s: %v is below %v", at, n, node[k]))
			}
		case "maximum":
			if n, ok := v.(float64); ok && n > node[k].(float64) {
				errs = append(errs, fmt.Sprintf("%s: %v is above %v", at, n, node[k]))
			}
		case "required":
			if obj, ok := v.(map[string]any); ok {
				for _, r := range node[k].([]any) {
					if _, has := obj[r.(string)]; !has {
						errs = append(errs, fmt.Sprintf("%s: required member %q is absent", at, r))
					}
				}
			}
		case "properties":
			obj, ok := v.(map[string]any)
			if !ok {
				continue
			}
			props := node[k].(map[string]any)
			for name, sub := range props {
				if val, has := obj[name]; has {
					errs = append(errs, schemaErrors(root, sub.(map[string]any), val, at+"."+name)...)
				}
			}
		case "additionalProperties":
			if node[k] != false {
				errs = append(errs, fmt.Sprintf("%s: additionalProperties %v is not implemented here", at, node[k]))
				continue
			}
			obj, ok := v.(map[string]any)
			if !ok {
				continue
			}
			props, _ := node["properties"].(map[string]any)
			for name := range obj {
				if _, known := props[name]; !known {
					errs = append(errs, fmt.Sprintf("%s: member %q is not in the schema", at, name))
				}
			}
		case "description":
		default:
			errs = append(errs, fmt.Sprintf("%s: schema keyword %q is not implemented by this validator", at, k))
		}
	}
	return errs
}

func schemaTypeMatches(want string, v any) bool {
	switch want {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "null":
		return v == nil
	case "integer":
		n, ok := v.(float64)
		return ok && n == math.Trunc(n)
	}
	return false
}
