package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// TestSecretsWiringDescriptorDecodes pins that the reader decodes the secrets wiring the
// engine writes (SPEC.md 12.3): the scopes, the comment, every Worker that binds the
// secret and whether that list is complete. It decodes a real record line with the same
// plain json.Unmarshal OpenShard uses, then renders it the way inspect prints it. A reader
// that dropped these members would show a secret as bound by no Worker.
func TestSecretsWiringDescriptorDecodes(t *testing.T) {
	line := `{"kind":"record","sourceType":"secrets","name":"API_KEY","secrets":{"store":"0123abcd","bindingVar":"SRC_SEC_api_key","scopes":["ai_gateway","workers"],"comment":"prod API key","workers":[{"script":"api","binding":"KEY"},{"script":"web","binding":"UPSTREAM_KEY"}],"wiring":"captured"}}`
	var rec spec.ShardRecord
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := describeRestoreDescriptor(rec)
	for _, want := range []string{`store="0123abcd"`, `binding="SRC_SEC_api_key"`, `scopes="ai_gateway,workers"`, `workers="api:KEY,web:UPSTREAM_KEY"`, "wiring=captured", `comment="prod API key"`} {
		if !strings.Contains(got, want) {
			t.Errorf("describeRestoreDescriptor = %q, want it to contain %q", got, want)
		}
	}
	unknown := `{"kind":"record","sourceType":"secrets","name":"API_KEY","secrets":{"store":"0123abcd","wiring":"unknown"}}`
	var rec2 spec.ShardRecord
	if err := json.Unmarshal([]byte(unknown), &rec2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := describeRestoreDescriptor(rec2); !strings.Contains(got, "wiring=unknown") {
		t.Errorf("an unknown wiring must say so, got %q", got)
	}
}
