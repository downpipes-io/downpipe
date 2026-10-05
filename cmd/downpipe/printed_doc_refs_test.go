package main

import (
	"strings"
	"testing"
)

// The runbooks and the help point an operator at pages they can open. Of the engine's docs, only
// OPERATIONS.md is published with the engine. The token scopes and the upgrade runbook are on the
// docs site, so the printed text names those pages by URL.
const (
	tokenScopesURL = "https://docs.downpipes.io/operations/cloudflare-token-scopes"
	upgradesURL    = "https://docs.downpipes.io/operations/upgrades-and-rollback"
)

// engineDocRefsOtherThanOperations returns each engine/docs/ file the text names, other than
// OPERATIONS.md.
func engineDocRefsOtherThanOperations(text string) []string {
	var found []string
	rest := text
	for {
		i := strings.Index(rest, "engine/docs/")
		if i < 0 {
			return found
		}
		rest = rest[i+len("engine/docs/"):]
		if !strings.HasPrefix(rest, "OPERATIONS.md") {
			end := strings.IndexAny(rest, " \n\t),")
			if end < 0 {
				end = len(rest)
			}
			found = append(found, "engine/docs/"+strings.TrimRight(rest[:end], "."))
		}
	}
}

func TestPrintedTextNamesOnlyPagesAnOperatorCanOpen(t *testing.T) {
	texts := map[string]string{
		"init plan":   initPlan("eng.example.com", "con.example.com", "example.com", "archives"),
		"update plan": updatePlan("", "eng.example.com", "con.example.com"),
		"help":        captureUsage(t),
	}
	wants := map[string][]string{
		"init plan":   {tokenScopesURL, "engine/docs/OPERATIONS.md"},
		"update plan": {tokenScopesURL, upgradesURL, "engine/docs/OPERATIONS.md"},
		"help":        {tokenScopesURL, upgradesURL},
	}
	for name, text := range texts {
		if refs := engineDocRefsOtherThanOperations(text); len(refs) > 0 {
			t.Errorf("the %s names %v, which the engine does not publish", name, refs)
		}
		for _, want := range wants[name] {
			if !strings.Contains(text, want) {
				t.Errorf("the %s does not name %s:\n%s", name, want, text)
			}
		}
	}
}

// The init runbook states the token custody the engine has, and
// TestInitPlanStatesTheTokenAndKeyCustodyTheEngineHas holds it there. The help describes init in one
// paragraph and must not contradict it: the engine can store the optional read-only discovery token.
func TestHelpStatesTheTokenCustodyTheEngineHas(t *testing.T) {
	help := strings.Join(strings.Fields(captureUsage(t)), " ")
	if strings.Contains(help, "holds no Cloudflare API token") {
		t.Errorf("the help says the engine holds no Cloudflare API token, but it can store the optional read-only discovery token:\n%s", help)
	}
	if !strings.Contains(help, "optional read-only discovery token") {
		t.Errorf("the help does not name the optional read-only discovery token:\n%s", help)
	}
}

func TestEngineDocRefsOtherThanOperationsFindsAnUnpublishedFile(t *testing.T) {
	got := engineDocRefsOtherThanOperations("See engine/docs/OPERATIONS.md and engine/docs/UPDATES.md.\nAlso (engine/docs/CLOUDFLARE-PERMISSIONS.md)")
	want := []string{"engine/docs/UPDATES.md", "engine/docs/CLOUDFLARE-PERMISSIONS.md"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("engineDocRefsOtherThanOperations = %q, want %q", got, want)
	}
}
