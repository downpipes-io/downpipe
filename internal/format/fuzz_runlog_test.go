package format

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// FuzzRunlogKeyless fuzzes the ONE place fully arbitrary bytes reach the RUNLOG parser
// before any signature shields it: the keyless paths (attest without --signer, and
// `keys --which`) parse whatever the bucket holds. Everywhere else the RUNLOG signature
// is verified first, so a mutation dies at the signature and never reaches this parser.
//
// The invariants are safety, not acceptance: no panic, no unbounded growth, and a
// parse that succeeds must return entries whose declared fields are internally
// consistent, so the chain-anomaly detector downstream cannot be fed nonsense it will
// dereference. The chain detector itself is driven over the parsed entries, because a
// hostile bucket can present ANY set of well-formed entries: it must classify without
// panicking, whatever the ordering, indices or previous-run links say.
func FuzzRunlogKeyless(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("\n\n\n"))
	f.Add([]byte(`{"index":1,"runId":"01ARZ3NDEKTSV4RRFFQ69G5FAV","downpipeId":"dp","time":"2026-01-01T00:00:00.000Z","recordCount":1,"prevRunId":null,"status":"ok"}`))
	f.Add([]byte(`{"index":9007199254740993}`))
	f.Add([]byte(`{"index":-1}`))
	f.Add([]byte(`{"index":"1"}`))
	f.Add([]byte("{}\n{}\n{}"))
	f.Add([]byte(`{"index":0,"runId":"","downpipeId":"","time":"","recordCount":0,"prevRunId":"","status":""}`))
	// A real RUNLOG from the corpus, so the fuzzer starts from a structurally valid log.
	if b, err := os.ReadFile(filepath.Join("testdata", "vectors", "seg-single-chunk", "archive", "_RECOVERY", "RUNLOG")); err == nil {
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Bound the input: the parser is line-oriented, and a multi-megabyte input tells
		// us nothing a small one does not while eating the whole fuzz budget.
		if len(data) > 1<<16 {
			return
		}
		entries, err := ParseRunlog(data)
		if err != nil {
			if entries != nil {
				t.Fatalf("a rejected RUNLOG must not also return entries (got %d)", len(entries))
			}
			return
		}
		// An accepted parse must not invent entries out of nothing: every entry must
		// correspond to a non-blank line of the input.
		lines := 0
		for _, l := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(l) != "" {
				lines++
			}
		}
		if len(entries) > lines {
			t.Fatalf("parsed %d entries from %d non-blank lines", len(entries), lines)
		}
		for _, e := range entries {
			if e.Index < 0 {
				t.Fatalf("accepted a negative index %d", e.Index)
			}
			if e.RecordCount < 0 {
				t.Fatalf("accepted a negative recordCount %d", e.RecordCount)
			}
		}
		// The chain detector runs on whatever a hostile bucket presents. It must
		// classify, never panic, whatever the entry set says.
		_ = detectChainAnomaly(entries)
	})
}

// FuzzRunlogChainAnomaly drives the chain detector over ARBITRARY well-formed entry
// sets (built from the fuzz input rather than parsed from it), so the ordering, index
// and prev-link logic is exercised far past what a JSON parser will ever hand it: a
// hostile bucket can sign nothing and still present any shape it likes to the keyless
// tier.
func FuzzRunlogChainAnomaly(f *testing.F) {
	f.Add([]byte{1, 0, 2, 0, 3, 0})
	f.Add([]byte{1, 1, 1, 1})
	f.Add([]byte{})
	f.Add([]byte{255, 255, 0, 0, 128, 7})

	f.Fuzz(func(_ *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		// Each 2-byte group becomes one entry: an index and a link selector, so the
		// fuzzer explores gaps, duplicates, forks and out-of-order runs cheaply.
		entries := make([]spec.RunlogEntry, 0, len(data)/2)
		for i := 0; i+1 < len(data); i += 2 {
			idx := int64(data[i])
			link := data[i+1]
			e := spec.RunlogEntry{
				RunID:       runIDForByte(byte(len(entries))),
				DownpipeID:  "dp_fuzz",
				Index:       idx,
				RecordCount: 1,
				Time:        "2026-01-01T00:00:00.000Z",
				Status:      "ok",
			}
			if link != 0 && len(entries) > 0 {
				prev := entries[int(link)%len(entries)].RunID
				e.PrevRunID = &prev
			}
			entries = append(entries, e)
		}
		_ = detectChainAnomaly(entries)
	})
}

// runIDForByte builds a distinct valid ULID per entry so the chain logic sees real run
// ids rather than empty strings.
func runIDForByte(b byte) string {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	return "01ARZ3NDEKTSV4RRFFQ69G5F" + string(alphabet[int(b)%32]) + string(alphabet[int(b/32)%32])
}
