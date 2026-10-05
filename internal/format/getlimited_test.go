package format

import (
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/source"
)

// Compile-time proof that every shipped backend offers the bounded read, so the root,
// RUNLOG and signature caps are enforced before the read in the dir, S3 and Azure stores alike.
var (
	_ LimitStore = (*source.DirStore)(nil)
	_ LimitStore = (*source.S3Store)(nil)
	_ LimitStore = (*source.AzureStore)(nil)
)

// TestGetLimitedRefusesAnOversizedObjectFromAPlainStore pins the fallback for a store
// without the LimitStore capability: the object is read through Get and then refused
// with the same wording, and an object at the ceiling reads.
func TestGetLimitedRefusesAnOversizedObjectFromAPlainStore(t *testing.T) {
	store := memStore{"at": make([]byte, 8), "over": make([]byte, 9)}
	if got, err := GetLimited(store, "at", 8); err != nil || len(got) != 8 {
		t.Fatalf("an object at the ceiling must read: %d bytes, %v", len(got), err)
	}
	if _, err := GetLimited(store, "over", 8); err == nil || !strings.Contains(err.Error(), "read object over: 9 bytes exceeds the 8-byte limit") {
		t.Fatalf("an object above the ceiling must be refused, got: %v", err)
	}
	if _, err := GetLimited(store, "absent", 8); err == nil || !strings.Contains(err.Error(), "object not found") {
		t.Fatalf("a read failure must pass through, got: %v", err)
	}
}
