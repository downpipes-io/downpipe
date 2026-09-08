package restore

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"testing"
	"time"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/source"
)

// Memory regression tripwires for the streaming restore path.
//
// Opt in with DOWNPIPE_MEMCHECK=1 (or `make memcheck`), matching the repo's existing
// opt-in convention for expensive tests. Env-gated rather than build-tagged so the file
// stays compiled, vetted and linted on every ordinary run.
//
// These are TRIPWIRES, not performance claims: they assert the two properties the
// streaming work exists to guarantee, with generous headroom so ordinary GC jitter
// cannot red them.
//
//  1. Peak heap does not scale with the LARGEST RECORD. This is the property that broke
//     when the per-record streaming path was dead code: one 128 MiB record drove peak RSS
//     to 608 MB. The assertion is a delta, not an absolute: restoring an archive WITH a
//     large record must not cost materially more heap than the same archive without it.
//  2. Peak heap stays under a ceiling calibrated to the measured post-fix figure with a
//     wide margin, so a re-buffering regression anywhere on the path is caught.
const (
	memcheckSmallRecords = 2000
	memcheckSmallValue   = 4 << 10
	memcheckBigValue     = 32 << 20
	// The heap ceiling and the with/without-big-record delta. The measured streaming
	// restore of a 100k-record, 544 MB archive holding a 128 MiB record peaks at ~54 MB
	// RSS; this harness runs a much smaller archive, so the ceiling is generous and the
	// delta is the sharp instrument.
	memcheckHeapCeiling = 96 << 20
	memcheckHeapDelta   = 24 << 20
)

// peakHeapDuring samples HeapAlloc on a ticker while fn runs and returns the peak. The
// GC is pinned tighter than default for the duration so a lazy collection cannot inflate
// the sample, and a collection runs before the measurement so the baseline is clean.
func peakHeapDuring(fn func()) uint64 {
	old := debug.SetGCPercent(50)
	defer debug.SetGCPercent(old)
	runtime.GC()

	var peak atomic.Uint64
	done := make(chan struct{})
	go func() {
		tick := time.NewTicker(2 * time.Millisecond)
		defer tick.Stop()
		var ms runtime.MemStats
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				runtime.ReadMemStats(&ms)
				for {
					cur := peak.Load()
					if ms.HeapAlloc <= cur || peak.CompareAndSwap(cur, ms.HeapAlloc) {
						break
					}
				}
			}
		}
	}()
	fn()
	close(done)
	return peak.Load()
}

// restoreForMemcheck builds a real sealed archive on disk and restores it through the
// streaming reader to the discard sink, returning the peak heap observed.
func restoreForMemcheck(t *testing.T, withBigRecord bool) uint64 {
	t.Helper()
	values := make(map[string]string, memcheckSmallRecords+1)
	for i := 0; i < memcheckSmallRecords; i++ {
		values[fmt.Sprintf("rec/%05d", i)] = string(bytes.Repeat([]byte{byte(i)}, memcheckSmallValue))
	}
	if withBigRecord {
		values["rec/big"] = string(bytes.Repeat([]byte{0x5a}, memcheckBigValue))
	}

	store := memStore{}
	identity, verifier, runID := buildArchive(t, store, "dp_memcheck", "r2", values)

	// Spill the archive to disk and read it back through the real DirStore, so the
	// measurement covers the actual store reads (which stream) rather than a map lookup.
	dir := t.TempDir()
	writeStoreToDir(t, store, dir)

	// EVERY fixture must be dead before the measurement, or the harness measures its own
	// inputs rather than the restore path. The record count is hoisted out so the closure
	// below captures no fixture (a closure over `values` would pin the whole big record
	// live through the measurement, which is exactly the mistake this comment exists to
	// prevent); the sealed objects are dropped from the store map; and a collection runs
	// so only the on-disk archive survives into the sample.
	wantRecords := len(values)
	for k := range store {
		delete(store, k)
	}
	runtime.GC()

	return peakHeapDuring(func() {
		r, err := format.StreamOpen(source.NewDirStore(dir), runID, identity, verifier, format.Options{})
		if err != nil {
			t.Fatalf("stream open: %v", err)
		}
		target := NewDiscardTarget()
		_, res, err := ApplyStreaming(r, target, true)
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		if !res.OK() || res.Restored != wantRecords {
			t.Fatalf("restore: restored=%d of %d, failed=%v", res.Restored, wantRecords, res.Failed)
		}
	})
}

func TestMemcheckStreamingRestoreStaysBounded(t *testing.T) {
	if os.Getenv("DOWNPIPE_MEMCHECK") != "1" {
		t.Skip("set DOWNPIPE_MEMCHECK=1 (or run `make memcheck`) to run the memory tripwires")
	}

	withoutBig := restoreForMemcheck(t, false)
	withBig := restoreForMemcheck(t, true)

	t.Logf("peak heap: %.1f MiB without the big record, %.1f MiB with it (delta %.1f MiB)",
		float64(withoutBig)/(1<<20), float64(withBig)/(1<<20),
		float64(int64(withBig)-int64(withoutBig))/(1<<20))

	if withBig > memcheckHeapCeiling {
		t.Fatalf("peak heap %.1f MiB exceeds the %.0f MiB ceiling: something on the restore path is buffering",
			float64(withBig)/(1<<20), float64(memcheckHeapCeiling)/(1<<20))
	}
	// The keystone property: adding a 32 MiB record must not add 32 MiB of heap. If the
	// per-record streaming path regresses to buffering, this delta blows out immediately.
	if delta := int64(withBig) - int64(withoutBig); delta > memcheckHeapDelta {
		t.Fatalf("adding a %d MiB record raised peak heap by %.1f MiB (limit %.0f MiB): the record is being buffered, not streamed",
			memcheckBigValue>>20, float64(delta)/(1<<20), float64(memcheckHeapDelta)/(1<<20))
	}
}
