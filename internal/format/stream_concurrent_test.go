package format

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// countingStore wraps an ObjectStore to observe the prefetcher's concurrency for the
// shard-prefetch tests. It tracks the maximum number of SHARD GETs (.dpe objects) in flight
// at once with an atomic counter, can delay a key's GET by a per-key latency (to overlap and
// to reorder completions), and can fail a chosen key. The non-shard gets (root manifest,
// signature, runlog, recovery bundle) are sequential up-front and not counted, so maxInFlight
// is exactly the shard-fetch parallelism. It is safe for concurrent Get.
type countingStore struct {
	inner       ObjectStore
	latency     map[string]time.Duration
	failKey     string
	failErr     error
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
	shardGets   atomic.Int32
}

func (c *countingStore) Get(key string) ([]byte, error) {
	if strings.HasSuffix(key, ".dpe") {
		cur := c.inFlight.Add(1)
		for {
			old := c.maxInFlight.Load()
			if cur <= old || c.maxInFlight.CompareAndSwap(old, cur) {
				break
			}
		}
		c.shardGets.Add(1)
		defer c.inFlight.Add(-1)
	}
	if d := c.latency[key]; d > 0 {
		time.Sleep(d)
	}
	if c.failKey != "" && key == c.failKey {
		if c.failErr != nil {
			return nil, c.failErr
		}
		return nil, fmt.Errorf("simulated read failure for %s", key)
	}
	return c.inner.Get(key)
}

// uniformShardLatency builds a per-key latency map giving every shard object the same GET
// delay, so a multi-shard walk overlaps its fetches under concurrency.
func uniformShardLatency(nshards int, d time.Duration) map[string]time.Duration {
	m := make(map[string]time.Duration, nshards)
	for s := 0; s < nshards; s++ {
		m[runKey(vecRunID, fmt.Sprintf("manifest/%05d.dpe", s))] = d
	}
	return m
}

// streamReadIDsAndRoot opens the archive in the given prefetch mode and streams every record
// through EachRecord, returning the delivered RecordIDs in delivery order, the Merkle root it
// recomputes by folding the delivered record hashes (the apply-pass accumulator), and the
// signed root from the verified manifest. Both passes run: StreamOpen's verify pass and the
// EachRecord apply pass, each through walkShards in the chosen mode.
func streamReadIDsAndRoot(t *testing.T, store ObjectStore, bgPriv *crypto.HybridKEMPrivate, verifier *crypto.HybridVerifier, concurrency int, maxMem int64) (ids []string, recomputed, signed string) {
	t.Helper()
	sr, err := StreamOpen(store, vecRunID, bgPriv, verifier, Options{FetchConcurrency: concurrency, MaxMemoryBytes: maxMem})
	if err != nil {
		t.Fatalf("StreamOpen(concurrency=%d, maxMem=%d): %v", concurrency, maxMem, err)
	}
	var acc MerkleAccumulator
	if err := sr.EachRecord(func(rec spec.ShardRecord) error {
		ids = append(ids, rec.RecordID)
		rh, derr := hex.DecodeString(rec.RecordHash)
		if derr != nil {
			return derr
		}
		acc.Push(rh)
		return nil
	}); err != nil {
		t.Fatalf("EachRecord(concurrency=%d): %v", concurrency, err)
	}
	return ids, hex.EncodeToString(acc.Root()), sr.Root().MerkleRoot
}

// TestWalkShardsConcurrentByteIdenticalRoot is the keystone invariant: a prefetch window must
// change ONLY the fetch schedule, never the result. It restores one multi-shard archive at
// FetchConcurrency=1 (the sequential bounded-memory default) and =8 and asserts the recomputed
// Merkle root, the signed root, and the full restored record stream are identical -- the
// single-threaded ordered consumer folds the concurrently-fetched shards in canonical order, so
// the fold is byte-identical to sequential.
func TestWalkShardsConcurrentByteIdenticalRoot(t *testing.T) {
	store, bgPriv, verifier, _ := buildMultiShardArchive(t, "dp_par_root", 200, 40)

	seqIDs, seqRoot, signed := streamReadIDsAndRoot(t, store, bgPriv, verifier, 1, 0)
	parIDs, parRoot, signed8 := streamReadIDsAndRoot(t, store, bgPriv, verifier, 8, 0)

	if seqRoot != parRoot {
		t.Fatalf("recomputed Merkle root differs under concurrency: seq %s vs c=8 %s", seqRoot, parRoot)
	}
	if seqRoot != signed || parRoot != signed8 {
		t.Fatalf("recomputed root does not equal the signed root: seq=%s c8=%s signed=%s/%s", seqRoot, parRoot, signed, signed8)
	}
	if len(seqIDs) != 200 || len(parIDs) != 200 {
		t.Fatalf("record counts: seq=%d par=%d, want 200", len(seqIDs), len(parIDs))
	}
	for i := range seqIDs {
		if seqIDs[i] != parIDs[i] {
			t.Fatalf("restored record %d differs: seq %q vs c=8 %q", i, seqIDs[i], parIDs[i])
		}
	}
}

// TestWalkShardsConcurrentOrderedDelivery proves canonical delivery even when later shards
// finish FIRST. Each shard's GET is delayed so shard 0 returns slowest and the last shard
// fastest; with the window wide enough to hold them all, completion order is reversed. The
// consumer must still deliver records in ascending (canonical) order, and the verify pass must
// still reproduce the signed root (StreamOpen succeeds), proving the reorder buffer restores
// order before the single-threaded fold/apply sees a record.
func TestWalkShardsConcurrentOrderedDelivery(t *testing.T) {
	const nshards = 16
	store, bgPriv, verifier, _ := buildMultiShardArchive(t, "dp_par_order", nshards, nshards) // 1 record per shard
	cs := &countingStore{inner: store, latency: map[string]time.Duration{}}
	for s := 0; s < nshards; s++ {
		key := runKey(vecRunID, fmt.Sprintf("manifest/%05d.dpe", s))
		cs.latency[key] = time.Duration(nshards-s) * 2 * time.Millisecond // later shards return faster
	}

	sr, err := StreamOpen(cs, vecRunID, bgPriv, verifier, Options{FetchConcurrency: nshards})
	if err != nil {
		t.Fatalf("StreamOpen: %v", err)
	}
	var ids []string
	if err := sr.EachRecord(func(rec spec.ShardRecord) error {
		ids = append(ids, rec.RecordID)
		return nil
	}); err != nil {
		t.Fatalf("EachRecord: %v", err)
	}
	if len(ids) != nshards {
		t.Fatalf("got %d records, want %d", len(ids), nshards)
	}
	for i := 1; i < len(ids); i++ {
		if ids[i-1] >= ids[i] {
			t.Fatalf("records not delivered in canonical order at index %d: %q then %q", i, ids[i-1], ids[i])
		}
	}
	if got := cs.maxInFlight.Load(); got < 2 {
		t.Fatalf("expected overlapping (reordered) fetches; max in-flight was %d", got)
	}
}

// TestWalkShardsConcurrentBoundedMemory covers the memory bound four ways: the window hard cap,
// the byte budget assertion the task pins (max in-flight <= N with a small MaxMemoryBytes), a
// blocked-consumer proof that the byte budget keeps buffered shards from growing to the whole
// archive, and a run under a configured GOMEMLIMIT with no explicit cap.
func TestWalkShardsConcurrentBoundedMemory(t *testing.T) {
	t.Run("window caps in-flight fetches", func(t *testing.T) {
		const nshards, window = 64, 4
		store, bgPriv, verifier, _ := buildMultiShardArchive(t, "dp_par_window", nshards, nshards)
		cs := &countingStore{inner: store, latency: uniformShardLatency(nshards, 3*time.Millisecond)}
		streamReadIDsAndRoot(t, cs, bgPriv, verifier, window, 0)
		if got := cs.maxInFlight.Load(); int(got) > window {
			t.Fatalf("in-flight shard fetches %d exceeded the window %d", got, window)
		}
		if got := cs.maxInFlight.Load(); got < 2 {
			t.Fatalf("expected the window to fill (parallel fetches); max in-flight was %d", got)
		}
	})

	t.Run("small max-memory keeps in-flight <= N", func(t *testing.T) {
		const nshards, window = 32, 8
		store, bgPriv, verifier, _ := buildMultiShardArchive(t, "dp_par_mem", nshards, nshards)
		shardSize := int64(len(store[runKey(vecRunID, "manifest/00000.dpe")]))
		cs := &countingStore{inner: store, latency: uniformShardLatency(nshards, 2*time.Millisecond)}
		ids, _, _ := streamReadIDsAndRoot(t, cs, bgPriv, verifier, window, shardSize*2) // budget ~2 shards
		if len(ids) != nshards {
			t.Fatalf("got %d records, want %d", len(ids), nshards)
		}
		if got := cs.maxInFlight.Load(); int(got) > window {
			t.Fatalf("in-flight shard fetches %d exceeded the window %d under a small max-memory", got, window)
		}
	})

	t.Run("byte budget throttles buffered shards", func(t *testing.T) {
		const nshards, window = 24, 8
		store, bgPriv, verifier, _ := buildMultiShardArchive(t, "dp_par_throttle", nshards, nshards)
		shardSize := int64(len(store[runKey(vecRunID, "manifest/00000.dpe")]))
		cs := &countingStore{inner: store} // fast GETs so the launcher is gated by the byte budget, not latency
		sr, err := StreamOpen(cs, vecRunID, bgPriv, verifier, Options{FetchConcurrency: window, MaxMemoryBytes: shardSize * 3})
		if err != nil {
			t.Fatalf("StreamOpen: %v", err)
		}
		cs.shardGets.Store(0) // count only the apply-pass fetches below
		cs.maxInFlight.Store(0)

		release := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- sr.EachRecord(func(spec.ShardRecord) error {
				<-release // every record blocks, so buffered shards are never drained
				return nil
			})
		}()
		// With the consumer wedged, the launcher fills the byte budget (plus at most one window
		// of in-flight overshoot) and then stops -- it must NOT prefetch the whole archive.
		time.Sleep(120 * time.Millisecond)
		if got := cs.shardGets.Load(); int(got) >= nshards {
			t.Fatalf("byte budget did not throttle: prefetched %d of %d shards while the consumer was blocked", got, nshards)
		}
		if got := cs.maxInFlight.Load(); int(got) > window {
			t.Fatalf("in-flight shard fetches %d exceeded the window %d", got, window)
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatalf("EachRecord drain: %v", err)
		}
	})

	t.Run("runs under a configured GOMEMLIMIT with no explicit cap", func(t *testing.T) {
		prev := debug.SetMemoryLimit(-1) // read the current limit
		defer debug.SetMemoryLimit(prev)
		debug.SetMemoryLimit(256 << 20) // a deliberate soft cap; MaxMemoryBytes=0 defers the bound to it
		const nshards = 48
		store, bgPriv, verifier, _ := buildMultiShardArchive(t, "dp_par_gomemlimit", nshards, nshards)
		ids, recomputed, signed := streamReadIDsAndRoot(t, store, bgPriv, verifier, 8, 0)
		if len(ids) != nshards {
			t.Fatalf("got %d records, want %d", len(ids), nshards)
		}
		if recomputed != signed {
			t.Fatalf("recomputed root %s != signed root %s under GOMEMLIMIT", recomputed, signed)
		}
	})
}

// goroutineBaseline settles the scheduler and samples the live goroutine count, the reference
// assertNoLeak checks the prefetcher returned to.
func goroutineBaseline() int {
	for i := 0; i < 10; i++ {
		runtime.GC()
		time.Sleep(5 * time.Millisecond)
	}
	return runtime.NumGoroutine()
}

// assertNoLeak fails if the live goroutine count does not settle back to the baseline, proving
// the prefetcher joined every fetch goroutine (no leak) on the error path. walkShardsConcurrent
// wg.Waits before returning, so this settles immediately; the short poll only absorbs scheduler
// and race-detector jitter.
func assertNoLeak(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		runtime.GC()
		n := runtime.NumGoroutine()
		if n <= baseline+1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine leak: %d live, baseline %d", n, baseline)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestWalkShardsConcurrentErrorPropagationNoLeak proves a fetch error and a consumer error each
// stop the walk, surface, and leave no goroutine behind. Latency keeps several fetches in flight
// when the error lands, so the cancel-and-join path is genuinely exercised under load.
func TestWalkShardsConcurrentErrorPropagationNoLeak(t *testing.T) {
	t.Run("fetch error stops the verify walk", func(t *testing.T) {
		store, bgPriv, verifier, _ := buildMultiShardArchive(t, "dp_par_fetcherr", 40, 20)
		base := goroutineBaseline()
		cs := &countingStore{
			inner:   store,
			latency: uniformShardLatency(20, 2*time.Millisecond),
			failKey: runKey(vecRunID, "manifest/00003.dpe"),
		}
		_, err := StreamOpen(cs, vecRunID, bgPriv, verifier, Options{FetchConcurrency: 8})
		if err == nil {
			t.Fatal("StreamOpen must fail when a shard GET fails")
		}
		var ee *ExitError
		if !errors.As(err, &ee) || ee.Code != ExitIncomplete {
			t.Fatalf("a failed shard read must surface as ExitIncomplete, got %v", err)
		}
		assertNoLeak(t, base)
	})

	t.Run("consumer error stops the apply walk", func(t *testing.T) {
		store, bgPriv, verifier, _ := buildMultiShardArchive(t, "dp_par_conserr", 40, 20)
		base := goroutineBaseline()
		cs := &countingStore{inner: store, latency: uniformShardLatency(20, 2*time.Millisecond)}
		sr, err := StreamOpen(cs, vecRunID, bgPriv, verifier, Options{FetchConcurrency: 8})
		if err != nil {
			t.Fatalf("StreamOpen: %v", err)
		}
		sentinel := errors.New("stop the apply here")
		seen := 0
		gotErr := sr.EachRecord(func(spec.ShardRecord) error {
			seen++
			if seen == 5 {
				return sentinel
			}
			return nil
		})
		if !errors.Is(gotErr, sentinel) {
			t.Fatalf("EachRecord must propagate the consumer error, got %v", gotErr)
		}
		assertNoLeak(t, base)
	})
}

// writeRTOResults writes the RTO table to results/ at the repo root, anchored off this test
// file's compile-time path so it does not depend on the test's working directory.
func writeRTOResults(t *testing.T, content string) {
	t.Helper()
	// The committed results/ file is a static snapshot; overwriting it on every `go test` run
	// dirties the tree (and the numbers vary run to run). Only refresh it when explicitly asked
	// (DOWNPIPE_WRITE_RTO=1); otherwise just log the table.
	if os.Getenv("DOWNPIPE_WRITE_RTO") == "" {
		t.Logf("RTO table (set DOWNPIPE_WRITE_RTO=1 to refresh results/restore-parallel-rto-2026-06-30.txt):\n%s", content)
		return
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed to locate the test source")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(thisFile))) // internal/format -> repo root
	dir := filepath.Join(root, "results")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir results: %v", err)
	}
	path := filepath.Join(dir, "restore-parallel-rto-2026-06-30.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write results: %v", err)
	}
	t.Logf("wrote RTO table to %s", path)
}

// TestRestoreParallelRTO measures the restore RTO curve against a mock store with a FIXED
// simulated GET latency: it times the full read path (StreamOpen verify pass + EachRecord apply
// pass) at FetchConcurrency 1, 2, 4, 8, 16 over a modest count of tiny shards, prints a
// concurrency|wall-ms|speedup table, and writes it to results/. It is deterministic and uses no
// real data -- the speedup comes purely from overlapping the simulated latency. It asserts the
// curve actually drops (concurrency 8 is at least twice as fast as sequential) and that no level
// exceeds its window.
func TestRestoreParallelRTO(t *testing.T) {
	if testing.Short() {
		t.Skip("RTO timing table skipped under -short")
	}
	const nshards = 160
	const latency = 5 * time.Millisecond
	store, bgPriv, verifier, _ := buildMultiShardArchive(t, "dp_par_rto", nshards, nshards) // 1 tiny record per shard
	lat := uniformShardLatency(nshards, latency)

	levels := []int{1, 2, 4, 8, 16}
	walls := make(map[int]time.Duration, len(levels))
	for _, c := range levels {
		cs := &countingStore{inner: store, latency: lat}
		start := time.Now()
		sr, err := StreamOpen(cs, vecRunID, bgPriv, verifier, Options{FetchConcurrency: c})
		if err != nil {
			t.Fatalf("StreamOpen(concurrency=%d): %v", c, err)
		}
		recs := 0
		if err := sr.EachRecord(func(spec.ShardRecord) error { recs++; return nil }); err != nil {
			t.Fatalf("EachRecord(concurrency=%d): %v", c, err)
		}
		walls[c] = time.Since(start)
		if recs != nshards {
			t.Fatalf("concurrency=%d restored %d records, want %d", c, recs, nshards)
		}
		if got := cs.maxInFlight.Load(); int(got) > c {
			t.Fatalf("concurrency=%d exceeded its window: max in-flight %d", c, got)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "downpipe offline restore -- shard-prefetch RTO (deterministic mock store, no real data)\n")
	fmt.Fprintf(&b, "date: 2026-06-30   shards: %d (1 record each)   simulated per-GET latency: %s\n", nshards, latency)
	fmt.Fprintf(&b, "wall = full read path: StreamOpen verify pass + EachRecord apply pass (two shard walks)\n")
	fmt.Fprintf(&b, "ideal sequential lower bound = 2 walks x %d shards x %s = %s\n\n", nshards, latency, 2*nshards*latency)
	fmt.Fprintf(&b, "%-12s  %-10s  %-8s\n", "concurrency", "wall-ms", "speedup")
	base := walls[1]
	for _, c := range levels {
		fmt.Fprintf(&b, "%-12d  %-10.1f  %-8.2f\n", c, float64(walls[c].Microseconds())/1000.0, float64(base)/float64(walls[c]))
	}
	out := b.String()
	t.Logf("\n%s", out)
	writeRTOResults(t, out)

	if walls[8] >= base/2 {
		t.Fatalf("expected concurrency=8 to be at least ~2x faster than sequential: seq=%s c8=%s", base, walls[8])
	}
}
