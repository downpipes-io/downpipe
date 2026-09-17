package format

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// waitGoroutinesSettle polls until the goroutine count returns to at most start plus a
// small slack for runtime helpers, failing after 5 s: the leak guard for teardown paths.
func waitGoroutinesSettle(t *testing.T, start int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= start+2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("goroutines did not settle: started with %d, still %d", start, runtime.NumGoroutine())
}

// blockingCtxStore delegates to the inner store, fails one chosen shard manifest, and
// BLOCKS every later shard manifest fetch until the walk context is cancelled. It
// proves the teardown path actually cancels in-flight fetches: without cancellation the
// blocked fetches never return and the walk's join would hang.
type blockingCtxStore struct {
	inner     ObjectStore
	failShard int
	blockFrom int
	released  atomic.Int32
}

func shardIndexOf(key string) (int, bool) {
	i := strings.LastIndex(key, "manifest/")
	if i < 0 || !strings.HasSuffix(key, ".dpe") {
		return 0, false
	}
	var n int
	if _, err := fmt.Sscanf(key[i:], "manifest/%05d.dpe", &n); err != nil {
		return 0, false
	}
	return n, true
}

func (b *blockingCtxStore) Get(key string) ([]byte, error) { return b.inner.Get(key) }

func (b *blockingCtxStore) GetContext(ctx context.Context, key string) ([]byte, error) {
	if n, ok := shardIndexOf(key); ok {
		if n == b.failShard {
			return nil, fmt.Errorf("simulated read failure for %s", key)
		}
		if n >= b.blockFrom {
			<-ctx.Done()
			b.released.Add(1)
			return nil, ctx.Err()
		}
	}
	return b.inner.Get(key)
}

// A fetch error must tear the concurrent walk down PROMPTLY: the walk context is
// cancelled, in-flight fetches observe it through the store's context capability, and
// every goroutine joins. Without cancellation this test hangs on fetches that only a
// store timeout (60 s against a real bucket) would end.
func TestConcurrentTeardownCancelsInFlightFetches(t *testing.T) {
	const nshards = 8
	store, bgPriv, verifier, _ := buildMultiShardArchive(t, "dp_cancel_tear", nshards, nshards)
	bs := &blockingCtxStore{inner: store, failShard: 1, blockFrom: 2}

	before := runtime.NumGoroutine()
	start := time.Now()
	_, err := StreamOpen(bs, vecRunID, bgPriv, verifier, Options{FetchConcurrency: nshards})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("the poisoned shard must fail StreamOpen")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("teardown took %s; in-flight fetches were not cancelled", elapsed)
	}
	waitGoroutinesSettle(t, before)
	if bs.released.Load() == 0 {
		t.Fatal("no blocked fetch was released by cancellation")
	}
}

// A caller cancel must stop the walk between shards, so an operator interrupt ends a
// long restore promptly instead of walking every remaining shard.
func TestWalkStopsOnCallerCancel(t *testing.T) {
	const nshards = 8
	store, bgPriv, verifier, _ := buildMultiShardArchive(t, "dp_cancel_caller", nshards, nshards)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sr, err := StreamOpenContext(ctx, store, vecRunID, bgPriv, verifier, Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	seen := 0
	werr := sr.EachRecord(func(_ spec.ShardRecord) error {
		seen++
		if seen == 1 {
			cancel()
		}
		return nil
	})
	if werr == nil {
		t.Fatal("a cancelled context must stop the walk with an error")
	}
	if seen >= nshards {
		t.Fatalf("walk delivered %d records after the cancel", seen)
	}
}
