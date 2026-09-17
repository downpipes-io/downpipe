package format

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// StreamReader is the bounded-memory counterpart of Reader: it verifies and restores a run
// WITHOUT ever materialising the whole record set. The load-all Open holds every record's
// metadata in RAM (~700-800 bytes each) and the restore planner then takes a second copy,
// so a 50M-record archive needs tens of GB and OOMs a commodity DR box (the offline-restore
// ceiling). StreamReader instead walks the signed shards in listed order, holding at most
// one shard's records plus an O(log n) Merkle frontier, so memory is bounded by the shard
// size and the tree depth, not the record count.
//
// Every CLI command that opens a run for verification or restore uses this reader, so the
// load-all Open is the library path only. One honest caveat on the apply side: a restore
// or a deep verify still keeps an O(distinct keys) no-clobber set (and the discard sink an
// O(records) name map), which is small per record but not constant; it is the record
// METADATA and the per-record VALUES that never accumulate.
//
// StreamOpen returns a FULLY VERIFIED StreamReader, exactly as Open returns a fully verified
// Reader: it runs every up-front gate (root signature, master capsule, key commitment,
// recipient set, break-glass) and then a streaming verify pass that re-derives every
// record hash, recomputes the signed Merkle root incrementally with MerkleAccumulator
// (byte-identical to the load-all MerkleRoot, the keystone correctness property), and
// checks the declared record and shard counts, before the freshness and recovery-bundle
// gates. EachRecord then re-streams the shards for the apply pass, re-checking each shard's
// signed SHA-384 and each record's hash as it yields, so a streaming restore never trusts a
// record the verify pass did not authenticate. The big segment VALUES are read only on the
// apply pass and only for records that are actually written.
type StreamReader struct {
	*Reader
	signer      *crypto.HybridVerifier
	opts        Options
	recordCount int64
}

// StreamOpen reads and verifies a run in bounded memory and returns a StreamReader ready to
// restore (EachRecord) without the load-all record materialisation. The verification is the
// same contract as Open: it returns an error on any signature, structural, completeness or
// Merkle-root mismatch, and (unless Options.acknowledges the specific finding) on a
// freshness failure. The verified-mode policy in opts is honoured identically; the ONLY
// difference from Open is that the records are streamed, never held all at once.
func StreamOpen(store ObjectStore, runID string, recipient *crypto.HybridKEMPrivate, signer *crypto.HybridVerifier, opts Options) (*StreamReader, error) {
	return StreamOpenContext(context.Background(), store, runID, recipient, signer, opts)
}

// StreamOpenContext is StreamOpen bounded by a caller context: the walk checks it
// between shards, and in-flight shard fetches and streamed segment reads observe it
// (through the store's ContextStore and ReaderStore capabilities), so an operator
// interrupt or an error teardown stops promptly instead of waiting out a store
// timeout. The verification contract is identical.
func StreamOpenContext(ctx context.Context, store ObjectStore, runID string, recipient *crypto.HybridKEMPrivate, signer *crypto.HybridVerifier, opts Options) (*StreamReader, error) {
	runIDBytes, err := spec.DecodeULID(runID)
	if err != nil {
		return nil, coded(ExitUsage, fmt.Errorf("runId: %w", err))
	}
	rootBytes, err := openRootManifest(store, runID)
	if err != nil {
		return nil, err
	}
	outcome := Outcome{SignatureResult: "valid", Completeness: "complete", Mode: "verified"}
	if opts.AllowUnverified {
		outcome.Mode = "allow-unverified"
	}

	// Up-front gates, byte-identical to Open (the streaming reader reuses the same helpers
	// so the two paths cannot diverge on the security contract).
	if err := verifyRootSignatureGate(store, runID, rootBytes, signer, opts, &outcome); err != nil {
		return nil, err
	}
	root, err := ParseRoot(rootBytes)
	if err != nil {
		return nil, err
	}
	if err := checkFormatVersion(root.FormatVersion); err != nil {
		return nil, err
	}
	if err := checkEnvelopeCodec(root); err != nil {
		return nil, err
	}
	if root.RunID != runID {
		return nil, coded(ExitUnverified, fmt.Errorf("manifest runId %q does not match the requested run %q", root.RunID, runID))
	}
	master, err := unwrapMaster(root, recipient)
	if err != nil {
		return nil, coded(ExitUnverified, err)
	}
	if err := checkKeyCommitment(root, master, runIDBytes); err != nil {
		return nil, coded(ExitUnverified, err)
	}
	if err := checkRecipientSet(root); err != nil {
		return nil, coded(ExitUnverified, err)
	}
	outcome.BreakGlassVerified = identityIsBreakGlass(root, recipient)

	rdr := &Reader{store: store, ctx: ctx, runIDBytes: runIDBytes, master: master, root: root, outcome: outcome}
	sr := &StreamReader{Reader: rdr, signer: signer, opts: opts}

	// Streaming completeness + Merkle root (the load-all Open does openShards +
	// checkCompleteness here; the streaming reader does it without retaining the records).
	count, err := sr.verifyRecordsAndRoot()
	if err != nil {
		return nil, err
	}
	sr.recordCount = count

	// Freshness then recovery-bundle gate, in the same order and with the same downgrade
	// rules as Open's tail.
	fresh, ferr := checkFreshness(store, runID, root, signer, opts)
	if ferr != nil {
		sr.outcome.Completeness = "UNVERIFIED"
		if !opts.acknowledges(fresh) {
			return nil, ferr
		}
	}
	sr.freshness = fresh
	if err := verifyRecoveryBundleGate(store, signer, opts, &sr.outcome); err != nil {
		return nil, err
	}
	return sr, nil
}

// RecordCount returns the number of verified records, counted during the streaming verify
// pass without ever holding the record slice. It shadows the embedded Reader.RecordCount
// (which would read the unmaterialised, empty slice).
func (sr *StreamReader) RecordCount() int64 { return sr.recordCount }

// verifyRecordsAndRoot is the streaming equivalent of openShards + checkCompleteness: it
// walks the signed shards in order, applies the per-shard and per-record gates, re-derives
// each record hash and folds it into a Merkle frontier, and at the end checks the declared
// record count, the shard count, and that the streamed Merkle root equals the signed root
// BYTE FOR BYTE. It never retains more than one shard's records plus the O(log n) frontier.
// It returns the verified record count.
func (sr *StreamReader) verifyRecordsAndRoot() (int64, error) {
	if sr.root.ShardCount != len(sr.root.Shards) {
		return 0, coded(ExitUnverified, fmt.Errorf("shardCount %d does not match the %d listed shards", sr.root.ShardCount, len(sr.root.Shards)))
	}
	var acc MerkleAccumulator
	var count int64
	walkErr := sr.walkShards(func(rec spec.ShardRecord) error {
		if err := checkRecordStructural(sr.root, rec); err != nil {
			return err
		}
		rh, err := RecordHashOf(rec)
		if err != nil {
			return coded(ExitUnverified, err)
		}
		stated, err := hex.DecodeString(rec.RecordHash)
		if err != nil {
			return coded(ExitUnverified, fmt.Errorf("record %s recordHash: %w", rec.RecordID, err))
		}
		if !crypto.ConstantTimeEqual(rh, stated) {
			return coded(ExitUnverified, fmt.Errorf("record %s hash does not match its fields", rec.RecordID))
		}
		acc.Push(rh)
		count++
		return nil
	})
	if walkErr != nil {
		return 0, codedIfNot(ExitUnverified, walkErr)
	}
	if count != sr.root.DeclaredRecordCount {
		return 0, coded(ExitIncomplete, fmt.Errorf("recovered %d records, the root declares %d", count, sr.root.DeclaredRecordCount))
	}
	want, err := hex.DecodeString(sr.root.MerkleRoot)
	if err != nil {
		return 0, coded(ExitUnverified, fmt.Errorf("merkle root: %w", err))
	}
	if !crypto.ConstantTimeEqual(acc.Root(), want) {
		return 0, coded(ExitUnverified, fmt.Errorf("merkle root does not match the recovered records"))
	}
	return count, nil
}

// EachRecord streams the verified records to fn in canonical order, one at a time, re-reading
// each shard and re-checking its signed SHA-384 and every record's hash as it goes, so a
// streaming apply never acts on a record the archive does not authenticate (a shard mutated
// between the verify pass and here fails its signed-hash check). fn is called with one
// record at a time and the record is not retained after fn returns, so the apply holds
// bounded memory. A non-nil return from fn stops the walk and is propagated.
func (sr *StreamReader) EachRecord(fn func(spec.ShardRecord) error) error {
	return sr.walkShards(func(rec spec.ShardRecord) error {
		if err := checkRecordStructural(sr.root, rec); err != nil {
			return err
		}
		rh, err := RecordHashOf(rec)
		if err != nil {
			return coded(ExitUnverified, err)
		}
		stated, err := hex.DecodeString(rec.RecordHash)
		if err != nil {
			return coded(ExitUnverified, fmt.Errorf("record %s recordHash: %w", rec.RecordID, err))
		}
		if !crypto.ConstantTimeEqual(rh, stated) {
			return coded(ExitUnverified, fmt.Errorf("record %s hash does not match its fields", rec.RecordID))
		}
		return fn(rec)
	})
}

// walkShards opens each signed shard in listed order through the shared openOneShard gate
// (the signed SHA-384 and the run-binding preamble check) and calls perRecord for each
// record in shard order. It holds at most one shard's records at a time. Errors from
// openOneShard are already coded where it matters (ExitIncomplete for a missing shard); a
// per-record callback error is returned as-is for the caller to code.
//
// With Options.FetchConcurrency>1 it instead prefetches up to that many shards concurrently
// (walkShardsConcurrent) while still calling perRecord in canonical shard-list order, so a
// high-latency object store overlaps its GETs without changing the byte-identical record
// stream or the folded Merkle root. FetchConcurrency<=1 is this strict sequential loop,
// unchanged, the bounded-memory default.
func (sr *StreamReader) walkShards(perRecord func(rec spec.ShardRecord) error) error {
	mk := crypto.DeriveMK(sr.master, sr.runIDBytes)
	if sr.opts.FetchConcurrency > 1 {
		return sr.walkShardsConcurrent(mk, perRecord)
	}
	for _, sh := range sr.root.Shards {
		if err := sr.context().Err(); err != nil {
			return err
		}
		_, recs, err := openOneShard(sr.context(), sr.store, sr.root, mk, sr.runIDBytes, sh)
		if err != nil {
			return err
		}
		for _, rec := range recs {
			if err := perRecord(rec); err != nil {
				return err
			}
		}
	}
	return nil
}

// shardResult is one prefetched shard delivered from a fetch goroutine to the single
// consumer: the opened records (in shard order), the fetched-byte weight charged against
// the memory budget, and the error that stopped the fetch (records nil when err != nil).
type shardResult struct {
	recs []spec.ShardRecord
	size int
	err  error
}

// walkShardsConcurrent is the Options.FetchConcurrency>1 prefetcher. It overlaps the
// blocking shard GET+decrypt (openOneShardSized, the SAME signed-SHA-384 and preamble gate
// the sequential path uses -- nothing is bypassed) across up to FetchConcurrency goroutines,
// yet hands every shard's records to perRecord STRICTLY in shard-list order on this single
// goroutine. Because the consumer is single-threaded and ordered, the MerkleAccumulator fold
// (verify pass) and the apply (EachRecord) see record hashes in the exact canonical order the
// sequential walk produces, so the recomputed root and the restored records are byte-identical
// to FetchConcurrency=1; only fetch+decrypt parallelises.
//
// Memory bound. A launcher goroutine starts fetches in shard order, gated two ways:
//   - The window: a semaphore of FetchConcurrency tokens that the consumer releases only
//     after it has CONSUMED a shard, so at most FetchConcurrency shards are ever in flight
//     OR fetched-and-buffered at once -- the hard cap (also the bound on concurrent GETs).
//   - The byte budget: with MaxMemoryBytes M>0 the launcher additionally waits while the
//     fetched-but-not-yet-consumed shards already total >= M bytes. A shard's weight is only
//     known after its GET (a ShardRef has no pre-fetch size), so up to one window of in-flight
//     fetches can overshoot M before their sizes register; steady-state memory is therefore
//     ~M plus at most one window's worth, and never more than FetchConcurrency whole shards.
//
// Errors and shutdown. A fetch error (already coded, e.g. ExitIncomplete for a missing shard)
// or a perRecord error stops the walk: the consumer cancels the shared context, which unblocks
// the launcher's window/budget/order waits, and joins every goroutine (the fetch goroutines
// each send exactly one result into a buffered slot and then exit, so none can leak) before
// returning the first error.
func (sr *StreamReader) walkShardsConcurrent(mk []byte, perRecord func(rec spec.ShardRecord) error) error {
	shards := sr.root.Shards
	total := len(shards)
	if total == 0 {
		return nil
	}
	window := sr.opts.FetchConcurrency
	if window > total {
		window = total // never reserve more slots (or spawn more fetchers) than there are shards
	}
	maxMem := sr.opts.MaxMemoryBytes

	// Derive from the reader's caller context so an operator interrupt tears the
	// pipeline down exactly as an internal error does.
	ctx, cancel := context.WithCancel(sr.context())
	defer cancel()

	// sem bounds shards "in flight or buffered" to window; order carries the per-shard
	// result channels (futures) to the consumer in launch order, giving FIFO delivery.
	sem := make(chan struct{}, window)
	order := make(chan chan shardResult, window)

	// mu/cond guard bufferedBytes, the running weight of fetched-but-not-yet-consumed shards,
	// the soft byte budget the launcher waits on.
	var mu sync.Mutex
	cond := sync.NewCond(&mu)
	var bufferedBytes int64

	// stop cancels the context and wakes a launcher parked on the byte-budget cond, so a
	// consumer-side error tears the pipeline down without leaking the launcher.
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			mu.Lock()
			cond.Broadcast()
			mu.Unlock()
		})
	}

	var wg sync.WaitGroup

	// Launcher: walk the shards in order, gated by the byte budget then the window, and spawn
	// one fetch per shard, pushing its future into order so the consumer reads them in order.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range shards {
			// Byte budget: wait while the already-buffered shards meet the cap (M>0). Re-checks
			// ctx so a cancel (and its Broadcast) releases the wait instead of hanging.
			if maxMem > 0 {
				mu.Lock()
				for bufferedBytes >= maxMem && ctx.Err() == nil {
					cond.Wait()
				}
				mu.Unlock()
			}
			if ctx.Err() != nil {
				return
			}
			// Window: reserve a slot; the consumer frees it after consuming this shard.
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			ch := make(chan shardResult, 1) // buffered: the fetch never blocks handing off its one result
			select {
			case order <- ch:
			case <-ctx.Done():
				return
			}
			sh := shards[i]
			// Adding to the WaitGroup from inside this goroutine is safe HERE, and static analysis
			// (semgrep trailofbits.go.waitgroup-add-called-inside-goroutine) flags the shape without
			// being able to see why. The launcher itself holds a count: wg.Add(1) above runs in the
			// CALLING goroutine before the launcher starts, and the launcher's wg.Done is deferred
			// until after this loop has finished spawning. So the counter cannot reach zero while
			// Adds are still happening, and the wg.Wait below cannot return early. Removing the
			// launcher's own count, or moving its Add inside, would turn this into the real bug the
			// rule is about: a Wait that returns before every shard fetch has completed.
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, recs, size, err := openOneShardSized(ctx, sr.store, sr.root, mk, sr.runIDBytes, sh)
				if err == nil {
					mu.Lock()
					bufferedBytes += int64(size)
					mu.Unlock()
				}
				ch <- shardResult{recs: recs, size: size, err: err}
			}()
		}
	}()

	// Consumer: read the futures in launch order and deliver each shard's records to perRecord
	// single-threaded, so the fold/apply observes canonical order. On the first error, stop the
	// pipeline and join before returning.
	var walkErr error
	for i := 0; i < total; i++ {
		res := <-(<-order)
		if res.err != nil {
			walkErr = res.err
			break
		}
		for _, rec := range res.recs {
			if perr := perRecord(rec); perr != nil {
				walkErr = perr
				break
			}
		}
		// Release this shard's weight and window slot now that it is consumed, waking the
		// launcher's budget wait. Skipped on the error break: the pipeline is being torn down.
		if walkErr != nil {
			break
		}
		mu.Lock()
		bufferedBytes -= int64(res.size)
		cond.Broadcast()
		mu.Unlock()
		<-sem
	}

	stop()
	wg.Wait()
	return walkErr
}
