package crypto

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

func fixedKey(b byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = b + byte(i)
	}
	return k
}

// Seal then open must round-trip across the chunk-boundary cases: empty, sub-chunk,
// exactly one chunk, one byte over, and several chunks with a partial tail.
func TestStreamRoundTrip(t *testing.T) {
	fk := fixedKey(0x10)
	nonce := bytes.Repeat([]byte{0xab}, spec.StreamNonceSize)
	for _, n := range []int{0, 1, 100, spec.ChunkSize - 1, spec.ChunkSize, spec.ChunkSize + 1, 2 * spec.ChunkSize, 2*spec.ChunkSize + 7} {
		pt := make([]byte, n)
		for i := range pt {
			pt[i] = byte(i*7 + 1)
		}
		sealed, err := SealStream(fk, pt, nonce)
		if err != nil {
			t.Fatalf("size %d seal: %v", n, err)
		}
		got, err := OpenStream(fk, sealed)
		if err != nil {
			t.Fatalf("size %d open: %v", n, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("size %d round-trip mismatch (got %d bytes)", n, len(got))
		}
	}
}

// The same file key and the same pinned nonce must seal a value to the same bytes,
// which is what lets a pinned conformance vector be writer-authoritative.
func TestStreamDeterministicForPinnedNonce(t *testing.T) {
	fk := fixedKey(0x20)
	nonce := bytes.Repeat([]byte{0x01}, spec.StreamNonceSize)
	pt := []byte("a value that spans a little more than nothing")
	a, err := SealStream(fk, pt, nonce)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealStream(fk, pt, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("sealing the same value with the same key and nonce must be deterministic")
	}
}

// The streaming seal must produce bytes identical to the whole-buffer seal, and the
// streaming reader must round-trip them, holding only a couple of chunks in memory.
func TestStreamingMatchesWholeBuffer(t *testing.T) {
	fk := fixedKey(0x40)
	nonce := bytes.Repeat([]byte{0x11}, spec.StreamNonceSize)
	for _, n := range []int{0, 1, spec.ChunkSize, spec.ChunkSize + 5, 3 * spec.ChunkSize} {
		pt := make([]byte, n)
		for i := range pt {
			pt[i] = byte(i)
		}
		whole, err := SealStream(fk, pt, nonce)
		if err != nil {
			t.Fatal(err)
		}
		var streamed bytes.Buffer
		w, err := SealStreamTo(&streamed, fk, nonce, nil)
		if err != nil {
			t.Fatal(err)
		}
		for off := 0; off < len(pt); off += 7000 {
			if _, err := w.Write(pt[off:min(off+7000, len(pt))]); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(streamed.Bytes(), whole) {
			t.Fatalf("size %d: streaming seal differs from whole-buffer seal", n)
		}
		var out bytes.Buffer
		if err := OpenStreamTo(&out, fk, bytes.NewReader(whole), nil, 1000); err != nil {
			t.Fatalf("size %d streaming open: %v", n, err)
		}
		if !bytes.Equal(out.Bytes(), pt) {
			t.Fatalf("size %d streaming round-trip mismatch", n)
		}
	}
}

// The streaming reader must refuse a sealed input with more chunks than the bound.
func TestOpenStreamToEnforcesMaxChunks(t *testing.T) {
	fk := fixedKey(0x50)
	nonce := bytes.Repeat([]byte{0x22}, spec.StreamNonceSize)
	sealed, err := SealStream(fk, make([]byte, 3*spec.ChunkSize), nonce)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := OpenStreamTo(&out, fk, bytes.NewReader(sealed), nil, 2); err == nil {
		t.Fatal("a stream exceeding the chunk limit must be rejected")
	}
}

// Tampering, truncation, dropping the final chunk, and the wrong key must all fail
// authentication rather than returning wrong plaintext.
func TestStreamRejectsTamperTruncateWrongKey(t *testing.T) {
	fk := fixedKey(0x30)
	nonce := bytes.Repeat([]byte{0x5a}, spec.StreamNonceSize)
	pt := make([]byte, 3*spec.ChunkSize+11)
	for i := range pt {
		pt[i] = byte(i)
	}
	sealed, err := SealStream(fk, pt, nonce)
	if err != nil {
		t.Fatal(err)
	}

	tampered := bytes.Clone(sealed)
	tampered[spec.StreamNonceSize+10] ^= 0x01
	if _, err := OpenStream(fk, tampered); err == nil {
		t.Fatal("a tampered chunk must fail authentication")
	}

	if _, err := OpenStream(fk, sealed[:len(sealed)-1]); err == nil {
		t.Fatal("a truncated final tag must fail")
	}

	// Keep only the first full chunk. It was sealed without the last-chunk flag, so
	// opening it as the final chunk must fail (the flag binding catches the drop).
	if _, err := OpenStream(fk, sealed[:spec.StreamNonceSize+streamMaxChunk]); err == nil {
		t.Fatal("dropping the final chunk must fail")
	}

	if _, err := OpenStream(fixedKey(0xff), sealed); err == nil {
		t.Fatal("the wrong file key must fail authentication")
	}
}

// splitSealed splits a sealed multi-chunk payload into its payload nonce and the
// per-chunk frames. Every non-final chunk is exactly streamMaxChunk bytes (ChunkSize
// plaintext + TagSize tag); the final chunk is the shorter remainder. This mirrors the
// on-the-wire framing OpenStreamTo reads, so a test can drop, reorder or truncate whole
// chunks and feed the result back through the real streaming reader.
func splitSealed(t *testing.T, sealed []byte) (nonce []byte, chunks [][]byte) {
	t.Helper()
	if len(sealed) < spec.StreamNonceSize+spec.TagSize {
		t.Fatalf("sealed payload is too short to split: %d bytes", len(sealed))
	}
	nonce = sealed[:spec.StreamNonceSize]
	body := sealed[spec.StreamNonceSize:]
	for len(body) > streamMaxChunk {
		chunks = append(chunks, body[:streamMaxChunk])
		body = body[streamMaxChunk:]
	}
	chunks = append(chunks, body) // the final (short or full-but-last) chunk
	return nonce, chunks
}

// joinFrames reassembles a payload nonce and a sequence of chunk frames into a single
// sealed-style byte stream for OpenStreamTo to read.
func joinFrames(nonce []byte, chunks [][]byte) []byte {
	out := append([]byte(nil), nonce...)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

// openTo runs the streaming reader over a candidate sealed stream and reports its error.
func openTo(fk [32]byte, stream []byte) error {
	return OpenStreamTo(&bytes.Buffer{}, fk, bytes.NewReader(stream), nil, 1000)
}

// The streaming reader OpenStreamTo must reject every multi-chunk integrity break, not
// just a single-chunk bit-flip. The four sub-cases below cover a reordered chunk, a
// stream truncated by removing its final chunk, an interior chunk dropped, and a short
// final-tag mutation; each must fail authentication rather than yield partial or wrong
// plaintext. Each chunk's nonce binds its position and last-chunk flag
// (SPEC 7.8), so moving, removing or stopping short of the flagged final chunk breaks
// AES-GCM. The positive control proves the unmodified split round-trips, so the
// negatives are failing on the tamper and not on the framing helper.
func TestOpenStreamToRejectsMultiChunkTamper(t *testing.T) {
	fk := fixedKey(0x70)
	// Four chunks: three full non-final chunks and a short final chunk, so reorder and
	// drop have distinct interior chunks to act on and truncation removes a real final.
	pt := make([]byte, 3*spec.ChunkSize+101)
	for i := range pt {
		pt[i] = byte(i*5 + 3)
	}

	// Shared setup: seal the plaintext and split it into its four chunk frames. Each
	// sub-test starts from this untouched split and applies a single tamper variant.
	setup := func(t *testing.T) ([]byte, [][]byte) {
		t.Helper()
		nonce := bytes.Repeat([]byte{0x5b}, spec.StreamNonceSize)
		sealed, err := SealStream(fk, pt, nonce)
		if err != nil {
			t.Fatal(err)
		}
		gotNonce, chunks := splitSealed(t, sealed)
		if len(chunks) != 4 {
			t.Fatalf("expected 4 chunk frames, got %d", len(chunks))
		}
		return gotNonce, chunks
	}

	t.Run("positive control round-trips", func(t *testing.T) {
		// The untouched split must round-trip through OpenStreamTo, so a rejection in the
		// tamper sub-tests is attributable to the tamper, not to splitSealed/joinFrames.
		gotNonce, chunks := setup(t)
		var roundTrip bytes.Buffer
		if err := OpenStreamTo(&roundTrip, fk, bytes.NewReader(joinFrames(gotNonce, chunks)), nil, 1000); err != nil {
			t.Fatalf("the unmodified split must round-trip: %v", err)
		}
		if !bytes.Equal(roundTrip.Bytes(), pt) {
			t.Fatal("the unmodified split round-trip must return the original plaintext")
		}
	})

	t.Run("reordered chunk", func(t *testing.T) {
		// Swap two interior full chunks. Each was sealed under its own position's nonce,
		// so opening them in the wrong order fails authentication.
		gotNonce, chunks := setup(t)
		swapped := [][]byte{chunks[0], chunks[2], chunks[1], chunks[3]}
		if err := openTo(fk, joinFrames(gotNonce, swapped)); err == nil {
			t.Fatal("a reordered chunk must be rejected by OpenStreamTo")
		}
	})

	t.Run("truncated final chunk", func(t *testing.T) {
		// Drop the final chunk entirely. The new last frame (chunk 2) was sealed without
		// the last-chunk flag, so the reader, which flags its last frame, opens it with the
		// final-flag nonce and authentication fails.
		gotNonce, chunks := setup(t)
		truncated := [][]byte{chunks[0], chunks[1], chunks[2]}
		if err := openTo(fk, joinFrames(gotNonce, truncated)); err == nil {
			t.Fatal("a stream missing its final chunk must be rejected by OpenStreamTo")
		}
	})

	t.Run("dropped interior chunk", func(t *testing.T) {
		// Remove chunk 1 but keep the real final chunk. The chunks that follow the hole are
		// opened under the wrong counter, so authentication fails.
		gotNonce, chunks := setup(t)
		dropped := [][]byte{chunks[0], chunks[2], chunks[3]}
		if err := openTo(fk, joinFrames(gotNonce, dropped)); err == nil {
			t.Fatal("a dropped interior chunk must be rejected by OpenStreamTo")
		}
	})

	t.Run("short final chunk", func(t *testing.T) {
		// Truncating the final chunk's tag (a partial last frame) must fail rather than
		// return the chunk's plaintext unauthenticated.
		gotNonce, chunks := setup(t)
		shortFinal := append([][]byte(nil), chunks[0], chunks[1], chunks[2])
		shortFinal = append(shortFinal, chunks[3][:len(chunks[3])-1])
		if err := openTo(fk, joinFrames(gotNonce, shortFinal)); err == nil {
			t.Fatal("a truncated final-chunk tag must be rejected by OpenStreamTo")
		}
	})
}

// nonceInt reads a 12-byte chunk nonce as a big-endian integer so the sequence can be
// checked for strict monotonicity. The counter sits in the low 8 bytes of the 11-byte
// counter field and the last-chunk flag is the final byte, so the whole-nonce integer
// increases with the counter and, on the final chunk, by the extra flag bit.
func nonceInt(n [12]byte) (hi uint32, lo uint64) {
	hi = uint32(n[0])<<16 | uint32(n[1])<<8 | uint32(n[2])
	lo = binary.BigEndian.Uint64(n[3:11])
	return hi, lo
}

// The per-chunk nonce sequence within one stream must be unique and strictly
// monotonic, because a repeat under the same AES-256 key is a catastrophic AES-GCM
// nonce reuse. This drives chunkNonce over the same (counter, last) pattern SealStream
// uses for a multi-chunk payload and asserts the sequence never repeats, the reserved
// top three bytes stay zero, the flag is set only on the final chunk, and the empty
// stream's sole final chunk has its own distinct nonce.
func TestStreamChunkNonceSequenceUniqueAndMonotonic(t *testing.T) {
	const chunks = 5
	seen := make(map[[12]byte]int, chunks)
	var prevHi uint32
	var prevLo uint64
	var counter uint64
	for i := 0; i < chunks; i++ {
		last := i == chunks-1
		n := chunkNonce(counter, last)

		if first, dup := seen[n]; dup {
			t.Fatalf("chunk %d reuses the nonce of chunk %d: %x", i, first, n)
		}
		seen[n] = i

		if n[0] != 0 || n[1] != 0 || n[2] != 0 {
			t.Fatalf("chunk %d: reserved top three nonce bytes must be zero, got %x", i, n[:3])
		}
		wantFlag := byte(0x00)
		if last {
			wantFlag = 0x01
		}
		if n[11] != wantFlag {
			t.Fatalf("chunk %d: last-chunk flag is %#x, want %#x", i, n[11], wantFlag)
		}

		hi, lo := nonceInt(n)
		strictlyGreater := hi > prevHi || (hi == prevHi && lo > prevLo)
		if i > 0 && !strictlyGreater {
			t.Fatalf("chunk %d nonce %x is not strictly greater than the previous %d:%d", i, n, prevHi, prevLo)
		}
		prevHi, prevLo = hi, lo

		if !last {
			next, err := advanceChunk(counter)
			if err != nil {
				t.Fatalf("chunk %d advance: %v", i, err)
			}
			counter = next
		}
	}
	if len(seen) != chunks {
		t.Fatalf("expected %d distinct nonces, got %d", chunks, len(seen))
	}

	// A single-chunk stream seals chunk 0 with the last-chunk flag set; that nonce must
	// differ from the non-final chunk 0 nonce a longer stream would use, so the empty or
	// one-chunk case cannot collide with the first chunk of a multi-chunk stream.
	if chunkNonce(0, true) == chunkNonce(0, false) {
		t.Fatal("the final-flag chunk 0 nonce must differ from the non-final chunk 0 nonce")
	}
}

// advanceChunk is the single chokepoint that keeps the per-stream counter from
// wrapping. It must step normally well below the ceiling, reach the highest
// representable index, and then refuse to advance past it rather than wrap back to 0
// and reuse chunk 0's nonce. The boundary is checked directly so the overflow rejection
// is provable without sealing 2^64 chunks.
func TestStreamAdvanceChunkRejectsWrap(t *testing.T) {
	got, err := advanceChunk(0)
	if err != nil || got != 1 {
		t.Fatalf("advanceChunk(0) = (%d, %v), want (1, nil)", got, err)
	}

	got, err = advanceChunk(streamMaxChunkIndex - 1)
	if err != nil || got != streamMaxChunkIndex {
		t.Fatalf("advanceChunk(max-1) = (%d, %v), want (%d, nil)", got, err, streamMaxChunkIndex)
	}

	// Advancing from the last representable index would wrap the uint64 counter to 0 and
	// reuse the first chunk's nonce, so it must be rejected.
	if _, err := advanceChunk(streamMaxChunkIndex); err == nil {
		t.Fatal("advancing past the safe chunk count must be rejected, not wrap to 0")
	}

	// The ceiling index itself must still yield a well-formed nonce (no panic, reserved
	// bytes zero), so it is a usable index and only the step beyond it is refused.
	top := chunkNonce(streamMaxChunkIndex, true)
	if top[0] != 0 || top[1] != 0 || top[2] != 0 || top[11] != 0x01 {
		t.Fatalf("ceiling nonce is malformed: %x", top)
	}
	if binary.BigEndian.Uint64(top[3:11]) != math.MaxUint64 {
		t.Fatalf("ceiling nonce counter field = %d, want %d", binary.BigEndian.Uint64(top[3:11]), uint64(math.MaxUint64))
	}
}

// A capsule sealed with a non-nil AAD must be rejected by the nil-AAD whole-buffer
// reader. SealStreamTo binds the AAD into every chunk's GCM tag, so opening the stream
// without the matching AAD fails authentication on the first chunk, not just on the last.
// The reader cannot silently recover a capsule sealed for a different binding context.
func TestStreamAADMismatchRejected(t *testing.T) {
	fk := fixedKey(0x80)
	nonce := bytes.Repeat([]byte{0x99}, spec.StreamNonceSize)
	aad := []byte("binding-context-for-this-capsule")
	pt := []byte("a value sealed under an aad context")

	// Seal the value with a non-nil AAD (the capsule path).
	var sealed bytes.Buffer
	w, err := SealStreamTo(&sealed, fk, nonce, aad)
	if err != nil {
		t.Fatalf("SealStreamTo: %v", err)
	}
	if _, err := w.Write(pt); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Opening with the correct AAD must succeed (positive control).
	var out bytes.Buffer
	if err := OpenStreamTo(&out, fk, bytes.NewReader(sealed.Bytes()), aad, 1000); err != nil {
		t.Fatalf("OpenStreamTo with matching AAD: %v", err)
	}
	if !bytes.Equal(out.Bytes(), pt) {
		t.Fatalf("matching-AAD round-trip mismatch")
	}

	// Opening with nil AAD must fail: the GCM tag covers the AAD, so a nil AAD differs
	// from the non-nil AAD that was used to seal and authentication fails.
	var discard bytes.Buffer
	if err := OpenStreamTo(&discard, fk, bytes.NewReader(sealed.Bytes()), nil, 1000); err == nil {
		t.Fatal("OpenStreamTo with nil AAD must reject a stream sealed with a non-nil AAD")
	}
}

// This pins the failure mode the nonce-uniqueness invariant exists to prevent: the bare
// STREAM primitive trusts the caller for a fresh (fileKey, payloadNonce), and reusing
// the pair for two distinct plaintexts reuses chunk 0's keystream, so the two
// ciphertexts XOR to the two plaintexts XOR (a classic two-time-pad leak that AES-GCM
// forbids). The test documents that this is a foot-gun of the primitive, and then shows
// the in-tree non-secret seal path is not exposed to it because distinct content derives
// a distinct file key, so the (key, nonce) pair never repeats for different plaintext.
func TestStreamNonceReuseLeaksAndDerivedKeysDiffer(t *testing.T) {
	fk := fixedKey(0x60)
	nonce := bytes.Repeat([]byte{0x33}, spec.StreamNonceSize)
	a := []byte("AAAA")
	b := []byte("BBBB")

	sealedA, err := SealStream(fk, a, nonce)
	if err != nil {
		t.Fatal(err)
	}
	sealedB, err := SealStream(fk, b, nonce)
	if err != nil {
		t.Fatal(err)
	}

	// Strip the shared payload nonce prefix and compare the chunk-0 ciphertext (minus
	// the GCM tag). Reused keystream means ct_a XOR ct_b == pt_a XOR pt_b.
	ctA := sealedA[spec.StreamNonceSize : spec.StreamNonceSize+len(a)]
	ctB := sealedB[spec.StreamNonceSize : spec.StreamNonceSize+len(b)]
	for i := range a {
		if ctA[i]^ctB[i] != a[i]^b[i] {
			t.Fatalf("expected reused-keystream leak at byte %d: ct xor = %#x, pt xor = %#x", i, ctA[i]^ctB[i], a[i]^b[i])
		}
	}

	// The in-tree non-secret path binds the file key to the content via the segment id,
	// so distinct plaintext yields a distinct file key and the reuse precondition (same
	// key, same nonce, different plaintext) cannot arise from real seals.
	cak := DeriveCAK(fk[:], "downpipe-under-test")
	keyA := DeriveNonSecretFileKey(fk[:], SegID(cak, spec.AddrSingleNonSecret, nil, a), spec.CodecNone)
	keyB := DeriveNonSecretFileKey(fk[:], SegID(cak, spec.AddrSingleNonSecret, nil, b), spec.CodecNone)
	if keyA == keyB {
		t.Fatal("distinct non-secret content must derive distinct file keys so a shared nonce is not a reuse")
	}
}
