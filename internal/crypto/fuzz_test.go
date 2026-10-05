package crypto

// Go native fuzz targets for the STREAM envelope (SPEC.md 7.8), the construction that
// seals every segment and every shard manifest. The known-answer and unit tests in
// stream_test.go pin fixed sizes and fixed tampers. These targets let the fuzzer choose
// the plaintext length, the key, the nonce, the aad and the position of each tamper, so
// the chunk-boundary and framing arithmetic is searched rather than sampled.
//
// The bounded CI job (.github/workflows/ci.yml, the "fuzz" job) and the weekly extended
// job (.github/workflows/fuzz-extended.yml) run both targets. The seeds run as unit tests
// under `go test ./...` on every run, and so does any crasher checked in under
// testdata/fuzz/.

import (
	"bytes"
	"crypto/sha512"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// fuzzMaxPlaintext is one more than the longest plaintext a fuzz input can ask for:
// three full chunks and one byte of a fourth, so every framing case (empty, sub-chunk,
// exact multiple, partial tail, several chunks) is reachable while one iteration stays
// well under a millisecond.
const fuzzMaxPlaintext = 3*spec.ChunkSize + 2

// fuzzPlaintext expands seed to exactly size bytes by repetition, so a short fuzz input
// can still reach a multi-chunk length. An empty seed gives zero bytes of the length.
func fuzzPlaintext(seed []byte, size uint32) []byte {
	n := int(size % fuzzMaxPlaintext)
	out := make([]byte, n)
	if len(seed) == 0 {
		return out
	}
	for i := 0; i < n; i += len(seed) {
		copy(out[i:], seed)
	}
	return out
}

// fuzzNonce fits b into a payload nonce: the first 16 bytes, zero-padded when b is short.
func fuzzNonce(b []byte) []byte {
	n := make([]byte, spec.StreamNonceSize)
	copy(n, b)
	return n
}

// streamChunkCount is the number of STREAM chunks a plaintext of n bytes seals to.
func streamChunkCount(n int) int {
	c := n / streamChunkSize
	if n%streamChunkSize != 0 || n == 0 {
		c++
	}
	return c
}

// FuzzStreamRoundTrip seals a fuzz-chosen value and opens it again through every path.
//
// Invariants:
//   - SealStream then OpenStream returns the same bytes, and so the same SHA-384, which
//     is the plaintextSha384 a record binds.
//   - SealStreamTo with no aad writes the same bytes as SealStream, so the two writers
//     interoperate. SealStreamTo then OpenStreamTo with the fuzz aad returns the value.
//   - The sealed length is the nonce plus the plaintext plus one tag per chunk.
//   - OpenStreamTo accepts the stream at a maxChunks equal to its chunk count, and
//     refuses it at one fewer.
func FuzzStreamRoundTrip(f *testing.F) {
	for _, size := range []uint32{0, 1, 100, spec.ChunkSize - 1, spec.ChunkSize, spec.ChunkSize + 1, 2 * spec.ChunkSize, 2*spec.ChunkSize + 7} {
		f.Add([]byte("seed value"), size, byte(0x10), []byte{0xab}, []byte(nil))
	}
	f.Add([]byte{0x00}, uint32(3), byte(0xff), bytes.Repeat([]byte{0x5a}, 16), []byte("aad"))

	f.Fuzz(func(t *testing.T, seed []byte, size uint32, keyByte byte, nonceIn, aad []byte) {
		fk := fixedKey(keyByte)
		nonce := fuzzNonce(nonceIn)
		pt := fuzzPlaintext(seed, size)

		sealed, err := SealStream(fk, pt, nonce)
		if err != nil {
			t.Fatalf("seal %d bytes: %v", len(pt), err)
		}
		chunks := streamChunkCount(len(pt))
		if want := spec.StreamNonceSize + len(pt) + chunks*spec.TagSize; len(sealed) != want {
			t.Fatalf("sealed %d bytes to %d, want %d", len(pt), len(sealed), want)
		}
		got, err := OpenStream(fk, sealed)
		if err != nil {
			t.Fatalf("open %d bytes: %v", len(pt), err)
		}
		if !bytes.Equal(got, pt) || sha512.Sum384(got) != sha512.Sum384(pt) {
			t.Fatalf("round trip of %d bytes returned %d different bytes", len(pt), len(got))
		}

		var streamed bytes.Buffer
		w, err := SealStreamTo(&streamed, fk, nonce, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(pt); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(streamed.Bytes(), sealed) {
			t.Fatalf("SealStreamTo and SealStream sealed %d bytes differently", len(pt))
		}

		var withAAD bytes.Buffer
		w, err = SealStreamTo(&withAAD, fk, nonce, aad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(pt); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := OpenStreamTo(&out, fk, bytes.NewReader(withAAD.Bytes()), aad, chunks); err != nil {
			t.Fatalf("OpenStreamTo at maxChunks %d: %v", chunks, err)
		}
		if !bytes.Equal(out.Bytes(), pt) {
			t.Fatalf("OpenStreamTo round trip of %d bytes returned different bytes", len(pt))
		}
		if chunks > 1 {
			if err := OpenStreamTo(&bytes.Buffer{}, fk, bytes.NewReader(withAAD.Bytes()), aad, chunks-1); err == nil {
				t.Fatalf("OpenStreamTo accepted %d chunks at maxChunks %d", chunks, chunks-1)
			}
		}
	})
}

// Malformations FuzzStreamMalformed applies. Each one changes the sealed bytes, so an
// accepted result is always a failure.
const (
	malTruncate   = iota // cut 1 or more bytes from the end, into or past the final chunk
	malReorder           // swap two different chunks
	malFlipTag           // flip one bit of one chunk's GCM tag
	malWrongCount        // re-seal one chunk under a different counter
	malWrongLast         // re-seal one chunk with the last-chunk flag inverted
	malNonce             // flip one bit of the payload nonce
	malFlipAny           // flip one bit anywhere in the chunk bytes
	malJunk              // replace every chunk with the fuzz bytes
	malCount
)

// FuzzStreamMalformed seals a fuzz-sized value, applies one malformation at a
// fuzz-chosen position, and requires both readers to refuse the result.
//
// Invariants:
//   - OpenStream and OpenStreamTo never panic on the malformed bytes.
//   - Both return an error: a truncation into or past the final chunk, a reordered chunk,
//     a flipped tag, a wrong counter, a wrong last-chunk flag, a changed payload nonce and
//     arbitrary chunk bytes all fail authentication or framing.
//   - OpenStream returns no plaintext with its error. OpenStreamTo is not held to that:
//     it writes each chunk to dst once that chunk authenticates, so a fault in a later
//     chunk leaves the earlier chunks' plaintext in dst.
func FuzzStreamMalformed(f *testing.F) {
	for op := byte(0); op < malCount; op++ {
		f.Add(op, uint32(2*spec.ChunkSize+9), uint16(1), byte(3), []byte("junk"))
		f.Add(op, uint32(5), uint16(0), byte(0), []byte{})
	}

	fk := fixedKey(0x42)
	nonce := bytes.Repeat([]byte{0x24}, spec.StreamNonceSize)

	f.Fuzz(func(t *testing.T, op byte, size uint32, pos uint16, bit byte, junk []byte) {
		pt := fuzzPlaintext([]byte("the value under test"), size)
		sealed, err := SealStream(fk, pt, nonce)
		if err != nil {
			t.Fatal(err)
		}
		payloadNonce, frames := splitFrames(sealed)
		k := int(pos) % len(frames)
		mask := byte(1) << (bit % 8)

		switch op % malCount {
		case malTruncate:
			body := len(sealed) - spec.StreamNonceSize
			cut := 1 + int(pos)%body
			sealed = sealed[:len(sealed)-cut]
		case malReorder:
			if len(frames) < 2 {
				return
			}
			j := (k + 1 + int(bit)%(len(frames)-1)) % len(frames)
			frames[k], frames[j] = frames[j], frames[k]
			sealed = joinFrames(payloadNonce, frames)
		case malFlipTag:
			tag := len(frames[k]) - spec.TagSize + int(bit/8)%spec.TagSize
			frames[k] = flipBit(frames[k], tag, mask)
			sealed = joinFrames(payloadNonce, frames)
		case malWrongCount, malWrongLast:
			aead, err := streamAEAD(fk, payloadNonce)
			if err != nil {
				t.Fatal(err)
			}
			counter, last := uint64(k), k == len(frames)-1
			if op%malCount == malWrongCount {
				counter += 1 + uint64(bit)
			} else {
				last = !last
			}
			start := k * streamChunkSize
			end := min(start+streamChunkSize, len(pt))
			n := chunkNonce(counter, last)
			frames[k] = aead.Seal(nil, n[:], pt[start:end], nil)
			sealed = joinFrames(payloadNonce, frames)
		case malNonce:
			sealed = flipBit(sealed, int(pos)%spec.StreamNonceSize, mask)
		case malFlipAny:
			body := len(sealed) - spec.StreamNonceSize
			sealed = flipBit(sealed, spec.StreamNonceSize+int(pos)%body, mask)
		case malJunk:
			sealed = append(bytes.Clone(payloadNonce), junk...)
		}

		got, err := OpenStream(fk, sealed)
		if err == nil {
			t.Fatalf("OpenStream accepted malformation %d (%d plaintext bytes, chunk %d) and returned %d bytes", op%malCount, len(pt), k, len(got))
		}
		if got != nil {
			t.Fatalf("OpenStream refused malformation %d but still returned %d plaintext bytes", op%malCount, len(got))
		}
		if err := OpenStreamTo(&bytes.Buffer{}, fk, bytes.NewReader(sealed), nil, 0); err == nil {
			t.Fatalf("OpenStreamTo accepted malformation %d (%d plaintext bytes, chunk %d)", op%malCount, len(pt), k)
		}
	})
}

// splitFrames is splitSealed for a fuzz body: it splits a sealed payload into its nonce
// and its chunk frames, and copies each frame so a malformation cannot alias another.
func splitFrames(sealed []byte) (nonce []byte, frames [][]byte) {
	nonce = bytes.Clone(sealed[:spec.StreamNonceSize])
	body := sealed[spec.StreamNonceSize:]
	for len(body) > streamMaxChunk {
		frames = append(frames, bytes.Clone(body[:streamMaxChunk]))
		body = body[streamMaxChunk:]
	}
	return nonce, append(frames, bytes.Clone(body))
}

// flipBit returns a copy of b with the bits in mask flipped at index i.
func flipBit(b []byte, i int, mask byte) []byte {
	out := bytes.Clone(b)
	out[i] ^= mask
	return out
}
