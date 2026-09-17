package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/downpipes-io/downpipe/internal/spec"
)

const (
	streamChunkSize = spec.ChunkSize // 65536 plaintext bytes per chunk
	streamMaxChunk  = streamChunkSize + spec.TagSize

	// streamMaxChunkIndex is the highest chunk index whose nonce the uint64 counter
	// field can carry without wrapping (SPEC.md 7.8: the low 8 bytes of the 11-byte
	// counter field hold a uint64 index starting at 0). The per-chunk nonce is
	// derived only from this index and the last-chunk flag, so the sequence is unique
	// and strictly monotonic within a stream exactly while the index does not wrap:
	// a wrap back to 0 would reuse chunk 0's nonce under the same AES-256 key, which
	// is a catastrophic AES-GCM nonce reuse (keystream and authentication-key reuse).
	// The seal and open paths refuse to advance past this index rather than wrap. A
	// real backup never approaches it (2^64 chunks is 2^80 bytes of one sealed unit),
	// so the bound is a defensive assertion, not a working limit.
	streamMaxChunkIndex uint64 = math.MaxUint64
)

// SealStream seals a value as a downpipe STREAM payload: the payload nonce followed
// by AES-256-GCM chunks of 64 KiB plaintext each, the final chunk possibly shorter.
// Each chunk nonce is an 11-byte big-endian counter then a 1-byte last-chunk flag,
// so a reordered, truncated or spliced stream fails authentication (SPEC.md 7.8).
// The payload key is HKDF-SHA-384 of the file key salted by the payload nonce, so
// the AES-256 key is fresh per sealed unit. The caller supplies the payload nonce:
// random in production, pinned for writer-authoritative conformance vectors.
func SealStream(fileKey [32]byte, plaintext, payloadNonce []byte) ([]byte, error) {
	aead, err := streamAEAD(fileKey, payloadNonce)
	if err != nil {
		return nil, err
	}
	chunks := len(plaintext) / streamChunkSize
	if len(plaintext)%streamChunkSize != 0 || len(plaintext) == 0 {
		chunks++
	}
	out := make([]byte, 0, len(payloadNonce)+len(plaintext)+chunks*spec.TagSize)
	out = append(out, payloadNonce...)
	var counter uint64
	for i := 0; i < chunks; i++ {
		start := i * streamChunkSize
		end := start + streamChunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		nonce := chunkNonce(counter, i == chunks-1)
		out = aead.Seal(out, nonce[:], plaintext[start:end], nil)
		if i != chunks-1 {
			// Step the counter through the one chokepoint that refuses to wrap, so the
			// seal path can never emit two chunks under the same nonce. chunks is an int
			// so this never trips for a real in-memory payload; the guard is what keeps
			// SealStream and the streaming writer under the same no-reuse invariant.
			counter, err = advanceChunk(counter)
			if err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// OpenStream reverses SealStream. It returns the plaintext, or an error if any chunk
// fails authentication or a valid final chunk is missing (a truncation that drops
// the final chunk is caught because the preceding chunk does not carry the last-chunk
// flag).
func OpenStream(fileKey [32]byte, payload []byte) ([]byte, error) {
	if len(payload) < spec.StreamNonceSize {
		return nil, fmt.Errorf("payload is %d bytes, shorter than the %d-byte nonce", len(payload), spec.StreamNonceSize)
	}
	payloadNonce, body := payload[:spec.StreamNonceSize], payload[spec.StreamNonceSize:]
	aead, err := streamAEAD(fileKey, payloadNonce)
	if err != nil {
		return nil, err
	}
	var out []byte
	var counter uint64
	for len(body) > streamMaxChunk {
		nonce := chunkNonce(counter, false)
		out, err = aead.Open(out, nonce[:], body[:streamMaxChunk], nil)
		if err != nil {
			return nil, fmt.Errorf("chunk %d authentication failed: %w", counter, err)
		}
		body = body[streamMaxChunk:]
		counter, err = advanceChunk(counter)
		if err != nil {
			return nil, err
		}
	}
	if len(body) < spec.TagSize {
		return nil, fmt.Errorf("final chunk is %d bytes, shorter than the %d-byte tag", len(body), spec.TagSize)
	}
	nonce := chunkNonce(counter, true)
	out, err = aead.Open(out, nonce[:], body, nil)
	if err != nil {
		return nil, fmt.Errorf("final chunk %d authentication failed: %w", counter, err)
	}
	return out, nil
}

func streamAEAD(fileKey [32]byte, payloadNonce []byte) (cipher.AEAD, error) {
	if len(payloadNonce) != spec.StreamNonceSize {
		return nil, fmt.Errorf("payload nonce is %d bytes, want %d", len(payloadNonce), spec.StreamNonceSize)
	}
	payloadKey := hkdfKey(fileKey[:], payloadNonce, []byte(spec.InfoPayload), 32)
	block, err := aes.NewCipher(payloadKey)
	if err != nil {
		return nil, fmt.Errorf("aes-256 key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-256-gcm: %w", err)
	}
	return aead, nil
}

// SealStreamTo is the streaming form of SealStream. It writes the payload nonce to
// dst, then seals one 64 KiB chunk at a time as the caller writes, so neither the
// writer nor the reader holds a whole value in memory (SPEC.md 1, 7.8). Close emits
// the final chunk (the buffered remainder, which is the empty final chunk when
// nothing was written) and must be called exactly once. The optional aad binds extra
// context into every chunk. The bytes are identical to SealStream for the same key,
// nonce, aad and plaintext, so the two forms interoperate.
func SealStreamTo(dst io.Writer, fileKey [32]byte, payloadNonce, aad []byte) (io.WriteCloser, error) {
	aead, err := streamAEAD(fileKey, payloadNonce)
	if err != nil {
		return nil, err
	}
	if _, err := dst.Write(payloadNonce); err != nil {
		return nil, fmt.Errorf("write payload nonce: %w", err)
	}
	return &streamWriter{dst: dst, aead: aead, aad: aad, buf: make([]byte, 0, streamChunkSize)}, nil
}

type streamWriter struct {
	dst     io.Writer
	aead    cipher.AEAD
	aad     []byte
	buf     []byte
	counter uint64
	closed  bool
}

func (w *streamWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, fmt.Errorf("write after close")
	}
	written := 0
	for len(p) > 0 {
		// A full buffer is flushed as a non-final chunk only when more data is known
		// to follow; the last chunk is always held back for Close to flag as final.
		if len(w.buf) == streamChunkSize {
			if err := w.flush(false); err != nil {
				return written, err
			}
		}
		n := min(streamChunkSize-len(w.buf), len(p))
		w.buf = append(w.buf, p[:n]...)
		p = p[n:]
		written += n
	}
	return written, nil
}

func (w *streamWriter) flush(last bool) error {
	nonce := chunkNonce(w.counter, last)
	ct := w.aead.Seal(nil, nonce[:], w.buf, w.aad)
	if _, err := w.dst.Write(ct); err != nil {
		return err
	}
	w.buf = w.buf[:0]
	if last {
		// The final chunk is the last write; do not advance past it. Advancing here
		// would be the step that could wrap on the next non-final write, and there is
		// no next write after Close.
		return nil
	}
	next, err := advanceChunk(w.counter)
	if err != nil {
		return err
	}
	w.counter = next
	return nil
}

func (w *streamWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	return w.flush(true)
}

// OpenStreamTo is the streaming form of OpenStream. It reads a sealed payload from
// src, authenticates and decrypts one chunk at a time, and writes the plaintext to
// dst, holding only about two chunks in memory regardless of the value size. maxChunks
// bounds the number of chunks (pass the count implied by the signed chunkRange, or a
// non-positive value for no bound), so a malicious sealed input cannot drive
// unbounded memory or work. The aad must match the one used to seal.
func OpenStreamTo(dst io.Writer, fileKey [32]byte, src io.Reader, aad []byte, maxChunks int) error {
	nonce := make([]byte, spec.StreamNonceSize)
	if _, err := io.ReadFull(src, nonce); err != nil {
		return fmt.Errorf("read payload nonce: %w", err)
	}
	aead, err := streamAEAD(fileKey, nonce)
	if err != nil {
		return err
	}
	// The look-ahead read needs two ciphertext buffers, a current and a next, that we
	// swap each iteration so neither is reallocated per chunk. pt holds the decrypted
	// chunk and is written to dst before the next Open reuses it, so a single plaintext
	// buffer is reused for the whole stream.
	buf0 := make([]byte, streamMaxChunk)
	buf1 := make([]byte, streamMaxChunk)
	pt := make([]byte, 0, streamChunkSize)
	cur := buf0
	curN, err := readChunk(src, cur)
	if err != nil {
		return fmt.Errorf("read first chunk: %w", err)
	}
	if curN < spec.TagSize {
		return fmt.Errorf("first chunk is %d bytes, shorter than the %d-byte tag", curN, spec.TagSize)
	}
	next := buf1
	var counter uint64
	for {
		nextN, err := readChunk(src, next)
		if err != nil {
			return fmt.Errorf("read chunk %d: %w", counter+1, err)
		}
		last := nextN == 0
		if maxChunks > 0 && counter >= uint64(maxChunks) {
			return fmt.Errorf("stream exceeds the %d-chunk limit", maxChunks)
		}
		cn := chunkNonce(counter, last)
		out, err := aead.Open(pt[:0], cn[:], cur[:curN], aad)
		if err != nil {
			return fmt.Errorf("chunk %d authentication failed: %w", counter, err)
		}
		if _, err := dst.Write(out); err != nil {
			return fmt.Errorf("write chunk %d: %w", counter, err)
		}
		if last {
			return nil
		}
		counter, err = advanceChunk(counter)
		if err != nil {
			return err
		}
		if nextN < spec.TagSize {
			return fmt.Errorf("chunk %d is %d bytes, shorter than the %d-byte tag", counter, nextN, spec.TagSize)
		}
		cur, curN, next = next, nextN, cur
	}
}

// readChunk reads up to len(buf) bytes, returning the count. A clean end of stream
// returns 0; a short read returns the partial count (the final chunk).
func readChunk(src io.Reader, buf []byte) (int, error) {
	n, err := io.ReadFull(src, buf)
	switch err {
	case nil:
		return n, nil
	case io.EOF:
		return 0, nil
	case io.ErrUnexpectedEOF:
		return n, nil
	default:
		return 0, err
	}
}

// chunkNonce builds the 12-byte AES-256-GCM nonce for a chunk: an 11-byte big-endian
// counter then a 1-byte last-chunk flag (SPEC.md 7.8). The counter value occupies the
// low 8 bytes (the top 3 bytes of the counter field stay zero, the reserved wire
// form); a real backup never reaches 2^64 chunks.
//
// The nonce is a pure function of (counter, last). Within one stream the counter
// starts at 0, advances by 1 through advanceChunk, and only the final chunk sets last,
// so the (counter, last) pairs, and therefore the nonces, are unique and strictly
// monotonic in the counter for the whole stream as long as the counter does not wrap.
// advanceChunk is the single chokepoint that keeps the counter from wrapping, so every
// seal and open path inherits that guarantee. The counter occupies the low 8 bytes of
// the 11-byte field, so it cannot collide with the last-chunk flag in byte 11 and the
// reserved top 3 bytes stay zero by construction (PutUint64 writes only n[3:11]).
func chunkNonce(counter uint64, last bool) [12]byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[3:11], counter)
	if last {
		n[11] = 0x01
	}
	return n
}

// advanceChunk returns the next chunk counter, or an error when advancing would wrap
// the uint64 index field past streamMaxChunkIndex and reuse an earlier chunk's nonce
// under the same key. It is the one place the seal and open paths step the counter, so
// every path inherits the no-wrap, no-reuse invariant. The error is returned, never
// panicked, so a hostile or corrupt stream that claims more than the safe number of
// chunks is rejected rather than crashing the process.
func advanceChunk(counter uint64) (uint64, error) {
	if counter >= streamMaxChunkIndex {
		return 0, fmt.Errorf("stream would exceed the safe chunk count: chunk index %d wraps the per-stream nonce counter", counter)
	}
	return counter + 1, nil
}
