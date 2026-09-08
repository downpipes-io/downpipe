package format

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// recordSaltLen is the fixed per-record salt width in bytes that the secrets
// addressing and file-key derivation bind (SPEC.md 6.3).
const recordSaltLen = 16

// SegmentReadError is a failure to FETCH a segment object, carrying the seg/ path the
// manifest named. The text is exactly what the wrapped fmt.Errorf produced before this
// type existed, so nothing printed changes; what changes is that a caller can now recover
// the path structurally instead of parsing it back out of a message.
//
// It exists for the receipt's danglingSegments count (SPEC.md 10.1, 8.5). A dangling
// reference is a DISTINCT seg/ object path that a retained manifest names and the bucket
// does not hold, and records share segments by content address, so counting failed
// RECORDS would overcount and counting parsed message text would be a scanner reading
// prose as data. This carries the path itself.
//
// Only a fetch failure is wrapped. An AEAD, chunk-count or hash failure is a segment that
// WAS there and did not check out, which is a different finding and must never be counted
// as a dangling reference.
type SegmentReadError struct {
	// Object is the seg/ path the manifest named.
	Object string
	Err    error
}

func (e *SegmentReadError) Error() string { return fmt.Sprintf("read segment %s: %v", e.Object, e.Err) }
func (e *SegmentReadError) Unwrap() error { return e.Err }

// segmentReadErr wraps a segment fetch failure with its object path, preserving the
// message and the wrapped chain (so errors.Is against fs.ErrNotExist still answers).
func segmentReadErr(object string, err error) error {
	return &SegmentReadError{Object: object, Err: err}
}

// RestoreRecord reassembles a record's value from its segments and verifies it against
// the record's plaintext SHA-384 (SPEC.md 7.4, 8.3). It opens each segment (the
// non-secret content-derived path or the secrets per-run/record/salt path), takes the
// packed byte slice if the record shares a segment, decompresses the reassembled value
// if the record's codec is gzip, then checks the hash.
func (r *Reader) RestoreRecord(rec spec.ShardRecord) ([]byte, error) {
	return r.restoreRecord(rec, maxDecompressedBytes)
}

// restoreRecord is RestoreRecord's implementation, parameterised on the aggregate
// reassembly ceiling so a test can drive it with a tiny value instead of allocating real
// gigabytes. ceiling is always maxDecompressedBytes in production (RestoreRecord above).
func (r *Reader) restoreRecord(rec spec.ShardRecord, ceiling int64) ([]byte, error) {
	var buf bytes.Buffer
	for _, seg := range rec.Segments {
		segID, err := segIDFromObject(seg.Object)
		if err != nil {
			return nil, err
		}
		sealed, err := r.store.Get(seg.Object)
		if err != nil {
			return nil, codedGet(ExitUnverified, segmentReadErr(seg.Object, err))
		}
		plain, err := r.openSegment(rec, seg, segID, sealed)
		if err != nil {
			return nil, coded(ExitUnverified, err)
		}
		buf.Write(plain)
		// Bound the reassembly itself, not just gunzip's decompressed-output check below:
		// nothing else caps the number of segments a record's chain declares, so a hostile
		// or corrupt manifest can otherwise buffer far past maxDecompressedBytes before
		// codec or hash is ever consulted (ASVS 5.2.1).
		if int64(buf.Len()) > ceiling {
			return nil, coded(ExitUnverified, fmt.Errorf("record %s reassembled value exceeds the %d byte aggregate reassembly ceiling", rec.RecordID, ceiling))
		}
	}
	value := buf.Bytes()

	// A packed record owns a byte slice of one shared segment's decrypted bytes.
	if len(rec.Segments) == 1 && rec.Segments[0].Packed != nil {
		p := rec.Segments[0].Packed
		// Bounds-check without int64 overflow: never compute Offset+Length on
		// attacker-controlled values (it can wrap); compare Length against the
		// remaining space instead.
		n := int64(len(value))
		if p.Offset < 0 || p.Length < 0 || p.Offset > n || p.Length > n-p.Offset {
			return nil, coded(ExitUnverified, fmt.Errorf("record %s packed slice (offset %d, length %d) is out of range for %d bytes", rec.RecordID, p.Offset, p.Length, n))
		}
		value = value[p.Offset : p.Offset+p.Length]
	} else {
		for _, seg := range rec.Segments {
			if seg.Packed != nil {
				return nil, fmt.Errorf("record %s mixes a packed slice with a multi-segment chain", rec.RecordID)
			}
		}
	}

	// The codec applies to the whole reassembled value (SPEC.md 7.5); the hash is over
	// the decompressed bytes.
	if rec.Codec == spec.CodecNameGzip {
		decompressed, err := gunzip(value, rec.PlaintextSize)
		if err != nil {
			return nil, fmt.Errorf("record %s gunzip: %w", rec.RecordID, err)
		}
		value = decompressed
	}

	if !crypto.ConstantTimeEqual([]byte(SHA384Hex(value)), []byte(rec.PlaintextSHA)) {
		return nil, coded(ExitPlaintext, fmt.Errorf("record %s failed its plaintext hash check", rec.RecordID))
	}
	return value, nil
}

// IsStreamable reports whether a record can be restored through the streaming path
// (RestoreRecordTo) rather than the buffering path (RestoreRecord). A streamable record
// is a non-gzip, non-packed segment chain: its segments are decrypted directly to the
// destination one chunk at a time, so a multi-GiB value restores without ever holding
// the whole value in memory. A gzip record (whose hash is over the decompressed value,
// which the gunzip step must buffer to bound) and a packed record (whose value is a byte
// slice of a shared segment) fall back to RestoreRecord. The same per-record plaintext
// SHA-384 gate applies on both paths.
func IsStreamable(rec spec.ShardRecord) bool {
	if rec.Codec == spec.CodecNameGzip {
		return false
	}
	for _, seg := range rec.Segments {
		if seg.Packed != nil {
			return false
		}
	}
	return true
}

// IsStreamable is the method form of the predicate above. It exists so *Reader (and
// StreamReader, which embeds it) satisfy the restore package's optional streaming
// capability, which requires the predicate and RestoreRecordTo together on the same
// value; without it every record takes the buffered whole-value path.
func (r *Reader) IsStreamable(rec spec.ShardRecord) bool {
	return IsStreamable(rec)
}

// RestoreRecordTo reassembles a streamable record's value straight to dst, decrypting one
// chunk at a time so a value larger than memory restores on a constrained machine (SPEC.md
// 1, 7.4). It applies the same gates as RestoreRecord: each segment is bounded by its
// signed chunkRange and must terminate exactly at lastChunkExclusive, and the per-record
// plaintext SHA-384 is checked over the concatenated plaintext before this returns. The
// plaintext is teed through a running SHA-384 as it streams to dst, so no extra buffering
// is needed for the hash. The check is end-to-end: a tampered segment fails its AEAD tag
// inside OpenStreamTo, and any byte change that survives that fails the SHA-384 here.
//
// dst receives the verified plaintext as it is decrypted, BEFORE the final hash check, so
// a caller that cannot tolerate unverified bytes (because the hash mismatch is reported
// only after the last byte is written) must use RestoreRecord, or write to a quarantine
// the caller discards on a non-nil error. A file sink that creates the destination with
// O_EXCL and leaves the partial file on error is acceptable: the error is surfaced and the
// operator must not trust a file whose restore returned an error. Only IsStreamable
// records are accepted; a gzip or packed record returns an error so the caller falls back
// to RestoreRecord rather than silently skipping the codec or the slice.
func (r *Reader) RestoreRecordTo(rec spec.ShardRecord, dst io.Writer) error {
	if !IsStreamable(rec) {
		return fmt.Errorf("record %s is not streamable (gzip or packed); use RestoreRecord", rec.RecordID)
	}
	h := sha512.New384()
	// Tee the plaintext to both the destination and the running hash as it streams, so the
	// per-record SHA-384 is asserted without buffering the value.
	teed := io.MultiWriter(dst, h)
	rs, streams := r.store.(ReaderStore)
	for _, seg := range rec.Segments {
		segID, err := segIDFromObject(seg.Object)
		if err != nil {
			return err
		}
		if streams {
			// The sealed object is decrypted straight off the store stream, so even its
			// CIPHERTEXT is never held whole: peak memory is the chunk buffers, independent
			// of the segment size. The stream observes the reader's caller context, so an
			// interrupt aborts an in-flight segment instead of draining it.
			rc, gerr := openSegmentReader(r.context(), rs, seg.Object)
			if gerr != nil {
				return gerr
			}
			serr := r.openSegmentStream(teed, rec, seg, segID, rc)
			cerr := rc.Close()
			if serr != nil {
				return coded(ExitUnverified, serr)
			}
			if cerr != nil {
				return fmt.Errorf("read segment %s: %w", seg.Object, cerr)
			}
			continue
		}
		sealed, err := r.store.Get(seg.Object)
		if err != nil {
			return codedGet(ExitUnverified, segmentReadErr(seg.Object, err))
		}
		if err := r.openSegmentTo(teed, rec, seg, segID, sealed); err != nil {
			return coded(ExitUnverified, err)
		}
	}
	if !crypto.ConstantTimeEqual([]byte(hex.EncodeToString(h.Sum(nil))), []byte(rec.PlaintextSHA)) {
		return coded(ExitPlaintext, fmt.Errorf("record %s failed its plaintext hash check", rec.RecordID))
	}
	return nil
}

// deriveFileKey re-derives one segment's file key the same way the crypto segment
// helpers do, branching on the record's source type. The secrets branch first enforces
// the documented address shape:
//
// recordId and the decoded salt feed length-prefixed HKDF context fields, which reject
// anything over 255 bytes; enforce the documented recordId shape (6.3) and the fixed
// 16-byte salt width here so a malformed-but-authentic manifest fails as a clean error,
// not a panic.
//
// openSegment and openSegmentTo share this one definition so the derivation, and the
// recordId guard, stay byte-identical on both the buffered and the streaming open paths.
func deriveFileKey(r *Reader, rec spec.ShardRecord, segID [48]byte) ([32]byte, error) {
	var fileKey [32]byte
	if rec.SourceType == spec.SourceSecrets {
		if verr := ValidateRecordID(rec.RecordID); verr != nil {
			return fileKey, fmt.Errorf("record %s: %w", rec.RecordID, verr)
		}
		salt, derr := B64Decode(rec.RecordSalt)
		if derr != nil {
			return fileKey, fmt.Errorf("record %s salt: %w", rec.RecordID, derr)
		}
		if len(salt) != recordSaltLen {
			return fileKey, fmt.Errorf("record %s: recordSalt must be %d bytes, got %d", rec.RecordID, recordSaltLen, len(salt))
		}
		fileKey = crypto.DeriveSecretsFileKey(r.master, segID, []byte(rec.RecordID), salt, r.runIDBytes)
		return fileKey, nil
	}
	codecID := spec.CodecNone
	if rec.Codec == spec.CodecNameGzip {
		codecID = spec.CodecGzip
	}
	fileKey = crypto.DeriveNonSecretFileKey(r.master, segID, codecID)
	return fileKey, nil
}

// openSegmentTo is the streaming form of openSegment: it decrypts one segment straight to
// dst rather than into a buffer, applying the same chunkRange bound and exact-termination
// invariant (SPEC.md 6.3). It counts the plaintext bytes written so the whole-segment
// chunkRange rule (the STREAM must terminate exactly at lastChunkExclusive) is still
// enforced without buffering the plaintext. The file-key derivation is shared with
// openSegment through deriveFileKey.
func (r *Reader) openSegmentTo(dst io.Writer, rec spec.ShardRecord, seg spec.Segment, segID [48]byte, sealed []byte) error {
	maxChunks, err := segmentChunkBound(rec.RecordID, seg.ChunkRange)
	if err != nil {
		return err
	}

	fileKey, err := deriveFileKey(r, rec, segID)
	if err != nil {
		return err
	}

	body, err := spec.UnframeContainer(spec.MagicSeg, sealed)
	if err != nil {
		return fmt.Errorf("open segment %s: %w", crypto.SegIDHex(segID), err)
	}
	return r.decryptSegmentTo(dst, rec, seg, segID, fileKey, bytes.NewReader(body), maxChunks)
}

// openSegmentStream is openSegmentTo over a sealed object STREAM (framing included):
// the same chunkRange bound, key derivation, unframe checks and exact-termination
// invariant, applied in the same order, with the ciphertext never buffered.
func (r *Reader) openSegmentStream(dst io.Writer, rec spec.ShardRecord, seg spec.Segment, segID [48]byte, src io.Reader) error {
	maxChunks, err := segmentChunkBound(rec.RecordID, seg.ChunkRange)
	if err != nil {
		return err
	}

	fileKey, err := deriveFileKey(r, rec, segID)
	if err != nil {
		return err
	}

	body, err := spec.UnframeContainerReader(spec.MagicSeg, src)
	if err != nil {
		return fmt.Errorf("open segment %s: %w", crypto.SegIDHex(segID), err)
	}
	return r.decryptSegmentTo(dst, rec, seg, segID, fileKey, body, maxChunks)
}

// decryptSegmentTo is the shared decrypt tail of openSegmentTo and openSegmentStream.
// It counts the plaintext bytes as they stream so the exact-termination check holds
// without buffering the value: OpenStreamTo bounds the read above by maxChunks, and the
// count closes the lower bound (the segment's STREAM must terminate exactly at
// lastChunkExclusive, so a chunkRange that over-states the chunk count is also caught).
func (r *Reader) decryptSegmentTo(dst io.Writer, rec spec.ShardRecord, seg spec.Segment, segID [48]byte, fileKey [32]byte, body io.Reader, maxChunks int) error {
	counter := &countingWriter{w: dst}
	if oerr := crypto.OpenStreamTo(counter, fileKey, body, nil, maxChunks); oerr != nil {
		return fmt.Errorf("open segment %s: %w", crypto.SegIDHex(segID), oerr)
	}
	if got := segmentStreamChunks(int(counter.n)); got != maxChunks {
		return fmt.Errorf("record %s segment %s terminates after %d chunks but chunkRange declares %d", rec.RecordID, seg.Object, got, maxChunks)
	}
	return nil
}

// openSegmentReader opens one sealed segment object as a stream through the store's
// ReaderStore capability, wrapping the error the same way the buffered read does.
func openSegmentReader(ctx context.Context, rs ReaderStore, object string) (io.ReadCloser, error) {
	rc, _, err := rs.GetReader(ctx, object)
	if err != nil {
		return nil, codedGet(ExitUnverified, segmentReadErr(object, err))
	}
	return rc, nil
}

// countingWriter forwards every write to w and counts the bytes, so the streaming segment
// open can enforce the whole-segment chunk-count invariant without buffering the plaintext.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// maxDecompressedBytes is the absolute ceiling on a record's decompressed plaintext,
// independent of the record's own declared plaintextSize. The declared size is
// signer-attested in verified mode, but under allow-unverified (SPEC.md 8.3) or a corrupt
// archive a hostile member can declare a size toward 2^53-1; this ceiling rejects such a
// member before any decompression is attempted. It matches the per-segment 1 GiB
// codec=none plaintext bound (maxSegmentChunks chunks of ChunkSize), the largest plaintext
// a single in-memory restore reassembles.
const maxDecompressedBytes int64 = int64(maxSegmentChunks) * spec.ChunkSize

// gunzip decompresses b, bounded by the smaller of the record's declared plaintext size
// and the absolute maxDecompressedBytes ceiling so a crafted or unverified segment cannot
// drive an oversized allocation. A declared size above the ceiling is rejected outright.
func gunzip(b []byte, maxLen int64) ([]byte, error) {
	if maxLen > maxDecompressedBytes {
		return nil, fmt.Errorf("declared plaintext size %d exceeds the %d byte decompression ceiling", maxLen, maxDecompressedBytes)
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()
	out, err := io.ReadAll(io.LimitReader(zr, maxLen+1))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > maxLen {
		return nil, fmt.Errorf("decompressed output exceeds the declared %d bytes", maxLen)
	}
	return out, nil
}

// maxSegmentChunks is the per-segment STREAM-chunk ceiling for this format version
// (SPEC.md 14.5): a record is split into segments of at most 16384 chunks (16384 *
// 65536 = 1 GiB of codec=none plaintext) each, so a whole-segment chunkRange's
// lastChunkExclusive is at most this. It bounds the per-segment read independently of
// any single manifest's declared range.
const maxSegmentChunks = 16384

// openSegment decrypts one segment, bounding the read to the segment's signed
// chunkRange (SPEC.md 6.3). It unframes the container, re-derives the file key through the
// shared deriveFileKey helper, then streams through crypto.OpenStreamTo with
// maxChunks set from the chunkRange so a segment can never read beyond its declared
// chunk count, and finally checks that the segment's STREAM terminates exactly at
// lastChunkExclusive (the whole-segment chunkRange invariant of 6.3). The per-record
// plaintext SHA-384 check in RestoreRecord remains the end-to-end content gate.
func (r *Reader) openSegment(rec spec.ShardRecord, seg spec.Segment, segID [48]byte, sealed []byte) ([]byte, error) {
	maxChunks, err := segmentChunkBound(rec.RecordID, seg.ChunkRange)
	if err != nil {
		return nil, err
	}

	fileKey, err := deriveFileKey(r, rec, segID)
	if err != nil {
		return nil, err
	}

	body, err := spec.UnframeContainer(spec.MagicSeg, sealed)
	if err != nil {
		return nil, fmt.Errorf("open segment %s: %w", crypto.SegIDHex(segID), err)
	}
	var plain bytes.Buffer
	// maxChunks bounds the read to the declared chunkRange: OpenStreamTo refuses to open
	// a chunk at index >= maxChunks, so a segment whose true length exceeds its declared
	// range is rejected rather than fully buffered (the seal path used nil AAD).
	if oerr := crypto.OpenStreamTo(&plain, fileKey, bytes.NewReader(body), nil, maxChunks); oerr != nil {
		return nil, fmt.Errorf("open segment %s: %w", crypto.SegIDHex(segID), oerr)
	}
	// Closing the lower bound too: the segment's STREAM must terminate exactly at
	// lastChunkExclusive, not merely at or before it, so a chunkRange that over-states
	// the segment's chunk count is also caught (6.3 whole-segment rule).
	if got := segmentStreamChunks(plain.Len()); got != maxChunks {
		return nil, fmt.Errorf("record %s segment %s terminates after %d chunks but chunkRange declares %d", rec.RecordID, seg.Object, got, maxChunks)
	}
	return plain.Bytes(), nil
}

// segmentChunkBound validates a segment's signed chunkRange and returns the chunk count
// it declares, which drives the bounded read (SPEC.md 6.3, 14.5). The range is the
// half-open [firstChunk, lastChunkExclusive). This reader opens each segment object as a
// whole STREAM, so firstChunk MUST be 0 (a sub-segment chunk offset is not a shape this
// format version emits); lastChunkExclusive MUST be at least 1 and at most the per-segment
// ceiling of 14.5.
func segmentChunkBound(recordID string, chunkRange [2]int) (int, error) {
	first, last := chunkRange[0], chunkRange[1]
	if first != 0 {
		return 0, fmt.Errorf("record %s segment chunkRange firstChunk must be 0, got %d", recordID, first)
	}
	if last < 1 {
		return 0, fmt.Errorf("record %s segment chunkRange lastChunkExclusive must be at least 1, got %d", recordID, last)
	}
	if last > maxSegmentChunks {
		return 0, fmt.Errorf("record %s segment chunkRange lastChunkExclusive %d exceeds the %d-chunk segment ceiling", recordID, last, maxSegmentChunks)
	}
	return last, nil
}

// segmentStreamChunks returns the number of STREAM chunks a decrypted plaintext of n
// bytes occupies (SPEC.md 7.8): one chunk per 65536 plaintext bytes, an extra chunk for
// any remainder, and a single (empty) final chunk for a zero-length value.
func segmentStreamChunks(n int) int {
	chunks := n / spec.ChunkSize
	if n%spec.ChunkSize != 0 || n == 0 {
		chunks++
	}
	return chunks
}

func segIDFromObject(object string) ([48]byte, error) {
	// LastIndex returns -1 when there is no slash, so the +1 yields index 0 (the whole
	// string); an empty object slices to "" and fails the len(raw) != 48 check below as a
	// clean error. The slice index is therefore always in range.
	base := object[strings.LastIndex(object, "/")+1:]
	raw, err := hex.DecodeString(strings.TrimSuffix(base, ".seg"))
	if err != nil || len(raw) != 48 {
		return [48]byte{}, fmt.Errorf("invalid segment object %q", object)
	}
	var id [48]byte
	copy(id[:], raw)
	return id, nil
}
