package restore

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"io"
	"strconv"
)

// DiscardTarget is a restorability-verification sink: it runs every record through the
// full restore path (so each value is AEAD-tag verified and plaintext-hash checked by
// the reader) and then writes NOTHING. It exists to prove an archive is recoverable on
// a machine that must not hold the recovered plaintext, for example a scheduled
// restore-drill that confirms the break-glass key still opens the bucket without ever
// materialising a secret.
//
// No plaintext leaves the target. Write counts the record and the value's byte length,
// folds the record's destination key and a one-way SHA-384 OF the verified plaintext (never
// the plaintext bytes themselves) into a streaming restore digest, and discards the bytes;
// it never persists, prints or logs a value. The digest is a hash over a length-prefixed
// framing of each record's (key, plaintext-hash) pair in canonical write order, so two runs
// over the same archive produce the same digest and a record cannot be confused with its
// neighbour's, yet the digest never ingests a plaintext byte and so cannot be a confirmation
// oracle for a guessed value. This matches the engine's TS restore digest, which likewise
// folds recordId plus the verified plaintext SHA-384 and never the plaintext itself.
//
// The target never reports a conflict: it maps each record to a unique destination key
// by its position so every record is planned and therefore decrypted and verified.
// There is no existing state to clobber because nothing is written.
type DiscardTarget struct {
	digest  hash.Hash
	records int
	bytes   int64
	keySeq  int
	keyOf   map[string]string
}

// NewDiscardTarget returns a DiscardTarget with a fresh restore-digest accumulator.
func NewDiscardTarget() *DiscardTarget {
	return &DiscardTarget{digest: sha512.New384(), keyOf: make(map[string]string)}
}

// Kind reports the discard target enum. It is "discard", a closed label that the
// receipt and attestation carry; it is never a path or a value.
func (d *DiscardTarget) Kind() string { return "discard" }

// Key maps a record name to a unique, opaque destination key derived from the order in
// which names are first seen, so no two records ever collide on one key and every
// record is planned as a write (and therefore decrypted and verified). The key is a
// bare ordinal; it carries no part of the value and is never written anywhere.
//
// Key is called once per record by the planner and may be called again at apply time
// for the same name, so it is memoised: the same name always returns the same key. It
// never returns an error, so no record is ever classified unrepresentable and skipped.
func (d *DiscardTarget) Key(name string) (string, error) {
	if k, ok := d.keyOf[name]; ok {
		return k, nil
	}
	k := strconv.Itoa(d.keySeq)
	d.keySeq++
	d.keyOf[name] = k
	return k, nil
}

// Existing returns the empty set: a discard target holds no state, so the planner never
// marks a record as clobbering existing state and every record is verified.
func (d *DiscardTarget) Existing() (map[string]struct{}, error) {
	return map[string]struct{}{}, nil
}

// Write verifies-by-accounting and discards. The value has already been reassembled,
// AEAD-tag verified and plaintext-hash checked by the reader before it reaches here; this
// method folds the record's destination key and a SHA-384 OF the plaintext into the restore
// digest, counts the record and its length, then drops the bytes on the floor. It writes
// nothing to disk, stdout, stderr or any log, so no plaintext can leak through the discard
// sink.
//
// The raw plaintext is NEVER folded into the digest: it is first reduced to its own SHA-384,
// so the running digest cannot act as a low-entropy confirmation oracle for a guessed value
// (an attacker who can run the blind test still learns nothing testable about the plaintext).
// This mirrors the engine's TS digest, which folds recordId plus the verified plaintext
// SHA-384 rather than the plaintext.
//
// The fold frames each leaf as len(key) || key || sha384(value), each behind a fixed 8-byte
// big-endian length prefix, so the boundary between two records is unambiguous and a record
// cannot be shifted into its neighbour to forge a matching digest across two different
// archives.
func (d *DiscardTarget) Write(key string, value []byte) error {
	// Reduce the plaintext to its own SHA-384 so the digest is over a hash of the value, not
	// the value: the plaintext bytes never enter the running digest.
	valueHash := sha512.Sum384(value)
	d.fold(key, valueHash[:])
	d.records++
	d.bytes += int64(len(value))
	return nil
}

// WriteStream verifies-by-accounting and discards a record streamed one chunk at a time, so
// a value larger than memory is verified through a deep drill (verify --deep / restore
// --sink discard) in bounded memory (SPEC.md 1). The reader (RestoreRecordTo) has already
// AEAD-tag verified each chunk and asserts the per-record plaintext SHA-384 over the whole
// stream after the last byte; this method folds the record's destination key and a SHA-384
// OF the streamed plaintext into the restore digest, byte-identically to Write (both route
// through fold), counts the record and its length, and discards every byte as it arrives. It
// never buffers, persists, prints or logs a value. On a copy error (the reader closing the
// pipe with an integrity verdict) it returns the error and folds nothing, so a failed record
// is never counted as verified.
func (d *DiscardTarget) WriteStream(key string, src io.Reader, _ int64) error {
	// io.Copy reads src to EOF, hashing every byte and discarding it (the hash is the only
	// sink). When the reader closed the pipe with an integrity error, io.Copy surfaces it.
	h := sha512.New384()
	n, err := io.Copy(h, src)
	if err != nil {
		return err
	}
	d.fold(key, h.Sum(nil))
	d.records++
	d.bytes += n
	return nil
}

// fold mixes one verified record's destination key and its plaintext SHA-384 into the
// running restore digest, framing each leaf as len(key) || key || len(valueHash) ||
// valueHash, each length a fixed 8-byte big-endian prefix, so the boundary between two
// records is unambiguous and a record cannot be shifted into its neighbour to forge a
// matching digest. valueHash is a SHA-384 of the plaintext (never the plaintext itself), so
// the digest cannot act as a low-entropy confirmation oracle. The buffered (Write) and
// streamed (WriteStream) paths share this one definition, so a value's digest contribution
// is identical whichever path verified it.
func (d *DiscardTarget) fold(key string, valueHash []byte) {
	keyBytes := []byte(key)
	var lenPrefix [8]byte
	// hash.Hash.Write never returns an error (documented), so each framed leaf is folded in.
	binary.BigEndian.PutUint64(lenPrefix[:], uint64(len(keyBytes)))
	d.digest.Write(lenPrefix[:])
	d.digest.Write(keyBytes)
	binary.BigEndian.PutUint64(lenPrefix[:], uint64(len(valueHash)))
	d.digest.Write(lenPrefix[:])
	d.digest.Write(valueHash)
}

// Close is a no-op; a DiscardTarget holds no resources and has nothing to flush.
func (d *DiscardTarget) Close() error { return nil }

// Digest returns the restore digest accumulated over each verified record's destination key
// and the SHA-384 of its plaintext, as bare lowercase hex SHA-384. It is a one-way hash that
// never ingested a plaintext byte and so reveals no plaintext and cannot confirm a guessed
// value; it is stable across runs over the same archive, so an operator can pin it and detect
// a future change to the recovered content. When no record was written it is the digest of
// the empty stream.
func (d *DiscardTarget) Digest() string {
	return hex.EncodeToString(d.digest.Sum(nil))
}

// VerifiedRecords reports how many records the discard target verified (decrypted,
// AEAD-tag checked and plaintext-hash checked) and discarded.
func (d *DiscardTarget) VerifiedRecords() int { return d.records }

// VerifiedBytes reports the total plaintext byte length the discard target verified and
// discarded. It is a count only and carries no value bytes.
func (d *DiscardTarget) VerifiedBytes() int64 { return d.bytes }
