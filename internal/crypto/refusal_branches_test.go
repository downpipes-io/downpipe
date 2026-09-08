package crypto

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// The refusal branches of the crypto core, driven rather than reasoned about.
//
// Every one of the uncovered statements this package's floor requires was an error or
// refusal branch, which is the half of this package a customer meets only when something
// has already gone wrong, and the half whose behaviour a recovery depends on being exact.
//
// EACH TEST HERE ASSERTS THE REFUSAL, NOT MERELY THAT SOMETHING FAILED. A test that accepts any
// non-nil error passes when the code refuses for the wrong reason, which is how a wrong error
// message reaches a recoverer who is reading it at three in the morning. Each one names the
// message it expects.
//
// TWO BRANCHES ARE DELIBERATELY NOT HERE, because they are unreachable rather than untested:
// ParseKEMPrivate rejects a bad X25519 half and a bad ML-KEM half, and neither rejection can be
// reached from an input of the right length. crypto/ecdh accepts an all-zero X25519 private
// scalar, and crypto/mlkem accepts an all-zero 64-byte decapsulation seed. Both return nil
// error. The remaining uncovered branches are CSPRNG and AES key-schedule failures that have no
// seam short of injecting a failing primitive, which would be a seam added for a test rather
// than a property of the code.

// TestSealToRecipientsRefusesAnEmptyRecipientList covers the guard that stops a run sealing a
// master nobody can ever open. A capsule with no wraps is unrecoverable by construction, and the
// failure has to arrive at seal time rather than at restore time.
func TestSealToRecipientsRefusesAnEmptyRecipientList(t *testing.T) {
	var secret [32]byte
	_, err := SealToRecipients(secret, nil, []byte("ctx"), bytes.NewReader(make([]byte, 64)))
	if err == nil {
		t.Fatal("sealing to no recipients returned no error, so a run could be sealed that nobody can open")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("at least one recipient")) {
		t.Fatalf("the refusal does not say a recipient is needed: %v", err)
	}
}

// TestOpenCapsuleRefusesAWrapWhoseKEMCiphertextIsCorrupt covers the decapsulation failure inside
// openWrap. The fingerprint matches, so the wrap is selected and then fails, which is the shape a
// corrupted or forged manifest produces.
func TestOpenCapsuleRefusesAWrapWhoseKEMCiphertextIsCorrupt(t *testing.T) {
	priv, pub, err := GenerateHybridKEM()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	w := WrappedKey{Fingerprint: RecipientFingerprint(pub), KEMCiphertext: []byte("not a kem ciphertext"), Sealed: []byte("sealed")}
	_, err = OpenCapsule([]WrappedKey{w}, priv, []byte("ctx"), nil)
	if err == nil {
		t.Fatal("a wrap with a corrupt KEM ciphertext opened, so a forged capsule reads as recoverable")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("decapsulate for")) {
		t.Fatalf("the refusal does not name decapsulation as the step that failed: %v", err)
	}
}

// TestOpenCapsuleRefusesARecoveredSecretThatIsNot32Bytes covers the length assertion after the
// wrap opens. Everything cryptographic has already succeeded here: the wrap really was sealed to
// this recipient under the right context, and it carries the wrong number of bytes. Only the
// explicit check stands between that and a short or over-long "master" being copied into a
// fixed 32-byte array and used to derive every file key in the run.
func TestOpenCapsuleRefusesARecoveredSecretThatIsNot32Bytes(t *testing.T) {
	priv, pub, err := GenerateHybridKEM()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	context := []byte("run-context")
	ss, ct, err := EncapsulateHybrid(pub)
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}
	wrapKey := first32(hkdfKey(ss, nil, []byte(spec.InfoCapsuleDEM), spec.FileKeySize))
	var sealed bytes.Buffer
	sw, err := SealStreamTo(&sealed, wrapKey, make([]byte, spec.StreamNonceSize), context)
	if err != nil {
		t.Fatalf("seal writer: %v", err)
	}
	// Eight bytes where the format says thirty-two, sealed correctly in every other respect.
	if _, err := sw.Write(make([]byte, 8)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	w := WrappedKey{Fingerprint: RecipientFingerprint(pub), KEMCiphertext: ct, Sealed: sealed.Bytes()}
	_, err = OpenCapsule([]WrappedKey{w}, priv, context, nil)
	if err == nil {
		t.Fatal("a wrap carrying an 8-byte secret opened as a 32-byte master")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("recovered secret is 8 bytes, want 32")) {
		t.Fatalf("the refusal does not name the recovered length: %v", err)
	}
}

// TestDeriveSecretsFileKeyRefusesAWrongSizedRecordIdentity covers the size assertion on the
// secrets file-key derivation. A short record id or salt would derive a key from a different
// length-prefixed input than the writer used, so it panics rather than deriving a key that
// silently fails to open anything later.
func TestDeriveSecretsFileKeyRefusesAWrongSizedRecordIdentity(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("a 4-byte record id derived a secrets file key instead of refusing")
		}
		msg, ok := r.(string)
		if !ok {
			if err, isErr := r.(error); isErr {
				msg = err.Error()
			}
		}
		if !bytes.Contains([]byte(msg), []byte("16")) {
			t.Fatalf("the refusal does not name the required 16-byte length: %v", r)
		}
	}()
	var segID [48]byte
	DeriveSecretsFileKey(make([]byte, 32), segID, []byte("shrt"), make([]byte, 16), make([]byte, 16))
}

// TestSealStreamToRefusesAPayloadNonceOfTheWrongLength covers the nonce-length guard on the
// streaming seal. The payload nonce is the HKDF salt for the payload key, so a short one is a
// weaker key rather than a visible error anywhere downstream.
func TestSealStreamToRefusesAPayloadNonceOfTheWrongLength(t *testing.T) {
	var key [32]byte
	var dst bytes.Buffer
	_, err := SealStreamTo(&dst, key, make([]byte, spec.StreamNonceSize-1), nil)
	if err == nil {
		t.Fatal("a short payload nonce was accepted by the streaming seal")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("payload nonce is 15 bytes, want 16")) {
		t.Fatalf("the refusal does not name the nonce length: %v", err)
	}
	if dst.Len() != 0 {
		t.Fatalf("the refused seal wrote %d byte(s) to the destination", dst.Len())
	}
}

// TestStreamWriterRefusesAWriteAfterClose covers the closed-writer guard. Close emits the final
// chunk, which is the one that carries the last-chunk flag, so a later write would append a chunk
// after the end marker and produce a stream no reader accepts.
func TestStreamWriterRefusesAWriteAfterClose(t *testing.T) {
	var key [32]byte
	var dst bytes.Buffer
	sw, err := SealStreamTo(&dst, key, make([]byte, spec.StreamNonceSize), nil)
	if err != nil {
		t.Fatalf("seal writer: %v", err)
	}
	if _, err := sw.Write([]byte("before close")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	sealedLen := dst.Len()
	n, err := sw.Write([]byte("after close"))
	if err == nil {
		t.Fatal("a write after close was accepted, so a chunk can be appended past the final one")
	}
	if n != 0 {
		t.Fatalf("a refused write reported %d byte(s) written", n)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("write after close")) {
		t.Fatalf("the refusal does not name the cause: %v", err)
	}
	if dst.Len() != sealedLen {
		t.Fatalf("the refused write still added %d byte(s) to the stream", dst.Len()-sealedLen)
	}
}

// TestStreamWriterSurfacesADestinationFailureMidStream covers the non-final flush inside Write.
// A destination that fails part way through a large value must stop the seal there rather than
// let the writer carry on producing chunks nothing recorded.
func TestStreamWriterSurfacesADestinationFailureMidStream(t *testing.T) {
	var key [32]byte
	sentinel := errors.New("destination went away")
	// One byte more than the nonce, so the nonce write succeeds and the first CHUNK write is the
	// one that fails. failWriter reports its error on the write that exhausts the allowance.
	dst := &failWriter{remaining: spec.StreamNonceSize + 1, err: sentinel}
	sw, err := SealStreamTo(dst, key, make([]byte, spec.StreamNonceSize), nil)
	if err != nil {
		t.Fatalf("seal writer: %v", err)
	}
	// More than one chunk, so Write itself must flush rather than leaving it all to Close.
	_, err = sw.Write(make([]byte, spec.ChunkSize+1))
	if !errors.Is(err, sentinel) {
		t.Fatalf("a destination failure during a mid-stream flush was not surfaced: %v", err)
	}
}

// TestStreamWriterRefusesToWrapTheChunkCounter covers the no-wrap guard in the streaming flush.
// The per-chunk nonce is a pure function of the counter, so a wrap back to zero would reuse
// chunk zero's nonce under the same AES-256 key, which is catastrophic for AES-GCM. The counter
// is set here rather than reached, because reaching it means sealing 2^64 chunks.
func TestStreamWriterRefusesToWrapTheChunkCounter(t *testing.T) {
	var key [32]byte
	aead, err := streamAEAD(key, make([]byte, spec.StreamNonceSize))
	if err != nil {
		t.Fatalf("aead: %v", err)
	}
	var dst bytes.Buffer
	w := &streamWriter{dst: &dst, aead: aead, buf: []byte("a chunk"), counter: streamMaxChunkIndex}
	err = w.flush(false)
	if err == nil {
		t.Fatal("a non-final flush at the maximum chunk index advanced the counter instead of refusing")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("wraps the per-stream nonce counter")) {
		t.Fatalf("the refusal does not name nonce reuse as the reason: %v", err)
	}
	// The final flush is the one that must NOT advance, so it stays legal at the same index.
	w2 := &streamWriter{dst: &dst, aead: aead, buf: []byte("a chunk"), counter: streamMaxChunkIndex}
	if err := w2.flush(true); err != nil {
		t.Fatalf("the FINAL chunk at the maximum index was refused, and it never advances: %v", err)
	}
}

// TestOpenStreamToRefusesATruncatedPayloadNonce covers the first read of the streaming open. A
// payload shorter than its own nonce is a truncation, and it has to be named as one.
func TestOpenStreamToRefusesATruncatedPayloadNonce(t *testing.T) {
	var key [32]byte
	var out bytes.Buffer
	err := OpenStreamTo(&out, key, bytes.NewReader(make([]byte, spec.StreamNonceSize-1)), nil, 0)
	if err == nil {
		t.Fatal("a payload shorter than its nonce opened")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("read payload nonce")) {
		t.Fatalf("the refusal does not name the nonce read: %v", err)
	}
}

// TestOpenStreamToRefusesAFirstChunkShorterThanTheTag covers the first-chunk length guard. A
// chunk shorter than the authentication tag cannot be authenticated at all, so it is refused
// before the AEAD is asked about it.
func TestOpenStreamToRefusesAFirstChunkShorterThanTheTag(t *testing.T) {
	var key [32]byte
	payload := append(make([]byte, spec.StreamNonceSize), make([]byte, spec.TagSize-1)...)
	var out bytes.Buffer
	err := OpenStreamTo(&out, key, bytes.NewReader(payload), nil, 0)
	if err == nil {
		t.Fatal("a first chunk shorter than the tag opened")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("first chunk is 15 bytes, shorter than the 16-byte tag")) {
		t.Fatalf("the refusal does not name the short first chunk: %v", err)
	}
}

// TestOpenStreamToSurfacesAFirstChunkReadFailure covers the first read and the default arm of
// readChunk, which is the arm that keeps a real I/O error distinct from a clean end of stream. A
// storage error part way through a restore must not read as "the stream ended here", because that
// is the difference between a failed restore and a silently short one.
func TestOpenStreamToSurfacesAFirstChunkReadFailure(t *testing.T) {
	var key [32]byte
	sentinel := errors.New("bucket read failed")
	sealed, err := SealStream(key, []byte("a value worth recovering"), make([]byte, spec.StreamNonceSize))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	src := io.MultiReader(bytes.NewReader(sealed), &failReader{remaining: 0, err: sentinel})
	var out bytes.Buffer
	err = OpenStreamTo(&out, key, src, nil, 0)
	if !errors.Is(err, sentinel) {
		t.Fatalf("a read failure was not surfaced as itself: %v", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("read first chunk")) {
		t.Fatalf("the error does not name which read failed: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("a failed open still wrote %d byte(s) of plaintext", out.Len())
	}
}

// TestOpenStreamToSurfacesALookAheadReadFailure covers the second and later reads, which are a
// separate branch with a separate message because the open path reads one chunk ahead to know
// which chunk is the last. The first chunk here is complete and readable, so only the look-ahead
// fails.
func TestOpenStreamToSurfacesALookAheadReadFailure(t *testing.T) {
	var key [32]byte
	sentinel := errors.New("bucket read failed")
	sealed, err := SealStream(key, make([]byte, spec.ChunkSize+64), make([]byte, spec.StreamNonceSize))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	firstChunkEnd := spec.StreamNonceSize + spec.ChunkSize + spec.TagSize
	src := io.MultiReader(bytes.NewReader(sealed[:firstChunkEnd]), &failReader{remaining: 0, err: sentinel})
	var out bytes.Buffer
	err = OpenStreamTo(&out, key, src, nil, 0)
	if !errors.Is(err, sentinel) {
		t.Fatalf("a look-ahead read failure was not surfaced as itself: %v", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("read chunk 1")) {
		t.Fatalf("the error does not name which chunk failed to read: %v", err)
	}
}

// TestOpenStreamToSurfacesADestinationFailure covers the write of a decrypted chunk. The plaintext
// has authenticated by this point, so the only thing left to go wrong is the destination, and a
// restore that cannot write must fail rather than report a recovery it did not perform.
func TestOpenStreamToSurfacesADestinationFailure(t *testing.T) {
	var key [32]byte
	sentinel := errors.New("disk full")
	sealed, err := SealStream(key, []byte("a value worth recovering"), make([]byte, spec.StreamNonceSize))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	err = OpenStreamTo(&failWriter{remaining: 0, err: sentinel}, key, bytes.NewReader(sealed), nil, 0)
	if !errors.Is(err, sentinel) {
		t.Fatalf("a destination failure during open was not surfaced: %v", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("write chunk 0")) {
		t.Fatalf("the error does not name which chunk failed to write: %v", err)
	}
}

// TestOpenStreamToRefusesALaterChunkShorterThanTheTag covers the same tag-length guard for a chunk
// that is not the first. It is a separate branch and a separate message, and it is reached only on
// a multi-chunk stream whose tail has been truncated.
func TestOpenStreamToRefusesALaterChunkShorterThanTheTag(t *testing.T) {
	var key [32]byte
	plaintext := make([]byte, spec.ChunkSize+64)
	sealed, err := SealStream(key, plaintext, make([]byte, spec.StreamNonceSize))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Keep the whole first chunk, and leave a final chunk too short to carry a tag.
	firstChunkEnd := spec.StreamNonceSize + spec.ChunkSize + spec.TagSize
	truncated := sealed[:firstChunkEnd+5]
	var out bytes.Buffer
	err = OpenStreamTo(&out, key, bytes.NewReader(truncated), nil, 0)
	if err == nil {
		t.Fatal("a stream whose final chunk is shorter than the tag opened")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("chunk 1 is 5 bytes, shorter than the 16-byte tag")) {
		t.Fatalf("the refusal does not name the short later chunk: %v", err)
	}
}

// TestSealNonSecretSegmentSurfacesASealFailure and the two below it cover the error paths that
// carry a segment id into the message. The segment id is what a recoverer greps for when one
// segment of a run is bad, so the wrapping matters as much as the failure.
func TestSealNonSecretSegmentSurfacesASealFailure(t *testing.T) {
	_, _, err := SealNonSecretSegment(make([]byte, 32), "dp-1", spec.AddrSingleNonSecret, 0, []byte("plaintext"), make([]byte, spec.StreamNonceSize-1))
	if err == nil {
		t.Fatal("a short payload nonce sealed a non-secret segment")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("seal segment ")) {
		t.Fatalf("the error does not name the segment it failed on: %v", err)
	}
}

func TestSealSecretsSegmentSurfacesASealFailure(t *testing.T) {
	p := SecretsSegmentParams{RecordID: make([]byte, 16), RecordSalt: make([]byte, 16), RunIDBytes: make([]byte, 16)}
	_, _, err := SealSecretsSegment(make([]byte, 32), "dp-1", p, []byte("plaintext"), make([]byte, spec.StreamNonceSize-1))
	if err == nil {
		t.Fatal("a short payload nonce sealed a secrets segment")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("seal secrets segment ")) {
		t.Fatalf("the error does not name the segment it failed on: %v", err)
	}
}

func TestOpenSecretsSegmentSurfacesAnOpenFailure(t *testing.T) {
	master := make([]byte, 32)
	p := SecretsSegmentParams{RecordID: make([]byte, 16), RecordSalt: make([]byte, 16), RunIDBytes: make([]byte, 16)}
	segID, sealed, err := SealSecretsSegment(master, "dp-1", p, []byte("a secret value"), make([]byte, spec.StreamNonceSize))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Flip a byte inside the sealed body, past the container frame, so the frame still parses
	// and the failure is the authentication rather than the framing.
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0xff
	_, err = OpenSecretsSegment(master, segID, p, tampered)
	if err == nil {
		t.Fatal("a tampered secrets segment opened")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("open secrets segment ")) {
		t.Fatalf("the error does not name the segment it failed on: %v", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("authentication failed")) {
		t.Fatalf("the error does not name authentication as what failed: %v", err)
	}
}
