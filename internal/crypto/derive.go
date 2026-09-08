package crypto

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// The hash and KDF layer is SHA-384 throughout for CNSA 2.0 alignment: HKDF-SHA-384
// for key derivation, HMAC-SHA-384 for the keyed address, name MAC and key
// commitment, and SHA-384 for content, segment, shard, Merkle and recipient hashes.
// Derived symmetric keys are 32 bytes (256-bit, the AES-256-GCM key size); hashes
// and MAC-as-hash outputs are 48 bytes (SHA-384).

// hkdfKey runs HKDF-SHA-384 and returns n bytes of output key material. It panics
// only on the unreachable case where n exceeds the HKDF-Expand ceiling; every
// caller requests spec.FileKeySize bytes.
func hkdfKey(ikm, salt, info []byte, n int) []byte {
	out := make([]byte, n)
	if _, err := io.ReadFull(hkdf.New(sha512.New384, ikm, salt, info), out); err != nil {
		panic("downpipe/crypto: hkdf expand failed for a fixed small length: " + err.Error())
	}
	return out
}

// lpAppend appends a single-byte length prefix and the field bytes, the canonical
// length-prefixed concatenation of SPEC.md 7.4. It panics only on the unreachable
// case of a field longer than 255 bytes; every field here is a fixed small size.
func lpAppend(dst, field []byte) []byte {
	if len(field) > 255 {
		panic("downpipe/crypto: length-prefixed field exceeds 255 bytes")
	}
	return append(append(dst, byte(len(field))), field...)
}

// DeriveCAK derives the per-downpipe content-addressing key from the run master
// (SPEC.md 7.2 and 11.7). The downpipe identity is the HKDF salt, so the address
// space is stable for one downpipe and distinct across downpipes.
func DeriveCAK(master []byte, downpipeID string) []byte {
	return hkdfKey(master, []byte(downpipeID), []byte(spec.InfoContentAddress), spec.FileKeySize)
}

// SegID computes the keyed content address of a segment as HMAC-SHA-384 (SPEC.md
// 7.2). class is one of spec.AddrSingleNonSecret, spec.AddrPacked or
// spec.AddrSecrets. recordSalt is the 16-byte per-record salt and is mixed in only
// for the secrets class; pass nil for the non-secret classes. The result is the 48
// raw HMAC bytes; SegIDHex renders the lowercase-hex object-name form.
func SegID(cak []byte, class byte, recordSalt, segmentPlaintext []byte) [48]byte {
	mac := hmac.New(sha512.New384, cak)
	mac.Write([]byte{class})
	if class == spec.AddrSecrets {
		mac.Write(recordSalt)
	}
	mac.Write(segmentPlaintext)
	var id [48]byte
	mac.Sum(id[:0])
	return id
}

// SegIDHex renders a segment address as bare lowercase hex (SPEC.md 11.8), the
// form used in the seg/ object path.
func SegIDHex(id [48]byte) string { return hex.EncodeToString(id[:]) }

// DeriveNonSecretFileKey derives the 32-byte (AES-256) file key for a non-secret
// segment from the master and the content-only context (SPEC.md 7.4). No run,
// record or salt identity enters the key, so the same content under one downpipe
// derives the same file key across runs, which is what makes intra-downpipe dedup
// openable by any referencing run (SPEC.md 7.3).
func DeriveNonSecretFileKey(master []byte, segID [48]byte, codecID byte) [32]byte {
	info := append([]byte(spec.InfoSegKey), 0x00)
	info = append(info, nonSecretContext(segID, codecID)...)
	return first32(hkdfKey(master, nil, info, spec.FileKeySize))
}

// DeriveSecretsFileKey derives the 32-byte (AES-256) file key for a secrets segment
// from the master, with the run, record and salt identity bound in (SPEC.md 7.4).
// Secrets segments are never shared, so this binding is safe and adds defence in
// depth. runIDBytes is the 16-byte decoded ULID; recordID is the 16-byte ASCII
// record id; recordSalt is the 16-byte per-record salt.
func DeriveSecretsFileKey(master []byte, segID [48]byte, recordID, recordSalt, runIDBytes []byte) [32]byte {
	// Self-guard the crypto layer rather than relying on every caller's pre-validation:
	// recordID and recordSalt are each a fixed 16 bytes, so they can never overflow the
	// single-byte length prefix in lpAppend. An over-length value is a programming
	// error, so fail fast with a legible message.
	if len(recordID) != 16 || len(recordSalt) != 16 {
		panic("downpipe/crypto: DeriveSecretsFileKey requires 16-byte recordID and recordSalt")
	}
	info := append([]byte(spec.InfoSegKey), 0x00)
	info = append(info, secretsContext(segID, recordID, recordSalt)...)
	return first32(hkdfKey(master, runIDBytes, info, spec.FileKeySize))
}

func nonSecretContext(segID [48]byte, codecID byte) []byte {
	var ctx []byte
	ctx = lpAppend(ctx, segID[:])
	ctx = lpAppend(ctx, []byte{codecID})
	ctx = lpAppend(ctx, chunkSizeBytes())
	return ctx
}

func secretsContext(segID [48]byte, recordID, recordSalt []byte) []byte {
	var ctx []byte
	ctx = lpAppend(ctx, segID[:])
	ctx = lpAppend(ctx, recordID)
	ctx = lpAppend(ctx, recordSalt)
	ctx = lpAppend(ctx, []byte{spec.CodecNone})
	ctx = lpAppend(ctx, chunkSizeBytes())
	return ctx
}

func chunkSizeBytes() []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], spec.ChunkSize)
	return b[:]
}

// DeriveMK derives the per-run manifest subkey from the master (SPEC.md 11.7).
func DeriveMK(master, runIDBytes []byte) []byte {
	return hkdfKey(master, runIDBytes, []byte(spec.InfoManifestKey), spec.FileKeySize)
}

// DeriveNameMACKey derives the keyed-name MAC key from the manifest subkey (SPEC.md
// 6.4 and 11.7).
func DeriveNameMACKey(mk, runIDBytes []byte) []byte {
	return hkdfKey(mk, runIDBytes, []byte(spec.InfoNameMAC), spec.FileKeySize)
}

// NameMAC computes the keyed name MAC of a record's source name (SPEC.md 6.4):
// HMAC-SHA-384 over the source type, a 0x00 separator and the UTF-8 name, keyed by
// the name-MAC key. The 48-byte result is rendered lowercase hex in the manifest, so
// a bucket-read adversary cannot dictionary-confirm a guessed name.
func NameMAC(nameMACKey []byte, sourceType, name string) []byte {
	mac := hmac.New(sha512.New384, nameMACKey)
	mac.Write([]byte(sourceType))
	mac.Write([]byte{0x00})
	mac.Write([]byte(name))
	return mac.Sum(nil)
}

// DeriveManifestWrapKey derives the per-shard manifest-wrap key from the manifest
// subkey (SPEC.md 6.3 and 11.7). The shard id is appended to the info string after
// a 0x00 separator.
func DeriveManifestWrapKey(mk, runIDBytes []byte, shardID string) []byte {
	info := append([]byte(spec.InfoManifestWrap), 0x00)
	info = append(info, []byte(shardID)...)
	return hkdfKey(mk, runIDBytes, info, spec.FileKeySize)
}

// KeyCommitment is the run key commitment that binds the master to the run (SPEC.md
// 8.4 and 11.7): HMAC-SHA-384 keyed by the master over the label and the runId. The
// result is 48 bytes.
func KeyCommitment(master, runIDBytes []byte) []byte {
	mac := hmac.New(sha512.New384, master)
	mac.Write([]byte(spec.InfoKeyCommit))
	mac.Write(runIDBytes)
	return mac.Sum(nil)
}

func first32(b []byte) [32]byte {
	var k [32]byte
	copy(k[:], b)
	return k
}
