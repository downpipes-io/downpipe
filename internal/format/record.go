package format

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// recordIDDigits is the number of zero-padded decimal digits that follow the leading
// "r" in a recordId (SPEC.md 6.3). With the "r" prefix the field is exactly 16 ASCII
// bytes, which is what the record hash (6.5) and the secrets HKDF context (7.4) bind.
const recordIDDigits = 15

// ValidateRecordID checks that id has the documented recordId shape (SPEC.md 6.3): the
// ASCII letter "r" followed by exactly 15 zero-padded decimal digits, for example
// "r000000000000042". The form is fixed at 16 ASCII bytes, which is what the record
// hash (6.5) and, for a secrets record, the segment address and file-key derivation
// (7.2 case 0x03, 7.4) bind as 16 raw bytes; a malformed recordId is therefore a
// structural format violation, not merely a cosmetic one.
//
// On vanished-mid-crawl records, section 6.3 is normative: such a record is NOT emitted
// as a record line and carries no "vanished" field, so spec.ShardRecord has no Vanished
// field. Section 12.5 was revised to match section 6.3. This function only
// enforces the 6.3 recordId shape.
func ValidateRecordID(id string) error {
	if len(id) != recordIDDigits+1 {
		return fmt.Errorf("recordId %q must be %d ASCII bytes (r plus %d digits), got %d", id, recordIDDigits+1, recordIDDigits, len(id))
	}
	if id[0] != 'r' {
		return fmt.Errorf("recordId %q must begin with the letter r", id)
	}
	for i := 1; i < len(id); i++ {
		if id[i] < '0' || id[i] > '9' {
			return fmt.Errorf("recordId %q must be r followed by %d decimal digits", id, recordIDDigits)
		}
	}
	return nil
}

// RecordHashOf computes a record's Merkle-leaf hash from its signed fields (SPEC.md
// 6.5): SHA-384 over the domain label, the 16-byte record id, the raw plaintext
// SHA-384, the raw keyed name MAC, and the plaintext size as a big-endian uint64.
// Binding these is what makes the signed Merkle root cover each record's value and
// name; the reader recomputes it and compares to the manifest's value.
func RecordHashOf(rec spec.ShardRecord) ([]byte, error) {
	psha, err := hex.DecodeString(rec.PlaintextSHA)
	if err != nil {
		return nil, fmt.Errorf("record %s plaintextSha384: %w", rec.RecordID, err)
	}
	knh, err := hex.DecodeString(rec.KeyNameHash)
	if err != nil {
		return nil, fmt.Errorf("record %s keyNameHash: %w", rec.RecordID, err)
	}
	h := sha512.New384()
	h.Write([]byte(spec.Version + " record-hash"))
	h.Write([]byte(rec.RecordID))
	h.Write(psha)
	h.Write(knh)
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(rec.PlaintextSize))
	h.Write(size[:])
	return h.Sum(nil), nil
}
