package crypto

import (
	"fmt"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// SealNonSecretSegment addresses and seals a non-secret segment plaintext (the stored
// bytes, after any compression). class is the address class for the segment: pass
// spec.AddrSingleNonSecret for a single record or spec.AddrPacked for several packed
// records. It returns the 48-byte keyed segment id and the sealed STREAM bytes. The
// address and the file key are both content-only, so identical content under one
// downpipe yields the same id and key across runs and deduplicates (SPEC.md 7.2, 7.3,
// 7.4). payloadNonce is random in production and pinned for writer-authoritative
// vectors.
func SealNonSecretSegment(master []byte, downpipeID string, class byte, codecID byte, plaintext, payloadNonce []byte) ([48]byte, []byte, error) {
	if class != spec.AddrSingleNonSecret && class != spec.AddrPacked {
		return [48]byte{}, nil, fmt.Errorf("non-secret segment class must be single or packed, got 0x%02x", class)
	}
	segID := SegID(DeriveCAK(master, downpipeID), class, nil, plaintext)
	body, err := SealStream(DeriveNonSecretFileKey(master, segID, codecID), plaintext, payloadNonce)
	if err != nil {
		return [48]byte{}, nil, fmt.Errorf("seal segment %s: %w", SegIDHex(segID), err)
	}
	return segID, spec.FrameContainer(spec.MagicSeg, body), nil
}

// OpenNonSecretSegment re-derives the file key from the master and the manifest's
// segment id and opens the sealed bytes. The reader trusts the signed segment id, not
// a re-hash of the recovered plaintext; the per-record plaintext hash check at the
// format layer catches a content mismatch (SPEC.md 7.4, 8.4).
func OpenNonSecretSegment(master []byte, segID [48]byte, codecID byte, sealed []byte) ([]byte, error) {
	body, err := spec.UnframeContainer(spec.MagicSeg, sealed)
	if err != nil {
		return nil, fmt.Errorf("open segment %s: %w", SegIDHex(segID), err)
	}
	pt, err := OpenStream(DeriveNonSecretFileKey(master, segID, codecID), body)
	if err != nil {
		return nil, fmt.Errorf("open segment %s: %w", SegIDHex(segID), err)
	}
	return pt, nil
}

// SecretsSegmentParams carries the per-record identity inputs to the secrets file-key
// derivation. RecordID, RecordSalt and RunIDBytes are all []byte, so grouping them in a
// named struct makes each field unambiguous at the call site and avoids a silent
// key-derivation error from a positional swap. RecordID is the 16-byte ASCII record id;
// RecordSalt and RunIDBytes are 16 bytes each.
type SecretsSegmentParams struct {
	RecordID   []byte
	RecordSalt []byte
	RunIDBytes []byte
}

// SealSecretsSegment addresses and seals a secrets record's value (class 0x03). The
// per-record salt makes the address unique even for identical values, so secrets
// never deduplicate, and the file key binds the run, record and salt (SPEC.md 7.2,
// 7.4).
func SealSecretsSegment(master []byte, downpipeID string, p SecretsSegmentParams, plaintext, payloadNonce []byte) ([48]byte, []byte, error) {
	segID := SegID(DeriveCAK(master, downpipeID), spec.AddrSecrets, p.RecordSalt, plaintext)
	body, err := SealStream(DeriveSecretsFileKey(master, segID, p.RecordID, p.RecordSalt, p.RunIDBytes), plaintext, payloadNonce)
	if err != nil {
		return [48]byte{}, nil, fmt.Errorf("seal secrets segment %s: %w", SegIDHex(segID), err)
	}
	return segID, spec.FrameContainer(spec.MagicSeg, body), nil
}

// OpenSecretsSegment re-derives the secrets file key from the master and the manifest
// fields and opens the sealed bytes.
func OpenSecretsSegment(master []byte, segID [48]byte, p SecretsSegmentParams, sealed []byte) ([]byte, error) {
	body, err := spec.UnframeContainer(spec.MagicSeg, sealed)
	if err != nil {
		return nil, fmt.Errorf("open secrets segment %s: %w", SegIDHex(segID), err)
	}
	pt, err := OpenStream(DeriveSecretsFileKey(master, segID, p.RecordID, p.RecordSalt, p.RunIDBytes), body)
	if err != nil {
		return nil, fmt.Errorf("open secrets segment %s: %w", SegIDHex(segID), err)
	}
	return pt, nil
}
