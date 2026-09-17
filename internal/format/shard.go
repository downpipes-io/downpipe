package format

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// SealShard serialises the preamble and the records as newline-delimited canonical
// JSON (the preamble first, each kind-tagged) and seals the result under the per-shard
// manifest-wrap key with the STREAM (SPEC.md 6). It returns the sealed bytes to store
// and their SHA-384, which the root manifest binds and the signature covers. wrapKey
// is 32 bytes (the output of crypto.DeriveManifestWrapKey).
func SealShard(preamble spec.ShardPreamble, records []spec.ShardRecord, wrapKey, nonce []byte) (sealed []byte, sha384hex string, err error) {
	preamble.Kind = "preamble"
	preamble.RecordCountInShard = int64(len(records))
	var plain bytes.Buffer
	pre, err := CanonicalJSON(preamble)
	if err != nil {
		return nil, "", fmt.Errorf("canonicalise shard preamble: %w", err)
	}
	plain.Write(pre)
	plain.WriteByte('\n')
	for _, r := range records {
		r.Kind = "record"
		line, err := CanonicalJSON(r)
		if err != nil {
			return nil, "", fmt.Errorf("canonicalise record %s: %w", r.RecordID, err)
		}
		plain.Write(line)
		plain.WriteByte('\n')
	}
	body, err := crypto.SealStream(toKey(wrapKey), plain.Bytes(), nonce)
	if err != nil {
		return nil, "", fmt.Errorf("seal shard: %w", err)
	}
	sealed = spec.FrameContainer(spec.MagicDpe, body)
	return sealed, SHA384Hex(sealed), nil
}

// OpenShard opens a sealed shard manifest under the wrap key and parses its preamble
// and records, checking the kind discriminators and the declared record count. In
// verified mode the caller first confirms the sealed bytes' SHA-384 against the signed
// value in the root manifest (SPEC.md 8.3). A shard manifest holds metadata only and
// is bounded, so it is opened whole.
func OpenShard(sealed, wrapKey []byte) (spec.ShardPreamble, []spec.ShardRecord, error) {
	body, err := spec.UnframeContainer(spec.MagicDpe, sealed)
	if err != nil {
		return spec.ShardPreamble{}, nil, fmt.Errorf("open shard: %w", err)
	}
	plain, err := crypto.OpenStream(toKey(wrapKey), body)
	if err != nil {
		return spec.ShardPreamble{}, nil, fmt.Errorf("open shard: %w", err)
	}
	var lines [][]byte
	for _, l := range bytes.Split(plain, []byte{'\n'}) {
		if len(l) > 0 {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		return spec.ShardPreamble{}, nil, fmt.Errorf("shard manifest is empty")
	}
	if err := validateCounts(lines[0], "recordCountInShard"); err != nil {
		return spec.ShardPreamble{}, nil, err
	}
	var preamble spec.ShardPreamble
	if err := json.Unmarshal(lines[0], &preamble); err != nil {
		return spec.ShardPreamble{}, nil, fmt.Errorf("parse shard preamble: %w", err)
	}
	if preamble.Kind != "preamble" {
		return spec.ShardPreamble{}, nil, fmt.Errorf("first shard line is not a preamble (kind %q)", preamble.Kind)
	}
	records := make([]spec.ShardRecord, 0, len(lines)-1)
	for _, line := range lines[1:] {
		if err := validateCounts(line, "plaintextSize"); err != nil {
			return spec.ShardPreamble{}, nil, err
		}
		var r spec.ShardRecord
		if err := json.Unmarshal(line, &r); err != nil {
			return spec.ShardPreamble{}, nil, fmt.Errorf("parse shard record: %w", err)
		}
		if r.Kind != "record" {
			return spec.ShardPreamble{}, nil, fmt.Errorf("shard line is not a record (kind %q)", r.Kind)
		}
		records = append(records, r)
	}
	if preamble.RecordCountInShard != int64(len(records)) {
		return spec.ShardPreamble{}, nil, fmt.Errorf("shard declares %d records but carries %d", preamble.RecordCountInShard, len(records))
	}
	return preamble, records, nil
}

func toKey(b []byte) [32]byte {
	var k [32]byte
	copy(k[:], b)
	return k
}
