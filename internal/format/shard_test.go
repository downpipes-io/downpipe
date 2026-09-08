package format

import (
	"bytes"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

func TestSealOpenShard(t *testing.T) {
	master := bytes.Repeat([]byte{0x33}, 32)
	runID := bytes.Repeat([]byte{0x09}, 16)
	wrapKey := crypto.DeriveManifestWrapKey(crypto.DeriveMK(master, runID), runID, "00000")
	nonce := bytes.Repeat([]byte{0x01}, spec.StreamNonceSize)

	records := []spec.ShardRecord{
		{
			SourceType: "kv", Name: "user:1", RecordID: "r000000000000001",
			PlaintextSize: 10, PlaintextSHA: "aa", RecordHash: "bb",
			Segments: []spec.Segment{{Object: "seg/ab/abcd.seg", ChunkRange: [2]int{0, 1}}},
		},
		{
			SourceType: "kv", Name: "user:2", RecordID: "r000000000000002",
			PlaintextSize: 20, PlaintextSHA: "cc", RecordHash: "dd",
			Segments: []spec.Segment{{Object: "seg/ef/ef01.seg", ChunkRange: [2]int{0, 1}}},
		},
	}

	preamble := spec.ShardPreamble{
		FormatVersion: spec.Version, RunID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ShardID: "00000",
		ManifestCodec: spec.CodecNameNone,
		Downpipe:      spec.PreambleDownpipe{Name: "t", Cadence: "0 * * * *"},
		Source:        spec.Source{Type: "kv"},
	}
	sealed, sha, err := SealShard(preamble, records, wrapKey, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if sha != SHA384Hex(sealed) {
		t.Fatal("the returned hash must match the sealed bytes")
	}

	pre, got, err := OpenShard(sealed, wrapKey)
	if err != nil {
		t.Fatal(err)
	}
	if pre.Kind != "preamble" || pre.ShardID != "00000" || pre.RecordCountInShard != 2 {
		t.Fatalf("preamble did not round-trip: %+v", pre)
	}
	if len(got) != 2 || got[0].Name != "user:1" || got[1].RecordID != "r000000000000002" {
		t.Fatalf("shard records did not round-trip: %+v", got)
	}

	wrongKey := crypto.DeriveManifestWrapKey(crypto.DeriveMK(master, runID), runID, "99999")
	if _, _, err := OpenShard(sealed, wrongKey); err == nil {
		t.Fatal("the wrong wrap key must fail authentication")
	}
}

func TestBase64URLRoundTrip(t *testing.T) {
	in := []byte{0x00, 0xff, 0x10, 0x3f, 0xab}
	out, err := B64Decode(B64Encode(in))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(in, out) {
		t.Fatal("base64url did not round-trip")
	}
}
