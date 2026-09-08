package crypto

import (
	"bytes"
	"testing"

	"github.com/downpipes-io/downpipe/internal/spec"
)

func TestNonSecretSegmentRoundTripAndDedup(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x01}, spec.StreamNonceSize)
	pt := []byte("a kv value worth backing up")

	id, sealed, err := SealNonSecretSegment(master, "dp", spec.AddrSingleNonSecret, spec.CodecNone, pt, nonce)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenNonSecretSegment(master, id, spec.CodecNone, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("round-trip mismatch")
	}

	// Same content under the same downpipe addresses to the same segment (dedup).
	id2, _, err := SealNonSecretSegment(master, "dp", spec.AddrSingleNonSecret, spec.CodecNone, pt, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if id != id2 {
		t.Fatal("identical content must deduplicate to the same segment id")
	}
	// Different content addresses differently.
	id3, _, err := SealNonSecretSegment(master, "dp", spec.AddrSingleNonSecret, spec.CodecNone, []byte("different"), nonce)
	if err != nil {
		t.Fatal(err)
	}
	if id == id3 {
		t.Fatal("different content must address differently")
	}
}

func TestSecretsSegmentRoundTripAndUnique(t *testing.T) {
	master := bytes.Repeat([]byte{0x24}, 32)
	nonce := bytes.Repeat([]byte{0x02}, spec.StreamNonceSize)
	rec := []byte("recordid00000001")
	run := bytes.Repeat([]byte{0x09}, 16)
	val := []byte("an api token")

	salt1 := bytes.Repeat([]byte{0x01}, 16)
	id1, sealed, err := SealSecretsSegment(master, "dp", SecretsSegmentParams{RecordID: rec, RecordSalt: salt1, RunIDBytes: run}, val, nonce)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenSecretsSegment(master, id1, SecretsSegmentParams{RecordID: rec, RecordSalt: salt1, RunIDBytes: run}, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, val) {
		t.Fatal("secrets round-trip mismatch")
	}

	salt2 := bytes.Repeat([]byte{0x02}, 16)
	id2, _, err := SealSecretsSegment(master, "dp", SecretsSegmentParams{RecordID: rec, RecordSalt: salt2, RunIDBytes: run}, val, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if id1 == id2 {
		t.Fatal("identical secret values with different salts must not collide")
	}
}

func TestSegmentRejectsTamperAndWrongCodec(t *testing.T) {
	master := bytes.Repeat([]byte{0x55}, 32)
	nonce := bytes.Repeat([]byte{0x03}, spec.StreamNonceSize)
	id, sealed, err := SealNonSecretSegment(master, "dp", spec.AddrSingleNonSecret, spec.CodecNone, []byte("payload"), nonce)
	if err != nil {
		t.Fatal(err)
	}

	bad := bytes.Clone(sealed)
	bad[len(bad)-1] ^= 0x01
	if _, err := OpenNonSecretSegment(master, id, spec.CodecNone, bad); err == nil {
		t.Fatal("a tampered segment must fail authentication")
	}
	// The codec id is bound into the file key, so opening under the wrong codec fails.
	if _, err := OpenNonSecretSegment(master, id, spec.CodecGzip, sealed); err == nil {
		t.Fatal("the wrong codec id must fail to open (file key binds the codec)")
	}
}
