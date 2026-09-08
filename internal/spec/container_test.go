package spec

import (
	"bytes"
	"testing"
)

// TestFrameUnframeRoundTrip locks in the container framing contract (SPEC.md 7.1, 11.9):
// FrameContainer prepends the 4-byte magic and the 1-byte version, and UnframeContainer
// strips exactly that header and returns the original payload byte-for-byte. The framing
// is not bound into the AEAD, so it must be a plain, reversible wrapper.
func TestFrameUnframeRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		magic   [4]byte
		payload []byte
	}{
		{"seg empty payload", MagicSeg, nil},
		{"seg short payload", MagicSeg, []byte{0x01, 0x02, 0x03}},
		{"dpe short payload", MagicDpe, []byte("an encrypted shard manifest")},
		{"dpe large payload", MagicDpe, bytes.Repeat([]byte{0xab}, 4096)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			framed := FrameContainer(c.magic, c.payload)
			// The framed object is exactly the header plus the payload.
			if len(framed) != ContainerHeaderSize+len(c.payload) {
				t.Fatalf("framed length = %d, want %d", len(framed), ContainerHeaderSize+len(c.payload))
			}
			// The header is the magic followed by the single version byte.
			wantHeader := []byte{c.magic[0], c.magic[1], c.magic[2], c.magic[3], ContainerVersion}
			if !bytes.Equal(framed[:ContainerHeaderSize], wantHeader) {
				t.Fatalf("framed header = %x, want %x", framed[:ContainerHeaderSize], wantHeader)
			}
			got, err := UnframeContainer(c.magic, framed)
			if err != nil {
				t.Fatalf("UnframeContainer: %v", err)
			}
			// An empty payload round-trips to an empty (possibly nil) slice; compare by length
			// and bytes so nil and len-0 are both accepted.
			if len(got) != len(c.payload) || !bytes.Equal(got, c.payload) {
				t.Fatalf("round-trip payload = %x, want %x", got, c.payload)
			}
		})
	}
}

// TestUnframeContainerRejectsShort confirms a buffer shorter than the fixed header is
// rejected rather than slicing out of bounds (SPEC.md 11.9). Every length below the header
// size must error.
func TestUnframeContainerRejectsShort(t *testing.T) {
	for n := 0; n < ContainerHeaderSize; n++ {
		if _, err := UnframeContainer(MagicSeg, make([]byte, n)); err == nil {
			t.Errorf("UnframeContainer(%d-byte buffer) = nil error, want a short-input rejection", n)
		}
	}
}

// TestUnframeContainerRejectsBadMagic confirms a header whose magic does not match the
// expected container type is rejected. A .seg framed object must not unframe as a .dpe and
// vice versa, so a mislabelled object is caught before any crypto step.
func TestUnframeContainerRejectsBadMagic(t *testing.T) {
	// Frame as a seg, then try to unframe expecting a dpe magic: the magic mismatch must error.
	framedSeg := FrameContainer(MagicSeg, []byte("payload"))
	if _, err := UnframeContainer(MagicDpe, framedSeg); err == nil {
		t.Error("UnframeContainer with the wrong magic = nil error, want a bad-magic rejection")
	}
	// An arbitrary wrong magic with an otherwise valid version and length also errors.
	bad := []byte{0x00, 0x00, 0x00, 0x00, ContainerVersion, 0x01, 0x02}
	if _, err := UnframeContainer(MagicSeg, bad); err == nil {
		t.Error("UnframeContainer with a zeroed magic = nil error, want a bad-magic rejection")
	}
}

// TestUnframeContainerRejectsBadVersion confirms an unsupported container version byte is
// rejected even when the magic and length are valid (SPEC.md 11.9): a future version must
// not be silently parsed by a current reader.
func TestUnframeContainerRejectsBadVersion(t *testing.T) {
	framed := FrameContainer(MagicSeg, []byte("payload"))
	// Corrupt the version byte (index 4) to a value other than ContainerVersion.
	corrupt := make([]byte, len(framed))
	copy(corrupt, framed)
	corrupt[4] = ContainerVersion + 1
	if _, err := UnframeContainer(MagicSeg, corrupt); err == nil {
		t.Error("UnframeContainer with an unsupported version = nil error, want a rejection")
	}
	// Version 0x00 is also unsupported.
	corrupt[4] = 0x00
	if _, err := UnframeContainer(MagicSeg, corrupt); err == nil {
		t.Error("UnframeContainer with version 0x00 = nil error, want a rejection")
	}
}

// TestContainerHeaderConstants pins the framing constants to their frozen values
// (SPEC.md 7.1): the magics are the documented ASCII tags, the version is 0x01, and the
// header size is the magic plus the version. A change here is a new format version, a MINOR
// bump while the format major is 0 (SPEC.md 13), so this
// test guards against an accidental edit. The assertions compare the real package
// constants against their required values; they cannot pass trivially.
func TestContainerHeaderConstants(t *testing.T) {
	if ContainerHeaderSize != 5 {
		t.Errorf("ContainerHeaderSize = %d, want 5 (4-byte magic + 1-byte version)", ContainerHeaderSize)
	}
	if ContainerVersion != 0x01 {
		t.Errorf("ContainerVersion = 0x%02x, want 0x01", ContainerVersion)
	}
	// MagicSeg is ASCII "DPS1"; MagicDpe is ASCII "DPE1".
	if !bytes.Equal(MagicSeg[:], []byte("DPS1")) {
		t.Errorf("MagicSeg = %x, want ASCII DPS1", MagicSeg)
	}
	if !bytes.Equal(MagicDpe[:], []byte("DPE1")) {
		t.Errorf("MagicDpe = %x, want ASCII DPE1", MagicDpe)
	}
}
