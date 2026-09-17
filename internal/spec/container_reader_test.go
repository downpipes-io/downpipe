package spec

import (
	"bytes"
	"io"
	"testing"
)

// The reader form must apply the identical checks with the identical wording as the
// byte-slice form, so the streamed segment path cannot drift from the buffered one.
func TestUnframeContainerReaderParity(t *testing.T) {
	payload := []byte("sealed stream bytes")
	framed := FrameContainer(MagicSeg, payload)

	cases := []struct {
		name  string
		input []byte
	}{
		{"valid", framed},
		{"short", framed[:3]},
		{"empty", nil},
		{"bad magic", append([]byte{'X', 'X', 'X', 'X', ContainerVersion}, payload...)},
		{"wrong magic kind", FrameContainer(MagicDpe, payload)},
		{"bad version", append([]byte{MagicSeg[0], MagicSeg[1], MagicSeg[2], MagicSeg[3], 0x7f}, payload...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantBody, wantErr := UnframeContainer(MagicSeg, tc.input)
			gotReader, gotErr := UnframeContainerReader(MagicSeg, bytes.NewReader(tc.input))
			if (wantErr == nil) != (gotErr == nil) {
				t.Fatalf("error parity broken: slice=%v reader=%v", wantErr, gotErr)
			}
			if wantErr != nil {
				if wantErr.Error() != gotErr.Error() {
					t.Fatalf("error wording differs:\n slice:  %v\n reader: %v", wantErr, gotErr)
				}
				return
			}
			gotBody, err := io.ReadAll(gotReader)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotBody, wantBody) {
				t.Fatalf("payload differs: %d vs %d bytes", len(gotBody), len(wantBody))
			}
		})
	}
}
