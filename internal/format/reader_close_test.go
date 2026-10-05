package format

import (
	"bytes"
	"testing"
)

// The reader holds a run master for its whole lifetime, because openSegment derives a per-segment file key
// from it on every record restored. That makes ending it the caller's job, and Close is what they call.
//
// WHY THIS IS TESTED AT ALL. crypto.OpenCapsule is already careful: it zeroises the KEM shared secret, the
// wrap key and its own copy of the recovered master the moment recovery completes. The master it RETURNS
// then lived in this struct for the whole process with nothing to end it, on the binary a customer runs on
// their own machine with their break-glass key. A wipe nobody asserts is a wipe that quietly stops
// happening.

func TestCloseWipesTheRunMaster(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i + 1) // no zero bytes, so an unwiped buffer cannot pass by accident
	}
	r := &Reader{master: master}

	if bytes.Equal(master, make([]byte, 32)) {
		t.Fatal("the fixture started zeroed, so this test could not tell a wipe from no wipe")
	}

	r.Close()

	if !bytes.Equal(master, make([]byte, 32)) {
		t.Fatalf("Close must wipe the run master, got %x", master)
	}
}

// The caller's buffer is wiped, not a copy of it. `master []byte` is a slice, so the reader and the caller
// share one backing array; if that ever became an array or a copy, Close would wipe something nobody else
// can see and the real secret would survive.
func TestCloseWipesTheCallersBackingArray(t *testing.T) {
	backing := []byte{9, 9, 9, 9, 9, 9, 9, 9}
	r := &Reader{master: backing}
	r.Close()
	for i, b := range backing {
		if b != 0 {
			t.Fatalf("the caller's backing array must be wiped, byte %d is %d", i, b)
		}
	}
}

// Callers use defer, and a command can fail before it ever opens a run, so Close must be safe on a
// zero-value reader and on one that has already been closed.
func TestCloseIsSafeOnZeroValueAndRepeated(t *testing.T) {
	var zero Reader
	zero.Close() // must not panic on a nil master

	r := &Reader{master: []byte{1, 2, 3}}
	r.Close()
	r.Close() // idempotent
	if !bytes.Equal(r.master, []byte{0, 0, 0}) {
		t.Fatalf("repeated Close must leave the master wiped, got %v", r.master)
	}
}
