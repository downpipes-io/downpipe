//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestReadArtefactRefusesAFileThatIsNotRegular covers the custody size cap on a path whose
// stat size is not its length. A FIFO (like /dev/zero) stats at size 0, so a size check on
// the path alone passes it, and a plain read then buffers everything the writer sends. The
// artefact must be refused, not read, and a regular file under the cap must still be read.
func TestReadArtefactRefusesAFileThatIsNotRegular(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "share.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot make a FIFO here: %v", err)
	}
	// The writer offers three times the cap. It stops at the first write error, which is
	// what it sees once the reader closes its end.
	sent := make(chan int, 1)
	go func() {
		w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			sent <- 0
			return
		}
		defer func() { _ = w.Close() }()
		chunk := []byte(strings.Repeat("A", 64<<10))
		total := 0
		for total < 3*maxArtefactBytes {
			n, err := w.Write(chunk)
			total += n
			if err != nil {
				break
			}
		}
		sent <- total
	}()

	text, err := readArtefact(fifo)
	if err == nil {
		t.Errorf("a FIFO was read as a custody artefact (%d bytes), want a refusal", len(text))
	}
	if len(text) > maxArtefactBytes {
		t.Errorf("read %d bytes, more than the %d-byte cap", len(text), maxArtefactBytes)
	}
	<-sent

	// Control: a regular artefact under the cap is still read.
	regular := filepath.Join(dir, "share-1.txt")
	if err := os.WriteFile(regular, []byte("downpipe-shamir-share-v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readArtefact(regular); err != nil || got != "downpipe-shamir-share-v1\n" {
		t.Fatalf("a regular artefact under the cap must be read, got %q, %v", got, err)
	}
}
