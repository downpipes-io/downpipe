package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestUnsealExportConformance is the CROSS-IMPL agreement gate: the fixture in testdata/sealed-export was
// produced by the ENGINE (TypeScript, src/admin/control-plane-seal.ts) sealing a known inner export to the
// break-glass identity and signing the canonical bytes. This test opens that exact fixture with the Go reader
// and asserts the recovered inner is BYTE-IDENTICAL to what the engine sealed. If the two implementations ever
// disagree (an AAD drift, a JSON-shape drift, a b64 or nonce mismatch), this fails -- which is what keeps a
// sealing change from silently bricking recovery. Regenerate the fixture with:
//
//	(in the engine) node scripts/gen-sealed-export-fixture.mjs <this>/testdata/sealed-export
func TestUnsealExportConformance(t *testing.T) {
	dir := "testdata/sealed-export"
	out := filepath.Join(t.TempDir(), "recovered.json")
	if err := cmdUnsealExport([]string{
		"--in", filepath.Join(dir, "sealed.json"),
		"--sig", filepath.Join(dir, "sealed.json.sig"),
		"--identity", filepath.Join(dir, "identity.key"),
		"--signer", filepath.Join(dir, "signer.pub"),
		"--out", out,
	}); err != nil {
		t.Fatalf("unseal-export on the engine fixture failed: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading the recovered export: %v", err)
	}
	want, err := os.ReadFile(filepath.Join(dir, "expected-inner.json"))
	if err != nil {
		t.Fatalf("reading the expected inner: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the Go reader recovered a DIFFERENT inner export than the engine sealed (cross-impl drift): got %d bytes, want %d bytes", len(got), len(want))
	}
}

// TestUnsealExportRejectsTampered proves the verify-precedes-decrypt gate: a single flipped byte in the sealed
// artefact fails the signature and is refused before any decryption is attempted.
func TestUnsealExportRejectsTampered(t *testing.T) {
	dir := "testdata/sealed-export"
	sealed, err := os.ReadFile(filepath.Join(dir, "sealed.json"))
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	tampered := make([]byte, len(sealed))
	copy(tampered, sealed)
	tampered[len(tampered)/2] ^= 0xff
	td := t.TempDir()
	if werr := os.WriteFile(filepath.Join(td, "sealed.json"), tampered, 0o600); werr != nil {
		t.Fatalf("writing the tampered fixture: %v", werr)
	}
	if err := cmdUnsealExport([]string{
		"--in", filepath.Join(td, "sealed.json"),
		"--sig", filepath.Join(dir, "sealed.json.sig"),
		"--identity", filepath.Join(dir, "identity.key"),
		"--signer", filepath.Join(dir, "signer.pub"),
		"--out", filepath.Join(td, "out.json"),
	}); err == nil {
		t.Fatal("a tampered sealed export was accepted; unseal-export must refuse it")
	}
}

// TestUnsealExportUsage proves the flag guard.
func TestUnsealExportUsage(t *testing.T) {
	if err := cmdUnsealExport([]string{"--in", "x.json"}); err == nil {
		t.Fatal("unseal-export with missing flags should error")
	}
}
