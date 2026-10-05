package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/source"
)

// TestVerifyWritesSignedReceipt drives a full verify run with --receipt and
// --receipt-signer against a real archive, then re-opens the written receipt and verifies
// it against the receipt signer's public key. This covers emitReceipt end to end including
// the signing branch and the write-to-file branch, and proves the emitted receipt is a
// genuine, verifiable signed artefact (SPEC.md 8.5).
func TestVerifyWritesSignedReceipt(t *testing.T) {
	silenceOutput(t)
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("receipt test value"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)

	// A separate signer keypair signs the receipt; keep its verifier to check the result.
	rsigner, rverifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatalf("GenerateHybridSigner: %v", err)
	}
	rsignerPath := filepath.Join(dir, "receipt-signer.key")
	if err := writeKeyFile(rsignerPath, labelSignerPrivate, crypto.MarshalSigner(rsigner)); err != nil {
		t.Fatalf("write receipt signer key: %v", err)
	}
	receiptPath := filepath.Join(dir, "receipt.json")

	code := run([]string{
		"verify",
		"--archive", dir,
		"--run", runID,
		"--identity", idPath,
		"--signer", signerPath,
		"--receipt", receiptPath,
		"--receipt-signer", rsignerPath,
	})
	if code != 0 {
		t.Fatalf("verify with receipt = %d, want 0", code)
	}

	// The receipt must exist and verify against the receipt signer's public half.
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	rcpt, err := format.VerifyReceipt(raw, rverifier)
	if err != nil {
		t.Fatalf("emitted receipt failed to verify: %v", err)
	}
	if !rcpt.Signed {
		t.Error("emitted receipt is not marked Signed")
	}
	if rcpt.RunID != runID {
		t.Errorf("receipt runId = %q, want %q", rcpt.RunID, runID)
	}
	if rcpt.Target.Type != "verify" {
		t.Errorf("receipt target type = %q, want verify", rcpt.Target.Type)
	}
}

// TestRestoreWritesUnsignedReceiptToStderr drives a restore (dry run) with --receipt -
// (stderr) and no --receipt-signer, covering emitReceipt's unsigned branch and the
// write-to-stderr branch. An unsigned receipt still records the honest outcome.
func TestRestoreWritesUnsignedReceiptToStderr(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("unsigned receipt value"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	idPath, signerPath := writeArchiveKeys(t, dir, identity, verifier)
	outDir := filepath.Join(dir, "out")

	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{
			"restore",
			"--archive", dir,
			"--run", runID,
			"--identity", idPath,
			"--signer", signerPath,
			"--out", outDir,
			"--receipt", "-",
			// no --receipt-signer: the receipt is emitted unsigned
		})
	})
	if code != 0 {
		t.Fatalf("restore dry-run with receipt to stderr = %d, want 0", code)
	}
	// The receipt JSON goes to stderr; it must carry the receipt kind and the run id, and
	// must report Signed=false because no receipt signer was supplied.
	for _, want := range []string{"downpipe-restore-receipt", runID, "\"signed\":false"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr receipt missing %q\n%s", want, stderr)
		}
	}
}

// TestEmitReceiptNoPathSkips confirms emitReceipt with an empty path is a no-op that
// returns nil and writes nothing: the receipt is opt-in, so the common no-receipt run must
// not error or emit. It drives emitReceipt directly with a real Reader.
func TestEmitReceiptNoPathSkips(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("no receipt value"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	r, err := format.Open(source.NewDirStore(dir), runID, identity, verifier, format.Options{})
	if err != nil {
		t.Fatalf("format.Open: %v", err)
	}
	// path == "" must short-circuit to nil with no error and no signer key read.
	if err := emitReceipt(r, format.ReceiptInput{TargetType: "verify"}, false, "", ""); err != nil {
		t.Fatalf("emitReceipt with empty path = %v, want nil (no-op)", err)
	}
}

// TestEmitReceiptBadSignerKeyErrors confirms emitReceipt surfaces a clean error when the
// --receipt-signer path is not a valid signer private-key file, rather than panicking or
// emitting an unsigned receipt silently. It drives emitReceipt directly.
func TestEmitReceiptBadSignerKeyErrors(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("bad signer value"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	r, err := format.Open(source.NewDirStore(dir), runID, identity, verifier, format.Options{})
	if err != nil {
		t.Fatalf("format.Open: %v", err)
	}
	// A signer-key path that does not exist: the read fails inside emitReceipt.
	missing := filepath.Join(dir, "does-not-exist.key")
	if err := emitReceipt(r, format.ReceiptInput{TargetType: "verify"}, false, filepath.Join(dir, "rcpt.json"), missing); err == nil {
		t.Fatal("emitReceipt with a missing receipt-signer key = nil, want an error")
	}

	// A file that exists but is not a signer private key (wrong label): ParseSigner fails
	// after the label check, or the label check fails. Either way it must error.
	notASigner := filepath.Join(dir, "not-a-signer.key")
	if werr := writeKeyFile(notASigner, labelSignerPrivate, []byte("not-real-signer-bytes")); werr != nil {
		t.Fatalf("write fake signer file: %v", werr)
	}
	if err := emitReceipt(r, format.ReceiptInput{TargetType: "verify"}, false, filepath.Join(dir, "rcpt2.json"), notASigner); err == nil {
		t.Fatal("emitReceipt with an unparseable receipt-signer key = nil, want an error")
	}
}

// TestEmitReceiptSignsToFileDirect drives emitReceipt directly with a valid receipt-signer
// key and a file path, then reads back and verifies the signature. This exercises the same
// signing path as the command test but without the full run() dispatch, isolating
// emitReceipt's build/sign/marshal/write sequence.
func TestEmitReceiptSignsToFileDirect(t *testing.T) {
	dir := t.TempDir()
	identity, verifier, runID, err := buildSelftestArchive(dir, []byte("direct emit value"))
	if err != nil {
		t.Fatalf("buildSelftestArchive: %v", err)
	}
	r, err := format.Open(source.NewDirStore(dir), runID, identity, verifier, format.Options{})
	if err != nil {
		t.Fatalf("format.Open: %v", err)
	}

	rsigner, rverifier, err := crypto.GenerateHybridSigner()
	if err != nil {
		t.Fatalf("GenerateHybridSigner: %v", err)
	}
	rsignerPath := filepath.Join(dir, "rs.key")
	if err := writeKeyFile(rsignerPath, labelSignerPrivate, crypto.MarshalSigner(rsigner)); err != nil {
		t.Fatalf("write receipt signer: %v", err)
	}
	receiptPath := filepath.Join(dir, "direct-receipt.json")

	in := format.ReceiptInput{
		StartedAt: nowStamp(), FinishedAt: nowStamp(),
		SignerExpected: crypto.SignerFingerprint(verifier),
		TargetType:     "file", Restored: 1, ExitCode: 0,
	}
	// valueVerified=true mirrors a real file-sink apply.
	if err := emitReceipt(r, in, true, receiptPath, rsignerPath); err != nil {
		t.Fatalf("emitReceipt = %v, want nil", err)
	}
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	rcpt, err := format.VerifyReceipt(raw, rverifier)
	if err != nil {
		t.Fatalf("receipt failed to verify: %v", err)
	}
	if !rcpt.Target.ValueVerified {
		t.Error("receipt Target.ValueVerified = false, want true (file sink real apply)")
	}
}

// TestDefaultDoerConfig covers defaultDoer: it must be an *http.Client with a bounded
// timeout and a redirect policy that refuses to follow redirects (so the Bearer token is
// never replayed to a host chosen by a redirect). This is a pure configuration assertion;
// it makes no network call.
func TestDefaultDoerConfig(t *testing.T) {
	d := defaultDoer()
	hc, ok := d.(*http.Client)
	if !ok {
		t.Fatalf("defaultDoer returned %T, want *http.Client", d)
	}
	if hc.Timeout != 30*time.Second {
		t.Errorf("defaultDoer timeout = %v, want 30s", hc.Timeout)
	}
	if hc.CheckRedirect == nil {
		t.Fatal("defaultDoer CheckRedirect is nil; it must refuse redirects so the token is not replayed")
	}
	// The redirect policy must return ErrUseLastResponse so the client stops at the first
	// response rather than re-sending the Authorization header to a redirect target.
	err := hc.CheckRedirect(&http.Request{}, nil)
	if err != http.ErrUseLastResponse {
		t.Errorf("CheckRedirect returned %v, want http.ErrUseLastResponse", err)
	}
}
