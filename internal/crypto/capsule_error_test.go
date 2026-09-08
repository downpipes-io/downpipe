package crypto

import (
	"crypto/rand"
	"strings"
	"testing"
)

// When a held identity matches no wrap, the error must name the fingerprints the run
// was actually sealed to (with their roles), not only the held one, so a recoverer
// staring at an old archive with a rotated key learns which key it needs.
func TestOpenCapsuleWrongIdentityNamesWantedRecipients(t *testing.T) {
	var master [32]byte
	for i := range master {
		master[i] = byte(i*5 + 3)
	}
	_, bgPub := newRecipient(t)
	_, opPub := newRecipient(t)
	ctx := []byte("downpipe run context")

	wraps, err := SealToRecipients(master, []*HybridKEMPublic{bgPub, opPub}, ctx, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bgFP := RecipientFingerprint(bgPub)
	opFP := RecipientFingerprint(opPub)
	wanted := []RecipientDesc{
		{Role: "break-glass", Fingerprint: bgFP},
		{Role: "operational", Fingerprint: opFP},
	}

	wrongPriv, wrongPub := newRecipient(t)
	heldFP := RecipientFingerprint(wrongPub)

	_, err = OpenCapsule(wraps, wrongPriv, ctx, wanted)
	if err == nil {
		t.Fatal("a non-recipient must not open the capsule")
	}
	msg := err.Error()
	for _, want := range []string{heldFP, "break-glass " + bgFP, "operational " + opFP, "this run needs one of:"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q must contain %q", msg, want)
		}
	}
}

// With no recipient descriptors supplied, the error must still name the identities the
// run was sealed to by falling back to the wrap fingerprints.
func TestOpenCapsuleWrongIdentityFallsBackToWrapFingerprints(t *testing.T) {
	var master [32]byte
	for i := range master {
		master[i] = byte(i + 9)
	}
	_, bgPub := newRecipient(t)
	_, opPub := newRecipient(t)
	ctx := []byte("ctx")

	wraps, err := SealToRecipients(master, []*HybridKEMPublic{bgPub, opPub}, ctx, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongPriv, _ := newRecipient(t)

	_, err = OpenCapsule(wraps, wrongPriv, ctx, nil)
	if err == nil {
		t.Fatal("a non-recipient must not open the capsule")
	}
	msg := err.Error()
	for _, fp := range []string{RecipientFingerprint(bgPub), RecipientFingerprint(opPub)} {
		if !strings.Contains(msg, fp) {
			t.Fatalf("fallback error %q must contain wrap fingerprint %q", msg, fp)
		}
	}
}

// An empty capsule with no recipients at all must produce a coherent message rather
// than a dangling "needs one of:".
func TestOpenCapsuleNoRecipientsMessage(t *testing.T) {
	wrongPriv, _ := newRecipient(t)
	_, err := OpenCapsule(nil, wrongPriv, []byte("ctx"), nil)
	if err == nil {
		t.Fatal("an empty capsule must not open")
	}
	if !strings.Contains(err.Error(), "this run lists no recipients to open it") {
		t.Fatalf("unexpected empty-capsule message: %q", err.Error())
	}
}

// describeWanted renders a role-bearing recipient as "role fingerprint" and a
// role-less one as the bare fingerprint, and prefers the recipient list over the wraps.
func TestDescribeWantedFormatsRolesAndBareFingerprints(t *testing.T) {
	got := describeWanted([]RecipientDesc{
		{Role: "break-glass", Fingerprint: "dpr1:aaa"},
		{Role: "", Fingerprint: "dpr1:bbb"},
	}, []WrappedKey{{Fingerprint: "dpr1:ignored"}})
	want := "this run needs one of: break-glass dpr1:aaa, dpr1:bbb"
	if got != want {
		t.Fatalf("describeWanted = %q, want %q", got, want)
	}
	if strings.Contains(got, "dpr1:ignored") {
		t.Fatal("describeWanted must prefer the recipient list over the wrap fingerprints")
	}
}
