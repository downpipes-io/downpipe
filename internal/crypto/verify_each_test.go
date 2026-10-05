package crypto

import (
	"bytes"
	"testing"
)

// VerifyEach reports the two halves of a hybrid signature apart, for diagnosis. These cases pin each
// cell of the two-by-two: both pass, each half alone, neither, and a signature too short to split.
func TestVerifyEachReportsEachHalf(t *testing.T) {
	signer, verifier, err := GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	_, otherVerifier, err := GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("signed report body")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}

	check := func(name string, v *HybridVerifier, m, s []byte, wantEd, wantML bool) {
		t.Helper()
		ed, ml := v.VerifyEach(m, s)
		if ed != wantEd || ml != wantML {
			t.Errorf("%s: VerifyEach = (ed %v, ml-dsa %v), want (ed %v, ml-dsa %v)", name, ed, ml, wantEd, wantML)
		}
	}

	check("the signed message", verifier, msg, sig, true, true)
	check("a changed message", verifier, []byte("signed report bodY"), sig, false, false)
	check("another signer", otherVerifier, msg, sig, false, false)

	edBroken := bytes.Clone(sig)
	edBroken[0] ^= 0x01
	check("a flipped Ed25519 byte", verifier, msg, edBroken, false, true)

	mlBroken := bytes.Clone(sig)
	mlBroken[len(mlBroken)-1] ^= 0x01
	check("a flipped ML-DSA-87 byte", verifier, msg, mlBroken, true, false)

	// A verifier whose Ed25519 half comes from another key pair: the ML-DSA-87 half still verifies.
	mixed := &HybridVerifier{Ed: otherVerifier.Ed, MLDSA: verifier.MLDSA}
	check("a verifier with a foreign Ed25519 half", mixed, msg, sig, false, true)

	check("a signature shorter than the Ed25519 half", verifier, msg, sig[:10], false, false)
	check("the Ed25519 half alone", verifier, msg, sig[:64], true, false)

	// VerifyEach is diagnosis, and Verify is still the rule: a single passing half is a refusal.
	if err := verifier.Verify(msg, mlBroken); err == nil {
		t.Error("Verify accepted a signature whose ML-DSA-87 half fails")
	}
}
