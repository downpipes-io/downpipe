package crypto

import (
	"bytes"
	"testing"
)

// Every key type must survive marshal then parse, proven functionally: a parsed
// recipient opens what the public key sealed, and a parsed signer/verifier pair still
// signs and verifies.
func TestKeySerializationRoundTrip(t *testing.T) {
	priv, pub, err := GenerateHybridKEM()
	if err != nil {
		t.Fatal(err)
	}

	parsedPriv, err := ParseKEMPrivate(MarshalKEMPrivate(priv))
	if err != nil {
		t.Fatal(err)
	}
	ss1, ct, err := EncapsulateHybrid(pub)
	if err != nil {
		t.Fatal(err)
	}
	ss2, err := DecapsulateHybrid(parsedPriv, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("the recipient private identity did not round-trip")
	}

	parsedPub, err := ParseKEMPublic(MarshalKEMPublic(pub))
	if err != nil {
		t.Fatal(err)
	}
	if RecipientFingerprint(pub) != RecipientFingerprint(parsedPub) {
		t.Fatal("the recipient public key did not round-trip")
	}

	signer, verifier, err := GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	parsedVerifier, err := ParseVerifier(MarshalVerifier(verifier))
	if err != nil {
		t.Fatal(err)
	}
	parsedSigner, err := ParseSigner(MarshalSigner(signer))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("a message signed after a serialisation round-trip")
	sig, err := parsedSigner.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsedVerifier.Verify(msg, sig); err != nil {
		t.Fatalf("the round-tripped signer and verifier failed: %v", err)
	}
}

func TestParseRejectsWrongLength(t *testing.T) {
	if _, err := ParseKEMPrivate([]byte("short")); err == nil {
		t.Fatal("a wrong-length recipient private key must be rejected")
	}
	if _, err := ParseKEMPublic([]byte("short")); err == nil {
		t.Fatal("a wrong-length recipient public key must be rejected")
	}
}
