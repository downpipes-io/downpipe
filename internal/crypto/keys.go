package crypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"fmt"

	"filippo.io/mldsa"
)

// Key serialisation for the offline identity and signer files. The sizes are fixed by
// the CNSA 2.0 suite, so the parsers reject anything else. The offline tool holds a
// recipient private identity (the break-glass key) and a signer public key (the
// operator-pinned verifier); the signer private key lives with the writer.

const (
	// x25519KeySize is the byte length of an X25519 public or private key.
	x25519KeySize = 32
	// kemPrivateSize is the recipient private identity: x25519(32) || ML-KEM-1024 seed.
	kemPrivateSize = x25519KeySize + mlkem.SeedSize
	// kemPublicSize is the recipient public key: x25519(32) || ML-KEM-1024 encapsulation key.
	kemPublicSize = x25519KeySize + mlkem.EncapsulationKeySize1024
)

// MarshalKEMPrivate encodes a recipient private identity as x25519(32) followed by the
// 64-byte ML-KEM-1024 seed (96 bytes). This is the break-glass identity held offline.
func MarshalKEMPrivate(k *HybridKEMPrivate) []byte {
	out := make([]byte, 0, kemPrivateSize)
	out = append(out, k.X25519.Bytes()...)
	out = append(out, k.MLKEM.Bytes()...)
	return out
}

// ParseKEMPrivate parses a recipient private identity produced by MarshalKEMPrivate.
func ParseKEMPrivate(b []byte) (*HybridKEMPrivate, error) {
	if len(b) != kemPrivateSize {
		return nil, fmt.Errorf("recipient private identity is %d bytes, want %d", len(b), kemPrivateSize)
	}
	x, err := ecdh.X25519().NewPrivateKey(b[:x25519KeySize])
	if err != nil {
		return nil, fmt.Errorf("x25519 private key: %w", err)
	}
	m, err := mlkem.NewDecapsulationKey1024(b[x25519KeySize:])
	if err != nil {
		return nil, fmt.Errorf("ml-kem private key: %w", err)
	}
	return &HybridKEMPrivate{X25519: x, MLKEM: m}, nil
}

// MarshalKEMPublic encodes a recipient public key as x25519(32) || ML-KEM-1024(1568).
func MarshalKEMPublic(k *HybridKEMPublic) []byte { return recipientEncoding(k) }

// ParseKEMPublic parses a recipient public key produced by MarshalKEMPublic.
func ParseKEMPublic(b []byte) (*HybridKEMPublic, error) {
	if len(b) != kemPublicSize {
		return nil, fmt.Errorf("recipient public key is %d bytes, want %d", len(b), kemPublicSize)
	}
	return NewHybridPublic(b[:x25519KeySize], b[x25519KeySize:])
}

// MarshalVerifier encodes a signer public key as ed25519(32) || ML-DSA-87-public. This
// is the operator-pinned signer the offline reader verifies against.
func MarshalVerifier(v *HybridVerifier) []byte {
	mb := v.MLDSA.Bytes()
	out := make([]byte, 0, ed25519.PublicKeySize+len(mb))
	out = append(out, v.Ed...)
	out = append(out, mb...)
	return out
}

// ParseVerifier parses a signer public key produced by MarshalVerifier.
func ParseVerifier(b []byte) (*HybridVerifier, error) {
	const edLen = ed25519.PublicKeySize
	if len(b) <= edLen {
		return nil, fmt.Errorf("signer public key is %d bytes, too short", len(b))
	}
	ed := ed25519.PublicKey(append([]byte(nil), b[:edLen]...))
	m, err := mldsa.NewPublicKey(mldsa.MLDSA87(), b[edLen:])
	if err != nil {
		return nil, fmt.Errorf("ml-dsa public key: %w", err)
	}
	return &HybridVerifier{Ed: ed, MLDSA: m}, nil
}

// MarshalSigner encodes a signer private key as the ed25519 seed(32) followed by the
// ML-DSA-87 private key. The signer is held by the writer; the offline tool never
// holds it.
func MarshalSigner(s *HybridSigner) []byte {
	mb := s.MLDSA.Bytes()
	out := make([]byte, 0, ed25519.SeedSize+len(mb))
	out = append(out, s.Ed.Seed()...)
	out = append(out, mb...)
	return out
}

// ParseSigner parses a signer private key produced by MarshalSigner.
func ParseSigner(b []byte) (*HybridSigner, error) {
	const edSeed = ed25519.SeedSize
	if len(b) <= edSeed {
		return nil, fmt.Errorf("signer private key is %d bytes, too short", len(b))
	}
	m, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), b[edSeed:])
	if err != nil {
		return nil, fmt.Errorf("ml-dsa private key: %w", err)
	}
	return &HybridSigner{Ed: ed25519.NewKeyFromSeed(b[:edSeed]), MLDSA: m}, nil
}
