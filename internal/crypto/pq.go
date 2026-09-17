package crypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"filippo.io/mldsa"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// This file is the post-quantum foundation at CNSA 2.0 grade: a hybrid X25519 +
// ML-KEM-1024 key encapsulation for confidentiality and a hybrid Ed25519 +
// ML-DSA-87 signature for integrity. Both are hybrid on purpose, so a recovered
// archive stays confidential and tamper-evident if either the classical or the
// post-quantum half is later broken. The byte-exact wire format is pinned in the
// spec revision that adopts these; this file proves the constructions and the
// libraries.

// HybridKEMPublic is a recipient's public key material: an X25519 public key and an
// ML-KEM-1024 encapsulation key. A file key or the run master is wrapped to this
// set; the matching private halves recover it, and the break-glass copy of those
// lives offline (SPEC.md 1.1 and 7.6).
type HybridKEMPublic struct {
	X25519 *ecdh.PublicKey
	MLKEM  *mlkem.EncapsulationKey1024
}

// HybridKEMPrivate holds both private halves of a recipient identity.
type HybridKEMPrivate struct {
	X25519 *ecdh.PrivateKey
	MLKEM  *mlkem.DecapsulationKey1024
}

// GenerateHybridKEM generates a recipient identity from a secure random source.
func GenerateHybridKEM() (*HybridKEMPrivate, *HybridKEMPublic, error) {
	xk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("x25519 keygen: %w", err)
	}
	mk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, nil, fmt.Errorf("ml-kem keygen: %w", err)
	}
	return &HybridKEMPrivate{X25519: xk, MLKEM: mk},
		&HybridKEMPublic{X25519: xk.PublicKey(), MLKEM: mk.EncapsulationKey()}, nil
}

// PublicOf derives a recipient identity's public half from the private one. It is what lets
// the offline tool name a key file the operator holds: RecipientFingerprint over this result
// is the same dpr1: value the writer recorded in the run's root manifest and the console
// printed on the recovery sheet, so a holder of identity.key can confirm it is the key the
// archive was sealed to before attempting anything. It reads the private key and returns only
// public material.
func PublicOf(priv *HybridKEMPrivate) *HybridKEMPublic {
	return &HybridKEMPublic{X25519: priv.X25519.PublicKey(), MLKEM: priv.MLKEM.EncapsulationKey()}
}

// NewHybridPublic rebuilds a recipient public key from its raw X25519 (32-byte) and
// ML-KEM-1024 encapsulation-key bytes, as listed in a root manifest. It validates both
// encodings so the reader can recompute the recipient-set hash and the fingerprint.
func NewHybridPublic(x25519, mlkem1024 []byte) (*HybridKEMPublic, error) {
	xpub, err := ecdh.X25519().NewPublicKey(x25519)
	if err != nil {
		return nil, fmt.Errorf("x25519 public key: %w", err)
	}
	mpub, err := mlkem.NewEncapsulationKey1024(mlkem1024)
	if err != nil {
		return nil, fmt.Errorf("ml-kem public key: %w", err)
	}
	return &HybridKEMPublic{X25519: xpub, MLKEM: mpub}, nil
}

// EncapsulateHybrid produces a 32-byte shared secret and the hybrid ciphertext (the
// ML-KEM-1024 ciphertext followed by the 32-byte X25519 ephemeral share). The shared
// secret binds both component secrets, the ephemeral share and the recipient X25519
// key, so it is secure if either ML-KEM or X25519 holds. The X25519 exchange aborts
// on an all-zero shared secret (SPEC.md 4.1).
//
// Encapsulation is always freshly randomised from the system CSPRNG (crypto/rand) for
// both halves and takes no caller-supplied reader. ML-KEM-1024 encapsulation
// (crypto/mlkem EncapsulationKey1024.Encapsulate) draws its own randomness internally
// and exposes no reader; the only derandomised entry point (crypto/mlkem/mlkemtest) is
// documented as test-only and is rejected under FIPS 140-only mode, so honouring a
// caller reader for the X25519 half while the ML-KEM half silently ignored it would be
// a misleading contract. The earlier randr parameter was removed for that reason. A
// consequence is that a full encapsulation cannot be byte-pinned in a known-answer
// vector; the combiner is byte-locked separately via HybridKEMCombine (SPEC.md 14.6),
// and the KEM as a whole is verify-pinned (encapsulate then decapsulate agree).
func EncapsulateHybrid(pub *HybridKEMPublic) (sharedSecret, ciphertext []byte, err error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ephemeral x25519: %w", err)
	}
	ssX, err := eph.ECDH(pub.X25519)
	if err != nil {
		return nil, nil, fmt.Errorf("x25519 ecdh: %w", err)
	}
	ssM, ctM := pub.MLKEM.Encapsulate()
	ctX := eph.PublicKey().Bytes()
	ss := hybridCombiner(ssM, ssX, ctX, pub.X25519.Bytes())
	ct := make([]byte, 0, len(ctM)+len(ctX))
	ct = append(append(ct, ctM...), ctX...)
	return ss, ct, nil
}

// DecapsulateHybrid recovers the 32-byte shared secret from the hybrid ciphertext.
func DecapsulateHybrid(priv *HybridKEMPrivate, ciphertext []byte) ([]byte, error) {
	const ctMLen = mlkem.CiphertextSize1024
	if len(ciphertext) != ctMLen+32 {
		return nil, fmt.Errorf("hybrid ciphertext is %d bytes, want %d", len(ciphertext), ctMLen+32)
	}
	ctM, ctX := ciphertext[:ctMLen], ciphertext[ctMLen:]
	ssM, err := priv.MLKEM.Decapsulate(ctM)
	if err != nil {
		return nil, fmt.Errorf("ml-kem decapsulate: %w", err)
	}
	ephPub, err := ecdh.X25519().NewPublicKey(ctX)
	if err != nil {
		return nil, fmt.Errorf("x25519 ephemeral share: %w", err)
	}
	ssX, err := priv.X25519.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("x25519 ecdh: %w", err)
	}
	return hybridCombiner(ssM, ssX, ctX, priv.X25519.PublicKey().Bytes()), nil
}

// HybridKEMCombine exposes the combiner for the conformance known-answer vector
// (SPEC.md 14.6), so a second implementation can byte-lock the combiner in isolation
// before sealing any object.
func HybridKEMCombine(ssM, ssX, ctX, pkX []byte) []byte {
	return hybridCombiner(ssM, ssX, ctX, pkX)
}

// hybridCombiner derives the 32-byte shared secret from the two component shared
// secrets, binding the X25519 ephemeral share and the recipient X25519 public key
// so the secret is tied to this encapsulation. It mirrors the binding choices of
// X-Wing (ss_M, ss_X, ct_X, pk_X), generalised to ML-KEM-1024 over HKDF-SHA-384,
// since X-Wing itself is fixed to ML-KEM-768.
func hybridCombiner(ssM, ssX, ctX, pkX []byte) []byte {
	info := append([]byte(spec.HybridKEMLabel), 0x00)
	info = append(info, ctX...)
	info = append(info, pkX...)
	ikm := make([]byte, 0, len(ssM)+len(ssX))
	ikm = append(append(ikm, ssM...), ssX...)
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha512.New384, ikm, nil, info), out); err != nil {
		panic("downpipe/crypto: hybrid-kem hkdf failed for a fixed small length: " + err.Error())
	}
	return out
}

// HybridSigner signs with both Ed25519 and ML-DSA-87. A verifier requires BOTH, so a
// forgery must break a classical AND a post-quantum scheme, and neither half can be
// stripped to downgrade the archive (SPEC.md 8).
type HybridSigner struct {
	Ed    ed25519.PrivateKey
	MLDSA *mldsa.PrivateKey
}

// HybridVerifier holds the two public halves of a signer.
type HybridVerifier struct {
	Ed    ed25519.PublicKey
	MLDSA *mldsa.PublicKey
}

// GenerateHybridSigner generates a signer from a secure random source.
func GenerateHybridSigner() (*HybridSigner, *HybridVerifier, error) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ed25519 keygen: %w", err)
	}
	mPriv, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		return nil, nil, fmt.Errorf("ml-dsa keygen: %w", err)
	}
	return &HybridSigner{Ed: edPriv, MLDSA: mPriv},
		&HybridVerifier{Ed: edPub, MLDSA: mPriv.PublicKey()}, nil
}

// Sign returns the Ed25519 signature followed by the ML-DSA-87 signature. The fixed
// Ed25519 length lets a verifier split the two halves.
func (s *HybridSigner) Sign(message []byte) ([]byte, error) {
	mSig, err := s.MLDSA.Sign(rand.Reader, message, &mldsa.Options{})
	if err != nil {
		return nil, fmt.Errorf("ml-dsa sign: %w", err)
	}
	edSig := ed25519.Sign(s.Ed, message)
	out := make([]byte, 0, len(edSig)+len(mSig))
	return append(append(out, edSig...), mSig...), nil
}

// Verify requires both halves to pass. A signature missing or failing either half is
// rejected, so a post-quantum or classical downgrade is not possible.
func (v *HybridVerifier) Verify(message, signature []byte) error {
	if len(signature) < ed25519.SignatureSize {
		return fmt.Errorf("hybrid signature too short: %d bytes", len(signature))
	}
	edSig, mSig := signature[:ed25519.SignatureSize], signature[ed25519.SignatureSize:]
	// Run both verifications unconditionally and only judge afterwards, so the caller
	// cannot use early return to learn which half failed independently of the other.
	edOK := ed25519.Verify(v.Ed, message, edSig)
	mlErr := mldsa.Verify(v.MLDSA, message, mSig, &mldsa.Options{})
	if !edOK {
		return fmt.Errorf("ed25519 verification failed")
	}
	if mlErr != nil {
		return fmt.Errorf("ml-dsa verification failed: %w", mlErr)
	}
	return nil
}
