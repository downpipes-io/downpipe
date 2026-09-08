package crypto

import (
	"bytes"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sort"
	"strings"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// zeroize overwrites a byte slice with zeros as a best-effort wipe of key material
// once it is no longer needed. It is defence in depth: Go's runtime uses a copying
// garbage collector, gives no mlock, and may spill values to the stack or registers,
// so it cannot guarantee that every copy of a secret is erased from memory. The
// runtime.KeepAlive keeps the backing array live across the clear so the store is not
// treated as dead and elided. Highest value on the master-recovery and break-glass
// paths (see OpenCapsule), where the recovered run master and derived file keys pass
// through this package.
func zeroize(b []byte) {
	if len(b) == 0 {
		return
	}
	clear(b)
	runtime.KeepAlive(b)
}

// Zeroize is zeroize for callers outside this package. It exists because the run master does not stay
// here: OpenCapsule returns it, the reader holds it for its lifetime to derive per-segment file keys, and
// that buffer needs the same best-effort wipe when the reader is done. Exported rather than reimplemented,
// because a security primitive copied into a second package is a second thing to get wrong, and the
// runtime.KeepAlive above is exactly the part an independent reimplementation tends to omit.
func Zeroize(b []byte) { zeroize(b) }

// zeroizeArray is zeroize for a fixed 32-byte key array (the derived AES-256 wrap and
// file keys), taken by pointer so the caller's array, not a copy, is wiped.
func zeroizeArray(a *[32]byte) {
	clear(a[:])
	runtime.KeepAlive(a)
}

// RecipientFingerprint identifies a hybrid recipient by a type-prefixed SHA-384 of
// its concatenated X25519 and ML-KEM-1024 public keys. It is recorded with each wrap
// and printed on the recovery sheet, so an operator knows which offline identity
// opens an archive (SPEC.md 7.6.1).
func RecipientFingerprint(pub *HybridKEMPublic) string {
	sum := sha512.Sum384(recipientEncoding(pub))
	return "dpr1:" + hex.EncodeToString(sum[:])
}

// SignerFingerprint identifies a hybrid signer by the "edmldsa1:"-prefixed SHA-384 of
// its Ed25519 and ML-DSA-87 public keys (SPEC.md 11.4). It is the recovery-sheet and
// restore-receipt label for the operator-pinned signer.
func SignerFingerprint(v *HybridVerifier) string {
	sum := sha512.Sum384(MarshalVerifier(v))
	return "edmldsa1:" + hex.EncodeToString(sum[:])
}

// recipientEncoding is a recipient's public key material as the 1600 bytes
// X25519(32) || ML-KEM-1024(1568), the form hashed and sorted for the recipient-set
// hash and the fingerprint.
func recipientEncoding(pub *HybridKEMPublic) []byte {
	x := pub.X25519.Bytes()
	m := pub.MLKEM.Bytes()
	enc := make([]byte, 0, len(x)+len(m))
	return append(append(enc, x...), m...)
}

// RecipientSetHash binds the exact recipient set of a run into the signed root
// (SPEC.md 7.6.1), so a reader can detect a stripped or swapped recipient on a stored
// sealed unit. It is SHA-384 over the label and the recipient encodings sorted by
// their raw bytes, so it is independent of listing order.
func RecipientSetHash(recipients []*HybridKEMPublic) []byte {
	encs := make([][]byte, len(recipients))
	for i, r := range recipients {
		encs[i] = recipientEncoding(r)
	}
	sort.Slice(encs, func(i, j int) bool { return bytes.Compare(encs[i], encs[j]) < 0 })
	h := sha512.New384()
	h.Write([]byte(spec.InfoRecipientSet))
	h.Write([]byte{0x00})
	for _, e := range encs {
		h.Write(e)
	}
	return h.Sum(nil)
}

// ConstantTimeEqual reports whether two byte slices are equal. The reader uses it for
// every security-relevant comparison, such as the key commitment and the
// recipient-set hash, never the variable-time bytes.Equal.
//
// It checks the lengths upfront and then delegates the equal-length hot path to
// crypto/subtle.ConstantTimeCompare, the runtime-verified constant-time path. Every
// current caller compares fixed-size 48-byte SHA-384 digests, so the length is public
// today, and a length mismatch is reported as not-equal without revealing where the
// bytes first diverged.
func ConstantTimeEqual(a, b []byte) bool {
	// An explicit upfront length check reports a mismatch without revealing where the
	// bytes first diverged, then the equal-length hot path delegates to
	// subtle.ConstantTimeCompare so the comparison rides the runtime-verified
	// constant-time path rather than a hand-rolled loop.
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// WrappedKey is one recipient's hybrid KEM-DEM wrap of a 32-byte secret: the KEM
// ciphertext and the AES-256-GCM-sealed secret under the key derived from the KEM
// shared secret. A recipient whose private identity matches Fingerprint recovers the
// secret.
type WrappedKey struct {
	Fingerprint   string
	KEMCiphertext []byte
	Sealed        []byte
}

// SealToRecipients wraps a 32-byte secret (the run master) to every recipient by
// hybrid KEM-DEM, so any one recipient's private identity recovers it. The
// break-glass recipient is one of these; the running engine holds only its public
// key and so can wrap to it but never unwrap, which is what keeps a
// destination-bucket-alone compromise from yielding plaintext (SPEC.md 5.4 and 7.6).
//
// randr supplies the per-wrap AES-GCM nonce only. Hybrid KEM encapsulation is always
// freshly randomised from the system CSPRNG and does not draw from randr (see
// EncapsulateHybrid). The derived per-recipient KEM shared secret and wrap key are
// best-effort zeroized once each wrap is sealed; Go cannot guarantee erasure (see
// zeroize).
func SealToRecipients(secret [32]byte, recipients []*HybridKEMPublic, context []byte, randr io.Reader) ([]WrappedKey, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("a capsule needs at least one recipient")
	}
	wraps := make([]WrappedKey, 0, len(recipients))
	for _, r := range recipients {
		w, err := sealWrap(secret, r, context, randr)
		if err != nil {
			return nil, err
		}
		wraps = append(wraps, w)
	}
	return wraps, nil
}

// sealWrap produces one recipient's hybrid KEM-DEM wrap. It is split out of
// SealToRecipients so the deferred zeroization of this recipient's KEM shared secret
// and wrap key fires as soon as the wrap is sealed, rather than accumulating across
// every recipient to the end of the outer call.
func sealWrap(secret [32]byte, r *HybridKEMPublic, context []byte, randr io.Reader) (WrappedKey, error) {
	fp := RecipientFingerprint(r)
	ss, ct, err := EncapsulateHybrid(r)
	if err != nil {
		return WrappedKey{}, fmt.Errorf("encapsulate to %s: %w", fp, err)
	}
	// The KEM shared secret and the derived wrap key both gate this recipient's copy
	// of the master; wipe them once the wrap is sealed (best effort, see zeroize).
	defer zeroize(ss)
	wrapKey := first32(hkdfKey(ss, nil, []byte(spec.InfoCapsuleDEM), spec.FileKeySize))
	defer zeroizeArray(&wrapKey)
	nonce := make([]byte, spec.StreamNonceSize)
	if _, err := io.ReadFull(randr, nonce); err != nil {
		return WrappedKey{}, fmt.Errorf("capsule nonce: %w", err)
	}
	// The run context is bound as AAD, so a wrap cannot be replayed into a
	// different run's manifest even though AES-GCM is not key-committing.
	sealed, err := sealSecretTo(secret, wrapKey, nonce, context)
	if err != nil {
		return WrappedKey{}, fmt.Errorf("seal to %s: %w", fp, err)
	}
	return WrappedKey{Fingerprint: fp, KEMCiphertext: ct, Sealed: sealed}, nil
}

// sealSecretTo streams the 32-byte secret through a fresh seal writer bound to the
// given wrap key, nonce and context, and returns the sealed bytes.
func sealSecretTo(secret [32]byte, wrapKey [32]byte, nonce []byte, context []byte) ([]byte, error) {
	var sealed bytes.Buffer
	sw, err := SealStreamTo(&sealed, wrapKey, nonce, context)
	if err != nil {
		return nil, err
	}
	if _, err := sw.Write(secret[:]); err != nil {
		return nil, err
	}
	if err := sw.Close(); err != nil {
		return nil, err
	}
	return sealed.Bytes(), nil
}

// RecipientDesc names one of a run's recipients by role and fingerprint. OpenCapsule
// uses the run's recipient list to enumerate the identities that can open the run in its
// "no wrap matches" recovery error, so a recoverer holding the wrong (for example, a
// rotated) key learns which fingerprint the run actually needs — "this run needs one of:
// break-glass dpr1:<X>, operational dpr1:<Y>" — rather than only the held one.
type RecipientDesc struct {
	Role        string
	Fingerprint string
}

// OpenCapsule recovers the 32-byte secret using a held recipient identity, trying the
// wrap whose Fingerprint matches that identity's public keys. wanted lists the run's
// signed recipients (role + fingerprint) so that, when no wrap matches the held
// identity, the error names the fingerprints the run was actually sealed to rather than
// only the held one; it may be nil, in which case the error falls back to the wrap
// fingerprints.
//
// This is the master-recovery path, including the offline break-glass recovery of last
// resort, so every intermediate that holds key material (the KEM shared secret, the
// derived wrap key and the plaintext recovered master inside the open buffer) is
// best-effort zeroized before the call returns. The recovered master itself is
// returned by value to the caller, which owns wiping that copy; Go cannot guarantee
// erasure (see zeroize).
func OpenCapsule(wraps []WrappedKey, priv *HybridKEMPrivate, context []byte, wanted []RecipientDesc) ([32]byte, error) {
	want := RecipientFingerprint(&HybridKEMPublic{
		X25519: priv.X25519.PublicKey(),
		MLKEM:  priv.MLKEM.EncapsulationKey(),
	})
	for _, w := range wraps {
		if w.Fingerprint != want {
			continue
		}
		return openWrap(w, priv, context, want)
	}
	return [32]byte{}, fmt.Errorf("%w %s; %s", ErrIdentityMismatch, want, describeWanted(wanted, wraps))
}

// ErrIdentityMismatch marks the "the key you supplied is not one this run was sealed to"
// outcome, so the command layer can recognise it and add the next step without this package
// having to name a CLI flag or a subcommand.
//
// It matters because of what the operator is holding when they see it. Every other exit 2 is
// a statement about the ARCHIVE, and the tool's exit-code table accordingly tells the reader
// never to retry on a different key or file. This one is a statement about the KEY, and
// retrying with a different key file is the correct response: the message even prints the
// fingerprints of the keys that would work. Without a next step it dead-ends an operator
// against advice that is right everywhere else and wrong here.
var ErrIdentityMismatch = errors.New("no wrap matches the held identity")

// describeWanted renders the recipients a run can be opened by, for the "no wrap
// matches" error. It prefers the signed recipient list (role + fingerprint) so the
// message reads "this run needs one of: break-glass dpr1:<X>, operational dpr1:<Y>",
// and falls back to the wrap fingerprints when no recipient descriptors were supplied,
// so the error always names the identities the run was sealed to.
func describeWanted(wanted []RecipientDesc, wraps []WrappedKey) string {
	parts := make([]string, 0, len(wanted))
	for _, r := range wanted {
		if r.Role != "" {
			parts = append(parts, r.Role+" "+r.Fingerprint)
		} else {
			parts = append(parts, r.Fingerprint)
		}
	}
	if len(parts) == 0 {
		for _, w := range wraps {
			parts = append(parts, w.Fingerprint)
		}
	}
	if len(parts) == 0 {
		return "this run lists no recipients to open it"
	}
	return "this run needs one of: " + strings.Join(parts, ", ")
}

// openWrap recovers the master from a single matched wrap. It is split out of
// OpenCapsule so the deferred zeroization of the KEM shared secret, the wrap key and
// the recovered-master buffer fires the moment recovery completes, rather than living
// in the loop body of the caller.
func openWrap(w WrappedKey, priv *HybridKEMPrivate, context []byte, want string) ([32]byte, error) {
	ss, err := DecapsulateHybrid(priv, w.KEMCiphertext)
	if err != nil {
		return [32]byte{}, fmt.Errorf("decapsulate for %s: %w", want, err)
	}
	defer zeroize(ss)
	wrapKey := first32(hkdfKey(ss, nil, []byte(spec.InfoCapsuleDEM), spec.FileKeySize))
	defer zeroizeArray(&wrapKey)
	// The master capsule is a single chunk; bound the reader to one chunk and bind
	// the same run context that sealed it.
	var out bytes.Buffer
	if err := OpenStreamTo(&out, wrapKey, bytes.NewReader(w.Sealed), context, 1); err != nil {
		return [32]byte{}, fmt.Errorf("open wrap for %s: %w", want, err)
	}
	// out.Bytes() aliases the buffer's backing array, so wiping it clears the plaintext
	// master copy held in the buffer once it has been copied out into secret.
	defer zeroize(out.Bytes())
	if out.Len() != 32 {
		return [32]byte{}, fmt.Errorf("recovered secret is %d bytes, want 32", out.Len())
	}
	var secret [32]byte
	copy(secret[:], out.Bytes())
	return secret, nil
}
