package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"filippo.io/mldsa"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// The non-secret address and file key must be a function of content alone, so an
// unchanged value under one downpipe deduplicates across runs and the single
// stored segment is openable by every run that references it (SPEC.md 7.3).
func TestNonSecretAddressingIsContentOnly(t *testing.T) {
	master := bytes.Repeat([]byte{0x11}, 32)
	cak := DeriveCAK(master, "dp_test")
	pt := []byte("hello downpipe")

	if seg1, seg2 := SegID(cak, spec.AddrSingleNonSecret, nil, pt), SegID(cak, spec.AddrSingleNonSecret, nil, pt); seg1 != seg2 {
		t.Fatal("the same content must give the same segId")
	}
	id := SegID(cak, spec.AddrSingleNonSecret, nil, pt)
	if k1, k2 := DeriveNonSecretFileKey(master, id, spec.CodecNone), DeriveNonSecretFileKey(master, id, spec.CodecNone); k1 != k2 {
		t.Fatal("the non-secret file key must be content-only and so run-independent")
	}
	if SegID(cak, spec.AddrSingleNonSecret, nil, pt) == SegID(cak, spec.AddrSingleNonSecret, nil, []byte("other")) {
		t.Fatal("different content must give a different segId")
	}
	if SegID(cak, spec.AddrSingleNonSecret, nil, pt) == SegID(cak, spec.AddrPacked, nil, pt) {
		t.Fatal("the class domain separator must distinguish single from packed")
	}
}

// Identical secret values with different per-record salts must never collide on
// disk: secrets carry no dedup (SPEC.md 7.2 case 0x03, D2).
func TestSecretsNeverDedup(t *testing.T) {
	master := bytes.Repeat([]byte{0x22}, 32)
	cak := DeriveCAK(master, "dp_secrets")
	val := []byte("super-secret-token")
	a := SegID(cak, spec.AddrSecrets, bytes.Repeat([]byte{0x01}, 16), val)
	b := SegID(cak, spec.AddrSecrets, bytes.Repeat([]byte{0x02}, 16), val)
	if a == b {
		t.Fatal("identical secret values with different salts must not collide on disk")
	}
	if a != SegID(cak, spec.AddrSecrets, bytes.Repeat([]byte{0x01}, 16), val) {
		t.Fatal("the secrets address must be deterministic for a fixed salt")
	}
}

// A bucket-keyed address must not be recomputable from the same content under a
// different downpipe, which is what scopes dedup to one downpipe (SPEC.md 7.3).
func TestAddressIsScopedPerDownpipe(t *testing.T) {
	master := bytes.Repeat([]byte{0x33}, 32)
	pt := []byte("same content")
	if SegID(DeriveCAK(master, "dp_a"), spec.AddrSingleNonSecret, nil, pt) ==
		SegID(DeriveCAK(master, "dp_b"), spec.AddrSingleNonSecret, nil, pt) {
		t.Fatal("the same content under two downpipes must not share a segId")
	}
}

func TestSecretsFileKeyDeterministicAndBinds(t *testing.T) {
	master := bytes.Repeat([]byte{0x44}, 32)
	id := SegID(DeriveCAK(master, "dp"), spec.AddrSecrets, bytes.Repeat([]byte{0x07}, 16), []byte("v"))
	rec := []byte("recordid00000001")
	salt := bytes.Repeat([]byte{0x07}, 16)
	run := bytes.Repeat([]byte{0x55}, 16)
	if s1, s2 := DeriveSecretsFileKey(master, id, rec, salt, run), DeriveSecretsFileKey(master, id, rec, salt, run); s1 != s2 {
		t.Fatal("the secrets file key must be deterministic")
	}
	if DeriveSecretsFileKey(master, id, rec, salt, run) == DeriveSecretsFileKey(master, id, rec, salt, bytes.Repeat([]byte{0x56}, 16)) {
		t.Fatal("the secrets file key must bind the runId")
	}
}

func TestKeyCommitmentBindsRun(t *testing.T) {
	master := bytes.Repeat([]byte{0x66}, 32)
	run := bytes.Repeat([]byte{0x77}, 16)
	if !bytes.Equal(KeyCommitment(master, run), KeyCommitment(master, run)) {
		t.Fatal("the key commitment must be deterministic")
	}
	if bytes.Equal(KeyCommitment(master, run), KeyCommitment(master, bytes.Repeat([]byte{0x78}, 16))) {
		t.Fatal("the key commitment must bind the runId")
	}
}

// Locked known-answer vectors for the derivation and fingerprint helpers that had no
// direct coverage. The expected outputs were derived once from this code and pinned
// here as regression vectors: they have no external authority, so their job is to fail
// loudly if a derivation (its HKDF info string, salt, IKM, length prefix or hash) ever
// changes. Each case pairs the locked vector with a negative control that varies one
// input and asserts the output moves, so the vector cannot be satisfied by a constant
// or by ignoring the varied field.
//
// The fixed inputs:
//
//	master  = 32 bytes of 0xA1
//	run     = 16 bytes of 0xB2  (a 16-byte runId, as the manifest layer passes)
//	mk      = DeriveMK(master, run)
//	nameKey = DeriveNameMACKey(mk, run)

var (
	katMaster = bytes.Repeat([]byte{0xA1}, 32)
	katRun    = bytes.Repeat([]byte{0xB2}, 16)
)

func TestDeriveMKKnownAnswer(t *testing.T) {
	const want = "f22de65a03affcec31407b7e30b32bd38a9c337bdc9a815a44aa1c5d279ecdb9"
	got := DeriveMK(katMaster, katRun)
	if hex.EncodeToString(got) != want {
		t.Fatalf("DeriveMK regression: got %s, want locked %s", hex.EncodeToString(got), want)
	}
	if len(got) != 32 {
		t.Fatalf("the manifest subkey must be 32 bytes, got %d", len(got))
	}
	// The runId is the HKDF salt, so a different run must give a different subkey.
	if bytes.Equal(got, DeriveMK(katMaster, bytes.Repeat([]byte{0xB3}, 16))) {
		t.Fatal("DeriveMK must bind the runId salt")
	}
	if bytes.Equal(got, DeriveMK(bytes.Repeat([]byte{0xA2}, 32), katRun)) {
		t.Fatal("DeriveMK must bind the master IKM")
	}
}

func TestDeriveNameMACKeyKnownAnswer(t *testing.T) {
	const want = "e8548e2b0b6c4f17044be7b9c561785341207dd2e5f91a11a91664bd7ee9f411"
	mk := DeriveMK(katMaster, katRun)
	got := DeriveNameMACKey(mk, katRun)
	if hex.EncodeToString(got) != want {
		t.Fatalf("DeriveNameMACKey regression: got %s, want locked %s", hex.EncodeToString(got), want)
	}
	if len(got) != 32 {
		t.Fatalf("the name-MAC key must be 32 bytes, got %d", len(got))
	}
	// It is keyed by the manifest subkey and salted by the runId; vary each.
	if bytes.Equal(got, DeriveNameMACKey(bytes.Repeat([]byte{0x00}, 32), katRun)) {
		t.Fatal("DeriveNameMACKey must bind the manifest subkey")
	}
	if bytes.Equal(got, DeriveNameMACKey(mk, bytes.Repeat([]byte{0xB3}, 16))) {
		t.Fatal("DeriveNameMACKey must bind the runId salt")
	}
}

func TestNameMACKnownAnswer(t *testing.T) {
	const want = "b6a038f8c091d843af4386ee49735ba4ec3fd81fcefe9a72429bc49e93209b916ae911c15fbd3eab47cf2df7abab8ab9"
	nameKey := DeriveNameMACKey(DeriveMK(katMaster, katRun), katRun)
	got := NameMAC(nameKey, "kv", "config/app.json")
	if hex.EncodeToString(got) != want {
		t.Fatalf("NameMAC regression: got %s, want locked %s", hex.EncodeToString(got), want)
	}
	if len(got) != 48 {
		t.Fatalf("the name MAC must be the 48-byte SHA-384 HMAC, got %d", len(got))
	}
	// The MAC binds the source type, a 0x00 separator and the name. The separator means
	// type||name boundaries cannot be shifted without changing the MAC: ("kv","x/y") and
	// ("kvx","/y") concatenate to the same bytes but for the separator, so they must
	// differ. This guards the keyed-name privacy property in SPEC 6.4.
	if bytes.Equal(got, NameMAC(nameKey, "kvconfig/app.json", "")) {
		t.Fatal("the 0x00 separator must keep the type/name boundary unambiguous")
	}
	if bytes.Equal(got, NameMAC(nameKey, "r2", "config/app.json")) {
		t.Fatal("NameMAC must bind the source type")
	}
	if bytes.Equal(got, NameMAC(nameKey, "kv", "config/app.jsox")) {
		t.Fatal("NameMAC must bind the name")
	}
	if bytes.Equal(got, NameMAC(bytes.Repeat([]byte{0x00}, 32), "kv", "config/app.json")) {
		t.Fatal("NameMAC must bind the name-MAC key")
	}
}

func TestDeriveManifestWrapKeyKnownAnswer(t *testing.T) {
	const want = "9c9406e2b8a459aa7be11c7d392213aaef050ae099442402dc106236b3ed4c83"
	mk := DeriveMK(katMaster, katRun)
	got := DeriveManifestWrapKey(mk, katRun, "shard-0001")
	if hex.EncodeToString(got) != want {
		t.Fatalf("DeriveManifestWrapKey regression: got %s, want locked %s", hex.EncodeToString(got), want)
	}
	if len(got) != 32 {
		t.Fatalf("the manifest-wrap key must be 32 bytes, got %d", len(got))
	}
	// The shard id is appended to the info string after a 0x00 separator, so a different
	// shard must give a different wrap key under the same subkey and run.
	if bytes.Equal(got, DeriveManifestWrapKey(mk, katRun, "shard-0002")) {
		t.Fatal("DeriveManifestWrapKey must bind the shard id")
	}
	if bytes.Equal(got, DeriveManifestWrapKey(mk, bytes.Repeat([]byte{0xB3}, 16), "shard-0001")) {
		t.Fatal("DeriveManifestWrapKey must bind the runId salt")
	}
	if bytes.Equal(got, DeriveManifestWrapKey(bytes.Repeat([]byte{0x00}, 32), katRun, "shard-0001")) {
		t.Fatal("DeriveManifestWrapKey must bind the manifest subkey")
	}
}

// HybridKEMCombine is the hybrid-KEM combiner in isolation (SPEC 14.6). The vector
// pins the byte-exact derivation so a second implementation, or a future refactor, can
// be caught if the combiner's IKM order (ssM||ssX), the label, or the ctX||pkX binding
// changes. Inputs are fixed bytes; in a real run ssX is 32 bytes, ctX and pkX are the
// 32-byte X25519 share and recipient key, and ssM is the 32-byte ML-KEM secret.
func TestHybridKEMCombineKnownAnswer(t *testing.T) {
	const want = "1713807ad1920ce6dc30a973cc87a5f2212dd0bb0fe3262d94a08ab6f555624f"
	ssM := bytes.Repeat([]byte{0x01}, 32)
	ssX := bytes.Repeat([]byte{0x02}, 32)
	ctX := bytes.Repeat([]byte{0x03}, 32)
	pkX := bytes.Repeat([]byte{0x04}, 32)
	got := HybridKEMCombine(ssM, ssX, ctX, pkX)
	if hex.EncodeToString(got) != want {
		t.Fatalf("HybridKEMCombine regression: got %s, want locked %s", hex.EncodeToString(got), want)
	}
	if len(got) != 32 {
		t.Fatalf("the combined shared secret must be 32 bytes, got %d", len(got))
	}
	// Every input is bound. Swapping ssM and ssX must change the output (proves the IKM
	// is ordered, not a set), and varying each of the four arguments must move it.
	if bytes.Equal(got, HybridKEMCombine(ssX, ssM, ctX, pkX)) {
		t.Fatal("the combiner IKM order ssM||ssX must be significant")
	}
	for i, args := range [][4][]byte{
		{bytes.Repeat([]byte{0x11}, 32), ssX, ctX, pkX},
		{ssM, bytes.Repeat([]byte{0x12}, 32), ctX, pkX},
		{ssM, ssX, bytes.Repeat([]byte{0x13}, 32), pkX},
		{ssM, ssX, ctX, bytes.Repeat([]byte{0x14}, 32)},
	} {
		if bytes.Equal(got, HybridKEMCombine(args[0], args[1], args[2], args[3])) {
			t.Fatalf("the combiner must bind argument %d", i)
		}
	}
}

// SignerFingerprint labels the operator-pinned signer (SPEC 11.4). The verifier here is
// fully deterministic: an Ed25519 public key from a fixed seed and an ML-DSA-87 public
// key from a fixed seed, so the fingerprint is a stable regression vector over the real
// SHA-384(MarshalVerifier(v)) computation.
func TestSignerFingerprintKnownAnswer(t *testing.T) {
	const want = "edmldsa1:9ea2286cebc922c70e1e8e46d85746821b5491f973c05ad5daee8f24de54d8cde2adab3f2ebaa38fe5955e00a1014189"
	v := katFixedVerifier(t)
	got := SignerFingerprint(v)
	if got != want {
		t.Fatalf("SignerFingerprint regression: got %s, want locked %s", got, want)
	}
	// The fingerprint must move if either public half changes, so neither half can be
	// swapped without the label changing (it covers ed25519||ml-dsa, not just one).
	edOther := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x08}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if SignerFingerprint(&HybridVerifier{Ed: edOther, MLDSA: v.MLDSA}) == got {
		t.Fatal("SignerFingerprint must bind the Ed25519 half")
	}
	mPrivOther, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), bytes.Repeat([]byte{0x0a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if SignerFingerprint(&HybridVerifier{Ed: v.Ed, MLDSA: mPrivOther.PublicKey()}) == got {
		t.Fatal("SignerFingerprint must bind the ML-DSA-87 half")
	}
}

// katFixedVerifier builds the deterministic hybrid verifier used by the fingerprint
// vector: Ed25519 from a fixed 32-byte seed, ML-DSA-87 from a fixed 32-byte seed.
func katFixedVerifier(t *testing.T) *HybridVerifier {
	t.Helper()
	edPub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x07}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	mPriv, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), bytes.Repeat([]byte{0x09}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return &HybridVerifier{Ed: edPub, MLDSA: mPriv.PublicKey()}
}
