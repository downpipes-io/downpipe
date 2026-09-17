package custody

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func encodeB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// sealTestEnvelope mirrors the console's envelope seal (AES-256-GCM, 12-byte IV, tag
// appended, no additional data) so the open path is proven against genuine seals.
func sealTestEnvelope(t *testing.T, key, plaintext []byte) *EnvelopeFile {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, GCMIVBytes)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	return &EnvelopeFile{IV: iv, Ciphertext: aead.Seal(nil, iv, plaintext, nil)}
}
