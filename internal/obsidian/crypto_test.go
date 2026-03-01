package obsidian

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKey returns a deterministic 32-byte key for testing.
func testKey() []byte {
	h := sha256.Sum256([]byte("test-password"))
	return h[:]
}

func testCipher(t *testing.T) *CipherV0 {
	t.Helper()

	c, err := NewCipherV0(testKey())
	require.NoError(t, err)

	return c
}

// --- DeriveKey tests ---

func TestDeriveKey_Deterministic(t *testing.T) {
	k1, err := DeriveKey("password", "salt@example.com")
	require.NoError(t, err)
	assert.Len(t, k1, 32)

	k2, err := DeriveKey("password", "salt@example.com")
	require.NoError(t, err)
	assert.Equal(t, k1, k2, "same inputs must produce same key")
}

func TestDeriveKey_DifferentPasswordsDifferentKeys(t *testing.T) {
	k1, err := DeriveKey("password1", "salt")
	require.NoError(t, err)

	k2, err := DeriveKey("password2", "salt")
	require.NoError(t, err)
	assert.NotEqual(t, k1, k2)
}

func TestDeriveKey_DifferentSaltsDifferentKeys(t *testing.T) {
	k1, err := DeriveKey("password", "salt1")
	require.NoError(t, err)

	k2, err := DeriveKey("password", "salt2")
	require.NoError(t, err)
	assert.NotEqual(t, k1, k2)
}

func TestDeriveKey_NFKCNormalization(t *testing.T) {
	// Protocol doc line 96-97: password and salt must be NFKC-normalized.
	// The fullwidth 'A' (U+FF21) normalizes to ASCII 'A' under NFKC.
	k1, err := DeriveKey("\uFF21", "salt")
	require.NoError(t, err)

	k2, err := DeriveKey("A", "salt")
	require.NoError(t, err)
	assert.Equal(t, k1, k2, "NFKC-equivalent passwords must derive the same key")
}

func TestDeriveKey_NFKCSaltNormalization(t *testing.T) {
	// Salt is typically the user's email. Non-ASCII characters must be
	// NFKC-normalized too.
	k1, err := DeriveKey("pw", "\uFF21@example.com")
	require.NoError(t, err)

	k2, err := DeriveKey("pw", "A@example.com")
	require.NoError(t, err)
	assert.Equal(t, k1, k2, "NFKC-equivalent salts must derive the same key")
}

func TestDeriveKey_UnicodeAccents(t *testing.T) {
	// e-acute can be represented as U+00E9 (precomposed) or U+0065 U+0301
	// (decomposed). NFKC normalizes both to U+00E9.
	k1, err := DeriveKey("\u00E9", "salt")
	require.NoError(t, err)

	k2, err := DeriveKey("e\u0301", "salt")
	require.NoError(t, err)
	assert.Equal(t, k1, k2, "composed and decomposed accents must derive the same key")
}

// --- KeyHash tests ---

func TestKeyHash_Deterministic(t *testing.T) {
	key := testKey()
	h1 := KeyHash(key)
	h2 := KeyHash(key)
	assert.Equal(t, h1, h2)
	assert.Len(t, h1, 64, "SHA-256 hex is 64 characters")
}

func TestKeyHash_MatchesManualSHA256(t *testing.T) {
	key := testKey()
	h := sha256.Sum256(key)
	expected := hex.EncodeToString(h[:])
	assert.Equal(t, expected, KeyHash(key))
}

// --- NewCipherV0 tests ---

func TestNewCipherV0_ValidKey(t *testing.T) {
	c, err := NewCipherV0(testKey())
	require.NoError(t, err)
	assert.NotNil(t, c)
}

func TestNewCipherV0_InvalidKeyLength(t *testing.T) {
	_, err := NewCipherV0([]byte("too-short"))
	assert.Error(t, err)
}

// --- Path encryption round-trip tests ---

func TestPathEncryptDecrypt_RoundTrip(t *testing.T) {
	c := testCipher(t)

	paths := []string{
		"notes/hello.md",
		".obsidian/app.json",
		"folder/subfolder/deep/file.txt",
		"file with spaces.md",
		"unicode/\u00E9\u00E0\u00FC.md",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			enc, err := c.EncryptPath(path)
			require.NoError(t, err)
			assert.NotEmpty(t, enc)

			dec, err := c.DecryptPath(enc)
			require.NoError(t, err)
			assert.Equal(t, path, dec)
		})
	}
}

func TestPathEncrypt_Deterministic(t *testing.T) {
	// Protocol doc line 118: path encryption uses deterministic AES-GCM.
	// Same plaintext must always produce the same ciphertext.
	c := testCipher(t)

	enc1, err := c.EncryptPath("notes/hello.md")
	require.NoError(t, err)

	enc2, err := c.EncryptPath("notes/hello.md")
	require.NoError(t, err)

	assert.Equal(t, enc1, enc2, "path encryption must be deterministic")
}

func TestPathEncrypt_DifferentPathsDifferentCiphertext(t *testing.T) {
	c := testCipher(t)

	enc1, err := c.EncryptPath("file1.md")
	require.NoError(t, err)

	enc2, err := c.EncryptPath("file2.md")
	require.NoError(t, err)

	assert.NotEqual(t, enc1, enc2)
}

func TestPathEncrypt_OutputIsHex(t *testing.T) {
	c := testCipher(t)

	enc, err := c.EncryptPath("test.md")
	require.NoError(t, err)

	_, err = hex.DecodeString(enc)
	assert.NoError(t, err, "encrypted path must be valid hex")
}

func TestPathDecrypt_InvalidHex(t *testing.T) {
	c := testCipher(t)

	_, err := c.DecryptPath("not-hex!")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding hex")
}

func TestPathDecrypt_WrongKey(t *testing.T) {
	c1 := testCipher(t)
	enc, err := c1.EncryptPath("secret.md")
	require.NoError(t, err)

	wrongKey := sha256.Sum256([]byte("wrong-password"))
	c2, err := NewCipherV0(wrongKey[:])
	require.NoError(t, err)

	_, err = c2.DecryptPath(enc)
	assert.Error(t, err, "decryption with wrong key must fail")
}

func TestPathDecrypt_TooShort(t *testing.T) {
	c := testCipher(t)
	// Less than 12 bytes (nonce size) when decoded.
	_, err := c.DecryptPath(hex.EncodeToString([]byte{0x01, 0x02, 0x03}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

func TestPathEncrypt_EmptyPath(t *testing.T) {
	c := testCipher(t)

	enc, err := c.EncryptPath("")
	require.NoError(t, err)

	dec, err := c.DecryptPath(enc)
	require.NoError(t, err)
	assert.Empty(t, dec)
}

// --- Content encryption round-trip tests ---

func TestContentEncryptDecrypt_RoundTrip(t *testing.T) {
	c := testCipher(t)

	contents := [][]byte{
		[]byte("Hello, world!"),
		[]byte("# Markdown\n\nSome content with special chars: \u00E9\u00E0\u00FC"),
		bytes.Repeat([]byte("x"), 10000),
		{0x00, 0xFF, 0x80}, // binary content
	}

	for i, content := range contents {
		t.Run("", func(t *testing.T) {
			enc, err := c.EncryptContent(content)
			require.NoError(t, err)
			assert.Greater(t, len(enc), len(content), "encrypted content must be larger (IV + tag overhead)")

			dec, err := c.DecryptContent(enc)
			require.NoError(t, err)
			assert.Equal(t, content, dec, "case %d: content mismatch after round-trip", i)
		})
	}
}

func TestContentEncrypt_NonDeterministic(t *testing.T) {
	// Protocol doc line 119: content encryption uses random IV.
	c := testCipher(t)
	content := []byte("same content")

	enc1, err := c.EncryptContent(content)
	require.NoError(t, err)

	enc2, err := c.EncryptContent(content)
	require.NoError(t, err)

	assert.NotEqual(t, enc1, enc2, "content encryption must use random IV")
}

func TestContentDecrypt_WrongKey(t *testing.T) {
	c1 := testCipher(t)
	enc, err := c1.EncryptContent([]byte("secret data"))
	require.NoError(t, err)

	wrongKey := sha256.Sum256([]byte("wrong"))
	c2, err := NewCipherV0(wrongKey[:])
	require.NoError(t, err)

	_, err = c2.DecryptContent(enc)
	assert.Error(t, err)
}

func TestContentDecrypt_TooShort(t *testing.T) {
	c := testCipher(t)
	_, err := c.DecryptContent([]byte{0x01, 0x02, 0x03})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

func TestContentDecrypt_TamperedCiphertext(t *testing.T) {
	c := testCipher(t)

	enc, err := c.EncryptContent([]byte("important data"))
	require.NoError(t, err)

	// Flip a byte in the ciphertext portion (after the 12-byte IV).
	enc[15] ^= 0xFF

	_, err = c.DecryptContent(enc)
	assert.Error(t, err, "tampered ciphertext must fail GCM authentication")
}

// --- Empty content handling ---

func TestContentEncrypt_EmptyContent(t *testing.T) {
	// Empty content should be sent as zero bytes, not encrypted. Calling
	// encrypt on empty produces 28 bytes (12 IV + 16 GCM tag) which
	// differs from the expected 0-byte wire format. The caller is
	// responsible for skipping encryption on empty content. But if
	// someone does encrypt empty content, decrypt must handle it.
	c := testCipher(t)

	enc, err := c.EncryptContent([]byte{})
	require.NoError(t, err)
	// Should produce IV (12) + GCM tag (16) = 28 bytes.
	assert.Len(t, enc, 28, "encrypted empty content is 12-byte IV + 16-byte tag")

	// Round-trip must still work.
	dec, err := c.DecryptContent(enc)
	require.NoError(t, err)
	assert.Empty(t, dec)
}

func TestContentDecrypt_EmptyInput(t *testing.T) {
	// Protocol doc line 211: if encryptedContent.byteLength === 0,
	// skip decrypt and use empty content directly. Our code does not
	// call DecryptContent on empty input, but test the boundary anyway.
	c := testCipher(t)

	// Empty input is less than nonce size -- should error.
	_, err := c.DecryptContent([]byte{})
	assert.Error(t, err)
}

func TestContentDecrypt_ExactlyNonceSize(t *testing.T) {
	// If data.length == 12 (nonce size), return empty. Empty files are
	// transmitted as nonce-only payloads.
	c := testCipher(t)

	nonce := make([]byte, 12)
	dec, err := c.DecryptContent(nonce)
	require.NoError(t, err)
	assert.Empty(t, dec)
}

// --- Hash encryption round-trip test ---

func TestHashEncryptDecrypt_RoundTrip(t *testing.T) {
	// File hashes are encrypted with EncryptPath (deterministic) before
	// being sent to the server. Protocol doc lines 217-221.
	c := testCipher(t)

	content := []byte("file content")
	h := sha256.Sum256(content)
	plainHash := hex.EncodeToString(h[:])

	enc, err := c.EncryptPath(plainHash)
	require.NoError(t, err)

	dec, err := c.DecryptPath(enc)
	require.NoError(t, err)
	assert.Equal(t, plainHash, dec)
}

func TestHashEncrypt_Deterministic(t *testing.T) {
	// Same file content should always produce the same encrypted hash,
	// since both SHA-256 and path encryption are deterministic.
	c := testCipher(t)

	content := []byte("deterministic test")
	h := sha256.Sum256(content)
	plainHash := hex.EncodeToString(h[:])

	enc1, err := c.EncryptPath(plainHash)
	require.NoError(t, err)

	enc2, err := c.EncryptPath(plainHash)
	require.NoError(t, err)

	assert.Equal(t, enc1, enc2, "encrypted hashes must be deterministic")
}

// --- IV structure verification ---

func TestPathEncrypt_IVDerivedFromPlaintext(t *testing.T) {
	// Protocol doc line 118/170-171: IV = SHA-256(plaintext)[0:12].
	// Verify the encrypted output starts with the expected IV.
	c := testCipher(t)

	path := "notes/test.md"
	enc, err := c.EncryptPath(path)
	require.NoError(t, err)

	raw, err := hex.DecodeString(enc)
	require.NoError(t, err)

	h := sha256.Sum256([]byte(path))
	expectedIV := h[:12]
	actualIV := raw[:12]

	assert.Equal(t, expectedIV, actualIV, "IV must be SHA-256(plaintext)[0:12]")
}

func TestContentEncrypt_IVIs12Bytes(t *testing.T) {
	c := testCipher(t)

	enc, err := c.EncryptContent([]byte("data"))
	require.NoError(t, err)

	// First 12 bytes are the random IV. Total is 12 + len(plaintext) + 16 (GCM tag).
	assert.Len(t, enc, 12+4+16)
}

// =============================================================================
// Cipher interface compliance (compile-time)
// =============================================================================

// These assignments verify at compile time that both concrete types satisfy
// the Cipher interface. They produce no runtime overhead.
var (
	_ Cipher = (*CipherV0)(nil)
	_ Cipher = (*CipherV3)(nil)
)

// =============================================================================
// KeyHashV3 tests
// =============================================================================

// testSalt is the vault salt returned by the Obsidian API — a short random
// string used as HKDF salt input for versions 2 and 3.
const testSalt = "test-vault-salt"

func TestKeyHashV3_Deterministic(t *testing.T) {
	key := testKey()
	h1, err := KeyHashV3(key, testSalt)
	require.NoError(t, err)
	assert.Len(t, h1, 64, "HKDF-derived hash is 32 bytes → 64 hex chars")

	h2, err := KeyHashV3(key, testSalt)
	require.NoError(t, err)
	assert.Equal(t, h1, h2, "same inputs must produce same hash")
}

func TestKeyHashV3_DifferentSaltDifferentHash(t *testing.T) {
	key := testKey()
	h1, err := KeyHashV3(key, "salt-one")
	require.NoError(t, err)

	h2, err := KeyHashV3(key, "salt-two")
	require.NoError(t, err)
	assert.NotEqual(t, h1, h2)
}

func TestKeyHashV3_DiffersFromV0(t *testing.T) {
	// Version 3 uses HKDF, version 0 uses plain SHA-256. They must not collide.
	key := testKey()
	h0 := KeyHash(key)
	h3, err := KeyHashV3(key, testSalt)
	require.NoError(t, err)
	assert.NotEqual(t, h0, h3)
}

func TestKeyHashV3_NFKCSaltNormalization(t *testing.T) {
	// The fullwidth 'A' (U+FF21) normalizes to ASCII 'A' under NFKC.
	// The salt is NFKC-normalised in KeyHashV3, so both must produce the same hash.
	key := testKey()
	h1, err := KeyHashV3(key, "\uFF21")
	require.NoError(t, err)

	h2, err := KeyHashV3(key, "A")
	require.NoError(t, err)
	assert.Equal(t, h1, h2, "NFKC-equivalent salts must produce the same keyhash")
}

// =============================================================================
// CipherV3 constructor tests
// =============================================================================

func testCipherV3(t *testing.T) *CipherV3 {
	t.Helper()
	c, err := NewCipherV3(testKey(), testSalt)
	require.NoError(t, err)
	return c
}

func TestNewCipherV3_ValidKey(t *testing.T) {
	c, err := NewCipherV3(testKey(), testSalt)
	require.NoError(t, err)
	assert.NotNil(t, c)
}

func TestNewCipherV3_InvalidKeyLength(t *testing.T) {
	_, err := NewCipherV3([]byte("too-short"), testSalt)
	assert.Error(t, err)
}

// =============================================================================
// CipherV3 path encryption tests
// =============================================================================

func TestCipherV3Path_RoundTrip(t *testing.T) {
	c := testCipherV3(t)

	paths := []string{
		"notes/hello.md",
		".obsidian/app.json",
		"folder/subfolder/deep/file.txt",
		"file with spaces.md",
		"unicode/\u00E9\u00E0\u00FC.md",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			enc, err := c.EncryptPath(path)
			require.NoError(t, err)
			assert.NotEmpty(t, enc)

			dec, err := c.DecryptPath(enc)
			require.NoError(t, err)
			assert.Equal(t, path, dec)
		})
	}
}

func TestCipherV3Path_Deterministic(t *testing.T) {
	// AES-SIV is inherently deterministic: no nonce, same key+plaintext → same ciphertext.
	c := testCipherV3(t)

	enc1, err := c.EncryptPath("notes/hello.md")
	require.NoError(t, err)

	enc2, err := c.EncryptPath("notes/hello.md")
	require.NoError(t, err)

	assert.Equal(t, enc1, enc2, "path encryption must be deterministic")
}

func TestCipherV3Path_DifferentPathsDifferentCiphertext(t *testing.T) {
	c := testCipherV3(t)

	enc1, err := c.EncryptPath("file1.md")
	require.NoError(t, err)

	enc2, err := c.EncryptPath("file2.md")
	require.NoError(t, err)

	assert.NotEqual(t, enc1, enc2)
}

func TestCipherV3Path_OutputIsHex(t *testing.T) {
	c := testCipherV3(t)

	enc, err := c.EncryptPath("test.md")
	require.NoError(t, err)

	_, err = hex.DecodeString(enc)
	assert.NoError(t, err, "encrypted path must be valid hex")
}

func TestCipherV3Path_DecryptInvalidHex(t *testing.T) {
	c := testCipherV3(t)

	_, err := c.DecryptPath("not-hex!")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding hex")
}

func TestCipherV3Path_DecryptWrongKey(t *testing.T) {
	c1 := testCipherV3(t)
	enc, err := c1.EncryptPath("secret.md")
	require.NoError(t, err)

	// Different salt → entirely different SIV key → authentication failure.
	c2, err := NewCipherV3(testKey(), "different-salt")
	require.NoError(t, err)

	_, err = c2.DecryptPath(enc)
	assert.Error(t, err, "decryption with wrong key must fail")
}

func TestCipherV3Path_DecryptTooShort(t *testing.T) {
	c := testCipherV3(t)

	// AES-SIV tag is 16 bytes; anything shorter must be rejected.
	_, err := c.DecryptPath(hex.EncodeToString([]byte{0x01, 0x02, 0x03}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

func TestCipherV3Path_EmptyPath(t *testing.T) {
	c := testCipherV3(t)

	enc, err := c.EncryptPath("")
	require.NoError(t, err)

	dec, err := c.DecryptPath(enc)
	require.NoError(t, err)
	assert.Empty(t, dec)
}

// =============================================================================
// CipherV3 content encryption tests
// =============================================================================

func TestCipherV3Content_RoundTrip(t *testing.T) {
	c := testCipherV3(t)

	contents := [][]byte{
		[]byte("Hello, world!"),
		[]byte("# Markdown\n\nSome content with special chars: \u00E9\u00E0\u00FC"),
		bytes.Repeat([]byte("x"), 10000),
		{0x00, 0xFF, 0x80},
	}

	for i, content := range contents {
		t.Run("", func(t *testing.T) {
			enc, err := c.EncryptContent(content)
			require.NoError(t, err)

			dec, err := c.DecryptContent(enc)
			require.NoError(t, err)
			assert.Equal(t, content, dec, "case %d: content mismatch after round-trip", i)
		})
	}
}

func TestCipherV3Content_NonDeterministic(t *testing.T) {
	// Content encryption uses a random IV, so the same plaintext must produce
	// different ciphertext on each call.
	c := testCipherV3(t)
	content := []byte("same content")

	enc1, err := c.EncryptContent(content)
	require.NoError(t, err)

	enc2, err := c.EncryptContent(content)
	require.NoError(t, err)

	assert.NotEqual(t, enc1, enc2, "content encryption must use random IV")
}

func TestCipherV3Content_DecryptWrongKey(t *testing.T) {
	c1 := testCipherV3(t)
	enc, err := c1.EncryptContent([]byte("secret data"))
	require.NoError(t, err)

	// Use a different 32-byte scrypt key. GCM key is derived from the scrypt
	// key (not the vault salt), so the key must differ to trigger auth failure.
	wrongKey := make([]byte, 32)
	wrongKey[0] = 0xFF
	c2, err := NewCipherV3(wrongKey, testSalt)
	require.NoError(t, err)

	_, err = c2.DecryptContent(enc)
	assert.Error(t, err)
}

func TestCipherV3Content_DecryptTooShort(t *testing.T) {
	c := testCipherV3(t)
	_, err := c.DecryptContent([]byte{0x01, 0x02, 0x03})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

func TestCipherV3Content_DecryptExactlyNonceSize(t *testing.T) {
	// A 12-byte payload (nonce only, no ciphertext) represents empty file content.
	// This matches the protocol's empty-file wire format.
	c := testCipherV3(t)

	nonce := make([]byte, 12)
	dec, err := c.DecryptContent(nonce)
	require.NoError(t, err)
	assert.Empty(t, dec)
}

// =============================================================================
// CipherV3 hash encryption (via EncryptPath — same algorithm)
// =============================================================================

func TestCipherV3Hash_RoundTrip(t *testing.T) {
	// File hashes are encrypted with EncryptPath before being sent to the server.
	c := testCipherV3(t)

	content := []byte("file content")
	h := sha256.Sum256(content)
	plainHash := hex.EncodeToString(h[:])

	enc, err := c.EncryptPath(plainHash)
	require.NoError(t, err)

	dec, err := c.DecryptPath(enc)
	require.NoError(t, err)
	assert.Equal(t, plainHash, dec)
}
