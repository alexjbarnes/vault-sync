package obsidian

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"

	aessiv "github.com/jedisct1/go-aes-siv"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"
)

const (
	// scryptN is the CPU/memory cost parameter for scrypt key derivation (2^15).
	scryptN = 32768

	// scryptR is the block size parameter for scrypt key derivation.
	scryptR = 8

	// scryptP is the parallelization parameter for scrypt key derivation.
	scryptP = 1

	// scryptKeyLen is the derived key length in bytes.
	scryptKeyLen = 32

	// hkdfKeyLen is the output length for HKDF-derived subkeys (32 bytes / 256 bits).
	hkdfKeyLen = 32

	// sivTagLen is the AES-SIV authentication tag length in bytes (128 bits).
	sivTagLen = 16

	// MinEncryptionV3 is the lowest encryption version that uses the V3 cipher.
	MinEncryptionV3 = 2
)

// DeriveKey derives a 32-byte encryption key from password and salt using scrypt.
// Parameters: N=32768, r=8, p=1. Both inputs are normalized to NFKC before hashing.
func DeriveKey(password, salt string) ([]byte, error) {
	password = norm.NFKC.String(password)
	salt = norm.NFKC.String(salt)

	key, err := scrypt.Key([]byte(password), []byte(salt), scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, fmt.Errorf("deriving key: %w", err)
	}

	return key, nil
}

// KeyHash computes the keyhash for encryption version 0.
// This is hex(SHA-256(key)) and is sent to the server during init
// to verify the client has the correct encryption password.
func KeyHash(key []byte) string {
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:])
}

// CipherV0 handles encryption and decryption for vault encryption version 0.
// Path encryption uses deterministic AES-GCM (IV derived from plaintext hash).
// Content encryption uses AES-GCM with random IV prepended to ciphertext.
// Both formats store data as [12-byte IV][ciphertext+GCM tag].
type CipherV0 struct {
	gcm cipher.AEAD
}

// NewCipherV0 creates a v0 cipher from a 32-byte key.
func NewCipherV0(key []byte) (*CipherV0, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	return &CipherV0{gcm: gcm}, nil
}

// ZeroKey overwrites the key material in the given slice. Call this
// immediately after passing the key to NewCipherV0 to limit the window
// during which raw key bytes are accessible in memory.
func ZeroKey(key []byte) {
	for i := range key {
		key[i] = 0
	}
}

// DecryptPath decodes a hex-encoded encrypted path string.
// Format: hex([12-byte IV][ciphertext+tag])
func (c *CipherV0) DecryptPath(hexStr string) (string, error) {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", fmt.Errorf("decoding hex: %w", err)
	}

	plaintext, err := c.decrypt(data)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// DecryptContent decrypts file content.
// Format: [12-byte IV][ciphertext+tag]
func (c *CipherV0) DecryptContent(data []byte) ([]byte, error) {
	return c.decrypt(data)
}

// EncryptPath encrypts a path string using deterministic AES-GCM.
// The IV is derived from SHA-256(plaintext)[0:12], making identical paths
// produce identical ciphertext. Returns hex-encoded [IV][ciphertext+tag].
func (c *CipherV0) EncryptPath(path string) (string, error) {
	plaintext := []byte(path)
	h := sha256.Sum256(plaintext)
	iv := h[:c.gcm.NonceSize()]
	ciphertext := c.gcm.Seal(nil, iv, plaintext, nil)
	result := make([]byte, len(iv)+len(ciphertext))
	copy(result, iv)
	copy(result[len(iv):], ciphertext)

	return hex.EncodeToString(result), nil
}

// EncryptContent encrypts file content with a random IV.
// Returns [12-byte IV][ciphertext+tag].
func (c *CipherV0) EncryptContent(data []byte) ([]byte, error) {
	iv := make([]byte, c.gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("generating IV: %w", err)
	}

	ciphertext := c.gcm.Seal(nil, iv, data, nil)
	result := make([]byte, len(iv)+len(ciphertext))
	copy(result, iv)
	copy(result[len(iv):], ciphertext)

	return result, nil
}

func (c *CipherV0) decrypt(data []byte) ([]byte, error) {
	nonceSize := c.gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes", len(data))
	}
	// Empty content is transmitted as nonce-only payloads (12 bytes) with
	// no ciphertext or auth tag. Valid GCM-encrypted empty content would
	// be 28 bytes (12 nonce + 16 auth tag), so 12 bytes has no tag to
	// verify. Return empty for compatibility.
	if len(data) == nonceSize {
		return []byte{}, nil
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := c.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}

// Cipher is the interface implemented by all vault encryption versions.
// The sync and reconciliation layers use this interface so they remain
// agnostic to which version is in use for a given vault.
type Cipher interface {
	// EncryptPath encrypts a plaintext path deterministically and returns a hex string.
	EncryptPath(path string) (string, error)
	// DecryptPath decodes a hex-encoded encrypted path and returns the plaintext.
	DecryptPath(hexStr string) (string, error)
	// EncryptContent encrypts raw file content and returns ciphertext bytes.
	EncryptContent(data []byte) ([]byte, error)
	// DecryptContent decrypts raw ciphertext bytes and returns the plaintext.
	DecryptContent(data []byte) ([]byte, error)
}

// KeyHashV3 computes the keyhash for encryption versions 2 and 3.
//
// Obsidian derives the keyhash via HKDF-SHA256:
//
//	HKDF(ikm=scryptKey, salt=vaultSalt, info="ObsidianKeyHash") → 32 bytes → hex
//
// This differs from version 0 (plain SHA-256 of the key) and is used during
// the WebSocket init handshake to prove the client holds the correct password.
// The salt is NFKC-normalised before use, consistent with DeriveKey.
func KeyHashV3(key []byte, salt string) (string, error) {
	saltBytes := []byte(norm.NFKC.String(salt))

	derived, err := hkdfDeriveKey(key, saltBytes, []byte("ObsidianKeyHash"), hkdfKeyLen)
	if err != nil {
		return "", fmt.Errorf("deriving v3 keyhash: %w", err)
	}

	return hex.EncodeToString(derived), nil
}

// CipherV3 handles encryption and decryption for vault encryption versions 2 and 3.
//
// All keys are derived from the 32-byte scrypt key via HKDF-SHA256:
//
//   - Path encryption: AES-SIV-CMAC (RFC 5297).
//     mac_key = HKDF(ikm=key, salt=vaultSalt, info="ObsidianAesSivMac") 32 B
//     enc_key = HKDF(ikm=key, salt=vaultSalt, info="ObsidianAesSivEnc") 32 B
//     siv_key = mac_key ‖ enc_key  (64 B composite key for siv.NewCMAC)
//     Format:  hex([16-byte SIV tag][ciphertext])
//
//   - Content encryption: AES-256-GCM with a random 12-byte IV.
//     gcm_key = HKDF(ikm=key, salt=nil, info="ObsidianAesGcm") 32 B
//     Format:  [12-byte IV][ciphertext+GCM tag]
//
// AES-SIV provides deterministic authenticated encryption without a nonce,
// which is why it is used for paths (the same path must always encrypt to the
// same ciphertext so the server can track renames). Content uses a random IV
// so identical file content produces different ciphertext each time it is
// uploaded.
type CipherV3 struct {
	sivCipher cipher.AEAD // AES-SIV-CMAC for deterministic path encryption
	gcm       cipher.AEAD // AES-GCM for content encryption
}

// NewCipherV3 creates a CipherV3 from the 32-byte scrypt key and the vault
// salt string returned by the Obsidian API. The salt is NFKC-normalised
// before use. All derived key material is zeroed after the cipher objects
// are constructed.
func NewCipherV3(key []byte, salt string) (*CipherV3, error) {
	if len(key) != scryptKeyLen {
		return nil, fmt.Errorf("invalid key length %d: expected %d bytes", len(key), scryptKeyLen)
	}

	saltBytes := []byte(norm.NFKC.String(salt))

	macKey, err := hkdfDeriveKey(key, saltBytes, []byte("ObsidianAesSivMac"), hkdfKeyLen)
	if err != nil {
		return nil, fmt.Errorf("deriving SIV mac key: %w", err)
	}

	encKey, err := hkdfDeriveKey(key, saltBytes, []byte("ObsidianAesSivEnc"), hkdfKeyLen)
	if err != nil {
		return nil, fmt.Errorf("deriving SIV enc key: %w", err)
	}

	// aessiv.New expects a 64-byte composite key: [mac_key(32) || enc_key(32)].
	sivKey := append(macKey, encKey...) //nolint:gocritic

	sivCipher, err := aessiv.New(sivKey)
	if err != nil {
		return nil, fmt.Errorf("creating AES-SIV cipher: %w", err)
	}

	gcmKey, err := hkdfDeriveKey(key, nil, []byte("ObsidianAesGcm"), hkdfKeyLen)
	if err != nil {
		return nil, fmt.Errorf("deriving GCM key: %w", err)
	}

	block, err := aes.NewCipher(gcmKey)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcmCipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	// Zero all derived key material — the cipher objects retain copies internally.
	subtle.ConstantTimeCopy(1, sivKey, make([]byte, len(sivKey)))
	subtle.ConstantTimeCopy(1, macKey, make([]byte, len(macKey)))
	subtle.ConstantTimeCopy(1, encKey, make([]byte, len(encKey)))
	subtle.ConstantTimeCopy(1, gcmKey, make([]byte, len(gcmKey)))

	return &CipherV3{sivCipher: sivCipher, gcm: gcmCipher}, nil
}

// hkdfDeriveKey derives keyLen bytes using HKDF-SHA256 with the given IKM,
// salt, and info parameters.
func hkdfDeriveKey(ikm, salt, info []byte, keyLen int) ([]byte, error) {
	r := hkdf.New(sha256.New, ikm, salt, info)

	out := make([]byte, keyLen)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}

	return out, nil
}

// EncryptPath encrypts a path using AES-SIV-CMAC (deterministic, no nonce).
// Returns hex-encoded [16-byte SIV tag][ciphertext].
func (c *CipherV3) EncryptPath(path string) (string, error) {
	ct := c.sivCipher.Seal(nil, nil, []byte(path), nil)
	return hex.EncodeToString(ct), nil
}

// DecryptPath decodes a hex-encoded AES-SIV-CMAC encrypted path.
// Expects at least 16 bytes (SIV tag) after hex decoding.
func (c *CipherV3) DecryptPath(hexStr string) (string, error) {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", fmt.Errorf("decoding hex: %w", err)
	}

	if len(data) < sivTagLen {
		return "", fmt.Errorf("ciphertext too short: %d bytes", len(data))
	}

	plain, err := c.sivCipher.Open(nil, nil, data, nil)
	if err != nil {
		return "", fmt.Errorf("decrypting path: %w", err)
	}

	return string(plain), nil
}

// EncryptContent encrypts file content using AES-GCM with a random 12-byte IV.
// Returns [12-byte IV][ciphertext+GCM tag].
func (c *CipherV3) EncryptContent(data []byte) ([]byte, error) {
	iv := make([]byte, c.gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("generating IV: %w", err)
	}

	ct := c.gcm.Seal(nil, iv, data, nil)
	result := make([]byte, len(iv)+len(ct))
	copy(result, iv)
	copy(result[len(iv):], ct)

	return result, nil
}

// DecryptContent decrypts AES-GCM encrypted file content.
// Format: [12-byte IV][ciphertext+GCM tag].
// A payload of exactly 12 bytes (nonce only, no ciphertext) is treated as
// empty content, consistent with the protocol's empty-file wire format.
func (c *CipherV3) DecryptContent(data []byte) ([]byte, error) {
	nonceSize := c.gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes", len(data))
	}

	if len(data) == nonceSize {
		return []byte{}, nil
	}

	plain, err := c.gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting content: %w", err)
	}

	return plain, nil
}
