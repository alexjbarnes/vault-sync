package obsidian

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"
)

const (
	// scryptN is the CPU/memory cost parameter for scrypt key derivation,
	// matching Obsidian's N=32768 (2^15).
	scryptN = 32768

	// scryptR is the block size parameter for scrypt key derivation.
	scryptR = 8

	// scryptP is the parallelization parameter for scrypt key derivation.
	scryptP = 1

	// scryptKeyLen is the derived key length in bytes.
	scryptKeyLen = 32
)

// DeriveKey derives a 32-byte encryption key from password and salt using scrypt.
// Parameters match Obsidian exactly: N=32768, r=8, p=1.
// Both inputs are normalized to NFKC before hashing, matching app.js behavior.
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
	// The Obsidian app returns empty content when the input is exactly
	// the nonce size (12 bytes). Valid GCM-encrypted empty content would
	// be 28 bytes (12 nonce + 16 auth tag), so 12 bytes has no tag to
	// verify. We match this behavior for compatibility -- empty files
	// sync as nonce-only payloads with no ciphertext or tag.
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
