// Package auth implements OAuth 2.1 authorization for the MCP server.
// It acts as both the authorization server and resource server.
// All state is in-memory; tokens are invalidated on restart.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// AuthCode represents a pending authorization code.
type AuthCode struct {
	Code          string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	UserID        string
	Scopes        []string
	ExpiresAt     time.Time
}

// TokenInfo represents an issued access token.
type TokenInfo struct {
	Token     string
	UserID    string
	Scopes    []string
	ExpiresAt time.Time
}

// ClientInfo represents a dynamically registered client.
type ClientInfo struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
}

// Store holds all in-memory OAuth state.
type Store struct {
	mu      sync.RWMutex
	codes   map[string]*AuthCode   // code -> AuthCode
	tokens  map[string]*TokenInfo  // token -> TokenInfo
	clients map[string]*ClientInfo // client_id -> ClientInfo
}

// NewStore creates an empty OAuth store.
func NewStore() *Store {
	return &Store{
		codes:   make(map[string]*AuthCode),
		tokens:  make(map[string]*TokenInfo),
		clients: make(map[string]*ClientInfo),
	}
}

// SaveCode stores an authorization code.
func (s *Store) SaveCode(ac *AuthCode) {
	s.mu.Lock()
	s.codes[ac.Code] = ac
	s.mu.Unlock()
}

// ConsumeCode retrieves and deletes an authorization code.
// Returns nil if not found or expired.
func (s *Store) ConsumeCode(code string) *AuthCode {
	s.mu.Lock()
	defer s.mu.Unlock()

	ac, ok := s.codes[code]
	if !ok {
		return nil
	}
	delete(s.codes, code)

	if time.Now().After(ac.ExpiresAt) {
		return nil
	}
	return ac
}

// SaveToken stores an access token.
func (s *Store) SaveToken(ti *TokenInfo) {
	s.mu.Lock()
	s.tokens[ti.Token] = ti
	s.mu.Unlock()
}

// ValidateToken checks if a token is valid and not expired.
// Returns nil if invalid.
func (s *Store) ValidateToken(token string) *TokenInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ti, ok := s.tokens[token]
	if !ok {
		return nil
	}
	if time.Now().After(ti.ExpiresAt) {
		return nil
	}
	return ti
}

// RegisterClient stores a new client registration.
func (s *Store) RegisterClient(ci *ClientInfo) {
	s.mu.Lock()
	s.clients[ci.ClientID] = ci
	s.mu.Unlock()
}

// GetClient returns the client info for a given client_id, or nil.
func (s *Store) GetClient(clientID string) *ClientInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clients[clientID]
}

// RandomHex generates a cryptographically random hex string of the given byte length.
func RandomHex(byteLen int) string {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
