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

const (
	// maxClients caps the number of registered clients to prevent
	// unbounded growth from unauthenticated registration requests.
	maxClients = 100

	// csrfExpiry controls how long a CSRF token remains valid.
	csrfExpiry = 10 * time.Minute

	// cleanupInterval controls how often expired entries are reaped.
	cleanupInterval = 5 * time.Minute
)

// csrfEntry tracks a CSRF token with its expiry time.
type csrfEntry struct {
	expiresAt time.Time
}

// Store holds all in-memory OAuth state.
type Store struct {
	mu      sync.RWMutex
	codes   map[string]*AuthCode   // code -> AuthCode
	tokens  map[string]*TokenInfo  // token -> TokenInfo
	clients map[string]*ClientInfo // client_id -> ClientInfo
	csrf    map[string]csrfEntry   // csrf token -> expiry
	stopGC  chan struct{}

	// registrationTimes tracks recent registration timestamps for
	// rate limiting unauthenticated /oauth/register requests.
	registrationTimes []time.Time
}

// NewStore creates an empty OAuth store and starts a background
// goroutine that periodically removes expired tokens and codes.
// Call Stop() to clean up the goroutine.
func NewStore() *Store {
	s := &Store{
		codes:   make(map[string]*AuthCode),
		tokens:  make(map[string]*TokenInfo),
		clients: make(map[string]*ClientInfo),
		csrf:    make(map[string]csrfEntry),
		stopGC:  make(chan struct{}),
	}
	go s.gcLoop()
	return s
}

// Stop terminates the background cleanup goroutine.
func (s *Store) Stop() {
	close(s.stopGC)
}

// gcLoop periodically removes expired tokens, codes, and CSRF tokens.
func (s *Store) gcLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stopGC:
			return
		}
	}
}

// cleanup removes all expired entries from the store.
func (s *Store) cleanup() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	for k, ac := range s.codes {
		if now.After(ac.ExpiresAt) {
			delete(s.codes, k)
		}
	}
	for k, ti := range s.tokens {
		if now.After(ti.ExpiresAt) {
			delete(s.tokens, k)
		}
	}
	for k, entry := range s.csrf {
		if now.After(entry.expiresAt) {
			delete(s.csrf, k)
		}
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

// RegistrationAllowed checks whether a new registration is allowed under
// the rate limit (10 registrations per minute). Returns false if the
// limit is exceeded.
func (s *Store) RegistrationAllowed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	window := now.Add(-1 * time.Minute)

	// Prune entries older than the window.
	valid := s.registrationTimes[:0]
	for _, t := range s.registrationTimes {
		if t.After(window) {
			valid = append(valid, t)
		}
	}
	s.registrationTimes = valid

	if len(s.registrationTimes) >= 10 {
		return false
	}
	s.registrationTimes = append(s.registrationTimes, now)
	return true
}

// RegisterClient stores a new client registration. Returns false if the
// maximum number of registered clients has been reached.
func (s *Store) RegisterClient(ci *ClientInfo) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.clients) >= maxClients {
		return false
	}
	s.clients[ci.ClientID] = ci
	return true
}

// GetClient returns the client info for a given client_id, or nil.
func (s *Store) GetClient(clientID string) *ClientInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clients[clientID]
}

// SaveCSRF stores a CSRF token with a fixed expiry.
func (s *Store) SaveCSRF(token string) {
	s.mu.Lock()
	s.csrf[token] = csrfEntry{expiresAt: time.Now().Add(csrfExpiry)}
	s.mu.Unlock()
}

// ConsumeCSRF retrieves and deletes a CSRF token.
// Returns false if the token is not found, empty, or expired.
func (s *Store) ConsumeCSRF(token string) bool {
	if token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.csrf[token]
	if !ok {
		return false
	}
	delete(s.csrf, token)
	return time.Now().Before(entry.expiresAt)
}

// RandomHex generates a cryptographically random hex string of the given byte length.
func RandomHex(byteLen int) string {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
