// Package auth implements OAuth 2.1 authorization for the MCP server.
// It acts as both the authorization server and resource server.
// Tokens and client registrations are persisted in bbolt when a
// *state.State is provided; otherwise all state is in-memory only.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/models"
	"github.com/alexjbarnes/vault-sync/internal/state"
)

// Code represents a pending authorization code. Ephemeral, never persisted.
type Code struct {
	Code          string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Resource      string
	UserID        string
	Scopes        []string
	ExpiresAt     time.Time
}

const (
	// maxClients caps the number of registered clients to prevent
	// unbounded growth from unauthenticated registration requests.
	maxClients = 100

	// csrfExpiry controls how long a CSRF token remains valid.
	csrfExpiry = 10 * time.Minute

	// cleanupInterval controls how often expired entries are reaped.
	cleanupInterval = 5 * time.Minute

	// maxRegistrationsPerMinute caps the number of dynamic client
	// registrations allowed within a one-minute sliding window.
	maxRegistrationsPerMinute = 10
)

// csrfEntry tracks a CSRF token with its expiry and the OAuth
// parameters it was issued for, preventing cross-client reuse.
type csrfEntry struct {
	expiresAt   time.Time
	clientID    string
	redirectURI string
}

// Store holds all OAuth state. Tokens and clients are backed by bbolt
// when a persistence layer is provided; auth codes and CSRF tokens are
// always in-memory only.
type Store struct {
	mu      sync.RWMutex
	codes   map[string]*Code               // code -> Code
	tokens  map[string]*models.OAuthToken  // token -> OAuthToken
	clients map[string]*models.OAuthClient // client_id -> OAuthClient
	csrf    map[string]csrfEntry           // csrf token -> expiry
	stopGC  chan struct{}

	// registrationTimes tracks recent registration timestamps for
	// rate limiting unauthenticated /oauth/register requests.
	registrationTimes []time.Time

	// persist is the bbolt-backed state for tokens and clients.
	// Nil means in-memory only (used in tests).
	persist *state.State
	logger  *slog.Logger
}

// NewStore creates an OAuth store. If persist is non-nil, existing tokens
// and client registrations are loaded from bbolt and all mutations are
// written through. Pass nil for in-memory-only operation (tests).
func NewStore(persist *state.State, logger *slog.Logger) *Store {
	s := &Store{
		codes:   make(map[string]*Code),
		tokens:  make(map[string]*models.OAuthToken),
		clients: make(map[string]*models.OAuthClient),
		csrf:    make(map[string]csrfEntry),
		stopGC:  make(chan struct{}),
		persist: persist,
		logger:  logger,
	}

	if persist != nil {
		s.loadFromDisk()
	}

	go s.gcLoop()

	return s
}

// loadFromDisk populates the in-memory maps from bbolt.
func (s *Store) loadFromDisk() {
	now := time.Now()

	tokens, err := s.persist.AllOAuthTokens()
	if err != nil {
		s.logger.Warn("loading persisted OAuth tokens", slog.String("error", err.Error()))
	}

	for i := range tokens {
		t := tokens[i]
		if now.After(t.ExpiresAt) {
			_ = s.persist.DeleteOAuthToken(t.Token)
			continue
		}

		s.tokens[t.Token] = &t
	}

	clients, err := s.persist.AllOAuthClients()
	if err != nil {
		s.logger.Warn("loading persisted OAuth clients", slog.String("error", err.Error()))
	}

	for i := range clients {
		c := clients[i]
		s.clients[c.ClientID] = &c
	}

	s.logger.Info("loaded OAuth state from disk",
		slog.Int("tokens", len(s.tokens)),
		slog.Int("clients", len(s.clients)),
	)
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

	for k, t := range s.tokens {
		if now.After(t.ExpiresAt) {
			delete(s.tokens, k)

			if s.persist != nil {
				_ = s.persist.DeleteOAuthToken(k)
			}
		}
	}

	for k, entry := range s.csrf {
		if now.After(entry.expiresAt) {
			delete(s.csrf, k)
		}
	}
}

// SaveCode stores an authorization code.
func (s *Store) SaveCode(ac *Code) {
	s.mu.Lock()
	s.codes[ac.Code] = ac
	s.mu.Unlock()
}

// ConsumeCode retrieves and deletes an authorization code.
// Returns nil if not found or expired.
func (s *Store) ConsumeCode(code string) *Code {
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

// SaveToken stores a token in memory and persists it to disk.
func (s *Store) SaveToken(t *models.OAuthToken) {
	s.mu.Lock()
	s.tokens[t.Token] = t
	s.mu.Unlock()

	if s.persist != nil {
		if err := s.persist.SaveOAuthToken(*t); err != nil && s.logger != nil {
			s.logger.Warn("persisting OAuth token", slog.String("error", err.Error()))
		}
	}
}

// ValidateToken checks if an access token is valid and not expired.
// Returns nil if invalid. Refresh tokens are rejected.
func (s *Store) ValidateToken(token string) *models.OAuthToken {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, ok := s.tokens[token]
	if !ok {
		return nil
	}

	if time.Now().After(t.ExpiresAt) {
		return nil
	}
	// Reject refresh tokens used as bearer tokens.
	if t.Kind == "refresh" {
		return nil
	}

	return t
}

// ValidateRefreshToken checks if a refresh token is valid for the given
// client_id and resource. Returns nil if invalid.
func (s *Store) ValidateRefreshToken(token, clientID, resource string) *models.OAuthToken {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.validateRefreshTokenLocked(token, clientID, resource)
}

// validateRefreshTokenLocked performs refresh token validation without locking.
// Caller must hold at least s.mu.RLock().
func (s *Store) validateRefreshTokenLocked(token, clientID, resource string) *models.OAuthToken {
	t, ok := s.tokens[token]
	if !ok {
		return nil
	}

	if time.Now().After(t.ExpiresAt) {
		return nil
	}

	if t.Kind != "refresh" {
		return nil
	}
	// If the refresh token was issued to a specific client, require client_id match.
	// For tokens without ClientID (legacy), accept any client_id or none.
	if t.ClientID != "" {
		if clientID == "" || t.ClientID != clientID {
			return nil
		}
	}

	if resource != "" && strings.TrimRight(t.Resource, "/") != strings.TrimRight(resource, "/") {
		return nil
	}

	return t
}

// ConsumeRefreshToken atomically validates and deletes a refresh token.
// Returns nil if the token is invalid. This prevents TOCTOU races where
// two concurrent refresh requests could both succeed with the same token.
func (s *Store) ConsumeRefreshToken(token, clientID, resource string) *models.OAuthToken {
	s.mu.Lock()
	defer s.mu.Unlock()

	t := s.validateRefreshTokenLocked(token, clientID, resource)
	if t == nil {
		return nil
	}

	delete(s.tokens, token)

	if s.persist != nil {
		_ = s.persist.DeleteOAuthToken(token)
	}

	return t
}

// DeleteToken removes a token from the store and persistent storage.
func (s *Store) DeleteToken(token string) {
	s.mu.Lock()
	delete(s.tokens, token)
	s.mu.Unlock()

	if s.persist != nil {
		_ = s.persist.DeleteOAuthToken(token)
	}
}

// DeleteAccessTokenByRefreshToken removes the access token that was
// paired with the given refresh token. This ensures old access tokens
// are revoked when a refresh token is consumed.
func (s *Store) DeleteAccessTokenByRefreshToken(refreshToken string) {
	s.mu.Lock()

	var found string

	for k, t := range s.tokens {
		if t.Kind == "access" && t.RefreshToken == refreshToken {
			found = k

			break
		}
	}

	if found != "" {
		delete(s.tokens, found)
	}

	s.mu.Unlock()

	if found != "" && s.persist != nil {
		_ = s.persist.DeleteOAuthToken(found)
	}
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

	if len(s.registrationTimes) >= maxRegistrationsPerMinute {
		return false
	}

	s.registrationTimes = append(s.registrationTimes, now)

	return true
}

// RegisterClient stores a new client registration. Returns false if the
// maximum number of registered clients has been reached.
func (s *Store) RegisterClient(ci *models.OAuthClient) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.clients) >= maxClients {
		return false
	}

	s.clients[ci.ClientID] = ci

	if s.persist != nil {
		if err := s.persist.SaveOAuthClient(*ci); err != nil && s.logger != nil {
			s.logger.Warn("persisting OAuth client", slog.String("error", err.Error()))
		}
	}

	return true
}

// GetClient returns the client info for a given client_id, or nil.
func (s *Store) GetClient(clientID string) *models.OAuthClient {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.clients[clientID]
}

// SaveCSRF stores a CSRF token bound to specific OAuth parameters.
func (s *Store) SaveCSRF(token, clientID, redirectURI string) {
	s.mu.Lock()
	s.csrf[token] = csrfEntry{
		expiresAt:   time.Now().Add(csrfExpiry),
		clientID:    clientID,
		redirectURI: redirectURI,
	}
	s.mu.Unlock()
}

// ConsumeCSRF retrieves and deletes a CSRF token. Returns false if
// the token is invalid, expired, or was issued for different OAuth
// parameters than those provided.
func (s *Store) ConsumeCSRF(token, clientID, redirectURI string) bool {
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

	if time.Now().After(entry.expiresAt) {
		return false
	}

	return entry.clientID == clientID && entry.redirectURI == redirectURI
}

// ValidateClientSecret checks the provided secret against the stored
// SHA-256 hash for the given client. Returns false if the client does
// not exist or has no secret hash.
//
// The stored hash is read under the lock, then the comparison happens
// outside the lock to avoid holding it during the hash computation.
// A dummy hash is used for missing clients so the code path (hash +
// constant-time compare) is identical regardless of client existence.
func (s *Store) ValidateClientSecret(clientID, secret string) bool {
	s.mu.RLock()

	storedHash := ""
	if client, ok := s.clients[clientID]; ok {
		storedHash = client.SecretHash
	}

	s.mu.RUnlock()

	if storedHash == "" {
		// Use a dummy hash so the code path is identical to a real
		// comparison (hash + constant-time compare). The dummy never
		// matches any real hash.
		storedHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	computed := HashSecret(secret)

	return subtle.ConstantTimeCompare([]byte(computed), []byte(storedHash)) == 1
}

// RegisterPreConfiguredClient stores a pre-configured client (from
// MCP_CLIENT_CREDENTIALS) with its secret hash and grant types. Unlike
// RegisterClient, this bypasses the maxClients cap since pre-configured
// clients are operator-managed.
func (s *Store) RegisterPreConfiguredClient(client *models.OAuthClient) {
	s.mu.Lock()
	s.clients[client.ClientID] = client
	s.mu.Unlock()

	if s.persist != nil {
		if err := s.persist.SaveOAuthClient(*client); err != nil && s.logger != nil {
			s.logger.Warn("persisting pre-configured client", slog.String("error", err.Error()))
		}
	}
}

// HashSecret returns the hex-encoded SHA-256 hash of a secret string.
func HashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// ClientAllowsGrant checks whether the client is permitted to use the
// given grant type. Clients without explicit GrantTypes default to
// authorization_code for backward compatibility.
func (s *Store) ClientAllowsGrant(clientID, grantType string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, ok := s.clients[clientID]
	if !ok {
		return false
	}

	grants := client.GrantTypes
	if len(grants) == 0 {
		grants = []string{"authorization_code"}
	}

	for _, g := range grants {
		if g == grantType {
			return true
		}
	}

	return false
}

// RandomHex generates a cryptographically random hex string of the given byte length.
func RandomHex(byteLen int) string {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}

	return hex.EncodeToString(b)
}
