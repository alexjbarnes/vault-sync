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
	// APIKeyPrefix is the required prefix for all API key values.
	// The middleware uses this to distinguish API keys from OAuth tokens.
	APIKeyPrefix = "vs_"

	// APIKeyMinLen is the minimum valid API key length:
	// 3-char prefix + 64 hex chars (32 bytes of entropy).
	APIKeyMinLen = 67

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

	// dummyHash is used for timing-safe comparisons when no stored hash
	// exists. Ensures the code path (hash + constant-time compare) is
	// identical regardless of whether the entry exists.
	dummyHash = "0000000000000000000000000000000000000000000000000000000000000000"
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
	mu           sync.RWMutex
	codes        map[string]*Code               // code -> Code
	tokens       map[string]*models.OAuthToken  // SHA-256(token) -> OAuthToken
	refreshIndex map[string]string              // refreshHash -> accessTokenHash
	clients      map[string]*models.OAuthClient // client_id -> OAuthClient
	apiKeys      map[string]*models.APIKey      // SHA-256(raw key) -> APIKey
	csrf         map[string]csrfEntry           // csrf token -> expiry
	stopGC       chan struct{}

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
		codes:        make(map[string]*Code),
		tokens:       make(map[string]*models.OAuthToken),
		refreshIndex: make(map[string]string),
		clients:      make(map[string]*models.OAuthClient),
		apiKeys:      make(map[string]*models.APIKey),
		csrf:         make(map[string]csrfEntry),
		stopGC:       make(chan struct{}),
		persist:      persist,
		logger:       logger,
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

		// Backward compat: old entries have Token but no TokenHash.
		if t.TokenHash == "" && t.Token != "" {
			t.TokenHash = HashSecret(t.Token)
		}

		if t.TokenHash == "" {
			continue
		}

		if now.After(t.ExpiresAt) {
			_ = s.persist.DeleteOAuthToken(t.TokenHash)
			continue
		}

		// Backward compat: old access tokens have RefreshToken but
		// no RefreshHash. Compute the hash for the new lookup.
		if t.Kind == "access" && t.RefreshHash == "" && t.RefreshToken != "" {
			t.RefreshHash = HashSecret(t.RefreshToken)
		}

		// Clear raw secrets from memory after computing hashes.
		t.Token = ""
		t.RefreshToken = ""

		s.tokens[t.TokenHash] = &t

		if t.Kind == "access" && t.RefreshHash != "" {
			s.refreshIndex[t.RefreshHash] = t.TokenHash
		}
	}

	clients, err := s.persist.AllOAuthClients()
	if err != nil {
		s.logger.Warn("loading persisted OAuth clients", slog.String("error", err.Error()))
	}

	for i := range clients {
		c := clients[i]
		s.clients[c.ClientID] = &c
	}

	apiKeys, err := s.persist.AllAPIKeys()
	if err != nil {
		s.logger.Warn("loading persisted API keys", slog.String("error", err.Error()))
	}

	for hash, ak := range apiKeys {
		akCopy := ak
		s.apiKeys[hash] = &akCopy
	}

	s.logger.Info("loaded auth state from disk",
		slog.Int("tokens", len(s.tokens)),
		slog.Int("clients", len(s.clients)),
		slog.Int("api_keys", len(s.apiKeys)),
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

	for hash, t := range s.tokens {
		if now.After(t.ExpiresAt) {
			delete(s.tokens, hash)

			if t.Kind == "access" && t.RefreshHash != "" {
				delete(s.refreshIndex, t.RefreshHash)
			}

			if s.persist != nil {
				_ = s.persist.DeleteOAuthToken(hash)
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
// Computes TokenHash from Token and RefreshHash from RefreshToken
// if not already set by the caller. For access tokens with a
// RefreshHash, a reverse index entry is maintained for O(1)
// lookup in DeleteAccessTokenByRefreshToken.
func (s *Store) SaveToken(t *models.OAuthToken) {
	if t.TokenHash == "" {
		t.TokenHash = HashSecret(t.Token)
	}

	if t.RefreshHash == "" && t.RefreshToken != "" {
		t.RefreshHash = HashSecret(t.RefreshToken)
	}

	s.mu.Lock()
	s.tokens[t.TokenHash] = t

	if t.Kind == "access" && t.RefreshHash != "" {
		s.refreshIndex[t.RefreshHash] = t.TokenHash
	}

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
	hash := HashSecret(token)

	s.mu.RLock()
	defer s.mu.RUnlock()

	t, ok := s.tokens[hash]
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
	hash := HashSecret(token)

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.validateRefreshTokenLocked(hash, clientID, resource)
}

// validateRefreshTokenLocked performs refresh token validation without locking.
// Caller must hold at least s.mu.RLock(). tokenHash is the SHA-256 hex
// hash of the raw token.
func (s *Store) validateRefreshTokenLocked(tokenHash, clientID, resource string) *models.OAuthToken {
	t, ok := s.tokens[tokenHash]
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
	hash := HashSecret(token)

	s.mu.Lock()
	defer s.mu.Unlock()

	t := s.validateRefreshTokenLocked(hash, clientID, resource)
	if t == nil {
		return nil
	}

	delete(s.tokens, hash)

	if s.persist != nil {
		_ = s.persist.DeleteOAuthToken(hash)
	}

	return t
}

// DeleteToken removes a token from the store and persistent storage.
func (s *Store) DeleteToken(token string) {
	hash := HashSecret(token)

	s.mu.Lock()

	if t := s.tokens[hash]; t != nil && t.Kind == "access" && t.RefreshHash != "" {
		delete(s.refreshIndex, t.RefreshHash)
	}

	delete(s.tokens, hash)
	s.mu.Unlock()

	if s.persist != nil {
		_ = s.persist.DeleteOAuthToken(hash)
	}
}

// DeleteAccessTokenByRefreshToken removes the access token that was
// paired with the given refresh token. Uses the refreshIndex for O(1)
// lookup instead of scanning all tokens.
func (s *Store) DeleteAccessTokenByRefreshToken(refreshToken string) {
	refreshHash := HashSecret(refreshToken)

	s.mu.Lock()

	found := s.refreshIndex[refreshHash]
	if found != "" {
		delete(s.tokens, found)
		delete(s.refreshIndex, refreshHash)
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
		storedHash = dummyHash
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

// RegisterAPIKey stores an API key by hashing the raw key value.
// The raw key is never stored; only the SHA-256 hash is persisted.
func (s *Store) RegisterAPIKey(rawKey, userID string) {
	hash := HashSecret(rawKey)
	ak := &models.APIKey{
		KeyHash:   hash,
		UserID:    userID,
		CreatedAt: time.Now(),
	}

	s.mu.Lock()
	s.apiKeys[hash] = ak
	s.mu.Unlock()

	if s.persist != nil {
		if err := s.persist.SaveAPIKey(hash, *ak); err != nil && s.logger != nil {
			s.logger.Warn("persisting API key", slog.String("error", err.Error()))
		}
	}
}

// ValidateAPIKey checks if a raw API key is registered. Returns nil
// if the key is not found. The lookup is by SHA-256 hash of the raw
// key, which is the map key. No constant-time compare is needed here
// because the map lookup itself is the authentication gate (unlike
// ValidateClientSecret where the secret is compared against a stored
// hash for a known client_id).
func (s *Store) ValidateAPIKey(rawKey string) *models.APIKey {
	hash := HashSecret(rawKey)

	s.mu.RLock()
	ak := s.apiKeys[hash]
	s.mu.RUnlock()

	return ak
}

// RevokeAPIKey removes an API key by its hash.
func (s *Store) RevokeAPIKey(keyHash string) {
	s.mu.Lock()
	delete(s.apiKeys, keyHash)
	s.mu.Unlock()

	if s.persist != nil {
		_ = s.persist.DeleteAPIKey(keyHash)
	}
}

// ListAPIKeys returns all registered API keys.
func (s *Store) ListAPIKeys() []*models.APIKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]*models.APIKey, 0, len(s.apiKeys))
	for _, ak := range s.apiKeys {
		keys = append(keys, ak)
	}

	return keys
}

// ReconcileAPIKeys removes any persisted API keys not present in the
// provided set of current key hashes. Returns the number of keys removed.
// Call after registering all config-based keys to purge stale entries
// that were removed from MCP_API_KEYS between restarts.
func (s *Store) ReconcileAPIKeys(currentHashes map[string]struct{}) int {
	s.mu.Lock()

	var stale []string

	for hash := range s.apiKeys {
		if _, ok := currentHashes[hash]; !ok {
			stale = append(stale, hash)
		}
	}

	for _, hash := range stale {
		delete(s.apiKeys, hash)
	}

	s.mu.Unlock()

	if s.persist != nil {
		for _, hash := range stale {
			_ = s.persist.DeleteAPIKey(hash)
		}
	}

	return len(stale)
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
