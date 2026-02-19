package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/models"
)

const (
	tokenExpiry        = time.Hour
	refreshTokenExpiry = 30 * 24 * time.Hour

	// accessTokenBytes is the number of random bytes used to generate
	// an access token (hex-encoded to twice this length).
	accessTokenBytes = 32

	// refreshTokenBytes is the number of random bytes used to generate
	// a refresh token (hex-encoded to twice this length).
	refreshTokenBytes = 32

	// tokenRateLimitWindow is the sliding window for per-IP rate
	// limiting on the token endpoint.
	tokenRateLimitWindow = time.Minute

	// tokenRateLimitMaxFail is the maximum failed attempts per IP
	// within the window before requests are rejected.
	tokenRateLimitMaxFail = 5

	// lockoutThreshold is the number of consecutive failed attempts
	// per client_id before the account is locked.
	lockoutThreshold = 10

	// lockoutDuration is how long a locked account stays locked.
	lockoutDuration = 15 * time.Minute

	// tokenLimiterPruneThreshold triggers pruning of stale entries
	// to prevent unbounded map growth.
	tokenLimiterPruneThreshold = 1000
)

type tokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	CodeVerifier string `json:"code_verifier"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Resource     string `json:"resource"`
	RefreshToken string `json:"refresh_token"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// lockoutEntry tracks consecutive failures and lockout state for a
// single client_id.
type lockoutEntry struct {
	failures int
	lockedAt time.Time
}

// tokenRateLimiter combines per-IP sliding window rate limiting with
// per-client_id account lockout.
type tokenRateLimiter struct {
	mu       sync.Mutex
	ipFails  map[string][]time.Time   // IP -> failure timestamps
	lockouts map[string]*lockoutEntry // client_id -> lockout state
}

func newTokenRateLimiter() *tokenRateLimiter {
	return &tokenRateLimiter{
		ipFails:  make(map[string][]time.Time),
		lockouts: make(map[string]*lockoutEntry),
	}
}

// checkIP returns true if the IP is currently rate-limited.
func (trl *tokenRateLimiter) checkIP(ip string) bool {
	trl.mu.Lock()
	defer trl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-tokenRateLimitWindow)

	if len(trl.ipFails) > tokenLimiterPruneThreshold {
		for k, times := range trl.ipFails {
			if len(times) == 0 || times[len(times)-1].Before(cutoff) {
				delete(trl.ipFails, k)
			}
		}
	}

	recent := trl.ipFails[ip][:0]
	for _, t := range trl.ipFails[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) == 0 {
		delete(trl.ipFails, ip)
	} else {
		trl.ipFails[ip] = recent
	}

	return len(recent) >= tokenRateLimitMaxFail
}

// checkLockout returns true if the client_id is currently locked out.
func (trl *tokenRateLimiter) checkLockout(clientID string) bool {
	if clientID == "" {
		return false
	}

	trl.mu.Lock()
	defer trl.mu.Unlock()

	entry, ok := trl.lockouts[clientID]
	if !ok {
		return false
	}

	if !entry.lockedAt.IsZero() && time.Now().Before(entry.lockedAt.Add(lockoutDuration)) {
		return true
	}

	// Lockout expired, reset.
	if !entry.lockedAt.IsZero() {
		delete(trl.lockouts, clientID)
	}

	return false
}

// recordFailure records a failed attempt for both IP and client_id.
func (trl *tokenRateLimiter) recordFailure(ip, clientID string) {
	trl.mu.Lock()
	defer trl.mu.Unlock()

	trl.ipFails[ip] = append(trl.ipFails[ip], time.Now())

	if clientID == "" {
		return
	}

	entry, ok := trl.lockouts[clientID]
	if !ok {
		entry = &lockoutEntry{}
		trl.lockouts[clientID] = entry
	}

	entry.failures++

	if entry.failures >= lockoutThreshold {
		entry.lockedAt = time.Now()
	}
}

// clearLockout resets the failure counter for a client_id on successful auth.
func (trl *tokenRateLimiter) clearLockout(clientID string) {
	if clientID == "" {
		return
	}

	trl.mu.Lock()
	delete(trl.lockouts, clientID)
	trl.mu.Unlock()
}

// HandleToken returns the /oauth/token handler. The serverURL is the
// canonical resource identifier used to validate the resource parameter.
func HandleToken(store *Store, logger *slog.Logger, serverURL string) http.HandlerFunc {
	limiter := newTokenRateLimiter()

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

		// Per-IP rate limiting.
		ip := r.RemoteAddr
		if limiter.checkIP(ip) {
			logger.Warn("token endpoint rate limited", slog.String("ip", ip))
			writeJSONError(w, http.StatusTooManyRequests, "slow_down", "too many failed attempts, try again later")

			return
		}

		// Support both JSON and form-encoded bodies.
		var req tokenRequest

		contentType := r.Header.Get("Content-Type")
		if contentType == "application/json" {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
				return
			}
		} else {
			if err := r.ParseForm(); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid form data")
				return
			}

			req = tokenRequest{
				GrantType:    r.FormValue("grant_type"),
				Code:         r.FormValue("code"),
				RedirectURI:  r.FormValue("redirect_uri"),
				CodeVerifier: r.FormValue("code_verifier"),
				ClientID:     r.FormValue("client_id"),
				ClientSecret: r.FormValue("client_secret"),
				Resource:     r.FormValue("resource"),
				RefreshToken: r.FormValue("refresh_token"),
			}
		}

		switch req.GrantType {
		case "authorization_code", "refresh_token", "client_credentials":
			// supported
		default:
			writeJSONError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
			return
		}

		// Per-client lockout check.
		if limiter.checkLockout(req.ClientID) {
			logger.Warn("token endpoint client locked out",
				slog.String("client_id", req.ClientID))
			writeJSONError(w, http.StatusTooManyRequests, "slow_down", "account locked due to repeated failures")

			return
		}

		// Enforce grant type against client registration. The
		// refresh_token grant is always allowed since it continues
		// an existing authorized session.
		if req.GrantType != "refresh_token" && req.ClientID != "" && !store.ClientAllowsGrant(req.ClientID, req.GrantType) {
			writeJSONError(w, http.StatusBadRequest, "unauthorized_client", "client is not authorized for this grant type")
			return
		}

		switch req.GrantType {
		case "refresh_token":
			handleRefreshToken(w, store, limiter, ip, req, serverURL)
		case "client_credentials":
			handleClientCredentials(w, store, limiter, logger, ip, req, serverURL)
		default:
			handleAuthorizationCode(w, store, limiter, ip, req, serverURL)
		}
	}
}

func handleRefreshToken(w http.ResponseWriter, store *Store, limiter *tokenRateLimiter, ip string, req tokenRequest, serverURL string) {
	if req.RefreshToken == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	rt := store.ConsumeRefreshToken(req.RefreshToken, req.ClientID, req.Resource)
	if rt == nil {
		limiter.recordFailure(ip, req.ClientID)
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired refresh token")

		return
	}

	// Revoke the old access token that was paired with this
	// refresh token so it cannot be reused after rotation.
	store.DeleteAccessTokenByRefreshToken(req.RefreshToken)

	limiter.clearLockout(req.ClientID)

	// Issue new access token + new refresh token
	resource := rt.Resource
	if resource == "" {
		resource = serverURL
	}

	issueTokenPair(w, store, rt.UserID, resource, rt.Scopes, rt.ClientID)
}

func handleClientCredentials(w http.ResponseWriter, store *Store, limiter *tokenRateLimiter, logger *slog.Logger, ip string, req tokenRequest, serverURL string) {
	if req.ClientID == "" || req.ClientSecret == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "client_id and client_secret are required")
		return
	}

	if !store.ValidateClientSecret(req.ClientID, req.ClientSecret) {
		limiter.recordFailure(ip, req.ClientID)
		logger.Warn("client_credentials authentication failed",
			slog.String("client_id", req.ClientID),
			slog.String("ip", ip))
		writeJSONError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")

		return
	}

	limiter.clearLockout(req.ClientID)

	resource := req.Resource
	if resource == "" {
		resource = serverURL
	}

	if resource != "" && strings.TrimRight(resource, "/") != strings.TrimRight(serverURL, "/") {
		writeJSONError(w, http.StatusBadRequest, "invalid_target", "resource parameter does not match this server")
		return
	}

	// The client itself is the resource owner for client_credentials.
	// Use the client_id as the user_id on the tokens.
	issueTokenPair(w, store, req.ClientID, resource, nil, req.ClientID)
}

func handleAuthorizationCode(w http.ResponseWriter, store *Store, limiter *tokenRateLimiter, ip string, req tokenRequest, serverURL string) {
	if req.Code == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}

	ac := store.ConsumeCode(req.Code)
	if ac == nil {
		limiter.recordFailure(ip, req.ClientID)
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired authorization code")

		return
	}

	// Validate redirect_uri matches the one stored on the auth code.
	if ac.RedirectURI != "" && req.RedirectURI != ac.RedirectURI {
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	// RFC 8707: validate that the resource parameter matches what was
	// bound to the authorization code. Tolerate omission for backward
	// compatibility, but reject mismatches.
	if req.Resource != "" && strings.TrimRight(req.Resource, "/") != strings.TrimRight(serverURL, "/") {
		writeJSONError(w, http.StatusBadRequest, "invalid_target", "resource parameter does not match this server")
		return
	}

	if ac.Resource != "" && req.Resource != "" && strings.TrimRight(req.Resource, "/") != strings.TrimRight(ac.Resource, "/") {
		writeJSONError(w, http.StatusBadRequest, "invalid_target", "resource does not match authorization code")
		return
	}

	// PKCE is mandatory. The authorize endpoint enforces that a
	// code_challenge is present, so every auth code has one.
	if ac.CodeChallenge == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "authorization code was issued without PKCE")
		return
	}

	if req.CodeVerifier == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "code_verifier is required")
		return
	}

	if !verifyPKCE(req.CodeVerifier, ac.CodeChallenge) {
		limiter.recordFailure(ip, req.ClientID)
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")

		return
	}

	limiter.clearLockout(req.ClientID)

	// Issue access token bound to the resource.
	resource := ac.Resource
	if resource == "" {
		resource = serverURL
	}

	clientID := ac.ClientID
	if clientID == "" {
		clientID = req.ClientID
	}

	issueTokenPair(w, store, ac.UserID, resource, ac.Scopes, clientID)
}

// issueTokenPair generates and saves an access/refresh token pair, then
// writes the token response.
func issueTokenPair(w http.ResponseWriter, store *Store, userID, resource string, scopes []string, clientID string) {
	accessToken := RandomHex(accessTokenBytes)
	refreshToken := RandomHex(refreshTokenBytes)

	store.SaveToken(&models.OAuthToken{
		Token:        accessToken,
		Kind:         "access",
		UserID:       userID,
		Resource:     resource,
		Scopes:       scopes,
		ExpiresAt:    time.Now().Add(tokenExpiry),
		RefreshToken: refreshToken,
		ClientID:     clientID,
	})

	store.SaveToken(&models.OAuthToken{
		Token:     refreshToken,
		Kind:      "refresh",
		UserID:    userID,
		Resource:  resource,
		Scopes:    scopes,
		ExpiresAt: time.Now().Add(refreshTokenExpiry),
		ClientID:  clientID,
	})

	resp := tokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(tokenExpiry.Seconds()),
		RefreshToken: refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

// verifyPKCE checks that SHA256(verifier) matches the challenge (S256 method).
// Uses constant-time comparison to prevent timing side channels.
func verifyPKCE(verifier, challenge string) bool {
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])

	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}
