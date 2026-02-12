package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testUsers(t *testing.T) UserCredentials {
	t.Helper()
	return UserCredentials{"testuser": "password123"}
}

func testStore(t *testing.T) *Store {
	t.Helper()
	s := NewStore(nil, testLogger())
	t.Cleanup(s.Stop)
	return s
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// registerTestClient registers a client and returns its ID.
func registerTestClient(t *testing.T, store *Store, redirectURIs []string) string {
	t.Helper()
	clientID := RandomHex(16)
	ok := store.RegisterClient(&models.OAuthClient{
		ClientID:     clientID,
		RedirectURIs: redirectURIs,
	})
	require.True(t, ok)
	return clientID
}

// getCSRFToken renders the login form and extracts the CSRF token from
// the hidden field.
const testServerURL = "https://vault.example.com"

func getCSRFToken(t *testing.T, handler http.HandlerFunc, clientID, redirectURI string) string {
	t.Helper()
	challenge := pkceChallenge("test-verifier")
	req := httptest.NewRequest("GET", "/oauth/authorize?client_id="+clientID+"&redirect_uri="+url.QueryEscape(redirectURI)+"&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Extract csrf_token value from the hidden input.
	re := regexp.MustCompile(`name="csrf_token" value="([a-f0-9]+)"`)
	matches := re.FindStringSubmatch(rec.Body.String())
	require.Len(t, matches, 2, "CSRF token not found in form")
	return matches[1]
}

// --- Store ---

func TestStore_CodeRoundTrip(t *testing.T) {
	s := testStore(t)
	s.SaveCode(&AuthCode{
		Code:      "abc123",
		ClientID:  "client1",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})

	ac := s.ConsumeCode("abc123")
	require.NotNil(t, ac)
	assert.Equal(t, "client1", ac.ClientID)

	// Second consume should return nil (code is consumed).
	assert.Nil(t, s.ConsumeCode("abc123"))
}

func TestStore_CodeExpired(t *testing.T) {
	s := testStore(t)
	s.SaveCode(&AuthCode{
		Code:      "expired",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})

	assert.Nil(t, s.ConsumeCode("expired"))
}

func TestStore_CodeNotFound(t *testing.T) {
	s := testStore(t)
	assert.Nil(t, s.ConsumeCode("nonexistent"))
}

func TestStore_TokenRoundTrip(t *testing.T) {
	s := testStore(t)
	s.SaveToken(&models.OAuthToken{
		Token:     "tok_abc",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	ti := s.ValidateToken("tok_abc")
	require.NotNil(t, ti)
	assert.Equal(t, "user1", ti.UserID)
}

func TestStore_TokenExpired(t *testing.T) {
	s := testStore(t)
	s.SaveToken(&models.OAuthToken{
		Token:     "expired_tok",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})

	assert.Nil(t, s.ValidateToken("expired_tok"))
}

func TestStore_TokenNotFound(t *testing.T) {
	s := testStore(t)
	assert.Nil(t, s.ValidateToken("nonexistent"))
}

func TestStore_ClientRoundTrip(t *testing.T) {
	s := testStore(t)
	ok := s.RegisterClient(&models.OAuthClient{
		ClientID:     "client1",
		ClientName:   "Test",
		RedirectURIs: []string{"https://example.com/callback"},
	})
	assert.True(t, ok)

	ci := s.GetClient("client1")
	require.NotNil(t, ci)
	assert.Equal(t, "Test", ci.ClientName)
	assert.Nil(t, s.GetClient("nonexistent"))
}

func TestStore_ClientMaxLimit(t *testing.T) {
	s := testStore(t)
	for i := 0; i < maxClients; i++ {
		ok := s.RegisterClient(&models.OAuthClient{
			ClientID:     RandomHex(8),
			RedirectURIs: []string{"https://example.com/cb"},
		})
		require.True(t, ok)
	}

	// Next registration should fail.
	ok := s.RegisterClient(&models.OAuthClient{
		ClientID:     "overflow",
		RedirectURIs: []string{"https://example.com/cb"},
	})
	assert.False(t, ok)
}

func TestStore_CSRFRoundTrip(t *testing.T) {
	s := testStore(t)
	s.SaveCSRF("csrf123")

	assert.True(t, s.ConsumeCSRF("csrf123"))
	// Second consume should fail.
	assert.False(t, s.ConsumeCSRF("csrf123"))
}

func TestStore_CSRFEmpty(t *testing.T) {
	s := testStore(t)
	assert.False(t, s.ConsumeCSRF(""))
}

func TestStore_CSRFNotFound(t *testing.T) {
	s := testStore(t)
	assert.False(t, s.ConsumeCSRF("nonexistent"))
}

func TestStore_Cleanup(t *testing.T) {
	s := testStore(t)

	s.SaveCode(&AuthCode{
		Code:      "expired-code",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})
	s.SaveToken(&models.OAuthToken{
		Token:     "expired-token",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})
	s.mu.Lock()
	s.csrf["expired-csrf"] = csrfEntry{expiresAt: time.Now().Add(-1 * time.Minute)}
	s.mu.Unlock()

	s.cleanup()

	s.mu.RLock()
	assert.Empty(t, s.codes)
	assert.Empty(t, s.tokens)
	assert.Empty(t, s.csrf)
	s.mu.RUnlock()
}

func TestRandomHex_Length(t *testing.T) {
	h := RandomHex(16)
	assert.Len(t, h, 32) // 16 bytes = 32 hex chars
}

func TestRandomHex_Unique(t *testing.T) {
	a := RandomHex(16)
	b := RandomHex(16)
	assert.NotEqual(t, a, b)
}

// --- Metadata ---

func TestProtectedResourceMetadata(t *testing.T) {
	handler := HandleProtectedResourceMetadata("https://vault.example.com")
	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var meta ProtectedResourceMetadata
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&meta))
	assert.Equal(t, "https://vault.example.com", meta.Resource)
	assert.Contains(t, meta.AuthorizationServers, "https://vault.example.com")
	assert.Contains(t, meta.ScopesSupported, "vault:read")
}

func TestAuthServerMetadata(t *testing.T) {
	handler := HandleAuthServerMetadata("https://vault.example.com")
	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var meta AuthServerMetadata
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&meta))
	assert.Equal(t, "https://vault.example.com", meta.Issuer)
	assert.Equal(t, "https://vault.example.com/oauth/authorize", meta.AuthorizationEndpoint)
	assert.Equal(t, "https://vault.example.com/oauth/token", meta.TokenEndpoint)
	assert.Equal(t, "https://vault.example.com/oauth/register", meta.RegistrationEndpoint)
	assert.Contains(t, meta.CodeChallengeMethodsSupported, "S256")
}

// --- Registration ---

func TestRegistration_Success(t *testing.T) {
	store := testStore(t)
	handler := HandleRegistration(store)

	body := `{"client_name":"Claude","redirect_uris":["https://claude.ai/callback"]}`
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	var resp registrationResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.ClientID)
	assert.Equal(t, "Claude", resp.ClientName)
	assert.Equal(t, []string{"https://claude.ai/callback"}, resp.RedirectURIs)

	// Verify client was stored.
	ci := store.GetClient(resp.ClientID)
	require.NotNil(t, ci)
}

func TestRegistration_MissingRedirectURIs(t *testing.T) {
	store := testStore(t)
	handler := HandleRegistration(store)

	body := `{"client_name":"Claude"}`
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRegistration_WrongMethod(t *testing.T) {
	store := testStore(t)
	handler := HandleRegistration(store)

	req := httptest.NewRequest("GET", "/oauth/register", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestRegistration_ClientLimitReached(t *testing.T) {
	store := testStore(t)
	for i := 0; i < maxClients; i++ {
		store.RegisterClient(&models.OAuthClient{
			ClientID:     RandomHex(8),
			RedirectURIs: []string{"https://example.com/cb"},
		})
	}

	handler := HandleRegistration(store)
	body := `{"redirect_uris":["https://example.com/cb"]}`
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestRegistration_RejectsHTTPRedirectURI(t *testing.T) {
	store := testStore(t)
	handler := HandleRegistration(store)

	body := `{"redirect_uris":["http://attacker.com/steal"]}`
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "HTTPS")
}

func TestRegistration_AllowsHTTPLocalhost(t *testing.T) {
	store := testStore(t)
	handler := HandleRegistration(store)

	body := `{"redirect_uris":["http://localhost:8080/callback"]}`
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
}

// --- Authorize ---

func TestAuthorize_GET_ShowsLoginForm(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})

	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)
	challenge := pkceChallenge("test-verifier")
	req := httptest.NewRequest("GET", "/oauth/authorize?client_id="+clientID+"&redirect_uri=https://example.com/callback&state=xyz&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Vault Sync Login")
	assert.Contains(t, rec.Body.String(), clientID)
	assert.Contains(t, rec.Body.String(), "csrf_token")
}

func TestAuthorize_GET_MissingClientID(t *testing.T) {
	store := testStore(t)
	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)

	req := httptest.NewRequest("GET", "/oauth/authorize", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAuthorize_GET_UnknownClient(t *testing.T) {
	store := testStore(t)
	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)

	req := httptest.NewRequest("GET", "/oauth/authorize?client_id=unknown", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAuthorize_GET_InvalidRedirectURI(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})

	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)
	challenge := pkceChallenge("v")
	req := httptest.NewRequest("GET", "/oauth/authorize?client_id="+clientID+"&redirect_uri=https://evil.com/steal&code_challenge="+challenge, nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "redirect_uri not registered")
}

func TestAuthorize_GET_MissingPKCE(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})

	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)
	req := httptest.NewRequest("GET", "/oauth/authorize?client_id="+clientID+"&redirect_uri=https://example.com/callback", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "code_challenge is required")
}

func TestAuthorize_POST_ValidLogin(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})
	users := testUsers(t)
	handler := HandleAuthorize(store, users, testLogger(), testServerURL)

	csrfToken := getCSRFToken(t, handler, clientID, "https://example.com/callback")
	challenge := pkceChallenge("test-verifier")

	form := url.Values{
		"csrf_token":            {csrfToken},
		"client_id":             {clientID},
		"redirect_uri":          {"https://example.com/callback"},
		"state":                 {"mystate"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"username":              {"testuser"},
		"password":              {"password123"},
	}

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")
	assert.Contains(t, location, "https://example.com/callback")
	assert.Contains(t, location, "code=")
	assert.Contains(t, location, "state=mystate")
}

func TestAuthorize_POST_StateURLEncoded(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})
	users := testUsers(t)
	handler := HandleAuthorize(store, users, testLogger(), testServerURL)

	csrfToken := getCSRFToken(t, handler, clientID, "https://example.com/callback")
	challenge := pkceChallenge("test-verifier")

	// State containing special characters that need URL encoding.
	form := url.Values{
		"csrf_token":     {csrfToken},
		"client_id":      {clientID},
		"redirect_uri":   {"https://example.com/callback"},
		"state":          {"has&equals=and spaces"},
		"code_challenge": {challenge},
		"username":       {"testuser"},
		"password":       {"password123"},
	}

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")

	// Parse the redirect URL to verify proper encoding.
	u, err := url.Parse(location)
	require.NoError(t, err)
	assert.Equal(t, "has&equals=and spaces", u.Query().Get("state"))
}

func TestAuthorize_POST_InvalidPassword(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})
	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)

	csrfToken := getCSRFToken(t, handler, clientID, "https://example.com/callback")
	challenge := pkceChallenge("v")

	form := url.Values{
		"csrf_token":     {csrfToken},
		"client_id":      {clientID},
		"code_challenge": {challenge},
		"username":       {"testuser"},
		"password":       {"wrong"},
	}

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "Invalid username or password")
}

func TestAuthorize_POST_InvalidRedirectURI(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})
	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)

	csrfToken := getCSRFToken(t, handler, clientID, "https://example.com/callback")

	form := url.Values{
		"csrf_token":     {csrfToken},
		"client_id":      {clientID},
		"redirect_uri":   {"https://evil.com/steal"},
		"code_challenge": {"challenge"},
		"username":       {"testuser"},
		"password":       {"password123"},
	}

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "redirect_uri not registered")
}

func TestAuthorize_POST_MissingCSRF(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})
	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)

	form := url.Values{
		"client_id":      {clientID},
		"code_challenge": {"challenge"},
		"username":       {"testuser"},
		"password":       {"password123"},
	}

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "CSRF")
}

func TestAuthorize_POST_MissingPKCE(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})
	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)

	// Manually create a CSRF token (can't use getCSRFToken since GET
	// now requires code_challenge too).
	store.SaveCSRF("manual-csrf")

	form := url.Values{
		"csrf_token": {"manual-csrf"},
		"client_id":  {clientID},
		"username":   {"testuser"},
		"password":   {"password123"},
	}

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "code_challenge is required")
}

func TestAuthorize_POST_RateLimited(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})
	users := testUsers(t)
	handler := HandleAuthorize(store, users, testLogger(), testServerURL)

	challenge := pkceChallenge("v")

	// Exhaust the rate limit with failed attempts.
	for i := 0; i < rateLimitMaxFail; i++ {
		csrf := generateCSRFToken(store)
		form := url.Values{
			"csrf_token":     {csrf},
			"client_id":      {clientID},
			"code_challenge": {challenge},
			"username":       {"testuser"},
			"password":       {"wrong"},
		}
		req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		handler(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	}

	// Next attempt should be rate limited.
	csrf := generateCSRFToken(store)
	form := url.Values{
		"csrf_token":     {csrf},
		"client_id":      {clientID},
		"code_challenge": {challenge},
		"username":       {"testuser"},
		"password":       {"password123"},
	}
	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
}

// --- Resource Parameter (RFC 8707) ---

func TestAuthorize_GET_ResourceParameter(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})
	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)
	challenge := pkceChallenge("test-verifier")

	// Valid resource parameter shows login form.
	req := httptest.NewRequest("GET", "/oauth/authorize?client_id="+clientID+
		"&redirect_uri=https://example.com/callback"+
		"&code_challenge="+challenge+
		"&resource="+url.QueryEscape(testServerURL), nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Vault Sync Login")
	assert.Contains(t, rec.Body.String(), testServerURL)
}

func TestAuthorize_GET_WrongResource(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})
	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)
	challenge := pkceChallenge("test-verifier")

	req := httptest.NewRequest("GET", "/oauth/authorize?client_id="+clientID+
		"&redirect_uri=https://example.com/callback"+
		"&code_challenge="+challenge+
		"&resource="+url.QueryEscape("https://evil.example.com"), nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "resource parameter does not match")
}

func TestAuthorize_POST_ResourceBindsToCode(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})
	users := testUsers(t)
	handler := HandleAuthorize(store, users, testLogger(), testServerURL)

	csrfToken := getCSRFToken(t, handler, clientID, "https://example.com/callback")
	challenge := pkceChallenge("test-verifier")

	form := url.Values{
		"csrf_token":     {csrfToken},
		"client_id":      {clientID},
		"redirect_uri":   {"https://example.com/callback"},
		"state":          {"mystate"},
		"code_challenge": {challenge},
		"resource":       {testServerURL},
		"username":       {"testuser"},
		"password":       {"password123"},
	}

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")
	assert.Contains(t, location, "code=")

	// Extract code and verify it has the resource bound.
	u, err := url.Parse(location)
	require.NoError(t, err)
	code := u.Query().Get("code")
	ac := store.ConsumeCode(code)
	require.NotNil(t, ac)
	assert.Equal(t, testServerURL, ac.Resource)
}

func TestToken_ResourceParameter(t *testing.T) {
	store := testStore(t)
	verifier := "resource-test-verifier"
	challenge := pkceChallenge(verifier)

	store.SaveCode(&AuthCode{
		Code:          "res-code",
		ClientID:      "client1",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: challenge,
		Resource:      testServerURL,
		UserID:        "testuser",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testServerURL)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"res-code"},
		"redirect_uri":  {"https://example.com/callback"},
		"code_verifier": {verifier},
		"resource":      {testServerURL},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	// Verify the token is bound to the resource.
	ti := store.ValidateToken(resp.AccessToken)
	require.NotNil(t, ti)
	assert.Equal(t, testServerURL, ti.Resource)
}

func TestToken_WrongResourceParameter(t *testing.T) {
	store := testStore(t)
	verifier := "wrong-res-verifier"
	challenge := pkceChallenge(verifier)

	store.SaveCode(&AuthCode{
		Code:          "wrong-res-code",
		CodeChallenge: challenge,
		Resource:      testServerURL,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testServerURL)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"wrong-res-code"},
		"code_verifier": {verifier},
		"resource":      {"https://evil.example.com"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "resource parameter does not match")
}

func TestMiddleware_WrongResourceOnToken(t *testing.T) {
	store := testStore(t)
	store.SaveToken(&models.OAuthToken{
		Token:     "wrong-resource-token",
		UserID:    "user1",
		Resource:  "https://other-server.example.com",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	mw := Middleware(store, testServerURL)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer wrong-resource-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMetadata_MethodNotAllowed(t *testing.T) {
	prm := HandleProtectedResourceMetadata(testServerURL)
	req := httptest.NewRequest("POST", "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()
	prm(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)

	asm := HandleAuthServerMetadata(testServerURL)
	req = httptest.NewRequest("DELETE", "/.well-known/oauth-authorization-server", nil)
	rec = httptest.NewRecorder()
	asm(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestMetadata_CacheControl(t *testing.T) {
	prm := HandleProtectedResourceMetadata(testServerURL)
	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()
	prm(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Cache-Control"), "max-age=")

	asm := HandleAuthServerMetadata(testServerURL)
	req = httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	rec = httptest.NewRecorder()
	asm(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Cache-Control"), "max-age=")
}

// --- Token ---

func TestToken_FullFlow(t *testing.T) {
	store := testStore(t)
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)

	store.SaveCode(&AuthCode{
		Code:          "authcode123",
		ClientID:      "client1",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: challenge,
		UserID:        "testuser",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testServerURL)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"authcode123"},
		"redirect_uri":  {"https://example.com/callback"},
		"code_verifier": {verifier},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Greater(t, resp.ExpiresIn, 0)

	// Validate the issued token works.
	ti := store.ValidateToken(resp.AccessToken)
	require.NotNil(t, ti)
	assert.Equal(t, "testuser", ti.UserID)
}

func TestToken_InvalidCode(t *testing.T) {
	store := testStore(t)
	handler := HandleToken(store, testServerURL)

	form := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"invalid"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestToken_WrongGrantType(t *testing.T) {
	store := testStore(t)
	handler := HandleToken(store, testServerURL)

	form := url.Values{
		"grant_type": {"client_credentials"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestToken_PKCEVerificationFails(t *testing.T) {
	store := testStore(t)
	store.SaveCode(&AuthCode{
		Code:          "code-with-pkce",
		CodeChallenge: "validchallenge",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testServerURL)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code-with-pkce"},
		"code_verifier": {"wrong-verifier"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "PKCE")
}

func TestToken_MissingPKCE(t *testing.T) {
	store := testStore(t)
	// Auth code with a code_challenge but no verifier provided.
	store.SaveCode(&AuthCode{
		Code:          "code-needs-pkce",
		CodeChallenge: pkceChallenge("verifier"),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testServerURL)

	form := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"code-needs-pkce"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "code_verifier is required")
}

func TestToken_NoPKCEOnCode(t *testing.T) {
	store := testStore(t)
	// Auth code issued without code_challenge (legacy or attacker bypass).
	store.SaveCode(&AuthCode{
		Code:      "no-pkce-code",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testServerURL)

	form := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"no-pkce-code"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "without PKCE")
}

func TestToken_RedirectURIMismatch(t *testing.T) {
	store := testStore(t)
	store.SaveCode(&AuthCode{
		Code:          "code-redirect",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: pkceChallenge("v"),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testServerURL)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code-redirect"},
		"redirect_uri":  {"https://evil.com/callback"},
		"code_verifier": {"v"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestToken_JSONBody(t *testing.T) {
	store := testStore(t)
	verifier := "json-test-verifier"
	challenge := pkceChallenge(verifier)

	store.SaveCode(&AuthCode{
		Code:          "json-code",
		CodeChallenge: challenge,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testServerURL)

	body := `{"grant_type":"authorization_code","code":"json-code","code_verifier":"` + verifier + `"}`
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- PKCE ---

func TestVerifyPKCE_Valid(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)
	assert.True(t, verifyPKCE(verifier, challenge))
}

func TestVerifyPKCE_Invalid(t *testing.T) {
	assert.False(t, verifyPKCE("wrong-verifier", "wrong-challenge"))
}

// --- Middleware ---

func TestMiddleware_ValidToken(t *testing.T) {
	store := testStore(t)
	store.SaveToken(&models.OAuthToken{
		Token:     "valid-token",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	mw := Middleware(store, "https://vault.example.com")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())
}

func TestMiddleware_MissingToken(t *testing.T) {
	store := testStore(t)
	mw := Middleware(store, "https://vault.example.com")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "resource_metadata")
	assert.Contains(t, wwwAuth, "https://vault.example.com")
}

func TestMiddleware_InvalidToken(t *testing.T) {
	store := testStore(t)
	mw := Middleware(store, "https://vault.example.com")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddleware_ExpiredToken(t *testing.T) {
	store := testStore(t)
	store.SaveToken(&models.OAuthToken{
		Token:     "expired-token",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})

	mw := Middleware(store, "https://vault.example.com")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer expired-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddleware_NonBearerAuth(t *testing.T) {
	store := testStore(t)
	mw := Middleware(store, "https://vault.example.com")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
