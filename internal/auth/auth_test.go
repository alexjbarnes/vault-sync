package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/models"
	"github.com/alexjbarnes/vault-sync/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
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
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id="+clientID+"&redirect_uri="+url.QueryEscape(redirectURI)+"&code_challenge="+challenge+"&code_challenge_method=S256", nil)
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
	s.SaveCode(&Code{
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
	s.SaveCode(&Code{
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
	s.SaveCSRF("csrf123", "client1", "https://example.com/cb")

	assert.True(t, s.ConsumeCSRF("csrf123", "client1", "https://example.com/cb"))
	// Second consume should fail.
	assert.False(t, s.ConsumeCSRF("csrf123", "client1", "https://example.com/cb"))
}

func TestStore_CSRFEmpty(t *testing.T) {
	s := testStore(t)
	assert.False(t, s.ConsumeCSRF("", "", ""))
}

func TestStore_CSRFNotFound(t *testing.T) {
	s := testStore(t)
	assert.False(t, s.ConsumeCSRF("nonexistent", "", ""))
}

func TestStore_CSRFWrongBinding(t *testing.T) {
	s := testStore(t)
	s.SaveCSRF("csrf456", "client1", "https://example.com/cb")

	// Wrong client_id should fail.
	assert.False(t, s.ConsumeCSRF("csrf456", "wrong-client", "https://example.com/cb"))
}

func TestStore_CSRFWrongRedirect(t *testing.T) {
	s := testStore(t)
	s.SaveCSRF("csrf789", "client1", "https://example.com/cb")

	// Wrong redirect_uri should fail.
	assert.False(t, s.ConsumeCSRF("csrf789", "client1", "https://evil.com/cb"))
}

func TestStore_Cleanup(t *testing.T) {
	s := testStore(t)

	s.SaveCode(&Code{
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
	assert.Empty(t, meta.ScopesSupported)
}

func TestServerMetadata(t *testing.T) {
	handler := HandleServerMetadata("https://vault.example.com")
	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var meta ServerMetadata
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
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id="+clientID+"&redirect_uri=https://example.com/callback&state=xyz&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "vault-sync")
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
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id="+clientID+"&redirect_uri=https://evil.com/steal&code_challenge="+challenge, nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "redirect_uri not registered")
}

func TestAuthorize_GET_MissingPKCE(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})

	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id="+clientID+"&redirect_uri=https://example.com/callback&state=xyz", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	// After redirect_uri is validated, errors redirect to the client
	// per RFC 6749 Section 4.1.2.1.
	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")
	assert.Contains(t, location, "error=invalid_request")
	assert.Contains(t, location, "code_challenge")
	assert.Contains(t, location, "state=xyz")
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

func TestAuthorize_POST_RedirectURIWithQueryParams(t *testing.T) {
	store := testStore(t)
	redirectURI := "https://example.com/callback?existing=param"
	clientID := registerTestClient(t, store, []string{redirectURI})
	users := testUsers(t)
	handler := HandleAuthorize(store, users, testLogger(), testServerURL)

	// Get CSRF token (need to build the request manually since
	// getCSRFToken hardcodes a simple redirect URI).
	challenge := pkceChallenge("test-verifier")
	getReq := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id="+clientID+
		"&redirect_uri="+url.QueryEscape(redirectURI)+
		"&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	getRec := httptest.NewRecorder()
	handler(getRec, getReq)
	require.Equal(t, http.StatusOK, getRec.Code)

	re := regexp.MustCompile(`name="csrf_token" value="([a-f0-9]+)"`)
	matches := re.FindStringSubmatch(getRec.Body.String())
	require.Len(t, matches, 2)
	csrfToken := matches[1]

	form := url.Values{
		"csrf_token":            {csrfToken},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
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

	// The redirect should use "&" not "?" since the URI already has query params.
	u, err := url.Parse(location)
	require.NoError(t, err)
	assert.Equal(t, "param", u.Query().Get("existing"))
	assert.NotEmpty(t, u.Query().Get("code"))
	assert.Equal(t, "mystate", u.Query().Get("state"))
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
	store.SaveCSRF("manual-csrf", clientID, "https://example.com/callback")

	form := url.Values{
		"csrf_token":   {"manual-csrf"},
		"client_id":    {clientID},
		"redirect_uri": {"https://example.com/callback"},
		"state":        {"xyz"},
		"username":     {"testuser"},
		"password":     {"password123"},
	}

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	// Missing PKCE redirects with error after redirect_uri is validated.
	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")
	assert.Contains(t, location, "error=invalid_request")
	assert.Contains(t, location, "code_challenge")
	assert.Contains(t, location, "state=xyz")
}

func TestAuthorize_POST_RateLimited(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})
	users := testUsers(t)
	handler := HandleAuthorize(store, users, testLogger(), testServerURL)

	challenge := pkceChallenge("v")

	redirectURI := "https://example.com/callback"

	// Exhaust the rate limit with failed attempts.
	for i := 0; i < rateLimitMaxFail; i++ {
		csrf := generateCSRFToken(store, clientID, redirectURI)
		form := url.Values{
			"csrf_token":     {csrf},
			"client_id":      {clientID},
			"redirect_uri":   {redirectURI},
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

	// The next attempt should be rate-limited.
	csrf := generateCSRFToken(store, clientID, redirectURI)
	form := url.Values{
		"csrf_token":     {csrf},
		"client_id":      {clientID},
		"redirect_uri":   {redirectURI},
		"code_challenge": {challenge},
		"username":       {"testuser"},
		"password":       {"wrong"},
	}
	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
}

func TestAuthorize_GET_MissingResponseType(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})
	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)
	challenge := pkceChallenge("v")

	// No response_type parameter at all.
	req := httptest.NewRequest("GET", "/oauth/authorize?client_id="+clientID+
		"&redirect_uri=https://example.com/callback"+
		"&code_challenge="+challenge+"&state=abc", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")
	assert.Contains(t, location, "error=invalid_request")
	assert.Contains(t, location, "state=abc")
}

func TestAuthorize_GET_WrongResponseType(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})
	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)
	challenge := pkceChallenge("v")

	// response_type=token (implicit flow) should be rejected.
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=token&client_id="+clientID+
		"&redirect_uri=https://example.com/callback"+
		"&code_challenge="+challenge, nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")
	assert.Contains(t, location, "error=unsupported_response_type")
}

// --- Security fix tests ---

func TestToken_AuthCodeClientIDMismatch(t *testing.T) {
	store := testStore(t)
	store.RegisterClient(&models.OAuthClient{ClientID: "client-A", RedirectURIs: []string{"https://example.com/callback"}})
	store.RegisterClient(&models.OAuthClient{ClientID: "client-B", RedirectURIs: []string{"https://example.com/callback"}})

	verifier := "mismatch-verifier"
	challenge := pkceChallenge(verifier)

	store.SaveCode(&Code{
		Code:          "bound-code",
		ClientID:      "client-A",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: challenge,
		UserID:        "testuser",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testLogger(), testServerURL)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"bound-code"},
		"redirect_uri":  {"https://example.com/callback"},
		"code_verifier": {verifier},
		"client_id":     {"client-B"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "client_id mismatch")
}

func TestAuthorize_GET_ClickjackHeaders(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})
	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)

	challenge := pkceChallenge("v")
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id="+clientID+
		"&redirect_uri=https://example.com/callback"+
		"&code_challenge="+challenge, nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "frame-ancestors 'none'", rec.Header().Get("Content-Security-Policy"))
}

func TestRegistration_RejectsImplicitGrant(t *testing.T) {
	store := testStore(t)

	handler := HandleRegistration(store)

	body := `{"client_name":"Test","redirect_uris":["https://example.com/cb"],"grant_types":["implicit"]}`

	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "not available through dynamic registration")
}

func TestRegistration_RejectsPasswordGrant(t *testing.T) {
	store := testStore(t)

	handler := HandleRegistration(store)

	body := `{"client_name":"Test","redirect_uris":["https://example.com/cb"],"grant_types":["password"]}`

	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "not available through dynamic registration")
}

// --- Client credentials grant ---

// registerPreConfiguredClient creates a client with a hashed secret,
// simulating what main.go does. Pre-configured clients only support
// the client_credentials grant type for headless authentication.
func registerPreConfiguredClient(t *testing.T, store *Store, clientID, secret string) {
	t.Helper()

	store.RegisterPreConfiguredClient(&models.OAuthClient{
		ClientID:   clientID,
		SecretHash: HashSecret(secret),
		GrantTypes: []string{"client_credentials"},
	})
}

func TestClientCredentials_Success(t *testing.T) {
	store := testStore(t)
	registerPreConfiguredClient(t, store, "bot-client", "s3cret")

	handler := HandleToken(store, testLogger(), testServerURL)

	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"bot-client"},
		"client_secret": {"s3cret"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.AccessToken)
	assert.Empty(t, resp.RefreshToken, "client_credentials should not issue refresh tokens (RFC 6749 4.4.3)")
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, int(tokenExpiry.Seconds()), resp.ExpiresIn)
}

func TestClientCredentials_WrongSecret(t *testing.T) {
	store := testStore(t)
	registerPreConfiguredClient(t, store, "bot-client", "s3cret")

	handler := HandleToken(store, testLogger(), testServerURL)

	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"bot-client"},
		"client_secret": {"wrong-secret"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_client")
}

func TestClientCredentials_MissingSecret(t *testing.T) {
	store := testStore(t)
	registerPreConfiguredClient(t, store, "bot-client", "s3cret")

	handler := HandleToken(store, testLogger(), testServerURL)

	body := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"bot-client"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "client_id and client_secret are required")
}

func TestClientCredentials_MissingClientID(t *testing.T) {
	store := testStore(t)

	handler := HandleToken(store, testLogger(), testServerURL)

	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_secret": {"s3cret"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestClientCredentials_UnknownClient(t *testing.T) {
	store := testStore(t)

	handler := HandleToken(store, testLogger(), testServerURL)

	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"nonexistent"},
		"client_secret": {"whatever"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	// Unknown client gets the same 401 as wrong-secret to avoid
	// leaking whether the client_id is registered.
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_client")
}

func TestClientCredentials_DynamicClientCannotUse(t *testing.T) {
	store := testStore(t)

	// Dynamically registered client has authorization_code grant.
	clientID := registerTestClient(t, store, []string{"https://example.com/cb"})

	handler := HandleToken(store, testLogger(), testServerURL)

	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {"anything"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	// Dynamic client has no secret hash, so secret validation fails
	// with the same 401 as an unknown client (no information leak).
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_client")
}

func TestPreConfigured_AuthCodeFlowRejected(t *testing.T) {
	store := testStore(t)
	registerPreConfiguredClient(t, store, "bot-client", "s3cret")

	verifier := "preconfigured-verifier"
	challenge := pkceChallenge(verifier)

	store.SaveCode(&Code{
		Code:          "preconfig-code",
		ClientID:      "bot-client",
		RedirectURI:   "http://127.0.0.1:19876/callback",
		CodeChallenge: challenge,
		UserID:        "testuser",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testLogger(), testServerURL)

	body := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"preconfig-code"},
		"redirect_uri":  {"http://127.0.0.1:19876/callback"},
		"code_verifier": {verifier},
		"client_id":     {"bot-client"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	// Pre-configured clients only support client_credentials.
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unauthorized_client")
}

func TestClientCredentials_WithResource(t *testing.T) {
	store := testStore(t)
	registerPreConfiguredClient(t, store, "bot-client", "s3cret")

	handler := HandleToken(store, testLogger(), testServerURL)

	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"bot-client"},
		"client_secret": {"s3cret"},
		"resource":      {testServerURL},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.AccessToken)
	assert.Empty(t, resp.RefreshToken)
}

func TestClientCredentials_WrongResource(t *testing.T) {
	store := testStore(t)
	registerPreConfiguredClient(t, store, "bot-client", "s3cret")

	handler := HandleToken(store, testLogger(), testServerURL)

	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"bot-client"},
		"client_secret": {"s3cret"},
		"resource":      {"https://evil.example.com"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_target")
}

func TestClientCredentials_JSONBody(t *testing.T) {
	store := testStore(t)
	registerPreConfiguredClient(t, store, "bot-client", "s3cret")

	handler := HandleToken(store, testLogger(), testServerURL)

	body := `{"grant_type":"client_credentials","client_id":"bot-client","client_secret":"s3cret"}`

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.AccessToken)
	assert.Empty(t, resp.RefreshToken)
}

func TestClientCredentials_JSONBodyWithCharset(t *testing.T) {
	store := testStore(t)
	registerPreConfiguredClient(t, store, "bot-client", "s3cret")

	handler := HandleToken(store, testLogger(), testServerURL)

	body := `{"grant_type":"client_credentials","client_id":"bot-client","client_secret":"s3cret"}`

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.AccessToken)
}

func TestClientCredentials_TokenUsableAsBearer(t *testing.T) {
	store := testStore(t)
	registerPreConfiguredClient(t, store, "bot-client", "s3cret")

	handler := HandleToken(store, testLogger(), testServerURL)

	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"bot-client"},
		"client_secret": {"s3cret"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	// Verify the access token passes bearer validation.
	token := store.ValidateToken(resp.AccessToken)
	require.NotNil(t, token)
	assert.Equal(t, "bot-client", token.UserID)
	assert.Equal(t, "bot-client", token.ClientID)
	assert.Equal(t, testServerURL, token.Resource)

	// No refresh token on the access token record either.
	assert.Empty(t, token.RefreshToken)
}

func TestClientCredentials_NoRefreshToken(t *testing.T) {
	store := testStore(t)
	registerPreConfiguredClient(t, store, "bot-client", "s3cret")

	handler := HandleToken(store, testLogger(), testServerURL)

	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"bot-client"},
		"client_secret": {"s3cret"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	// RFC 6749 Section 4.4.3: no refresh token for client_credentials.
	assert.Empty(t, resp.RefreshToken)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestRegistration_BlocksClientCredentials(t *testing.T) {
	store := testStore(t)

	handler := HandleRegistration(store)

	body := `{"client_name":"Bot","redirect_uris":["https://example.com/cb"],"grant_types":["client_credentials"]}`

	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "not available through dynamic registration")
}

func TestRegistration_BlocksClientCredentialsMixed(t *testing.T) {
	store := testStore(t)

	handler := HandleRegistration(store)

	body := `{"client_name":"Bot","redirect_uris":["https://example.com/cb"],"grant_types":["authorization_code","client_credentials"]}`

	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "not available through dynamic registration")
}

func TestStore_ValidateClientSecret(t *testing.T) {
	store := testStore(t)
	registerPreConfiguredClient(t, store, "test-client", "correct-secret")

	assert.True(t, store.ValidateClientSecret("test-client", "correct-secret"))
	assert.False(t, store.ValidateClientSecret("test-client", "wrong-secret"))
	assert.False(t, store.ValidateClientSecret("nonexistent", "any-secret"))
}

func TestStore_ValidateClientSecret_NoHash(t *testing.T) {
	store := testStore(t)

	// Client without SecretHash (dynamically registered).
	registerTestClient(t, store, []string{"https://example.com/cb"})

	// ValidateClientSecret should return false for clients without a hash.
	clients := store.clients
	for clientID := range clients {
		assert.False(t, store.ValidateClientSecret(clientID, "any"))
	}
}

func TestHashSecret_Deterministic(t *testing.T) {
	h1 := HashSecret("test-secret")
	h2 := HashSecret("test-secret")
	assert.Equal(t, h1, h2)

	h3 := HashSecret("different-secret")
	assert.NotEqual(t, h1, h3)
}

func TestMetadata_IncludesClientCredentials(t *testing.T) {
	handler := HandleServerMetadata(testServerURL)

	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var meta ServerMetadata
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&meta))

	assert.Contains(t, meta.GrantTypesSupported, "client_credentials")
	assert.Contains(t, meta.TokenEndpointAuthMethodsSupported, "client_secret_post")
}

// --- Token endpoint rate limiting and lockout ---

func TestToken_IPRateLimit(t *testing.T) {
	store := testStore(t)

	handler := HandleToken(store, testLogger(), testServerURL)

	// Send tokenRateLimitMaxFail+1 requests from the same IP with bad codes.
	for i := 0; i < tokenRateLimitMaxFail; i++ {
		body := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"bad-code"},
			"code_verifier": {"verifier"},
		}

		req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "1.2.3.4:5678"

		rec := httptest.NewRecorder()
		handler(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	}

	// The next request from the same IP should be rate limited.
	body := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"bad-code"},
		"code_verifier": {"verifier"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "1.2.3.4:5678"

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Contains(t, rec.Body.String(), "slow_down")
}

func TestToken_ClientLockout(t *testing.T) {
	store := testStore(t)

	clientID := registerTestClient(t, store, []string{"https://example.com/cb"})

	handler := HandleToken(store, testLogger(), testServerURL)

	// Send lockoutThreshold requests with bad codes from different IPs.
	for i := 0; i < lockoutThreshold; i++ {
		body := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"bad-code"},
			"client_id":     {clientID},
			"code_verifier": {"verifier"},
		}

		req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "10.0.0." + url.QueryEscape(strings.Repeat("1", i%10)) + ":5678"

		rec := httptest.NewRecorder()
		handler(rec, req)
	}

	// The client should now be locked out even from a new IP.
	body := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"any-code"},
		"client_id":     {clientID},
		"code_verifier": {"verifier"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "99.99.99.99:5678"

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Contains(t, rec.Body.String(), "account locked")
}

func TestToken_GrantTypeEnforcement(t *testing.T) {
	store := testStore(t)

	// Register client with only client_credentials grant.
	clientID := RandomHex(16)
	ok := store.RegisterClient(&models.OAuthClient{
		ClientID:   clientID,
		GrantTypes: []string{"client_credentials"},
	})
	require.True(t, ok)

	handler := HandleToken(store, testLogger(), testServerURL)

	// Attempt authorization_code grant with this client should fail.
	body := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"some-code"},
		"client_id":     {clientID},
		"code_verifier": {"verifier"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unauthorized_client")
}

func TestToken_DefaultGrantTypeAllowsAuthCode(t *testing.T) {
	store := testStore(t)

	// Register client without explicit grant types (should default to authorization_code).
	clientID := registerTestClient(t, store, []string{"https://example.com/cb"})

	handler := HandleToken(store, testLogger(), testServerURL)

	// authorization_code should be allowed (will fail on the code itself, not on grant type).
	body := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"bad-code"},
		"client_id":     {clientID},
		"code_verifier": {"verifier"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	// Should fail with invalid_grant (bad code), not unauthorized_client.
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_grant")
}

func TestToken_RefreshAlwaysAllowed(t *testing.T) {
	store := testStore(t)

	// Register client with only authorization_code (no explicit refresh_token).
	clientID := RandomHex(16)
	ok := store.RegisterClient(&models.OAuthClient{
		ClientID:   clientID,
		GrantTypes: []string{"authorization_code"},
	})
	require.True(t, ok)

	// Save a refresh token for this client.
	store.SaveToken(&models.OAuthToken{
		Token:     "test-refresh",
		Kind:      "refresh",
		UserID:    "testuser",
		Resource:  testServerURL,
		ExpiresAt: time.Now().Add(refreshTokenExpiry),
		ClientID:  clientID,
	})

	handler := HandleToken(store, testLogger(), testServerURL)

	body := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"test-refresh"},
		"client_id":     {clientID},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	// Should succeed -- refresh_token is always allowed.
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
}

func TestRegistration_StoresGrantTypes(t *testing.T) {
	store := testStore(t)

	handler := HandleRegistration(store)

	body := `{"client_name":"Test","redirect_uris":["https://example.com/cb"],"grant_types":["authorization_code"]}`

	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)

	var resp registrationResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	// Verify the grant types are stored on the client.
	client := store.GetClient(resp.ClientID)
	require.NotNil(t, client)
	assert.Equal(t, []string{"authorization_code"}, client.GrantTypes)
}

func TestRegistration_AllowsRefreshTokenGrant(t *testing.T) {
	store := testStore(t)

	handler := HandleRegistration(store)

	body := `{"client_name":"Test","redirect_uris":["https://example.com/cb"],"grant_types":["authorization_code","refresh_token"]}`

	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)

	var resp registrationResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	client := store.GetClient(resp.ClientID)
	require.NotNil(t, client)
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, client.GrantTypes)
}

// --- Resource Parameter (RFC 8707) ---

func TestAuthorize_GET_ResourceParameter(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})
	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)
	challenge := pkceChallenge("test-verifier")

	// Valid resource parameter shows login form.
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id="+clientID+
		"&redirect_uri=https://example.com/callback"+
		"&code_challenge="+challenge+
		"&resource="+url.QueryEscape(testServerURL), nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "vault-sync")
	assert.Contains(t, rec.Body.String(), testServerURL)
}

func TestAuthorize_GET_WrongResource(t *testing.T) {
	store := testStore(t)
	clientID := registerTestClient(t, store, []string{"https://example.com/callback"})
	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)
	challenge := pkceChallenge("test-verifier")

	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id="+clientID+
		"&redirect_uri=https://example.com/callback"+
		"&code_challenge="+challenge+
		"&resource="+url.QueryEscape("https://evil.example.com"), nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	// Bad resource redirects with error after redirect_uri is validated.
	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")
	assert.Contains(t, location, "error=invalid_request")
	assert.Contains(t, location, "resource")
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
	store.RegisterClient(&models.OAuthClient{ClientID: "client1", RedirectURIs: []string{"https://example.com/callback"}})

	verifier := "resource-test-verifier"
	challenge := pkceChallenge(verifier)

	store.SaveCode(&Code{
		Code:          "res-code",
		ClientID:      "client1",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: challenge,
		Resource:      testServerURL,
		UserID:        "testuser",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testLogger(), testServerURL)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"res-code"},
		"redirect_uri":  {"https://example.com/callback"},
		"code_verifier": {verifier},
		"client_id":     {"client1"},
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

	store.SaveCode(&Code{
		Code:          "wrong-res-code",
		CodeChallenge: challenge,
		Resource:      testServerURL,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testLogger(), testServerURL)

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

	asm := HandleServerMetadata(testServerURL)
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

	asm := HandleServerMetadata(testServerURL)
	req = httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	rec = httptest.NewRecorder()
	asm(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Cache-Control"), "max-age=")
}

// --- Token ---

func TestToken_FullFlow(t *testing.T) {
	store := testStore(t)
	store.RegisterClient(&models.OAuthClient{ClientID: "client1", RedirectURIs: []string{"https://example.com/callback"}})

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)

	store.SaveCode(&Code{
		Code:          "authcode123",
		ClientID:      "client1",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: challenge,
		UserID:        "testuser",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testLogger(), testServerURL)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"authcode123"},
		"redirect_uri":  {"https://example.com/callback"},
		"code_verifier": {verifier},
		"client_id":     {"client1"},
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
	assert.Positive(t, resp.ExpiresIn)

	// Validate the issued token works.
	ti := store.ValidateToken(resp.AccessToken)
	require.NotNil(t, ti)
	assert.Equal(t, "testuser", ti.UserID)
}

func TestToken_InvalidCode(t *testing.T) {
	store := testStore(t)
	handler := HandleToken(store, testLogger(), testServerURL)

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
	handler := HandleToken(store, testLogger(), testServerURL)

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
	store.SaveCode(&Code{
		Code:          "code-with-pkce",
		CodeChallenge: "validchallenge",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testLogger(), testServerURL)

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
	store.SaveCode(&Code{
		Code:          "code-needs-pkce",
		CodeChallenge: pkceChallenge("verifier"),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testLogger(), testServerURL)

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
	store.SaveCode(&Code{
		Code:      "no-pkce-code",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testLogger(), testServerURL)

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
	store.SaveCode(&Code{
		Code:          "code-redirect",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: pkceChallenge("v"),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testLogger(), testServerURL)

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

	store.SaveCode(&Code{
		Code:          "json-code",
		CodeChallenge: challenge,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testLogger(), testServerURL)

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

func TestMiddleware_InjectsRequestContext(t *testing.T) {
	store := testStore(t)
	store.SaveToken(&models.OAuthToken{
		Token:     "ctx-token",
		UserID:    "ctx-user",
		ClientID:  "ctx-client",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	mw := Middleware(store, "https://vault.example.com")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "ctx-user", RequestUserID(r.Context()))
		assert.Equal(t, "ctx-client", RequestClientID(r.Context()))
		assert.NotEmpty(t, RequestRemoteIP(r.Context()))
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer ctx-token")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

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
		_, _ = w.Write([]byte("ok"))
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
	// RFC 6750: no error attribute when no token was provided
	assert.NotContains(t, wwwAuth, "invalid_token")
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
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error="invalid_token"`)
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

// --- Refresh Token ---

func TestToken_FullFlowWithRefresh(t *testing.T) {
	store := testStore(t)
	store.RegisterClient(&models.OAuthClient{ClientID: "client1", RedirectURIs: []string{"https://example.com/callback"}})

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)

	store.SaveCode(&Code{
		Code:          "authcode-with-refresh",
		ClientID:      "client1",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: challenge,
		UserID:        "testuser",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testLogger(), testServerURL)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"authcode-with-refresh"},
		"redirect_uri":  {"https://example.com/callback"},
		"code_verifier": {verifier},
		"client_id":     {"client1"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, 3600, resp.ExpiresIn) // 1 hour

	// Validate the issued tokens.
	ti := store.ValidateToken(resp.AccessToken)
	require.NotNil(t, ti)
	assert.Equal(t, "testuser", ti.UserID)
	assert.Equal(t, "access", ti.Kind)
	assert.Equal(t, HashSecret(resp.RefreshToken), ti.RefreshHash)
	assert.Equal(t, "client1", ti.ClientID)

	// Validate the refresh token exists.
	rt := store.ValidateRefreshToken(resp.RefreshToken, "client1", "")
	require.NotNil(t, rt)
	assert.Equal(t, "refresh", rt.Kind)
	assert.Equal(t, "testuser", rt.UserID)
}

func TestToken_RefreshGrant(t *testing.T) {
	store := testStore(t)

	// Create an existing refresh token.
	refreshToken := RandomHex(32)
	accessToken := RandomHex(32)
	store.SaveToken(&models.OAuthToken{
		Token:        refreshToken,
		Kind:         "refresh",
		UserID:       "testuser",
		Resource:     testServerURL,
		Scopes:       []string{"vault:read"},
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
		RefreshToken: accessToken,
		ClientID:     "client1",
	})

	handler := HandleToken(store, testLogger(), testServerURL)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"client1"},
		"resource":      {testServerURL},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.NotEqual(t, refreshToken, resp.RefreshToken)

	// Old refresh token should be deleted.
	assert.Nil(t, store.ValidateRefreshToken(refreshToken, "client1", ""))

	// New tokens should work.
	ti := store.ValidateToken(resp.AccessToken)
	require.NotNil(t, ti)
	assert.Equal(t, "testuser", ti.UserID)
	assert.Equal(t, "client1", ti.ClientID)
}

func TestToken_RefreshRotation(t *testing.T) {
	store := testStore(t)

	// Create existing tokens.
	refreshToken := RandomHex(32)
	store.SaveToken(&models.OAuthToken{
		Token:     refreshToken,
		Kind:      "refresh",
		UserID:    "testuser",
		Resource:  testServerURL,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		ClientID:  "client1",
	})

	handler := HandleToken(store, testLogger(), testServerURL)

	// First refresh.
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"client1"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp1 tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp1))

	// Old refresh token should be invalid.
	assert.Nil(t, store.ValidateRefreshToken(refreshToken, "client1", ""))

	// Second refresh with old token should fail.
	form2 := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"client1"},
	}

	req2 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec2 := httptest.NewRecorder()
	handler(rec2, req2)

	assert.Equal(t, http.StatusBadRequest, rec2.Code)
	assert.Contains(t, rec2.Body.String(), "invalid or expired refresh token")
}

func TestToken_RefreshExpired(t *testing.T) {
	store := testStore(t)

	// Create an expired refresh token.
	refreshToken := RandomHex(32)
	store.SaveToken(&models.OAuthToken{
		Token:     refreshToken,
		Kind:      "refresh",
		UserID:    "testuser",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
	})

	handler := HandleToken(store, testLogger(), testServerURL)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid or expired refresh token")
}

func TestToken_RefreshWrongClient(t *testing.T) {
	store := testStore(t)

	// Create refresh token for client1.
	refreshToken := RandomHex(32)
	store.SaveToken(&models.OAuthToken{
		Token:     refreshToken,
		Kind:      "refresh",
		UserID:    "testuser",
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		ClientID:  "client1",
	})

	handler := HandleToken(store, testLogger(), testServerURL)

	// Try to refresh with different client_id.
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"client2"}, // Different client
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid or expired refresh token")
}

func TestToken_RefreshWrongResource(t *testing.T) {
	store := testStore(t)

	// Create refresh token for a different resource.
	refreshToken := RandomHex(32)
	store.SaveToken(&models.OAuthToken{
		Token:     refreshToken,
		Kind:      "refresh",
		UserID:    "testuser",
		Resource:  "https://other-server.example.com",
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		ClientID:  "client1",
	})

	handler := HandleToken(store, testLogger(), testServerURL)

	// Try to refresh with different resource.
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"resource":      {testServerURL},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid or expired refresh token")
}

func TestToken_RefreshMissingToken(t *testing.T) {
	store := testStore(t)
	handler := HandleToken(store, testLogger(), testServerURL)

	form := url.Values{
		"grant_type": {"refresh_token"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "refresh_token is required")
}

func TestMiddleware_ExpiredTokenHeader(t *testing.T) {
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
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error="invalid_token"`)
	assert.Contains(t, wwwAuth, "resource_metadata")
}

func TestStore_ValidateRefreshToken(t *testing.T) {
	store := testStore(t)

	// Valid refresh token.
	store.SaveToken(&models.OAuthToken{
		Token:     "valid-refresh",
		Kind:      "refresh",
		UserID:    "user1",
		Resource:  testServerURL,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		ClientID:  "client1",
	})

	rt := store.ValidateRefreshToken("valid-refresh", "client1", testServerURL)
	require.NotNil(t, rt)
	assert.Equal(t, "user1", rt.UserID)

	// Wrong kind (access token).
	store.SaveToken(&models.OAuthToken{
		Token:     "access-token",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	assert.Nil(t, store.ValidateRefreshToken("access-token", "", ""))

	// Expired.
	store.SaveToken(&models.OAuthToken{
		Token:     "expired-refresh",
		Kind:      "refresh",
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	assert.Nil(t, store.ValidateRefreshToken("expired-refresh", "", ""))

	// Not found.
	assert.Nil(t, store.ValidateRefreshToken("nonexistent", "", ""))
}

func TestStore_DeleteToken(t *testing.T) {
	store := testStore(t)

	store.SaveToken(&models.OAuthToken{
		Token:     "token-to-delete",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	// Verify token exists.
	require.NotNil(t, store.ValidateToken("token-to-delete"))

	// Delete it.
	store.DeleteToken("token-to-delete")

	// Verify it's gone.
	assert.Nil(t, store.ValidateToken("token-to-delete"))
}

func TestServerMetadata_RefreshTokenGrant(t *testing.T) {
	handler := HandleServerMetadata("https://vault.example.com")
	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var meta ServerMetadata
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&meta))
	assert.Contains(t, meta.GrantTypesSupported, "authorization_code")
	assert.Contains(t, meta.GrantTypesSupported, "refresh_token")
}

func TestToken_RefreshWithoutClientID(t *testing.T) {
	store := testStore(t)

	// Create refresh token for a specific client.
	refreshToken := RandomHex(32)
	store.SaveToken(&models.OAuthToken{
		Token:     refreshToken,
		Kind:      "refresh",
		UserID:    "testuser",
		Resource:  testServerURL,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		ClientID:  "client1",
	})

	handler := HandleToken(store, testLogger(), testServerURL)

	// Try to refresh WITHOUT client_id - should fail because client_id is required
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		// NO client_id!
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	// This should fail because client_id is required to match
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestToken_RefreshDeletesOldAccessToken(t *testing.T) {
	store := testStore(t)

	// Create an access token and refresh token pair the way the actual code does.
	// Access token has RefreshToken pointing to refresh token.
	// Refresh token does NOT have RefreshToken set.
	refreshToken := RandomHex(32)
	accessToken := RandomHex(32)

	// Save refresh token (no RefreshToken field set - this is how it's created)
	store.SaveToken(&models.OAuthToken{
		Token:     refreshToken,
		Kind:      "refresh",
		UserID:    "testuser",
		Resource:  testServerURL,
		Scopes:    []string{"vault:read"},
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		ClientID:  "client1",
	})

	// Save access token (has RefreshToken pointing to refresh token)
	store.SaveToken(&models.OAuthToken{
		Token:        accessToken,
		Kind:         "access",
		UserID:       "testuser",
		Resource:     testServerURL,
		Scopes:       []string{"vault:read"},
		ExpiresAt:    time.Now().Add(time.Hour), // Still valid
		RefreshToken: refreshToken,
		ClientID:     "client1",
	})

	handler := HandleToken(store, testLogger(), testServerURL)

	// Refresh the token
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"client1"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	// The old refresh token should be deleted (rotated)
	assert.Nil(t, store.ValidateRefreshToken(refreshToken, "client1", ""))

	// The old access token should be revoked during refresh rotation.
	ti := store.ValidateToken(accessToken)
	assert.Nil(t, ti, "old access token should be revoked after refresh")
}

func TestToken_AccessTokenUsedAsRefresh(t *testing.T) {
	store := testStore(t)

	// Create an access token
	accessToken := RandomHex(32)
	store.SaveToken(&models.OAuthToken{
		Token:     accessToken,
		Kind:      "access",
		UserID:    "testuser",
		ExpiresAt: time.Now().Add(time.Hour),
		ClientID:  "client1",
	})

	handler := HandleToken(store, testLogger(), testServerURL)

	// Try to use access token as refresh token
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {accessToken},
		"client_id":     {"client1"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	// Should fail because it's an access token, not a refresh token
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid or expired refresh token")
}

func TestToken_RefreshTokenReuseFails(t *testing.T) {
	store := testStore(t)

	// Create a refresh token
	refreshToken := RandomHex(32)
	store.SaveToken(&models.OAuthToken{
		Token:     refreshToken,
		Kind:      "refresh",
		UserID:    "testuser",
		Resource:  testServerURL,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		ClientID:  "client1",
	})

	handler := HandleToken(store, testLogger(), testServerURL)

	// First refresh should succeed
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"client1"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	// Second refresh with same token should fail (token was rotated)
	form2 := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"client1"},
	}

	req2 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec2 := httptest.NewRecorder()
	handler(rec2, req2)

	assert.Equal(t, http.StatusBadRequest, rec2.Code)
	assert.Contains(t, rec2.Body.String(), "invalid or expired refresh token")
}

// --- Spec compliance tests ---

func TestClientCredentials_BasicAuth(t *testing.T) {
	store := testStore(t)
	registerPreConfiguredClient(t, store, "basic-client", "basic-secret")

	handler := HandleToken(store, testLogger(), testServerURL)

	// Send client_id and client_secret via HTTP Basic auth header
	// (client_secret_basic per RFC 6749 Section 2.3.1).
	body := url.Values{
		"grant_type": {"client_credentials"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("basic-client", "basic-secret")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
}

func TestClientCredentials_BasicAuthOverridesBody(t *testing.T) {
	store := testStore(t)
	registerPreConfiguredClient(t, store, "basic-client", "basic-secret")

	handler := HandleToken(store, testLogger(), testServerURL)

	// Body has wrong credentials, Basic auth has correct ones.
	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"wrong-client"},
		"client_secret": {"wrong-secret"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("basic-client", "basic-secret")

	rec := httptest.NewRecorder()
	handler(rec, req)

	// Basic auth overrides body credentials.
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestClientCredentials_BasicAuthWrongPassword(t *testing.T) {
	store := testStore(t)
	registerPreConfiguredClient(t, store, "basic-client", "basic-secret")

	handler := HandleToken(store, testLogger(), testServerURL)

	body := url.Values{
		"grant_type": {"client_credentials"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("basic-client", "wrong")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestToken_ScopeInResponse(t *testing.T) {
	store := testStore(t)
	store.RegisterClient(&models.OAuthClient{ClientID: "client1", RedirectURIs: []string{"https://example.com/callback"}})

	verifier := "scope-test-verifier"
	challenge := pkceChallenge(verifier)

	store.SaveCode(&Code{
		Code:          "scope-code",
		ClientID:      "client1",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: challenge,
		UserID:        "testuser",
		Scopes:        []string{"vault:read", "vault:write"},
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store, testLogger(), testServerURL)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"scope-code"},
		"redirect_uri":  {"https://example.com/callback"},
		"code_verifier": {verifier},
		"client_id":     {"client1"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "vault:read vault:write", resp.Scope)
}

func TestToken_PragmaNoCache(t *testing.T) {
	store := testStore(t)
	registerPreConfiguredClient(t, store, "bot-client", "s3cret")

	handler := HandleToken(store, testLogger(), testServerURL)

	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"bot-client"},
		"client_secret": {"s3cret"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))
}

func TestRegistration_ConfidentialClientGetsSecret(t *testing.T) {
	store := testStore(t)
	handler := HandleRegistration(store)

	body := `{"client_name":"Confidential","redirect_uris":["https://example.com/cb"],"token_endpoint_auth_method":"client_secret_post"}`
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)

	var resp registrationResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.ClientSecret, "confidential client should receive a client_secret")
	assert.Equal(t, "client_secret_post", resp.TokenEndpointAuthMethod)

	// The secret should authenticate against the store.
	assert.True(t, store.ValidateClientSecret(resp.ClientID, resp.ClientSecret))
}

func TestRegistration_PublicClientNoSecret(t *testing.T) {
	store := testStore(t)
	handler := HandleRegistration(store)

	body := `{"client_name":"Public","redirect_uris":["https://example.com/cb"]}`
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)

	var resp registrationResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Empty(t, resp.ClientSecret, "public client should not receive a client_secret")
	assert.Equal(t, "none", resp.TokenEndpointAuthMethod)
}

func TestRegistration_ClientIDIssuedAt(t *testing.T) {
	store := testStore(t)
	handler := HandleRegistration(store)

	body := `{"client_name":"Test","redirect_uris":["https://example.com/cb"]}`
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)

	var resp registrationResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Positive(t, resp.ClientIDIssuedAt, "client_id_issued_at should be a positive Unix timestamp")
}

func TestRegistration_PersistsResponseTypesAndAuthMethod(t *testing.T) {
	store := testStore(t)
	handler := HandleRegistration(store)

	body := `{"client_name":"Test","redirect_uris":["https://example.com/cb"],"response_types":["code"],"token_endpoint_auth_method":"none"}`
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)

	var resp registrationResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	client := store.GetClient(resp.ClientID)
	require.NotNil(t, client)
	assert.Equal(t, []string{"code"}, client.ResponseTypes)
	assert.Equal(t, "none", client.TokenEndpointAuthMethod)
}

func TestRegistration_RejectsWrongContentType(t *testing.T) {
	store := testStore(t)
	handler := HandleRegistration(store)

	body := `{"client_name":"Test","redirect_uris":["https://example.com/cb"]}`
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code)
}

func TestRegistration_AcceptsNoContentType(t *testing.T) {
	store := testStore(t)
	handler := HandleRegistration(store)

	// Some clients may omit Content-Type entirely. We accept it
	// rather than being overly strict, since json.Decoder handles it.
	body := `{"client_name":"Test","redirect_uris":["https://example.com/cb"]}`
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestAuthorize_POST_IssInResponse(t *testing.T) {
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

	u, err := url.Parse(location)
	require.NoError(t, err)

	// RFC 9207: iss parameter prevents mix-up attacks.
	assert.Equal(t, testServerURL, u.Query().Get("iss"))
}

func TestAuthorize_POST_ScopeBindsToCode(t *testing.T) {
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
		"scope":                 {"vault:read vault:write"},
		"username":              {"testuser"},
		"password":              {"password123"},
	}

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")

	u, err := url.Parse(location)
	require.NoError(t, err)

	code := u.Query().Get("code")
	ac := store.ConsumeCode(code)
	require.NotNil(t, ac)
	assert.Equal(t, []string{"vault:read", "vault:write"}, ac.Scopes)
}

func TestAuthorize_GET_LocalhostPrefixRedirect(t *testing.T) {
	store := testStore(t)

	// Register a client with localhost prefix redirect URIs
	// (same as pre-configured clients).
	store.RegisterClient(&models.OAuthClient{
		ClientID: "localhost-client",
		RedirectURIs: []string{
			"http://127.0.0.1",
			"http://localhost",
		},
	})

	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)
	challenge := pkceChallenge("v")

	// Any port and path on 127.0.0.1 should be accepted (RFC 8252 Section 7.3).
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id=localhost-client"+
		"&redirect_uri="+url.QueryEscape("http://127.0.0.1:19876/mcp/oauth/callback")+
		"&code_challenge="+challenge, nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Sign in")
}

func TestAuthorize_GET_LocalhostPrefixRejectsHTTPS(t *testing.T) {
	store := testStore(t)

	store.RegisterClient(&models.OAuthClient{
		ClientID:     "localhost-client",
		RedirectURIs: []string{"http://127.0.0.1"},
	})

	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)
	challenge := pkceChallenge("v")

	// HTTPS on 127.0.0.1 should not match the http:// prefix.
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id=localhost-client"+
		"&redirect_uri="+url.QueryEscape("https://127.0.0.1:19876/callback")+
		"&code_challenge="+challenge, nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAuthorize_GET_PreConfiguredNoRedirectURIs_RejectsHTTPS(t *testing.T) {
	store := testStore(t)
	registerPreConfiguredClient(t, store, "preconfig-client", "s3cret")

	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)
	challenge := pkceChallenge("v")

	// Pre-configured clients with no registered redirect URIs only accept
	// loopback URIs. Non-loopback HTTPS URIs should be rejected.
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id=preconfig-client"+
		"&redirect_uri="+url.QueryEscape("https://claude.ai/api/mcp/auth_callback")+
		"&code_challenge="+challenge, nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAuthorize_GET_PreConfiguredNoRedirectURIs_AcceptsLoopback(t *testing.T) {
	store := testStore(t)
	registerPreConfiguredClient(t, store, "preconfig-client", "s3cret")

	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)
	challenge := pkceChallenge("v")

	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id=preconfig-client"+
		"&redirect_uri="+url.QueryEscape("http://127.0.0.1:19876/callback")+
		"&code_challenge="+challenge, nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Sign in")
}

func TestAuthorize_GET_PreConfiguredNoRedirectURIs_RejectsHTTP(t *testing.T) {
	store := testStore(t)
	registerPreConfiguredClient(t, store, "preconfig-client", "s3cret")

	handler := HandleAuthorize(store, testUsers(t), testLogger(), testServerURL)
	challenge := pkceChallenge("v")

	// Plain HTTP to a non-loopback host should be rejected.
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id=preconfig-client"+
		"&redirect_uri="+url.QueryEscape("http://evil.com/steal")+
		"&code_challenge="+challenge, nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestMetadata_IncludesBasicAuth(t *testing.T) {
	handler := HandleServerMetadata(testServerURL)

	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var meta ServerMetadata
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&meta))
	assert.Contains(t, meta.TokenEndpointAuthMethodsSupported, "client_secret_basic")
}

func TestMiddleware_RefreshTokenAsBearer(t *testing.T) {
	store := testStore(t)

	// Save a refresh token
	store.SaveToken(&models.OAuthToken{
		Token:     "refresh-as-bearer",
		Kind:      "refresh",
		UserID:    "testuser",
		Resource:  "https://vault.example.com",
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		ClientID:  "client1",
	})

	mw := Middleware(store, "https://vault.example.com")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer refresh-as-bearer")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// --- API Key Store ---

func TestStore_RegisterAndValidateAPIKey(t *testing.T) {
	s := testStore(t)
	rawKey := "vs_" + RandomHex(32)

	s.RegisterAPIKey(rawKey, "deploy-bot")

	ak := s.ValidateAPIKey(rawKey)
	require.NotNil(t, ak)
	assert.Equal(t, "deploy-bot", ak.UserID)
	assert.Equal(t, HashSecret(rawKey), ak.KeyHash)
	assert.False(t, ak.CreatedAt.IsZero())
}

func TestStore_ValidateAPIKey_Unknown(t *testing.T) {
	s := testStore(t)

	ak := s.ValidateAPIKey("vs_" + RandomHex(32))
	assert.Nil(t, ak)
}

func TestStore_ValidateAPIKey_WrongKey(t *testing.T) {
	s := testStore(t)
	rawKey := "vs_" + RandomHex(32)
	wrongKey := "vs_" + RandomHex(32)

	s.RegisterAPIKey(rawKey, "user1")

	assert.Nil(t, s.ValidateAPIKey(wrongKey))
	assert.NotNil(t, s.ValidateAPIKey(rawKey))
}

func TestStore_RevokeAPIKey(t *testing.T) {
	s := testStore(t)
	rawKey := "vs_" + RandomHex(32)

	s.RegisterAPIKey(rawKey, "user1")
	require.NotNil(t, s.ValidateAPIKey(rawKey))

	s.RevokeAPIKey(HashSecret(rawKey))
	assert.Nil(t, s.ValidateAPIKey(rawKey))
}

func TestStore_ListAPIKeys(t *testing.T) {
	s := testStore(t)

	assert.Empty(t, s.ListAPIKeys())

	s.RegisterAPIKey("vs_"+RandomHex(32), "user1")
	s.RegisterAPIKey("vs_"+RandomHex(32), "user2")

	keys := s.ListAPIKeys()
	assert.Len(t, keys, 2)

	users := map[string]bool{}
	for _, k := range keys {
		users[k.UserID] = true
	}

	assert.True(t, users["user1"])
	assert.True(t, users["user2"])
}

func TestStore_RegisterAPIKey_OverwritesSameKey(t *testing.T) {
	s := testStore(t)
	rawKey := "vs_" + RandomHex(32)

	s.RegisterAPIKey(rawKey, "original-user")
	s.RegisterAPIKey(rawKey, "new-user")

	ak := s.ValidateAPIKey(rawKey)
	require.NotNil(t, ak)
	assert.Equal(t, "new-user", ak.UserID)
	assert.Len(t, s.ListAPIKeys(), 1)
}

// --- API Key Middleware ---

func TestMiddleware_APIKey_Valid(t *testing.T) {
	store := testStore(t)
	rawKey := "vs_" + RandomHex(32)
	store.RegisterAPIKey(rawKey, "apikey-user")

	mw := Middleware(store, testServerURL)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "apikey-user", RequestUserID(r.Context()))
		assert.Equal(t, "apikey-user", RequestClientID(r.Context()))
		assert.NotEmpty(t, RequestRemoteIP(r.Context()))
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+rawKey)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddleware_APIKey_Invalid(t *testing.T) {
	store := testStore(t)

	mw := Middleware(store, testServerURL)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer vs_"+RandomHex(32))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
}

func TestMiddleware_APIKey_RevokedReturns401(t *testing.T) {
	store := testStore(t)
	rawKey := "vs_" + RandomHex(32)
	store.RegisterAPIKey(rawKey, "user1")

	// Verify it works first.
	mw := Middleware(store, testServerURL)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+rawKey)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Revoke and verify 401.
	store.RevokeAPIKey(HashSecret(rawKey))

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+rawKey)
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddleware_APIKey_DoesNotAffectOAuthTokens(t *testing.T) {
	store := testStore(t)

	// Register an API key and an OAuth token.
	rawKey := "vs_" + RandomHex(32)
	store.RegisterAPIKey(rawKey, "apikey-user")

	store.SaveToken(&models.OAuthToken{
		Token:     "oauth-token-123",
		Kind:      "access",
		UserID:    "oauth-user",
		ClientID:  "oauth-client",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	mw := Middleware(store, testServerURL)

	// API key path.
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(RequestUserID(r.Context())))
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+rawKey)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "apikey-user", rec.Body.String())

	// OAuth token path.
	req = httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer oauth-token-123")

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "oauth-user", rec.Body.String())
}

// --- API Key Reconciliation ---

func TestStore_ReconcileAPIKeys_RemovesStaleKeys(t *testing.T) {
	s := testStore(t)
	key1 := "vs_" + RandomHex(32)
	key2 := "vs_" + RandomHex(32)
	key3 := "vs_" + RandomHex(32)

	s.RegisterAPIKey(key1, "user1")
	s.RegisterAPIKey(key2, "user2")
	s.RegisterAPIKey(key3, "user3")
	require.Len(t, s.ListAPIKeys(), 3)

	// Reconcile with only key1 and key3 as current.
	current := map[string]struct{}{
		HashSecret(key1): {},
		HashSecret(key3): {},
	}
	removed := s.ReconcileAPIKeys(current)

	assert.Equal(t, 1, removed)
	assert.Len(t, s.ListAPIKeys(), 2)
	assert.NotNil(t, s.ValidateAPIKey(key1))
	assert.Nil(t, s.ValidateAPIKey(key2))
	assert.NotNil(t, s.ValidateAPIKey(key3))
}

func TestStore_ReconcileAPIKeys_KeepsAllCurrent(t *testing.T) {
	s := testStore(t)
	key1 := "vs_" + RandomHex(32)
	key2 := "vs_" + RandomHex(32)

	s.RegisterAPIKey(key1, "user1")
	s.RegisterAPIKey(key2, "user2")

	current := map[string]struct{}{
		HashSecret(key1): {},
		HashSecret(key2): {},
	}
	removed := s.ReconcileAPIKeys(current)

	assert.Equal(t, 0, removed)
	assert.Len(t, s.ListAPIKeys(), 2)
}

func TestStore_ReconcileAPIKeys_EmptyConfigPurgesAll(t *testing.T) {
	s := testStore(t)
	s.RegisterAPIKey("vs_"+RandomHex(32), "user1")
	s.RegisterAPIKey("vs_"+RandomHex(32), "user2")
	require.Len(t, s.ListAPIKeys(), 2)

	removed := s.ReconcileAPIKeys(map[string]struct{}{})

	assert.Equal(t, 2, removed)
	assert.Empty(t, s.ListAPIKeys())
}

func TestMiddleware_APIKey_ClientIDMatchesUserID(t *testing.T) {
	store := testStore(t)
	rawKey := "vs_" + RandomHex(32)
	store.RegisterAPIKey(rawKey, "deploy-bot")

	mw := Middleware(store, testServerURL)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "deploy-bot", RequestUserID(r.Context()))
		assert.Equal(t, "deploy-bot", RequestClientID(r.Context()))
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+rawKey)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- remoteIP fallback ---

func TestRemoteIP_WithPort(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	assert.Equal(t, "10.0.0.1", remoteIP(r))
}

func TestRemoteIP_WithoutPort(t *testing.T) {
	// net.SplitHostPort fails when there is no port, so remoteIP
	// should fall back to returning RemoteAddr as-is.
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4"
	assert.Equal(t, "1.2.3.4", remoteIP(r))
}

func TestRemoteIP_IPv6WithPort(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[::1]:9999"
	assert.Equal(t, "::1", remoteIP(r))
}

func TestRemoteIP_IPv6WithoutPort(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "::1"
	assert.Equal(t, "::1", remoteIP(r))
}

// --- isLoopbackRedirect error paths ---

func TestIsLoopbackRedirect_InvalidRedirectURI(t *testing.T) {
	// url.Parse fails on the redirect URI.
	assert.False(t, isLoopbackRedirect("://bad", "http://127.0.0.1"))
}

func TestIsLoopbackRedirect_InvalidRegisteredPrefix(t *testing.T) {
	// url.Parse fails on the registered prefix.
	assert.False(t, isLoopbackRedirect("http://127.0.0.1:8080/cb", "://bad"))
}

func TestIsLoopbackRedirect_BothInvalid(t *testing.T) {
	assert.False(t, isLoopbackRedirect("://bad", "://bad"))
}

func TestIsLoopbackRedirect_PercentEncodingInvalid(t *testing.T) {
	// %zz is not valid percent-encoding, url.Parse returns an error.
	assert.False(t, isLoopbackRedirect("http://127.0.0.1:8080/%zz", "http://127.0.0.1"))
}

func TestIsLoopbackRedirect_ValidMatch(t *testing.T) {
	assert.True(t, isLoopbackRedirect("http://127.0.0.1:9999/callback", "http://127.0.0.1"))
}

func TestIsLoopbackRedirect_SchemeMismatch(t *testing.T) {
	assert.False(t, isLoopbackRedirect("https://127.0.0.1:9999/callback", "http://127.0.0.1"))
}

// --- checkLockout coverage ---

func TestCheckLockout_EmptyClientID(t *testing.T) {
	trl := newTokenRateLimiter()
	assert.False(t, trl.checkLockout(""))
}

func TestCheckLockout_NoEntry(t *testing.T) {
	trl := newTokenRateLimiter()
	assert.False(t, trl.checkLockout("unknown-client"))
}

func TestCheckLockout_SubThresholdEntry(t *testing.T) {
	// An entry with some failures but no lockout should return false.
	trl := newTokenRateLimiter()
	trl.lockouts["client-a"] = &lockoutEntry{failures: 3}
	assert.False(t, trl.checkLockout("client-a"))
}

func TestCheckLockout_ActiveLockout(t *testing.T) {
	trl := newTokenRateLimiter()
	trl.lockouts["client-a"] = &lockoutEntry{
		failures: lockoutThreshold,
		lockedAt: time.Now(),
	}
	assert.True(t, trl.checkLockout("client-a"))
}

func TestCheckLockout_ExpiredLockoutResets(t *testing.T) {
	// When lockedAt is non-zero but the lockout has expired, checkLockout
	// should delete the entry and return false. This covers lines 155-157.
	trl := newTokenRateLimiter()
	trl.lockouts["client-a"] = &lockoutEntry{
		failures: lockoutThreshold,
		lockedAt: time.Now().Add(-lockoutDuration - time.Minute),
	}

	assert.False(t, trl.checkLockout("client-a"))

	// The entry should have been removed.
	trl.mu.Lock()
	_, exists := trl.lockouts["client-a"]
	trl.mu.Unlock()
	assert.False(t, exists, "expired lockout entry should be pruned")
}

func TestCheckLockout_PrunesStaleEntries(t *testing.T) {
	// When the lockouts map exceeds tokenLimiterPruneThreshold, stale
	// entries are pruned. This covers the branch at line 136.
	trl := newTokenRateLimiter()

	// Fill the map past the prune threshold with expired lockout entries.
	for i := 0; i < tokenLimiterPruneThreshold+100; i++ {
		id := "stale-" + RandomHex(8)
		trl.lockouts[id] = &lockoutEntry{
			failures: lockoutThreshold,
			lockedAt: time.Now().Add(-lockoutDuration - time.Hour),
		}
	}

	// Add one active lockout that should survive pruning.
	trl.lockouts["active-client"] = &lockoutEntry{
		failures: lockoutThreshold,
		lockedAt: time.Now(),
	}

	// Add one sub-threshold entry (no lockout) that should be pruned.
	trl.lockouts["sub-threshold"] = &lockoutEntry{failures: 2}

	// Query for a client that does not exist to trigger pruning.
	assert.False(t, trl.checkLockout("nonexistent"))

	trl.mu.Lock()
	_, activeExists := trl.lockouts["active-client"]
	_, subExists := trl.lockouts["sub-threshold"]
	remaining := len(trl.lockouts)
	trl.mu.Unlock()

	assert.True(t, activeExists, "active lockout should survive pruning")
	assert.False(t, subExists, "sub-threshold entry should be pruned")
	// Only the active entry should remain (all stale + sub-threshold pruned).
	assert.Equal(t, 1, remaining)
}

func TestCheckLockout_PruneKeepsActiveLockouts(t *testing.T) {
	trl := newTokenRateLimiter()

	// Fill past threshold with a mix of active and expired lockouts.
	for i := 0; i < tokenLimiterPruneThreshold+50; i++ {
		id := "expired-" + RandomHex(8)
		trl.lockouts[id] = &lockoutEntry{
			failures: lockoutThreshold,
			lockedAt: time.Now().Add(-lockoutDuration - time.Hour),
		}
	}

	// Add several active lockouts.
	for i := 0; i < 5; i++ {
		id := "keep-" + RandomHex(4)
		trl.lockouts[id] = &lockoutEntry{
			failures: lockoutThreshold,
			lockedAt: time.Now(),
		}
	}

	// Trigger pruning by checking any client.
	trl.checkLockout("trigger")

	trl.mu.Lock()
	remaining := len(trl.lockouts)
	trl.mu.Unlock()

	// Only the 5 active lockouts should remain.
	assert.Equal(t, 5, remaining)
}

// --- Persistence (bbolt-backed store) ---

func testStoreWithPersist(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	persist, err := state.LoadAt(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { persist.Close() })

	s := NewStore(persist, testLogger())
	t.Cleanup(s.Stop)

	return s
}

func TestLoadFromDisk_TokensClientsAPIKeys(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	// Phase 1: create a store, populate it, close it.
	func() {
		persist, err := state.LoadAt(dbPath)
		require.NoError(t, err)

		s := NewStore(persist, testLogger())

		s.SaveToken(&models.OAuthToken{
			Token:     "persist-tok",
			Kind:      "access",
			UserID:    "user1",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		})

		s.RegisterClient(&models.OAuthClient{
			ClientID:     "persist-client",
			ClientName:   "Persisted",
			RedirectURIs: []string{"https://example.com/cb"},
		})

		rawKey := "vs_" + RandomHex(32)
		s.RegisterAPIKey(rawKey, "persist-user")

		s.Stop()
		require.NoError(t, persist.Close())
	}()

	// Phase 2: reopen the DB and verify data was loaded from disk.
	persist, err := state.LoadAt(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { persist.Close() })

	s := NewStore(persist, testLogger())
	t.Cleanup(s.Stop)

	s.mu.RLock()
	assert.Len(t, s.tokens, 1)
	assert.Len(t, s.clients, 1)
	assert.Len(t, s.apiKeys, 1)
	s.mu.RUnlock()

	ci := s.GetClient("persist-client")
	require.NotNil(t, ci)
	assert.Equal(t, "Persisted", ci.ClientName)
}

func TestLoadFromDisk_ExpiredTokensDeleted(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	// Phase 1: save an expired token to disk.
	persist, err := state.LoadAt(dbPath)
	require.NoError(t, err)

	expiredHash := HashSecret("expired-disk-token")
	require.NoError(t, persist.SaveOAuthToken(models.OAuthToken{
		TokenHash: expiredHash,
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}))
	require.NoError(t, persist.Close())

	// Phase 2: reopen. loadFromDisk should delete the expired token.
	persist, err = state.LoadAt(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { persist.Close() })

	s := NewStore(persist, testLogger())
	t.Cleanup(s.Stop)

	s.mu.RLock()
	assert.Empty(t, s.tokens, "expired token should be pruned on load")
	s.mu.RUnlock()

	// Verify it was also deleted from disk.
	allTokens, err := persist.AllOAuthTokens()
	require.NoError(t, err)
	assert.Empty(t, allTokens)
}

func TestLoadFromDisk_EmptyTokenHashSkipped(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	// Save two valid tokens with known hashes. Both should load.
	persist, err := state.LoadAt(dbPath)
	require.NoError(t, err)

	hash1 := HashSecret("token-1")
	hash2 := HashSecret("token-2")

	require.NoError(t, persist.SaveOAuthToken(models.OAuthToken{
		TokenHash: hash1,
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}))
	require.NoError(t, persist.SaveOAuthToken(models.OAuthToken{
		TokenHash: hash2,
		Kind:      "access",
		UserID:    "user2",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}))
	require.NoError(t, persist.Close())

	persist, err = state.LoadAt(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { persist.Close() })

	s := NewStore(persist, testLogger())
	t.Cleanup(s.Stop)

	s.mu.RLock()
	assert.Len(t, s.tokens, 2)
	s.mu.RUnlock()
}

func TestLoadFromDisk_RefreshHashBackwardCompat(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	// Phase 1: save an access token with RefreshToken via SaveToken,
	// which computes RefreshHash before persisting.
	persist, err := state.LoadAt(dbPath)
	require.NoError(t, err)

	refreshRaw := "the-refresh-token"
	s := NewStore(persist, testLogger())
	s.SaveToken(&models.OAuthToken{
		Token:        "access-with-refresh",
		Kind:         "access",
		UserID:       "user1",
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		RefreshToken: refreshRaw,
	})
	s.Stop()
	require.NoError(t, persist.Close())

	// Phase 2: reopen and verify RefreshHash is present.
	persist, err = state.LoadAt(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { persist.Close() })

	s = NewStore(persist, testLogger())
	t.Cleanup(s.Stop)

	tokenHash := HashSecret("access-with-refresh")

	s.mu.RLock()
	tok, ok := s.tokens[tokenHash]
	s.mu.RUnlock()

	require.True(t, ok)
	assert.Equal(t, HashSecret(refreshRaw), tok.RefreshHash)
	// Raw secrets should be cleared.
	assert.Empty(t, tok.Token)
	assert.Empty(t, tok.RefreshToken)
}

func TestRegisterPreConfiguredClient_WithPersist(t *testing.T) {
	s := testStoreWithPersist(t)

	s.RegisterPreConfiguredClient(&models.OAuthClient{
		ClientID:   "preconfig-1",
		SecretHash: HashSecret("s3cret"),
		GrantTypes: []string{"client_credentials"},
	})

	ci := s.GetClient("preconfig-1")
	require.NotNil(t, ci)
	assert.Equal(t, HashSecret("s3cret"), ci.SecretHash)

	// Verify persisted to disk.
	allClients, err := s.persist.AllOAuthClients()
	require.NoError(t, err)

	found := false

	for _, c := range allClients {
		if c.ClientID == "preconfig-1" {
			found = true
		}
	}

	assert.True(t, found, "pre-configured client should be persisted")
}

func TestRegisterClient_WithPersist(t *testing.T) {
	s := testStoreWithPersist(t)

	ok := s.RegisterClient(&models.OAuthClient{
		ClientID:     "dyn-client",
		ClientName:   "Dynamic",
		RedirectURIs: []string{"https://example.com/cb"},
	})
	require.True(t, ok)

	allClients, err := s.persist.AllOAuthClients()
	require.NoError(t, err)

	found := false

	for _, c := range allClients {
		if c.ClientID == "dyn-client" {
			found = true
		}
	}

	assert.True(t, found, "dynamically registered client should be persisted")
}

func TestRegisterAPIKey_WithPersist(t *testing.T) {
	s := testStoreWithPersist(t)
	rawKey := "vs_" + RandomHex(32)

	s.RegisterAPIKey(rawKey, "persist-user")

	ak := s.ValidateAPIKey(rawKey)
	require.NotNil(t, ak)
	assert.Equal(t, "persist-user", ak.UserID)

	// Verify on disk.
	allKeys, err := s.persist.AllAPIKeys()
	require.NoError(t, err)

	hash := HashSecret(rawKey)
	_, ok := allKeys[hash]
	assert.True(t, ok, "API key should be persisted to disk")
}

func TestRevokeAPIKey_WithPersist(t *testing.T) {
	s := testStoreWithPersist(t)
	rawKey := "vs_" + RandomHex(32)
	hash := HashSecret(rawKey)

	s.RegisterAPIKey(rawKey, "user1")
	require.NotNil(t, s.ValidateAPIKey(rawKey))

	s.RevokeAPIKey(hash)

	assert.Nil(t, s.ValidateAPIKey(rawKey))

	// Verify removed from disk.
	allKeys, err := s.persist.AllAPIKeys()
	require.NoError(t, err)

	_, ok := allKeys[hash]
	assert.False(t, ok, "revoked API key should be deleted from disk")
}

func TestReconcileAPIKeys_WithPersist(t *testing.T) {
	s := testStoreWithPersist(t)

	key1 := "vs_" + RandomHex(32)
	key2 := "vs_" + RandomHex(32)
	key3 := "vs_" + RandomHex(32)

	s.RegisterAPIKey(key1, "user1")
	s.RegisterAPIKey(key2, "user2")
	s.RegisterAPIKey(key3, "user3")

	// Keep only key1, remove key2 and key3.
	current := map[string]struct{}{
		HashSecret(key1): {},
	}
	removed := s.ReconcileAPIKeys(current)
	assert.Equal(t, 2, removed)

	// Verify stale keys removed from disk.
	allKeys, err := s.persist.AllAPIKeys()
	require.NoError(t, err)
	assert.Len(t, allKeys, 1)
	_, ok := allKeys[HashSecret(key1)]
	assert.True(t, ok)
}

func TestSaveToken_ComputesRefreshHash(t *testing.T) {
	s := testStore(t)

	s.SaveToken(&models.OAuthToken{
		Token:        "access-tok",
		Kind:         "access",
		UserID:       "user1",
		ExpiresAt:    time.Now().Add(time.Hour),
		RefreshToken: "refresh-tok",
	})

	s.mu.RLock()
	tok := s.tokens[HashSecret("access-tok")]
	s.mu.RUnlock()

	require.NotNil(t, tok)
	assert.Equal(t, HashSecret("access-tok"), tok.TokenHash)
	assert.Equal(t, HashSecret("refresh-tok"), tok.RefreshHash)
}

func TestSaveToken_NoRefreshHash_WhenNoRefreshToken(t *testing.T) {
	s := testStore(t)

	s.SaveToken(&models.OAuthToken{
		Token:     "access-only",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	s.mu.RLock()
	tok := s.tokens[HashSecret("access-only")]
	s.mu.RUnlock()

	require.NotNil(t, tok)
	assert.Empty(t, tok.RefreshHash)
}

func TestSaveToken_WithPersist(t *testing.T) {
	s := testStoreWithPersist(t)

	s.SaveToken(&models.OAuthToken{
		Token:     "persist-access-tok",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	allTokens, err := s.persist.AllOAuthTokens()
	require.NoError(t, err)
	assert.Len(t, allTokens, 1)
	assert.Equal(t, HashSecret("persist-access-tok"), allTokens[0].TokenHash)
}

func TestRegistrationAllowed_PrunesOldEntries(t *testing.T) {
	s := testStore(t)

	// Inject old registration timestamps outside the 1-minute window.
	s.mu.Lock()

	past := time.Now().Add(-2 * time.Minute)
	for i := 0; i < maxRegistrationsPerMinute; i++ {
		s.registrationTimes = append(s.registrationTimes, past)
	}
	s.mu.Unlock()

	// All old entries should be pruned, so registration should be allowed.
	assert.True(t, s.RegistrationAllowed())

	// Verify the old entries were pruned and only the new one remains.
	s.mu.RLock()
	assert.Len(t, s.registrationTimes, 1)
	s.mu.RUnlock()
}

func TestRegistrationAllowed_SlidingWindow(t *testing.T) {
	s := testStore(t)

	// Fill to max within the window.
	for i := 0; i < maxRegistrationsPerMinute; i++ {
		assert.True(t, s.RegistrationAllowed())
	}

	// Next should be denied.
	assert.False(t, s.RegistrationAllowed())

	// Simulate time passing by backdating all entries.
	s.mu.Lock()

	past := time.Now().Add(-2 * time.Minute)
	for i := range s.registrationTimes {
		s.registrationTimes[i] = past
	}
	s.mu.Unlock()

	// Should be allowed again after old entries are pruned.
	assert.True(t, s.RegistrationAllowed())
}

func TestRandomHex_VariousLengths(t *testing.T) {
	tests := []struct {
		name    string
		byteLen int
		hexLen  int
	}{
		{"1 byte", 1, 2},
		{"8 bytes", 8, 16},
		{"16 bytes", 16, 32},
		{"32 bytes", 32, 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := RandomHex(tt.byteLen)
			assert.Len(t, h, tt.hexLen)
		})
	}
}

func TestCleanup_WithPersist_DeletesExpiredTokens(t *testing.T) {
	s := testStoreWithPersist(t)

	s.SaveToken(&models.OAuthToken{
		Token:     "cleanup-expired",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})

	s.SaveToken(&models.OAuthToken{
		Token:     "cleanup-valid",
		Kind:      "access",
		UserID:    "user2",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	s.cleanup()

	s.mu.RLock()
	assert.Len(t, s.tokens, 1)
	s.mu.RUnlock()

	allTokens, err := s.persist.AllOAuthTokens()
	require.NoError(t, err)
	assert.Len(t, allTokens, 1)
}

func TestDeleteToken_WithPersist(t *testing.T) {
	s := testStoreWithPersist(t)

	s.SaveToken(&models.OAuthToken{
		Token:     "delete-me",
		Kind:      "access",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	s.DeleteToken("delete-me")

	assert.Nil(t, s.ValidateToken("delete-me"))

	allTokens, err := s.persist.AllOAuthTokens()
	require.NoError(t, err)
	assert.Empty(t, allTokens)
}

func TestConsumeRefreshToken_WithPersist(t *testing.T) {
	s := testStoreWithPersist(t)

	refreshToken := RandomHex(32)
	s.SaveToken(&models.OAuthToken{
		Token:     refreshToken,
		Kind:      "refresh",
		UserID:    "user1",
		Resource:  testServerURL,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		ClientID:  "client1",
	})

	tok := s.ConsumeRefreshToken(refreshToken, "client1", testServerURL)
	require.NotNil(t, tok)
	assert.Equal(t, "user1", tok.UserID)

	// Should be gone from disk.
	allTokens, err := s.persist.AllOAuthTokens()
	require.NoError(t, err)
	assert.Empty(t, allTokens)
}

func TestDeleteAccessTokenByRefreshToken_WithPersist(t *testing.T) {
	s := testStoreWithPersist(t)

	refreshToken := RandomHex(32)
	accessToken := RandomHex(32)

	s.SaveToken(&models.OAuthToken{
		Token:     refreshToken,
		Kind:      "refresh",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		ClientID:  "client1",
	})

	s.SaveToken(&models.OAuthToken{
		Token:        accessToken,
		Kind:         "access",
		UserID:       "user1",
		ExpiresAt:    time.Now().Add(time.Hour),
		RefreshToken: refreshToken,
		ClientID:     "client1",
	})

	s.DeleteAccessTokenByRefreshToken(refreshToken)

	assert.Nil(t, s.ValidateToken(accessToken))

	allTokens, err := s.persist.AllOAuthTokens()
	require.NoError(t, err)
	// Only the refresh token should remain.
	assert.Len(t, allTokens, 1)
}
