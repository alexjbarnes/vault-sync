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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testUsers(t *testing.T) UserCredentials {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
	require.NoError(t, err)
	return UserCredentials{"testuser": string(hash)}
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// --- Store ---

func TestStore_CodeRoundTrip(t *testing.T) {
	s := NewStore()
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
	s := NewStore()
	s.SaveCode(&AuthCode{
		Code:      "expired",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})

	assert.Nil(t, s.ConsumeCode("expired"))
}

func TestStore_CodeNotFound(t *testing.T) {
	s := NewStore()
	assert.Nil(t, s.ConsumeCode("nonexistent"))
}

func TestStore_TokenRoundTrip(t *testing.T) {
	s := NewStore()
	s.SaveToken(&TokenInfo{
		Token:     "tok_abc",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	ti := s.ValidateToken("tok_abc")
	require.NotNil(t, ti)
	assert.Equal(t, "user1", ti.UserID)
}

func TestStore_TokenExpired(t *testing.T) {
	s := NewStore()
	s.SaveToken(&TokenInfo{
		Token:     "expired_tok",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})

	assert.Nil(t, s.ValidateToken("expired_tok"))
}

func TestStore_TokenNotFound(t *testing.T) {
	s := NewStore()
	assert.Nil(t, s.ValidateToken("nonexistent"))
}

func TestStore_ClientRoundTrip(t *testing.T) {
	s := NewStore()
	s.RegisterClient(&ClientInfo{
		ClientID:     "client1",
		ClientName:   "Test",
		RedirectURIs: []string{"https://example.com/callback"},
	})

	ci := s.GetClient("client1")
	require.NotNil(t, ci)
	assert.Equal(t, "Test", ci.ClientName)
	assert.Nil(t, s.GetClient("nonexistent"))
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
	store := NewStore()
	handler := HandleRegistration(store)

	body := `{"client_name":"Claude","redirect_uris":["https://claude.ai/callback"]}`
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)

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
	store := NewStore()
	handler := HandleRegistration(store)

	body := `{"client_name":"Claude"}`
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRegistration_WrongMethod(t *testing.T) {
	store := NewStore()
	handler := HandleRegistration(store)

	req := httptest.NewRequest("GET", "/oauth/register", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// --- Authorize ---

func TestAuthorize_GET_ShowsLoginForm(t *testing.T) {
	store := NewStore()
	store.RegisterClient(&ClientInfo{
		ClientID:     "test-client",
		RedirectURIs: []string{"https://example.com/callback"},
	})

	handler := HandleAuthorize(store, testUsers(t), testLogger())
	req := httptest.NewRequest("GET", "/oauth/authorize?client_id=test-client&redirect_uri=https://example.com/callback&state=xyz&code_challenge=abc&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Vault Sync Login")
	assert.Contains(t, rec.Body.String(), "test-client")
}

func TestAuthorize_GET_MissingClientID(t *testing.T) {
	store := NewStore()
	handler := HandleAuthorize(store, testUsers(t), testLogger())

	req := httptest.NewRequest("GET", "/oauth/authorize", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAuthorize_GET_UnknownClient(t *testing.T) {
	store := NewStore()
	handler := HandleAuthorize(store, testUsers(t), testLogger())

	req := httptest.NewRequest("GET", "/oauth/authorize?client_id=unknown", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAuthorize_POST_ValidLogin(t *testing.T) {
	store := NewStore()
	store.RegisterClient(&ClientInfo{
		ClientID:     "test-client",
		RedirectURIs: []string{"https://example.com/callback"},
	})
	users := testUsers(t)

	handler := HandleAuthorize(store, users, testLogger())

	form := url.Values{
		"client_id":             {"test-client"},
		"redirect_uri":          {"https://example.com/callback"},
		"state":                 {"mystate"},
		"code_challenge":        {"challenge123"},
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

func TestAuthorize_POST_InvalidPassword(t *testing.T) {
	store := NewStore()
	store.RegisterClient(&ClientInfo{
		ClientID:     "test-client",
		RedirectURIs: []string{"https://example.com/callback"},
	})

	handler := HandleAuthorize(store, testUsers(t), testLogger())

	form := url.Values{
		"client_id": {"test-client"},
		"username":  {"testuser"},
		"password":  {"wrong"},
	}

	req := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "Invalid username or password")
}

// --- Token ---

func TestToken_FullFlow(t *testing.T) {
	store := NewStore()
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

	handler := HandleToken(store)

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
	store := NewStore()
	handler := HandleToken(store)

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
	store := NewStore()
	handler := HandleToken(store)

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
	store := NewStore()
	store.SaveCode(&AuthCode{
		Code:          "code-with-pkce",
		CodeChallenge: "validchallenge",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store)

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

func TestToken_RedirectURIMismatch(t *testing.T) {
	store := NewStore()
	store.SaveCode(&AuthCode{
		Code:        "code-redirect",
		RedirectURI: "https://example.com/callback",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store)

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"code-redirect"},
		"redirect_uri": {"https://evil.com/callback"},
	}

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestToken_JSONBody(t *testing.T) {
	store := NewStore()
	store.SaveCode(&AuthCode{
		Code:      "json-code",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})

	handler := HandleToken(store)

	body := `{"grant_type":"authorization_code","code":"json-code"}`
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
	store := NewStore()
	store.SaveToken(&TokenInfo{
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
	store := NewStore()
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
	store := NewStore()
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
	store := NewStore()
	store.SaveToken(&TokenInfo{
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
	store := NewStore()
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
