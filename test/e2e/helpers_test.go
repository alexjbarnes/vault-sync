package e2e_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/alexjbarnes/vault-sync/internal/auth"
	"github.com/alexjbarnes/vault-sync/internal/mcpserver"
	"github.com/alexjbarnes/vault-sync/internal/models"
	"github.com/alexjbarnes/vault-sync/internal/server"
	"github.com/alexjbarnes/vault-sync/internal/vault"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

const (
	testUsername = "testuser"
	testPassword = "testpass"
	testClientID = "e2e-test-client"
	testSecret   = "e2e-test-secret-value"
	pkceVerifier = "e2e-test-pkce-verifier-that-is-long-enough"
	redirectURI  = "http://127.0.0.1:19876/callback"
)

// harness holds the full e2e test stack: a real HTTP server backed by
// the OAuth auth layer and MCP tool server.
type harness struct {
	URL      string
	Store    *auth.Store
	VaultDir string
	Client   *http.Client
}

// newHarness creates a temp vault with seed files, wires up the full
// OAuth + MCP HTTP stack via server.NewMux, and starts an httptest server.
func newHarness(t *testing.T) *harness {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "notes"), 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "notes", "hello.md"),
		[]byte("# Hello\nThis is a test note."),
		0o644,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "readme.md"),
		[]byte("# Vault Readme"),
		0o644,
	))

	v, err := vault.New(dir)
	require.NoError(t, err)

	logger := slog.New(slog.DiscardHandler)

	mcpServer := mcp.NewServer(
		&mcp.Implementation{Name: "vault-sync-e2e", Version: "test"},
		nil,
	)
	mcpserver.RegisterTools(mcpServer, v, logger)

	mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return mcpServer
	}, nil)

	store := auth.NewStore(nil, logger)
	t.Cleanup(store.Stop)

	users := auth.UserCredentials{testUsername: testPassword}

	// Use NewUnstartedServer so we can read the listener address before
	// building the mux (the serverURL must match for audience validation).
	ts := httptest.NewUnstartedServer(nil)
	serverURL := "http://" + ts.Listener.Addr().String()

	ts.Config.Handler = server.NewMux(server.MuxConfig{
		Store:      store,
		Users:      users,
		MCPHandler: mcpHandler,
		Logger:     logger,
		ServerURL:  serverURL,
	})
	ts.Start()
	t.Cleanup(ts.Close)

	return &harness{
		URL:      serverURL,
		Store:    store,
		VaultDir: dir,
		Client:   ts.Client(),
	}
}

// registerPreConfiguredClient registers a pre-configured client directly
// in the store (not via HTTP, since pre-configured clients are loaded
// from env vars at startup). Supports all grant types so it matches
// the production registration in main.go.
func (h *harness) registerPreConfiguredClient(clientID, secret string) {
	h.Store.RegisterPreConfiguredClient(&models.OAuthClient{
		ClientID:   clientID,
		SecretHash: auth.HashSecret(secret),
		GrantTypes: []string{"client_credentials", "authorization_code", "refresh_token"},
		RedirectURIs: []string{
			"http://127.0.0.1",
			"http://localhost",
		},
	})
}

// tokenResponse is the JSON body returned by POST /oauth/token.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// clientCredentialsToken obtains a token via the client_credentials grant.
func (h *harness) clientCredentialsToken(t *testing.T, clientID, secret string) tokenResponse {
	t.Helper()

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {secret},
		"resource":      {h.URL},
	}

	resp := h.doPostForm(t, "/oauth/token", form)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tr tokenResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tr))

	return tr
}

// registerDynamicClient registers a client via POST /oauth/register.
func (h *harness) registerDynamicClient(t *testing.T, redirectURIs []string) string {
	t.Helper()

	body := map[string][]string{"redirect_uris": redirectURIs}
	b, err := json.Marshal(body)
	require.NoError(t, err)

	resp := h.doPostJSON(t, "/oauth/register", b)
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var result struct {
		ClientID     string   `json:"client_id"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	require.NotEmpty(t, result.ClientID)

	return result.ClientID
}

// authCodeFlow performs the full authorization code + PKCE flow with
// a freshly registered dynamic client.
func (h *harness) authCodeFlow(t *testing.T) tokenResponse {
	t.Helper()

	clientID := h.registerDynamicClient(t, []string{redirectURI})

	return h.authCodeFlowWithClient(t, clientID)
}

// authCodeFlowWithClient performs the authorization code + PKCE flow
// for a specific client ID. Steps: GET authorize (scrape CSRF), POST
// authorize (get code from redirect), POST token.
func (h *harness) authCodeFlowWithClient(t *testing.T, clientID string) tokenResponse {
	t.Helper()

	challenge := pkceChallenge(pkceVerifier)

	// GET /oauth/authorize to render the login form and get a CSRF token.
	authURL := h.URL + "/oauth/authorize?" + url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"e2e-state"},
		"resource":              {h.URL},
	}.Encode()

	resp := h.doGet(t, authURL)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	csrf := extractCSRF(t, string(bodyBytes))

	// POST /oauth/authorize with credentials. Don't follow the redirect.
	form := url.Values{
		"username":              {testUsername},
		"password":              {testPassword},
		"csrf_token":            {csrf},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"e2e-state"},
		"resource":              {h.URL},
	}

	postResp := h.doPostFormNoRedirect(t, "/oauth/authorize", form)
	defer postResp.Body.Close()

	require.Equal(t, http.StatusFound, postResp.StatusCode)

	loc := postResp.Header.Get("Location")
	require.NotEmpty(t, loc)

	locURL, err := url.Parse(loc)
	require.NoError(t, err)

	code := locURL.Query().Get("code")
	require.NotEmpty(t, code, "authorization code missing from redirect")

	// POST /oauth/token to exchange the code.
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {pkceVerifier},
		"resource":      {h.URL},
	}

	tokenResp := h.doPostForm(t, "/oauth/token", tokenForm)
	defer tokenResp.Body.Close()

	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tr tokenResponse
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tr))

	return tr
}

// refreshToken exchanges a refresh token for a new access token.
func (h *harness) refreshToken(t *testing.T, clientID, refresh string) tokenResponse {
	t.Helper()

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {clientID},
		"resource":      {h.URL},
	}

	resp := h.doPostForm(t, "/oauth/token", form)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tr tokenResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tr))

	return tr
}

// mcpSession creates an MCP client session authenticated with the given
// Bearer token. Uses the MCP SDK's StreamableClientTransport with a
// custom HTTP RoundTripper that injects the Authorization header.
func (h *harness) mcpSession(t *testing.T, token string) *mcp.ClientSession {
	t.Helper()

	transport := &mcp.StreamableClientTransport{
		Endpoint: h.URL + "/mcp",
		HTTPClient: &http.Client{
			Transport: &bearerTransport{
				token: token,
				base:  h.Client.Transport,
			},
		},
		DisableStandaloneSSE: true,
	}

	client := mcp.NewClient(
		&mcp.Implementation{Name: "e2e-test-client", Version: "test"},
		nil,
	)

	session, err := client.Connect(t.Context(), transport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })

	return session
}

// doGet performs a GET request with t.Context().
func (h *harness) doGet(t *testing.T, fullURL string) *http.Response {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), "GET", fullURL, nil)
	require.NoError(t, err)

	resp, err := h.Client.Do(req)
	require.NoError(t, err)

	return resp
}

// doPostForm performs a POST with form-encoded body and t.Context().
func (h *harness) doPostForm(t *testing.T, path string, form url.Values) *http.Response {
	t.Helper()

	req, err := http.NewRequestWithContext(
		t.Context(), "POST", h.URL+path,
		bytes.NewBufferString(form.Encode()),
	)
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.Client.Do(req)
	require.NoError(t, err)

	return resp
}

// doPostFormNoRedirect performs a form POST that does not follow redirects.
func (h *harness) doPostFormNoRedirect(t *testing.T, path string, form url.Values) *http.Response {
	t.Helper()

	noRedirect := *h.Client
	noRedirect.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	req, err := http.NewRequestWithContext(
		t.Context(), "POST", h.URL+path,
		bytes.NewBufferString(form.Encode()),
	)
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := noRedirect.Do(req)
	require.NoError(t, err)

	return resp
}

// doPostJSON performs a POST with JSON body and t.Context().
func (h *harness) doPostJSON(t *testing.T, path string, body []byte) *http.Response {
	t.Helper()

	req, err := http.NewRequestWithContext(
		t.Context(), "POST", h.URL+path,
		bytes.NewReader(body),
	)
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	resp, err := h.Client.Do(req)
	require.NoError(t, err)

	return resp
}

// bearerTransport is an http.RoundTripper that injects a Bearer token
// into every request's Authorization header.
type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (bt *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+bt.token)

	return bt.base.RoundTrip(req)
}

// pkceChallenge computes the S256 code challenge for a given verifier.
func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// extractCSRF scrapes the CSRF token from the authorize HTML form.
func extractCSRF(t *testing.T, body string) string {
	t.Helper()

	re := regexp.MustCompile(`name="csrf_token" value="([a-f0-9]+)"`)
	matches := re.FindStringSubmatch(body)
	require.Len(t, matches, 2, "CSRF token not found in form HTML")

	return matches[1]
}
