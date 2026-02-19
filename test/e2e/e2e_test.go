package e2e_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- client_credentials flow ---

func TestClientCredentials_MCPToolCall(t *testing.T) {
	h := newHarness(t)
	h.registerPreConfiguredClient(testClientID, testSecret)

	tr := h.clientCredentialsToken(t, testClientID, testSecret)
	assert.Equal(t, "Bearer", tr.TokenType)
	assert.Empty(t, tr.RefreshToken, "client_credentials must not issue refresh tokens")

	session := h.mcpSession(t, tr.AccessToken)

	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "vault_list",
		Arguments: map[string]any{"path": ""},
	})
	require.NoError(t, err)
	assert.False(t, result.IsError)

	text := extractTextContent(t, result)
	assert.Contains(t, text, "notes/hello.md")
	assert.Contains(t, text, "readme.md")
}

func TestClientCredentials_ReadFile(t *testing.T) {
	h := newHarness(t)
	h.registerPreConfiguredClient(testClientID, testSecret)

	tr := h.clientCredentialsToken(t, testClientID, testSecret)
	session := h.mcpSession(t, tr.AccessToken)

	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "vault_read",
		Arguments: map[string]any{"path": "notes/hello.md"},
	})
	require.NoError(t, err)
	assert.False(t, result.IsError)

	text := extractTextContent(t, result)
	assert.Contains(t, text, "This is a test note")
}

func TestClientCredentials_WrongSecret(t *testing.T) {
	h := newHarness(t)
	h.registerPreConfiguredClient(testClientID, testSecret)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {testClientID},
		"client_secret": {"wrong-secret"},
		"resource":      {h.URL},
	}

	resp := h.doPostForm(t, "/oauth/token", form)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// --- auth code + PKCE flow ---

func TestAuthCodePKCE_MCPToolCall(t *testing.T) {
	h := newHarness(t)

	tr := h.authCodeFlow(t)
	assert.Equal(t, "Bearer", tr.TokenType)
	assert.NotEmpty(t, tr.RefreshToken, "auth code flow should issue a refresh token")

	session := h.mcpSession(t, tr.AccessToken)

	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "vault_list",
		Arguments: map[string]any{"path": ""},
	})
	require.NoError(t, err)
	assert.False(t, result.IsError)

	text := extractTextContent(t, result)
	assert.Contains(t, text, "notes/hello.md")
}

func TestAuthCodePKCE_WriteAndRead(t *testing.T) {
	h := newHarness(t)

	tr := h.authCodeFlow(t)
	session := h.mcpSession(t, tr.AccessToken)

	// Write a new file through MCP.
	_, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "vault_write",
		Arguments: map[string]any{
			"path":    "e2e-created.md",
			"content": "created by e2e test",
		},
	})
	require.NoError(t, err)

	// Read it back.
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "vault_read",
		Arguments: map[string]any{"path": "e2e-created.md"},
	})
	require.NoError(t, err)
	assert.False(t, result.IsError)
	assert.Contains(t, extractTextContent(t, result), "created by e2e test")
}

// --- token refresh ---

func TestTokenRefresh_MCPToolCall(t *testing.T) {
	h := newHarness(t)

	// Register a client we can track across auth code + refresh.
	clientID := h.registerDynamicClient(t, []string{redirectURI})
	tr := h.authCodeFlowWithClient(t, clientID)
	require.NotEmpty(t, tr.RefreshToken)

	refreshed := h.refreshToken(t, clientID, tr.RefreshToken)
	assert.NotEmpty(t, refreshed.AccessToken)
	assert.NotEqual(t, tr.AccessToken, refreshed.AccessToken)

	// The new token should work for MCP calls.
	session := h.mcpSession(t, refreshed.AccessToken)

	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "vault_list",
		Arguments: map[string]any{"path": ""},
	})
	require.NoError(t, err)
	assert.False(t, result.IsError)
}

// --- unauthenticated and invalid token ---

func TestUnauthenticated_Returns401(t *testing.T) {
	h := newHarness(t)

	req, err := http.NewRequestWithContext(t.Context(), "POST", h.URL+"/mcp", strings.NewReader("{}"))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	resp, err := h.Client.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "Bearer")
	assert.Contains(t, wwwAuth, "resource_metadata")
	assert.NotContains(t, wwwAuth, `error=`, "no-token response should not include error attribute")
}

func TestInvalidToken_Returns401(t *testing.T) {
	h := newHarness(t)

	req, err := http.NewRequestWithContext(t.Context(), "POST", h.URL+"/mcp", strings.NewReader("{}"))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer invalid-token-value")

	resp, err := h.Client.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error="invalid_token"`)
}

// --- OAuth metadata discovery ---

func TestOAuthMetadata_ProtectedResource(t *testing.T) {
	h := newHarness(t)

	resp := h.doGet(t, h.URL+"/.well-known/oauth-protected-resource")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var meta map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))

	assert.Equal(t, h.URL, meta["resource"])

	servers, ok := meta["authorization_servers"].([]any)
	require.True(t, ok)
	assert.Contains(t, servers, h.URL)
}

func TestOAuthMetadata_AuthorizationServer(t *testing.T) {
	h := newHarness(t)

	resp := h.doGet(t, h.URL+"/.well-known/oauth-authorization-server")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var meta map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))

	assert.Equal(t, h.URL, meta["issuer"])
	assert.Equal(t, h.URL+"/oauth/authorize", meta["authorization_endpoint"])
	assert.Equal(t, h.URL+"/oauth/token", meta["token_endpoint"])
	assert.Equal(t, h.URL+"/oauth/register", meta["registration_endpoint"])

	grantTypes, ok := meta["grant_types_supported"].([]any)
	require.True(t, ok)
	assert.Contains(t, grantTypes, "authorization_code")
	assert.Contains(t, grantTypes, "client_credentials")
	assert.Contains(t, grantTypes, "refresh_token")
}

// --- dynamic client registration ---

func TestDynamicClientRegistration(t *testing.T) {
	h := newHarness(t)

	resp := h.doPostJSON(t, "/oauth/register", []byte(`{"redirect_uris": ["http://127.0.0.1:9999/callback"]}`))
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

	assert.NotEmpty(t, result["client_id"])

	uris, ok := result["redirect_uris"].([]any)
	require.True(t, ok)
	assert.Equal(t, "http://127.0.0.1:9999/callback", uris[0])
}

func TestDynamicClientRegistration_RejectsHTTP(t *testing.T) {
	h := newHarness(t)

	resp := h.doPostJSON(t, "/oauth/register", []byte(`{"redirect_uris": ["http://evil.example.com/callback"]}`))
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// --- helpers ---

// extractTextContent pulls the text from the first TextContent in a
// CallToolResult. MCP tools return JSON-serialized results as TextContent.
func extractTextContent(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()

	require.NotEmpty(t, result.Content, "tool result has no content")

	for _, c := range result.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			return tc.Text
		}
	}

	t.Fatal("no TextContent found in tool result")

	return ""
}
