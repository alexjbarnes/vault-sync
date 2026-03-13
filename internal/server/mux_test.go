package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	mcpauth "github.com/alexjbarnes/mcp-auth"
	"github.com/stretchr/testify/assert"
)

func TestNewMux_RoutesRegistered(t *testing.T) {
	auth := mcpauth.New(mcpauth.Config{
		ServerURL: "https://example.com",
	})
	defer auth.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux := NewMux(MuxConfig{
		Auth:       auth,
		MCPHandler: handler,
	})

	// OAuth metadata endpoint should be wired.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil))
	assert.Equal(t, http.StatusOK, rec.Code)

	// MCP endpoint should require auth (401 without token).
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/mcp", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
