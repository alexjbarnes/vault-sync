// Package server provides HTTP server construction for vault-sync.
package server

import (
	"net/http"

	mcpauth "github.com/alexjbarnes/mcp-auth"
)

// MuxConfig holds dependencies for building the HTTP mux.
type MuxConfig struct {
	Auth       *mcpauth.Server
	MCPHandler http.Handler
}

// NewMux builds the HTTP mux with OAuth discovery, registration,
// authorization, token, and MCP endpoints. The MCP endpoint is
// protected by Bearer token middleware.
func NewMux(cfg MuxConfig) *http.ServeMux {
	mux := http.NewServeMux()
	cfg.Auth.Register(mux)

	authMiddleware := cfg.Auth.Middleware()
	mux.Handle("/mcp", authMiddleware(cfg.MCPHandler))

	return mux
}
