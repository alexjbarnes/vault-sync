// Package server provides HTTP server construction for vault-sync.
package server

import (
	"log/slog"
	"net/http"

	"github.com/alexjbarnes/vault-sync/internal/auth"
)

// MuxConfig holds dependencies for building the HTTP mux.
type MuxConfig struct {
	Store      *auth.Store
	Users      auth.UserCredentials
	MCPHandler http.Handler
	Logger     *slog.Logger
	ServerURL  string
}

// NewMux builds the HTTP mux with OAuth discovery, registration,
// authorization, token, and MCP endpoints. The MCP endpoint is
// protected by Bearer token middleware.
func NewMux(cfg MuxConfig) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", auth.HandleProtectedResourceMetadata(cfg.ServerURL))
	mux.HandleFunc("/.well-known/oauth-authorization-server", auth.HandleServerMetadata(cfg.ServerURL))
	mux.HandleFunc("/oauth/register", auth.HandleRegistration(cfg.Store, cfg.Logger))
	mux.HandleFunc("/oauth/authorize", auth.HandleAuthorize(cfg.Store, cfg.Users, cfg.Logger, cfg.ServerURL))
	mux.HandleFunc("/oauth/token", auth.HandleToken(cfg.Store, cfg.Logger, cfg.ServerURL))

	authMiddleware := auth.Middleware(cfg.Store, cfg.Logger, cfg.ServerURL)
	mux.Handle("/mcp", authMiddleware(cfg.MCPHandler))

	return mux
}
