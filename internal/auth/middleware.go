package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type contextKey int

const (
	ctxUserID contextKey = iota
	ctxClientID
	ctxRemoteIP
)

// RequestUserID returns the authenticated user ID from the context, or "".
func RequestUserID(ctx context.Context) string {
	v, _ := ctx.Value(ctxUserID).(string)
	return v
}

// RequestClientID returns the OAuth client ID from the context, or "".
func RequestClientID(ctx context.Context) string {
	v, _ := ctx.Value(ctxClientID).(string)
	return v
}

// RequestRemoteIP returns the client IP from the context, or "".
func RequestRemoteIP(ctx context.Context) string {
	v, _ := ctx.Value(ctxRemoteIP).(string)
	return v
}

// Middleware returns HTTP middleware that validates Bearer tokens.
// Unauthenticated requests get a 401 with the WWW-Authenticate header
// pointing to the protected resource metadata URL (RFC 9728 Section 5.1).
// Tokens are validated for expiry and audience (RFC 8707).
func Middleware(store *Store, serverURL string) func(http.Handler) http.Handler {
	metadataURL := serverURL + "/.well-known/oauth-protected-resource"
	// RFC 6750 Section 3.1: no error attribute when no token was provided.
	wwwAuthNoToken := fmt.Sprintf(`Bearer resource_metadata="%s"`, metadataURL)
	// error="invalid_token" signals the client should attempt a refresh.
	wwwAuthInvalid := fmt.Sprintf(`Bearer error="invalid_token", resource_metadata="%s"`, metadataURL)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				w.Header().Set("WWW-Authenticate", wwwAuthNoToken)
				w.WriteHeader(http.StatusUnauthorized)

				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")

			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}

			// API key authentication: keys use the "vs_" prefix to
			// distinguish them from OAuth Bearer tokens.
			if strings.HasPrefix(token, APIKeyPrefix) {
				ak := store.ValidateAPIKey(token)
				if ak == nil {
					w.Header().Set("WWW-Authenticate", wwwAuthInvalid)
					w.WriteHeader(http.StatusUnauthorized)

					return
				}

				ctx := r.Context()
				ctx = context.WithValue(ctx, ctxUserID, ak.UserID)
				ctx = context.WithValue(ctx, ctxClientID, ak.UserID)
				ctx = context.WithValue(ctx, ctxRemoteIP, ip)

				next.ServeHTTP(w, r.WithContext(ctx))

				return
			}

			// OAuth Bearer token authentication.
			ti := store.ValidateToken(token)
			if ti == nil {
				w.Header().Set("WWW-Authenticate", wwwAuthInvalid)
				w.WriteHeader(http.StatusUnauthorized)

				return
			}

			// RFC 8707: reject tokens not issued for this resource server.
			if ti.Resource != "" && strings.TrimRight(ti.Resource, "/") != strings.TrimRight(serverURL, "/") {
				w.Header().Set("WWW-Authenticate", wwwAuthInvalid)
				w.WriteHeader(http.StatusUnauthorized)

				return
			}

			// Inject authenticated identity into the request context
			// so downstream handlers (MCP tools) can log it.
			ctx := r.Context()
			ctx = context.WithValue(ctx, ctxUserID, ti.UserID)
			ctx = context.WithValue(ctx, ctxClientID, ti.ClientID)
			ctx = context.WithValue(ctx, ctxRemoteIP, ip)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
