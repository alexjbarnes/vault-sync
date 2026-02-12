package auth

import (
	"fmt"
	"net/http"
	"strings"
)

// Middleware returns HTTP middleware that validates Bearer tokens.
// Unauthenticated requests get a 401 with the WWW-Authenticate header
// pointing to the protected resource metadata URL (RFC 9728 Section 5.1).
// Tokens are validated for expiry and audience (RFC 8707).
func Middleware(store *Store, serverURL string) func(http.Handler) http.Handler {
	metadataURL := serverURL + "/.well-known/oauth-protected-resource"
	wwwAuth := fmt.Sprintf(`Bearer resource_metadata="%s"`, metadataURL)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				w.Header().Set("WWW-Authenticate", wwwAuth)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			ti := store.ValidateToken(token)
			if ti == nil {
				w.Header().Set("WWW-Authenticate", wwwAuth)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// RFC 8707: reject tokens not issued for this resource server.
			if ti.Resource != "" && strings.TrimRight(ti.Resource, "/") != strings.TrimRight(serverURL, "/") {
				w.Header().Set("WWW-Authenticate", wwwAuth)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
