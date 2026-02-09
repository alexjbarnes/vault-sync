package auth

import (
	"fmt"
	"net/http"
	"strings"
)

// Middleware returns HTTP middleware that validates Bearer tokens.
// Unauthenticated requests get a 401 with the WWW-Authenticate header
// pointing to the protected resource metadata URL.
func Middleware(store *Store, serverURL string) func(http.Handler) http.Handler {
	metadataURL := serverURL + "/.well-known/oauth-protected-resource"

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				w.Header().Set("WWW-Authenticate",
					fmt.Sprintf(`Bearer resource_metadata="%s"`, metadataURL))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			ti := store.ValidateToken(token)
			if ti == nil {
				w.Header().Set("WWW-Authenticate",
					fmt.Sprintf(`Bearer resource_metadata="%s"`, metadataURL))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
