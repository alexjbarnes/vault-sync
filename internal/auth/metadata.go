package auth

import (
	"encoding/json"
	"net/http"
)

// ProtectedResourceMetadata is the RFC 9728 response.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
}

// AuthServerMetadata is the RFC 8414 response.
type AuthServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

// HandleProtectedResourceMetadata returns the /.well-known/oauth-protected-resource handler.
func HandleProtectedResourceMetadata(serverURL string) http.HandlerFunc {
	meta := ProtectedResourceMetadata{
		Resource:               serverURL,
		AuthorizationServers:   []string{serverURL},
		ScopesSupported:        []string{"vault:read", "vault:write"},
		BearerMethodsSupported: []string{"header"},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		json.NewEncoder(w).Encode(meta)
	}
}

// HandleAuthServerMetadata returns the /.well-known/oauth-authorization-server handler.
func HandleAuthServerMetadata(serverURL string) http.HandlerFunc {
	meta := AuthServerMetadata{
		Issuer:                            serverURL,
		AuthorizationEndpoint:             serverURL + "/oauth/authorize",
		TokenEndpoint:                     serverURL + "/oauth/token",
		RegistrationEndpoint:              serverURL + "/oauth/register",
		ScopesSupported:                   []string{"vault:read", "vault:write"},
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		json.NewEncoder(w).Encode(meta)
	}
}
