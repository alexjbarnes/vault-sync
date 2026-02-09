package auth

import (
	"encoding/json"
	"net/http"
)

// registrationRequest is the DCR POST body (RFC 7591).
type registrationRequest struct {
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

// registrationResponse is the DCR response.
type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// HandleRegistration returns the /oauth/register handler.
func HandleRegistration(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req registrationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if len(req.RedirectURIs) == 0 {
			writeJSONError(w, http.StatusBadRequest, "invalid_client_metadata", "redirect_uris is required")
			return
		}

		clientID := RandomHex(16)

		grantTypes := req.GrantTypes
		if len(grantTypes) == 0 {
			grantTypes = []string{"authorization_code"}
		}
		responseTypes := req.ResponseTypes
		if len(responseTypes) == 0 {
			responseTypes = []string{"code"}
		}
		authMethod := req.TokenEndpointAuthMethod
		if authMethod == "" {
			authMethod = "none"
		}

		store.RegisterClient(&ClientInfo{
			ClientID:     clientID,
			ClientName:   req.ClientName,
			RedirectURIs: req.RedirectURIs,
		})

		resp := registrationResponse{
			ClientID:                clientID,
			ClientName:              req.ClientName,
			RedirectURIs:            req.RedirectURIs,
			GrantTypes:              grantTypes,
			ResponseTypes:           responseTypes,
			TokenEndpointAuthMethod: authMethod,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}
}

func writeJSONError(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
