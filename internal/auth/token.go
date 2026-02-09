package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"
)

const tokenExpiry = 24 * time.Hour

type tokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	CodeVerifier string `json:"code_verifier"`
	ClientID     string `json:"client_id"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// HandleToken returns the /oauth/token handler.
func HandleToken(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Support both JSON and form-encoded bodies.
		var req tokenRequest
		contentType := r.Header.Get("Content-Type")
		if contentType == "application/json" {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
				return
			}
		} else {
			if err := r.ParseForm(); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid form data")
				return
			}
			req = tokenRequest{
				GrantType:    r.FormValue("grant_type"),
				Code:         r.FormValue("code"),
				RedirectURI:  r.FormValue("redirect_uri"),
				CodeVerifier: r.FormValue("code_verifier"),
				ClientID:     r.FormValue("client_id"),
			}
		}

		if req.GrantType != "authorization_code" {
			writeJSONError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
			return
		}

		if req.Code == "" {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", "code is required")
			return
		}

		ac := store.ConsumeCode(req.Code)
		if ac == nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired authorization code")
			return
		}

		// Validate redirect_uri matches.
		if ac.RedirectURI != "" && req.RedirectURI != ac.RedirectURI {
			writeJSONError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
			return
		}

		// PKCE verification.
		if ac.CodeChallenge != "" {
			if req.CodeVerifier == "" {
				writeJSONError(w, http.StatusBadRequest, "invalid_grant", "code_verifier is required")
				return
			}
			if !verifyPKCE(req.CodeVerifier, ac.CodeChallenge) {
				writeJSONError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
				return
			}
		}

		// Issue access token.
		token := RandomHex(32)
		store.SaveToken(&TokenInfo{
			Token:     token,
			UserID:    ac.UserID,
			ExpiresAt: time.Now().Add(tokenExpiry),
		})

		resp := tokenResponse{
			AccessToken: token,
			TokenType:   "Bearer",
			ExpiresIn:   int(tokenExpiry.Seconds()),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// verifyPKCE checks that SHA256(verifier) matches the challenge (S256 method).
func verifyPKCE(verifier, challenge string) bool {
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return computed == challenge
}
