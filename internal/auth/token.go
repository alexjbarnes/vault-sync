package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/models"
)

const tokenExpiry = 24 * time.Hour

type tokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	CodeVerifier string `json:"code_verifier"`
	ClientID     string `json:"client_id"`
	Resource     string `json:"resource"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// HandleToken returns the /oauth/token handler. The serverURL is the
// canonical resource identifier used to validate the resource parameter.
func HandleToken(store *Store, serverURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

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
				Resource:     r.FormValue("resource"),
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

		// Validate redirect_uri matches the one stored on the auth code.
		if ac.RedirectURI != "" && req.RedirectURI != ac.RedirectURI {
			writeJSONError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
			return
		}

		// RFC 8707: validate that the resource parameter matches what was
		// bound to the authorization code. Tolerate omission for backward
		// compatibility, but reject mismatches.
		if req.Resource != "" && strings.TrimRight(req.Resource, "/") != strings.TrimRight(serverURL, "/") {
			writeJSONError(w, http.StatusBadRequest, "invalid_target", "resource parameter does not match this server")
			return
		}
		if ac.Resource != "" && req.Resource != "" && strings.TrimRight(req.Resource, "/") != strings.TrimRight(ac.Resource, "/") {
			writeJSONError(w, http.StatusBadRequest, "invalid_target", "resource does not match authorization code")
			return
		}

		// PKCE is mandatory. The authorize endpoint enforces that a
		// code_challenge is present, so every auth code has one.
		if ac.CodeChallenge == "" {
			writeJSONError(w, http.StatusBadRequest, "invalid_grant", "authorization code was issued without PKCE")
			return
		}
		if req.CodeVerifier == "" {
			writeJSONError(w, http.StatusBadRequest, "invalid_grant", "code_verifier is required")
			return
		}
		if !verifyPKCE(req.CodeVerifier, ac.CodeChallenge) {
			writeJSONError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}

		// Issue access token bound to the resource.
		resource := ac.Resource
		if resource == "" {
			resource = serverURL
		}
		token := RandomHex(32)
		store.SaveToken(&models.OAuthToken{
			Token:     token,
			UserID:    ac.UserID,
			Resource:  resource,
			ExpiresAt: time.Now().Add(tokenExpiry),
		})

		resp := tokenResponse{
			AccessToken: token,
			TokenType:   "Bearer",
			ExpiresIn:   int(tokenExpiry.Seconds()),
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(resp)
	}
}

// verifyPKCE checks that SHA256(verifier) matches the challenge (S256 method).
// Uses constant-time comparison to prevent timing side channels.
func verifyPKCE(verifier, challenge string) bool {
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}
