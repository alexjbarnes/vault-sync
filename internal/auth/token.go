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

const (
	tokenExpiry        = time.Hour
	refreshTokenExpiry = 30 * 24 * time.Hour
)

type tokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	CodeVerifier string `json:"code_verifier"`
	ClientID     string `json:"client_id"`
	Resource     string `json:"resource"`
	RefreshToken string `json:"refresh_token"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
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
				RefreshToken: r.FormValue("refresh_token"),
			}
		}

		if req.GrantType != "authorization_code" && req.GrantType != "refresh_token" {
			writeJSONError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code and refresh_token are supported")
			return
		}

		// Handle refresh_token grant
		if req.GrantType == "refresh_token" {
			if req.RefreshToken == "" {
				writeJSONError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
				return
			}

			rt := store.ConsumeRefreshToken(req.RefreshToken, req.ClientID, req.Resource)
			if rt == nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired refresh token")
				return
			}

			// Delete old access token if still present
			if rt.RefreshToken != "" {
				store.DeleteToken(rt.RefreshToken)
			}

			// Issue new access token + new refresh token
			resource := rt.Resource
			if resource == "" {
				resource = serverURL
			}

			newAccessToken := RandomHex(32)
			newRefreshToken := RandomHex(32)

			store.SaveToken(&models.OAuthToken{
				Token:        newAccessToken,
				Kind:         "access",
				UserID:       rt.UserID,
				Resource:     resource,
				Scopes:       rt.Scopes,
				ExpiresAt:    time.Now().Add(tokenExpiry),
				RefreshToken: newRefreshToken,
				ClientID:     rt.ClientID,
			})

			store.SaveToken(&models.OAuthToken{
				Token:     newRefreshToken,
				Kind:      "refresh",
				UserID:    rt.UserID,
				Resource:  resource,
				Scopes:    rt.Scopes,
				ExpiresAt: time.Now().Add(refreshTokenExpiry),
				ClientID:  rt.ClientID,
			})

			resp := tokenResponse{
				AccessToken:  newAccessToken,
				TokenType:    "Bearer",
				ExpiresIn:    int(tokenExpiry.Seconds()),
				RefreshToken: newRefreshToken,
			}

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			json.NewEncoder(w).Encode(resp)
			return
		}

		// Handle authorization_code grant
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

		// Get client ID from the auth code or request
		clientID := ac.ClientID
		if clientID == "" {
			clientID = req.ClientID
		}

		// Generate both access and refresh tokens
		accessToken := RandomHex(32)
		refreshToken := RandomHex(32)

		// Save access token
		store.SaveToken(&models.OAuthToken{
			Token:        accessToken,
			Kind:         "access",
			UserID:       ac.UserID,
			Resource:     resource,
			Scopes:       ac.Scopes,
			ExpiresAt:    time.Now().Add(tokenExpiry),
			RefreshToken: refreshToken,
			ClientID:     clientID,
		})

		// Save refresh token
		store.SaveToken(&models.OAuthToken{
			Token:     refreshToken,
			Kind:      "refresh",
			UserID:    ac.UserID,
			Resource:  resource,
			Scopes:    ac.Scopes,
			ExpiresAt: time.Now().Add(refreshTokenExpiry),
			ClientID:  clientID,
		})

		resp := tokenResponse{
			AccessToken:  accessToken,
			TokenType:    "Bearer",
			ExpiresIn:    int(tokenExpiry.Seconds()),
			RefreshToken: refreshToken,
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
