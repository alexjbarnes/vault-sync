// Package models defines types shared across internal packages.
package models

import "time"

// OAuthToken represents an issued access or refresh token.
// Kind is "access" or "refresh". Tokens without a Kind (pre-existing)
// are treated as "access" for backward compatibility.
type OAuthToken struct {
	Token        string    `json:"token"`
	Kind         string    `json:"kind,omitempty"` // "access" or "refresh"
	UserID       string    `json:"user_id"`
	Resource     string    `json:"resource"`
	Scopes       []string  `json:"scopes,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken string    `json:"refresh_token,omitempty"` // On access tokens only
	ClientID     string    `json:"client_id,omitempty"`     // Which client this token was issued to
}

// OAuthClient represents a dynamically registered OAuth client.
type OAuthClient struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
}
