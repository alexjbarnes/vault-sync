// Package models defines types shared across internal packages.
package models

import "time"

// OAuthToken represents an issued access token.
type OAuthToken struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	Resource  string    `json:"resource"`
	Scopes    []string  `json:"scopes,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// OAuthClient represents a dynamically registered OAuth client.
type OAuthClient struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
}
