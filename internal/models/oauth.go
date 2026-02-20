// Package models defines types shared across internal packages.
package models

import "time"

// OAuthToken represents an issued access or refresh token.
// Kind is "access" or "refresh". Tokens without a Kind (pre-existing)
// are treated as "access" for backward compatibility.
//
// Raw token values (Token, RefreshToken) are transient and never
// persisted to disk. Only their SHA-256 hashes are stored. The raw
// fields are populated with omitempty so old bbolt entries that
// contain them can still be deserialized for migration.
type OAuthToken struct {
	Token        string    `json:"token,omitempty"`      // Transient; cleared before persistence
	TokenHash    string    `json:"token_hash,omitempty"` // SHA-256 hex; primary lookup key
	Kind         string    `json:"kind,omitempty"`       // "access" or "refresh"
	UserID       string    `json:"user_id"`
	Resource     string    `json:"resource"`
	Scopes       []string  `json:"scopes,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken string    `json:"refresh_token,omitempty"` // Transient; cleared before persistence
	RefreshHash  string    `json:"refresh_hash,omitempty"`  // SHA-256 of paired refresh token (access tokens only)
	ClientID     string    `json:"client_id,omitempty"`     // Which client this token was issued to
}

// OAuthClient represents a dynamically registered OAuth client.
type OAuthClient struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	SecretHash              string   `json:"secret_hash,omitempty"`
	IssuedAt                int64    `json:"client_id_issued_at,omitempty"`
}

// APIKey represents a pre-configured API key for Bearer token authentication.
// Unlike OAuth tokens, API keys are permanent and only removed by revocation.
type APIKey struct {
	KeyHash   string    `json:"key_hash"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
}
