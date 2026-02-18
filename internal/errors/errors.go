package errors

import "errors"

// Client errors.
var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrVaultNotFound      = errors.New("vault not found")
)

// Server/transport errors.
var (
	ErrAPIRequest  = errors.New("API request failed")
	ErrAPIResponse = errors.New("unexpected API response")
)
