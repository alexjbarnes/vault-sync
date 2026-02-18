package errors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSentinelErrors_ImplementErrorInterface(t *testing.T) {
	sentinels := []error{
		ErrInvalidCredentials,
		ErrInvalidToken,
		ErrVaultNotFound,
		ErrAPIRequest,
		ErrAPIResponse,
	}
	for _, err := range sentinels {
		assert.NotEmpty(t, err.Error(), "sentinel error should have non-empty message")
	}
}

func TestSentinelErrors_AreDistinct(t *testing.T) {
	sentinels := []error{
		ErrInvalidCredentials,
		ErrInvalidToken,
		ErrVaultNotFound,
		ErrAPIRequest,
		ErrAPIResponse,
	}
	for i := 0; i < len(sentinels); i++ {
		for j := i + 1; j < len(sentinels); j++ {
			assert.NotEqual(t, sentinels[i], sentinels[j],
				"sentinel errors should be distinct: %q vs %q", sentinels[i], sentinels[j])
		}
	}
}

func TestSentinelErrors_ExpectedMessages(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{ErrInvalidCredentials, "invalid email or password"},
		{ErrInvalidToken, "invalid or expired token"},
		{ErrVaultNotFound, "vault not found"},
		{ErrAPIRequest, "API request failed"},
		{ErrAPIResponse, "unexpected API response"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.err.Error())
	}
}
