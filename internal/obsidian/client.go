package obsidian

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// TransientError wraps an error that is likely temporary and safe to retry.
type TransientError struct {
	Err error
}

func (e *TransientError) Error() string { return e.Err.Error() }
func (e *TransientError) Unwrap() error { return e.Err }

// IsTransient reports whether err (or any error in its chain) is a
// TransientError, meaning the caller should retry after a backoff.
func IsTransient(err error) bool {
	var te *TransientError
	return errors.As(err, &te)
}

const baseURL = "https://api.obsidian.md"

const (
	// maxRedirects is the maximum number of HTTP redirects to follow
	// before giving up, matching the default net/http limit.
	maxRedirects = 10

	// httpClientTimeout is the timeout for the default HTTP client used
	// by the API client when no custom client is provided.
	httpClientTimeout = 30 * time.Second

	// maxAPIResponseBytes caps response body reads to prevent a
	// misbehaving server from consuming unbounded memory.
	maxAPIResponseBytes = 1024 * 1024

	// supportedEncryptionVersion is the encryption version sent to the
	// server in vault list requests.
	supportedEncryptionVersion = 3
)

// Client talks to the Obsidian REST API.
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// sameHostRedirectPolicy follows redirects only when the target host
// matches the original request host. This prevents credentials or
// Origin headers from leaking to third-party domains.
func sameHostRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return errors.New("stopped after 10 redirects")
	}

	if len(via) > 0 {
		origHost := via[0].URL.Host
		if req.URL.Host != origHost {
			return fmt.Errorf("redirect to different host blocked: %s -> %s", origHost, req.URL.Host)
		}
	}

	return nil
}

// NewClient creates an API client with the given http.Client.
// If httpClient is nil, a client with a 30-second timeout and
// same-host redirect policy is created.
func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout:       httpClientTimeout,
			CheckRedirect: sameHostRedirectPolicy,
		}
	}

	return &Client{
		httpClient: httpClient,
		baseURL:    baseURL,
	}
}

// sanitizeResponseBody truncates and sanitizes a response body for
// inclusion in error messages. Limits to 256 bytes and replaces
// non-printable characters to prevent log injection.
func sanitizeResponseBody(body []byte) string {
	const maxLen = 256
	if len(body) > maxLen {
		body = body[:maxLen]
	}
	// Ensure valid UTF-8 and replace control characters.
	var clean []byte

	for len(body) > 0 {
		r, size := utf8.DecodeRune(body)
		if r == utf8.RuneError && size <= 1 {
			clean = append(clean, '?')
			body = body[1:]

			continue
		}

		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			clean = append(clean, '?')
		} else {
			clean = append(clean, body[:size]...)
		}

		body = body[size:]
	}

	return string(clean)
}

// post sends a JSON POST request and decodes the response into result.
func (c *Client) post(ctx context.Context, endpoint string, body, result interface{}) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshalling request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "app://obsidian.md")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		wrapped := fmt.Errorf("sending request to %s: %w", endpoint, err)
		// Network errors (timeouts, connection refused, DNS failures)
		// are transient by nature.
		return &TransientError{Err: wrapped}
	}
	defer resp.Body.Close()

	// Cap response reads at 1MB. API responses are small JSON payloads.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseBytes))
	if err != nil {
		return fmt.Errorf("reading response from %s: %w", endpoint, err)
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr APIError
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Error != "" {
			err := fmt.Errorf("API %s (%d): %s", endpoint, resp.StatusCode, apiErr.Error)
			if isTransientStatus(resp.StatusCode) || isTransientMessage(apiErr.Error) {
				return &TransientError{Err: err}
			}

			return err
		}

		err := fmt.Errorf("API %s returned status %d: %s", endpoint, resp.StatusCode, sanitizeResponseBody(respBody))
		if isTransientStatus(resp.StatusCode) {
			return &TransientError{Err: err}
		}

		return err
	}

	// Obsidian API returns errors as 200 with an "error" field in the body.
	var apiErr APIError
	if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Error != "" {
		err := fmt.Errorf("API %s: %s", endpoint, apiErr.Error)
		if isTransientMessage(apiErr.Error) {
			return &TransientError{Err: err}
		}

		return err
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("decoding response from %s: %w", endpoint, err)
		}
	}

	return nil
}

// Signin authenticates with email and password, returning a session token.
func (c *Client) Signin(ctx context.Context, email, password string) (*SigninResponse, error) {
	req := SigninRequest{
		Email:    email,
		Password: password,
	}

	var resp SigninResponse
	if err := c.post(ctx, "/user/signin", req, &resp); err != nil {
		return nil, fmt.Errorf("signing in: %w", err)
	}

	return &resp, nil
}

// Signout invalidates the given token.
func (c *Client) Signout(ctx context.Context, token string) error {
	req := SignoutRequest{Token: token}

	if err := c.post(ctx, "/user/signout", req, nil); err != nil {
		return fmt.Errorf("signing out: %w", err)
	}

	return nil
}

// isTransientStatus returns true for HTTP status codes that indicate a
// temporary server-side problem worth retrying.
func isTransientStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}

	return false
}

// isTransientMessage checks whether an API error message suggests a
// temporary condition. Obsidian returns "Server overloaded, please try
// again later." as a 200 with an error body, so we match on that.
func isTransientMessage(msg string) bool {
	lower := strings.ToLower(msg)

	return strings.Contains(lower, "overloaded") ||
		strings.Contains(lower, "try again") ||
		strings.Contains(lower, "temporarily unavailable")
}

// ListVaults returns all vaults accessible to the authenticated user.
func (c *Client) ListVaults(ctx context.Context, token string) (*VaultListResponse, error) {
	req := VaultListRequest{
		Token:                      token,
		SupportedEncryptionVersion: supportedEncryptionVersion,
	}

	var resp VaultListResponse
	if err := c.post(ctx, "/vault/list", req, &resp); err != nil {
		return nil, fmt.Errorf("listing vaults: %w", err)
	}

	return &resp, nil
}
