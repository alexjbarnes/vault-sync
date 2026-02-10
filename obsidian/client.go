package obsidian

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
	"unicode/utf8"
)

const baseURL = "https://api.obsidian.md"

// Client talks to the Obsidian REST API.
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// sameHostRedirectPolicy follows redirects only when the target host
// matches the original request host. This prevents credentials or
// Origin headers from leaking to third-party domains.
func sameHostRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
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
			Timeout:       30 * time.Second,
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
		return fmt.Errorf("sending request to %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	// Cap response reads at 1MB. API responses are small JSON payloads.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return fmt.Errorf("reading response from %s: %w", endpoint, err)
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr APIError
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Error != "" {
			return fmt.Errorf("API %s (%d): %s", endpoint, resp.StatusCode, apiErr.Error)
		}
		return fmt.Errorf("API %s returned status %d: %s", endpoint, resp.StatusCode, sanitizeResponseBody(respBody))
	}

	// Obsidian API returns errors as 200 with an "error" field in the body.
	var apiErr APIError
	if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Error != "" {
		return fmt.Errorf("API %s: %s", endpoint, apiErr.Error)
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

// ListVaults returns all vaults accessible to the authenticated user.
func (c *Client) ListVaults(ctx context.Context, token string) (*VaultListResponse, error) {
	req := VaultListRequest{
		Token:                      token,
		SupportedEncryptionVersion: 3,
	}

	var resp VaultListResponse
	if err := c.post(ctx, "/vault/list", req, &resp); err != nil {
		return nil, fmt.Errorf("listing vaults: %w", err)
	}

	return &resp, nil
}
