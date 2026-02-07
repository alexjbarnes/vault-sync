package obsidian

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const baseURL = "https://api.obsidian.md"

// Client talks to the Obsidian REST API.
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// NewClient creates an API client with the given http.Client.
// If httpClient is nil, http.DefaultClient is used.
func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{
		httpClient: httpClient,
		baseURL:    baseURL,
	}
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

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response from %s: %w", endpoint, err)
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr APIError
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Error != "" {
			return fmt.Errorf("API %s (%d): %s", endpoint, resp.StatusCode, apiErr.Error)
		}
		return fmt.Errorf("API %s returned status %d: %s", endpoint, resp.StatusCode, string(respBody))
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
