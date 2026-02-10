package obsidian

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestClient creates a Client pointed at the given httptest server.
func newTestClient(srv *httptest.Server) *Client {
	return &Client{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
	}
}

// --- post() internals ---

func TestPost_SetsContentTypeAndOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "app://obsidian.md", r.Header.Get("Origin"))
		assert.Equal(t, http.MethodPost, r.Method)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	err := c.post(context.Background(), "/test", struct{}{}, nil)
	require.NoError(t, err)
}

func TestPost_MarshalsRequestBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req SigninRequest
		require.NoError(t, json.Unmarshal(body, &req))
		assert.Equal(t, "user@example.com", req.Email)
		assert.Equal(t, "secret", req.Password)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	err := c.post(context.Background(), "/user/signin", SigninRequest{
		Email:    "user@example.com",
		Password: "secret",
	}, nil)
	require.NoError(t, err)
}

func TestPost_DecodesResponseIntoResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"token":"abc123","email":"u@e.com","name":"Test","license":"sync"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	var resp SigninResponse
	err := c.post(context.Background(), "/user/signin", struct{}{}, &resp)
	require.NoError(t, err)
	assert.Equal(t, "abc123", resp.Token)
	assert.Equal(t, "u@e.com", resp.Email)
	assert.Equal(t, "Test", resp.Name)
}

func TestPost_NilResultSkipsDecode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"some":"data"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	err := c.post(context.Background(), "/test", struct{}{}, nil)
	require.NoError(t, err)
}

func TestPost_NonOKStatusWithAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid token"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	err := c.post(context.Background(), "/vault/list", struct{}{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token")
	assert.Contains(t, err.Error(), "401")
}

func TestPost_NonOKStatusWithoutAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`Internal Server Error`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	err := c.post(context.Background(), "/test", struct{}{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
	assert.Contains(t, err.Error(), "Internal Server Error")
}

func TestPost_OKStatusWithAPIError(t *testing.T) {
	// Obsidian's quirk: 200 OK with an error field in the body.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"error":"subscription expired"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	err := c.post(context.Background(), "/vault/list", struct{}{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subscription expired")
}

func TestPost_OKStatusEmptyErrorFieldNotTreatedAsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"error":"","token":"good"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	var resp SigninResponse
	err := c.post(context.Background(), "/test", struct{}{}, &resp)
	require.NoError(t, err)
	assert.Equal(t, "good", resp.Token)
}

func TestPost_MalformedResponseJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{not json`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	var resp SigninResponse
	err := c.post(context.Background(), "/test", struct{}{}, &resp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding response")
}

func TestPost_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := c.post(ctx, "/test", struct{}{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sending request")
}

func TestPost_EndpointAppendsToBaseURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/user/signin", r.URL.Path)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	err := c.post(context.Background(), "/user/signin", struct{}{}, nil)
	require.NoError(t, err)
}

// --- NewClient ---

func TestNewClient_NilHTTPClient(t *testing.T) {
	c := NewClient(nil)
	assert.NotNil(t, c.httpClient)
	assert.Equal(t, 30*time.Second, c.httpClient.Timeout, "default client should have a 30s timeout")
	assert.NotNil(t, c.httpClient.CheckRedirect, "default client should have a redirect policy")
	assert.Equal(t, baseURL, c.baseURL)
}

func TestNewClient_CustomHTTPClient(t *testing.T) {
	custom := &http.Client{}
	c := NewClient(custom)
	assert.Equal(t, custom, c.httpClient)
}

// --- Signin ---

func TestSignin_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/user/signin", r.URL.Path)

		body, _ := io.ReadAll(r.Body)
		var req SigninRequest
		require.NoError(t, json.Unmarshal(body, &req))
		assert.Equal(t, "test@example.com", req.Email)
		assert.Equal(t, "pass123", req.Password)

		resp := SigninResponse{
			Token:   "tok_abc",
			Email:   "test@example.com",
			Name:    "Test User",
			License: "sync",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	resp, err := c.Signin(context.Background(), "test@example.com", "pass123")
	require.NoError(t, err)
	assert.Equal(t, "tok_abc", resp.Token)
	assert.Equal(t, "Test User", resp.Name)
	assert.Equal(t, "sync", resp.License)
}

func TestSignin_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"error":"invalid credentials"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	resp, err := c.Signin(context.Background(), "bad@example.com", "wrong")
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid credentials")
}

func TestSignin_ServerDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // Close immediately so connection fails.

	c := newTestClient(srv)
	resp, err := c.Signin(context.Background(), "a@b.com", "p")
	require.Error(t, err)
	assert.Nil(t, resp)
}

// --- Signout ---

func TestSignout_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/user/signout", r.URL.Path)

		body, _ := io.ReadAll(r.Body)
		var req SignoutRequest
		require.NoError(t, json.Unmarshal(body, &req))
		assert.Equal(t, "tok_xyz", req.Token)

		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	err := c.Signout(context.Background(), "tok_xyz")
	require.NoError(t, err)
}

func TestSignout_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"token expired"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	err := c.Signout(context.Background(), "bad_token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token expired")
}

// --- ListVaults ---

func TestListVaults_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/vault/list", r.URL.Path)

		body, _ := io.ReadAll(r.Body)
		var req VaultListRequest
		require.NoError(t, json.Unmarshal(body, &req))
		assert.Equal(t, "tok_abc", req.Token)
		assert.Equal(t, 3, req.SupportedEncryptionVersion)

		resp := VaultListResponse{
			Vaults: []VaultInfo{
				{ID: "v1", Name: "My Vault", Size: 1024, Salt: "s1", EncryptionVersion: 2},
			},
			Shared: []VaultInfo{
				{ID: "v2", Name: "Shared Vault", Size: 512},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	resp, err := c.ListVaults(context.Background(), "tok_abc")
	require.NoError(t, err)
	require.Len(t, resp.Vaults, 1)
	assert.Equal(t, "v1", resp.Vaults[0].ID)
	assert.Equal(t, "My Vault", resp.Vaults[0].Name)
	assert.Equal(t, int64(1024), resp.Vaults[0].Size)
	require.Len(t, resp.Shared, 1)
	assert.Equal(t, "v2", resp.Shared[0].ID)
}

func TestListVaults_EmptyVaults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vaults":[],"shared":[]}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	resp, err := c.ListVaults(context.Background(), "tok")
	require.NoError(t, err)
	assert.Empty(t, resp.Vaults)
	assert.Empty(t, resp.Shared)
}

func TestListVaults_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	resp, err := c.ListVaults(context.Background(), "bad_token")
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "unauthorized")
}

func TestListVaults_SetsEncryptionVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		assert.True(t, strings.Contains(string(body), `"supported_encryption_version":3`),
			"request should include supported_encryption_version=3")
		w.Write([]byte(`{"vaults":[],"shared":[]}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := c.ListVaults(context.Background(), "tok")
	require.NoError(t, err)
}

// --- post() edge cases ---

func TestPost_NonOKStatusWithMalformedErrorJSON(t *testing.T) {
	// Non-200 with body that isn't valid JSON -- should still return
	// the raw body in the error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`<html>Bad Gateway</html>`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	err := c.post(context.Background(), "/test", struct{}{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "502")
	assert.Contains(t, err.Error(), "<html>Bad Gateway</html>")
}

func TestPost_OKStatusWithNonErrorJSON(t *testing.T) {
	// 200 with body that has no "error" field -- should decode into result
	// and not treat it as an error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vaults":[{"id":"v1","name":"test"}],"shared":[]}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	var resp VaultListResponse
	err := c.post(context.Background(), "/vault/list", struct{}{}, &resp)
	require.NoError(t, err)
	require.Len(t, resp.Vaults, 1)
	assert.Equal(t, "v1", resp.Vaults[0].ID)
}
