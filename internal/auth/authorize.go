package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/models"
)

// remoteIP extracts the IP address from r.RemoteAddr, stripping the
// port. Falls back to the raw value if parsing fails.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

// resourceMatches compares a client-supplied resource URI against the
// server's canonical URL. Trailing slashes are stripped before comparison
// because clients may include them (both forms are valid per RFC 3986).
func resourceMatches(resource, serverURL string) bool {
	return strings.TrimRight(resource, "/") == strings.TrimRight(serverURL, "/")
}

// UserCredentials maps usernames to plain text passwords.
type UserCredentials map[string]string

const (
	codeExpiry = 5 * time.Minute

	// rateLimitPruneThreshold is the number of tracked IPs above which
	// the rate limiter prunes expired entries to prevent unbounded growth.
	rateLimitPruneThreshold = 1000

	// csrfTokenBytes is the number of random bytes used to generate
	// a CSRF token (hex-encoded to twice this length).
	csrfTokenBytes = 16

	// authCodeBytes is the number of random bytes used to generate
	// an authorization code (hex-encoded to twice this length).
	authCodeBytes = 32
)

// loginPage renders the OAuth login form. The csrf_token hidden field
// prevents cross-site form submission.
var loginPage = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vault-sync</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: #f5f5f5;
    color: #1a1a1a;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
  }
  .card {
    background: #fff;
    border: 1px solid #e0e0e0;
    border-radius: 8px;
    padding: 2.5rem 2rem;
    width: 100%;
    max-width: 380px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.06);
  }
  .card h1 {
    font-size: 1.25rem;
    font-weight: 600;
    margin-bottom: 0.25rem;
  }
  .card p.sub {
    font-size: 0.85rem;
    color: #666;
    margin-bottom: 1.5rem;
  }
  .consent {
    background: #f8f9fa;
    border: 1px solid #e0e0e0;
    border-radius: 6px;
    padding: 0.6rem 0.75rem;
    font-size: 0.85rem;
    margin-bottom: 1rem;
  }
  .consent p { margin-bottom: 0.3rem; }
  .consent p:last-child { margin-bottom: 0; }
  .consent .redirect { color: #666; word-break: break-all; }
  .consent code { font-size: 0.8rem; }
  .error {
    background: #fef2f2;
    color: #991b1b;
    border: 1px solid #fecaca;
    border-radius: 6px;
    padding: 0.6rem 0.75rem;
    font-size: 0.85rem;
    margin-bottom: 1rem;
  }
  label {
    display: block;
    font-size: 0.85rem;
    font-weight: 500;
    margin-bottom: 0.35rem;
    color: #333;
  }
  input[type="text"], input[type="password"] {
    width: 100%;
    padding: 0.55rem 0.7rem;
    border: 1px solid #d0d0d0;
    border-radius: 6px;
    font-size: 0.9rem;
    outline: none;
    transition: border-color 0.15s;
    margin-bottom: 1rem;
  }
  input[type="text"]:focus, input[type="password"]:focus {
    border-color: #2563eb;
    box-shadow: 0 0 0 2px rgba(37,99,235,0.15);
  }
  button {
    width: 100%;
    padding: 0.6rem;
    background: #1a1a1a;
    color: #fff;
    border: none;
    border-radius: 6px;
    font-size: 0.9rem;
    font-weight: 500;
    cursor: pointer;
    transition: background 0.15s;
  }
  button:hover { background: #333; }
  button:active { background: #000; }
</style>
</head>
<body>
<div class="card">
  <h1>vault-sync</h1>
  <p class="sub">Sign in to authorize access to your vault.</p>
  <div class="consent">
    <p><strong>{{if .ClientName}}{{.ClientName}}{{else}}{{.ClientID}}{{end}}</strong> is requesting access.</p>
    {{if .RedirectURI}}<p class="redirect">You will be redirected to: <code>{{.RedirectURI}}</code></p>{{end}}
  </div>
  {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
  <form method="POST">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <input type="hidden" name="client_id" value="{{.ClientID}}">
    <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
    <input type="hidden" name="state" value="{{.State}}">
    <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
    <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
    <input type="hidden" name="scope" value="{{.Scope}}">
    <input type="hidden" name="resource" value="{{.Resource}}">
    <label for="username">Username</label>
    <input type="text" id="username" name="username" autocomplete="username" required autofocus>
    <label for="password">Password</label>
    <input type="password" id="password" name="password" autocomplete="current-password" required>
    <button type="submit">Sign in</button>
  </form>
</div>
</body>
</html>`))

type loginData struct {
	CSRFToken           string
	ClientID            string
	ClientName          string
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	Resource            string
	Error               string
}

// loginRateLimiter tracks failed login attempts per IP with a sliding
// window. After maxFailures within the window, further attempts are
// rejected until the window expires.
type loginRateLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

const (
	rateLimitWindow  = 5 * time.Minute
	rateLimitMaxFail = 10
)

func newLoginRateLimiter() *loginRateLimiter {
	return &loginRateLimiter{
		failures: make(map[string][]time.Time),
	}
}

// check returns true if the IP is currently rate-limited.
func (rl *loginRateLimiter) check(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rateLimitWindow)

	// Prevent unbounded growth from many distinct source IPs. When
	// the map gets large, prune all IPs whose most recent failure
	// has expired beyond the window.
	if len(rl.failures) > rateLimitPruneThreshold {
		for k, times := range rl.failures {
			if len(times) == 0 || times[len(times)-1].Before(cutoff) {
				delete(rl.failures, k)
			}
		}
	}

	// Prune old entries for the requested IP.
	recent := rl.failures[ip][:0]
	for _, t := range rl.failures[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) == 0 {
		delete(rl.failures, ip)
	} else {
		rl.failures[ip] = recent
	}

	return len(recent) >= rateLimitMaxFail
}

// record adds a failed attempt for the IP.
func (rl *loginRateLimiter) record(ip string) {
	rl.mu.Lock()
	rl.failures[ip] = append(rl.failures[ip], time.Now())
	rl.mu.Unlock()
}

// redirectWithError redirects the user-agent back to the client with an
// error response per RFC 6749 Section 4.1.2.1. This must only be called
// after the redirect_uri and client_id have been validated.
func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, description string) {
	params := url.Values{}
	params.Set("error", errCode)
	params.Set("error_description", description)

	if state != "" {
		params.Set("state", state)
	}

	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}

	http.Redirect(w, r, redirectURI+sep+params.Encode(), http.StatusFound)
}

// HandleAuthorize returns the /oauth/authorize handler. The serverURL
// serves as both the canonical resource identifier (RFC 8707) and the
// issuer identifier for mix-up attack prevention (RFC 9207).
func HandleAuthorize(store *Store, users UserCredentials, logger *slog.Logger, serverURL string) http.HandlerFunc {
	limiter := newLoginRateLimiter()

	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleAuthorizeGET(w, r, store, serverURL)
		case http.MethodPost:
			handleAuthorizePOST(w, r, store, users, logger, limiter, serverURL)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// validateRedirectURI checks that redirectURI matches one of the client's
// registered redirect_uris. Exact match is required for HTTPS URIs.
// For localhost URIs (http://127.0.0.1 or http://localhost), prefix
// matching is used so any port and path are accepted. This follows
// RFC 8252 Section 7.3 which allows dynamic ports for loopback redirects.
//
// When a client has no registered redirect URIs, only loopback URIs
// are accepted. This prevents open redirect attacks where an attacker
// uses a known client_id to redirect authorization codes to an
// external server they control.
func validateRedirectURI(client *models.OAuthClient, redirectURI string) bool {
	if len(client.RedirectURIs) == 0 {
		u, err := url.Parse(redirectURI)
		if err != nil {
			return false
		}

		return u.Scheme == "http" && isLoopbackHost(u.Hostname())
	}

	for _, registered := range client.RedirectURIs {
		if redirectURI == registered {
			return true
		}

		// RFC 8252 Section 7.3: loopback redirect URIs may use any
		// port. Parse both as URLs and compare hostnames to prevent
		// DNS confusion (e.g. 127.0.0.1.evil.com).
		if isLocalhostPrefix(registered) && isLoopbackRedirect(redirectURI, registered) {
			return true
		}
	}

	return false
}

// isLocalhostPrefix returns true if the URI is an HTTP loopback prefix
// (http://127.0.0.1 or http://localhost) without a port or path, making
// it suitable for prefix matching per RFC 8252 Section 7.3.
func isLocalhostPrefix(uri string) bool {
	return uri == "http://127.0.0.1" || uri == "http://localhost"
}

// isLoopbackHost returns true if the hostname is a loopback address.
func isLoopbackHost(host string) bool {
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

// isLoopbackRedirect checks if redirectURI is a valid loopback redirect
// matching the registered prefix URI. It parses both as URLs and
// compares scheme and hostname to prevent DNS confusion attacks
// (e.g. 127.0.0.1.evil.com matching a 127.0.0.1 prefix).
func isLoopbackRedirect(redirectURI, registeredPrefix string) bool {
	ru, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}

	pu, err := url.Parse(registeredPrefix)
	if err != nil {
		return false
	}

	return ru.Scheme == pu.Scheme && ru.Hostname() == pu.Hostname()
}

// generateCSRFToken creates a random CSRF token bound to specific
// OAuth parameters and stores it.
func generateCSRFToken(store *Store, clientID, redirectURI string) string {
	b := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}

	token := hex.EncodeToString(b)
	store.SaveCSRF(token, clientID, redirectURI)

	return token
}

func handleAuthorizeGET(w http.ResponseWriter, r *http.Request, store *Store, serverURL string) {
	q := r.URL.Query()

	clientID := q.Get("client_id")
	if clientID == "" {
		http.Error(w, "missing client_id", http.StatusBadRequest)
		return
	}

	client := store.GetClient(clientID)
	if client == nil {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}

	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		// RFC 6749 Section 3.1.2.3: when only one redirect URI is
		// registered, use it. Otherwise require an explicit value.
		if len(client.RedirectURIs) == 1 {
			redirectURI = client.RedirectURIs[0]
		} else {
			http.Error(w, "redirect_uri is required when multiple URIs are registered", http.StatusBadRequest)
			return
		}
	} else if !validateRedirectURI(client, redirectURI) {
		http.Error(w, "redirect_uri not registered for this client", http.StatusBadRequest)
		return
	}

	// RFC 6749 Section 4.1.1: response_type is REQUIRED and must be "code".
	// Errors after redirect_uri validation are returned as query params on
	// the redirect URI per RFC 6749 Section 4.1.2.1.
	responseType := q.Get("response_type")
	state := q.Get("state")

	if responseType != "code" {
		errCode := "unsupported_response_type"
		if responseType == "" {
			errCode = "invalid_request"
		}

		redirectWithError(w, r, redirectURI, state, errCode, "response_type must be \"code\"")

		return
	}

	codeChallenge := q.Get("code_challenge")
	if codeChallenge == "" {
		redirectWithError(w, r, redirectURI, state, "invalid_request", "code_challenge is required (PKCE)")
		return
	}

	codeChallengeMethod := q.Get("code_challenge_method")
	if codeChallengeMethod != "" && codeChallengeMethod != "S256" {
		redirectWithError(w, r, redirectURI, state, "invalid_request", "only S256 code_challenge_method is supported")
		return
	}

	// RFC 8707: accept the resource parameter. Clients MUST send it,
	// but we tolerate its absence for backward compatibility.
	resource := q.Get("resource")
	if resource != "" && !resourceMatches(resource, serverURL) {
		redirectWithError(w, r, redirectURI, state, "invalid_request", "resource parameter does not match this server")
		return
	}

	data := loginData{
		CSRFToken:           generateCSRFToken(store, clientID, redirectURI),
		ClientID:            clientID,
		ClientName:          client.ClientName,
		RedirectURI:         redirectURI,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Scope:               q.Get("scope"),
		Resource:            resource,
	}

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	_ = loginPage.Execute(w, data)
}

func handleAuthorizePOST(w http.ResponseWriter, r *http.Request, store *Store, users UserCredentials, logger *slog.Logger, limiter *loginRateLimiter, serverURL string) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}

	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	codeChallenge := r.FormValue("code_challenge")
	csrfToken := r.FormValue("csrf_token")
	username := r.FormValue("username")
	password := r.FormValue("password")
	resource := r.FormValue("resource")

	client := store.GetClient(clientID)
	if client == nil {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}

	// Validate redirect_uri against registered URIs.
	if redirectURI == "" {
		if len(client.RedirectURIs) == 1 {
			redirectURI = client.RedirectURIs[0]
		} else {
			http.Error(w, "redirect_uri is required when multiple URIs are registered", http.StatusBadRequest)
			return
		}
	} else if !validateRedirectURI(client, redirectURI) {
		http.Error(w, "redirect_uri not registered for this client", http.StatusBadRequest)
		return
	}

	// PKCE is mandatory. Return error as redirect since client_id and
	// redirect_uri have been validated.
	if codeChallenge == "" {
		redirectWithError(w, r, redirectURI, state, "invalid_request", "code_challenge is required (PKCE)")
		return
	}

	// RFC 8707: validate resource parameter matches this server.
	if resource != "" && !resourceMatches(resource, serverURL) {
		redirectWithError(w, r, redirectURI, state, "invalid_request", "resource parameter does not match this server")
		return
	}

	// Rate limiting by remote IP. Check before consuming CSRF so a
	// rate-limited request does not destroy the user's CSRF token.
	ip := remoteIP(r)
	if limiter.check(ip) {
		logger.Warn("login rate limited", slog.String("ip", ip))
		http.Error(w, "too many failed login attempts, try again later", http.StatusTooManyRequests)

		return
	}

	// CSRF validation. A failed CSRF check may indicate a cross-site
	// attack, so return a plain error rather than redirecting to the
	// client (which could be the attacker's URI in a forged form).
	if !store.ConsumeCSRF(csrfToken, clientID, redirectURI) {
		http.Error(w, "invalid or expired CSRF token", http.StatusForbidden)
		return
	}

	// Validate credentials. Both sides are SHA-256 hashed before
	// comparison to normalize length. subtle.ConstantTimeCompare
	// returns 0 immediately when lengths differ, which would leak
	// password length if raw values were compared.
	expected, ok := users[username]
	if !ok {
		expected = "\x00invalid"
	}

	expectedH := sha256.Sum256([]byte(expected))
	passwordH := sha256.Sum256([]byte(password))

	if !ok || subtle.ConstantTimeCompare(expectedH[:], passwordH[:]) != 1 {
		logger.Warn("login failed", slog.String("username", username))
		limiter.record(ip)

		data := loginData{
			CSRFToken:           generateCSRFToken(store, clientID, redirectURI),
			ClientID:            clientID,
			ClientName:          client.ClientName,
			RedirectURI:         redirectURI,
			State:               state,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: r.FormValue("code_challenge_method"),
			Scope:               r.FormValue("scope"),
			Resource:            resource,
			Error:               "Invalid username or password",
		}

		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.WriteHeader(http.StatusUnauthorized)
		_ = loginPage.Execute(w, data)

		return
	}

	logger.Info("login successful", slog.String("username", username))

	// Issue authorization code bound to the resource (RFC 8707).
	// Parse the scope parameter into individual scope values. The
	// authorize endpoint carries scope through the form; store them
	// on the code so they propagate to the issued token.
	var scopes []string
	if scopeParam := r.FormValue("scope"); scopeParam != "" {
		scopes = strings.Fields(scopeParam)
	}

	code := RandomHex(authCodeBytes)
	store.SaveCode(&Code{
		Code:          code,
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		Resource:      resource,
		UserID:        username,
		Scopes:        scopes,
		ExpiresAt:     time.Now().Add(codeExpiry),
	})

	// Build redirect URL with proper encoding. Use "&" if the
	// redirect URI already contains a query component (RFC 6749
	// Section 4.1.2 requires retaining existing query parameters).
	params := url.Values{}
	params.Set("code", code)

	if state != "" {
		params.Set("state", state)
	}

	// RFC 9207: include the issuer identifier to prevent mix-up attacks.
	if serverURL != "" {
		params.Set("iss", serverURL)
	}

	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}

	redirectURL := redirectURI + sep + params.Encode()
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
