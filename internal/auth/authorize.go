package auth

import (
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// UserCredentials maps usernames to bcrypt hashes.
type UserCredentials map[string]string

const codeExpiry = 5 * time.Minute

// loginPage is a minimal HTML login form. The csrf_token hidden field
// prevents cross-site form submission.
var loginPage = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html>
<head><title>Vault Sync - Login</title></head>
<body>
<h2>Vault Sync Login</h2>
{{if .Error}}<p style="color:red">{{.Error}}</p>{{end}}
<form method="POST">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<input type="hidden" name="client_id" value="{{.ClientID}}">
<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
<input type="hidden" name="state" value="{{.State}}">
<input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
<input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
<input type="hidden" name="scope" value="{{.Scope}}">
<label>Username: <input type="text" name="username" required></label><br><br>
<label>Password: <input type="password" name="password" required></label><br><br>
<button type="submit">Login</button>
</form>
</body>
</html>`))

type loginData struct {
	CSRFToken           string
	ClientID            string
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
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

	// Prune old entries.
	recent := rl.failures[ip][:0]
	for _, t := range rl.failures[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	rl.failures[ip] = recent

	return len(recent) >= rateLimitMaxFail
}

// record adds a failed attempt for the IP.
func (rl *loginRateLimiter) record(ip string) {
	rl.mu.Lock()
	rl.failures[ip] = append(rl.failures[ip], time.Now())
	rl.mu.Unlock()
}

// HandleAuthorize returns the /oauth/authorize handler.
func HandleAuthorize(store *Store, users UserCredentials, logger *slog.Logger) http.HandlerFunc {
	limiter := newLoginRateLimiter()

	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleAuthorizeGET(w, r, store)
		case http.MethodPost:
			handleAuthorizePOST(w, r, store, users, logger, limiter)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// validateRedirectURI checks that redirectURI matches one of the client's
// registered redirect_uris. Returns true if valid.
func validateRedirectURI(client *ClientInfo, redirectURI string) bool {
	for _, registered := range client.RedirectURIs {
		if redirectURI == registered {
			return true
		}
	}
	return false
}

// generateCSRFToken creates a random CSRF token and stores it.
func generateCSRFToken(store *Store) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	token := hex.EncodeToString(b)
	store.SaveCSRF(token)
	return token
}

func handleAuthorizeGET(w http.ResponseWriter, r *http.Request, store *Store) {
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
	if redirectURI != "" && !validateRedirectURI(client, redirectURI) {
		http.Error(w, "redirect_uri not registered for this client", http.StatusBadRequest)
		return
	}

	codeChallenge := q.Get("code_challenge")
	if codeChallenge == "" {
		http.Error(w, "code_challenge is required (PKCE)", http.StatusBadRequest)
		return
	}

	codeChallengeMethod := q.Get("code_challenge_method")
	if codeChallengeMethod != "" && codeChallengeMethod != "S256" {
		http.Error(w, "only S256 code_challenge_method is supported", http.StatusBadRequest)
		return
	}

	data := loginData{
		CSRFToken:           generateCSRFToken(store),
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               q.Get("state"),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Scope:               q.Get("scope"),
	}

	w.Header().Set("Content-Type", "text/html")
	loginPage.Execute(w, data)
}

func handleAuthorizePOST(w http.ResponseWriter, r *http.Request, store *Store, users UserCredentials, logger *slog.Logger, limiter *loginRateLimiter) {
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

	client := store.GetClient(clientID)
	if client == nil {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}

	// Validate redirect_uri against registered URIs.
	if redirectURI != "" && !validateRedirectURI(client, redirectURI) {
		http.Error(w, "redirect_uri not registered for this client", http.StatusBadRequest)
		return
	}

	// PKCE is mandatory.
	if codeChallenge == "" {
		http.Error(w, "code_challenge is required (PKCE)", http.StatusBadRequest)
		return
	}

	// CSRF validation.
	if !store.ConsumeCSRF(csrfToken) {
		http.Error(w, "invalid or expired CSRF token", http.StatusForbidden)
		return
	}

	// Rate limiting by remote IP.
	ip := r.RemoteAddr
	if limiter.check(ip) {
		logger.Warn("login rate limited", slog.String("ip", ip))
		http.Error(w, "too many failed login attempts, try again later", http.StatusTooManyRequests)
		return
	}

	// Validate credentials.
	hash, ok := users[username]
	if !ok || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		logger.Warn("login failed", slog.String("username", username))
		limiter.record(ip)

		data := loginData{
			CSRFToken:           generateCSRFToken(store),
			ClientID:            clientID,
			RedirectURI:         redirectURI,
			State:               state,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: r.FormValue("code_challenge_method"),
			Scope:               r.FormValue("scope"),
			Error:               "Invalid username or password",
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusUnauthorized)
		loginPage.Execute(w, data)
		return
	}

	logger.Info("login successful", slog.String("username", username))

	// Issue authorization code.
	code := RandomHex(32)
	store.SaveCode(&AuthCode{
		Code:          code,
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		UserID:        username,
		ExpiresAt:     time.Now().Add(codeExpiry),
	})

	// Build redirect URL with proper encoding.
	params := url.Values{}
	params.Set("code", code)
	if state != "" {
		params.Set("state", state)
	}

	redirectURL := redirectURI + "?" + params.Encode()
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
