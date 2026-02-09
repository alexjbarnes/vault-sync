package auth

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// UserCredentials maps usernames to bcrypt hashes.
type UserCredentials map[string]string

const codeExpiry = 5 * time.Minute

// loginPage is a minimal HTML login form.
var loginPage = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html>
<head><title>Vault Sync - Login</title></head>
<body>
<h2>Vault Sync Login</h2>
{{if .Error}}<p style="color:red">{{.Error}}</p>{{end}}
<form method="POST">
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
	ClientID            string
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	Error               string
}

// HandleAuthorize returns the /oauth/authorize handler.
func HandleAuthorize(store *Store, users UserCredentials, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleAuthorizeGET(w, r, store)
		case http.MethodPost:
			handleAuthorizePOST(w, r, store, users, logger)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
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

	data := loginData{
		ClientID:            clientID,
		RedirectURI:         q.Get("redirect_uri"),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Scope:               q.Get("scope"),
	}

	w.Header().Set("Content-Type", "text/html")
	loginPage.Execute(w, data)
}

func handleAuthorizePOST(w http.ResponseWriter, r *http.Request, store *Store, users UserCredentials, logger *slog.Logger) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}

	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	codeChallenge := r.FormValue("code_challenge")
	username := r.FormValue("username")
	password := r.FormValue("password")

	client := store.GetClient(clientID)
	if client == nil {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}

	// Validate credentials.
	hash, ok := users[username]
	if !ok || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		logger.Warn("login failed", slog.String("username", username))

		data := loginData{
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

	// Redirect back to the client.
	redirectURL := fmt.Sprintf("%s?code=%s", redirectURI, code)
	if state != "" {
		redirectURL += "&state=" + state
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}
