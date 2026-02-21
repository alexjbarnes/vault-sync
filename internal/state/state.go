package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/models"
	bolt "go.etcd.io/bbolt"
)

const (
	// stateDirPerm is the permission mode for the state directory (~/.vault-sync/).
	stateDirPerm = fs.FileMode(0o700)

	// stateFilePerm is the permission mode for the state database file.
	stateFilePerm = fs.FileMode(0o600)

	// stateOpenTimeout is the maximum time to wait for the bolt database lock.
	stateOpenTimeout = 5 * time.Second
)

var (
	appBucket         = []byte("app")
	tokenKey          = []byte("token")
	oauthTokensBucket = []byte("oauth_tokens")
	oauthClientBucket = []byte("oauth_clients")
	apiKeysBucket     = []byte("api_keys")
)

func vaultMetaBucket(vaultID string) []byte {
	return []byte("vault:" + vaultID + ":meta")
}

func vaultLocalBucket(vaultID string) []byte {
	return []byte("vault:" + vaultID + ":local")
}

func vaultServerBucket(vaultID string) []byte {
	return []byte("vault:" + vaultID + ":server")
}

// tokenKeyHash returns the SHA-256 hex digest of a token string.
// Used as the bbolt key so raw tokens are not stored on disk.
//
// Deprecated: new code uses OAuthToken.TokenHash directly. Kept
// for GetOAuthToken which accepts a raw token for convenience.
func tokenKeyHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	dst := make([]byte, hex.EncodedLen(len(h)))
	hex.Encode(dst, h[:])

	return dst
}

// VaultState holds the sync cursor for a single vault.
type VaultState struct {
	Version int64 `json:"version"`
	Initial bool  `json:"initial"`
}

// LocalFile tracks the last known state of a local file on disk.
// Hash is cleared (set to "") when mtime or size changes, signaling
// that the file needs re-hashing before sync.
type LocalFile struct {
	Path     string `json:"path"`
	MTime    int64  `json:"mtime"`
	CTime    int64  `json:"ctime"`
	Size     int64  `json:"size"`
	Hash     string `json:"hash"`
	SyncHash string `json:"synchash"`
	SyncTime int64  `json:"synctime"`
	Folder   bool   `json:"folder"`
}

// ServerFile tracks the last known state of a file on the server.
// Populated from server push messages and used during reconciliation
// to detect whether the local copy has diverged. When a file is deleted,
// its entry is removed from bbolt rather than stored with a flag, so
// the Deleted field no longer exists on this struct.
type ServerFile struct {
	Path   string `json:"path"`
	Hash   string `json:"hash"`
	UID    int64  `json:"uid"`
	MTime  int64  `json:"mtime"`
	CTime  int64  `json:"ctime"`
	Size   int64  `json:"size"`
	Folder bool   `json:"folder"`
	Device string `json:"device"`
}

// State wraps a bbolt database for all persistent application state.
type State struct {
	db *bolt.DB
}

// Load opens the state database at ~/.vault-sync/state.db, creating it
// if it does not exist. The app bucket is created on open.
func Load() (*State, error) {
	return LoadAt(dbPath())
}

// LoadAt opens a state database at the given path, creating it if it
// does not exist. Useful for tests that need an isolated database.
func LoadAt(path string) (*State, error) {
	if err := os.MkdirAll(filepath.Dir(path), stateDirPerm); err != nil {
		return nil, fmt.Errorf("creating state directory: %w", err)
	}

	db, err := bolt.Open(path, stateFilePerm, &bolt.Options{Timeout: stateOpenTimeout})
	if err != nil {
		return nil, fmt.Errorf("opening state db: %w", err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(appBucket); err != nil {
			return err
		}

		if _, err := tx.CreateBucketIfNotExists(oauthTokensBucket); err != nil {
			return err
		}

		if _, err := tx.CreateBucketIfNotExists(oauthClientBucket); err != nil {
			return err
		}

		_, err := tx.CreateBucketIfNotExists(apiKeysBucket)

		return err
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("initializing state db: %w", err)
	}

	return &State{db: db}, nil
}

// Close closes the database.
func (s *State) Close() error {
	return s.db.Close()
}

// Token returns the cached authentication token, or empty string.
func (s *State) Token() string {
	var token string

	_ = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(appBucket)

		v := b.Get(tokenKey)
		if v != nil {
			token = string(v)
		}

		return nil
	})

	return token
}

// SetToken persists the authentication token.
func (s *State) SetToken(token string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(appBucket).Put(tokenKey, []byte(token))
	})
}

// GetVault returns the sync cursor for a vault, defaulting to initial sync.
func (s *State) GetVault(vaultID string) (VaultState, error) {
	vs := VaultState{Version: 0, Initial: true}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(vaultMetaBucket(vaultID))
		if b == nil {
			return nil
		}

		v := b.Get([]byte("state"))
		if v == nil {
			return nil
		}

		return json.Unmarshal(v, &vs)
	})

	return vs, err
}

// SetVault updates the sync cursor for a vault.
func (s *State) SetVault(vaultID string, vs VaultState) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(vaultMetaBucket(vaultID))
		if err != nil {
			return err
		}

		data, err := json.Marshal(vs)
		if err != nil {
			return err
		}

		return b.Put([]byte("state"), data)
	})
}

// InitVaultBuckets ensures the local and server file buckets exist for
// the given vault. Call this once after selecting the vault.
func (s *State) InitVaultBuckets(vaultID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(vaultLocalBucket(vaultID)); err != nil {
			return err
		}

		_, err := tx.CreateBucketIfNotExists(vaultServerBucket(vaultID))

		return err
	})
}

// GetLocalFile returns the local file state for a path, or nil if not found.
func (s *State) GetLocalFile(vaultID, path string) (*LocalFile, error) {
	var lf *LocalFile

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(vaultLocalBucket(vaultID))
		if b == nil {
			return nil
		}

		v := b.Get([]byte(path))
		if v == nil {
			return nil
		}

		lf = &LocalFile{}

		return json.Unmarshal(v, lf)
	})

	return lf, err
}

// SetLocalFile persists the local file state for a path.
func (s *State) SetLocalFile(vaultID string, lf LocalFile) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(vaultLocalBucket(vaultID))
		if b == nil {
			return fmt.Errorf("local bucket not initialized for vault %s", vaultID)
		}

		data, err := json.Marshal(lf)
		if err != nil {
			return err
		}

		return b.Put([]byte(lf.Path), data)
	})
}

// DeleteLocalFile removes the local file state for a path.
func (s *State) DeleteLocalFile(vaultID, path string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(vaultLocalBucket(vaultID))
		if b == nil {
			return nil
		}

		return b.Delete([]byte(path))
	})
}

// AllLocalFiles returns all local file entries for a vault.
func (s *State) AllLocalFiles(vaultID string) (map[string]LocalFile, error) {
	result := make(map[string]LocalFile)
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(vaultLocalBucket(vaultID))
		if b == nil {
			return nil
		}

		return b.ForEach(func(k, v []byte) error {
			var lf LocalFile
			if err := json.Unmarshal(v, &lf); err != nil {
				return err
			}

			result[string(k)] = lf

			return nil
		})
	})

	return result, err
}

// GetServerFile returns the server file state for a path, or nil if not found.
func (s *State) GetServerFile(vaultID, path string) (*ServerFile, error) {
	var sf *ServerFile

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(vaultServerBucket(vaultID))
		if b == nil {
			return nil
		}

		v := b.Get([]byte(path))
		if v == nil {
			return nil
		}

		sf = &ServerFile{}

		return json.Unmarshal(v, sf)
	})

	return sf, err
}

// SetServerFile persists the server file state for a path.
func (s *State) SetServerFile(vaultID string, sf ServerFile) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(vaultServerBucket(vaultID))
		if b == nil {
			return fmt.Errorf("server bucket not initialized for vault %s", vaultID)
		}

		data, err := json.Marshal(sf)
		if err != nil {
			return err
		}

		return b.Put([]byte(sf.Path), data)
	})
}

// DeleteServerFile removes the server file state for a path.
func (s *State) DeleteServerFile(vaultID, path string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(vaultServerBucket(vaultID))
		if b == nil {
			return nil
		}

		return b.Delete([]byte(path))
	})
}

// AllServerFiles returns all server file entries for a vault.
func (s *State) AllServerFiles(vaultID string) (map[string]ServerFile, error) {
	result := make(map[string]ServerFile)
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(vaultServerBucket(vaultID))
		if b == nil {
			return nil
		}

		return b.ForEach(func(k, v []byte) error {
			var sf ServerFile
			if err := json.Unmarshal(v, &sf); err != nil {
				return err
			}

			result[string(k)] = sf

			return nil
		})
	})

	return result, err
}

// SaveOAuthToken persists an OAuth token. The TokenHash field must
// be set by the caller. Raw secrets (Token, RefreshToken) are cleared
// before writing so they never reach disk.
func (s *State) SaveOAuthToken(t models.OAuthToken) error {
	if t.TokenHash == "" {
		return fmt.Errorf("token hash is required for persistence")
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(oauthTokensBucket)

		// Clear raw secrets before serializing to disk.
		t.Token = ""
		t.RefreshToken = ""

		data, err := json.Marshal(t)
		if err != nil {
			return err
		}

		return b.Put([]byte(t.TokenHash), data)
	})
}

// GetOAuthToken returns an OAuth token by its value, or nil if not found.
func (s *State) GetOAuthToken(token string) (*models.OAuthToken, error) {
	var t *models.OAuthToken

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(oauthTokensBucket)

		v := b.Get(tokenKeyHash(token))
		if v == nil {
			return nil
		}

		t = &models.OAuthToken{}

		return json.Unmarshal(v, t)
	})

	return t, err
}

// DeleteOAuthToken removes an OAuth token by its hash.
func (s *State) DeleteOAuthToken(tokenHash string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(oauthTokensBucket).Delete([]byte(tokenHash))
	})
}

// AllOAuthTokens returns all stored OAuth tokens.
func (s *State) AllOAuthTokens() ([]models.OAuthToken, error) {
	var tokens []models.OAuthToken

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(oauthTokensBucket)

		return b.ForEach(func(k, v []byte) error {
			var t models.OAuthToken
			if err := json.Unmarshal(v, &t); err != nil {
				return err
			}

			tokens = append(tokens, t)

			return nil
		})
	})

	return tokens, err
}

// SaveOAuthClient persists a registered OAuth client.
func (s *State) SaveOAuthClient(c models.OAuthClient) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(oauthClientBucket)

		data, err := json.Marshal(c)
		if err != nil {
			return err
		}

		return b.Put([]byte(c.ClientID), data)
	})
}

// GetOAuthClient returns a registered client by ID, or nil if not found.
func (s *State) GetOAuthClient(clientID string) (*models.OAuthClient, error) {
	var c *models.OAuthClient

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(oauthClientBucket)

		v := b.Get([]byte(clientID))
		if v == nil {
			return nil
		}

		c = &models.OAuthClient{}

		return json.Unmarshal(v, c)
	})

	return c, err
}

// DeleteOAuthClient removes a registered OAuth client by ID.
func (s *State) DeleteOAuthClient(clientID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(oauthClientBucket).Delete([]byte(clientID))
	})
}

// AllOAuthClients returns all registered OAuth clients.
func (s *State) AllOAuthClients() ([]models.OAuthClient, error) {
	var clients []models.OAuthClient

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(oauthClientBucket)

		return b.ForEach(func(k, v []byte) error {
			var c models.OAuthClient
			if err := json.Unmarshal(v, &c); err != nil {
				return err
			}

			clients = append(clients, c)

			return nil
		})
	})

	return clients, err
}

// SaveAPIKey persists an API key, keyed by its hash.
func (s *State) SaveAPIKey(keyHash string, ak models.APIKey) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(apiKeysBucket)

		data, err := json.Marshal(ak)
		if err != nil {
			return err
		}

		return b.Put([]byte(keyHash), data)
	})
}

// DeleteAPIKey removes an API key by its hash.
func (s *State) DeleteAPIKey(keyHash string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(apiKeysBucket).Delete([]byte(keyHash))
	})
}

// AllAPIKeys returns all stored API keys, keyed by hash.
func (s *State) AllAPIKeys() (map[string]models.APIKey, error) {
	result := make(map[string]models.APIKey)

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(apiKeysBucket)

		return b.ForEach(func(k, v []byte) error {
			var ak models.APIKey
			if err := json.Unmarshal(v, &ak); err != nil {
				return err
			}

			result[string(k)] = ak

			return nil
		})
	})

	return result, err
}

// OAuthClientCount returns the number of registered OAuth clients.
func (s *State) OAuthClientCount() int {
	count := 0
	_ = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(oauthClientBucket)
		count = b.Stats().KeyN

		return nil
	})

	return count
}

func dbPath() string {
	dir, err := os.UserHomeDir()
	if err != nil {
		// Fail loudly rather than silently writing to the current directory
		// where the database (containing session tokens) might end up with
		// wrong permissions or inside a source-controlled tree.
		fmt.Fprintf(os.Stderr, "fatal: cannot determine home directory: %v\n", err)
		os.Exit(1)
	}

	return filepath.Join(dir, ".vault-sync", "state.db")
}
