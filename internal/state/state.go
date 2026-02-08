package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

var (
	appBucket = []byte("app")
	tokenKey  = []byte("token")
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
	p := dbPath()
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return nil, fmt.Errorf("creating state directory: %w", err)
	}

	db, err := bolt.Open(p, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("opening state db: %w", err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(appBucket)
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
	s.db.View(func(tx *bolt.Tx) error {
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

func dbPath() string {
	if dir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(dir, ".vault-sync", "state.db")
	}
	return "state.db"
}
