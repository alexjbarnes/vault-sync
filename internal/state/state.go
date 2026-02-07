package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const stateFile = "state.json"

// VaultState holds the sync state for a single vault.
type VaultState struct {
	Version int64 `json:"version"`
	Initial bool  `json:"initial"`
}

// State holds all persisted state for the application.
type State struct {
	Token  string                `json:"token"`
	Vaults map[string]VaultState `json:"vaults"`

	path string
}

// Load reads state from ~/.vault-sync/state.json.
// Returns a zero-value State if the file does not exist.
func Load() (*State, error) {
	s := &State{
		Vaults: make(map[string]VaultState),
		path:   statePath(),
	}

	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading state file: %w", err)
	}

	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("parsing state file: %w", err)
	}

	if s.Vaults == nil {
		s.Vaults = make(map[string]VaultState)
	}

	return s, nil
}

// Save writes state to disk.
func (s *State) Save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return fmt.Errorf("creating state directory: %w", err)
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling state: %w", err)
	}

	if err := os.WriteFile(s.path, data, 0600); err != nil {
		return fmt.Errorf("writing state file: %w", err)
	}

	return nil
}

// GetVault returns the sync state for a vault, defaulting to initial sync.
func (s *State) GetVault(vaultID string) VaultState {
	if vs, ok := s.Vaults[vaultID]; ok {
		return vs
	}
	return VaultState{Version: 0, Initial: true}
}

// SetVault updates the sync state for a vault and saves to disk.
func (s *State) SetVault(vaultID string, vs VaultState) error {
	s.Vaults[vaultID] = vs
	return s.Save()
}

func statePath() string {
	if dir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(dir, ".vault-sync", stateFile)
	}
	return stateFile
}
