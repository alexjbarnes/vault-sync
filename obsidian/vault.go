package obsidian

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/text/unicode/norm"
)

// Vault provides thread-safe filesystem operations on the sync directory.
// All writes are serialized by an exclusive lock. Reads take a shared lock
// to prevent reading partial writes. SyncClient, Watcher, API, and MCP
// all go through this type for file access.
type Vault struct {
	dir string
	mu  sync.RWMutex
}

// NewVault creates a Vault rooted at the given directory. The directory
// must be an absolute path (resolved at config load time).
func NewVault(dir string) *Vault {
	return &Vault{dir: dir}
}

// Dir returns the root directory of the vault.
func (v *Vault) Dir() string {
	return v.dir
}

// ReadFile reads a file by relative path. Returns the content or an error.
func (v *Vault) ReadFile(relPath string) ([]byte, error) {
	absPath, err := v.resolve(relPath)
	if err != nil {
		return nil, err
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	return os.ReadFile(absPath)
}

// WriteFile writes content to a file by relative path. Creates parent
// directories as needed. If mtime is non-zero, the file's modification
// time is set to that value after writing (matching Obsidian's behavior
// of preserving server timestamps on downloaded files).
func (v *Vault) WriteFile(relPath string, data []byte, mtime time.Time) error {
	absPath, err := v.resolve(relPath)
	if err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating directory for %s: %w", relPath, err)
	}

	if err := os.WriteFile(absPath, data, 0644); err != nil {
		return err
	}

	if !mtime.IsZero() {
		if err := os.Chtimes(absPath, mtime, mtime); err != nil {
			return fmt.Errorf("setting mtime for %s: %w", relPath, err)
		}
	}

	return nil
}

// DeleteFile removes a file by relative path. Returns nil if the file
// does not exist.
func (v *Vault) DeleteFile(relPath string) error {
	absPath, err := v.resolve(relPath)
	if err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	err = os.Remove(absPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing %s: %w", relPath, err)
	}
	return nil
}

// DeleteDir removes a directory and all its contents by relative path.
// Returns nil if the directory does not exist. Use this instead of
// DeleteFile for directories that may be non-empty.
func (v *Vault) DeleteDir(relPath string) error {
	absPath, err := v.resolve(relPath)
	if err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	err = os.RemoveAll(absPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing directory %s: %w", relPath, err)
	}
	return nil
}

// DeleteEmptyDir removes a directory only if it is empty. Returns nil
// if the directory does not exist or was successfully removed. Returns
// a non-nil error if the directory is non-empty. The Obsidian app
// refuses to delete folders that still have children (protocol doc
// lines 753 and 965).
func (v *Vault) DeleteEmptyDir(relPath string) error {
	absPath, err := v.resolve(relPath)
	if err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// os.Remove fails on non-empty directories, which is exactly
	// the behavior we want.
	err = os.Remove(absPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing directory %s: %w", relPath, err)
	}
	return nil
}

// MkdirAll creates a directory (and parents) by relative path.
func (v *Vault) MkdirAll(relPath string) error {
	absPath, err := v.resolve(relPath)
	if err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	return os.MkdirAll(absPath, 0755)
}

// Rename moves a file or directory from one relative path to another
// within the vault. Works for both empty and non-empty directories.
func (v *Vault) Rename(oldRel, newRel string) error {
	oldAbs, err := v.resolve(oldRel)
	if err != nil {
		return err
	}
	newAbs, err := v.resolve(newRel)
	if err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// Ensure parent directory of destination exists.
	if err := os.MkdirAll(filepath.Dir(newAbs), 0755); err != nil {
		return fmt.Errorf("creating directory for %s: %w", newRel, err)
	}

	return os.Rename(oldAbs, newAbs)
}

// Stat returns file info for a relative path. Takes a read lock to
// ensure the file isn't being written mid-stat.
func (v *Vault) Stat(relPath string) (os.FileInfo, error) {
	absPath, err := v.resolve(relPath)
	if err != nil {
		return nil, err
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	return os.Stat(absPath)
}

// resolve converts a relative path to an absolute path within the vault
// directory, rejecting path traversal attempts.
func (v *Vault) resolve(relPath string) (string, error) {
	if relPath == "" {
		return "", fmt.Errorf("empty path")
	}
	absPath := filepath.Join(v.dir, relPath)
	if !strings.HasPrefix(absPath, v.dir+string(os.PathSeparator)) {
		return "", fmt.Errorf("path traversal blocked: %q resolves outside vault dir", relPath)
	}
	return absPath, nil
}

// normalizePath matches Obsidian's normalizePath() function. It replaces
// non-breaking spaces with regular spaces, collapses repeated slashes,
// trims leading/trailing slashes, and applies Unicode NFC normalization.
// Call this on every path entering the system: scanner output, watcher
// events, and decrypted server paths.
func normalizePath(path string) string {
	path = strings.ReplaceAll(path, "\u00A0", " ")
	path = strings.ReplaceAll(path, "\u202F", " ")

	// Collapse multiple slashes and trim leading/trailing.
	var b strings.Builder
	prevSlash := false
	for _, r := range path {
		if r == '/' {
			if prevSlash {
				continue
			}
			prevSlash = true
		} else {
			prevSlash = false
		}
		b.WriteRune(r)
	}
	path = strings.Trim(b.String(), "/")

	return norm.NFC.String(path)
}
