package obsidian

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/text/unicode/norm"
)

const (
	// vaultDirPerm is the permission mode for directories created inside
	// the vault. Group and other get read+execute for Obsidian access.
	vaultDirPerm = fs.FileMode(0o755)

	// vaultFilePerm is the permission mode for files written inside the
	// vault. Group and other get read access for shared access.
	vaultFilePerm = fs.FileMode(0o644)
)

// mtimeMin and mtimeMax clamp server-provided modification times to a
// reasonable range, preventing a malicious server from setting far-future
// or far-past timestamps that could confuse the reconciler.
var (
	mtimeMin = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	mtimeMax = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
)

// Vault provides thread-safe filesystem operations on the sync directory.
// All writes are serialized by an exclusive lock. Reads take a shared lock
// to prevent reading partial writes. SyncClient, Watcher, API, and MCP
// all go through this type for file access.
type Vault struct {
	dir string
	mu  sync.RWMutex
}

// NewVault creates a Vault rooted at the given directory, creating it if
// it does not exist. The directory must be an absolute path (resolved at
// config load time).
func NewVault(dir string) (*Vault, error) {
	if dir == "" {
		return nil, fmt.Errorf("vault directory must not be empty")
	}

	if err := os.MkdirAll(dir, vaultDirPerm); err != nil {
		return nil, fmt.Errorf("creating vault directory %s: %w", dir, err)
	}

	return &Vault{dir: dir}, nil
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

	return os.ReadFile(absPath) //nolint:gosec // G304: absPath validated by Vault.resolve
}

// WriteFile writes content to a file by relative path. Creates parent
// directories as needed. If mtime is non-zero, the file's modification
// time is set to that value after writing to preserve server timestamps
// on downloaded files.
func (v *Vault) WriteFile(relPath string, data []byte, mtime time.Time) error {
	absPath, err := v.resolve(relPath)
	if err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, vaultDirPerm); err != nil {
		return fmt.Errorf("creating directory for %s: %w", relPath, err)
	}

	if err := os.WriteFile(absPath, data, vaultFilePerm); err != nil {
		return err
	}

	if !mtime.IsZero() {
		mtime = clampMtime(mtime)
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
// a non-nil error if the directory is non-empty. Folders that still
// have children must not be deleted.
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

	return os.MkdirAll(absPath, vaultDirPerm)
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
	if err := os.MkdirAll(filepath.Dir(newAbs), vaultDirPerm); err != nil {
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

// StatAndWriteFile atomically checks that a file has not changed since
// prePullInfo and writes new content. Both the check and write happen
// under a single write lock, closing the TOCTOU gap between separate
// Stat and WriteFile calls. If prePullInfo is nil, the write proceeds
// unconditionally. Returns an error if the file was modified between
// the pre-pull stat and now.
func (v *Vault) StatAndWriteFile(relPath string, data []byte, mtime time.Time, prePullInfo os.FileInfo) error {
	absPath, err := v.resolve(relPath)
	if err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if prePullInfo != nil {
		info, err := os.Stat(absPath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("stat %s: %w", relPath, err)
		}

		if err == nil {
			if !info.ModTime().Equal(prePullInfo.ModTime()) || info.Size() != prePullInfo.Size() {
				return fmt.Errorf("download cancelled because %s was changed locally during download", relPath)
			}
		}
		// If file was deleted (os.IsNotExist), let the write recreate it.
	}

	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, vaultDirPerm); err != nil {
		return fmt.Errorf("creating directory for %s: %w", relPath, err)
	}

	if err := os.WriteFile(absPath, data, vaultFilePerm); err != nil {
		return err
	}

	if !mtime.IsZero() {
		mtime = clampMtime(mtime)
		if err := os.Chtimes(absPath, mtime, mtime); err != nil {
			return fmt.Errorf("setting mtime for %s: %w", relPath, err)
		}
	}

	return nil
}

// resolve converts a relative path to an absolute path within the vault
// directory, rejecting path traversal attempts. Validates against null
// bytes, ".." segments, and symlinks that escape the vault.
func (v *Vault) resolve(relPath string) (string, error) {
	if relPath == "" {
		return "", fmt.Errorf("empty path")
	}

	if strings.ContainsRune(relPath, 0) {
		return "", fmt.Errorf("path contains null byte: %q", relPath)
	}

	// Normalize backslashes to forward slashes so the ".." segment check
	// below catches Windows-style traversal like "foo\..\..\etc\passwd".
	relPath = strings.ReplaceAll(relPath, "\\", "/")

	// Reject paths containing ".." segments before filepath.Join cleans
	// them, as defense in depth against traversal in decrypted server paths.
	for _, seg := range strings.Split(relPath, "/") {
		if seg == ".." {
			return "", fmt.Errorf("path contains ..: %q", relPath)
		}
	}

	absPath := filepath.Join(v.dir, relPath)
	if !strings.HasPrefix(absPath, v.dir+string(os.PathSeparator)) {
		return "", fmt.Errorf("path traversal blocked: %q resolves outside vault dir", relPath)
	}

	// Resolve symlinks and verify the real path stays within the vault.
	// This prevents a symlink at any path component from escaping the vault.
	realPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		// If the file does not exist yet (WriteFile for a new file), check
		// the parent directory instead. If the parent is a symlink pointing
		// outside, that is still a traversal.
		if os.IsNotExist(err) {
			parentReal, pErr := filepath.EvalSymlinks(filepath.Dir(absPath))
			if pErr != nil {
				// Parent doesn't exist either. MkdirAll will create it.
				// The prefix check above already passed, so we allow it.
				return absPath, nil //nolint:nilerr // intentional: parent will be created by MkdirAll
			}

			parentExpected := filepath.Dir(absPath)

			vaultPrefix := v.dir + string(os.PathSeparator)
			if !strings.HasPrefix(parentReal+string(os.PathSeparator), vaultPrefix) && parentReal != v.dir {
				// Check if parentExpected is the vault dir itself (single-level file).
				if parentExpected != v.dir {
					return "", fmt.Errorf("symlink traversal blocked: parent of %q resolves to %q outside vault", relPath, parentReal)
				}
			}

			return absPath, nil
		}

		return "", fmt.Errorf("resolving symlinks for %q: %w", relPath, err)
	}

	if !strings.HasPrefix(realPath, v.dir+string(os.PathSeparator)) && realPath != v.dir {
		return "", fmt.Errorf("symlink traversal blocked: %q resolves to %q outside vault dir", relPath, realPath)
	}

	return absPath, nil
}

// clampMtime restricts a timestamp to the range [2000, 2100) to prevent
// a malicious server from setting unreasonable modification times.
func clampMtime(t time.Time) time.Time {
	if t.Before(mtimeMin) {
		return mtimeMin
	}

	if t.After(mtimeMax) {
		return mtimeMax
	}

	return t
}

// normalizePath normalizes a vault-relative path. It converts OS-native
// path separators to forward slashes, replaces non-breaking spaces with
// regular spaces, collapses repeated slashes, trims leading/trailing
// slashes, and applies Unicode NFC normalization. Call this on every path
// entering the system: scanner output, watcher events, and decrypted
// server paths.
func normalizePath(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
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
