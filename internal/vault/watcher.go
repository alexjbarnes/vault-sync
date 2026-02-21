package vault

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
)

// Watch monitors the vault directory for filesystem changes and keeps
// the in-memory index up to date. It blocks until the context is
// cancelled. Intended to run in a background goroutine when the MCP
// server is active alongside the sync daemon.
func (v *Vault) Watch(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("creating fsnotify watcher: %w", err)
	}
	defer watcher.Close()

	if err := v.addRecursive(watcher); err != nil {
		return fmt.Errorf("adding vault to watcher: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case event, ok := <-watcher.Events:
			if !ok {
				return fmt.Errorf("fsnotify events channel closed")
			}

			v.handleEvent(watcher, event)

		case err, ok := <-watcher.Errors:
			if !ok {
				return fmt.Errorf("fsnotify errors channel closed")
			}
			// fsnotify errors are non-fatal (e.g. too many watches).
			// Log would be ideal but Vault has no logger. Silently
			// continue; the index just won't update for the affected
			// paths.
			_ = err
		}
	}
}

// handleEvent processes a single fsnotify event, updating the index.
func (v *Vault) handleEvent(watcher *fsnotify.Watcher, event fsnotify.Event) {
	if v.shouldIgnore(event.Name) {
		return
	}

	relPath, err := filepath.Rel(v.root, event.Name)
	if err != nil {
		return
	}

	relPath = filepath.ToSlash(relPath)

	if event.Has(fsnotify.Create) || event.Has(fsnotify.Write) {
		// New directory: start watching it so we catch files created
		// inside it. No index update needed for directories themselves.
		// Use Lstat to avoid following symlinks to directories outside
		// the vault.
		if event.Has(fsnotify.Create) {
			if info, err := os.Lstat(event.Name); err == nil && info.IsDir() {
				_ = watcher.Add(event.Name)
				return
			}
		}

		v.index.Update(relPath)
	}

	if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
		v.index.Remove(relPath)
		// Clean up the watch on removed directories. Harmless if
		// the path wasn't a watched directory.
		_ = watcher.Remove(event.Name)
	}
}

// addRecursive walks the vault root and adds all non-hidden directories
// to the fsnotify watcher.
func (v *Vault) addRecursive(watcher *fsnotify.Watcher) error {
	return filepath.WalkDir(v.root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			return nil
		}

		name := d.Name()
		if strings.HasPrefix(name, ".") {
			return filepath.SkipDir
		}

		if name == "node_modules" {
			return filepath.SkipDir
		}

		return watcher.Add(path)
	})
}

// shouldIgnore returns true for paths that should not be indexed.
func (v *Vault) shouldIgnore(absPath string) bool {
	rel, err := filepath.Rel(v.root, absPath)
	if err != nil {
		return true
	}

	name := filepath.Base(absPath)

	// Hidden files and directories.
	if strings.HasPrefix(name, ".") {
		return true
	}

	// Temp files from editors.
	if strings.HasSuffix(name, "~") || strings.HasSuffix(name, ".swp") {
		return true
	}

	// Vault write temp files (created by Vault.Write and Vault.Edit).
	if strings.HasPrefix(name, ".vault-write-") || strings.HasPrefix(name, ".vault-edit-") {
		return true
	}

	if name == "node_modules" {
		return true
	}

	// Protected paths (.obsidian/).
	if isProtectedPath(filepath.ToSlash(rel)) {
		return true
	}

	return false
}
