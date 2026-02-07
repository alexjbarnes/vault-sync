package obsidian

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watcher monitors the sync directory for file changes and pushes them
// to the server via the SyncClient.
type Watcher struct {
	vault   *Vault
	client  *SyncClient
	logger  *slog.Logger
	watcher *fsnotify.Watcher
}

// NewWatcher creates a file watcher for the given vault and sync client.
func NewWatcher(vault *Vault, client *SyncClient, logger *slog.Logger) *Watcher {
	return &Watcher{
		vault:  vault,
		client: client,
		logger: logger,
	}
}

// Watch starts watching the sync directory for changes. It blocks until
// the context is cancelled. Directories are watched recursively.
func (w *Watcher) Watch(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("creating watcher: %w", err)
	}
	w.watcher = watcher
	defer watcher.Close()

	syncDir := w.vault.Dir()

	if err := os.MkdirAll(syncDir, 0755); err != nil {
		return fmt.Errorf("creating sync dir: %w", err)
	}

	if err := w.addRecursive(syncDir); err != nil {
		return fmt.Errorf("watching sync dir: %w", err)
	}

	w.logger.Info("file watcher started", slog.String("dir", syncDir))

	// Debounce: batch rapid writes into a single push per file.
	pending := make(map[string]time.Time)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if w.shouldIgnore(event.Name) {
				continue
			}

			if event.Has(fsnotify.Create) || event.Has(fsnotify.Write) {
				pending[event.Name] = time.Now()

				// If a new directory was created, watch it recursively.
				if event.Has(fsnotify.Create) {
					info, err := os.Stat(event.Name)
					if err == nil && info.IsDir() {
						w.addRecursive(event.Name)
					}
				}
			}

			if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
				// For rename, fsnotify fires Remove on the old path.
				// The new path fires Create separately.
				delete(pending, event.Name)
				w.handleDelete(ctx, event.Name)
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			w.logger.Warn("watcher error", slog.String("error", err.Error()))

		case <-ticker.C:
			now := time.Now()
			for path, t := range pending {
				if now.Sub(t) < 300*time.Millisecond {
					continue
				}
				delete(pending, path)
				w.handleWrite(ctx, path)
			}
		}
	}
}

func (w *Watcher) handleWrite(ctx context.Context, absPath string) {
	relPath, err := filepath.Rel(w.vault.Dir(), absPath)
	if err != nil {
		w.logger.Warn("computing relative path", slog.String("error", err.Error()))
		return
	}

	info, err := w.vault.Stat(relPath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		w.logger.Warn("stat failed", slog.String("path", relPath), slog.String("error", err.Error()))
		return
	}

	if info.IsDir() {
		if err := w.client.Push(ctx, relPath, nil, 0, 0, true, false); err != nil {
			w.logger.Warn("push folder failed",
				slog.String("path", relPath),
				slog.String("error", err.Error()),
			)
		}
		return
	}

	content, err := w.vault.ReadFile(relPath)
	if err != nil {
		w.logger.Warn("reading file", slog.String("path", relPath), slog.String("error", err.Error()))
		return
	}

	// Compare against hash cache to avoid pushing content we just received.
	h := sha256.Sum256(content)
	contentHash := hex.EncodeToString(h[:])
	if cached := w.client.ContentHash(relPath); cached == contentHash {
		return
	}

	mtime := info.ModTime().UnixMilli()
	if err := w.client.Push(ctx, relPath, content, mtime, 0, false, false); err != nil {
		w.logger.Warn("push file failed",
			slog.String("path", relPath),
			slog.String("error", err.Error()),
		)
	}
}

func (w *Watcher) handleDelete(ctx context.Context, absPath string) {
	relPath, err := filepath.Rel(w.vault.Dir(), absPath)
	if err != nil {
		w.logger.Warn("computing relative path", slog.String("error", err.Error()))
		return
	}

	if err := w.client.Push(ctx, relPath, nil, 0, 0, false, true); err != nil {
		w.logger.Warn("push delete failed",
			slog.String("path", relPath),
			slog.String("error", err.Error()),
		)
	}
}

func (w *Watcher) addRecursive(dir string) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if w.shouldIgnore(path) {
				return filepath.SkipDir
			}
			return w.watcher.Add(path)
		}
		return nil
	})
}

func (w *Watcher) shouldIgnore(path string) bool {
	base := filepath.Base(path)
	// Ignore hidden files and common editor temp files.
	if strings.HasPrefix(base, ".") {
		return true
	}
	if strings.HasSuffix(base, "~") || strings.HasSuffix(base, ".swp") {
		return true
	}
	return false
}
