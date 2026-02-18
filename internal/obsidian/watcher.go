package obsidian

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/state"
	"github.com/fsnotify/fsnotify"
)

const (
	// watcherDirPerm is the permission mode for the sync directory when
	// ensuring it exists before starting the file watcher.
	watcherDirPerm = fs.FileMode(0o755)

	// watcherDebounceInterval is how often the watcher checks for pending
	// filesystem events to batch rapid writes into a single push per file.
	watcherDebounceInterval = 500 * time.Millisecond
)

type pendingEvent struct {
	absPath  string
	isDelete bool
}

// syncPusher is the subset of SyncClient that Watcher needs to push
// changes and check connection state. Extracted for testability.
type syncPusher interface {
	Connected() bool
	Push(ctx context.Context, path string, content []byte, mtime int64, ctime int64, isFolder bool, isDeleted bool) error
	ContentHash(relPath string) string
	ServerFileState(path string) *state.ServerFile
}

// Watcher monitors the sync directory for file changes and pushes them
// to the server via the SyncClient.
type Watcher struct {
	vault   *Vault
	pusher  syncPusher
	filter  *SyncFilter
	logger  *slog.Logger
	watcher *fsnotify.Watcher

	// queued holds events that occurred while disconnected. Keyed by
	// absolute path so later events for the same file overwrite earlier
	// ones (last event wins).
	queued map[string]pendingEvent
}

// NewWatcher creates a file watcher for the given vault and sync client.
// If filter is non-nil, .obsidian/ paths not allowed by the filter are
// ignored.
func NewWatcher(vault *Vault, client *SyncClient, logger *slog.Logger, filter *SyncFilter) *Watcher {
	return &Watcher{
		vault:  vault,
		pusher: client,
		filter: filter,
		logger: logger,
		queued: make(map[string]pendingEvent),
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

	if err := os.MkdirAll(syncDir, watcherDirPerm); err != nil {
		return fmt.Errorf("creating sync dir: %w", err)
	}

	if err := w.addRecursive(syncDir); err != nil {
		return fmt.Errorf("watching sync dir: %w", err)
	}

	w.logger.Info("file watcher started", slog.String("dir", syncDir))

	// Debounce: batch rapid writes into a single push per file.
	pending := make(map[string]time.Time)

	ticker := time.NewTicker(watcherDebounceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case event, ok := <-watcher.Events:
			if !ok {
				return fmt.Errorf("fsnotify events channel closed unexpectedly")
			}

			if w.shouldIgnore(event.Name) {
				continue
			}

			if event.Has(fsnotify.Create) || event.Has(fsnotify.Write) {
				pending[event.Name] = time.Now()

				// If a new directory was created, watch it recursively.
				// Use Lstat to avoid following symlinks that could point
				// outside the vault directory.
				if event.Has(fsnotify.Create) {
					info, err := os.Lstat(event.Name)
					if err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
						_ = w.addRecursive(event.Name)
					}
				}
			}

			if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
				// For rename, fsnotify fires Remove on the old path.
				// The new path fires Create separately.
				delete(pending, event.Name)
				// Remove watch for deleted directories. On Linux inotify
				// handles this automatically, but other platforms may leak.
				_ = watcher.Remove(event.Name)
				w.handleDelete(ctx, event.Name)
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return fmt.Errorf("fsnotify errors channel closed unexpectedly")
			}

			w.logger.Warn("watcher error", slog.String("error", err.Error()))

		case <-ticker.C:
			w.drainQueue(ctx)

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
	if !w.pusher.Connected() {
		w.queued[absPath] = pendingEvent{absPath: absPath, isDelete: false}
		w.logger.Debug("queued write (disconnected)", slog.String("path", absPath))

		return
	}

	relPath, err := filepath.Rel(w.vault.Dir(), absPath)
	if err != nil {
		w.logger.Warn("computing relative path", slog.String("error", err.Error()))
		return
	}

	relPath = normalizePath(relPath)

	info, err := w.vault.Stat(relPath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}

		w.logger.Warn("stat failed", slog.String("path", relPath), slog.String("error", err.Error()))

		return
	}

	if info.IsDir() {
		if err := w.pusher.Push(ctx, relPath, nil, 0, 0, true, false); err != nil {
			w.logger.Warn("push folder failed",
				slog.String("path", relPath),
				slog.String("error", err.Error()),
			)
			w.requeueIfDisconnected(absPath, false)
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
	if cached := w.pusher.ContentHash(relPath); cached == contentHash {
		return
	}

	mtime := info.ModTime().UnixMilli()
	ctime := fileCtime(info)

	// Ctime adoption: preserve the earliest known creation time.
	// If the server has an older ctime, use that instead of the local one.
	if sf := w.pusher.ServerFileState(relPath); sf != nil && sf.CTime > 0 {
		if ctime == 0 || sf.CTime < ctime {
			ctime = sf.CTime
		}
	}

	if err := w.pusher.Push(ctx, relPath, content, mtime, ctime, false, false); err != nil {
		w.logger.Warn("push file failed",
			slog.String("path", relPath),
			slog.String("error", err.Error()),
		)
		w.requeueIfDisconnected(absPath, false)
	}
}

func (w *Watcher) handleDelete(ctx context.Context, absPath string) {
	if !w.pusher.Connected() {
		w.queued[absPath] = pendingEvent{absPath: absPath, isDelete: true}
		w.logger.Debug("queued delete (disconnected)", slog.String("path", absPath))

		return
	}

	relPath, err := filepath.Rel(w.vault.Dir(), absPath)
	if err != nil {
		w.logger.Warn("computing relative path", slog.String("error", err.Error()))
		return
	}

	relPath = normalizePath(relPath)

	// Only push the delete if the server knows about this path.
	// Local-only files that were never synced have no server entry.
	sf := w.pusher.ServerFileState(relPath)
	if sf == nil {
		return
	}

	if err := w.pusher.Push(ctx, relPath, nil, 0, 0, sf.Folder, true); err != nil {
		w.logger.Warn("push delete failed",
			slog.String("path", relPath),
			slog.String("error", err.Error()),
		)
		w.requeueIfDisconnected(absPath, true)
	}
}

// requeueIfDisconnected adds a failed push back to the queue if the
// connection dropped. If still connected, the server rejected the push
// and retrying won't help.
func (w *Watcher) requeueIfDisconnected(absPath string, isDelete bool) {
	if !w.pusher.Connected() {
		w.queued[absPath] = pendingEvent{absPath: absPath, isDelete: isDelete}
		w.logger.Debug("re-queued after push failure", slog.String("path", absPath))
	}
}

// drainQueue pushes any events that were queued while disconnected. Only
// runs when the connection is back up. Re-reads files from disk since
// content may have changed since the event was queued.
func (w *Watcher) drainQueue(ctx context.Context) {
	if len(w.queued) == 0 || !w.pusher.Connected() {
		return
	}

	w.logger.Info("draining queued events", slog.Int("count", len(w.queued)))

	// Snapshot keys to avoid iterating a map that callees may modify
	// (handleWrite/handleDelete can re-queue via requeueIfDisconnected).
	type queuedItem struct {
		absPath string
		ev      pendingEvent
	}

	items := make([]queuedItem, 0, len(w.queued))
	for absPath, ev := range w.queued {
		items = append(items, queuedItem{absPath: absPath, ev: ev})
	}

	for _, item := range items {
		delete(w.queued, item.absPath)

		if item.ev.isDelete {
			w.handleDelete(ctx, item.absPath)
		} else {
			w.handleWrite(ctx, item.absPath)
		}

		// If we lost connection again while draining, stop and let the
		// remaining events stay queued for the next reconnect.
		if !w.pusher.Connected() {
			break
		}
	}
}

func (w *Watcher) addRecursive(dir string) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			return nil
		}

		if w.shouldIgnore(path) {
			return filepath.SkipDir
		}

		// Skip symlinked directories to prevent watching outside the
		// vault. WalkDir does not follow symlinks for entries it
		// discovers, but the root argument is resolved, so we check
		// each directory entry explicitly.
		if d.Type()&os.ModeSymlink != 0 {
			return filepath.SkipDir
		}

		return w.watcher.Add(path)
	})
}

func (w *Watcher) shouldIgnore(path string) bool {
	base := filepath.Base(path)
	// Ignore hidden files/dirs except .obsidian, which contains
	// workspace, plugins, and config.
	if strings.HasPrefix(base, ".") && base != ".obsidian" {
		return true
	}

	if strings.HasSuffix(base, "~") || strings.HasSuffix(base, ".swp") {
		return true
	}

	if base == "node_modules" {
		return true
	}
	// Obsidian never syncs workspace state files.
	if base == "workspace.json" || base == "workspace-mobile.json" {
		return true
	}
	// Apply config sync filter for .obsidian/ paths.
	if w.filter != nil {
		relPath, err := filepath.Rel(w.vault.Dir(), path)
		if err == nil {
			relPath = normalizePath(relPath)
			if !w.filter.AllowPath(relPath) {
				return true
			}
		}
	}

	return false
}
