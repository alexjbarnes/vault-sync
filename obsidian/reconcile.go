package obsidian

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/state"
	"github.com/sergi/go-diff/diffmatchpatch"
)

const configDir = ".obsidian"

// Reconciler runs the three-phase reconciliation between local state,
// server pushes, and persisted state. It mirrors the logic in Obsidian's
// app.js _sync function.
type Reconciler struct {
	vault       *Vault
	client      *SyncClient
	state       *state.State
	vaultID     string
	cipher      *CipherV0
	logger      *slog.Logger
	serverFiles map[string]state.ServerFile
}

// NewReconciler creates a reconciler with the given dependencies.
func NewReconciler(vault *Vault, client *SyncClient, appState *state.State, vaultID string, cipher *CipherV0, logger *slog.Logger) *Reconciler {
	return &Reconciler{
		vault:   vault,
		client:  client,
		state:   appState,
		vaultID: vaultID,
		cipher:  cipher,
		logger:  logger,
	}
}

// Run executes the full reconciliation sequence:
//  1. Process new server files (download, merge, or skip)
//  2. Delete remote files that were deleted locally
//  3. Upload local files that changed offline
//
// serverPushes are the queued pushes from the initial pull (before "ready").
// scan is the result of walking the local vault directory.
//
// Phase1 must be called BEFORE the read loop starts (it calls pull directly).
// Phase2And3 must be called AFTER the read loop starts (it calls Push which
// requires the read loop to deliver acks via responseCh).
func (r *Reconciler) Phase1(ctx context.Context, serverPushes []ServerPush, scan *ScanResult) error {
	serverFiles, err := r.state.AllServerFiles(r.vaultID)
	if err != nil {
		return fmt.Errorf("loading server files: %w", err)
	}

	r.logger.Info("reconciliation phase 1 starting",
		slog.Int("server_pushes", len(serverPushes)),
		slog.Int("local_changed", len(scan.Changed)),
		slog.Int("local_deleted", len(scan.Deleted)),
		slog.Int("persisted_server", len(serverFiles)),
	)

	if err := r.processServerPushes(ctx, serverPushes, scan, serverFiles); err != nil {
		return fmt.Errorf("phase 1 (server pushes): %w", err)
	}

	// Store serverFiles for phases 2 and 3.
	r.serverFiles = serverFiles

	r.logger.Info("reconciliation phase 1 complete")
	return nil
}

// Phase2And3 runs after the read loop starts. It deletes remote files
// that were deleted locally and uploads local changes.
func (r *Reconciler) Phase2And3(ctx context.Context, scan *ScanResult) error {
	r.logger.Info("reconciliation phases 2-3 starting")

	// Reload server files to include any updates from phase 1.
	serverFiles, err := r.state.AllServerFiles(r.vaultID)
	if err != nil {
		return fmt.Errorf("loading server files: %w", err)
	}

	if err := r.deleteRemoteFiles(ctx, scan, serverFiles); err != nil {
		return fmt.Errorf("phase 2 (remote deletes): %w", err)
	}

	if err := r.uploadLocalChanges(ctx, scan, serverFiles); err != nil {
		return fmt.Errorf("phase 3 (local uploads): %w", err)
	}

	r.logger.Info("reconciliation complete")
	return nil
}

// processServerPushes is Phase 1: handle each queued server push.
func (r *Reconciler) processServerPushes(ctx context.Context, pushes []ServerPush, scan *ScanResult, serverFiles map[string]state.ServerFile) error {
	var failures int
	for _, sp := range pushes {
		if err := r.processOneServerPush(ctx, sp, scan, serverFiles); err != nil {
			failures++
			r.logger.Warn("reconcile server push",
				slog.String("path", sp.Path),
				slog.String("error", err.Error()),
			)
		}
	}
	if failures > 0 {
		return fmt.Errorf("%d of %d server pushes failed to reconcile", failures, len(pushes))
	}
	return nil
}

func (r *Reconciler) processOneServerPush(ctx context.Context, sp ServerPush, scan *ScanResult, serverFiles map[string]state.ServerFile) error {
	path := sp.Path
	push := sp.Msg
	local, hasLocal := scan.Current[path]
	prev, hasPrev := serverFiles[path]

	// No local file exists.
	if !hasLocal {
		if push.Deleted {
			// Deleted on server, not present locally -- nothing to do.
			r.persistServerPush(path, push, true)
			return nil
		}
		// Download from server.
		return r.downloadServerFile(ctx, path, push)
	}

	// Both are folders.
	if local.Folder && push.Folder {
		if push.Deleted {
			// Server wants to delete folder. Accept only if empty on disk.
			// For simplicity, always accept and let the OS refuse if non-empty.
			r.vault.DeleteFile(path)
			r.persistServerPush(path, push, true)
			r.deleteLocalState(path)
			return nil
		}
		// Both folder, not deleted -- no-op.
		r.persistServerPush(path, push, false)
		return nil
	}

	// Hashes match -- file is identical, accept.
	if !local.Folder && !push.Folder && !push.Deleted && local.Hash != "" {
		encLocalHash, err := r.cipher.EncryptPath(local.Hash)
		if err == nil && encLocalHash == push.Hash {
			r.persistServerPush(path, push, false)
			return nil
		}
	}

	// "Clean local" check: local hash matches previous server hash.
	// This means the user made no local changes -- server wins.
	if hasPrev && !local.Folder && !prev.Folder && local.Hash != "" && prev.Hash != "" {
		encLocalHash, err := r.cipher.EncryptPath(local.Hash)
		if err == nil && encLocalHash == prev.Hash {
			if push.Deleted {
				r.logger.Info("reconcile: deleting clean local file", slog.String("path", path))
				r.vault.DeleteFile(path)
				r.persistServerPush(path, push, true)
				r.deleteLocalState(path)
				return nil
			}
			r.logger.Info("reconcile: downloading over clean local", slog.String("path", path))
			return r.downloadServerFile(ctx, path, push)
		}
	}

	// Type conflict: local is file, server is folder (or vice versa).
	if local.Folder != push.Folder {
		return r.handleTypeConflict(ctx, path, push, local)
	}

	// Both changed. Server is deleted -- keep local (local wins).
	if push.Deleted {
		r.logger.Info("reconcile: keeping local, server deleted", slog.String("path", path))
		r.persistServerPush(path, push, true)
		return nil
	}

	// Both changed, both are files. Try to merge.
	ext := strings.ToLower(filepath.Ext(path))

	// Three-way merge for .md files.
	if ext == ".md" {
		return r.threeWayMerge(ctx, path, push, local, prev, hasPrev)
	}

	// JSON shallow merge for .obsidian/ config files.
	if ext == ".json" && strings.HasPrefix(path, configDir+"/") {
		return r.jsonMerge(ctx, path, push)
	}

	// All other files: server wins.
	r.logger.Info("reconcile: server wins (non-mergeable)", slog.String("path", path))
	return r.downloadServerFile(ctx, path, push)
}

// threeWayMerge performs a diff-match-patch merge for .md files.
// base = previous server version (from prev.UID)
// local = current file on disk
// server = new server version (from push.UID)
// Result: patch(base->local) applied onto server.
func (r *Reconciler) threeWayMerge(ctx context.Context, path string, push PushMessage, local state.LocalFile, prev state.ServerFile, hasPrev bool) error {
	// Check if server hash matches our last upload hash. If so, the "new"
	// server version is what we pushed and no merge is needed.
	if local.SyncHash != "" {
		encSyncHash, err := r.cipher.EncryptPath(local.SyncHash)
		if err == nil && encSyncHash == push.Hash {
			r.logger.Debug("reconcile: server matches last push, skip merge", slog.String("path", path))
			r.persistServerPush(path, push, false)
			return nil
		}
	}

	// Read local content.
	localContent, err := r.vault.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading local file for merge: %w", err)
	}
	localText := string(localContent)

	// Get base version (previous server state).
	baseText := ""
	if hasPrev && prev.UID > 0 {
		baseEnc, err := r.client.pullDirect(ctx, prev.UID)
		if err != nil {
			r.logger.Warn("reconcile: failed to pull base for merge, server wins",
				slog.String("path", path),
				slog.String("error", err.Error()),
			)
			return r.downloadServerFile(ctx, path, push)
		}
		if baseEnc != nil && len(baseEnc) > 0 {
			basePlain, err := r.cipher.DecryptContent(baseEnc)
			if err != nil {
				r.logger.Warn("reconcile: failed to decrypt base, server wins",
					slog.String("path", path),
					slog.String("error", err.Error()),
				)
				return r.downloadServerFile(ctx, path, push)
			}
			baseText = string(basePlain)
		}
	}

	// Get new server version.
	serverEnc, err := r.client.pullDirect(ctx, push.UID)
	if err != nil {
		return fmt.Errorf("pulling server version for merge: %w", err)
	}
	if serverEnc == nil {
		// Server returned deleted content during merge -- keep local.
		r.persistServerPush(path, push, true)
		return nil
	}

	var serverText string
	if len(serverEnc) > 0 {
		serverPlain, err := r.cipher.DecryptContent(serverEnc)
		if err != nil {
			return fmt.Errorf("decrypting server version for merge: %w", err)
		}
		serverText = string(serverPlain)
	}

	// Trivial cases.
	if baseText == serverText || localText == serverText {
		r.persistServerPush(path, push, false)
		return nil
	}
	if serverText == "" {
		// Empty server version -- keep local.
		r.persistServerPush(path, push, false)
		return nil
	}

	// No base available -- server wins, but save local as conflict copy
	// so the user can recover their changes. Without a base we cannot
	// merge, and silently discarding local edits is data loss.
	if baseText == "" {
		r.logger.Warn("reconcile: no base for merge, saving conflict copy", slog.String("path", path))
		conflictExt := filepath.Ext(path)
		conflictBase := strings.TrimSuffix(path, conflictExt)
		conflictPath := r.uniqueConflictPath(conflictBase, conflictExt)
		if err := r.vault.WriteFile(conflictPath, localContent); err != nil {
			r.logger.Warn("reconcile: failed to write conflict copy",
				slog.String("path", conflictPath),
				slog.String("error", err.Error()),
			)
		}
		return r.writeServerContent(path, push, []byte(serverText))
	}

	// Full three-way merge: compute patch(base->local), apply onto server.
	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(baseText, localText, true)
	if len(diffs) > 2 {
		diffs = dmp.DiffCleanupSemantic(diffs)
		diffs = dmp.DiffCleanupEfficiency(diffs)
	}
	patches := dmp.PatchMake(baseText, diffs)
	merged, applied := dmp.PatchApply(patches, serverText)

	allApplied := true
	for _, ok := range applied {
		if !ok {
			allApplied = false
			break
		}
	}

	if !allApplied {
		// Some local edits could not be applied to the server version.
		// Save local content as a conflict copy so the user can recover
		// their changes manually.
		r.logger.Warn("reconcile: three-way merge had failed patches, saving conflict copy",
			slog.String("path", path),
		)
		conflictExt := filepath.Ext(path)
		conflictBase := strings.TrimSuffix(path, conflictExt)
		conflictPath := r.uniqueConflictPath(conflictBase, conflictExt)
		if err := r.vault.WriteFile(conflictPath, localContent); err != nil {
			r.logger.Warn("reconcile: failed to write merge conflict copy",
				slog.String("path", conflictPath),
				slog.String("error", err.Error()),
			)
		}
	}

	r.logger.Info("reconcile: three-way merge", slog.String("path", path), slog.Bool("clean", allApplied))
	return r.writeServerContent(path, push, []byte(merged))
}

// jsonMerge performs a shallow JSON key merge for .obsidian/ config files.
// Server keys overwrite local keys. Local-only keys are preserved.
func (r *Reconciler) jsonMerge(ctx context.Context, path string, push PushMessage) error {
	// Read local JSON.
	localContent, err := r.vault.ReadFile(path)
	if err != nil {
		// Can't read local -- just download server version.
		return r.downloadServerFile(ctx, path, push)
	}

	var localObj map[string]json.RawMessage
	if err := json.Unmarshal(localContent, &localObj); err != nil {
		// Not a JSON object -- server wins.
		return r.downloadServerFile(ctx, path, push)
	}

	// Pull server content.
	serverEnc, err := r.client.pullDirect(ctx, push.UID)
	if err != nil {
		return fmt.Errorf("pulling server config for merge: %w", err)
	}
	if serverEnc == nil {
		r.persistServerPush(path, push, true)
		return nil
	}

	var serverPlain []byte
	if len(serverEnc) > 0 {
		serverPlain, err = r.cipher.DecryptContent(serverEnc)
		if err != nil {
			return fmt.Errorf("decrypting server config: %w", err)
		}
	}

	var serverObj map[string]json.RawMessage
	if err := json.Unmarshal(serverPlain, &serverObj); err != nil {
		// Server content not a JSON object -- server wins with raw content.
		return r.writeServerContent(path, push, serverPlain)
	}

	// Shallow merge: server keys overwrite local.
	for k, v := range serverObj {
		localObj[k] = v
	}

	merged, err := json.MarshalIndent(localObj, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling merged config: %w", err)
	}

	r.logger.Info("reconcile: JSON merge", slog.String("path", path))
	return r.writeServerContent(path, push, merged)
}

// handleTypeConflict handles the case where one side has a file and the
// other has a folder at the same path. The local file is renamed to a
// conflict copy, then the server version is applied.
func (r *Reconciler) handleTypeConflict(ctx context.Context, path string, push PushMessage, local state.LocalFile) error {
	if local.Folder {
		// Local is folder, server wants a file. Remove the folder first
		// so WriteFile can create a file at that path.
		r.logger.Info("reconcile: type conflict, removing folder for file", slog.String("path", path))
		if err := r.vault.DeleteFile(path); err != nil {
			r.logger.Warn("reconcile: failed to remove folder for type conflict",
				slog.String("path", path),
				slog.String("error", err.Error()),
			)
		}
		return r.downloadServerFile(ctx, path, push)
	}

	// Local is file, server wants a folder. Save local content to a
	// conflict copy before removing the original. If the conflict copy
	// cannot be written, abort to avoid data loss.
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	conflictPath := r.uniqueConflictPath(base, ext)

	r.logger.Info("reconcile: type conflict, renaming local",
		slog.String("from", path),
		slog.String("to", conflictPath),
	)

	content, err := r.vault.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading local file for conflict copy: %w", err)
	}
	if err := r.vault.WriteFile(conflictPath, content); err != nil {
		return fmt.Errorf("writing conflict copy %s: %w", conflictPath, err)
	}
	r.vault.DeleteFile(path)

	if push.Deleted {
		r.persistServerPush(path, push, true)
		return nil
	}

	return r.downloadServerFile(ctx, path, push)
}

// uniqueConflictPath returns a conflict copy path that does not already
// exist on disk. Appends " (1)", " (2)", etc. if needed.
func (r *Reconciler) uniqueConflictPath(base, ext string) string {
	candidate := base + " (Conflicted copy)" + ext
	if _, err := r.vault.Stat(candidate); err != nil {
		return candidate
	}
	for i := 1; i < 100; i++ {
		candidate = fmt.Sprintf("%s (Conflicted copy %d)%s", base, i, ext)
		if _, err := r.vault.Stat(candidate); err != nil {
			return candidate
		}
	}
	return candidate
}

// downloadServerFile pulls content from the server, decrypts it, and
// writes it to disk. Persists both server and local state.
func (r *Reconciler) downloadServerFile(ctx context.Context, path string, push PushMessage) error {
	if push.Folder {
		if err := r.vault.MkdirAll(path); err != nil {
			return fmt.Errorf("creating folder %s: %w", path, err)
		}
		r.persistServerPush(path, push, false)
		r.client.persistLocalFolder(path)
		return nil
	}

	content, err := r.client.pullDirect(ctx, push.UID)
	if err != nil {
		return fmt.Errorf("pulling %s (uid %d): %w", path, push.UID, err)
	}
	if content == nil {
		r.persistServerPush(path, push, true)
		r.deleteLocalState(path)
		return nil
	}

	var plaintext []byte
	if len(content) > 0 {
		plaintext, err = r.cipher.DecryptContent(content)
		if err != nil {
			return fmt.Errorf("decrypting %s: %w", path, err)
		}
	}

	return r.writeServerContent(path, push, plaintext)
}

// writeServerContent writes plaintext to disk and persists state.
func (r *Reconciler) writeServerContent(path string, push PushMessage, plaintext []byte) error {
	if err := r.vault.WriteFile(path, plaintext); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}

	h := sha256.Sum256(plaintext)
	contentHash := hex.EncodeToString(h[:])

	r.persistServerPush(path, push, false)
	r.client.persistLocalFileAfterWrite(path, contentHash)

	// Update hash cache so the watcher doesn't re-push this file.
	r.client.hashCacheMu.Lock()
	r.client.hashCache[path] = hashEntry{
		encHash:     push.Hash,
		contentHash: contentHash,
	}
	r.client.hashCacheMu.Unlock()

	r.logger.Info("reconcile: wrote",
		slog.String("path", path),
		slog.Int("bytes", len(plaintext)),
	)
	return nil
}

// persistServerPush saves the server file state from a queued push message.
func (r *Reconciler) persistServerPush(path string, push PushMessage, deleted bool) {
	r.client.persistServerFile(path, push, deleted)
}

// deleteLocalState removes the local file tracking entry from bbolt.
func (r *Reconciler) deleteLocalState(path string) {
	r.client.deleteLocalState(path)
}

// deleteRemoteFiles is Phase 2: push deletions for files that were
// deleted locally while offline.
func (r *Reconciler) deleteRemoteFiles(ctx context.Context, scan *ScanResult, serverFiles map[string]state.ServerFile) error {
	// Process deepest paths first (children before parents) by sorting
	// by path length descending. Simple approach: find the longest first.
	remaining := make(map[string]bool)
	for _, path := range scan.Deleted {
		_, ok := serverFiles[path]
		if !ok {
			// Not tracked on server -- clean up local state.
			r.deleteLocalState(path)
			continue
		}
		remaining[path] = true
	}

	for len(remaining) > 0 {
		// Find the deepest path (longest string).
		var deepest string
		for path := range remaining {
			if len(path) > len(deepest) {
				deepest = path
			}
		}
		delete(remaining, deepest)

		sf := serverFiles[deepest]
		r.logger.Info("reconcile: deleting remote", slog.String("path", deepest), slog.Bool("folder", sf.Folder))

		mtime := time.Now().UnixMilli()
		if err := r.client.Push(ctx, deepest, nil, mtime, 0, sf.Folder, true); err != nil {
			r.logger.Warn("reconcile: failed to push delete",
				slog.String("path", deepest),
				slog.String("error", err.Error()),
			)
			continue
		}
		r.deleteLocalState(deepest)
	}

	return nil
}

// uploadLocalChanges is Phase 3: push files that changed locally while offline.
func (r *Reconciler) uploadLocalChanges(ctx context.Context, scan *ScanResult, serverFiles map[string]state.ServerFile) error {
	// Separate folders and files. Upload folders first (shallowest first),
	// then files (smallest first, matching Obsidian app behavior).
	var folders []string
	var files []string

	for _, path := range scan.Changed {
		lf, ok := scan.Current[path]
		if !ok {
			continue
		}
		if lf.Folder {
			folders = append(folders, path)
		} else {
			files = append(files, path)
		}
	}

	// Upload folders, shallowest (shortest path) first.
	sortByLengthAsc(folders)
	for _, path := range folders {
		sf, hasSF := serverFiles[path]
		if hasSF && sf.Folder {
			// Already exists as folder on server -- skip.
			continue
		}
		r.logger.Info("reconcile: uploading folder", slog.String("path", path))
		if err := r.client.Push(ctx, path, nil, 0, 0, true, false); err != nil {
			r.logger.Warn("reconcile: failed to push folder",
				slog.String("path", path),
				slog.String("error", err.Error()),
			)
		}
	}

	// Upload files, smallest first.
	sortByFileSize(files, scan.Current)
	for _, path := range files {
		lf := scan.Current[path]
		sf, hasSF := serverFiles[path]

		// Skip if server already has the same content.
		if hasSF && !sf.Folder && lf.Hash != "" {
			encHash, err := r.cipher.EncryptPath(lf.Hash)
			if err == nil && encHash == sf.Hash {
				continue
			}
		}

		content, err := r.vault.ReadFile(path)
		if err != nil {
			r.logger.Warn("reconcile: reading file for upload",
				slog.String("path", path),
				slog.String("error", err.Error()),
			)
			continue
		}

		// Recompute hash to be sure.
		h := sha256.Sum256(content)
		contentHash := hex.EncodeToString(h[:])
		if hasSF && !sf.Folder && sf.Hash != "" {
			encHash, err := r.cipher.EncryptPath(contentHash)
			if err == nil && encHash == sf.Hash {
				continue
			}
		}

		info, err := r.vault.Stat(path)
		var mtime int64
		if err == nil {
			mtime = info.ModTime().UnixMilli()
		}

		r.logger.Info("reconcile: uploading file",
			slog.String("path", path),
			slog.Int("bytes", len(content)),
		)

		if err := r.client.Push(ctx, path, content, mtime, 0, false, false); err != nil {
			r.logger.Warn("reconcile: failed to push file",
				slog.String("path", path),
				slog.String("error", err.Error()),
			)
		}
	}

	return nil
}

// sortByLengthAsc sorts paths by string length, shortest first.
func sortByLengthAsc(paths []string) {
	for i := 1; i < len(paths); i++ {
		for j := i; j > 0 && len(paths[j]) < len(paths[j-1]); j-- {
			paths[j], paths[j-1] = paths[j-1], paths[j]
		}
	}
}

// sortByFileSize sorts paths by the file size in scan.Current, smallest first.
func sortByFileSize(paths []string, current map[string]state.LocalFile) {
	for i := 1; i < len(paths); i++ {
		for j := i; j > 0 && current[paths[j]].Size < current[paths[j-1]].Size; j-- {
			paths[j], paths[j-1] = paths[j-1], paths[j]
		}
	}
}
