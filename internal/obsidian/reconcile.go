package obsidian

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/state"
	"github.com/sergi/go-diff/diffmatchpatch"
)

const configDir = ".obsidian"

const (
	// recentlyCreatedThresholdMs is the maximum age in milliseconds for a
	// file to be considered "recently created" during merge. Files younger
	// than this threshold let the server win unconditionally when no base
	// version is available (3 minutes).
	recentlyCreatedThresholdMs = 180_000

	// diffCleanupThreshold is the minimum number of diffs before running
	// semantic and efficiency cleanup passes. Below this count the diffs
	// are simple enough that cleanup would not improve the result.
	diffCleanupThreshold = 2
)

// ReconcileDecision is the outcome of comparing local state against an
// incoming server push. The caller performs I/O based on the decision.
type ReconcileDecision int

const (
	// DecisionSkip means no disk I/O is needed. The caller should persist
	// the server push record (using push.Deleted to decide whether to
	// store or remove the entry).
	DecisionSkip ReconcileDecision = iota

	// DecisionDownload means the server version should be pulled and
	// written to disk, replacing the local file.
	DecisionDownload

	// DecisionDeleteLocal means the local file should be deleted because
	// it is clean (unchanged since last sync) and the server says deleted.
	DecisionDeleteLocal

	// DecisionKeepLocal means the local file has unpushed changes and the
	// server says deleted. Keep the local file; persist the server record
	// as deleted so the next upload cycle pushes local back up.
	DecisionKeepLocal

	// DecisionMergeMD means both sides changed a .md file. The caller
	// should attempt a three-way merge using the previous server version
	// as the common ancestor.
	DecisionMergeMD

	// DecisionMergeJSON means both sides changed a .obsidian/*.json file.
	// The caller should perform a shallow JSON key merge.
	DecisionMergeJSON

	// DecisionTypeConflict means one side has a file and the other has a
	// folder at the same path. The caller should rename the local entry
	// to a conflict copy and then apply the server version.
	DecisionTypeConflict
)

// Reconcile decides what to do with an incoming server push by comparing
// it against the local file state and previous server record. This is a
// pure decision function with no I/O. Both startup reconciliation and
// live push handling call this to get a consistent decision.
//
// Parameters:
//   - local: current local file state, or nil if the file does not exist locally
//   - prev: previous server record from bbolt, or nil if none
//   - push: the incoming server push message
//   - encLocalHash: the local file's hash encrypted with the path cipher,
//     or empty if local is nil or hash is unavailable
//   - initial: true during initial sync (first connection, version 0)
func Reconcile(local *state.LocalFile, prev *state.ServerFile, push PushMessage, encLocalHash string, initial bool) ReconcileDecision {
	// Step 0: initial sync safety net -- drop deletions.
	if initial && push.Deleted {
		return DecisionSkip
	}

	// Step 1: no local file.
	if local == nil {
		if push.Deleted {
			return DecisionSkip
		}

		return DecisionDownload
	}

	// Step 2: both are folders.
	if local.Folder && push.Folder {
		if push.Deleted {
			return DecisionDeleteLocal
		}

		return DecisionSkip
	}

	// Step 3: hashes match -- files are identical.
	if !local.Folder && !push.Folder && !push.Deleted && encLocalHash != "" {
		if encLocalHash == push.Hash {
			return DecisionSkip
		}
	}

	// Step 4: clean local check. Local hash matches previous server hash,
	// meaning the user made no changes since last sync. Server wins.
	if prev != nil && !local.Folder && !prev.Folder && encLocalHash != "" && prev.Hash != "" {
		if encLocalHash == prev.Hash {
			if push.Deleted {
				return DecisionDeleteLocal
			}

			return DecisionDownload
		}
	}

	// Step 5: type conflict (file vs folder). If the server is deleting
	// the mismatched type, just skip -- no reason to rename a local folder
	// because the server deleted a file at the same path (or vice versa).
	if local.Folder != push.Folder {
		if push.Deleted {
			return DecisionSkip
		}

		return DecisionTypeConflict
	}

	// Step 6: server deleted but local is dirty. Keep local.
	if push.Deleted {
		return DecisionKeepLocal
	}

	// Step 7: initial sync -- use mtime comparison, never merge.
	// Server wins if its mtime is strictly newer; otherwise local wins.
	if initial {
		if push.MTime > local.MTime {
			return DecisionDownload
		}

		return DecisionSkip
	}

	// Step 8: both changed, both are files. Decide merge strategy.
	path := local.Path
	ext := extractExtension(path)

	if ext == "md" {
		return DecisionMergeMD
	}

	if ext == "json" && strings.HasPrefix(path, configDir+"/") {
		return DecisionMergeJSON
	}

	// Step 9: all other file types -- server wins.
	return DecisionDownload
}

// Reconciler runs the three-phase reconciliation between local state,
// server pushes, and persisted state.
type Reconciler struct {
	vault       *Vault
	client      *SyncClient
	state       *state.State
	vaultID     string
	cipher      *CipherV0
	filter      *SyncFilter
	logger      *slog.Logger
	serverFiles map[string]state.ServerFile
}

// NewReconciler creates a reconciler with the given dependencies.
func NewReconciler(vault *Vault, client *SyncClient, appState *state.State, vaultID string, cipher *CipherV0, logger *slog.Logger, filter *SyncFilter) *Reconciler {
	return &Reconciler{
		vault:   vault,
		client:  client,
		state:   appState,
		vaultID: vaultID,
		cipher:  cipher,
		filter:  filter,
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

	if r.filter != nil && !r.filter.AllowPath(path) {
		r.logger.Debug("skipping filtered path", slog.String("path", path))
		return nil
	}

	local, hasLocal := scan.Current[path]
	prev, hasPrev := serverFiles[path]

	var localPtr *state.LocalFile
	if hasLocal {
		localPtr = &local
	}

	var prevPtr *state.ServerFile
	if hasPrev {
		prevPtr = &prev
	}

	encLocalHash := r.encryptLocalHash(localPtr)
	decision := Reconcile(localPtr, prevPtr, push, encLocalHash, r.client.initial)

	return r.executeDecision(ctx, decision, path, push, localPtr, prevPtr)
}

// encryptLocalHash returns the encrypted form of the local file's hash,
// or empty string if the local file is nil or has no hash.
func (r *Reconciler) encryptLocalHash(local *state.LocalFile) string {
	if local == nil || local.Hash == "" || local.Folder {
		return ""
	}

	enc, err := r.cipher.EncryptPath(local.Hash)
	if err != nil {
		return ""
	}

	return enc
}

// executeDecision performs the I/O action determined by Reconcile().
// Used by startup reconciliation (Phase 1). The reconciler calls
// pullDirect for downloads since the reader goroutine isn't running yet.
func (r *Reconciler) executeDecision(ctx context.Context, decision ReconcileDecision, path string, push PushMessage, local *state.LocalFile, prev *state.ServerFile) error {
	switch decision {
	case DecisionSkip:
		r.persistServerPush(path, push, push.Deleted)
		return nil

	case DecisionDownload:
		r.logger.Info("reconcile: downloading", slog.String("path", path))
		return r.downloadServerFile(ctx, path, push)

	case DecisionDeleteLocal:
		r.logger.Info("reconcile: deleting local", slog.String("path", path))

		if push.Folder {
			if err := r.vault.DeleteEmptyDir(path); err != nil {
				r.logger.Info("reconcile: folder not empty, skipping delete", slog.String("path", path))
				r.persistServerPush(path, push, true)

				return nil //nolint:nilerr // intentional: non-empty folder is not an error, skip delete
			}
		} else {
			if err := r.vault.DeleteFile(path); err != nil {
				r.logger.Warn("reconcile: delete failed", slog.String("path", path), slog.String("error", err.Error()))
			}
		}

		r.persistServerPush(path, push, true)
		r.deleteLocalState(path)

		return nil

	case DecisionKeepLocal:
		r.logger.Info("reconcile: keeping local, server deleted", slog.String("path", path))
		r.persistServerPush(path, push, true)

		return nil

	case DecisionMergeMD:
		hasPrev := prev != nil

		var prevVal state.ServerFile
		if hasPrev {
			prevVal = *prev
		}

		var localVal state.LocalFile
		if local != nil {
			localVal = *local
		}

		return r.threeWayMerge(ctx, path, push, localVal, prevVal, hasPrev)

	case DecisionMergeJSON:
		return r.jsonMerge(ctx, path, push)

	case DecisionTypeConflict:
		var localVal state.LocalFile
		if local != nil {
			localVal = *local
		}

		return r.handleTypeConflict(ctx, path, push, localVal)

	default:
		r.logger.Warn("reconcile: unknown decision", slog.String("path", path), slog.Int("decision", int(decision)))
		return nil
	}
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

		if len(baseEnc) > 0 {
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

	// No base available -- check ctime then use mtime comparison.
	// No conflict copy is created in this case.
	if baseText == "" {
		// Files created less than 3 minutes ago: server wins unconditionally.
		if local.CTime > 0 {
			age := time.Now().UnixMilli() - local.CTime
			if age < 0 {
				age = -age
			}

			if age < recentlyCreatedThresholdMs {
				r.logger.Info("reconcile: no base, recently created, server wins", slog.String("path", path))
				return r.writeServerContent(path, push, []byte(serverText))
			}
		}

		if push.MTime > local.MTime {
			r.logger.Info("reconcile: no base, server wins by mtime", slog.String("path", path))
			return r.writeServerContent(path, push, []byte(serverText))
		}

		r.logger.Info("reconcile: no base, local wins by mtime", slog.String("path", path))
		r.persistServerPush(path, push, false)

		return nil
	}

	// Full three-way merge: compute patch(base->local), apply onto server.
	dmp := diffmatchpatch.New()

	diffs := dmp.DiffMain(baseText, localText, true)
	if len(diffs) > diffCleanupThreshold {
		diffs = dmp.DiffCleanupSemantic(diffs)
		diffs = dmp.DiffCleanupEfficiency(diffs)
	}

	patches := dmp.PatchMake(baseText, diffs)
	// Obsidian discards the applied-status array and writes the result
	// regardless. We match this behavior but log a warning when patches
	// fail so users can identify potential data loss.
	merged, applied := dmp.PatchApply(patches, serverText)
	for i, ok := range applied {
		if !ok {
			r.logger.Warn("reconcile: merge patch failed to apply",
				slog.String("path", path),
				slog.Int("patch_index", i),
			)
		}
	}

	r.logger.Info("reconcile: three-way merge", slog.String("path", path))

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
		// Local is folder, server wants a file. Rename the folder to a
		// conflict copy so it works for non-empty directories too.
		cp := conflictCopyPath(path, "")
		r.logger.Info("reconcile: type conflict, renaming folder",
			slog.String("from", path),
			slog.String("to", cp),
		)

		if err := r.vault.Rename(path, cp); err != nil {
			r.logger.Warn("reconcile: failed to rename folder for type conflict",
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
	conflictPath := conflictCopyPath(base, ext)

	r.logger.Info("reconcile: type conflict, renaming local",
		slog.String("from", path),
		slog.String("to", conflictPath),
	)

	content, err := r.vault.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading local file for conflict copy: %w", err)
	}

	if err := r.vault.WriteFile(conflictPath, content, time.Time{}); err != nil {
		return fmt.Errorf("writing conflict copy %s: %w", conflictPath, err)
	}

	if err := r.vault.DeleteFile(path); err != nil {
		r.logger.Warn("reconcile: delete after conflict copy failed", slog.String("path", path), slog.String("error", err.Error()))
	}

	if push.Deleted {
		r.persistServerPush(path, push, true)
		return nil
	}

	return r.downloadServerFile(ctx, path, push)
}

// conflictCopyPath returns the conflict copy path for a file. Appends
// a counter if the base conflict path already exists on disk to avoid
// silently overwriting a previous conflict copy or a user-created file.
func conflictCopyPath(base, ext string) string {
	candidate := base + " (Conflicted copy)" + ext
	if _, err := os.Stat(candidate); os.IsNotExist(err) {
		return candidate
	}

	for i := 2; i <= 100; i++ {
		candidate = fmt.Sprintf("%s (Conflicted copy %d)%s", base, i, ext)
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
	// Fallback: use timestamp to guarantee uniqueness.
	return fmt.Sprintf("%s (Conflicted copy %d)%s", base, time.Now().UnixMilli(), ext)
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
	var mtime time.Time
	if push.MTime > 0 {
		mtime = time.UnixMilli(push.MTime)
	}

	if err := r.vault.WriteFile(path, plaintext, mtime); err != nil {
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
// deleted locally while offline. Deletes files first (deepest first),
// then folders (deepest first) in separate passes.
func (r *Reconciler) deleteRemoteFiles(ctx context.Context, scan *ScanResult, serverFiles map[string]state.ServerFile) error {
	// Collect files and folders separately.
	var filePaths, folderPaths []string

	for _, path := range scan.Deleted {
		if r.filter != nil && !r.filter.AllowPath(path) {
			continue
		}

		sf, ok := serverFiles[path]
		if !ok {
			// Not tracked on server -- clean up local state.
			r.deleteLocalState(path)
			continue
		}

		if sf.Folder {
			folderPaths = append(folderPaths, path)
		} else {
			filePaths = append(filePaths, path)
		}
	}

	// First pass: delete all files (deepest first).
	if err := r.deletePaths(ctx, filePaths, serverFiles); err != nil {
		return err
	}

	// Second pass: delete all folders (deepest first).
	if err := r.deletePaths(ctx, folderPaths, serverFiles); err != nil {
		return err
	}

	return nil
}

// deletePaths deletes the given paths in order, deepest first.
func (r *Reconciler) deletePaths(ctx context.Context, paths []string, serverFiles map[string]state.ServerFile) error {
	// Sort by path length descending (deepest first).
	sort.Slice(paths, func(i, j int) bool {
		return len(paths[i]) > len(paths[j])
	})

	for _, path := range paths {
		// Phase 1 may have re-created this file by downloading a server
		// push. Check whether the file now exists on disk before pushing
		// a delete.
		if _, err := r.vault.Stat(path); err == nil {
			r.logger.Info("reconcile: skipping delete, file re-created by phase 1", slog.String("path", path))
			continue
		}

		sf := serverFiles[path]
		r.logger.Info("reconcile: deleting remote", slog.String("path", path), slog.Bool("folder", sf.Folder))

		mtime := time.Now().UnixMilli()
		if err := r.client.Push(ctx, path, nil, mtime, 0, sf.Folder, true); err != nil {
			r.logger.Warn("reconcile: failed to push delete",
				slog.String("path", path),
				slog.String("error", err.Error()),
			)

			continue
		}

		r.deleteLocalState(path)
	}

	return nil
}

// uploadLocalChanges is Phase 3: push files that changed locally while offline.
func (r *Reconciler) uploadLocalChanges(ctx context.Context, scan *ScanResult, serverFiles map[string]state.ServerFile) error {
	// Separate folders and files. Upload folders first (shallowest first),
	// then files (smallest first).
	var (
		folders []string
		files   []string
	)

	for _, path := range scan.Changed {
		if r.filter != nil && !r.filter.AllowPath(path) {
			continue
		}

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

		var (
			mtime int64
			ctime int64
		)

		if err == nil {
			mtime = info.ModTime().UnixMilli()
			ctime = fileCtime(info)
		}

		// Ctime adoption: preserve the earliest known creation time.
		if hasSF && sf.CTime > 0 {
			if ctime == 0 || sf.CTime < ctime {
				ctime = sf.CTime
			}
		}

		r.logger.Info("reconcile: uploading file",
			slog.String("path", path),
			slog.Int("bytes", len(content)),
		)

		if err := r.client.Push(ctx, path, content, mtime, ctime, false, false); err != nil {
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

func extractExtension(path string) string {
	base := filepath.Base(path)
	if dotIdx := strings.LastIndex(base, "."); dotIdx > 0 && dotIdx < len(base)-1 {
		return strings.ToLower(base[dotIdx+1:])
	}

	return ""
}
