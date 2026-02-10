package obsidian

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/alexjbarnes/vault-sync/internal/state"
)

// ScanResult holds the outcome of scanning the local vault directory
// against persisted local file state.
type ScanResult struct {
	// Current maps all files/folders currently on disk by relative path.
	Current map[string]state.LocalFile
	// Changed contains paths where the local file was modified offline
	// (mtime or size differs from persisted state, or file is new).
	Changed []string
	// Deleted contains paths that were in persisted state but are no
	// longer on disk (locally deleted while offline).
	Deleted []string
}

// ScanLocal walks the vault directory and compares each file against the
// persisted localFiles from bbolt. Files whose mtime or size changed get
// their hash cleared (needs recomputation). New files get a fresh entry.
// Files that existed in persisted state but are gone from disk are returned
// in Deleted.
func ScanLocal(vault *Vault, appState *state.State, vaultID string, logger *slog.Logger) (*ScanResult, error) {
	persisted, err := appState.AllLocalFiles(vaultID)
	if err != nil {
		return nil, fmt.Errorf("loading persisted local files: %w", err)
	}

	result := &ScanResult{
		Current: make(map[string]state.LocalFile),
	}

	seen := make(map[string]bool)
	dir := vault.Dir()

	err = filepath.WalkDir(dir, func(absPath string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(dir, absPath)
		if err != nil {
			return err
		}

		// Skip the root directory itself.
		if relPath == "." {
			return nil
		}

		relPath = normalizePath(relPath)

		// Skip hidden files/dirs at any level (like .git), but NOT .obsidian
		// which is part of the vault config that gets synced.
		base := filepath.Base(absPath)
		if strings.HasPrefix(base, ".") && base != ".obsidian" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if base == "node_modules" && d.IsDir() {
			return filepath.SkipDir
		}
		// Obsidian never syncs workspace state files.
		if base == "workspace.json" || base == "workspace-mobile.json" {
			return nil
		}

		// Skip symlinks to prevent following links to files outside the
		// vault or to special files (devices, FIFOs) that could hang or
		// produce unexpected data.
		if d.Type()&os.ModeSymlink != 0 {
			logger.Debug("skipping symlink during scan", slog.String("path", relPath))
			return nil
		}

		seen[relPath] = true

		info, err := d.Info()
		if err != nil {
			logger.Warn("stat failed during scan", slog.String("path", relPath), slog.String("error", err.Error()))
			return nil
		}

		if d.IsDir() {
			lf := state.LocalFile{
				Path:   relPath,
				Folder: true,
				MTime:  info.ModTime().UnixMilli(),
			}
			result.Current[relPath] = lf

			prev, exists := persisted[relPath]
			if !exists {
				result.Changed = append(result.Changed, relPath)
			} else if !prev.Folder {
				// Was a file, now a folder -- treat as changed.
				result.Changed = append(result.Changed, relPath)
			}
			return nil
		}

		mtime := info.ModTime().UnixMilli()
		size := info.Size()

		prev, exists := persisted[relPath]
		ctime := fileCtime(info)

		if !exists {
			// New file not in persisted state. Hash it now.
			hash, hashErr := hashFile(vault, relPath)
			if hashErr != nil {
				logger.Warn("hashing new file", slog.String("path", relPath), slog.String("error", hashErr.Error()))
				hash = ""
			}
			lf := state.LocalFile{
				Path:  relPath,
				MTime: mtime,
				CTime: ctime,
				Size:  size,
				Hash:  hash,
			}
			result.Current[relPath] = lf
			result.Changed = append(result.Changed, relPath)
			return nil
		}

		// File exists in persisted state. Check if it changed.
		if prev.MTime != mtime || prev.Size != size {
			// Changed offline. Rehash.
			hash, hashErr := hashFile(vault, relPath)
			if hashErr != nil {
				logger.Warn("hashing changed file", slog.String("path", relPath), slog.String("error", hashErr.Error()))
				hash = ""
			}
			lf := state.LocalFile{
				Path:     relPath,
				MTime:    mtime,
				CTime:    ctime,
				Size:     size,
				Hash:     hash,
				SyncHash: prev.SyncHash,
				SyncTime: prev.SyncTime,
			}
			result.Current[relPath] = lf
			// Only mark as changed if the content actually differs.
			if hash == "" || hash != prev.Hash {
				result.Changed = append(result.Changed, relPath)
			}
			return nil
		}

		// Unchanged. Carry forward persisted state.
		result.Current[relPath] = prev
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking vault directory: %w", err)
	}

	// Find files in persisted state that are no longer on disk.
	for path := range persisted {
		if !seen[path] {
			result.Deleted = append(result.Deleted, path)
		}
	}

	logger.Info("local scan complete",
		slog.Int("on_disk", len(seen)),
		slog.Int("changed", len(result.Changed)),
		slog.Int("deleted", len(result.Deleted)),
	)

	return result, nil
}

func hashFile(vault *Vault, relPath string) (string, error) {
	content, err := vault.ReadFile(relPath)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:]), nil
}
