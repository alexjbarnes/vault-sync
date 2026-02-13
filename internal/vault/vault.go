// Package vault provides filesystem operations for reading, writing,
// listing, searching, and editing files in an Obsidian vault directory.
// It has no dependency on MCP or HTTP.
package vault

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Error codes returned by vault operations.
const (
	ErrCodeFileNotFound   = "FILE_NOT_FOUND"
	ErrCodePathNotAllowed = "PATH_NOT_ALLOWED"
	ErrCodeIsDirectory    = "IS_DIRECTORY"
	ErrCodeTextNotFound   = "TEXT_NOT_FOUND"
	ErrCodeTextNotUnique  = "TEXT_NOT_UNIQUE"
	ErrCodeInvalidRange   = "INVALID_RANGE"
)

// Error is a structured error returned by vault operations.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return e.Message
}

// Vault provides operations on a local Obsidian vault directory.
type Vault struct {
	root  string
	index *Index
}

// New creates a new Vault rooted at the given directory.
// It builds the initial file index.
func New(root string) (*Vault, error) {
	if root == "" {
		return nil, fmt.Errorf("vault path must not be empty")
	}

	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolving vault path: %w", err)
	}

	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("accessing vault path: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("vault path is not a directory: %s", abs)
	}

	v := &Vault{
		root:  abs,
		index: NewIndex(abs),
	}

	if err := v.index.Build(); err != nil {
		return nil, fmt.Errorf("building vault index: %w", err)
	}

	return v, nil
}

// Root returns the absolute path to the vault root.
func (v *Vault) Root() string {
	return v.root
}

// resolve converts a vault-relative path to an absolute path, validating
// that it stays within the vault root. It evaluates symlinks to prevent
// symlink-based escape from the vault directory.
func (v *Vault) resolve(relPath string) (string, error) {
	if err := validatePath(relPath); err != nil {
		return "", err
	}
	abs := filepath.Join(v.root, filepath.FromSlash(relPath))
	// Ensure the joined path is within the vault root before touching disk.
	if !strings.HasPrefix(abs, v.root+string(filepath.Separator)) && abs != v.root {
		return "", &Error{
			Code:    ErrCodePathNotAllowed,
			Message: fmt.Sprintf("path escapes vault root: %s", relPath),
		}
	}
	// Evaluate symlinks to catch symlink-based escape. We resolve the
	// longest existing prefix so this works for paths where the final
	// component doesn't exist yet (e.g. Write creating a new file).
	real, err := evalExistingPrefix(abs)
	if err != nil {
		return "", fmt.Errorf("evaluating path: %w", err)
	}
	if !strings.HasPrefix(real, v.root+string(filepath.Separator)) && real != v.root {
		return "", &Error{
			Code:    ErrCodePathNotAllowed,
			Message: fmt.Sprintf("path escapes vault root via symlink: %s", relPath),
		}
	}
	return abs, nil
}

// evalExistingPrefix resolves symlinks for the longest existing prefix of
// the path. For a path like /vault/newdir/newfile.md where newdir doesn't
// exist, it evaluates /vault (which does exist) and appends the remaining
// components. This lets us detect symlink escape even for not-yet-created
// paths.
func evalExistingPrefix(abs string) (string, error) {
	real, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return real, nil
	}
	// Walk up until we find an existing directory, then append the rest.
	dir := filepath.Dir(abs)
	base := filepath.Base(abs)
	if dir == abs {
		// Reached filesystem root without finding anything.
		return abs, nil
	}
	parentReal, err := evalExistingPrefix(dir)
	if err != nil {
		return "", err
	}
	return filepath.Join(parentReal, base), nil
}

// validatePath checks for path traversal attempts.
func validatePath(relPath string) error {
	if strings.Contains(relPath, "..") {
		return &Error{
			Code:    ErrCodePathNotAllowed,
			Message: "path must not contain '..'",
		}
	}
	return nil
}

// isProtectedPath returns true if the path is in a protected directory
// that should not be read from or written to via the MCP interface.
func isProtectedPath(relPath string) bool {
	normalized := filepath.ToSlash(relPath)
	return strings.HasPrefix(normalized, ".obsidian/") || normalized == ".obsidian"
}

// ListAllResult is the response for listing all files.
type ListAllResult struct {
	TotalFiles int         `json:"total_files"`
	Files      []FileEntry `json:"files"`
}

// ListAll returns metadata for every file in the vault.
func (v *Vault) ListAll() *ListAllResult {
	files := v.index.AllFiles()
	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})
	return &ListAllResult{
		TotalFiles: len(files),
		Files:      files,
	}
}

// DirEntry is a single entry in a directory listing.
type DirEntry struct {
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	Size     int64     `json:"size,omitempty"`
	Modified time.Time `json:"modified,omitempty"`
	Children int       `json:"children,omitempty"`
}

// ListResult is the response for listing a directory.
type ListResult struct {
	Path         string     `json:"path"`
	Entries      []DirEntry `json:"entries"`
	TotalEntries int        `json:"total_entries"`
}

// List returns the contents of a specific directory, one level deep.
func (v *Vault) List(dirPath string) (*ListResult, error) {
	if dirPath == "" || dirPath == "/" {
		dirPath = ""
	}

	if dirPath != "" && isProtectedPath(dirPath) {
		return nil, &Error{
			Code:    ErrCodePathNotAllowed,
			Message: fmt.Sprintf("listing .obsidian/ is not allowed: %s", dirPath),
		}
	}

	absDir, err := v.resolve(dirPath)
	if err != nil && dirPath != "" {
		return nil, err
	}
	if dirPath == "" {
		absDir = v.root
	}

	info, err := os.Stat(absDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &Error{
				Code:    ErrCodeFileNotFound,
				Message: fmt.Sprintf("directory not found: %s", dirPath),
			}
		}
		return nil, fmt.Errorf("reading directory: %w", err)
	}
	if !info.IsDir() {
		return nil, &Error{
			Code:    ErrCodeFileNotFound,
			Message: fmt.Sprintf("not a directory: %s", dirPath),
		}
	}

	dirEntries, err := os.ReadDir(absDir)
	if err != nil {
		return nil, fmt.Errorf("reading directory: %w", err)
	}

	var entries []DirEntry
	for _, de := range dirEntries {
		name := de.Name()

		// Skip hidden files/directories.
		if strings.HasPrefix(name, ".") {
			continue
		}

		if de.IsDir() {
			children := countChildren(filepath.Join(absDir, name))
			entries = append(entries, DirEntry{
				Name:     name,
				Type:     "folder",
				Children: children,
			})
		} else {
			fi, err := de.Info()
			if err != nil {
				continue
			}
			entries = append(entries, DirEntry{
				Name:     name,
				Type:     "file",
				Size:     fi.Size(),
				Modified: fi.ModTime().UTC(),
			})
		}
	}

	displayPath := "/" + dirPath
	if dirPath == "" {
		displayPath = "/"
	}

	return &ListResult{
		Path:         displayPath,
		Entries:      entries,
		TotalEntries: len(entries),
	}, nil
}

// countChildren returns the number of immediate non-hidden children.
func countChildren(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			count++
		}
	}
	return count
}

// ReadResult is the response for reading a file.
type ReadResult struct {
	Path       string `json:"path"`
	TotalLines int    `json:"total_lines"`
	Showing    [2]int `json:"showing"`
	Content    string `json:"content"`
	Truncated  bool   `json:"truncated,omitempty"`
}

// DefaultReadLimit is the maximum number of lines returned when no limit is specified.
const DefaultReadLimit = 200

// Read reads a file with optional line-range pagination.
// offset is 1-indexed. limit of 0 means all remaining lines.
func (v *Vault) Read(relPath string, offset, limit int) (*ReadResult, error) {
	if isProtectedPath(relPath) {
		return nil, &Error{
			Code:    ErrCodePathNotAllowed,
			Message: fmt.Sprintf("reading from .obsidian/ is not allowed: %s", relPath),
		}
	}

	abs, err := v.resolve(relPath)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &Error{
				Code:    ErrCodeFileNotFound,
				Message: fmt.Sprintf("file not found: %s", relPath),
			}
		}
		return nil, fmt.Errorf("reading file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	totalLines := len(lines)

	if offset <= 0 {
		offset = 1
	}
	if offset > totalLines {
		return nil, &Error{
			Code:    ErrCodeInvalidRange,
			Message: fmt.Sprintf("offset %d exceeds file length of %d lines", offset, totalLines),
		}
	}

	startIdx := offset - 1 // convert 1-indexed to 0-indexed

	truncated := false
	endIdx := totalLines
	if limit > 0 {
		endIdx = startIdx + limit
		if endIdx > totalLines {
			endIdx = totalLines
		}
	} else if totalLines > DefaultReadLimit && offset == 1 {
		// Auto-truncate large files when reading from the beginning with no explicit limit.
		endIdx = DefaultReadLimit
		truncated = true
	}

	selected := lines[startIdx:endIdx]

	return &ReadResult{
		Path:       relPath,
		TotalLines: totalLines,
		Showing:    [2]int{offset, startIdx + len(selected)},
		Content:    strings.Join(selected, "\n"),
		Truncated:  truncated,
	}, nil
}

// WriteResult is the response for writing a file.
type WriteResult struct {
	Path       string `json:"path"`
	Created    bool   `json:"created"`
	Size       int64  `json:"size"`
	TotalLines int    `json:"total_lines"`
}

// Write creates or replaces a file. It uses atomic write (temp file + rename).
func (v *Vault) Write(relPath string, content string, createDirs bool) (*WriteResult, error) {
	if err := validatePath(relPath); err != nil {
		return nil, err
	}

	if isProtectedPath(relPath) {
		return nil, &Error{
			Code:    ErrCodePathNotAllowed,
			Message: fmt.Sprintf("writing to .obsidian/ is not allowed: %s", relPath),
		}
	}

	abs, err := v.resolve(relPath)
	if err != nil {
		return nil, err
	}

	// Check if the file already exists.
	_, statErr := os.Stat(abs)
	created := os.IsNotExist(statErr)

	// Create parent directories if requested.
	dir := filepath.Dir(abs)
	if createDirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("creating directories: %w", err)
		}
	} else {
		if _, err := os.Stat(dir); err != nil {
			return nil, &Error{
				Code:    ErrCodeFileNotFound,
				Message: fmt.Sprintf("parent directory does not exist: %s", filepath.Dir(relPath)),
			}
		}
	}

	// Atomic write: write to temp file, then rename.
	tmp, err := os.CreateTemp(dir, ".vault-write-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return nil, fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return nil, fmt.Errorf("closing temp file: %w", err)
	}

	// Preserve permissions of existing file, or use default.
	perm := fs.FileMode(0644)
	if !created {
		if info, err := os.Stat(abs); err == nil {
			perm = info.Mode()
		}
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		os.Remove(tmpName)
		return nil, fmt.Errorf("setting file permissions: %w", err)
	}

	if err := os.Rename(tmpName, abs); err != nil {
		os.Remove(tmpName)
		return nil, fmt.Errorf("renaming temp file: %w", err)
	}

	// Update index.
	v.index.Update(relPath)

	totalLines := strings.Count(content, "\n") + 1

	return &WriteResult{
		Path:       relPath,
		Created:    created,
		Size:       int64(len(content)),
		TotalLines: totalLines,
	}, nil
}

// EditResult is the response for editing a file.
type EditResult struct {
	Path       string `json:"path"`
	Replaced   bool   `json:"replaced"`
	TotalLines int    `json:"total_lines"`
}

// Edit performs a find-and-replace on an existing file. The old_text must
// appear exactly once.
func (v *Vault) Edit(relPath string, oldText string, newText string) (*EditResult, error) {
	abs, err := v.resolve(relPath)
	if err != nil {
		return nil, err
	}

	if isProtectedPath(relPath) {
		return nil, &Error{
			Code:    ErrCodePathNotAllowed,
			Message: fmt.Sprintf("editing .obsidian/ is not allowed: %s", relPath),
		}
	}

	data, err := os.ReadFile(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &Error{
				Code:    ErrCodeFileNotFound,
				Message: fmt.Sprintf("file not found: %s", relPath),
			}
		}
		return nil, fmt.Errorf("reading file: %w", err)
	}

	content := string(data)
	count := strings.Count(content, oldText)

	if count == 0 {
		return nil, &Error{
			Code:    ErrCodeTextNotFound,
			Message: "text not found in file",
		}
	}
	if count > 1 {
		return nil, &Error{
			Code:    ErrCodeTextNotUnique,
			Message: fmt.Sprintf("text appears %d times in file, must be unique", count),
		}
	}

	updated := strings.Replace(content, oldText, newText, 1)

	// Atomic write.
	dir := filepath.Dir(abs)
	tmp, err := os.CreateTemp(dir, ".vault-edit-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.WriteString(updated); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return nil, fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return nil, fmt.Errorf("closing temp file: %w", err)
	}

	// Preserve original permissions.
	if info, err := os.Stat(abs); err == nil {
		_ = os.Chmod(tmpName, info.Mode())
	}

	if err := os.Rename(tmpName, abs); err != nil {
		os.Remove(tmpName)
		return nil, fmt.Errorf("renaming temp file: %w", err)
	}

	// Update index.
	v.index.Update(relPath)

	totalLines := strings.Count(updated, "\n") + 1

	return &EditResult{
		Path:       relPath,
		Replaced:   true,
		TotalLines: totalLines,
	}, nil
}

// DeleteResult is the response for deleting a file.
type DeleteResult struct {
	Path    string `json:"path"`
	Deleted bool   `json:"deleted"`
}

// Delete removes a single file from the vault. It refuses to delete
// directories; only files can be deleted through this method.
func (v *Vault) Delete(relPath string) (*DeleteResult, error) {
	if err := validatePath(relPath); err != nil {
		return nil, err
	}

	if isProtectedPath(relPath) {
		return nil, &Error{
			Code:    ErrCodePathNotAllowed,
			Message: fmt.Sprintf("deleting from .obsidian/ is not allowed: %s", relPath),
		}
	}

	abs, err := v.resolve(relPath)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &Error{
				Code:    ErrCodeFileNotFound,
				Message: fmt.Sprintf("file not found: %s", relPath),
			}
		}
		return nil, fmt.Errorf("checking file: %w", err)
	}

	if info.IsDir() {
		return nil, &Error{
			Code:    ErrCodeIsDirectory,
			Message: fmt.Sprintf("cannot delete directory: %s (delete individual files within it instead)", relPath),
		}
	}

	if err := os.Remove(abs); err != nil {
		return nil, fmt.Errorf("deleting file: %w", err)
	}

	v.index.Remove(relPath)

	return &DeleteResult{
		Path:    relPath,
		Deleted: true,
	}, nil
}

// DeleteBatchItem is the result for a single file in a batch delete.
type DeleteBatchItem struct {
	Path    string `json:"path"`
	Deleted bool   `json:"deleted"`
	Error   string `json:"error,omitempty"`
}

// DeleteBatchResult is the response for deleting multiple files.
type DeleteBatchResult struct {
	Deleted int               `json:"deleted"`
	Failed  int               `json:"failed"`
	Total   int               `json:"total"`
	Results []DeleteBatchItem `json:"results"`
}

// DeleteBatch removes multiple files from the vault. It uses best-effort
// semantics: each file is attempted independently and failures are reported
// per-item rather than aborting the whole batch.
func (v *Vault) DeleteBatch(paths []string) *DeleteBatchResult {
	result := &DeleteBatchResult{
		Total:   len(paths),
		Results: make([]DeleteBatchItem, 0, len(paths)),
	}

	for _, relPath := range paths {
		_, err := v.Delete(relPath)
		if err != nil {
			result.Failed++
			result.Results = append(result.Results, DeleteBatchItem{
				Path:  relPath,
				Error: err.Error(),
			})
			continue
		}
		result.Deleted++
		result.Results = append(result.Results, DeleteBatchItem{
			Path:    relPath,
			Deleted: true,
		})
	}

	return result
}

// MoveResult is the response for moving/renaming a file.
type MoveResult struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Moved       bool   `json:"moved"`
}

// Move renames a file within the vault. It creates parent directories for the
// destination if they do not exist. Both source and destination must be files
// (not directories) and must not be in .obsidian/.
func (v *Vault) Move(srcPath, dstPath string) (*MoveResult, error) {
	if err := validatePath(srcPath); err != nil {
		return nil, err
	}
	if err := validatePath(dstPath); err != nil {
		return nil, err
	}

	if isProtectedPath(srcPath) {
		return nil, &Error{
			Code:    ErrCodePathNotAllowed,
			Message: fmt.Sprintf("moving from .obsidian/ is not allowed: %s", srcPath),
		}
	}
	if isProtectedPath(dstPath) {
		return nil, &Error{
			Code:    ErrCodePathNotAllowed,
			Message: fmt.Sprintf("moving to .obsidian/ is not allowed: %s", dstPath),
		}
	}

	absSrc, err := v.resolve(srcPath)
	if err != nil {
		return nil, err
	}
	absDst, err := v.resolve(dstPath)
	if err != nil {
		return nil, err
	}

	srcInfo, err := os.Stat(absSrc)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &Error{
				Code:    ErrCodeFileNotFound,
				Message: fmt.Sprintf("source file not found: %s", srcPath),
			}
		}
		return nil, fmt.Errorf("checking source: %w", err)
	}
	if srcInfo.IsDir() {
		return nil, &Error{
			Code:    ErrCodeIsDirectory,
			Message: fmt.Sprintf("cannot move directory: %s", srcPath),
		}
	}

	// Refuse to overwrite an existing file.
	if _, err := os.Stat(absDst); err == nil {
		return nil, &Error{
			Code:    ErrCodePathNotAllowed,
			Message: fmt.Sprintf("destination already exists: %s", dstPath),
		}
	}

	// Create parent directories for destination.
	if err := os.MkdirAll(filepath.Dir(absDst), 0755); err != nil {
		return nil, fmt.Errorf("creating destination directories: %w", err)
	}

	if err := os.Rename(absSrc, absDst); err != nil {
		return nil, fmt.Errorf("moving file: %w", err)
	}

	v.index.Remove(srcPath)
	v.index.Update(dstPath)

	return &MoveResult{
		Source:      srcPath,
		Destination: dstPath,
		Moved:       true,
	}, nil
}

// CopyResult is the response for copying a file.
type CopyResult struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Copied      bool   `json:"copied"`
	Size        int64  `json:"size"`
}

// Copy duplicates a file within the vault. It creates parent directories for
// the destination if they do not exist. Both source and destination must be
// files (not directories) and must not be in .obsidian/.
func (v *Vault) Copy(srcPath, dstPath string) (*CopyResult, error) {
	if err := validatePath(srcPath); err != nil {
		return nil, err
	}
	if err := validatePath(dstPath); err != nil {
		return nil, err
	}

	if isProtectedPath(srcPath) {
		return nil, &Error{
			Code:    ErrCodePathNotAllowed,
			Message: fmt.Sprintf("copying from .obsidian/ is not allowed: %s", srcPath),
		}
	}
	if isProtectedPath(dstPath) {
		return nil, &Error{
			Code:    ErrCodePathNotAllowed,
			Message: fmt.Sprintf("copying to .obsidian/ is not allowed: %s", dstPath),
		}
	}

	absSrc, err := v.resolve(srcPath)
	if err != nil {
		return nil, err
	}
	absDst, err := v.resolve(dstPath)
	if err != nil {
		return nil, err
	}

	srcInfo, err := os.Stat(absSrc)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &Error{
				Code:    ErrCodeFileNotFound,
				Message: fmt.Sprintf("source file not found: %s", srcPath),
			}
		}
		return nil, fmt.Errorf("checking source: %w", err)
	}
	if srcInfo.IsDir() {
		return nil, &Error{
			Code:    ErrCodeIsDirectory,
			Message: fmt.Sprintf("cannot copy directory: %s", srcPath),
		}
	}

	// Refuse to overwrite an existing file.
	if _, err := os.Stat(absDst); err == nil {
		return nil, &Error{
			Code:    ErrCodePathNotAllowed,
			Message: fmt.Sprintf("destination already exists: %s", dstPath),
		}
	}

	data, err := os.ReadFile(absSrc)
	if err != nil {
		return nil, fmt.Errorf("reading source file: %w", err)
	}

	// Create parent directories for destination.
	dstDir := filepath.Dir(absDst)
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return nil, fmt.Errorf("creating destination directories: %w", err)
	}

	// Atomic write: temp file + rename.
	tmp, err := os.CreateTemp(dstDir, ".vault-copy-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return nil, fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return nil, fmt.Errorf("closing temp file: %w", err)
	}

	if err := os.Chmod(tmpName, srcInfo.Mode()); err != nil {
		os.Remove(tmpName)
		return nil, fmt.Errorf("setting file permissions: %w", err)
	}

	if err := os.Rename(tmpName, absDst); err != nil {
		os.Remove(tmpName)
		return nil, fmt.Errorf("renaming temp file: %w", err)
	}

	v.index.Update(dstPath)

	return &CopyResult{
		Source:      srcPath,
		Destination: dstPath,
		Copied:      true,
		Size:        int64(len(data)),
	}, nil
}
