package vault

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FileEntry holds metadata about a single file in the vault.
type FileEntry struct {
	Path     string    `json:"path"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	Tags     []string  `json:"tags,omitempty"`
	IsDir    bool      `json:"-"`
}

// Index maintains an in-memory cache of vault files and their metadata.
// It is safe for concurrent use.
type Index struct {
	root string

	mu      sync.RWMutex
	entries map[string]*FileEntry // path -> entry
}

// NewIndex creates a new empty index rooted at the given directory.
func NewIndex(root string) *Index {
	return &Index{
		root:    root,
		entries: make(map[string]*FileEntry),
	}
}

// Build walks the vault directory and populates the index.
// It excludes hidden files/directories and the .obsidian directory.
func (idx *Index) Build() error {
	entries := make(map[string]*FileEntry)

	err := filepath.Walk(idx.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(idx.root, path)
		if err != nil {
			return err
		}
		// Normalize to forward slashes for consistent paths.
		rel = filepath.ToSlash(rel)

		if rel == "." {
			return nil
		}

		name := info.Name()

		// Skip hidden files/directories (except .obsidian is excluded entirely).
		if strings.HasPrefix(name, ".") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip node_modules.
		if info.IsDir() && name == "node_modules" {
			return filepath.SkipDir
		}

		if info.IsDir() {
			return nil
		}

		entry := &FileEntry{
			Path:     rel,
			Size:     info.Size(),
			Modified: info.ModTime().UTC(),
		}

		// Parse frontmatter for markdown files.
		if isMarkdown(rel) {
			data, readErr := os.ReadFile(path)
			if readErr == nil {
				if fm := parseFrontmatter(data); fm != nil {
					entry.Tags = fm.Tags
				}
			}
		}

		entries[rel] = entry
		return nil
	})
	if err != nil {
		return err
	}

	idx.mu.Lock()
	idx.entries = entries
	idx.mu.Unlock()
	return nil
}

// AllFiles returns a copy of all file entries.
func (idx *Index) AllFiles() []FileEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	result := make([]FileEntry, 0, len(idx.entries))
	for _, e := range idx.entries {
		result = append(result, *e)
	}
	return result
}

// Get returns the entry for a specific path, or nil if not found.
func (idx *Index) Get(path string) *FileEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	e := idx.entries[path]
	if e == nil {
		return nil
	}
	copy := *e
	return &copy
}

// Update refreshes the index entry for a single path by re-reading
// its metadata from disk. If the file no longer exists, it is removed
// from the index.
func (idx *Index) Update(relPath string) {
	absPath := filepath.Join(idx.root, filepath.FromSlash(relPath))

	info, err := os.Stat(absPath)
	if err != nil {
		idx.mu.Lock()
		delete(idx.entries, relPath)
		idx.mu.Unlock()
		return
	}

	if info.IsDir() {
		return
	}

	entry := &FileEntry{
		Path:     relPath,
		Size:     info.Size(),
		Modified: info.ModTime().UTC(),
	}

	if isMarkdown(relPath) {
		data, readErr := os.ReadFile(absPath)
		if readErr == nil {
			if fm := parseFrontmatter(data); fm != nil {
				entry.Tags = fm.Tags
			}
		}
	}

	idx.mu.Lock()
	idx.entries[relPath] = entry
	idx.mu.Unlock()
}

// Remove deletes an entry from the index.
func (idx *Index) Remove(relPath string) {
	idx.mu.Lock()
	delete(idx.entries, relPath)
	idx.mu.Unlock()
}

func isMarkdown(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".md" || ext == ".markdown"
}
