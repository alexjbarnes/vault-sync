package obsidian

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testState creates an isolated bbolt state database in a temp dir and
// initializes the vault buckets for the given vault ID.
func testState(t *testing.T, vaultID string) *state.State {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := state.LoadAt(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })
	require.NoError(t, s.InitVaultBuckets(vaultID))
	return s
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

var (
	testVaultID   = "test-vault-001"
	discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))
)

// --- File filtering ---

func TestScanLocal_SkipsDotGit(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	require.NoError(t, os.MkdirAll(filepath.Join(v.Dir(), ".git", "objects"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(v.Dir(), ".git", "HEAD"), []byte("ref: refs/heads/main"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(v.Dir(), "notes.md"), []byte("hello"), 0o644))

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	_, hasGitHead := result.Current[".git/HEAD"]
	assert.False(t, hasGitHead, ".git/HEAD should be excluded")
	_, hasGitDir := result.Current[".git"]
	assert.False(t, hasGitDir, ".git dir should be excluded")
	_, hasNotes := result.Current["notes.md"]
	assert.True(t, hasNotes, "notes.md should be included")
}

func TestScanLocal_IncludesObsidianDir(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	require.NoError(t, os.MkdirAll(filepath.Join(v.Dir(), ".obsidian", "plugins"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(v.Dir(), ".obsidian", "app.json"), []byte(`{}`), 0o644))

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	_, hasDir := result.Current[".obsidian"]
	assert.True(t, hasDir, ".obsidian directory should be included")
	_, hasAppJSON := result.Current[".obsidian/app.json"]
	assert.True(t, hasAppJSON, ".obsidian/app.json should be included")
}

func TestScanLocal_SkipsDotFiles(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	require.NoError(t, os.WriteFile(filepath.Join(v.Dir(), ".hidden"), []byte("secret"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(v.Dir(), ".DS_Store"), []byte("junk"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(v.Dir(), "visible.md"), []byte("ok"), 0o644))

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	_, hasHidden := result.Current[".hidden"]
	assert.False(t, hasHidden, ".hidden should be excluded")
	_, hasDSStore := result.Current[".DS_Store"]
	assert.False(t, hasDSStore, ".DS_Store should be excluded")
	_, hasVisible := result.Current["visible.md"]
	assert.True(t, hasVisible)
}

func TestScanLocal_SkipsNodeModules(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	require.NoError(t, os.MkdirAll(filepath.Join(v.Dir(), "node_modules", "pkg"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(v.Dir(), "node_modules", "pkg", "index.js"), []byte("module"), 0o644))

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	for path := range result.Current {
		assert.NotContains(t, path, "node_modules", "node_modules contents should be excluded")
	}
}

func TestScanLocal_SkipsWorkspaceJSON(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	require.NoError(t, os.WriteFile(filepath.Join(v.Dir(), "workspace.json"), []byte(`{}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(v.Dir(), "workspace-mobile.json"), []byte(`{}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(v.Dir(), "other.json"), []byte(`{}`), 0o644))

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	_, hasWorkspace := result.Current["workspace.json"]
	assert.False(t, hasWorkspace, "workspace.json should be excluded")
	_, hasMobile := result.Current["workspace-mobile.json"]
	assert.False(t, hasMobile, "workspace-mobile.json should be excluded")
	_, hasOther := result.Current["other.json"]
	assert.True(t, hasOther, "other.json should be included")
}

func TestScanLocal_SkipsNestedDotDirs(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	// A dotdir nested inside a regular directory should be skipped.
	require.NoError(t, os.MkdirAll(filepath.Join(v.Dir(), "notes", ".secret"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(v.Dir(), "notes", ".secret", "file.txt"), []byte("hidden"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(v.Dir(), "notes", "visible.md"), []byte("ok"), 0o644))

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	_, hasSecret := result.Current["notes/.secret/file.txt"]
	assert.False(t, hasSecret)
	_, hasVisible := result.Current["notes/visible.md"]
	assert.True(t, hasVisible)
}

// --- Change detection ---

func TestScanLocal_NewFileIsChanged(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	content := []byte("new file content")
	require.NoError(t, os.WriteFile(filepath.Join(v.Dir(), "new.md"), content, 0o644))

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	assert.Contains(t, result.Changed, "new.md")
	lf := result.Current["new.md"]
	assert.Equal(t, "new.md", lf.Path)
	assert.Equal(t, int64(len(content)), lf.Size)
	assert.Equal(t, sha256Hex(content), lf.Hash)
	assert.False(t, lf.Folder)
}

func TestScanLocal_NewFolderIsChanged(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	require.NoError(t, os.MkdirAll(filepath.Join(v.Dir(), "notes", "sub"), 0o755))

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	assert.Contains(t, result.Changed, "notes")
	assert.Contains(t, result.Changed, "notes/sub")
	lf := result.Current["notes"]
	assert.True(t, lf.Folder)
}

func TestScanLocal_ModifiedFileIsChanged(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	originalContent := []byte("original")
	filePath := filepath.Join(v.Dir(), "doc.md")
	require.NoError(t, os.WriteFile(filePath, originalContent, 0o644))

	// Persist initial state so the scanner has something to compare against.
	info, _ := os.Stat(filePath)
	require.NoError(t, s.SetLocalFile(testVaultID, state.LocalFile{
		Path:  "doc.md",
		MTime: info.ModTime().UnixMilli(),
		Size:  info.Size(),
		Hash:  sha256Hex(originalContent),
	}))

	// Modify the file. Use a different mtime to trigger change detection.
	newContent := []byte("modified content that is different")
	require.NoError(t, os.WriteFile(filePath, newContent, 0o644))
	// Ensure mtime differs (filesystem resolution can be 1s on some FS).
	future := time.Now().Add(2 * time.Second)
	require.NoError(t, os.Chtimes(filePath, future, future))

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	assert.Contains(t, result.Changed, "doc.md")
	lf := result.Current["doc.md"]
	assert.Equal(t, sha256Hex(newContent), lf.Hash)
	assert.Equal(t, int64(len(newContent)), lf.Size)
}

func TestScanLocal_UnchangedFileCarriedForward(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	content := []byte("stable content")
	filePath := filepath.Join(v.Dir(), "stable.md")
	require.NoError(t, os.WriteFile(filePath, content, 0o644))

	info, _ := os.Stat(filePath)
	persisted := state.LocalFile{
		Path:     "stable.md",
		MTime:    info.ModTime().UnixMilli(),
		Size:     info.Size(),
		Hash:     sha256Hex(content),
		SyncHash: "sync-abc",
		SyncTime: 12345,
	}
	require.NoError(t, s.SetLocalFile(testVaultID, persisted))

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	assert.NotContains(t, result.Changed, "stable.md")
	lf := result.Current["stable.md"]
	assert.Equal(t, persisted.Hash, lf.Hash)
	assert.Equal(t, persisted.SyncHash, lf.SyncHash)
	assert.Equal(t, persisted.SyncTime, lf.SyncTime)
}

func TestScanLocal_SameHashAfterMtimeChangeNotChanged(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	content := []byte("same content")
	filePath := filepath.Join(v.Dir(), "touched.md")
	require.NoError(t, os.WriteFile(filePath, content, 0o644))

	info, _ := os.Stat(filePath)
	require.NoError(t, s.SetLocalFile(testVaultID, state.LocalFile{
		Path:  "touched.md",
		MTime: info.ModTime().UnixMilli() - 1000, // Old mtime triggers rehash.
		Size:  info.Size(),
		Hash:  sha256Hex(content), // But hash matches.
	}))

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	// mtime changed but content hash is the same, so not marked changed.
	assert.NotContains(t, result.Changed, "touched.md")
}

// --- Delete detection ---

func TestScanLocal_DeletedFileInDeletedList(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	// Persist a file that no longer exists on disk.
	require.NoError(t, s.SetLocalFile(testVaultID, state.LocalFile{
		Path:  "gone.md",
		MTime: 1000,
		Size:  42,
		Hash:  "deadbeef",
	}))

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	assert.Contains(t, result.Deleted, "gone.md")
	_, inCurrent := result.Current["gone.md"]
	assert.False(t, inCurrent, "deleted file should not be in Current")
}

func TestScanLocal_DeletedFolderInDeletedList(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	require.NoError(t, s.SetLocalFile(testVaultID, state.LocalFile{
		Path:   "old-folder",
		Folder: true,
	}))

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	assert.Contains(t, result.Deleted, "old-folder")
}

func TestScanLocal_MultipleDeletedFiles(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	for _, path := range []string{"a.md", "b.md", "c/d.md"} {
		require.NoError(t, s.SetLocalFile(testVaultID, state.LocalFile{
			Path: path,
			Size: 1,
		}))
	}

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	sort.Strings(result.Deleted)
	assert.Equal(t, []string{"a.md", "b.md", "c/d.md"}, result.Deleted)
}

// --- Path normalization at scan boundary ---

func TestScanLocal_NFDPathNormalizedToNFC(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	// Create file with NFD e-acute (e + combining acute U+0301).
	nfdName := "caf\u0065\u0301.md" // e + combining acute
	nfcName := "caf\u00e9.md"       // precomposed e-acute
	require.NoError(t, os.WriteFile(filepath.Join(v.Dir(), nfdName), []byte("coffee"), 0o644))

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	// The scanner normalizes to NFC.
	_, hasNFC := result.Current[nfcName]
	assert.True(t, hasNFC, "scanner should normalize NFD path to NFC: %v", keysOf(result.Current))
}

// --- Directories tracked ---

func TestScanLocal_DirectoriesInCurrent(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	require.NoError(t, os.MkdirAll(filepath.Join(v.Dir(), "a", "b"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(v.Dir(), "a", "b", "file.md"), []byte("leaf"), 0o644))

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	lfA := result.Current["a"]
	assert.True(t, lfA.Folder)
	lfB := result.Current["a/b"]
	assert.True(t, lfB.Folder)
	lfFile := result.Current["a/b/file.md"]
	assert.False(t, lfFile.Folder)
}

func TestScanLocal_FolderBecameFile(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	// Persisted state says "thing" was a folder.
	require.NoError(t, s.SetLocalFile(testVaultID, state.LocalFile{
		Path:   "thing",
		Folder: true,
	}))

	// On disk "thing" is now a file.
	require.NoError(t, os.WriteFile(filepath.Join(v.Dir(), "thing"), []byte("file now"), 0o644))

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	// Should be marked as changed since it went from folder to file.
	assert.Contains(t, result.Changed, "thing")
}

// --- Modified file preserves SyncHash/SyncTime ---

func TestScanLocal_ModifiedFilePreservesSyncFields(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	filePath := filepath.Join(v.Dir(), "synced.md")
	require.NoError(t, os.WriteFile(filePath, []byte("v1"), 0o644))
	info, _ := os.Stat(filePath)

	require.NoError(t, s.SetLocalFile(testVaultID, state.LocalFile{
		Path:     "synced.md",
		MTime:    info.ModTime().UnixMilli(),
		Size:     info.Size(),
		Hash:     sha256Hex([]byte("v1")),
		SyncHash: "server-hash-xyz",
		SyncTime: 99999,
	}))

	// Modify the file.
	require.NoError(t, os.WriteFile(filePath, []byte("v2 longer"), 0o644))
	future := time.Now().Add(2 * time.Second)
	require.NoError(t, os.Chtimes(filePath, future, future))

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	lf := result.Current["synced.md"]
	assert.Equal(t, "server-hash-xyz", lf.SyncHash, "SyncHash should carry forward")
	assert.Equal(t, int64(99999), lf.SyncTime, "SyncTime should carry forward")
}

// --- Empty vault ---

func TestScanLocal_EmptyVault(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	assert.Empty(t, result.Current)
	assert.Empty(t, result.Changed)
	assert.Empty(t, result.Deleted)
}

// --- Hash computation ---

func TestScanLocal_NewFileHashIsCorrect(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	content := []byte("hash me please")
	require.NoError(t, os.WriteFile(filepath.Join(v.Dir(), "hashtest.md"), content, 0o644))

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	expected := sha256Hex(content)
	assert.Equal(t, expected, result.Current["hashtest.md"].Hash)
}

func TestScanLocal_EmptyFileHashed(t *testing.T) {
	v := tempVault(t)
	s := testState(t, testVaultID)

	require.NoError(t, os.WriteFile(filepath.Join(v.Dir(), "empty.md"), []byte{}, 0o644))

	result, err := ScanLocal(v, s, testVaultID, discardLogger, nil)
	require.NoError(t, err)

	lf := result.Current["empty.md"]
	assert.Equal(t, int64(0), lf.Size)
	assert.Equal(t, sha256Hex([]byte{}), lf.Hash)
}

// keysOf returns the keys of a map for diagnostic output.
func keysOf(m map[string]state.LocalFile) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
