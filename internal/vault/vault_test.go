package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testVault creates a temporary vault with some test files.
func testVault(t *testing.T) *Vault {
	t.Helper()
	dir := t.TempDir()

	// Create test files.
	files := map[string]string{
		"notes/hello.md":          "---\ntags:\n  - project\n  - go\n---\n# Hello World\n\nThis is a test note about Go programming.\nLine 4\nLine 5\n",
		"notes/second.md":         "# Second Note\n\nAnother note here.\n",
		"daily/2026-02-08.md":     "---\ntags: [daily]\n---\n# Daily Note\n\nToday was productive.\n",
		"recipes/cold-brew.md":    "---\ntags:\n  - coffee\n  - recipe\n---\n# Cold Brew\n\nSteep for 12 hours.\n",
		"images/photo.png":        "fake-png-data",
		"projects/archive/old.md": "# Old Note\n",
		".obsidian/app.json":      `{"theme": "dark"}`,
	}

	for path, content := range files {
		abs := filepath.Join(dir, filepath.FromSlash(path))
		require.NoError(t, os.MkdirAll(filepath.Dir(abs), 0755))
		require.NoError(t, os.WriteFile(abs, []byte(content), 0644))
	}

	v, err := New(dir)
	require.NoError(t, err)
	return v
}

// --- New ---

func TestNew_ValidDir(t *testing.T) {
	dir := t.TempDir()
	v, err := New(dir)
	require.NoError(t, err)
	assert.Equal(t, dir, v.Root())
}

func TestNew_NonexistentDir(t *testing.T) {
	_, err := New("/nonexistent/path/vault")
	require.Error(t, err)
}

func TestNew_FileNotDir(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file.txt")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0644))
	_, err := New(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a directory")
}

// --- ListAll ---

func TestListAll_ReturnsAllFiles(t *testing.T) {
	v := testVault(t)
	result := v.ListAll()

	// .obsidian/ should be excluded.
	for _, f := range result.Files {
		assert.False(t, filepath.HasPrefix(f.Path, ".obsidian"), "should exclude .obsidian: %s", f.Path)
	}

	// Should include markdown and non-markdown files.
	paths := make(map[string]bool)
	for _, f := range result.Files {
		paths[f.Path] = true
	}
	assert.True(t, paths["notes/hello.md"])
	assert.True(t, paths["images/photo.png"])
	assert.Equal(t, result.TotalFiles, len(result.Files))
}

func TestListAll_ParsesFrontmatterTags(t *testing.T) {
	v := testVault(t)
	result := v.ListAll()

	var helloEntry *FileEntry
	for i := range result.Files {
		if result.Files[i].Path == "notes/hello.md" {
			helloEntry = &result.Files[i]
			break
		}
	}
	require.NotNil(t, helloEntry)
	assert.Equal(t, []string{"project", "go"}, helloEntry.Tags)
}

func TestListAll_NoTagsForNonMarkdown(t *testing.T) {
	v := testVault(t)
	result := v.ListAll()

	for _, f := range result.Files {
		if f.Path == "images/photo.png" {
			assert.Nil(t, f.Tags)
		}
	}
}

// --- List ---

func TestList_Root(t *testing.T) {
	v := testVault(t)
	result, err := v.List("")
	require.NoError(t, err)
	assert.Equal(t, "/", result.Path)
	assert.Greater(t, result.TotalEntries, 0)

	// Should have directories like "notes", "daily", etc.
	names := make(map[string]string)
	for _, e := range result.Entries {
		names[e.Name] = e.Type
	}
	assert.Equal(t, "folder", names["notes"])
	assert.Equal(t, "folder", names["daily"])
}

func TestList_Subdirectory(t *testing.T) {
	v := testVault(t)
	result, err := v.List("notes")
	require.NoError(t, err)
	assert.Equal(t, "/notes", result.Path)

	names := make(map[string]bool)
	for _, e := range result.Entries {
		names[e.Name] = true
	}
	assert.True(t, names["hello.md"])
	assert.True(t, names["second.md"])
}

func TestList_FolderChildCount(t *testing.T) {
	v := testVault(t)
	result, err := v.List("")
	require.NoError(t, err)

	for _, e := range result.Entries {
		if e.Name == "notes" {
			assert.Equal(t, 2, e.Children)
		}
	}
}

func TestList_NonexistentDir(t *testing.T) {
	v := testVault(t)
	_, err := v.List("nonexistent")
	require.Error(t, err)
	vErr, ok := err.(*Error)
	require.True(t, ok)
	assert.Equal(t, ErrCodeFileNotFound, vErr.Code)
}

func TestList_PathTraversal(t *testing.T) {
	v := testVault(t)
	_, err := v.List("../etc")
	require.Error(t, err)
	vErr, ok := err.(*Error)
	require.True(t, ok)
	assert.Equal(t, ErrCodePathNotAllowed, vErr.Code)
}

func TestList_ExcludesHiddenFiles(t *testing.T) {
	v := testVault(t)
	result, err := v.List("")
	require.NoError(t, err)

	for _, e := range result.Entries {
		assert.False(t, e.Name[0] == '.', "hidden entry should be excluded: %s", e.Name)
	}
}

// --- Read ---

func TestRead_FullFile(t *testing.T) {
	v := testVault(t)
	result, err := v.Read("notes/second.md", 0, 0)
	require.NoError(t, err)
	assert.Equal(t, "notes/second.md", result.Path)
	assert.Contains(t, result.Content, "# Second Note")
	assert.Equal(t, 4, result.TotalLines)
	assert.Equal(t, [2]int{1, 4}, result.Showing)
}

func TestRead_WithOffset(t *testing.T) {
	v := testVault(t)
	result, err := v.Read("notes/hello.md", 6, 2)
	require.NoError(t, err)
	assert.Contains(t, result.Content, "# Hello World")
	assert.Equal(t, [2]int{6, 7}, result.Showing)
}

func TestRead_OffsetBeyondFile(t *testing.T) {
	v := testVault(t)
	_, err := v.Read("notes/second.md", 100, 0)
	require.Error(t, err)
	vErr, ok := err.(*Error)
	require.True(t, ok)
	assert.Equal(t, ErrCodeInvalidRange, vErr.Code)
}

func TestRead_NonexistentFile(t *testing.T) {
	v := testVault(t)
	_, err := v.Read("nonexistent.md", 0, 0)
	require.Error(t, err)
	vErr, ok := err.(*Error)
	require.True(t, ok)
	assert.Equal(t, ErrCodeFileNotFound, vErr.Code)
}

func TestRead_PathTraversal(t *testing.T) {
	v := testVault(t)
	_, err := v.Read("../../etc/passwd", 0, 0)
	require.Error(t, err)
	vErr, ok := err.(*Error)
	require.True(t, ok)
	assert.Equal(t, ErrCodePathNotAllowed, vErr.Code)
}

func TestRead_NonMarkdownFile(t *testing.T) {
	v := testVault(t)
	result, err := v.Read("images/photo.png", 0, 0)
	require.NoError(t, err)
	assert.Equal(t, "fake-png-data", result.Content)
}

func TestRead_AutoTruncation(t *testing.T) {
	dir := t.TempDir()
	// Create a file with more than DefaultReadLimit lines.
	var content string
	for i := 0; i < 300; i++ {
		content += "line\n"
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "big.md"), []byte(content), 0644))

	v, err := New(dir)
	require.NoError(t, err)

	result, err := v.Read("big.md", 0, 0)
	require.NoError(t, err)
	assert.True(t, result.Truncated)
	assert.Equal(t, [2]int{1, DefaultReadLimit}, result.Showing)
}

func TestRead_ExplicitLimitNoTruncation(t *testing.T) {
	dir := t.TempDir()
	var content string
	for i := 0; i < 300; i++ {
		content += "line\n"
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "big.md"), []byte(content), 0644))

	v, err := New(dir)
	require.NoError(t, err)

	// With explicit limit, truncated should be false.
	result, err := v.Read("big.md", 1, 50)
	require.NoError(t, err)
	assert.False(t, result.Truncated)
	assert.Equal(t, [2]int{1, 50}, result.Showing)
}

// --- Search ---

func TestSearch_ByFilename(t *testing.T) {
	v := testVault(t)
	result, err := v.Search("cold-brew", 20)
	require.NoError(t, err)
	assert.Greater(t, result.TotalMatches, 0)

	found := false
	for _, m := range result.Results {
		if m.Path == "recipes/cold-brew.md" && m.MatchType == "filename" {
			found = true
		}
	}
	assert.True(t, found, "should find cold-brew.md by filename")
}

func TestSearch_ByTag(t *testing.T) {
	v := testVault(t)
	result, err := v.Search("coffee", 20)
	require.NoError(t, err)

	found := false
	for _, m := range result.Results {
		if m.Path == "recipes/cold-brew.md" && m.MatchType == "tag" {
			found = true
		}
	}
	assert.True(t, found, "should find cold-brew.md by tag")
}

func TestSearch_ByContent(t *testing.T) {
	v := testVault(t)
	result, err := v.Search("productive", 20)
	require.NoError(t, err)

	found := false
	for _, m := range result.Results {
		if m.Path == "daily/2026-02-08.md" && m.MatchType == "content" {
			found = true
			assert.Contains(t, m.Snippet, "**productive**")
			assert.Equal(t, 6, m.Line)
		}
	}
	assert.True(t, found, "should find content match")
}

func TestSearch_CaseInsensitive(t *testing.T) {
	v := testVault(t)
	result, err := v.Search("HELLO", 20)
	require.NoError(t, err)
	assert.Greater(t, result.TotalMatches, 0)
}

func TestSearch_MaxResults(t *testing.T) {
	v := testVault(t)
	result, err := v.Search("e", 2)
	require.NoError(t, err)
	assert.LessOrEqual(t, result.TotalMatches, 2)
}

func TestSearch_NoResults(t *testing.T) {
	v := testVault(t)
	result, err := v.Search("xyznonexistent", 20)
	require.NoError(t, err)
	assert.Equal(t, 0, result.TotalMatches)
}

// --- Write ---

func TestWrite_NewFile(t *testing.T) {
	v := testVault(t)
	result, err := v.Write("new-note.md", "# New\n\nContent here.\n", true)
	require.NoError(t, err)
	assert.True(t, result.Created)
	assert.Equal(t, "new-note.md", result.Path)
	assert.Equal(t, 4, result.TotalLines)

	// Verify file exists on disk.
	data, err := os.ReadFile(filepath.Join(v.Root(), "new-note.md"))
	require.NoError(t, err)
	assert.Equal(t, "# New\n\nContent here.\n", string(data))
}

func TestWrite_OverwriteExisting(t *testing.T) {
	v := testVault(t)
	result, err := v.Write("notes/hello.md", "replaced content", true)
	require.NoError(t, err)
	assert.False(t, result.Created)

	data, err := os.ReadFile(filepath.Join(v.Root(), "notes/hello.md"))
	require.NoError(t, err)
	assert.Equal(t, "replaced content", string(data))
}

func TestWrite_CreateDirs(t *testing.T) {
	v := testVault(t)
	result, err := v.Write("new/nested/dir/file.md", "content", true)
	require.NoError(t, err)
	assert.True(t, result.Created)
}

func TestWrite_NoDirsCreation(t *testing.T) {
	v := testVault(t)
	_, err := v.Write("missing-dir/file.md", "content", false)
	require.Error(t, err)
}

func TestWrite_ProtectedPath(t *testing.T) {
	v := testVault(t)
	_, err := v.Write(".obsidian/app.json", "hacked", true)
	require.Error(t, err)
	vErr, ok := err.(*Error)
	require.True(t, ok)
	assert.Equal(t, ErrCodePathNotAllowed, vErr.Code)
}

func TestWrite_PathTraversal(t *testing.T) {
	v := testVault(t)
	_, err := v.Write("../etc/evil", "bad", true)
	require.Error(t, err)
	vErr, ok := err.(*Error)
	require.True(t, ok)
	assert.Equal(t, ErrCodePathNotAllowed, vErr.Code)
}

func TestWrite_UpdatesIndex(t *testing.T) {
	v := testVault(t)
	_, err := v.Write("indexed.md", "---\ntags: [new]\n---\n# Indexed\n", true)
	require.NoError(t, err)

	entry := v.index.Get("indexed.md")
	require.NotNil(t, entry)
	assert.Equal(t, []string{"new"}, entry.Tags)
}

// --- Edit ---

func TestEdit_SimpleReplace(t *testing.T) {
	v := testVault(t)
	result, err := v.Edit("notes/second.md", "Another note", "Updated note")
	require.NoError(t, err)
	assert.True(t, result.Replaced)

	data, err := os.ReadFile(filepath.Join(v.Root(), "notes/second.md"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "Updated note")
	assert.NotContains(t, string(data), "Another note")
}

func TestEdit_TextNotFound(t *testing.T) {
	v := testVault(t)
	_, err := v.Edit("notes/second.md", "nonexistent text", "replacement")
	require.Error(t, err)
	vErr, ok := err.(*Error)
	require.True(t, ok)
	assert.Equal(t, ErrCodeTextNotFound, vErr.Code)
}

func TestEdit_TextNotUnique(t *testing.T) {
	v := testVault(t)
	// Write a file with duplicate text.
	_, err := v.Write("dup.md", "hello world hello world", true)
	require.NoError(t, err)

	_, err = v.Edit("dup.md", "hello world", "replaced")
	require.Error(t, err)
	vErr, ok := err.(*Error)
	require.True(t, ok)
	assert.Equal(t, ErrCodeTextNotUnique, vErr.Code)
	assert.Contains(t, vErr.Message, "2 times")
}

func TestEdit_NonexistentFile(t *testing.T) {
	v := testVault(t)
	_, err := v.Edit("nonexistent.md", "old", "new")
	require.Error(t, err)
	vErr, ok := err.(*Error)
	require.True(t, ok)
	assert.Equal(t, ErrCodeFileNotFound, vErr.Code)
}

func TestEdit_ProtectedPath(t *testing.T) {
	v := testVault(t)
	_, err := v.Edit(".obsidian/app.json", "dark", "light")
	require.Error(t, err)
	vErr, ok := err.(*Error)
	require.True(t, ok)
	assert.Equal(t, ErrCodePathNotAllowed, vErr.Code)
}

func TestEdit_DeleteText(t *testing.T) {
	v := testVault(t)
	_, err := v.Edit("notes/second.md", "\nAnother note here.\n", "")
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(v.Root(), "notes/second.md"))
	require.NoError(t, err)
	assert.NotContains(t, string(data), "Another note")
}

func TestEdit_UpdatesIndex(t *testing.T) {
	v := testVault(t)
	_, err := v.Edit("notes/second.md", "# Second Note", "# Updated Title")
	require.NoError(t, err)

	entry := v.index.Get("notes/second.md")
	require.NotNil(t, entry)
	// Size should have changed.
	assert.Greater(t, entry.Size, int64(0))
}

// --- buildSnippet ---

func TestBuildSnippet_ShortLine(t *testing.T) {
	snippet := buildSnippet("hello world", 6, 5)
	assert.Equal(t, "hello **world**", snippet)
}

func TestBuildSnippet_LongLine(t *testing.T) {
	line := "prefix " + strings.Repeat("a", 100) + " the keyword " + strings.Repeat("b", 100) + " suffix"
	idx := strings.Index(line, "the keyword")
	snippet := buildSnippet(line, idx, len("the keyword"))
	assert.Contains(t, snippet, "**the keyword**")
	assert.Contains(t, snippet, "...")
}
