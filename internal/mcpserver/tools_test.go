package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexjbarnes/vault-sync/internal/vault"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSetup creates a temp vault, registers tools on an MCP server,
// and returns a connected client session for calling tools.
func testSetup(t *testing.T) (*mcp.ClientSession, *vault.Vault) {
	t.Helper()
	dir := t.TempDir()

	files := map[string]string{
		"notes/hello.md":       "---\ntags:\n  - project\n  - go\n---\n# Hello World\n\nThis is a test note.\n",
		"notes/second.md":      "# Second Note\n\nAnother note here.\n",
		"daily/2026-02-08.md":  "---\ntags: [daily]\n---\n# Daily\n\nToday was productive.\n",
		"recipes/cold-brew.md": "---\ntags:\n  - coffee\n---\n# Cold Brew\n\nSteep for 12 hours.\n",
		"images/photo.png":     "fake-png-data",
		".obsidian/app.json":   `{"theme": "dark"}`,
	}
	for path, content := range files {
		abs := filepath.Join(dir, filepath.FromSlash(path))
		require.NoError(t, os.MkdirAll(filepath.Dir(abs), 0755))
		require.NoError(t, os.WriteFile(abs, []byte(content), 0644))
	}

	v, err := vault.New(dir)
	require.NoError(t, err)

	server := mcp.NewServer(
		&mcp.Implementation{Name: "vault-sync-mcp-test", Version: "test"},
		nil,
	)
	RegisterTools(server, v)

	ctx := context.Background()
	t1, t2 := mcp.NewInMemoryTransports()
	_, err = server.Connect(ctx, t1, nil)
	require.NoError(t, err)

	client := mcp.NewClient(
		&mcp.Implementation{Name: "test-client", Version: "test"},
		nil,
	)
	session, err := client.Connect(ctx, t2, nil)
	require.NoError(t, err)
	t.Cleanup(func() { session.Close() })

	return session, v
}

// callTool is a helper that calls a tool and returns the result.
func callTool(t *testing.T, session *mcp.ClientSession, name string, args map[string]interface{}) *mcp.CallToolResult {
	t.Helper()
	ctx := context.Background()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	require.NoError(t, err)
	return result
}

// extractJSON unmarshals the first text content from a CallToolResult.
func extractJSON(t *testing.T, result *mcp.CallToolResult, dest interface{}) {
	t.Helper()
	require.NotEmpty(t, result.Content, "result has no content")
	tc, ok := result.Content[0].(*mcp.TextContent)
	require.True(t, ok, "first content is not TextContent")
	require.NoError(t, json.Unmarshal([]byte(tc.Text), dest))
}

// --- vault_list ---

func TestList_AllFiles(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_list", nil)
	assert.False(t, result.IsError)

	var out struct {
		TotalFiles int               `json:"total_files"`
		Files      []vault.FileEntry `json:"files"`
	}
	extractJSON(t, result, &out)
	assert.Greater(t, out.TotalFiles, 0)

	paths := make(map[string]bool)
	for _, f := range out.Files {
		paths[f.Path] = true
		assert.False(t, filepath.HasPrefix(f.Path, ".obsidian"), "should exclude .obsidian: %s", f.Path)
	}
	assert.True(t, paths["notes/hello.md"])
	assert.True(t, paths["images/photo.png"])
}

func TestList_AllFilesIncludesTags(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_list", nil)

	var out struct {
		Files []vault.FileEntry `json:"files"`
	}
	extractJSON(t, result, &out)

	for _, f := range out.Files {
		if f.Path == "notes/hello.md" {
			assert.Equal(t, []string{"project", "go"}, f.Tags)
			return
		}
	}
	t.Fatal("notes/hello.md not found in results")
}

func TestList_Root(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_list", map[string]interface{}{
		"path": "/",
	})
	assert.False(t, result.IsError)

	var out vault.ListResult
	extractJSON(t, result, &out)
	assert.Equal(t, "/", out.Path)
	assert.Greater(t, out.TotalEntries, 0)
}

func TestList_Subdirectory(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_list", map[string]interface{}{
		"path": "notes",
	})
	assert.False(t, result.IsError)

	var out vault.ListResult
	extractJSON(t, result, &out)
	assert.Equal(t, "/notes", out.Path)
	assert.Equal(t, 2, out.TotalEntries) // hello.md and second.md
}

func TestList_NonexistentDir(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_list", map[string]interface{}{
		"path": "nonexistent",
	})
	// Errors from ToolHandlerFor are returned as tool errors (IsError=true),
	// not protocol errors.
	assert.True(t, result.IsError)
	tc := result.Content[0].(*mcp.TextContent)
	assert.Contains(t, tc.Text, "not found")
}

// --- vault_read ---

func TestRead_FullFile(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_read", map[string]interface{}{
		"path": "notes/hello.md",
	})
	assert.False(t, result.IsError)

	var out vault.ReadResult
	extractJSON(t, result, &out)
	assert.Equal(t, "notes/hello.md", out.Path)
	assert.Contains(t, out.Content, "Hello World")
	assert.Greater(t, out.TotalLines, 0)
}

func TestRead_WithPagination(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_read", map[string]interface{}{
		"path":   "notes/hello.md",
		"offset": 6,
		"limit":  1,
	})
	assert.False(t, result.IsError)

	var out vault.ReadResult
	extractJSON(t, result, &out)
	assert.Equal(t, [2]int{6, 6}, out.Showing)
	assert.Contains(t, out.Content, "Hello World")
}

func TestRead_NonexistentFile(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_read", map[string]interface{}{
		"path": "nonexistent.md",
	})
	assert.True(t, result.IsError)
}

func TestRead_PathTraversal(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_read", map[string]interface{}{
		"path": "../../../etc/passwd",
	})
	assert.True(t, result.IsError)
}

// --- vault_search ---

func TestSearch_ByFilename(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_search", map[string]interface{}{
		"query": "cold-brew",
	})
	assert.False(t, result.IsError)

	var out vault.SearchResult
	extractJSON(t, result, &out)
	assert.Greater(t, out.TotalMatches, 0)

	found := false
	for _, m := range out.Results {
		if m.Path == "recipes/cold-brew.md" && m.MatchType == "filename" {
			found = true
		}
	}
	assert.True(t, found, "should find by filename")
}

func TestSearch_ByContent(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_search", map[string]interface{}{
		"query": "productive",
	})
	assert.False(t, result.IsError)

	var out vault.SearchResult
	extractJSON(t, result, &out)

	found := false
	for _, m := range out.Results {
		if m.Path == "daily/2026-02-08.md" && m.MatchType == "content" {
			found = true
		}
	}
	assert.True(t, found, "should find content match")
}

func TestSearch_MaxResults(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_search", map[string]interface{}{
		"query":       "e",
		"max_results": 2,
	})
	assert.False(t, result.IsError)

	var out vault.SearchResult
	extractJSON(t, result, &out)
	assert.LessOrEqual(t, out.TotalMatches, 2)
}

// --- vault_write ---

func TestWrite_NewFile(t *testing.T) {
	session, v := testSetup(t)
	result := callTool(t, session, "vault_write", map[string]interface{}{
		"path":    "new-note.md",
		"content": "# New Note\n\nContent here.\n",
	})
	assert.False(t, result.IsError)

	var out vault.WriteResult
	extractJSON(t, result, &out)
	assert.True(t, out.Created)
	assert.Equal(t, "new-note.md", out.Path)

	// Verify file exists on disk.
	data, err := os.ReadFile(filepath.Join(v.Root(), "new-note.md"))
	require.NoError(t, err)
	assert.Equal(t, "# New Note\n\nContent here.\n", string(data))
}

func TestWrite_CreateDirs(t *testing.T) {
	session, v := testSetup(t)
	result := callTool(t, session, "vault_write", map[string]interface{}{
		"path":        "deep/nested/note.md",
		"content":     "# Nested\n",
		"create_dirs": true,
	})
	assert.False(t, result.IsError)

	var out vault.WriteResult
	extractJSON(t, result, &out)
	assert.True(t, out.Created)

	_, err := os.Stat(filepath.Join(v.Root(), "deep/nested/note.md"))
	require.NoError(t, err)
}

func TestWrite_ProtectedPath(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_write", map[string]interface{}{
		"path":    ".obsidian/test.json",
		"content": "{}",
	})
	assert.True(t, result.IsError)
}

func TestWrite_Overwrite(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_write", map[string]interface{}{
		"path":    "notes/hello.md",
		"content": "# Updated\n",
	})
	assert.False(t, result.IsError)

	var out vault.WriteResult
	extractJSON(t, result, &out)
	assert.False(t, out.Created) // overwrite, not create
}

// --- vault_edit ---

func TestEdit_SimpleReplace(t *testing.T) {
	session, v := testSetup(t)
	result := callTool(t, session, "vault_edit", map[string]interface{}{
		"path":     "notes/second.md",
		"old_text": "Another note here.",
		"new_text": "A completely different note.",
	})
	assert.False(t, result.IsError)

	var out vault.EditResult
	extractJSON(t, result, &out)
	assert.True(t, out.Replaced)

	data, err := os.ReadFile(filepath.Join(v.Root(), "notes/second.md"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "A completely different note.")
}

func TestEdit_TextNotFound(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_edit", map[string]interface{}{
		"path":     "notes/second.md",
		"old_text": "nonexistent text",
		"new_text": "replacement",
	})
	assert.True(t, result.IsError)
}

func TestEdit_NonexistentFile(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_edit", map[string]interface{}{
		"path":     "nonexistent.md",
		"old_text": "foo",
		"new_text": "bar",
	})
	assert.True(t, result.IsError)
}

func TestEdit_DeleteText(t *testing.T) {
	session, v := testSetup(t)
	result := callTool(t, session, "vault_edit", map[string]interface{}{
		"path":     "notes/second.md",
		"old_text": "Another note here.\n",
		"new_text": "",
	})
	assert.False(t, result.IsError)

	data, err := os.ReadFile(filepath.Join(v.Root(), "notes/second.md"))
	require.NoError(t, err)
	assert.NotContains(t, string(data), "Another note here.")
}

// --- vault_delete ---

func TestDelete_SingleFile(t *testing.T) {
	session, v := testSetup(t)
	// Verify file exists before delete.
	_, err := os.Stat(filepath.Join(v.Root(), "notes/second.md"))
	require.NoError(t, err)

	result := callTool(t, session, "vault_delete", map[string]interface{}{
		"paths": []string{"notes/second.md"},
	})
	assert.False(t, result.IsError)

	var out vault.DeleteBatchResult
	extractJSON(t, result, &out)
	assert.Equal(t, 1, out.Deleted)
	assert.Equal(t, 0, out.Failed)
	assert.Equal(t, 1, out.Total)

	// Verify file is gone.
	_, err = os.Stat(filepath.Join(v.Root(), "notes/second.md"))
	assert.True(t, os.IsNotExist(err))
}

func TestDelete_MultipleFiles(t *testing.T) {
	session, v := testSetup(t)
	result := callTool(t, session, "vault_delete", map[string]interface{}{
		"paths": []string{"notes/hello.md", "notes/second.md"},
	})
	assert.False(t, result.IsError)

	var out vault.DeleteBatchResult
	extractJSON(t, result, &out)
	assert.Equal(t, 2, out.Deleted)
	assert.Equal(t, 0, out.Failed)

	for _, name := range []string{"notes/hello.md", "notes/second.md"} {
		_, err := os.Stat(filepath.Join(v.Root(), name))
		assert.True(t, os.IsNotExist(err))
	}
}

func TestDelete_NonexistentFile(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_delete", map[string]interface{}{
		"paths": []string{"nonexistent.md"},
	})
	// Best-effort: the call itself succeeds, but the item reports failure.
	assert.False(t, result.IsError)

	var out vault.DeleteBatchResult
	extractJSON(t, result, &out)
	assert.Equal(t, 0, out.Deleted)
	assert.Equal(t, 1, out.Failed)
	assert.NotEmpty(t, out.Results[0].Error)
}

func TestDelete_Directory(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_delete", map[string]interface{}{
		"paths": []string{"notes"},
	})
	assert.False(t, result.IsError)

	var out vault.DeleteBatchResult
	extractJSON(t, result, &out)
	assert.Equal(t, 0, out.Deleted)
	assert.Equal(t, 1, out.Failed)
	assert.Contains(t, out.Results[0].Error, "cannot delete directory")
}

func TestDelete_ProtectedPath(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_delete", map[string]interface{}{
		"paths": []string{".obsidian/app.json"},
	})
	assert.False(t, result.IsError)

	var out vault.DeleteBatchResult
	extractJSON(t, result, &out)
	assert.Equal(t, 0, out.Deleted)
	assert.Equal(t, 1, out.Failed)
	assert.Contains(t, out.Results[0].Error, ".obsidian/")
}

func TestDelete_PathTraversal(t *testing.T) {
	session, _ := testSetup(t)
	for _, p := range traversalPaths {
		result := callTool(t, session, "vault_delete", map[string]interface{}{
			"paths": []string{p},
		})
		assert.False(t, result.IsError, "vault_delete should not return protocol error for %q", p)

		var out vault.DeleteBatchResult
		extractJSON(t, result, &out)
		assert.Equal(t, 0, out.Deleted, "vault_delete should not delete for %q", p)
		assert.Equal(t, 1, out.Failed, "vault_delete should report failure for %q", p)
	}
}

func TestDelete_PartialFailure(t *testing.T) {
	session, v := testSetup(t)
	result := callTool(t, session, "vault_delete", map[string]interface{}{
		"paths": []string{"notes/hello.md", "nonexistent.md", "notes/second.md"},
	})
	assert.False(t, result.IsError)

	var out vault.DeleteBatchResult
	extractJSON(t, result, &out)
	assert.Equal(t, 2, out.Deleted)
	assert.Equal(t, 1, out.Failed)
	assert.Equal(t, 3, out.Total)

	// Valid files deleted.
	_, err := os.Stat(filepath.Join(v.Root(), "notes/hello.md"))
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(v.Root(), "notes/second.md"))
	assert.True(t, os.IsNotExist(err))
}

func TestDelete_EmptyPaths(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_delete", map[string]interface{}{
		"paths": []string{},
	})
	assert.True(t, result.IsError)
}

// --- vault_move ---

func TestMove_Success(t *testing.T) {
	session, v := testSetup(t)
	result := callTool(t, session, "vault_move", map[string]interface{}{
		"source":      "notes/second.md",
		"destination": "archive/second.md",
	})
	assert.False(t, result.IsError)

	var out vault.MoveResult
	extractJSON(t, result, &out)
	assert.True(t, out.Moved)
	assert.Equal(t, "notes/second.md", out.Source)
	assert.Equal(t, "archive/second.md", out.Destination)

	_, err := os.Stat(filepath.Join(v.Root(), "notes/second.md"))
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(v.Root(), "archive/second.md"))
	require.NoError(t, err)
}

func TestMove_NonexistentSource(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_move", map[string]interface{}{
		"source":      "nonexistent.md",
		"destination": "dest.md",
	})
	assert.True(t, result.IsError)
}

func TestMove_DestExists(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_move", map[string]interface{}{
		"source":      "notes/hello.md",
		"destination": "notes/second.md",
	})
	assert.True(t, result.IsError)
}

func TestMove_ProtectedPath(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_move", map[string]interface{}{
		"source":      ".obsidian/app.json",
		"destination": "moved.json",
	})
	assert.True(t, result.IsError)
}

func TestMove_PathTraversal(t *testing.T) {
	session, _ := testSetup(t)
	for _, p := range traversalPaths {
		result := callTool(t, session, "vault_move", map[string]interface{}{
			"source":      p,
			"destination": "dest.md",
		})
		assert.True(t, result.IsError, "vault_move should reject source %q", p)

		result = callTool(t, session, "vault_move", map[string]interface{}{
			"source":      "notes/hello.md",
			"destination": p,
		})
		assert.True(t, result.IsError, "vault_move should reject destination %q", p)
	}
}

// --- vault_copy ---

func TestCopy_Success(t *testing.T) {
	session, v := testSetup(t)
	result := callTool(t, session, "vault_copy", map[string]interface{}{
		"source":      "notes/second.md",
		"destination": "archive/second.md",
	})
	assert.False(t, result.IsError)

	var out vault.CopyResult
	extractJSON(t, result, &out)
	assert.True(t, out.Copied)
	assert.Greater(t, out.Size, int64(0))

	// Both files exist.
	_, err := os.Stat(filepath.Join(v.Root(), "notes/second.md"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(v.Root(), "archive/second.md"))
	require.NoError(t, err)
}

func TestCopy_NonexistentSource(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_copy", map[string]interface{}{
		"source":      "nonexistent.md",
		"destination": "dest.md",
	})
	assert.True(t, result.IsError)
}

func TestCopy_DestExists(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_copy", map[string]interface{}{
		"source":      "notes/hello.md",
		"destination": "notes/second.md",
	})
	assert.True(t, result.IsError)
}

func TestCopy_ProtectedPath(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_copy", map[string]interface{}{
		"source":      ".obsidian/app.json",
		"destination": "copied.json",
	})
	assert.True(t, result.IsError)
}

func TestCopy_PathTraversal(t *testing.T) {
	session, _ := testSetup(t)
	for _, p := range traversalPaths {
		result := callTool(t, session, "vault_copy", map[string]interface{}{
			"source":      p,
			"destination": "dest.md",
		})
		assert.True(t, result.IsError, "vault_copy should reject source %q", p)

		result = callTool(t, session, "vault_copy", map[string]interface{}{
			"source":      "notes/hello.md",
			"destination": p,
		})
		assert.True(t, result.IsError, "vault_copy should reject destination %q", p)
	}
}

// --- Security: path traversal through MCP layer ---

// traversalPaths exercises the most common directory traversal attack vectors.
var traversalPaths = []string{
	"../../../etc/passwd",
	"../../etc/shadow",
	"notes/../../etc/passwd",
	"notes/../../../etc/passwd",
	"..\\..\\etc\\passwd",
}

func TestList_PathTraversal(t *testing.T) {
	session, _ := testSetup(t)
	for _, p := range traversalPaths {
		result := callTool(t, session, "vault_list", map[string]interface{}{
			"path": p,
		})
		assert.True(t, result.IsError, "vault_list should reject %q", p)
	}
}

func TestWrite_PathTraversal(t *testing.T) {
	session, _ := testSetup(t)
	for _, p := range traversalPaths {
		result := callTool(t, session, "vault_write", map[string]interface{}{
			"path":    p,
			"content": "pwned",
		})
		assert.True(t, result.IsError, "vault_write should reject %q", p)
	}
}

func TestEdit_PathTraversal(t *testing.T) {
	session, _ := testSetup(t)
	for _, p := range traversalPaths {
		result := callTool(t, session, "vault_edit", map[string]interface{}{
			"path":     p,
			"old_text": "foo",
			"new_text": "bar",
		})
		assert.True(t, result.IsError, "vault_edit should reject %q", p)
	}
}

// --- Security: .obsidian protection through MCP layer ---

func TestRead_ObsidianProtected(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_read", map[string]interface{}{
		"path": ".obsidian/app.json",
	})
	assert.True(t, result.IsError, "vault_read should block .obsidian paths")
}

func TestList_ObsidianProtected(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_list", map[string]interface{}{
		"path": ".obsidian",
	})
	assert.True(t, result.IsError, "vault_list should block .obsidian paths")
}

func TestEdit_ProtectedPath(t *testing.T) {
	session, _ := testSetup(t)
	result := callTool(t, session, "vault_edit", map[string]interface{}{
		"path":     ".obsidian/app.json",
		"old_text": "dark",
		"new_text": "light",
	})
	assert.True(t, result.IsError, "vault_edit should block .obsidian paths")
}

// --- Tool listing ---

func TestToolsRegistered(t *testing.T) {
	session, _ := testSetup(t)
	ctx := context.Background()

	var names []string
	for tool, err := range session.Tools(ctx, nil) {
		require.NoError(t, err)
		names = append(names, tool.Name)
	}

	expected := []string{
		"vault_list",
		"vault_read",
		"vault_search",
		"vault_write",
		"vault_edit",
		"vault_delete",
		"vault_move",
		"vault_copy",
	}
	for _, name := range expected {
		assert.Contains(t, names, name, "tool %s should be registered", name)
	}
}
