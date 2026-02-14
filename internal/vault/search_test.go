package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- buildSnippet (Go fallback path) ---

func TestBuildSnippet_MatchAtStart(t *testing.T) {
	snippet := buildSnippet("hello world foo bar", 0, 5)
	assert.Equal(t, "**hello** world foo bar", snippet)
}

func TestBuildSnippet_MatchAtEnd(t *testing.T) {
	line := "some text at the end"
	snippet := buildSnippet(line, 17, 3)
	assert.Contains(t, snippet, "**end**")
	assert.False(t, containsSuffix(snippet), "should not have trailing ellipsis")
}

func TestBuildSnippet_MatchInMiddleLongLine(t *testing.T) {
	// Build a line long enough that context trimming kicks in.
	line := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa KEYWORD bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	idx := 62 // byte position of "KEYWORD"
	snippet := buildSnippet(line, idx, 7)
	assert.Contains(t, snippet, "**KEYWORD**")
	assert.True(t, len(snippet) < len(line)+10, "snippet should be shorter than full line")
}

func TestBuildSnippet_EmptyMatch(t *testing.T) {
	snippet := buildSnippet("hello", 0, 0)
	assert.Equal(t, "****hello", snippet)
}

// --- buildSnippetFromBytes (ripgrep path) ---

func TestBuildSnippetFromBytes_Simple(t *testing.T) {
	snippet := buildSnippetFromBytes("hello world", 6, 11)
	assert.Equal(t, "hello **world**", snippet)
}

func TestBuildSnippetFromBytes_WithContext(t *testing.T) {
	line := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa MATCH bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	snippet := buildSnippetFromBytes(line, 62, 67)
	assert.Contains(t, snippet, "**MATCH**")
	assert.Contains(t, snippet, "...")
}

func TestBuildSnippetFromBytes_AtStartOfLine(t *testing.T) {
	snippet := buildSnippetFromBytes("MATCH is here", 0, 5)
	assert.True(t, hasPrefix(snippet, "**MATCH**"))
}

func TestBuildSnippetFromBytes_AtEndOfLine(t *testing.T) {
	snippet := buildSnippetFromBytes("ends with MATCH", 10, 15)
	assert.True(t, hasSuffix(snippet, "**MATCH**"))
}

func TestBuildSnippetFromBytes_InvalidRange(t *testing.T) {
	// start >= end should fall back to truncation.
	snippet := buildSnippetFromBytes("some line", 5, 3)
	assert.Equal(t, "some line", snippet)
}

func TestBuildSnippetFromBytes_MultiByte(t *testing.T) {
	// UTF-8 multi-byte: each emoji is 4 bytes.
	line := "before cafe\u0301 after"
	// "cafe\u0301" = cafe + combining accent, search for "caf"
	snippet := buildSnippetFromBytes(line, 7, 10)
	assert.Contains(t, snippet, "**caf**")
}

// --- truncateLine ---

func TestTruncateLine_Short(t *testing.T) {
	assert.Equal(t, "hello", truncateLine("hello", 10))
}

func TestTruncateLine_Long(t *testing.T) {
	result := truncateLine("hello world", 5)
	assert.Equal(t, "hello...", result)
}

func TestTruncateLine_ExactLength(t *testing.T) {
	assert.Equal(t, "hello", truncateLine("hello", 5))
}

// --- parseRgMatchLine ---

func TestParseRgMatchLine_ValidMatch(t *testing.T) {
	msg := rgMessage{
		Type: "match",
		Data: mustMarshal(t, rgMatchData{
			Path:       rgText{Text: "/vault/notes/hello.md"},
			Lines:      rgText{Text: "This line has a keyword in it\n"},
			LineNumber: 14,
			Submatches: []rgSubmatch{
				{Match: rgText{Text: "keyword"}, Start: 16, End: 23},
			},
		}),
	}
	line := mustMarshal(t, msg)
	m, ok := parseRgMatchLine(line, "/vault")
	require.True(t, ok)
	assert.Equal(t, "notes/hello.md", m.Path)
	assert.Equal(t, "content", m.MatchType)
	assert.Equal(t, 14, m.Line)
	assert.Contains(t, m.Snippet, "**keyword**")
}

func TestParseRgMatchLine_SummaryType(t *testing.T) {
	msg := rgMessage{Type: "summary", Data: json.RawMessage(`{}`)}
	line := mustMarshal(t, msg)
	_, ok := parseRgMatchLine(line, "/vault")
	assert.False(t, ok)
}

func TestParseRgMatchLine_InvalidJSON(t *testing.T) {
	_, ok := parseRgMatchLine([]byte("not json"), "/vault")
	assert.False(t, ok)
}

func TestParseRgMatchLine_NoSubmatches(t *testing.T) {
	msg := rgMessage{
		Type: "match",
		Data: mustMarshal(t, rgMatchData{
			Path:       rgText{Text: "/vault/test.md"},
			Lines:      rgText{Text: "a very long line of text here\n"},
			LineNumber: 1,
			Submatches: nil,
		}),
	}
	line := mustMarshal(t, msg)
	m, ok := parseRgMatchLine(line, "/vault")
	require.True(t, ok)
	assert.Equal(t, "test.md", m.Path)
	// Should fall back to truncation, not bold.
	assert.NotContains(t, m.Snippet, "**")
}

func TestParseRgMatchLine_PathStripping(t *testing.T) {
	msg := rgMessage{
		Type: "match",
		Data: mustMarshal(t, rgMatchData{
			Path:       rgText{Text: "/my/vault/deep/nested/file.md"},
			Lines:      rgText{Text: "match\n"},
			LineNumber: 1,
			Submatches: []rgSubmatch{{Match: rgText{Text: "match"}, Start: 0, End: 5}},
		}),
	}
	line := mustMarshal(t, msg)
	m, ok := parseRgMatchLine(line, "/my/vault")
	require.True(t, ok)
	assert.Equal(t, "deep/nested/file.md", m.Path)
}

// --- Integration: Search with ripgrep ---

func TestSearch_Rg_ContentMatch(t *testing.T) {
	if RgPath() == "" {
		t.Skip("ripgrep not available")
	}

	v := testVault(t)
	result, err := v.Search("productive", 20)
	require.NoError(t, err)

	found := false

	for _, m := range result.Results {
		if m.Path == "daily/2026-02-08.md" && m.MatchType == "content" {
			found = true

			assert.Contains(t, m.Snippet, "**productive**")
		}
	}

	assert.True(t, found, "rg should find content match")
}

func TestSearch_Rg_Deduplication(t *testing.T) {
	if RgPath() == "" {
		t.Skip("ripgrep not available")
	}

	v := testVault(t)
	// "cold-brew" matches filename. It should not also appear as a content match.
	result, err := v.Search("cold-brew", 20)
	require.NoError(t, err)

	pathCounts := make(map[string]int)
	for _, m := range result.Results {
		pathCounts[m.Path]++
	}

	for path, count := range pathCounts {
		assert.Equal(t, 1, count, "path %s should appear only once, got %d", path, count)
	}
}

func TestSearch_Rg_SpecialChars(t *testing.T) {
	if RgPath() == "" {
		t.Skip("ripgrep not available")
	}
	// --fixed-strings should prevent regex interpretation.
	v := testVault(t)
	// "[daily]" contains regex metacharacters but should be treated literally.
	result, err := v.Search("[daily]", 20)
	require.NoError(t, err)
	// Should not error. May or may not find results depending on content.
	assert.NotNil(t, result)
}

// --- Integration: Search with Go fallback ---

func TestSearch_GoFallback_ContentMatch(t *testing.T) {
	// Force Go fallback by clearing rg path.
	orig := RgPath()

	SetRgPath("")
	defer SetRgPath(orig)

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

	assert.True(t, found, "Go fallback should find content match")
}

func TestSearch_GoFallback_Deduplication(t *testing.T) {
	orig := RgPath()

	SetRgPath("")
	defer SetRgPath(orig)

	v := testVault(t)
	result, err := v.Search("cold-brew", 20)
	require.NoError(t, err)

	pathCounts := make(map[string]int)
	for _, m := range result.Results {
		pathCounts[m.Path]++
	}

	for path, count := range pathCounts {
		assert.Equal(t, 1, count, "path %s should appear only once, got %d", path, count)
	}
}

func TestSearch_GoFallback_SkipsBinaryFiles(t *testing.T) {
	orig := RgPath()

	SetRgPath("")
	defer SetRgPath(orig)

	dir := t.TempDir()
	// Create a binary file containing the search term but with null bytes.
	binContent := []byte("some text with keyword\x00 and more binary\x00 data")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "binary.dat"), binContent, 0o644))
	// Create a text file with the same term.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "text.md"), []byte("has keyword here"), 0o644))

	v, err := New(dir)
	require.NoError(t, err)

	result, err := v.Search("keyword", 20)
	require.NoError(t, err)

	for _, m := range result.Results {
		if m.MatchType == "content" {
			assert.NotEqual(t, "binary.dat", m.Path, "should skip binary file")
		}
	}
}

func TestSearch_GoFallback_MaxResults(t *testing.T) {
	orig := RgPath()

	SetRgPath("")
	defer SetRgPath(orig)

	v := testVault(t)
	result, err := v.Search("e", 2)
	require.NoError(t, err)
	assert.LessOrEqual(t, result.TotalMatches, 2)
}

// --- Phase interaction tests ---

func TestSearch_FilenameMatchTakesPrecedence(t *testing.T) {
	// A file that matches by filename should not appear again as content match.
	orig := RgPath()

	SetRgPath("")
	defer SetRgPath(orig)

	dir := t.TempDir()
	// File whose name contains "report" and whose content also contains "report".
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "docs"), 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "docs/report.md"),
		[]byte("This report covers the quarterly results."),
		0o644,
	))

	v, err := New(dir)
	require.NoError(t, err)

	result, err := v.Search("report", 20)
	require.NoError(t, err)

	matches := 0

	for _, m := range result.Results {
		if m.Path == "docs/report.md" {
			matches++

			assert.Equal(t, "filename", m.MatchType)
		}
	}

	assert.Equal(t, 1, matches, "should appear exactly once as filename match")
}

func TestSearch_TagMatchNotDuplicatedByContent(t *testing.T) {
	orig := RgPath()

	SetRgPath("")
	defer SetRgPath(orig)

	dir := t.TempDir()
	content := "---\ntags:\n  - cooking\n---\n# Recipe\n\nThis is about cooking pasta.\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pasta.md"), []byte(content), 0o644))

	v, err := New(dir)
	require.NoError(t, err)

	result, err := v.Search("cooking", 20)
	require.NoError(t, err)

	matches := 0

	for _, m := range result.Results {
		if m.Path == "pasta.md" {
			matches++
		}
	}

	assert.Equal(t, 1, matches, "should appear exactly once (as tag match)")
}

func TestSearch_DefaultMaxResults(t *testing.T) {
	v := testVault(t)
	result, err := v.Search("e", 0)
	require.NoError(t, err)
	// Default is 20 max. With our small test vault we won't hit it,
	// but the function should not panic on maxResults=0.
	assert.NotNil(t, result)
}

// --- Helpers ---

func mustMarshal(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()

	data, err := json.Marshal(v)
	require.NoError(t, err)

	return data
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func containsSuffix(s string) bool {
	return len(s) >= 3 && s[len(s)-3:] == "..."
}

// --- searchContentRg edge cases ---

func TestSearchContentRg_InvalidBinary(t *testing.T) {
	// When rgPath points to a nonexistent binary, searchContentRg should
	// return nil (not panic).
	orig := rgPath
	rgPath = "/nonexistent/rg"

	defer func() { rgPath = orig }()

	matches := searchContentRg("/tmp", "query", map[string]bool{}, 10)
	assert.Nil(t, matches)
}

func TestSearchContentRg_SeenFilesSkipped(t *testing.T) {
	if RgPath() == "" {
		t.Skip("ripgrep not available")
	}

	v := testVault(t)

	// Mark all files as already seen.
	seen := make(map[string]bool)

	files := v.index.AllFiles()
	for _, f := range files {
		seen[f.Path] = true
	}

	matches := searchContentRg(v.root, "productive", seen, 20)
	assert.Empty(t, matches, "all files are seen, should return no matches")
}

// --- searchContentGo edge cases ---

func TestSearchContentGo_EmptyVault(t *testing.T) {
	dir := t.TempDir()
	matches := searchContentGo(dir, "query", nil, map[string]bool{}, 10)
	assert.Empty(t, matches)
}

func TestSearchContentGo_FileReadError(t *testing.T) {
	// File in index but deleted from disk.
	files := []FileEntry{{Path: "gone.md"}}
	matches := searchContentGo(t.TempDir(), "test", files, map[string]bool{}, 10)
	assert.Empty(t, matches)
}

// Verify both search paths produce equivalent results on the same vault.
func TestSearch_RgAndGoFallbackConsistency(t *testing.T) {
	if RgPath() == "" {
		t.Skip("ripgrep not available")
	}

	v := testVault(t)

	// Run with ripgrep.
	resultRg, err := v.Search("productive", 20)
	require.NoError(t, err)

	// Run with Go fallback.
	origRg := RgPath()

	SetRgPath("")

	resultGo, err := v.Search("productive", 20)

	SetRgPath(origRg)
	require.NoError(t, err)

	// Both should find the same file with the same match type.
	assert.Equal(t, resultRg.TotalMatches, resultGo.TotalMatches,
		"rg matches=%d, go matches=%d", resultRg.TotalMatches, resultGo.TotalMatches)

	for i := range resultRg.Results {
		assert.Equal(t, resultRg.Results[i].Path, resultGo.Results[i].Path)
		assert.Equal(t, resultRg.Results[i].MatchType, resultGo.Results[i].MatchType)
		assert.Equal(t, resultRg.Results[i].Line, resultGo.Results[i].Line)
		// Snippets may differ slightly in formatting, but both should contain the bold match.
		assert.Contains(t, resultRg.Results[i].Snippet, "**productive**",
			"rg snippet: %s", resultRg.Results[i].Snippet)
		assert.Contains(t, resultGo.Results[i].Snippet, "**productive**",
			"go snippet: %s", resultGo.Results[i].Snippet)
	}
}

// Verify SetRgPath/RgPath round-trip.
func TestSetRgPath(t *testing.T) {
	orig := RgPath()
	defer SetRgPath(orig)

	SetRgPath("/usr/bin/rg")
	assert.Equal(t, "/usr/bin/rg", RgPath())

	SetRgPath("")
	assert.Equal(t, "", RgPath())
}

// Verify interface{} isn't used anywhere by checking mustMarshal accepts concrete types.
func TestParseRgMatchLine_MalformedData(t *testing.T) {
	msg := `{"type":"match","data":"not an object"}`
	_, ok := parseRgMatchLine([]byte(msg), "/vault")
	assert.False(t, ok)
}
