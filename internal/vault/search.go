package vault

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// rgPath holds the path to ripgrep if found at startup.
// Empty string means ripgrep is not available.
var rgPath string

func init() {
	path, err := exec.LookPath("rg")
	if err == nil {
		rgPath = path
	}
}

// SetRgPath overrides the ripgrep binary path. Pass "" to force the Go
// fallback. Intended for testing.
func SetRgPath(path string) {
	rgPath = path
}

// RgPath returns the current ripgrep binary path.
func RgPath() string {
	return rgPath
}

// SearchMatch is a single search result.
type SearchMatch struct {
	Path      string `json:"path"`
	MatchType string `json:"match_type"`
	Snippet   string `json:"snippet"`
	Line      int    `json:"line"`
}

// SearchResult is the response for searching the vault.
type SearchResult struct {
	Query        string        `json:"query"`
	TotalMatches int           `json:"total_matches"`
	Results      []SearchMatch `json:"results"`
}

// Search performs a case-insensitive full-text search across file names,
// frontmatter tags, and file content. When ripgrep is available, content
// search delegates to it for performance. Falls back to pure Go otherwise.
func (v *Vault) Search(query string, maxResults int) (*SearchResult, error) {
	if maxResults <= 0 {
		maxResults = 20
	}

	files := v.index.AllFiles()
	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	lowerQuery := strings.ToLower(query)

	var matches []SearchMatch

	seen := make(map[string]bool)

	// Phase 1: filename matches.
	for _, f := range files {
		if len(matches) >= maxResults {
			break
		}

		if strings.Contains(strings.ToLower(f.Path), lowerQuery) {
			matches = append(matches, SearchMatch{
				Path:      f.Path,
				MatchType: "filename",
				Snippet:   f.Path,
				Line:      1,
			})
			seen[f.Path] = true
		}
	}

	// Phase 2: tag matches.
	for _, f := range files {
		if len(matches) >= maxResults {
			break
		}

		if seen[f.Path] {
			continue
		}

		for _, tag := range f.Tags {
			if strings.Contains(strings.ToLower(tag), lowerQuery) {
				matches = append(matches, SearchMatch{
					Path:      f.Path,
					MatchType: "tag",
					Snippet:   fmt.Sprintf("tags: [%s]", strings.Join(f.Tags, ", ")),
					Line:      1,
				})
				seen[f.Path] = true

				break
			}
		}
	}

	// Phase 3: content matches.
	if len(matches) < maxResults {
		remaining := maxResults - len(matches)

		var contentMatches []SearchMatch
		if rgPath != "" {
			contentMatches = searchContentRg(v.root, query, seen, remaining)
		}
		// Fall back to Go if rg is not available or returned nothing
		// (rg returning nothing is fine, but if rg itself errored we
		// already fell back inside searchContentRg).
		if rgPath == "" {
			contentMatches = searchContentGo(v.root, lowerQuery, files, seen, remaining)
		}

		matches = append(matches, contentMatches...)
	}

	return &SearchResult{
		Query:        query,
		TotalMatches: len(matches),
		Results:      matches,
	}, nil
}

// searchContentRg shells out to ripgrep for content search.
// Returns matches for files not already in seen. On rg error (exit code 2
// or timeout), returns nil so the caller can fall back to Go.
func searchContentRg(vaultRoot, query string, seen map[string]bool, maxResults int) []SearchMatch {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	args := []string{
		"--json",
		"--ignore-case",
		"--fixed-strings",
		"--max-count", "1",
		"--glob", "!.obsidian/**",
		"--glob", "!.*",
		"--", query, vaultRoot,
	}

	cmd := exec.CommandContext(ctx, rgPath, args...) //nolint:gosec // G204: rgPath from exec.LookPath, args not shell-interpreted

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil
	}

	if err := cmd.Start(); err != nil {
		return nil
	}

	var matches []SearchMatch

	scanner := bufio.NewScanner(stdout)
	// Increase buffer for long lines.
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)

	for scanner.Scan() {
		if len(matches) >= maxResults {
			break
		}

		m, ok := parseRgMatchLine(scanner.Bytes(), vaultRoot)
		if !ok {
			continue
		}

		if seen[m.Path] {
			continue
		}

		seen[m.Path] = true
		matches = append(matches, m)
	}

	// Wait for the process to finish. Exit code 1 means no matches (not
	// an error). Exit code 2 means a real error, but we already collected
	// whatever output we got.
	_ = cmd.Wait()

	return matches
}

// rgMessage is the top-level JSON structure from ripgrep --json output.
type rgMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// rgMatchData holds the fields we need from a "match" type message.
type rgMatchData struct {
	Path       rgText       `json:"path"`
	Lines      rgText       `json:"lines"`
	LineNumber int          `json:"line_number"`
	Submatches []rgSubmatch `json:"submatches"`
}

type rgText struct {
	Text string `json:"text"`
}

type rgSubmatch struct {
	Match rgText `json:"match"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

// parseRgMatchLine parses a single line of ripgrep --json output.
// Returns the SearchMatch and true if this was a "match" type, false otherwise.
func parseRgMatchLine(line []byte, vaultRoot string) (SearchMatch, bool) {
	var msg rgMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		return SearchMatch{}, false
	}

	if msg.Type != "match" {
		return SearchMatch{}, false
	}

	var data rgMatchData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		return SearchMatch{}, false
	}

	// Convert absolute path to vault-relative, using forward slashes.
	relPath := data.Path.Text
	if strings.HasPrefix(relPath, vaultRoot) {
		relPath = strings.TrimPrefix(relPath, vaultRoot)
		relPath = strings.TrimPrefix(relPath, string(filepath.Separator))
	}

	relPath = filepath.ToSlash(relPath)

	// Build snippet from the matched line and submatch positions.
	lineText := strings.TrimRight(data.Lines.Text, "\n\r")

	var snippet string

	if len(data.Submatches) > 0 {
		sub := data.Submatches[0]
		snippet = buildSnippetFromBytes(lineText, sub.Start, sub.End)
	} else {
		snippet = truncateLine(lineText, 120)
	}

	return SearchMatch{
		Path:      relPath,
		MatchType: "content",
		Snippet:   snippet,
		Line:      data.LineNumber,
	}, true
}

// buildSnippetFromBytes creates a context snippet around a byte-offset match,
// bolding the matched text. The start and end are byte offsets into the
// original line (as reported by ripgrep).
func buildSnippetFromBytes(line string, start, end int) string {
	lineBytes := []byte(line)

	// Clamp to valid range.
	if start < 0 {
		start = 0
	}

	if end > len(lineBytes) {
		end = len(lineBytes)
	}

	if start >= end {
		return truncateLine(line, 120)
	}

	const contextBytes = 50

	// Compute the context window on the original bytes.
	winStart := start - contextBytes
	if winStart < 0 {
		winStart = 0
	}

	winEnd := end + contextBytes
	if winEnd > len(lineBytes) {
		winEnd = len(lineBytes)
	}

	before := string(lineBytes[winStart:start])
	matched := string(lineBytes[start:end])
	after := string(lineBytes[end:winEnd])

	prefix := ""
	if winStart > 0 {
		prefix = "..."
	}

	suffix := ""
	if winEnd < len(lineBytes) {
		suffix = "..."
	}

	return prefix + before + "**" + matched + "**" + after + suffix
}

// truncateLine shortens a line to maxLen characters, adding ellipsis.
func truncateLine(line string, maxLen int) string {
	if len(line) <= maxLen {
		return line
	}

	return line[:maxLen] + "..."
}

// searchContentGo is the pure Go fallback for content search.
func searchContentGo(vaultRoot, lowerQuery string, files []FileEntry, seen map[string]bool, maxResults int) []SearchMatch {
	var matches []SearchMatch
	for _, f := range files {
		if len(matches) >= maxResults {
			break
		}

		if seen[f.Path] {
			continue
		}

		abs := filepath.Join(vaultRoot, filepath.FromSlash(f.Path))

		data, err := os.ReadFile(abs) //nolint:gosec // G304: abs built from vaultRoot + validated index path
		if err != nil {
			continue
		}

		// Skip binary files: check for null bytes in the first 512 bytes.
		checkLen := len(data)
		if checkLen > 512 {
			checkLen = 512
		}

		for i := 0; i < checkLen; i++ {
			if data[i] == 0 {
				goto nextFile
			}
		}

		{
			content := string(data)

			lines := strings.Split(content, "\n")
			for lineNum, line := range lines {
				lowerLine := strings.ToLower(line)

				idx := strings.Index(lowerLine, lowerQuery)
				if idx < 0 {
					continue
				}

				snippet := buildSnippet(line, idx, len(lowerQuery))
				matches = append(matches, SearchMatch{
					Path:      f.Path,
					MatchType: "content",
					Snippet:   snippet,
					Line:      lineNum + 1,
				})
				seen[f.Path] = true

				break // one match per file
			}
		}

	nextFile:
	}

	return matches
}

// buildSnippet creates a context snippet around a match, bolding the match.
// matchStart and matchLen are byte offsets into the line string.
func buildSnippet(line string, matchStart, matchLen int) string {
	const contextChars = 50

	start := matchStart - contextChars
	if start < 0 {
		start = 0
	}

	end := matchStart + matchLen + contextChars
	if end > len(line) {
		end = len(line)
	}

	prefix := ""
	if start > 0 {
		prefix = "..."
	}

	suffix := ""
	if end < len(line) {
		suffix = "..."
	}

	before := line[start:matchStart]
	matched := line[matchStart : matchStart+matchLen]
	after := line[matchStart+matchLen : end]

	return prefix + before + "**" + matched + "**" + after + suffix
}
