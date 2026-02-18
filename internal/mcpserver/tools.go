// Package mcpserver registers MCP tools that expose vault operations.
// It adapts the vault package to the MCP SDK's tool handler interface.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/vault"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// logToolCall logs the start and end of a tool invocation. It returns a
// function that should be deferred to log completion with duration.
func logToolCall(logger *slog.Logger, tool string, args ...slog.Attr) func(error) {
	attrs := make([]slog.Attr, 0, len(args)+1)
	attrs = append(attrs, slog.String("tool", tool))
	attrs = append(attrs, args...)
	start := time.Now()

	return func(err error) {
		attrs = append(attrs, slog.Duration("duration", time.Since(start)))
		if err != nil {
			attrs = append(attrs, slog.String("error", err.Error()))
			logger.LogAttrs(context.Background(), slog.LevelWarn, "tool call failed", attrs...)

			return
		}

		logger.LogAttrs(context.Background(), slog.LevelInfo, "tool call", attrs...)
	}
}

// RegisterTools adds all vault tools to the given MCP server.
func RegisterTools(server *mcp.Server, v *vault.Vault, logger *slog.Logger) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "vault_list",
		Description: "List vault contents. Without a path: returns every file with metadata (path, size, modified, tags). With a path: lists one folder level deep, showing files with size/modified and folders with child counts.",
	}, listHandler(v, logger))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "vault_read",
		Description: "Read file content with optional line-range pagination. Lines are 1-indexed. Large files are auto-truncated at 200 lines unless a limit is specified.",
	}, readHandler(v, logger))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "vault_search",
		Description: "Full-text search across file names, frontmatter tags, and file content. Case-insensitive. Returns matching files with context snippets and line numbers.",
	}, searchHandler(v, logger))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "vault_write",
		Description: "Create a new file or fully replace an existing file. Uses atomic write. Cannot write to .obsidian/ directory.",
	}, writeHandler(v, logger))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "vault_edit",
		Description: "Find-and-replace edit on an existing file. The old_text must appear exactly once. Uses atomic write. Same semantics as str_replace.",
	}, editHandler(v, logger))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "vault_delete",
		Description: "Delete one or more files from the vault. Accepts an array of paths. Best-effort: each file is attempted independently, failures are reported per-item. Cannot delete directories or .obsidian/ paths.",
	}, deleteHandler(v, logger))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "vault_move",
		Description: "Move or rename a file within the vault. Creates destination parent directories automatically. Refuses to overwrite existing files. Cannot move directories or .obsidian/ paths.",
	}, moveHandler(v, logger))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "vault_copy",
		Description: "Copy a file within the vault. Creates destination parent directories automatically. Refuses to overwrite existing files. Uses atomic write. Cannot copy directories or .obsidian/ paths.",
	}, copyHandler(v, logger))
}

// --- Input types ---
// The MCP SDK infers JSON schema from these struct types via jsonschema tags.

// ListInput holds parameters for vault_list.
type ListInput struct {
	Path string `json:"path,omitempty" jsonschema:"folder path relative to vault root; omit to list all files"`
}

// listResult is the combined response for vault_list. When path is omitted,
// TotalFiles and Files are populated. When path is provided, Path, Entries,
// and TotalEntries are populated.
type listResult struct {
	// Fields for all-files mode (no path).
	TotalFiles int               `json:"total_files,omitempty"`
	Files      []vault.FileEntry `json:"files,omitempty"`

	// Fields for directory mode (with path).
	Path         string           `json:"path,omitempty"`
	Entries      []vault.DirEntry `json:"entries,omitempty"`
	TotalEntries int              `json:"total_entries,omitempty"`
}

// ReadInput holds parameters for vault_read.
type ReadInput struct {
	Path   string `json:"path" jsonschema:"required,file path relative to vault root"`
	Offset int    `json:"offset,omitempty" jsonschema:"start line (1-indexed), defaults to 1"`
	Limit  int    `json:"limit,omitempty" jsonschema:"number of lines to return, 0 means all remaining"`
}

// SearchInput holds parameters for vault_search.
type SearchInput struct {
	Query      string `json:"query" jsonschema:"required,search query"`
	MaxResults int    `json:"max_results,omitempty" jsonschema:"maximum number of results, defaults to 20"`
}

// WriteInput holds parameters for vault_write.
type WriteInput struct {
	Path       string `json:"path" jsonschema:"required,file path relative to vault root"`
	Content    string `json:"content" jsonschema:"required,full file content"`
	CreateDirs *bool  `json:"create_dirs,omitempty" jsonschema:"create parent directories if missing, defaults to true"`
}

// EditInput holds parameters for vault_edit.
type EditInput struct {
	Path    string `json:"path" jsonschema:"required,file path relative to vault root"`
	OldText string `json:"old_text" jsonschema:"required,exact text to find (must appear once)"`
	NewText string `json:"new_text" jsonschema:"required,replacement text, empty to delete"`
}

// DeleteInput holds parameters for vault_delete.
type DeleteInput struct {
	Paths []string `json:"paths" jsonschema:"required,file paths relative to vault root"`
}

// MoveInput holds parameters for vault_move.
type MoveInput struct {
	Source      string `json:"source" jsonschema:"required,source file path relative to vault root"`
	Destination string `json:"destination" jsonschema:"required,destination file path relative to vault root"`
}

// CopyInput holds parameters for vault_copy.
type CopyInput struct {
	Source      string `json:"source" jsonschema:"required,source file path relative to vault root"`
	Destination string `json:"destination" jsonschema:"required,destination file path relative to vault root"`
}

// --- Handlers ---

func listHandler(v *vault.Vault, logger *slog.Logger) mcp.ToolHandlerFor[ListInput, *listResult] {
	return func(_ context.Context, _ *mcp.CallToolRequest, input ListInput) (*mcp.CallToolResult, *listResult, error) {
		done := logToolCall(logger, "vault_list", slog.String("path", input.Path))
		if input.Path == "" {
			all := v.ListAll()
			r := &listResult{
				TotalFiles: all.TotalFiles,
				Files:      all.Files,
			}

			done(nil)

			return textResult(r), r, nil
		}

		dir, err := v.List(input.Path)
		if err != nil {
			done(err)
			return nil, nil, err
		}

		r := &listResult{
			Path:         dir.Path,
			Entries:      dir.Entries,
			TotalEntries: dir.TotalEntries,
		}

		done(nil)

		return textResult(r), r, nil
	}
}

func readHandler(v *vault.Vault, logger *slog.Logger) mcp.ToolHandlerFor[ReadInput, *vault.ReadResult] {
	return func(_ context.Context, _ *mcp.CallToolRequest, input ReadInput) (*mcp.CallToolResult, *vault.ReadResult, error) {
		done := logToolCall(logger, "vault_read", slog.String("path", input.Path))

		result, err := v.Read(input.Path, input.Offset, input.Limit)
		if err != nil {
			done(err)
			return nil, nil, err
		}

		done(nil)

		return textResult(result), result, nil
	}
}

func searchHandler(v *vault.Vault, logger *slog.Logger) mcp.ToolHandlerFor[SearchInput, *vault.SearchResult] {
	return func(_ context.Context, _ *mcp.CallToolRequest, input SearchInput) (*mcp.CallToolResult, *vault.SearchResult, error) {
		done := logToolCall(logger, "vault_search", slog.String("query", input.Query))

		result, err := v.Search(input.Query, input.MaxResults)
		if err != nil {
			done(err)
			return nil, nil, err
		}

		done(nil)

		return textResult(result), result, nil
	}
}

func writeHandler(v *vault.Vault, logger *slog.Logger) mcp.ToolHandlerFor[WriteInput, *vault.WriteResult] {
	return func(_ context.Context, _ *mcp.CallToolRequest, input WriteInput) (*mcp.CallToolResult, *vault.WriteResult, error) {
		done := logToolCall(logger, "vault_write", slog.String("path", input.Path), slog.Int("bytes", len(input.Content)))

		createDirs := true
		if input.CreateDirs != nil {
			createDirs = *input.CreateDirs
		}

		result, err := v.Write(input.Path, input.Content, createDirs)
		if err != nil {
			done(err)
			return nil, nil, err
		}

		done(nil)

		return textResult(result), result, nil
	}
}

func editHandler(v *vault.Vault, logger *slog.Logger) mcp.ToolHandlerFor[EditInput, *vault.EditResult] {
	return func(_ context.Context, _ *mcp.CallToolRequest, input EditInput) (*mcp.CallToolResult, *vault.EditResult, error) {
		done := logToolCall(logger, "vault_edit", slog.String("path", input.Path))

		result, err := v.Edit(input.Path, input.OldText, input.NewText)
		if err != nil {
			done(err)
			return nil, nil, err
		}

		done(nil)

		return textResult(result), result, nil
	}
}

func deleteHandler(v *vault.Vault, logger *slog.Logger) mcp.ToolHandlerFor[DeleteInput, *vault.DeleteBatchResult] {
	return func(_ context.Context, _ *mcp.CallToolRequest, input DeleteInput) (*mcp.CallToolResult, *vault.DeleteBatchResult, error) {
		done := logToolCall(logger, "vault_delete", slog.Int("paths", len(input.Paths)))
		if len(input.Paths) == 0 {
			err := &vault.Error{
				Code:    vault.ErrCodePathNotAllowed,
				Message: "paths must not be empty",
			}
			done(err)

			return nil, nil, err
		}

		result := v.DeleteBatch(input.Paths)

		done(nil)

		return textResult(result), result, nil
	}
}

func moveHandler(v *vault.Vault, logger *slog.Logger) mcp.ToolHandlerFor[MoveInput, *vault.MoveResult] {
	return func(_ context.Context, _ *mcp.CallToolRequest, input MoveInput) (*mcp.CallToolResult, *vault.MoveResult, error) {
		done := logToolCall(logger, "vault_move", slog.String("source", input.Source), slog.String("destination", input.Destination))

		result, err := v.Move(input.Source, input.Destination)
		if err != nil {
			done(err)
			return nil, nil, err
		}

		done(nil)

		return textResult(result), result, nil
	}
}

func copyHandler(v *vault.Vault, logger *slog.Logger) mcp.ToolHandlerFor[CopyInput, *vault.CopyResult] {
	return func(_ context.Context, _ *mcp.CallToolRequest, input CopyInput) (*mcp.CallToolResult, *vault.CopyResult, error) {
		done := logToolCall(logger, "vault_copy", slog.String("source", input.Source), slog.String("destination", input.Destination))

		result, err := v.Copy(input.Source, input.Destination)
		if err != nil {
			done(err)
			return nil, nil, err
		}

		done(nil)

		return textResult(result), result, nil
	}
}

// textResult builds a CallToolResult with JSON text content from any value.
// This provides the unstructured content alongside the structured output
// that the SDK populates automatically.
func textResult(v interface{}) *mcp.CallToolResult {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error marshaling result: %v", err)}},
			IsError: true,
		}
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}
}
