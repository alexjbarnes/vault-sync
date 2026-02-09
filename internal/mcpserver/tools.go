// Package mcpserver registers MCP tools that expose vault operations.
// It adapts the vault package to the MCP SDK's tool handler interface.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/alexjbarnes/vault-sync/internal/vault"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RegisterTools adds all vault tools to the given MCP server.
func RegisterTools(server *mcp.Server, v *vault.Vault) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "vault_list_all",
		Description: "List every file in the vault with metadata (path, size, modified, tags). No file content. Use this as the first call to get a complete map of the vault.",
	}, listAllHandler(v))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "vault_list",
		Description: "List contents of a specific folder, one level deep. Returns files with size/modified and folders with child counts.",
	}, listHandler(v))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "vault_read",
		Description: "Read file content with optional line-range pagination. Lines are 1-indexed. Large files are auto-truncated at 200 lines unless a limit is specified.",
	}, readHandler(v))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "vault_search",
		Description: "Full-text search across file names, frontmatter tags, and file content. Case-insensitive. Returns matching files with context snippets and line numbers.",
	}, searchHandler(v))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "vault_write",
		Description: "Create a new file or fully replace an existing file. Uses atomic write. Cannot write to .obsidian/ directory.",
	}, writeHandler(v))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "vault_edit",
		Description: "Find-and-replace edit on an existing file. The old_text must appear exactly once. Uses atomic write. Same semantics as str_replace.",
	}, editHandler(v))
}

// --- Input types ---
// The MCP SDK infers JSON schema from these struct types via jsonschema tags.

// ListAllInput has no parameters.
type ListAllInput struct{}

// ListInput holds parameters for vault_list.
type ListInput struct {
	Path string `json:"path,omitempty" jsonschema:"folder path relative to vault root, defaults to root"`
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

// --- Handlers ---

func listAllHandler(v *vault.Vault) mcp.ToolHandlerFor[ListAllInput, *vault.ListAllResult] {
	return func(_ context.Context, _ *mcp.CallToolRequest, _ ListAllInput) (*mcp.CallToolResult, *vault.ListAllResult, error) {
		result := v.ListAll()
		return textResult(result), result, nil
	}
}

func listHandler(v *vault.Vault) mcp.ToolHandlerFor[ListInput, *vault.ListResult] {
	return func(_ context.Context, _ *mcp.CallToolRequest, input ListInput) (*mcp.CallToolResult, *vault.ListResult, error) {
		result, err := v.List(input.Path)
		if err != nil {
			return nil, nil, err
		}
		return textResult(result), result, nil
	}
}

func readHandler(v *vault.Vault) mcp.ToolHandlerFor[ReadInput, *vault.ReadResult] {
	return func(_ context.Context, _ *mcp.CallToolRequest, input ReadInput) (*mcp.CallToolResult, *vault.ReadResult, error) {
		result, err := v.Read(input.Path, input.Offset, input.Limit)
		if err != nil {
			return nil, nil, err
		}
		return textResult(result), result, nil
	}
}

func searchHandler(v *vault.Vault) mcp.ToolHandlerFor[SearchInput, *vault.SearchResult] {
	return func(_ context.Context, _ *mcp.CallToolRequest, input SearchInput) (*mcp.CallToolResult, *vault.SearchResult, error) {
		result, err := v.Search(input.Query, input.MaxResults)
		if err != nil {
			return nil, nil, err
		}
		return textResult(result), result, nil
	}
}

func writeHandler(v *vault.Vault) mcp.ToolHandlerFor[WriteInput, *vault.WriteResult] {
	return func(_ context.Context, _ *mcp.CallToolRequest, input WriteInput) (*mcp.CallToolResult, *vault.WriteResult, error) {
		createDirs := true
		if input.CreateDirs != nil {
			createDirs = *input.CreateDirs
		}
		result, err := v.Write(input.Path, input.Content, createDirs)
		if err != nil {
			return nil, nil, err
		}
		return textResult(result), result, nil
	}
}

func editHandler(v *vault.Vault) mcp.ToolHandlerFor[EditInput, *vault.EditResult] {
	return func(_ context.Context, _ *mcp.CallToolRequest, input EditInput) (*mcp.CallToolResult, *vault.EditResult, error) {
		result, err := v.Edit(input.Path, input.OldText, input.NewText)
		if err != nil {
			return nil, nil, err
		}
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
