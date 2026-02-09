# Build variables
version := `git describe --tags --always --dirty 2>/dev/null || echo "dev"`
ldflags := "-X main.Version=" + version

# Build the sync daemon
build:
    go build -ldflags "{{ldflags}}" -o bin/vault-sync ./cmd/vault-sync

# Build the MCP server
build-mcp:
    go build -ldflags "{{ldflags}}" -o bin/vault-sync-mcp ./cmd/vault-sync-mcp

# Build both binaries
build-all: build build-mcp

# Run the sync daemon
run:
    go run -ldflags "{{ldflags}}" ./cmd/vault-sync

# Run the MCP server
run-mcp:
    go run -ldflags "{{ldflags}}" ./cmd/vault-sync-mcp

# Run all tests
test:
    go test -v -race ./...

# Run tests with coverage report
test-coverage:
    go test -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html
    @echo "Coverage report: coverage.html"

# Run linter
lint:
    golangci-lint run

# Clean build artifacts
clean:
    rm -rf bin/ coverage.out coverage.html

# Quick check - lint, test, and build
check: lint test build-all
