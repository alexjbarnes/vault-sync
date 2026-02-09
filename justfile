# Build variables
version := `git describe --tags --always --dirty 2>/dev/null || echo "dev"`
ldflags := "-X main.Version=" + version

# Build the binary
build:
    go build -ldflags "{{ldflags}}" -o bin/vault-sync ./cmd/vault-sync

# Run locally
run:
    go run -ldflags "{{ldflags}}" ./cmd/vault-sync

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
check: lint test build
