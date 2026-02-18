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
    go tool cover -func=coverage.out | tail -1
    go tool cover -html=coverage.out -o coverage.html
    @echo "Coverage report: coverage.html"

# Run tests with coverage for a specific package (e.g. just test-coverage-pkg ./internal/state/...)
test-coverage-pkg pkg:
    go test -coverprofile=coverage.out {{pkg}}
    go tool cover -func=coverage.out
    go tool cover -html=coverage.out -o coverage.html
    @echo "Coverage report: coverage.html"

# Run linter
lint:
    golangci-lint run

# Run linter with auto-fix
lint-fix:
    golangci-lint run --fix

# Clean build artifacts
clean:
    rm -rf bin/ coverage.out coverage.html

# Build Docker image
docker-build:
    docker build -f docker/Dockerfile -t vault-sync:{{version}} .

# Cross-compile check
cross-compile:
    GOOS=darwin go build ./...
    GOOS=windows go build ./...
    GOOS=linux go build ./...

# Install pre-commit hook
setup-hooks:
    cp scripts/pre-commit .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit
    @echo "Pre-commit hook installed"

# Quick check - lint, test, build, and cross-compile
check: lint test build cross-compile
