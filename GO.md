# Go Project Patterns

Reference conventions for Go projects. Based on established patterns from existing codebases.

## Project layout

```
cmd/<name>/main.go          Entry point per binary. main() calls run() which returns error.
internal/
  config/                    Env var parsing (caarlos0/env + godotenv)
  errors/                    Sentinel errors only
  logging/                   slog factory (JSON for prod, text for dev)
  state/ or store/           Persistence layer behind an interface
  <domain packages>/         One package per concern (hash/, matcher/, pipeline/, etc.)
```

All domain logic in `internal/`. No `pkg/` directory. `cmd/` holds only entry points.

## Preferred libraries

| Purpose | Library | Notes |
|---------|---------|-------|
| Config | `caarlos0/env/v11` + `joho/godotenv` | Struct tags, .env file support |
| Logging | `log/slog` (stdlib) | JSON handler in prod, text in dev |
| HTTP router | `gin-gonic/gin` | With `gin.Recovery()` middleware |
| Testing | `stretchr/testify` | `assert` + `require` sub-packages |
| Metrics | `prometheus/client_golang` | `promauto` for registration |
| WebSocket | `coder/websocket` | nhooyr fork |
| Embedded KV | `go.etcd.io/bbolt` | For local state persistence |
| JSON peeking | `tidwall/gjson` | When full unmarshal is overkill |
| Linting | `golangci-lint` | Extensive linter set |

Do not use: Cobra, Viper, zap, logrus, zerolog, GORM, sqlx.

## Imports

Three groups separated by blank lines: stdlib, external, internal. Each group alphabetical.

```go
import (
    "context"
    "fmt"
    "log/slog"

    "github.com/gin-gonic/gin"
    "github.com/stretchr/testify/assert"

    "github.com/org/project/internal/config"
    apperrors "github.com/org/project/internal/errors"
)
```

When only two groups exist (e.g., stdlib + internal), one blank line separates them.

## Error handling

Wrap with `fmt.Errorf`, lowercase gerund phrase, `%w` verb:

```go
return fmt.Errorf("parsing config: %w", err)
return fmt.Errorf("creating directory for %s: %w", path, err)
```

Sentinel errors in `internal/errors/`:

```go
var ErrInvalidRequest = errors.New("invalid request")     // exported, Err prefix
var errResponseTimeout = fmt.Errorf("response timed out")  // unexported, err prefix
```

Wrap sentinels with context using `%w`:

```go
return fmt.Errorf("%w: file is empty", apperrors.ErrInvalidRequest)
```

Map sentinel errors to HTTP status codes in the API layer. No custom error types (no struct implementing `error`).

## Logging

`log/slog` exclusively. Injected as `*slog.Logger` parameter, not stored globally.

```go
h.logger.Info("processing image",
    slog.String("content_id", req.ContentID),
    slog.Int("file_size", len(req.File)),
)
h.logger.Warn("blocked content detected",
    slog.String("error", err.Error()),  // always slog.String for errors, not slog.Any
)
```

Messages are short lowercase phrases.

## Naming

- Constructors: `NewFoo(...)` returning `*Foo`
- Method receivers: single letter matching type (`h` for Handler, `s` for Store)
- Acronyms: Go standard (`SHA256Hasher`, `ContentID`, `VaultID`, `baseURL`)
- Enum constants: typed int with prefix (`DecisionSkip`, `DecisionDownload`)
- Unexported helpers: descriptive lowercase (`hashFile`, `validateRequest`)
- Package aliases: `apperrors` for `internal/errors` to avoid stdlib collision
- Package names: single lowercase word

## Types

- Never use `any`. `interface{}` only at JSON serialization boundaries.
- No generics.
- Pointer receivers on all mutable structs.
- Small structs by value to setters, pointer from getters (nil = not found).
- Platform-specific code uses `//go:build` constraints.

## Interfaces

Define at package boundaries where needed for testing or multiple implementations. Keep them small (1-3 methods). Define the interface in the package that uses it, or in its own file alongside the data types.

```go
// In store/store.go - interface + data types
type HashStore interface { ... }
type HashMetadata struct { ... }

// In store/memory.go - implementation
type MemoryStore struct { ... }
```

Do not create interfaces preemptively. Only when there are multiple implementations or a testing boundary requires it.

## Testing

### Framework and assertions

Use `testify/assert` for assertions, `testify/require` for setup steps where failure should abort:

```go
func TestStore_Exists(t *testing.T) {
    s := store.NewMemoryStore()
    ctx := context.Background()

    exists, err := s.Exists(ctx, "abc123")
    require.NoError(t, err)       // require for preconditions
    assert.False(t, exists)        // assert for actual test
}
```

### Test naming

`TestTypeName_MethodName_Scenario` or `TestTypeName_Scenario`:

```go
func TestSHA256Hasher_Deterministic(t *testing.T) { ... }
func TestHandler_Check_BlockedImage(t *testing.T) { ... }
func TestMemoryStore_ConcurrentAccess(t *testing.T) { ... }
func TestE2E_CheckEndpoint(t *testing.T) { ... }
```

### Table-driven tests

Use for any test with multiple cases:

```go
tests := []struct {
    name       string
    input      string
    wantStatus int
    wantError  string
}{
    {name: "valid input", input: "foo", wantStatus: 200},
    {name: "empty input", input: "", wantStatus: 400, wantError: "invalid"},
}
for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) { ... })
}
```

### Test helpers

Use `t.Helper()` on all helper functions. Prefix with `create` or `setup`:

```go
func setupTestHandler(t *testing.T) (*Handler, *store.MemoryStore) {
    t.Helper()
    ...
}

func createTestImage(width, height int, c color.Color) image.Image { ... }
```

### Mocks and fakes

Hand-rolled fakes or generated mocks (e.g., gomock/mockgen) are both acceptable. Use whichever is clearer for the test at hand.

Hand-rolled fake example:

```go
type failingHasher struct{ err error }

func (f *failingHasher) Name() string { return "failing" }

func (f *failingHasher) Hash(ctx context.Context, img image.Image) (string, error) {
    return "", f.err
}
```

Use real implementations (e.g., MemoryStore) when practical instead of mocking.

### Test mode for frameworks

Suppress framework debug output in test init:

```go
func init() {
    gin.SetMode(gin.TestMode)
}
```

## Concurrency

- `sync.RWMutex` for concurrent map access. RLock for reads, Lock for writes.
- Context cancellation check at the start of every method that accepts context:

```go
select {
case <-ctx.Done():
    return ctx.Err()
default:
}
```

- Race testing: always run `go test -race`.

## Comments

- All exported symbols get godoc comments: `// TypeName does X.`
- Comments explain WHY, not WHAT.
- Reference protocol docs or external behavior when matching third-party systems.
- Group sentinel errors with header comments: `// Client errors (4xx)`.

## Formatting

- `gofmt` standard. No custom formatter config.
- No trailing whitespace on any line, including blank lines.
- Blank lines between functions contain zero whitespace characters.
