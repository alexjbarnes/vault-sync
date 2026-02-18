package vault

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// securityVault creates a vault for path security tests. It includes files
// that an attacker might try to access or escape through.
func securityVault(t *testing.T) *Vault {
	t.Helper()
	dir := t.TempDir()

	files := map[string]string{
		"notes/safe.md":       "safe content",
		".obsidian/app.json":  `{"theme":"dark"}`,
		".obsidian/core.json": `{"plugins":[]}`,
	}
	for path, content := range files {
		abs := filepath.Join(dir, filepath.FromSlash(path))
		require.NoError(t, os.MkdirAll(filepath.Dir(abs), 0o755))
		require.NoError(t, os.WriteFile(abs, []byte(content), 0o644))
	}

	v, err := New(dir)
	require.NoError(t, err)

	return v
}

// ============================================================
// Path traversal attacks
// ============================================================

// Tests a collection of malicious paths that attempt to escape the vault
// root via ".." sequences, absolute paths, and encoding tricks.
var traversalPaths = []struct {
	name string
	path string
}{
	{"basic dotdot", "../etc/passwd"},
	{"double dotdot", "../../etc/passwd"},
	{"triple dotdot", "../../../etc/passwd"},
	{"nested escape", "notes/../../etc/passwd"},
	{"deep nested escape", "notes/sub/../../../etc/passwd"},
	{"dotdot at end", "notes/.."},
	{"dotdot with trailing slash", "../"},
	{"backslash dotdot", `notes\..\..\..\etc\passwd`},
	{"dotdot with dot component", "notes/./../../../etc/passwd"},
	{"hidden dotdot in filename", "notes/..hidden/../../etc/passwd"},
}

func TestRead_TraversalAttacks(t *testing.T) {
	v := securityVault(t)
	for _, tc := range traversalPaths {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Read(tc.path, 0, 0)
			require.Error(t, err, "path %q should be rejected", tc.path)

			vErr := &Error{}
			ok := errors.As(err, &vErr)
			require.True(t, ok, "expected vault.Error, got %T: %v", err, err)
			assert.Equal(t, ErrCodePathNotAllowed, vErr.Code)
		})
	}
}

func TestList_TraversalAttacks(t *testing.T) {
	v := securityVault(t)
	for _, tc := range traversalPaths {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.List(tc.path)
			require.Error(t, err, "path %q should be rejected", tc.path)

			vErr := &Error{}
			ok := errors.As(err, &vErr)
			require.True(t, ok, "expected vault.Error, got %T: %v", err, err)
			assert.Equal(t, ErrCodePathNotAllowed, vErr.Code)
		})
	}
}

func TestWrite_TraversalAttacks(t *testing.T) {
	v := securityVault(t)
	for _, tc := range traversalPaths {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Write(tc.path, "malicious", true)
			require.Error(t, err, "path %q should be rejected", tc.path)

			vErr := &Error{}
			ok := errors.As(err, &vErr)
			require.True(t, ok, "expected vault.Error, got %T: %v", err, err)
			assert.Equal(t, ErrCodePathNotAllowed, vErr.Code)
		})
	}
}

func TestEdit_TraversalAttacks(t *testing.T) {
	v := securityVault(t)
	for _, tc := range traversalPaths {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Edit(tc.path, "old", "new")
			require.Error(t, err, "path %q should be rejected", tc.path)

			vErr := &Error{}
			ok := errors.As(err, &vErr)
			require.True(t, ok, "expected vault.Error, got %T: %v", err, err)
			assert.Equal(t, ErrCodePathNotAllowed, vErr.Code)
		})
	}
}

// ============================================================
// Symlink escape
// ============================================================

func TestRead_SymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests not reliable on Windows")
	}

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "notes"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "notes/safe.md"), []byte("safe"), 0o644))

	// Create a target file outside the vault.
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	require.NoError(t, os.WriteFile(outsideFile, []byte("top secret"), 0o644))

	// Create a symlink inside the vault pointing outside.
	symlinkPath := filepath.Join(dir, "notes/escape")
	require.NoError(t, os.Symlink(outsideDir, symlinkPath))

	v, err := New(dir)
	require.NoError(t, err)

	// Attempt to read through the symlink.
	_, err = v.Read("notes/escape/secret.txt", 0, 0)
	require.Error(t, err, "symlink escape should be blocked")

	vErr := &Error{}
	ok := errors.As(err, &vErr)
	require.True(t, ok, "expected vault.Error, got %T: %v", err, err)
	assert.Equal(t, ErrCodePathNotAllowed, vErr.Code)
}

func TestList_SymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests not reliable on Windows")
	}

	dir := t.TempDir()
	outsideDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outsideDir, "secret.txt"), []byte("secret"), 0o644))
	require.NoError(t, os.Symlink(outsideDir, filepath.Join(dir, "escape")))

	v, err := New(dir)
	require.NoError(t, err)

	_, err = v.List("escape")
	require.Error(t, err, "symlink escape should be blocked")

	vErr := &Error{}
	ok := errors.As(err, &vErr)
	require.True(t, ok, "expected vault.Error, got %T: %v", err, err)
	assert.Equal(t, ErrCodePathNotAllowed, vErr.Code)
}

func TestWrite_SymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests not reliable on Windows")
	}

	dir := t.TempDir()
	outsideDir := t.TempDir()
	require.NoError(t, os.Symlink(outsideDir, filepath.Join(dir, "escape")))

	v, err := New(dir)
	require.NoError(t, err)

	_, err = v.Write("escape/evil.txt", "malicious", false)
	require.Error(t, err, "symlink escape should be blocked")

	vErr := &Error{}
	ok := errors.As(err, &vErr)
	require.True(t, ok, "expected vault.Error, got %T: %v", err, err)
	assert.Equal(t, ErrCodePathNotAllowed, vErr.Code)

	// Verify nothing was written outside the vault.
	_, statErr := os.Stat(filepath.Join(outsideDir, "evil.txt"))
	assert.True(t, os.IsNotExist(statErr), "file should not exist outside vault")
}

func TestEdit_SymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests not reliable on Windows")
	}

	dir := t.TempDir()
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "target.md")
	require.NoError(t, os.WriteFile(outsideFile, []byte("original content"), 0o644))

	// Symlink a file directly.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "notes"), 0o755))
	require.NoError(t, os.Symlink(outsideFile, filepath.Join(dir, "notes/linked.md")))

	v, err := New(dir)
	require.NoError(t, err)

	_, err = v.Edit("notes/linked.md", "original", "hacked")
	require.Error(t, err, "symlink escape should be blocked")

	vErr := &Error{}
	ok := errors.As(err, &vErr)
	require.True(t, ok, "expected vault.Error, got %T: %v", err, err)
	assert.Equal(t, ErrCodePathNotAllowed, vErr.Code)

	// Verify original file was not modified.
	data, readErr := os.ReadFile(outsideFile)
	require.NoError(t, readErr)
	assert.Equal(t, "original content", string(data))
}

// ============================================================
// .obsidian/ directory protection
// ============================================================

func TestRead_ObsidianProtected(t *testing.T) {
	v := securityVault(t)

	paths := []string{
		".obsidian/app.json",
		".obsidian/core.json",
		".obsidian",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			_, err := v.Read(p, 0, 0)
			require.Error(t, err, "reading %s should be blocked", p)

			vErr := &Error{}
			ok := errors.As(err, &vErr)
			require.True(t, ok)
			assert.Equal(t, ErrCodePathNotAllowed, vErr.Code)
		})
	}
}

func TestList_ObsidianProtected(t *testing.T) {
	v := securityVault(t)

	paths := []string{
		".obsidian",
		".obsidian/",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			_, err := v.List(p)
			require.Error(t, err, "listing %s should be blocked", p)

			vErr := &Error{}
			ok := errors.As(err, &vErr)
			require.True(t, ok)
			assert.Equal(t, ErrCodePathNotAllowed, vErr.Code)
		})
	}
}

func TestWrite_ObsidianProtected(t *testing.T) {
	v := securityVault(t)

	paths := []string{
		".obsidian/app.json",
		".obsidian/new.json",
		".obsidian",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			_, err := v.Write(p, "{}", true)
			require.Error(t, err, "writing %s should be blocked", p)

			vErr := &Error{}
			ok := errors.As(err, &vErr)
			require.True(t, ok)
			assert.Equal(t, ErrCodePathNotAllowed, vErr.Code)
		})
	}
}

func TestEdit_ObsidianProtected(t *testing.T) {
	v := securityVault(t)

	_, err := v.Edit(".obsidian/app.json", "dark", "light")
	require.Error(t, err)

	vErr := &Error{}
	ok := errors.As(err, &vErr)
	require.True(t, ok)
	assert.Equal(t, ErrCodePathNotAllowed, vErr.Code)
}

// ============================================================
// .obsidian/ excluded from listings and index
// ============================================================

func TestListAll_ExcludesObsidian(t *testing.T) {
	v := securityVault(t)

	result := v.ListAll()
	for _, f := range result.Files {
		assert.False(t, isProtectedPath(f.Path),
			".obsidian file should not appear in ListAll: %s", f.Path)
	}
}

func TestList_RootExcludesObsidian(t *testing.T) {
	v := securityVault(t)
	result, err := v.List("")
	require.NoError(t, err)

	for _, e := range result.Entries {
		assert.NotEqual(t, ".obsidian", e.Name,
			".obsidian should not appear in root listing")
	}
}

func TestSearch_DoesNotSurfaceObsidian(t *testing.T) {
	v := securityVault(t)
	// "theme" appears in .obsidian/app.json content.
	result, err := v.Search("theme", 20)
	require.NoError(t, err)

	for _, m := range result.Results {
		assert.False(t, isProtectedPath(m.Path),
			".obsidian file should not appear in search: %s", m.Path)
	}
}

// ============================================================
// validatePath unit tests
// ============================================================

func TestValidatePath_Clean(t *testing.T) {
	clean := []string{
		"notes/hello.md",
		"a/b/c/d.txt",
		"file.md",
		"deeply/nested/path/to/file.md",
	}
	for _, p := range clean {
		assert.NoError(t, validatePath(p), "path %q should be valid", p)
	}
}

func TestValidatePath_DotDot(t *testing.T) {
	bad := []string{
		"..",
		"../foo",
		"foo/..",
		"foo/../bar",
		"foo/bar/../../../etc",
		"..hidden", // contains ".." substring
	}
	for _, p := range bad {
		err := validatePath(p)
		require.Error(t, err, "path %q should be rejected", p)

		vErr := &Error{}
		ok := errors.As(err, &vErr)
		require.True(t, ok)
		assert.Equal(t, ErrCodePathNotAllowed, vErr.Code)
	}
}

// ============================================================
// isProtectedPath unit tests
// ============================================================

func TestIsProtectedPath(t *testing.T) {
	tests := []struct {
		path      string
		protected bool
	}{
		{".obsidian", true},
		{".obsidian/app.json", true},
		{".obsidian/plugins/foo", true},
		{"notes/hello.md", false},
		{"obsidian/notes.md", false},
		{".obsidianbackup/foo", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.protected, isProtectedPath(tc.path))
		})
	}
}

// ============================================================
// resolve unit tests
// ============================================================

func TestResolve_NormalPath(t *testing.T) {
	v := securityVault(t)
	abs, err := v.resolve("notes/safe.md")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(v.root, "notes/safe.md"), abs)
}

func TestResolve_EmptyPath(t *testing.T) {
	v := securityVault(t)
	// Empty string resolves to the vault root itself.
	abs, err := v.resolve("")
	require.NoError(t, err)
	assert.Equal(t, v.root, abs)
}

func TestResolve_AbsolutePathInInput(t *testing.T) {
	v := securityVault(t)
	// filepath.Join with an absolute second arg on Unix replaces the first.
	// But validatePath catches ".." first, and resolve checks prefix after.
	// An absolute path like "/etc/passwd" doesn't contain ".." so it passes
	// validatePath, but filepath.Join(root, "/etc/passwd") on Linux gives
	// root + "/etc/passwd" (Join cleans but doesn't make absolute).
	abs, err := v.resolve("/etc/passwd")
	// This should either error or resolve to root/etc/passwd (inside vault).
	if err != nil {
		// If it errors, it should be a path escape.
		vErr := &Error{}
		ok := errors.As(err, &vErr)
		require.True(t, ok)
		assert.Equal(t, ErrCodePathNotAllowed, vErr.Code)
	} else {
		// If it doesn't error, the resolved path must be inside the vault.
		assert.True(t, pathInside(abs, v.root),
			"resolved path %s should be inside vault root %s", abs, v.root)
	}
}

func pathInside(abs, root string) bool {
	return abs == root || len(abs) > len(root) && abs[:len(root)+1] == root+string(filepath.Separator)
}
