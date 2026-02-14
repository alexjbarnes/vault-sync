package obsidian

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tempVault(t *testing.T) *Vault {
	t.Helper()
	dir := t.TempDir()
	v, err := NewVault(dir)
	require.NoError(t, err)

	return v
}

// --- Vault basic operations ---

func TestVault_Dir(t *testing.T) {
	dir := t.TempDir()
	v, err := NewVault(dir)
	require.NoError(t, err)
	assert.Equal(t, dir, v.Dir())
}

func TestVault_WriteAndReadFile(t *testing.T) {
	v := tempVault(t)

	content := []byte("hello world")
	err := v.WriteFile("test.md", content, time.Time{})
	require.NoError(t, err)

	got, err := v.ReadFile("test.md")
	require.NoError(t, err)
	assert.Equal(t, content, got)
}

func TestVault_WriteCreatesParentDirs(t *testing.T) {
	v := tempVault(t)

	err := v.WriteFile("a/b/c/deep.md", []byte("deep"), time.Time{})
	require.NoError(t, err)

	got, err := v.ReadFile("a/b/c/deep.md")
	require.NoError(t, err)
	assert.Equal(t, []byte("deep"), got)
}

func TestVault_WritePreservesMtime(t *testing.T) {
	// Protocol doc line 800: adapter.writeBinary sets both atime and mtime.
	v := tempVault(t)

	mtime := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	err := v.WriteFile("test.md", []byte("data"), mtime)
	require.NoError(t, err)

	info, err := v.Stat("test.md")
	require.NoError(t, err)
	assert.Equal(t, mtime.Unix(), info.ModTime().Unix())
}

func TestVault_WriteZeroMtimeDoesNotSetTime(t *testing.T) {
	v := tempVault(t)

	before := time.Now().Add(-time.Second)
	err := v.WriteFile("test.md", []byte("data"), time.Time{})
	require.NoError(t, err)

	info, err := v.Stat("test.md")
	require.NoError(t, err)
	assert.True(t, info.ModTime().After(before), "mtime should be recent when zero time passed")
}

func TestVault_WriteEmptyFile(t *testing.T) {
	v := tempVault(t)

	err := v.WriteFile("empty.md", []byte{}, time.Time{})
	require.NoError(t, err)

	got, err := v.ReadFile("empty.md")
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestVault_ReadNonexistent(t *testing.T) {
	v := tempVault(t)

	_, err := v.ReadFile("nope.md")
	assert.Error(t, err)
}

// --- DeleteFile ---

func TestVault_DeleteFile(t *testing.T) {
	v := tempVault(t)

	err := v.WriteFile("doomed.md", []byte("bye"), time.Time{})
	require.NoError(t, err)

	err = v.DeleteFile("doomed.md")
	require.NoError(t, err)

	_, err = v.ReadFile("doomed.md")
	assert.Error(t, err)
}

func TestVault_DeleteNonexistentFile(t *testing.T) {
	v := tempVault(t)

	err := v.DeleteFile("does-not-exist.md")
	assert.NoError(t, err, "deleting nonexistent file should not error")
}

// --- DeleteEmptyDir (bug 9 fix) ---

func TestVault_DeleteEmptyDir_Empty(t *testing.T) {
	v := tempVault(t)

	err := v.MkdirAll("empty-dir")
	require.NoError(t, err)

	err = v.DeleteEmptyDir("empty-dir")
	require.NoError(t, err)

	_, err = v.Stat("empty-dir")
	assert.True(t, os.IsNotExist(err))
}

func TestVault_DeleteEmptyDir_NonEmpty(t *testing.T) {
	// Protocol doc lines 753, 965: the app refuses to delete folders
	// that still have children. DeleteEmptyDir must fail on non-empty.
	v := tempVault(t)

	err := v.WriteFile("parent/child.md", []byte("content"), time.Time{})
	require.NoError(t, err)

	err = v.DeleteEmptyDir("parent")
	require.Error(t, err, "deleting non-empty directory must fail")

	// Directory must still exist.
	_, err = v.Stat("parent")
	assert.NoError(t, err)
}

func TestVault_DeleteEmptyDir_Nonexistent(t *testing.T) {
	v := tempVault(t)

	err := v.DeleteEmptyDir("nope")
	assert.NoError(t, err, "deleting nonexistent directory should not error")
}

func TestVault_DeleteEmptyDir_NestedEmpty(t *testing.T) {
	v := tempVault(t)

	err := v.MkdirAll("a/b/c")
	require.NoError(t, err)

	// Delete innermost first.
	err = v.DeleteEmptyDir("a/b/c")
	require.NoError(t, err)

	// Now b is empty too.
	err = v.DeleteEmptyDir("a/b")
	require.NoError(t, err)

	// Now a is empty.
	err = v.DeleteEmptyDir("a")
	require.NoError(t, err)
}

// --- DeleteDir (force remove) ---

func TestVault_DeleteDir_NonEmpty(t *testing.T) {
	v := tempVault(t)

	err := v.WriteFile("dir/file.md", []byte("data"), time.Time{})
	require.NoError(t, err)

	err = v.DeleteDir("dir")
	require.NoError(t, err)

	_, err = v.Stat("dir")
	assert.True(t, os.IsNotExist(err))
}

// --- MkdirAll ---

func TestVault_MkdirAll(t *testing.T) {
	v := tempVault(t)

	err := v.MkdirAll("a/b/c")
	require.NoError(t, err)

	info, err := v.Stat("a/b/c")
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

// --- Rename ---

func TestVault_Rename(t *testing.T) {
	v := tempVault(t)

	err := v.WriteFile("old.md", []byte("content"), time.Time{})
	require.NoError(t, err)

	err = v.Rename("old.md", "new.md")
	require.NoError(t, err)

	_, err = v.ReadFile("old.md")
	require.Error(t, err)

	got, err := v.ReadFile("new.md")
	require.NoError(t, err)
	assert.Equal(t, []byte("content"), got)
}

func TestVault_RenameCreatesParentDirs(t *testing.T) {
	v := tempVault(t)

	err := v.WriteFile("src.md", []byte("data"), time.Time{})
	require.NoError(t, err)

	err = v.Rename("src.md", "new/dir/dest.md")
	require.NoError(t, err)

	got, err := v.ReadFile("new/dir/dest.md")
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), got)
}

// --- Stat ---

func TestVault_Stat(t *testing.T) {
	v := tempVault(t)

	err := v.WriteFile("file.md", []byte("12345"), time.Time{})
	require.NoError(t, err)

	info, err := v.Stat("file.md")
	require.NoError(t, err)
	assert.Equal(t, int64(5), info.Size())
}

func TestVault_StatNonexistent(t *testing.T) {
	v := tempVault(t)

	_, err := v.Stat("nope.md")
	assert.True(t, os.IsNotExist(err))
}

// --- Path traversal protection ---

func TestVault_RejectsPathTraversal(t *testing.T) {
	v := tempVault(t)

	_, err := v.ReadFile("../../etc/passwd")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path contains ..")
}

func TestVault_RejectsEmptyPath(t *testing.T) {
	v := tempVault(t)

	_, err := v.ReadFile("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty path")
}

// --- normalizePath tests ---

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no change",
			input: "notes/hello.md",
			want:  "notes/hello.md",
		},
		{
			name:  "non-breaking space U+00A0 replaced",
			input: "notes/hello\u00A0world.md",
			want:  "notes/hello world.md",
		},
		{
			name:  "narrow non-breaking space U+202F replaced",
			input: "notes/hello\u202Fworld.md",
			want:  "notes/hello world.md",
		},
		{
			name:  "multiple slashes collapsed",
			input: "notes///hello.md",
			want:  "notes/hello.md",
		},
		{
			name:  "leading slash trimmed",
			input: "/notes/hello.md",
			want:  "notes/hello.md",
		},
		{
			name:  "trailing slash trimmed",
			input: "notes/hello.md/",
			want:  "notes/hello.md",
		},
		{
			name:  "leading and trailing slashes trimmed",
			input: "///notes/hello.md///",
			want:  "notes/hello.md",
		},
		{
			name:  "NFC normalization of decomposed e-acute",
			input: "Re\u0301sume\u0301.md",
			want:  "R\u00e9sum\u00e9.md",
		},
		{
			name:  "already NFC stays the same",
			input: "R\u00e9sum\u00e9.md",
			want:  "R\u00e9sum\u00e9.md",
		},
		{
			name:  "combined: NBSP + double slash + NFD",
			input: "/notes//hello\u00A0e\u0301.md/",
			want:  "notes/hello \u00e9.md",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "just slashes",
			input: "///",
			want:  "",
		},
		{
			name:  "backslash not collapsed",
			input: "notes\\hello.md",
			want:  "notes\\hello.md",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizePath(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// --- conflictCopyPath integration with vault ---

func TestVault_ConflictCopyRename(t *testing.T) {
	// Simulate the type conflict flow: local file renamed to conflict copy.
	v := tempVault(t)

	err := v.WriteFile("notes/doc.md", []byte("local content"), time.Time{})
	require.NoError(t, err)

	cp := conflictCopyPath("notes/doc", ".md")
	err = v.Rename("notes/doc.md", cp)
	require.NoError(t, err)

	got, err := v.ReadFile(cp)
	require.NoError(t, err)
	assert.Equal(t, []byte("local content"), got)

	// Original should be gone.
	_, err = v.ReadFile("notes/doc.md")
	assert.Error(t, err)
}

// --- WriteFile overwrites existing ---

func TestVault_WriteOverwritesExisting(t *testing.T) {
	v := tempVault(t)

	err := v.WriteFile("file.md", []byte("v1"), time.Time{})
	require.NoError(t, err)

	err = v.WriteFile("file.md", []byte("v2"), time.Time{})
	require.NoError(t, err)

	got, err := v.ReadFile("file.md")
	require.NoError(t, err)
	assert.Equal(t, []byte("v2"), got)
}

// --- resolve edge cases ---

func TestVault_ResolveAbsolutePathComponent(t *testing.T) {
	v := tempVault(t)

	// filepath.Join cleans the leading slash, so "/etc/passwd" becomes
	// "etc/passwd" under the vault dir. The resolve check passes but the
	// file doesn't exist. Either way the caller gets an error.
	_, err := v.ReadFile("/etc/passwd")
	require.Error(t, err)
}

// --- Concurrent access ---

func TestVault_ConcurrentReadWrite(t *testing.T) {
	v := tempVault(t)

	err := v.WriteFile("shared.md", []byte("initial"), time.Time{})
	require.NoError(t, err)

	done := make(chan struct{}, 20)

	// 10 concurrent writers.
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()

			_ = v.WriteFile("shared.md", []byte("updated"), time.Time{})
		}()
	}

	// 10 concurrent readers.
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()

			_, _ = v.ReadFile("shared.md")
		}()
	}

	for i := 0; i < 20; i++ {
		<-done
	}

	// File should still be readable after concurrent access.
	_, err = v.ReadFile("shared.md")
	assert.NoError(t, err)
}

// --- Verify vault dir is cleaned by resolve ---

func TestVault_ResolveDoesNotAllowDotDot(t *testing.T) {
	v := tempVault(t)

	// Create a file inside the vault.
	err := v.WriteFile("legit.md", []byte("ok"), time.Time{})
	require.NoError(t, err)

	// Attempting to escape using .. should be blocked.
	_, err = v.ReadFile("../../../etc/passwd")
	assert.Error(t, err)
}

// --- Stat returns correct info for directories ---

func TestVault_StatDir(t *testing.T) {
	v := tempVault(t)

	err := v.MkdirAll("testdir")
	require.NoError(t, err)

	info, err := v.Stat("testdir")
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

// --- WriteFile with mtime on different platforms ---

func TestVault_WriteFilePreservesMtimeRoundTrip(t *testing.T) {
	v := tempVault(t)

	// Use a specific time to verify round-trip. Truncate to second
	// precision since some filesystems don't support sub-second mtime.
	mtime := time.Date(2023, 1, 15, 10, 30, 0, 0, time.UTC)
	err := v.WriteFile("ts.md", []byte("timestamped"), mtime)
	require.NoError(t, err)

	info, err := v.Stat("ts.md")
	require.NoError(t, err)

	// Compare at second precision.
	assert.Equal(t, mtime.Unix(), info.ModTime().Unix())
}

// --- Verify MkdirAll is idempotent ---

func TestVault_MkdirAllIdempotent(t *testing.T) {
	v := tempVault(t)

	err := v.MkdirAll("dir/sub")
	require.NoError(t, err)

	err = v.MkdirAll("dir/sub")
	assert.NoError(t, err, "MkdirAll should be idempotent")
}

// --- Verify resolve uses filepath.Join ---

func TestVault_ResolveJoinsCorrectly(t *testing.T) {
	dir := t.TempDir()
	v, err := NewVault(dir)
	require.NoError(t, err)

	err = v.WriteFile("sub/file.md", []byte("data"), time.Time{})
	require.NoError(t, err)

	expected := filepath.Join(dir, "sub", "file.md")
	_, err = os.Stat(expected)
	assert.NoError(t, err, "file should exist at joined path")
}
