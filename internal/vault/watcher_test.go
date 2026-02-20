package vault

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// waitFor polls until cond returns true or the timeout expires.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}

		time.Sleep(20 * time.Millisecond)
	}

	t.Fatal("timed out waiting for condition")
}

// watchedVault creates a vault and starts the watcher in a background
// goroutine. The watcher is stopped when the test ends.
func watchedVault(t *testing.T) *Vault {
	t.Helper()
	dir := t.TempDir()

	// Seed with one file so the index is non-empty.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "notes"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "notes", "existing.md"), []byte("# Existing\n"), 0o644))

	v, err := New(dir)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	errCh := make(chan error, 1)

	go func() {
		errCh <- v.Watch(ctx)
	}()

	// Give fsnotify a moment to set up watches.
	time.Sleep(50 * time.Millisecond)

	t.Cleanup(func() {
		cancel()

		err := <-errCh
		// context.Canceled is the expected shutdown error.
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("watcher error: %v", err)
		}
	})

	return v
}

func TestWatch_NewFileIndexed(t *testing.T) {
	v := watchedVault(t)

	// Create a new file.
	abs := filepath.Join(v.Root(), "notes", "new.md")
	require.NoError(t, os.WriteFile(abs, []byte("# New Note\n"), 0o644))

	waitFor(t, 2*time.Second, func() bool {
		return v.index.Get("notes/new.md") != nil
	})

	entry := v.index.Get("notes/new.md")
	require.NotNil(t, entry)
	assert.Equal(t, "notes/new.md", entry.Path)
}

func TestWatch_ModifiedFileUpdated(t *testing.T) {
	v := watchedVault(t)

	entry := v.index.Get("notes/existing.md")
	require.NotNil(t, entry)
	origSize := entry.Size

	// Overwrite with larger content.
	abs := filepath.Join(v.Root(), "notes", "existing.md")
	require.NoError(t, os.WriteFile(abs, []byte("# Existing\n\nWith more content now.\n"), 0o644))

	waitFor(t, 2*time.Second, func() bool {
		e := v.index.Get("notes/existing.md")
		return e != nil && e.Size > origSize
	})

	entry = v.index.Get("notes/existing.md")
	require.NotNil(t, entry)
	assert.Greater(t, entry.Size, origSize)
}

func TestWatch_DeletedFileRemoved(t *testing.T) {
	v := watchedVault(t)

	require.NotNil(t, v.index.Get("notes/existing.md"))

	abs := filepath.Join(v.Root(), "notes", "existing.md")
	require.NoError(t, os.Remove(abs))

	waitFor(t, 2*time.Second, func() bool {
		return v.index.Get("notes/existing.md") == nil
	})
}

func TestWatch_NewDirAndFile(t *testing.T) {
	v := watchedVault(t)

	// Create a new directory and file inside it.
	newDir := filepath.Join(v.Root(), "journal")
	require.NoError(t, os.MkdirAll(newDir, 0o755))

	// Small delay so the watcher picks up the new directory before
	// we write files into it.
	time.Sleep(100 * time.Millisecond)

	abs := filepath.Join(newDir, "entry.md")
	require.NoError(t, os.WriteFile(abs, []byte("# Journal Entry\n"), 0o644))

	waitFor(t, 2*time.Second, func() bool {
		return v.index.Get("journal/entry.md") != nil
	})
}

func TestWatch_FrontmatterTagsParsed(t *testing.T) {
	v := watchedVault(t)

	content := "---\ntags:\n  - travel\n  - 2026\n---\n# Trip Notes\n"
	abs := filepath.Join(v.Root(), "notes", "trip.md")
	require.NoError(t, os.WriteFile(abs, []byte(content), 0o644))

	waitFor(t, 2*time.Second, func() bool {
		e := v.index.Get("notes/trip.md")
		return e != nil && len(e.Tags) > 0
	})

	entry := v.index.Get("notes/trip.md")
	require.NotNil(t, entry)
	assert.Equal(t, []string{"travel", "2026"}, entry.Tags)
}

func TestWatch_HiddenFilesIgnored(t *testing.T) {
	v := watchedVault(t)

	abs := filepath.Join(v.Root(), "notes", ".hidden.md")
	require.NoError(t, os.WriteFile(abs, []byte("secret"), 0o644))

	// Wait a bit then verify it was never indexed.
	time.Sleep(200 * time.Millisecond)
	assert.Nil(t, v.index.Get("notes/.hidden.md"))
}

func TestWatch_TempFilesIgnored(t *testing.T) {
	v := watchedVault(t)

	// Editor backup files.
	for _, name := range []string{"file.md~", "file.md.swp", ".vault-write-123", ".vault-edit-456"} {
		abs := filepath.Join(v.Root(), "notes", name)
		require.NoError(t, os.WriteFile(abs, []byte("tmp"), 0o644))
	}

	time.Sleep(200 * time.Millisecond)

	assert.Nil(t, v.index.Get("notes/file.md~"))
	assert.Nil(t, v.index.Get("notes/file.md.swp"))
	assert.Nil(t, v.index.Get("notes/.vault-write-123"))
	assert.Nil(t, v.index.Get("notes/.vault-edit-456"))
}

func TestWatch_NodeModulesIgnored(t *testing.T) {
	v := watchedVault(t)

	nmDir := filepath.Join(v.Root(), "node_modules")
	require.NoError(t, os.MkdirAll(nmDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(nmDir, "package.json"), []byte(`{}`), 0o644))

	time.Sleep(200 * time.Millisecond)
	assert.Nil(t, v.index.Get("node_modules/package.json"))
}

func TestWatch_ObsidianDirIgnored(t *testing.T) {
	v := watchedVault(t)

	obsDir := filepath.Join(v.Root(), ".obsidian", "plugins")
	require.NoError(t, os.MkdirAll(obsDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(obsDir, "test.json"), []byte(`{}`), 0o644))

	time.Sleep(200 * time.Millisecond)
	assert.Nil(t, v.index.Get(".obsidian/plugins/test.json"))
}

func TestShouldIgnore_Cases(t *testing.T) {
	dir := t.TempDir()
	v, err := New(dir)
	require.NoError(t, err)

	tests := []struct {
		name   string
		path   string
		ignore bool
	}{
		{"hidden file", filepath.Join(dir, ".hidden"), true},
		{"editor backup", filepath.Join(dir, "file.md~"), true},
		{"vim swap", filepath.Join(dir, "file.md.swp"), true},
		{"vault write temp", filepath.Join(dir, ".vault-write-abc"), true},
		{"vault edit temp", filepath.Join(dir, ".vault-edit-abc"), true},
		{"node_modules", filepath.Join(dir, "node_modules"), true},
		{"obsidian dir", filepath.Join(dir, ".obsidian", "app.json"), true},
		{"normal file", filepath.Join(dir, "notes", "hello.md"), false},
		{"normal nested", filepath.Join(dir, "a", "b", "c.md"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.ignore, v.shouldIgnore(tt.path), "shouldIgnore(%q)", tt.path)
		})
	}
}

func TestWatch_RenameUpdatesIndex(t *testing.T) {
	v := watchedVault(t)

	require.NotNil(t, v.index.Get("notes/existing.md"))

	oldAbs := filepath.Join(v.Root(), "notes", "existing.md")
	newAbs := filepath.Join(v.Root(), "notes", "renamed.md")
	require.NoError(t, os.Rename(oldAbs, newAbs))

	waitFor(t, 2*time.Second, func() bool {
		return v.index.Get("notes/existing.md") == nil && v.index.Get("notes/renamed.md") != nil
	})
}
