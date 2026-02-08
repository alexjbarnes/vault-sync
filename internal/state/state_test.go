package state

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testDB(t *testing.T) *State {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := LoadAt(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })
	return s
}

const testVault = "vault-test-001"

// --- LoadAt / Close ---

func TestLoadAt_CreatesDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "sub", "state.db")
	s, err := LoadAt(dbPath)
	require.NoError(t, err)
	require.NoError(t, s.Close())
}

func TestLoadAt_ReopensExistingDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")

	s1, err := LoadAt(dbPath)
	require.NoError(t, err)
	require.NoError(t, s1.SetToken("persist-me"))
	require.NoError(t, s1.Close())

	s2, err := LoadAt(dbPath)
	require.NoError(t, err)
	defer s2.Close()

	assert.Equal(t, "persist-me", s2.Token())
}

// --- Token ---

func TestToken_EmptyByDefault(t *testing.T) {
	s := testDB(t)
	assert.Equal(t, "", s.Token())
}

func TestSetToken_RoundTrip(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.SetToken("tok_abc123"))
	assert.Equal(t, "tok_abc123", s.Token())
}

func TestSetToken_Overwrite(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.SetToken("old"))
	require.NoError(t, s.SetToken("new"))
	assert.Equal(t, "new", s.Token())
}

func TestSetToken_EmptyString(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.SetToken("something"))
	require.NoError(t, s.SetToken(""))
	assert.Equal(t, "", s.Token())
}

// --- VaultState ---

func TestGetVault_DefaultsToInitialSync(t *testing.T) {
	s := testDB(t)
	vs, err := s.GetVault("nonexistent")
	require.NoError(t, err)
	assert.Equal(t, int64(0), vs.Version)
	assert.True(t, vs.Initial)
}

func TestSetGetVault_RoundTrip(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.SetVault(testVault, VaultState{Version: 42, Initial: false}))

	vs, err := s.GetVault(testVault)
	require.NoError(t, err)
	assert.Equal(t, int64(42), vs.Version)
	assert.False(t, vs.Initial)
}

func TestSetVault_Overwrite(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.SetVault(testVault, VaultState{Version: 1, Initial: true}))
	require.NoError(t, s.SetVault(testVault, VaultState{Version: 100, Initial: false}))

	vs, err := s.GetVault(testVault)
	require.NoError(t, err)
	assert.Equal(t, int64(100), vs.Version)
	assert.False(t, vs.Initial)
}

func TestGetVault_IsolatedBetweenVaults(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.SetVault("v1", VaultState{Version: 10}))
	require.NoError(t, s.SetVault("v2", VaultState{Version: 20}))

	vs1, _ := s.GetVault("v1")
	vs2, _ := s.GetVault("v2")
	assert.Equal(t, int64(10), vs1.Version)
	assert.Equal(t, int64(20), vs2.Version)
}

// --- InitVaultBuckets ---

func TestInitVaultBuckets_Idempotent(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.InitVaultBuckets(testVault))
	require.NoError(t, s.InitVaultBuckets(testVault))
}

// --- LocalFile CRUD ---

func TestGetLocalFile_NilBeforeInit(t *testing.T) {
	s := testDB(t)
	lf, err := s.GetLocalFile(testVault, "nonexistent.md")
	require.NoError(t, err)
	assert.Nil(t, lf)
}

func TestGetLocalFile_NilWhenNotFound(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.InitVaultBuckets(testVault))

	lf, err := s.GetLocalFile(testVault, "missing.md")
	require.NoError(t, err)
	assert.Nil(t, lf)
}

func TestSetLocalFile_ErrorBeforeInit(t *testing.T) {
	s := testDB(t)
	err := s.SetLocalFile(testVault, LocalFile{Path: "test.md"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestSetGetLocalFile_RoundTrip(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.InitVaultBuckets(testVault))

	input := LocalFile{
		Path:     "notes/hello.md",
		MTime:    1000,
		CTime:    900,
		Size:     42,
		Hash:     "abc123",
		SyncHash: "sync456",
		SyncTime: 2000,
		Folder:   false,
	}
	require.NoError(t, s.SetLocalFile(testVault, input))

	lf, err := s.GetLocalFile(testVault, "notes/hello.md")
	require.NoError(t, err)
	require.NotNil(t, lf)
	assert.Equal(t, input, *lf)
}

func TestSetLocalFile_Overwrite(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.InitVaultBuckets(testVault))

	require.NoError(t, s.SetLocalFile(testVault, LocalFile{Path: "a.md", Size: 1}))
	require.NoError(t, s.SetLocalFile(testVault, LocalFile{Path: "a.md", Size: 99}))

	lf, err := s.GetLocalFile(testVault, "a.md")
	require.NoError(t, err)
	assert.Equal(t, int64(99), lf.Size)
}

func TestSetLocalFile_Folder(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.InitVaultBuckets(testVault))

	require.NoError(t, s.SetLocalFile(testVault, LocalFile{Path: "folder", Folder: true}))

	lf, err := s.GetLocalFile(testVault, "folder")
	require.NoError(t, err)
	assert.True(t, lf.Folder)
}

func TestDeleteLocalFile(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.InitVaultBuckets(testVault))

	require.NoError(t, s.SetLocalFile(testVault, LocalFile{Path: "gone.md", Size: 10}))
	require.NoError(t, s.DeleteLocalFile(testVault, "gone.md"))

	lf, err := s.GetLocalFile(testVault, "gone.md")
	require.NoError(t, err)
	assert.Nil(t, lf)
}

func TestDeleteLocalFile_NonexistentIsNoOp(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.InitVaultBuckets(testVault))
	require.NoError(t, s.DeleteLocalFile(testVault, "never-existed.md"))
}

func TestDeleteLocalFile_BeforeInit(t *testing.T) {
	s := testDB(t)
	// No error -- bucket doesn't exist, nothing to delete.
	require.NoError(t, s.DeleteLocalFile(testVault, "x.md"))
}

func TestAllLocalFiles_Empty(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.InitVaultBuckets(testVault))

	all, err := s.AllLocalFiles(testVault)
	require.NoError(t, err)
	assert.Empty(t, all)
}

func TestAllLocalFiles_ReturnsAll(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.InitVaultBuckets(testVault))

	require.NoError(t, s.SetLocalFile(testVault, LocalFile{Path: "a.md", Size: 1}))
	require.NoError(t, s.SetLocalFile(testVault, LocalFile{Path: "b.md", Size: 2}))
	require.NoError(t, s.SetLocalFile(testVault, LocalFile{Path: "c/d.md", Size: 3}))

	all, err := s.AllLocalFiles(testVault)
	require.NoError(t, err)
	require.Len(t, all, 3)
	assert.Equal(t, int64(1), all["a.md"].Size)
	assert.Equal(t, int64(2), all["b.md"].Size)
	assert.Equal(t, int64(3), all["c/d.md"].Size)
}

func TestAllLocalFiles_BeforeInit(t *testing.T) {
	s := testDB(t)
	all, err := s.AllLocalFiles(testVault)
	require.NoError(t, err)
	assert.Empty(t, all)
}

func TestAllLocalFiles_ExcludesDeletedEntries(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.InitVaultBuckets(testVault))

	require.NoError(t, s.SetLocalFile(testVault, LocalFile{Path: "keep.md", Size: 1}))
	require.NoError(t, s.SetLocalFile(testVault, LocalFile{Path: "remove.md", Size: 2}))
	require.NoError(t, s.DeleteLocalFile(testVault, "remove.md"))

	all, err := s.AllLocalFiles(testVault)
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.Contains(t, all, "keep.md")
}

// --- ServerFile CRUD ---

func TestGetServerFile_NilBeforeInit(t *testing.T) {
	s := testDB(t)
	sf, err := s.GetServerFile(testVault, "x.md")
	require.NoError(t, err)
	assert.Nil(t, sf)
}

func TestGetServerFile_NilWhenNotFound(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.InitVaultBuckets(testVault))

	sf, err := s.GetServerFile(testVault, "missing.md")
	require.NoError(t, err)
	assert.Nil(t, sf)
}

func TestSetServerFile_ErrorBeforeInit(t *testing.T) {
	s := testDB(t)
	err := s.SetServerFile(testVault, ServerFile{Path: "test.md"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestSetGetServerFile_RoundTrip(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.InitVaultBuckets(testVault))

	input := ServerFile{
		Path:   "notes/hello.md",
		Hash:   "hash789",
		UID:    12345,
		MTime:  1000,
		CTime:  900,
		Size:   42,
		Folder: false,
		Device: "device-abc",
	}
	require.NoError(t, s.SetServerFile(testVault, input))

	sf, err := s.GetServerFile(testVault, "notes/hello.md")
	require.NoError(t, err)
	require.NotNil(t, sf)
	assert.Equal(t, input, *sf)
}

func TestSetServerFile_Overwrite(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.InitVaultBuckets(testVault))

	require.NoError(t, s.SetServerFile(testVault, ServerFile{Path: "a.md", UID: 1}))
	require.NoError(t, s.SetServerFile(testVault, ServerFile{Path: "a.md", UID: 99}))

	sf, err := s.GetServerFile(testVault, "a.md")
	require.NoError(t, err)
	assert.Equal(t, int64(99), sf.UID)
}

func TestDeleteServerFile(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.InitVaultBuckets(testVault))

	require.NoError(t, s.SetServerFile(testVault, ServerFile{Path: "gone.md", UID: 1}))
	require.NoError(t, s.DeleteServerFile(testVault, "gone.md"))

	sf, err := s.GetServerFile(testVault, "gone.md")
	require.NoError(t, err)
	assert.Nil(t, sf)
}

func TestDeleteServerFile_NonexistentIsNoOp(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.InitVaultBuckets(testVault))
	require.NoError(t, s.DeleteServerFile(testVault, "never-existed.md"))
}

func TestDeleteServerFile_BeforeInit(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.DeleteServerFile(testVault, "x.md"))
}

func TestAllServerFiles_Empty(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.InitVaultBuckets(testVault))

	all, err := s.AllServerFiles(testVault)
	require.NoError(t, err)
	assert.Empty(t, all)
}

func TestAllServerFiles_ReturnsAll(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.InitVaultBuckets(testVault))

	require.NoError(t, s.SetServerFile(testVault, ServerFile{Path: "a.md", UID: 1}))
	require.NoError(t, s.SetServerFile(testVault, ServerFile{Path: "b.md", UID: 2}))

	all, err := s.AllServerFiles(testVault)
	require.NoError(t, err)
	require.Len(t, all, 2)
	assert.Equal(t, int64(1), all["a.md"].UID)
	assert.Equal(t, int64(2), all["b.md"].UID)
}

func TestAllServerFiles_BeforeInit(t *testing.T) {
	s := testDB(t)
	all, err := s.AllServerFiles(testVault)
	require.NoError(t, err)
	assert.Empty(t, all)
}

// --- Vault isolation ---

func TestLocalFiles_IsolatedBetweenVaults(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.InitVaultBuckets("v1"))
	require.NoError(t, s.InitVaultBuckets("v2"))

	require.NoError(t, s.SetLocalFile("v1", LocalFile{Path: "shared.md", Size: 1}))
	require.NoError(t, s.SetLocalFile("v2", LocalFile{Path: "shared.md", Size: 2}))

	lf1, _ := s.GetLocalFile("v1", "shared.md")
	lf2, _ := s.GetLocalFile("v2", "shared.md")
	assert.Equal(t, int64(1), lf1.Size)
	assert.Equal(t, int64(2), lf2.Size)
}

func TestServerFiles_IsolatedBetweenVaults(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.InitVaultBuckets("v1"))
	require.NoError(t, s.InitVaultBuckets("v2"))

	require.NoError(t, s.SetServerFile("v1", ServerFile{Path: "shared.md", UID: 10}))
	require.NoError(t, s.SetServerFile("v2", ServerFile{Path: "shared.md", UID: 20}))

	sf1, _ := s.GetServerFile("v1", "shared.md")
	sf2, _ := s.GetServerFile("v2", "shared.md")
	assert.Equal(t, int64(10), sf1.UID)
	assert.Equal(t, int64(20), sf2.UID)
}
