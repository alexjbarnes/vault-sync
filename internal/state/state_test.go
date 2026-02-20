package state

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
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
	assert.Empty(t, s.Token())
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
	assert.Empty(t, s.Token())
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

// --- Corrupt data / error branches ---

// putRaw writes raw bytes into a bbolt bucket, bypassing JSON marshaling.
// Used to inject corrupt data that triggers unmarshal errors.
func putRaw(t *testing.T, s *State, bucket []byte, key, value string) {
	t.Helper()

	err := s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucket)
		if err != nil {
			return err
		}

		return b.Put([]byte(key), []byte(value))
	})
	require.NoError(t, err)
}

func TestGetVault_CorruptJSON(t *testing.T) {
	s := testDB(t)
	putRaw(t, s, vaultMetaBucket("bad"), "state", "not-json{{{")

	_, err := s.GetVault("bad")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}

func TestAllLocalFiles_CorruptJSON(t *testing.T) {
	s := testDB(t)
	putRaw(t, s, vaultLocalBucket(testVault), "corrupt.md", "%%%bad")

	_, err := s.AllLocalFiles(testVault)
	require.Error(t, err)
}

func TestAllServerFiles_CorruptJSON(t *testing.T) {
	s := testDB(t)
	putRaw(t, s, vaultServerBucket(testVault), "corrupt.md", "%%%bad")

	_, err := s.AllServerFiles(testVault)
	require.Error(t, err)
}

func TestGetLocalFile_CorruptJSON(t *testing.T) {
	s := testDB(t)
	putRaw(t, s, vaultLocalBucket(testVault), "bad.md", "not-json")

	_, err := s.GetLocalFile(testVault, "bad.md")
	require.Error(t, err)
}

func TestGetServerFile_CorruptJSON(t *testing.T) {
	s := testDB(t)
	putRaw(t, s, vaultServerBucket(testVault), "bad.md", "not-json")

	_, err := s.GetServerFile(testVault, "bad.md")
	require.Error(t, err)
}

func TestGetVault_BucketExistsButNoStateKey(t *testing.T) {
	s := testDB(t)
	// Create the meta bucket without writing the "state" key.
	putRaw(t, s, vaultMetaBucket("empty-meta"), "other-key", "irrelevant")

	vs, err := s.GetVault("empty-meta")
	require.NoError(t, err)
	assert.Equal(t, int64(0), vs.Version)
	assert.True(t, vs.Initial)
}

func TestLoadAt_InvalidPath(t *testing.T) {
	// /dev/null is not a directory, so MkdirAll for a subpath should fail.
	_, err := LoadAt("/dev/null/sub/state.db")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creating state directory")
}

// --- OAuth Token CRUD ---

func TestSaveGetOAuthToken_RoundTrip(t *testing.T) {
	s := testDB(t)
	tok := models.OAuthToken{
		Token:       "tok_abc",
		TokenHash:   "abc123hash",
		Kind:        "access",
		UserID:      "user1",
		Resource:    "https://example.com",
		Scopes:      []string{"read", "write"},
		ExpiresAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		RefreshHash: "ref_xyz_hash",
		ClientID:    "client1",
	}
	require.NoError(t, s.SaveOAuthToken(tok))

	all, err := s.AllOAuthTokens()
	require.NoError(t, err)
	require.Len(t, all, 1)

	got := all[0]
	// Raw secrets are cleared before persistence.
	assert.Empty(t, got.Token)
	assert.Empty(t, got.RefreshToken)
	assert.Equal(t, "abc123hash", got.TokenHash)
	assert.Equal(t, "access", got.Kind)
	assert.Equal(t, "user1", got.UserID)
	assert.Equal(t, "https://example.com", got.Resource)
	assert.Equal(t, []string{"read", "write"}, got.Scopes)
	assert.Equal(t, "ref_xyz_hash", got.RefreshHash)
	assert.Equal(t, "client1", got.ClientID)
}

func TestGetOAuthToken_NotFound(t *testing.T) {
	s := testDB(t)

	got, err := s.GetOAuthToken("nonexistent")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestSaveOAuthToken_Overwrite(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.SaveOAuthToken(models.OAuthToken{TokenHash: "hash1", UserID: "old"}))
	require.NoError(t, s.SaveOAuthToken(models.OAuthToken{TokenHash: "hash1", UserID: "new"}))

	all, err := s.AllOAuthTokens()
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.Equal(t, "new", all[0].UserID)
}

func TestDeleteOAuthToken(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.SaveOAuthToken(models.OAuthToken{TokenHash: "hash_del", UserID: "u1"}))
	require.NoError(t, s.DeleteOAuthToken("hash_del"))

	all, err := s.AllOAuthTokens()
	require.NoError(t, err)
	assert.Empty(t, all)
}

func TestDeleteOAuthToken_NonexistentIsNoOp(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.DeleteOAuthToken("nonexistent-hash"))
}

func TestAllOAuthTokens_Empty(t *testing.T) {
	s := testDB(t)

	tokens, err := s.AllOAuthTokens()
	require.NoError(t, err)
	assert.Empty(t, tokens)
}

func TestAllOAuthTokens_ReturnsAll(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.SaveOAuthToken(models.OAuthToken{TokenHash: "h1", UserID: "u1"}))
	require.NoError(t, s.SaveOAuthToken(models.OAuthToken{TokenHash: "h2", UserID: "u2"}))
	require.NoError(t, s.SaveOAuthToken(models.OAuthToken{TokenHash: "h3", UserID: "u3"}))

	tokens, err := s.AllOAuthTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 3)
}

func TestAllOAuthTokens_ExcludesDeleted(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.SaveOAuthToken(models.OAuthToken{TokenHash: "keep_hash", UserID: "u1"}))
	require.NoError(t, s.SaveOAuthToken(models.OAuthToken{TokenHash: "remove_hash", UserID: "u2"}))
	require.NoError(t, s.DeleteOAuthToken("remove_hash"))

	tokens, err := s.AllOAuthTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "keep_hash", tokens[0].TokenHash)
}

func TestAllOAuthTokens_CorruptJSON(t *testing.T) {
	s := testDB(t)
	putRaw(t, s, oauthTokensBucket, "bad-tok", "%%%corrupt")

	_, err := s.AllOAuthTokens()
	require.Error(t, err)
}

func TestGetOAuthToken_CorruptJSON(t *testing.T) {
	s := testDB(t)
	// Insert corrupt data under the hashed key that GetOAuthToken will look up.
	putRaw(t, s, oauthTokensBucket, string(tokenKeyHash("bad-tok")), "not-json")

	_, err := s.GetOAuthToken("bad-tok")
	require.Error(t, err)
}

// --- OAuth Client CRUD ---

func TestSaveGetOAuthClient_RoundTrip(t *testing.T) {
	s := testDB(t)
	client := models.OAuthClient{
		ClientID:     "client_abc",
		ClientName:   "Test App",
		RedirectURIs: []string{"https://example.com/callback"},
	}
	require.NoError(t, s.SaveOAuthClient(client))

	got, err := s.GetOAuthClient("client_abc")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, client, *got)
}

func TestGetOAuthClient_NotFound(t *testing.T) {
	s := testDB(t)

	got, err := s.GetOAuthClient("nonexistent")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestSaveOAuthClient_Overwrite(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.SaveOAuthClient(models.OAuthClient{ClientID: "c1", ClientName: "old"}))
	require.NoError(t, s.SaveOAuthClient(models.OAuthClient{ClientID: "c1", ClientName: "new"}))

	got, err := s.GetOAuthClient("c1")
	require.NoError(t, err)
	assert.Equal(t, "new", got.ClientName)
}

func TestAllOAuthClients_Empty(t *testing.T) {
	s := testDB(t)

	clients, err := s.AllOAuthClients()
	require.NoError(t, err)
	assert.Empty(t, clients)
}

func TestAllOAuthClients_ReturnsAll(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.SaveOAuthClient(models.OAuthClient{ClientID: "c1"}))
	require.NoError(t, s.SaveOAuthClient(models.OAuthClient{ClientID: "c2"}))

	clients, err := s.AllOAuthClients()
	require.NoError(t, err)
	require.Len(t, clients, 2)
}

func TestAllOAuthClients_CorruptJSON(t *testing.T) {
	s := testDB(t)
	putRaw(t, s, oauthClientBucket, "bad-client", "%%%corrupt")

	_, err := s.AllOAuthClients()
	require.Error(t, err)
}

func TestGetOAuthClient_CorruptJSON(t *testing.T) {
	s := testDB(t)
	putRaw(t, s, oauthClientBucket, "bad-client", "not-json")

	_, err := s.GetOAuthClient("bad-client")
	require.Error(t, err)
}

func TestOAuthClientCount_Zero(t *testing.T) {
	s := testDB(t)
	assert.Equal(t, 0, s.OAuthClientCount())
}

func TestOAuthClientCount_AfterInserts(t *testing.T) {
	s := testDB(t)
	require.NoError(t, s.SaveOAuthClient(models.OAuthClient{ClientID: "c1"}))
	require.NoError(t, s.SaveOAuthClient(models.OAuthClient{ClientID: "c2"}))
	require.NoError(t, s.SaveOAuthClient(models.OAuthClient{ClientID: "c3"}))
	assert.Equal(t, 3, s.OAuthClientCount())
}

// --- API Keys ---

func TestSaveAPIKey_RoundTrip(t *testing.T) {
	s := testDB(t)

	ak := models.APIKey{UserID: "alice"}
	require.NoError(t, s.SaveAPIKey("hash1", ak))

	keys, err := s.AllAPIKeys()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "alice", keys["hash1"].UserID)
}

func TestDeleteAPIKey(t *testing.T) {
	s := testDB(t)

	require.NoError(t, s.SaveAPIKey("hash1", models.APIKey{UserID: "alice"}))
	require.NoError(t, s.DeleteAPIKey("hash1"))

	keys, err := s.AllAPIKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestAllAPIKeys_Empty(t *testing.T) {
	s := testDB(t)

	keys, err := s.AllAPIKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestSaveAPIKey_Overwrite(t *testing.T) {
	s := testDB(t)

	require.NoError(t, s.SaveAPIKey("hash1", models.APIKey{UserID: "alice"}))
	require.NoError(t, s.SaveAPIKey("hash1", models.APIKey{UserID: "bob"}))

	keys, err := s.AllAPIKeys()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "bob", keys["hash1"].UserID)
}

func TestAllAPIKeys_Multiple(t *testing.T) {
	s := testDB(t)

	require.NoError(t, s.SaveAPIKey("h1", models.APIKey{UserID: "alice"}))
	require.NoError(t, s.SaveAPIKey("h2", models.APIKey{UserID: "bob"}))

	keys, err := s.AllAPIKeys()
	require.NoError(t, err)
	require.Len(t, keys, 2)
	assert.Equal(t, "alice", keys["h1"].UserID)
	assert.Equal(t, "bob", keys["h2"].UserID)
}
