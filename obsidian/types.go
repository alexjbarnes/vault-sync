package obsidian

// SigninRequest is the payload for POST /user/signin.
type SigninRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// SigninResponse is returned from POST /user/signin.
type SigninResponse struct {
	Token   string `json:"token"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	License string `json:"license"`
}

// VaultListRequest is the payload for POST /vault/list.
type VaultListRequest struct {
	Token                      string `json:"token"`
	SupportedEncryptionVersion int    `json:"supported_encryption_version"`
}

// VaultListResponse is returned from POST /vault/list.
type VaultListResponse struct {
	Vaults []VaultInfo `json:"vaults"`
	Shared []VaultInfo `json:"shared"`
}

// VaultInfo represents a single vault from the vault list API response.
type VaultInfo struct {
	ID                string `json:"id"`
	Host              string `json:"host"`
	Salt              string `json:"salt"`
	EncryptionVersion int    `json:"encryption_version"`
	Name              string `json:"name"`
	Size              int64  `json:"size"`
	Password          string `json:"password"`
}

// SignoutRequest is the payload for POST /user/signout.
type SignoutRequest struct {
	Token string `json:"token"`
}

// APIError represents an error response from the Obsidian API.
type APIError struct {
	Error string `json:"error"`
	Msg   string `json:"msg"`
}

// WebSocket message types.

// InitMessage is sent as the first message after WebSocket connect.
type InitMessage struct {
	Op                string `json:"op"`
	Token             string `json:"token"`
	ID                string `json:"id"`
	KeyHash           string `json:"keyhash"`
	Version           int64  `json:"version"`
	Initial           bool   `json:"initial"`
	Device            string `json:"device"`
	EncryptionVersion int    `json:"encryption_version"`
}

// InitResponse is the server reply to an init message.
type InitResponse struct {
	Res        string `json:"res"`
	PerFileMax int    `json:"perFileMax"`
	UserID     int    `json:"userId"`
}

// ReadyMessage is sent by the server after all pending pushes are delivered.
type ReadyMessage struct {
	Op      string `json:"op"`
	Version int64  `json:"version"`
}

// PushMessage represents a file change from the server.
type PushMessage struct {
	Op      string `json:"op"`
	Path    string `json:"path"`
	Hash    string `json:"hash"`
	Size    int64  `json:"size"`
	CTime   int64  `json:"ctime"`
	MTime   int64  `json:"mtime"`
	Folder  bool   `json:"folder"`
	Deleted bool   `json:"deleted"`
	Device  string `json:"device"`
	UID     int64  `json:"uid"`
	User    int    `json:"user"`
}

// PullRequest is sent by the client to download file content.
type PullRequest struct {
	Op  string `json:"op"`
	UID int64  `json:"uid"`
}

// PullResponse is the server reply to a pull request.
type PullResponse struct {
	Size    int  `json:"size"`
	Pieces  int  `json:"pieces"`
	Deleted bool `json:"deleted"`
}

// ClientPushMessage is sent by the client to upload a file change.
type ClientPushMessage struct {
	Op          string  `json:"op"`
	Path        string  `json:"path"`
	RelatedPath *string `json:"relatedpath"`
	Extension   string  `json:"extension"`
	Hash        string  `json:"hash"`
	CTime       int64   `json:"ctime"`
	MTime       int64   `json:"mtime"`
	Folder      bool    `json:"folder"`
	Deleted     bool    `json:"deleted"`
	Size        int     `json:"size,omitempty"`
	Pieces      int     `json:"pieces,omitempty"`
}

// GenericMessage is used to decode the "op" field before dispatching.
type GenericMessage struct {
	Op  string `json:"op"`
	Res string `json:"res"`
}
