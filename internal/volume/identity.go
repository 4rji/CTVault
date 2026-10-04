package volume

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/fsutil"
)

// Marker file names and format version (spec §9.1).
const (
	VaultIDFile   = "VAULT_ID"
	DirIDFile     = "DIR_ID"
	FormatVersion = 1
)

// Role is a volume's purpose within the vault.
type Role string

const (
	RoleRoot     Role = "root"
	RoleVaultDir Role = "vault_dir"
)

// Volume is one CTVault volume recorded in VAULT_ID. Path is relative to the
// root for directories inside it (so the drive can be remounted elsewhere)
// and absolute otherwise; for the root itself it records where init ran.
type Volume struct {
	Role   Role   `json:"role"`
	Path   string `json:"path"`
	DirID  string `json:"dir_id,omitempty"`
	FSUUID string `json:"fs_uuid"`
	FSType string `json:"fs_type"`
}

// VaultID is the content of <root>/VAULT_ID.
type VaultID struct {
	Format     int        `json:"format"`
	VaultUUID  string     `json:"vault_uuid"`
	Mode       string     `json:"mode"` // ModeProduction or ModeDev; empty (Plan 1 vaults) means production
	CreatedAt  time.Time  `json:"created_at"`
	Durability Durability `json:"durability"`
	Volumes    []Volume   `json:"volumes"`
}

// Vault modes (amendment A1 §1). A production binary only opens production
// vaults; a ctvault_dev binary only opens dev vaults.
const (
	ModeProduction = "production"
	ModeDev        = "dev"
)

// requireMode refuses a vault whose mode is not want.
func requireMode(root string, id VaultID, want string) error {
	mode := id.Mode
	if mode == "" {
		mode = ModeProduction
	}
	switch {
	case mode == want:
		return nil
	case mode == ModeDev:
		return volErr("%s is a dev vault created by a ctvault_dev build; the production binary refuses it", root)
	case mode == ModeProduction:
		return volErr("%s is a production vault; the ctvault_dev build refuses it", root)
	default:
		return volErr("%s has unknown vault mode %q", root, id.Mode)
	}
}

// DirID is the content of <vault dir>/DIR_ID.
type DirID struct {
	Format    int    `json:"format"`
	VaultUUID string `json:"vault_uuid"`
	DirID     string `json:"dir_id"`
	FSUUID    string `json:"fs_uuid"`
}

// NewUUID returns a random RFC 4122 version 4 UUID.
func NewUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, append(b, '\n'), 0o644)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// ReadVaultID reads <root>/VAULT_ID.
func ReadVaultID(root string) (VaultID, error) {
	var id VaultID
	if err := readJSON(filepath.Join(root, VaultIDFile), &id); err != nil {
		return id, err
	}
	if id.Format != FormatVersion || id.VaultUUID == "" {
		return id, fmt.Errorf("%s: unsupported format %d or missing vault_uuid", VaultIDFile, id.Format)
	}
	return id, nil
}

// ReadDirID reads <dir>/DIR_ID.
func ReadDirID(dir string) (DirID, error) {
	var d DirID
	err := readJSON(filepath.Join(dir, DirIDFile), &d)
	return d, err
}
