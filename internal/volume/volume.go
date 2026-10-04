// Package volume implements CTVault's volume-safety rules (spec §9): a vault
// lives on a dedicated, supported, identified filesystem, never on the system
// disk, and every command re-checks that identity before touching data.
package volume

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/fsutil"
)

// ErrVolume wraps every volume-check failure; the CLI maps it to exit code 4.
var ErrVolume = errors.New("volume check failed")

// LayoutDirs are created by Init (spec §4.3).
var LayoutDirs = []string{
	"state", "state/intent", "state/incidents", "state/logs",
	"vault", "vault/dict", "vault/segments",
	"dataset", "tmp", "logs",
}

// Checker performs volume checks through an injectable Probe.
type Checker struct {
	Probe Probe
	Now   func() time.Time
}

// Info describes the filesystem holding a path.
type Info struct {
	Path         string // absolute, symlinks resolved
	Mount        MountEntry
	IsMountPoint bool
	OnSystemRoot bool // same device as "/"
	FSUUID       string
	Durability   Durability
}

// Inspect resolves path and describes the filesystem that holds it.
func (c Checker) Inspect(path string) (Info, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Info{}, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return Info{}, err
	}
	mounts, err := c.Probe.MountInfo()
	if err != nil {
		return Info{}, fmt.Errorf("reading mount table: %w", err)
	}
	m, ok := MountFor(mounts, real)
	if !ok {
		return Info{}, fmt.Errorf("%s is not on any mounted filesystem", real)
	}
	sys, ok := MountFor(mounts, "/")
	if !ok {
		return Info{}, errors.New("mount table has no entry for /")
	}
	info := Info{Path: real, Mount: m, IsMountPoint: m.MountPoint == real, OnSystemRoot: m.MajorMinor == sys.MajorMinor}
	if info.Durability, err = Classify(m); err != nil {
		return info, err
	}
	info.FSUUID, err = c.Probe.FSUUID(m)
	return info, err
}

func volErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrVolume, fmt.Sprintf(format, args...))
}

// InitOptions are the user's choices for Init and AddDir.
type InitOptions struct {
	AllowUntestedFS bool
}

func requireUsable(info Info, opts InitOptions, needMountPoint bool) error {
	switch {
	case needMountPoint && !info.IsMountPoint:
		return volErr("%s is not a mount point; mount the external SSD there first", info.Path)
	case info.OnSystemRoot:
		return volErr("%s is on the same device as /; CTVault refuses to write to the system disk", info.Path)
	case info.Durability == DurabilityUntested && !opts.AllowUntestedFS:
		return volErr("%s is %s, which is untested; pass --allow-untested-fs to accept weaker durability guarantees", info.Path, info.Mount.FSType)
	}
	return nil
}

// requireEmpty allows only lost+found and leftovers of an interrupted init.
func requireEmpty(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	allowed := map[string]bool{"lost+found": true, "ctvault.toml": true}
	for _, d := range LayoutDirs {
		allowed[strings.SplitN(d, "/", 2)[0]] = true
	}
	for _, e := range ents {
		if e.Name() == VaultIDFile {
			return volErr("%s is already an initialized CTVault root", dir)
		}
		if !allowed[e.Name()] {
			return volErr("%s is not empty (found %q)", dir, e.Name())
		}
	}
	return nil
}

func (c Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Init prepares a new vault at root (spec §9.1). VAULT_ID is written last, so
// an interrupted Init can simply be run again.
func (c Checker) Init(root string, opts InitOptions) (VaultID, error) {
	info, err := c.Inspect(root)
	if err != nil {
		return VaultID{}, fmt.Errorf("%w: %v", ErrVolume, err)
	}
	if err := requireUsable(info, opts, true); err != nil {
		return VaultID{}, err
	}
	if err := requireEmpty(info.Path); err != nil {
		return VaultID{}, err
	}
	vaultUUID, err := NewUUID()
	if err != nil {
		return VaultID{}, err
	}
	dirUUID, err := NewUUID()
	if err != nil {
		return VaultID{}, err
	}
	for _, d := range LayoutDirs {
		if err := fsutil.MkdirAllSync(filepath.Join(info.Path, d), 0o755); err != nil {
			return VaultID{}, err
		}
	}
	dir := DirID{Format: FormatVersion, VaultUUID: vaultUUID, DirID: dirUUID, FSUUID: info.FSUUID}
	if err := writeJSON(filepath.Join(info.Path, "vault", DirIDFile), dir); err != nil {
		return VaultID{}, err
	}
	id := VaultID{
		Format: FormatVersion, VaultUUID: vaultUUID, CreatedAt: c.now().UTC(), Durability: info.Durability,
		Volumes: []Volume{
			{Role: RoleRoot, Path: info.Path, FSUUID: info.FSUUID, FSType: info.Mount.FSType},
			{Role: RoleVaultDir, Path: "vault", DirID: dirUUID, FSUUID: info.FSUUID, FSType: info.Mount.FSType},
		},
	}
	return id, writeJSON(filepath.Join(info.Path, VaultIDFile), id)
}

// Check verifies that root holds the vault its VAULT_ID describes and that
// every recorded volume is still the same filesystem (spec §9.2).
func (c Checker) Check(root string) (VaultID, error) {
	info, err := c.Inspect(root)
	if err != nil {
		return VaultID{}, fmt.Errorf("%w: %v", ErrVolume, err)
	}
	id, err := ReadVaultID(info.Path)
	if err != nil {
		return VaultID{}, volErr("%s is not an initialized CTVault root (%v)", info.Path, err)
	}
	for _, v := range id.Volumes {
		switch v.Role {
		case RoleRoot:
			if err := requireUsable(info, InitOptions{AllowUntestedFS: id.Durability == DurabilityUntested}, true); err != nil {
				return id, err
			}
			if v.FSUUID != info.FSUUID || v.FSType != info.Mount.FSType {
				return id, volErr("%s is filesystem %s (%s) but VAULT_ID records %s (%s)", info.Path, info.FSUUID, info.Mount.FSType, v.FSUUID, v.FSType)
			}
		case RoleVaultDir:
			if err := c.checkDir(info.Path, id, v); err != nil {
				return id, err
			}
		default:
			return id, volErr("VAULT_ID has unknown volume role %q", v.Role)
		}
	}
	return id, nil
}

func (c Checker) checkDir(root string, id VaultID, v Volume) error {
	p := v.Path
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	vi, err := c.Inspect(p)
	if err != nil {
		return fmt.Errorf("%w: vault dir %s: %v", ErrVolume, p, err)
	}
	if err := requireUsable(vi, InitOptions{AllowUntestedFS: id.Durability == DurabilityUntested}, false); err != nil {
		return err
	}
	if vi.FSUUID != v.FSUUID {
		return volErr("vault dir %s is filesystem %s but VAULT_ID records %s", p, vi.FSUUID, v.FSUUID)
	}
	d, err := ReadDirID(vi.Path)
	if err != nil {
		return volErr("vault dir %s has no readable %s (%v)", p, DirIDFile, err)
	}
	if d.VaultUUID != id.VaultUUID || d.DirID != v.DirID {
		return volErr("vault dir %s belongs to vault %s dir %s, not %s dir %s", p, d.VaultUUID, d.DirID, id.VaultUUID, v.DirID)
	}
	return nil
}

// AddDir records an additional vault directory, usually on another disk
// (spec §9.1). The caller must hold the writer lock.
func (c Checker) AddDir(root, dir string, opts InitOptions) (VaultID, error) {
	id, err := c.Check(root)
	if err != nil {
		return id, err
	}
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return id, err
	}
	vi, err := c.Inspect(dir)
	if err != nil {
		return id, fmt.Errorf("%w: %v", ErrVolume, err)
	}
	if err := requireUsable(vi, opts, false); err != nil {
		return id, err
	}
	if ents, err := os.ReadDir(vi.Path); err != nil {
		return id, err
	} else if len(ents) > 0 {
		return id, volErr("%s is not empty", vi.Path)
	}
	if slices.ContainsFunc(id.Volumes, func(v Volume) bool { return v.Path == vi.Path }) {
		return id, volErr("%s is already a vault dir", vi.Path)
	}
	for _, sub := range []string{"dict", "segments"} {
		if err := fsutil.MkdirAllSync(filepath.Join(vi.Path, sub), 0o755); err != nil {
			return id, err
		}
	}
	dirUUID, err := NewUUID()
	if err != nil {
		return id, err
	}
	if err := writeJSON(filepath.Join(vi.Path, DirIDFile), DirID{Format: FormatVersion, VaultUUID: id.VaultUUID, DirID: dirUUID, FSUUID: vi.FSUUID}); err != nil {
		return id, err
	}
	id.Volumes = append(id.Volumes, Volume{Role: RoleVaultDir, Path: vi.Path, DirID: dirUUID, FSUUID: vi.FSUUID, FSType: vi.Mount.FSType})
	if vi.Durability == DurabilityUntested {
		id.Durability = DurabilityUntested
	}
	rootInfo, err := c.Inspect(root)
	if err != nil {
		return id, err
	}
	return id, writeJSON(filepath.Join(rootInfo.Path, VaultIDFile), id)
}
