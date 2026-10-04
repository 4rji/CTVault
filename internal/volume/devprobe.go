//go:build ctvault_dev

package volume

import (
	"errors"
	"fmt"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/fsutil"
)

// DevProbe is the volume policy of the ctvault_dev build (amendment A1 §1):
// vaults live only under Base, a folder on the normal disk, and are marked
// "dev" in VAULT_ID. It exists only in binaries built with -tags ctvault_dev;
// production binaries cannot construct it.
type DevProbe struct {
	Base  string // the dev base, normally DefaultDevBase(); tests use a temp folder
	Probe Probe  // mount table and filesystem UUIDs
	Now   func() time.Time
}

// DefaultDevBase is <home>/.cache/ctvault-dev, with <home> taken from the OS
// user database rather than $HOME.
func DefaultDevBase() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("looking up the current user: %w", err)
	}
	if u.HomeDir == "" {
		return "", errors.New("the current user has no home directory")
	}
	return filepath.Join(u.HomeDir, ".cache", "ctvault-dev"), nil
}

// resolve returns root's real path, requiring it to lie strictly inside the
// dev base both before and after symlinks are resolved. With create set, the
// folder (and the base) is created first.
func (p DevProbe) resolve(root string, create bool) (string, error) {
	base, err := filepath.Abs(p.Base)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if !within(abs, base) || abs == base {
		return "", volErr("%s is outside the dev base %s; dev vaults may live only there", abs, base)
	}
	if create {
		if err := fsutil.MkdirAllSync(abs, 0o700); err != nil {
			return "", err
		}
	}
	realBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", volErr("dev base %s: %v", base, err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", volErr("%s: %v", abs, err)
	}
	if !within(real, realBase) || real == realBase {
		return "", volErr("%s escapes the dev base %s (resolves to %s)", abs, realBase, real)
	}
	return real, nil
}

// devFSRefused lists filesystems that cannot hold even a dev vault.
func devFSRefused(fstype string) bool {
	switch fstype {
	case "nfs", "nfs4", "cifs", "smb3", "smbfs", "9p", "tmpfs", "ramfs":
		return true
	}
	return fstype == "fuseblk" || fstype == "fuse" || strings.HasPrefix(fstype, "fuse.")
}

// inspect describes the filesystem holding a resolved dev path.
func (p DevProbe) inspect(real string) (Info, error) {
	mounts, err := p.Probe.MountInfo()
	if err != nil {
		return Info{}, fmt.Errorf("%w: reading mount table: %v", ErrVolume, err)
	}
	m, ok := MountFor(mounts, real)
	if !ok {
		return Info{}, volErr("%s is not on any mounted filesystem", real)
	}
	if devFSRefused(m.FSType) {
		return Info{}, volErr("%s is on %s (%s); dev vaults need a local filesystem", real, m.MountPoint, m.FSType)
	}
	uuid, err := p.Probe.FSUUID(m)
	if err != nil {
		return Info{}, fmt.Errorf("%w: %v", ErrVolume, err)
	}
	return Info{Path: real, Mount: m, IsMountPoint: m.MountPoint == real, FSUUID: uuid, Durability: DurabilityDevUnsafe}, nil
}

func (p DevProbe) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Init creates a dev vault at root, which must lie inside the dev base.
func (p DevProbe) Init(root string, _ InitOptions) (VaultID, error) {
	real, err := p.resolve(root, true)
	if err != nil {
		return VaultID{}, err
	}
	info, err := p.inspect(real)
	if err != nil {
		return VaultID{}, err
	}
	if err := requireEmpty(real); err != nil {
		return VaultID{}, err
	}
	return createVault(info, ModeDev, DurabilityDevUnsafe, p.now())
}

// Check verifies a dev vault: inside the dev base, marked dev, on the same
// filesystem as recorded, with an intact layout.
func (p DevProbe) Check(root string) (VaultID, error) {
	real, err := p.resolve(root, false)
	if err != nil {
		return VaultID{}, err
	}
	id, err := ReadVaultID(real)
	if err != nil {
		return VaultID{}, volErr("%s is not an initialized CTVault root (%v)", real, err)
	}
	if err := requireMode(real, id, ModeDev); err != nil {
		return id, err
	}
	info, err := p.inspect(real)
	if err != nil {
		return id, err
	}
	rootVol, dirs, err := splitVolumes(id)
	if err != nil {
		return id, err
	}
	if rootVol.FSUUID != info.FSUUID {
		return id, volErr("%s is filesystem %s but VAULT_ID records %s", real, info.FSUUID, rootVol.FSUUID)
	}
	if err := checkLayout(p.Probe, info); err != nil {
		return id, err
	}
	for _, v := range dirs {
		if filepath.IsAbs(v.Path) {
			return id, volErr("dev vaults keep their vault directory inside the root, not at %s", v.Path)
		}
		if err := checkDirID(filepath.Join(real, v.Path), id, v); err != nil {
			return id, err
		}
	}
	return id, nil
}

// AddDir is not supported for dev vaults: they keep one vault directory.
func (p DevProbe) AddDir(root, dir string, _ InitOptions) (VaultID, error) {
	return VaultID{}, volErr("dev vaults keep a single vault directory; vault add-dir is production-only")
}
