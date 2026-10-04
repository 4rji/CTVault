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
	OnSystemRoot bool     // shares a backing device with "/"
	Backing      []string // devices that really hold the data (loop/dm/md resolved)
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
	info := Info{Path: real, Mount: m, IsMountPoint: m.MountPoint == real}
	// A loop image or dm/md device stored on the system disk is the system
	// disk: compare the devices that really hold the data, not just major:minor.
	sysBacking, err := c.Probe.BackingDevices(sys)
	if err != nil {
		return info, fmt.Errorf("cannot determine the devices behind /: %w", err)
	}
	if info.Backing, err = c.Probe.BackingDevices(m); err != nil {
		return info, fmt.Errorf("cannot determine the devices behind %s: %w", m.MountPoint, err)
	}
	info.OnSystemRoot = m.MajorMinor == sys.MajorMinor ||
		slices.ContainsFunc(info.Backing, func(d string) bool { return slices.Contains(sysBacking, d) })
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
		return volErr("%s is on the same device as / (its data is stored on %s); CTVault refuses to write to the system disk",
			info.Path, strings.Join(info.Backing, ", "))
	case info.Durability == DurabilityUntested && !opts.AllowUntestedFS:
		return volErr("%s is %s, which is untested; pass --allow-untested-fs to accept weaker durability guarantees", info.Path, info.Mount.FSType)
	}
	return nil
}

// requireEmpty allows only lost+found and the leftovers of an interrupted
// init: empty layout directories, vault/DIR_ID and the temp files of the
// atomic writes. Anything else (user files, a foreign ctvault.toml, an old
// vault's segments) means the volume is not dedicated to this vault.
func requireEmpty(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	layout := map[string]bool{}
	for _, d := range LayoutDirs {
		layout[d] = true
		layout[strings.SplitN(d, "/", 2)[0]] = true
	}
	for _, e := range ents {
		name := e.Name()
		switch {
		case name == VaultIDFile:
			return volErr("%s is already an initialized CTVault root", dir)
		case name == "lost+found" || strings.HasPrefix(name, "."+VaultIDFile+".tmp-"):
			continue
		case layout[name] && e.IsDir():
			if err := requireLeftover(dir, name, layout); err != nil {
				return err
			}
		default:
			return volErr("%s is not empty (found %q)", dir, name)
		}
	}
	return nil
}

// requireLeftover walks one top-level layout directory and fails on anything
// an interrupted init could not have created.
func requireLeftover(root, top string, layout map[string]bool) error {
	return filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		dirID := "vault/" + DirIDFile
		switch {
		case d.IsDir() && layout[rel]:
			return nil
		case d.Type().IsRegular() && (rel == dirID || strings.HasPrefix(rel, "vault/."+DirIDFile+".tmp-")):
			return nil
		default:
			return volErr("%s is not empty (found %q)", root, rel)
		}
	})
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
	return createVault(info, ModeProduction, info.Durability, c.now())
}

// createVault writes the layout, vault/DIR_ID and, last, VAULT_ID. The caller
// has already applied its mode's volume policy and checked that path is empty.
func createVault(info Info, mode string, durability Durability, now time.Time) (VaultID, error) {
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
		Format: FormatVersion, VaultUUID: vaultUUID, Mode: mode, CreatedAt: now.UTC(), Durability: durability,
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
	if err := requireMode(info.Path, id, ModeProduction); err != nil {
		return id, err
	}
	// The root checks run whatever VAULT_ID says (Plan 1 review, minor 6).
	if err := requireUsable(info, InitOptions{AllowUntestedFS: id.Durability == DurabilityUntested}, true); err != nil {
		return id, err
	}
	rootVol, dirs, err := splitVolumes(id)
	if err != nil {
		return id, err
	}
	if rootVol.FSUUID != info.FSUUID || rootVol.FSType != info.Mount.FSType {
		return id, volErr("%s is filesystem %s (%s) but VAULT_ID records %s (%s)", info.Path, info.FSUUID, info.Mount.FSType, rootVol.FSUUID, rootVol.FSType)
	}
	if err := checkLayout(c.Probe, info); err != nil {
		return id, err
	}
	for _, v := range dirs {
		if err := c.checkDir(info.Path, id, v); err != nil {
			return id, err
		}
	}
	return id, nil
}

// splitVolumes requires exactly one root volume and at least one vault dir.
func splitVolumes(id VaultID) (Volume, []Volume, error) {
	var roots, dirs []Volume
	for _, v := range id.Volumes {
		switch v.Role {
		case RoleRoot:
			roots = append(roots, v)
		case RoleVaultDir:
			dirs = append(dirs, v)
		default:
			return Volume{}, nil, volErr("VAULT_ID has unknown volume role %q", v.Role)
		}
	}
	if len(roots) != 1 {
		return Volume{}, nil, volErr("VAULT_ID must list exactly one root volume, found %d", len(roots))
	}
	if len(dirs) == 0 {
		return Volume{}, nil, volErr("VAULT_ID lists no vault directory")
	}
	return roots[0], dirs, nil
}

// checkLayout requires every layout folder to be a real directory on the
// root's own filesystem, so nothing inside the vault can lead off the volume
// (Plan 1 review, minor 7).
func checkLayout(p Probe, root Info) error {
	mounts, err := p.MountInfo()
	if err != nil {
		return fmt.Errorf("%w: reading mount table: %v", ErrVolume, err)
	}
	for _, d := range LayoutDirs {
		path := filepath.Join(root.Path, d)
		fi, err := os.Lstat(path)
		switch {
		case err != nil:
			return volErr("layout folder %s is missing (%v)", path, err)
		case fi.Mode()&fs.ModeSymlink != 0:
			return volErr("layout folder %s is a symlink; CTVault refuses folders that may lead off the vault volume", path)
		case !fi.IsDir():
			return volErr("layout folder %s is not a directory", path)
		}
		m, ok := MountFor(mounts, path)
		if !ok || m.MountPoint != root.Mount.MountPoint || m.MajorMinor != root.Mount.MajorMinor {
			return volErr("layout folder %s is on a different filesystem (%s) than the vault root", path, m.MountPoint)
		}
	}
	return nil
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
	return checkDirID(vi.Path, id, v)
}

// checkDirID requires dir's DIR_ID to belong to this vault and volume entry.
func checkDirID(dir string, id VaultID, v Volume) error {
	d, err := ReadDirID(dir)
	if err != nil {
		return volErr("vault dir %s has no readable %s (%v)", dir, DirIDFile, err)
	}
	if d.VaultUUID != id.VaultUUID || d.DirID != v.DirID {
		return volErr("vault dir %s belongs to vault %s dir %s, not %s dir %s", dir, d.VaultUUID, d.DirID, id.VaultUUID, v.DirID)
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
	abs, err := filepath.Abs(dir)
	if err != nil {
		return id, err
	}
	// Check the disk before writing anything (spec §9.1): the nearest existing
	// ancestor is on the filesystem the new directory will be created on.
	anc := abs
	for {
		if _, err := os.Lstat(anc); err == nil || filepath.Dir(anc) == anc {
			break
		}
		anc = filepath.Dir(anc)
	}
	ai, err := c.Inspect(anc)
	if err != nil {
		return id, fmt.Errorf("%w: %v", ErrVolume, err)
	}
	if err := requireUsable(ai, opts, false); err != nil {
		return id, err
	}
	if err := fsutil.MkdirAllSync(abs, 0o755); err != nil {
		return id, err
	}
	vi, err := c.Inspect(abs)
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
