package commit

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/vault"
)

// RecoverOptions are the writer's resources, under the writer lock.
type RecoverOptions struct {
	Paths     Paths
	VaultDirs []string
	VaultUUID [16]byte // every segment header must carry it
	Index     *index.Index
	Codec     *vault.Codec // with every dictionary loaded
	// ChainIDs reads the chain_id column of a committed chains.parquet.
	ChainIDs func(path string) ([][32]byte, error)
}

// Recovered is the committed state after recovery.
type Recovered struct {
	Committed  []Manifest // by commit_seq
	Tail       vault.Tail // committed vault tail
	NextCertID uint64     // where cert_id allocation resumes
	Crashed    bool       // an attempt was lost; IDs resume at ID_FLOOR
	Actions    []string   // what recovery did, for the log
}

// LastSeq returns the highest committed commit_seq, 0 if none.
func (r Recovered) LastSeq() uint64 {
	if len(r.Committed) == 0 {
		return 0
	}
	return r.Committed[len(r.Committed)-1].CommitSeq
}

// Recover brings the vault back to its last committed state (spec §8.5). It
// runs at writer start, under the lock, before any work:
//
//  1. Committed batches are read and checked; a damaged one is corruption.
//  2. Vault data beyond the committed tail lifts ID_FLOOR above every
//     cert_id seen there, then is truncated.
//  3. Intents of committed batches are dropped; uncommitted batches lose
//     their staging directory, and their intents stay, marked abandoned,
//     until a later batch commits: every start until then resumes cert_id
//     allocation at ID_FLOOR, even if the writer that recovered stops
//     before committing anything (spec §8.6: IDs are never reused).
//  4. Only tmp/stage/* and tmp/rebuild/* are cleaned (amendment A1 §7),
//     plus the temp files of interrupted atomic writes in the vault's
//     metadata folders, derived files a batch's manifests do not list, and
//     a leftover state/pebble.reindex (amendment A2 §5.5).
//  5. Every committed segment must exist and carry this vault's UUID.
//  6. Pebble catches up on committed batches it has not applied, by
//     re-reading their vault ranges and chains.parquet; this is idempotent.
func Recover(o RecoverOptions) (Recovered, error) {
	var r Recovered
	committed, err := ListCommitted(o.Paths.Root)
	if err != nil {
		return r, err
	}
	r.Committed, r.NextCertID = committed, 1
	if n := len(committed); n > 0 {
		r.Tail, r.NextCertID = committed[n-1].Vault.End, committed[n-1].NextCertID
	}

	// Pebble is applied after the commit point, so it may lag the dataset but
	// never lead it. A log applied beyond its highest committed batch means
	// committed batch directories are missing: stop before changing anything.
	applied, err := o.Index.AppliedLogs()
	if err != nil {
		return r, err
	}
	highest := map[string]uint64{}
	for _, m := range committed {
		highest[m.Log] = max(highest[m.Log], m.CommitSeq)
	}
	for log, seq := range applied {
		if seq > highest[log] {
			return r, corrupt("the index has applied commit_seq %d of log %s, but its highest committed batch is %d: "+
				"committed batch directories are missing; restore them (nothing was changed)", seq, log, highest[log])
		}
	}

	intents, err := ReadIntents(o.Paths)
	if err != nil {
		return r, err
	}
	u, err := vault.InspectTail(o.VaultDirs, r.Tail)
	if err != nil {
		return r, err
	}
	if u.Bytes > 0 {
		// Every legitimate crash leaves the intent of the batch in flight,
		// written (P1) before its first append, whose vault tail is the
		// committed tail. Data nothing explains belongs to committed batches
		// whose directories are gone: never truncate it.
		explained := false
		for _, in := range intents {
			_, err := os.Stat(filepath.Join(o.Paths.BatchDir(in.ID()), ManifestFile))
			if in.VaultTail == r.Tail && err != nil {
				explained = true
			}
		}
		if !explained {
			return r, corrupt("%d bytes of vault data lie beyond the committed tail %d:%d and no batch in flight explains them: "+
				"committed batch directories may be missing; restore them (nothing was changed)", u.Bytes, r.Tail.Segment, r.Tail.Offset)
		}
		r.Crashed = true
		ids, err := LoadIDs(o.Paths.StateDir(), 1, nil)
		if err != nil {
			return r, err
		}
		if err := ids.Raise(u.MaxCertID + 1); err != nil {
			return r, err
		}
		if err := vault.Truncate(o.VaultDirs, r.Tail); err != nil {
			return r, err
		}
		r.Actions = append(r.Actions, fmt.Sprintf("truncated %d uncommitted vault bytes (highest cert_id %d)", u.Bytes, u.MaxCertID))
	}

	for _, in := range intents {
		if _, err := os.Stat(filepath.Join(o.Paths.BatchDir(in.ID()), ManifestFile)); err == nil {
			r.Actions = append(r.Actions, "batch "+in.BatchID+" was committed; finishing it")
			if err := RemoveIntent(o.Paths, in.ID(), nil); err != nil {
				return r, err
			}
			continue
		}
		r.Crashed = true
		if err := os.RemoveAll(o.Paths.StageDir(in.ID())); err != nil {
			return r, err
		}
		if !in.Abandoned {
			in.Abandoned = true
			if err := WriteIntent(o.Paths, in, nil); err != nil {
				return r, err
			}
			r.Actions = append(r.Actions, "abandoned uncommitted batch "+in.BatchID)
		}
	}

	for _, sub := range []string{"stage", "rebuild"} {
		dir := filepath.Join(o.Paths.Root, "tmp", sub)
		left, _ := os.ReadDir(dir)
		for _, e := range left {
			if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
				return r, err
			}
			r.Actions = append(r.Actions, "removed leftover tmp/"+sub+"/"+e.Name())
		}
	}

	if err := removeUnlistedDerived(o, committed, &r); err != nil {
		return r, err
	}
	for _, name := range []string{ReindexDir, probeA, probeB} {
		p := filepath.Join(o.Paths.StateDir(), name)
		if _, err := os.Stat(p); err == nil {
			if err := os.RemoveAll(p); err != nil {
				return r, err
			}
			r.Actions = append(r.Actions, "removed the leftover of an interrupted repair --reindex: state/"+name)
		}
	}

	if err := removeInterruptedWrites(o, &r); err != nil {
		return r, err
	}

	if err := vault.CheckSegments(o.VaultDirs, o.VaultUUID, r.Tail); err != nil {
		return r, err
	}

	if err := catchUp(o, committed, &r); err != nil {
		return r, err
	}

	if r.Crashed {
		floor, err := ReadFloor(o.Paths.StateDir())
		if err != nil {
			return r, err
		}
		r.NextCertID = max(r.NextCertID, floor)
	}
	return r, nil
}

// catchUp re-applies committed batches that Pebble has not recorded (spec
// §8.5: Pebble only ever lags the dataset).
func catchUp(o RecoverOptions, committed []Manifest, r *Recovered) error {
	applied := map[string]uint64{}
	var reader *vault.Reader
	defer func() {
		if reader != nil {
			reader.Close()
		}
	}()
	for _, m := range committed {
		seq, ok := applied[m.Log]
		if !ok {
			var err error
			if seq, err = o.Index.Applied(m.Log); err != nil {
				return err
			}
			applied[m.Log] = seq
		}
		if m.CommitSeq <= seq {
			continue
		}
		if reader == nil {
			var err error
			if reader, err = vault.OpenReader(o.VaultDirs, o.Codec); err != nil {
				return err
			}
		}
		if _, _, err := applyBatch(o.Index, reader, o, m); err != nil {
			return err
		}
		applied[m.Log] = m.CommitSeq
		r.Actions = append(r.Actions, "re-applied batch "+m.BatchID+" to the index")
	}
	return nil
}

// applied is what applyBatch wrote for one certificate.
type applied struct {
	sha [32]byte
	ref index.Ref
}

// applyBatch writes a committed batch to the index in one Pebble batch: its
// vault records' certificates, the chains of its chains.parquet, and its
// commit_seq as the log's applied position. It is idempotent.
func applyBatch(x *index.Index, reader *vault.Reader, o RecoverOptions, m Manifest) ([]applied, [][32]byte, error) {
	var certs []applied
	b := x.NewBatch()
	defer b.Close()
	err := vault.Scan(o.VaultDirs, m.Vault.Start, m.Vault.End, func(loc vault.Loc, rec vault.Record) error {
		der, _, err := reader.Read(loc)
		if err != nil {
			return err
		}
		a := applied{sha: sha256.Sum256(der), ref: index.Ref{CertID: rec.CertID, Loc: loc}}
		certs = append(certs, a)
		return b.AddCert(a.sha, a.ref)
	})
	var chains [][32]byte
	if err == nil {
		chains, err = o.ChainIDs(filepath.Join(o.Paths.BatchDir(m.ID()), dataset.ChainsFile))
		for _, id := range chains {
			if err == nil {
				err = b.AddChain(id)
			}
		}
	}
	if err == nil {
		err = b.SetApplied(m.Log, m.CommitSeq)
	}
	if err == nil {
		err = b.Commit()
	}
	if err != nil {
		return nil, nil, fmt.Errorf("applying batch %s to the index: %w", m.BatchID, err)
	}
	return certs, chains, nil
}

// removeInterruptedWrites deletes what a writer killed inside
// fsutil.WriteFileAtomic leaves behind: ".<name>.tmp-<digits>" files in the
// root (views.sql), state/ and its folders (intents, ID_FLOOR, heads, log
// records, incidents) and each vault folder's dict/. Pebble's folder and
// every other name are left alone. The writer lock excludes every other
// writer of these folders.
func removeInterruptedWrites(o RecoverOptions, r *Recovered) error {
	root, state := o.Paths.Root, o.Paths.StateDir()
	dirs := []string{root}
	err := filepath.WalkDir(state, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p == filepath.Join(state, "pebble") {
				return filepath.SkipDir
			}
			dirs = append(dirs, p)
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, v := range o.VaultDirs {
		dirs = append(dirs, filepath.Join(v, "dict"))
	}
	for _, dir := range dirs {
		es, err := os.ReadDir(dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, e := range es {
			if !e.Type().IsRegular() || !fsutil.IsAtomicTemp(e.Name()) {
				continue
			}
			p := filepath.Join(dir, e.Name())
			if err := os.Remove(p); err != nil {
				return err
			}
			if rel, err := filepath.Rel(root, p); err == nil && !strings.HasPrefix(rel, "..") {
				p = rel
			}
			r.Actions = append(r.Actions, "removed the leftover of an interrupted write: "+p)
		}
	}
	return nil
}

// ReindexDir is where repair --reindex builds a new index beside
// state/pebble (amendment A2 §5.6).
const ReindexDir = "pebble.reindex"

// derivedName matches a derived table's file name, <table>.p<version>.parquet.
var derivedName = regexp.MustCompile(`^[a-z][a-z0-9_]*\.p[0-9]+\.parquet$`)

// removeUnlistedDerived deletes, in committed batch directories, the derived
// files neither _COMMIT.json nor _DERIVED.json lists, and the temp files of
// an interrupted _DERIVED.json write: a rebuild killed after placing its
// files and before its commit point leaves them. They are derived and
// regenerable (amendment A2 §5.5). Other files are left alone.
func removeUnlistedDerived(o RecoverOptions, committed []Manifest, r *Recovered) error {
	for _, m := range committed {
		dir := o.Paths.BatchDir(m.ID())
		es, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		removed := false
		for _, e := range es {
			name := e.Name()
			if _, listed := m.Listed(name); listed || !e.Type().IsRegular() {
				continue
			}
			if !derivedName.MatchString(name) && !(fsutil.IsAtomicTemp(name) && strings.HasPrefix(name, "."+DerivedFile+".")) {
				continue
			}
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				return err
			}
			removed = true
			r.Actions = append(r.Actions, "removed unlisted derived file "+m.BatchID+"/"+name)
		}
		if removed {
			if err := fsutil.SyncDir(dir); err != nil {
				return err
			}
		}
	}
	return nil
}
