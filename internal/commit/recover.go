package commit

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/vault"
)

// RecoverOptions are the writer's resources, under the writer lock.
type RecoverOptions struct {
	Paths     Paths
	VaultDirs []string
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
//  3. Intents of committed batches are dropped; intents of uncommitted
//     batches lose their staging directory, then the intent.
//  4. Only tmp/stage/* and tmp/rebuild/* are cleaned (amendment A1 §7).
//  5. Pebble catches up on committed batches it has not applied, by
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
		} else {
			r.Crashed = true
			if err := os.RemoveAll(o.Paths.StageDir(in.ID())); err != nil {
				return r, err
			}
			r.Actions = append(r.Actions, "abandoned uncommitted batch "+in.BatchID)
		}
		if err := RemoveIntent(o.Paths, in.ID(), nil); err != nil {
			return r, err
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
		b := o.Index.NewBatch()
		err := vault.Scan(o.VaultDirs, m.Vault.Start, m.Vault.End, func(loc vault.Loc, rec vault.Record) error {
			der, _, err := reader.Read(loc)
			if err != nil {
				return err
			}
			return b.AddCert(sha256.Sum256(der), index.Ref{CertID: rec.CertID, Loc: loc})
		})
		if err == nil {
			var ids [][32]byte
			ids, err = o.ChainIDs(filepath.Join(o.Paths.BatchDir(m.ID()), dataset.ChainsFile))
			for _, id := range ids {
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
		b.Close()
		if err != nil {
			return fmt.Errorf("re-applying batch %s to the index: %w", m.BatchID, err)
		}
		applied[m.Log] = m.CommitSeq
		r.Actions = append(r.Actions, "re-applied batch "+m.BatchID+" to the index")
	}
	return nil
}
