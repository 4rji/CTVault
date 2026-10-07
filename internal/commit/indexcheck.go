package commit

import (
	"crypto/sha256"
	"maps"
	"path/filepath"
	"slices"

	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/vault"
)

// IndexCheck is what CheckIndex compares an index with: the committed
// batches, read from the vault and chains.parquet, the authority.
type IndexCheck struct {
	Paths     Paths
	VaultDirs []string
	Codec     *vault.Codec // with every dictionary loaded
	ChainIDs  func(path string) ([][32]byte, error)
	Committed []Manifest // in commit_seq order
	// Live marks the writer's own index, which may lag the commits by whole
	// batches (spec §8.5): a batch past applied/<log> is pending, not
	// damage. A rebuilt index must hold every batch.
	Live     bool
	Progress func(done, total int) // after each batch; may be nil
}

// IndexReport is what a sound index holds.
type IndexReport struct {
	Batches, Certs, Chains int
	Pending                []string // committed batches the live index has not applied yet
}

// CheckIndex compares an index with the vault (amendment A5 §3.1). Every
// record of an applied batch is looked up as it is scanned and must map to
// its own cert_id and location; then the index must hold exactly as many
// certificate keys as there are records, so no key lacks a record. A
// certificate vaulted twice fails the lookup of its second record. Chains
// are checked the same way. Nothing is kept per certificate, so memory does
// not grow with the vault. Damage is ErrCorrupt.
func CheckIndex(x *index.Index, c IndexCheck) (IndexReport, error) {
	var rep IndexReport
	applied, err := x.AppliedLogs()
	if err != nil {
		return rep, err
	}
	last := map[string]uint64{}
	for _, m := range c.Committed {
		last[m.Log] = max(last[m.Log], m.CommitSeq)
	}
	for _, log := range slices.Sorted(maps.Keys(applied)) {
		if applied[log] > last[log] {
			return rep, corrupt("the index has applied %s up to commit_seq %d, ahead of its last committed batch (%d)", log, applied[log], last[log])
		}
	}
	if !c.Live {
		for _, log := range slices.Sorted(maps.Keys(last)) {
			if applied[log] != last[log] {
				return rep, corrupt("the index has applied %s up to commit_seq %d; its batches end at %d", log, applied[log], last[log])
			}
		}
	}
	reader, err := vault.OpenReader(c.VaultDirs, c.Codec)
	if err != nil {
		return rep, err
	}
	defer reader.Close()
	for i, m := range c.Committed {
		if m.CommitSeq > applied[m.Log] {
			rep.Pending = append(rep.Pending, m.BatchID)
			continue
		}
		err := vault.Scan(c.VaultDirs, m.Vault.Start, m.Vault.End, func(loc vault.Loc, rec vault.Record) error {
			der, _, err := reader.Read(loc)
			if err != nil {
				return err
			}
			sha, want := sha256.Sum256(der), index.Ref{CertID: rec.CertID, Loc: loc}
			got, ok, err := x.Lookup(sha)
			switch {
			case err != nil:
				return err
			case !ok:
				return corrupt("the index lacks certificate %x (cert_id %d at %d:%d, batch %s)", sha[:8], rec.CertID, loc.Segment, loc.Offset, m.BatchID)
			case got != want:
				return corrupt("the index maps %x to cert_id %d at %d:%d; the vault holds it as cert_id %d at %d:%d, batch %s (a wrong key, or a certificate vaulted twice)",
					sha[:8], got.CertID, got.Loc.Segment, got.Loc.Offset, rec.CertID, loc.Segment, loc.Offset, m.BatchID)
			}
			rep.Certs++
			return nil
		})
		if err != nil {
			return rep, err
		}
		ids, err := c.ChainIDs(filepath.Join(c.Paths.BatchDir(m.ID()), dataset.ChainsFile))
		if err != nil {
			return rep, err
		}
		for _, id := range ids {
			ok, err := x.HasChain(id)
			if err != nil {
				return rep, err
			}
			if !ok {
				return rep, corrupt("the index lacks chain %x (batch %s)", id[:8], m.BatchID)
			}
		}
		rep.Chains += len(ids)
		rep.Batches++
		if c.Progress != nil {
			c.Progress(i+1, len(c.Committed))
		}
	}
	keys := 0
	if err := x.EachCert(func([32]byte, index.Ref) error { keys++; return nil }); err != nil {
		return rep, err
	}
	if keys != rep.Certs {
		return rep, corrupt("the index holds %d certificate keys and the applied batches %d records: %d keys have no record", keys, rep.Certs, keys-rep.Certs)
	}
	chains := 0
	if err := x.EachChain(func([32]byte) error { chains++; return nil }); err != nil {
		return rep, err
	}
	if chains != rep.Chains {
		return rep, corrupt("the index holds %d chain keys and the applied batches' chains.parquet %d chains", chains, rep.Chains)
	}
	return rep, nil
}
