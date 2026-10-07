package powerloss

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/query"
	"github.com/4rji/ctvault/internal/vault"
	"github.com/4rji/ctvault/internal/verify"
)

// Point is what a vault holds after recovery at one crash point.
type Point struct {
	Manifests map[string][]byte   // batch ID → its _COMMIT.json
	IDs       map[uint64][32]byte // cert_id → the SHA-256 of its record
	Seq       uint64              // ACTIVE.json's seq
}

// Tracker carries what the earlier points showed (amendment A5 §15): no
// record outside the vault says what was committed when, so consistency
// across points stands in for one.
type Tracker struct {
	seen   Point
	Points int // points compared
}

// Compare checks a point against everything earlier points showed: every
// batch committed at an earlier point is still committed with an identical
// _COMMIT.json, every cert_id keeps its certificate, and ACTIVE.json's seq
// does not go back. A point that passes is recorded.
func (tr *Tracker) Compare(p Point) error {
	tr.Points++
	var problems []string
	for _, id := range slices.Sorted(maps.Keys(tr.seen.Manifests)) {
		now, ok := p.Manifests[id]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("batch %s was committed at an earlier point and is gone", id))
		case !bytes.Equal(now, tr.seen.Manifests[id]):
			problems = append(problems, fmt.Sprintf("batch %s changed its _COMMIT.json since an earlier point", id))
		}
	}
	for _, id := range slices.Sorted(maps.Keys(p.IDs)) {
		if was, now := tr.seen.IDs[id], p.IDs[id]; was != ([32]byte{}) && was != now {
			problems = append(problems, fmt.Sprintf("cert_id %d names certificate %x now and %x at an earlier point: an ID was reused", id, now[:8], was[:8]))
		}
	}
	if p.Seq < tr.seen.Seq {
		problems = append(problems, fmt.Sprintf("ACTIVE.json's seq went back from %d to %d", tr.seen.Seq, p.Seq))
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	if tr.seen.Manifests == nil {
		tr.seen = Point{Manifests: map[string][]byte{}, IDs: map[uint64][32]byte{}}
	}
	maps.Copy(tr.seen.Manifests, p.Manifests)
	maps.Copy(tr.seen.IDs, p.IDs)
	tr.seen.Seq = max(tr.seen.Seq, p.Seq)
	return nil
}

// Committed is the batch IDs the tracker has seen committed, sorted.
func (tr *Tracker) Committed() []string { return slices.Sorted(maps.Keys(tr.seen.Manifests)) }

// Inspect checks the vault at one crash point (amendment A5 §15): its writer
// opens, which runs recovery; verify --full then finds no damage, nothing
// pending and a sound index. It returns what the vault holds.
func Inspect(ctx context.Context, o ingest.Options) (Point, error) {
	var p Point
	w, err := ingest.Open(o)
	if err != nil {
		return p, fmt.Errorf("recovery: %w", err)
	}
	if err := w.Close(); err != nil {
		return p, fmt.Errorf("closing the writer after recovery: %w", err)
	}
	sess, err := query.NewSession(o.Root, diskguard.Guard{Cap: 0.95, Stat: o.Guard.Stat})
	if err != nil {
		return p, err
	}
	rep, err := verify.Run(ctx, verify.Options{Root: o.Root, VaultDirs: o.VaultDirs, VaultUUID: o.VaultUUID, Full: true, Session: sess})
	sess.Close()
	if err != nil {
		return p, fmt.Errorf("verify: %w", err)
	}
	var text strings.Builder
	rep.WriteText(&text)
	switch {
	case rep.Damaged():
		return p, fmt.Errorf("verify --full after recovery found damage:\n%s", text.String())
	case len(rep.Pending) > 0:
		return p, fmt.Errorf("recovery left work pending:\n%s", text.String())
	case rep.Check("index") == nil || rep.Check("index").Status != verify.StatusOK:
		return p, fmt.Errorf("the index was not checked:\n%s", text.String())
	}
	return read(o)
}

// read collects a recovered vault's committed manifests, cert_id
// assignments and ACTIVE.json seq.
func read(o ingest.Options) (Point, error) {
	p := Point{Manifests: map[string][]byte{}, IDs: map[uint64][32]byte{}}
	ms, err := commit.ListCommitted(o.Root)
	if err != nil {
		return p, err
	}
	paths := commit.Paths{Root: o.Root}
	for _, m := range ms {
		b, err := os.ReadFile(paths.BatchDir(m.ID()) + "/" + commit.ManifestFile)
		if err != nil {
			return p, err
		}
		p.Manifests[m.BatchID] = b
	}
	a, _, err := derive.ReadActive(o.Root)
	if err != nil {
		return p, err
	}
	p.Seq = a.Seq
	if len(ms) == 0 {
		return p, nil
	}
	codec, err := vault.NewCodec()
	if err != nil {
		return p, err
	}
	defer codec.Close()
	dicts, err := vault.ReadDicts(o.VaultDirs)
	if err != nil {
		return p, err
	}
	for _, d := range dicts {
		if err := codec.AddDict(d.Manifest.ID, d.Content); err != nil {
			return p, err
		}
	}
	r, err := vault.OpenReader(o.VaultDirs, codec)
	if err != nil {
		return p, err
	}
	defer r.Close()
	err = vault.Scan(o.VaultDirs, ms[0].Vault.Start, ms[len(ms)-1].Vault.End, func(loc vault.Loc, rec vault.Record) error {
		der, _, err := r.Read(loc)
		if err != nil {
			return err
		}
		p.IDs[rec.CertID] = sha256.Sum256(der)
		return nil
	})
	return p, err
}
