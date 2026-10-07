package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/extract"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// Batch ingests entries [first, end) of src and commits them, verified
// against the pinned head sth (spec §8.3). A failed Merkle verification or
// canary abandons the attempt and refetches the batch once; a second
// failure writes an incident and returns ErrVerification. Any other error
// abandons the batch and is returned as is (a stall, a full disk, a second
// signal). The caller resets src's chain cache after every call.
func (w *Writer) Batch(ctx context.Context, src logsource.LogSource, sth logsource.SignedHead, first, end uint64) (commit.Manifest, error) {
	if w.broken != nil {
		return commit.Manifest{}, w.broken
	}
	m, err := w.attempt(ctx, src, sth, first, end)
	var firstTry, secondTry errRetry
	if !errors.As(err, &firstTry) {
		return m, err
	}
	w.logf("batch %s: %v; refetching it once", w.batchID(src, first, end), err)
	m, err = w.attempt(ctx, src, sth, first, end)
	if !errors.As(err, &secondTry) {
		return m, err
	}
	dir, ierr := w.incident(w.batchID(src, first, end), sth, firstTry, secondTry)
	if ierr != nil {
		return m, errors.Join(fmt.Errorf("%w: %v", ErrVerification, err), ierr)
	}
	return m, fmt.Errorf("%w: %v (incident written to %s)", ErrVerification, err, dir)
}

func (w *Writer) batchID(src logsource.LogSource, first, end uint64) commit.BatchID {
	return commit.BatchID{Log: src.Info().Name, First: first, Last: end - 1}
}

// batch is one attempt's in-memory state.
type batch struct {
	w       *Writer
	ctx     context.Context
	src     logsource.LogSource
	pb      *index.Batch
	before  *merkle.State // the compact range before the batch
	state   *merkle.State
	rows    []dataset.EntryRow
	chains  []dataset.ChainRow
	quar    bytes.Buffer
	counts  commit.Counts
	firstID uint64
	lastID  uint64
	samples *reservoir            // vault records the canary reads back
	builds  []derive.Builder      // the builders ACTIVE.json enables (amendment A2 §4.6)
	dstage  *dataset.DerivedStage // their rows, staged as they are built (amendment A2 §4.3)

	fetch      fetch.Stats    // the attempt's fetcher statistics
	parse      map[string]int // parse_status of the new certificates
	deltaSamp  int            // sampled leaf-delta records (amendment A2 §6.1)
	deltaSaved int64          // bytes they saved against full records
}

type sample struct {
	sha [32]byte
	loc vault.Loc
}

// canaryReservoir is how many new vault records a batch keeps for the
// canary to choose from.
const canaryReservoir = 4096

// reservoir keeps a uniform random sample of a stream (Algorithm R), so the
// canary reads records from the whole batch, not only its start.
type reservoir struct {
	items []sample
	seen  int
	rnd   *rand.Rand
}

func newReservoir(n int, seed1, seed2 uint64) *reservoir {
	return &reservoir{items: make([]sample, 0, n), rnd: rand.New(rand.NewPCG(seed1, seed2))}
}

func (r *reservoir) add(s sample) {
	r.seen++
	if len(r.items) < cap(r.items) {
		r.items = append(r.items, s)
	} else if j := r.rnd.IntN(r.seen); j < len(r.items) {
		r.items[j] = s
	}
}

func (w *Writer) attempt(ctx context.Context, src logsource.LogSource, sth logsource.SignedHead, first, end uint64) (commit.Manifest, error) {
	id := w.batchID(src, first, end)
	tip := w.tips[id.Log]
	if first != tip.Next || end <= first || end > sth.TreeSize {
		return commit.Manifest{}, fmt.Errorf("batch %s: must start at %d and end within the signed tree of %d", id, tip.Next, sth.TreeSize)
	}
	state := merkle.NewState()
	if tip.State != nil {
		state = tip.State.Clone()
	}
	// P0: volume checks, the disk-guard peak preflight, then dictionary
	// training, which may take minutes and so runs only for a batch that
	// can start. A cache left cold by a stopped attempt is warmed first.
	if w.cold {
		if err := w.warm(); err != nil {
			return commit.Manifest{}, err
		}
		w.cold = false
	}
	if w.o.CheckVolumes != nil {
		if err := w.o.CheckVolumes(); err != nil {
			return commit.Manifest{}, err
		}
	}
	dir, err := w.preflight(end - first)
	if err != nil {
		return commit.Manifest{}, err
	}
	dict, err := w.maybeTrain(ctx)
	if err != nil {
		return commit.Manifest{}, err
	}
	w.vw.Prefer(dir)
	// P1
	in := commit.Intent{BatchID: id.String(), Log: id.Log, First: id.First, Last: id.Last, STH: toSTH(sth),
		VaultTail: w.vw.Tail(), NextCertID: w.ids.Peek(), MerkleBefore: state.Clone(), Builders: map[string]int{},
		StartedAt: w.o.Now().UTC()}
	if err := commit.WriteIntent(w.paths, in, w.o.Hook); err != nil {
		return commit.Manifest{}, err
	}
	b := &batch{w: w, ctx: ctx, src: src, pb: w.idx.NewBatch(), state: state, before: in.MerkleBefore,
		samples: newReservoir(canaryReservoir, first, end)}
	b.builds = w.builders()
	defer b.pb.Close()
	m, err := w.run(b, in, sth, dict)
	var after errCommitted
	if err != nil && !errors.As(err, &after) {
		if aerr := w.abandon(ctx, in); aerr != nil {
			w.broken = fmt.Errorf("%w: %s: %v", ErrAbandonFailed, id, aerr)
			return m, errors.Join(err, w.broken)
		}
	}
	return m, err
}

// ErrAbandonFailed means an attempt could not be cleaned up in process: the
// vault could not be cut back, or its intent could not be marked. The
// writer then refuses every further batch, and the next start recovers
// (spec §8.5).
var ErrAbandonFailed = errors.New("abandoning the batch failed; run update again to recover")

// run is P2-P10 of one attempt.
func (w *Writer) run(b *batch, in commit.Intent, sth logsource.SignedHead, dict commit.DictInfo) (commit.Manifest, error) {
	id := in.ID()
	// P2
	if len(b.builds) > 0 {
		var tables []derive.Table
		for _, bl := range b.builds {
			tables = append(tables, bl.Table())
		}
		d, err := w.stager.BeginDerived(b.ctx, tables, w.o.CanarySamples, rand.New(rand.NewPCG(id.First, id.Last)))
		if err != nil {
			return commit.Manifest{}, err
		}
		defer d.Close()
		b.dstage = d
	}
	stats, err := fetch.Run(b.ctx, b.src, id.First, id.Last+1, w.o.Fetch, b.add)
	b.fetch = stats
	if err != nil {
		return commit.Manifest{}, err
	}
	// P3
	if err := w.vw.Sync(); err != nil {
		return commit.Manifest{}, err
	}
	w.hook(HookAfterVaultSync)
	// P4
	verified, err := w.verify(b, sth, id.Last+1)
	if err != nil {
		return commit.Manifest{}, err
	}
	// P5
	stage := w.paths.StageDir(id)
	files, err := w.stager.Stage(b.ctx, stage, b.rows, b.chains)
	if err != nil {
		return commit.Manifest{}, err
	}
	if b.dstage != nil {
		dfiles, err := b.dstage.Write(b.ctx, stage)
		if err != nil {
			return commit.Manifest{}, err
		}
		maps.Copy(files, dfiles)
	}
	if b.quar.Len() > 0 {
		p := filepath.Join(stage, commit.QuarantineFile)
		if err := os.WriteFile(p, b.quar.Bytes(), 0o644); err != nil {
			return commit.Manifest{}, err
		}
		fi, err := dataset.Sum(p)
		if err != nil {
			return commit.Manifest{}, err
		}
		fi.Rows = b.counts.LeafErrors
		files[commit.QuarantineFile] = fi
	}
	if err := w.o.Guard.Check(w.o.Root, 0); err != nil { // spec §10.1: a hard check after every staged write
		return commit.Manifest{}, err
	}
	// P6
	if err := w.canary(b, stage); err != nil {
		return commit.Manifest{}, err
	}
	// P7, P8
	seq := w.LastCommitSeq() + 1
	m := commit.Manifest{Format: commit.ManifestFormat, CommitSeq: seq, BatchID: id.String(), Log: id.Log,
		First: id.First, Last: id.Last, STH: toSTH(sth), MerkleAfter: b.state, Verified: verified,
		NextCertID: w.ids.Peek(), Vault: commit.Span{Start: in.VaultTail, End: w.vw.Tail()}, Builders: b.tables(),
		Files: files, Counts: b.counts, Dictionary: dict, CTVaultVersion: w.o.Version, CommittedAt: w.o.Now().UTC(),
		Fetch: b.fetchCounts(), ParseStatus: b.parse, DeltaSaved: b.deltaSavedEstimate()}
	m.Counts.Entries = len(b.rows)
	if b.firstID != 0 {
		m.CertIDRange = &[2]uint64{b.firstID, b.lastID}
	}
	perr := commit.Publish(w.paths, m, w.o.Hook)
	if perr != nil && !errors.Is(perr, commit.ErrPostCommit) {
		return m, perr // the rename did not happen: abandon
	}
	// From here the batch is committed; failures below are repaired by
	// recovery at the next start, never by abandoning.
	w.committed = append(w.committed, m)
	w.tips[id.Log] = commit.LogTip{Next: id.Last + 1, State: b.state}
	if perr != nil {
		return m, errCommitted{perr}
	}
	// P9
	if err := b.pb.SetApplied(id.Log, seq); err != nil {
		return m, errCommitted{err}
	}
	w.hook(HookBeforePebble)
	if err := b.pb.Commit(); err != nil {
		return m, errCommitted{err}
	}
	w.hook(HookAfterPebble)
	// P10
	if err := commit.RemoveIntent(w.paths, id, w.o.Hook); err != nil {
		return m, errCommitted{err}
	}
	if err := commit.ClearAbandoned(w.paths); err != nil {
		return m, errCommitted{err}
	}
	if _, err := dataset.WriteViews(w.o.Root, w.active); err != nil { // the first commit changes it
		return m, errCommitted{err}
	}
	w.logf("batch %s: %d entries, %d new certificates (%d deltas), %d leaf errors, %d vault bytes, verified by %s; commit_seq %d",
		id, m.Counts.Entries, m.Counts.NewCerts, m.Counts.DeltaRecords, m.Counts.LeafErrors, m.Counts.VaultBytes, verified.Method, seq)
	// P11
	w.audit(b.ctx, m)
	return m, nil
}

// Hook points of the engine's own steps, for crash tests (spec §13.5).
const (
	HookAfterVaultSync = "commit.P3.after_vault_sync"
	HookDuringCanary   = "commit.P6.during_canary" // between the Parquet and the vault checks
	HookBeforePebble   = "commit.P9.before_pebble"
	HookAfterPebble    = "commit.P9.after_pebble"
)

func (w *Writer) hook(p string) {
	if w.o.Hook != nil {
		w.o.Hook(p)
	}
}

// errCommitted wraps a failure after the commit point: the batch is
// committed, so it must not be abandoned.
type errCommitted struct{ err error }

func (e errCommitted) Error() string { return "after commit: " + e.err.Error() }
func (e errCommitted) Unwrap() error { return e.err }

// abandon discards an attempt: vault, staging and intent go, the Pebble
// batch is discarded by the caller, cert_ids skip to the floor, and the
// delta cache forgets records that no longer exist. When ctx is done the
// process is stopping: the cache is emptied and left cold instead of
// re-reading the vault, and the next attempt warms it.
func (w *Writer) abandon(ctx context.Context, in commit.Intent) error {
	if err := w.vw.Close(); err != nil {
		return err
	}
	if err := commit.Abandon(w.paths, w.o.VaultDirs, in); err != nil {
		return err
	}
	w.ids.SkipToFloor()
	var err error
	if w.vw, err = vault.OpenWriter(w.vaultOptions(), w.codec, in.VaultTail); err != nil {
		return err
	}
	if ctx.Err() != nil {
		w.delta.Reset()
		w.cold = true
		return nil
	}
	return w.warm()
}

// add handles one entry in index order (P2).
func (b *batch) add(e logsource.RawEntry) error {
	if err := b.state.Append(e.Leaf.LeafHash); err != nil {
		return err
	}
	row := dataset.EntryRow{Idx: e.Index, CTTimestamp: e.Leaf.Timestamp, EntryType: e.Leaf.Type.String(), LeafHash: e.Leaf.LeafHash}
	if k, ok := e.Leaf.IssuanceKey(); ok {
		row.IssuanceKey, row.HasIssuanceKey = k, true
	}
	if e.Leaf.HasIssuerKeyHash {
		row.IssuerKeyHash, row.HasIssuerKeyHash = e.Leaf.IssuerKeyHash, true
	}
	if e.Leaf.Code != leaf.OK {
		row.LeafError = string(e.Leaf.Code)
		b.counts.LeafErrors++
		line, _ := json.Marshal(map[string]any{"idx": e.Index, "leaf_error": e.Leaf.Code,
			"leaf_input": base64.StdEncoding.EncodeToString(e.LeafInput), "extra_data": base64.StdEncoding.EncodeToString(e.ExtraData)})
		b.quar.Write(append(line, '\n'))
	}
	if e.Leaf.CertDER != nil {
		id, err := b.vaultLeaf(e.Leaf)
		if err != nil {
			return err
		}
		row.CertID = id
	}
	if e.Chain != nil {
		chainID, err := b.vaultChain(e.Chain)
		if err != nil {
			return err
		}
		row.ChainID, row.HasChainID = chainID, true
	}
	b.rows = append(b.rows, row)
	return nil
}

func (b *batch) assign() (uint64, error) {
	id, err := b.w.ids.Next()
	if err != nil {
		return 0, err
	}
	if b.firstID == 0 {
		b.firstID = id
	}
	b.lastID = id
	return id, nil
}

func (b *batch) vaulted(sha [32]byte, ref index.Ref) error {
	b.counts.NewCerts++
	b.counts.VaultBytes += uint64(ref.Loc.Len)
	b.samples.add(sample{sha, ref.Loc})
	return b.pb.AddCert(sha, ref)
}

// vaultLeaf stores a leaf certificate unless it is already vaulted. A final
// certificate whose precert is cached becomes a leaf-delta record.
func (b *batch) vaultLeaf(l leaf.Entry) (uint64, error) {
	sha := sha256.Sum256(l.CertDER)
	if ref, ok, err := b.pb.Lookup(sha); err != nil || ok {
		return ref.CertID, err
	}
	id, err := b.assign()
	if err != nil {
		return 0, err
	}
	var loc vault.Loc
	var baseID uint64
	if base, bid, ok := b.w.delta.Get(l.IssuanceDigest); ok && l.Type == leaf.TypeX509 && l.HasIssuanceDigest {
		if loc, err = b.w.vw.AppendDelta(id, l.CertDER, base); err != nil {
			return 0, err
		}
		b.counts.DeltaRecords++
		baseID = bid
		if deltaSampled(sha) {
			if err := b.sampleDelta(id, l.CertDER, loc); err != nil {
				return 0, err
			}
		}
	} else if loc, err = b.w.vw.AppendCert(vault.KindLeaf, id, l.CertDER, b.w.dictID); err != nil {
		return 0, err
	}
	kind := derive.KindFinal
	if l.Type == leaf.TypePrecert {
		kind = derive.KindPrecert
	}
	if err := b.derive(l.CertDER, derive.Context{CertID: id, SHA256: sha, Kind: kind, Loc: loc, DeltaBaseCertID: baseID}); err != nil {
		return 0, err
	}
	if l.Type == leaf.TypePrecert && l.HasIssuanceDigest {
		b.w.delta.Put(l.IssuanceDigest, loc, id)
	}
	return id, b.vaulted(sha, index.Ref{CertID: id, Loc: loc})
}

// vaultChain stores unseen chain certificates and returns the chain_id,
// adding chains.parquet rows the first time a chain is seen.
func (b *batch) vaultChain(fps [][32]byte) ([32]byte, error) {
	ids := make([]uint64, len(fps))
	h := sha256.New()
	for i, fp := range fps {
		h.Write(fp[:])
		ref, ok, err := b.pb.Lookup(fp)
		if err != nil {
			return [32]byte{}, err
		}
		if ok {
			ids[i] = ref.CertID
			continue
		}
		der, err := b.src.Issuer(b.ctx, fp)
		if err != nil {
			return [32]byte{}, err
		}
		if sha256.Sum256(der) != fp {
			return [32]byte{}, fmt.Errorf("chain certificate %x does not match its fingerprint", fp[:8])
		}
		if ids[i], err = b.assign(); err != nil {
			return [32]byte{}, err
		}
		loc, err := b.w.vw.AppendCert(vault.KindChain, ids[i], der, b.w.dictID)
		if err != nil {
			return [32]byte{}, err
		}
		if err := b.derive(der, derive.Context{CertID: ids[i], SHA256: fp, Kind: derive.KindChain, Loc: loc}); err != nil {
			return [32]byte{}, err
		}
		if err := b.vaulted(fp, index.Ref{CertID: ids[i], Loc: loc}); err != nil {
			return [32]byte{}, err
		}
	}
	var chainID [32]byte
	copy(chainID[:], h.Sum(nil))
	seen, err := b.pb.HasChain(chainID)
	if err != nil || seen {
		return chainID, err
	}
	for i, id := range ids {
		b.chains = append(b.chains, dataset.ChainRow{ChainID: chainID, Position: uint16(i), CertID: id})
	}
	return chainID, b.pb.AddChain(chainID)
}

// verify is P4 (spec §5.5): the computed root at end must equal the signed
// root, or be proven a prefix of it.
func (w *Writer) verify(b *batch, sth logsource.SignedHead, end uint64) (commit.Verified, error) {
	root, err := b.state.Root()
	if err != nil {
		return commit.Verified{}, err
	}
	if end == sth.TreeSize {
		if root != sth.RootHash {
			return commit.Verified{}, errRetry{err: errors.New("the computed root differs from the signed root"),
				before: b.before, root: root, end: end}
		}
		return commit.Verified{Method: "root_equals_sth"}, nil
	}
	var proof [][32]byte
	if err := fetch.Retry(b.ctx, w.o.Fetch, func(ctx context.Context) (err error) {
		proof, err = b.src.ConsistencyProof(ctx, end, sth.TreeSize)
		return err
	}); err != nil {
		return commit.Verified{}, err
	}
	if err := merkle.VerifyConsistency(end, sth.TreeSize, root, sth.RootHash, proof); err != nil {
		return commit.Verified{}, errRetry{err: err, before: b.before, root: root, end: end, proof: proof}
	}
	nodes := make([]string, len(proof))
	for i, n := range proof {
		nodes[i] = hex.EncodeToString(n[:])
	}
	return commit.Verified{Method: "consistency_proof", ProofNodes: len(proof), Proof: nodes}, nil
}

// canary is P6: the staged files, and vault reads of sampled new records.
func (w *Writer) canary(b *batch, stage string) error {
	rnd := rand.New(rand.NewPCG(b.rows[0].Idx, uint64(len(b.rows))))
	if err := w.stager.Canary(b.ctx, stage, b.rows, b.chains, w.o.CanarySamples, rnd); err != nil {
		return errRetry{err: err}
	}
	if b.dstage != nil {
		if err := b.dstage.Canary(b.ctx, stage); err != nil {
			return errRetry{err: err}
		}
	}
	w.hook(HookDuringCanary)
	r, err := vault.OpenReader(w.o.VaultDirs, w.codec)
	if err != nil {
		return err
	}
	defer r.Close()
	for range min(w.o.CanarySamples, len(b.samples.items)) {
		s := b.samples.items[rnd.IntN(len(b.samples.items))]
		if _, err := r.ReadVerified(s.loc, s.sha); err != nil {
			return errRetry{err: err}
		}
	}
	return nil
}

// maybeTrain trains dictionary 1 once the committed vault holds
// DictSamples leaf certificates; a training failure is recorded and
// ingestion goes on with dictionary 0 (amendment A1 §5). It is tried once
// per process. Vault corruption met while reading the samples is returned:
// corruption is never ignored (spec §12). Training takes minutes, so a
// cancelled ctx returns at once; the abandoned training finishes in the
// background and is discarded, and a later run trains again.
func (w *Writer) maybeTrain(ctx context.Context) (commit.DictInfo, error) {
	if w.dictID != 0 || w.trainTried {
		return commit.DictInfo{ID: w.dictID}, nil
	}
	samples, tr, err := vault.TrainingSet(w.o.VaultDirs, w.codec, w.vw.Tail(), w.o.DictSamples)
	if err != nil {
		return commit.DictInfo{}, fmt.Errorf("reading dictionary training samples: %w", err)
	}
	if len(samples) < w.o.DictSamples {
		return commit.DictInfo{ID: 0}, nil
	}
	w.trainTried = true
	w.logf("training dictionary 1 on %d leaf certificates", len(samples))
	type trained struct {
		content []byte
		err     error
	}
	done := make(chan trained, 1)
	go func() {
		c, err := w.o.Train(samples, 1)
		done <- trained{c, err}
	}()
	var res trained
	select {
	case res = <-done:
	case <-ctx.Done():
		w.trainTried = false
		return commit.DictInfo{}, ctx.Err()
	}
	content, err := res.content, res.err
	if err == nil {
		var d vault.Dict
		if d, err = vault.InstallDict(w.o.VaultDirs, 1, content, tr, w.o.Now()); err == nil {
			err = w.codec.AddDict(1, d.Content)
		}
	}
	if err != nil {
		w.logf("dictionary training failed; continuing without a dictionary: %v", err)
		return commit.DictInfo{ID: 0, TrainingError: err.Error()}, nil
	}
	w.dictID = 1
	return commit.DictInfo{ID: 1}, nil
}

// preflight is the spec §10.1 peak check before a batch starts. It returns
// the vault directory whose filesystem holds the vault peak; the batch's new
// segments go there.
func (w *Writer) preflight(n uint64) (string, error) {
	var vaultHist, parquetHist []float64
	for i := max(0, len(w.committed)-diskguard.MinHistory); i < len(w.committed); i++ {
		m := w.committed[i]
		if m.Counts.Entries == 0 {
			continue
		}
		var pq int64
		for _, f := range m.Files {
			pq += f.Bytes
		}
		vaultHist = append(vaultHist, float64(m.Counts.VaultBytes)/float64(m.Counts.Entries))
		parquetHist = append(parquetHist, float64(pq)/float64(m.Counts.Entries))
	}
	cfg := w.o.Config
	peak := diskguard.EstimatePeak(diskguard.PeakInput{Entries: n,
		VaultP95: diskguard.P95(vaultHist, diskguard.SeedVaultBytesPerEntry), ParquetP95: diskguard.P95(parquetHist, diskguard.SeedParquetBytesPerEntry),
		PebbleP95: diskguard.SeedPebbleBytesPerEntry, Safety: cfg.Disk.SafetyFactor,
		PebbleSize: dirSize(filepath.Join(w.o.Root, "state", "pebble")), DuckDBSpill: w.spillLimit()})
	var err error
	for _, d := range w.o.VaultDirs {
		if err = w.o.Guard.Preflight([]diskguard.Target{{Path: w.o.Root, Need: peak.Root}, {Path: d, Need: peak.Vault}}); err == nil {
			return d, nil
		}
	}
	return "", err
}

func dirSize(dir string) uint64 {
	var n uint64
	filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += uint64(fi.Size())
			}
		}
		return nil
	})
	return n
}

func toSTH(h logsource.SignedHead) commit.STH {
	return commit.STH{TreeSize: h.TreeSize, Timestamp: h.Timestamp, RootHash: hex.EncodeToString(h.RootHash[:]),
		Signature: base64.StdEncoding.EncodeToString(h.Signature)}
}

// incident writes the evidence of a batch that failed verification twice
// (spec §12): the pinned head as received, both attempts' causes, and for a
// Merkle failure our compact range before the batch, the root we computed
// and the proof the log served. The fetched data itself is truncated.
func (w *Writer) incident(id commit.BatchID, sth logsource.SignedHead, first, second errRetry) (string, error) {
	dir := filepath.Join(w.o.Root, "state", "incidents", w.o.Now().UTC().Format("20060102T150405Z")+"_"+id.Log+"_"+fmt.Sprint(id.First))
	if err := fsutil.MkdirAllSync(dir, 0o755); err != nil {
		return "", err
	}
	ev := map[string]any{"batch_id": id.String(), "causes": []string{first.Error(), second.Error()}, "sth": toSTH(sth),
		"sth_raw": base64.StdEncoding.EncodeToString(sth.Raw), "time": w.o.Now().UTC().Format(time.RFC3339)}
	if second.before != nil {
		proof := make([]string, len(second.proof))
		for i, n := range second.proof {
			proof[i] = hex.EncodeToString(n[:])
		}
		ev["merkle_before"], ev["computed_root"], ev["end"], ev["proof"] = second.before, hex.EncodeToString(second.root[:]), second.end, proof
	}
	b, err := json.MarshalIndent(ev, "", " ")
	if err != nil {
		return dir, err
	}
	return dir, fsutil.WriteFileAtomic(filepath.Join(dir, "incident.json"), b, 0o644)
}

// builders are the builders of every version a new batch builds: each
// table's active and building versions, or only the building one while
// mixed (amendment A2 §4.6, A5 §8, §10).
func (w *Writer) builders() []derive.Builder {
	if w.o.NoDerived {
		return nil
	}
	var out []derive.Builder
	for _, bl := range derive.Builders {
		for _, t := range w.active.BuildVersions(bl.Table().Name) {
			if b := derive.BuilderOf(t.Name, t.Version); b != nil {
				out = append(out, b)
			}
		}
	}
	return out
}

// derive extracts a newly vaulted certificate once and stages its rows in
// every derived table of the batch.
func (b *batch) derive(der []byte, ctx derive.Context) error {
	if b.dstage == nil {
		return nil
	}
	c := extract.Parse(der)
	if b.parse == nil {
		b.parse = map[string]int{}
	}
	b.parse[string(c.Status)]++
	for i, bl := range b.builds {
		if err := b.dstage.Add(i, bl.Build(c, ctx)); err != nil {
			return err
		}
	}
	return nil
}

// tables records the derived tables this batch built, for _COMMIT.json:
// the newest version of each; files lists every version's file.
func (b *batch) tables() map[string]int {
	out := map[string]int{}
	for _, bl := range b.builds {
		out[bl.Table().Name] = max(out[bl.Table().Name], bl.Table().Version)
	}
	return out
}

// deltaSampleDomain keeps the delta-saved sample apart from every other use
// of a certificate's hash.
var deltaSampleDomain = []byte("ctvault/delta-saved-sample/v1")

// deltaSampled reports whether a leaf-delta certificate is in the
// delta-saved sample: the first byte of SHA-256(domain ‖ certificate
// SHA-256) is below 16, about 1 in 16, reproducible from the certificate
// alone and uncorrelated with cert_id order (amendment A2 §6.1).
func deltaSampled(sha [32]byte) bool {
	h := sha256.Sum256(append(append([]byte(nil), deltaSampleDomain...), sha[:]...))
	return h[0] < 16
}

// sampleDelta also compresses a sampled leaf-delta certificate as a full
// record, to measure what the delta saved. Nothing is written.
func (b *batch) sampleDelta(id uint64, der []byte, loc vault.Loc) error {
	frame, err := b.w.codec.Compress(der, b.w.dictID)
	if err != nil {
		return err
	}
	full := len(vault.AppendRecord(nil, vault.Record{Kind: vault.KindLeaf, CertID: id, DictID: b.w.dictID, Frame: frame}))
	b.deltaSamp++
	b.deltaSaved += int64(full) - int64(loc.Len)
	return nil
}

// fetchCounts is the attempt's fetcher statistics for _COMMIT.json.
func (b *batch) fetchCounts() *commit.FetchCounts {
	s := b.fetch
	return &commit.FetchCounts{Requests: s.Requests, RateLimited: s.RateLimited,
		Retries: s.RateLimited + s.ServerErrors + s.FramingErrors + s.NetworkErrors + s.OtherErrors}
}

// deltaSavedEstimate scales the sampled savings to every delta record; nil
// when the batch wrote none.
func (b *batch) deltaSavedEstimate() *commit.DeltaSaved {
	if b.counts.DeltaRecords == 0 {
		return nil
	}
	d := &commit.DeltaSaved{Approximate: true, DeltaRecords: b.counts.DeltaRecords, SampledRecords: b.deltaSamp, SampledSavedBytes: b.deltaSaved}
	if b.deltaSamp > 0 {
		d.Bytes = b.deltaSaved * int64(b.counts.DeltaRecords) / int64(b.deltaSamp)
	}
	return d
}
