package verify

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/lock"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// chunk is how many records the decoders share at a time.
const chunk = 4096

// full runs --full's checks (amendment A5 §2.2-2.3): every file's checksum,
// then one pass per batch in commit_seq order over its records, entries and
// chains, then the index.
func (v *verifier) full(ctx context.Context) error {
	if v.o.Session == nil {
		return errors.New("verify --full needs a reader session")
	}
	dicts, _ := vault.ReadDicts(v.o.VaultDirs) // damage there is the vault check's; records then fail to decode
	if err := v.checksums(ctx, v.rep.add("checksums")); err != nil {
		return err
	}
	p := &pass{v: v, db: v.o.Session.DB(), records: v.rep.add("records"), refs: v.rep.add("references"),
		merkle: v.rep.add("merkle"), sths: v.rep.add("sth roots")}
	if err := p.run(ctx, dicts); err != nil {
		return err
	}
	return v.index(ctx, dicts, v.rep.add("index"))
}

func (v *verifier) progress(stage string, done, total int) {
	if v.o.Progress != nil {
		v.o.Progress(stage, done, total)
	}
}

// checksums hashes every listed file.
func (v *verifier) checksums(ctx context.Context, c *Check) error {
	n := 0
	for i, b := range v.batches {
		type want struct{ sum, by string }
		files := map[string]want{}
		for name, fi := range b.m.Files {
			if !b.m.Retired(name) {
				files[name] = want{fi.SHA256, commit.ManifestFile}
			}
		}
		if b.m.Derived != nil {
			for _, t := range b.m.Derived.Tables {
				files[t.File] = want{t.SHA256, commit.DerivedFile}
			}
		}
		for _, name := range slices.Sorted(maps.Keys(files)) {
			if err := ctx.Err(); err != nil {
				return err
			}
			got, err := fileSHA256(filepath.Join(b.dir, name))
			switch {
			case errors.Is(err, fs.ErrNotExist):
				continue // the files check reports it
			case err != nil:
				c.fail("batch %s: %s cannot be read: %v", b.m.BatchID, name, err)
			case got != files[name].sum:
				c.fail("batch %s: %s has SHA-256 %s; %s records %s", b.m.BatchID, name, got, files[name].by, files[name].sum)
			default:
				n++
			}
		}
		v.progress("checksums", i+1, len(v.batches))
	}
	c.Summary = count(n, "file") + " match their recorded SHA-256"
	return nil
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// pass is the content checks' state across batches.
type pass struct {
	v                              *verifier
	db                             *sql.DB
	records, refs, merkle, sths    *Check
	decoders                       []*decoder
	seen                           []uint64 // a bit per cert_id with a record
	last                           uint64   // the previous record's cert_id, across the vault
	nRecords, nRefs, noRows        int
	states                         map[string]*merkle.State
	next                           map[string]uint64
	heads                          map[string]map[uint64][32]byte // log → tree size → signed root
	matched                        map[[2]any]bool
	proofs, unproven, certsMissing int
	certsFile                      func(m commit.Manifest) string
}

func (p *pass) mark(id uint64) {
	if w := id / 64; w < uint64(len(p.seen)) {
		p.seen[w] |= 1 << (id % 64)
	}
}

func (p *pass) has(id uint64) bool {
	w := id / 64
	return w < uint64(len(p.seen)) && p.seen[w]&(1<<(id%64)) != 0
}

func (p *pass) run(ctx context.Context, dicts []vault.Dict) error {
	workers := p.v.o.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	for range workers {
		d, err := newDecoder(p.v.o.VaultDirs, dicts)
		if err != nil {
			return err
		}
		defer d.close()
		p.decoders = append(p.decoders, d)
	}
	ids := uint64(0)
	committed := map[string]uint64{}
	p.heads, p.states, p.next, p.matched = map[string]map[uint64][32]byte{}, map[string]*merkle.State{}, map[string]uint64{}, map[[2]any]bool{}
	for _, b := range p.v.batches {
		ids = max(ids, b.m.NextCertID)
		committed[b.m.Log] = max(committed[b.m.Log], b.m.Last+1)
		if root, err := hex.DecodeString(b.m.STH.RootHash); err == nil && len(root) == 32 {
			if p.heads[b.m.Log] == nil {
				p.heads[b.m.Log] = map[uint64][32]byte{}
			}
			p.heads[b.m.Log][b.m.STH.TreeSize] = [32]byte(root)
		}
	}
	p.seen = make([]uint64, ids/64+1)
	p.certsFile = certsFile(p.v.o.Root)
	for i, b := range p.v.batches {
		if err := p.batch(ctx, b); err != nil {
			return err
		}
		p.proof(b.m, committed[b.m.Log])
		p.v.progress("records", i+1, len(p.v.batches))
	}
	p.records.Summary = fmt.Sprintf("%s decoded and matched to their certs rows", count(p.nRecords, "record"))
	if p.certsMissing > 0 {
		p.records.Summary += fmt.Sprintf("; %s without a certs file (being built) checked by decoding only", count(p.certsMissing, "batch"))
	}
	p.refs.Summary = fmt.Sprintf("%s of entries and chains name a certificate", count(p.nRefs, "cert_id"))
	p.merkle.Summary = fmt.Sprintf("%s rebuilt from entries.leaf_hash match merkle_after", count(len(p.v.batches), "batch"))
	p.sths.Summary = fmt.Sprintf("%s matched by the rebuilt tree, %s re-checked, %d proved at ingest, proof not recorded",
		count(len(p.matched), "signed head"), count(p.proofs, "proof"), p.unproven)
	return nil
}

// certsFile returns the certs file a batch's records are compared with:
// the active version's, or the version being built when the batch has it.
func certsFile(root string) func(m commit.Manifest) string {
	a, _, _ := derive.ReadActive(root)
	st := a.Tables[derive.CertsV1.Name]
	return func(m commit.Manifest) string {
		for _, ver := range []*int{st.Active, st.Building} {
			if ver == nil {
				continue
			}
			f := derive.Table{Name: derive.CertsV1.Name, Version: *ver}.File()
			if _, ok := m.Listed(f); ok {
				return f
			}
		}
		return ""
	}
}

// certRow is the part of a certs row that describes its record.
type certRow struct {
	id        uint64
	sha, kind string
	seg       uint32
	off       uint64
	len       uint32
	base      sql.Null[uint64]
}

func (p *pass) rows(ctx context.Context, b batch) ([]certRow, bool) {
	f := p.certsFile(b.m)
	if f == "" {
		p.certsMissing++
		return nil, false
	}
	rs, err := p.db.QueryContext(ctx, `SELECT cert_id, sha256, kind, vault_seg, vault_off, vault_len, delta_base_cert_id
FROM read_parquet(`+sqlQuote(filepath.Join(b.dir, f))+`) ORDER BY cert_id`)
	if err != nil {
		p.records.fail("batch %s: %s cannot be read: %v", b.m.BatchID, f, err)
		return nil, false
	}
	defer rs.Close()
	var out []certRow
	for rs.Next() {
		var r certRow
		if err := rs.Scan(&r.id, &r.sha, &r.kind, &r.seg, &r.off, &r.len, &r.base); err != nil {
			p.records.fail("batch %s: %s: %v", b.m.BatchID, f, err)
			return nil, false
		}
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		p.records.fail("batch %s: %s cannot be read: %v", b.m.BatchID, f, err)
		return nil, false
	}
	return out, true
}

func sqlQuote(s string) string {
	b := []byte{'\''}
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			b = append(b, '\'')
		}
		b = append(b, s[i])
	}
	return string(append(b, '\''))
}

// item is a record and what decoding it found.
type item struct {
	loc  vault.Loc
	rec  vault.Record
	sha  [32]byte
	base uint64 // a delta's base record's cert_id
	err  error
}

// batch checks one batch: its records against its certs rows, then its
// entries and chains.
func (p *pass) batch(ctx context.Context, b batch) error {
	m := b.m
	rows, haveRows := p.rows(ctx, b)
	ri := 0
	merge := func(it *item) {
		p.nRecords++
		id, at := it.rec.CertID, fmt.Sprintf("record %d:%d (cert_id %d)", it.loc.Segment, it.loc.Offset, it.rec.CertID)
		if id <= p.last {
			p.records.fail("%s: cert_ids must increase in vault order; the record before has %d", at, p.last)
		}
		p.last = max(p.last, id)
		if r := m.CertIDRange; r == nil || id < r[0] || id > r[1] {
			p.records.fail("%s lies outside batch %s's cert_id range %v", at, m.BatchID, m.CertIDRange)
		}
		p.mark(id)
		if it.err != nil {
			p.records.fail("%s does not decode: %v", at, it.err)
		}
		if !haveRows {
			return
		}
		for ri < len(rows) && rows[ri].id < id {
			p.records.fail("batch %s: the certs row of cert_id %d has no record", m.BatchID, rows[ri].id)
			ri++
		}
		if ri == len(rows) || rows[ri].id != id {
			p.records.fail("%s has no certs row", at)
			return
		}
		r := rows[ri]
		ri++
		if it.err == nil && r.sha != hex.EncodeToString(it.sha[:]) {
			p.records.fail("%s: its SHA-256 is %x; its certs row says %s", at, it.sha, r.sha)
		}
		if uint64(r.seg) != it.loc.Segment || r.off != it.loc.Offset || r.len != it.loc.Len {
			p.records.fail("%s: its certs row gives another location (%d:%d, %d bytes)", at, r.seg, r.off, r.len)
		}
		want := map[byte][]string{vault.KindLeaf: {derive.KindPrecert, derive.KindFinal}, vault.KindChain: {derive.KindChain}, vault.KindDelta: {derive.KindFinal}}[it.rec.Kind]
		if !slices.Contains(want, r.kind) {
			p.records.fail("%s is a kind %d record; its certs row says %s", at, it.rec.Kind, r.kind)
		}
		switch {
		case it.rec.Kind == vault.KindDelta && it.err == nil && (!r.base.Valid || r.base.V != it.base):
			p.records.fail("%s is a delta on cert_id %d; its certs row says delta_base_cert_id %v", at, it.base, nullString(r.base))
		case it.rec.Kind != vault.KindDelta && r.base.Valid:
			p.records.fail("%s is not a delta; its certs row says delta_base_cert_id %d", at, r.base.V)
		}
	}
	var items []*item
	flush := func() {
		p.decode(items)
		for _, it := range items {
			merge(it)
		}
		items = items[:0]
	}
	err := vault.Scan(p.v.o.VaultDirs, m.Vault.Start, m.Vault.End, func(loc vault.Loc, rec vault.Record) error {
		items = append(items, &item{loc: loc, rec: rec})
		if len(items) == chunk {
			flush()
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		return nil
	})
	flush()
	switch {
	case errors.Is(err, vault.ErrCorrupt), errors.Is(err, vault.ErrTorn):
		p.records.fail("batch %s: its vault span cannot be read to the end: %v", m.BatchID, err)
	case err != nil:
		return err
	}
	for ; haveRows && ri < len(rows); ri++ {
		p.records.fail("batch %s: the certs row of cert_id %d has no record", m.BatchID, rows[ri].id)
	}
	if err := p.entries(ctx, b); err != nil {
		return err
	}
	return p.chains(ctx, b)
}

// decode decodes items with every decoder, each on its share.
func (p *pass) decode(items []*item) {
	var wg sync.WaitGroup
	n := len(p.decoders)
	for w, d := range p.decoders {
		lo, hi := len(items)*w/n, len(items)*(w+1)/n
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, it := range items[lo:hi] {
				d.decode(it)
			}
		}()
	}
	wg.Wait()
}

// entries rebuilds the log's Merkle tree from the batch's leaf hashes in
// idx order, compares it with merkle_after and with every signed head on
// the way, and checks each entry's cert_id.
func (p *pass) entries(ctx context.Context, b batch) error {
	m := b.m
	st, ok := p.states[m.Log]
	if !ok {
		st = merkle.NewState()
	}
	broken := p.next[m.Log] != m.First
	if broken {
		p.merkle.fail("batch %s: not rebuilt: the batches before it are missing or unreadable", m.BatchID)
	}
	rs, err := p.db.QueryContext(ctx, `SELECT idx, cert_id, leaf_hash FROM read_parquet(`+sqlQuote(filepath.Join(b.dir, dataset.EntriesFile))+`) ORDER BY idx`)
	if err != nil {
		p.merkle.fail("batch %s: %s cannot be read: %v", m.BatchID, dataset.EntriesFile, err)
		broken = true
	} else {
		defer rs.Close()
		next := m.First
		for rs.Next() {
			var idx uint64
			var cert sql.Null[uint64]
			var leaf []byte
			if err := rs.Scan(&idx, &cert, &leaf); err != nil {
				return err
			}
			if cert.Valid {
				p.nRefs++
				if !p.has(cert.V) {
					p.refs.fail("log %s entry %d references cert_id %d, which names no certificate", m.Log, idx, cert.V)
				}
			}
			if broken {
				continue
			}
			if idx != next {
				p.merkle.fail("batch %s: %s has idx %d where %d was expected (a gap or a repeat in idx)", m.BatchID, dataset.EntriesFile, idx, next)
				broken = true
				continue
			}
			if len(leaf) != 32 {
				p.merkle.fail("batch %s: %s entry %d has a leaf_hash of %d bytes", m.BatchID, dataset.EntriesFile, idx, len(leaf))
				broken = true
				continue
			}
			st.Append([32]byte(leaf))
			next++
			if root, ok := p.heads[m.Log][next]; ok {
				got, _ := st.Root()
				key := [2]any{m.Log, next}
				if got != root {
					p.sths.fail("log %s: the tree rebuilt to size %d has root %x; the signed head at that size says %x", m.Log, next, got, root)
				} else {
					p.matched[key] = true
				}
			}
		}
		if err := rs.Err(); err != nil {
			p.merkle.fail("batch %s: %s cannot be read: %v", m.BatchID, dataset.EntriesFile, err)
			broken = true
		}
	}
	if !broken {
		got, _ := st.Root()
		want, _ := m.MerkleAfter.Root()
		if st.Size() != m.MerkleAfter.Size() || got != want {
			p.merkle.fail("batch %s: the tree rebuilt from entries.leaf_hash (size %d, root %x) differs from merkle_after (size %d, root %x)",
				m.BatchID, st.Size(), got, m.MerkleAfter.Size(), want)
			broken = true
		}
	}
	if broken {
		st = m.MerkleAfter.Clone() // later batches are judged on their own
	}
	p.states[m.Log], p.next[m.Log] = st, m.Last+1
	return nil
}

// chains checks that every chain's certificates exist.
func (p *pass) chains(ctx context.Context, b batch) error {
	rs, err := p.db.QueryContext(ctx, `SELECT cert_id FROM read_parquet(`+sqlQuote(filepath.Join(b.dir, dataset.ChainsFile))+`) WHERE cert_id IS NOT NULL`)
	if err != nil {
		p.refs.fail("batch %s: %s cannot be read: %v", b.m.BatchID, dataset.ChainsFile, err)
		return nil
	}
	defer rs.Close()
	for rs.Next() {
		var id uint64
		if err := rs.Scan(&id); err != nil {
			return err
		}
		p.nRefs++
		if !p.has(id) {
			p.refs.fail("batch %s: a chain references cert_id %d, which names no certificate", b.m.BatchID, id)
		}
	}
	return rs.Err()
}

// proof re-checks a batch's recorded consistency proof, if any (amendment
// A5 §2.3). A head within the committed size is also checked by the
// rebuilt tree; one beyond it without a recorded proof is skipped.
func (p *pass) proof(m commit.Manifest, committed uint64) {
	if m.Verified.Method != "consistency_proof" {
		return
	}
	if len(m.Verified.Proof) == 0 {
		if m.STH.TreeSize > committed {
			p.unproven++
		}
		return
	}
	nodes, err := m.Verified.DecodeProof()
	root, _ := m.MerkleAfter.Root()
	sth, herr := hex.DecodeString(m.STH.RootHash)
	switch {
	case err != nil:
		p.sths.fail("batch %s: its recorded proof is malformed: %v", m.BatchID, err)
	case herr != nil || len(sth) != 32:
		p.sths.fail("batch %s: its signed head's root hash is malformed", m.BatchID)
	default:
		if err := merkle.VerifyConsistency(m.Last+1, m.STH.TreeSize, root, [32]byte(sth), nodes); err != nil {
			p.sths.fail("batch %s: its recorded consistency proof to tree size %d does not verify: %v", m.BatchID, m.STH.TreeSize, err)
			return
		}
		p.proofs++
	}
}

func nullString(n sql.Null[uint64]) string {
	if !n.Valid {
		return "NULL"
	}
	return fmt.Sprint(n.V)
}

// decoder decodes records with its own codec and reader.
type decoder struct {
	codec  *vault.Codec
	reader *vault.Reader
}

func newDecoder(dirs []string, dicts []vault.Dict) (*decoder, error) {
	c, err := vault.NewCodec()
	if err != nil {
		return nil, err
	}
	for _, d := range dicts {
		if err := c.AddDict(d.Manifest.ID, d.Content); err != nil {
			c.Close()
			return nil, err
		}
	}
	r, err := vault.OpenReader(dirs, c)
	if err != nil {
		c.Close()
		return nil, err
	}
	return &decoder{codec: c, reader: r}, nil
}

func (d *decoder) close() {
	d.reader.Close()
	d.codec.Close()
}

func (d *decoder) decode(it *item) {
	var der []byte
	switch it.rec.Kind {
	case vault.KindLeaf, vault.KindChain:
		der, it.err = d.codec.Decompress(it.rec.Frame, it.rec.DictID)
	case vault.KindDelta:
		der, _, it.err = d.reader.Read(it.loc) // checks that the base lies before it and is a leaf record
		if it.err == nil {
			var base vault.Record
			base, _, it.err = d.reader.RecordAt(it.rec.BaseSeg, it.rec.BaseOff)
			it.base = base.CertID
		}
	default:
		it.err = fmt.Errorf("unknown record kind %d", it.rec.Kind)
	}
	if it.err == nil {
		it.sha = sha256.Sum256(der)
	}
}

// index compares the live index with the vault, under the writer lock, and
// only when no writer holds it (amendment A5 §1).
func (v *verifier) index(ctx context.Context, dicts []vault.Dict, c *Check) error {
	if v.writer {
		c.Status, c.Summary = StatusSkipped, v.rep.Writer
		return nil
	}
	lk, err := lock.Acquire(filepath.Join(v.o.Root, "state", "LOCK"))
	if errors.Is(err, lock.ErrHeld) {
		c.Status, c.Summary = StatusSkipped, "a writer started during the check: "+err.Error()
		return nil
	}
	if err != nil {
		return err
	}
	defer lk.Release()
	dir := filepath.Join(v.p.StateDir(), "pebble")
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) && len(v.all) == 0 {
		c.Summary = "no batch committed yet, and no index"
		return nil
	}
	x, err := index.OpenReadOnly(dir)
	switch {
	case err != nil && indexInUse(err):
		c.Status, c.Summary = StatusSkipped, "the index is in use by another holder: "+err.Error()
		return nil
	case err != nil:
		c.fail("%v (repair --reindex rebuilds it)", err)
		return nil
	}
	defer x.Close()
	d, err := newDecoder(v.o.VaultDirs, dicts)
	if err != nil {
		return err
	}
	defer d.close()
	ms := make([]commit.Manifest, len(v.all))
	for i, b := range v.all {
		ms[i] = b.m
	}
	rep, err := commit.CheckIndex(x, commit.IndexCheck{Paths: v.p, VaultDirs: v.o.VaultDirs, Codec: d.codec, ChainIDs: v.chainIDs(ctx),
		Committed: ms, Live: true, Progress: func(done, total int) { v.progress("index", done, total) }})
	switch {
	case errors.Is(err, commit.ErrCorrupt), errors.Is(err, vault.ErrCorrupt):
		c.fail("%v (repair --reindex rebuilds it)", err)
		return nil
	case err != nil:
		return err
	}
	for _, id := range rep.Pending {
		v.rep.Pending = append(v.rep.Pending, "the index has not applied batch "+id+" yet")
	}
	c.Summary = fmt.Sprintf("%s and %s map to the vault", count(rep.Certs, "certificate"), count(rep.Chains, "chain"))
	return nil
}

// chainIDs lists a chains.parquet's distinct chains, as the writer's stager
// does.
func (v *verifier) chainIDs(ctx context.Context) func(path string) ([][32]byte, error) {
	return func(path string) ([][32]byte, error) {
		rs, err := v.o.Session.DB().QueryContext(ctx, `SELECT DISTINCT chain_id FROM read_parquet(`+sqlQuote(path)+`)`)
		if err != nil {
			return nil, err
		}
		defer rs.Close()
		var out [][32]byte
		for rs.Next() {
			var b []byte
			if err := rs.Scan(&b); err != nil {
				return nil, err
			}
			if len(b) != 32 {
				return nil, fmt.Errorf("%s: a chain_id of %d bytes", path, len(b))
			}
			out = append(out, [32]byte(b))
		}
		return out, rs.Err()
	}
}

// indexInUse reports whether opening the index failed on its lock, which
// another process (or this one) holds: not damage.
func indexInUse(err error) bool {
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EACCES) || strings.Contains(err.Error(), "lock held")
}
