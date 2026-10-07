// Package verify is `ctvault verify` (spec §8.7, amendment A5 §1-§2): it
// checks a vault without changing it. --quick reads manifests and metadata;
// --full reads every byte. It takes no lock and never stops ingestion: it
// checks the batches committed when it starts, as readers do, and leaves
// what a running writer has in flight alone.
package verify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/health"
	"github.com/4rji/ctvault/internal/lock"
	"github.com/4rji/ctvault/internal/logreg"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/query"
	"github.com/4rji/ctvault/internal/vault"
)

// ErrUsage marks options the user must correct (exit 2).
var ErrUsage = errors.New("invalid verify options")

// Options say what to verify.
type Options struct {
	Root      string
	VaultDirs []string
	VaultUUID [16]byte
	AsOf      uint64 // check the batches up to this commit_seq; 0: all
	Full      bool
	Session   *query.Session // --full: the reader session its queries run in
	Workers   int            // --full: record decoders; 0: one per core
	// Progress reports a long stage's steps (--full); it may be nil.
	Progress func(stage string, done, total int)
}

// batch is a committed batch as verify read it.
type batch struct {
	m   commit.Manifest
	dir string
}

type verifier struct {
	o   Options
	rep *Report
	p   commit.Paths

	all     []batch // every committed batch that parsed, in commit_seq order
	batches []batch // those up to --as-of
	writer  bool    // a writer holds the lock

	list, files *Check
}

// Run verifies the vault. Damage is in the report; an error means verify
// itself could not run.
func Run(ctx context.Context, o Options) (*Report, error) {
	v := &verifier{o: o, p: commit.Paths{Root: o.Root}, rep: &Report{Mode: "quick"}}
	if o.Full {
		v.rep.Mode = "full"
	}
	pid, held, err := lock.Holder(filepath.Join(o.Root, "state", "LOCK"))
	if err != nil {
		return nil, err
	}
	if held {
		v.writer = true
		v.rep.Writer = fmt.Sprintf("a writer (PID %d) is running; its batch in flight is not checked", pid)
	}
	v.list = v.rep.add("batches")
	ids := v.rep.add("ids")
	vlt := v.rep.add("vault")
	v.files = v.rep.add("files")
	if err := v.read(); err != nil {
		return nil, err
	}
	if err := v.asOf(); err != nil {
		return nil, err
	}
	v.checkBatches(v.list)
	if err := v.checkIDs(ids); err != nil {
		return nil, err
	}
	if err := v.checkVault(vlt); err != nil {
		return nil, err
	}
	v.checkFiles(v.files)
	if err := v.checkTables(v.rep.add("tables")); err != nil {
		return nil, err
	}
	v.checkSignatures(v.rep.add("sth signatures"))
	if err := v.pending(); err != nil {
		return nil, err
	}
	if err := v.health(); err != nil {
		return nil, err
	}
	if o.Full {
		if err := v.full(ctx); err != nil {
			return nil, err
		}
	}
	return v.rep, nil
}

// read reads every committed batch directory, each on its own, so that one
// unreadable manifest is reported without hiding the others (readers stop
// at the first).
func (v *verifier) read() error {
	root := filepath.Join(v.o.Root, "dataset")
	logs, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, l := range logs {
		log, ok := strings.CutPrefix(l.Name(), "log=")
		if !ok || !l.IsDir() {
			continue
		}
		bs, err := os.ReadDir(filepath.Join(root, l.Name()))
		if err != nil {
			return err
		}
		for _, b := range bs {
			span, ok := strings.CutPrefix(b.Name(), "batch=")
			if !ok || !b.IsDir() {
				continue
			}
			dir := filepath.Join(root, l.Name(), b.Name())
			if m, ok := v.manifest(dir, log, span); ok {
				v.all = append(v.all, batch{m: m, dir: dir})
			}
		}
	}
	sort.SliceStable(v.all, func(i, j int) bool {
		a, b := v.all[i].m, v.all[j].m
		return a.CommitSeq < b.CommitSeq || (a.CommitSeq == b.CommitSeq && a.BatchID < b.BatchID)
	})
	return nil
}

// manifest reads one batch's _COMMIT.json and _DERIVED.json. ok is false
// when the manifest cannot be used at all.
func (v *verifier) manifest(dir, log, span string) (commit.Manifest, bool) {
	name := log + "/" + span
	b, err := os.ReadFile(filepath.Join(dir, commit.ManifestFile))
	if err != nil {
		v.list.fail("batch %s has no readable %s: %v", name, commit.ManifestFile, err)
		return commit.Manifest{}, false
	}
	var m commit.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		v.list.fail("batch %s: %s is malformed: %v", name, commit.ManifestFile, err)
		return m, false
	}
	switch {
	case m.Format != commit.ManifestFormat:
		v.list.fail("batch %s: %s has format %d", name, commit.ManifestFile, m.Format)
		return m, false
	case m.Log != log || m.BatchID != name || fmt.Sprintf("%012d-%012d", m.First, m.Last) != span || m.First > m.Last:
		v.list.fail("batch %s: %s describes batch %s (%d-%d of %s)", name, commit.ManifestFile, m.BatchID, m.First, m.Last, m.Log)
		return m, false
	case m.CommitSeq == 0 || m.MerkleAfter == nil:
		v.list.fail("batch %s: %s lacks its commit_seq or merkle_after", name, commit.ManifestFile)
		return m, false
	}
	if m.MerkleAfter.Size() != m.Last+1 {
		v.list.fail("batch %s: merkle_after.size is %d; the batch ends at index %d", name, m.MerkleAfter.Size(), m.Last)
	}
	for _, f := range []string{dataset.EntriesFile, dataset.ChainsFile} {
		if _, ok := m.Files[f]; !ok {
			v.list.fail("batch %s: %s does not list %s", name, commit.ManifestFile, f)
		}
	}
	d, ok, err := commit.ReadDerived(dir, m.ID())
	if err != nil {
		v.files.fail("batch %s: %v", name, err)
	} else if ok {
		m.Derived = &d
	}
	return m, true
}

// asOf keeps the batches up to --as-of.
func (v *verifier) asOf() error {
	last := uint64(0)
	if n := len(v.all); n > 0 {
		last = v.all[n-1].m.CommitSeq
	}
	if v.o.AsOf > last {
		return fmt.Errorf("%w: --as-of %d: the last commit_seq is %d", ErrUsage, v.o.AsOf, last)
	}
	to := last
	if v.o.AsOf > 0 {
		to = v.o.AsOf
	}
	for _, b := range v.all {
		if b.m.CommitSeq <= to {
			v.batches = append(v.batches, b)
		}
	}
	v.rep.AsOf, v.rep.Batches = to, len(v.batches)
	return nil
}

// checkBatches: each log contiguous from index 0, and commit_seq 1..N, each
// exactly once.
func (v *verifier) checkBatches(c *Check) {
	byLog := map[string][]commit.Manifest{}
	seqs := map[uint64]int{}
	for _, b := range v.batches {
		byLog[b.m.Log] = append(byLog[b.m.Log], b.m)
		seqs[b.m.CommitSeq]++
	}
	for _, log := range slices.Sorted(maps.Keys(byLog)) {
		ms := byLog[log]
		sort.Slice(ms, func(i, j int) bool { return ms[i].First < ms[j].First })
		next := uint64(0)
		for _, m := range ms {
			switch {
			case m.First > next:
				c.fail("log %s: a gap from index %d to %d: batches are missing", log, next, m.First-1)
			case m.First < next:
				c.fail("log %s: batch %s overlaps the batch before it, which ends at index %d", log, m.BatchID, next-1)
			}
			next = max(next, m.Last+1)
		}
	}
	for seq := uint64(1); seq <= v.rep.AsOf; seq++ {
		switch n := seqs[seq]; {
		case n == 0:
			c.fail("commit_seq %d is missing: its batch directory is gone or unreadable", seq)
		case n > 1:
			c.fail("commit_seq %d appears in %d batches", seq, n)
		}
	}
	c.Summary = fmt.Sprintf("%s in %s, commit_seq 1-%d", count(len(v.batches), "batch"), count(len(byLog), "log"), v.rep.AsOf)
	if len(v.batches) == 0 {
		c.Summary = "no batch committed yet"
	}
}

// checkIDs: cert_id ranges increase with commit_seq and never overlap, and
// state/ID_FLOOR lies above every assigned cert_id.
func (v *verifier) checkIDs(c *Check) error {
	var next, assigned uint64
	for _, b := range v.batches {
		m := b.m
		if r := m.CertIDRange; r != nil {
			switch {
			case r[0] > r[1]:
				c.fail("batch %s: cert_id range %d-%d is reversed", m.BatchID, r[0], r[1])
			case r[0] <= assigned:
				c.fail("batch %s: cert_id range %d-%d overlaps cert_ids already assigned (up to %d)", m.BatchID, r[0], r[1], assigned)
			case r[0] < next:
				c.fail("batch %s: cert_id range starts at %d, below the previous batch's next_cert_id %d", m.BatchID, r[0], next)
			}
			if m.NextCertID <= r[1] {
				c.fail("batch %s: next_cert_id %d is not past its cert_id range's end %d", m.BatchID, m.NextCertID, r[1])
			}
			assigned = max(assigned, r[1])
		}
		if m.NextCertID < next {
			c.fail("batch %s: next_cert_id %d is below the previous batch's %d", m.BatchID, m.NextCertID, next)
		}
		next = max(next, m.NextCertID)
	}
	highest := uint64(0)
	for _, b := range v.all {
		highest = max(highest, b.m.NextCertID)
	}
	floor, err := commit.ReadFloor(v.p.StateDir())
	switch {
	case errors.Is(err, commit.ErrCorrupt):
		c.fail("state/ID_FLOOR: %v", err)
	case err != nil:
		return err
	case len(v.all) > 0 && floor < highest:
		c.fail("state/ID_FLOOR (%d) is below the highest next_cert_id (%d): cert_ids could be reused", floor, highest)
	}
	c.Summary = fmt.Sprintf("cert_ids up to %d, ID_FLOOR %d", assigned, floor)
	return nil
}

// tail is the committed vault tail: the end of the last batch committed.
func (v *verifier) tail() vault.Tail {
	if n := len(v.all); n > 0 {
		return v.all[n-1].m.Vault.End
	}
	return vault.Tail{}
}

// checkVault: contiguous spans, every committed segment present and its
// own, no batch's span past its segment's end, nothing past the committed
// tail that no batch in flight explains, and the dictionaries.
func (v *verifier) checkVault(c *Check) error {
	for i := 1; i < len(v.all); i++ {
		a, b := v.all[i-1].m, v.all[i].m
		if b.Vault.Start != a.Vault.End {
			c.fail("batch %s's vault span starts at %d:%d, not where batch %s's ends (%d:%d)", b.BatchID, b.Vault.Start.Segment, b.Vault.Start.Offset,
				a.BatchID, a.Vault.End.Segment, a.Vault.End.Offset)
		}
	}
	segs, err := vault.FindSegments(v.o.VaultDirs)
	if err != nil {
		c.fail("segments: %v", err)
		return nil
	}
	tail := v.tail()
	for id := uint64(1); id <= tail.Segment; id++ {
		p, ok := segs[id]
		if !ok {
			c.fail("segment %d is missing", id)
			continue
		}
		if err := vault.CheckHeader(p, id, v.o.VaultUUID); err != nil {
			c.fail("segment %d: %v", id, err)
		}
	}
	size := func(id uint64) (int64, bool) {
		st, err := os.Stat(segs[id])
		if err != nil {
			return 0, false
		}
		return st.Size(), true
	}
	for _, b := range v.all {
		end := b.m.Vault.End
		if n, ok := size(end.Segment); ok && uint64(n) < end.Offset {
			what := "batch " + b.m.BatchID + "'s span"
			if end == tail {
				what = "the committed tail"
			}
			c.fail("segment %d ends at byte %d, before %s (%d:%d)", end.Segment, n, what, end.Segment, end.Offset)
		}
	}
	if !v.writer {
		u, err := vault.InspectTail(v.o.VaultDirs, tail)
		switch {
		case errors.Is(err, vault.ErrCorrupt):
			c.fail("%v", err)
		case err != nil:
			return err
		}
		if err == nil && u.Bytes > 0 {
			in, err := v.inFlight(tail)
			if err != nil {
				return err
			}
			if in == "" {
				c.fail("%d bytes of vault data lie beyond the committed tail %d:%d and no batch in flight explains them: committed batch directories may be missing",
					u.Bytes, tail.Segment, tail.Offset)
			} else {
				v.rep.Pending = append(v.rep.Pending, fmt.Sprintf("%d vault bytes past the committed tail, from batch %s in flight", u.Bytes, in))
			}
		}
	}
	dicts, err := vault.ReadDicts(v.o.VaultDirs)
	if err != nil {
		c.fail("dictionaries: %v", err)
	}
	have := map[uint64]bool{}
	for _, d := range dicts {
		have[d.Manifest.ID] = true
	}
	for _, b := range v.batches {
		if id := b.m.Dictionary.ID; id != 0 && !have[id] {
			c.fail("batch %s uses dictionary %d, which the vault lacks", b.m.BatchID, id)
		}
	}
	c.Summary = fmt.Sprintf("%s to the committed tail %d:%d, %s", count(int(tail.Segment), "segment"), tail.Segment, tail.Offset, count(len(dicts), "dictionary"))
	return nil
}

// inFlight names the uncommitted batch whose intent starts at the committed
// tail: what recovery accepts as the cause of bytes past it (spec §8.5).
func (v *verifier) inFlight(tail vault.Tail) (string, error) {
	intents, err := commit.ReadIntents(v.p)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		if errors.Is(err, commit.ErrCorrupt) {
			return "", nil
		}
		return "", err
	}
	for _, in := range intents {
		if _, err := os.Stat(filepath.Join(v.p.BatchDir(in.ID()), commit.ManifestFile)); err != nil && in.VaultTail == tail {
			return in.BatchID, nil
		}
	}
	return "", nil
}

// checkFiles: every file a manifest lists is there with its recorded size.
func (v *verifier) checkFiles(c *Check) {
	n := 0
	for _, b := range v.batches {
		check := func(name string, bytes int64, by string) {
			n++
			st, err := os.Stat(filepath.Join(b.dir, name))
			switch {
			case err != nil:
				c.fail("batch %s: %s is missing (%v)", b.m.BatchID, name, err)
			case st.Size() != bytes:
				c.fail("batch %s: %s is %d bytes; %s says %d", b.m.BatchID, name, st.Size(), by, bytes)
			}
		}
		for _, name := range slices.Sorted(maps.Keys(b.m.Files)) {
			if !b.m.Retired(name) {
				check(name, b.m.Files[name].Bytes, commit.ManifestFile)
			}
		}
		if b.m.Derived != nil {
			for _, t := range slices.Sorted(maps.Keys(b.m.Derived.Tables)) {
				check(b.m.Derived.Tables[t].File, b.m.Derived.Tables[t].Bytes, commit.DerivedFile)
			}
		}
	}
	c.Summary = fmt.Sprintf("%s present with their recorded sizes", count(n, "file"))
}

// checkTables: ACTIVE.json is valid for this binary, a complete table's
// file is in every batch, and views.sql is what they generate.
func (v *verifier) checkTables(c *Check) error {
	a, ok, err := derive.ReadActive(v.o.Root)
	switch {
	case err != nil:
		c.fail("%s: %v", derive.ActiveFile, err)
		return nil
	case !ok && len(v.all) > 0:
		c.fail("dataset/%s is missing", derive.ActiveFile)
		return nil
	case !ok:
		c.Summary = "no table yet"
		return nil
	}
	if err := a.Check(); err != nil {
		c.fail("%v", err)
		return nil
	}
	var states []string
	for _, name := range slices.Sorted(maps.Keys(a.Tables)) {
		st := a.Tables[name]
		file := func(v int) string { return derive.Table{Name: name, Version: v}.File() }
		tb, readable := a.Readable(name)
		switch {
		case st.Status == derive.StatusMixed:
			states = append(states, fmt.Sprintf("%s mixed (v%d to v%d)", name, *st.Active, *st.Building))
		case readable && st.Building != nil:
			states = append(states, fmt.Sprintf("%s v%d complete, v%d building", name, tb.Version, *st.Building))
		case readable:
			states = append(states, fmt.Sprintf("%s v%d complete", name, tb.Version))
		default:
			states = append(states, fmt.Sprintf("%s v%d building", name, *st.Building))
		}
		if st.Retiring != nil {
			states[len(states)-1] += fmt.Sprintf(", v%d retiring", *st.Retiring)
		}
		for _, b := range v.batches {
			switch {
			case readable:
				if _, ok := b.m.Listed(tb.File()); !ok {
					c.fail("batch %s lacks %s, though %s makes v%d of %s readable", b.m.BatchID, tb.File(), derive.ActiveFile, tb.Version, name)
				}
			case st.Status == derive.StatusMixed:
				_, old := b.m.Listed(file(*st.Active))
				_, cur := b.m.Listed(file(*st.Building))
				if !old && !cur {
					c.fail("batch %s has neither %s nor %s, though %s is mixed", b.m.BatchID, file(*st.Active), file(*st.Building), name)
				}
			}
		}
	}
	got, err := os.ReadFile(filepath.Join(v.o.Root, dataset.ViewsFile))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// views.sql names the root as the writer was given it.
	spelled := v.o.Root
	if r, ok := dataset.ViewsRoot(got); ok && r != v.o.Root {
		if !sameDir(r, v.o.Root) {
			v.rep.Pending = append(v.rep.Pending, fmt.Sprintf("%s was written for a vault at %s (a moved or copied vault); the next update rewrites it", dataset.ViewsFile, r))
			c.Summary = strings.Join(states, ", ") + "; views.sql names another path"
			return nil
		}
		spelled = r
	}
	want, err := dataset.ExpectedViews(spelled, a)
	if err != nil {
		return err
	}
	views := "views.sql current"
	switch {
	case !bytes.Equal(got, want) && v.writer:
		views = "views.sql not compared: a writer is committing" // it rewrites the file after each commit
	case got == nil:
		c.fail("%s is missing", dataset.ViewsFile)
	case !bytes.Equal(got, want):
		c.fail("%s differs from what %s and the committed batches generate", dataset.ViewsFile, derive.ActiveFile)
	}
	c.Summary = strings.Join(states, ", ") + "; " + views
	return nil
}

// checkSignatures: every recorded signed head verifies with its log's
// pinned key.
func (v *verifier) checkSignatures(c *Check) {
	type head struct {
		log string
		sth commit.STH
	}
	seen := map[head]string{}
	var heads []head
	for _, b := range v.batches {
		h := head{b.m.Log, b.m.STH}
		if _, ok := seen[h]; !ok {
			seen[h] = b.m.BatchID
			heads = append(heads, h)
		}
	}
	keys := map[string]any{}
	n := 0
	for _, h := range heads {
		pub, ok := keys[h.log]
		if !ok {
			rec, err := logreg.Get(v.o.Root, h.log)
			if err == nil {
				pub, err = rec.PublicKey()
			}
			if err != nil {
				c.fail("log %s has no usable pinned key in state/logs: %v", h.log, err)
				pub = nil
			}
			keys[h.log] = pub
		}
		if pub == nil {
			continue
		}
		root, err := hex.DecodeString(h.sth.RootHash)
		sig, serr := base64.StdEncoding.DecodeString(h.sth.Signature)
		if err != nil || len(root) != 32 || serr != nil {
			c.fail("batch %s: the signed head at tree size %d is malformed (root hash or signature)", seen[h], h.sth.TreeSize)
			continue
		}
		sth := merkle.SignedTreeHead{TreeSize: h.sth.TreeSize, Timestamp: h.sth.Timestamp, RootHash: [32]byte(root), Signature: sig}
		if err := merkle.VerifySTH(pub, sth); err != nil {
			c.fail("batch %s: the signed head at tree size %d: %v", seen[h], h.sth.TreeSize, err)
			continue
		}
		n++
	}
	c.Summary = fmt.Sprintf("%s verified with the pinned keys", count(n, "signed head"))
}

// pending lists what a stopped writer left, which its next start finishes
// (spec §8.5). With a writer running, that is its work in flight.
func (v *verifier) pending() error {
	if v.writer {
		return nil
	}
	intents, err := commit.ReadIntents(v.p)
	switch {
	case errors.Is(err, commit.ErrCorrupt):
		v.list.fail("state/intent: %v", err)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return err
	}
	for _, in := range intents {
		_, err := os.Stat(filepath.Join(v.p.BatchDir(in.ID()), commit.ManifestFile))
		switch {
		case err == nil:
			v.rep.Pending = append(v.rep.Pending, "batch "+in.BatchID+" committed, and its intent remains")
		case in.Abandoned:
			// Recovery already gave the attempt up; the next update fetches
			// the batch again. That is the recovered state.
		default:
			v.rep.Pending = append(v.rep.Pending, "an intent for batch "+in.BatchID+": a writer stopped before committing it")
		}
	}
	for _, sub := range []string{"stage", "rebuild"} {
		es, err := os.ReadDir(filepath.Join(v.o.Root, "tmp", sub))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		for _, e := range es {
			v.rep.Pending = append(v.rep.Pending, "tmp/"+sub+"/"+e.Name()+" is left over")
		}
	}
	for _, name := range commit.ReindexLeftovers {
		if _, err := os.Stat(filepath.Join(v.p.StateDir(), name)); err == nil {
			v.rep.Pending = append(v.rep.Pending, "state/"+name+" is left from an interrupted repair --reindex")
		}
	}
	for _, b := range v.all {
		names, err := commit.UnlistedDerived(b.dir, b.m)
		if err != nil {
			return err
		}
		for _, name := range names {
			v.rep.Pending = append(v.rep.Pending, "batch "+b.m.BatchID+": "+name+" is not listed (an interrupted rebuild or retirement)")
		}
	}
	return nil
}

// health lists post-commit audit failures as warnings: each batch stayed
// committed (spec §8.3 P11).
func (v *verifier) health() error {
	h, ok, err := health.Read(v.p.StateDir())
	if err != nil {
		v.rep.Warnings = append(v.rep.Warnings, "state/health.json is unreadable: "+err.Error())
		return nil
	}
	if !ok {
		return nil
	}
	fs := h.Failures
	if len(fs) > 5 {
		v.rep.Warnings = append(v.rep.Warnings, fmt.Sprintf("%d post-commit audit failures are recorded; the last 5 follow", len(fs)))
		fs = fs[len(fs)-5:]
	}
	for _, f := range fs {
		v.rep.Warnings = append(v.rep.Warnings, fmt.Sprintf("the post-commit audit of batch %s (commit_seq %d) failed its %s check at %s: %s",
			f.BatchID, f.CommitSeq, f.Check, f.At.UTC().Format("2006-01-02 15:04:05Z"), f.Detail))
	}
	return nil
}

// count is "1 batch", "2 batches".
func count(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	switch {
	case strings.HasSuffix(unit, "y"):
		unit = unit[:len(unit)-1] + "ie"
	case strings.HasSuffix(unit, "ch"):
		unit += "e"
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// sameDir reports whether two paths name the same directory.
func sameDir(a, b string) bool {
	x, err := os.Stat(a)
	if err != nil {
		return false
	}
	y, err := os.Stat(b)
	return err == nil && os.SameFile(x, y)
}
