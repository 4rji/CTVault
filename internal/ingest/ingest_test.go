package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

var ctx = context.Background()

type harness struct {
	t      *testing.T
	root   string
	log    *ctlogtest.Log
	chains *logsource.ChainCache
	src    *rfc6962.Source
	opts   Options
	out    bytes.Buffer
}

func entries(t *testing.T, n int) []ctlogtest.Entry {
	t.Helper()
	g, err := ctlogtest.NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	es, err := g.Entries(n)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

func newHarness(t *testing.T, es []ctlogtest.Entry, lo ctlogtest.Options) *harness {
	t.Helper()
	h := &harness{t: t, root: t.TempDir()}
	for _, d := range []string{"state/intent", "state/incidents", "state/logs", "vault/segments", "vault/dict", "dataset", "tmp/stage", "tmp/rebuild"} {
		os.MkdirAll(filepath.Join(h.root, d), 0o755)
	}
	h.log = ctlogtest.NewWithEntries(t, es, lo)
	pub, _ := x509.ParsePKIXPublicKey(h.log.PublicKeyDER)
	h.chains = logsource.NewChainCache(logsource.DefaultChainCacheBytes)
	h.src = rfc6962.NewSource(logsource.LogInfo{Name: "fakelog", LogID: h.log.LogID, PublicKey: pub, URL: h.log.URL}, nil, h.chains, nil)
	cfg := config.Default()
	cfg.Ingest.DeltaLRUEntries = 1000
	cfg.Vault.SegmentSize = 64 << 10
	free := func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: 1 << 40, Avail: 1 << 39, Dev: 1}, nil
	}
	h.opts = Options{Root: h.root, VaultDirs: []string{filepath.Join(h.root, "vault")}, Config: cfg,
		Guard: diskguard.Guard{Cap: 0.85, Stat: free}, Version: "test", Out: &h.out, DictSamples: 1 << 30, CanarySamples: 16,
		Fetch: fetch.Options{MaxRPS: 1000, MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond},
		Now:   func() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC) }}
	return h
}

func (h *harness) open() *Writer {
	h.t.Helper()
	w, err := Open(h.opts)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { w.Close() })
	return w
}

func (h *harness) head() logsource.SignedHead {
	h.t.Helper()
	sth, err := h.src.Head(ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	return sth
}

// ingest commits [from, to) in batches of size and resets the chain cache
// after each, as update does.
func (h *harness) ingest(w *Writer, sth logsource.SignedHead, from, to, size uint64) []commit.Manifest {
	h.t.Helper()
	var ms []commit.Manifest
	for first := from; first < to; first += size {
		m, err := w.Batch(ctx, h.src, sth, first, min(first+size, to))
		if err != nil {
			h.t.Fatalf("batch at %d: %v", first, err)
		}
		h.chains.Reset()
		ms = append(ms, m)
	}
	return ms
}

func (h *harness) vaultDirs() []string { return h.opts.VaultDirs }

func TestIngestCommitsVerifiedBatches(t *testing.T) {
	es := entries(t, 200)
	h := newHarness(t, es, ctlogtest.Options{})
	w := h.open()
	sth := h.head()
	ms := h.ingest(w, sth, 0, 200, 50)
	if w.Next("fakelog") != 200 || w.LastCommitSeq() != 4 {
		t.Fatalf("next %d, commit_seq %d", w.Next("fakelog"), w.LastCommitSeq())
	}
	if ms[0].Verified.Method != "consistency_proof" || ms[3].Verified.Method != "root_equals_sth" {
		t.Fatalf("verification methods %q, %q", ms[0].Verified.Method, ms[3].Verified.Method)
	}
	if root, _ := ms[3].MerkleAfter.Root(); root != sth.RootHash {
		t.Fatal("the final compact range must reach the signed root")
	}
	// The proofs are recorded, so verify can re-check them offline
	// (amendment A5 §2.3); the batch that ends at the STH needs none.
	stored, err := commit.ListCommitted(h.opts.Root)
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range stored {
		proof, err := m.Verified.DecodeProof()
		if err != nil {
			t.Fatalf("batch %d: %v", i, err)
		}
		if i == 3 {
			if len(proof) != 0 {
				t.Fatalf("batch 3 ends at the STH, yet records %d proof nodes", len(proof))
			}
			continue
		}
		root, _ := m.MerkleAfter.Root()
		if len(proof) == 0 || len(proof) != m.Verified.ProofNodes || merkle.VerifyConsistency(m.Last+1, sth.TreeSize, root, sth.RootHash, proof) != nil {
			t.Fatalf("batch %d: %d recorded proof nodes (%d checked at ingest) do not prove its root", i, len(proof), m.Verified.ProofNodes)
		}
	}
	// A field a later version adds is ignored, as verified.proof is by
	// earlier binaries.
	mp := filepath.Join(commit.Paths{Root: h.opts.Root}.BatchDir(stored[0].ID()), commit.ManifestFile)
	b, err := os.ReadFile(mp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mp, append([]byte(`{"a_later_field": [1, 2], `), b[1:]...), 0o644); err != nil {
		t.Fatal(err)
	}
	if again, err := commit.ListCommitted(h.opts.Root); err != nil || len(again) != 4 {
		t.Fatalf("a manifest with an unknown field: %v", err)
	}
	total := 0
	for i, m := range ms {
		total += m.Counts.NewCerts
		if m.Counts.Entries != 50 || m.Counts.DeltaRecords != 25 || m.Files["entries.parquet"].Rows != 50 {
			t.Fatalf("batch %d: %+v; every final certificate follows its precert, so 25 deltas", i, m.Counts)
		}
		if want := map[bool]int{true: 1, false: 0}[i == 0]; m.Files["chains.parquet"].Rows != want {
			t.Fatalf("batch %d: %d chain rows; the CA chain is written once, in batch 0", i, m.Files["chains.parquet"].Rows)
		}
	}
	if total != 201 {
		t.Fatalf("200 certificates plus the CA: %d new certificates", total)
	}
	w.Close()
	idx, _ := index.Open(filepath.Join(h.root, "state", "pebble"))
	defer idx.Close()
	codec, _ := vault.NewCodec()
	defer codec.Close()
	r, _ := vault.OpenReader(h.vaultDirs(), codec)
	defer r.Close()
	for _, e := range es {
		sha := sha256.Sum256(e.CertDER)
		ref, ok, err := idx.Lookup(sha)
		if err != nil || !ok {
			t.Fatalf("certificate missing from the index: %v", err)
		}
		if _, err := r.ReadVerified(ref.Loc, sha); err != nil {
			t.Fatal(err)
		}
	}
	if seq, _ := idx.Applied("fakelog"); seq != 4 {
		t.Fatalf("applied %d", seq)
	}
	if v, err := os.ReadFile(filepath.Join(h.root, "views.sql")); err != nil || !bytes.Contains(v, []byte("CREATE OR REPLACE VIEW entries")) {
		t.Fatalf("views.sql: %v", err)
	}
}

func TestDedupAndLeafErrors(t *testing.T) {
	es := entries(t, 20)
	dup := es[2] // the same certificate logged again later
	dup.LeafInput = ctlogtest.MerkleTreeLeaf(dup.Timestamp+5, dup.Type, dup.PrecertTBS, dup.IssuerKeyHash)
	es = append(es, dup, ctlogtest.MalformedEntry(7))
	h := newHarness(t, es, ctlogtest.Options{})
	w := h.open()
	ms := h.ingest(w, h.head(), 0, 22, 22)
	m := ms[0]
	if m.Counts.LeafErrors != 1 || m.Files[commit.QuarantineFile].Rows != 1 || m.Counts.NewCerts != 21 {
		t.Fatalf("one quarantined leaf error, and the duplicate is not vaulted again: %+v %+v", m.Counts, m.Files)
	}
	q, _ := os.ReadFile(filepath.Join(h.root, "dataset", "log=fakelog", "batch=000000000000-000000000021", commit.QuarantineFile))
	if !bytes.Contains(q, []byte(`"idx":21`)) || !bytes.Contains(q, []byte(`"leaf_error":"leaf_bad_version"`)) {
		t.Fatalf("quarantine.ndjson: %s", q)
	}
}

func TestForkedLogIsAnIncident(t *testing.T) {
	es := entries(t, 100)
	h := newHarness(t, es, ctlogtest.Options{})
	h.log.Fork(10) // heads and proofs come from a tree whose leaf 10 differs
	w := h.open()
	floor0, _ := commit.ReadFloor(filepath.Join(h.root, "state"))
	_, err := w.Batch(ctx, h.src, h.head(), 0, 40)
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("a forked log must be an incident after one refetch: %v", err)
	}
	if h.log.Requests("get-entries") < 4 {
		t.Fatal("the batch must have been fetched twice")
	}
	inc, _ := os.ReadDir(filepath.Join(h.root, "state", "incidents"))
	if len(inc) != 1 {
		t.Fatalf("one incident directory, got %d", len(inc))
	}
	// Spec §12: the evidence holds the STH, the proof, our compact range and
	// the raw response, since the fetched data itself is truncated.
	b, err := os.ReadFile(filepath.Join(h.root, "state", "incidents", inc[0].Name(), "incident.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ev map[string]any
	json.Unmarshal(b, &ev)
	for _, k := range []string{"sth", "sth_raw", "merkle_before", "computed_root", "end", "proof", "causes"} {
		if ev[k] == nil {
			t.Errorf("incident evidence lacks %q: %s", k, b)
		}
	}
	if c, _ := ev["causes"].([]any); len(c) != 2 {
		t.Errorf("both attempts' causes are recorded: %v", ev["causes"])
	}
	if w.Next("fakelog") != 0 || w.LastCommitSeq() != 0 {
		t.Fatal("nothing may be committed")
	}
	if u, _ := vault.InspectTail(h.vaultDirs(), vault.Tail{}); u.Bytes != 0 {
		t.Fatal("the vault must be cut back")
	}
	if f, _ := commit.ReadFloor(filepath.Join(h.root, "state")); f <= floor0 {
		t.Fatal("IDs touched by the attempts are skipped")
	}
}

// crashAt makes the hook panic at point, like a SIGKILL there.
func crashAt(point string) func(string) {
	return func(p string) {
		if p == point {
			panic("crash at " + p)
		}
	}
}

func (h *harness) crashingBatch(w *Writer, sth logsource.SignedHead, first, end uint64) {
	h.t.Helper()
	defer func() {
		if recover() == nil {
			h.t.Fatal("the hook did not fire")
		}
		w.Close()
		h.chains.Reset()
	}()
	w.Batch(ctx, h.src, sth, first, end)
}

// TestRecoveryAfterCrashes kills a batch before the commit point and another
// after it but before the Pebble apply; each reopen recovers and ingestion
// ends in the same verified state as a clean run.
func TestRecoveryAfterCrashes(t *testing.T) {
	es := entries(t, 120)
	for _, point := range []string{commit.HookAfterIntent, vault.HookAppendMidRecord, vault.HookRolloverAfterHeader, HookAfterVaultSync,
		HookDuringCanary, commit.HookBeforeRename, HookBeforePebble} {
		t.Run(point, func(t *testing.T) {
			h := newHarness(t, es, ctlogtest.Options{})
			h.opts.Config.Vault.SegmentSize = 8 << 10 // batches roll over segments
			sth := h.head()
			first := h.open()
			h.ingest(first, sth, 0, 40, 40)
			first.Close()
			h.opts.Hook = crashAt(point)
			w := h.open()
			h.crashingBatch(w, sth, 40, 80)
			h.opts.Hook = nil
			w = h.open()
			if !strings.Contains(h.out.String(), "recovery:") {
				t.Fatalf("recovery must report what it did: %s", h.out.String())
			}
			h.ingest(w, sth, w.Next("fakelog"), 120, 40)
			if w.Next("fakelog") != 120 {
				t.Fatalf("next %d", w.Next("fakelog"))
			}
			ms, err := commit.ListCommitted(h.root)
			if err != nil || len(ms) != 3 {
				t.Fatalf("three contiguous committed batches: %d, %v", len(ms), err)
			}
			if root, _ := ms[2].MerkleAfter.Root(); root != sth.RootHash {
				t.Fatal("the recovered vault must verify to the signed root")
			}
			seen := map[uint64]bool{}
			for _, m := range ms {
				if m.CertIDRange == nil {
					continue
				}
				for id := m.CertIDRange[0]; id <= m.CertIDRange[1]; id++ {
					if seen[id] {
						t.Fatalf("cert_id %d committed twice", id)
					}
					seen[id] = true
				}
			}
		})
	}
}

func TestDiskCapRefusesBeforeAnyWrite(t *testing.T) {
	h := newHarness(t, entries(t, 20), ctlogtest.Options{})
	h.opts.Guard.Stat = func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: 100 << 30, Avail: 10 << 30, Dev: 1}, nil // 90% used
	}
	w := h.open()
	if _, err := w.Batch(ctx, h.src, h.head(), 0, 20); !errors.Is(err, diskguard.ErrCap) {
		t.Fatalf("a full disk refuses the batch: %v", err)
	}
	if in, _ := commit.ReadIntents(commit.Paths{Root: h.root}); len(in) != 0 || h.log.Requests("get-entries") != 0 {
		t.Fatal("nothing may be written or fetched")
	}
}

func TestDictionaryTraining(t *testing.T) {
	es := entries(t, 100)
	h := newHarness(t, es, ctlogtest.Options{})
	h.opts.DictSamples = 20
	w := h.open()
	ms := h.ingest(w, h.head(), 0, 100, 50)
	if ms[0].Dictionary.ID != 0 || ms[1].Dictionary.ID != 1 {
		t.Fatalf("batch 0 has no dictionary yet; batch 1 trains and uses dictionary 1: %+v %+v", ms[0].Dictionary, ms[1].Dictionary)
	}
	ds, err := vault.LoadDicts(h.vaultDirs())
	if err != nil || len(ds) != 1 || ds[0].Manifest.Training.Records != 20 {
		t.Fatalf("dictionary 1 on disk: %v %v", ds, err)
	}

	f := newHarness(t, es, ctlogtest.Options{})
	f.opts.DictSamples = 20
	calls := 0
	f.opts.Train = func([][]byte, uint64) ([]byte, error) { calls++; return nil, errors.New("training blew up") }
	fw := f.open()
	failed := 0
	for _, m := range f.ingest(fw, f.head(), 0, 100, 25) {
		if m.Dictionary.ID != 0 {
			t.Fatal("after a failed training every batch goes on without a dictionary")
		}
		if m.Dictionary.TrainingError != "" {
			failed++
		}
	}
	if failed != 1 || calls != 1 {
		t.Fatalf("the failure is recorded in the batch that tried, and training is tried once per run: %d records, %d calls", failed, calls)
	}
}

// TestWarmUpAfterRestart: a final certificate whose precert was committed
// before a restart is still delta-encoded, thanks to the warm-up.
func TestWarmUpAfterRestart(t *testing.T) {
	es := entries(t, 100)
	for warm, want := range map[int]int{4: 25, 0: 24} {
		h := newHarness(t, es, ctlogtest.Options{})
		h.opts.Config.Delta.WarmBatches = warm
		sth := h.head()
		w := h.open()
		h.ingest(w, sth, 0, 51, 51) // ends with the precert of pair 25
		w.Close()
		ms := h.ingest(h.open(), sth, 51, 100, 49)
		if ms[0].Counts.DeltaRecords != want {
			t.Fatalf("warm_batches %d: %d deltas, want %d", warm, ms[0].Counts.DeltaRecords, want)
		}
	}
}

// TestErrorAfterTheCommitPointKeepsTheBatch: an error after the commit
// rename (here the directory fsync fails with EACCES) must never abandon
// the batch: its vault data stays, and the next start finishes it.
func TestErrorAfterTheCommitPointKeepsTheBatch(t *testing.T) {
	es := entries(t, 40)
	h := newHarness(t, es, ctlogtest.Options{})
	logDir := filepath.Join(h.root, "dataset", "log=fakelog")
	h.opts.Hook = func(p string) {
		if p == commit.HookAfterRename {
			os.Chmod(logDir, 0)
		}
	}
	t.Cleanup(func() { os.Chmod(logDir, 0o755) })
	w := h.open()
	_, err := w.Batch(ctx, h.src, h.head(), 0, 40)
	var after errCommitted
	if !errors.As(err, &after) {
		t.Fatalf("an error after the rename must be reported as after the commit point: %v", err)
	}
	os.Chmod(logDir, 0o755)
	if u, _ := vault.InspectTail(h.vaultDirs(), vault.Tail{}); u.Bytes == 0 {
		t.Fatal("the committed batch's vault data must survive")
	}
	w.Close()
	h.opts.Hook = nil
	w = h.open()
	if w.Next("fakelog") != 40 {
		t.Fatalf("the batch stays committed: next %d", w.Next("fakelog"))
	}
	w.Close()
	idx, _ := index.Open(filepath.Join(h.root, "state", "pebble"))
	defer idx.Close()
	codec, _ := vault.NewCodec()
	defer codec.Close()
	r, _ := vault.OpenReader(h.vaultDirs(), codec)
	defer r.Close()
	sha := sha256.Sum256(es[7].CertDER)
	ref, ok, _ := idx.Lookup(sha)
	if !ok {
		t.Fatal("recovery re-applies the batch to the index")
	}
	if _, err := r.ReadVerified(ref.Loc, sha); err != nil {
		t.Fatalf("the certificate must still read back: %v", err)
	}
}

// TestAbandonedIDsAreNeverReusedAfterARestart: cert_ids an abandoned attempt
// touched are skipped forever (spec §8.6), also when the process exits after
// the abandon (an incident, a second Ctrl-C) and a later run starts afresh.
func TestAbandonedIDsAreNeverReusedAfterARestart(t *testing.T) {
	h := newHarness(t, entries(t, 60), ctlogtest.Options{})
	h.log.Fork(10)
	w := h.open()
	if _, err := w.Batch(ctx, h.src, h.head(), 0, 40); !errors.Is(err, ErrVerification) {
		t.Fatalf("setup: the forked log must end in an incident: %v", err)
	}
	w.Close()
	floor, _ := commit.ReadFloor(filepath.Join(h.root, "state"))

	honest := newHarness(t, entries(t, 60), ctlogtest.Options{}) // other certificates, same vault
	honest.opts.Root, honest.opts.VaultDirs = h.root, h.opts.VaultDirs
	hw := honest.open()
	ms := honest.ingest(hw, honest.head(), 0, 40, 40)
	if got := ms[0].CertIDRange[0]; got < floor {
		t.Fatalf("the first cert_id after the restart is %d; IDs below the floor %d were touched by the abandoned attempts", got, floor)
	}
	if in, _ := commit.ReadIntents(commit.Paths{Root: h.root}); len(in) != 0 {
		t.Fatalf("a successful commit clears the abandoned intent: %d left", len(in))
	}
}

// TestVolumeCheckRunsBeforeEveryBatch: spec §8.3 P0 and §9.2 repeat the
// volume checks at every batch preflight, so a vanished SSD stops ingestion
// before anything is written.
func TestVolumeCheckRunsBeforeEveryBatch(t *testing.T) {
	h := newHarness(t, entries(t, 80), ctlogtest.Options{})
	checks := 0
	gone := errors.New("volume check failed: the SSD is gone")
	h.opts.CheckVolumes = func() error {
		if checks++; checks > 1 {
			return gone
		}
		return nil
	}
	w := h.open()
	sth := h.head()
	if _, err := w.Batch(ctx, h.src, sth, 0, 40); err != nil {
		t.Fatal(err)
	}
	h.chains.Reset()
	if _, err := w.Batch(ctx, h.src, sth, 40, 80); !errors.Is(err, gone) {
		t.Fatalf("the second batch must stop on the failed check: %v", err)
	}
	if in, _ := commit.ReadIntents(commit.Paths{Root: h.root}); len(in) != 0 || w.Next("fakelog") != 40 {
		t.Fatal("nothing may be started after a failed volume check")
	}
}

// TestCorruptionFoundByTrainingStops: vault corruption is never ignored
// (spec §12), including when dictionary training reads committed records.
func TestCorruptionFoundByTrainingStops(t *testing.T) {
	h := newHarness(t, entries(t, 80), ctlogtest.Options{})
	h.opts.DictSamples = 20
	w := h.open()
	sth := h.head()
	h.ingest(w, sth, 0, 40, 40)
	segs, _ := vault.FindSegments(h.vaultDirs())
	b, _ := os.ReadFile(segs[1])
	b[vault.HeaderSize+40] ^= 0xff // inside the first record's frame
	os.WriteFile(segs[1], b, 0o644)
	if _, err := w.Batch(ctx, h.src, sth, 40, 80); !errors.Is(err, vault.ErrCorrupt) {
		t.Fatalf("training over a damaged record must stop the batch as corruption: %v", err)
	}
	if in, _ := commit.ReadIntents(commit.Paths{Root: h.root}); len(in) != 0 {
		t.Fatal("nothing may be started")
	}
}

// TestSegmentsGoWhereThePreflightReserved: with a second vault directory on
// another disk (vault add-dir, spec §10.2), a batch that only fits there
// must write its segments there, not onto the root volume.
func TestSegmentsGoWhereThePreflightReserved(t *testing.T) {
	h := newHarness(t, entries(t, 80), ctlogtest.Options{})
	second := filepath.Join(t.TempDir(), "disk2")
	os.MkdirAll(filepath.Join(second, "segments"), 0o755)
	os.MkdirAll(filepath.Join(second, "dict"), 0o755)
	h.opts.VaultDirs = append(h.opts.VaultDirs, second)
	h.opts.Guard.Stat = func(p string) (diskguard.Usage, error) {
		if strings.HasPrefix(p, second) {
			return diskguard.Usage{Total: 1 << 40, Avail: 1 << 40, Dev: 2}, nil
		}
		// The root volume: 6.5 GiB below the cap, enough for the root's own
		// peak (spill budget, Pebble reserve) but not for a vault peak too.
		return diskguard.Usage{Total: 100 << 30, Avail: 21<<30 + 512<<20, Dev: 1}, nil
	}
	w := h.open()
	h.ingest(w, h.head(), 0, 80, 40)
	segs, _ := vault.FindSegments(h.opts.VaultDirs)
	for id, p := range segs {
		if !strings.HasPrefix(p, second) {
			t.Fatalf("segment %d went to %s; the preflight reserved the vault peak on %s", id, p, second)
		}
	}
	if len(segs) == 0 {
		t.Fatal("no segments written")
	}
}
