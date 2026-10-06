package ingest

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/vault"
)

// TestDeltaSampleRule: about 1 in 16 certificates is sampled, by a stable
// hash of the certificate alone (amendment A2 §6.1).
func TestDeltaSampleRule(t *testing.T) {
	n := 0
	for range 16000 {
		var sha [32]byte
		rand.Read(sha[:])
		if deltaSampled(sha) {
			n++
		}
	}
	if n < 850 || n > 1150 {
		t.Fatalf("%d of 16,000 sampled, want about 1,000", n)
	}
	sha := sha256.Sum256([]byte("x"))
	h := sha256.Sum256(append([]byte("ctvault/delta-saved-sample/v1"), sha[:]...))
	if deltaSampled(sha) != (h[0] < 16) {
		t.Fatal("the rule is SHA-256(\"ctvault/delta-saved-sample/v1\" ‖ certificate SHA-256)[0] < 16")
	}
}

// TestBatchCounters: _COMMIT.json records the fetcher's requests, 429s and
// retries, the parse_status mix of the batch's new certificates, and an
// approximate delta_saved estimated from the sampled leaf-delta records
// (amendment A2 §6.1).
func TestBatchCounters(t *testing.T) {
	h := newHarness(t, entries(t, 400), ctlogtest.Options{})
	w := h.open()
	ms := h.ingest(w, h.head(), 0, 400, 400)
	w.Close()
	m := ms[0]
	if m.Fetch == nil || m.Fetch.Requests == 0 {
		t.Fatalf("fetch counters: %+v", m.Fetch)
	}
	total := 0
	for _, n := range m.ParseStatus {
		total += n
	}
	if total != m.Counts.NewCerts || m.ParseStatus["ok"] == 0 {
		t.Fatalf("parse_status %v for %d new certificates", m.ParseStatus, m.Counts.NewCerts)
	}
	sampled := 0
	r, err := vault.OpenReader(h.opts.VaultDirs, codecFor(t, h))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	vault.Scan(h.opts.VaultDirs, m.Vault.Start, m.Vault.End, func(loc vault.Loc, rec vault.Record) error {
		if rec.Kind == vault.KindDelta {
			der, _, err := r.Read(loc)
			if err != nil {
				t.Fatal(err)
			}
			if deltaSampled(sha256.Sum256(der)) {
				sampled++
			}
		}
		return nil
	})
	if sampled == 0 {
		t.Fatal("no leaf-delta record is in the sample: the test needs more entries")
	}
	d := m.DeltaSaved
	if m.Counts.DeltaRecords == 0 || d == nil || !d.Approximate || d.DeltaRecords != m.Counts.DeltaRecords || d.SampledRecords != sampled {
		t.Fatalf("delta_saved %+v: %d delta records, %d sampled", d, m.Counts.DeltaRecords, sampled)
	}
	if d.SampledSavedBytes <= 0 || d.Bytes != d.SampledSavedBytes*int64(d.DeltaRecords)/int64(sampled) {
		t.Fatalf("delta_saved %+v does not scale its sample", d)
	}
}

func codecFor(t *testing.T, h *harness) *vault.Codec {
	t.Helper()
	c, err := vault.NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	ds, err := vault.LoadDicts(h.opts.VaultDirs)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range ds {
		c.AddDict(d.Manifest.ID, d.Content)
	}
	return c
}
