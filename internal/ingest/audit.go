package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/health"
	"github.com/4rji/ctvault/internal/query"
)

// HookDuringAudit is a crash point inside the post-commit audit.
const HookDuringAudit = "post_commit_audit"

// Audit sizes (amendment A3 §6).
const (
	auditCerts = 8
	auditNames = 8
)

// audit is P11 (spec §8.3, amendment A3 §6): it looks the batch it just
// committed up through the read path, over the full committed snapshot, and
// records the outcome in state/health.json. A failure is reported and
// recorded; the batch stays committed, and nothing else changes. It reads
// through the writer's own DuckDB session, so it leaves no spill folder.
func (w *Writer) audit(ctx context.Context, m commit.Manifest) {
	if !w.o.Config.Ingest.PostCommitAudit {
		return
	}
	var fails []health.Failure
	add := func(check, format string, args ...any) {
		fails = append(fails, health.Failure{Check: check, Detail: fmt.Sprintf(format, args...)})
	}
	w.runAudit(ctx, m, add)
	if err := health.Record(filepath.Join(w.o.Root, "state"), m.BatchID, m.CommitSeq, fails, w.o.Now()); err != nil {
		w.logf("warning: recording the post-commit audit of batch %s: %v", m.BatchID, err)
	}
	if len(fails) > 0 {
		w.logf("warning: post-commit audit of batch %s: %d checks failed (first: %s: %s); the batch stays committed; see state/%s",
			m.BatchID, len(fails), fails[0].Check, fails[0].Detail, health.File)
	}
}

func (w *Writer) runAudit(ctx context.Context, m commit.Manifest, add func(check, format string, args ...any)) {
	snap, err := query.Open(w.o.Root, 0)
	if err != nil {
		add("snapshot", "%v", err)
		return
	}
	certs, err := snap.Table("certs")
	if err != nil {
		return // being built or mixed: nothing to look up yet
	}
	names, err := snap.Table("names")
	if err != nil {
		return
	}
	sess := query.SessionOn(w.stager.DB())
	f, err := query.NewFetcher(snap, sess, w.o.VaultDirs)
	if err != nil {
		add("snapshot", "%v", err)
		return
	}
	defer f.Close()
	dir := w.paths.BatchDir(m.ID())
	db := w.stager.DB()

	rows, err := db.QueryContext(ctx, fmt.Sprintf(`SELECT sha256, cert_id FROM read_parquet('%s') ORDER BY sha256 LIMIT %d`,
		filepath.Join(dir, certs.File()), auditCerts))
	if err != nil {
		add("sha256", "reading the batch's certs: %v", err)
	} else {
		for rows.Next() {
			var s string
			var id uint64
			if err := rows.Scan(&s, &id); err != nil {
				add("sha256", "%v", err)
				break
			}
			var sha [32]byte
			b, _ := hex.DecodeString(s)
			copy(sha[:], b)
			if c, err := f.BySHA256(ctx, sha); err != nil || c.CertID != id || sha256.Sum256(c.DER) != sha {
				add("sha256", "%s (cert_id %d): %v", s, id, err)
			}
		}
		rows.Close()
	}
	w.hook(HookDuringAudit)

	nrows, err := db.QueryContext(ctx, fmt.Sprintf(`SELECT name, etld1 FROM read_parquet('%s') WHERE dns_valid ORDER BY name LIMIT %d`,
		filepath.Join(dir, names.File()), auditNames))
	if err != nil {
		add("name", "reading the batch's names: %v", err)
	} else {
		for nrows.Next() {
			var name string
			var etld1 *string
			if err := nrows.Scan(&name, &etld1); err != nil {
				add("name", "%v", err)
				break
			}
			if n, err := query.CountNames(ctx, snap, sess, "name", name); err != nil || n == 0 {
				add("name", "%s: %d rows (%v)", name, n, err)
			}
			if etld1 != nil {
				if n, err := query.CountNames(ctx, snap, sess, "etld1", *etld1); err != nil || n == 0 {
					add("etld1", "%s: %d rows (%v)", *etld1, n, err)
				}
			}
		}
		nrows.Close()
	}

	if m.CertIDRange != nil {
		if c, err := f.ByCertID(ctx, m.CertIDRange[0]); err != nil || c.CertID != m.CertIDRange[0] {
			add("cert_id", "%d: %v", m.CertIDRange[0], err)
		}
	}
}
