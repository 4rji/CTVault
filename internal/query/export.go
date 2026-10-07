package query

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/fsutil"
)

// LogHead is the signed tree head a log's last batch in the snapshot was
// verified against: the snapshot's own committed head.
type LogHead struct {
	Log              string    `json:"log"`
	VerifiedTreeSize uint64    `json:"verified_tree_size"`
	RootHash         string    `json:"root_hash"`
	STHTimestamp     time.Time `json:"sth_timestamp"`
}

// Meta is what every export carries to be reproduced (spec §11.6,
// amendment A3 §5).
type Meta struct {
	CTVaultVersion string         `json:"ctvault_version"`
	GeneratedAt    time.Time      `json:"generated_at"`
	Query          Query          `json:"query"`
	AsOfCommitSeq  uint64         `json:"as_of_commit_seq"`
	Builders       map[string]any `json:"builders"`
	Logs           []LogHead      `json:"logs"`
	RowCount       int            `json:"row_count"`
	Approximate    bool           `json:"approximate"`
	Selection      *Selection     `json:"selection,omitempty"`
	// Mixed records how mixed tables were read (amendment A5 §10).
	Mixed []MixedTable `json:"mixed_tables,omitempty"`
}

// Selection records an export of marked rows (amendment A4 §3): the
// group's unique key and the marked rows' values, sorted. Marked rows the
// query no longer returns are recorded but not exported.
type Selection struct {
	Key    string   `json:"key"`
	Values []string `json:"values"`
}

// NewMeta describes a search's result over s.
func NewMeta(s *Snapshot, q Query, version string, now time.Time, rows int) Meta {
	m := Meta{CTVaultVersion: version, GeneratedAt: now.UTC(), Query: q, AsOfCommitSeq: s.AsOf, RowCount: rows,
		Builders: map[string]any{"extractor": derive.ExtractorVersion, "psl": derive.PSLSnapshot}, Mixed: s.mixedReads()}
	for name, st := range s.Active.Tables {
		if st.Active != nil {
			m.Builders[name] = *st.Active
		}
	}
	last := map[string]int{}
	for i, b := range s.Batches {
		if _, ok := last[b.Log]; !ok {
			m.Logs = append(m.Logs, LogHead{Log: b.Log})
		}
		last[b.Log] = i
	}
	for i := range m.Logs {
		b := s.Batches[last[m.Logs[i].Log]]
		m.Logs[i].VerifiedTreeSize, m.Logs[i].RootHash = b.STH.TreeSize, b.STH.RootHash
		m.Logs[i].STHTimestamp = time.UnixMilli(int64(b.STH.Timestamp)).UTC()
	}
	return m
}

// ExportOptions name an export's destination.
type ExportOptions struct {
	Path    string
	Format  string // md, json or csv
	Force   bool   // replace an existing file
	Version string
	Now     func() time.Time
	// Selection, when not nil, exports only the rows whose key (KeyColumn
	// of the group, as Render shows it) it holds.
	Selection []string
}

// Export writes a search's result with its metadata (amendment A3 §5). The
// rows stream to a temp file next to the destination; the final file is
// assembled, fsynced and renamed into place, so a reader never sees a
// partial export. A CSV's metadata goes to <path>.meta.json.
func Export(ctx context.Context, s *Snapshot, sess *Session, vaultDirs []string, q Query, o ExportOptions) error {
	return export(s, &q, o, func(fn rowFunc) error { return run(ctx, s, sess, vaultDirs, &q, nil, q.Limit, fn) })
}

// export writes the rows each gives; each normalizes *q before its first
// row.
func export(s *Snapshot, q *Query, o ExportOptions, each func(rowFunc) error) error {
	if o.Format != "md" && o.Format != "json" && o.Format != "csv" {
		return usage("export format %q (md, json or csv)", o.Format)
	}
	targets := []string{o.Path}
	if o.Format == "csv" {
		targets = append(targets, o.Path+".meta.json")
	}
	if !o.Force {
		for _, p := range targets {
			if _, err := os.Stat(p); err == nil {
				return fmt.Errorf("%s: %w (use --force to replace it)", p, os.ErrExist)
			}
		}
	}
	dir := filepath.Dir(o.Path)
	body, err := os.CreateTemp(dir, ".ctvault-export-*")
	if err != nil {
		return err
	}
	defer os.Remove(body.Name())
	defer body.Close()
	rw := NewRowWriter(o.Format, body)
	rows, started := 0, false
	var sel map[string]bool
	if o.Selection != nil {
		sel = map[string]bool{}
		for _, k := range o.Selection {
			sel[k] = true
		}
	}
	err = each(func(cols []string, row []any, c Cursor) error {
		if sel != nil && !sel[Render(c.Tie)] {
			return nil
		}
		if !started {
			started = true
			if err := rw.Header(cols); err != nil {
				return err
			}
		}
		rows++
		return rw.Row(row)
	})
	if err != nil {
		return err
	}
	if !started {
		if err := rw.Header(q.Columns()); err != nil {
			return err
		}
	}
	if err := rw.End(); err != nil {
		return err
	}
	meta := NewMeta(s, *q, o.Version, o.Now(), rows)
	if sel != nil {
		meta.Selection = &Selection{Key: KeyColumn(q.Group), Values: slices.Sorted(maps.Keys(sel))}
	}
	mb, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	var head, tail string
	switch o.Format {
	case "json":
		head, tail = "{\"meta\": "+string(mb)+",\n\"rows\": [\n", "\n]}\n"
	case "md":
		head = "```json\n" + string(mb) + "\n```\n\n"
	}
	if err := assemble(o.Path, head, body, tail); err != nil {
		return err
	}
	if o.Format == "csv" {
		return fsutil.WriteFileAtomic(o.Path+".meta.json", append(mb, '\n'), 0o644)
	}
	return nil
}

// assemble writes head, body's content and tail to a temp file next to
// path, fsyncs it and renames it over path.
func assemble(path, head string, body *os.File, tail string) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	if _, err := io.WriteString(f, head); err != nil {
		return err
	}
	if _, err := body.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := io.Copy(f, body); err != nil {
		return err
	}
	if _, err := io.WriteString(f, tail); err != nil {
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	ok = true
	return fsutil.SyncDir(filepath.Dir(path))
}
