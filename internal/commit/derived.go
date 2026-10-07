package commit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/fsutil"
)

// DerivedFile is a batch's manifest of the derived files a local rebuild
// added after the batch committed (amendment A2 §5.3). _COMMIT.json is never
// rewritten; writing _DERIVED.json is the commit point of the rebuilt files.
const DerivedFile = "_DERIVED.json"

// DerivedFormat is _DERIVED.json's format version.
const DerivedFormat = 1

// DerivedTable is one derived file a rebuild added.
type DerivedTable struct {
	Version      int    `json:"version"`
	File         string `json:"file"`
	Bytes        int64  `json:"bytes"`
	Rows         int    `json:"rows"`
	SHA256       string `json:"sha256"`
	Extractor    string `json:"extractor"`
	SchemaSHA256 string `json:"schema_sha256"`
	PSL          string `json:"psl"`
}

// Derived is _DERIVED.json. Its JSON is deterministic, so the same binary
// over the same batch writes the same bytes: fields in a fixed order, map
// keys sorted, no timestamps. Checksum is the SHA-256 of the file's JSON
// written with Checksum empty.
type Derived struct {
	Format      int                     `json:"format"`
	BatchID     string                  `json:"batch_id"`
	Tables      map[string]DerivedTable `json:"tables"`
	ParseStatus map[string]int          `json:"parse_status"`
	// Retired names derived files that are no longer part of the batch,
	// sorted, whichever manifest listed them (amendment A5 §9).
	Retired        []string `json:"retired,omitempty"`
	CTVaultVersion string   `json:"ctvault_version"`
	Checksum       string   `json:"checksum"`
}

func (d Derived) encode() ([]byte, error) {
	d.Checksum = ""
	b, err := json.MarshalIndent(d, "", " ")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append(b, '\n'))
	d.Checksum = hex.EncodeToString(sum[:])
	b, err = json.MarshalIndent(d, "", " ")
	return append(b, '\n'), err
}

// WriteDerived replaces dir/_DERIVED.json atomically.
func WriteDerived(dir string, d Derived) error {
	b, err := d.encode()
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, DerivedFile), b, 0o644)
}

// ReadDerived reads dir/_DERIVED.json; ok is false when there is none. A file
// that fails its checksum, has an unknown format or names another batch is
// corruption.
func ReadDerived(dir string, id BatchID) (d Derived, ok bool, err error) {
	b, err := os.ReadFile(filepath.Join(dir, DerivedFile))
	if errors.Is(err, fs.ErrNotExist) {
		return d, false, nil
	}
	if err != nil {
		return d, false, err
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return d, false, corrupt("%s/%s: %v", dir, DerivedFile, err)
	}
	want, err := d.encode()
	if err != nil {
		return d, false, err
	}
	if !bytes.Equal(b, want) || d.Format != DerivedFormat || d.BatchID != id.String() {
		return d, false, corrupt("%s/%s fails its checksum or does not belong to batch %s", dir, DerivedFile, id)
	}
	return d, true, nil
}

// Retired reports whether _DERIVED.json retired a file (amendment A5 §9).
func (m Manifest) Retired(name string) bool {
	return m.Derived != nil && slices.Contains(m.Derived.Retired, name)
}

// Listed returns the batch's entry for a file that _COMMIT.json or
// _DERIVED.json lists: a file is part of a batch only then (amendment A2
// §5.3).
func (m Manifest) Listed(name string) (dataset.FileInfo, bool) {
	if m.Retired(name) {
		return dataset.FileInfo{}, false
	}
	if fi, ok := m.Files[name]; ok {
		return fi, true
	}
	if m.Derived != nil {
		for _, t := range m.Derived.Tables {
			if t.File == name {
				return dataset.FileInfo{SHA256: t.SHA256, Bytes: t.Bytes, Rows: t.Rows}, true
			}
		}
	}
	return dataset.FileInfo{}, false
}

// HookRetireRecorded is the crash point between a retirement's record and
// its delete (amendment A5 §11).
const HookRetireRecorded = "retire_recorded"

// Retire removes derived files from a committed batch (amendment A5 §9):
// _DERIVED.json is rewritten with the files in its retired list, which is
// the retirement's commit point, then the files are deleted and the folder
// synced. A retired file is no longer part of the batch; if a crash leaves
// it on disk, recovery deletes it as an unlisted file. _COMMIT.json is never
// rewritten. It returns the manifest as it now stands.
func Retire(p Paths, m Manifest, names []string, version string, hook func(string)) (Manifest, error) {
	dir := p.BatchDir(m.ID())
	d := Derived{Format: DerivedFormat, BatchID: m.BatchID, Tables: map[string]DerivedTable{}, CTVaultVersion: version}
	if m.Derived != nil {
		d = *m.Derived
		d.Tables = maps.Clone(d.Tables)
		d.Retired = slices.Clone(d.Retired)
	}
	for _, name := range names {
		for t, dt := range d.Tables {
			if dt.File == name {
				delete(d.Tables, t)
			}
		}
		if !slices.Contains(d.Retired, name) {
			d.Retired = append(d.Retired, name)
		}
	}
	slices.Sort(d.Retired)
	if err := WriteDerived(dir, d); err != nil {
		return m, err
	}
	m.Derived = &d
	call(hook, HookRetireRecorded)
	for _, name := range names {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return m, err
		}
	}
	return m, fsutil.SyncDir(dir)
}
