// Package logreg stores the logs a vault follows, pinned at the moment they
// were added, under <root>/state/logs/<name>.json. Later changes to Chrome's
// log list never silently change a pinned key.
package logreg

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/loglist"
)

var (
	ErrExists  = errors.New("log is already pinned")
	ErrUnknown = errors.New("log is not pinned in this vault")
)

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Record is a pinned log.
type Record struct {
	Name             string            `json:"name"`
	Operator         string            `json:"operator"`
	Description      string            `json:"description"`
	URL              string            `json:"url"`
	LogID            string            `json:"log_id"`
	Key              string            `json:"key"`
	MMD              int               `json:"mmd"`
	State            string            `json:"state"`
	TemporalInterval *loglist.Interval `json:"temporal_interval,omitempty"`
	LogListVersion   string            `json:"log_list_version"`
	LogListTimestamp string            `json:"log_list_timestamp"`
	PinnedAt         time.Time         `json:"pinned_at"`
}

// FromList builds a record from a resolved log-list entry.
func FromList(l *loglist.List, r loglist.Resolved, now time.Time) Record {
	return Record{
		Name: r.Name, Operator: r.Operator, Description: r.Log.Description, URL: r.Log.URL,
		LogID: r.Log.LogID, Key: r.Log.Key, MMD: r.Log.MMD, State: r.Log.CurrentState(),
		TemporalInterval: r.Log.TemporalInterval, LogListVersion: l.Version, LogListTimestamp: l.Timestamp,
		PinnedAt: now.UTC(),
	}
}

// PublicKey returns the pinned key after re-checking it against the log ID.
func (r Record) PublicKey() (crypto.PublicKey, error) { return loglist.ParseKey(r.Key, r.LogID) }

// Dir is where records live.
func Dir(root string) string { return filepath.Join(root, "state", "logs") }

func path(root, name string) (string, error) {
	if !validName.MatchString(name) {
		return "", fmt.Errorf("invalid log name %q", name)
	}
	return filepath.Join(Dir(root), name+".json"), nil
}

// Add pins a log. The caller must hold the writer lock.
func Add(root string, r Record) error {
	if _, err := r.PublicKey(); err != nil {
		return fmt.Errorf("refusing to pin %s: %w", r.Name, err)
	}
	p, err := path(root, r.Name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(p); err == nil {
		return fmt.Errorf("%w: %s", ErrExists, r.Name)
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(p, append(b, '\n'), 0o644)
}

// Get loads one pinned log.
func Get(root, name string) (Record, error) {
	var r Record
	p, err := path(root, strings.ToLower(name))
	if err != nil {
		return r, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return r, fmt.Errorf("%w: %s (run: ctvault logs add %s)", ErrUnknown, name, name)
	}
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, fmt.Errorf("%s: %w", p, err)
	}
	return r, nil
}

// List returns every pinned log, sorted by name.
func List(root string) ([]Record, error) {
	ents, err := os.ReadDir(Dir(root))
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || e.IsDir() {
			continue
		}
		r, err := Get(root, name)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Record) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}
