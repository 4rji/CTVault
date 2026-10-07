package powerloss

import (
	"strings"
	"testing"
)

func point(seq uint64, batches map[string]string, ids map[uint64]byte) Point {
	p := Point{Seq: seq, Manifests: map[string][]byte{}, IDs: map[uint64][32]byte{}}
	for k, v := range batches {
		p.Manifests[k] = []byte(v)
	}
	for id, b := range ids {
		p.IDs[id] = [32]byte{b}
	}
	return p
}

// TestTrackerCompare: what one point shows committed survives every later
// point unchanged; a cert_id keeps its certificate; ACTIVE.json's seq never
// goes back (amendment A5 §15).
func TestTrackerCompare(t *testing.T) {
	var tr Tracker
	steps := []struct {
		p    Point
		want string // "" passes
	}{
		{point(1, nil, nil), ""},
		{point(1, map[string]string{"a/0-39": "m1"}, map[uint64]byte{1: 'x', 2: 'y'}), ""},
		{point(2, map[string]string{"a/0-39": "m1", "a/40-79": "m2"}, map[uint64]byte{1: 'x', 2: 'y', 3: 'z'}), ""},
		{point(2, map[string]string{"a/40-79": "m2"}, map[uint64]byte{1: 'x'}), "a/0-39 was committed at an earlier point and is gone"},
		{point(2, map[string]string{"a/0-39": "m1", "a/40-79": "changed"}, nil), "a/40-79 changed"},
		{point(2, map[string]string{"a/0-39": "m1", "a/40-79": "m2"}, map[uint64]byte{3: 'q'}), "cert_id 3"},
		{point(1, map[string]string{"a/0-39": "m1", "a/40-79": "m2"}, nil), "seq went back"},
		{point(3, map[string]string{"a/0-39": "m1", "a/40-79": "m2", "a/80-119": "m3"}, map[uint64]byte{4: 'w'}), ""},
	}
	for i, s := range steps {
		err := tr.Compare(s.p)
		switch {
		case s.want == "" && err != nil:
			t.Fatalf("step %d: %v", i, err)
		case s.want != "" && (err == nil || !strings.Contains(err.Error(), s.want)):
			t.Fatalf("step %d: %v, want an error mentioning %q", i, err, s.want)
		}
	}
	if tr.Points != 8 || len(tr.seen.Manifests) != 3 || tr.seen.Seq != 3 {
		t.Fatalf("tracker %+v", tr)
	}
}
