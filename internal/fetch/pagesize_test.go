package fetch

import (
	"context"
	"sync"
	"testing"

	"github.com/4rji/ctvault/internal/logsource"
)

// pagedSource answers any range and records the requests it got.
type pagedSource struct {
	page int
	mu   sync.Mutex
	reqs [][2]uint64
}

func (p *pagedSource) Info() logsource.LogInfo { return logsource.LogInfo{Name: "paged"} }
func (p *pagedSource) Head(context.Context) (logsource.SignedHead, error) {
	return logsource.SignedHead{}, nil
}
func (p *pagedSource) ConsistencyProof(context.Context, uint64, uint64) ([][32]byte, error) {
	return nil, nil
}
func (p *pagedSource) Issuer(context.Context, [32]byte) ([]byte, error) { return nil, nil }
func (p *pagedSource) PageSize() int                                    { return p.page }
func (p *pagedSource) Fetch(_ context.Context, start, end uint64) ([]logsource.RawEntry, error) {
	p.mu.Lock()
	p.reqs = append(p.reqs, [2]uint64{start, end})
	p.mu.Unlock()
	out := make([]logsource.RawEntry, end-start)
	for i := range out {
		out[i].Index = start + uint64(i)
	}
	return out, nil
}

// TestPageSizeFromTheSource: a source that states its page size gets
// requests aligned to it, whatever the options say (amendment A6 §4.4): a
// tiled log is read one tile per request.
func TestPageSizeFromTheSource(t *testing.T) {
	src := &pagedSource{page: 256}
	n := uint64(0)
	if _, err := Run(context.Background(), src, 100, 700, Options{PageSize: 32, MaxRPS: 1000}, func(logsource.RawEntry) error { n++; return nil }); err != nil {
		t.Fatal(err)
	}
	want := map[[2]uint64]bool{{100, 256}: true, {256, 512}: true, {512, 700}: true}
	if n != 600 || len(src.reqs) != 3 {
		t.Fatalf("%d entries in requests %v", n, src.reqs)
	}
	for _, r := range src.reqs {
		if !want[r] {
			t.Fatalf("request %v is not tile-aligned: %v", r, src.reqs)
		}
	}
}
