package sources

import (
	"testing"

	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/logsource/tiled"
)

// TestOpenByKind: every caller gets its source from the pinned kind
// (amendment A6 §1); an unknown kind is refused, never guessed.
func TestOpenByKind(t *testing.T) {
	chains := logsource.NewChainCache(1 << 20)
	src, err := Open(logsource.LogInfo{Name: "a", Kind: loglist.KindRFC6962, URL: "https://ct.example/a/"}, nil, chains, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := src.(*rfc6962.Source); !ok || src.Info().Name != "a" {
		t.Fatalf("rfc6962: got %T", src)
	}
	src, err = Open(logsource.LogInfo{Name: "t", Kind: loglist.KindTiled, URL: "https://mon.example/t/", Origin: "ct.example/t"}, nil, chains, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ts, ok := src.(*tiled.Source); !ok || ts.Info().Origin != "ct.example/t" || ts.PageSize() != tiled.PageSize {
		t.Fatalf("tiled: got %T", src)
	}
	if _, err := Open(logsource.LogInfo{Name: "b", Kind: "sunlight"}, nil, chains, nil); err == nil {
		t.Fatal("an unknown kind was opened")
	}
}
