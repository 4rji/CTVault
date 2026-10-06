package query_test

import (
	"context"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/querytest"
)

var ctx = context.Background()

// testVault is a vault written by the production writer from a fake log.
type testVault struct {
	root string
	dirs []string
	gen  *ctlogtest.Generator
	es   []ctlogtest.Entry
}

var freeDisk = querytest.FreeDisk

// entriesWithSigner makes n entries (querytest.Pairs).
func entriesWithSigner(t testing.TB, n int) (*ctlogtest.Generator, []ctlogtest.Entry) {
	t.Helper()
	return querytest.Pairs(t, n)
}

func hostName(i int) string { return querytest.HostName(i) }

// newTestVault ingests es in batches of size into a new vault.
func newTestVault(t testing.TB, g *ctlogtest.Generator, es []ctlogtest.Entry, size uint64) *testVault {
	t.Helper()
	return newTestVaultLRU(t, g, es, size, 1000)
}

// newTestVaultLRU is newTestVault with a delta cache of lru entries.
func newTestVaultLRU(t testing.TB, g *ctlogtest.Generator, es []ctlogtest.Entry, size uint64, lru int) *testVault {
	t.Helper()
	v := querytest.New(t, g, es, size, lru)
	return &testVault{root: v.Root, dirs: v.Dirs, gen: v.Gen, es: v.Entries}
}
