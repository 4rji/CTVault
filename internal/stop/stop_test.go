package stop

import (
	"context"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func wait(t *testing.T, ctx context.Context, what string) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatalf("%s was not cancelled", what)
	}
}

func TestFirstSignalIsSoftSecondIsHard(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		var first, second atomic.Int32
		c := OnSignals(context.Background(), func() { first.Add(1) }, func() { second.Add(1) })
		if err := syscall.Kill(os.Getpid(), sig); err != nil {
			t.Fatal(err)
		}
		wait(t, c.Soft, "Soft")
		time.Sleep(50 * time.Millisecond)
		if c.Hard.Err() != nil || first.Load() != 1 || second.Load() != 0 {
			t.Fatalf("%v: one signal must cancel only Soft (first=%d second=%d)", sig, first.Load(), second.Load())
		}
		syscall.Kill(os.Getpid(), sig)
		wait(t, c.Hard, "Hard")
		if second.Load() != 1 {
			t.Fatalf("%v: the second signal runs onSecond", sig)
		}
		c.Close()
	}
}

func TestParentAndCloseEndBoth(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	c := OnSignals(parent, nil, nil)
	cancel()
	wait(t, c.Soft, "Soft after parent")
	wait(t, c.Hard, "Hard after parent")
	c.Close()

	c = OnSignals(context.Background(), nil, nil)
	c.Close()
	wait(t, c.Hard, "Hard after Close")
}
