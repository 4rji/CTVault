// Package stop turns SIGINT and SIGTERM into two contexts (amendment A1 §4).
// The first signal cancels Soft: finish the work in hand, start nothing new.
// The second cancels Hard: abandon the work in flight; the next start
// recovers. Hard also ends when the parent context does, and Soft ends
// whenever Hard does.
package stop

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// Contexts holds the two stop levels.
type Contexts struct {
	Soft, Hard context.Context

	ch         chan os.Signal
	done       chan struct{}
	cancelSoft context.CancelFunc
	cancelHard context.CancelFunc
}

// OnSignals starts listening. onFirst, if set, runs once on the first signal
// (to tell the user what is happening); onSecond on the second.
func OnSignals(parent context.Context, onFirst, onSecond func()) *Contexts {
	hard, cancelHard := context.WithCancel(parent)
	soft, cancelSoft := context.WithCancel(hard)
	c := &Contexts{Soft: soft, Hard: hard, ch: make(chan os.Signal, 2), done: make(chan struct{}),
		cancelSoft: cancelSoft, cancelHard: cancelHard}
	signal.Notify(c.ch, syscall.SIGINT, syscall.SIGTERM)
	go c.loop(onFirst, onSecond)
	return c
}

func (c *Contexts) loop(onFirst, onSecond func()) {
	for n := 0; ; {
		select {
		case <-c.ch:
		case <-c.done:
			return
		}
		n++
		if n == 1 {
			if onFirst != nil {
				onFirst()
			}
			c.cancelSoft()
			continue
		}
		if onSecond != nil {
			onSecond()
		}
		c.cancelHard()
		return
	}
}

// Close stops listening and releases both contexts. Signals after Close get
// Go's default behaviour again.
func (c *Contexts) Close() {
	signal.Stop(c.ch)
	close(c.done)
	c.cancelHard()
}
