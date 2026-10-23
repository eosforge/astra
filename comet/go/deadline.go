// Fence initial-confirmation and incomplete-page timers against late delivery.
package comet

import (
	"context"
	"sync"
	"time"
)

// deadline serializes timer cancellation against confirmation/page installation.
// Generation fencing prevents a delayed prior timer from canceling a later page.
type deadline struct {
	mu     sync.Mutex         // Serializes timer firing against page/login confirmation.
	timer  *time.Timer        // Current virtualizable Go timer; stopped on replacement.
	epoch  *deadlineToken     // Captured arm identity, fenced without a wrapping counter.
	timed  bool               // Once expired, this guard cannot regain a confirmation budget.
	cancel context.CancelFunc // Cancels only this captured RPC/Session generation.
}

// deadlineToken is a nonzero-sized identity retained by one timer closure.
type deadlineToken struct{ marker byte }

// newDeadline creates an inactive guard owned by one actual stream.
func newDeadline(cancel context.CancelFunc) *deadline { return &deadline{cancel: cancel} }

// arm replaces the current progress deadline; a prior expiry cannot be undone.
func (guard *deadline) arm(timeout time.Duration) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.timer != nil {
		guard.timer.Stop()
	}
	epoch := &deadlineToken{}
	guard.epoch = epoch
	guard.timer = time.AfterFunc(timeout, func() {
		guard.mu.Lock()
		defer guard.mu.Unlock()
		if guard.epoch == epoch {
			guard.timed = true
			guard.cancel()
		}
	})
}

// disarm returns false after actual expiry, even if Recv raced with cancellation.
func (guard *deadline) disarm() bool {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	guard.epoch = nil
	if guard.timer != nil {
		guard.timer.Stop()
	}
	return !guard.timed
}

// expired distinguishes local progress timeout from server/session cancellation.
func (guard *deadline) expired() bool {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	return guard.timed
}

// stop invalidates even a scheduled timer callback during final stream cleanup.
func (guard *deadline) stop() { guard.disarm() }
