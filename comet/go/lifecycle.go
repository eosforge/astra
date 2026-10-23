// Keep logical closure separate from in-flight work and parent quota release.
package comet

import (
	"context"
	"sync"
)

// lifecycle owns one role's cancellation and a counted completion boundary.
// Its initial reference keeps construction/stop cleanup alive. It is never copied.
type lifecycle struct {
	client   *Client            // Shared transport and quota owner.
	ctx      context.Context    // Role cancellation, independent of factory Context.
	cancel   context.CancelFunc // Called exactly once at logical close.
	done     chan struct{}      // Closed after cleanup and every retained operation.
	mu       sync.Mutex         // Protects references/closed, never application code.
	closed   bool               // One-way transition, including failed initialization.
	active   int                // Owner plus actual operations/callbacks/timer deliveries.
	reader   bool               // Selects the subscription or writer admission quota.
	onstop   func()             // Nonblocking cancellation/detachment, outside mu.
	onfinish func()             // Release retained storage after the final operation.
}

// newLifecycle constructs an unpublished owner; attach must precede background work.
func newLifecycle(client *Client, reader bool) *lifecycle {
	ctx, cancel := context.WithCancel(context.Background())
	return &lifecycle{client: client, reader: reader, ctx: ctx, cancel: cancel, done: make(chan struct{}), active: 1}
}

// begin admits ordinary work while both owner and Client accept new operations.
func (life *lifecycle) begin() bool {
	life.mu.Lock()
	defer life.mu.Unlock()
	if life.closed || life.client.closed.Load() {
		return false
	}
	life.active++
	return true
}

// retainCleanup is used only within onstop, before the initial reference leaves.
// It preserves already-authorized bounded cleanup after ordinary admission stops.
func (life *lifecycle) retainCleanup() {
	life.mu.Lock()
	life.active++
	life.mu.Unlock()
}

// release reclaims capacity at actual completion, never merely at cancellation.
func (life *lifecycle) release() {
	life.mu.Lock()
	life.active--
	finished := life.closed && life.active == 0
	life.mu.Unlock()
	if finished {
		if life.onfinish != nil {
			life.onfinish()
		}
		life.client.retire(life)
		close(life.done)
	}
}

// stop is idempotent and performs no blocking network or callback wait.
func (life *lifecycle) stop() {
	life.mu.Lock()
	if life.closed {
		life.mu.Unlock()
		return
	}
	life.closed = true
	life.mu.Unlock()
	life.cancel()
	if life.onstop != nil {
		life.onstop()
	}
	life.release()
}

// stopped tests the cancellation boundary without locking application state.
func (life *lifecycle) stopped() bool { return life.ctx.Err() != nil || life.client.closed.Load() }
