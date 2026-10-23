// Own shared client admission, storage accounting and explicit shutdown.
package comet

import (
	"bytes"
	"context"
	"crypto/tls"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Client owns a shared connection and its business roles. Use New; the zero
// value accepts no work. Do not copy a Client. Close is explicit and idempotent.
type Client struct {
	options       Options                 // Validated local configuration; Secret lives separately.
	trust         *tls.Config             // Read-only trust configuration, cloned for transports.
	ctx           context.Context         // Bounded network lifetime, including shutdown cleanup grace.
	cancel        context.CancelFunc      // Revokes Session/transports after cleanup or grace expiry.
	done          chan struct{}           // Closed after all roles, transports and workers drain.
	closed        atomic.Bool             // One-way ordinary admission boundary.
	mu            sync.Mutex              // Guards admission and the current authenticated binding.
	actors        map[*lifecycle]struct{} // Admitted owners until their actual final release.
	readers       int                     // Active reader/Observer ownership tokens.
	writers       int                     // Active Publisher/Beacon ownership tokens.
	roles         sync.WaitGroup          // Added only under mu before closed is published.
	manager       sync.WaitGroup          // Single connection supervisor completion.
	changed       chan struct{}           // Replaced after each shared binding/error transition.
	binding       *binding                // One currently published Session/target generation.
	blocked       *Error                  // Definite login rejection, awaiting explicit Secret recovery.
	secret        []byte                  // Replaced as one immutable copy; never formatted or logged.
	serial        uint64                  // Credential revision fencing old login completions.
	used          atomic.Int64            // Reserved controlled bytes, not process RSS.
	panics        atomic.Uint64           // Saturating diagnostic count, without panic values/stacks.
	explicit      chan struct{}           // Ordinary admitted unary calls, including readiness waits.
	recovery      chan struct{}           // Recovery never consumes maintenance capacity.
	maintenance   chan struct{}           // Dedicated renewal/removal reservation.
	notifications *dispatcher             // Fixed workers for coalesced state/content callbacks.
	timers        *scheduler              // Shared Beacon deadline heap and one timer.
	sampling      *sampler                // Lazily created by Tick, under mu.
}

// New validates local configuration and begins asynchronous connection/login.
// Success is not a remote readiness acknowledgment. No files or packages are fetched.
func New(options Options) (*Client, error) {
	settings, trust, failure := normalizeOptions(options)
	if failure != nil {
		return nil, failure
	}
	// Construct all owned control state before publishing the connection goroutine.
	ctx, cancel := context.WithCancel(context.Background())
	client := &Client{
		options: settings, trust: trust, ctx: ctx, cancel: cancel, done: make(chan struct{}),
		actors: make(map[*lifecycle]struct{}), changed: make(chan struct{}), secret: settings.Secret,
		explicit: make(chan struct{}, 256), recovery: make(chan struct{}, 48), maintenance: make(chan struct{}, 16),
		notifications: newDispatcher(), timers: newScheduler(),
	}
	client.options.Secret = nil
	client.manager.Add(1)
	go client.connect()
	return client, nil
}

// Secret replaces the current APIKEY's secret for subsequent authentication.
// A valid existing Session continues. Resubmission, including identical bytes,
// explicitly retries paused authentication; closed Clients never reopen.
func (client *Client) Secret(secret []byte) error {
	if client == nil || client.ctx == nil || client.closed.Load() {
		return localError(CodeClosed)
	}
	if client.options.Anonymous || len(secret) == 0 || len(secret) > 4096 {
		return localError(CodeInput)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed.Load() {
		return localError(CodeClosed)
	}
	if client.serial == ^uint64(0) {
		return localError(CodeLimit)
	}
	owned := bytes.Clone(secret)
	wipe(client.secret) // Login attempts own separate copies before releasing client.mu.
	client.secret, client.blocked = owned, nil
	client.serial++
	client.signalLocked()
	return nil
}

// Close immediately prevents new business calls and stops every admitted role.
// Bounded unregister cleanup may use the existing Session before it is canceled.
// User callbacks that already started are not forcibly terminated.
func (client *Client) Close() {
	if client == nil || client.ctx == nil {
		return
	}
	client.mu.Lock()
	if client.closed.Swap(true) {
		client.mu.Unlock()
		return
	}
	wipe(client.secret) // Established/in-flight logins already own their separate copies.
	client.secret = nil
	// Copy owners before cancellation; no role lock or callback runs under mu.
	actors := make([]*lifecycle, 0, len(client.actors))
	for actor := range client.actors {
		actors = append(actors, actor)
	}
	client.signalLocked()
	client.mu.Unlock()
	for _, actor := range actors {
		actor.stop()
	}
	go func() {
		// A stuck application callback cannot keep network credentials alive forever.
		grace := time.AfterFunc(client.options.Timeout, client.cancel)
		client.roles.Wait()
		grace.Stop()
		client.cancel()
		client.manager.Wait()
		client.timers.close()
		client.notifications.close()
		client.mu.Lock()
		sampling := client.sampling
		wipe(client.secret)
		client.secret = nil
		client.mu.Unlock()
		if sampling != nil {
			sampling.close()
		}
		close(client.done)
	}()
}

// wipe clears a drained SDK-owned secret buffer on a best-effort basis. Managed
// runtime, TLS/gRPC and immutable-string copies prevent a secure-erasure guarantee.
func wipe(secret []byte) {
	clear(secret)
	runtime.KeepAlive(secret)
}

// Wait waits for an explicitly closed Client to finish. It never calls Close.
// Waiting from one of this Client's callbacks would wait for that same callback.
func (client *Client) Wait(ctx context.Context) error {
	if client == nil || client.ctx == nil {
		if ctx == nil {
			return localError(CodeInput)
		}
		return nil
	}
	return waitDone(ctx, client.done)
}

// Panics reports sanitized asynchronous callback failures, not their values.
func (client *Client) Panics() uint64 {
	if client == nil {
		return 0
	}
	return client.panics.Load()
}

// recordPanic saturates the diagnostic counter without invoking another callback.
func (client *Client) recordPanic() {
	for {
		previous := client.panics.Load()
		if previous == ^uint64(0) || client.panics.CompareAndSwap(previous, previous+1) {
			return
		}
	}
}

// attach admits an initialized role without starting work under the Client lock.
func (client *Client) attach(life *lifecycle) *Error {
	if client == nil || client.ctx == nil {
		return localError(CodeClosed)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed.Load() {
		return localError(CodeClosed)
	}
	if life.reader {
		if client.readers >= client.options.Readers {
			return localError(CodeBusy)
		}
		client.readers++
	} else {
		if client.writers >= client.options.Beacons {
			return localError(CodeBusy)
		}
		client.writers++
	}
	client.actors[life] = struct{}{}
	client.roles.Add(1)
	return nil
}

// retire returns the role quota only after its actual callbacks/RPCs complete.
func (client *Client) retire(life *lifecycle) {
	client.mu.Lock()
	delete(client.actors, life)
	if life.reader {
		client.readers--
	} else {
		client.writers--
	}
	client.mu.Unlock()
	client.roles.Done()
}

// reserve accounts bounded storage before allocation or installation.
func (client *Client) reserve(bytes int64) bool {
	if bytes < 0 || bytes > client.options.Bytes {
		return false
	}
	for {
		previous := client.used.Load()
		if bytes > client.options.Bytes-previous {
			return false
		}
		if client.used.CompareAndSwap(previous, previous+bytes) {
			return true
		}
	}
}

// release returns storage after the final internal user releases it.
func (client *Client) release(bytes int64) { client.used.Add(-bytes) }

// claim performs immediate bounded admission, without a hidden operation queue.
func claim(slots chan struct{}) bool {
	select {
	case slots <- struct{}{}:
		return true
	default:
		return false
	}
}

// signalLocked broadcasts a state change; client.mu is held by the caller.
func (client *Client) signalLocked() {
	close(client.changed)
	client.changed = make(chan struct{})
}

// acquire waits only within the caller's original budget and freezes one binding.
func (client *Client) acquire(ctx context.Context) (*binding, *Error) {
	for {
		if cause := ctx.Err(); cause != nil {
			return nil, contextError(cause, Unapplied)
		}
		client.mu.Lock()
		if client.closed.Load() {
			client.mu.Unlock()
			return nil, localError(CodeClosed)
		}
		if client.blocked != nil {
			failure := copyError(client.blocked)
			failure.Effect = Unapplied // Readiness failed before this caller submitted business data.
			client.mu.Unlock()
			return nil, failure
		}
		if client.binding != nil && client.binding.ctx.Err() == nil {
			selected := client.binding
			client.mu.Unlock()
			return selected, nil
		}
		changed := client.changed
		client.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, contextError(ctx.Err(), Unapplied)
		}
	}
}

// current rejects late binding use without redirecting the captured request.
func (client *Client) current(selected *binding) bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	return !client.closed.Load() && client.binding == selected && selected.ctx.Err() == nil
}

// lost invalidates only the still-current binding and coalesces shared relogin.
func (client *Client) lost(selected *binding, failure *Error) {
	if failure.Code != CodeSession && failure.Code != CodeTransport && failure.Code != CodeInstance {
		return
	}
	client.mu.Lock()
	if !client.closed.Load() && client.binding == selected && selected.ctx.Err() == nil {
		selected.failure = copyError(failure)
		selected.cancel()
		client.signalLocked()
	}
	client.mu.Unlock()
}
