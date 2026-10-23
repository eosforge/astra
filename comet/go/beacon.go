// Expose explicit Ephemeris ownership, synchronous updates and optional sampling.
package comet

import (
	"context"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// BeaconState is a local registration snapshot, not proof of remote liveness.
type BeaconState struct {
	Phase       Phase    // Ready is rechecked against the suspend-aware lease clock.
	Identity    Identity // Most recently acknowledged registration, if present.
	HasIdentity bool     // False until a valid Create reply has been installed.
	Error       *Error   // Independent sanitized copy of the latest failure.
}

// beaconNotice owns one replaceable callback and its pending delivery bit.
type beaconNotice struct {
	call    func(BeaconState) // Application code, always invoked outside SDK locks.
	pending bool              // Complete state changes coalesce before delivery.
}

// Beacon maintains one fixed Scope/Attr/TTL registration. Do not copy a Beacon.
// Use Client.Beacon and explicitly Destroy it; GC does not stop registration.
type Beacon struct {
	life        *lifecycle             // Parent admission and actual cleanup boundary.
	mu          sync.Mutex             // Protects registration, operations and callback settings.
	scope       Scope                  // Immutable public registration scope.
	attr        Value                  // Immutable fixed registration attributes.
	data        Value                  // Only acknowledged Data, never an unknown update payload.
	ttl         time.Duration          // Fixed whole-millisecond lifetime.
	beat        time.Duration          // Maximum normal interval between sends.
	state       BeaconState            // Latest local phase, identity and diagnostic.
	capability  string                 // Private recovery credential, never exposed to callbacks.
	bound       *binding               // Current acknowledged registration's transport generation.
	generation  uint64                 // Consumed before each recovery Create, never reused.
	issued      uint64                 // Consumed Data orders, including lost replies.
	confirmed   uint64                 // Data order corresponding to the recovery cache.
	renewal     uint64                 // Independent consumed renewal orders.
	lease       lease                  // Conservatively confirmed local lease budget.
	sent        int64                  // Most recent actual Create/Update/Renew send time.
	hasSent     bool                   // Distinguishes a zero timestamp from no send.
	active      bool                   // One explicit or sampled update at a time.
	automatic   bool                   // One recovery or renewal RPC at a time.
	initialized bool                   // Automatic recovery starts only after successful construction.
	failed      bool                   // Permanent errors stop automatic registration/renewal.
	operations  int                    // Active network work, excluding callbacks and timer tokens.
	quiet       chan struct{}          // Closed when operations reaches zero; replaced on admission.
	charged     int64                  // Retained Attr/Data/identity storage allowance.
	retry       time.Time              // Earliest automatic retry after failure or admission pressure.
	failures    uint                   // Bounded exponential-backoff exponent.
	alarm       *alarm                 // One replaceable shared timer entry.
	note        *notification          // One coalesced shared notification entry.
	notice      *beaconNotice          // Current Changed callback, nil when detached.
	samples     *sampler               // Shared bounded queue, present only after Tick installation.
	tick        func() ([]byte, error) // Optional complete-data sampler, outside SDK locks.
	interval    time.Duration          // Positive sampling interval, no catch-up bursts.
	nextTick    time.Time              // Next sample deadline after completion/manual admission.
	ticket      *sampleTicket          // Replaced by manual update, Tick replacement or Destroy.
	sampling    bool                   // Queued/running samples for this Beacon never overlap.
}

// Beacon synchronously registers fixed Attr and initial Data under Scope. TTL is
// 1s..10min in whole milliseconds; beat is a positive whole millisecond below TTL.
// Each body is at most 1 MiB. Nil is valid empty data. The caller must not mutate
// inputs concurrently. The factory Context controls only registration; later
// cancellation does not end a successfully returned Beacon.
func (client *Client) Beacon(ctx context.Context, scope Scope, attr, data []byte, ttl, beat time.Duration) (*Beacon, error) {
	if client == nil || client.ctx == nil || client.closed.Load() {
		return nil, localError(CodeClosed)
	}
	budget, cancel, failure := requestContext(ctx, client.options.Timeout)
	if failure != nil {
		return nil, failure
	}
	defer cancel()
	if !validScope(scope) || !validTTL(ttl) || beat <= 0 || beat >= ttl || beat%time.Millisecond != 0 || len(attr) > maxPayload || len(data) > maxPayload {
		return nil, localError(CodeInput)
	}
	// Reserve both retained state and complete in-flight/reply copies before copying.
	retained := int64(len(attr)+len(data)) + 2048
	reserved := int64(2*len(attr)+3*maxPayload) + 8192
	if !client.reserve(retained + reserved) {
		return nil, localError(CodeBusy)
	}
	beacon := &Beacon{life: newLifecycle(client, false), scope: cloneScope(scope), attr: NewValue(attr), data: NewValue(data),
		ttl: ttl, beat: beat, generation: 1, state: BeaconState{Phase: Waiting}, charged: retained, operations: 1, quiet: make(chan struct{})}
	beacon.alarm = &alarm{life: beacon.life, run: beacon.advance, index: -1}
	beacon.note = &notification{queue: client.notifications, life: beacon.life, run: beacon.deliver}
	beacon.life.onstop, beacon.life.onfinish = beacon.stop, beacon.finish
	beacon.life.active++ // Retain the factory before publishing it to concurrent Close.
	if failure := client.attach(beacon.life); failure != nil {
		client.release(retained + reserved)
		beacon.life.cancel()
		return nil, failure
	}
	defer func() { client.release(reserved); beacon.settled(); beacon.life.release() }()
	if !claim(client.explicit) {
		beacon.Destroy()
		return nil, localError(CodeBusy)
	}
	defer func() { <-client.explicit }()
	call, stop := linkedContext(budget, beacon.life.ctx)
	defer stop()
	selected, failure := client.acquire(call)
	if failure == nil {
		failure = beacon.create(call, selected, 1, &reserved)
	}
	if failure != nil {
		if beacon.life.stopped() {
			failure.Code = CodeClosed
		}
		beacon.Destroy()
		return nil, failure
	}
	beacon.mu.Lock()
	beacon.initialized = true
	beacon.mu.Unlock()
	beacon.wake()
	return beacon, nil
}

// State returns the latest local state with a fresh lease check and copied error.
func (beacon *Beacon) State() BeaconState {
	if beacon == nil || beacon.life == nil {
		return BeaconState{Phase: Closed}
	}
	beacon.mu.Lock()
	defer beacon.mu.Unlock()
	return beacon.stateLocked()
}

// stateLocked derives readiness without mutating or deleting the remote record.
func (beacon *Beacon) stateLocked() BeaconState {
	state := beacon.state
	state.Error = copyError(state.Error)
	now, valid := leaseNow()
	if beacon.life.stopped() {
		state.Phase = Closed
	} else if state.Phase == Ready && !beacon.lease.ready(now, valid, beacon.ttl) {
		state.Phase = Uncertain
	}
	return state
}

// Changed replaces the serial state callback and schedules the current state.
// Nil unregisters it. Panic disables that callback and increments Client.Panics.
func (beacon *Beacon) Changed(callback func(BeaconState)) error {
	if beacon == nil || beacon.life == nil {
		return localError(CodeClosed)
	}
	beacon.mu.Lock()
	if beacon.life.stopped() {
		beacon.mu.Unlock()
		return localError(CodeClosed)
	}
	beacon.notice = nil
	if callback != nil {
		beacon.notice = &beaconNotice{call: callback, pending: true}
	}
	beacon.mu.Unlock()
	beacon.note.signal()
	return nil
}

// Tick installs or replaces a serial sampler. interval must be positive when
// callback is non-nil; nil disables sampling. Returned bytes must be owned by the
// callback and remain unchanged until copied. An error skips submission; panic
// also disables that sampler. Neither stops beat. A valid nil slice means empty
// Data. Manual Update invalidates unfinished older samples and restarts Tick.
func (beacon *Beacon) Tick(interval time.Duration, callback func() ([]byte, error)) error {
	if beacon == nil || beacon.life == nil || beacon.life.stopped() {
		return localError(CodeClosed)
	}
	if callback != nil && interval <= 0 {
		return localError(CodeInput)
	}
	var queue *sampler // Lazy construction is outside the Beacon's admission lock.
	if callback != nil {
		queue = beacon.life.client.sampleQueue()
		if queue == nil {
			return localError(CodeClosed)
		}
	}
	beacon.mu.Lock()
	if beacon.life.stopped() {
		beacon.mu.Unlock()
		return localError(CodeClosed)
	}
	beacon.tick, beacon.samples, beacon.interval = callback, queue, interval
	beacon.ticket, beacon.nextTick = &sampleTicket{}, time.Now().Add(interval)
	beacon.mu.Unlock()
	beacon.wake()
	return nil
}

// Update synchronously replaces complete Data, consuming an internal order.
// Concurrent updates return CodeBusy. Unknown outcomes are not replayed and do
// not replace confirmed recovery data. One Context deadline covers the call.
func (beacon *Beacon) Update(ctx context.Context, data []byte) (BeaconReceipt, error) {
	return beacon.submit(ctx, data, nil)
}

// submit fences sampled results and accounts copies before admitting one send.
func (beacon *Beacon) submit(ctx context.Context, data []byte, ticket *sampleTicket) (BeaconReceipt, error) {
	if beacon == nil || beacon.life == nil || beacon.life.stopped() {
		return BeaconReceipt{}, localError(CodeClosed)
	}
	client := beacon.life.client
	budget, cancel, failure := requestContext(ctx, client.options.Timeout)
	if failure != nil {
		return BeaconReceipt{}, failure
	}
	defer cancel()
	if len(data) > maxPayload {
		return BeaconReceipt{}, localError(CodeInput)
	}
	beacon.mu.Lock()
	if ticket != nil && ticket != beacon.ticket {
		beacon.mu.Unlock()
		return BeaconReceipt{}, localError(CodeObsolete)
	}
	if beacon.active || !beacon.initialized || beacon.bound == nil || beacon.failed || beacon.state.Phase == Recovering {
		beacon.mu.Unlock()
		return BeaconReceipt{}, localError(CodeBusy)
	}
	if beacon.issued == ^uint64(0) {
		beacon.failLocked(beacon.bound, localError(CodeLimit))
		beacon.mu.Unlock()
		return BeaconReceipt{}, localError(CodeLimit)
	}
	if !beacon.life.begin() {
		beacon.mu.Unlock()
		return BeaconReceipt{}, localError(CodeClosed)
	}
	beacon.active = true
	beacon.startLocked()
	selected, generation := beacon.bound, beacon.generation
	receipt := BeaconReceipt{Identity: beacon.state.Identity, Order: beacon.issued + 1}
	capability := beacon.capability
	if ticket == nil {
		beacon.ticket, beacon.nextTick = &sampleTicket{}, time.Now().Add(beacon.interval)
	}
	beacon.mu.Unlock()
	defer func() {
		beacon.mu.Lock()
		beacon.active = false
		beacon.mu.Unlock()
		beacon.settled()
		beacon.wake()
		beacon.life.release()
	}()
	if !claim(client.explicit) {
		return BeaconReceipt{}, localError(CodeBusy)
	}
	defer func() { <-client.explicit }()
	reserved := int64(3*len(data)) + 8192
	if !client.reserve(reserved) {
		return BeaconReceipt{}, localError(CodeBusy)
	}
	defer func() { client.release(reserved) }()
	owned := NewValue(data)
	call, stop := linkedContext(budget, beacon.life.ctx)
	defer stop()
	if !client.current(selected) {
		return BeaconReceipt{}, localError(CodeInstance)
	}
	if cause := call.Err(); cause != nil {
		return BeaconReceipt{}, contextError(cause, Unapplied)
	}
	request := &protocol.UpdateRequest{Instance: []byte(receipt.Identity.Instance), Scope: wireScope(beacon.scope), Uuid: []byte(receipt.Identity.ID),
		Capability: []byte(capability), Generation: generation, Order: receipt.Order, Data: owned.Bytes()}
	sent, valid := leaseNow()
	if !valid {
		return BeaconReceipt{}, localError(CodeClock)
	}
	beacon.mu.Lock()
	// Tick replacement/manual update may have overtaken preparation before send.
	if ticket != nil && ticket != beacon.ticket {
		beacon.mu.Unlock()
		return BeaconReceipt{}, localError(CodeObsolete)
	}
	beacon.issued, beacon.sent, beacon.hasSent = receipt.Order, sent, true
	beacon.mu.Unlock()
	rpc, release := selected.context(call)
	var trailer metadata.MD // Only bounded recognized trailer fields enter Error.
	reply, cause := protocol.NewEphemerisClient(selected.unary).Update(rpc, request, grpc.Trailer(&trailer))
	release()
	beacon.mu.Lock()
	defer beacon.mu.Unlock()
	if cause != nil {
		failure := rpcError(cause, trailer)
		if beacon.life.stopped() {
			failure.Code = CodeClosed
		}
		beacon.failLocked(selected, failure)
		return BeaconReceipt{}, failure
	}
	if reply == nil || reply.Order != receipt.Order {
		failure := &Error{Code: CodeProtocol, Effect: Unknown}
		beacon.failLocked(selected, failure)
		return BeaconReceipt{}, failure
	}
	if beacon.life.stopped() {
		return BeaconReceipt{}, &Error{Code: CodeClosed, Effect: Unknown}
	}
	if !client.current(selected) || beacon.bound != selected || beacon.generation != generation {
		return BeaconReceipt{}, &Error{Code: CodeInstance, Effect: Unknown}
	}
	beacon.cacheLocked(owned, &reserved)
	beacon.confirmed = receipt.Order
	beacon.lease.confirm(sent)
	beacon.readyLocked()
	selected.healthy.Store(true)
	return receipt, nil
}

// Destroy immediately ends local ownership and schedules bounded best-effort Remove.
// It does not promise immediate remote deletion. An unknown Create may live to TTL.
func (beacon *Beacon) Destroy() {
	if beacon != nil && beacon.life != nil {
		beacon.life.stop()
	}
}

// Close is the same explicit ownership boundary as Destroy.
func (beacon *Beacon) Close() { beacon.Destroy() }

// Wait observes actual RPC/callback cleanup after Destroy; it does not close.
// Never wait for this Beacon or its Client from one of their own callbacks.
func (beacon *Beacon) Wait(ctx context.Context) error {
	if beacon == nil || beacon.life == nil {
		if ctx == nil {
			return localError(CodeInput)
		}
		return nil
	}
	return waitDone(ctx, beacon.life.done)
}
