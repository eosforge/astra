// Coordinate Beacon recovery, renewal, bounded cleanup and callback completion.
package comet

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// wake schedules a prompt nonblocking control turn in the shared timer heap.
func (beacon *Beacon) wake() { beacon.life.client.timers.at(beacon.alarm, time.Now()) }

// startLocked marks network activity before stop can capture the quiet boundary.
func (beacon *Beacon) startLocked() {
	if beacon.operations == 0 {
		beacon.quiet = make(chan struct{})
	}
	beacon.operations++
}

// settled closes the captured quiet channel after all admitted RPC work ends.
func (beacon *Beacon) settled() {
	beacon.mu.Lock()
	beacon.operations--
	if beacon.operations == 0 {
		close(beacon.quiet)
	}
	beacon.mu.Unlock()
}

// cacheLocked transfers reserved transient capacity to acknowledged cached data.
func (beacon *Beacon) cacheLocked(data Value, reserved *int64) {
	charged := int64(beacon.attr.Len()+data.Len()) + 2048
	if growth := charged - beacon.charged; growth > 0 {
		*reserved -= growth
	} else {
		beacon.life.client.release(-growth)
	}
	beacon.charged, beacon.data = charged, data
}

// publishLocked coalesces state changes without invoking application code.
func (beacon *Beacon) publishLocked(phase Phase, failure *Error) {
	if beacon.state.Phase == phase && sameFailure(beacon.state.Error, failure) {
		return
	}
	beacon.state.Phase, beacon.state.Error = phase, copyError(failure)
	if beacon.notice != nil {
		beacon.notice.pending = true
	}
	beacon.note.signal()
}

// readyLocked rechecks the lease origin and clears previous transient failure.
func (beacon *Beacon) readyLocked() {
	now, valid := leaseNow()
	phase := Uncertain
	if beacon.lease.ready(now, valid, beacon.ttl) {
		phase = Ready
	}
	beacon.failures, beacon.retry = 0, time.Time{}
	beacon.publishLocked(phase, nil)
}

// failLocked records a sanitized result and classifies recovery without replaying Data.
func (beacon *Beacon) failLocked(selected *binding, failure *Error) {
	if beacon.life.stopped() {
		return
	}
	beacon.life.client.lost(selected, failure)
	phase := Uncertain
	if permanent(failure.Code) || failure.Code == CodeObsolete {
		beacon.failed, phase = true, Failed
	} else if failure.Code == CodeEnded || failure.Code == CodeInstance {
		beacon.bound, phase = nil, Recovering
	}
	beacon.retry = time.Now().Add(max(backoff(beacon.failures), failure.Retry))
	beacon.failures = min(beacon.failures+1, 6)
	beacon.publishLocked(phase, failure)
}

// create freezes a recovery request from confirmed state and validates the full reply.
// A valid late identity is retained for best-effort cleanup even after logical close.
func (beacon *Beacon) create(ctx context.Context, selected *binding, generation uint64, reserved *int64) *Error {
	beacon.mu.Lock()
	request := &protocol.CreateRequest{Instance: []byte(selected.instance()), Scope: wireScope(beacon.scope), Attr: beacon.attr.Bytes(), Data: beacon.data.Bytes(),
		TtlMs: uint32(beacon.ttl / time.Millisecond), Uuid: []byte(beacon.state.Identity.ID), Capability: []byte(beacon.capability), Generation: generation, Order: beacon.confirmed}
	beacon.mu.Unlock()
	if !beacon.life.client.current(selected) {
		return localError(CodeInstance)
	}
	if cause := ctx.Err(); cause != nil {
		return contextError(cause, Unapplied)
	}
	sent, valid := leaseNow()
	if !valid {
		return localError(CodeClock)
	}
	beacon.mu.Lock()
	beacon.sent, beacon.hasSent = sent, true
	beacon.mu.Unlock()
	rpc, cancel := selected.context(ctx)
	var trailer metadata.MD // Errors expose only the recognized bounded detail schema.
	reply, cause := protocol.NewEphemerisClient(selected.unary).Create(rpc, request, grpc.Trailer(&trailer))
	cancel()
	beacon.mu.Lock()
	defer beacon.mu.Unlock()
	if cause != nil {
		failure := rpcError(cause, trailer)
		if beacon.life.stopped() {
			failure.Code = CodeClosed
		}
		beacon.failLocked(selected, failure)
		return failure
	}
	valid = reply != nil && validID(string(reply.Uuid)) && selected.accept(string(reply.Instance)) &&
		reply.Generation == generation && reply.TtlMs == request.TtlMs && len(reply.Capability) == 32 &&
		len(reply.Data) <= maxPayload && reply.Order >= beacon.confirmed
	if valid && beacon.state.HasIdentity {
		valid = string(reply.Uuid) == beacon.state.Identity.ID && string(reply.Capability) == beacon.capability
	} else if valid {
		valid = reply.Order == 0
	}
	if valid && reply.Order == beacon.confirmed {
		valid = string(reply.Data) == beacon.data.data
	}
	if !valid {
		failure := &Error{Code: CodeProtocol, Effect: Unknown}
		beacon.failLocked(selected, failure)
		return failure
	}
	// Installation is atomic; reply growth consumes an allowance held before send.
	beacon.cacheLocked(NewValue(reply.Data), reserved)
	beacon.state.Identity = Identity{Scope: beacon.scope, Instance: string(reply.Instance), ID: string(reply.Uuid)}
	beacon.state.HasIdentity, beacon.capability, beacon.bound = true, string(reply.Capability), selected
	beacon.confirmed, beacon.issued, beacon.renewal = reply.Order, max(beacon.issued, reply.Order), 0
	beacon.lease.confirm(sent)
	if beacon.notice != nil {
		beacon.notice.pending = true // Identity may change even if the phase stays Ready.
	}
	beacon.readyLocked()
	beacon.note.signal()
	if beacon.life.stopped() {
		return &Error{Code: CodeClosed, Effect: Unknown}
	}
	if !beacon.life.client.current(selected) {
		return &Error{Code: CodeInstance, Effect: Unknown}
	}
	selected.healthy.Store(true)
	return nil
}

// advance is a short shared-scheduler turn. Network and application work are
// dispatched only after separate bounded admission; neither runs on this goroutine.
func (beacon *Beacon) advance() {
	client := beacon.life.client
	client.mu.Lock()
	selected, blocked := client.binding, copyError(client.blocked)
	client.mu.Unlock()
	beacon.mu.Lock()
	defer beacon.mu.Unlock()
	if beacon.life.stopped() || !beacon.initialized || beacon.failed {
		return
	}
	// A finite control interval detects reauthentication and suspend even without traffic.
	now := time.Now()
	next := now.Add(100 * time.Millisecond)
	defer func() { client.timers.at(beacon.alarm, next) }()
	clock, valid := leaseNow()
	if !valid {
		beacon.publishLocked(Uncertain, localError(CodeClock))
		return
	}
	if beacon.state.Phase == Ready && !beacon.lease.ready(clock, true, beacon.ttl) {
		beacon.publishLocked(Uncertain, beacon.state.Error)
	}
	if selected == nil || selected.ctx.Err() != nil {
		if blocked == nil {
			blocked = localError(CodeTransport)
		}
		beacon.publishLocked(Uncertain, blocked)
		return
	}
	if beacon.bound != nil && beacon.bound != selected {
		if beacon.bound.endpoint == selected.endpoint && selected.instance() == beacon.state.Identity.Instance {
			// Session renewal on the same target does not consume a registration generation.
			if !beacon.active && !beacon.automatic {
				beacon.bound = selected
			}
		} else {
			beacon.bound = nil
			beacon.publishLocked(Recovering, localError(CodeInstance))
		}
	}
	if beacon.bound == nil {
		if !beacon.active && !beacon.automatic && !now.Before(beacon.retry) {
			beacon.launchLocked(selected, true)
		}
		return
	}
	if beacon.bound != selected {
		return
	}
	// Never derive a lease from acknowledgment arrival. Frequent manual sends may
	// suppress beat, while an expired confirmation budget still forces renewal.
	period := min(beacon.beat, beacon.ttl/3)
	due := !beacon.hasSent || clock < beacon.sent || clock-beacon.sent >= int64(period/time.Millisecond) || !beacon.lease.ready(clock, true, beacon.ttl)
	if !beacon.automatic && !now.Before(beacon.retry) && due {
		beacon.launchLocked(selected, false)
	}
	if !beacon.automatic && !due {
		remaining := period - time.Duration(clock-beacon.sent)*time.Millisecond
		next = earlier(next, now.Add(remaining))
	}
	if beacon.tick != nil && !beacon.sampling && !beacon.active && !now.Before(beacon.nextTick) && beacon.life.begin() {
		beacon.sampling = true
		select {
		case beacon.samples.jobs <- sampleJob{beacon: beacon, ticket: beacon.ticket}:
		default:
			beacon.sampling = false
			beacon.nextTick = now.Add(100 * time.Millisecond)
			beacon.life.release()
		}
	}
	if beacon.tick != nil && !beacon.sampling && !beacon.active {
		next = earlier(next, beacon.nextTick)
	}
}

// earlier selects a real owner deadline without allocating another timer.
func earlier(left, right time.Time) time.Time {
	if right.Before(left) {
		return right
	}
	return left
}

// launchLocked owns bounded storage, a network slot and a completion reference
// before creating a goroutine. Restoration never overlaps an active Data update.
func (beacon *Beacon) launchLocked(selected *binding, restore bool) {
	client := beacon.life.client
	slots, reserved := client.maintenance, int64(4096)
	sequence := beacon.renewal
	if restore {
		slots, reserved = client.recovery, int64(2*beacon.attr.Len()+3*maxPayload)+8192
		sequence = beacon.generation
	}
	if sequence == ^uint64(0) {
		beacon.failLocked(selected, localError(CodeLimit))
		return
	}
	if !claim(slots) {
		return
	}
	if !client.reserve(reserved) {
		<-slots
		return
	}
	if !beacon.life.begin() {
		client.release(reserved)
		<-slots
		return
	}
	beacon.automatic = true
	beacon.startLocked()
	sequence++
	if restore {
		beacon.generation = sequence
		beacon.publishLocked(Recovering, nil)
	} else {
		beacon.renewal = sequence
	}
	go func() {
		defer func() {
			client.release(reserved)
			<-slots
			beacon.mu.Lock()
			beacon.automatic = false
			beacon.mu.Unlock()
			beacon.settled()
			beacon.wake()
			beacon.life.release()
		}()
		ctx, cancel := context.WithTimeout(beacon.life.ctx, client.options.Timeout)
		defer cancel()
		if restore {
			failure := beacon.create(ctx, selected, sequence, &reserved)
			if failure != nil {
				beacon.mu.Lock()
				// create classifies RPC errors itself; pre-send failures still need backoff.
				if beacon.retry.IsZero() || time.Now().After(beacon.retry) {
					beacon.failLocked(selected, failure)
				}
				beacon.mu.Unlock()
			}
		} else {
			beacon.renew(ctx, selected, sequence)
		}
	}()
}

// renew uses its own order space and confirms only the matching registration.
func (beacon *Beacon) renew(ctx context.Context, selected *binding, order uint64) {
	beacon.mu.Lock()
	request := &protocol.RenewRequest{Instance: []byte(beacon.state.Identity.Instance), Scope: wireScope(beacon.scope), Uuid: []byte(beacon.state.Identity.ID),
		Capability: []byte(beacon.capability), Generation: beacon.generation, Order: order}
	beacon.mu.Unlock()
	sent, valid := leaseNow()
	if !valid || ctx.Err() != nil || !beacon.life.client.current(selected) {
		return
	}
	beacon.mu.Lock()
	beacon.sent, beacon.hasSent = sent, true
	beacon.mu.Unlock()
	rpc, cancel := selected.context(ctx)
	var trailer metadata.MD // Captured independently of concurrent Update trailers.
	reply, cause := protocol.NewEphemerisClient(selected.unary).Renew(rpc, request, grpc.Trailer(&trailer))
	cancel()
	beacon.mu.Lock()
	defer beacon.mu.Unlock()
	if beacon.life.stopped() || beacon.bound != selected || beacon.generation != request.Generation || !beacon.life.client.current(selected) {
		return
	}
	if cause != nil {
		beacon.failLocked(selected, rpcError(cause, trailer))
	} else if reply == nil || reply.Order != order {
		beacon.failLocked(selected, &Error{Code: CodeProtocol, Effect: Unknown})
	} else {
		beacon.lease.confirm(sent)
		beacon.readyLocked()
		selected.healthy.Store(true)
	}
}

// sample always returns serial sampling ownership, including panic or replacement.
func (beacon *Beacon) sample(ticket *sampleTicket) {
	beacon.mu.Lock()
	callback := beacon.tick
	valid := !beacon.life.stopped() && ticket == beacon.ticket && callback != nil
	beacon.mu.Unlock()
	defer func() {
		beacon.mu.Lock()
		beacon.sampling = false
		if ticket == beacon.ticket {
			beacon.nextTick = time.Now().Add(beacon.interval)
		}
		beacon.mu.Unlock()
		beacon.wake()
	}()
	if !valid {
		return
	}
	var data []byte // Application-owned output, copied only by an admitted update.
	var cause error // Error text/value is neither logged nor retained by the SDK.
	panicked := invokeCallback(func() { data, cause = callback() })
	if panicked || cause != nil {
		if panicked {
			beacon.life.client.recordPanic()
		}
		beacon.mu.Lock()
		if ticket == beacon.ticket && !beacon.life.stopped() {
			if panicked {
				beacon.tick = nil
			}
			beacon.publishLocked(beacon.state.Phase, localError(CodeCallback))
		}
		beacon.mu.Unlock()
		return
	}
	_, _ = beacon.submit(beacon.life.ctx, data, ticket)
}

// deliver serializes this Beacon's latest Changed notice, outside SDK locks.
func (beacon *Beacon) deliver() {
	beacon.mu.Lock()
	notice := beacon.notice
	if beacon.life.stopped() || notice == nil || !notice.pending {
		beacon.mu.Unlock()
		return
	}
	notice.pending = false
	state := beacon.stateLocked()
	beacon.mu.Unlock()
	if invokeCallback(func() { notice.call(state) }) {
		beacon.life.client.recordPanic()
		beacon.mu.Lock()
		if beacon.notice == notice {
			beacon.notice = nil
			beacon.state.Error = localError(CodeCallback)
		}
		beacon.mu.Unlock()
	}
}

// stop prevents new callbacks and retains one bounded cleanup task before the
// lifecycle's owner reference leaves. Existing operation completion is still counted.
func (beacon *Beacon) stop() {
	beacon.life.client.timers.cancel(beacon.alarm)
	beacon.note.stop()
	beacon.mu.Lock()
	beacon.tick, beacon.ticket, beacon.notice = nil, nil, nil
	quiet := beacon.quiet
	beacon.life.retainCleanup()
	beacon.mu.Unlock()
	go func() {
		defer beacon.life.release()
		ctx, cancel := context.WithTimeout(beacon.life.client.ctx, beacon.life.client.options.Timeout)
		defer cancel()
		select {
		case <-quiet:
			beacon.remove(ctx)
		case <-ctx.Done():
		}
	}()
}

// remove attempts one capability-bound unregister after earlier sends settle.
func (beacon *Beacon) remove(ctx context.Context) {
	beacon.mu.Lock()
	selected := beacon.bound
	if !beacon.state.HasIdentity || selected == nil {
		beacon.mu.Unlock()
		return
	}
	request := &protocol.RemoveRequest{Instance: []byte(beacon.state.Identity.Instance), Scope: wireScope(beacon.scope), Uuid: []byte(beacon.state.Identity.ID),
		Capability: []byte(beacon.capability), Generation: beacon.generation}
	beacon.mu.Unlock()
	client := beacon.life.client
	client.mu.Lock()
	if current := client.binding; current != nil && current.endpoint == selected.endpoint && current.instance() == string(request.Instance) {
		selected = current // Existing reauthentication may supply a usable cleanup Session.
	}
	client.mu.Unlock()
	if selected.ctx.Err() != nil || !claim(client.maintenance) {
		return
	}
	defer func() { <-client.maintenance }()
	if !client.reserve(4096) {
		return
	}
	defer client.release(4096)
	rpc, cancel := selected.context(ctx)
	defer cancel()
	_, _ = protocol.NewEphemerisClient(selected.unary).Remove(rpc, request)
}

// finish releases only SDK-retained data after every actual operation has drained.
func (beacon *Beacon) finish() {
	beacon.life.client.release(beacon.charged)
	beacon.mu.Lock()
	beacon.attr, beacon.data, beacon.capability, beacon.bound = Value{}, Value{}, "", nil
	beacon.mu.Unlock()
}
