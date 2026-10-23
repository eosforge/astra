// Coordinate complete stream publication, stale views and bounded notifications.
package comet

import (
	"context"
	"sync"

	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// contentNotice remembers the last delivered root for one callback registration.
type contentNotice struct {
	whole func(Map)                 // Whole-scope callback, mutually exclusive with exact.
	exact func(string, Value, bool) // Exact-key callback with explicit presence.
	last  *snapshotToken            // Identity only; avoid keeping an undelivered old root alive.
}

// viewNotice coalesces local state changes without suppressing late attachment.
type viewNotice struct {
	call    func(View) // Current application state callback.
	pending bool       // At least one undelivered local state change exists.
}

// watching shares the transport algorithm across three domains. Receiver-local
// drafts are private; mu protects installed roots, estimates and callback slots.
type watching struct {
	life      *lifecycle     // Cancellation and stream/callback drain ownership.
	domain    domain         // Distinct authority, Catalog or registration semantics.
	scope     Scope          // Immutable public subscription scope.
	target    string         // Empty for whole scope; otherwise exact key or binary ID.
	options   ReadOptions    // Fixed content/count bounds for this role.
	mu        sync.Mutex     // Installed state, callbacks and accounting commit together.
	root      *snapshot      // Last complete baseline, retained across transient failure.
	estimates table          // Ephemeris local adjustments, never sent to the server.
	phase     Phase          // Local readiness, staleness or terminal failure.
	failure   *Error         // Latest sanitized diagnostic, copied on public reads.
	content   *contentNotice // Replaceable whole-scope or exact-key registration.
	notice    *viewNotice    // Replaceable state-change registration.
	note      *notification  // One coalesced dispatch token for this role.
	stage     int64          // Current unpublished draft/duplicate metadata charge.
	decoded   int64          // Received protocol message awaiting adapter/installation completion.
	charged   int64          // Total reservation owned by this receiver.
}

// viewLocked copies wrapper/error state while retaining the immutable root.
func (watch *watching) viewLocked() View {
	view := View{Phase: watch.phase, Scope: watch.scope, Target: watch.target, Error: copyError(watch.failure), Data: Map{root: watch.root}}
	if watch.root != nil {
		view.Instance, view.Version, view.HasVersion = watch.root.instance, watch.root.version, true
	}
	return view
}

// resizeLocked adjusts a reservation before allocating/installing more state.
func (watch *watching) resizeLocked(total int64) bool {
	if total > watch.charged && !watch.life.client.reserve(total-watch.charged) {
		return false
	}
	if total < watch.charged {
		watch.life.client.release(watch.charged - total)
	}
	watch.charged = total
	return true
}

// retainedLocked computes the visible/internal roots, excluding external history.
func (watch *watching) retainedLocked() int64 {
	bytes := int64(2048)
	if watch.root != nil {
		bytes += watch.root.data.bytes
	}
	if watch.domain == ephemeris {
		bytes += watch.estimates.bytes
	}
	return bytes
}

// prepare changes only the receiver-local staging reservation.
func (watch *watching) prepare(size int64) bool {
	watch.mu.Lock()
	defer watch.mu.Unlock()
	if !watch.resizeLocked(watch.retainedLocked() + watch.decoded + size) {
		return false
	}
	watch.stage = size
	return true
}

// message accounts a decoded page until installation/discard releases it.
func (watch *watching) message(size int64) bool {
	watch.mu.Lock()
	defer watch.mu.Unlock()
	if !watch.resizeLocked(watch.retainedLocked() + watch.stage + size) {
		return false
	}
	watch.decoded = size
	return true
}

// transition records local state without creating fake content/deletion callbacks.
func (watch *watching) transition(phase Phase, failure *Error) {
	watch.mu.Lock()
	if watch.life.stopped() {
		watch.mu.Unlock()
		return
	}
	changed := watch.phase != phase || !sameFailure(watch.failure, failure)
	watch.phase, watch.failure = phase, copyError(failure)
	if watch.notice != nil && changed {
		watch.notice.pending = true
	}
	watch.mu.Unlock()
	if changed {
		watch.note.signal()
	}
}

// install commits only complete contents and invalidates exactly the affected
// local estimates. Estimates created while pages were in flight are considered here.
func (watch *watching) install(selected *binding, assembly *batch, next *snapshot) *Error {
	watch.mu.Lock()
	defer watch.mu.Unlock()
	if watch.life.stopped() {
		return localError(CodeClosed)
	}
	if !watch.life.client.current(selected) {
		return localError(CodeInstance)
	}
	estimates := watch.estimates
	if watch.domain == ephemeris {
		// Charge a second estimate root before cloning changed buckets. The copy
		// can only shrink, and remains unpublished if its combined limit fails.
		if !watch.resizeLocked(watch.retainedLocked() + watch.stage + watch.decoded + estimates.bytes + 1024) {
			return localError(CodeLimit)
		}
		if assembly.mode == protocol.Mode_MODE_RESET {
			estimates = emptyTable()
		} else {
			candidate := newDraft(estimates)
			for key := range assembly.seen {
				candidate.set(key, nil)
			}
			estimates = candidate.data
		}
		if next.data.bytes+estimates.bytes > watch.options.Bytes {
			return localError(CodeLimit)
		}
	}
	watch.root, watch.estimates, watch.phase, watch.failure = next, estimates, Ready, nil
	watch.stage = 0
	watch.resizeLocked(watch.retainedLocked() + watch.decoded)
	if watch.notice != nil {
		watch.notice.pending = true
	}
	return nil
}

// stop prevents future callbacks while preserving the last externally usable view.
func (watch *watching) stop() {
	watch.note.stop()
	watch.mu.Lock()
	watch.phase, watch.failure, watch.content, watch.notice = Closed, nil, nil, nil
	watch.mu.Unlock()
}

// finish releases internal accounting only after receiver and callbacks finish.
func (watch *watching) finish() {
	watch.mu.Lock()
	watch.life.client.release(watch.charged)
	watch.charged, watch.stage, watch.decoded = 0, 0, 0
	watch.estimates = table{}
	watch.mu.Unlock()
}

// deliver executes each selected callback outside locks, fencing replacement
// and Stop between callbacks. Panics disable only the offending registration.
func (watch *watching) deliver() {
	watch.mu.Lock()
	if watch.life.stopped() {
		watch.mu.Unlock()
		return
	}
	content, root, target := watch.content, watch.root, watch.target
	invoke := content != nil && root != nil && content.last != root.token
	if invoke {
		content.last = root.token // Linearize callback start before releasing the owner lock.
	}
	watch.mu.Unlock()
	if invoke && invokeCallback(func() {
		values := Map{root: root}
		if content.whole != nil {
			content.whole(values)
		} else {
			value, present := values.Get(target)
			content.exact(target, value, present)
		}
	}) {
		watch.life.client.recordPanic()
		watch.mu.Lock()
		if watch.content == content {
			watch.content = nil
		}
		if !watch.life.stopped() {
			watch.failure = localError(CodeCallback)
			if watch.notice != nil {
				watch.notice.pending = true
			}
		}
		watch.mu.Unlock()
	}
	watch.mu.Lock()
	notice := watch.notice
	if watch.life.stopped() || notice == nil || !notice.pending {
		watch.mu.Unlock()
		return
	}
	view := watch.viewLocked()
	notice.pending = false
	watch.mu.Unlock()
	if invokeCallback(func() { notice.call(view) }) {
		watch.life.client.recordPanic()
		watch.mu.Lock()
		if watch.notice == notice {
			watch.notice = nil
		}
		if !watch.life.stopped() {
			watch.failure = localError(CodeCallback)
		}
		watch.mu.Unlock()
	}
}

// run retries bounded stream recovery while permanent invalid content stops the
// object. There is never more than one actual receiving RPC per admitted watch.
func (watch *watching) run() {
	defer watch.life.release()
	failures, fresh, repaired := uint(0), false, false
	for !watch.life.stopped() {
		watch.mu.Lock()
		baseline := watch.root
		watch.mu.Unlock()
		selected, failure := watch.life.client.acquire(watch.life.ctx)
		if failure == nil {
			failure = watch.receive(selected, fresh)
		}
		if watch.life.stopped() {
			return
		}
		if failure == nil {
			failure = localError(CodeTransport)
		}
		watch.mu.Lock()
		if watch.root != baseline {
			fresh, failures = false, 0 // A completed repair becomes the next resumable baseline.
		}
		phase := Waiting
		if watch.root != nil {
			phase = Stale
		}
		watch.mu.Unlock()
		if permanent(failure.Code) {
			watch.transition(Failed, failure)
			return
		}
		if failure.Code == CodeHistory {
			if repaired {
				watch.transition(Failed, localError(CodeProtocol))
				return
			}
			fresh, repaired = true, true
		}
		watch.transition(phase, failure)
		if selected != nil {
			watch.life.client.lost(selected, failure)
		}
		if !pause(watch.life.ctx, max(failure.Retry, backoff(failures))) {
			return
		}
		failures = min(failures+1, 6)
	}
}

// receiver adapts the three generated stream types through their real Recv calls.
type receiver struct {
	next    func() (proto.Message, error) // One real generated Recv call on the owned stream.
	trailer func() metadata.MD            // Final transport trailers, never arbitrary error text.
}

// openStream creates one domain stream without exposing generated interfaces.
func (watch *watching) openStream(ctx context.Context, selected *binding, request *protocol.WatchRequest) (receiver, error) {
	switch watch.domain {
	case almanac:
		stream, failure := protocol.NewAlmanacClient(selected.streams).Watch(ctx, request)
		if failure != nil {
			return receiver{}, failure
		}
		return receiver{next: func() (proto.Message, error) { return stream.Recv() }, trailer: stream.Trailer}, nil
	case catalog:
		stream, failure := protocol.NewCatalogClient(selected.streams).Watch(ctx, request)
		if failure != nil {
			return receiver{}, failure
		}
		return receiver{next: func() (proto.Message, error) { return stream.Recv() }, trailer: stream.Trailer}, nil
	default:
		stream, failure := protocol.NewEphemerisClient(selected.streams).Watch(ctx, request)
		if failure != nil {
			return receiver{}, failure
		}
		return receiver{next: func() (proto.Message, error) { return stream.Recv() }, trailer: stream.Trailer}, nil
	}
}

// receive owns paging and its watchdog. Completed idle streams have no content
// deadline; initial and incomplete batches must keep making bounded progress.
func (watch *watching) receive(selected *binding, fresh bool) *Error {
	ctx, cancel := selected.context(watch.life.ctx)
	defer cancel()
	guard := newDeadline(cancel)
	defer guard.stop()
	guard.arm(watch.life.client.options.Timeout)
	watch.mu.Lock()
	current := watch.root
	watch.mu.Unlock()
	request := &protocol.WatchRequest{Scope: wireScope(watch.scope), Target: []byte(watch.target)}
	if current != nil && (!fresh || watch.domain == almanac) {
		request.Instance, request.Version = []byte(current.instance), &current.version
	}
	stream, cause := watch.openStream(ctx, selected, request)
	if cause != nil {
		if guard.expired() {
			return localError(CodeTimeout)
		}
		return rpcError(cause, nil)
	}
	assembly := batch{
		domain: watch.domain, target: watch.target, expected: selected.instance(), options: watch.options,
		current: current, first: true, fresh: fresh && watch.domain != almanac, reserve: watch.prepare,
	}
	defer assembly.clear()
	defer watch.message(0)
	for {
		message, cause := stream.next()
		if cause != nil {
			if guard.expired() {
				return localError(CodeTimeout)
			}
			failure := rpcError(cause, stream.trailer())
			if failure.Code == CodeCanceled && selected.session != "" && ctx.Err() == nil {
				failure.Code = CodeSession
			}
			return failure
		}
		if !guard.disarm() {
			return localError(CodeTimeout)
		}
		if !watch.life.client.current(selected) || watch.life.stopped() {
			return localError(CodeInstance)
		}
		// Bound raw messages and adapter rows before making additional owned copies.
		if proto.Size(message) > 8*maxPayload || messageCount(message) > watch.options.Records*2 {
			return localError(CodeLimit)
		}
		if !watch.message(pageBytes(message)) {
			return localError(CodeLimit)
		}
		input := decodePage(message)
		next, failure := assembly.accept(input)
		if failure != nil {
			return failure
		}
		if next != nil {
			if !selected.accept(next.instance) {
				return localError(CodeInstance)
			}
			if failure := watch.install(selected, &assembly, next); failure != nil {
				return failure
			}
			assembly.current, assembly.expected, assembly.first, assembly.fresh = next, next.instance, false, false
			assembly.clear()
			selected.healthy.Store(true)
			watch.note.signal()
		} else {
			guard.arm(watch.life.client.options.Timeout)
		}
		watch.message(0)
	}
}

// messageCount inspects generated lengths before allocating an adapter slice.
func messageCount(message proto.Message) int {
	switch value := message.(type) {
	case *protocol.AlmanacWatchReply:
		return len(value.Changes)
	case *protocol.CatalogWatchReply:
		return len(value.Changes)
	case *protocol.EphemerisWatchReply:
		return len(value.Changes)
	default:
		return 1 << 30
	}
}
