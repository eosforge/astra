// Deliver authoritative state through owned streams with bounded progress and lifecycle handling.

package server

import (
	"context"
	"errors"
	"io"
	rand "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eosforge/astra/internal/admission"
	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/orbit"
	"github.com/eosforge/astra/internal/generated/polaris"
	"github.com/eosforge/astra/polaris/internal/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Streams shares management snapshot cache, permits one current stream per Star instance, and never dials back.
type Streams struct {
	polaris.UnimplementedAlmanacServer
	node      *admission.Node     // Admission node provides directory and Session verification.
	authority *Authority          // Authority supplies persistent storage and snapshot cache.
	mutex     sync.Mutex          // Short lock protecting active instances.
	active    map[string]struct{} // Online instance IDs; a second connection for one instance is rejected.
	slots     chan struct{}       // 16 stream permits; full capacity rejects immediately.
	workers   sync.WaitGroup      // Background send/receive workers; Wait awaits every exit.
}

// NewStreams starts no worker or listener; authority storage must already be recovered.
func NewStreams(node *admission.Node, authority *Authority) *Streams {
	return &Streams{node: node, authority: authority, active: make(map[string]struct{}), slots: make(chan struct{}, 16)}
}

// Wait follows gRPC admission stop and handler completion; actual send/receive resources must exit before storage closes.
func (streams *Streams) Wait() { streams.workers.Wait() }

// incoming has one Recv owner and a one-frame channel, preventing unbounded control-message predecoding.
type incoming struct {
	packet *polaris.Packet // Decoded frame, nil on error.
	err    error           // Receive error including EOF; nil for a normal frame.
}

// transfer protocol state belongs only to run's goroutine; Open monitors blocked-stage deadlines.
type transfer struct {
	owner     *Streams                                                 // Owning stream collection for directory and instance checks.
	wire      grpc.BidiStreamingServer[polaris.Packet, polaris.Packet] // Bidi stream with one owner per I/O direction.
	ctx       context.Context                                          // Transfer context canceled when handler exits.
	input     chan incoming                                            // Decoded-frame queue, capacity one, separating receive from processing.
	received  chan struct{}                                            // Receive-worker exit signal, awaited before permit return.
	deadline  atomic.Pointer[time.Time]                                // Current blocked-stage deadline monitored by Open.
	wake      chan struct{}                                            // Capacity-one deadline-change wake, nonblocking for run.
	remote    *orbit.Member                                            // Peer Star identity fixed after handshake.
	maximum   int                                                      // Peer-declared maximum frame bytes; sending must respect it.
	installed map[storage.Scope]storage.Version                        // Confirmed installed positions for initial readiness and reconciliation.
	sent      map[storage.Scope]storage.Version                        // Sent positions; ACK cannot exceed them.
	plan      map[storage.Scope]storage.Version                        // Frozen initial plan; later changes do not redefine initial completion.
	probe     map[storage.Scope]storage.Version                        // Peer reconciliation inventory under construction, transferred to actual when complete.
	boundary  map[storage.Scope]storage.Version                        // Sent positions at probe time, excluding later sends from loss classification.
	floor     map[storage.Scope]storage.Version                        // Installed positions at probe time, forming the loss-detection floor.
	actual    map[storage.Scope]storage.Version                        // Completed reconciliation result awaiting reconcile.
	credits   []credit                                                 // Sending credits; see window.go.
	bytes     int64                                                    // In-flight byte charges for credit admission.
	ready     bool                                                     // Initial completion flag; Ready sends once.
}

// Open retains handler authority to end the RPC under monotonic deadlines even when slow peers block Send/Recv.
// Return permits only after actual worker and Recv exit; cancellation alone does not release resources.
// wire is the bidi stream; returns protocol result or deadline error for blocked slow peers.
func (streams *Streams) Open(wire grpc.BidiStreamingServer[polaris.Packet, polaris.Packet]) error {
	// Acquire stream permit first; reject without queuing at capacity.
	select {
	case streams.slots <- struct{}{}:
	default:
		return status.Error(codes.ResourceExhausted, "Almanac stream capacity exceeded")
	}
	// Derived transfer context is canceled on every exit to unblock I/O.
	ctx, cancel := context.WithCancel(wire.Context())
	defer cancel()
	transfer := &transfer{owner: streams, wire: wire, ctx: ctx, input: make(chan incoming, 1), received: make(chan struct{}), wake: make(chan struct{}, 1), maximum: 8 << 20, installed: make(map[storage.Scope]storage.Version), sent: make(map[storage.Scope]storage.Version)}
	done := make(chan error, 1)
	streams.workers.Add(1)
	// Receive only decodes/queues while run owns protocol; received enforces worker-exit ordering.
	go transfer.receive()
	go func() {
		defer streams.workers.Done()
		// run borrows no mutable Open stack state. Handler return cancels transport; actual Recv drains before permit return.
		err := transfer.run()
		done <- err
		<-transfer.received
		<-streams.slots
	}()
	// Stage-deadline changes wake this monotonic timer monitor; blocked slow peers end at expiry.
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		select {
		case err := <-done:

			return err
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		case <-transfer.wake:
			// Reset timer on deadline change, or stop it when no stage deadline exists.
			if deadline := transfer.deadline.Load(); deadline != nil {
				timer.Reset(max(time.Until(*deadline), time.Nanosecond))
			} else {
				timer.Stop()
			}
		case <-timer.C:
			// A wake may have extended or cleared the phase after this timer became ready.
			if err := transfer.expire(timer); err != nil {
				return err
			}
		}
	}
}

// expire checks the current phase after a timer notification, preserving a concurrently extended deadline.
// Only the watchdog owns timer; the protocol worker publishes deadline atomically.
func (transfer *transfer) expire(timer *time.Timer) error {
	deadline := transfer.deadline.Load()
	if deadline == nil {
		return nil
	}
	remaining := time.Until(*deadline)
	if remaining <= 0 {
		return status.Error(codes.DeadlineExceeded, "Almanac stream progress deadline exceeded")
	}
	timer.Reset(remaining)
	return nil
}

// wait sets a finite blocked-stage duration; zero clears it. time.Time retains local monotonic time and changes wake Open.
func (transfer *transfer) wait(duration time.Duration) {
	if duration == 0 {
		transfer.deadline.Store(nil)
	} else {
		deadline := time.Now().Add(duration)
		transfer.deadline.Store(&deadline)
	}
	// Wake send is nonblocking; a full channel already contains a pending notification.
	select {
	case transfer.wake <- struct{}{}:
	default:
	}
}

// receive alone decodes; handler-return cancellation unblocks transport without releasing snapshots still used by run.
func (transfer *transfer) receive() {
	defer close(transfer.received)
	// Queue frames/errors until cancellation or stream failure; main protocol path decides receive errors.
	for {
		packet, err := transfer.wire.Recv()
		select {
		case transfer.input <- incoming{packet: packet, err: err}:
		case <-transfer.ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

// next returns one decoded frame or error; EOF never substitutes for initial-sync completion.
func (transfer *transfer) next() (*polaris.Packet, error) {
	select {
	case item := <-transfer.input:
		if errors.Is(item.err, io.EOF) {
			// Normal peer EOF ends protocol with cancellation, not successful synchronization.
			return nil, status.Error(codes.Canceled, "Almanac upstream closed")
		}
		return item.packet, item.err
	case <-transfer.ctx.Done():
		return nil, transfer.ctx.Err()
	}
}

// send exclusively owns writes; reuse quota only after actual page send. Identity replacement forbids further pages.
// Validate context, instance currency, and Packet size, then apply a 30-second blocked-send deadline.
func (transfer *transfer) send(packet *polaris.Packet) error {

	if transfer.ctx.Err() != nil {
		return transfer.ctx.Err()
	}

	if transfer.remote != nil && !transfer.owner.node.Directory().Current(transfer.remote) {
		return status.Error(codes.Unauthenticated, "Star admission replaced")
	}

	if proto.Size(packet) > transfer.maximum {
		return status.Error(codes.ResourceExhausted, "Almanac frame exceeds receiver capacity")
	}
	// Clear stage deadline after send; Open judges stalled-peer expiry.
	transfer.wait(30 * time.Second)
	err := transfer.wire.Send(packet)
	transfer.wait(0)
	return err
}

// inventory collects one complete installed-position list with unique Scopes within deployment capacity; no partial table is published.
func (transfer *transfer) inventory() (map[storage.Scope]storage.Version, error) {
	positions := make(map[storage.Scope]storage.Version)
	// Ten-second inventory deadline is enforced by Open.
	transfer.wait(10 * time.Second)
	defer transfer.wait(0)

	for {
		packet, err := transfer.next()
		if err != nil {
			return nil, err
		}
		page := packet.GetInventory()
		if page == nil {
			return nil, status.Error(codes.InvalidArgument, "Expected complete installation inventory")
		}
		if err := transfer.positions(positions, page); err != nil {
			return nil, err
		}
		if page.Complete {
			return positions, nil
		}
	}
}

// positions merges metadata-bounded pages; version zero is a complete baseline distinct from an absent map entry.
// target receives page entries after uniqueness and Scope validation.
func (transfer *transfer) positions(target map[storage.Scope]storage.Version, page *polaris.Inventory) error {
	for _, position := range page.Positions {
		// Reject nil entries rather than skipping them.
		if position == nil || position.Scope == nil {
			return status.Error(codes.InvalidArgument, "Missing installation scope")
		}
		scope := storage.Scope{Sector: string(position.Scope.Sector), Spectrum: string(position.Scope.Spectrum)}
		// Reject duplicate or invalid Scopes to prevent ambiguous inventories.
		if _, duplicate := target[scope]; duplicate || !scope.Valid() {
			return status.Error(codes.InvalidArgument, "Invalid or duplicate installation scope")
		}
		// Scope count cannot exceed deployment capacity.
		if int64(len(target)) >= transfer.owner.authority.store.Limits().Scopes {
			return status.Error(codes.ResourceExhausted, "Installation inventory capacity exceeded")
		}
		target[scope] = storage.Version(position.Version)
	}
	return nil
}

// run freezes the initial inventory, installs Scopes with a retained commit suffix, and bases readiness on actual installation ACKs.
func (transfer *transfer) run() error {
	// First frame has a ten-second limit and must be valid Hello with major version 1 and frame cap 1 KiB..8 MiB.
	transfer.wait(10 * time.Second)
	packet, err := transfer.next()
	transfer.wait(0)
	if err != nil {
		return err
	}
	hello := packet.GetHello()
	if hello == nil || hello.ProtocolMajor != 1 || hello.MaxFrameBytes < 1024 || hello.MaxFrameBytes > 8<<20 {
		return status.Error(codes.InvalidArgument, "Invalid Almanac Hello")
	}
	// Verify peer Star signature and use its declared send cap.
	transfer.remote, err = transfer.owner.node.Directory().Verify(hello.Admission, hello.AdmissionSignature, orbit.Role_ROLE_STAR)
	if err != nil {
		return err
	}
	transfer.maximum = int(hello.MaxFrameBytes)
	// Reject duplicate same-instance streams; reconnect waits for actual old handler/buffer exit without mutual preemption loops.
	transfer.owner.mutex.Lock()
	if _, exists := transfer.owner.active[string(transfer.remote.Id)]; exists {
		transfer.owner.mutex.Unlock()
		return status.Error(codes.AlreadyExists, "Star already has an Almanac stream")
	}
	transfer.owner.active[string(transfer.remote.Id)] = struct{}{}
	transfer.owner.mutex.Unlock()
	defer func() {
		transfer.owner.mutex.Lock()
		delete(transfer.owner.active, string(transfer.remote.Id))
		transfer.owner.mutex.Unlock()
	}()
	// Return local Hello only after admission readiness.
	local := transfer.owner.node.Hello()
	if local == nil {
		return status.Error(codes.Unavailable, "Polaris admission pending")
	}
	if err := transfer.send(&polaris.Packet{Body: &polaris.Packet_Hello{Hello: local}}); err != nil {
		return err
	}
	// Collect peer installed positions as the initial starting point.
	transfer.installed, err = transfer.inventory()
	if err != nil {
		return err
	}
	// Subscribe to concurrent commits before freezing the plan so Scopes created during initialization/discovery are not lost.
	feed, err := transfer.owner.authority.store.Subscribe(8<<20, 16384)
	if err != nil {
		return failure(err)
	}
	defer feed.Close()
	// Freeze complete current authority positions; reject peer positions ahead of authority.
	positions, err := transfer.owner.authority.store.List(transfer.ctx)
	if err != nil {
		return failure(err)
	}
	transfer.plan = make(map[storage.Scope]storage.Version, len(positions))
	for _, position := range positions {
		transfer.plan[position.Scope] = position.Version
	}
	for scope, version := range transfer.installed {
		if current, exists := transfer.plan[scope]; !exists || version > current {
			return status.Error(codes.Aborted, "Star is ahead of authority database")
		}
		transfer.sent[scope] = version
	}
	// Send initial plan and synchronize each Scope, consuming controls between Scopes.
	if err := transfer.manifest(positions); err != nil {
		return err
	}
	for _, position := range positions {
		if err := transfer.synchronize(position); err != nil {
			return err
		}
		if err := transfer.drain(); err != nil {
			return err
		}
	}
	// Event-driven steady state handles reconciliation results, initial completion, periodic probes, and commit suffix in that order.
	period := time.NewTimer(30*time.Second + time.Duration(rand.IntN(5000))*time.Millisecond)
	defer period.Stop()
	for {

		if transfer.actual != nil {
			actual := transfer.actual
			transfer.actual = nil
			if err := transfer.reconcile(actual); err != nil {
				return err
			}
		}

		if err := transfer.complete(); err != nil {
			return err
		}
		// Continuous writes must still check reconciliation time instead of waiting for an idle Feed.
		select {
		case <-period.C:
			if err := transfer.assess(); err != nil {
				return err
			}
			period.Reset(30*time.Second + time.Duration(rand.IntN(5000))*time.Millisecond)
		default:
		}

		changed := feed.Ready()
		events, err := feed.Take()
		if err != nil {
			return failure(err)
		}
		for begin := 0; begin < len(events); {
			// Combine adjacent same-Scope events into bounded sends while preserving each +1 version, avoiding one network round trip per commit.
			scope := events[begin].Scope
			if _, exists := transfer.sent[scope]; !exists {
				// A new Scope needs an actual complete snapshot; its first Patch cannot fabricate an empty baseline.
				if err := transfer.synchronize(storage.Position{Scope: scope, Version: events[begin].Version}); err != nil {
					return err
				}
			}
			changes := make([]storage.Change, 0, min(128, len(events)-begin))
			version := transfer.sent[scope]
			// Versions remain contiguous +1; skip already-sent events and reject gaps.
			for begin < len(events) && events[begin].Scope == scope && len(changes) < 128 {
				event := events[begin]
				begin++
				if event.Version <= version {
					continue
				}
				if event.Version != version+1 {
					return status.Error(codes.OutOfRange, "Almanac suffix is not continuous")
				}
				changes = append(changes, event.Change)
				version = event.Version
			}
			if err := transfer.update(scope, changes); err != nil {
				return err
			}
			if err := transfer.drain(); err != nil {
				return err
			}
		}
		if len(events) != 0 {

			continue
		}
		// Without work, wait for cancellation, suffix readiness, control frames, or reconciliation timer.
		select {
		case <-transfer.ctx.Done():
			return transfer.ctx.Err()
		case <-changed:
		case item := <-transfer.input:
			if item.err != nil {
				return item.err
			}
			if err := transfer.control(item.packet); err != nil {
				return err
			}
		case <-period.C:
			if err := transfer.assess(); err != nil {
				return err
			}
			period.Reset(30*time.Second + time.Duration(rand.IntN(5000))*time.Millisecond)
		}
	}
}

// manifest traverses captured metadata only; later pages cannot requery and expand initial requirements.
// Sends planned positions toward 256 KiB pages with complete on the final page.
func (transfer *transfer) manifest(positions []storage.Position) error {
	page := &polaris.Inventory{}
	size := 16
	// Pack entries once, charging per-entry overhead and flushing full pages.
	for _, position := range positions {
		item := &polaris.Position{Scope: &comet.Scope{Sector: []byte(position.Sector), Spectrum: []byte(position.Spectrum)}, Version: uint64(position.Version)}
		cost := proto.Size(item) + 6
		if len(page.Positions) != 0 && size+cost > min(transfer.maximum, 256<<10) {
			if err := transfer.send(&polaris.Packet{Body: &polaris.Packet_Plan{Plan: page}}); err != nil {
				return err
			}
			page, size = &polaris.Inventory{}, 16
		}
		page.Positions = append(page.Positions, item)
		size += cost
	}
	page.Complete = true
	return transfer.send(&polaris.Packet{Body: &polaris.Packet_Plan{Plan: page}})
}

// synchronize prefers durable contiguous history; only absent baselines or gaps require a full Scope snapshot.
// Returns when position is reached, otherwise replays history or sends a snapshot.
func (transfer *transfer) synchronize(position storage.Position) error {

	if after, present := transfer.sent[position.Scope]; present {
		if after >= position.Version {
			return nil
		}
		replay, err := transfer.owner.authority.store.Since(transfer.ctx, position.Scope, after)
		if err == nil {
			return transfer.update(position.Scope, replay.Changes)
		}
		if !errors.Is(err, storage.ErrHistory) {
			return failure(err)
		}
		// Only history gaps select snapshot fallback; other errors return directly.
	}
	return transfer.restore(position)
}

// restore sends a complete frozen snapshot at least at the target, for gaps or batches above one frame.
// Install once at the complete final page; never split one atomic commit into visible Patch versions.
func (transfer *transfer) restore(position storage.Position) error {
	pin, err := transfer.owner.authority.cache.acquire(transfer.ctx, position.Scope, position.Version)
	if err != nil {
		return failure(err)
	}
	defer pin.release()
	return transfer.snapshot(pin.Snapshot)
}

// update sends ordered same-Scope suffix pages within encoding budget, without merging duplicate Keys or skipping no-op commits.
// Empty changes return immediately; nonempty pages preserve order and process controls between sends.
func (transfer *transfer) update(scope storage.Scope, changes []storage.Change) error {
	page := &polaris.Updates{Scope: &comet.Scope{Sector: []byte(scope.Sector), Spectrum: []byte(scope.Spectrum)}}
	size := proto.Size(page) + 16

	for _, change := range changes {
		entries, err := change.Entries()
		if err != nil {
			return failure(storage.ErrCorrupt)
		}
		patch := &polaris.Patch{Version: uint64(change.Version)}
		for _, item := range entries {
			entry := &comet.AlmanacChange{Key: item.Key, Action: &comet.AlmanacChange_Value{Value: item.Value}}
			if item.Erase {
				entry.Action = &comet.AlmanacChange_Erase{Erase: &comet.Empty{}}
			}
			if change.Key == "" {
				patch.Changes = append(patch.Changes, entry)
			} else {
				patch.Change = entry
			}
		}
		cost := proto.Size(patch) + 6
		if proto.Size(page.Scope)+32+cost > transfer.maximum {
			// Fallback snapshot covers this whole suffix, so staged prefixes and remaining events need no duplicate sending.
			return transfer.restore(storage.Position{Scope: scope, Version: changes[len(changes)-1].Version})
		}
		if len(page.Patches) != 0 && size+cost > min(transfer.maximum, 256<<10) {
			if err := transfer.updates(scope, page); err != nil {
				return err
			}
			page = &polaris.Updates{Scope: page.Scope}
			size = proto.Size(page) + 16
			if err := transfer.drain(); err != nil {
				return err
			}
		}
		page.Patches = append(page.Patches, patch)
		size += cost
	}
	if len(page.Patches) == 0 {
		return nil
	}
	return transfer.updates(scope, page)
}

// drain consumes at most 16 ready control frames between data batches, without waiting or preempting in-flight data.
func (transfer *transfer) drain() error {
	for count := 0; count < 16; count++ {
		select {
		case item := <-transfer.input:
			if item.err != nil {
				return item.err
			}
			if err := transfer.control(item.packet); err != nil {
				return err
			}
		default:
			return nil
		}
	}
	return nil
}

// control accepts monotonic ACKs within actual sent positions, or complete inventories during an active probe.
// Validate current identity before interpreting ACK or probe-inventory Packet.
func (transfer *transfer) control(packet *polaris.Packet) error {

	if packet == nil || !transfer.owner.node.Directory().Current(transfer.remote) {
		return status.Error(codes.Unauthenticated, "Almanac stream identity unavailable")
	}
	// ACK validates position, advances installed state, and returns covered credits.
	if position := packet.GetAcknowledged(); position != nil && position.Scope != nil {
		scope := storage.Scope{Sector: string(position.Scope.Sector), Spectrum: string(position.Scope.Spectrum)}
		sent, exists := transfer.sent[scope]
		if !scope.Valid() || !exists || storage.Version(position.Version) > sent {
			return status.Error(codes.InvalidArgument, "Acknowledgement exceeds sent state")
		}
		transfer.installed[scope] = max(transfer.installed[scope], storage.Version(position.Version))
		transfer.release(scope, storage.Version(position.Version))
		return nil
	}
	// Probe inventory is accepted only during reconciliation; complete results validate loss/ahead positions and transfer to actual.
	if inventory := packet.GetInventory(); inventory != nil && transfer.probe != nil {
		if err := transfer.positions(transfer.probe, inventory); err != nil {
			return err
		}
		if inventory.Complete {
			// Do not send recursively while processing controls; return credits for actual positions, then repair at outer send boundaries.
			// Below acknowledged floor is confirmed data loss.
			for scope, minimum := range transfer.floor {
				if version, exists := transfer.probe[scope]; !exists || version < minimum {
					return status.Error(codes.DataLoss, "Star lost previously acknowledged state")
				}
			}
			// Above sent ceiling is protocol failure.
			for scope, version := range transfer.probe {
				if sent, exists := transfer.sent[scope]; !exists || version > sent {
					return status.Error(codes.Aborted, "Installation exceeds sent state")
				}
				transfer.installed[scope] = max(transfer.installed[scope], version)
				transfer.release(scope, version)
			}
			transfer.actual = transfer.probe
			transfer.probe = nil
		}
		return nil
	}
	return status.Error(codes.InvalidArgument, "Unexpected Almanac control frame")
}

// assess freezes positions when Probe is sent, excluding later sends from this probe's loss detection.
func (transfer *transfer) assess() error {
	// Reject overlapping reconciliation attempts.
	if transfer.probe != nil || transfer.actual != nil {
		return status.Error(codes.DeadlineExceeded, "Installation assessment not completed")
	}
	transfer.probe = make(map[storage.Scope]storage.Version)
	transfer.boundary = make(map[storage.Scope]storage.Version, len(transfer.sent))
	transfer.floor = make(map[storage.Scope]storage.Version, len(transfer.installed))
	// Freeze current sent ceiling and installed floor; later sends do not change this decision boundary.
	for scope, version := range transfer.sent {
		transfer.boundary[scope] = version
	}
	for scope, version := range transfer.installed {
		transfer.floor[scope] = version
	}
	return transfer.send(&polaris.Packet{Body: &polaris.Packet_Probe{Probe: &comet.Empty{}}})
}

// reconcile compares durable authority with actual installed positions and repairs differing Scopes; complete inventory may recover lost ACKs.
// actual is the complete peer inventory; lag selects contiguous replay or full snapshot.
func (transfer *transfer) reconcile(actual map[storage.Scope]storage.Version) error {
	// Capture complete authority positions as the comparison baseline.
	positions, err := transfer.owner.authority.store.List(transfer.ctx)
	if err != nil {
		return failure(err)
	}
	authoritative := make(map[storage.Scope]storage.Version, len(positions))
	for _, position := range positions {
		authoritative[position.Scope] = position.Version
	}
	// Reject peer positions beyond authority or actual sent limits.
	for scope, version := range actual {
		if current, exists := authoritative[scope]; !exists || version > current || version > transfer.sent[scope] {
			return status.Error(codes.Aborted, "Installation exceeds confirmed authority state")
		}
		transfer.installed[scope] = max(transfer.installed[scope], version)
	}
	// Repair each difference at the frozen boundary, using snapshot only for replay gaps and normal synchronization once reached.
	for _, position := range positions {
		after, present := actual[position.Scope]
		minimum, expected := transfer.boundary[position.Scope]
		if expected && (!present || after < minimum) {
			if present {
				replay, err := transfer.owner.authority.store.Since(transfer.ctx, position.Scope, after)
				if err == nil {
					if err := transfer.update(position.Scope, replay.Changes); err != nil {
						return err
					}
					continue
				}
				if !errors.Is(err, storage.ErrHistory) {
					return failure(err)
				}
			}
			pin, err := transfer.owner.authority.cache.acquire(transfer.ctx, position.Scope, position.Version)
			if err != nil {
				return failure(err)
			}
			err = transfer.snapshot(pin.Snapshot)
			pin.release()
			if err != nil {
				return err
			}
			continue
		}
		if err := transfer.synchronize(position); err != nil {
			return err
		}
	}
	// Clear reconciliation ceiling/floor afterward; the next probe freezes new ones.
	transfer.boundary = nil
	transfer.floor = nil
	return nil
}

// complete sends Ready once all frozen initial minima are installation-confirmed; later new Scopes do not redefine the first round.
func (transfer *transfer) complete() error {
	if transfer.ready {
		return nil
	}

	for scope, minimum := range transfer.plan {
		if installed, present := transfer.installed[scope]; !present || installed < minimum {
			return nil
		}
	}
	if err := transfer.send(&polaris.Packet{Body: &polaris.Packet_Ready{Ready: &comet.Empty{}}}); err != nil {
		return err
	}
	transfer.ready = true
	return nil
}
