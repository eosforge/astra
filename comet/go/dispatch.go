// Coalesce application notifications in a bounded, shared worker facility.
package comet

import "sync"

// notification queues at most one pending delivery for a live role. A slow
// callback holds one worker, never the connection or automatic-renewal loop.
type notification struct {
	queue   *dispatcher   // Protects every field below, except immutable callbacks.
	life    *lifecycle    // Retained while queued/running, so Wait includes callbacks.
	run     func()        // Obtains the latest immutable view outside queue locks.
	next    *notification // Intrusive queue link, nil while detached.
	queued  bool          // Appears once in the linked queue.
	running bool          // Only one worker may deliver this role's callbacks.
	dirty   bool          // Another complete state arrived during delivery.
	closed  bool          // Pending notifications may drain but cannot invoke user code.
}

// dispatcher owns a queue with one node per admitted role, rather than an
// unbounded closure channel. Two workers isolate callback progress from I/O.
type dispatcher struct {
	mu      sync.Mutex     // Guards queue membership and shutdown.
	ready   *sync.Cond     // Workers sleep until a node or shutdown arrives.
	head    *notification  // First pending role, nil when empty.
	tail    *notification  // Append position, nil when empty.
	closed  bool           // Prevents new queue admission.
	workers sync.WaitGroup // Actual completion of the fixed worker pair.
}

// newDispatcher starts a fixed callback worker pair owned by one Client.
func newDispatcher() *dispatcher {
	queue := new(dispatcher)
	queue.ready = sync.NewCond(&queue.mu)
	queue.workers.Add(2)
	for range 2 {
		go queue.work()
	}
	return queue
}

// appendLocked links an already-retained node; queue.mu is held by the caller.
func (queue *dispatcher) appendLocked(note *notification) {
	note.next, note.queued = nil, true
	if queue.tail == nil {
		queue.head = note
	} else {
		queue.tail.next = note
	}
	queue.tail = note
	queue.ready.Signal()
}

// signal coalesces intermediate states and retains at most one delivery token.
func (note *notification) signal() {
	queue := note.queue
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if note.closed || queue.closed {
		return
	}
	if note.running {
		note.dirty = true
		return
	}
	if !note.queued && note.life.begin() {
		queue.appendLocked(note)
	}
}

// stop prevents future delivery; any already-running callback may finish.
func (note *notification) stop() {
	note.queue.mu.Lock()
	note.closed, note.dirty = true, false
	note.queue.mu.Unlock()
}

// work serializes each role while allowing notifications from other roles.
func (queue *dispatcher) work() {
	defer queue.workers.Done()
	for {
		queue.mu.Lock()
		for queue.head == nil && !queue.closed {
			queue.ready.Wait()
		}
		if queue.head == nil {
			queue.mu.Unlock()
			return
		}
		note := queue.head
		queue.head = note.next
		if queue.head == nil {
			queue.tail = nil
		}
		note.next, note.queued, note.running = nil, false, true
		invoke := !note.closed
		queue.mu.Unlock()
		if invoke {
			note.run()
		}
		queue.mu.Lock()
		note.running = false
		again := note.dirty && !note.closed && !queue.closed
		note.dirty = false
		if again {
			queue.appendLocked(note) // Transfer the same completion token to the next turn.
		}
		queue.mu.Unlock()
		if !again {
			note.life.release()
		}
	}
}

// close stops the workers only after their owners have stopped and drained.
func (queue *dispatcher) close() {
	queue.mu.Lock()
	queue.closed = true
	queue.ready.Broadcast()
	queue.mu.Unlock()
	queue.workers.Wait()
}

// invokeCallback catches panic without retaining its value or stack. A boolean
// return also detects panic(nil); runtime.Goexit is not a supported callback exit.
func invokeCallback(callback func()) (panicked bool) {
	panicked = true
	defer func() { _ = recover() }()
	callback()
	return false
}
