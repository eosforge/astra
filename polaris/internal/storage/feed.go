// Expose durable authority history and snapshot progression to downstream feeds.

package storage

import (
	"sync"
)

// Event is one complete durable commit, borrowed read-only from Feed; callers must not mutate payload.
// Several Stars may share one Event; Scope/version order matches durable commits.
type Event struct {
	Scope
	Change
}

// Feed retains a bounded suffix during initial synchronization/sending instead of relying solely on SQLite history duration.
// Overflow ends this Feed without blocking commits or pinning history indefinitely; consumer rebuilds a full baseline.
type Feed struct {
	mutex   sync.Mutex    // Protects queue and state with fixed nesting under store.notify.
	store   *Store        // Owning Store ends every Feed during closure.
	queue   []*Event      // Ordered queued suffix transferred and cleared by Take.
	bytes   int64         // Queued payload bytes checked against limit.
	limit   int64         // Fixed target payload budget.
	items   int           // Target item cap bounds metadata growth from tiny messages.
	changed chan struct{} // Ready channel closes on new data or termination.
	err     error         // Terminal error returned by later operations.
}

// Subscribe precedes inventory/snapshot capture so every later durable commit enters the bounded suffix.
// Positive limit at most 16 MiB bounds payload; positive items at most 65536 bounds metadata.
// Returns a controlled subscription; count or aggregate budget exhaustion returns capacity error.
func (store *Store) Subscribe(limit int64, items int) (*Feed, error) {

	if limit < 1 || limit > 16<<20 || items < 1 || items > 65536 {
		return nil, ErrInput
	}
	// Lifecycle read lock prevents subscription during closure.
	store.life.RLock()
	defer store.life.RUnlock()
	if store.closed {
		return nil, ErrClosed
	}
	store.notify.Lock()
	defer store.notify.Unlock()
	// Bound subscription count and aggregate maximum budgets together so connections cannot multiply suffix copies without limit.
	if len(store.feeds) >= 128 || limit > (128<<20)-store.feedBytes {
		return nil, ErrCapacity
	}
	feed := &Feed{store: store, limit: limit, items: items, changed: make(chan struct{})}
	store.feeds[feed] = struct{}{}
	store.feedBytes += limit
	return feed, nil
}

// Close idempotently releases Feed membership/budget; sole nested-lock order is store.notify then feed.mutex.
func (feed *Feed) Close() {
	// Remove from Store and return budget before ending this Feed, preserving lock order.
	feed.store.notify.Lock()
	defer feed.store.notify.Unlock()
	if _, exists := feed.store.feeds[feed]; exists {
		delete(feed.store.feeds, feed)
		feed.store.feedBytes -= feed.limit
	}
	feed.mutex.Lock()
	defer feed.mutex.Unlock()
	feed.stop(ErrClosed)
}

// Ready captures notification state before Take so an intervening commit cannot be missed.
// Channel closure means new events or termination; caller then uses Take.
func (feed *Feed) Ready() <-chan struct{} {
	feed.mutex.Lock()
	defer feed.mutex.Unlock()
	return feed.changed
}

// Take transfers the current complete ordered suffix; finish sending before taking again instead of accumulating in-flight batches.
// Service sender owns returned-event budget; Feed quota bounds only the not-yet-taken suffix.
// Returns ordered events or terminal reason.
func (feed *Feed) Take() ([]*Event, error) {
	feed.mutex.Lock()
	defer feed.mutex.Unlock()
	if feed.err != nil {
		return nil, feed.err
	}

	result := feed.queue
	feed.queue = nil
	feed.bytes = 0
	return result, nil
}

// push runs under store.notify only after durable success; never notifies network inside disk transactions.
// event is durable; overflow terminates this Feed and first queued event wakes waiters.
func (feed *Feed) push(event *Event) {
	feed.mutex.Lock()
	defer feed.mutex.Unlock()
	if feed.err != nil {
		return
	}
	cost := int64(128 + len(event.Sector) + len(event.Spectrum) + len(event.Key) + len(event.Value))

	if len(feed.queue) == feed.items || cost > feed.limit-feed.bytes {
		feed.stop(ErrCapacity)
		return
	}
	feed.queue = append(feed.queue, event)
	feed.bytes += cost
	if len(feed.queue) == 1 {
		close(feed.changed)
		feed.changed = make(chan struct{})
	}
}

// stop requires feed.mutex, releases undelivered payload on first failure, wakes waiters, and preserves the original error.
func (feed *Feed) stop(err error) {
	if feed.err == nil {
		feed.err = err
		feed.queue = nil
		feed.bytes = 0
		close(feed.changed)
	}
}
