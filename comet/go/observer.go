// Select Ephemeris items and apply generation-checked local estimates.
package comet

import (
	"context"
	"sync"
)

// Observer synchronizes an Ephemeris pool for local selection only. One sends no
// RPC and adds no universal weighting policy. Use Client.Observer, then Stop.
type Observer struct{ watch *watching } // Private authority receiver and local estimate owner.

// Observer admits a whole-scope Ephemeris pool and starts synchronization.
func (client *Client) Observer(scope Scope, options ...ReadOptions) (*Observer, error) {
	watch, failure := client.watch(ephemeris, scope, "", options)
	if failure != nil {
		return nil, failure
	}
	return &Observer{watch: watch}, nil
}

// Pool is one fixed authority/estimate snapshot. A selector may retain it, but
// updates through its Items still compare against the live authority generation.
type Pool struct {
	owner     *watching // Identity checked when returning an Item from a selector.
	root      *snapshot // Complete immutable authority snapshot retained by this Pool.
	estimates table     // Immutable local values captured at the same selection boundary.
}

// Len reports the complete candidate count in this snapshot.
func (pool Pool) Len() int {
	if pool.root == nil {
		return 0
	}
	return pool.root.data.count
}

// Find returns a selected item with the estimate captured by this Pool, or nil.
func (pool Pool) Find(id string) *Item {
	if pool.root == nil {
		return nil
	}
	authority := pool.root.data.find(id)
	if authority == nil {
		return nil
	}
	previous := authority
	if estimate := pool.estimates.find(id); estimate != nil && estimate.authority == authority {
		previous = estimate
	}
	return &Item{owner: pool.owner, id: id, authority: authority, previous: previous}
}

// Range visits owned Items from this fixed pool until visit returns false.
// No global pool lock is held while running application code.
func (pool Pool) Range(visit func(*Item) bool) {
	if pool.root == nil || visit == nil {
		return
	}
	pool.root.data.each(func(id string, _ *row) bool { return visit(pool.Find(id)) })
}

// Item owns a selected record, not a reservation or long-term service lease.
// Do not copy an Item; its methods safely serialize use of the same pointer.
type Item struct {
	owner     *watching  // Mutation authority; stops with the owning Observer.
	id        string     // Immutable binary logical ID in the selected pool.
	mu        sync.Mutex // Serializes one Item's successful local adjustments.
	authority *row       // Exact authoritative row at selection time.
	previous  *row       // Exact estimate expected by the next local CAS.
}

// ID returns the unchanged binary logical ID; an empty Item has no identity.
func (item *Item) ID() string {
	if item == nil {
		return ""
	}
	return item.id
}

// Record returns retained immutable attributes/data, even after Observer.Stop.
func (item *Item) Record() Record {
	if item == nil {
		return Record{}
	}
	item.mu.Lock()
	defer item.mu.Unlock()
	if item.authority == nil || item.previous == nil {
		return Record{}
	}
	return Record{Attr: item.authority.attr, Data: item.previous.data}
}

// Update changes only this Observer's local estimate. A newer network value wins
// with CodeObsolete; a competing local adjustment wins with CodeConflict. Success
// affects future selections, never Beacon/Star data. Nil data is a valid empty value.
func (item *Item) Update(data []byte) error {
	if item == nil || item.owner == nil {
		return localError(CodeClosed)
	}
	if len(data) > maxPayload {
		return localError(CodeInput)
	}
	item.mu.Lock()
	defer item.mu.Unlock()
	watch := item.owner
	watch.mu.Lock()
	defer watch.mu.Unlock()
	if watch.life.stopped() {
		return localError(CodeClosed)
	}
	if watch.root == nil || watch.root.data.find(item.id) != item.authority {
		return localError(CodeObsolete)
	}
	previous := watch.estimates.find(item.id)
	if previous == nil {
		previous = item.authority
	}
	if previous != item.previous {
		return localError(CodeConflict)
	}
	// Reserve the old and proposed estimate roots before cloning any payload/bucket.
	projected := watch.estimates.bytes - footprint(item.id, watch.estimates.find(item.id)) + int64(len(item.id)+len(data)) + 192
	if watch.root.data.bytes+projected > watch.options.Bytes || !watch.resizeLocked(watch.retainedLocked()+watch.stage+watch.decoded+projected) {
		return localError(CodeLimit)
	}
	next := &row{data: NewValue(data), authority: item.authority}
	candidate := newDraft(watch.estimates)
	candidate.set(item.id, next)
	watch.estimates, item.previous = candidate.data, next
	watch.resizeLocked(watch.retainedLocked() + watch.stage + watch.decoded)
	return nil
}

// One runs selector synchronously without SDK locks. Nil item with nil error
// means no candidate; unready/failed/closed is an error. Selector panics propagate.
// Returned Items must belong to this Observer. Stale pools are not selected.
// Wait must not be called for this Observer or Client from its selector.
func (observer *Observer) One(selector func(Pool) *Item) (*Item, error) {
	if observer == nil || observer.watch == nil {
		return nil, localError(CodeClosed)
	}
	if selector == nil {
		return nil, localError(CodeInput)
	}
	watch := observer.watch
	watch.mu.Lock()
	if watch.life.stopped() {
		watch.mu.Unlock()
		return nil, localError(CodeClosed)
	}
	if watch.root == nil || watch.phase != Ready {
		failure := copyError(watch.failure)
		if failure == nil {
			failure = localError(CodeBusy)
		}
		watch.mu.Unlock()
		return nil, failure
	}
	pool := Pool{owner: watch, root: watch.root, estimates: watch.estimates}
	if !watch.life.begin() {
		watch.mu.Unlock()
		return nil, localError(CodeClosed)
	}
	watch.mu.Unlock()
	defer watch.life.release()
	item := selector(pool)
	if watch.life.stopped() {
		return nil, localError(CodeClosed)
	}
	if item != nil && item.owner != watch {
		return nil, localError(CodeInput)
	}
	return item, nil
}

// Stop closes only this Observer. Retained Items remain readable but cannot update.
func (observer *Observer) Stop() {
	if observer != nil && observer.watch != nil {
		observer.watch.life.stop()
	}
}

// Wait drains stream/callback work after explicit Stop; it does not stop implicitly.
func (observer *Observer) Wait(ctx context.Context) error {
	if observer == nil || observer.watch == nil {
		if ctx == nil {
			return localError(CodeInput)
		}
		return nil
	}
	return waitDone(ctx, observer.watch.life.done)
}
