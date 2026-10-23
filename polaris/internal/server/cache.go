// Retain prepared authority responses for bounded reuse by server streams.

package server

import (
	"context"
	"sync"

	"github.com/eosforge/astra/polaris/internal/storage"
)

// cache retains preparing/sending snapshots only and releases unreferenced entries immediately, without a permanent second authority copy.
type cache struct {
	mutex   sync.Mutex             // Protects entries and budget; SQL preparation runs outside this lock.
	store   *storage.Store         // Persistent source for cache misses.
	entries map[position]*prepared // Preparations indexed by Scope and minimum version; equal targets share work.
	used    int64                  // Reserved shared bytes, charged at the conservative reservation floor.
	maximum int64                  // Shared budget cap; excess preparation is rejected.
	reserve int64                  // Per-preparation reservation for maximum Scope, index, and one page, not exact current size.
}

// position identifies minimum requested version; concurrent equal targets share bounded SQL preparation.
type position struct {
	storage.Scope                 // Snapshot Scope.
	version       storage.Version // Minimum usable snapshot version.
}

// prepared snapshot/error become read-only when ready closes; references and budget mutate under cache.mutex only.
type prepared struct {
	ready      chan struct{}    // Preparation completion channel; closure publishes immutable result/error.
	snapshot   storage.Snapshot // Frozen snapshot, immutable once ready.
	err        error            // Preparation error, immutable once ready.
	references int              // Reference count; zero removes the entry and returns budget.
}

// pin owns read-only snapshot and budget responsibility; idempotent release must follow actual network use.
type pin struct {
	Snapshot *storage.Snapshot // Pinned immutable snapshot, valid until release.
	cache    *cache            // Owning cache for reference return.
	key      position          // Entry lookup key for release.
	entry    *prepared         // Entry pointer whose reference count is returned.
	once     sync.Once         // Enforces idempotent release.
}

// newCache reserves maximum Scope, index, and one send page per preparation, without trusting current database size to remain fixed.
// store/limits are dependencies, maximum caps shared budget, and reserve covers a maximum Scope; insufficient new reservations are rejected.
func newCache(store *storage.Store, limits storage.Limits, maximum int64) *cache {
	return &cache{store: store, entries: make(map[position]*prepared), maximum: maximum, reserve: limits.Bytes + limits.Records*128 + 2<<20}
}

// acquire returns a pinned snapshot at least minimum for scope under ctx, publishing payload only after SQL transaction completion.

// Concurrent equal targets share preparation; budget exhaustion or context cancellation fails.
func (cache *cache) acquire(ctx context.Context, scope storage.Scope, minimum storage.Version) (*pin, error) {

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := position{Scope: scope, version: minimum}
	// Find or reserve/create under lock; reject insufficient quota immediately.
	cache.mutex.Lock()
	entry := cache.entries[key]
	create := entry == nil
	if create {
		if cache.reserve > cache.maximum-cache.used {
			cache.mutex.Unlock()
			return nil, storage.ErrCapacity
		}
		entry = &prepared{ready: make(chan struct{})}
		cache.entries[key] = entry
		cache.used += cache.reserve
	}
	entry.references++
	cache.mutex.Unlock()
	result := &pin{cache: cache, key: key, entry: entry}
	if create {
		// First requester loads SQL outside the lock, then closes ready to publish.
		entry.snapshot, entry.err = cache.store.Load(ctx, scope)
		if entry.err == nil && entry.snapshot.Version < minimum {
			entry.err = storage.ErrVersion
		}
		close(entry.ready)
	}
	// Await readiness or cancellation; every failure returns this reference.
	select {
	case <-ctx.Done():
		result.release()
		return nil, ctx.Err()
	case <-entry.ready:
		if err := ctx.Err(); err != nil {
			result.release()
			return nil, err
		}
		if entry.err != nil {
			result.release()
			return nil, entry.err
		}
		result.Snapshot = &entry.snapshot
		return result, nil
	}
}

// release is idempotent and removes the final reference instead of caching unused old versions.
func (pin *pin) release() {
	pin.once.Do(func() {
		pin.cache.mutex.Lock()
		defer pin.cache.mutex.Unlock()
		pin.entry.references--

		if pin.entry.references == 0 {
			delete(pin.cache.entries, pin.key)
			pin.cache.used -= pin.cache.reserve
		}
	})
}
