// Retry WAL pressure relief independently of foreground admission.

package storage

import (
	"context"
	"time"
)

// maintenance owns one timer and at most one checkpoint attempt, without acquiring the lifecycle lock.
// Failed attempts remain admission failures; retrying them never confirms or publishes business writes.
func (store *Store) maintenance(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if store.poisoned.Load() {
				continue
			}
			current, cancel := context.WithTimeout(ctx, store.limits.Timeout)
			// Foreground operations independently check this result before admitting any new SQL work.
			store.maintain(current)
			cancel()
		}
	}
}
