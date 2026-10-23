// Commit authority mutations and their durable version and history state.

package storage

import (
	"bytes"
	"context"
	"errors"
	"math"

	"gorm.io/gorm"
)

// Commit succeeds only after SQLite durable commit; caller keeps arguments read-only during the call and no network notification is performed here.
// Retained equal-version/equal-content retries return original confirmation; missing history returns ErrUncertain.
// scope/change identify the write; returns confirmed version or storage error.
func (store *Store) Commit(ctx context.Context, scope Scope, change Change) (Version, error) {
	if !validChange(change) {
		return 0, ErrInput
	}
	return store.commit(ctx, scope, change)
}

// commit transaction covers all Keys, the sole version, and history, without publishing partial writes.
func (store *Store) commit(ctx context.Context, scope Scope, change Change) (Version, error) {
	entries, err := change.Entries()
	if !scope.Valid() || change.Version == 0 || err != nil {
		return 0, ErrInput
	}
	// Lifecycle read lock prevents concurrent closure; closed Store rejects.
	store.life.RLock()
	defer store.life.RUnlock()
	if store.closed {
		return 0, ErrClosed
	}
	// Derived context bounds the entire commit by configured timeout.
	ctx, cancel := context.WithTimeout(ctx, store.limits.Timeout)
	defer cancel()
	// Single-writer permit is cancelable by deadline.
	select {
	case store.writer <- struct{}{}:
		defer func() { <-store.writer }()
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	// Perform WAL maintenance before committing; maintenance failure rejects the attempt.
	if err := store.maintain(ctx); err != nil {
		return 0, err
	}
	// Copy payload needed across RPCs once before durable commit; targets later share immutable Event.
	// Even without current subscribers, never borrow request storage after commit: Subscribe may race this commit.
	event := &Event{Scope: scope, Change: change}
	event.Value = bytes.Clone(change.Value)
	applied := false
	err = store.transaction(ctx, func(tx *gorm.DB) error {
		// Absent Scope is a valid zero-version candidate, not created by this read.
		state, exists, err := current(tx, scope)
		if err != nil {
			return err
		}
		// Retained history confirms old equal-content replay without applying again.
		if change.Version <= state.Version {
			return confirm(tx, scope, change)
		}
		// Require exactly current+1; reject exhaustion and gaps.
		if state.Version == Version(math.MaxUint64) || change.Version != state.Version+1 {
			return ErrVersion
		}
		// New Scope admission checks global Scope capacity.
		var meta metadata
		if err := tx.Table("meta").Where("id=1").Take(&meta).Error; err != nil {
			return ErrUnavailable
		}
		if !exists && meta.Scopes >= store.limits.Scopes {
			return ErrCapacity
		}
		// Compute final batch charges before writing so decreases offset growth regardless of request order.
		previous := state.Bytes
		for _, entry := range entries {
			var old struct{ Size int64 }
			row := tx.Table("records").Select("length(value) AS size").Where("sector=? AND spectrum=? AND key=?", scope.Sector, scope.Spectrum, entry.Key).Scan(&old)
			if row.Error != nil {
				return ErrUnavailable
			}
			if row.RowsAffected != 0 {
				state.Records--
				state.Bytes -= int64(len(entry.Key)) + old.Size
			}
			if !entry.Erase {
				state.Records++
				state.Bytes += int64(len(entry.Key) + len(entry.Value))
			}
		}
		if state.Records < 0 || state.Bytes < 0 {
			return ErrCorrupt
		}
		// Check Scope record count, Scope bytes, and global active bytes.
		if state.Records > store.limits.Records || state.Bytes > store.limits.Bytes || meta.Bytes+state.Bytes-previous > store.limits.Total {
			return ErrCapacity
		}

		if !exists {
			if err := tx.Exec("INSERT INTO scopes(sector,spectrum,version,records,bytes,retained,backlog) VALUES(?,?,?,0,0,0,0)", scope.Sector, scope.Spectrum, Version(0)).Error; err != nil {
				return ErrUnavailable
			}
			meta.Scopes++
		}
		// Any SQL failure rolls back the transaction; no partially written prefix is notified.
		for _, entry := range entries {
			value := entry.Value
			if value == nil {
				value = []byte{}
			}
			if entry.Erase {
				err = tx.Exec("DELETE FROM records WHERE sector=? AND spectrum=? AND key=?", scope.Sector, scope.Spectrum, entry.Key).Error
			} else {
				err = tx.Exec("INSERT INTO records(sector,spectrum,key,value) VALUES(?,?,?,?) ON CONFLICT(sector,spectrum,key) DO UPDATE SET value=excluded.value", scope.Sector, scope.Spectrum, entry.Key, value).Error
			}
			if err != nil {
				return ErrUnavailable
			}
		}
		value := change.Value
		if value == nil {
			value = []byte{}
		}
		// Retain and trim history within the same transaction.
		if err = store.retain(tx, scope, change, value, &state); err != nil {
			return err
		}
		// Conditional Scope update requires the version read earlier; mismatch indicates concurrency conflict.
		result := tx.Exec("UPDATE scopes SET version=?,records=?,bytes=?,retained=?,backlog=? WHERE sector=? AND spectrum=? AND version=?", change.Version, state.Records, state.Bytes, state.Retained, state.Backlog, scope.Sector, scope.Spectrum, state.Version)
		if result.Error != nil || result.RowsAffected != 1 {
			return ErrVersion
		}
		// Global metadata update must satisfy the same state conditions; mismatch is corruption.
		result = tx.Exec("UPDATE meta SET scopes=?,bytes=? WHERE id=1 AND scopes=? AND bytes=?", meta.Scopes, meta.Bytes+state.Bytes-previous, meta.Scopes-boolint(!exists), meta.Bytes)
		if result.Error != nil || result.RowsAffected != 1 {
			return ErrCorrupt
		}
		applied = true
		return nil
	})
	if err != nil {
		return 0, err
	}
	if applied {
		// Share one change notification; targets replay durable history instead of per-Star event queues.
		store.notify.Lock()
		for feed := range store.feeds {
			feed.push(event)
		}
		close(store.changed)
		store.changed = make(chan struct{})
		store.notify.Unlock()
	}
	return change.Version, nil
}

// current distinguishes valid absent zero-version Scopes from corrupt/failed reads without creating state.
// Returns transaction-local state and existence for scope; missing rows yield zero, not an error.
func current(tx *gorm.DB, scope Scope) (group, bool, error) {
	var state group
	err := tx.Table("scopes").Where("sector=? AND spectrum=?", scope.Sector, scope.Spectrum).Take(&state).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {

		return group{}, false, nil
	}
	if err != nil {
		return group{}, false, ErrUnavailable
	}
	return state, true, nil
}

// confirm uses retained original commit payload only, never reconstructs past success from current final values.
// expected is the request to confirm; missing history is uncertain and differing content is a version conflict.
func confirm(tx *gorm.DB, scope Scope, expected Change) error {
	var actual Change
	err := tx.Table("history").Where("sector=? AND spectrum=? AND version=?", scope.Sector, scope.Spectrum, expected.Version).Take(&actual).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {

		return ErrUncertain
	}
	if err != nil {
		return ErrUnavailable
	}
	if actual.Key != expected.Key || actual.Erase != expected.Erase || !bytes.Equal(actual.Value, expected.Value) {
		return ErrVersion
	}
	return nil
}

// retain trims a continuous prefix in the transaction; one oversized entry may clear history while the authority commit still succeeds.
// change/value are the committed entry/encoding; state receives updated retention counts.
func (store *Store) retain(tx *gorm.DB, scope Scope, change Change, value []byte, state *group) error {
	cost := int64(64 + len(change.Key) + len(value))
	// Disabled history or oversized entry clears this Scope's history and counters.
	if store.limits.History == 0 || cost > store.limits.Backlog {
		if err := tx.Exec("DELETE FROM history WHERE sector=? AND spectrum=?", scope.Sector, scope.Spectrum).Error; err != nil {
			return ErrUnavailable
		}
		state.Retained, state.Backlog = 0, 0
		return nil
	}

	if err := tx.Exec("INSERT INTO history(sector,spectrum,version,key,value,erase,cost) VALUES(?,?,?,?,?,?,?)", scope.Sector, scope.Spectrum, change.Version, change.Key, value, change.Erase, cost).Error; err != nil {
		return ErrUnavailable
	}
	state.Retained++
	state.Backlog += cost
	if state.Retained <= store.limits.History && state.Backlog <= store.limits.Backlog {

		return nil
	}
	// Read only the necessary primary-key prefix, avoiding whole-history metadata copying on every steady commit.
	rows, err := tx.Table("history").Select("version,cost").Where("sector=? AND spectrum=?", scope.Sector, scope.Spectrum).Order("version").Limit(int(state.Retained)).Rows()
	if err != nil {
		return ErrUnavailable
	}
	defer rows.Close() // Release Rows even on scan failure; close explicitly before DELETE so a cursor never spans same-table writes.

	var through Version
	for (state.Retained > store.limits.History || state.Backlog > store.limits.Backlog) && rows.Next() {
		var version Version
		var cost int64
		if err := rows.Scan(&version, &cost); err != nil {
			return ErrUnavailable
		}
		state.Retained--
		state.Backlog -= cost
		through = version
	}
	if rows.Err() != nil {
		return ErrUnavailable
	}
	if err := rows.Close(); err != nil {
		return ErrUnavailable
	}
	// Counts remaining above limits or inconsistent after trimming mean corruption.
	if through == 0 || state.Retained > store.limits.History || state.Backlog < 0 || state.Backlog > store.limits.Backlog {
		return ErrCorrupt
	}
	// Delete the version prefix in one statement, not per entry.
	if err := tx.Exec("DELETE FROM history WHERE sector=? AND spectrum=? AND version<=?", scope.Sector, scope.Spectrum, through).Error; err != nil {
		return ErrUnavailable
	}
	return nil
}

// boolint converts new-Scope presence into the database count delta: true 1, otherwise 0.
func boolint(value bool) int64 {
	if value {
		return 1
	}
	return 0
}
