// Read consistent authority state and query results from storage.

package storage

import (
	"context"

	"gorm.io/gorm"
)

// readOnly bounds the SQL transaction and completes payload preparation before return; read must not send network data.
// Executes read within the configured timeout, then commits the read transaction and releases its connection.
func (store *Store) readOnly(ctx context.Context, read func(*gorm.DB) error) error {
	// Lifecycle read lock excludes closure.
	store.life.RLock()
	defer store.life.RUnlock()
	if store.closed {
		return ErrClosed
	}

	ctx, cancel := context.WithTimeout(ctx, store.limits.Timeout)
	defer cancel()
	// Perform WAL maintenance before reading; failure rejects this read.
	if err := store.maintain(ctx); err != nil {
		return err
	}
	// Keep lifecycle admission until native cancellation rollback returns the borrowed connection.
	db, conn, err := session(ctx, store.readSQL, store.read)
	if err != nil {
		return err
	}
	defer conn.Close()
	return db.Transaction(read)
}

// List captures durable Scope/version metadata in one read transaction without copying database payloads.
// Returns complete positions or capacity failure.
func (store *Store) List(ctx context.Context) (positions []Position, err error) {
	err = store.readOnly(ctx, func(tx *gorm.DB) error {
		// Order by Scope and fetch one extra row to detect overflow.
		if err := tx.Table("scopes").Select("sector,spectrum,version").Order("sector,spectrum").Limit(int(store.limits.Scopes) + 1).Find(&positions).Error; err != nil {
			return ErrUnavailable
		}
		if int64(len(positions)) > store.limits.Scopes {
			return ErrCapacity
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return positions, nil
}

// Version reads the durable position without loading whole-Scope content for management or cache lookup.
// Returns current version for scope, or zero if not created.
func (store *Store) Version(ctx context.Context, scope Scope) (version Version, err error) {
	if !scope.Valid() {
		return 0, ErrInput
	}
	err = store.readOnly(ctx, func(tx *gorm.DB) error {
		state, _, err := current(tx, scope)
		version = state.Version
		return err
	})
	return version, err
}

// Load returns complete consistent Scope contents, or a valid empty version-zero baseline when absent.
// Snapshot version and records belong to the same read transaction.
func (store *Store) Load(ctx context.Context, scope Scope) (snapshot Snapshot, err error) {
	if !scope.Valid() {
		return Snapshot{}, ErrInput
	}
	err = store.readOnly(ctx, func(tx *gorm.DB) error {
		snapshot, err = store.snapshot(tx, scope)
		return err
	})
	if err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

// snapshot uses the existing transaction so Scope version and records cannot mix separate SQL snapshots.
// Returns consistent scope data; record/count mismatch is corruption.
func (store *Store) snapshot(tx *gorm.DB, scope Scope) (Snapshot, error) {

	state, _, err := current(tx, scope)
	if err != nil {
		return Snapshot{}, err
	}
	result := Snapshot{Position: Position{Scope: scope, Version: state.Version}}
	// Reject out-of-budget stored counts before loading payload.
	if state.Records > store.limits.Records || state.Bytes > store.limits.Bytes {
		return Snapshot{}, ErrCapacity
	}
	// Bound each SQL row by actual charges; forged small counters must not allow arbitrary allocation.
	rows, err := tx.Table("records").Select("key,value").Where("sector=? AND spectrum=?", scope.Sector, scope.Spectrum).Order("key").Limit(int(state.Records) + 1).Rows()
	if err != nil {
		return Snapshot{}, ErrUnavailable
	}
	defer rows.Close()
	// Validate every record and require exact agreement with stored counters.
	var total int64
	for rows.Next() {
		var record Record
		if err := rows.Scan(&record.Key, &record.Value); err != nil || !text(record.Key, 1024) || record.Value == nil || len(record.Value) > 1<<20 {
			return Snapshot{}, ErrCorrupt
		}
		total += int64(len(record.Key) + len(record.Value))
		if total > state.Bytes || int64(len(result.Records)) >= state.Records {
			return Snapshot{}, ErrCorrupt
		}
		result.Records = append(result.Records, record)
	}
	if rows.Err() != nil {
		return Snapshot{}, ErrUnavailable
	}

	if total != state.Bytes || int64(len(result.Records)) != state.Records {
		return Snapshot{}, ErrCorrupt
	}
	return result, nil
}

// Since returns a complete suffix; future cursors are not empty success and ErrHistory requires a full snapshot.
// scope/after select the resumption range.
func (store *Store) Since(ctx context.Context, scope Scope, after Version) (replay Replay, err error) {
	if !scope.Valid() {
		return Replay{}, ErrInput
	}
	err = store.readOnly(ctx, func(tx *gorm.DB) error {
		state, _, err := current(tx, scope)
		if err != nil {
			return err
		}
		replay, err = store.history(tx, scope, state, after)
		return err
	})
	if err != nil {
		return Replay{}, err
	}
	return replay, nil
}

// history validates window and continuity within one SQL snapshot, bounded by retained entries/bytes.
// Returns contiguous suffix from state/after; older unavailable cursors yield ErrHistory, future cursors yield version conflict.
func (store *Store) history(tx *gorm.DB, scope Scope, state group, after Version) (Replay, error) {

	if after > state.Version {
		return Replay{}, ErrVersion
	}
	// Invalid retained counters mean corruption.
	if state.Retained < 0 || uint64(state.Retained) > uint64(state.Version) || state.Retained > store.limits.History || state.Backlog < 0 || state.Backlog > store.limits.Backlog {
		return Replay{}, ErrCorrupt
	}

	if after < state.Version-Version(state.Retained) {
		return Replay{}, ErrHistory
	}
	result := Replay{Version: state.Version}
	// Fetch ordered history after cursor, capped at retained count plus one to detect excess.
	rows, err := tx.Table("history").Select("version,key,value,erase,cost").Where("sector=? AND spectrum=? AND version>?", scope.Sector, scope.Spectrum, after).Order("version").Limit(int(state.Retained) + 1).Rows()
	if err != nil {
		return Replay{}, ErrUnavailable
	}
	defer rows.Close()
	// Validate each version step and cost; gaps or mismatches mean corruption.
	position := after
	var total int64
	for rows.Next() {
		var change Change
		var cost int64
		if err := rows.Scan(&change.Version, &change.Key, &change.Value, &change.Erase, &cost); err != nil || position == state.Version || change.Version != position+1 || change.Value == nil || cost != int64(64+len(change.Key)+len(change.Value)) {
			return Replay{}, ErrCorrupt
		}
		if _, err := change.Entries(); err != nil {
			return Replay{}, ErrCorrupt
		}
		total += cost
		if total > state.Backlog {
			return Replay{}, ErrCorrupt
		}
		position = change.Version
		result.Changes = append(result.Changes, change)
	}
	if rows.Err() != nil {
		return Replay{}, ErrUnavailable
	}
	// Suffix must end exactly at current version.
	if position != state.Version {
		return Replay{}, ErrCorrupt
	}
	return result, nil
}
