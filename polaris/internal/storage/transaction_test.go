//go:build linux && cgo

// Verify real SQLite finalization, lost receipts, cancellation and repeated recovery failures.
package storage

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mattn/go-sqlite3"
	"gorm.io/gorm"
)

// boundary selects fixture-only native transaction controls; every statement still executes in the real database.
type boundary struct {
	point  string             // One declared finalization or cancellation boundary.
	hits   atomic.Int32       // Reached injections, independent of the returned error.
	cancel context.CancelFunc // Cancellation at an explicit SQL/commit boundary.
	active atomic.Bool        // Disarm the observer before verification or healthy recovery operations.
}

// bordering preserves native execution while attaching this fixture's reached transaction boundary.
type bordering struct {
	*sqlite3.SQLiteConn           // Actual native connection and its optional context interfaces.
	pool                *boundary // Immutable point and fixture-owned activation/counters.
}

// BeginTx preserves the native transaction except for an explicitly rejected begin.
func (conn *bordering) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	if conn.pool.active.Load() && conn.pool.point == "begin" {
		conn.pool.hits.Add(1)
		return nil, errors.New("assurance-begin")
	}
	tx, err := conn.SQLiteConn.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &ending{Tx: tx, pool: conn.pool, ctx: ctx}, nil
}

// ending delegates SQL and rollback to SQLite, intercepting only the named receipt boundary.
type ending struct {
	driver.Tx                 // Real SQLite transaction, enclosed by database/sql's original cancellation lifetime.
	pool      *boundary       // Injection state owned by the enclosing test case.
	ctx       context.Context // Original transaction context, including caller cancellation and deadline.
}

// Commit distinguishes an unattempted commit from a durable commit whose receipt was lost.
func (tx *ending) Commit() error {
	if !tx.pool.active.Load() {
		return tx.Tx.Commit()
	}
	switch tx.pool.point {
	case "commit-before":
		tx.pool.hits.Add(1)
		// Match a native failed COMMIT's rollback: database/sql has already claimed finalization.
		if err := tx.Tx.Rollback(); err != nil {
			return err
		}
		return errors.New("assurance-commit-before")
	case "commit-cancel":
		tx.pool.hits.Add(1)
		tx.pool.cancel()
		if err := tx.Tx.Rollback(); err != nil {
			return err
		}
		return tx.ctx.Err()
	case "commit-after":
		if err := tx.Tx.Commit(); err != nil {
			return err
		}
		tx.pool.hits.Add(1)
		return errors.New("assurance-commit-after")
	default:
		return tx.Tx.Commit()
	}
}

// Rollback can lose its success receipt without pretending that an open native transaction ended.
func (tx *ending) Rollback() error {
	err := tx.Tx.Rollback()
	if tx.pool.active.Load() && tx.pool.point == "rollback-after" && err == nil {
		tx.pool.hits.Add(1)
		return errors.New("assurance-rollback-after")
	}
	return err
}

// inspection includes published data, retained history and both levels of durable accounting.
type inspection struct {
	view    Snapshot // Public snapshot, including its authoritative version.
	history Replay   // Complete retained journal for this bounded case.
	group   group    // Per-scope counts and retained-byte accounting.
	meta    metadata // Global counts and deployment identity.
}

// inspect reads every commit-owned state surface after all transaction work has drained.
func inspect(t *testing.T, store *Store, scope Scope) inspection {
	return inspectAt(t, store, scope, 0)
}

// inspectAt reconciles durable state using an explicitly valid retained-history cursor.
func inspectAt(t *testing.T, store *Store, scope Scope, since Version) inspection {
	t.Helper()
	var image inspection
	var err error
	if image.view, err = store.Load(t.Context(), scope); err != nil {
		t.Fatal(err)
	}
	if image.history, err = store.Since(t.Context(), scope, since); err != nil {
		t.Fatal(err)
	}
	if err = store.read.Table("scopes").Where("sector=? AND spectrum=?", scope.Sector, scope.Spectrum).Take(&image.group).Error; err != nil {
		t.Fatal(err)
	}
	if err = store.read.Table("meta").Where("id=1").Take(&image.meta).Error; err != nil {
		t.Fatal(err)
	}
	return image
}

// TestFinalization reaches every declared fault twice, with a verified close/reopen between attempts.
// These are transaction/API failures, not a power-loss or failed-fsync simulation.
func TestFinalization(t *testing.T) {
	verified := verification(t, "STORAGE-FINALIZE")
	completed := 0
	points := []struct {
		name              string
		poison, committed bool
	}{
		{"begin", false, false},
		{"commit-before", true, false},
		{"commit-after", true, true},
		{"commit-cancel", true, false},
		{"rollback-after", true, false},
		{"cancel-record", false, false},
	}
	for _, point := range points {
		t.Run(point.name, func(t *testing.T) {
			check := func(ok bool, detail string) {
				t.Helper()
				if !ok {
					t.Fatal(detail)
				}
				verified(true, detail)
			}
			limits := Default()
			store, path, binding := fixture(t, limits)
			scope := Scope{"finalize", "boundary"}
			changes := []Change{{Key: "a", Value: []byte("new")}, {Key: "b", Value: []byte("new")}, {Key: "c", Erase: true}}
			got, err := store.CommitBatch(t.Context(), scope, 1, []Change{{Key: "b", Value: []byte("old")}, {Key: "c", Value: []byte("keep")}})
			check(err == nil && got == 1, "seed independent baseline")
			version := Version(2)
			for attempt := range 2 {
				before := inspect(t, store, scope)
				feed, err := store.Subscribe(4096, 8)
				check(err == nil, "capture notification boundary")
				changed, ready := store.Changed(), feed.Ready()
				ctx, cancel := context.WithCancel(t.Context())
				pool := &boundary{point: point.name, cancel: cancel}
				adapt(t, store, func(conn *sqlite3.SQLiteConn) driver.Conn { return &bordering{SQLiteConn: conn, pool: pool} })
				writer := store.write
				pool.active.Store(true)
				if point.name == "rollback-after" {
					check(store.write.Exec("CREATE TRIGGER assurance_finalization BEFORE INSERT ON records WHEN NEW.key='b' BEGIN SELECT RAISE(ABORT,'assurance-finalization'); END").Error == nil, "fail after the first real record write")
				}
				if point.name == "cancel-record" {
					check(store.write.Callback().Raw().After("gorm:raw").Register("assurance:cancel", func(tx *gorm.DB) {
						if tx.Error == nil && strings.HasPrefix(tx.Statement.SQL.String(), "INSERT INTO records") && len(tx.Statement.Vars) > 2 && tx.Statement.Vars[2] == "a" && pool.hits.CompareAndSwap(0, 1) {
							cancel()
						}
					}) == nil, "install deterministic cancellation after the first write")
					t.Cleanup(func() { writer.Callback().Raw().Remove("assurance:cancel") })
				}
				got, err = store.CommitBatch(ctx, scope, version, changes)
				cancel()
				want := ErrUnavailable
				if point.poison {
					want = ErrUncertain
				}
				check(got == 0 && errors.Is(err, want), "failed receipt preserves the specified error class")
				check(pool.hits.Load() == 1 && store.poisoned.Load() == point.poison, "fault reached exactly once; uncertain finalization freezes writes")
				pool.active.Store(false)
				if point.name == "cancel-record" {
					check(store.write.Callback().Raw().Remove("assurance:cancel") == nil, "remove reached cancellation probe")
				}
				// The single write connection cannot be reacquired until database/sql cancellation drains.
				check(store.writeSQL.PingContext(t.Context()) == nil, "native transaction cleanup has completed")
				after := inspect(t, store, scope)
				if point.committed {
					check(after.view.Version == version && len(after.view.Records) == 2, "lost receipt retains the complete committed snapshot")
					for index, key := range []string{"a", "b"} {
						check(after.view.Records[index].Key == key && bytes.Equal(after.view.Records[index].Value, []byte("new")), "complete values survive a lost receipt")
					}
					check(after.meta.Scopes == 1 && after.meta.Bytes == 8 && after.group.Version == version && after.group.Records == 2 && after.group.Bytes == 8, "committed global and scope accounting agree with the literal payload")
					check(after.history.Version == version && len(after.history.Changes) == int(version) && after.group.Retained == int64(version) && after.group.Backlog == 99+106*int64(version-1), "complete history and byte accounting survive receipt loss")
					entries, err := after.history.Changes[len(after.history.Changes)-1].Entries()
					check(err == nil && len(entries) == 3, "one retained atomic batch, not a partial journal")
					for index, entry := range entries {
						check(entry.Key == changes[index].Key && entry.Erase == changes[index].Erase && bytes.Equal(entry.Value, changes[index].Value), "journal preserves the exact attempted batch")
					}
				} else {
					check(reflect.DeepEqual(before, after), "failed transaction preserves every record, history row and accounting field")
				}
				// Recovery rejects extra schema objects, so remove the test-only trigger after checking rollback.
				if point.name == "rollback-after" {
					check(store.write.Exec("DROP TRIGGER assurance_finalization").Error == nil, "remove the reached SQL fault")
				}
				check(store.validate(t.Context(), binding) == nil, "durable invariants remain valid")
				if point.poison {
					got, err = store.CommitBatch(t.Context(), scope, version+1, changes)
					check(got == 0 && errors.Is(err, ErrUncertain) && pool.hits.Load() == 1, "poisoned writes cannot produce a new commit or repeat the fault")
					check(reflect.DeepEqual(after, inspect(t, store, scope)), "rejected follow-up write preserves the recovered state")
				}
				events, err := feed.Take()
				check(err == nil && len(events) == 0, "failed receipts never publish a success event")
				select {
				case <-changed:
					check(false, "failed receipt must not announce a store change")
				case <-ready:
					check(false, "failed receipt must not announce a feed event")
				default:
					check(true, "both notification boundaries remain open")
				}
				check(len(store.writer) == 0 && store.readSQL.Stats().InUse == 0 && store.writeSQL.Stats().InUse == 0, "writer permit and both connection pools drain")
				check(store.Close() == nil, "close without retaining transaction resources")
				_, err = feed.Take()
				check(errors.Is(err, ErrClosed) && store.feedBytes == 0 && len(store.feeds) == 0, "close drains feeds and their budgets")
				store, err = Open(t.Context(), path, binding, limits, false)
				check(err == nil && !store.poisoned.Load(), "reopen validates the actual durable outcome")
				opened := store
				t.Cleanup(func() { check(opened.Close() == nil, "close reopened store") })
				check(reflect.DeepEqual(after, inspect(t, store, scope)), "reopen preserves the complete outcome of the failed receipt")
				t.Logf("finalization=%s attempt=%d injected=1 reached=%d reopened=verified", point.name, attempt+1, pool.hits.Load())
				if point.committed && attempt == 0 {
					version++
				}
			}
			feed, err := store.Subscribe(4096, 8)
			check(err == nil, "observe post-recovery publication")
			defer feed.Close()
			before := inspect(t, store, scope)
			got, err = store.CommitBatch(t.Context(), scope, version, changes)
			check(err == nil && got == version, "retry after recovery confirms or performs exactly one commit")
			events, err := feed.Take()
			if point.committed {
				check(err == nil && len(events) == 0 && reflect.DeepEqual(before, inspect(t, store, scope)), "confirmed durable retry does not change history or republish")
			} else {
				check(err == nil && len(events) == 1 && events[0].Version == version, "uncommitted retry publishes exactly once")
			}
			got, err = store.CommitBatch(t.Context(), scope, version+1, changes)
			check(err == nil && got == version+1 && store.validate(t.Context(), binding) == nil, "new commits remain possible after recovery")
			completed++
		})
	}
	verified(completed == 6, "all six finalization cases complete both failures and recovery")
}

// TestTransactionPanic verifies rollback without swallowing or translating an application panic.
func TestTransactionPanic(t *testing.T) {
	store, _, binding := fixture(t, Default())
	check := verification(t, "STORAGE-PANIC")
	scope := Scope{"panic", "transaction"}
	got, err := store.Commit(t.Context(), scope, Change{Version: 1, Key: "a", Value: []byte("old")})
	check(err == nil && got == 1, "seed panic rollback baseline")
	before := inspect(t, store, scope)
	sentinel := errors.New("assurance-panic")
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		store.transaction(t.Context(), func(tx *gorm.DB) error {
			check(tx.Exec("UPDATE records SET value=X'6E6577' WHERE sector=? AND spectrum=? AND key='a'", scope.Sector, scope.Spectrum).Error == nil, "panic follows a real partial write")
			panic(sentinel)
		})
	}()
	check(recovered == sentinel, "original panic escapes after cleanup")
	check(store.writeSQL.PingContext(t.Context()) == nil && store.writeSQL.Stats().InUse == 0, "panic releases the native transaction")
	check(reflect.DeepEqual(before, inspect(t, store, scope)) && !store.poisoned.Load(), "successful rollback preserves the complete baseline")
	got, err = store.Commit(t.Context(), scope, Change{Version: 2, Key: "a", Value: []byte("new")})
	check(err == nil && got == 2 && store.validate(t.Context(), binding) == nil, "panic cleanup leaves healthy storage usable")
}
