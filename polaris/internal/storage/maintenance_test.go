//go:build linux && cgo

// Verify idle WAL progress and task drainage without relying on elapsed host time.
package storage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mattn/go-sqlite3"
)

// TestIdleCheckpoint requires the real Store to retry a blocked checkpoint after all foreground work stops.
func TestIdleCheckpoint(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		check := verification(t, "STORAGE-CHECKPOINT")
		limits := Default()
		limits.WAL = 1 << 20
		path := filepath.Join(t.TempDir(), "idle.db")
		binding := Binding{Galaxy: "test", Username: "polaris", Advertise: "127.0.0.1:45001"}
		store, err := Open(t.Context(), path, binding, limits, true)
		check(err == nil, "open the real Store and its owned tasks")
		defer func() { check(store.Close() == nil, "drain all Store tasks before leaving virtual time") }()
		scope := Scope{Sector: "idle", Spectrum: "checkpoint"}
		requireCommit(t, store, scope, Change{Version: 1, Key: "k", Value: []byte{1}})
		reader, err := store.readSQL.BeginTx(t.Context(), nil)
		check(err == nil, "open a pinned read transaction")
		defer reader.Rollback()
		var version Version
		check(reader.QueryRowContext(t.Context(), "SELECT version FROM scopes").Scan(&version) == nil && version == 1, "establish the old read mark")
		for version := Version(2); version <= 3; version++ {
			requireCommit(t, store, scope, Change{Version: version, Key: "k", Value: bytes.Repeat([]byte{byte(version)}, 256<<10)})
		}
		info, err := os.Stat(path + "-wal")
		check(err == nil && info.Size() >= limits.WAL, "reach the real WAL admission threshold")
		var attempts atomic.Int32
		check(native(t, store.writeSQL, func(conn *sqlite3.SQLiteConn) error {
			conn.RegisterAuthorizer(func(operation int, first, second, _ string) int {
				if operation == sqlite3.SQLITE_PRAGMA && first == "wal_checkpoint" && strings.EqualFold(second, "PASSIVE") {
					attempts.Add(1)
				}
				return sqlite3.SQLITE_OK
			})
			return nil
		}) == nil, "observe actual passive checkpoints without replacing their outcome")
		snapshot, err := store.Load(t.Context(), scope)
		check(errors.Is(err, ErrUnavailable) && snapshot.Version == 0, "the pinned read mark blocks new snapshot admission")
		before := attempts.Load()
		check(before > 0, "reach the foreground checkpoint refusal")
		check(reader.Rollback() == nil, "release the final pinned read mark")
		changed, saved := store.Changed(), contents(t, store.writeSQL)
		var busy, log, checkpointed int64
		check(store.writeSQL.QueryRowContext(t.Context(), "PRAGMA wal_checkpoint(NOOP)").Scan(&busy, &log, &checkpointed) == nil && log > checkpointed, "observe pending frames without performing a checkpoint")
		// Advance only the test clock. No public read or write is allowed to retry maintenance for us.
		time.Sleep(2 * time.Second)
		synctest.Wait()
		check(attempts.Load() > before, "idle checkpoint retry after reader release")
		check(store.writeSQL.QueryRowContext(t.Context(), "PRAGMA wal_checkpoint(NOOP)").Scan(&busy, &log, &checkpointed) == nil && busy == 0 && log == checkpointed, "idle maintenance checkpoints every committed frame")
		check(contents(t, store.writeSQL) == saved && store.Changed() == changed, "maintenance changes neither durable business state nor commit notifications")
		check(store.writeSQL.Stats().InUse == 0 && store.readSQL.Stats().InUse == 0, "idle maintenance releases both connection owners")
	})
}

// pressure opens the public owner and leaves real, uncheckpointed frames after releasing a pinned reader.
func pressure(t *testing.T, limits Limits) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "maintenance.db")
	binding := Binding{Galaxy: "test", Username: "polaris", Advertise: "127.0.0.1:45002"}
	store, err := Open(t.Context(), path, binding, limits, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	scope := Scope{Sector: "maintenance", Spectrum: "wal"}
	requireCommit(t, store, scope, Change{Version: 1, Key: "k", Value: []byte{1}})
	reader, err := store.readSQL.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback()
	var version Version
	if err := reader.QueryRowContext(t.Context(), "SELECT version FROM scopes").Scan(&version); err != nil || version != 1 {
		t.Fatal("establish the real read mark", err, version)
	}
	for version := Version(2); version <= 3; version++ {
		requireCommit(t, store, scope, Change{Version: version, Key: "k", Value: bytes.Repeat([]byte{byte(version)}, 256<<10)})
	}
	info, err := os.Stat(path + "-wal")
	if err != nil || info.Size() < limits.WAL {
		t.Fatal("real WAL pressure was not reached", err)
	}
	return store
}

// TestMaintenanceFailure retries an actual denied checkpoint without publishing or changing business contents.
func TestMaintenanceFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		check := verification(t, "STORAGE-CHECKPOINT")
		limits := Default()
		limits.WAL = 1 << 20
		store := pressure(t, limits)
		defer store.Close()
		changed, saved := store.Changed(), contents(t, store.writeSQL)
		var attempts, denied atomic.Int32
		var reject atomic.Bool
		reject.Store(true)
		check(native(t, store.writeSQL, func(conn *sqlite3.SQLiteConn) error {
			conn.RegisterAuthorizer(func(operation int, first, second, _ string) int {
				if operation == sqlite3.SQLITE_PRAGMA && first == "wal_checkpoint" && strings.EqualFold(second, "PASSIVE") {
					attempts.Add(1)
					if reject.Load() {
						denied.Add(1)
						return sqlite3.SQLITE_DENY
					}
				}
				return sqlite3.SQLITE_OK
			})
			return nil
		}) == nil, "install a checkpoint-only native authorization fault")
		time.Sleep(time.Second)
		synctest.Wait()
		check(attempts.Load() == 1 && denied.Load() == 1, "one bounded maintenance attempt reaches the exact refusal")
		check(contents(t, store.writeSQL) == saved && store.Changed() == changed, "a failed checkpoint preserves contents and notification identity")
		check(store.writeSQL.Stats().InUse == 0, "the denied attempt releases its SQL owner")
		reject.Store(false)
		time.Sleep(time.Second)
		synctest.Wait()
		var busy, log, checkpointed int64
		check(attempts.Load() == 2 && denied.Load() == 1, "the next scheduled attempt recovers after the fault is removed")
		check(store.writeSQL.QueryRowContext(t.Context(), "PRAGMA wal_checkpoint(NOOP)").Scan(&busy, &log, &checkpointed) == nil && busy == 0 && log == checkpointed, "native checkpoint progress confirms recovery")
		check(contents(t, store.writeSQL) == saved && store.Changed() == changed, "recovery does not manufacture a business commit")
	})
}

// TestMaintenancePoison keeps unknown commit outcomes frozen until the Store is closed for recovery.
func TestMaintenancePoison(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		check := verification(t, "STORAGE-LIFETIME")
		limits := Default()
		limits.WAL = 1 << 20
		store := pressure(t, limits)
		defer store.Close()
		changed, saved := store.Changed(), contents(t, store.writeSQL)
		var attempts atomic.Int32
		check(native(t, store.writeSQL, func(conn *sqlite3.SQLiteConn) error {
			conn.RegisterAuthorizer(func(operation int, first, second, _ string) int {
				if operation == sqlite3.SQLITE_PRAGMA && first == "wal_checkpoint" && strings.EqualFold(second, "PASSIVE") {
					attempts.Add(1)
				}
				return sqlite3.SQLITE_OK
			})
			return nil
		}) == nil, "observe checkpoint work before poisoning the owner")
		store.poisoned.Store(true)
		time.Sleep(3 * time.Second)
		synctest.Wait()
		check(attempts.Load() == 0, "poisoned ownership suppresses all three scheduled checkpoints")
		check(contents(t, store.writeSQL) == saved && store.Changed() == changed, "maintenance cannot change a frozen outcome")
		check(store.Close() == nil, "a poisoned Store still cancels and joins its task")
		select {
		case <-store.done:
			check(true, "poisoned ownership leaves no maintenance task")
		default:
			check(false, "maintenance outlived its poisoned Store")
		}
	})
}

// TestMaintenanceDeadline cancels a real pool wait and retries only at the next bounded interval.
func TestMaintenanceDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		check := verification(t, "STORAGE-TIME")
		limits := Default()
		limits.WAL, limits.Timeout = 1<<20, 100*time.Millisecond
		store := pressure(t, limits)
		defer store.Close()
		changed, saved := store.Changed(), contents(t, store.writeSQL)
		conn, err := store.writeSQL.Conn(t.Context())
		check(err == nil, "hold the sole native write connection")
		defer conn.Close()
		before := store.writeSQL.Stats()
		time.Sleep(time.Second)
		synctest.Wait()
		check(store.writeSQL.Stats().WaitCount == before.WaitCount+1, "the scheduled checkpoint actually waits for the exhausted pool")
		time.Sleep(limits.Timeout)
		synctest.Wait()
		after := store.writeSQL.Stats()
		check(after.InUse == 1 && after.WaitCount == before.WaitCount+1 && after.WaitDuration-before.WaitDuration >= limits.Timeout, "deadline drainage completes the actual pool wait without an immediate retry")
		check(store.Changed() == changed && conn.Close() == nil, "cancelled work publishes nothing and the held connection can be returned")
		time.Sleep(time.Second)
		synctest.Wait()
		var busy, log, checkpointed int64
		check(store.writeSQL.QueryRowContext(t.Context(), "PRAGMA wal_checkpoint(NOOP)").Scan(&busy, &log, &checkpointed) == nil && busy == 0 && log == checkpointed, "a later idle attempt recovers after pool pressure clears")
		check(store.writeSQL.Stats().InUse == 0 && contents(t, store.writeSQL) == saved, "retry releases its connection without changing durable state")
	})
}

// TestMaintenanceClose requires cancellation and completed task drainage before either dependency pool is destroyed.
func TestMaintenanceClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		check := verification(t, "STORAGE-LIFETIME")
		limits := Default()
		limits.WAL = 1 << 20
		store := pressure(t, limits)
		entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var once sync.Once
		resume := func() { once.Do(func() { close(release) }) }
		defer resume()
		// Native connection ownership synchronizes hook registration; mutating active GORM processors does not.
		check(native(t, store.writeSQL, func(conn *sqlite3.SQLiteConn) error {
			conn.RegisterAuthorizer(func(operation int, first, second, _ string) int {
				if operation == sqlite3.SQLITE_PRAGMA && first == "wal_checkpoint" && strings.EqualFold(second, "PASSIVE") {
					close(entered)
					<-release
				}
				return sqlite3.SQLITE_OK
			})
			return nil
		}) == nil, "hold an actual maintenance query at native authorization")
		// Observe the real cancellation call without changing its context or completion semantics.
		cancel := store.cancel
		defer cancel() // Counterexamples must still release the real task if Close omits cancellation.
		store.cancel = func() {
			cancel()
			close(cancelled)
		}
		watch := time.NewTimer(3 * time.Second)
		defer watch.Stop()
		select {
		case <-entered:
		case <-watch.C:
			check(false, "scheduled maintenance never reaches the native query")
		}
		closed := make(chan error, 1)
		go func() { closed <- store.Close() }()
		select {
		case <-cancelled:
		case <-watch.C:
			check(false, "Close never cancels its maintenance task")
		}
		synctest.Wait()
		check(store.readSQL.PingContext(t.Context()) == nil, "the read dependency outlives the cancelled but undrained task")
		ctx, stop := context.WithCancel(t.Context())
		stop()
		_, err := store.writeSQL.Conn(ctx)
		check(errors.Is(err, context.Canceled), "the still-open write pool refuses a cancelled borrow before teardown")
		select {
		case <-store.done:
			check(false, "the held maintenance callback has not drained")
		case <-closed:
			check(false, "Close returned before maintenance drained")
		default:
			check(true, "Close waits for actual task completion")
		}
		resume()
		check(<-closed == nil && store.Close() == nil, "the task drains before close completes and repeated close remains safe")
		select {
		case <-store.done:
			check(true, "the maintenance owner has terminated")
		default:
			check(false, "Close left an active maintenance owner")
		}
		check(store.readSQL.Stats().OpenConnections == 0 && store.writeSQL.Stats().OpenConnections == 0, "both native pools contain no remaining connections")
		_, err = store.Load(context.Background(), Scope{Sector: "maintenance", Spectrum: "wal"})
		check(errors.Is(err, ErrClosed), "late reads remain refused after the worker is gone")
	})
}
