//go:build linux && cgo

// Verify all combinations of lost native connection-close receipts and actual lock-handle cleanup errors.
package storage

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/mattn/go-sqlite3"
	"golang.org/x/sys/unix"
)

// termination owns one real fixture connection and an optional error after its actual release.
type termination struct {
	*sqlite3.SQLiteDriver              // Existing native driver and connection initialization.
	path                  string       // Fixture-owned database; no global driver registration.
	fail                  bool         // Lose this completed native close's success receipt.
	opened, closed        atomic.Int32 // Actual ownership transitions, separate from the delivered error.
}

// Connect delegates native opening after checking the caller's existing cancellation.
func (probe *termination) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := probe.Open(probe.path)
	if err != nil {
		return nil, err
	}
	probe.opened.Add(1)
	return &terminated{SQLiteConn: conn.(*sqlite3.SQLiteConn), owner: probe}, nil
}

// Driver preserves the existing SQLite implementation behind this per-fixture connector.
func (probe *termination) Driver() driver.Driver { return probe.SQLiteDriver }

// terminated returns a controlled receipt only after the real SQLite connection has closed.
type terminated struct {
	*sqlite3.SQLiteConn              // Native SQL and optional interfaces remain unchanged.
	owner               *termination // Fixture-owned accounting and immutable fault selection.
}

// Close retains the original native error; a selected successful release may lose its receipt.
func (conn *terminated) Close() error {
	err := conn.SQLiteConn.Close()
	if err != nil {
		return err
	}
	conn.owner.closed.Add(1)
	if conn.owner.fail {
		return unix.EIO
	}
	return nil
}

// TestTermination reaches all eight combinations, preserving later cleanup after earlier errors.
func TestTermination(t *testing.T) {
	verified := verification(t, "STORAGE-TERMINATION")
	for mask := range 8 {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			check := func(ok bool, detail string) {
				t.Helper()
				if !ok {
					t.Fatal(detail)
				}
				verified(true, detail)
			}
			store, path, binding := fixture(t, Default())
			scope := Scope{"termination", "state"}
			requireCommit(t, store, scope, Change{Version: 1, Key: "retained", Value: []byte("durable")})
			// Replace only the privately owned pools consumed by Close, after their original connections drain.
			check(store.readSQL.Close() == nil && store.writeSQL.Close() == nil, "release original healthy native pools before controlled close receipts")
			var owners [2]*termination
			for index := range 2 {
				probe := &termination{SQLiteDriver: &sqlite3.SQLiteDriver{ConnectHook: connection}, path: path + "?_journal_mode=WAL&_synchronous=FULL&_foreign_keys=on", fail: mask&(1<<index) != 0}
				pool := sql.OpenDB(probe)
				pool.SetMaxOpenConns(1)
				pool.SetMaxIdleConns(1)
				t.Cleanup(func() { pool.Close() })
				check(pool.PingContext(t.Context()) == nil && probe.opened.Load() == 1 && probe.closed.Load() == 0, "acquire one real native connection for each selected finalization boundary")
				owners[index] = probe
				if index == 0 {
					store.readSQL = pool
				} else {
					store.writeSQL = pool
				}
			}
			feed, err := store.Subscribe(4096, 8)
			check(err == nil, "own a feed reservation before teardown")
			ready, changed := feed.Ready(), store.Changed()
			if mask&4 != 0 {
				check(store.file.Close() == nil, "reach an actual already-closed lock descriptor before Store cleanup")
			}
			err = store.Close()
			check((mask == 0 && err == nil) || (mask != 0 && errors.Is(err, ErrUnavailable)), "close reports the primary stable failure without hiding secondary release")
			for _, probe := range owners {
				check(probe.opened.Load() == 1 && probe.closed.Load() == 1, "all later native connections close despite earlier error receipts")
			}
			check(store.readSQL.Stats().OpenConnections == 0 && store.writeSQL.Stats().OpenConnections == 0 && store.readSQL.Stats().InUse == 0 && store.writeSQL.Stats().InUse == 0, "both pools retain no owned or borrowed native connection")
			check(store.closed && len(store.feeds) == 0 && store.feedBytes == 0 && len(store.writer) == 0, "terminal admission, reservations and writer ownership reconcile")
			for _, signal := range []<-chan struct{}{ready, changed} {
				select {
				case <-signal:
					check(true, "finalization errors still wake existing notification waiters")
				default:
					t.Fatal("failed close left an existing waiter alive")
				}
			}
			_, err = feed.Take()
			check(errors.Is(err, ErrClosed) && feed.queue == nil && feed.bytes == 0, "teardown returns a terminal feed with no queued references")
			feed.Close()
			feed.Close()
			check(store.Close() == nil && owners[0].closed.Load() == 1 && owners[1].closed.Load() == 1, "repeated close cannot repeat connection release")
			version, err := store.Commit(t.Context(), scope, Change{Version: 2, Key: "late"})
			check(version == 0 && errors.Is(err, ErrClosed), "close errors cannot reopen write admission")
			opened, err := Open(t.Context(), path, binding, Default(), false)
			check(err == nil, "every error combination releases database lock ownership")
			defer opened.Close()
			view, err := opened.Load(t.Context(), scope)
			check(err == nil && view.Version == 1 && len(view.Records) == 1 && view.Records[0].Key == "retained" && string(view.Records[0].Value) == "durable", "cleanup failures preserve the complete previously durable state")
			t.Logf("STORAGE-TERMINATION {\"mask\":%d,\"opened\":[1,1],\"closed\":[1,1],\"pools\":0,\"feeds\":0,\"version\":1,\"records\":1}", mask)
		})
	}
}
