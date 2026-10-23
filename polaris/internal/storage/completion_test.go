//go:build linux && cgo

// Verify native SQL cursor error conservation and the interface assumption behind EOF finalization.
package storage

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
	"golang.org/x/sys/unix"
)

// completion owns one isolated native connection and its immutable response scenario.
type completion struct {
	*sqlite3.SQLiteDriver                 // Existing native driver; no global driver registration.
	path                  string          // Fixture-owned database path.
	next, final           error           // Optional response errors after the native operations.
	following             bool            // Explicit alternative-driver control with another result set.
	opened, closed        atomic.Int32    // Actual native connection ownership.
	rows                  chan *completed // The synchronous query publishes its owned cursor.
}

// Connect acquires the real database and returns only an instrumented connection boundary.
func (probe *completion) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := probe.Open(probe.path)
	if err != nil {
		return nil, err
	}
	probe.opened.Add(1)
	return &completing{SQLiteConn: conn.(*sqlite3.SQLiteConn), owner: probe}, nil
}

// Driver identifies the existing SQLite implementation used by this connector.
func (probe *completion) Driver() driver.Driver { return probe.SQLiteDriver }

// completing intercepts only foreign-key inspection; SQL execution and connection release remain native.
type completing struct {
	*sqlite3.SQLiteConn             // Real SQL and transaction support.
	owner               *completion // Borrowed for this bounded database lifetime.
}

// Close records a native connection release after all cursor checks have completed.
func (conn *completing) Close() error {
	err := conn.SQLiteConn.Close()
	if err == nil {
		conn.owner.closed.Add(1)
	}
	return err
}

// QueryContext retains native execution while exposing exactly one finalization scenario.
func (conn *completing) QueryContext(ctx context.Context, query string, values []driver.NamedValue) (driver.Rows, error) {
	rows, err := conn.SQLiteConn.QueryContext(ctx, query, values)
	if err != nil || query != "PRAGMA foreign_key_check" {
		return rows, err
	}
	// This assumption is deliberately checked on the actual native method set, before wrapping it.
	if _, ok := rows.(driver.RowsNextResultSet); ok {
		if err := rows.Close(); err != nil {
			return nil, fmt.Errorf("unexpected result-set cursor did not close: %w", err)
		}
		return nil, errors.New("native SQLite cursor gained result-set continuation")
	}
	cursor := &completed{SQLiteRows: rows.(*sqlite3.SQLiteRows), owner: conn.owner, done: make(chan struct{})}
	conn.owner.rows <- cursor
	if conn.owner.following {
		return &continued{completed: cursor}, nil
	}
	return cursor, nil
}

// completed conserves native cursor ownership while changing only a declared driver response.
type completed struct {
	*sqlite3.SQLiteRows               // Actual iteration and finalization.
	owner               *completion   // Immutable errors and interface selection.
	next, closed        atomic.Int32  // Actual driver operations, also used by cancellation.
	done                chan struct{} // Native close completion, rather than a sleep.
}

// Next steps the real cursor before exposing the selected iteration error.
func (rows *completed) Next(values []driver.Value) error {
	err := rows.SQLiteRows.Next(values)
	rows.next.Add(1)
	if rows.owner.next != nil {
		return rows.owner.next
	}
	return err
}

// Close finalizes the real cursor before returning the selected close receipt.
func (rows *completed) Close() error {
	if err := rows.SQLiteRows.Close(); err != nil {
		return err
	}
	if rows.closed.Add(1) == 1 {
		close(rows.done)
	}
	return rows.owner.final
}

// continued models a different driver capability; it must not be treated as native SQLite behavior.
type continued struct{ *completed }

// HasNextResultSet keeps database/sql from automatically closing after an empty current result set.
func (*continued) HasNextResultSet() bool { return true }

// NextResultSet is unused: the control intentionally closes before requesting its advertised continuation.
func (*continued) NextResultSet() error { return errors.New("unexpected result-set request") }

// TestCursorCompletion checks error conservation, native release and the alternative-interface counterexample.
func TestCursorCompletion(t *testing.T) {
	check := verification(t, "STORAGE-READ-FAULT")
	for _, point := range []struct {
		name                   string // Stable independently counted scenario.
		next, final            error  // Driver receipts, including distinct error precedence.
		row, cancel, following bool   // Real orphan row, cancellation, or explicit result-set control.
	}{
		{"eof", nil, nil, false, false, false},
		{"eof-close", nil, unix.EIO, false, false, false},
		{"next", unix.ENOSPC, nil, false, false, false},
		{"both", unix.ENOSPC, unix.EIO, false, false, false},
		{"row", nil, nil, true, false, false},
		{"row-close", nil, unix.EIO, true, false, false},
		{"cancel", nil, nil, false, true, false},
		{"result-set-control", nil, unix.EIO, false, false, true},
	} {
		check(t.Run(point.name, func(t *testing.T) {
			probe := &completion{SQLiteDriver: &sqlite3.SQLiteDriver{}, path: filepath.Join(t.TempDir(), "cursor.db"), next: point.next, final: point.final,
				following: point.following, rows: make(chan *completed, 1)}
			// One connection is enough; the SQL database path remains isolated and is not supplied by input.
			database := sql.OpenDB(probe)
			database.SetMaxOpenConns(1)
			defer database.Close()
			conn, err := database.Conn(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			for _, query := range []string{"CREATE TABLE parent (id INTEGER PRIMARY KEY)", "CREATE TABLE child (parent INTEGER REFERENCES parent(id))"} {
				if _, err := conn.ExecContext(t.Context(), query); err != nil {
					t.Fatal(err)
				}
			}
			if point.row {
				if _, err := conn.ExecContext(t.Context(), "INSERT INTO child VALUES (7)"); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			rows, err := conn.QueryContext(ctx, "PRAGMA foreign_key_check")
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			cursor := <-probe.rows
			if point.cancel {
				budget, drain := context.WithTimeout(t.Context(), 5*time.Second)
				defer drain()
				cancel()
				select {
				case <-cursor.done:
				case <-budget.Done():
					t.Fatal("cancelled cursor did not drain")
				}
			}
			invalid := rows.Next()
			observed := rows.Err()
			closed := rows.Close()
			wantError, wantClose := point.next, error(nil)
			if point.cancel {
				wantError = context.Canceled
			} else if point.row || point.following {
				wantClose = point.final
			} else if wantError == nil {
				wantError = point.final
			}
			if invalid != point.row || !errors.Is(observed, wantError) || !errors.Is(closed, wantClose) || cursor.closed.Load() != 1 {
				t.Fatalf("cursor error/ownership disagreement: invalid=%v err=%v close=%v native-close=%d", invalid, observed, closed, cursor.closed.Load())
			}
			if cursor.next.Load() != 1 && !point.cancel || point.cancel && cursor.next.Load() != 0 {
				t.Fatal("declared cursor step was not reached exactly once")
			}
			// The alternative driver must make the final close independently observable; native EOF must not.
			if (!invalid && observed == nil && closed != nil) != point.following {
				t.Fatal("result-set capability no longer explains independent close observability")
			}
			if err := rows.Close(); err != nil || cursor.closed.Load() != 1 {
				t.Fatal("database/sql repeated native finalization", err)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if err := database.Close(); err != nil || probe.opened.Load() != 1 || probe.closed.Load() != 1 {
				t.Fatal("connection did not drain", err)
			}
			t.Logf("STORAGE-CURSOR scenario=%s next=%d finalized=1 retained=0 invalid=%v err=%v close=%v", point.name, cursor.next.Load(), invalid, observed, closed)
		}), fmt.Sprintf("native cursor completion: %s", point.name))
	}
}
