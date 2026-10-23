//go:build linux && cgo

// Verify connection configuration failures through real SQLite cursors and an owned response adapter.
package storage

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/mattn/go-sqlite3"
	"golang.org/x/sys/unix"
)

// configured owns one borrowed connection's fault selection and exact native cursor accounting.
type configured struct {
	*sqlite3.SQLiteConn                 // Native SQL and optional connection behavior remain unchanged.
	query               string          // Only this pragma may receive a changed response.
	point               string          // Empty for recovery; otherwise next, close, both or value.
	opened, closed      int             // Actual acquired cursors and successful native finalizations.
	next, finalized     int             // Reached injected iteration and finalization responses.
	rows                []driver.Rows   // Cleanup retains native cursors without concealing missing production closes.
	receipt             *settingReceipt // Selected cursor's actual native and delivered receipts for independent-effect witnesses.
}

// settingReceipt retains immutable pragma inputs and the real operations behind one delivered response tuple.
type settingReceipt struct {
	query                   string       // Stable selected pragma; unrelated cursor receipts never supply this witness.
	native, value           driver.Value // Native SQLite value and the value delivered to configure, respectively.
	next, close             error        // Actual delivered iteration/finalization errors.
	steps, closes           int          // Reached selected native operations, each required exactly once.
	nativeStep, nativeClose bool         // Native success is distinct from the deliberately substituted response.
}

// Query preserves native SQL execution and records ownership before returning the response adapter.
func (conn *configured) Query(query string, values []driver.Value) (driver.Rows, error) {
	rows, err := conn.SQLiteConn.Query(query, values)
	if err != nil {
		return nil, err
	}
	conn.opened++
	conn.rows = append(conn.rows, rows)
	if query == conn.query {
		conn.receipt = &settingReceipt{query: query}
	}
	return &setting{Rows: rows, owner: conn, selected: query == conn.query}, nil
}

// release runs after the oracle so fixture cleanup cannot make an omitted production close appear successful.
func (conn *configured) release(t *testing.T) {
	t.Helper()
	for _, rows := range conn.rows {
		if err := rows.Close(); err != nil {
			t.Error(err)
		}
	}
}

// setting changes a reached driver receipt after the corresponding native operation has completed.
type setting struct {
	driver.Rows             // The real SQLite cursor and column metadata.
	owner       *configured // Borrowed only during this synchronous configuration call.
	selected    bool        // Match one named pragma rather than depending on map iteration order.
}

// Next models a failed step receipt while preserving the actual native cursor lifecycle.
func (rows *setting) Next(values []driver.Value) error {
	err := rows.Rows.Next(values)
	if rows.selected {
		rows.owner.receipt.steps++
		rows.owner.receipt.nativeStep = err == nil
		rows.owner.receipt.native = values[0]
	}
	if err != nil {
		return err
	}
	if rows.selected && (rows.owner.point == "next" || rows.owner.point == "both") {
		rows.owner.next++
		err = unix.EIO
	}
	if rows.selected && rows.owner.point == "value" {
		values[0] = nil
	}
	if rows.selected {
		rows.owner.receipt.value, rows.owner.receipt.next = values[0], err
	}
	return err
}

// Close releases the real cursor before modelling a finalization error.
func (rows *setting) Close() error {
	err := rows.Rows.Close()
	if rows.selected {
		rows.owner.receipt.closes++
		rows.owner.receipt.nativeClose = err == nil
	}
	if err != nil {
		return err
	}
	rows.owner.closed++
	if rows.selected && (rows.owner.point == "close" || rows.owner.point == "both") {
		rows.owner.finalized++
		err = unix.EIO
	}
	if rows.selected {
		rows.owner.receipt.close = err
	}
	return err
}

// settingDecisions changes exactly one delivered predicate while all native cursor operations remain successful.
func settingDecisions(t *testing.T, conn *sqlite3.SQLiteConn) {
	t.Helper()
	for query, wanted := range map[string]driver.Value{"PRAGMA journal_mode": "wal", "PRAGMA synchronous": int64(2), "PRAGMA foreign_keys": int64(1), "PRAGMA wal_autocheckpoint": int64(1000)} {
		var witnesses []decision
		for _, point := range []string{"", "next", "close", "value"} {
			probe := &configured{SQLiteConn: conn, query: query, point: point}
			defer probe.release(t)
			err := configure(probe)
			receipt := probe.receipt
			if receipt == nil || receipt.query != query || receipt.steps != 1 || receipt.closes != 1 || !receipt.nativeStep || !receipt.nativeClose || receipt.native != wanted || probe.opened != probe.closed {
				t.Fatalf("selected pragma did not reach healthy native step/close receipts: %s/%s, receipt=%+v opened=%d closed=%d", query, point, receipt, probe.opened, probe.closed)
			}
			if (point == "" && err != nil) || (point != "" && !errors.Is(err, ErrUnavailable)) {
				t.Fatalf("configuration predicate had the wrong result: %s/%s, error=%v", query, point, err)
			}
			if (point == "next") != errors.Is(receipt.next, unix.EIO) || (point == "close") != errors.Is(receipt.close, unix.EIO) || (point == "value") != (receipt.value == nil) {
				t.Fatal("delivered receipt differs from the single declared substitution")
			}
			values := []any{receipt.next != nil, receipt.close != nil, receipt.value != wanted}
			input := map[string]any{"query": query, "point": point, "native": receipt.native, "value": receipt.value, "next_error": receipt.next != nil, "close_error": receipt.close != nil, "steps": receipt.steps, "closes": receipt.closes, "native_step": receipt.nativeStep, "native_close": receipt.nativeClose}
			witnesses = append(witnesses, decision{point, values, errors.Is(err, ErrUnavailable), input})
		}
		decisions(t, "configuration/"+query, []string{"iteration-error", "finalization-error", "wrong-value"}, witnesses, [][2]int{{0, 1}, {0, 2}, {0, 3}})
	}
}

// TestConnectionFault requires two reached failures and recovery for every pragma and response-failure combination.
func TestConnectionFault(t *testing.T) {
	check := verification(t, "STORAGE-CONNECTION")
	check(t.Run("release", func(t *testing.T) {
		// Bypass Store initialization so its connection hook cannot conceal a missing configure Close.
		driver := &sqlite3.SQLiteDriver{}
		opened, err := driver.Open(filepath.Join(t.TempDir(), "settings.db") + "?_journal_mode=WAL&_synchronous=FULL&_foreign_keys=ON")
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := opened.Close(); err != nil {
				t.Error(err)
			}
		}()
		probe := &configured{SQLiteConn: opened.(*sqlite3.SQLiteConn)}
		defer probe.release(t)
		err = configure(probe)
		if probe.opened == 0 || probe.closed != probe.opened {
			t.Fatalf("configuration did not finalize every acquired cursor: opened=%d closed=%d", probe.opened, probe.closed)
		}
		if err != nil || probe.opened != 4 || probe.next != 0 || probe.finalized != 0 {
			t.Fatal("healthy native configuration failed", err)
		}
		t.Log("STORAGE-SETTINGS release opened=4 closed=4 retained=0")
		settingDecisions(t, opened.(*sqlite3.SQLiteConn))
	}), "release")
	for _, query := range []string{"PRAGMA journal_mode", "PRAGMA synchronous", "PRAGMA foreign_keys", "PRAGMA wal_autocheckpoint"} {
		for _, point := range []string{"next", "close", "both"} {
			check(t.Run(query+"/"+point, func(t *testing.T) {
				store, _, _ := fixture(t, Default())
				before, changed := contents(t, store.writeSQL), store.Changed()
				var attempts, recoveries int
				err := native(t, store.readSQL, func(conn *sqlite3.SQLiteConn) error {
					for range 2 {
						probe := &configured{SQLiteConn: conn, query: query, point: point}
						defer probe.release(t)
						err := configure(probe)
						if !errors.Is(err, ErrUnavailable) {
							return fmt.Errorf("configuration accepted a failed %s receipt: %v", point, err)
						}
						if probe.opened == 0 || probe.closed != probe.opened {
							return fmt.Errorf("configuration did not finalize every acquired cursor: opened=%d closed=%d", probe.opened, probe.closed)
						}
						wantNext, wantClose := 0, 0
						if point == "next" || point == "both" {
							wantNext = 1
						}
						if point == "close" || point == "both" {
							wantClose = 1
						}
						if probe.next != wantNext || probe.finalized != wantClose {
							return fmt.Errorf("configuration fault was not reached exactly once: next=%d close=%d", probe.next, probe.finalized)
						}
						attempts++
						recovery := &configured{SQLiteConn: conn, query: query}
						defer recovery.release(t)
						if err := configure(recovery); err != nil || recovery.opened != 4 || recovery.closed != 4 || recovery.next != 0 || recovery.finalized != 0 {
							return fmt.Errorf("configuration did not recover all native pragmas: %v", err)
						}
						recoveries++
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				if attempts != 2 || recoveries != 2 || contents(t, store.writeSQL) != before || store.Changed() != changed {
					t.Fatal("configuration changed durable contents, notifications or the declared exposure")
				}
				requireCommit(t, store, Scope{"configuration", "recovery"}, Change{Version: 1, Key: "key", Value: []byte("value")})
				t.Logf("STORAGE-SETTINGS query=%q fault=%s rejected=%d recovered=%d retained=0", query, point, attempts, recoveries)
			}), query+"/"+point)
		}
	}
}
