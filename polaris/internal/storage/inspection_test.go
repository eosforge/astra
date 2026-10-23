//go:build linux && cgo

// Verify malformed driver replies and cursor errors using isolated native SQLite lifetimes.
package storage

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

// audit records one explicitly selected driver response fault without changing stored bytes.
type audit struct {
	native                 sqlite3.SQLiteDriver // Real driver with production connection initialization.
	point                  string               // Immutable fault selected before the child registers its driver.
	active                 atomic.Bool          // Enable only around the operation being challenged.
	opened, closed         atomic.Int32         // Delegated native connection acquisition and release.
	scans, hits, finalized atomic.Int32         // Exact query, injected response and native cursor finalization counts.
}

// Open delegates all SQL setup and counts only successfully acquired connections.
func (probe *audit) Open(name string) (driver.Conn, error) {
	conn, err := probe.native.Open(name)
	if err != nil {
		return nil, err
	}
	probe.opened.Add(1)
	return &auditing{SQLiteConn: conn.(*sqlite3.SQLiteConn), probe: probe}, nil
}

// auditing preserves the native driver's optional interfaces and scopes response changes to one query.
type auditing struct {
	*sqlite3.SQLiteConn        // Native SQL, transactions and context propagation.
	probe               *audit // Child-owned schedule and resource counters.
}

// Close records completed native releases, including cleanup after rejected reads.
func (conn *auditing) Close() error {
	err := conn.SQLiteConn.Close()
	if err == nil {
		conn.probe.closed.Add(1)
	}
	return err
}

// QueryContext intercepts only the selected successful query; stored data and SQL execution remain native.
func (conn *auditing) QueryContext(ctx context.Context, query string, arguments []driver.NamedValue) (driver.Rows, error) {
	rows, err := conn.SQLiteConn.QueryContext(ctx, query, arguments)
	if err != nil || !conn.probe.active.Load() {
		return rows, err
	}
	point := conn.probe.point
	matched := strings.HasPrefix(point, "snapshot-") && strings.HasPrefix(query, "SELECT key,value FROM `records`") ||
		strings.HasPrefix(point, "history-") && strings.HasPrefix(query, "SELECT version,key,value,erase,cost FROM `history`") ||
		strings.HasPrefix(point, "state-") && strings.HasPrefix(query, "SELECT * FROM `scopes`") ||
		point == "format" && strings.HasPrefix(query, "SELECT * FROM `meta`") ||
		point == "checkpoint-busy" && query == "PRAGMA wal_checkpoint(PASSIVE)" ||
		strings.HasPrefix(point, "foreign-") && query == "PRAGMA foreign_key_check"
	if !matched {
		return rows, nil
	}
	conn.probe.scans.Add(1)
	return &audited{SQLiteRows: rows.(*sqlite3.SQLiteRows), probe: conn.probe}, nil
}

// audited changes one driver-visible value or terminal receipt after native row execution.
type audited struct {
	*sqlite3.SQLiteRows        // Native cursor metadata and finalization.
	probe               *audit // Fault identity and reached-boundary counts.
}

// Next exposes explicitly malformed driver values rather than pretending SQLite accepted an invalid schema row.
func (rows *audited) Next(values []driver.Value) error {
	err := rows.SQLiteRows.Next(values)
	point := rows.probe.point
	if point == "foreign-next" && errors.Is(err, io.EOF) {
		rows.probe.hits.Add(1)
		return errors.New("assurance-inspection-next")
	}
	if err != nil || strings.HasPrefix(point, "foreign-") {
		return err
	}
	var column string
	var value driver.Value
	switch point {
	case "snapshot-key":
		column = "key"
	case "snapshot-value", "history-value":
		column = "value"
	case "history-version":
		column, value = "version", []byte{0}
	case "state-retained", "state-validation":
		column, value = "retained", int64(-1)
	case "state-backlog":
		column, value = "backlog", int64(-1)
	case "format":
		column, value = "format", int64(2)
	case "checkpoint-busy":
		column, value = "busy", int64(1)
	default:
		return errors.New("unknown inspection fault")
	}
	for index, name := range rows.Columns() {
		if name == column {
			values[index] = value
			rows.probe.hits.Add(1)
			return nil
		}
	}
	return errors.New("inspection target column missing")
}

// Close finalizes the real cursor before modelling a failed driver close receipt.
func (rows *audited) Close() error {
	if err := rows.SQLiteRows.Close(); err != nil {
		return err
	}
	rows.probe.finalized.Add(1)
	if rows.probe.point == "foreign-close" {
		rows.probe.hits.Add(1)
		return errors.New("assurance-inspection-close")
	}
	return nil
}

// inspectionChild verifies two reached failures, unchanged state and healthy recovery before releasing its native resources.
func inspectionChild(t *testing.T, point, root string) {
	t.Helper()
	if !filepath.IsAbs(root) || filepath.Clean(root) == string(os.PathSeparator) {
		t.Fatal("invalid private inspection root")
	}
	probe := &audit{point: point}
	probe.native.ConnectHook = connection
	driverOnce.Do(func() { sql.Register("astra-polaris", probe) })
	binding := Binding{Galaxy: "test", Username: "polaris", Advertise: "127.0.0.1:45101"}
	limits := Default()
	if point == "checkpoint-busy" {
		limits.WAL = 1 << 20
	}
	store, err := Open(t.Context(), filepath.Join(root, "polaris.db"), binding, limits, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	scope := Scope{"inspection", "reply"}
	value := []byte("v")
	if point == "checkpoint-busy" {
		// Record and retained history together cross the valid maintenance threshold through a normal public write.
		value = make([]byte, 768<<10)
	}
	requireCommit(t, store, scope, Change{Version: 1, Key: "k", Value: value})
	if point == "checkpoint-busy" {
		info, err := os.Stat(store.path + "-wal")
		if err != nil || info.Size() < limits.WAL {
			t.Fatal("native WAL did not reach the declared maintenance threshold", err)
		}
	}
	before, saved := inspect(t, store, scope), contents(t, store.writeSQL)
	changed := store.Changed()
	var attempts, hits, finalized int32
	for attempt := range 2 {
		probe.hits.Store(0)
		probe.scans.Store(0)
		probe.finalized.Store(0)
		probe.active.Store(true)
		empty := true
		var err error
		expected := ErrCorrupt
		switch {
		case point == "checkpoint-busy":
			var version Version
			version, err = store.Commit(t.Context(), scope, Change{Version: 2, Key: "k", Value: []byte("recovered")})
			empty, expected = version == 0, ErrUnavailable
		case strings.HasPrefix(point, "snapshot-"):
			var image Snapshot
			image, err = store.Load(t.Context(), scope)
			empty = reflect.DeepEqual(image, Snapshot{})
		case strings.HasPrefix(point, "history-") || point == "state-retained" || point == "state-backlog":
			var replay Replay
			replay, err = store.Since(t.Context(), scope, 0)
			empty = reflect.DeepEqual(replay, Replay{})
		default:
			err = store.validate(t.Context(), binding)
		}
		probe.active.Store(false)
		if !errors.Is(err, expected) || !empty || probe.hits.Load() != 1 || probe.scans.Load() != 1 || probe.finalized.Load() != 1 {
			t.Fatalf("attempt=%d error=%v empty=%v hits=%d scans=%d finalized=%d", attempt, err, empty, probe.hits.Load(), probe.scans.Load(), probe.finalized.Load())
		}
		if store.poisoned.Load() || len(store.writer) != 0 || store.writeSQL.Stats().InUse != 0 || store.readSQL.Stats().InUse != 0 {
			t.Fatal("driver response failure leaked a transaction, cursor or admission")
		}
		if contents(t, store.writeSQL) != saved || !reflect.DeepEqual(inspect(t, store, scope), before) || store.validate(t.Context(), binding) != nil {
			t.Fatal("driver response failure changed durable state or prevented exact healthy recovery")
		}
		select {
		case <-changed:
			t.Fatal("rejected driver response published a commit")
		default:
		}
		attempts++
		hits += probe.hits.Load()
		finalized += probe.finalized.Load()
	}
	if point == "checkpoint-busy" {
		requireCommit(t, store, scope, Change{Version: 2, Key: "k", Value: []byte("recovered")})
		image, err := store.Load(t.Context(), scope)
		if err != nil || image.Version != 2 || len(image.Records) != 1 || image.Records[0].Key != "k" || string(image.Records[0].Value) != "recovered" {
			t.Fatal("healthy retry did not publish exactly the rejected request", err)
		}
		select {
		case <-changed:
		default:
			t.Fatal("healthy retry did not publish its completion")
		}
	}
	if err := store.Close(); err != nil || probe.opened.Load() != probe.closed.Load() {
		t.Fatal("inspection retained a native connection", err)
	}
	openingFiles(t, root)
	fmt.Printf("STORAGE-INSPECTION point=%s attempts=%d hits=%d finalized=%d opened=%d closed=%d\n", point, attempts, hits, finalized, probe.opened.Load(), probe.closed.Load())
}

// TestCursorGuard bounds and joins child-only driver faults without altering the parent driver registry.
func TestCursorGuard(t *testing.T) {
	if point := os.Getenv("ASTRA_STORAGE_INSPECTION_POINT"); point != "" {
		inspectionChild(t, point, os.Getenv("ASTRA_STORAGE_INSPECTION_ROOT"))
		return
	}
	check := verification(t, "STORAGE-READ-FAULT")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, point := range []string{"snapshot-key", "snapshot-value", "history-version", "history-value", "state-retained", "state-backlog", "state-validation", "format", "foreign-next", "foreign-close", "checkpoint-busy"} {
		check(t.Run(point, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			arguments := []string{"-test.run=^TestCursorGuard$", "-test.count=1"}
			if testing.CoverMode() != "" {
				cover := flag.Lookup("test.gocoverdir")
				if cover == nil || cover.Value.String() == "" {
					t.Fatal("instrumented parent lacks its native coverage directory")
				}
				arguments = append(arguments, "-test.gocoverdir="+cover.Value.String())
			}
			command := exec.CommandContext(ctx, binary, arguments...)
			command.Env = append(os.Environ(), "ASTRA_STORAGE_INSPECTION_POINT="+point, "ASTRA_STORAGE_INSPECTION_ROOT="+t.TempDir())
			command.WaitDelay = time.Second
			output, err := command.CombinedOutput()
			if err != nil || ctx.Err() != nil || strings.Count(string(output), "STORAGE-INSPECTION point="+point+" ") != 1 {
				t.Fatalf("inspection child failed: error=%v context=%v output=%s", err, ctx.Err(), output)
			}
			t.Log(strings.TrimSpace(string(output)))
		}), "joined driver response fault "+point)
	}
}
