//go:build linux && cgo

// Verify retained-history iteration and finalization faults after real prefix writes, with joined driver ownership.
package storage

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mattn/go-sqlite3"
)

// QueryContext delegates native queries, wrapping only the retained-prefix stream in the isolated fault child.
func (conn *initializing) QueryContext(ctx context.Context, query string, arguments []driver.NamedValue) (driver.Rows, error) {
	rows, err := conn.SQLiteConn.QueryContext(ctx, query, arguments)
	if err != nil || !conn.probe.active.Load() || !strings.HasPrefix(conn.probe.point, "retain-") || !strings.Contains(query, "SELECT version,cost FROM `history`") {
		return rows, err
	}
	conn.probe.scans.Add(1)
	return &cursor{SQLiteRows: rows.(*sqlite3.SQLiteRows), probe: conn.probe}, nil
}

// cursor preserves native optional row interfaces and injects only declared driver receipts after delegated work.
type cursor struct {
	*sqlite3.SQLiteRows          // Real SQLite cursor, column metadata and finalization.
	probe               *opening // Child-owned fault schedule and reached-boundary accounting.
}

// Next rejects the second native row after one prefix row has already been consumed.
func (rows *cursor) Next(values []driver.Value) error {
	if err := rows.SQLiteRows.Next(values); err != nil {
		return err
	}
	step := rows.probe.steps.Add(1)
	if step == 2 && (rows.probe.point == "retain-next" || rows.probe.point == "retain-both") {
		rows.probe.hits.Add(1)
		return errors.New("assurance-retention-next")
	}
	return nil
}

// Close always finalizes the actual cursor before returning an optional driver-boundary failure.
func (rows *cursor) Close() error {
	if err := rows.SQLiteRows.Close(); err != nil {
		return err
	}
	rows.probe.finalized.Add(1)
	if rows.probe.point == "retain-close" || rows.probe.point == "retain-both" {
		rows.probe.hits.Add(1)
		return errors.New("assurance-retention-close")
	}
	return nil
}

// retentionChild checks two persistent failures, exact rollback and clean recovery in one private native database.
func retentionChild(t *testing.T, point, root string) {
	t.Helper()
	want, exists := map[string]int32{"retain-control": 0, "retain-next": 1, "retain-close": 1, "retain-both": 2}[point]
	if !exists || !filepath.IsAbs(root) || filepath.Clean(root) == string(os.PathSeparator) {
		t.Fatal("invalid retained-history fault or private root")
	}
	parent := filepath.Join(root, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	probe := &opening{point: point, root: root}
	probe.native.ConnectHook = connection
	driverOnce.Do(func() { sql.Register("astra-polaris", probe) })
	limits := Default()
	limits.History, limits.Backlog = 3, 512
	binding := Binding{Galaxy: "test", Username: "polaris", Advertise: "127.0.0.1:45101"}
	store, err := Open(t.Context(), filepath.Join(parent, "polaris.db"), binding, limits, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	scope := Scope{"retention", "atomic"}
	for version := Version(1); version <= 3; version++ {
		requireCommit(t, store, scope, Change{Version: version, Key: "a", Value: []byte{1}})
	}
	before, saved := inspect(t, store, scope), contents(t, store.writeSQL)
	feed, err := store.Subscribe(4096, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer feed.Close()
	changed, ready := store.Changed(), feed.Ready()
	changes := []Change{{Key: "a", Value: bytes.Repeat([]byte{2}, 192)}, {Key: "b", Value: bytes.Repeat([]byte{3}, 192)}}
	if point != "retain-control" {
		for attempt := range 2 {
			probe.hits.Store(0)
			probe.scans.Store(0)
			probe.steps.Store(0)
			probe.finalized.Store(0)
			probe.active.Store(true)
			version, err := store.CommitBatch(t.Context(), scope, 4, changes)
			probe.active.Store(false)
			steps := int32(2)
			if point == "retain-close" {
				steps = 3
			}
			if version != 0 || !errors.Is(err, ErrUnavailable) || probe.hits.Load() != want || probe.scans.Load() != 1 || probe.steps.Load() != steps || probe.finalized.Load() != 1 {
				t.Fatalf("attempt=%d version=%d error=%v injections=%d scans=%d steps=%d finalized=%d", attempt, version, err, probe.hits.Load(), probe.scans.Load(), probe.steps.Load(), probe.finalized.Load())
			}
			if contents(t, store.writeSQL) != saved || !reflect.DeepEqual(inspect(t, store, scope), before) {
				t.Fatal("retained-history failure changed a durable prefix or accounting")
			}
			if len(store.writer) != 0 || store.poisoned.Load() || store.writeSQL.Stats().InUse != 0 || store.readSQL.Stats().InUse != 0 {
				t.Fatal("retained-history failure leaked admission, a cursor or a transaction")
			}
			for _, notification := range []<-chan struct{}{changed, ready} {
				select {
				case <-notification:
					t.Fatal("retained-history failure published a commit")
				default:
				}
			}
			if events, err := feed.Take(); err != nil || len(events) != 0 {
				t.Fatal("retained-history failure published a feed prefix", err)
			}
		}
	} else {
		probe.active.Store(true)
	}
	version, err := store.CommitBatch(t.Context(), scope, 4, changes)
	probe.active.Store(false)
	image, loaded := store.Load(t.Context(), scope)
	history, replayed := store.Since(t.Context(), scope, 3)
	if err != nil || version != 4 || loaded != nil || replayed != nil || image.Version != 4 || len(image.Records) != 2 || image.Records[0].Key != "a" || image.Records[1].Key != "b" || !bytes.Equal(image.Records[0].Value, changes[0].Value) || !bytes.Equal(image.Records[1].Value, changes[1].Value) || history.Version != 4 || len(history.Changes) != 1 || history.Changes[0].Version != 4 {
		t.Fatal("retained-history recovery failed exact public state/history", version, image, history, err, loaded, replayed)
	}
	if point == "retain-control" && (probe.scans.Load() != 1 || probe.steps.Load() != 3 || probe.finalized.Load() != 1 || probe.hits.Load() != 0) {
		t.Fatal("healthy control did not reach all three retained prefix rows")
	}
	if err := store.validate(t.Context(), binding); err != nil {
		t.Fatal(err)
	}
	events, err := feed.Take()
	if err != nil || len(events) != 1 || events[0].Version != 4 {
		t.Fatal("recovery did not publish exactly one complete batch", err)
	}
	if err := store.Close(); err != nil || probe.opened.Load() != probe.closed.Load() {
		t.Fatal("retained-history child did not drain native connections", err)
	}
	openingFiles(t, root)
	fmt.Printf("STORAGE-OPEN point=%s hits=%d opened=%d closed=%d\n", point, probe.hits.Load(), probe.opened.Load(), probe.closed.Load())
}
