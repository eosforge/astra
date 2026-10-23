//go:build linux && cgo

// Verify native query failures, malformed accounting and public resource boundaries.
package storage

import (
	"context"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mattn/go-sqlite3"
	"golang.org/x/sys/unix"
)

// TestWriteFault denies native preparation before and after real writes, twice per site.
func TestWriteFault(t *testing.T) {
	if point := os.Getenv("ASTRA_STORAGE_OPEN_POINT"); point != "" {
		openingChild(t, point, os.Getenv("ASTRA_STORAGE_OPEN_ROOT"))
		return
	}
	verified := verification(t, "STORAGE-WRITE-FAULT")
	openingCases(t, verified)
	verified(t.Run("wal-path", walFault), "WAL stat refusal preserves the entire commit state")
	for _, point := range []struct {
		name   string // Failed preparation site in the durable commit path.
		table  string // SQLite authorizer table identity.
		column string // Read column, or empty for a DELETE refusal.
		retry  bool   // Reissue the retained version instead of creating a new one.
		clear  bool   // Disable retained history to reach its clearing boundary.
	}{
		{"current", "scopes", "version", false, false},
		{"metadata", "meta", "id", false, false},
		{"record-size", "records", "value", false, false},
		{"retry-history", "history", "value", true, false},
		{"clear-history", "history", "", false, true},
		{"prune-history", "history", "version", false, false},
	} {
		verified(t.Run(point.name, func(t *testing.T) {
			limits := Default()
			limits.History = 1
			if point.clear {
				limits.History = 0
			}
			store, _, binding := fixture(t, limits)
			scope := Scope{"s", "p"}
			seed := Change{Version: 1, Key: "a", Value: []byte{1}}
			requireCommit(t, store, scope, seed)
			cursor := Version(0) // Retained replay starts at origin unless retention is disabled.
			if point.clear {
				cursor = 1
			}
			before := inspectAt(t, store, scope, cursor)
			saved := contents(t, store.writeSQL)
			feed, err := store.Subscribe(4096, 8)
			if err != nil {
				t.Fatal(err)
			}
			defer feed.Close()
			changed, ready := store.Changed(), feed.Ready()
			for attempt := range 2 {
				var hits atomic.Int32
				if err := native(t, store.writeSQL, func(conn *sqlite3.SQLiteConn) error {
					conn.RegisterAuthorizer(func(operation int, first, second, _ string) int {
						if first == point.table && (point.column == "" && operation == sqlite3.SQLITE_DELETE || point.column != "" && operation == sqlite3.SQLITE_READ && second == point.column) {
							hits.Add(1)
							return sqlite3.SQLITE_DENY
						}
						return sqlite3.SQLITE_OK
					})
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				var version Version
				if point.retry {
					version, err = store.Commit(t.Context(), scope, seed)
				} else {
					version, err = store.CommitBatch(t.Context(), scope, 2, []Change{{Key: "a", Value: []byte{2}}, {Key: "b", Value: []byte{2}}})
				}
				if err := native(t, store.writeSQL, func(conn *sqlite3.SQLiteConn) error { conn.RegisterAuthorizer(nil); return nil }); err != nil {
					t.Fatal(err)
				}
				if !errors.Is(err, ErrUnavailable) || version != 0 || hits.Load() != 1 {
					t.Fatalf("attempt=%d version=%d error=%v injections=%d", attempt, version, err, hits.Load())
				}
				if contents(t, store.writeSQL) != saved || !reflect.DeepEqual(inspectAt(t, store, scope, cursor), before) {
					t.Fatal("failed query changed durable records, history or accounting")
				}
				if len(store.writer) != 0 || store.poisoned.Load() || store.writeSQL.Stats().InUse != 0 || store.readSQL.Stats().InUse != 0 {
					t.Fatal("failed query retained admission/connection ownership or poisoned a rolled-back transaction")
				}
				for _, signal := range []<-chan struct{}{changed, ready} {
					select {
					case <-signal:
						t.Fatal("failed query published a durable notification")
					default:
					}
				}
				if events, err := feed.Take(); err != nil || len(events) != 0 {
					t.Fatal("failed query published a feed prefix", err)
				}
			}
			if _, err := store.CommitBatch(t.Context(), scope, 2, []Change{{Key: "a", Value: []byte{2}}, {Key: "b", Value: []byte{2}}}); err != nil {
				t.Fatal("recovery", err)
			}
			if err := store.validate(t.Context(), binding); err != nil {
				t.Fatal(err)
			}
			events, err := feed.Take()
			if err != nil || len(events) != 1 || events[0].Version != 2 {
				t.Fatal("recovery did not publish exactly one complete commit", err)
			}
			t.Log("native-refusals=2 rollback=verified notification=absent recovery=verified")
		}), point.name)
	}
}

// walFault makes only the owned WAL directory entry inaccessible; native connections retain their files.
func walFault(t *testing.T) {
	store, path, binding := fixture(t, Default())
	scope := Scope{"s", "p"}
	requireCommit(t, store, scope, Change{Version: 1, Key: "a", Value: []byte{1}})
	before, saved := inspect(t, store, scope), contents(t, store.writeSQL)
	changed := store.Changed()
	wal, held := path+"-wal", path+"-wal-held"
	if err := os.Rename(wal, held); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		if err := os.Remove(wal); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.Rename(held, wal); err != nil {
			t.Fatal(err)
		}
		restored = true
	}
	t.Cleanup(restore) // Restore before the earlier fixture cleanup closes SQLite.
	if err := os.Symlink(filepath.Base(wal), wal); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(wal); !errors.Is(err, unix.ELOOP) {
		t.Fatal("owned WAL fault was not reached", err)
	}
	version, err := store.CommitBatch(t.Context(), scope, 2, []Change{{Key: "a", Value: []byte{2}}, {Key: "b", Value: []byte{2}}})
	restore()
	if version != 0 || !errors.Is(err, ErrUnavailable) || contents(t, store.writeSQL) != saved || !reflect.DeepEqual(inspect(t, store, scope), before) {
		t.Fatal("WAL refusal changed a durable batch or concealed the failure", version, err)
	}
	if len(store.writer) != 0 || store.poisoned.Load() || store.writeSQL.Stats().InUse != 0 || store.readSQL.Stats().InUse != 0 {
		t.Fatal("WAL refusal retained admission, a transaction or poisoned state")
	}
	select {
	case <-changed:
		t.Fatal("WAL refusal published a change")
	default:
	}
	requireCommit(t, store, scope, Change{Version: 2, Key: "b", Value: []byte{2}})
	if err := store.validate(t.Context(), binding); err != nil {
		t.Fatal("restored WAL did not recover", err)
	}
}

// TestWriteDamage refuses inconsistent accounting without repairing or committing a prefix.
func TestWriteDamage(t *testing.T) {
	verified := verification(t, "STORAGE-WRITE-DAMAGE")
	for index, statement := range []string{
		"UPDATE scopes SET records=0,bytes=0",
		"UPDATE scopes SET retained=3",
	} {
		verified(t.Run(statement, func(t *testing.T) {
			limits := Default()
			limits.History = 1
			store, _, binding := fixture(t, limits)
			scope := Scope{"s", "p"}
			requireCommit(t, store, scope, Change{Version: 1, Key: "a", Value: []byte{1}})
			before := inspect(t, store, scope)
			if err := store.write.Exec(statement).Error; err != nil {
				t.Fatal(err)
			}
			saved := contents(t, store.writeSQL)
			changed := store.Changed()
			change := Change{Version: 2, Key: "a", Value: []byte{2}}
			if index == 0 {
				change.Value, change.Erase = nil, true
			}
			version, err := store.Commit(t.Context(), scope, change)
			if !errors.Is(err, ErrCorrupt) || version != 0 || contents(t, store.writeSQL) != saved {
				t.Fatal("damaged accounting was accepted or changed", version, err)
			}
			select {
			case <-changed:
				t.Fatal("damaged accounting produced a success notification")
			default:
			}
			// Restore the fixture's independently specified one-record, one-history baseline.
			if err := store.write.Exec("UPDATE scopes SET records=1,bytes=2,retained=1,backlog=66").Error; err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(inspect(t, store, scope), before) {
				t.Fatal("rejection did not preserve the prior baseline")
			}
			requireCommit(t, store, scope, Change{Version: 2, Key: "a", Value: []byte{2}})
			if err := store.validate(t.Context(), binding); err != nil {
				t.Fatal(err)
			}
		}), statement)
	}
}

// TestBoundary checks encoded prefixes, aggregate feed limits, file ownership and closing errors.
func TestBoundary(t *testing.T) {
	verified := verification(t, "STORAGE-BOUNDARY")
	verified(t.Run("encoding", func(t *testing.T) {
		store, _, _ := fixture(t, Default())
		if version, err := store.CommitBatch(t.Context(), Scope{"s", "p"}, 1, nil); version != 0 || !errors.Is(err, ErrInput) {
			t.Fatal("empty batch admitted", version, err)
		}
		// Two promised entries have sixteen payload bytes, all consumed by the first entry.
		data := binary.BigEndian.AppendUint64([]byte("AB02"), 2)
		data = binary.BigEndian.AppendUint16(data, 9)
		data = binary.BigEndian.AppendUint32(data, 0)
		data = append(data, 0)
		data = append(data, "123456789"...)
		if entries, err := (Change{Value: data}).Entries(); entries != nil || !errors.Is(err, ErrInput) {
			t.Fatal("truncated second header published a prefix", len(entries), err)
		}
	}), "encoding")
	verified(t.Run("feeds", func(t *testing.T) {
		store, _, _ := fixture(t, Default())
		for _, invalid := range []struct {
			bytes int64 // Invalid per-feed byte limit.
			items int   // Invalid per-feed item limit.
		}{{0, 1}, {16<<20 + 1, 1}, {1, 0}, {1, 65537}} {
			if feed, err := store.Subscribe(invalid.bytes, invalid.items); feed != nil || !errors.Is(err, ErrInput) {
				t.Fatal("invalid feed admitted", invalid, err)
			}
		}
		for _, limit := range []int64{1, 16 << 20} {
			count := 128
			if limit != 1 {
				count = 8
			}
			feeds := make([]*Feed, 0, count)
			for range count {
				feed, err := store.Subscribe(limit, 1)
				if err != nil {
					t.Fatal(err)
				}
				feeds = append(feeds, feed)
			}
			if feed, err := store.Subscribe(1, 1); feed != nil || !errors.Is(err, ErrCapacity) || store.feedBytes != int64(count)*limit {
				t.Fatal("aggregate feed boundary admitted excess capacity", err)
			}
			feeds[0].Close()
			feeds[0].Close()
			replacement, err := store.Subscribe(limit, 1)
			if err != nil || store.feedBytes != int64(count)*limit {
				t.Fatal("closed feed did not release its exact reservation", err)
			}
			replacement.Close()
			for _, feed := range feeds {
				feed.Close()
			}
			if len(store.feeds) != 0 || store.feedBytes != 0 {
				t.Fatal("feed reservations leaked")
			}
		}
		feed, err := store.Subscribe(1, 1)
		if err != nil {
			t.Fatal(err)
		}
		for version := Version(1); version <= 2; version++ {
			requireCommit(t, store, Scope{"s", "p"}, Change{Version: version, Key: "k", Value: []byte{byte(version)}})
			if events, err := feed.Take(); events != nil || !errors.Is(err, ErrCapacity) {
				t.Fatal("failed feed resumed or retained a prefix", err)
			}
		}
		feed.Close()
		if _, err := feed.Take(); !errors.Is(err, ErrCapacity) || store.feedBytes != 0 {
			t.Fatal("close replaced the first overload cause or leaked its budget", err)
		}
	}), "feeds")
	verified(t.Run("locks", func(t *testing.T) {
		directory := t.TempDir()
		fifo := filepath.Join(directory, "fifo")
		if err := unix.Mkfifo(fifo+".lock", 0600); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(directory, "alias")
		if err := os.Symlink(fifo+".lock", alias+".lock"); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{fifo, alias, filepath.Join(directory, "missing", "database")} {
			if file, err := lock(path); file != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatal("invalid lock target admitted", path, err)
			}
		}
		path := filepath.Join(directory, "regular")
		owner, err := lock(path)
		if err != nil {
			t.Fatal(err)
		}
		if second, err := lock(path); second != nil || !errors.Is(err, ErrUnavailable) {
			t.Fatal("duplicate lock owner admitted", err)
		}
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
		owner, err = lock(path)
		if err != nil {
			t.Fatal("released ownership cannot be reacquired", err)
		}
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
	}), "locks")
	verified(t.Run("lifecycle", func(t *testing.T) {
		store, path, binding := fixture(t, Default())
		if store.Limits() != Default() {
			t.Fatal("effective limits changed")
		}
		for _, invalid := range []Binding{
			{Galaxy: "", Username: binding.Username, Advertise: binding.Advertise},
			{Galaxy: binding.Galaxy, Username: "", Advertise: binding.Advertise},
			{Galaxy: strings.Repeat("g", 65), Username: binding.Username, Advertise: binding.Advertise},
			{Galaxy: binding.Galaxy, Username: strings.Repeat("u", 65), Advertise: binding.Advertise},
			{Galaxy: "bad/name", Username: binding.Username, Advertise: binding.Advertise},
			{Galaxy: binding.Galaxy, Username: "bad\x00name", Advertise: binding.Advertise},
		} {
			if opened, err := Open(t.Context(), path, invalid, Default(), false); opened != nil || !errors.Is(err, ErrInput) {
				t.Fatal("invalid deployment name admitted", err)
			}
		}
		for _, size := range []int{1, 64} {
			identity := Binding{Galaxy: strings.Repeat("g", size), Username: strings.Repeat("u", size), Advertise: binding.Advertise}
			path := filepath.Join(t.TempDir(), "boundary.db")
			opened, err := Open(t.Context(), path, identity, Default(), true)
			if err != nil {
				t.Fatal("valid identity length rejected", size, err)
			}
			if err := opened.Close(); err != nil {
				t.Fatal(err)
			}
			opened, err = Open(t.Context(), path, identity, Default(), false)
			if err != nil {
				t.Fatal("valid identity did not persist at its boundary", size, err)
			}
			if err := opened.Close(); err != nil {
				t.Fatal(err)
			}
		}
		// A closed lock descriptor is a real cleanup failure, not a fabricated Close result.
		if err := store.file.Close(); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); !errors.Is(err, ErrUnavailable) || store.readSQL.Stats().OpenConnections != 0 || store.writeSQL.Stats().OpenConnections != 0 {
			t.Fatal("cleanup failure hidden or connections left open", err)
		}
		if err := store.Close(); err != nil {
			t.Fatal("repeated close is not idempotent", err)
		}
		if version, err := store.Commit(t.Context(), Scope{"s", "p"}, Change{Version: 1, Key: "k"}); version != 0 || !errors.Is(err, ErrClosed) {
			t.Fatal("closed store admitted a commit", version, err)
		}
		owner, err := lock(path)
		if err != nil {
			t.Fatal("cleanup error retained file ownership", err)
		}
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
	}), "lifecycle")
}

// TestRetainScan rejects a malformed native prefix before publishing any commit.
func TestRetainScan(t *testing.T) {
	verified := verification(t, "STORAGE-RETAIN-SCAN")
	limits := Default()
	limits.History = 1
	store, _, binding := fixture(t, limits)
	scope := Scope{"s", "p"}
	requireCommit(t, store, scope, Change{Version: 1, Key: "a", Value: []byte{1}})
	saved := contents(t, store.writeSQL)
	// The durable history format remains valid; only the query result has a wrong dynamic type.
	pool := &boundary{point: "retain-scan"}
	adapt(t, store, func(conn *sqlite3.SQLiteConn) driver.Conn { return &bordering{SQLiteConn: conn, pool: pool} })
	pool.active.Store(true)
	version, err := store.Commit(t.Context(), scope, Change{Version: 2, Key: "a", Value: []byte{2}})
	pool.active.Store(false)
	verified(version == 0 && errors.Is(err, ErrUnavailable) && pool.hits.Load() == 1, "wrong native prefix type is rejected once")
	verified(contents(t, store.writeSQL) == saved && len(store.writer) == 0 && store.writeSQL.Stats().InUse == 0, "prefix scan failure rolls back and drains")
	requireCommit(t, store, scope, Change{Version: 2, Key: "a", Value: []byte{2}})
	verified(store.validate(t.Context(), binding) == nil, "normal prefix scan recovers")
}

// QueryContext substitutes only a retained-prefix result type, using the real native transaction.
func (conn *bordering) QueryContext(ctx context.Context, query string, arguments []driver.NamedValue) (driver.Rows, error) {
	if conn.pool.active.Load() && conn.pool.point == "retain-scan" && strings.HasPrefix(query, "SELECT version,cost FROM ") {
		conn.pool.hits.Add(1)
		query = strings.Replace(query, "SELECT version,cost", "SELECT 1 AS version,cost", 1)
	}
	return conn.SQLiteConn.QueryContext(ctx, query, arguments)
}
