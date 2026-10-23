//go:build linux && cgo

// Exercise real SQLite read preparation, iteration and checkpoint failure boundaries.
package storage

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mattn/go-sqlite3"
)

// native configures a private pool's sole connection outside any active operation.
func native(t *testing.T, pool *sql.DB, apply func(*sqlite3.SQLiteConn) error) error {
	t.Helper()
	pool.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(t.Context(), Default().Timeout)
	defer cancel()
	conn, err := pool.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	return conn.Raw(func(value any) error { return apply(value.(*sqlite3.SQLiteConn)) })
}

// TestReadFault rejects native authorizer failures and recovers without SQL changes.
func TestReadFault(t *testing.T) {
	check := verification(t, "STORAGE-READ-FAULT")
	for _, point := range []struct {
		name  string // Public operation and failed native boundary.
		table string // Authorizer target; a leading pragma: selects SQLITE_PRAGMA.
	}{
		{"list", "scopes"}, {"version", "scopes"}, {"load-state", "scopes"},
		{"load-records", "records"}, {"since-state", "scopes"}, {"since-history", "history"},
		{"validate-quick", "pragma:quick_check"}, {"validate-scopes", "scopes"}, {"validate-foreign", "pragma:foreign_key_check"},
	} {
		check(t.Run(point.name, func(t *testing.T) {
			store, _, binding := fixture(t, Default())
			scope := Scope{"s", "p"}
			requireCommit(t, store, scope, Change{Version: 1, Key: "a", Value: []byte{1}})
			before := inspect(t, store, scope)
			saved := contents(t, store.writeSQL)
			var hits atomic.Int32
			if err := native(t, store.readSQL, func(conn *sqlite3.SQLiteConn) error {
				conn.RegisterAuthorizer(func(operation int, first, _, _ string) int {
					if operation == sqlite3.SQLITE_READ && first == point.table || operation == sqlite3.SQLITE_PRAGMA && "pragma:"+first == point.table {
						hits.Add(1)
						return sqlite3.SQLITE_DENY
					}
					return sqlite3.SQLITE_OK
				})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			var err error
			empty := false
			wanted := ErrUnavailable
			switch point.name {
			case "list":
				var value []Position
				value, err = store.List(t.Context())
				empty = value == nil
			case "version":
				var value Version
				value, err = store.Version(t.Context(), scope)
				empty = value == 0
			case "load-state", "load-records":
				var value Snapshot
				value, err = store.Load(t.Context(), scope)
				empty = reflect.DeepEqual(value, Snapshot{})
			case "since-state", "since-history":
				var value Replay
				value, err = store.Since(t.Context(), scope, 0)
				empty = reflect.DeepEqual(value, Replay{})
			default:
				err = store.validate(t.Context(), binding)
				empty, wanted = true, ErrCorrupt
			}
			if !errors.Is(err, wanted) || !empty || hits.Load() != 1 {
				t.Fatalf("error=%v empty=%v injections=%d", err, empty, hits.Load())
			}
			if err := native(t, store.readSQL, func(conn *sqlite3.SQLiteConn) error { conn.RegisterAuthorizer(nil); return nil }); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(inspect(t, store, scope), before) || contents(t, store.writeSQL) != saved || store.readSQL.Stats().InUse != 0 {
				t.Fatal("failed read changed state or retained a connection")
			}
			requireCommit(t, store, scope, Change{Version: 2, Key: "b", Value: []byte{2}})
			if err := store.validate(t.Context(), binding); err != nil {
				t.Fatal("recovery", err)
			}
		}), point.name)
	}
}

// TestReadStep fails the second native row after a real prefix, without sleeps.
func TestReadStep(t *testing.T) {
	check := verification(t, "STORAGE-READ-STEP")
	for _, table := range []string{"records", "history"} {
		for _, mode := range []string{"error", "cancel-replace", "cancel"} {
			check(t.Run(table+"-"+mode, func(t *testing.T) {
				store, _, binding := fixture(t, Default())
				scope := Scope{"s", "p"}
				requireCommit(t, store, scope, Change{Version: 1, Key: "a", Value: []byte{1}})
				requireCommit(t, store, scope, Change{Version: 2, Key: "b", Value: []byte{2}})
				before := inspect(t, store, scope)
				saved := contents(t, store.writeSQL)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var rows, hits atomic.Int32
				var installed *sqlite3.SQLiteConn
				if err := native(t, store.readSQL, func(conn *sqlite3.SQLiteConn) error {
					installed = conn
					if err := conn.RegisterFunc("read_fault", func(key string, value []byte) ([]byte, error) {
						rows.Add(1)
						if key == "b" {
							hits.Add(1)
							if mode != "error" {
								cancel()
							} else {
								return nil, errors.New("assurance-read-step")
							}
						}
						return value, nil
					}, false); err != nil {
						return err
					}
					columns := "sector,spectrum,key,read_fault(key,value) AS value"
					if table == "history" {
						columns += ",version,erase,cost"
					}
					// A connection-local view leaves the durable schema and rows untouched.
					_, err := conn.Exec("CREATE TEMP VIEW "+table+" AS SELECT "+columns+" FROM main."+table, nil)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				var err error
				empty := false
				if table == "records" {
					var value Snapshot
					value, err = store.Load(ctx, scope)
					empty = reflect.DeepEqual(value, Snapshot{})
				} else {
					var value Replay
					value, err = store.Since(ctx, scope, 0)
					empty = reflect.DeepEqual(value, Replay{})
				}
				if !errors.Is(err, ErrUnavailable) || !empty || hits.Load() != 1 || rows.Load() != 2 {
					t.Fatalf("error=%v empty=%v rows=%d injections=%d", err, empty, rows.Load(), hits.Load())
				}
				if mode == "cancel-replace" {
					// Force the legal cancellation outcome where the pool discards a connection.
					store.readSQL.SetMaxIdleConns(0)
					if err := native(t, store.readSQL, func(*sqlite3.SQLiteConn) error { return nil }); err != nil {
						t.Fatal(err)
					}
					store.readSQL.SetMaxIdleConns(1)
				}
				if err := native(t, store.readSQL, func(conn *sqlite3.SQLiteConn) error {
					if mode == "cancel-replace" && conn == installed {
						return errors.New("forced connection replacement did not occur")
					}
					if conn != installed {
						if mode == "error" {
							return errors.New("non-cancelled read unexpectedly replaced its connection")
						}
						return nil // Connection-local objects were destroyed with their owner.
					}
					_, err := conn.Exec("DROP VIEW temp."+table, nil)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(inspect(t, store, scope), before) || contents(t, store.writeSQL) != saved || store.readSQL.Stats().InUse != 0 {
					t.Fatal("partial read changed state or retained its native transaction")
				}
				requireCommit(t, store, scope, Change{Version: 3, Key: "c", Value: []byte{3}})
				if err := store.validate(t.Context(), binding); err != nil {
					t.Fatal(err)
				}
			}), table+"-"+mode)
		}
	}
}

// TestCheckpoint bounds WAL growth while a pinned reader prevents full checkpointing.
func TestCheckpoint(t *testing.T) {
	check := verification(t, "STORAGE-CHECKPOINT")
	limits := Default()
	limits.WAL = 1 << 20
	store, path, binding := fixture(t, limits)
	scope := Scope{"s", "p"}
	requireCommit(t, store, scope, Change{Version: 1, Key: "k", Value: []byte{1}})
	reader, err := store.readSQL.BeginTx(t.Context(), nil)
	check(err == nil, "begin pinned reader")
	defer reader.Rollback()
	var version Version
	check(reader.QueryRowContext(t.Context(), "SELECT version FROM scopes").Scan(&version) == nil && version == 1, "establish pinned read mark")
	for version := Version(2); version <= 3; version++ {
		requireCommit(t, store, scope, Change{Version: version, Key: "k", Value: bytes.Repeat([]byte{byte(version)}, 256<<10)})
	}
	info, err := os.Stat(path + "-wal")
	check(err == nil && info.Size() >= limits.WAL, "real WAL threshold reached")
	saved := contents(t, store.writeSQL)
	snapshot, err := store.Load(t.Context(), scope)
	check(errors.Is(err, ErrUnavailable) && reflect.DeepEqual(snapshot, Snapshot{}), "blocked checkpoint refuses read")
	_, err = store.Commit(t.Context(), scope, Change{Version: 4, Key: "k", Value: []byte{4}})
	check(errors.Is(err, ErrUnavailable) && contents(t, store.writeSQL) == saved, "blocked checkpoint refuses write without mutation")
	check(reader.Rollback() == nil, "release pinned read mark")
	var hits atomic.Int32
	check(native(t, store.writeSQL, func(conn *sqlite3.SQLiteConn) error {
		conn.RegisterAuthorizer(func(operation int, first, _, _ string) int {
			if operation == sqlite3.SQLITE_PRAGMA && first == "wal_checkpoint" {
				hits.Add(1)
				return sqlite3.SQLITE_DENY
			}
			return sqlite3.SQLITE_OK
		})
		return nil
	}) == nil, "install native checkpoint failure")
	snapshot, err = store.Load(t.Context(), scope)
	check(errors.Is(err, ErrUnavailable) && reflect.DeepEqual(snapshot, Snapshot{}) && hits.Load() == 1, "checkpoint SQL failure reached")
	check(native(t, store.writeSQL, func(conn *sqlite3.SQLiteConn) error { conn.RegisterAuthorizer(nil); return nil }) == nil, "remove checkpoint failure")
	snapshot, err = store.Load(t.Context(), scope)
	check(err == nil && snapshot.Version == 3 && len(snapshot.Records) == 1 && bytes.Equal(snapshot.Records[0].Value, bytes.Repeat([]byte{3}, 256<<10)), "checkpoint catches up after reader release")
	check(contents(t, store.writeSQL) == saved, "checkpoint preserves logical state")
	requireCommit(t, store, scope, Change{Version: 4, Key: "k", Value: []byte{4}})
	check(store.validate(t.Context(), binding) == nil, "writes resume on the same database")
	loop := filepath.Join(t.TempDir(), "loop")
	check(os.Symlink("loop", loop) == nil, "create isolated filesystem failure")
	unavailable := &Store{path: filepath.Join(loop, "database"), limits: limits}
	check(errors.Is(unavailable.maintain(t.Context()), ErrUnavailable), "WAL stat failure is not an absent WAL")
}

// TestConnection checks each configurable native connection defense and its recovery.
func TestConnection(t *testing.T) {
	check := verification(t, "STORAGE-CONNECTION")
	for _, point := range []string{"set-checkpoint", "set-trust", "read-mode", "foreign-keys", "synchronous"} {
		check(t.Run(point, func(t *testing.T) {
			store, _, _ := fixture(t, Default())
			var hits int
			err := native(t, store.readSQL, func(conn *sqlite3.SQLiteConn) error {
				conn.RegisterAuthorizer(func(operation int, first, second, _ string) int {
					if operation == sqlite3.SQLITE_PRAGMA && (point == "set-checkpoint" && first == "wal_autocheckpoint" && second == "1000" || point == "set-trust" && first == "trusted_schema" && strings.EqualFold(second, "OFF") || point == "read-mode" && first == "journal_mode" && second == "") {
						hits++
						return sqlite3.SQLITE_DENY
					}
					return sqlite3.SQLITE_OK
				})
				defer conn.RegisterAuthorizer(nil)
				if point == "foreign-keys" || point == "synchronous" {
					statement, restore := "PRAGMA foreign_keys=OFF", "PRAGMA foreign_keys=ON"
					if point == "synchronous" {
						statement, restore = "PRAGMA synchronous=NORMAL", "PRAGMA synchronous=FULL"
					}
					if _, err := conn.Exec(statement, nil); err != nil {
						return err
					}
					defer func() {
						if _, err := conn.Exec(restore, nil); err != nil {
							t.Error(err)
						}
					}()
				}
				return connection(conn)
			})
			if !errors.Is(err, ErrUnavailable) || (point == "set-checkpoint" || point == "set-trust" || point == "read-mode") && hits != 1 {
				t.Fatalf("connection error=%v injections=%d", err, hits)
			}
			if err := native(t, store.readSQL, connection); err != nil {
				t.Fatal("connection did not recover", err)
			}
		}), point)
	}
}
