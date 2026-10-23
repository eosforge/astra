//go:build linux && cgo

// Challenge persisted accounting, deployment binding and native validation queries without repairing failed state.
package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mattn/go-sqlite3"
)

// TestAccountingGuard rejects inconsistent persisted costs after tentative writes, preserving the original damage.
func TestAccountingGuard(t *testing.T) {
	check := verification(t, "STORAGE-CORRUPTION")
	for _, point := range []struct {
		name   string // Independent damaged accounting boundary.
		damage string // Legal SQL mutation that violates the higher-level accounting contract.
		repair string // Exact restoration used only after rejection has been verified.
	}{
		{"record-bytes", "UPDATE scopes SET bytes=0", "UPDATE scopes SET bytes=4"},
		{"zero-prefix", "UPDATE history SET version=zeroblob(8) WHERE version=X'0000000000000001'", "UPDATE history SET version=X'0000000000000001' WHERE version=zeroblob(8)"},
		{"negative-backlog", "UPDATE history SET cost=999 WHERE version=X'0000000000000001'", "UPDATE history SET cost=68 WHERE version=X'0000000000000001'"},
		{"excess-backlog", "UPDATE scopes SET backlog=1000", "UPDATE scopes SET backlog=136"},
	} {
		check(t.Run(point.name, func(t *testing.T) {
			limits := Default()
			limits.History, limits.Backlog = 2, 256
			store, _, binding := fixture(t, limits)
			scope := Scope{"integrity", "accounting"}
			for version := Version(1); version <= 2; version++ {
				requireCommit(t, store, scope, Change{Version: version, Key: "k", Value: []byte("old")})
			}
			if err := store.write.Exec(point.damage).Error; err != nil {
				t.Fatal(err)
			}
			before := contents(t, store.writeSQL)
			changed := store.Changed()
			for range 2 {
				version, err := store.Commit(t.Context(), scope, Change{Version: 3, Key: "k", Value: []byte("n")})
				if version != 0 || !errors.Is(err, ErrCorrupt) || contents(t, store.writeSQL) != before || store.poisoned.Load() || len(store.writer) != 0 {
					t.Fatal("accounting fault changed durable state or leaked admission", version, err)
				}
				select {
				case <-changed:
					t.Fatal("rejected accounting fault published a commit")
				default:
				}
			}
			if err := store.write.Exec(point.repair).Error; err != nil {
				t.Fatal(err)
			}
			requireCommit(t, store, scope, Change{Version: 3, Key: "k", Value: []byte("n")})
			if err := store.validate(t.Context(), binding); err != nil {
				t.Fatal("exact restoration did not recover consistency", err)
			}
		}), point.name)
	}
}

// TestValidationGuard exercises independent binding/query failures and unchanged healthy recovery.
func TestValidationGuard(t *testing.T) {
	check := verification(t, "STORAGE-CORRUPTION")
	store, path, binding := fixture(t, Default())
	for _, scope := range []Scope{{"a", "p"}, {"b", "p"}} {
		requireCommit(t, store, scope, Change{Version: 1, Key: "k", Value: []byte("v")})
	}
	before := contents(t, store.writeSQL)
	// Deliberately violate a persisted CHECK through SQLite's diagnostic pragma, then restore enforcement before reading.
	for _, statement := range []string{"PRAGMA ignore_check_constraints=ON", "UPDATE meta SET format=2", "PRAGMA ignore_check_constraints=OFF"} {
		if err := store.write.Exec(statement).Error; err != nil {
			t.Fatal(err)
		}
	}
	damaged := contents(t, store.writeSQL)
	var integrity string
	check(store.read.Raw("PRAGMA quick_check").Scan(&integrity).Error == nil && integrity != "ok", "native integrity check observes the deliberate CHECK violation")
	check(errors.Is(store.validate(t.Context(), binding), ErrCorrupt) && contents(t, store.writeSQL) == damaged, "recovery rejects and preserves the native integrity failure")
	check(store.write.Exec("UPDATE meta SET format=1").Error == nil, "restore the exact original format after rejecting damaged state")
	check(contents(t, store.writeSQL) == before && store.validate(t.Context(), binding) == nil, "original state is healthy after exact fixture restoration")
	for _, invalid := range []Binding{{Galaxy: "other", Username: binding.Username, Advertise: binding.Advertise}, {Galaxy: binding.Galaxy, Username: binding.Username, Advertise: "127.0.0.1:45102"}} {
		check(errors.Is(store.validate(t.Context(), invalid), ErrBinding) && contents(t, store.writeSQL) == before, "changed deployment binding does not rewrite the database")
	}
	for _, point := range []struct {
		table  string // Native table read whose preparation must be denied.
		column string // Exact column separates schema and accounting queries from preceding checks.
	}{{"sqlite_master", "sql"}, {"records", "key"}, {"history", "cost"}} {
		check(t.Run(point.table, func(t *testing.T) {
			hits := 0
			if err := native(t, store.readSQL, func(conn *sqlite3.SQLiteConn) error {
				conn.RegisterAuthorizer(func(operation int, table, column, _ string) int {
					if operation == sqlite3.SQLITE_READ && table == point.table && column == point.column {
						hits++
						return sqlite3.SQLITE_DENY
					}
					return sqlite3.SQLITE_OK
				})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			err := store.validate(t.Context(), binding)
			if removed := native(t, store.readSQL, func(conn *sqlite3.SQLiteConn) error { conn.RegisterAuthorizer(nil); return nil }); removed != nil {
				t.Fatal(removed)
			}
			if !errors.Is(err, ErrCorrupt) || hits != 1 || contents(t, store.writeSQL) != before {
				t.Fatal("native validation query was not rejected atomically", err, hits)
			}
			if err := store.validate(t.Context(), binding); err != nil {
				t.Fatal("validation did not recover after query rejection", err)
			}
		}), "denied native validation query")
	}
	check(store.Close() == nil, "close before testing a reduced startup capacity")
	limits := Default()
	limits.Scopes = 1
	reopened, err := Open(t.Context(), path, binding, limits, false)
	if reopened != nil {
		defer reopened.Close()
	}
	check(reopened == nil && errors.Is(err, ErrCapacity), "existing scopes exceed a reduced startup capacity")
	recovered, err := Open(t.Context(), path, binding, Default(), false)
	check(err == nil, "failed startup released exclusive ownership")
	defer recovered.Close()
	check(contents(t, recovered.writeSQL) == before, "rejected startup preserved all persisted rows")

	// No WAL is a legitimate pre-database state and must not attempt a checkpoint through a nonexistent pool.
	root := t.TempDir()
	absent := &Store{path: filepath.Join(root, "absent"), limits: Default()}
	check(absent.maintain(t.Context()) == nil, "missing WAL needs no checkpoint")
	entries, err := os.ReadDir(root)
	check(err == nil && len(entries) == 0, "missing WAL check has no filesystem side effects")
}
