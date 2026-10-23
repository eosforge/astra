//go:build linux && cgo

// Attach fixture-only transaction observers to actual native connections, including explicitly borrowed SQL connections.
package storage

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"net/url"
	"testing"

	"github.com/mattn/go-sqlite3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// adapting owns one fixture's native driver, immutable DSN and connection transformation.
type adapting struct {
	*sqlite3.SQLiteDriver                                       // Production connection initialization and original optional interfaces.
	path                  string                                // Exact fixture-owned write database and connection settings.
	wrap                  func(*sqlite3.SQLiteConn) driver.Conn // Observer attached before any SQL caller borrows the connection.
}

// Connect checks original cancellation before opening and transforming a real SQLite connection.
func (source *adapting) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := source.Open(source.path)
	if err != nil {
		return nil, err
	}
	return source.wrap(conn.(*sqlite3.SQLiteConn)), nil
}

// Driver retains the actual registered driver's semantics without adding a process-wide driver name.
func (source *adapting) Driver() driver.Driver { return source.SQLiteDriver }

// adapt replaces a drained fixture write pool with one observed native pool using the production DSN and ORM settings.
func adapt(t *testing.T, store *Store, wrap func(*sqlite3.SQLiteConn) driver.Conn) {
	t.Helper()
	if err := store.writeSQL.Close(); err != nil {
		t.Fatal("close original fixture write pool", err)
	}
	parameters := url.Values{"mode": {"rw"}, "_journal_mode": {"WAL"}, "_synchronous": {"FULL"}, "_busy_timeout": {"1000"}, "_foreign_keys": {"1"}, "_txlock": {"immediate"}}
	location := url.URL{Scheme: "file", Path: store.path, RawQuery: parameters.Encode()}
	source := &adapting{SQLiteDriver: &sqlite3.SQLiteDriver{ConnectHook: connection}, path: location.String(), wrap: wrap}
	pool := sql.OpenDB(source)
	pool.SetMaxOpenConns(1)
	pool.SetMaxIdleConns(1)
	t.Cleanup(func() { pool.Close() })
	if err := pool.PingContext(t.Context()); err != nil {
		t.Fatal("open observed native fixture pool", err)
	}
	db, err := gorm.Open(sqlite.New(sqlite.Config{Conn: pool}), &gorm.Config{SkipDefaultTransaction: true, Logger: logger.Discard, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal("bind observed fixture ORM", err)
	}
	store.write, store.writeSQL = db, pool
}
