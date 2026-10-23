// Define the SQLite schema and initialization rules for durable authority state.

package storage

import (
	"context"
	"database/sql/driver"
	"strings"

	"github.com/mattn/go-sqlite3"
	"gorm.io/gorm"
)

// schema runs only for explicit initialization; STRICT/CHECK and composite keys reject coercion and duplicates.
// Four WITHOUT ROWID tables cluster by primary key: singleton metadata, Scope state, current records, and retained history.
var schema = []string{
	`CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), format INTEGER NOT NULL CHECK(format=1), galaxy TEXT NOT NULL, username TEXT NOT NULL, advertise TEXT NOT NULL, scopes INTEGER NOT NULL CHECK(scopes>=0), bytes INTEGER NOT NULL CHECK(bytes>=0)) STRICT`,
	`CREATE TABLE scopes (sector TEXT NOT NULL, spectrum TEXT NOT NULL, version BLOB NOT NULL CHECK(length(version)=8), records INTEGER NOT NULL CHECK(records>=0), bytes INTEGER NOT NULL CHECK(bytes>=0), retained INTEGER NOT NULL CHECK(retained>=0), backlog INTEGER NOT NULL CHECK(backlog>=0), PRIMARY KEY(sector,spectrum)) STRICT, WITHOUT ROWID`,
	`CREATE TABLE records (sector TEXT NOT NULL, spectrum TEXT NOT NULL, key TEXT NOT NULL, value BLOB NOT NULL, PRIMARY KEY(sector,spectrum,key), FOREIGN KEY(sector,spectrum) REFERENCES scopes(sector,spectrum)) STRICT, WITHOUT ROWID`,
	`CREATE TABLE history (sector TEXT NOT NULL, spectrum TEXT NOT NULL, version BLOB NOT NULL CHECK(length(version)=8), key TEXT NOT NULL, value BLOB NOT NULL, erase INTEGER NOT NULL CHECK(erase IN (0,1)), cost INTEGER NOT NULL CHECK(cost>0), PRIMARY KEY(sector,spectrum,version), FOREIGN KEY(sector,spectrum) REFERENCES scopes(sector,spectrum)) STRICT, WITHOUT ROWID`,
}

// settings is the private SQL boundary used to set and verify connection-local pragmas.
type settings interface {
	Exec(string, []driver.Value) (driver.Result, error)
	Query(string, []driver.Value) (driver.Rows, error)
}

// connection bounds native rows and verifies every newly opened connection before admitting it to a pool.
func connection(conn *sqlite3.SQLiteConn) error {
	// History can contain a complete retained batch plus its row header; this does not cap the committed batch.
	conn.SetLimit(sqlite3.SQLITE_LIMIT_LENGTH, (64<<20)+1024)
	conn.SetLimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 64<<10)
	return configure(conn)
}

// configure checks actual pragma receipts and closes every acquired cursor even when reading fails.
func configure(conn settings) error {
	// Set these values on every connection, independently of whichever connection the pool selects later.
	for _, statement := range []string{"PRAGMA wal_autocheckpoint=1000", "PRAGMA trusted_schema=OFF"} {
		if _, err := conn.Exec(statement, nil); err != nil {
			return ErrUnavailable
		}
	}
	// Reject incorrect durability, integrity or checkpoint settings before admitting the connection.
	for query, expected := range map[string]driver.Value{"PRAGMA journal_mode": "wal", "PRAGMA synchronous": int64(2), "PRAGMA foreign_keys": int64(1), "PRAGMA wal_autocheckpoint": int64(1000)} {
		rows, err := conn.Query(query, nil)
		if err != nil {
			return ErrUnavailable
		}
		value := make([]driver.Value, 1)
		err = rows.Next(value)
		closed := rows.Close()
		if err != nil || closed != nil || value[0] != expected {
			return ErrUnavailable
		}
	}
	return nil
}

// validate checks format, binding, schema, and active charges before listening, without repairing invalid databases.
// binding is expected deployment identity; mismatches return errors without modifying storage.
func (store *Store) validate(ctx context.Context, binding Binding) error {
	// Recovery must also join native cancellation rollback before failed construction releases its database lock.
	db, conn, err := session(ctx, store.readSQL, store.read)
	if err != nil {
		return err
	}
	defer conn.Close()
	return db.Transaction(func(tx *gorm.DB) error {
		// Run quick integrity checks first; invalid pages mean corruption.
		var integrity string
		if err := tx.Raw("PRAGMA quick_check").Scan(&integrity).Error; err != nil || integrity != "ok" {
			return ErrCorrupt
		}
		// Require exact normalized schema definitions and table count.
		var definitions []struct{ SQL string }
		if err := tx.Raw("SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name").Scan(&definitions).Error; err != nil || len(definitions) != len(schema) {
			return ErrCorrupt
		}
		wanted := make(map[string]bool, len(schema))
		for _, definition := range schema {
			wanted[strings.Join(strings.Fields(definition), " ")] = true
		}
		for _, definition := range definitions {
			if !wanted[strings.Join(strings.Fields(definition.SQL), " ")] {
				return ErrCorrupt
			}
		}
		// Metadata must exist at format 1 with matching deployment binding.
		var meta metadata
		if err := tx.Table("meta").Where("id=1").Take(&meta).Error; err != nil || meta.Format != 1 {
			return ErrCorrupt
		}
		if meta.Galaxy != binding.Galaxy || meta.Username != binding.Username || meta.Advertise != binding.Advertise {
			return ErrBinding
		}
		// Validate each Scope's counters, actual records, snapshot consistency, and continuous history.
		var scopes []struct {
			Scope
			State group `gorm:"embedded"`
		}
		if err := tx.Table("scopes").Limit(int(store.limits.Scopes) + 1).Find(&scopes).Error; err != nil {
			return ErrCorrupt
		}
		if int64(len(scopes)) > store.limits.Scopes || meta.Scopes != int64(len(scopes)) || meta.Bytes > store.limits.Total {
			return ErrCapacity
		}
		var total int64
		for _, scope := range scopes {
			state := scope.State
			// Check Scope shape first: valid Scope, positive version, bounded self-consistent counters.
			if !scope.Scope.Valid() || state.Version == 0 || state.Records > store.limits.Records || state.Bytes > store.limits.Bytes || state.Retained > store.limits.History || state.Backlog > store.limits.Backlog || state.Retained < 0 || uint64(state.Retained) > uint64(state.Version) {
				return ErrCorrupt
			}
			// Actual record count and bytes must match state.
			var actual struct {
				Records int64
				Bytes   int64
			}
			if err := tx.Raw("SELECT COUNT(*) AS records, COALESCE(SUM(length(CAST(key AS BLOB))+length(value)),0) AS bytes FROM records WHERE sector=? AND spectrum=?", scope.Sector, scope.Spectrum).Scan(&actual).Error; err != nil || actual.Records != state.Records || actual.Bytes != state.Bytes {
				return ErrCorrupt
			}
			// Validate one Scope at a time to avoid copying whole-database payload at startup.
			if _, err := store.snapshot(tx, scope.Scope); err != nil {
				return err
			}
			// Actual retained-history counts must match a continuous replayable suffix.
			var retained struct {
				Count int64
				Bytes int64
			}
			if err := tx.Raw("SELECT COUNT(*) AS count, COALESCE(SUM(cost),0) AS bytes FROM history WHERE sector=? AND spectrum=?", scope.Sector, scope.Spectrum).Scan(&retained).Error; err != nil || retained.Count != state.Retained || retained.Bytes != state.Backlog {
				return ErrCorrupt
			}
			if _, err := store.history(tx, scope.Scope, state, state.Version-Version(state.Retained)); err != nil {
				return err
			}
			total += actual.Bytes
		}
		// Total bytes must match metadata.
		if total != meta.Bytes {
			return ErrCorrupt
		}
		// Foreign-key checks catch orphan rows absent from Scope traversal.
		rows, err := tx.Raw("PRAGMA foreign_key_check").Rows()
		if err != nil {
			return ErrCorrupt
		}
		invalid := rows.Next()
		err = rows.Err()
		closed := rows.Close()
		if invalid || err != nil || closed != nil {
			return ErrCorrupt
		}
		return nil
	})
}
