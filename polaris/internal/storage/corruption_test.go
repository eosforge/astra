//go:build linux && cgo

// Exercise persisted corruption without repairing it or publishing partial reads.
package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// contents hashes ordered SQL values and definitions independently of storage readers.
func contents(t *testing.T, pool *sql.DB) string {
	t.Helper()
	digest := sha256.New()
	encoder := json.NewEncoder(digest)
	for _, query := range []string{
		"SELECT type,name,sql FROM sqlite_schema ORDER BY type,name",
		"SELECT * FROM meta ORDER BY id",
		"SELECT * FROM scopes ORDER BY sector,spectrum",
		"SELECT * FROM records ORDER BY sector,spectrum,key",
		"SELECT * FROM history ORDER BY sector,spectrum,version",
	} {
		rows, err := pool.QueryContext(t.Context(), query)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for index := range values {
				pointers[index] = &values[index]
			}
			if err := rows.Scan(pointers...); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			// Preserve invalid UTF-8 bytes instead of JSON replacement characters.
			for index, value := range values {
				if text, ok := value.(string); ok {
					values[index] = struct{ Text []byte }{[]byte(text)}
				}
			}
			if err := encoder.Encode(values); err != nil {
				rows.Close()
				t.Fatal(err)
			}
		}
		err = rows.Err()
		closed := rows.Close()
		if err != nil || closed != nil {
			t.Fatal(err, closed)
		}
	}
	return fmt.Sprintf("%x", digest.Sum(nil))
}

// TestCorruption rejects independently constructed SQL inconsistencies on read/reopen.
func TestCorruption(t *testing.T) {
	// Expected failures follow the durable format, not values obtained from the reader.
	type damage struct {
		name    string   // Stable identity of the corrupt format boundary.
		sql     []string // Mutations applied only to this case's private database.
		load    error    // Non-nil requires an empty failed snapshot.
		history error    // Non-nil requires an empty failed replay.
		open    error    // Required startup rejection, including configuration capacity.
	}
	const scope = " WHERE sector='s' AND spectrum='p'"
	const records = "UPDATE scopes SET bytes=(SELECT SUM(length(CAST(key AS BLOB))+length(value)) FROM records" + scope + ")" + scope
	const history = "UPDATE scopes SET retained=(SELECT COUNT(*) FROM history" + scope + "),backlog=(SELECT SUM(cost) FROM history" + scope + ")" + scope
	const total = "UPDATE meta SET bytes=(SELECT SUM(bytes) FROM scopes)"
	cases := []damage{
		{"record-empty-key", []string{"UPDATE records SET key=''" + scope + " AND key='a'", records, total}, ErrCorrupt, nil, ErrCorrupt},
		{"record-zero-key", []string{"UPDATE records SET key=char(0)" + scope + " AND key='a'", records, total}, ErrCorrupt, nil, ErrCorrupt},
		{"record-utf8", []string{"UPDATE records SET key=CAST(X'ff' AS TEXT)" + scope + " AND key='a'", records, total}, ErrCorrupt, nil, ErrCorrupt},
		{"record-long-key", []string{"UPDATE records SET key=printf('%01025d',0)" + scope + " AND key='a'", records, total}, ErrCorrupt, nil, ErrCorrupt},
		{"record-long-value", []string{"UPDATE records SET value=zeroblob(1048577)" + scope + " AND key='b'", records, total}, ErrCorrupt, nil, ErrCorrupt},
		{"record-under-count", []string{"UPDATE scopes SET records=1" + scope}, ErrCorrupt, nil, ErrCorrupt},
		{"record-over-count", []string{"UPDATE scopes SET records=3" + scope}, ErrCorrupt, nil, ErrCorrupt},
		{"record-under-bytes", []string{"UPDATE scopes SET bytes=3" + scope}, ErrCorrupt, nil, ErrCorrupt},
		{"record-over-bytes", []string{"UPDATE scopes SET bytes=5" + scope}, ErrCorrupt, nil, ErrCorrupt},
		{"record-count-capacity", []string{"UPDATE scopes SET records=65537" + scope}, ErrCapacity, nil, ErrCorrupt},
		{"record-byte-capacity", []string{"UPDATE scopes SET bytes=67108865" + scope}, ErrCapacity, nil, ErrCorrupt},
		{"history-version-count", []string{"UPDATE scopes SET retained=4" + scope}, nil, ErrCorrupt, ErrCorrupt},
		{"history-count-capacity", []string{"UPDATE scopes SET retained=1001,version=X'00000000000003e9'" + scope}, nil, ErrCorrupt, ErrCorrupt},
		{"history-byte-capacity", []string{"UPDATE scopes SET backlog=8388609" + scope}, nil, ErrCorrupt, ErrCorrupt},
		{"history-under-bytes", []string{"UPDATE scopes SET backlog=197" + scope}, nil, ErrCorrupt, ErrCorrupt},
		{"history-over-bytes", []string{"UPDATE scopes SET backlog=199" + scope}, nil, nil, ErrCorrupt},
		{"history-gap", []string{"DELETE FROM history" + scope + " AND version=X'0000000000000002'"}, nil, ErrCorrupt, ErrCorrupt},
		{"history-tail", []string{"DELETE FROM history" + scope + " AND version=X'0000000000000003'"}, nil, ErrCorrupt, ErrCorrupt},
		{"history-ahead", []string{"UPDATE history SET version=X'0000000000000004'" + scope + " AND version=X'0000000000000003'"}, nil, ErrCorrupt, ErrCorrupt},
		{"history-extra", []string{"INSERT INTO history VALUES('s','p',X'0000000000000004','a',X'04',0,66)"}, nil, ErrCorrupt, ErrCorrupt},
		{"history-cost", []string{"UPDATE history SET cost=67" + scope + " AND version=X'0000000000000003'", history}, nil, ErrCorrupt, ErrCorrupt},
		{"history-erase-value", []string{"UPDATE history SET erase=1" + scope + " AND version=X'0000000000000003'"}, nil, ErrCorrupt, ErrCorrupt},
		{"history-batch", []string{"UPDATE history SET key='',cost=65" + scope + " AND version=X'0000000000000003'", history}, nil, ErrCorrupt, ErrCorrupt},
		{"history-shifted", []string{"UPDATE history SET version=X'0000000000000000'" + scope + " AND version=X'0000000000000001'"}, nil, ErrCorrupt, ErrCorrupt},
		{"scope-zero-version", []string{"UPDATE scopes SET version=zeroblob(8)" + scope}, nil, nil, ErrCorrupt},
		{"scope-invalid", []string{"PRAGMA foreign_keys=OFF", "UPDATE scopes SET sector=''" + scope}, nil, nil, ErrCorrupt},
		{"meta-missing", []string{"DELETE FROM meta"}, nil, nil, ErrCorrupt},
		{"meta-scopes", []string{"UPDATE meta SET scopes=3"}, nil, nil, ErrCapacity},
		{"meta-bytes", []string{"UPDATE meta SET bytes=10"}, nil, nil, ErrCorrupt},
		{"meta-capacity", []string{"UPDATE meta SET bytes=268435457"}, nil, nil, ErrCapacity},
		{"schema-extra", []string{"CREATE INDEX unexpected ON records(key)"}, nil, nil, ErrCorrupt},
		{"schema-changed", []string{"ALTER TABLE records ADD COLUMN unexpected INTEGER NOT NULL DEFAULT 0"}, nil, nil, ErrCorrupt},
		{"orphan-record", []string{"PRAGMA foreign_keys=OFF", "INSERT INTO records VALUES('absent','p','k',X'01')"}, nil, nil, ErrCorrupt},
		{"orphan-history", []string{"PRAGMA foreign_keys=OFF", "INSERT INTO history VALUES('absent','p',X'0000000000000001','k',X'01',0,66)"}, nil, nil, ErrCorrupt},
	}
	check := verification(t, "STORAGE-CORRUPTION")
	for _, damaged := range cases {
		check(t.Run(damaged.name, func(t *testing.T) {
			store, path, binding := fixture(t, Default())
			scope := Scope{"s", "p"}
			for index, key := range []string{"a", "b", "a"} {
				requireCommit(t, store, scope, Change{Version: Version(index + 1), Key: key, Value: []byte{byte(index + 1)}})
			}
			healthy := Scope{"z", "p"}
			requireCommit(t, store, healthy, Change{Version: 1, Key: "keep", Value: []byte{9}})
			before := contents(t, store.writeSQL)
			for _, statement := range damaged.sql {
				if err := store.write.Exec(statement).Error; err != nil {
					t.Fatal("construct corruption", statement, err)
				}
			}
			corrupt := contents(t, store.writeSQL)
			if corrupt == before {
				t.Fatal("corruption did not change persisted values")
			}
			if damaged.load != nil {
				value, err := store.Load(t.Context(), scope)
				if !errors.Is(err, damaged.load) || !reflect.DeepEqual(value, Snapshot{}) {
					t.Fatalf("partial/accepted snapshot: version=%v records=%d error=%v", value.Version, len(value.Records), err)
				}
			}
			if damaged.history != nil {
				value, err := store.Since(t.Context(), scope, 0)
				if !errors.Is(err, damaged.history) || !reflect.DeepEqual(value, Replay{}) {
					t.Fatalf("partial/accepted history: version=%v changes=%d error=%v", value.Version, len(value.Changes), err)
				}
			}
			value, err := store.Load(t.Context(), healthy)
			wanted := Snapshot{Position: Position{Scope: healthy, Version: 1}, Records: []Record{{Key: "keep", Value: []byte{9}}}}
			if err != nil || !reflect.DeepEqual(value, wanted) || contents(t, store.writeSQL) != corrupt {
				t.Fatal("reads changed stored data or contaminated the independent scope", err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				reopened, err := Open(t.Context(), path, binding, Default(), false)
				if reopened != nil {
					reopened.Close()
					t.Fatal("corrupt database opened")
				}
				if !errors.Is(err, damaged.open) {
					t.Fatalf("open error=%v, want %v", err, damaged.open)
				}
				// A rejected open must release its exclusive ownership immediately.
				owner, err := lock(path)
				if err != nil {
					t.Fatal("failed open retained ownership", err)
				}
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
				_, pool, err := database(t.Context(), path, false)
				if err != nil {
					t.Fatal(err)
				}
				unchanged := contents(t, pool) == corrupt
				if err := pool.Close(); err != nil || !unchanged {
					t.Fatal("rejected open repaired or changed corruption", err)
				}
			}
		}), damaged.name)
	}
}

// TestReadBoundary checks public empty, invalid, and closed read results.
func TestReadBoundary(t *testing.T) {
	limits := Default()
	limits.Scopes = 1
	store, _, _ := fixture(t, limits)
	scope := Scope{"s", "p"}
	check := verification(t, "STORAGE-READ")
	version, err := store.Version(t.Context(), scope)
	check(err == nil && version == 0, "missing scope has version zero")
	requireCommit(t, store, scope, Change{Version: 1, Key: "k", Value: []byte{1}})
	version, err = store.Version(t.Context(), scope)
	check(err == nil && version == 1, "committed scope version")
	for _, invalid := range []Scope{{}, {"s", ""}, {"s", "\xff"}} {
		version, err = store.Version(t.Context(), invalid)
		check(errors.Is(err, ErrInput) && version == 0, "invalid version query")
		snapshot, err := store.Load(t.Context(), invalid)
		check(errors.Is(err, ErrInput) && reflect.DeepEqual(snapshot, Snapshot{}), "invalid snapshot query")
		replay, err := store.Since(t.Context(), invalid, 0)
		check(errors.Is(err, ErrInput) && reflect.DeepEqual(replay, Replay{}), "invalid history query")
	}
	check(store.write.Exec("INSERT INTO scopes VALUES('extra','p',X'0000000000000001',0,0,0,0)").Error == nil, "inject scope over capacity")
	saved := contents(t, store.writeSQL)
	positions, err := store.List(t.Context())
	check(errors.Is(err, ErrCapacity) && positions == nil, "over-capacity list has no partial result")
	check(contents(t, store.writeSQL) == saved, "list did not repair scope accounting")
	check(store.write.Exec("DELETE FROM scopes WHERE sector='extra'").Error == nil, "remove extra scope")
	positions, err = store.List(t.Context())
	check(err == nil && reflect.DeepEqual(positions, []Position{{Scope: scope, Version: 1}}), "list recovers after removing excess scope")
	check(store.Close() == nil, "close owned store")
	positions, err = store.List(t.Context())
	check(errors.Is(err, ErrClosed) && positions == nil, "closed list")
	version, err = store.Version(t.Context(), scope)
	check(errors.Is(err, ErrClosed) && version == 0, "closed version")
	snapshot, err := store.Load(t.Context(), scope)
	check(errors.Is(err, ErrClosed) && reflect.DeepEqual(snapshot, Snapshot{}), "closed snapshot")
	replay, err := store.Since(t.Context(), scope, 0)
	check(errors.Is(err, ErrClosed) && reflect.DeepEqual(replay, Replay{}), "closed history")
}
