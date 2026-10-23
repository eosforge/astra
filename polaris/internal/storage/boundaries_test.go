//go:build linux && cgo

// Verify independent rejection causes without losing data, notifications or resource reservations.
package storage

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gorm.io/gorm"
)

// TestDeploymentGuard rejects each unsafe endpoint before creating a database or ownership file.
func TestDeploymentGuard(t *testing.T) {
	check := verification(t, "STORAGE-BOUNDARY")
	for _, endpoint := range []string{"invalid", "[2001:0db8::1]:45101", "127.0.0.1:0", "0.0.0.0:45101", "224.0.0.1:45101", "[::ffff:127.0.0.1]:45101", "[fe80::1%eth0]:45101", ""} {
		check(t.Run(endpoint, func(t *testing.T) {
			root := t.TempDir()
			binding := Binding{Galaxy: "guard", Username: "polaris", Advertise: endpoint}
			path := filepath.Join(root, "database")
			if endpoint == "" {
				binding.Advertise, path = "127.0.0.1:45101", ""
			}
			store, err := Open(t.Context(), path, binding, Default(), true)
			if store != nil {
				defer store.Close()
			}
			if store != nil || !errors.Is(err, ErrInput) {
				t.Fatal("unsafe deployment admitted", endpoint, err)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatal("rejected deployment created filesystem state", entries, err)
			}
		}), "endpoint rejection")
	}
}

// TestBatchGuard checks the published AB02 layout and whole-commit rejection with fixed wire counterexamples.
func TestBatchGuard(t *testing.T) {
	check := verification(t, "STORAGE-BOUNDARY")
	// Each literal starts with magic/count followed by big-endian key length, value length, erase and payload.
	for _, wire := range []string{
		"414230330000000000000001000100000000006b",                 // Unknown magic with otherwise complete data.
		"414230320000000000000001000200000000006b",                 // Key extends beyond the remaining payload.
		"414230320000000000000001000100000000026b",                 // Erase discriminator is neither set nor delete.
		"414230320000000000000002000100000000006b000100000000006b", // Two valid entries repeat a key.
	} {
		data, err := hex.DecodeString(wire)
		check(err == nil, "decode fixed wire counterexample")
		entries, err := (Change{Version: 1, Value: data}).Entries()
		check(entries == nil && errors.Is(err, ErrInput), "reject malformed complete batch without a prefix")
	}
	valid, err := hex.DecodeString("414230320000000000000001000100000000006b")
	check(err == nil, "decode fixed valid wire")
	entries, err := (Change{Version: 1, Value: valid, Erase: true}).Entries()
	check(entries == nil && errors.Is(err, ErrInput), "batch envelope cannot also be a deletion")
	entries, err = (Change{Version: 1, Value: valid}).Entries()
	check(err == nil && len(entries) == 1 && entries[0].Key == "k" && !entries[0].Erase && entries[0].Version == 1 && len(entries[0].Value) == 0, "healthy fixed wire remains valid")

	store, _, _ := fixture(t, Default())
	scope := Scope{"guard", "batch"}
	requireCommit(t, store, scope, Change{Version: 1, Key: "keep", Value: []byte("old")})
	saved := contents(t, store.writeSQL)
	for _, changes := range [][]Change{{{Key: ""}}, {{Key: "x", Version: 3}}, {{Key: "x", Erase: true, Value: []byte("invalid")}}} {
		version, err := store.CommitBatch(t.Context(), scope, 2, changes)
		check(version == 0 && errors.Is(err, ErrInput) && contents(t, store.writeSQL) == saved, "batch input failure preserves the entire database")
	}
	for _, attempt := range []struct {
		scope  Scope  // Invalid scope or valid scope paired with a malformed batch.
		change Change // Mutating request whose rejection must precede commit.
	}{{Scope{"", "batch"}, Change{Version: 2, Key: "x"}}, {scope, Change{Version: 2, Value: []byte("invalid")}}} {
		version, err := store.Commit(t.Context(), attempt.scope, attempt.change)
		check(version == 0 && errors.Is(err, ErrInput) && contents(t, store.writeSQL) == saved, "single commit input failure preserves the entire database")
	}
	// Exercise the internal decoder guard independently; public Commit rejects this envelope before delegation.
	changed := store.Changed()
	for range 2 {
		version, err := store.commit(t.Context(), scope, Change{Version: 2, Value: []byte("invalid")})
		check(version == 0 && errors.Is(err, ErrInput) && contents(t, store.writeSQL) == saved, "internal batch rejection preserves durable state")
		check(!store.poisoned.Load() && len(store.writer) == 0 && store.writeSQL.Stats().InUse == 0, "internal batch rejection acquires no retained admission")
		select {
		case <-changed:
			t.Fatal("internal batch rejection published a commit")
		default:
		}
	}
	version, err := store.CommitBatch(t.Context(), scope, 2, []Change{{Key: "x", Version: 2}})
	check(err == nil && version == 2, "matching explicit entry version is accepted after rejection")
	snapshot, err := store.Load(t.Context(), scope)
	check(err == nil && snapshot.Version == 2 && len(snapshot.Records) == 2 && snapshot.Records[0].Key == "keep" && bytes.Equal(snapshot.Records[0].Value, []byte("old")) && snapshot.Records[1].Key == "x", "recovery publishes the complete intended state")
}

// TestCapacityGuard distinguishes the global payload budget and feed item budget from their byte counterparts.
func TestCapacityGuard(t *testing.T) {
	check := verification(t, "STORAGE-BOUNDARY")
	limits := Default()
	limits.Bytes, limits.Total = 4, 4
	store, _, _ := fixture(t, limits)
	first, second := Scope{"s", "first"}, Scope{"s", "second"}
	requireCommit(t, store, first, Change{Version: 1, Key: "k", Value: []byte("123")})
	saved := contents(t, store.writeSQL)
	version, err := store.Commit(t.Context(), second, Change{Version: 1, Key: "k", Value: []byte("1")})
	check(version == 0 && errors.Is(err, ErrCapacity) && contents(t, store.writeSQL) == saved, "individually fitting scope exceeds the shared budget atomically")
	requireCommit(t, store, first, Change{Version: 2, Key: "k", Erase: true})
	requireCommit(t, store, second, Change{Version: 1, Key: "k", Value: []byte("1")})
	feed, err := store.Subscribe(4096, 1)
	check(err == nil, "admit one-item feed with ample byte capacity")
	t.Cleanup(feed.Close)
	requireCommit(t, store, second, Change{Version: 2, Key: "k", Value: []byte("2")})
	ready := feed.Ready()
	requireCommit(t, store, second, Change{Version: 3, Key: "k", Value: []byte("3")})
	select {
	case <-ready:
		check(true, "full item queue wakes the consumer")
	default:
		t.Fatal("full item queue did not notify termination")
	}
	events, err := feed.Take()
	check(events == nil && errors.Is(err, ErrCapacity) && feed.bytes == 0 && len(feed.queue) == 0, "item overflow releases the queued prefix")
	snapshot, err := store.Load(t.Context(), second)
	check(err == nil && snapshot.Version == 3 && len(snapshot.Records) == 1 && bytes.Equal(snapshot.Records[0].Value, []byte("3")), "feed failure does not undo durable authority commits")
	feed.Close()
	check(store.feedBytes == 0, "closing the failed feed releases its reservation")
}

// TestReceiptGuard distinguishes ignored SQL updates and conflicting retry identities from execution errors.
func TestReceiptGuard(t *testing.T) {
	check := verification(t, "STORAGE-BOUNDARY")
	for _, point := range []struct {
		table string // Real SQLite update suppressed by a controlled trigger.
		err   error  // Contract-level result for the missing update receipt.
	}{{"scopes", ErrVersion}, {"meta", ErrCorrupt}} {
		check(t.Run(point.table, func(t *testing.T) {
			store, _, binding := fixture(t, Default())
			scope := Scope{"guard", "receipt"}
			requireCommit(t, store, scope, Change{Version: 1, Key: "a", Value: []byte("old")})
			before := inspect(t, store, scope)
			if err := store.write.Exec("CREATE TRIGGER ignore_update BEFORE UPDATE ON " + point.table + " BEGIN SELECT RAISE(IGNORE); END").Error; err != nil {
				t.Fatal(err)
			}
			hits := 0
			if err := store.write.Callback().Raw().After("gorm:raw").Register("assurance:ignored", func(tx *gorm.DB) {
				if strings.HasPrefix(tx.Statement.SQL.String(), "UPDATE "+point.table+" SET") && tx.Error == nil && tx.RowsAffected == 0 {
					hits++
				}
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := store.write.Callback().Raw().Remove("assurance:ignored"); err != nil {
					t.Error(err)
				}
			})
			version, err := store.Commit(t.Context(), scope, Change{Version: 2, Key: "b", Value: []byte("new")})
			if version != 0 || !errors.Is(err, point.err) || hits != 1 || !reflect.DeepEqual(inspect(t, store, scope), before) {
				t.Fatal("ignored update was not reached or leaked a partial commit", version, err, hits)
			}
			if err := store.write.Exec("DROP TRIGGER ignore_update").Error; err != nil {
				t.Fatal(err)
			}
			requireCommit(t, store, scope, Change{Version: 2, Key: "b", Value: []byte("new")})
			if err := store.validate(t.Context(), binding); err != nil {
				t.Fatal("recovered state failed native consistency checks", err)
			}
		}), "ignored native SQL receipt")
	}
	store, _, _ := fixture(t, Default())
	scope := Scope{"guard", "retry"}
	requireCommit(t, store, scope, Change{Version: 1, Key: "a", Value: []byte("old")})
	saved := contents(t, store.writeSQL)
	version, err := store.Commit(t.Context(), scope, Change{Version: 1, Key: "b", Value: []byte("old")})
	check(version == 0 && errors.Is(err, ErrVersion) && contents(t, store.writeSQL) == saved, "equal version and value do not authorize a different retry key")
	// An already completed rollback is benign and must not poison an otherwise healthy authority.
	wanted := errors.New("rejected transaction")
	err = store.transaction(t.Context(), func(tx *gorm.DB) error {
		if err := tx.Rollback().Error; err != nil {
			t.Fatal(err)
		}
		return wanted
	})
	check(errors.Is(err, wanted) && !store.poisoned.Load() && contents(t, store.writeSQL) == saved, "already rolled-back transaction retains the application result")
	requireCommit(t, store, scope, Change{Version: 2, Key: "a", Value: []byte("new")})
}
