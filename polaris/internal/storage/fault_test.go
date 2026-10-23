//go:build linux && cgo

// Exercise SQL commit boundaries with reached-fault accounting and complete rollback oracles.
package storage

import (
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"gorm.io/gorm"
)

// TestFault enumerates mutating SQL boundaries, including failure after earlier writes.
// SQLite triggers model statement failure; they do not model power loss or failed fsync.
func TestFault(t *testing.T) {
	points := []struct {
		name, event, table, condition string
		fresh                         bool
	}{
		{"scope-insert", "INSERT", "scopes", "1", true},
		{"record-insert", "INSERT", "records", "NEW.key='b'", false},
		{"record-update", "UPDATE", "records", "NEW.key='b'", false},
		{"record-delete", "DELETE", "records", "OLD.key='c'", false},
		{"history-insert", "INSERT", "history", "1", false},
		{"history-delete", "DELETE", "history", "1", false},
		{"scope-update", "UPDATE", "scopes", "1", false},
		{"meta-update", "UPDATE", "meta", "1", false},
	}
	reached := 0
	for _, point := range points {
		t.Run(point.name, func(t *testing.T) {
			limits := Default()
			limits.History = 1
			store, _, binding := fixture(t, limits)
			check := func(ok bool, detail string) {
				t.Helper()
				if !ok {
					t.Fatal(detail)
				}
			}
			scope := Scope{"fault", "existing"}
			_, err := store.CommitBatch(t.Context(), scope, 1, []Change{{Key: "b", Value: []byte("old")}, {Key: "c", Value: []byte("keep")}})
			check(err == nil, "seed durable records")
			version := Version(2)
			if point.fresh {
				scope.Spectrum = "new"
				version = 1
			}
			before, err := store.Load(t.Context(), scope)
			check(err == nil, "read baseline")
			history, err := store.Since(t.Context(), scope, 0)
			check(err == nil, "read baseline history")
			var meta metadata
			check(store.read.Table("meta").Where("id=1").Take(&meta).Error == nil, "read baseline accounting")
			var hits atomic.Int32
			callback := "assurance:fault"
			check(store.write.Callback().Raw().After("gorm:raw").Register(callback, func(tx *gorm.DB) {
				if tx.Error != nil && strings.Contains(tx.Error.Error(), "assurance-fault") {
					hits.Add(1)
				}
			}) == nil, "install native SQL error observer")
			t.Cleanup(func() { store.write.Callback().Raw().Remove(callback) })
			statement := fmt.Sprintf("CREATE TRIGGER assurance_fault BEFORE %s ON %s WHEN %s BEGIN SELECT RAISE(ABORT,'assurance-fault'); END", point.event, point.table, point.condition)
			check(store.write.Exec(statement).Error == nil, "install declared fault")
			changes := []Change{{Key: "a", Value: []byte("new")}, {Key: "b", Value: []byte("new")}, {Key: "c", Erase: true}}
			_, err = store.CommitBatch(t.Context(), scope, version, changes)
			check(err != nil && hits.Load() == 1, "declared SQL fault must execute exactly once")
			after, err := store.Load(t.Context(), scope)
			check(err == nil && reflect.DeepEqual(before, after), "rollback preserves every record and version")
			replay, err := store.Since(t.Context(), scope, 0)
			check(err == nil && reflect.DeepEqual(history, replay), "rollback preserves complete history")
			var actual metadata
			check(store.read.Table("meta").Where("id=1").Take(&actual).Error == nil && reflect.DeepEqual(meta, actual), "rollback preserves global accounting")
			check(store.write.Exec("DROP TRIGGER assurance_fault").Error == nil, "remove reached fault")
			check(store.validate(t.Context(), binding) == nil, "all durable invariants survive rollback")
			got, err := store.CommitBatch(t.Context(), scope, version, changes)
			check(err == nil && got == version && hits.Load() == 1, "same operation recovers without repeating the fault")
			check(store.validate(t.Context(), binding) == nil, "all durable invariants survive recovery")
			t.Logf("fault-point=%s injected=1 reached=%d rollback=verified recovery=verified", point.name, hits.Load())
			reached++
		})
	}
	check := verification(t, "STORAGE-FAULT")
	check(reached == 8, "all eight declared fault boundaries must reach rollback and recovery")
}
