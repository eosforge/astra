//go:build linux && cgo

package storage

import (
	"bytes"
	"errors"
	"testing"
)

// verification records hits only after actual decisions; test or cleanup failure invalidates the whole gate observation.
func verification(t *testing.T, contract string) func(bool, string) {
	t.Helper()
	hits := 0
	t.Cleanup(func() {
		if !t.Failed() {
			t.Logf("ASTRA-CONTRACT {\"contract\":%q,\"hits\":%d}", contract, hits)
		}
	})
	return func(ok bool, detail string) {
		t.Helper()
		hits++
		if !ok {
			t.Fatal(detail)
		}
	}
}

// TestVerification emits native hits for four bounded contract examples, without claiming exhaustive state/schedule coverage.
func TestVerification(t *testing.T) {
	t.Run("atomic", func(t *testing.T) {
		store, _, _ := fixture(t, Default())
		check := verification(t, "STORAGE-ATOMIC")
		scope := Scope{"pilot", "atomic"}
		version, err := store.CommitBatch(t.Context(), scope, 1, []Change{{Key: "a", Value: []byte("one")}, {Key: "b", Value: []byte("two")}})
		check(err == nil && version == 1, "batch receipt")
		snapshot, err := store.Load(t.Context(), scope)
		check(err == nil && snapshot.Version == 1, "snapshot version")
		check(len(snapshot.Records) == 2, "snapshot cardinality")
		check(snapshot.Records[0].Key == "a" && bytes.Equal(snapshot.Records[0].Value, []byte("one")), "first record")
		check(snapshot.Records[1].Key == "b" && bytes.Equal(snapshot.Records[1].Value, []byte("two")), "second record")
		replay, err := store.Since(t.Context(), scope, 0)
		check(err == nil && replay.Version == 1 && len(replay.Changes) == 1, "one atomic history entry")
		entries, err := replay.Changes[0].Entries()
		check(err == nil && len(entries) == 2 && entries[0].Key == "a" && entries[1].Key == "b" && bytes.Equal(entries[0].Value, []byte("one")) && bytes.Equal(entries[1].Value, []byte("two")), "complete replay batch")
	})
	t.Run("retry", func(t *testing.T) {
		store, _, _ := fixture(t, Default())
		check := verification(t, "STORAGE-RETRY")
		scope := Scope{"pilot", "retry"}
		changes := []Change{{Key: "a", Value: []byte("original")}}
		version, err := store.CommitBatch(t.Context(), scope, 1, changes)
		check(err == nil && version == 1, "initial commit")
		version, err = store.CommitBatch(t.Context(), scope, 1, changes)
		check(err == nil && version == 1, "identical retry")
		_, err = store.CommitBatch(t.Context(), scope, 1, []Change{{Key: "a", Value: []byte("conflict")}})
		check(errors.Is(err, ErrVersion), "conflicting retry rejected")
		snapshot, err := store.Load(t.Context(), scope)
		check(err == nil && snapshot.Version == 1 && len(snapshot.Records) == 1, "retry retained version")
		check(bytes.Equal(snapshot.Records[0].Value, []byte("original")), "conflict did not overwrite")
		replay, err := store.Since(t.Context(), scope, 0)
		check(err == nil && len(replay.Changes) == 1 && replay.Version == 1, "retry did not duplicate history")
	})
	t.Run("rollback", func(t *testing.T) {
		store, _, _ := fixture(t, Default())
		check := verification(t, "STORAGE-ROLLBACK")
		scope := Scope{"pilot", "rollback"}
		_, err := store.Commit(t.Context(), scope, Change{Version: 1, Key: "a", Value: []byte("old")})
		check(err == nil, "initial commit")
		check(store.write.Exec("CREATE TRIGGER pilot_failure BEFORE INSERT ON records WHEN NEW.key='b' BEGIN SELECT RAISE(ABORT,'pilot'); END").Error == nil, "install SQL fault")
		_, err = store.CommitBatch(t.Context(), scope, 2, []Change{{Key: "a", Value: []byte("new")}, {Key: "b", Value: []byte("new")}})
		check(errors.Is(err, ErrUnavailable), "second write fault reached")
		snapshot, err := store.Load(t.Context(), scope)
		check(err == nil && snapshot.Version == 1 && len(snapshot.Records) == 1 && bytes.Equal(snapshot.Records[0].Value, []byte("old")), "state rolled back")
		replay, err := store.Since(t.Context(), scope, 0)
		check(err == nil && replay.Version == 1 && len(replay.Changes) == 1, "history rolled back")
		check(store.write.Exec("DROP TRIGGER pilot_failure").Error == nil, "remove SQL fault")
		version, err := store.CommitBatch(t.Context(), scope, 2, []Change{{Key: "a", Value: []byte("new")}, {Key: "b", Value: []byte("new")}})
		check(err == nil && version == 2, "recovery commit")
	})
	t.Run("history", func(t *testing.T) {
		limits := Default()
		limits.History = 2
		store, path, binding := fixture(t, limits)
		check := verification(t, "STORAGE-HISTORY")
		scope := Scope{"pilot", "history"}
		for version := Version(1); version <= 3; version++ {
			got, err := store.Commit(t.Context(), scope, Change{Version: version, Key: "k", Value: []byte{byte(version)}})
			check(err == nil && got == version, "ordered commit")
		}
		_, err := store.Since(t.Context(), scope, 0)
		check(errors.Is(err, ErrHistory), "expired cursor rejected")
		replay, err := store.Since(t.Context(), scope, 1)
		check(err == nil && replay.Version == 3 && len(replay.Changes) == 2 && replay.Changes[0].Version == 2 && replay.Changes[1].Version == 3, "contiguous suffix")
		check(store.Close() == nil, "close persisted store")
		reopened, err := Open(t.Context(), path, binding, limits, false)
		check(err == nil, "reopen persisted store")
		t.Cleanup(func() { check(reopened.Close() == nil, "close reopened store") })
		snapshot, err := reopened.Load(t.Context(), scope)
		check(err == nil && snapshot.Version == 3 && len(snapshot.Records) == 1 && bytes.Equal(snapshot.Records[0].Value, []byte{3}), "reopened state")
	})
}
