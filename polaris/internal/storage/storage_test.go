//go:build linux && cgo

package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
)

// fixture creates independent database/lock files per case, without shared ports, global databases, or external services.
func fixture(t *testing.T, limits Limits) (*Store, string, Binding) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "polaris.db")
	binding := Binding{Galaxy: "test", Username: "polaris", Advertise: "127.0.0.1:45101"}
	store, err := Open(t.Context(), path, binding, limits, true)
	if err != nil {
		t.Fatal(err)
	}
	// These component fixtures control SQL boundaries directly. Public maintenance tests keep the owned task running.
	store.cancel()
	<-store.done
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store, path, binding
}

// TestDatabasePath rejects aliases bypassing path-based exclusivity while preserving the original database's active connection.
func TestDatabasePath(t *testing.T) {
	t.Parallel()
	original, path, binding := fixture(t, Default())
	alias := filepath.Join(t.TempDir(), "alias.db")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(t.Context(), alias, binding, Default(), false)
	if opened != nil {
		opened.Close()
		t.Fatal("database symlink unexpectedly accepted")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatal("database symlink did not fail before SQLite access", err)
	}
	if _, err := original.Load(t.Context(), Scope{"routes", "main"}); err != nil {
		t.Fatal("rejected alias changed the original database", err)
	}
}

// requireCommit checks the durable receipt version, not nil error alone.
func requireCommit(t *testing.T, store *Store, scope Scope, change Change) {
	t.Helper()
	version, err := store.Commit(t.Context(), scope, change)
	if err != nil || version != change.Version {
		t.Fatalf("commit version=%d error=%v", version, err)
	}
}

// TestCommit covers new Scopes, empty values, no-op commits, retained replay evidence, and content conflicts.
func TestCommit(t *testing.T) {
	t.Parallel()
	store, _, _ := fixture(t, Default())
	scope := Scope{"routes", "main"}
	before := store.Changed()
	snapshot, err := store.Load(t.Context(), scope)
	if err != nil || snapshot.Version != 0 || len(snapshot.Records) != 0 {
		t.Fatal(snapshot, err)
	}
	positions, err := store.List(t.Context())
	if err != nil || len(positions) != 0 {
		t.Fatal(positions, err)
	}
	requireCommit(t, store, scope, Change{Version: 1, Key: "empty"})
	select {
	case <-before:
	default:
		t.Fatal("commit did not notify")
	}
	snapshot, err = store.Load(t.Context(), scope)
	if err != nil || snapshot.Version != 1 || len(snapshot.Records) != 1 || snapshot.Records[0].Value == nil || len(snapshot.Records[0].Value) != 0 {
		t.Fatal(snapshot, err)
	}
	before = store.Changed()
	requireCommit(t, store, scope, Change{Version: 1, Key: "empty", Value: []byte{}})
	select {
	case <-before:
		t.Fatal("retry notified as new commit")
	default:
	}
	if _, err = store.Commit(t.Context(), scope, Change{Version: 1, Key: "empty", Erase: true}); !errors.Is(err, ErrVersion) {
		t.Fatal(err)
	}
	requireCommit(t, store, scope, Change{Version: 2, Key: "empty"})
	requireCommit(t, store, scope, Change{Version: 3, Key: "missing", Erase: true})
	requireCommit(t, store, scope, Change{Version: 4, Key: "empty", Erase: true})
	snapshot, err = store.Load(t.Context(), scope)
	if err != nil || snapshot.Version != 4 || len(snapshot.Records) != 0 {
		t.Fatal(snapshot, err)
	}
	replay, err := store.Since(t.Context(), scope, 0)
	if err != nil || replay.Version != 4 || len(replay.Changes) != 4 || !replay.Changes[3].Erase {
		t.Fatal(replay, err)
	}
	// The same Key in another Scope still starts at version one.
	requireCommit(t, store, Scope{"routes", "other"}, Change{Version: 1, Key: "empty", Value: []byte{7}})
}

// TestHistory checks finite windows, oversized entries, zero budget, and later continuous suffix recovery.
func TestHistory(t *testing.T) {
	for _, mode := range []string{"count", "bytes", "zero"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			limits := Default()
			limits.History = 2
			if mode == "bytes" {
				limits.Backlog = 66
			}
			if mode == "zero" {
				limits.History = 0
			}
			store, _, _ := fixture(t, limits)
			scope := Scope{"s", "p"}
			for version := Version(1); version <= 3; version++ {
				requireCommit(t, store, scope, Change{Version: version, Key: "k", Value: []byte{byte(version)}})
			}
			if _, err := store.Since(t.Context(), scope, 0); !errors.Is(err, ErrHistory) {
				t.Fatal(err)
			}
			if _, err := store.Commit(t.Context(), scope, Change{Version: 1, Key: "k", Value: []byte{1}}); !errors.Is(err, ErrUncertain) {
				t.Fatal(err)
			}
			if replay, err := store.Since(t.Context(), scope, 3); err != nil || len(replay.Changes) != 0 {
				t.Fatal(replay, err)
			}
			if _, err := store.Since(t.Context(), scope, 4); !errors.Is(err, ErrVersion) {
				t.Fatal(err)
			}
			if mode == "bytes" {
				requireCommit(t, store, scope, Change{Version: 4, Key: "k", Value: make([]byte, 512<<10)})
				if _, err := store.Since(t.Context(), scope, 3); !errors.Is(err, ErrHistory) {
					t.Fatal(err)
				}
				requireCommit(t, store, scope, Change{Version: 5, Key: "k", Value: []byte{5}})
				if replay, err := store.Since(t.Context(), scope, 4); err != nil || len(replay.Changes) != 1 || replay.Changes[0].Version != 5 {
					t.Fatal(replay, err)
				}
			}
		})
	}
}

// TestHistoryPrefix trims only the necessary continuous prefix across count/byte limits, multiple evictions, and Scope isolation.
func TestHistoryPrefix(t *testing.T) {
	t.Parallel()
	limits := Default()
	limits.History, limits.Backlog = 4, 450
	store, _, _ := fixture(t, limits)
	scope := Scope{"s", "p"}
	other := Scope{"s", "other"}
	requireCommit(t, store, other, Change{Version: 1, Key: "k", Value: []byte{9}})
	for version := Version(1); version <= 4; version++ {
		requireCommit(t, store, scope, Change{Version: version, Key: "k", Value: []byte{byte(version)}})
	}
	// Entry cost 315 and total 579; evicting two 66-byte prefix entries leaves 447, not empty history.
	requireCommit(t, store, scope, Change{Version: 5, Key: "k", Value: make([]byte, 250)})
	for _, boundary := range []struct {
		since Version
		last  Version
	}{{2, 5}, {3, 6}} {
		if boundary.last == 6 {
			requireCommit(t, store, scope, Change{Version: 6, Key: "k", Value: []byte{6}})
		}
		if _, err := store.Since(t.Context(), scope, boundary.since-1); !errors.Is(err, ErrHistory) {
			t.Fatal("evicted prefix accepted", err)
		}
		replay, err := store.Since(t.Context(), scope, boundary.since)
		if err != nil || len(replay.Changes) != 3 {
			t.Fatal("retained suffix lost", replay, err)
		}
		for index, change := range replay.Changes {
			if change.Version != boundary.since+Version(index)+1 {
				t.Fatal("retained suffix is not continuous", replay)
			}
		}
	}
	if replay, err := store.Since(t.Context(), other, 0); err != nil || len(replay.Changes) != 1 || replay.Changes[0].Version != 1 {
		t.Fatal("other scope history changed", replay, err)
	}
}

// TestRestart checks binding, exclusivity, explicit initialization, durable versions, and old-request confirmation after restart.
func TestRestart(t *testing.T) {
	t.Parallel()
	store, path, binding := fixture(t, Default())
	scope := Scope{"__auth", "comet"}
	change := Change{Version: 1, Key: "key", Value: []byte{1, 2}}
	requireCommit(t, store, scope, change)
	if duplicate, err := Open(t.Context(), path, binding, Default(), false); err == nil {
		duplicate.Close()
		t.Fatal("second owner accepted")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if duplicate, err := Open(t.Context(), path, binding, Default(), true); err == nil {
		duplicate.Close()
		t.Fatal("existing database overwritten")
	}
	wrong := binding
	wrong.Username = "other"
	if duplicate, err := Open(t.Context(), path, wrong, Default(), false); !errors.Is(err, ErrBinding) {
		if duplicate != nil {
			duplicate.Close()
		}
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), path, binding, Default(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	requireCommit(t, reopened, scope, change)
	snapshot, err := reopened.Load(t.Context(), scope)
	if err != nil || snapshot.Version != 1 || len(snapshot.Records) != 1 || !bytes.Equal(snapshot.Records[0].Value, change.Value) {
		t.Fatal(snapshot, err)
	}
}

// TestAtomicity injects SQL failure after record write but before history; observers must retain complete old state.
func TestAtomicity(t *testing.T) {
	t.Parallel()
	store, _, _ := fixture(t, Default())
	scope := Scope{"s", "p"}
	requireCommit(t, store, scope, Change{Version: 1, Key: "k", Value: []byte{1}})
	if err := store.write.Exec("CREATE TRIGGER fail_history BEFORE INSERT ON history BEGIN SELECT RAISE(ABORT,'injected'); END").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(t.Context(), scope, Change{Version: 2, Key: "k", Value: []byte{2}}); err == nil {
		t.Fatal("failed transaction succeeded")
	}
	snapshot, err := store.Load(t.Context(), scope)
	if err != nil || snapshot.Version != 1 || !bytes.Equal(snapshot.Records[0].Value, []byte{1}) {
		t.Fatal(snapshot, err)
	}
	if replay, err := store.Since(t.Context(), scope, 0); err != nil || len(replay.Changes) != 1 {
		t.Fatal(replay, err)
	}
	if err := store.write.Exec("DROP TRIGGER fail_history").Error; err != nil {
		t.Fatal(err)
	}
	requireCommit(t, store, scope, Change{Version: 2, Key: "k", Value: []byte{2}})
}

// TestUncertain triggers COMMIT failure through deferred foreign keys; unknown outcomes cannot seed the next write baseline.
func TestUncertain(t *testing.T) {
	t.Parallel()
	store, _, _ := fixture(t, Default())
	err := store.transaction(t.Context(), func(tx *gorm.DB) error {
		if err := tx.Exec("PRAGMA defer_foreign_keys=ON").Error; err != nil {
			return err
		}
		return tx.Exec("INSERT INTO records VALUES('missing','scope','key',X'01')").Error
	})
	if !errors.Is(err, ErrUncertain) || !store.poisoned.Load() {
		t.Fatal(err)
	}
	if _, err = store.Commit(t.Context(), Scope{"s", "p"}, Change{Version: 1, Key: "k"}); !errors.Is(err, ErrUncertain) {
		t.Fatal(err)
	}
}

// TestVersion checks high-version byte order and invalid SQL types without signed or float conversion.
func TestVersion(t *testing.T) {
	for _, input := range []uint64{0, 1, 1<<63 - 1, 1 << 63, math.MaxUint64} {
		var version Version
		if err := version.Scan(binary.BigEndian.AppendUint64(nil, input)); err != nil || uint64(version) != input {
			t.Fatal(version, err)
		}
		value, err := version.Value()
		if err != nil || !bytes.Equal(value.([]byte), binary.BigEndian.AppendUint64(nil, input)) {
			t.Fatal(value, err)
		}
	}
	for _, input := range []any{nil, int64(1), "00000000", []byte{1}, make([]byte, 9)} {
		version := Version(9)
		if err := version.Scan(input); !errors.Is(err, ErrCorrupt) || version != 9 {
			t.Fatal(version, err)
		}
	}
}

// TestExhaustion preserves the full uint64 boundary through commits, retries, rejection and native reopen.
func TestExhaustion(t *testing.T) {
	t.Parallel()
	check := verification(t, "STORAGE-RETRY")
	store, path, binding := fixture(t, Default())
	scope := Scope{"s", "p"}
	requireCommit(t, store, scope, Change{Version: 1, Key: "absent", Erase: true})
	if err := store.write.Exec("DELETE FROM history").Error; err != nil {
		t.Fatal(err)
	}
	if err := store.write.Exec("UPDATE scopes SET version=?,retained=0,backlog=0", Version(math.MaxUint64-1)).Error; err != nil {
		t.Fatal(err)
	}
	requireCommit(t, store, scope, Change{Version: Version(math.MaxUint64), Key: "k", Value: []byte{1}})
	before, changed := contents(t, store.writeSQL), store.Changed()
	for range 2 {
		version, err := store.Commit(t.Context(), scope, Change{Version: Version(math.MaxUint64), Key: "k", Value: []byte{1}})
		check(err == nil && version == Version(math.MaxUint64), "maximum-version identical retry")
		version, err = store.Commit(t.Context(), scope, Change{Version: Version(math.MaxUint64), Key: "k", Value: []byte{2}})
		check(errors.Is(err, ErrVersion) && version == 0, "maximum-version conflicting retry")
		version, err = store.Commit(t.Context(), scope, Change{Version: 0, Key: "k"})
		check(errors.Is(err, ErrInput) && version == 0, "wrapped version rejected")
		version, err = store.Commit(t.Context(), scope, Change{Version: 1, Key: "absent", Erase: true})
		check(errors.Is(err, ErrUncertain) && version == 0, "evicted older receipt remains unknown")
	}
	check(contents(t, store.writeSQL) == before && store.Changed() == changed, "maximum retries preserve durable state and notifications")
	check(store.Close() == nil, "maximum-version native close")
	reopened, err := Open(t.Context(), path, binding, Default(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	snapshot, err := reopened.Load(t.Context(), scope)
	check(err == nil && snapshot.Version == Version(math.MaxUint64) && len(snapshot.Records) == 1 && snapshot.Records[0].Key == "k" && bytes.Equal(snapshot.Records[0].Value, []byte{1}), "maximum-version complete reopened snapshot")
}

// TestLimits checks inputs, Scope capacity, and unchanged version on failure; Delete returns active capacity.
func TestLimits(t *testing.T) {
	t.Parallel()
	limits := Default()
	limits.Scopes, limits.Records, limits.Bytes, limits.Total = 1, 1, 2, 2
	store, _, _ := fixture(t, limits)
	scope := Scope{"s", "p"}
	requireCommit(t, store, scope, Change{Version: 1, Key: "k", Value: []byte{1}})
	for _, change := range []Change{{Version: 2, Key: "k", Value: []byte{1, 2}}, {Version: 2, Key: "x"}} {
		if _, err := store.Commit(t.Context(), scope, change); !errors.Is(err, ErrCapacity) {
			t.Fatal(err)
		}
	}
	if _, err := store.Commit(t.Context(), Scope{"s", "new"}, Change{Version: 1, Key: "k"}); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	for _, change := range []Change{{Version: 0, Key: "k"}, {Version: 2, Key: ""}, {Version: 2, Key: "\xff"}, {Version: 2, Key: "a\x00b"}, {Version: 2, Key: "k", Value: make([]byte, 1<<20+1)}, {Version: 2, Key: "k", Erase: true, Value: []byte{1}}} {
		if _, err := store.Commit(t.Context(), scope, change); !errors.Is(err, ErrInput) {
			t.Fatal(err)
		}
	}
	requireCommit(t, store, scope, Change{Version: 2, Key: "k", Erase: true})
	requireCommit(t, store, scope, Change{Version: 3, Key: "x", Value: []byte{3}})
}

// TestCancellation cancels write-permit waiting without sleeps to create random races.
func TestCancellation(t *testing.T) {
	t.Parallel()
	store, _, _ := fixture(t, Default())
	store.writer <- struct{}{}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.Commit(ctx, Scope{"s", "p"}, Change{Version: 1, Key: "k"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	<-store.writer
	requireCommit(t, store, Scope{"s", "p"}, Change{Version: 1, Key: "k"})
	store.Close()
	if _, err := store.Load(t.Context(), Scope{"s", "p"}); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

// TestConcurrent permits at most one differing payload at one expected version; snapshots/replay match the winner.
func TestConcurrent(t *testing.T) {
	t.Parallel()
	store, _, _ := fixture(t, Default())
	scope := Scope{"s", "p"}
	var work sync.WaitGroup
	results := make(chan error, 16)
	for index := range 16 {
		work.Go(func() {
			_, err := store.Commit(t.Context(), scope, Change{Version: 1, Key: "k", Value: []byte{byte(index)}})
			results <- err
		})
	}
	work.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrVersion) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal("successful writers", success)
	}
	snapshot, err := store.Load(t.Context(), scope)
	if err != nil || snapshot.Version != 1 || len(snapshot.Records) != 1 {
		t.Fatal(snapshot, err)
	}
}

// TestInvalidDatabase rejects missing storage, unknown formats, and invalid bindings without creating or clearing authority data.
func TestInvalidDatabase(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "absent.db")
	binding := Binding{"g", "p", "127.0.0.1:45102"}
	if store, err := Open(t.Context(), path, binding, Default(), false); err == nil {
		store.Close()
		t.Fatal("missing database accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("missing database created", err)
	}
	if err := os.WriteFile(path, []byte("not a sqlite database"), 0600); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(t.Context(), path, binding, Default(), false); err == nil {
		store.Close()
		t.Fatal("invalid database accepted")
	}
	limits := Default()
	limits.Timeout = 31 * time.Second
	if store, err := Open(t.Context(), path, binding, limits, false); !errors.Is(err, ErrInput) {
		if store != nil {
			store.Close()
		}
		t.Fatal(err)
	}
}
