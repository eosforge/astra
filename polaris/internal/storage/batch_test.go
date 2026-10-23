//go:build linux && cgo

package storage

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// TestBatchEncoding rejects truncation, length overflow, and trailing bytes without accepting partial history.
func TestBatchEncoding(t *testing.T) {
	valid := []byte{'A', 'B', '0', '2', 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 'k'}
	entries, err := (Change{Version: 7, Value: valid}).Entries()
	if err != nil || len(entries) != 1 || entries[0].Key != "k" || entries[0].Version != 7 || entries[0].Erase {
		t.Fatalf("empty value: %+v %v", entries, err)
	}
	for length := range len(valid) {
		if _, err := (Change{Value: valid[:length]}).Entries(); !errors.Is(err, ErrInput) {
			t.Fatalf("truncated at %d: %v", length, err)
		}
	}
	malformed := [][]byte{
		{'A', 'B', '0', '2', 255, 255, 255, 255, 255, 255, 255, 255},
		append(bytes.Clone(valid), 0),
		{'A', 'B', '0', '2', 0, 0, 0, 0, 0, 0, 0, 0},
		{'A', 'B', '0', '2', 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 255, 255, 255, 255, 0, 'k'},
		{'A', 'B', '0', '2', 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 'k', 'v'},
	}
	for _, data := range malformed {
		if _, err := (Change{Value: data}).Entries(); !errors.Is(err, ErrInput) {
			t.Fatalf("malformed encoding accepted: %v", err)
		}
	}
}

// TestBatchPersistence checks one version across Keys, complete retry evidence, mixed deletion, and restart recovery.
func TestBatchPersistence(t *testing.T) {
	store, path, binding := fixture(t, Default())
	scope := Scope{Sector: "batch", Spectrum: "scope"}
	changes := []Change{{Key: "a", Value: []byte("a")}, {Key: "b", Value: []byte{}}}
	if version, err := store.CommitBatch(t.Context(), scope, 1, changes); err != nil || version != 1 {
		t.Fatalf("commit: %v %v", version, err)
	}
	if version, err := store.CommitBatch(t.Context(), scope, 1, changes); err != nil || version != 1 {
		t.Fatalf("repeat: %v %v", version, err)
	}
	changes[1].Value = []byte("conflict")
	if _, err := store.CommitBatch(t.Context(), scope, 1, changes); !errors.Is(err, ErrVersion) {
		t.Fatalf("conflict: %v", err)
	}
	if _, err := store.CommitBatch(t.Context(), scope, 2, []Change{{Key: "a", Erase: true}, {Key: "c", Value: []byte("c")}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), path, binding, Default(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	snapshot, err := reopened.Load(t.Context(), scope)
	if err != nil || snapshot.Version != 2 || len(snapshot.Records) != 2 || snapshot.Records[0].Key != "b" || snapshot.Records[1].Key != "c" {
		t.Fatalf("snapshot: %+v %v", snapshot, err)
	}
	replay, err := reopened.Since(t.Context(), scope, 0)
	if err != nil || len(replay.Changes) != 2 {
		t.Fatalf("replay: %+v %v", replay, err)
	}
	for _, change := range replay.Changes {
		entries, err := change.Entries()
		if err != nil || len(entries) != 2 {
			t.Fatalf("partial batch: %v %v", entries, err)
		}
	}
}

// TestBatchRollback fails the second SQL statement and verifies first write, version, and history all roll back.
func TestBatchRollback(t *testing.T) {
	store, _, _ := fixture(t, Default())
	scope := Scope{Sector: "batch", Spectrum: "rollback"}
	if _, err := store.Commit(t.Context(), scope, Change{Version: 1, Key: "a", Value: []byte("old")}); err != nil {
		t.Fatal(err)
	}
	if err := store.write.Exec("CREATE TRIGGER batch_failure BEFORE INSERT ON records WHEN NEW.key='b' BEGIN SELECT RAISE(ABORT,'injected'); END").Error; err != nil {
		t.Fatal(err)
	}
	_, err := store.CommitBatch(t.Context(), scope, 2, []Change{{Key: "a", Value: []byte("new")}, {Key: "b", Value: []byte("new")}})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected SQL refusal: %v", err)
	}
	if err := store.write.Exec("DROP TRIGGER batch_failure").Error; err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Load(t.Context(), scope)
	if err != nil || snapshot.Version != 1 || len(snapshot.Records) != 1 || !bytes.Equal(snapshot.Records[0].Value, []byte("old")) {
		t.Fatalf("partial state: %+v %v", snapshot, err)
	}
	replay, err := store.Since(t.Context(), scope, 0)
	if err != nil || len(replay.Changes) != 1 {
		t.Fatalf("partial history: %+v %v", replay, err)
	}
	if _, err := store.CommitBatch(t.Context(), scope, 2, []Change{{Key: "a"}, {Key: "a"}}); !errors.Is(err, ErrInput) {
		t.Fatalf("duplicate: %v", err)
	}
}

// TestBatchSnapshot requires concurrent SQLite reads to capture a complete batch, without relying on single-connection serialization.
func TestBatchSnapshot(t *testing.T) {
	store, _, _ := fixture(t, Default())
	scope := Scope{Sector: "batch", Spectrum: "concurrent"}
	write := func(version Version) error {
		_, err := store.CommitBatch(t.Context(), scope, version, []Change{{Key: "a", Value: []byte{byte(version)}}, {Key: "b", Value: []byte{byte(version)}}})
		return err
	}
	if err := write(1); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		defer close(finished)
		for version := Version(2); version <= 64; version++ {
			if err := write(version); err != nil {
				finished <- err
				return
			}
		}
		finished <- nil
	}()
	defer func() { <-finished }() // Failure paths still await writers before fixture destruction.
	for {
		snapshot, err := store.Load(t.Context(), scope)
		if err != nil || len(snapshot.Records) != 2 {
			t.Fatalf("snapshot: %+v %v", snapshot, err)
		}
		for _, record := range snapshot.Records {
			if !bytes.Equal(record.Value, []byte{byte(snapshot.Version)}) {
				t.Fatalf("mixed snapshot: %+v", snapshot)
			}
		}
		select {
		case err := <-finished:
			if err != nil {
				t.Fatal(err)
			}
			return
		default:
		}
	}
}

// TestLargeBatchPersistence commits batches beyond former count/size/SQLite-row limits once and reloads complete history.
func TestLargeBatchPersistence(t *testing.T) {
	store, path, binding := fixture(t, Default())
	scope := Scope{Sector: "large", Spectrum: "batch"}
	changes := make([]Change, 257)
	for index := range changes {
		changes[index] = Change{Key: fmt.Sprint(index), Value: bytes.Repeat([]byte{byte(index)}, 8192)}
	}
	if version, err := store.CommitBatch(t.Context(), scope, 1, changes); err != nil || version != 1 {
		t.Fatalf("large commit: %v %v", version, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), path, binding, Default(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	snapshot, err := reopened.Load(t.Context(), scope)
	if err != nil || snapshot.Version != 1 || len(snapshot.Records) != len(changes) {
		t.Fatalf("incomplete snapshot: %v", err)
	}
	replay, err := reopened.Since(t.Context(), scope, 0)
	if err != nil || len(replay.Changes) != 1 {
		t.Fatalf("incomplete history: %v", err)
	}
	entries, err := replay.Changes[0].Entries()
	if err != nil || len(entries) != len(changes) {
		t.Fatalf("incomplete batch: %v", err)
	}
	for index, entry := range entries {
		if entry.Key != changes[index].Key || !bytes.Equal(entry.Value, changes[index].Value) {
			t.Fatal("history content changed")
		}
	}
	if version, err := reopened.CommitBatch(t.Context(), scope, 1, changes); err != nil || version != 1 {
		t.Fatalf("large repeat: %v %v", version, err)
	}
}
