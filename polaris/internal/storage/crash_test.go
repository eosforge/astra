//go:build linux && cgo

// Verify database recovery after owned process death at reached SQL and commit boundaries.
package storage

import (
	"bufio"
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
	"gorm.io/gorm"
)

// crash owns a child-only transaction probe; SQL and finalization still run in SQLite.
type crash struct {
	point string   // Declared boundary: prefix, prepared or durable.
	ready *os.File // Parent observes a boundary before sending SIGKILL.
	hold  *os.File // Parent lifetime pipe; no business-time sleep.
}

// crashConnection attaches the owned process-death point to a real native transaction.
type crashConnection struct {
	*sqlite3.SQLiteConn        // Unchanged native statement execution and context interfaces.
	probe               *crash // Parent synchronization, scoped to this child only.
}

// park reports the reached boundary and keeps the child alive until death or parent loss.
func (probe *crash) park() error {
	if _, err := fmt.Fprintln(probe.ready, probe.point); err != nil {
		return err
	}
	var signal [1]byte
	_, err := io.ReadFull(probe.hold, signal[:])
	return fmt.Errorf("crash probe released instead of killed: %w", err)
}

// BeginTx wraps the native transaction without replacing statement execution.
func (conn *crashConnection) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	tx, err := conn.SQLiteConn.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &crashing{Tx: tx, probe: conn.probe}, nil
}

// crashing intercepts only the transaction finalization boundary in the owned child.
type crashing struct {
	driver.Tx        // Real SQLite transaction, enclosed by database/sql cancellation ownership.
	probe     *crash // Parent synchronization and selected boundary.
}

// Commit parks before native COMMIT or after its successful durable return, before the receipt.
func (tx *crashing) Commit() error {
	if tx.probe.point == "prepared" {
		return tx.probe.park()
	}
	if err := tx.Tx.Commit(); err != nil {
		return err
	}
	if tx.probe.point == "durable" {
		return tx.probe.park()
	}
	return nil
}

// crashChanges includes insert, update and erase in one version with independently known values.
func crashChanges() []Change {
	return []Change{{Key: "a", Value: bytes.Repeat([]byte("a"), 64<<10)}, {Key: "b", Value: bytes.Repeat([]byte("b"), 64<<10)}, {Key: "c", Erase: true}}
}

// crashChild reopens the parent's database and cannot acknowledge a reached probe normally.
func crashChild(t *testing.T, path, point string) {
	t.Helper()
	store, err := Open(t.Context(), path, Binding{Galaxy: "test", Username: "polaris", Advertise: "127.0.0.1:45101"}, Default(), false)
	if err != nil {
		t.Fatal("child reopen", err)
	}
	defer store.Close()
	probe := &crash{point: point, ready: os.NewFile(3, "ready"), hold: os.NewFile(4, "hold")}
	defer probe.ready.Close()
	defer probe.hold.Close()
	adapt(t, store, func(conn *sqlite3.SQLiteConn) driver.Conn { return &crashConnection{SQLiteConn: conn, probe: probe} })
	if point == "prefix" {
		if err := store.write.Callback().Raw().After("gorm:raw").Register("assurance:crash", func(tx *gorm.DB) {
			if tx.Error == nil && strings.HasPrefix(tx.Statement.SQL.String(), "INSERT INTO records") && len(tx.Statement.Vars) > 2 && tx.Statement.Vars[2] == "a" {
				tx.AddError(probe.park())
			}
		}); err != nil {
			t.Fatal("install reached SQL probe", err)
		}
	}
	version, err := store.CommitBatch(t.Context(), Scope{"crash", "batch"}, 2, crashChanges())
	t.Fatalf("child escaped crash boundary: version=%d error=%v", version, err)
}

// TestCrash validates process death, not power loss, storage-device failure or torn-sector recovery.
func TestCrash(t *testing.T) {
	if path := os.Getenv("ASTRA_STORAGE_CRASH_PATH"); path != "" {
		crashChild(t, path, os.Getenv("ASTRA_STORAGE_CRASH_POINT"))
		return
	}
	completed := 0
	for _, point := range []string{"prefix", "prepared", "durable"} {
		t.Run(point, func(t *testing.T) {
			store, path, binding := fixture(t, Default())
			scope := Scope{"crash", "batch"}
			version, err := store.CommitBatch(t.Context(), scope, 1, []Change{{Key: "b", Value: []byte("old")}, {Key: "c", Value: []byte("keep")}})
			if err != nil || version != 1 {
				t.Fatal("seed crash baseline", err)
			}
			before := inspect(t, store, scope)
			if err := store.Close(); err != nil {
				t.Fatal("release database to child", err)
			}
			ready, report, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer ready.Close()
			defer report.Close()
			hold, release, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer hold.Close()
			defer release.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCrash$", "-test.timeout=12s")
			command.Env = append(os.Environ(), "ASTRA_STORAGE_CRASH_PATH="+path, "ASTRA_STORAGE_CRASH_POINT="+point)
			command.ExtraFiles = []*os.File{report, hold}
			command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
			var output bytes.Buffer
			command.Stdout, command.Stderr = &output, &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				if !waited {
					_ = command.Process.Kill()
					_ = command.Wait()
				}
			}()
			// Drop parent's copies so child exit closes the readiness pipe, including watchdog failure.
			report.Close()
			hold.Close()
			line, err := bufio.NewReader(ready).ReadString('\n')
			if err != nil || line != point+"\n" {
				_ = command.Process.Kill()
				_ = command.Wait()
				waited = true
				t.Fatalf("boundary not reached: %q %v; child: %s", line, err, output.String())
			}
			// The direct unreaped child cannot have its PID recycled; Kill targets only this test owner.
			if err := command.Process.Kill(); err != nil {
				t.Fatal("kill reached child", err)
			}
			err = command.Wait()
			waited = true
			var ended *exec.ExitError
			if !errors.As(err, &ended) || !ended.ProcessState.Sys().(syscall.WaitStatus).Signaled() || ended.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL || ctx.Err() != nil {
				t.Fatalf("expected owned SIGKILL before watchdog: %v; child: %s", err, output.String())
			}
			store, err = Open(t.Context(), path, binding, Default(), false)
			if err != nil {
				t.Fatal("recover after process death", err)
			}
			t.Cleanup(func() {
				if err := store.Close(); err != nil {
					t.Error("close recovered store", err)
				}
			})
			after := inspect(t, store, scope)
			changes := crashChanges()
			if point != "durable" {
				if !reflect.DeepEqual(before, after) {
					t.Fatal("process death exposed a partial uncommitted batch")
				}
			} else {
				if after.view.Version != 2 || len(after.view.Records) != 2 || after.history.Version != 2 || len(after.history.Changes) != 2 {
					t.Fatal("successful native COMMIT lost its complete snapshot or history")
				}
				for index, key := range []string{"a", "b"} {
					if after.view.Records[index].Key != key || !bytes.Equal(after.view.Records[index].Value, changes[index].Value) {
						t.Fatal("recovered durable values differ from the submitted batch")
					}
				}
				entries, err := after.history.Changes[1].Entries()
				if err != nil || len(entries) != len(changes) || after.group.Bytes != 2*((64<<10)+1) || after.meta.Bytes != after.group.Bytes || after.group.Records != 2 {
					t.Fatal("recovered history or accounting differs from the complete batch")
				}
				for index, entry := range entries {
					if entry.Version != 2 || entry.Key != changes[index].Key || entry.Erase != changes[index].Erase || !bytes.Equal(entry.Value, changes[index].Value) {
						t.Fatal("recovered journal must preserve every action and its shared version")
					}
				}
			}
			feed, err := store.Subscribe(1<<20, 8)
			if err != nil {
				t.Fatal(err)
			}
			defer feed.Close()
			version, err = store.CommitBatch(t.Context(), scope, 2, changes)
			if err != nil || version != 2 {
				t.Fatal("retry must confirm or commit exactly one version", err)
			}
			events, err := feed.Take()
			want := 1
			if point == "durable" {
				want = 0
			}
			if err != nil || len(events) != want || point == "durable" && !reflect.DeepEqual(after, inspect(t, store, scope)) {
				t.Fatal("recovery retry duplicated or omitted publication", err)
			}
			version, err = store.Commit(t.Context(), scope, Change{Version: 3, Key: "next", Value: []byte("healthy")})
			if err != nil || version != 3 || store.validate(t.Context(), binding) != nil || store.readSQL.Stats().InUse != 0 || store.writeSQL.Stats().InUse != 0 || len(store.writer) != 0 {
				t.Fatal("recovered store cannot continue or leaked owned SQL resources", err)
			}
			t.Logf("crash-point=%s reached=1 signal=SIGKILL reaped=1 recovery=verified retry=verified", point)
			completed++
		})
	}
	verification(t, "STORAGE-CRASH")(completed == 3, "all declared process-death boundaries reached, recovered and continued")
}
