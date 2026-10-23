//go:build linux && amd64 && cgo

// Inject owned WAL syscalls in isolated children and reconcile atomic state after native SQLite recovery.
package storage

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/mattn/go-sqlite3"
	"golang.org/x/sys/unix"
)

// ioConnection observes real commit errors before the public adapter classifies them.
type ioConnection struct {
	*sqlite3.SQLiteConn            // Real native SQL execution and its context-aware driver interfaces.
	errors              chan error // Exactly one observed native commit result per attempt.
}

// BeginTx preserves the native transaction and attaches a receipt observer.
func (conn *ioConnection) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	tx, err := conn.SQLiteConn.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &ioTx{Tx: tx, errors: conn.errors}, nil
}

// ioTx retains the native cancellation and rollback lifetime.
type ioTx struct {
	driver.Tx              // Native SQLite transaction, enclosed by database/sql cancellation ownership.
	errors    chan<- error // Commit result, delivered before production classifies it.
}

// Commit reports the driver's original error and returns it unchanged.
func (tx *ioTx) Commit() error {
	err := tx.Tx.Commit()
	tx.errors <- err
	return err
}

// ioImage reads public state, history and accounting without terminating the recovery worker.
func ioImage(ctx context.Context, store *Store, scope Scope) (inspection, error) {
	var image inspection
	var err error
	if image.view, err = store.Load(ctx, scope); err != nil {
		return image, err
	}
	if image.history, err = store.Since(ctx, scope, 0); err != nil {
		return image, err
	}
	if err = store.read.Table("scopes").Where("sector=? AND spectrum=?", scope.Sector, scope.Spectrum).Take(&image.group).Error; err != nil {
		return image, err
	}
	err = store.read.Table("meta").Where("id=1").Take(&image.meta).Error
	return image, err
}

// ioHandles selects only this child's writable WAL descriptors, never a host-wide device or unrelated file.
func ioHandles(t *testing.T, path string) []int {
	t.Helper()
	files, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var handles []int
	for _, file := range files {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", file.Name()))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if target != path+"-wal" {
			continue
		}
		handle, err := strconv.Atoi(file.Name())
		if err != nil || handle < 3 {
			t.Fatal("invalid owned WAL descriptor", err)
		}
		flags, err := unix.FcntlInt(uintptr(handle), unix.F_GETFL, 0)
		if err != nil {
			t.Fatal(err)
		}
		if flags&unix.O_ACCMODE == unix.O_RDWR {
			handles = append(handles, handle)
		}
	}
	if len(handles) == 0 || len(handles) > 16 {
		t.Fatal("missing or unexpectedly large native WAL descriptor set", handles)
	}
	return handles
}

// ioFilter returns EIO only for the declared syscalls and WAL descriptors on the calling locked thread.
func ioFilter(t *testing.T, point string, handles []int) {
	t.Helper()
	calls := []uint32{unix.SYS_PWRITE64, unix.SYS_WRITE}
	if point == "sync" {
		calls = []uint32{unix.SYS_FDATASYNC, unix.SYS_FSYNC}
	} else if point != "write" {
		t.Fatal("undeclared native I/O boundary")
	}
	program := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4}, // seccomp_data.arch.
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.AUDIT_ARCH_X86_64, Jt: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
	}
	for _, call := range calls {
		program = append(program,
			unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0}, // Syscall number.
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: call, Jf: uint8(len(handles) + 5)},
			unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 20}, // High word of arg0.
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: 0, Jf: uint8(len(handles) + 1)},
			unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16}, // Low word of arg0.
		)
		for index, handle := range handles {
			program = append(program, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(handle), Jt: uint8(len(handles) - index)})
		}
		program = append(program,
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EIO)},
		)
	}
	program = append(program, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal("cannot establish child-only filter prerequisites", err)
	}
	filter := unix.SockFprog{Len: uint16(len(program)), Filter: &program[0]}
	_, _, failure := syscall.Syscall6(unix.SYS_PRCTL, unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&filter)), 0, 0, 0)
	runtime.KeepAlive(program) // The kernel copies the filter before this synchronous syscall returns.
	if failure != 0 {
		t.Fatal("cannot install owned WAL failure", failure)
	}
}

// ioFailure joins a pre-existing healthy worker before retiring the irreversibly filtered test thread.
func ioFailure(t *testing.T, point, path string) {
	t.Helper()
	if !filepath.IsAbs(path) || filepath.Base(path) != "native.db" {
		t.Fatal("invalid owned I/O fixture")
	}
	check := verification(t, "STORAGE-BOUNDARY")
	ready, done := make(chan struct{}), make(chan struct{})
	requests, replies := make(chan func() error), make(chan error)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(done)
		close(ready)
		for apply := range requests {
			replies <- apply()
		}
	}()
	<-ready
	defer func() { close(requests); <-done }()
	recover := func(apply func() error) error { requests <- apply; return <-replies }
	defer debug.SetGCPercent(debug.SetGCPercent(-1)) // Finalizers cannot conceal missing production Close calls.
	runtime.LockOSThread()
	// Do not unlock: Go destroys this filtered thread when the test goroutine exits.
	binding := Binding{Galaxy: "test", Username: "polaris", Advertise: "127.0.0.1:45101"}
	scope := Scope{"native", "io"}
	store, err := Open(t.Context(), path, binding, Default(), false)
	check(err == nil, "recover the acknowledged baseline")
	defer func() {
		if store != nil {
			check(recover(store.Close) == nil, "close the native fixture on its healthy worker")
		}
	}()
	observed := make(chan error, 1)
	adapt(t, store, func(conn *sqlite3.SQLiteConn) driver.Conn { return &ioConnection{SQLiteConn: conn, errors: observed} })
	before := inspect(t, store, scope)
	check(before.view.Version == 1 && reflect.DeepEqual(before.view.Records, []Record{{Key: "a", Value: []byte("old")}, {Key: "b", Value: []byte("old")}}), "independently anchored two-key baseline")
	check(len(before.history.Changes) == 1 && before.group.Records == 2 && before.group.Bytes == 8 && before.meta.Bytes == 8, "baseline journal and accounting")
	want := before
	want.view.Version = 2
	want.view.Records = []Record{{Key: "a", Value: []byte("new")}, {Key: "b", Value: []byte("new")}}
	want.history.Version = 2
	change := before.history.Changes[0]
	change.Version, change.Value = 2, bytes.ReplaceAll(change.Value, []byte("old"), []byte("new"))
	want.history.Changes = append(append([]Change(nil), before.history.Changes...), change)
	want.group.Version, want.group.Retained = 2, 2
	want.group.Backlog += int64(64 + len(change.Value))
	handles := ioHandles(t, path)
	probe := func(handle int) error {
		if point == "sync" {
			return unix.Fdatasync(handle)
		}
		_, err := unix.Pwrite(handle, nil, 0) // Zero length: the control cannot alter WAL bytes.
		return err
	}
	for _, handle := range handles {
		check(probe(handle) == nil, "native WAL control succeeds before injection")
	}
	decoy, err := os.Create(filepath.Join(filepath.Dir(path), "decoy"))
	check(err == nil, "open a separate owned file to prove descriptor isolation")
	defer decoy.Close()
	changed := store.Changed()
	feed, err := store.Subscribe(4096, 8)
	check(err == nil, "capture the subscription publication boundary")
	defer feed.Close()
	availability := feed.Ready()
	ioFilter(t, point, handles)
	for _, handle := range handles {
		check(errors.Is(probe(handle), unix.EIO), "native WAL control reaches the injected syscall")
		check(recover(func() error { return probe(handle) }) == nil, "pre-existing recovery thread does not inherit the filter")
	}
	check(probe(int(decoy.Fd())) == nil, "unrelated file syscall remains healthy on the filtered thread")
	version, err := store.CommitBatch(t.Context(), scope, 2, []Change{{Key: "a", Value: []byte("new")}, {Key: "b", Value: []byte("new")}})
	check(version == 0 && errors.Is(err, ErrUncertain) && store.poisoned.Load(), "failed native COMMIT exposes no receipt and freezes subsequent writes")
	var native error
	select {
	case native = <-observed:
	default:
		t.Fatal("production did not reach the observed native commit")
	}
	var sqlite sqlite3.Error
	check(errors.As(native, &sqlite) && sqlite.Code == sqlite3.ErrIoErr, "actual SQLite commit reports an I/O error")
	select {
	case <-changed:
		t.Fatal("unacknowledged commit published a change")
	default:
		check(true, "unacknowledged commit preserves the notification boundary")
	}
	select {
	case <-availability:
		t.Fatal("unacknowledged commit published a partial subscription event")
	default:
		check(true, "unacknowledged commit publishes no subscription event")
	}
	check(recover(store.Close) == nil && decoy.Close() == nil, "drain all owned database and control descriptors")
	openingFiles(t, filepath.Dir(path))
	var recovered inspection
	check(recover(func() error {
		var err error
		store, err = Open(t.Context(), path, binding, Default(), false)
		if err != nil {
			return err
		}
		recovered, err = ioImage(t.Context(), store, scope)
		return err
	}) == nil, "recover after the actual native write or sync failure")
	check(reflect.DeepEqual(recovered, before) || reflect.DeepEqual(recovered, want), "recovered state, journal and accounting are wholly old or wholly new")
	check(recover(func() error {
		version, err := store.CommitBatch(t.Context(), scope, 2, []Change{{Key: "a", Value: []byte("new")}, {Key: "b", Value: []byte("new")}})
		if err != nil || version != 2 {
			return fmt.Errorf("recovery retry returned version %d: %w", version, err)
		}
		recovered, err = ioImage(t.Context(), store, scope)
		return err
	}) == nil, "retry the same batch and version on the healthy thread")
	check(reflect.DeepEqual(recovered, want), "retry commits exactly one whole journal entry without duplicate effects")
	check(recover(store.Close) == nil, "close the recovered native store")
	openingFiles(t, filepath.Dir(path))
	fmt.Printf("STORAGE-IO point=%s native_errors=1 uncertain=1 atomic=1 retry=1 retained=0\n", point)
}

// TestNativeIO repeats each WAL boundary in two fresh, bounded and reaped child processes.
func TestNativeIO(t *testing.T) {
	if point := os.Getenv("ASTRA_STORAGE_IO_POINT"); point != "" {
		ioFailure(t, point, os.Getenv("ASTRA_STORAGE_IO_PATH"))
		return
	}
	for _, point := range []string{"write", "sync"} {
		t.Run(point, func(t *testing.T) {
			check := verification(t, "STORAGE-BOUNDARY")
			for range 2 {
				path := filepath.Join(t.TempDir(), "native.db")
				binding := Binding{Galaxy: "test", Username: "polaris", Advertise: "127.0.0.1:45101"}
				store, err := Open(t.Context(), path, binding, Default(), true)
				check(err == nil, "create a fresh private WAL fixture")
				t.Cleanup(func() {
					if store != nil {
						check(store.Close() == nil, "release the parent's store on every exit")
					}
				})
				version, err := store.CommitBatch(t.Context(), Scope{"native", "io"}, 1, []Change{{Key: "a", Value: []byte("old")}, {Key: "b", Value: []byte("old")}})
				check(err == nil && version == 1 && store.Close() == nil, "acknowledge and drain the baseline before child ownership")
				binary, err := os.Executable()
				check(err == nil, "locate the current native binary")
				arguments := []string{"-test.run=^TestNativeIO$", "-test.count=1"}
				if testing.CoverMode() != "" {
					cover := flag.Lookup("test.gocoverdir")
					check(cover != nil && cover.Value.String() != "", "retain the native child coverage directory")
					arguments = append(arguments, "-test.gocoverdir="+cover.Value.String())
				}
				ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
				command := exec.CommandContext(ctx, binary, arguments...)
				command.Env = append(os.Environ(), "ASTRA_STORAGE_IO_POINT="+point, "ASTRA_STORAGE_IO_PATH="+path)
				command.WaitDelay = time.Second
				output, err := command.CombinedOutput()
				deadline := ctx.Err()
				cancel()
				check(err == nil && deadline == nil, "native I/O child completed and was reaped: "+string(output))
				marker := "STORAGE-IO point=" + point + " native_errors=1 uncertain=1 atomic=1 retry=1 retained=0"
				check(strings.Count(string(output), marker) == 1, "observe native SQLite error, atomic recovery, retry and cleanup")
				openingFiles(t, filepath.Dir(path))
				store, err = Open(t.Context(), path, binding, Default(), false)
				check(err == nil, "parent recovery remains unaffected by child-only filters")
				image := inspect(t, store, Scope{"native", "io"})
				check(image.view.Version == 2 && reflect.DeepEqual(image.view.Records, []Record{{Key: "a", Value: []byte("new")}, {Key: "b", Value: []byte("new")}}) && len(image.history.Changes) == 2 && image.group.Records == 2 && image.group.Bytes == 8 && image.meta.Bytes == 8, "parent independently confirms the complete recovered batch")
				check(store.Close() == nil, "parent drains its recovered store")
				openingFiles(t, filepath.Dir(path))
				t.Log(strings.TrimSpace(string(output)))
			}
		})
	}
}
