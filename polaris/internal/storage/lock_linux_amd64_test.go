//go:build linux && amd64 && cgo

// Inject a thread-local native metadata failure and verify lock acquisition cleanup in an owned child.
package storage

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// lockHandles counts only this fixture's native lock descriptors; unrelated runtime descriptors are outside its ownership.
func lockHandles(t *testing.T, path string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue // The directory iterator's own descriptor has already closed.
		}
		if err != nil {
			t.Fatal(err)
		}
		if target == path+".lock" {
			count++
		}
	}
	return count
}

// lockFailure confines irreversible seccomp state to one locked thread in a disposable test child.
func lockFailure(t *testing.T, path string) {
	t.Helper()
	if !filepath.IsAbs(path) || filepath.Clean(path) == string(os.PathSeparator) {
		t.Fatal("invalid owned lock path")
	}
	probe, err := lock(path)
	if err != nil {
		t.Fatal("healthy native lock failed", err)
	}
	if info, err := probe.Stat(); err != nil || !info.Mode().IsRegular() {
		t.Fatal("healthy descriptor is not a regular file", err)
	}
	if err := probe.Close(); err != nil || lockHandles(t, path) != 0 {
		t.Fatal("healthy lock did not release its descriptor", err)
	}

	ready, requests, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	replies := make(chan error, 1)
	go func() {
		// Start and pin the recovery thread before installing any filter; it cannot inherit the injected failure.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(done)
		close(ready)
		for range requests {
			owner, err := lock(path)
			if err == nil {
				_, status := owner.Stat()
				err = errors.Join(status, owner.Close())
			}
			replies <- err
		}
	}()
	<-ready
	defer func() {
		close(requests)
		<-done
	}()

	// A finalizer must not conceal a missing production Close before descriptor reconciliation.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	runtime.LockOSThread()
	// Deliberately do not unlock: Go terminates a locked OS thread when its test goroutine exits.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal("cannot establish child-only filter prerequisites", err)
	}
	program := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4}, // seccomp_data.arch.
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.AUDIT_ARCH_X86_64, Jt: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0}, // seccomp_data.nr.
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SYS_FSTAT, Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EIO)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	filter := unix.SockFprog{Len: uint16(len(program)), Filter: &program[0]}
	// The kernel copies the filter synchronously; no pointer escapes this syscall's lifetime.
	_, _, failure := syscall.Syscall6(unix.SYS_PRCTL, unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&filter)), 0, 0, 0)
	runtime.KeepAlive(program)
	if failure != 0 {
		t.Fatal("cannot install the owned thread's native fault", failure)
	}
	for range 2 {
		// Confirm that acquisition still succeeds and the real standard-library metadata call returns the injected errno.
		file, err := os.OpenFile(path+".lock", os.O_RDWR|unix.O_NOFOLLOW, 0600)
		if err != nil {
			t.Fatal("fault unexpectedly affected file acquisition", err)
		}
		info, observed := file.Stat()
		closed := file.Close()
		if info != nil || !errors.Is(observed, unix.EIO) || closed != nil {
			t.Fatal("native fault control did not reach fstat alone", observed, closed)
		}
		owner, err := lock(path)
		if owner != nil {
			owner.Close()
			t.Fatal("metadata failure exposed a lock handle")
		}
		if !errors.Is(err, ErrUnavailable) || lockHandles(t, path) != 0 {
			t.Fatal("metadata failure did not reject and release the acquired descriptor", err)
		}
		requests <- struct{}{}
		if err := <-replies; err != nil || lockHandles(t, path) != 0 {
			t.Fatal("healthy thread could not recover the same lock after rejection", err)
		}
	}
	fmt.Println("STORAGE-LOCK syscall=fstat attempts=2 native_errors=2 rejected=2 recovered=2 retained=0")
}

// TestLockFault bounds and joins the isolated filter, then checks the same inode, bytes and healthy parent recovery.
func TestLockFault(t *testing.T) {
	if path := os.Getenv("ASTRA_STORAGE_LOCK_FAULT"); path != "" {
		lockFailure(t, path)
		return
	}
	check := verification(t, "STORAGE-BOUNDARY")
	path := filepath.Join(t.TempDir(), "native.db")
	check(os.WriteFile(path+".lock", []byte("preserved"), 0600) == nil, "create owned native lock fixture")
	before, err := os.Stat(path + ".lock")
	check(err == nil, "capture lock inode before the child fault")
	binary, err := os.Executable()
	check(err == nil, "locate the current native test binary")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	arguments := []string{"-test.run=^TestLockFault$", "-test.count=1"}
	if testing.CoverMode() != "" {
		cover := flag.Lookup("test.gocoverdir")
		if cover == nil || cover.Value.String() == "" {
			t.Fatal("instrumented parent lacks a native coverage directory")
		}
		arguments = append(arguments, "-test.gocoverdir="+cover.Value.String())
	}
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Env = append(os.Environ(), "ASTRA_STORAGE_LOCK_FAULT="+path)
	command.WaitDelay = time.Second
	output, err := command.CombinedOutput()
	check(err == nil && ctx.Err() == nil, "native fault child completed and was reaped: "+string(output))
	check(strings.Count(string(output), "STORAGE-LOCK syscall=fstat attempts=2 native_errors=2 rejected=2 recovered=2 retained=0") == 1, "observe both native failures and healthy recoveries")
	data, err := os.ReadFile(path + ".lock")
	check(err == nil && string(data) == "preserved", "fault preserves lock file content")
	after, err := os.Stat(path + ".lock")
	check(err == nil && os.SameFile(before, after) && after.Mode().Perm() == 0600, "fault preserves lock inode and permissions")
	owner, err := lock(path)
	check(err == nil && owner != nil, "parent native lock remains unaffected")
	check(owner.Close() == nil && lockHandles(t, path) == 0, "parent releases the recovered lock")
	t.Log(strings.TrimSpace(string(output)))
}
