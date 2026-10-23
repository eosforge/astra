"""Own native Windows jobs and bounded command streams without touching unrelated processes."""

import ctypes
from ctypes import wintypes as w
import subprocess
import queue
import threading
import time
from pathlib import Path
from collections.abc import Callable
from typing import BinaryIO


class BasicLimits(ctypes.Structure):
    """Mirror JOBOBJECT_BASIC_LIMIT_INFORMATION without changing native field order or widths."""

    # Native durations use 100 ns ticks; memory limits use bytes. Field order is part of the Windows ABI.
    _fields_ = [
        ("process_time", ctypes.c_int64),
        ("job_time", ctypes.c_int64),
        ("flags", w.DWORD),
        ("minimum", ctypes.c_size_t),
        ("maximum", ctypes.c_size_t),
        ("active", w.DWORD),
        ("affinity", ctypes.c_size_t),
        ("priority", w.DWORD),
        ("scheduling", w.DWORD),
    ]


class ExtendedLimits(ctypes.Structure):
    """Mirror Windows extended job limits, including accounting fields required by the ABI."""

    # IO_COUNTERS contains six 64-bit counts; memory and peak fields use native pointer-sized byte counts.
    _fields_ = [
        ("basic", BasicLimits),
        ("io", ctypes.c_uint64 * 6),
        ("process_memory", ctypes.c_size_t),
        ("job_memory", ctypes.c_size_t),
        ("peak_process", ctypes.c_size_t),
        ("peak_job", ctypes.c_size_t),
    ]


class ThreadEntry(ctypes.Structure):
    """Mirror THREADENTRY32 for finding the suspended child's primary thread."""

    # size identifies this ABI; thread and owner are the thread ID and owning process ID, not handles.
    _fields_ = [("size", w.DWORD), ("usage", w.DWORD), ("thread", w.DWORD), ("owner", w.DWORD), ("priority", w.LONG), ("delta", w.LONG), ("flags", w.DWORD)]


class Job:
    """Own a kill-on-close Windows job and drain descendants before releasing its handle."""

    def __init__(self) -> None:
        """Bind native signatures and acquire a kill-on-close job, cleaning up failed configuration."""
        # Keep native handles pointer-sized on 64-bit hosts and preserve GetLastError for diagnostics.
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([ctypes.c_void_p, w.LPCWSTR], w.HANDLE),
            "SetInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
            "AssignProcessToJobObject": ([w.HANDLE, w.HANDLE], w.BOOL),
            "TerminateJobObject": ([w.HANDLE, w.UINT], w.BOOL),
            "QueryInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.c_void_p], w.BOOL),
            "CloseHandle": ([w.HANDLE], w.BOOL),
            "CreateToolhelp32Snapshot": ([w.DWORD, w.DWORD], w.HANDLE),
            "Thread32First": ([w.HANDLE, ctypes.POINTER(ThreadEntry)], w.BOOL),
            "Thread32Next": ([w.HANDLE, ctypes.POINTER(ThreadEntry)], w.BOOL),
            "OpenThread": ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            "ResumeThread": ([w.HANDLE], w.DWORD),
            "GetProcessId": ([w.HANDLE], w.DWORD),
            "GetProcessTimes": ([w.HANDLE, *([ctypes.POINTER(w.FILETIME)] * 4)], w.BOOL),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = args, result
        # This instance exclusively owns the handle; stop() releases it after descendant accounting reaches zero.
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
        if not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            error = ctypes.WinError(ctypes.get_last_error())
            self.stop()
            raise error

    def attach(self, process: subprocess.Popen) -> None:
        """Assign a suspended child before resuming its thread so descendants inherit job ownership."""
        if not self.api.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())
        snapshot = self.api.CreateToolhelp32Snapshot(4, 0)  # TH32CS_SNAPTHREAD.
        if snapshot == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            entry = ThreadEntry()
            entry.size = ctypes.sizeof(entry)
            found = self.api.Thread32First(snapshot, ctypes.byref(entry))
            while found:
                if entry.owner == process.pid:
                    thread = self.api.OpenThread(2, False, entry.thread)  # THREAD_SUSPEND_RESUME.
                    if not thread:
                        raise ctypes.WinError(ctypes.get_last_error())
                    try:
                        if self.api.ResumeThread(thread) == 0xFFFFFFFF:
                            raise ctypes.WinError(ctypes.get_last_error())
                    finally:
                        self.api.CloseHandle(thread)
                    return
                found = self.api.Thread32Next(snapshot, ctypes.byref(entry))
            raise RuntimeError("Suspended child has no primary thread")
        finally:
            self.api.CloseHandle(snapshot)

    def identity(self, process: subprocess.Popen) -> dict[str, int]:
        """Bind the borrowed child handle to its native PID and immutable creation FILETIME."""
        handle = int(process._handle)
        pid = self.api.GetProcessId(handle)
        if not pid or pid != process.pid:
            raise RuntimeError("Windows child handle identity differs from its PID")
        times = [w.FILETIME() for _ in range(4)]
        if not self.api.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
            raise ctypes.WinError(ctypes.get_last_error())
        return {"pid": pid, "creation_time": (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime}

    def active(self) -> int:
        """Read actual live descendants from this job's native accounting, never from a PID scan."""
        accounting = (ctypes.c_uint64 * 6)()
        if not self.api.QueryInformationJobObject(self.handle, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return ctypes.cast(ctypes.byref(accounting, 40), ctypes.POINTER(w.DWORD)).contents.value

    def stop(self) -> None:
        """Terminate the job and await zero active processes within ten seconds before closing the handle."""
        if not self.handle:
            return
        try:
            if not self.api.TerminateJobObject(self.handle, 130):
                raise ctypes.WinError(ctypes.get_last_error())
            # JOBOBJECT_BASIC_ACCOUNTING_INFORMATION: four LARGE_INTEGER times followed by four DWORD counters.
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if self.active() == 0:
                    return
                time.sleep(0.02)
            raise TimeoutError("Windows job descendants did not terminate")
        finally:
            self.api.CloseHandle(self.handle)
            self.handle = None


def capture(
    arguments: list[str],
    root: Path,
    environment: dict[str, str],
    outputs: dict[str, BinaryIO],
    *,
    timeout: float,
    log_bytes: int,
    cancelled: Callable[[], bool],
    identify: Callable[[dict[str, int]], None],
) -> dict:
    """Capture complete native pipes or a bounded failure, then join readers and drain the owned job.

    Args:
        identify: Persist native creation identity before resuming the suspended child.

    Raises:
        OSError: Native startup, I/O or job ownership failed; cleanup still runs.
        TimeoutError: Owned pipe readers cannot drain within the cleanup budget.
    """
    # At most eight 64 KiB blocks wait in memory; neither a fast child nor cancellation creates an unbounded queue.
    blocks = queue.Queue(maxsize=8)
    stopping = threading.Event()
    readers = []
    process = None
    started = time.monotonic()
    sizes = {name: 0 for name in outputs}
    reason, complete, cleanup = "exited", True, False
    job = Job()

    def deliver(name: str, block: bytes | None, error: OSError | None = None) -> None:
        """Bound queued output and let cancellation unblock a producer waiting for a reader slot."""
        while not stopping.is_set():
            try:
                blocks.put((name, block, error), timeout=0.05)
                return
            except queue.Full:
                continue

    def read(name: str, pipe: BinaryIO) -> None:
        """Own one blocking native pipe until EOF or cancellation; the parent joins this thread."""
        try:
            while not stopping.is_set():
                block = pipe.read1(65536)
                deliver(name, block or None)
                if not block:
                    return
        except OSError as error:
            deliver(name, None, error)

    try:
        process = subprocess.Popen(
            arguments,
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=4 | subprocess.CREATE_NO_WINDOW,
        )
        identify(job.identity(process))
        # No descendant can escape before ownership is established; no breakaway flag is enabled.
        job.attach(process)
        for name in outputs:
            thread = threading.Thread(target=read, args=(name, getattr(process, name)), name="astra-pipe-" + name)
            thread.start()
            readers.append(thread)
        ended = set()
        while len(ended) != len(outputs) or process.poll() is None:
            if cancelled():
                reason, complete = "interrupted", False
                break
            if time.monotonic() - started > timeout:
                reason, complete = "timeout", False
                break
            try:
                name, block, error = blocks.get(timeout=0.05)
            except queue.Empty:
                continue
            if error is not None:
                raise error
            if block is None:
                ended.add(name)
                continue
            remaining = log_bytes - sizes[name]
            outputs[name].write(block[:remaining])
            sizes[name] += min(remaining, len(block))
            if len(block) > remaining:
                reason, complete = "log-limit", False
                break
    except KeyboardInterrupt:
        reason, complete = "interrupted", False
    finally:
        stopping.set()
        try:
            job.stop()
        finally:
            if process is not None:
                # A failed assignment may leave only the exact suspended Popen child outside the job.
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=10)
            deadline = time.monotonic() + 10
            for thread in readers:
                thread.join(max(0, deadline - time.monotonic()))
            if any(thread.is_alive() for thread in readers):
                raise TimeoutError("Windows command pipe readers did not terminate")
            if process is not None:
                process.stdout.close()
                process.stderr.close()
            cleanup = True
    return {"exit_code": process.returncode, "termination": reason, "complete": complete, "cleanup": cleanup}
