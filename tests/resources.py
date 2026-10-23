"""Read native host and process resources without installing a monitoring dependency."""

from types import SimpleNamespace
import ctypes
from ctypes import wintypes as w
from functools import cache
from pathlib import Path
import subprocess
import sys

from tests.windows_job import ThreadEntry


class Memory(ctypes.Structure):
    """Mirror MEMORYSTATUSEX; all byte counters are unsigned 64-bit values."""

    _fields_ = [("size", w.DWORD), ("load", w.DWORD)] + [
        (name, ctypes.c_uint64) for name in ("total", "available", "commit", "remaining", "virtual", "free", "extended")
    ]


class Usage(ctypes.Structure):
    """Mirror PROCESS_MEMORY_COUNTERS, whose working-set counters use native pointer width."""

    _fields_ = [("size", w.DWORD), ("faults", w.DWORD)] + [
        (name, ctypes.c_size_t) for name in ("peak", "resident", "peak_paged", "paged", "peak_nonpaged", "nonpaged", "pagefile", "peak_pagefile")
    ]


class Windows:
    """Inspect an owned process handle and close every temporary native handle on failure too."""

    def __init__(self) -> None:
        """Bind the system ABI once; imports on Linux do not load Windows libraries."""
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "GlobalMemoryStatusEx": ([ctypes.POINTER(Memory)], w.BOOL),
            "K32GetProcessMemoryInfo": ([w.HANDLE, ctypes.POINTER(Usage), w.DWORD], w.BOOL),
            "GetProcessHandleCount": ([w.HANDLE, ctypes.POINTER(w.DWORD)], w.BOOL),
            "GetProcessId": ([w.HANDLE], w.DWORD),
            "GetProcessTimes": ([w.HANDLE] + [ctypes.POINTER(w.FILETIME)] * 4, w.BOOL),
            "OpenProcess": ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            "WaitForSingleObject": ([w.HANDLE, w.DWORD], w.DWORD),
            "CreateToolhelp32Snapshot": ([w.DWORD, w.DWORD], w.HANDLE),
            "Thread32First": ([w.HANDLE, ctypes.POINTER(ThreadEntry)], w.BOOL),
            "Thread32Next": ([w.HANDLE, ctypes.POINTER(ThreadEntry)], w.BOOL),
            "CloseHandle": ([w.HANDLE], w.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = arguments, result

    def error(self) -> None:
        """Preserve native diagnostics; only vanished-process errors enter the bounded exit drain."""
        code = ctypes.get_last_error()
        if code in (87, 299):  # ERROR_INVALID_PARAMETER / ERROR_PARTIAL_COPY during process inspection.
            raise ProcessLookupError(code, "Windows process inspection lost its target")
        raise ctypes.WinError(code)

    def close(self, handle: int) -> None:
        """Release only a handle created by this sampler, never the Popen-owned process handle."""
        if not self.api.CloseHandle(handle):
            self.error()

    def alive(self, handle: int) -> None:
        """A signaled process is retired even when its actual exit code equals STILL_ACTIVE (259)."""
        result = self.api.WaitForSingleObject(handle, 0)
        if result == 0:
            raise ProcessLookupError("Windows process exited during resource sampling")
        if result != 258:  # WAIT_TIMEOUT proves that this specific process object is still running.
            self.error()

    def memory(self) -> dict[str, int | None]:
        """Read physical availability; Windows commit charge is not reported as Linux swap usage."""
        value = Memory()
        value.size = ctypes.sizeof(value)
        if not self.api.GlobalMemoryStatusEx(ctypes.byref(value)):
            self.error()
        return {"available": value.available, "swap": None}

    def threads(self, pid: int) -> int:
        """Count a native thread snapshot, rejecting incomplete enumeration instead of undercounting."""
        handle = self.api.CreateToolhelp32Snapshot(4, 0)  # TH32CS_SNAPTHREAD.
        if handle == ctypes.c_void_p(-1).value:
            self.error()
        try:
            value = ThreadEntry()
            value.size = ctypes.sizeof(value)
            found = self.api.Thread32First(handle, ctypes.byref(value))
            count = 0
            visited = 0
            while found:
                count += value.owner == pid
                visited += 1
                if visited > 100000:
                    raise RuntimeError("Native thread snapshot exceeded its sampling budget")
                value.size = ctypes.sizeof(value)
                found = self.api.Thread32Next(handle, ctypes.byref(value))
            if ctypes.get_last_error() != 18:  # ERROR_NO_MORE_FILES is the only complete traversal terminal.
                self.error()
            return count
        finally:
            self.close(handle)

    def sample(self, process: subprocess.Popen | SimpleNamespace) -> dict[str, int]:
        """Use the owning Popen handle when present, so PID reuse cannot change the observed process."""
        borrowed = isinstance(process, subprocess.Popen)
        handle = int(process._handle) if borrowed else self.api.OpenProcess(0x1000 | 0x100000, False, process.pid)
        if not handle:
            self.error()
        try:
            self.alive(handle)
            if self.api.GetProcessId(handle) != process.pid:
                raise ProcessLookupError("Windows process handle does not match its owner")
            times = [w.FILETIME() for _ in range(4)]
            if not self.api.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
                self.error()
            usage = Usage()
            usage.size = ctypes.sizeof(usage)
            handles = w.DWORD()
            if not self.api.K32GetProcessMemoryInfo(handle, ctypes.byref(usage), usage.size) or not self.api.GetProcessHandleCount(
                handle, ctypes.byref(handles)
            ):
                self.error()
            threads = self.threads(process.pid)
            self.alive(handle)
            if threads < 1:
                raise ProcessLookupError("Windows thread snapshot lost its live process")
            return {
                "rss": usage.resident,
                "peak": usage.peak,
                "threads": threads,
                "handles": handles.value,
                "started": times[0].dwLowDateTime | times[0].dwHighDateTime << 32,
            }
        finally:
            if not borrowed:
                self.close(handle)


@cache
def windows() -> Windows:
    """Share immutable native function signatures, without retaining process or snapshot handles."""
    return Windows()


def memory() -> dict[str, int | None]:
    """Read actual host memory using the supported platform's native definition."""
    if sys.platform == "win32":
        return windows().memory()
    if sys.platform != "linux":
        raise RuntimeError("Resource sampling requires Linux or Windows")
    values = {key: int(value.split()[0]) * 1024 for key, value in (line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())}
    return {"available": values["MemAvailable"], "swap": values["SwapTotal"] - values["SwapFree"]}


def sample(process: subprocess.Popen | SimpleNamespace) -> dict[str, int]:
    """Read one live process; verify Linux start ticks around the sample to reject PID reuse."""
    if sys.platform == "win32":
        return windows().sample(process)
    if sys.platform != "linux":
        raise RuntimeError("Resource sampling requires Linux or Windows")
    path = Path(f"/proc/{process.pid}")
    started = int((path / "stat").read_text().rsplit(")", 1)[1].split()[19])
    status = dict(line.split(":", 1) for line in (path / "status").read_text().splitlines())
    value = {
        "rss": int(status.get("VmRSS", "0").split()[0]) * 1024,
        "peak": int(status.get("VmHWM", "0").split()[0]) * 1024,
        "threads": int(status["Threads"]),
        "fds": len(list((path / "fd").iterdir())),
        "started": started,
    }
    if int((path / "stat").read_text().rsplit(")", 1)[1].split()[19]) != started:
        raise ProcessLookupError("Linux process identity changed during resource sampling")
    return value
