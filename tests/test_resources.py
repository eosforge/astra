"""Verify native Windows sampling, handle ownership, and fail-closed diagnostic boundaries."""

import ctypes
from pathlib import Path
import os
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from tests import resources


@unittest.skipUnless(sys.platform == "linux", "Native Linux resource API")
class Linux(unittest.TestCase):
    """Preserve actual /proc accounting and reject a changed process identity during inspection."""

    def test_identity(self) -> None:
        """A controlled start-tick change cannot turn PID reuse into a successful resource sample."""
        process = Mock(pid=os.getpid())
        value = resources.sample(process)
        self.assertGreater(value["rss"], 0)
        self.assertGreater(value["fds"], 0)
        self.assertGreater(value["threads"], 0)
        self.assertNotIn("handles", value)
        original = Path.read_text
        reads = []

        def changed(path: Path, *arguments: object, **keywords: object) -> str:
            """Alter only the second native identity read, keeping the resource observations real."""
            text = original(path, *arguments, **keywords)
            if path == Path(f"/proc/{process.pid}/stat"):
                reads.append(text)
                if len(reads) == 2:
                    prefix, tail = text.rsplit(")", 1)
                    fields = tail.split()
                    fields[19] = str(int(fields[19]) + 1)
                    return prefix + ") " + " ".join(fields)
            return text

        with patch.object(Path, "read_text", changed), self.assertRaisesRegex(ProcessLookupError, "identity changed"):
            resources.sample(process)
        self.assertEqual(len(reads), 2)
        self.assertEqual(resources.sample(process)["started"], value["started"])

    def test_memory(self) -> None:
        """Use physical availability and actual swap usage; an unreadable host counter remains a failure."""
        value = resources.memory()
        self.assertGreater(value["available"], 0)
        self.assertGreaterEqual(value["swap"], 0)
        with patch.object(Path, "read_text", side_effect=PermissionError("Controlled native memory read failure")), self.assertRaises(PermissionError):
            resources.memory()


@unittest.skipUnless(sys.platform == "win32", "Native Windows resource API")
class Resources(unittest.TestCase):
    """Exercise actual Windows counters; injected failures never stand in for successful native samples."""

    def test_handles(self) -> None:
        """Repeated snapshots and every denied native read close temporary handles exactly."""
        process = Mock(pid=os.getpid())
        native = resources.windows()
        self.assertEqual(ctypes.sizeof(resources.Memory), 64)
        self.assertEqual(ctypes.sizeof(resources.Usage), 72)
        self.assertEqual(ctypes.sizeof(resources.ThreadEntry), 28)
        self.assertGreater(resources.memory()["available"], 0)
        self.assertIsNone(resources.memory()["swap"])
        original = resources.sample(process)
        for _ in range(32):
            current = resources.sample(process)
            self.assertEqual(current["handles"], original["handles"])
            self.assertEqual(current["started"], original["started"])
            self.assertGreater(current["threads"], 0)

        def denied(*_: object) -> int:
            """Inject the native access-denied result after the sampler acquires its handles."""
            ctypes.set_last_error(5)
            return 0

        for name in ("GetProcessTimes", "K32GetProcessMemoryInfo", "GetProcessHandleCount", "Thread32First", "Thread32Next"):
            with self.subTest(api=name), patch.object(native.api, name, side_effect=denied), self.assertRaises(PermissionError):
                resources.sample(process)
            self.assertEqual(resources.sample(process)["handles"], original["handles"])
        with patch.object(native.api, "GetProcessId", return_value=process.pid + 1), self.assertRaises(ProcessLookupError):
            resources.sample(process)
        self.assertEqual(resources.sample(process)["handles"], original["handles"])

    def test_owner(self) -> None:
        """Sample the real child, preserve its borrowed handle on errors, and reject its retired identity."""
        script = """
import os,sys,threading
gate=threading.Event(); ready=threading.Barrier(3)
def worker():
    ready.wait(); gate.wait()
threads=[threading.Thread(target=worker) for _ in range(2)]
handles=[open(os.devnull,'wb') for _ in range(4)]
data=bytearray(16*1024*1024)
for offset in range(0,len(data),4096): data[offset]=1
for thread in threads: thread.start()
ready.wait(); print('ready',flush=True)
assert sys.stdin.readline()=='stop\\n'
gate.set()
for thread in threads: thread.join()
for handle in handles: handle.close()
"""
        with subprocess.Popen(
            # A Windows venv redirector launches another process; bind the real existing runtime's PID to its allocation.
            [sys._base_executable, "-B", "-c", script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        ) as process:
            try:
                self.assertEqual(process.stdout.readline(), "ready\n")
                native = resources.windows()
                with patch.object(native.api, "OpenProcess", side_effect=AssertionError("Borrowed child must not be reopened by PID")):
                    sample = resources.sample(process)
                self.assertGreaterEqual(sample["rss"], 16 * 1024 * 1024)
                self.assertGreaterEqual(sample["peak"], sample["rss"])
                self.assertGreaterEqual(sample["threads"], 3)
                self.assertGreaterEqual(sample["handles"], 4)
                self.assertEqual(native.api.GetProcessId(int(process._handle)), process.pid)
                with patch.object(native.api, "GetProcessId", return_value=process.pid + 1), self.assertRaises(ProcessLookupError):
                    resources.sample(process)
                self.assertIsNone(process.poll())
                self.assertEqual(resources.sample(process)["started"], sample["started"])
                output, errors = process.communicate("stop\n", timeout=10)
                self.assertEqual((process.returncode, output, errors), (0, "", ""))
                with self.assertRaises(ProcessLookupError):
                    resources.sample(process)
                self.assertEqual(native.api.GetProcessId(int(process._handle)), process.pid)
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=10)

    def test_failures(self) -> None:
        """Native permission and incomplete traversal errors remain failures, including exit code 259."""
        native = resources.windows()
        for code, error in ((5, PermissionError), (87, ProcessLookupError), (299, ProcessLookupError), (6, OSError)):
            with self.subTest(code=code):
                ctypes.set_last_error(code)
                with self.assertRaises(error):
                    native.error()
        process = Mock(pid=os.getpid())
        with patch.object(native.api, "WaitForSingleObject", return_value=0), self.assertRaises(ProcessLookupError):
            resources.sample(process)
        with patch.object(native.api, "Thread32First", side_effect=lambda *_: (ctypes.set_last_error(18), 0)[1]), self.assertRaises(ProcessLookupError):
            resources.sample(process)
        with patch.object(resources.sys, "platform", "unsupported"):
            with self.assertRaisesRegex(RuntimeError, "Linux or Windows"):
                resources.memory()
            with self.assertRaisesRegex(RuntimeError, "Linux or Windows"):
                resources.sample(process)
        with subprocess.Popen([sys.executable, "-B", "-c", "raise SystemExit(259)"], creationflags=subprocess.CREATE_NO_WINDOW) as child:
            self.assertEqual(child.wait(timeout=10), 259)
            with self.assertRaises(ProcessLookupError):
                resources.sample(child)


if __name__ == "__main__":
    unittest.main(verbosity=2)
