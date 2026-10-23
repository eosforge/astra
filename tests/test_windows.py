"""Falsify native Windows command ownership, bounded pipes and cancellation with actual child processes."""

from collections.abc import Callable
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from tools import verify, windows


@unittest.skipUnless(os.name == "nt", "Native Windows job and pipe lifecycle")
class WindowsTests(unittest.TestCase):
    """Keep local command execution distinct from CI provenance or Windows service support."""

    @staticmethod
    def execute(root: Path, name: str, code: str, *, timeout: float = 2, log_bytes: int = 4096, cancelled: Callable[[], bool] = lambda: False) -> tuple:
        """Run one owned fixture through the production collector, retaining actual streams and creation identity."""
        directory = root / "build" / name
        directory.mkdir(parents=True)
        record = verify.execute(
            {
                "id": name,
                "argv": [sys._base_executable, "-B", "-c", code],
                "environment": {"SYNTHETIC_SECRET": "fixture-secret", "CL": "/untrusted", "_CL_": "/untrusted"},
                "timeout_s": timeout,
                "log_bytes": log_bytes,
            },
            root,
            directory,
            "windows-amd64",
            cancelled,
        )
        streams = {name: verify.reference(directory, record[name], log_bytes) for name in ("stdout", "stderr")}
        return record, streams, verify.decode(verify.read(directory / (name + ".process.json")))

    def test_exit(self) -> None:
        """Native successful and 259 exits require complete streams; 259 is a completed status, never assumed liveness."""
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            cases = [
                (
                    "success",
                    "import os,sys; assert all(k not in os.environ for k in ('SYNTHETIC_SECRET','CL','_CL_')); print('out'); print('err',file=sys.stderr)",
                    0,
                ),
                ("code", "import os; os._exit(259)", 259),
            ]
            for name, code, status in cases:
                with self.subTest(status=status):
                    record, streams, process = self.execute(root, name, code)
                    self.assertEqual(record["exit_code"], status)
                    self.assertEqual(record["termination"], "exited")
                    self.assertTrue(record["complete"] and record["cleanup"])
                    self.assertEqual(record["platform"], "windows-amd64")
                    self.assertGreater(process["identity"]["pid"], 0)
                    self.assertGreater(process["identity"]["creation_time"], 0)
                    self.assertNotIn("start_ticks", process["identity"])
                    self.assertFalse((root / "build" / name / "tmp").exists())
                    if status == 0:
                        self.assertEqual(streams, {"stdout": b"out\r\n", "stderr": b"err\r\n"})

    def test_limits(self) -> None:
        """Timeout, cancellation and overflow are incomplete failures with joined native cleanup and bounded retained output."""
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            cases = [
                ("timeout", "import time; time.sleep(30)", 0.3, lambda: False),
                ("interrupted", "import time; time.sleep(30)", 2, lambda: True),
                ("log-limit", "import os; os.write(1,b'x'*8192); os.write(2,b'y'*8192)", 2, lambda: False),
            ]
            for reason, code, timeout, cancelled in cases:
                with self.subTest(reason=reason):
                    record, streams, _ = self.execute(root, reason, code, timeout=timeout, log_bytes=1024, cancelled=cancelled)
                    self.assertEqual(record["termination"], reason)
                    self.assertFalse(record["complete"])
                    self.assertTrue(record["cleanup"])
                    self.assertIsInstance(record["exit_code"], int)
                    self.assertLessEqual(sum(map(len, streams.values())), 2048)
                    if reason == "log-limit":
                        self.assertEqual(max(map(len, streams.values())), 1024)
                    self.assertFalse(any(thread.name.startswith("astra-pipe-") for thread in threading.enumerate()))

    def test_orphan(self) -> None:
        """A parent exiting zero cannot turn a still-running descendant holding inherited pipes into a passed command."""
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            code = "import os,subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); os._exit(0)"
            record, _, _ = self.execute(root, "orphan", code, timeout=0.5)
            self.assertEqual(record["exit_code"], 0)
            self.assertEqual(record["termination"], "timeout")
            self.assertFalse(record["complete"])
            self.assertTrue(record["cleanup"])
            self.assertFalse(any(thread.name.startswith("astra-pipe-") for thread in threading.enumerate()))

    def test_ownership(self) -> None:
        """Draining a timed-out job leaves a separately owned live job untouched."""
        job = windows.Job()
        process = None
        try:
            process = subprocess.Popen(
                [sys._base_executable, "-B", "-c", "import time; time.sleep(30)"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                # This one-process sentinel needs no console host; keep its exact native count assertion.
                creationflags=4 | subprocess.DETACHED_PROCESS,
            )
            identity = job.identity(process)
            job.attach(process)
            self.assertEqual(job.active(), 1)
            with tempfile.TemporaryDirectory() as value:
                record, _, _ = self.execute(Path(value), "isolated", "import time; time.sleep(30)", timeout=0.3)
                self.assertTrue(record["cleanup"])
            self.assertIsNone(process.poll())
            self.assertEqual(job.identity(process), identity)
            self.assertEqual(job.active(), 1)
        finally:
            job.stop()
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=10)

    def test_startup(self) -> None:
        """Identity and assignment failures kill the exact suspended child and cannot leave reader threads or a success record."""
        original = subprocess.Popen
        children = []

        def start(*args: object, **kwargs: object) -> subprocess.Popen:
            """Retain the actual fixture child for an independent retirement assertion."""
            child = original(*args, **kwargs)
            children.append(child)
            return child

        with tempfile.TemporaryDirectory() as value:
            for method in ("identity", "attach"):
                with self.subTest(method=method), patch.object(windows.subprocess, "Popen", side_effect=start):
                    with patch.object(windows.Job, method, side_effect=RuntimeError("controlled ownership failure")):
                        with self.assertRaisesRegex(RuntimeError, "controlled ownership failure"):
                            self.execute(Path(value), method, "import time; time.sleep(30)")
                    self.assertIsNotNone(children[-1].poll())
                    self.assertFalse(any(thread.name.startswith("astra-pipe-") for thread in threading.enumerate()))
                    # Log files can be opened for exclusive append after the collector has released them.
                    for path in (Path(value) / "build" / method).glob("*.log"):
                        with path.open("ab") as stream:
                            self.assertEqual(stream.tell(), 0)


if __name__ == "__main__":
    unittest.main()
