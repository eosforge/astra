"""Check soak budgets, evidence, and failure classification without starting a cluster or downloading dependencies."""

import contextlib
import io
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.soak import Recorder, parse, runtime


class Soak(unittest.TestCase):
    """Check long-run admission, watchdogs, evidence preservation, and resource observations."""

    def setUp(self) -> None:
        """Own an isolated evidence root with cleanup registered before each case."""
        root = Path(__file__).resolve().parents[1] / "build/tmp"
        root.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix="soak-unit-", dir=root)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_duration_bounds(self) -> None:
        """Reject invalid or inconsistent duration arguments before starting a run."""
        for flags in (
            ["--fault-seconds", "-1"],
            ["--steady-seconds", "604801"],
            ["--fault-seconds", "604800", "--steady-seconds", "1"],
            ["--interval", "3601"],
            ["--records", "0"],
            ["--records", "17"],
            ["--persistent"],
            ["--persistent", "--fault-seconds", "1"],
            ["--persistent", "--fault-seconds", "0", "--steady-seconds", "604800", "--interval", "1"],
        ):
            with self.subTest(flags=flags), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                parse(["--binaries", "build", "--output", "out", *flags])
        actual = parse(
            [
                "--binaries",
                "build",
                "--output",
                "out",
                "--fault-seconds",
                "0",
                "--steady-seconds",
                "0",
                "--interval",
                "0",
            ]
        )
        self.assertEqual((actual.fault_seconds, actual.steady_seconds, actual.interval), (0, 0, 0))
        actual = parse(["--binaries", "build", "--output", "out", "--persistent", "--fault-seconds", "0", "--steady-seconds", "0"])
        self.assertTrue(actual.persistent)

    def test_go_residence_requires_the_declared_envelope(self) -> None:
        """Keep the short control and complete Go envelope explicit; reject partial or unbounded substitutes."""
        arguments = [
            "--binaries",
            "build",
            "--output",
            "out",
            "--comet-go",
            "go-test",
            "--comet-go-residence",
            "--persistent",
            "--fault-seconds",
            "0",
            "--interval",
            "0",
            "--records",
            "16",
        ]
        for seconds in (0, 7200):
            actual = parse([*arguments, "--steady-seconds", str(seconds)])
            self.assertTrue(actual.comet_go_residence)
            self.assertEqual(actual.steady_seconds, seconds)
        for flags in (
            ["--steady-seconds", "1"],
            ["--until-stopped"],
            ["--steady-seconds", "0", "--records", "15"],
            ["--steady-seconds", "0", "--interval", "1"],
            ["--steady-seconds", "0", "--fault-seconds", "1"],
        ):
            with self.subTest(flags=flags), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                parse([*arguments, *flags])
        for removed in (("--comet-go", "go-test"), ("--persistent",)):
            with self.subTest(removed=removed), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                parse([value for value in arguments if value not in removed] + ["--steady-seconds", "0"])

    def test_explicit_unbounded_steady(self) -> None:
        """Allow explicitly requested unlimited steady operation without a total-duration deadline."""
        actual = parse(["--binaries", "build", "--output", "out", "--fault-seconds", "0", "--until-stopped"])
        self.assertIsNone(actual.steady_seconds)
        self.assertEqual(actual.fault_seconds, 0)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parse(["--binaries", "build", "--output", "out", "--until-stopped", "--steady-seconds", "10"])

    def test_installed_environment(self) -> None:
        """Reject loader interposition and prove package mode cannot select development runtimes."""
        actual = parse(["--binaries", "build", "--output", "out", "--installed"])
        self.assertTrue(actual.installed)
        with patch.dict(os.environ, {"PATH": "/usr/bin", "LANG": "C.UTF-8"}, clear=True), patch("tests.soak.environment") as development:
            self.assertEqual(runtime(True), {"PATH": "/usr/bin", "LANG": "C.UTF-8"})
            development.assert_not_called()
            for name in ("LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"):
                with self.subTest(name=name), patch.dict(os.environ, {name: "/private"}), self.assertRaisesRegex(RuntimeError, "loader overrides"):
                    runtime(True)
            self.assertNotIn("LD_LIBRARY_PATH", os.environ)
            with patch("tests.soak.os.sched_getaffinity", return_value={0, 1, 2, 3}, create=True):
                runtime(False)
            development.assert_called_once_with(jobs=4)

    def test_progress_requires_new_confirmed_round(self) -> None:
        """Require complete, increasing business-round observations to refresh the watchdog."""
        recorder = Recorder(self.root / "evidence", 0, None, 0)
        log = self.root / "steady.log"
        recorder.watch(log)
        start = recorder.progress[log]["updated"]
        recorder.observe(log, b'{"event":"mesh_progress","round":100}\n', start + 10)
        self.assertEqual(recorder.progress[log]["round"], 100)
        # Duplicates, partial lines, and process liveness cannot hide stalled business progress; this deadline bounds one round, not total runtime.
        recorder.observe(log, b'{"event":"mesh_progress","round":100}\n{"event":', start + 100)
        self.assertEqual(recorder.progress[log]["updated"], start + 10)
        with self.assertRaisesRegex(RuntimeError, "no confirmed progress"):
            recorder.observe(log, b"", start + 191)
        with self.assertRaisesRegex(RuntimeError, "backwards"):
            recorder.observe(log, b'{"event":"mesh_progress","round":99}\n', start + 192)

    def test_existing_evidence_is_not_overwritten(self) -> None:
        """Reject an existing evidence directory rather than replacing previous observations."""
        with self.assertRaises(FileExistsError):
            Recorder(self.root, 0, 0, 0)

    def test_completion_and_interruption_are_distinct(self) -> None:
        """Record requested interruption without translating it into a successful completion."""
        recorder = Recorder(self.root / "evidence", 0, 0, 0)
        with contextlib.redirect_stdout(io.StringIO()):
            recorder.record("interrupted")
        values = [json.loads(line) for line in (recorder.output / "events.jsonl").read_text().splitlines()]
        self.assertEqual([item["event"] for item in values], ["interrupted"])

    def test_unexpected_even_clean_exit_fails(self) -> None:
        """Fail when a resident service exits unexpectedly, including exit code zero."""
        recorder = Recorder(self.root / "evidence", 0, 0, 0)
        process = Mock(pid=123)
        process.poll.return_value = 0
        recorder.expect(process, "star")
        with self.assertRaisesRegex(RuntimeError, "unexpectedly"):
            recorder.check([], force=True)
        recorder.retire(process)
        self.assertFalse(recorder.expected)

    def test_incremental_sanitizer_marker_and_tail(self) -> None:
        """Detect sanitizer markers split across reads and preserve their diagnostic tail."""
        recorder = Recorder(self.root / "evidence", 0, 0, 0)
        log = self.root / "service.log"
        log.write_bytes(b"ThreadSan")
        process = Mock(pid=os.getpid())
        process.poll.return_value = None
        recorder.check([(process, log)], force=True)
        self.assertEqual(recorder.offsets[log], 9)
        with log.open("ab") as stream:
            stream.write(b"itizer: data race\n")
        with self.assertRaisesRegex(RuntimeError, "Sanitizer"):
            recorder.check([(process, log)], force=True)
        self.assertIn(b"data race", (recorder.output / log.name).read_bytes())

    def test_process_resources_and_sampling_throttle(self) -> None:
        """Collect real per-process resource counts while throttling repeated sampling."""
        recorder = Recorder(self.root / "evidence", 0, 0, 0)
        log = self.root / "service.log"
        log.write_bytes(b"ready\n")
        process = Mock(pid=os.getpid())
        process.poll.return_value = None
        recorder.check([(process, log)], force=True)
        recorder.check([(process, log)])
        records = [json.loads(line) for line in (recorder.output / "events.jsonl").read_text().splitlines()]
        self.assertEqual(len(records), 1)
        sample = records[0]["processes"][0]
        self.assertGreater(sample["rss"], 0)
        self.assertGreater(sample["threads"], 0)
        self.assertGreater(sample["handles" if sys.platform == "win32" else "fds"], 0)
        self.assertGreaterEqual(sample["peak"], sample["rss"])
        self.assertGreater(sample["started"], 0)
        self.assertEqual("fds" in sample, sys.platform == "linux")
        self.assertEqual("handles" in sample, sys.platform == "win32")

    def test_sampling_exit_race(self) -> None:
        """Reproduce denied native reads at finite-child exit without hiding live or resident failures."""
        for error in (PermissionError, FileNotFoundError, ProcessLookupError):
            for resident, code in ((False, 0), (False, 7), (False, None), (True, 0)):
                with self.subTest(error=error.__name__, resident=resident, code=code):
                    directory = self.root / f"{error.__name__}-{resident}-{code}"
                    recorder = Recorder(directory, 0, 0, 0)
                    log = self.root / "finite.log"
                    log.write_bytes(b"completed\n")
                    process = Mock(pid=os.getpid())
                    process.poll.side_effect = ([None] if resident else []) + [None, code]
                    process.wait.side_effect = subprocess.TimeoutExpired("owned finite child", 1)
                    if resident:
                        recorder.expect(process, "resident")
                    with patch("tests.soak.resources.sample", side_effect=error("controlled native exit race")), contextlib.redirect_stdout(io.StringIO()):
                        if resident:
                            with self.assertRaisesRegex(RuntimeError, "Resident service disappeared"):
                                recorder.check([(process, log)], force=True)
                        elif code is None:
                            with self.assertRaises(error):
                                recorder.check([(process, log)], force=True)
                        else:
                            recorder.check([(process, log)], force=True)
                            records = [json.loads(line) for line in (directory / "events.jsonl").read_text().splitlines()]
                            self.assertEqual(records[0]["event"], "sampling_exit")
                            self.assertEqual(records[0]["exit_code"], code)
                            self.assertEqual(records[1]["processes"], [])
                    self.assertEqual(process.poll.call_count, 3 if resident else 2)
                    self.assertEqual(process.wait.call_count, int(not resident and code is None))

    def test_sampling_exit_drain(self) -> None:
        """An inaccessible finite child can be reaped after poll; retain its real success or failure code."""
        for code in (0, 7):
            with self.subTest(code=code):
                recorder = Recorder(self.root / f"drain-{code}", 0, 0, 0)
                log = self.root / "finite.log"
                log.write_bytes(b"completed\n")
                process = Mock(pid=os.getpid())
                process.poll.side_effect = [None, None]
                process.wait.return_value = code
                with (
                    patch("tests.soak.resources.sample", side_effect=PermissionError("controlled exit-time diagnostic window")),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    recorder.check([(process, log)], force=True)
                process.wait.assert_called_once_with(timeout=1)
                records = [json.loads(line) for line in (recorder.output / "events.jsonl").read_text().splitlines()]
                self.assertEqual(records[0]["event"], "sampling_exit")
                self.assertEqual(records[0]["exit_code"], code)
                self.assertEqual(records[1]["processes"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
