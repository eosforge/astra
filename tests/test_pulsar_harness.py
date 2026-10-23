"""Reject false recovery evidence and hidden diagnostics in the Pulsar process harness."""

from __future__ import annotations

import json
import io
from contextlib import redirect_stderr
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests import test_pulsar as harness


class PulsarHarnessTests(unittest.TestCase):
    """Check that harness verdicts depend on fresh, valid process observations."""

    def setUp(self) -> None:
        """Create an isolated log fixture with test-owned cleanup."""
        root = harness.ROOT / "build/tmp"
        root.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="pulsar-harness-", dir=root)
        self.addCleanup(temporary.cleanup)
        self.log = Path(temporary.name) / "service.log"

    def records(self, *samples: dict) -> None:
        """Write the supplied clock observations as complete JSONL events."""
        records = [{"event": "clock_status", "fields": fields} for fields in samples]
        self.log.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")

    def test_continuous_holdover_and_recovery(self) -> None:
        """Accept monotonic local time through reference loss and subsequent synchronization recovery."""
        self.records(
            {"ready": False, "synchronized": False},
            {"ready": True, "synchronized": True, "nanoseconds": 100},
            {"ready": True, "synchronized": True, "nanoseconds": 100},
            {"ready": True, "synchronized": False, "nanoseconds": 110},
            {"ready": True, "synchronized": True, "nanoseconds": 120},
        )
        self.assertEqual(
            harness.verify_clock_log(self.log, require_holdover=True),
            {"samples": 5, "nanoseconds": 120, "holdover": True, "recovered": True},
        )

    def test_invalid_epoch_and_anchor_loss(self) -> None:
        """Reject malformed clock state, backward epochs, and loss of an initialized anchor."""
        for fields in (
            {"ready": True, "synchronized": True, "nanoseconds": 99},
            {"ready": False, "synchronized": False},
            {"ready": True, "synchronized": True, "nanoseconds": -1},
            {"ready": True, "synchronized": True, "nanoseconds": True},
            {"ready": False, "synchronized": False, "nanoseconds": 110},
            {"ready": False, "synchronized": True, "nanoseconds": 110},
            {"ready": True, "nanoseconds": 110},
            {"ready": True, "synchronized": 1, "nanoseconds": 110},
            {"ready": 1, "synchronized": True, "nanoseconds": 110},
            {"ready": True, "synchronized": True},
        ):
            with self.subTest(fields=fields):
                self.records({"ready": True, "synchronized": True, "nanoseconds": 100}, fields)
                with self.assertRaises(RuntimeError):
                    harness.verify_clock_log(self.log)

    def test_missing_holdover_or_recovery_is_not_success(self) -> None:
        """Require both outage holdover and new recovery evidence when the scenario promises them."""
        for samples in (
            ({"ready": False, "synchronized": False},),
            (
                {"ready": True, "synchronized": True, "nanoseconds": 100},
                {"ready": True, "synchronized": True, "nanoseconds": 110},
            ),
            (
                {"ready": True, "synchronized": True, "nanoseconds": 100},
                {"ready": True, "synchronized": False, "nanoseconds": 110},
            ),
            (
                {"ready": True, "synchronized": False, "nanoseconds": 100},
                {"ready": True, "synchronized": False, "nanoseconds": 110},
                {"ready": True, "synchronized": True, "nanoseconds": 120},
            ),
        ):
            with self.subTest(samples=samples):
                self.records(*samples)
                with self.assertRaises(RuntimeError):
                    harness.verify_clock_log(self.log, require_holdover=True)

    def test_sanitizer_diagnostics_cannot_be_ignored_as_non_json(self) -> None:
        """Treat sanitizer diagnostics as failures even though they are not structured service events."""
        for marker in (
            "WARNING: ThreadSanitizer:",
            "ERROR: AddressSanitizer:",
            "ERROR: LeakSanitizer:",
            "runtime error:",
        ):
            with self.subTest(marker=marker):
                self.log.write_text(marker + " injected failure\n", encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "sanitizer"):
                    harness.events(self.log)

    def test_non_json_and_incomplete_lines_do_not_create_events(self) -> None:
        """Ignore unrelated or partial lines without inventing complete service observations."""
        self.records({"ready": True, "synchronized": True, "nanoseconds": 100})
        with self.log.open("a", encoding="utf-8") as output:
            output.write('ordinary diagnostic\n[1,2]\n{"event":')
        self.assertEqual(len(harness.events(self.log)), 1)

    def test_wait_does_not_reuse_an_earlier_synchronized_event(self) -> None:
        """Prevent stale synchronization evidence from satisfying a later recovery wait."""
        self.records(
            {"ready": True, "synchronized": True, "nanoseconds": 100},
            {"ready": True, "synchronized": False, "nanoseconds": 110},
        )
        process = Mock()
        process.poll.return_value = None
        with patch.object(harness.time, "monotonic", side_effect=[0, 0, 1]), patch.object(harness.time, "sleep"):
            with self.assertRaises(TimeoutError):
                harness.wait(
                    process,
                    self.log,
                    lambda record: record["fields"]["synchronized"],
                    seconds=0.5,
                    overall_deadline=100,
                    after=1,
                )

    def test_wait_accepts_new_recovery_event(self) -> None:
        """Accept a synchronization event appended after the recovery phase begins."""
        self.records(
            {"ready": True, "synchronized": False, "nanoseconds": 100},
            {"ready": True, "synchronized": True, "nanoseconds": 110},
        )
        process = Mock()
        process.poll.return_value = None
        with patch.object(harness.time, "monotonic", side_effect=[0, 0]):
            value = harness.wait(
                process,
                self.log,
                lambda record: record["fields"]["synchronized"],
                seconds=0.5,
                overall_deadline=100,
                after=1,
            )
        self.assertEqual(value["fields"]["nanoseconds"], 110)

    def test_failure_keeps_original_error_and_bounded_log_tail(self) -> None:
        """Preserve the primary failure while attaching only a bounded diagnostic tail."""
        self.log.write_text("x" * 20000 + "\nuseful tail\n", encoding="utf-8")
        diagnostic = io.StringIO()
        with redirect_stderr(diagnostic):
            with self.assertRaisesRegex(ValueError, "original failure"):
                with harness.failure_logs(self.log.parent):
                    raise ValueError("original failure")
        self.assertIn("useful tail", diagnostic.getvalue())
        self.assertLess(len(diagnostic.getvalue()), 8300)

    def test_success_retains_complete_logs_after_temporary_cleanup(self) -> None:
        """Keep the full native service output after its temporary process directory disappears."""
        destination = self.log.parent / "evidence"
        with tempfile.TemporaryDirectory(prefix="process-", dir=self.log.parent) as temporary:
            directory = Path(temporary)
            content = "header\n" + "x" * 20000 + "\nfinal state\n"
            (directory / "service.log").write_text(content, encoding="utf-8")
            retained = destination / directory.name / "service.log"
            with patch.dict(harness.os.environ, {"ASTRA_TEST_LOG_DIR": str(destination)}):
                with harness.failure_logs(directory):
                    pass
        self.assertFalse(directory.exists())
        self.assertEqual(retained.read_text(encoding="utf-8"), content)

    def test_failure_retains_complete_logs_and_original_error(self) -> None:
        """Preserve both complete output and the primary failure without expanding console tails."""
        destination = self.log.parent / "evidence"
        content = "header\n" + "x" * 20000 + "\nfinal state\n"
        self.log.write_text(content, encoding="utf-8")
        diagnostic = io.StringIO()
        with patch.dict(harness.os.environ, {"ASTRA_TEST_LOG_DIR": str(destination)}), redirect_stderr(diagnostic):
            with self.assertRaisesRegex(ValueError, "original failure"):
                with harness.failure_logs(self.log.parent):
                    raise ValueError("original failure")
        self.assertEqual((destination / self.log.parent.name / self.log.name).read_text(encoding="utf-8"), content)
        self.assertLess(len(diagnostic.getvalue()), 8300)

    def test_success_cannot_hide_log_collection_failure(self) -> None:
        """A completed test cannot pass when its configured evidence copy fails."""
        self.log.write_text("native output\n", encoding="utf-8")
        destination = self.log.parent / "evidence"
        with (
            patch.dict(harness.os.environ, {"ASTRA_TEST_LOG_DIR": str(destination)}),
            patch.object(harness.shutil, "copyfile", side_effect=OSError("copy failed")),
        ):
            with self.assertRaisesRegex(OSError, "copy failed"):
                with harness.failure_logs(self.log.parent):
                    pass

    def test_collection_failure_does_not_replace_primary_error(self) -> None:
        """Report evidence loss while propagating the original process failure."""
        self.log.write_text("native output\n", encoding="utf-8")
        destination = self.log.parent / "evidence"
        diagnostic = io.StringIO()
        with (
            patch.dict(harness.os.environ, {"ASTRA_TEST_LOG_DIR": str(destination)}),
            patch.object(harness.shutil, "copyfile", side_effect=OSError("copy failed")),
            redirect_stderr(diagnostic),
        ):
            with self.assertRaisesRegex(ValueError, "original failure"):
                with harness.failure_logs(self.log.parent):
                    raise ValueError("original failure")
        self.assertIn("Service log preservation failed: OSError", diagnostic.getvalue())


if __name__ == "__main__":
    unittest.main()
