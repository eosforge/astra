"""Falsify native cancellation-drain attribution, complete case selection and resource-release evidence."""

import copy
import json
from pathlib import Path
import unittest

from tools import draining, models, storage_numeric, verify as v

ROOT = Path(__file__).resolve().parents[1]


def configured() -> dict:
    """Read the actual current native selection rather than an invented permissive control configuration."""
    return next(check for check in v.decode(v.read(ROOT / "development.json"))["checks"] if check["id"] == "storage-draining")


def encoded(mode: str) -> bytes:
    """Build parser-control output only; this is never a native process or package-pass receipt."""
    return (
        json.dumps(
            {
                "Action": "output",
                "Package": storage_numeric.PACKAGE,
                "Test": "TestDraining/" + mode,
                "Output": "STORAGE-DRAINED mode=" + mode + " rollback=1 in_use=0 writer=0 opened=1 closed=1\n",
            }
        ).encode()
        + b"\n"
    )


def borrow(owner: str, fault: str) -> bytes:
    """Emit synthetic parser input; native pass status and counters are validated separately by the runner."""
    return (
        v.encode(
            {
                "Action": "output",
                "Package": storage_numeric.PACKAGE,
                "Test": "TestBorrowing/" + owner + "/" + fault,
                "Output": "STORAGE-BORROWING owner=" + owner + " fault=" + fault + " entered=0 in_use=0 published=0 version=1 records=1\n",
            }
        ).replace(b"\n", b"")
        + b"\n"
    )


class DrainingTests(unittest.TestCase):
    """Require both reached rollback histories and reject invented native cleanup."""

    def test_configuration(self) -> None:
        """Reject incomplete drain-check configuration and preserve the required two observations."""
        self.assertIsNone(models.configuration(configured()))
        for key, value in (("model", "unknown"), ("component", "unknown"), ("package", "unknown"), ("argv", []), ("expected_tests", []), ("probes", [])):
            changed = copy.deepcopy(configured())
            changed[key] = value
            with self.assertRaises(v.Invalid):
                models.configuration(changed)
        self.assertEqual(draining.HITS, 2)

    def test_histories(self) -> None:
        """Require both drain histories, rollback, and release of every opened resource."""
        raw = encoded("write") + encoded("read")
        self.assertEqual(models.observations(raw, configured(), ROOT), {"STORAGE-DRAINING": 2})
        for damaged in (b"", encoded("write"), encoded("read"), raw + encoded("write"), raw[:-20]):
            with self.assertRaises(v.Invalid):
                models.observations(damaged, configured(), ROOT)
        for old, new in (
            (b"rollback=1", b"rollback=0"),
            (b"in_use=0", b"in_use=1"),
            (b"writer=0", b"writer=1"),
            (b"closed=1", b"closed=0"),
            (b"opened=1", b"opened=2"),
        ):
            with self.assertRaises(v.Invalid):
                models.observations(raw.replace(old, new), configured(), ROOT)

    def test_attribution(self) -> None:
        """Reject observations attributed to the wrong test, package, action, or drain mode."""
        raw = encoded("write") + encoded("read")
        for old, new in (
            (b"TestDraining/write", b"TestDraining/read"),
            (storage_numeric.PACKAGE.encode(), b"wrong"),
            (b'"Action": "output"', b'"Action": "pass"'),
            (b"mode=write", b"mode=read"),
        ):
            with self.assertRaises(v.Invalid):
                models.observations(raw.replace(old, new), configured(), ROOT)


class BorrowingTests(unittest.TestCase):
    """Falsify complete connection-owner/fault coverage and unchanged persistent state after rejected admission."""

    def configured(self) -> dict:
        """Use the actual declared native acquisition-refusal check."""
        return next(check for check in v.decode(v.read(ROOT / "development.json"))["checks"] if check["id"] == "storage-borrowing")

    def test_configuration(self) -> None:
        """Reject altered selections or weakened non-vacuity budgets."""
        self.assertIsNone(models.configuration(self.configured()))
        for key, value in (("model", "unknown"), ("component", "unknown"), ("package", "unknown"), ("argv", []), ("expected_tests", []), ("probes", [])):
            changed = copy.deepcopy(self.configured())
            changed[key] = value
            with self.assertRaises(v.Invalid):
                models.configuration(changed)
        self.assertEqual(len(draining.BORROWS), 9)

    def test_histories(self) -> None:
        """Require each real ownership/refusal pair and its complete durable recovery witness."""
        rows = [borrow(owner, fault) for owner, fault in draining.BORROWS]
        raw = b"".join(rows)
        self.assertEqual(models.observations(raw, self.configured(), ROOT), {"STORAGE-BORROWING": 9})
        for damaged in (b"", raw + rows[0], raw[:-20], *(b"".join(rows[:index] + rows[index + 1 :]) for index in range(len(rows)))):
            with self.assertRaises(v.Invalid):
                models.observations(damaged, self.configured(), ROOT)
        for old, new in (
            (b"entered=0", b"entered=1"),
            (b"in_use=0", b"in_use=1"),
            (b"published=0", b"published=1"),
            (b"version=1", b"version=0"),
            (b"records=1", b"records=0"),
        ):
            with self.assertRaises(v.Invalid):
                models.observations(raw.replace(old, new), self.configured(), ROOT)

    def test_attribution(self) -> None:
        """Reject cross-case, false package/action and owner/fault substitution."""
        raw = b"".join(borrow(owner, fault) for owner, fault in draining.BORROWS)
        for old, new in (
            (b"TestBorrowing/write/closed", b"TestBorrowing/read/closed"),
            (storage_numeric.PACKAGE.encode(), b"wrong"),
            (b'"Action": "output"', b'"Action": "pass"'),
            (b"owner=write", b"owner=read"),
            (b"fault=closed", b"fault=cancelled"),
        ):
            with self.assertRaises(v.Invalid):
                models.observations(raw.replace(old, new), self.configured(), ROOT)
