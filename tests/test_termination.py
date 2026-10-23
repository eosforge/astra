"""Challenge complete close-error attribution and state/resource observations independently of native execution."""

import copy
import json
from pathlib import Path
import unittest

from tools import models, storage_numeric, termination, verify as v

ROOT = Path(__file__).resolve().parents[1]


def configured() -> dict:
    """Read the actual frozen Race command and complete case selection."""
    return next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "storage-termination")


def encoded(rows: list[dict]) -> bytes:
    """Produce parser-control bytes, never an application receipt or fabricated native pass."""
    return b"".join(
        json.dumps(
            {
                "Action": "output",
                "Package": storage_numeric.PACKAGE,
                "Test": "TestTermination/" + str(row["mask"]),
                "Output": "STORAGE-TERMINATION " + json.dumps(row) + "\n",
            }
        ).encode()
        + b"\n"
        for row in rows
    )


class TerminationTests(unittest.TestCase):
    """Preserve the full fault grid; zero exit or another case's observations cannot satisfy it."""

    def test_configuration(self) -> None:
        """Require termination-check configuration and the prescribed 132 observations."""
        self.assertIsNone(models.configuration(configured()))
        for key, value in (("model", "unknown"), ("component", "unknown"), ("package", "unknown"), ("argv", []), ("expected_tests", []), ("probes", [])):
            changed = copy.deepcopy(configured())
            changed[key] = value
            with self.assertRaises(v.Invalid):
                models.configuration(changed)
        self.assertEqual(termination.HITS, 8 * 16 + 4)

    def test_combinations(self) -> None:
        """Require every resource combination exactly once with balanced release and commit state."""
        rows = [{"mask": mask, "opened": [1, 1], "closed": [1, 1], "pools": 0, "feeds": 0, "version": 1, "records": 1} for mask in range(8)]
        self.assertEqual(models.observations(encoded(rows), configured(), ROOT), {"STORAGE-TERMINATION": 132})
        for index in range(8):
            for changed in (rows[:index] + rows[index + 1 :], rows[:index] + [rows[index]] + rows[index:]):
                with self.assertRaises(v.Invalid):
                    models.observations(encoded(changed), configured(), ROOT)
        for key, value in (("closed", [1, 0]), ("opened", [True, 1]), ("pools", 1), ("feeds", 1), ("version", 0), ("records", 0), ("unexpected", 0)):
            changed = copy.deepcopy(rows)
            changed[0][key] = value
            with self.assertRaises(v.Invalid):
                models.observations(encoded(changed), configured(), ROOT)

    def test_stream(self) -> None:
        """Reject malformed termination streams, wrong attribution, and invalid resource masks."""
        raw = encoded([termination.expected(mask) for mask in range(8)])
        for damaged in (
            b"",
            raw[:-20],
            raw.replace(b"TestTermination/0", b"TestTermination/1"),
            raw.replace(storage_numeric.PACKAGE.encode(), b"wrong"),
            raw.replace(b'"Action": "output"', b'"Action": "pass"'),
            raw.replace(b"TestTermination/0", b"TestTermination/8"),
        ):
            with self.assertRaises(v.Invalid):
                models.observations(damaged, configured(), ROOT)
        for mask in (-1, 8, True, "0"):
            with self.assertRaises(v.Invalid):
                termination.expected(mask)
