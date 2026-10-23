"""Challenge native lifecycle transcript attribution, complete outcomes and immutable production scope."""

import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tools import lifecycle, models, storage_numeric, verify as v

ROOT = Path(__file__).resolve().parents[1]


def configured() -> dict:
    """Read the frozen actual Race selection and all declared cases."""
    return next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "storage-lifecycle")


def encoded(rows: list[dict]) -> bytes:
    """Build parser-control output only, never a native process or package-success receipt."""
    return b"".join(
        json.dumps(
            {
                "Action": "output",
                "Package": storage_numeric.PACKAGE,
                "Test": "TestLifecycle/" + row["mode"],
                "Output": "STORAGE-LIFETIME " + json.dumps(row) + "\n",
            }
        ).encode()
        + b"\n"
        for row in rows
    )


class LifecycleTests(unittest.TestCase):
    """Require every controlled close boundary and reject forged drain/commit observations."""

    def test_configuration(self) -> None:
        """Require lifecycle configuration and the source proof for the supported storage revision."""
        self.assertIsNone(models.configuration(configured()))
        for key, value in (("model", "unknown"), ("component", "unknown"), ("package", "unknown"), ("argv", []), ("expected_tests", []), ("probes", [])):
            changed = copy.deepcopy(configured())
            changed[key] = value
            with self.assertRaises(v.Invalid):
                models.configuration(changed)
        proof = lifecycle.proof(ROOT)
        self.assertEqual(len(proof["sources"]), 11 if storage_numeric.revision(ROOT)[0] == 884 else 10)
        if "maintenance.go" in proof["sources"]:
            self.assertIn("cancels and joins its sole maintenance task", proof["drain"])

    def test_histories(self) -> None:
        """Require each lifecycle mode exactly once with its prescribed drain and commit outcome."""
        rows = [
            {"mode": "commit", "late": 3, "queued_cancelled": True, "drained": True, "version": 1, "records": 2},
            {"mode": "cancel", "late": 3, "queued_cancelled": True, "drained": True, "version": 0, "records": 0},
            {"mode": "feed", "late": 0, "queued_cancelled": False, "drained": True, "version": 0, "records": 0},
        ]
        self.assertEqual(models.observations(encoded(rows), configured(), ROOT), {"STORAGE-LIFETIME": 58})
        for index in range(len(rows)):
            for changed in (rows[:index] + rows[index + 1 :], rows[:index] + [rows[index]] + rows[index:]):
                with self.assertRaises(v.Invalid):
                    models.observations(encoded(changed), configured(), ROOT)
        for index, key, value in (
            (0, "late", 2),
            (0, "records", 1),
            (0, "version", True),
            (1, "version", 1),
            (1, "records", 1),
            (1, "queued_cancelled", False),
            (2, "drained", False),
            (2, "queued_cancelled", 0),
        ):
            changed = copy.deepcopy(rows)
            changed[index][key] = value
            with self.assertRaises(v.Invalid):
                models.observations(encoded(changed), configured(), ROOT)

    def test_stream(self) -> None:
        """Reject incomplete lifecycle streams and observations with incorrect attribution."""
        raw = encoded([lifecycle.expected(mode) for mode in ("commit", "cancel", "feed")])
        for damaged in (b"", raw[:-20], raw.replace(b"TestLifecycle/commit", b"TestLifecycle/feed"), raw.replace(storage_numeric.PACKAGE.encode(), b"wrong")):
            with self.assertRaises(v.Invalid):
                models.observations(damaged, configured(), ROOT)

    def test_source(self) -> None:
        """Reject a lifecycle source proof after any protected source changes."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / storage_numeric.DIRECTORY
            directory.mkdir(parents=True)
            for name in ["numeric.json", *storage_numeric.manifest(ROOT)["sources"]]:
                shutil.copyfile(ROOT / storage_numeric.DIRECTORY / name, directory / name)
            self.assertEqual(lifecycle.proof(root)["sources"], lifecycle.proof(ROOT)["sources"])
            for name in storage_numeric.manifest(ROOT)["sources"]:
                path = directory / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n// changed\n")
                with self.assertRaises(v.Invalid):
                    lifecycle.proof(root)
                path.write_bytes(original)
