"""Falsify finite pragma-response evidence; synthetic streams never replace native application receipts."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from tools import settings, verify as v

ROOT = Path(__file__).resolve().parents[1]


def events(rows: list[dict]) -> list[dict]:
    """Build complete synthetic native ownership and terminals for reader controls only."""
    rows = [
        {"Action": "start", "Package": settings.PACKAGE},
        {"Action": "run", "Package": settings.PACKAGE, "Test": "TestConnectionFault"},
        {"Action": "run", "Package": settings.PACKAGE, "Test": settings.TEST},
        *[{"Action": "output", "Package": settings.PACKAGE, "Test": settings.TEST, "Output": "STORAGE-DECISION " + json.dumps(row) + "\n"} for row in rows],
        {"Action": "pass", "Package": settings.PACKAGE, "Test": settings.TEST},
        *[
            event
            for case in settings.CASES[2:]
            for event in ({"Action": "run", "Package": settings.PACKAGE, "Test": case}, {"Action": "pass", "Package": settings.PACKAGE, "Test": case})
        ],
        {
            "Action": "output",
            "Package": settings.PACKAGE,
            "Test": "TestConnectionFault",
            "Output": 'ASTRA-CONTRACT {"contract":"STORAGE-CONNECTION","hits":13}\n',
        },
        {"Action": "pass", "Package": settings.PACKAGE, "Test": "TestConnectionFault"},
        {"Action": "pass", "Package": settings.PACKAGE},
    ]
    return rows


def stream(rows: list[dict]) -> bytes:
    """Keep actual newlines and native fragments rather than serializing a multiline JSON array."""
    return b"".join(json.dumps(row, separators=(",", ":")).encode() + b"\n" for row in rows)


def fixtures() -> list[dict]:
    """Supply model-shaped inputs; the separate axiom test checks their semantic values and effects."""
    return [settings.expected(query) for query in settings.VALUES]


class SettingTests(unittest.TestCase):
    """Preserve complete finite inputs, native operation identity, non-vacuity and single-condition influence."""

    def test_axioms(self) -> None:
        """Every pair changes only its selected predicate and reverses the result without skipped operands."""
        self.assertEqual(settings.VALUES, {"PRAGMA journal_mode": "wal", "PRAGMA synchronous": 2, "PRAGMA foreign_keys": 1, "PRAGMA wal_autocheckpoint": 1000})
        self.assertEqual(settings.CONDITIONS, ["iteration-error", "finalization-error", "wrong-value"])
        for frame in fixtures():
            self.assertEqual(len(frame["rows"]), 4)
            for condition, pair in enumerate(frame["pairs"]):
                first, last = [frame["rows"][index] for index in pair]
                self.assertEqual([i for i in range(3) if first["values"][i] != last["values"][i]], [condition])
                self.assertIs(first["result"], False)
                self.assertIs(last["result"], True)
                self.assertIs(first["input"]["native_step"], True)
                self.assertIs(last["input"]["native_close"], True)
                self.assertEqual(first["input"]["native"], last["input"]["native"])

    def test_receipts(self) -> None:
        """Missing, duplicate, coupled, fabricated, mistyped or differently scoped tuples must be rejected."""
        rows = fixtures()
        self.assertEqual(settings.observations(stream(events(rows)), ROOT)["independent_pairs"], 12)
        self.assertEqual(settings.observations(stream(events(list(reversed(rows)))), ROOT)["receipt_tuples"], 16)
        for altered in ([], rows[:-1], rows + rows[:1]):
            with self.subTest(rows=len(altered)), self.assertRaises(v.Invalid):
                settings.observations(stream(events(altered)), ROOT)
        for key, value in (
            ("query", "unknown"),
            ("point", "both"),
            ("native", None),
            ("value", "wrong"),
            ("next_error", True),
            ("close_error", True),
            ("steps", 0),
            ("closes", True),
            ("native_step", False),
            ("native_close", False),
        ):
            altered = copy.deepcopy(rows)
            altered[0]["rows"][0]["input"][key] = value
            with self.subTest(key=key), self.assertRaises(v.Invalid):
                settings.observations(stream(events(altered)), ROOT)
        for key, value in (("values", [True, True, False]), ("result", True), ("name", "unknown"), ("input", {})):
            altered = copy.deepcopy(rows)
            altered[0]["rows"][0][key] = value
            with self.subTest(key=key), self.assertRaises(v.Invalid):
                settings.observations(stream(events(altered)), ROOT)
        for key, value in (("id", "unknown"), ("conditions", []), ("pairs", [[0, 2]]), ("basis", "self-certified")):
            altered = copy.deepcopy(rows)
            altered[0][key] = value
            with self.subTest(key=key), self.assertRaises(v.Invalid):
                settings.observations(stream(events(altered)), ROOT)

    def test_stream(self) -> None:
        """Failed/skipped/missing terminals, foreign ownership and truncated fragments cannot qualify a witness."""
        original = events(fixtures())
        for index, key, value in ((0, "Package", "foreign"), (3, "Test", "foreign"), (-3, "Action", "fail"), (-3, "Action", "skip"), (-1, "Action", "skip")):
            altered = copy.deepcopy(original)
            altered[index][key] = value
            with self.subTest(index=index, value=value), self.assertRaises(v.Invalid):
                settings.observations(stream(altered), ROOT)
        for altered in (original[:-1], original[:-3], original[1:]):
            with self.subTest(length=len(altered)), self.assertRaises(v.Invalid):
                settings.observations(stream(altered), ROOT)
        fragment = copy.deepcopy(original)
        output = fragment[3]["Output"]
        fragment[3]["Output"] = output[:50]
        fragment.insert(4, {**fragment[3], "Output": output[50:]})
        self.assertEqual(settings.observations(stream(fragment), ROOT)["independent_pairs"], 12)
        del fragment[4]
        with self.assertRaises(v.Invalid):
            settings.observations(stream(fragment), ROOT)

    def test_source(self) -> None:
        """A changed production guard invalidates every tuple even when the printed inputs remain identical."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "polaris/internal/storage/schema.go"
            target.parent.mkdir(parents=True)
            source = v.read(ROOT / "polaris/internal/storage/schema.go")
            target.write_bytes(source)
            self.assertEqual(settings.observations(stream(events(fixtures())), root)["conditions"], 3)
            target.write_bytes(source.replace(b"closed != nil", b"closed == nil", 1))
            with self.assertRaisesRegex(v.Invalid, "settings-source"):
                settings.observations(stream(events(fixtures())), root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
