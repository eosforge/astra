"""Falsify the fixed startup-input oracle using synthetic data; these controls are not native engine receipts."""

import copy
from pathlib import Path
import unittest
from unittest.mock import patch

from tools import storage, verify as v

ROOT = Path(__file__).resolve().parents[1]


class OpeningTests(unittest.TestCase):
    """Keep endpoint grammar, argument identity, source binding and native reached masks independently mandatory."""

    def setUp(self) -> None:
        """Load the labelled synthetic copies without granting them native execution credit."""
        fixture = v.decode(v.read(ROOT / "tests/fixtures/storage-opening.json"))
        self.decision = fixture["decision"]
        self.native = {self.decision["id"]: [(values, result) for values, result in fixture["vectors"]]}
        self.frames = fixture["frames"]

    def receive(self, frames: list[dict] | None = None, *, decision: dict | None = None, native: dict | None = None) -> list[dict]:
        """Separate the pure input witness algorithm from the independently checked log/manifest reader."""
        selected = self.decision if decision is None else decision
        with (
            patch.object(storage.logic, "inventory", return_value={selected["id"]: selected}),
            patch.object(storage.logic, "observe", return_value=(self.native if native is None else native, {})),
        ):
            return storage.opening({}, b"", self.frames if frames is None else frames)

    def test_pairs(self) -> None:
        """Nine total-input effects hold every other predicate fixed; parse-error coupling gets no credit."""
        pairs = self.receive()
        self.assertEqual(len(pairs), 9)
        self.assertEqual({pair["condition"] for pair in pairs}, {0, 1, 2, 4, 5, 6, 7, 8, 9})
        self.assertNotIn(3, {pair["condition"] for pair in pairs})
        for pair in pairs:
            self.assertEqual(pair["criterion"], "total-input-single-condition-v1")
            self.assertNotEqual(pair["before"]["result"], pair["after"]["result"])
            self.assertEqual(
                [index for index, (first, last) in enumerate(zip(pair["before"]["values"], pair["after"]["values"], strict=True)) if first != last],
                [pair["condition"]],
            )
            self.assertEqual(pair["inputs_sha256"], v.digest(v.encode(self.frames)))
            self.assertEqual(pair["cases"][0], "valid")

    def test_arguments(self) -> None:
        """Labels cannot substitute for exact, ordered arguments, strict integer types or real filesystem outcomes."""
        for index in range(len(self.frames)):
            for field in ("name", "input", "refused", "filesystem", "extra"):
                changed = copy.deepcopy(self.frames)
                changed[index][field] = "unreported"
                with self.subTest(index=index, field=field), self.assertRaises(v.Invalid):
                    self.receive(changed)
        for changed in ([], self.frames[:-1], self.frames + [self.frames[-1]], list(reversed(self.frames))):
            with self.subTest(length=len(changed)), self.assertRaises(v.Invalid):
                self.receive(changed)
        for field in self.frames[0]["input"]["limits"]:
            for value in (True, float(self.frames[0]["input"]["limits"][field]), None):
                changed = copy.deepcopy(self.frames)
                changed[0]["input"]["limits"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(v.Invalid):
                    self.receive(changed)
        for index in (0, 1):
            for value in (True, False, -1):
                changed = copy.deepcopy(self.frames)
                changed[index]["filesystem"] = value
                with self.subTest(index=index, value=value), self.assertRaises(v.Invalid):
                    self.receive(changed)
        for index in (0, 1):
            changed = copy.deepcopy(self.frames)
            changed[index]["refused"] = not changed[index]["refused"]
            with self.subTest(index=index), self.assertRaises(v.Invalid):
                self.receive(changed)
        changed = copy.deepcopy(self.frames)
        changed[0]["filesystem"] = 0
        with self.assertRaises(v.Invalid):
            self.receive(changed)
        changed = copy.deepcopy(self.frames)
        changed[1]["filesystem"] = 1
        with self.assertRaises(v.Invalid):
            self.receive(changed)

    def test_paths(self) -> None:
        """Relative, escaping, wrong-basename, foreign-host and unencodable paths cannot masquerade as owned fixture inputs."""
        for value in (
            "",
            "database",
            "../database",
            "/fixture/../database",
            "/fixture/other",
            "C:\\fixture\\database",
            "/fixture:other/database",
            None,
            "/fixture/\ud800/database",
        ):
            changed = copy.deepcopy(self.frames)
            changed[0]["input"]["path"] = value
            with self.subTest(value=value), self.assertRaises(v.Invalid):
                self.receive(changed)
        changed = copy.deepcopy(self.frames)
        changed[-1]["input"]["path"] = "/fixture/database"
        with self.assertRaises(v.Invalid):
            self.receive(changed)

    def test_native(self) -> None:
        """Every actual reached mask and unchanged source expression remains required even for an uncredited input."""
        for vector in self.native[self.decision["id"]]:
            changed = {self.decision["id"]: [item for item in self.native[self.decision["id"]] if item != vector]}
            with self.subTest(vector=vector), self.assertRaises(v.Invalid):
                self.receive(native=changed)
        with self.assertRaises(v.Invalid):
            self.receive(native={self.decision["id"]: []})
        changed = copy.deepcopy(self.decision)
        changed["text"] += " || true"
        with self.assertRaisesRegex(v.Invalid, "storage-open-source-decision"):
            self.receive(decision=changed)
        changed = copy.deepcopy(self.decision)
        changed["id"] = "foreign/source:0"
        with self.assertRaisesRegex(v.Invalid, "storage-open-source-decision"):
            self.receive(decision=changed)


if __name__ == "__main__":
    unittest.main()
