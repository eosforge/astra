"""Falsify the finite member-equality interpreter; synthetic frames are never native application evidence."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from tools import equality, verify as v

ROOT = Path(__file__).resolve().parents[1]


def pack(value: dict) -> bytes:
    """Encode one compact native-shaped event for parser controls only."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def configured() -> dict:
    """Read the registered finite decision capability without weakening its native selection."""
    return next(c for c in v.decode(v.read(ROOT / "development.json"))["checks"] if c["id"] == "admission-same")


def encode(rows: list[dict], *, name: str = "TestSame", package: str | None = None) -> bytes:
    """Frame synthetic observations with explicit test/package ownership."""
    return b"".join(
        pack(
            {
                "Action": "output",
                "Package": package or configured()["package"],
                "Test": name,
                "Output": "decisions_test.go:1: ADMISSION-SAME " + pack(row).decode() + "\n",
            }
        )
        + b"\n"
        for row in rows
    )


def pairs() -> list[dict]:
    """Supply parser fixtures whose independent semantic anchors are checked separately."""
    return [equality.expected(condition) for condition in range(9)]


class EqualityTests(unittest.TestCase):
    """Keep scope, input independence, complete pairs, native framing and frozen source binding explicit."""

    def test_configuration(self) -> None:
        """Selection, capability and hit denominators cannot be relaxed by configuration edits."""
        check = configured()
        equality.configuration(check)
        for key, value in (
            ("decisions", "unknown"),
            ("component", "unknown"),
            ("package", "unknown"),
            ("argv", check["argv"] + ["-short"]),
            ("expected_tests", []),
            ("expected_tests", ["TestSame", "TestSame"]),
            ("probes", []),
        ):
            changed = copy.deepcopy(check)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(v.Invalid):
                equality.configuration(changed)
        for count in (0, 17, True, 18.0):
            changed = copy.deepcopy(check)
            changed["probes"][0]["minimum_hits"] = count
            with self.subTest(count=count), self.assertRaisesRegex(v.Invalid, "equality-configuration"):
                equality.configuration(changed)

    def test_axioms(self) -> None:
        """Each actual input pair changes one nullable operand or field and reverses the required equality result."""
        fields = ("galaxy", "id", "principal", "advertise", "epoch", "role", "group")
        self.assertEqual(equality.FIELDS, fields)
        self.assertEqual(set(equality.member()), set(fields))
        for condition, row in enumerate(pairs()):
            before, after = row["before"], row["after"]
            self.assertIs(before["result"], True)
            self.assertIs(after["result"], False)
            self.assertEqual(before["a"], before["b"])
            if condition < 2:
                selected, other = ("a", "b") if condition == 0 else ("b", "a")
                self.assertIsNone(after[selected])
                self.assertEqual(after[other], before[other])
            else:
                self.assertEqual(after["a"], before["a"])
                self.assertEqual([field for field in fields if before["b"][field] != after["b"][field]], [fields[condition - 2]])
        self.assertEqual([pairs()[i]["after"]["b"][fields[i - 2]] for i in (2, 3, 5, 6, 7, 8)], ["beta", "b3RoZXI=", "127.0.0.1:7444", 2, 3, "other"])
        self.assertEqual(len(pairs()), 9)

    def test_pairs(self) -> None:
        """Absent, duplicated, reordered or modified semantic observations must never pass the pair oracle."""
        rows, check = pairs(), configured()
        self.assertEqual(equality.observations(encode(rows), check, ROOT), {"ADMISSION-SAME": 18})
        for forged in ([], rows[:-1], rows + [rows[0]], list(reversed(rows)), rows[:1]):
            with self.subTest(size=len(forged)), self.assertRaises(v.Invalid):
                equality.observations(encode(forged), check, ROOT)
        for path, value in (
            (("case",), True),
            (("case",), 0.0),
            (("extra",), 0),
            (("before", "result"), False),
            (("before", "result"), 1),
            (("after", "result"), True),
            (("after", "a"), equality.member()),
            (("before", "b", "epoch"), 2),
            (("after", "b", "group"), "changed"),
        ):
            forged = copy.deepcopy(rows)
            target = forged[0]
            for field in path[:-1]:
                target = target[field]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaisesRegex(v.Invalid, "equality-pairs"):
                equality.observations(encode(forged), check, ROOT)
        for field in rows[0]:
            forged = copy.deepcopy(rows)
            del forged[0][field]
            with self.subTest(missing=field), self.assertRaisesRegex(v.Invalid, "equality-pairs"):
                equality.observations(encode(forged), check, ROOT)

    def test_stream(self) -> None:
        """Accept split native output while rejecting foreign ownership, truncation and malformed frames."""
        rows, check = pairs(), configured()
        events = [v.decode(line) for line in encode(rows).splitlines()]
        split = []
        for event in events:
            output = event["Output"]
            split.extend([{**event, "Output": output[:29]}, {**event, "Output": output[29:]}])
        self.assertEqual(equality.observations(b"".join(pack(event) + b"\n" for event in split), check, ROOT), {"ADMISSION-SAME": 18})
        events[-1]["Output"] = events[-1]["Output"].rstrip("\n")
        for raw, reason in (
            (encode(rows, name="Other"), "equality-test"),
            (encode(rows, package="Other"), "equality-package"),
            (b"".join(pack(event) + b"\n" for event in events), "equality-truncated"),
            (pack({"Package": check["package"], "Action": "output", "Test": [], "Output": ""}), "equality-output"),
            (pack({"Package": check["package"], "Action": "output", "Output": 3}), "equality-output"),
            (pack({"Package": check["package"], "Action": "output", "Output": "x" * 65537}), "equality-line-budget"),
            (b"[]", "equality-package"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(v.Invalid, reason):
                equality.observations(raw, check, ROOT)

    def test_source(self) -> None:
        """Identical pairs cannot qualify changed production predicates or a missing frozen source."""
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = root / "internal/admission/directory.go"
            path.parent.mkdir(parents=True)
            path.write_bytes((ROOT / "internal/admission/directory.go").read_bytes())
            self.assertEqual(equality.observations(encode(pairs()), configured(), root), {"ADMISSION-SAME": 18})
            path.write_bytes(path.read_bytes() + b"\n")
            with self.assertRaisesRegex(v.Invalid, "equality-source"):
                equality.observations(encode(pairs()), configured(), root)
