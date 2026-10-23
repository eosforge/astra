"""Falsify native identity-file matrix acceptance without passing fabricated logs as execution evidence."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import admission, faults, materials, verify as v

ROOT = Path(__file__).resolve().parents[1]


def pack(value: dict) -> bytes:
    """Encode a single-line native event without the evidence file formatter's indentation."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def configured() -> dict:
    """Read the actual complete Admission capability rather than a reduced test-only registration."""
    return next(c for c in v.decode(v.read(ROOT / "development.json"))["checks"] if c["id"] == "admission-model")


def encode(rows: list[dict], *, name: str = "TestLoadFault", package: str | None = None) -> bytes:
    """Build explicitly synthetic native-shaped frames solely for parser rejection controls."""
    package = package or configured()["package"]
    return b"".join(
        pack({"Action": "output", "Package": package, "Test": name, "Output": "file_test.go:1: ADMISSION-IDENTITY-FAULT " + pack(row).decode() + "\n"}) + b"\n"
        for row in rows
    )


def matrix() -> list[dict]:
    """Provide all declared cells for negative parser transformations, independently anchored by the axioms below."""
    return [materials.expected(fault, slot, phase) for fault in materials.FAULTS for slot in range(5) for phase in range(3)]


class MaterialTests(unittest.TestCase):
    """Verify configuration, independent ownership axioms and resistance to false positive matrices."""

    def test_refresh(self) -> None:
        """A changed refresh scope, omitted phase or falsely recovered replacement must never qualify."""
        check = next(c for c in v.decode(v.read(ROOT / "development.json"))["checks"] if c["id"] == "admission-refresh-faults")
        faults.configuration(check)
        for field, value in (
            ("argv", check["argv"][:-2] + check["argv"][-1:]),
            ("expected_tests", []),
            ("component", "other"),
            ("package", "other"),
            ("probes", [{"contract": "ADMISSION-NODE-REFRESH", "test": "TestRefreshFaults", "minimum_hits": 105}]),
        ):
            other = copy.deepcopy(check)
            other[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "refresh-configuration"):
                faults.configuration(other)
        rows = []
        # Independent literal outcomes: replacement never recovers; metadata refusal never enters List.
        for scenario, (codes, calls) in enumerate(
            (([14, 14, 0], [1, 2, 3]), ([16, 16, 0], [1, 2, 3]), ([2, 2, 0], [1, 2, 3]), ([16, 16, 16], [1, 2, 3]), ([2, 2, 0], [0, 0, 1]))
        ):
            for phase, (code, count) in enumerate(zip(codes, calls, strict=True)):
                rows.append(
                    {
                        "scenario": scenario,
                        "phase": phase,
                        "code": code,
                        "calls": count,
                        "permits": 0,
                        "member": True,
                        "hello": True,
                        "request": True,
                        "directory": True,
                    }
                )

        def stream(values: list[dict]) -> bytes:
            """Encode parser-only fixtures; these synthetic values are never native acceptance evidence."""
            return b"".join(
                pack(
                    {
                        "Action": "output",
                        "Package": check["package"],
                        "Test": "TestRefreshFaults",
                        "Output": "fixture.go:1: ADMISSION-REFRESH-FAULT " + pack(row).decode() + "\n",
                    }
                )
                + b"\n"
                for row in values
            )

        data = stream(rows)
        self.assertEqual(faults.observations(data, check, ROOT), {"ADMISSION-NODE-REFRESH": 106})
        for index, row in enumerate(rows):
            with self.subTest(missing=index), self.assertRaisesRegex(v.Invalid, "refresh-matrix"):
                faults.observations(stream(rows[:index] + rows[index + 1 :]), check, ROOT)
            for field in row:
                other = copy.deepcopy(rows)
                other[index][field] = False if type(row[field]) is bool else row[field] + 1
                with self.subTest(row=index, field=field), self.assertRaisesRegex(v.Invalid, "refresh-matrix"):
                    faults.observations(stream(other), check, ROOT)
        for values in ([], rows + rows[-1:], list(reversed(rows)), [{**rows[0], "extra": True}, *rows[1:]], [{**rows[0], "permits": False}, *rows[1:]]):
            with self.assertRaisesRegex(v.Invalid, "refresh-matrix"):
                faults.observations(stream(values), check, ROOT)
        with self.assertRaisesRegex(v.Invalid, "material-test-identity"):
            faults.observations(data.replace(b"TestRefreshFaults", b"TestOther"), check, ROOT)
        with self.assertRaisesRegex(v.Invalid, "material-stream-tail"):
            faults.observations(
                data + pack({"Action": "output", "Package": check["package"], "Test": "TestRefreshFaults", "Output": "ADMISSION-REFRESH-FAULT {"}) + b"\n",
                check,
                ROOT,
            )
        with patch("tools.admission.matches", return_value=False), self.assertRaisesRegex(v.Invalid, "refresh-source"):
            faults.observations(data, check, ROOT)
        digest = v.file_digest
        with (
            patch.object(v, "file_digest", side_effect=lambda p: "0" * 64 if p.name.endswith(".go.in") else digest(p)),
            self.assertRaisesRegex(v.Invalid, "refresh-fixture"),
        ):
            faults.observations(data, check, ROOT)

    def test_configuration(self) -> None:
        """Filters, capability substitution, absent or duplicate tests and dishonest counters are rejected."""
        check = configured()
        faults.configuration(check)
        for name in check["expected_tests"]:
            changed = copy.deepcopy(check)
            changed["expected_tests"].remove(name)
            with self.subTest(missing=name), self.assertRaisesRegex(v.Invalid, "material-configuration"):
                faults.configuration(changed)
        for key, value in (
            ("faults", "other"),
            ("component", "other"),
            ("package", "other"),
            ("argv", check["argv"] + ["-run=TestLoadFault"]),
            ("expected_tests", check["expected_tests"][:-1]),
            ("expected_tests", check["expected_tests"] + ["TestLoadFault"]),
            ("expected_tests", check["expected_tests"] + ["TestUnregistered"]),
            ("probes", [probe for probe in check["probes"] if probe["contract"] != "ADMISSION-IDENTITY-FAULT"]),
        ):
            changed = copy.deepcopy(check)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(v.Invalid):
                faults.configuration(changed)
        for count in (1500, 0, True, 1501.0):
            changed = copy.deepcopy(check)
            next(p for p in changed["probes"] if p["contract"] == "ADMISSION-IDENTITY-FAULT")["minimum_hits"] = count
            with self.subTest(count=count), self.assertRaisesRegex(v.Invalid, "material-configuration"):
                materials.configuration(changed)
        for probe in check["probes"]:
            if probe["test"] not in materials.ACQUISITION:
                continue
            for action in ("missing", "duplicate", "reduced", "float"):
                changed = copy.deepcopy(check)
                selected = next(p for p in changed["probes"] if p["test"] == probe["test"])
                if action == "missing":
                    changed["probes"].remove(selected)
                elif action == "duplicate":
                    changed["probes"].append(copy.deepcopy(selected))
                else:
                    selected["minimum_hits"] = float(selected["minimum_hits"]) if action == "float" else selected["minimum_hits"] - 1
                with self.subTest(test=probe["test"], action=action), self.assertRaisesRegex(v.Invalid, "material-acquisition-probes"):
                    materials.configuration(changed)

    def test_axioms(self) -> None:
        """Pre-open refusal owns no selected handle; post-open refusal must close it; recovery reads every slot."""
        self.assertEqual(materials.FAULTS, ("lstat", "nonregular", "open", "stat", "restat", "read", "partial", "close"))
        for slot in range(5):
            for phase in (0, 1):
                for fault in materials.FAULTS:
                    row = materials.expected(fault, slot, phase)
                    self.assertEqual(row["inspected"], slot + 1)
                    self.assertEqual(row["attempted"], slot if fault in ("lstat", "nonregular") else slot + 1)
                    self.assertEqual(row["opened"], slot if fault in ("lstat", "nonregular", "open") else slot + 1)
                    self.assertEqual(row["closed"], row["opened"])
                    self.assertEqual(row["result"], "rejected")
            for fault in materials.FAULTS:
                row = materials.expected(fault, slot, 2)
                self.assertEqual([row[name] for name in ("inspected", "attempted", "opened", "closed")], [5, 5, 5, 5])
                self.assertEqual(row["result"], "loaded")
        self.assertEqual(len(matrix()), 120)
        self.assertEqual(1 + sum(2 + row["inspected"] + 2 * row["opened"] for row in matrix()), 1501)

    def test_matrix(self) -> None:
        """Every field, cell identity and ordering matters; one summary or repeated row cannot stand for the matrix."""
        check, rows = configured(), matrix()
        self.assertEqual(faults.observations(encode(rows), check, ROOT), {"ADMISSION-IDENTITY-FAULT": 1531})
        for forged in ([], rows[:-1], rows + [rows[0]], list(reversed(rows)), rows[:1]):
            with self.subTest(size=len(forged)), self.assertRaisesRegex(v.Invalid, "material-matrix"):
                materials.observations(encode(forged), check, ROOT)
        for field, value in (
            ("fault", "unknown"),
            ("slot", True),
            ("phase", 2),
            ("inspected", 5),
            ("attempted", 1),
            ("opened", 1),
            ("closed", 1),
            ("result", "loaded"),
            ("extra", 0),
        ):
            forged = copy.deepcopy(rows)
            forged[0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "material-matrix"):
                materials.observations(encode(forged), check, ROOT)
        for field in rows[0]:
            forged = copy.deepcopy(rows)
            del forged[0][field]
            with self.subTest(missing=field), self.assertRaisesRegex(v.Invalid, "material-matrix"):
                materials.observations(encode(forged), check, ROOT)

    def test_stream(self) -> None:
        """Misattributed, truncated, malformed and oversized native-shaped streams are rejected."""
        check = configured()
        partial = [v.decode(line) for line in encode(matrix()).splitlines()]
        partial[-1]["Output"] = partial[-1]["Output"].removesuffix("\n")
        tail = b"".join(pack(event) + b"\n" for event in partial)
        for raw, reason in (
            (encode(matrix(), name="TestIdentity"), "material-test-identity"),
            (encode(matrix(), package="forged"), "material-test-identity"),
            (tail, "material-stream-tail"),
            (pack({"Action": "output", "Test": "TestLoadFault", "Output": 5}) + b"\n", "material-output-shape"),
            (pack({"Action": "output", "Test": "TestLoadFault", "Output": "x" * 65537}) + b"\n", "material-line-budget"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex((v.Invalid, json.JSONDecodeError), reason):
                materials.observations(raw, check, ROOT)

    def test_source(self) -> None:
        """A changed production boundary cannot inherit this frozen matrix qualification."""
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for relative in admission.MATERIAL:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / relative).read_bytes())
            self.assertEqual(materials.observations(encode(matrix()), configured(), root), {"ADMISSION-IDENTITY-FAULT": 1531})
            for relative in admission.MATERIAL:
                path = root / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.subTest(changed=relative), self.assertRaisesRegex(v.Invalid, "material-source"):
                    materials.observations(encode(matrix()), configured(), root)
                path.unlink()
                if not relative.endswith("identity.go"):
                    with self.subTest(missing=relative), self.assertRaisesRegex(v.Invalid, "material-source"):
                        materials.observations(encode(matrix()), configured(), root)
                path.write_bytes(original)
