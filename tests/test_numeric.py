"""Challenge integer derivations, complete native witnesses and non-vacuous numerical qualification."""

import copy
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from tools import admission, numeric, verify as v

ROOT = Path(__file__).resolve().parents[1]


def configured() -> dict:
    """Read the registered capability; synthetic rows below are only parser controls."""
    return next(c for c in v.decode(v.read(ROOT / "development.json"))["checks"] if c["id"] == "admission-numeric")


def encode(rows: list[dict]) -> bytes:
    """Encode synthetic output without manufacturing a native command or pass receipt."""
    return b"".join(
        json.dumps(
            {"Action": "output", "Package": configured()["package"], "Test": "TestNumeric", "Output": "ADMISSION-NUMERIC " + json.dumps(row) + "\n"}
        ).encode()
        + b"\n"
        for row in rows
    )


class NumericTests(unittest.TestCase):
    """Keep whole-rule dependency composition distinct from actual native boundary observations."""

    def test_configuration(self) -> None:
        """Reject altered algorithms, selection, scope, probes and numeric counter types."""
        check = configured()
        numeric.configuration(check)
        for key, value in (("numeric", "unknown"), ("component", "unknown"), ("package", "unknown"), ("argv", []), ("expected_tests", []), ("probes", [])):
            altered = copy.deepcopy(check)
            altered[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(v.Invalid, "numeric-configuration"):
                numeric.configuration(altered)
        for count in (0, 1045, True, 1046.0):
            altered = copy.deepcopy(check)
            altered["probes"][0]["minimum_hits"] = count
            with self.subTest(count=count), self.assertRaisesRegex(v.Invalid, "numeric-configuration"):
                numeric.configuration(altered)

    def test_axioms(self) -> None:
        """Literal interval endpoints and every unsigned epoch transition anchor the independent derivation."""
        bounds = numeric.bounds(ROOT)
        self.assertEqual(bounds["floating_operations"], 0)
        self.assertEqual((bounds["int_bits"], bounds["epoch_bits"], bounds["duration_bits"]), (64, 64, 64))
        self.assertEqual(
            (bounds["maximum_members"], bounds["maximum_material_bytes"], bounds["frame_bytes"], bounds["outgoing_bytes"]), (16384, 81920, 8388608, 4096)
        )
        delays = bounds["delays"]
        self.assertEqual(len(delays), 9)
        self.assertEqual(delays[0], {"delay_ns": 500000000, "doubled_ns": 1000000000, "random_exclusive": 100000001, "wait_max_ns": 600000000})
        self.assertEqual(delays[-1], {"delay_ns": 120000000000, "doubled_ns": 240000000000, "random_exclusive": 24000000001, "wait_max_ns": 144000000000})
        for row in delays:
            self.assertLess(row["wait_max_ns"], 9223372036854775807)
            self.assertGreater(row["random_exclusive"], 0)
        rows = [row["value"] for row in numeric.expected()]
        self.assertEqual(len(rows), 225)
        epochs = [row for row in rows if row["kind"] == "epoch"]
        self.assertEqual(len(epochs), 200)
        self.assertEqual(
            {row["old"] for row in epochs},
            {1, 2, 2147483647, 2147483648, 4294967295, 4294967296, 9223372036854775807, 9223372036854775808, 18446744073709551614, 18446744073709551615},
        )
        for row in epochs:
            self.assertEqual(row["epoch"], max(row["old"], row["next"]))
            self.assertIs(row["accepted"], row["install"] or row["next"] >= row["old"])
            self.assertIs(row["current"], row["next"] >= row["old"])
        self.assertEqual(numeric.HITS, 3 + 7 * 2 + 200 * 5 + 3 + 4 + 2 * 3 + 8 * 2)

    def test_witnesses(self) -> None:
        """Missing, reordered, duplicated and type-forged records cannot pass through marker totals."""
        rows, check = numeric.expected(), configured()
        self.assertEqual(numeric.observations(encode(rows), check, ROOT), {"ADMISSION-NUMERIC": 1046})
        for altered in ([], rows[:-1], rows + [rows[0]], list(reversed(rows))):
            with self.assertRaises(v.Invalid):
                numeric.observations(encode(altered), check, ROOT)
        for value in (False, 64.0, 32, "64"):
            altered = copy.deepcopy(rows)
            altered[0]["value"]["int"] = value
            with self.assertRaisesRegex(v.Invalid, "numeric-witnesses"):
                numeric.observations(encode(altered), check, ROOT)
        for field, value in (("accepted", True), ("epoch", 1), ("next", 18446744073709551616)):
            altered = copy.deepcopy(rows)
            row = next(r["value"] for r in altered if r["value"].get("old") == 18446744073709551615 and r["value"].get("next") == 1)
            row[field] = value
            with self.assertRaisesRegex(v.Invalid, "numeric-witnesses"):
                numeric.observations(encode(altered), check, ROOT)

    def test_stream(self) -> None:
        """Fragmentation preserves records; foreign owners, truncation, overflow and repeated markers fail."""
        check = configured()
        events = [v.decode(line) for line in encode(numeric.expected()).splitlines()]
        split = []
        for event in events:
            output = event["Output"]
            split.extend([{**event, "Output": output[:22]}, {**event, "Output": output[22:]}])
        raw = lambda values: b"".join(json.dumps(e).encode() + b"\n" for e in values)
        self.assertEqual(numeric.observations(raw(split), check, ROOT), {"ADMISSION-NUMERIC": 1046})
        for field, value in (
            ("Test", "Other"),
            ("Package", "Other"),
            ("Output", events[-1]["Output"].rstrip("\n")),
            ("Output", "x" * 65537),
            ("Output", "ADMISSION-NUMERIC " + events[-1]["Output"]),
        ):
            altered = copy.deepcopy(events)
            altered[-1][field] = value
            with self.assertRaises(v.Invalid):
                numeric.observations(raw(altered), check, ROOT)

    def test_source(self) -> None:
        """All owned numerical paths and generated wire widths are pinned; new production files invalidate scope."""
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for relative in {**admission.SOURCES, **admission.MATERIAL}:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / relative).read_bytes())
            self.assertEqual(numeric.bounds(root), numeric.bounds(ROOT))
            for relative in {**admission.SOURCES, **admission.MATERIAL}:
                path = root / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.subTest(relative=relative), self.assertRaisesRegex(v.Invalid, "numeric-source"):
                    numeric.bounds(root)
                path.write_bytes(original)
            (root / "internal/admission/extra.go").write_text("package admission\n")
            with self.assertRaisesRegex(v.Invalid, "numeric-scope"):
                numeric.bounds(root)

    def test_gate(self) -> None:
        """The original full-rule identity requires every named child; no child or whole-system pass is invented."""
        config = v.decode(v.read(ROOT / "development.json"))
        obligations = v.expand(config)
        key = "admission/DEV-NUMERIC/ADMISSION-ASSURANCE/linux-amd64-cgo/full-rule"
        parent = obligations[key]
        self.assertIs(parent["aggregate"], True)
        self.assertEqual(parent["checks"], [])
        _, dependencies = v.dependency_order(obligations)
        required = dependencies[key]
        self.assertEqual(len(required), 10)
        # Supply synthetic statuses only to test conjunction semantics, never as native evidence.
        observed = {(check, obligations[k]["platform"], obligations[k]["contract"]): "passed" for k in required for check in obligations[k]["checks"]}
        now = dt.datetime.now(dt.timezone.utc)
        result = v.decide(config, observed, [], [], now)
        self.assertIn(key, result["passed"])
        self.assertEqual(result["status"], "blocked")
        for dependency in required:
            altered = dict(observed)
            item = obligations[dependency]
            for check in item["checks"]:
                altered.pop((check, item["platform"], item["contract"]))
            self.assertIn(key, v.decide(config, altered, [], [], now)["missing"])
