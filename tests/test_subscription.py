"""Challenge scheduling transformations and native-result classification without substituting component execution."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from tools import subscription as s, verify as v


def stream(profile: str) -> list[dict]:
    """Construct explicitly synthetic native-shaped events for adversarial parser checks."""
    outcome = "fail" if profile == "late" else "pass"
    rows = [
        {"Action": "start"},
        {"Action": "run", "Test": s.TEST},
        {"Action": "output", "Test": s.TEST, "Output": (s.FAILURE if profile == "late" else s.SUCCESS) + "\n"},
        {"Action": outcome, "Test": s.TEST},
        {"Action": outcome},
    ]
    return [{"Package": s.PACKAGE, **row} for row in rows]


def encoded(rows: list[dict]) -> bytes:
    """Keep each synthetic event on one line, including malformed variants supplied by a test."""
    return b"\n".join(json.dumps(row).encode("utf-8") for row in rows) + b"\n"


def receipt(profile: str) -> dict:
    """Supply parser inputs only; these fixtures are never recorded as component evidence."""
    return {"complete": True, "cleanup": True, "termination": "exited", "exit_code": 1 if profile == "late" else 0}


class SubscriptionTests(unittest.TestCase):
    """Bind exact current source transformations, reject false greens and retain the separate native execution requirement."""

    def setUp(self) -> None:
        """Own an isolated source pair and fresh output path for each parser or generator check."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.origin = Path(s.__file__).resolve().parents[1]
        for name in (s.SOURCE, s.FIXTURE):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((self.origin / name).read_bytes())
        self.output = self.root / "build/schedules"

    def test_transform(self) -> None:
        """Removing only the checkpoint restores production; moving exactly one whole block defines the negative."""
        original = (self.root / s.SOURCE).read_text(encoding="utf-8")
        result = s.generate(self.root, self.output)
        normal = (self.output / "baseline/stream.go.txt").read_text(encoding="utf-8")
        late = (self.output / "late/stream.go.txt").read_text(encoding="utf-8")
        self.assertEqual(normal.removesuffix(s.HOOK).replace(s.POINT, ""), original)
        self.assertEqual(late.replace(s.POINT + s.BLOCK, s.POINT), normal.replace(s.BLOCK, ""))
        self.assertEqual(late.count(s.BLOCK), 1)
        self.assertLess(normal.index(s.BLOCK), normal.index(s.POINT))
        self.assertGreater(late.index(s.BLOCK), late.index(s.POINT))
        self.assertEqual(result["qualification"], "not-evaluated")
        for variant in ("baseline", "late"):
            folder = self.output / variant
            self.assertEqual((folder / "subscription.go.txt").read_bytes(), (self.root / s.FIXTURE).read_bytes())
            self.assertEqual(
                v.decode(v.read(folder / "overlay.json")),
                {
                    "Replace": {
                        str(self.root / s.SOURCE): str(folder / "stream.go.txt"),
                        str((self.root / s.SOURCE).parent / "subscription_test.go"): str(folder / "subscription.go.txt"),
                    }
                },
            )
            for name, digest in result["variants"][variant].items():
                path = folder / name
                self.assertEqual(v.file_digest(path), digest)
                original_bytes = path.read_bytes()
                path.write_bytes(original_bytes + b" \n")
                with self.subTest(variant=variant, file=name), self.assertRaisesRegex(v.Invalid, "subscription-overlay-drift"):
                    s.inspect(self.root, self.output)
                path.write_bytes(original_bytes)
        self.assertEqual((self.root / s.SOURCE).read_text(encoding="utf-8"), original)

    def test_source(self) -> None:
        """Missing, repeated, reordered and preinstrumented boundaries cannot silently produce an alternative mutant."""
        text = (self.root / s.SOURCE).read_text(encoding="utf-8")
        variants = [
            text.replace(s.BLOCK, ""),
            text + s.BLOCK,
            text.replace(s.ANCHOR, ""),
            text + s.ANCHOR,
            text.replace(s.BLOCK, "").replace(s.ANCHOR, s.ANCHOR + "\n" + s.BLOCK),
            text + "inventoryPoint",
            text + "inventoryCheckpoint",
        ]
        for changed in variants:
            with self.subTest(source=changed[-45:]), self.assertRaises(v.Invalid):
                s.transform(changed)

    def test_output(self) -> None:
        """Reserved tests, escaping output and evidence-directory reuse are rejected before a plan is overwritten."""
        for output in (self.root, self.root / "build", self.root / "build/../outside"):
            with self.subTest(output=output), self.assertRaises(v.Invalid):
                s.generate(self.root, output)
        virtual = (self.root / s.SOURCE).parent / "subscription_test.go"
        virtual.write_bytes(b"package server\n")
        with self.assertRaisesRegex(v.Invalid, "subscription-existing-test"):
            s.generate(self.root, self.output)
        virtual.unlink()
        s.generate(self.root, self.output)
        with self.assertRaises(FileExistsError):
            s.generate(self.root, self.output)
        (self.output / "late/extra.go").write_bytes(b"package server\n")
        with self.assertRaisesRegex(v.Invalid, "subscription-overlay-files"):
            s.inspect(self.root, self.output)

    def test_fixture(self) -> None:
        """A missing or duplicate test identity and an altered fixture cannot borrow an earlier overlay manifest."""
        path = self.root / s.FIXTURE
        original = path.read_bytes()
        for changed in (original.replace(b"func TestSubscription(", b"func TestOther("), original + original):
            path.write_bytes(changed)
            with self.assertRaisesRegex(v.Invalid, "subscription-fixture"):
                s.generate(self.root, self.output)
        path.write_bytes(original)
        s.generate(self.root, self.output)
        path.write_bytes(original + b"\n// Changed fixture.\n")
        with self.assertRaisesRegex(v.Invalid, "subscription-overlay-drift"):
            s.inspect(self.root, self.output)

    def test_outcome(self) -> None:
        """Each profile requires its own exit, witness and exactly one native test terminal."""
        for profile in s.PROFILES:
            self.assertEqual(
                s.outcome(encoded(stream(profile)), b"", receipt(profile), profile),
                {
                    "terminals": 1,
                    "outcome": "fail" if profile == "late" else "pass",
                    "marker": s.FAILURE if profile == "late" else s.SUCCESS,
                },
            )
            argv = s.command(self.output, profile)
            self.assertEqual("-race" in argv, profile == "race")
            self.assertIn("-run=^TestSubscription$", argv)
            self.assertIn("-count=1", argv)
        for call in (lambda: s.command(self.output, "other"), lambda: s.outcome(b"", b"", {}, "other")):
            with self.assertRaisesRegex(v.Invalid, "subscription-profile"):
                call()

    def test_stream(self) -> None:
        """Truncation, wrong packages, skipped tests, duplicate terminals and misplaced witnesses cannot pass."""
        for profile in s.PROFILES:
            rows = stream(profile)
            attacks = [rows[:index] for index in range(len(rows))]
            attacks += [
                rows[1:],
                rows + [rows[-1]],
                [rows[0]] + rows,
                rows[:2] + [rows[1]] + rows[2:],
                rows[:2] + [rows[-1]] + rows[2:],
                [rows[0], rows[2], rows[1], *rows[3:]],
                [rows[0], rows[1], rows[3], rows[2], rows[4]],
            ]
            for index, field, value in (
                (0, "Package", "other"),
                (1, "Test", "TestOther"),
                (1, "Action", "pause"),
                (3, "Action", "skip"),
                (4, "Action", "skip"),
                (2, "Output", ""),
                (2, "Output", 1),
                (2, "Test", None),
                (0, "Test", s.TEST),
            ):
                changed = copy.deepcopy(rows)
                changed[index][field] = value
                attacks.append(changed)
            changed = copy.deepcopy(rows)
            changed[2]["Output"] *= 2
            attacks.append(changed)
            for index, attack in enumerate(attacks):
                with self.subTest(profile=profile, attack=index), self.assertRaises(v.Invalid):
                    s.outcome(encoded(attack), b"", receipt(profile), profile)
            for data in (b"[]\n", b"{}\n", b"not-json\n", encoded(rows) + b"{}\n"):
                with self.assertRaises(v.Invalid):
                    s.outcome(data, b"", receipt(profile), profile)

    def test_failure(self) -> None:
        """Timeout, compilation failure, undrained descendants and runtime diagnostics never count as semantic detection."""
        for profile in s.PROFILES:
            for field, value in (("complete", False), ("cleanup", False), ("termination", "timeout"), ("exit_code", 2)):
                record = {**receipt(profile), field: value}
                with self.subTest(profile=profile, field=field), self.assertRaises(v.Invalid):
                    s.outcome(encoded(stream(profile)), b"", record, profile)
            for marker in (
                "WARNING: DATA RACE",
                "panic:",
                "fatal error:",
                "inventory-boundary stream did not release its owned state",
                "inventory-boundary store did not close",
                s.SUCCESS if profile == "late" else s.FAILURE,
            ):
                for stderr in (True, False):
                    rows = stream(profile)
                    if not stderr:
                        rows[2]["Output"] += marker
                    with self.subTest(profile=profile, marker=marker, stderr=stderr), self.assertRaises(v.Invalid):
                        s.outcome(encoded(rows), marker.encode() if stderr else b"", receipt(profile), profile)

    def test_registration(self) -> None:
        """The bounded native campaign and every reader/generator counterexample remain in configured discovery."""
        config = v.decode(v.read(self.origin / "development.json"))
        step = next(step for step in config["campaigns"][0]["steps"] if step["id"] == "subscription")
        self.assertEqual(step["argv"], ["{python}", "-B", "tools/subscription.py", "--root", "{root}", "--output", "{run}/subscription-schedules", "--run"])
        self.assertEqual(step["timeout_s"], 1000)
        self.assertEqual(step["requires"], [])
        check = next(check for check in config["checks"] if check["id"] == "verification-python")
        self.assertIn("tests.test_subscription", check["argv"])
        expected = {"tests.test_subscription.SubscriptionTests." + name for name in dir(type(self)) if name.startswith("test_")}
        self.assertTrue(expected <= set(check["expected_tests"]))
