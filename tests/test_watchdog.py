"""Challenge exact schedule-overlay transformations, reserved paths and source-drift rejection."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools import verify as v, watchdog


def stream(profile: str) -> list[dict]:
    """Construct synthetic native-shaped witnesses for parser attacks, never component acceptance evidence."""
    action = "fail" if profile == "expired" else "pass"
    rows = [{"Action": "start"}, {"Action": "run", "Test": "TestWatchdog"}]
    markers = (
        ("stale timer replaced completed send result", "stale timer ended replacement phase")
        if profile == "expired"
        else ("WATCHDOG-SCHEDULE cleared complete 1", "WATCHDOG-SCHEDULE extended complete 2")
    )
    for name, marker in zip(("cleared", "extended"), markers):
        test = "TestWatchdog/" + name
        rows.extend([{"Action": "run", "Test": test}, {"Action": "output", "Test": test, "Output": marker + "\n"}, {"Action": action, "Test": test}])
    rows.extend([{"Action": action, "Test": "TestWatchdog"}, {"Action": action}])
    return [{"Package": watchdog.PACKAGE, **row} for row in rows]


def encoded(rows: list[dict]) -> bytes:
    """Serialize attacker-controlled native event fixtures with one record per line."""
    return b"\n".join(json.dumps(row, separators=(",", ":")).encode("utf-8") for row in rows) + b"\n"


def receipt(profile: str) -> dict:
    """Provide only the synthetic completion fields used by the semantic classifier."""
    return {"complete": True, "cleanup": True, "termination": "exited", "exit_code": 1 if profile == "expired" else 0}


class WatchdogTests(unittest.TestCase):
    """Exercise generation only; real Go execution and its negative variant have separate native receipts."""

    def setUp(self) -> None:
        """Copy the actual reviewed source and fixture into an isolated project boundary."""
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        origin = Path(watchdog.__file__).resolve().parents[1]
        for name in (watchdog.SOURCE, watchdog.FIXTURE):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((origin / name).read_bytes())
        self.output = self.root / "build/schedule"

    def test_transform(self) -> None:
        """Removing the single pause and helper must reproduce production; one guard substitution defines the mutant."""
        original = (self.root / watchdog.SOURCE).read_bytes()
        fixture = (self.root / watchdog.FIXTURE).read_bytes()
        result = watchdog.generate(self.root, self.output)
        expected = original.decode("utf-8").replace("\r\n", "\n")
        baseline = (self.output / "baseline/stream.go").read_text(encoding="utf-8")
        broken = (self.output / "expired/stream.go").read_text(encoding="utf-8")
        self.assertEqual(baseline.count("\t\t\tcheckpoint(transfer, timer)\n"), 1)
        restored = baseline.removesuffix(watchdog.HOOK).replace("\t\t\tcheckpoint(transfer, timer)\n", "")
        self.assertEqual(restored, expected)
        self.assertEqual(broken.replace(watchdog.BROKEN, watchdog.GUARD), baseline)
        self.assertNotEqual(broken, baseline)
        for name in ("baseline", "expired"):
            folder = self.output / name
            self.assertEqual((folder / "watchdog_test.go").read_bytes(), fixture)
            overlay = json.loads((folder / "overlay.json").read_text(encoding="utf-8"))["Replace"]
            self.assertEqual(set(overlay), {str(self.root / watchdog.SOURCE), str((self.root / watchdog.SOURCE).parent / "watchdog_test.go")})
            for path, digest in result["variants"][name].items():
                self.assertEqual(hashlib.sha256((folder / path).read_bytes()).hexdigest(), digest)
        self.assertEqual((self.root / watchdog.SOURCE).read_bytes(), original)
        self.assertEqual(result["qualification"], "not-evaluated")

    def test_composition(self) -> None:
        """Reject changes to copied helpers, the pause, the fixture, mapping and receipt before interpreting any counters."""
        origin = self.root / "build/typed/overlay"
        origin.mkdir(parents=True)
        source = (self.root / watchdog.SOURCE).read_text(encoding="utf-8")
        # This is deliberately synthetic collector output for transformation checks, not compiled evidence.
        body = source.replace(watchdog.GUARD, "if err := transfer.expire(timer); func() bool {")
        contents = {"stream.go": body, "zz_astra_probe.go": "package server\n", "zz_astra_probe_test.go": "package server\n"}
        folder = (self.root / watchdog.SOURCE).parent
        for name, data in contents.items():
            (origin / name).write_bytes(data.encode("utf-8"))
        (origin / "trace.json").write_bytes(b"{}\n")
        v.write_new(origin / "overlay.json", {"Replace": {str(folder / name): str(origin / name) for name in contents}})
        receipt = watchdog.compose(self.root, origin, self.output, create=True)
        self.assertEqual(watchdog.compose(self.root, origin, self.output), receipt)
        self.assertEqual(receipt["qualification"], "not-evaluated")
        self.assertEqual((self.output / "stream.go").read_text(encoding="utf-8"), watchdog.pause(body, traced=True))
        self.assertEqual((self.root / watchdog.SOURCE).read_text(encoding="utf-8"), source)
        for path in sorted(self.output.iterdir()):
            original = path.read_bytes()
            path.write_bytes(original + b" \n")
            # JSON whitespace alone is not semantic drift, so alter the JSON value as well.
            if path.suffix == ".json":
                path.write_bytes(b"{}\n")
            with self.subTest(file=path.name), self.assertRaises(v.Invalid):
                watchdog.compose(self.root, origin, self.output)
            path.write_bytes(original)
        extra = self.output / "unrecorded.go"
        extra.write_bytes(b"package server\n")
        with self.assertRaisesRegex(v.Invalid, "watchdog-compose-files"):
            watchdog.compose(self.root, origin, self.output)
        extra.unlink()
        for destination in (self.root, origin, origin / "nested", origin.parent):
            with self.subTest(destination=destination), self.assertRaises(v.Invalid):
                watchdog.compose(self.root, origin, destination)
        (folder / "watchdog_test.go").write_bytes(b"package server\n")
        with self.assertRaisesRegex(v.Invalid, "watchdog-compose-source"):
            watchdog.compose(self.root, origin, self.output)

    def test_source(self) -> None:
        """Changed control shape or a reserved helper cannot silently receive a nearby checkpoint."""
        path = self.root / watchdog.SOURCE
        original = path.read_text(encoding="utf-8")
        for altered in (original.replace(watchdog.GUARD, "if false {"), original + watchdog.ANCHOR, original + "\nvar watchpoint int\n"):
            with self.subTest(altered=altered[-40:]):
                path.write_text(altered, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "reviewed checkpoint"):
                    watchdog.generate(self.root, self.output)
                self.assertFalse(self.output.exists())

    def test_trace(self) -> None:
        """A schedule pause preserves each collector byte; ambiguous or already modified inputs fail closed."""
        original = (self.root / watchdog.SOURCE).read_text(encoding="utf-8")
        guard = "if err := transfer.expire(timer); func() bool {"
        # This synthetic transformation input is not a compiled instrumentation receipt.
        traced = original.replace(watchdog.GUARD, guard)
        paused = watchdog.pause(traced, traced=True)
        call = "\t\t\tcheckpoint(transfer, timer)\n"
        self.assertEqual(paused.count(call), 1)
        self.assertEqual(paused.removesuffix(watchdog.HOOK).replace(call, ""), traced)
        self.assertEqual(paused.count(guard), 1)
        for value in (original, paused, traced + watchdog.ANCHOR, traced + guard, traced.replace(guard, "if false {")):
            with self.subTest(value=value[-30:]), self.assertRaisesRegex(ValueError, "reviewed checkpoint"):
                watchdog.pause(value, traced=True)
        with self.assertRaisesRegex(ValueError, "reviewed checkpoint"):
            watchdog.pause(traced)

    def test_output(self) -> None:
        """Escaping, replacing build itself or reusing evidence must fail without touching retained bytes."""
        for output in (self.root / "outside", self.root / "build", self.root / "build/../../escape"):
            with self.subTest(output=output):
                with self.assertRaisesRegex(ValueError, "build subdirectory"):
                    watchdog.generate(self.root, output)
        watchdog.generate(self.root, self.output)
        before = {p.relative_to(self.output): p.read_bytes() for p in self.output.rglob("*") if p.is_file()}
        with self.assertRaises(FileExistsError):
            watchdog.generate(self.root, self.output)
        self.assertEqual(before, {p.relative_to(self.output): p.read_bytes() for p in self.output.rglob("*") if p.is_file()})

    def test_fixture(self) -> None:
        """Reject missing or ambiguous schedule entry points and collision with a user-owned test."""
        path = self.root / watchdog.FIXTURE
        original = path.read_bytes()
        for altered in (b"package server\n", original + b"func TestWatchdog("):
            path.write_bytes(altered)
            with self.assertRaisesRegex(ValueError, "fixture identity"):
                watchdog.generate(self.root, self.output)
            self.assertFalse(self.output.exists())
        path.write_bytes(original)
        occupied = (self.root / watchdog.SOURCE).parent / "watchdog_test.go"
        occupied.write_text("retained user input", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "existing test"):
            watchdog.generate(self.root, self.output)
        self.assertEqual(occupied.read_text(encoding="utf-8"), "retained user input")

    def test_outcome(self) -> None:
        """Each positive profile and the exact two semantic rejections have distinct complete native terminals."""
        for profile in watchdog.PROFILES:
            result = watchdog.outcome(encoded(stream(profile)), b"", receipt(profile), profile)
            self.assertEqual(result["terminals"], 3)
            self.assertEqual(result["outcome"], "fail" if profile == "expired" else "pass")
            self.assertEqual(len(result["markers"]), 2)

    def test_stream(self) -> None:
        """Missing children, copied witnesses, skipped tests and malformed lifecycle facts cannot masquerade as success."""
        for profile in watchdog.PROFILES:
            original = stream(profile)
            attacks = {
                "empty": [],
                "no-start": original[1:],
                "duplicate-start": original[:1] + original,
                "no-terminal": original[:-1],
                "after-terminal": original + original[:1],
                "missing-child": [row for row in original if row.get("Test") != "TestWatchdog/cleared"],
                "missing-witness": [row for row in original if row.get("Action") != "output"],
                "skip": [
                    {**row, "Action": "skip"} if row.get("Test") == "TestWatchdog/cleared" and row["Action"] in ("pass", "fail") else row for row in original
                ],
                "borrowed-witness": [{**row, "Test": "TestWatchdog"} if row["Action"] == "output" else row for row in original],
                "duplicate-witness": [{**row, "Output": row["Output"] * 2} if row["Action"] == "output" else row for row in original],
                "wrong-package": [{**row, "Package": "other"} for row in original],
                "end-before-run": original[:2] + original[4:5] + original[2:4] + original[5:],
            }
            for name, rows in attacks.items():
                with self.subTest(profile=profile, attack=name), self.assertRaises(v.Invalid):
                    watchdog.outcome(encoded(rows), b"", receipt(profile), profile)
            with self.assertRaises(v.Invalid):
                watchdog.outcome(encoded(original) + b"{", b"", receipt(profile), profile)

    def test_failure(self) -> None:
        """Timeout, orphan cleanup, compiler failure or runtime damage cannot count as killed semantic mutants."""
        for profile in watchdog.PROFILES:
            for field, value in (("complete", False), ("cleanup", False), ("termination", "timeout"), ("exit_code", 2), ("exit_code", -9)):
                with self.subTest(profile=profile, field=field, value=value), self.assertRaises(v.Invalid):
                    watchdog.outcome(encoded(stream(profile)), b"", {**receipt(profile), field: value}, profile)
            for error in (b"WARNING: DATA RACE", b"panic: timeout", b"fatal error: deadlock"):
                with self.subTest(profile=profile, error=error), self.assertRaises(v.Invalid):
                    watchdog.outcome(encoded(stream(profile)), error, receipt(profile), profile)
        with self.assertRaises(v.Invalid):
            watchdog.outcome(encoded(stream("baseline")), b"", receipt("baseline"), "expired")

    def test_registration(self) -> None:
        """The versioned campaign discovers the actual wrapper, while all parser tests stay in the required tool selection."""
        root = Path(watchdog.__file__).resolve().parents[1]
        config = v.decode(v.read(root / "development.json"))
        step = v.unique(config["campaigns"][0]["steps"])["watchdog"]
        self.assertEqual(step["argv"], ["{python}", "-B", "tools/watchdog.py", "--root", "{root}", "--output", "{run}/watchdog-schedules", "--run"])
        self.assertGreaterEqual(step["timeout_s"], 3 * 300)
        check = v.unique(config["checks"])["verification-python"]
        self.assertIn("tests.test_watchdog", check["argv"])
        methods = {"tests.test_watchdog.WatchdogTests." + name for name in unittest.defaultTestLoader.getTestCaseNames(type(self))}
        self.assertTrue(methods <= set(check["expected_tests"]))
        baseline, race, expired = (watchdog.command(self.output, name) for name in watchdog.PROFILES)
        self.assertEqual([arg for arg in race if arg != "-race"], baseline)
        self.assertEqual([arg.replace("/expired/", "/baseline/").replace("\\expired\\", "\\baseline\\") for arg in expired], baseline)
        self.assertIn("-count=1", baseline)
        with self.assertRaises(v.Invalid):
            watchdog.command(self.output, "unregistered")


if __name__ == "__main__":
    unittest.main()
