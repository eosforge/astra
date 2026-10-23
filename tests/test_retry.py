"""Challenge the complete authority retry-grid interpreter; synthetic streams are not application evidence."""

import copy
import datetime as dt
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tools import models, retry, storage_numeric, verify as v

ROOT = Path(__file__).resolve().parents[1]


def configured() -> dict:
    """Read the actual versioned native selection and exposure budget."""
    return next(check for check in v.decode(v.read(ROOT / "development.json"))["checks"] if check["id"] == "storage-retry")


def encode(rows: list) -> bytes:
    """Construct parser-control framing only, without native run/pass receipts or process identities."""
    return b"".join(
        (
            json.dumps(
                {
                    "Action": "output",
                    "Package": configured()["package"],
                    "Test": "TestRetryIdentity",
                    "Output": "STORAGE-RETRY-IDENTITY " + json.dumps(row) + "\n",
                }
            )
            + "\n"
        ).encode()
        for row in rows
    )


def recovery_rows() -> list[dict]:
    """Build independently specified recovery parser controls, never command or process-success receipts."""
    rows = []
    for point in ("begin", "commit-before", "commit-after", "commit-cancel", "rollback-after", "cancel-record"):
        for attempt in (1, 2):
            rows.append({"Test": "TestFinalization/" + point, "Output": f"finalization={point} attempt={attempt} injected=1 reached=1 reopened=verified\n"})
    for point in ("prefix", "prepared", "durable"):
        rows.append({"Test": "TestCrash/" + point, "Output": f"crash-point={point} reached=1 signal=SIGKILL reaped=1 recovery=verified retry=verified\n"})
    for point in ("write", "sync"):
        rows.extend(
            {"Test": "TestNativeIO/" + point, "Output": f"STORAGE-IO point={point} native_errors=1 uncertain=1 atomic=1 retry=1 retained=0\n"} for _ in range(2)
        )
    return rows


def recovery_encode(rows: list[dict]) -> bytes:
    """Encode intentionally synthetic case attribution and output for sensitivity checks only."""
    return b"".join(json.dumps({"Action": "output", "Package": storage_numeric.PACKAGE, **row}).encode() + b"\n" for row in rows)


class RetryTests(unittest.TestCase):
    """Keep receipt windows, ordered intent, scope isolation and source binding independently observable."""

    def test_configuration(self) -> None:
        """Require retry-check configuration and the revision-specific identity source proof."""
        check = configured()
        self.assertIsNone(models.configuration(check))
        for key, value in (("model", "unknown"), ("component", "unknown"), ("package", "wrong"), ("argv", []), ("expected_tests", []), ("probes", [])):
            changed = copy.deepcopy(check)
            changed[key] = value
            with self.assertRaises(v.Invalid):
                models.configuration(changed)
        proof = retry.proof(ROOT)
        self.assertEqual(len(proof["sources"]), 11 if storage_numeric.revision(ROOT)[0] == 884 else 10)
        self.assertIn("ordered", proof["identity"])
        self.assertIn("caller", proof["boundary"])

    def test_intents(self) -> None:
        """Require every ordered retry intent with its independent publication and outcome counts."""
        rows = retry.expected()
        self.assertEqual(len(rows), 33)
        self.assertEqual(models.observations(encode(rows), configured(), ROOT), {"STORAGE-RETRY-IDENTITY": 176})
        self.assertEqual(sum(row.get("result") == "confirmed" for row in rows), 3)
        self.assertEqual(sum(row.get("result") == "uncertain" for row in rows), 18)
        self.assertEqual(sum(row.get("published") == 1 for row in rows), 6)
        for index in range(len(rows)):
            with self.assertRaises(v.Invalid):
                models.observations(encode(rows[:index] + rows[index + 1 :]), configured(), ROOT)
            with self.assertRaises(v.Invalid):
                models.observations(encode(rows[:index] + [rows[index]] + rows[index:]), configured(), ROOT)
        for index in range(len(rows) - 1):
            changed = copy.deepcopy(rows)
            changed[index], changed[index + 1] = changed[index + 1], changed[index]
            with self.assertRaises(v.Invalid):
                models.observations(encode(changed), configured(), ROOT)
        for key, value in (("result", "confirmed"), ("version", True), ("unchanged", False), ("published", 1)):
            changed = copy.deepcopy(rows)
            changed[3][key] = value
            with self.assertRaises(v.Invalid):
                models.observations(encode(changed), configured(), ROOT)

    def test_stream(self) -> None:
        """Reject truncated retry streams and output assigned to a different test or package."""
        raw = encode(retry.expected())
        for damaged in (
            b"",
            raw[: len(raw) // 2],
            raw.replace(b"TestRetryIdentity", b"WrongTest"),
            raw.replace(configured()["package"].encode(), b"wrong-package"),
        ):
            with self.assertRaises(v.Invalid):
                models.observations(damaged, configured(), ROOT)

    def test_recovery_configuration(self) -> None:
        """Recovery completeness is a bound capability, not an optional counter interpreted for arbitrary commands."""
        checks = v.unique(v.decode(v.read(ROOT / "development.json"))["checks"])
        for identifier in ("storage-examples", "storage-io"):
            check = checks[identifier]
            self.assertIsNone(retry.recovery_configuration(check))
            for key, value in (
                ("recovery", "unknown"),
                ("component", "unknown"),
                ("package", "unknown"),
                ("adapter", "unavailable"),
                ("argv", []),
                ("probes", []),
                ("expected_tests", []),
            ):
                changed = copy.deepcopy(check)
                changed[key] = value
                with self.assertRaises(v.Invalid):
                    retry.recovery_configuration(changed)
        changed = copy.deepcopy(checks["storage-examples"])
        del changed["recovery"]
        with self.assertRaises(v.Invalid):
            models.configuration(changed)

    def test_recovery(self) -> None:
        """Missed, duplicated, reordered, untriggered or misattributed boundaries cannot hide behind sufficient counters."""
        checks = v.unique(v.decode(v.read(ROOT / "development.json"))["checks"])
        rows = recovery_rows()
        self.assertEqual(
            retry.recovery(recovery_encode(rows), checks["storage-examples"], ROOT), {"finalization_attempts": 12, "crash_points": 3, "wal_attempts": 4}
        )
        self.assertEqual(
            retry.recovery(recovery_encode(rows[-4:]), checks["storage-io"], ROOT), {"finalization_attempts": 0, "crash_points": 0, "wal_attempts": 4}
        )
        for index in range(len(rows)):
            for changed in (rows[:index] + rows[index + 1 :], rows[:index] + [rows[index]] + rows[index:]):
                with self.assertRaises(v.Invalid):
                    retry.recovery(recovery_encode(changed), checks["storage-examples"], ROOT)
        swapped = [rows[1], rows[0], *rows[2:]]
        with self.assertRaises(v.Invalid):
            retry.recovery(recovery_encode(swapped), checks["storage-examples"], ROOT)
        for index, before, after in (
            (0, "injected=1", "injected=0"),
            (0, "reached=1", "reached=0"),
            (12, "SIGKILL", "SIGTERM"),
            (12, "reaped=1", "reaped=0"),
            (15, "uncertain=1", "uncertain=0"),
            (15, "retained=0", "retained=1"),
        ):
            changed = copy.deepcopy(rows)
            changed[index]["Output"] = changed[index]["Output"].replace(before, after)
            with self.assertRaises(v.Invalid):
                retry.recovery(recovery_encode(changed), checks["storage-examples"], ROOT)
        for key, value in (("Action", "pass"), ("Package", "wrong"), ("Test", "TestCrash/prefix"), ("Output", 1)):
            changed = copy.deepcopy(rows)
            changed[0][key] = value
            with self.assertRaises(v.Invalid):
                retry.recovery(recovery_encode(changed), checks["storage-examples"], ROOT)
        with self.assertRaises(v.Invalid):
            retry.recovery(recovery_encode(rows), checks["storage-io"], ROOT)
        check = checks["storage-io"]
        events = [{"Action": "start", "Package": check["package"]}]
        for name in check["expected_tests"]:
            events.append({"Action": "run", "Package": check["package"], "Test": name})
            for probe in check["probes"]:
                if probe["test"] == name:
                    marker = {"contract": probe["contract"], "hits": probe["minimum_hits"]}
                    events.append({"Action": "output", "Package": check["package"], "Test": name, "Output": "ASTRA-CONTRACT " + json.dumps(marker) + "\n"})
            events.append({"Action": "pass", "Package": check["package"], "Test": name})
        events.append({"Action": "pass", "Package": check["package"]})
        raw = b"".join(json.dumps(event).encode() + b"\n" for event in events)
        self.assertEqual(v.go_observations(raw, check)[1], [])
        with self.assertRaisesRegex(v.Invalid, "retry-recovery-incomplete"):
            v.parse_observations(raw, check, ROOT)

    def test_recovery_source(self) -> None:
        """Native recovery assertions retain their complete source identity, including injected API/OS boundaries."""
        check = next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "storage-examples")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / storage_numeric.DIRECTORY
            directory.mkdir(parents=True)
            for name in ["numeric.json", *storage_numeric.manifest(ROOT)["sources"], *retry.RECOVERY_SOURCES]:
                shutil.copyfile(ROOT / storage_numeric.DIRECTORY / name, directory / name)
            self.assertEqual(retry.recovery(recovery_encode(recovery_rows()), check, root)["wal_attempts"], 4)
            for name in retry.RECOVERY_SOURCES:
                path = directory / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n// changed\n")
                with self.assertRaisesRegex(v.Invalid, "retry-recovery-source"):
                    retry.recovery(recovery_encode(recovery_rows()), check, root)
                path.write_bytes(original)

    def test_gate(self) -> None:
        """Each prerequisite, including the nested numerical proof, blocks the original full retry coordinate when absent or unsuccessful."""
        config = v.decode(v.read(ROOT / "development.json"))
        obligations = v.expand(config)
        key = "polaris-storage/DEV-RETRY/STORAGE-ASSURANCE/linux-amd64-cgo/full-rule"
        self.assertEqual(obligations[key]["requires"], retry.requirements())
        self.assertTrue(obligations[key]["aggregate"])
        _, dependencies = v.dependency_order(obligations)
        pending, leaves, seen = [key], set(), set()
        while pending:
            item = pending.pop()
            if item in seen:
                continue
            seen.add(item)
            obligation = obligations[item]
            leaves.update((check, obligation["platform"], obligation["contract"]) for check in obligation["checks"])
            pending.extend(dependencies[item])
        states = {leaf: "passed" for leaf in leaves}
        now = dt.datetime(2026, 10, 10, tzinfo=dt.timezone.utc)
        passed = v.decide(config, states, [], [], now)
        self.assertIn(key, passed["passed"])
        self.assertEqual(passed["status"], "blocked")
        self.assertEqual(passed["exceptions"], [])
        for leaf in leaves:
            for state in (None, "failed", "unknown", "not-run", "skipped", "interrupted"):
                changed = dict(states)
                if state is None:
                    del changed[leaf]
                else:
                    changed[leaf] = state
                decision = v.decide(config, changed, [], [], now)
                self.assertIn(key, decision["missing"])
                self.assertNotIn(key, decision["passed"])
