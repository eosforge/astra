"""Attack native clock-evidence attribution, temporal boundaries, mutation sensitivity and current-source binding."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from tools import timeouts, verify as v

ROOT = Path(__file__).resolve().parents[1]


def frames(rows: list[dict]) -> bytes:
    """Create parser controls only; these synthesized frames never substitute for a native command receipt."""
    return b"".join(
        (
            json.dumps(
                {
                    "Action": "output",
                    "Package": timeouts.PACKAGE,
                    "Test": timeouts.CASES[row.get("scope", "write")][0] + "/" + row["mode"],
                    "Output": "    fixture.go:1: STORAGE-TIME " + " ".join(key + "=" + str(value) for key, value in row.items()) + "\n",
                }
            )
            + "\n"
        ).encode()
        for row in rows
    )


class TimeoutTests(unittest.TestCase):
    """Retain real local outcomes while rejecting convenient changes to their expected results or source ownership."""

    @classmethod
    def setUpClass(cls) -> None:
        """Load original immutable archives once; synthetic damaged controls remain separate dictionaries."""
        cls.artifacts = {name: v.read(ROOT / "build/results/assurance" / name, 128 * 1024**2) for name in timeouts.ARTIFACTS}
        cls.retained = timeouts.retained(cls.artifacts)
        cls.commands = {number: timeouts.native(files, number) for number, (files, _) in cls.retained.items()}
        cls.receipt = timeouts.reconcile(ROOT, cls.artifacts)
        cls.config = v.decode(v.read(ROOT / "development.json"))

    def test_current(self) -> None:
        """Every declared native history and physical mutation is present, attributed and bound to current software."""
        self.assertEqual(len(self.receipt["cases"]), 24)
        self.assertEqual(len(self.receipt["killed"]), 8)
        self.assertEqual(self.receipt["observations"], 26)
        self.assertEqual(
            self.receipt["maintenance"],
            [
                {"test": "TestMaintenanceFailure", "contract": "STORAGE-CHECKPOINT", "minimum_hits": 7},
                {"test": "TestMaintenanceDeadline", "contract": "STORAGE-TIME", "minimum_hits": 6},
            ],
        )
        self.assertEqual(self.receipt["trust"], "local")
        for row in self.receipt["cases"]:
            scope = row.get("scope", "write")
            self.assertIn(row["mode"], timeouts.CASES[scope][1])
            self.assertIs(type(row["elapsed"]), int)
        self.assertEqual(len(set(self.receipt["killed"])), 8)
        self.assertGreater(len(self.receipt["sources"]), 24)
        self.assertNotIn((1, "disabled"), timeouts.MUTANTS)
        self.assertEqual(timeouts.reconcile(ROOT, self.artifacts)["cases"], self.receipt["cases"])

    def test_archive(self) -> None:
        """Neither fabricated passing summaries nor changed raw archives can replace original runner facts."""
        for name in self.artifacts:
            with self.subTest(name=name), self.assertRaises(v.Invalid):
                timeouts.retained({**self.artifacts, name: self.artifacts[name] + b" "})
        for changed in ({}, {**self.artifacts, "passed.json": b"{}"}):
            with self.assertRaises(v.Invalid):
                timeouts.retained(changed)

    def test_native(self) -> None:
        """Block lifecycle ambiguity, foreign tool/process identity, online resolution and incomplete streams."""
        for number in (5, 7):
            self.native_controls(number)

    def native_controls(self, number: int) -> None:
        """Apply the same retirement, compiler, source-library and stream attacks to old and current producers."""
        files, _ = self.retained[number]
        terminal = v.decode(files["terminal.json"])
        edits = [
            ("terminal.json", {**terminal, key: value})
            for key, value in (("interrupted", True), ("remaining_owned", [{"pid": 1}]), ("errors", ["failure"]), ("cache_restored", False))
        ]
        prefix = "source/build/commands/baseline/"
        record = v.decode(files[prefix + "record.json"])
        process = v.decode(files[prefix + "baseline.process.json"])
        edits.extend(
            (prefix + "record.json", {**record, key: value})
            for key, value in (("exit_code", 1), ("cleanup", False), ("complete", False), ("duration_ms", -1), ("executable_sha256", "0" * 64))
        )
        edits.extend(
            (prefix + "baseline.process.json", {**process, key: value})
            for key, value in (("cwd", "/other"), ("boot_id", "other"), ("identity", {**process["identity"], "start_ticks": "1"}))
        )
        edits.append((prefix + "record.json", {**record, "resolved_environment": {**record["resolved_environment"], "GOPROXY": "https://example.invalid"}}))
        libraries = v.decode(files["stdlib.native.json"])
        libraries["files"]["src/time/time.go"]["data"] += "\n"
        edits.append(("stdlib.native.json", libraries))
        for name, value in edits:
            with self.subTest(name=name, value=value), self.assertRaises(v.Invalid):
                timeouts.native({**files, name: v.encode(value)}, number)
        for name in ("journal.native.jsonl", prefix + record["stdout"]["path"], prefix + "coverage.out"):
            with self.subTest(name=name), self.assertRaises(v.Invalid):
                timeouts.native({**files, name: b""}, number)

    def test_boundaries(self) -> None:
        """Challenge every mode's elapsed domain, refusal ownership, durable result and nonempty denominator."""
        for scopes in (("write",), ("read", "open"), ("native",)):
            rows = [copy.deepcopy(row) for row in self.receipt["cases"] if row.get("scope", "write") in scopes]
            self.assertEqual(timeouts.histories(frames(rows), scopes), rows)
            for index, row in enumerate(rows):
                for key in (name for name, value in row.items() if type(value) is int and (name != "elapsed" or row.get("scope") != "native")):
                    changed = copy.deepcopy(rows)
                    changed[index][key] += 1
                    with self.subTest(scope=row.get("scope", "write"), mode=row["mode"], key=key), self.assertRaises(v.Invalid):
                        timeouts.histories(frames(changed), scopes)
                for changed in (rows[:index] + rows[index + 1 :], rows[:index] + [row] + rows[index:]):
                    with self.assertRaises(v.Invalid):
                        timeouts.histories(frames(changed), scopes)
            for damaged in (
                b"",
                frames(rows)[:-8],
                frames(rows).replace(timeouts.PACKAGE.encode(), b"other"),
                frames(rows).replace(b"budget=", b"budget=true ignored="),
            ):
                with self.assertRaises(v.Invalid):
                    timeouts.histories(damaged, scopes)
        native = [row for row in self.receipt["cases"] if row.get("scope") == "native"]
        native[0] = {**native[0], "elapsed": 19_999_999}
        with self.assertRaises(v.Invalid):
            timeouts.histories(frames(native), ("native",))

    def test_mutants(self) -> None:
        """A crash, ineffective overlay, forged digest or surviving mutant cannot satisfy sensitivity."""
        selected = [*timeouts.MUTANTS, *((7, name) for _, name in timeouts.MUTANTS)]
        for number, name in selected:
            files, original = self.retained[number]
            command = self.commands[number][name]
            self.assertIsNone(timeouts.sensitivity(files, original, number, name, command))
            prefix = "source/build/commands/" + name + "/"
            facts = v.decode(files[prefix + "mutation.native.json"])
            file = timeouts.mutation(number, name)[0]
            for changed in (
                {**files, prefix + "mutation.native.json": v.encode({**facts, "mutant_sha256": "0" * 64})},
                {**files, prefix + file: original[timeouts.DIRECTORY + file]},
                {**files, prefix + "overlay.json": v.encode({"Replace": {"/source/" + file: "/variant/" + file}})},
            ):
                with self.assertRaises(v.Invalid):
                    timeouts.sensitivity(changed, original, number, name, command)
            with self.assertRaises(v.Invalid):
                timeouts.sensitivity(files, original, number, name, {**command, "record": {**command["record"], "exit_code": 0}})
            with self.assertRaises(v.Invalid):
                timeouts.sensitivity(files, original, number, name, {**command, "output": command["output"] + b"panic:"})

    def test_sources(self) -> None:
        """Added/deleted sources and dirty content changes invalidate reuse even when a commit identifier is unchanged."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Exercise the historical source guard in its actual frozen input context.
            # The current compiler bridge is independently challenged by AcquisitionTests.
            original_source = self.retained[max(self.retained)][1]
            names = set(self.receipt["sources"]) & original_source.keys()
            expected = {name: v.digest(original_source[name]) for name in names}
            for name in names:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(original_source[name])
            self.assertEqual(timeouts.sources(root, self.retained), expected)
            path = root / timeouts.DIRECTORY / "read.go"
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            with self.assertRaises(v.Invalid):
                timeouts.sources(root, self.retained)
            path.write_bytes(original)
            added = path.with_name("unknown.go")
            added.write_bytes(b"package storage\n")
            with self.assertRaises(v.Invalid):
                timeouts.sources(root, self.retained)
            added.unlink()
            path.unlink()
            with self.assertRaises(v.Invalid):
                timeouts.sources(root, self.retained)

    def test_policy(self) -> None:
        """The rule retains its numeric/core prerequisites and the complete reader inventory."""
        self.assertIsNone(timeouts.policy(self.config))
        for mode in ("tests", "hits", "core", "numeric", "aggregate"):
            config = copy.deepcopy(self.config)
            check = next(item for item in config["checks"] if item["id"] == "gap-time")
            component = next(item for item in config["components"] if item["id"] == "polaris-storage")
            full = next(item for item in component["requirements"] if item["rule"] == "DEV-TIME" and item["scenario"] == "full-rule")
            if mode == "tests":
                check["expected_tests"] = check["expected_tests"][:-1]
            elif mode == "hits":
                check["probes"][0]["minimum_hits"] -= 1
            elif mode == "aggregate":
                full["aggregate"] = False
            else:
                full["requires"] = [item for item in full["requires"] if item["rule"] != ("DEV-CORE" if mode == "core" else "DEV-NUMERIC")]
            with self.subTest(mode=mode), self.assertRaises(v.Invalid):
                timeouts.policy(config)
