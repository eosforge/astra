"""Attack stale Storage impact mappings, forged native completion and omission of mandatory consumer obligations."""

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import consumers, entry, impact, installation, statements, verify as v


class ImpactTests(unittest.TestCase):
    """Original native archives provide positive facts; edited inputs are rejection controls only."""

    @classmethod
    def setUpClass(cls) -> None:
        """Authenticate the frozen native compiler and both complete consumer packages once per reader invocation."""
        cls.root = Path(__file__).resolve().parents[1]
        cls.artifacts = {name: v.read(cls.root / "build/results/assurance" / name, 128 * 1024**2) for name in impact.ARTIFACTS}
        cls.files, cls.original, cls.previous, cls.seal = impact.retained(cls.artifacts)
        cls.original_results, cls.original_exports = impact.consumers(cls.files, cls.seal)
        cls.current, cls.results, cls.exports = consumers.refresh(cls.artifacts, cls.previous, cls.files, cls.original_results)
        old = entry.unpack(cls.artifacts["reuse-plan/entry-closure/evidence.tar.gz"])
        cls.before = impact.graph(old[entry.PREFIX + "typed/exports/exports.stdout.log"])
        cls.after = impact.graph(cls.exports)
        cls.receipt = impact.sources(cls.root, cls.original, cls.current, cls.before, cls.after)

    def test_current(self) -> None:
        """Every actually completed native case remains in the full, nonempty discovery inventory."""
        for name, count in (("server", 47), ("entry", 8)):
            actual = self.results[name]
            self.assertEqual(actual["tests"], count)
            for case in actual["expected"]:
                self.assertTrue(case.startswith("Test"))
                self.assertEqual(actual["expected"].count(case), 1)
        self.assertEqual(self.receipt["affected"], ["polaris", "polaris/internal/server", impact.STORAGE])
        self.assertEqual(len(self.receipt["changes"]), 5)
        self.assertIn(installation.PATH, self.receipt["changes"])
        self.assertIn(impact.STORAGE + "/maintenance.go", self.receipt["changes"])
        self.assertEqual(self.results["server"]["cases"], 300)
        self.assertIsNone(self.results["server"]["coverage_sha256"])
        self.assertEqual(self.results["server"]["coverage_status"], "not-collected-for-current-source")
        self.assertIsNotNone(self.original_results["server"]["coverage_sha256"])
        self.assertEqual(self.results["entry"]["cases"], 50)
        self.assertIsNone(self.results["entry"]["coverage_sha256"])
        self.assertEqual(self.results["entry"]["coverage_status"], "not-collected-for-current-source")
        self.assertIsNotNone(self.original_results["entry"]["coverage_sha256"])
        self.assertNotEqual(self.results["server"]["duration_ms"], self.original_results["server"]["duration_ms"])
        self.assertGreater(len(self.receipt["sources"]), 55)
        self.assertEqual(impact.reconcile(self.root, self.artifacts)["checks"], self.results)

    def test_archive(self) -> None:
        """Reject missing/extra archives and changed raw facts, even with a plausible synthesized passing receipt."""
        for name in impact.ARTIFACTS:
            changed = dict(self.artifacts)
            changed[name] += b" "
            with self.subTest(name=name), self.assertRaises(v.Invalid):
                impact.retained(changed)
        for mode in ("missing", "extra"):
            changed = dict(self.artifacts)
            if mode == "missing":
                changed.pop(next(iter(changed)))
            else:
                changed["received.json"] = v.encode({"status": "passed"})
            with self.subTest(mode=mode), self.assertRaises(v.Invalid):
                impact.retained(changed)

    def test_native(self) -> None:
        """Block skipped/missing cases, foreign packages, PID reuse, dirty tools, unfinished rollback and missing native journals."""
        terminal = v.decode(self.files["terminal.json"])
        edits = [
            ("terminal.json", {**terminal, "remaining_owned": [{"pid": 1}]}),
            ("terminal.json", {**terminal, "interrupted": True}),
            ("terminal.json", {**terminal, "cache_restored": False}),
            ("terminal.json", {**terminal, "errors": ["failure"]}),
        ]
        prefix = "source/build/commands/server-race/"
        record = v.decode(self.files[prefix + "record.json"])
        process = v.decode(self.files[prefix + "server-race.process.json"])
        edits += [
            (prefix + "record.json", {**record, "exit_code": 1}),
            (prefix + "record.json", {**record, "complete": False}),
            (prefix + "record.json", {**record, "cleanup": False}),
            (prefix + "record.json", {**record, "resolved_environment": {**record["resolved_environment"], "GOPROXY": "https://example.invalid"}}),
            (prefix + "server-race.process.json", {**process, "identity": {**process["identity"], "start_ticks": "1"}}),
            (prefix + "server-race.process.json", {**process, "boot_id": "other"}),
            (prefix + "server-race.process.json", {**process, "cwd": "/other"}),
        ]
        for name, value in edits:
            changed = {**self.files, name: v.encode(value)}
            with self.subTest(name=name, value=value), self.assertRaises(v.Invalid):
                impact.consumers(changed, self.seal)
        with self.assertRaises(v.Invalid):
            impact.consumers({**self.files, "journal.native.jsonl": b""}, self.seal)
        events = [v.decode(line) for line in self.files[prefix + record["stdout"]["path"]].splitlines()]
        case = next(index for index, row in enumerate(events) if row.get("Action") == "pass" and "Test" in row and "/" not in row["Test"])
        for mode in ("skip", "missing", "duplicate", "foreign"):
            rows = copy.deepcopy(events)
            if mode == "missing":
                rows.pop(case)
            elif mode == "duplicate":
                rows.append(rows[case])
            elif mode == "foreign":
                rows[case]["Package"] = "foreign"
            else:
                rows[case]["Action"] = "skip"
            output = b"\n".join(v.encode(row).strip() for row in rows) + b"\n"
            replacement = {**record, "stdout": {**record["stdout"], "bytes": len(output), "sha256": v.digest(output)}}
            changed = {**self.files, prefix + "record.json": v.encode(replacement), prefix + record["stdout"]["path"]: output}
            with self.subTest(mode=mode), self.assertRaises(v.Invalid):
                impact.consumers(changed, self.seal)
        for campaign in consumers.ARCHIVES:
            files, _, records, outputs = consumers.load(self.artifacts, campaign)
            name = "server-batch-race" if campaign == "server-batch-green-current-3" else "entry-race"
            prefix = consumers.PREFIX + name + "/"
            record = records[name]
            process = v.decode(files[prefix + name + ".process.json"])
            terminal = v.decode(files["terminal.json"])
            owner = v.decode(files["controller.json"])
            edits = [
                ("terminal.json", {**terminal, "errors": ["failed"]}),
                ("terminal.json", {**terminal, "interrupted": True}),
                ("terminal.json", {**terminal, "remaining_owned": [{"pid": 1}]}),
                ("controller.json", {**owner, "boot_id": "other"}),
                ("controller.json", {**owner, "cwd": "/other"}),
                (prefix + "record.json", {**record, "exit_code": 1}),
                (prefix + "record.json", {**record, "cleanup": False}),
                (prefix + "record.json", {**record, "complete": False}),
                (prefix + "record.json", {**record, "resolved_environment": {**record["resolved_environment"], "GOPROXY": "https://example.invalid"}}),
                (prefix + "record.json", {**record, "resolved_environment": {**record["resolved_environment"], "GOOS": "windows"}}),
                (prefix + name + ".process.json", {**process, "identity": {**process["identity"], "start_ticks": "1"}}),
                (prefix + name + ".process.json", {**process, "identity": {**process["identity"], "parent": 1}}),
                (prefix + name + ".process.json", {**process, "cwd": "/other"}),
            ]
            for path, value in edits:
                with self.subTest(campaign=campaign, path=path, value=value), self.assertRaises(v.Invalid):
                    consumers.native({**files, path: v.encode(value)}, campaign)
            with self.subTest(campaign=campaign, mode="missing-journal"), self.assertRaises(v.Invalid):
                consumers.native({**files, "journal.native.jsonl": b""}, campaign)
            if campaign != consumers.CURRENT:
                with self.subTest(campaign=campaign, mode="wrong-collector-format"), self.assertRaises(v.Invalid):
                    consumers.native(files, campaign, collected=True)
            if campaign == consumers.CURRENT:
                for path, field, value in (
                    ("cache-handoff.native.json", "inode", 0),
                    ("cache-handoff.native.json", "to", "/foreign"),
                    ("cache-return.native.json", "device", 0),
                    ("cache-return.native.json", "owner", {}),
                    ("cache-return.native.json", "remaining_owned", [1]),
                ):
                    changed = {**files, path: v.encode({**v.decode(files[path]), field: value})}
                    with self.subTest(current=path, field=field), self.assertRaises(v.Invalid):
                        consumers.native(changed, campaign)
            events = [v.decode(row) for row in outputs[name].splitlines()]
            expected = entry.tests(outputs[name])
            for mode in ("skip", "missing", "duplicate", "foreign", "missing-run"):
                rows = copy.deepcopy(events)
                index = next(index for index, row in enumerate(rows) if row.get("Action") == ("run" if mode == "missing-run" else "pass") and "Test" in row)
                if mode in ("missing", "missing-run"):
                    rows.pop(index)
                elif mode == "duplicate":
                    rows.append(rows[index])
                elif mode == "foreign":
                    rows[index]["Package"] = "foreign"
                else:
                    rows[index]["Action"] = "skip"
                with self.subTest(campaign=campaign, mode=mode), self.assertRaises(v.Invalid):
                    consumers.cases(b"\n".join(v.encode(row) for row in rows), events[0]["Package"], expected)

    def test_graph(self) -> None:
        """An incomplete or expanded compiler graph cannot silently retain the former impact boundary."""
        self.assertEqual(self.before, self.after)
        packages = statements.stream(self.exports)
        own = next(index for index, row in enumerate(packages) if row["ImportPath"] == impact.MODULE + impact.STORAGE)
        for mode in ("incomplete", "duplicate", "unknown", "error"):
            rows = copy.deepcopy(packages)
            if mode == "duplicate":
                rows.append(rows[own])
            elif mode == "unknown":
                rows[own]["Imports"] = [impact.MODULE + "unknown"]
            elif mode == "error":
                rows[own]["Error"] = {"Err": "compile failure"}
            else:
                rows[own]["Incomplete"] = True
            with self.subTest(mode=mode), self.assertRaises(v.Invalid):
                impact.graph(b"\n".join(v.encode(row) for row in rows))
        changed = {**self.after, "new-consumer": [impact.STORAGE]}
        self.assertIn("new-consumer", impact.closure(changed))
        with self.assertRaises(v.Invalid):
            impact.sources(self.root, self.original, self.current, self.before, changed)

    def test_delta(self) -> None:
        """Reject additions, deletions, renames and hidden SQL/caller changes outside the exact reviewed lifecycle edits."""
        name = impact.STORAGE + "/store.go"
        for mode in ("add", "delete", "rename", "body", "old"):
            changed = dict(self.current)
            if mode == "add":
                changed[impact.STORAGE + "/extra.go"] = b"package storage\n"
            elif mode == "delete":
                del changed[name]
            elif mode == "rename":
                changed[impact.STORAGE + "/other.go"] = changed.pop(name)
            elif mode == "old":
                changed[name] = self.original[name]
            else:
                changed[name] += b"\n// unreviewed\n"
            with self.subTest(mode=mode), self.assertRaises(v.Invalid):
                impact.delta(self.original, changed, set(self.after))
        with self.assertRaises(v.Invalid):
            impact.delta(self.original, {**self.current, installation.PATH: self.current[installation.PATH] + b"\n// unknown\n"}, set(self.after))
        worker = impact.STORAGE + "/maintenance.go"
        for replacement in (b"package storage\n", self.current[worker] + b"\n// unknown\n"):
            with self.subTest(worker=replacement), self.assertRaises(v.Invalid):
                impact.delta(self.original, {**self.current, worker: replacement}, set(self.after))
        # Every new compiled fixture is pinned independently of producer tools and cannot lend its identity to another revision.
        for name in ("compatibility_test.go", "maintenance_test.go", "storage_test.go", "maintenance.go"):
            original_load = consumers.load

            def changed_current(artifacts: dict[str, bytes], campaign: str) -> tuple[dict[str, bytes], dict[str, bytes], dict, dict]:
                """Substitute one changed storage input in the current campaign only."""
                files, source, records, outputs = original_load(artifacts, campaign)
                if campaign == consumers.CURRENT:
                    source = {**source, impact.STORAGE + "/" + name: b"changed"}
                return files, source, records, outputs

            with self.subTest(current_source=name), patch.object(consumers, "load", side_effect=changed_current), self.assertRaises(v.Invalid):
                consumers.refresh(self.artifacts, self.previous, self.files, self.original_results)
        original = consumers.load
        for name in (installation.PATH, impact.STORAGE + "/crash_test.go", "go.sum"):

            def changed(artifacts: dict[str, bytes], campaign: str) -> tuple[dict[str, bytes], dict[str, bytes], dict, dict]:
                """Substitute one changed input in the selected server consumer campaign."""
                files, source, records, outputs = original(artifacts, campaign)
                if campaign == "server-batch-consumers-current-1":
                    source = {**source, name: b"changed"}
                return files, source, records, outputs

            with self.subTest(name=name), patch.object(consumers, "load", side_effect=changed), self.assertRaises(v.Invalid):
                consumers.refresh(self.artifacts, self.previous, self.files, self.original_results)

    def test_sources(self) -> None:
        """Bind compiled/oracle inputs while leaving current producer-tool edits outside historical Go execution."""
        original = v.read
        self.assertNotIn("tools/verify.py", self.receipt["sources"])
        consumers.protocol_document(self.current["proto/README.md"], original(self.root / "proto/README.md"))
        document = original(self.root / "proto/README.md")
        altered = document.replace(b"## Admission Identity\n", b"## Admission Identity\nUnreviewed behavior\n", 1)
        with self.assertRaisesRegex(v.Invalid, "consumers-protocol-document-contract"):
            consumers.protocol_document(self.current["proto/README.md"], altered)
        with patch.object(v, "read", side_effect=lambda path, *args: b"changed" if path == self.root / "tools/verify.py" else original(path, *args)):
            self.assertEqual(impact.sources(self.root, self.original, self.current, self.before, self.after), self.receipt)
        for name in ("tools/decisions/runtime.go.in", "tests/fixtures/storage.tests.json", "go.sum", "dependencies.lock.json"):
            with (
                self.subTest(name=name),
                patch.object(v, "read", side_effect=lambda path, *args: b"changed" if path == self.root / name else original(path, *args)),
                self.assertRaises(v.Invalid),
            ):
                impact.sources(self.root, self.original, self.current, self.before, self.after)
        name = impact.STORAGE + "/crash_test.go"
        with patch.object(v, "read", side_effect=lambda path, *args: b"changed" if path == self.root / name else original(path, *args)):
            with self.assertRaises(v.Invalid):
                impact.sources(self.root, self.original, self.current, self.before, self.after)
        for name in ("go.mod", "proto/astra.proto", "internal/generated/astra/astra.pb.go"):
            self.assertIn(name, self.current)
            with self.subTest(name=name), self.assertRaises(v.Invalid):
                impact.sources(self.root, self.original, {**self.current, name: b"changed"}, self.before, self.after)
        with self.assertRaises(v.Invalid):
            impact.sources(self.root, self.original, {**self.current, "polaris/new/consumer.go": b"package new"}, self.before, self.after)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(v.Invalid):
                impact.sources(Path(directory), self.original, self.current, self.before, self.after)

    def test_policy(self) -> None:
        """Reader success cannot waive full current core or real delivery prerequisites, or remove rejection controls."""
        config = v.decode(v.read(self.root / "development.json"))
        impact.policy(config)
        self.assertEqual(len(impact.PREREQUISITES), 2)
        for index in range(2):
            changed = copy.deepcopy(config)
            component = next(item for item in changed["components"] if item["id"] == "polaris-storage")
            requirement = next(item for item in component["requirements"] if item["rule"] == "DEV-IMPACT")
            requirement["requires"].pop(index)
            with self.assertRaises(v.Invalid):
                impact.policy(changed)
        for mode in ("missing-control", "vacuous", "wrong-owner"):
            changed = copy.deepcopy(config)
            check = next(item for item in changed["checks"] if item["id"] == "gap-impact")
            if mode == "missing-control":
                check["expected_tests"].pop()
            elif mode == "vacuous":
                check["probes"] = []
            else:
                check["component"] = "polaris-server"
            with self.subTest(mode=mode), self.assertRaises(v.Invalid):
                impact.policy(changed)
