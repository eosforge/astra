"""Reject weakened source and vector projections for the Storage maintenance revision."""

import copy
from collections.abc import Iterator
from contextlib import contextmanager
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import entry, idle, independence, profileweights, statements, storagecompiler, structure, verify as v

ROOT = Path(__file__).resolve().parents[1]


def archived_policy(files: dict[str, bytes]) -> bytes:
    """Give an isolated parser fixture its original native test declaration, never today's toolchain identity."""
    policy = v.decode(v.read(ROOT / "development.json"))
    check = v.decode(files["inputs.json"])["full_package_check"]
    policy["checks"] = [check if item["id"] == "storage-examples" else item for item in policy["checks"]]
    return v.encode(policy)


@contextmanager
def historical(files: dict[str, bytes], artifacts: dict[str, bytes] | None = None) -> Iterator[Path]:
    """Keep immutable archived compilation inputs and existing evidence links separate from the current workspace."""
    parent = ROOT / "build/tmp"
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="idle-archived-", dir=parent) as directory:
        root = Path(directory)
        for name, data in entry.unpack(files["source.tar.gz"]).items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (root / "development.json").write_bytes(archived_policy(files))
        for name, data in (artifacts or {}).items():
            origin = ROOT / "build/results/assurance" / name
            if v.file_digest(origin) != v.digest(data):
                raise ValueError("Historical fixture reference changed")
            path = root / "build/results/assurance" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.hardlink_to(origin)
        yield root


def predicate(identity: str, text: str) -> dict:
    """Give mapping tests one explicit typed single-atom expectation, independent of production parsing."""
    return {"id": identity, "kind": "if", "text": text, "tree": [{"kind": "atom", "atom": 0}], "root": 0, "atoms": [{"text": text}]}


def fixture() -> tuple:
    """Keep the same two rules while their native source offsets move and one declared rule is added."""
    before = [{"file": "input.go", "decisions": [predicate("input.go:10", "ready"), predicate("input.go:20", "closed")]}]
    after = [{"file": "input.go", "decisions": [predicate("input.go:30", "ready"), predicate("input.go:40", "owned"), predicate("input.go:50", "closed")]}]
    rows = {("1", False): 1, ("2", True): 1}
    previous = {item["id"]: rows.copy() for item in before[0]["decisions"]}
    observed = {item["id"]: rows.copy() for item in after[0]["decisions"]}
    return before, after, {"input.go:40"}, previous, observed


def archive(files: dict[str, bytes]) -> bytes:
    """Create parser fixtures only; these bytes have no authorized artifact digest or qualification."""
    data = dict(files)
    data["manifest.json"] = v.encode({"trust": "local", "files": {name: {"bytes": len(value), "sha256": v.digest(value)} for name, value in data.items()}})
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as stream:
        for name, value in data.items():
            item = tarfile.TarInfo(name)
            item.size = len(value)
            stream.addfile(item, io.BytesIO(value))
    return output.getvalue()


class IdleTests(unittest.TestCase):
    """Protect the exact new denominator and keep historical failures separate from native success."""

    def test_current(self) -> None:
        """Replay all semantic ancestors and require both added current independent pairs."""
        values = independence.artifacts(ROOT)
        current = entry.unpack(values[idle.ACQUISITION])
        legacy = {name: data for name, data in values.items() if name not in storagecompiler.ARTIFACTS}
        with historical(current, legacy) as root:
            result = independence.reconcile(root, legacy)
            for name, sha in result["source_bindings"].items():
                self.assertEqual(v.file_digest(root / name), sha)
        self.assertEqual((result["raw_conditions"], result["supported_conditions"], result["qualified_denominator"]), (281, 273, 273))
        self.assertEqual(result["reused_conditions"], 271)
        self.assertEqual(len(result["new_pairs"]), 2)
        self.assertEqual(len(result["exclusions"]), 8)
        self.assertEqual(len(result["mapping"]), 160)
        self.assertEqual(result["compiler_exports_reused"], 21)
        self.assertEqual(result["trust"], "local")
        with self.assertRaisesRegex(v.Invalid, "storage-compiler-artifact"):
            independence.reconcile(ROOT, legacy)
        current = independence.reconcile(ROOT, values)
        self.assertEqual((current["raw_conditions"], current["supported_conditions"], current["qualified_denominator"]), (281, 273, 273))
        self.assertEqual(current["compiler"], "1.27.2")
        self.assertEqual(current["compiler_exports_reused"], 0)
        self.assertEqual(current["legacy_compiler_exports_reused"], 21)
        self.assertEqual(current["current_structure"]["statements"]["raw"], {"blocks": 412, "statements": 586, "statements_hit": 586})
        self.assertEqual(current["current_structure"]["statements"]["compiler_weights"]["obligations"], {"statements": 643, "statements_hit": 643})
        self.assertEqual(current["current_structure"]["statements"]["compiler_weights"]["model_sha256"], profileweights.STORAGE_MODEL)
        self.assertEqual(set(current["backup_supplement"]["profiles"]), {"ordinary", "race"})
        self.assertTrue(all(item["tests"] == 259 for item in current["backup_supplement"]["profiles"].values()))
        self.assertEqual((len(current["new_pairs"]), len(current["exclusions"])), (2, 8))

    def test_mapping(self) -> None:
        """Offset changes preserve rules only with identical operand trees and every earlier vector."""
        before, after, added, previous, observed = fixture()
        expected = {"input.go:10": "input.go:30", "input.go:20": "input.go:50"}
        self.assertEqual(idle.predicates(before, after, added, previous, observed), expected)
        observed["input.go:30"][("2", False)] = 1
        self.assertEqual(idle.predicates(before, after, added, previous, observed), expected)

    def test_changed(self) -> None:
        """Equal counts cannot hide changed expressions, operands, grouping or declaration order."""
        for kind in ("text", "atom", "tree", "root", "order"):
            before, after, added, previous, observed = fixture()
            item = after[0]["decisions"][0]
            if kind == "text":
                item["text"] = "different"
            elif kind == "atom":
                item["atoms"][0]["text"] = "different"
            elif kind == "tree":
                item["tree"] = [{"kind": "not", "children": [0]}]
            elif kind == "root":
                item["root"] = 1
            else:
                after[0]["decisions"][0], after[0]["decisions"][2] = after[0]["decisions"][2], after[0]["decisions"][0]
            with self.subTest(change=kind), self.assertRaisesRegex(v.Invalid, "idle-source-projection"):
                idle.predicates(before, after, added, previous, observed)

    def test_vectors(self) -> None:
        """Both decision outcomes alone cannot replace an earlier complete short-circuit vector."""
        for vector in (("1", False), ("2", True)):
            before, after, added, previous, observed = fixture()
            del observed["input.go:30"][vector]
            observed["input.go:30"][("0", vector[1])] = 1
            with self.subTest(vector=vector), self.assertRaisesRegex(v.Invalid, "idle-source-projection"):
                idle.predicates(before, after, added, previous, observed)

    def test_scope(self) -> None:
        """Missing files, duplicate identities and undeclared additions cannot narrow the mapping."""
        for kind in ("missing-file", "duplicate-file", "extra-decision", "duplicate-id"):
            before, after, added, previous, observed = fixture()
            if kind == "missing-file":
                after.clear()
            elif kind == "duplicate-file":
                after.append(copy.deepcopy(after[0]))
            elif kind == "extra-decision":
                after[0]["decisions"].append(predicate("input.go:60", "surplus"))
            else:
                after[0]["decisions"][2]["id"] = "input.go:30"
            with self.subTest(change=kind), self.assertRaisesRegex(v.Invalid, "idle-source-projection"):
                idle.predicates(before, after, added, previous, observed)

    def test_sources(self) -> None:
        """Require the exact reviewed owner additions, rejecting changes in either source version."""
        original = idle.unpack(v.read(ROOT / "build/results/assurance" / idle.SOURCE), source=True)[idle.STORE]
        current = v.read(ROOT / idle.STORE)
        self.assertIsNone(idle.source_guard(original, current))
        for before, after in ((original + b"\n", current), (original, current + b"\n"), (original, current.replace(b"store.cancel()", b"store.Close()"))):
            with self.subTest(before=v.digest(before), after=v.digest(after)), self.assertRaisesRegex(v.Invalid, "idle-source-projection"):
                idle.source_guard(before, after)
        self.assertTrue(idle.current(ROOT))

    def test_archives(self) -> None:
        """An unrelated failure, active owner, interruption or escaping member is never acceptable."""
        clean = {"errors": [], "interrupted": False, "remaining_owned": []}
        good = archive({"terminal.json": v.encode(clean), "value": b"real"})
        self.assertEqual(idle.unpack(good)["value"], b"real")
        for changed in ({**clean, "errors": ["unrelated"]}, {**clean, "interrupted": True}, {**clean, "remaining_owned": [1]}):
            with self.subTest(terminal=changed), self.assertRaisesRegex(v.Invalid, "idle-native-terminal"):
                idle.unpack(archive({"terminal.json": v.encode(changed)}))
        with self.assertRaisesRegex(v.Invalid, "idle-archive-boundary"):
            idle.unpack(archive({"../escape": b"no", "terminal.json": v.encode(clean)}))

    def test_streams(self) -> None:
        """Keep native exit, completeness, cleanup and both stream hashes independently mandatory."""
        record = {
            "exit_code": 0,
            "complete": True,
            "cleanup": True,
            "termination": "exited",
            "stdout": {"path": "stdout", "bytes": 4, "sha256": v.digest(b"real")},
            "stderr": {"path": "stderr", "bytes": 0, "sha256": v.digest(b"")},
        }
        files = {"run/stdout": b"real", "run/stderr": b""}
        self.assertEqual(idle.stream(files, "run/", record), b"real")
        for field, value in (("exit_code", 1), ("complete", False), ("cleanup", False), ("termination", "timeout")):
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "idle-native-command"):
                idle.stream(files, "run/", {**record, field: value})
        for field in ("stdout", "stderr"):
            changed = copy.deepcopy(record)
            changed[field]["sha256"] = "0" * 64
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "idle-native-stream"):
                idle.stream(files, "run/", changed)

    def test_geometry(self) -> None:
        """Recompute all native statement and outcome counts; historical geometry remains independently named."""
        files = idle.unpack(idle.artifacts(ROOT)[idle.CURRENT])
        current = entry.unpack(idle.artifacts(ROOT)[idle.ACQUISITION])
        with historical(current) as root:
            result, _, _ = idle.acquisition(root, current)
        with self.assertRaisesRegex(v.Invalid, "idle-acquisition-source"):
            idle.acquisition(ROOT, current)
        self.assertEqual(result["status"], "complete-under-assumptions")
        self.assertEqual(result["statements"]["raw"], {"blocks": 412, "statements": 643, "statements_hit": 643})
        roots, atoms = result["boolean"]["totals"]["roots"], result["boolean"]["totals"]["atoms"]
        self.assertEqual((roots["raw"], roots["observed"], roots["literal_impossible"]), (324, 321, 3))
        self.assertEqual((atoms["raw"], atoms["observed"], atoms["literal_impossible"], atoms["conditional"]), (562, 557, 3, 2))
        self.assertEqual((result["controls"]["required"], result["controls"]["observed"]), (37, 37))
        self.assertEqual(result["boolean"]["missing"], [])
        self.assertEqual(result["controls"]["missing"], [])
        self.assertEqual(structure.revision(ROOT, structure.STORAGE)["counts"], [643, 321, 557, 37])
        self.assertEqual(structure.domain(structure.STORAGE)["counts"], [622, 317, 553, 34])

    def test_commands(self) -> None:
        """Missing work, forged command identities, expanded budgets and live owners cannot retain native credit."""
        files = idle.unpack(idle.artifacts(ROOT)[idle.CURRENT])
        self.assertEqual(
            set(idle.commands(files)),
            {name for name, _, _ in structure.plan(idle.DIRECTORY / "build/commands/raw-structure/structure", package=structure.STORAGE)},
        )
        name = idle.PREFIX + "typed/tests/record.json"
        record = v.decode(files[name])
        for field, value in (
            ("id", "other"),
            ("argv", ["go", "test"]),
            ("platform", "windows-amd64"),
            ("environment", {}),
            ("resolved_environment", {}),
            ("toolchain", {}),
            ("executable", "/other/go"),
            ("executable_sha256", "0" * 64),
            ("duration_ms", 240001),
            ("exit_code", 1),
            ("complete", False),
            ("cleanup", False),
            ("termination", "timeout"),
            ("started_at", "2000-01-01T00:00:00Z"),
        ):
            changed = {**files, name: v.encode({**record, field: value})}
            with self.subTest(field=field), self.assertRaises(v.Invalid):
                idle.commands(changed)
        for changed in ({key: data for key, data in files.items() if key != name}, {**files, idle.PREFIX + "extra/record.json": files[name]}):
            with self.assertRaisesRegex(v.Invalid, "idle-structure-command-inventory"):
                idle.commands(changed)
        owner_name = idle.PREFIX + "typed/tests/tests.process.json"
        owner = v.decode(files[owner_name])
        for field, value in (
            ("argv", []),
            ("cwd", "/other"),
            ("boot_id", "other"),
            ("identity", {**owner["identity"], "parent": 1}),
            ("identity", {**owner["identity"], "start_ticks": "0"}),
        ):
            with self.subTest(owner=field), self.assertRaises(v.Invalid):
                idle.commands({**files, owner_name: v.encode({**owner, field: value})})

    def test_terminals(self) -> None:
        """A missing, extra or substituted native case cannot shrink the fixed 257-case inventory."""
        files = idle.unpack(idle.artifacts(ROOT)[idle.CURRENT])
        data = idle.commands(files)["coverage"]
        events = [v.decode(line) for line in data.splitlines()]
        tests = sorted(row["Test"] for row in events if row.get("Action") == "pass" and "Test" in row)
        structure.terminals(data, tests, package=structure.STORAGE)
        self.assertEqual((len(tests), v.digest(v.encode(tests))), (257, idle.TESTS))
        changed = [row for row in events if not (row.get("Action") == "pass" and row.get("Test") == "TestMaintenancePoison")]
        for rows, names in ((changed, tests), (changed, [name for name in tests if name != "TestMaintenancePoison"]), (events, tests[:-1])):
            with self.assertRaisesRegex(v.Invalid, "structure-test-selection"):
                structure.terminals(b"\n".join(json.dumps(row).encode() for row in rows), names, package=structure.STORAGE)

    def test_policy(self) -> None:
        """The current policy requires the full new native inventory and larger denominators without changing obligations."""
        config, _, _ = v.configuration(ROOT / "development.json", ROOT)
        native = next(row for row in config["checks"] if row["id"] == "storage-structure")
        check = next(row for row in config["checks"] if row["id"] == "storage-independence")
        structure.configuration(native)
        independence.configuration(check, native)
        self.assertEqual((len(native["native_tests"]), len(check["native_tests"])), (259, 262))
        self.assertEqual((native["probes"][0]["minimum_hits"], check["probes"][0]["minimum_hits"]), (1558, 273))
        self.assertEqual(len(v.expand(config)), 1370)
        for changed in ({**native, "native_tests": native["native_tests"][:-1]}, {**native, "native_tests": list(reversed(native["native_tests"]))}):
            with self.assertRaisesRegex(v.Invalid, "structure-native-inventory-policy"):
                structure.configuration(changed)
        for minimum in (1526, 1557, 1559):
            changed = copy.deepcopy(native)
            changed["probes"][0]["minimum_hits"] = minimum
            with self.subTest(structure=minimum), self.assertRaises(v.Invalid):
                structure.configuration(changed)
        for minimum in (271, 272, 274):
            changed = copy.deepcopy(check)
            changed["probes"][0]["minimum_hits"] = minimum
            with self.subTest(independence=minimum), self.assertRaisesRegex(v.Invalid, "storage-independence-policy"):
                independence.configuration(changed, native)


class BackupTests(unittest.TestCase):
    """Reject damaged source-impact inputs without attributing synthetic controls to native execution."""

    @classmethod
    def setUpClass(cls) -> None:
        """Read the exact received archives once; parser controls never launch Go or change the real workspace."""
        raw = v.read(ROOT / "build/results/assurance" / idle.BACKUP, 16 * 1024**2)
        if v.digest(raw) != idle.BACKUP_DIGEST:
            raise ValueError("Unexpected backup supplement")
        cls.files = entry.unpack(raw)
        cls.source = entry.unpack(cls.files["source.tar.gz"])
        cls.compiled = idle.unpack(v.read(ROOT / "build/results/assurance" / idle.CURRENT, 64 * 1024**2))
        inputs = v.decode(cls.compiled["inputs.json"])
        cls.package = {name: digest for name, digest in inputs["files"].items() if Path(name).parent.as_posix() == structure.STORAGE and name.endswith(".go")}

    def setUp(self) -> None:
        """Own a small isolated copy of the 63 compilation inputs and their prospective package check."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name, data in self.source.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (self.root / "development.json").write_bytes(archived_policy(self.files))

    def test_supplement(self) -> None:
        """The unchanged production proof keeps its counts while both complete new package profiles remain explicit."""
        result = idle.backup(self.root, self.package, self.compiled, self.files)
        self.assertEqual(result["test_file"], idle.BACKUP_FILE)
        self.assertEqual(result["test_sha256"], v.file_digest(self.root / idle.BACKUP_FILE))
        self.assertEqual((result["historical_cases"], result["current_cases"], result["new_structure_or_mcdc_hits"]), (257, 259, 0))
        self.assertEqual(set(result["profiles"]), {"ordinary", "race"})
        self.assertTrue(all(profile["tests"] == 259 for profile in result["profiles"].values()))
        (self.root / "development.json").write_bytes(v.read(ROOT / "development.json"))
        with self.assertRaisesRegex(v.Invalid, "idle-backup-test-declaration"):
            idle.backup(self.root, self.package, self.compiled, self.files)

    def test_sources(self) -> None:
        """An unfamiliar test, missing new test, changed test body or changed production file cannot use the supplement."""
        for name, damage in (
            ("extra", "polaris/internal/storage/extra_test.go"),
            ("missing", idle.BACKUP_FILE),
            ("test", idle.BACKUP_FILE),
            ("production", idle.STORE),
        ):
            path = self.root / damage
            before = path.read_bytes() if path.exists() else None
            try:
                if name == "missing":
                    path.unlink()
                else:
                    path.write_bytes((before or b"package storage\n") + b"\n")
                with self.subTest(source=name), self.assertRaisesRegex(v.Invalid, "idle-backup-compilation-source"):
                    idle.backup(self.root, self.package, self.compiled, self.files)
            finally:
                if before is None:
                    path.unlink()
                else:
                    path.write_bytes(before)
        with patch.object(v, "read", return_value=b"damaged native archive"):
            with self.assertRaisesRegex(v.Invalid, "idle-artifact-integrity"):
                idle.artifacts(self.root)
        retained = idle.artifacts(ROOT)
        with patch.object(
            v,
            "read",
            side_effect=lambda path, maximum: (
                b"damaged supplement" if path.as_posix().endswith(idle.BACKUP) else retained[path.relative_to(self.root / "build/results/assurance").as_posix()]
            ),
        ):
            with self.assertRaisesRegex(v.Invalid, "idle-backup-artifact-integrity"):
                idle.artifacts(self.root)

    def test_receipts(self) -> None:
        """Every required native profile, owner, command, compiler, resource and stream receipt stays mandatory."""
        cases = [
            ("record.json", ("exit_code",), 1, "command"),
            ("record.json", ("complete",), False, "command"),
            ("record.json", ("cleanup",), False, "command"),
            ("record.json", ("termination",), "timeout", "command"),
            ("record.json", ("resolved_environment", "GOMAXPROCS"), "2", "command"),
            ("record.json", ("toolchain", "CC", "sha256"), "0" * 64, "compiler"),
            ("record.json", ("stdout", "sha256"), "0" * 64, "stream"),
            ("exec.native.json", ("observed",), [], "exec"),
            ("leaf.after.json", ("cgroup.procs",), "1", "resources"),
            ("leaf.after.json", ("memory.events",), "low 0\nhigh 0\nmax 0\noom 1\noom_kill 0\noom_group_kill 0", "resources"),
        ]
        for filename, keys, value, reason in cases:
            name = "commands/race/" + filename
            content = v.decode(self.files[name])
            target = content
            for key in keys[:-1]:
                target = target[key]
            target[keys[-1]] = value
            code = "idle-native-stream" if reason == "stream" else "idle-backup-native-" + reason
            with self.subTest(file=filename, keys=keys), self.assertRaisesRegex(v.Invalid, code):
                idle.backup(self.root, self.package, self.compiled, {**self.files, name: v.encode(content)})
        for field, value, reason in (("remaining_owned", [1], "owner"), ("unit", {"MainPID": "1", "ControlGroup": "/live"}, "owner")):
            content = v.decode(self.files["cleanup.native.json"])
            content[field] = value
            with self.subTest(cleanup=field), self.assertRaisesRegex(v.Invalid, "idle-backup-native-" + reason):
                idle.backup(self.root, self.package, self.compiled, {**self.files, "cleanup.native.json": v.encode(content)})
        content = v.decode(self.files["owner.json"])
        content["whole_limits"]["memory.max"] = str(3 * 1024**3)
        with self.assertRaisesRegex(v.Invalid, "idle-backup-native-resources"):
            idle.backup(self.root, self.package, self.compiled, {**self.files, "owner.json": v.encode(content)})
        inputs = v.decode(self.files["inputs.json"])
        inputs["commands"] = [row for row in inputs["commands"] if row["id"] != "race"]
        content = v.decode(self.files["owner.json"])
        content["inputs_sha256"] = v.digest(v.encode(inputs))
        with self.assertRaisesRegex(v.Invalid, "idle-backup-native-profiles"):
            idle.backup(self.root, self.package, self.compiled, {**self.files, "inputs.json": v.encode(inputs), "owner.json": v.encode(content)})

    def test_tests(self) -> None:
        """Skipping, omitting, inventing a case or reducing a contract hit cannot qualify the full package."""
        prefix = "commands/ordinary/"
        original = v.decode(self.files[prefix + "record.json"])
        for damage in ("skip", "missing", "extra", "probe"):
            events = [v.decode(row) for row in self.files[prefix + original["stdout"]["path"]].splitlines()]
            if damage == "missing":
                events = [event for event in events if event.get("Test") != "TestAtomicity"]
            elif damage == "extra":
                index = next(index for index, event in enumerate(events) if event["Action"] == "pass" and "Test" not in event)
                events[index:index] = [{"Package": events[index]["Package"], "Action": action, "Test": "TestFabricatedBackup"} for action in ("run", "pass")]
            else:
                changed = False
                for event in events:
                    if damage == "skip" and event.get("Test") == "TestAtomicity" and event["Action"] == "pass":
                        event["Action"], changed = "skip", True
                    if damage == "probe" and event.get("Test") == "TestOnlineBackup" and "ASTRA-CONTRACT" in event.get("Output", ""):
                        self.assertIn('"hits":11', event["Output"])
                        event["Output"] = event["Output"].replace('"hits":11', '"hits":10')
                        changed = True
                self.assertTrue(changed)
            data = b"".join((json.dumps(event, separators=(",", ":")) + "\n").encode() for event in events)
            record = copy.deepcopy(original)
            record["stdout"].update(bytes=len(data), sha256=v.digest(data))
            files = {**self.files, prefix + record["stdout"]["path"]: data, prefix + "record.json": v.encode(record)}
            with self.subTest(damage=damage), self.assertRaisesRegex(v.Invalid, "idle-backup-native-tests"):
                idle.backup(self.root, self.package, self.compiled, files)


class AcquisitionTests(unittest.TestCase):
    """Exercise the current collector boundary with real receipts and explicitly damaged parser inputs."""

    @classmethod
    def setUpClass(cls) -> None:
        """Retain one immutable current acquisition; no test launches the application."""
        raw = v.read(ROOT / "build/results/assurance" / idle.ACQUISITION, 16 * 1024**2)
        if v.digest(raw) != idle.ACQUISITION_DIGEST:
            raise ValueError("Unexpected structural acquisition")
        cls.files = entry.unpack(raw)
        cls.source = entry.unpack(cls.files["source.tar.gz"])
        raw = v.read(ROOT / "build/results/assurance" / storagecompiler.ACQUISITION, 32 * 1024**2)
        if v.digest(raw) != storagecompiler.ACQUISITION_SHA:
            raise ValueError("Unexpected current compiler acquisition")
        cls.current = entry.unpack(raw)
        cls.trace = v.decode(cls.current["commands/raw-structure/structure/typed/overlay/trace.json"])

    def setUp(self) -> None:
        """Keep source-damage controls isolated from the main workspace and archived inputs."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name, data in self.source.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (self.root / "development.json").write_bytes(archived_policy(self.files))

    def test_semantic_review(self) -> None:
        """Current compiler input association preserves original semantic bytes and rejects hidden module, source or inventory changes."""
        current = entry.unpack(self.current["source.tar.gz"])
        for name, data in current.items():
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        (self.root / "development.json").write_bytes(v.read(ROOT / "development.json"))
        archive = self.root / "build/results/assurance" / storagecompiler.ACQUISITION
        archive.parent.mkdir(parents=True)
        archive.write_bytes(v.read(ROOT / "build/results/assurance" / storagecompiler.ACQUISITION, 32 * 1024**2))
        names = {name for name in self.source if name.startswith("polaris/internal/storage/") and name.endswith(".go")} | {"go.mod", "go.sum"}
        bindings = storagecompiler.review(self.root, self.source, names)
        self.assertTrue(names <= bindings.keys())
        self.assertTrue(all(sha == v.file_digest(self.root / name) for name, sha in bindings.items()))
        for name in ("go.mod", "go.sum", "polaris/internal/storage/read.go"):
            altered = dict(self.source)
            altered[name] += b"\n"
            with self.subTest(original=name), self.assertRaisesRegex(v.Invalid, "storage-compiler-review-delta"):
                storagecompiler.review(self.root, altered, names)
        name = "polaris/internal/storage/read.go"
        removed = {key: value for key, value in self.source.items() if key != name}
        with self.assertRaisesRegex(v.Invalid, "storage-compiler-review-inventory"):
            storagecompiler.review(self.root, removed, names - {name})
        with self.assertRaisesRegex(v.Invalid, "storage-compiler-review-inputs"):
            storagecompiler.review(self.root, self.source, names - {"go.sum"})
        for name in ("polaris/internal/storage/read.go", "go.mod"):
            target = self.root / name
            data = target.read_bytes()
            target.write_bytes(data + b"\n")
            with self.subTest(current=name), self.assertRaises(v.Invalid):
                storagecompiler.review(self.root, self.source, names)
            target.write_bytes(data)
        target = self.root / "polaris/internal/storage/unreviewed_test.go"
        target.write_bytes(b"package storage\n")
        with self.assertRaises(v.Invalid):
            storagecompiler.review(self.root, self.source, names)

    def test_current(self) -> None:
        """A fresh acquisition preserves all outcome denominators and every preceding native predicate vector."""
        ledger, trace, rows = idle.acquisition(self.root, self.files)
        self.assertEqual(ledger["status"], "complete-under-assumptions")
        self.assertEqual(ledger["statements"]["raw"], {"blocks": 412, "statements": 643, "statements_hit": 643})
        old = idle.unpack(v.read(ROOT / "build/results/assurance" / idle.CURRENT, 64 * 1024**2))
        previous = v.decode(old[idle.PREFIX + "typed/overlay/trace.json"])
        data = idle.stream(old, idle.PREFIX + "typed/tests/", v.decode(old[idle.PREFIX + "typed/tests/record.json"]))
        from tools import logic

        previous_rows, processes = logic.observe(previous, data, "github.com/eosforge/astra/" + structure.STORAGE, 257)
        mapping = idle.predicates(previous["files"], trace["files"], set(), previous_rows, rows)
        self.assertEqual((len(mapping), processes), (162, 32))
        self.assertEqual(set(ledger["native_profiles"]), {name for name, _, _ in structure.plan(Path("unused"), package=structure.STORAGE)})
        for profile in ("coverage", "typed/tests", "control/tests"):
            self.assertEqual(len(ledger["native_profiles"][profile]["observed"]), 32)
        (self.root / "development.json").write_bytes(v.read(ROOT / "development.json"))
        with self.assertRaisesRegex(v.Invalid, "idle-acquisition-test-declaration"):
            idle.acquisition(self.root, self.files)
        with historical(self.current) as root:
            fixture = root / profileweights.STORAGE_FIXTURE
            fixture.parent.mkdir(parents=True, exist_ok=True)
            fixture.write_bytes(v.read(ROOT / profileweights.STORAGE_FIXTURE))
            ledger, _, _ = idle.acquisition(root, self.current, compiler="1.27.2")
            self.assertEqual(ledger["statements"]["raw"], {"blocks": 412, "statements": 586, "statements_hit": 586})
            self.assertEqual(ledger["statements"]["compiler_weights"]["obligations"], {"statements": 643, "statements_hit": 643})
            with self.assertRaisesRegex(v.Invalid, "structure-profile-compiler"):
                structure.storage_counters(self.current["commands/raw-structure/structure/coverage.profile"], root, self.trace, compiler="unsupported")

    def test_sources(self) -> None:
        """Changed collectors, tests and unknown compilation inputs cannot retain current qualification."""
        for name in ("tools/decisions/main.go", idle.BACKUP_FILE, "polaris/internal/storage/unknown_test.go"):
            path = self.root / name
            before = path.read_bytes() if path.exists() else None
            try:
                path.write_bytes((before or b"package storage\n") + b"\n")
                with self.subTest(source=name), self.assertRaisesRegex(v.Invalid, "idle-acquisition-source"):
                    idle.acquisition(self.root, self.files)
            finally:
                if before is None:
                    path.unlink()
                else:
                    path.write_bytes(before)
        old = idle.unpack(v.read(ROOT / "build/results/assurance" / idle.CURRENT, 64 * 1024**2))
        with self.assertRaisesRegex(v.Invalid, "idle-native-collector-source"):
            idle.outcomes(ROOT, old)
        prefix = "commands/raw-structure/structure/"
        names = v.decode(v.read(ROOT / profileweights.STORAGE_FIXTURE))["source_sha256"]
        _, blocks, _ = statements.profile(
            self.current[prefix + "coverage.profile"],
            {name: {"data": v.read(ROOT / name)} for name in names},
            {"github.com/eosforge/astra/" + name: name for name in names},
        )
        for index in range(len(blocks)):
            changed = [dict(row) for row in blocks]
            changed[index]["statements"] += 1
            with self.subTest(weight=index), self.assertRaisesRegex(v.Invalid, "profile-weights-geometry"):
                profileweights.reconcile(ROOT, structure.STORAGE, changed)
        for changed in (blocks[:-1], blocks + [blocks[0]], list(reversed(blocks))):
            with self.assertRaisesRegex(v.Invalid, "profile-weights-geometry"):
                profileweights.reconcile(ROOT, structure.STORAGE, changed)
        for index, row in enumerate(blocks):
            changed = [dict(item) for item in blocks]
            changed[index]["count"] = 0
            proof = profileweights.reconcile(ROOT, structure.STORAGE, changed)
            self.assertLess(proof["obligations"]["statements_hit"], 643)
            if row["statements"]:
                self.assertLess(proof["native"]["statements_hit"], 586)

    def test_receipts(self) -> None:
        """Missing commands, partial streams, wrong executables, live owners and expanded limits fail closed."""
        prefix = "commands/raw-structure/structure/typed/tests/"
        for filename, keys, value, reason in (
            ("record.json", ("exit_code",), 1, "command"),
            ("record.json", ("complete",), False, "command"),
            ("record.json", ("stdout", "sha256"), "0" * 64, "idle-native-stream"),
            ("record.json", ("resolved_environment", "GOPROXY"), "direct", "command"),
            ("record.json", ("toolchain", "CC", "sha256"), "0" * 64, "compiler"),
            ("exec.native.json", ("observed",), [], "exec"),
            ("leaf.after.json", ("cgroup.procs",), "1", "resources"),
            ("leaf.before.json", ("memory.max",), str(3 * 1024**3), "resources"),
        ):
            name = prefix + filename
            content = v.decode(self.files[name])
            target = content
            for key in keys[:-1]:
                target = target[key]
            target[keys[-1]] = value
            code = reason if reason.startswith("idle-") else "idle-acquisition-" + reason
            with self.subTest(file=filename, keys=keys), self.assertRaisesRegex(v.Invalid, code):
                idle.acquisition(self.root, {**self.files, name: v.encode(content)})
        name = prefix + "record.json"
        with self.assertRaisesRegex(v.Invalid, "idle-acquisition-command-inventory"):
            idle.acquisition(self.root, {key: value for key, value in self.files.items() if key != name})
        cleanup = v.decode(self.files["cleanup.native.json"])
        cleanup["remaining_owned"] = [1]
        with self.assertRaisesRegex(v.Invalid, "idle-acquisition-owner"):
            idle.acquisition(self.root, {**self.files, "cleanup.native.json": v.encode(cleanup)})
        for member, fields, value, reason in (
            ("cleanup.native.json", ("remaining_owned",), [1], "owner"),
            ("owner.json", ("controller_limits", "memory.high"), "469762048", "resources"),
            ("terminal.json", ("controller_resources", "memory.events"), "low 0\nhigh 1\nmax 0\noom 0\noom_kill 0\noom_group_kill 0", "resources"),
            ("terminal.json", ("controller_resources", "memory.max"), str(3 * 1024**3), "resources"),
            ("terminal.json", ("whole_resources", "memory.high"), str(3 * 1024**3), "resources"),
            ("cache-handoff.json", ("to",), "/foreign/cache", "cache"),
            ("source.native.after.json", ("commit",), "0" * 40, "source"),
        ):
            changed = v.decode(self.current[member])
            target = changed
            for field in fields[:-1]:
                target = target[field]
            target[fields[-1]] = value
            altered = {**self.current, member: v.encode(changed)}
            if member == "terminal.json":
                original = v.decode(self.current[member])
                journal = v.decode(self.current["journal.native.json"])
                for row in journal:
                    if row.get("MESSAGE", "").startswith("{") and v.decode(row["MESSAGE"].encode()) == original:
                        row["MESSAGE"] = v.encode(changed).decode()
                altered["journal.native.json"] = v.encode(journal)
            with self.subTest(current=member, fields=fields), self.assertRaisesRegex(v.Invalid, "storage-compiler-" + reason):
                storagecompiler.receipt(ROOT, altered)
        race = entry.unpack(v.read(ROOT / "build/results/assurance" / storagecompiler.RACE, 32 * 1024**2))
        for member, fields, value, reason in (
            ("commands/race/request.json", ("log_bytes",), 32 * 1024**2, "command"),
            ("commands/race/exec.native.json", ("observed",), [], "exec"),
            ("commands/race/leaf.after.json", ("cgroup.procs",), "1", "resources"),
            ("commands/race/record.json", ("toolchain", "CC", "sha256"), "0" * 64, "compiler"),
        ):
            changed = v.decode(race[member])
            target = changed
            for field in fields[:-1]:
                target = target[field]
            target[fields[-1]] = value
            with self.subTest(race=member), self.assertRaisesRegex(v.Invalid, "storage-compiler-race-" + reason):
                storagecompiler.race_profiles(ROOT, {**race, member: v.encode(changed)})
        for key in ("GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR", "LD_LIBRARY_PATH"):
            record = v.decode(race["commands/race/record.json"])
            request = v.decode(race["commands/race/request.json"])
            for environment in (record["environment"], record["resolved_environment"], request["environment"]):
                environment[key] = "/foreign/path"
            altered = {**race, "commands/race/record.json": v.encode(record), "commands/race/request.json": v.encode(request)}
            with self.subTest(environment=key), self.assertRaisesRegex(v.Invalid, "storage-compiler-race-command"):
                storagecompiler.race_profiles(ROOT, altered)
        with self.assertRaisesRegex(v.Invalid, "storage-compiler-race-compile"):
            storagecompiler.race_profiles(ROOT, {name: data for name, data in race.items() if name != "commands/compile-race/storage.test"})

    def test_tests(self) -> None:
        """Hash-consistent streams still fail when a required new case is skipped, removed or replaced."""
        prefix = "commands/raw-structure/structure/coverage/"
        original = v.decode(self.files[prefix + "record.json"])
        for damage in ("missing", "skip", "extra"):
            events = [v.decode(row) for row in self.files[prefix + original["stdout"]["path"]].splitlines()]
            if damage == "missing":
                events = [event for event in events if event.get("Test") != "TestBackupRestore"]
            elif damage == "skip":
                for event in events:
                    if event.get("Test") == "TestOnlineBackup" and event["Action"] == "pass":
                        event["Action"] = "skip"
            else:
                index = next(index for index, event in enumerate(events) if event["Action"] == "pass" and "Test" not in event)
                events[index:index] = [{"Package": events[index]["Package"], "Action": action, "Test": "TestFabricatedBackup"} for action in ("run", "pass")]
            data = b"".join((json.dumps(event, separators=(",", ":")) + "\n").encode() for event in events)
            record = copy.deepcopy(original)
            record["stdout"].update(bytes=len(data), sha256=v.digest(data))
            changed = {**self.files, prefix + original["stdout"]["path"]: data, prefix + "record.json": v.encode(record)}
            reason = "structure-test-selection" if damage == "extra" else "idle-acquisition-tests"
            with self.subTest(damage=damage), self.assertRaisesRegex(v.Invalid, reason):
                idle.acquisition(self.root, changed)
