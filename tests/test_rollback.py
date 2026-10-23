"""Attack rollback-proof readers with synthetic records that cannot pass the pinned native archive boundary."""

import copy
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tests.test_repair import fixture as admission_fixture
from tools import consumers, entry, rollback, verify as v

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "source/build/commands/storage-rollback-before/"


def stream(rows: list[dict]) -> bytes:
    """Use the same framed JSON-lines representation as native Go output."""
    return b"".join(json.dumps(row, separators=(",", ":")).encode() + b"\n" for row in rows)


def events(modes: tuple[str, ...] = ("write",), status: str = "fail") -> list[dict]:
    """Produce explicitly synthetic controlled-operation histories, including their parent and package terminals."""
    result = [{"Action": "run", "Package": rollback.PACKAGE, "Test": "TestDraining"}]
    for mode in modes:
        name = "TestDraining/" + mode
        error = "almanac storage unavailable" if mode == "write" else "sql: transaction has already been committed or rolled back"
        text = "STORAGE-ROLLBACK-NOT-DRAINED mode=" + mode + " error=" + error + " in_use=1\n"
        if status == "pass":
            text = "STORAGE-DRAINED mode=" + mode + " rollback=1 in_use=0 writer=0 opened=1 closed=1\n"
        result.extend(
            [
                {"Action": "run", "Package": rollback.PACKAGE, "Test": name},
                {"Action": "output", "Package": rollback.PACKAGE, "Test": name, "Output": text},
                {"Action": status, "Package": rollback.PACKAGE, "Test": name},
            ]
        )
    return result + [{"Action": status, "Package": rollback.PACKAGE, "Test": "TestDraining"}, {"Action": status, "Package": rollback.PACKAGE}]


def fixture(*, failed: bool = False) -> dict[str, bytes]:
    """Share the existing bounded collector shape; these bytes remain inadmissible as real native evidence."""
    files = {name.replace("command/", PREFIX, 1) if name.startswith("command/") else name: data for name, data in admission_fixture(modern=True).items()}
    record = v.decode(files[PREFIX + "record.json"])
    data = stream(events())
    files[PREFIX + "stdout.log"] = data
    record["stdout"] = {"path": "stdout.log", "bytes": len(data), "sha256": v.digest(data)}
    files[PREFIX + "record.json"] = v.encode(record)
    inputs = v.decode(files["inputs.json"])
    inputs.update({"selections": [], "auxiliary": [{"id": record["id"], "argv": record["argv"], "environment": record["environment"]}]})
    files["inputs.json"] = v.encode(inputs)
    owner = v.decode(files["controller.json"])
    owner["inputs_sha256"] = v.digest(files["inputs.json"])
    files["controller.json"] = v.encode(owner)
    terminal = v.decode(files["terminal.json"])
    terminal["errors"] = ["AssertionError: "] if failed else []
    files["terminal.json"] = v.encode(terminal)
    cleanup = v.decode(files["cleanup.native.json"])
    cleanup["original_exit_code"] = 1 if failed else 0
    cleanup["unit"]["ExecMainStatus"] = str(cleanup["original_exit_code"])
    files["cleanup.native.json"] = v.encode(cleanup)
    messages = [
        "Started astra-fixture.service - fixture",
        json.dumps(terminal),
        "astra-fixture.service: Main process exited, code=exited, status=1/FAILURE" if failed else "astra-fixture.service: Deactivated successfully.",
    ]
    files["journal.native.jsonl"] = stream(
        [{"_BOOT_ID": owner["boot_id"].replace("-", ""), "INVOCATION_ID": owner["invocation_id"], "MESSAGE": message} for message in messages]
    )
    return files


class RollbackTests(unittest.TestCase):
    """Keep provenance, resource, source and prerequisite refusals independently observable."""

    def test_archives(self) -> None:
        """Only exact reviewed archive names and bytes may enter native interpretation."""
        with self.assertRaises(v.Invalid):
            rollback.archive(b"not an archive", rollback.READ)
        with self.assertRaises(v.Invalid):
            rollback.archive(b"not an archive", "foreign")
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            member = tarfile.TarInfo("source.tar.gz")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        raw = buffer.getvalue()
        with patch.dict(rollback.ARCHIVES, {rollback.ORIGINAL: v.digest(raw)}):
            self.assertEqual(rollback.archive(raw, rollback.ORIGINAL), {"source.tar.gz": b"x"})
            with self.assertRaises(v.Invalid):
                rollback.archive(raw + b"changed", rollback.ORIGINAL)
        with self.assertRaises(v.Invalid):
            rollback.reconcile(ROOT, {})

    def test_cases(self) -> None:
        """A crash, wrong resource result, missing leaf or repeated observation cannot stand in for a semantic pair."""
        baseline = events()
        self.assertIsNone(rollback.cases(baseline, ("write",), "fail"))
        self.assertIsNone(rollback.cases(events(("read",)), ("read",), "fail"))
        self.assertIsNone(rollback.cases(events(("read", "write"), "pass"), ("read", "write"), "pass"))
        swapped = events(("read",))
        swapped[2]["Output"] = swapped[2]["Output"].replace("sql: transaction has already been committed or rolled back", "almanac storage unavailable")
        with self.assertRaises(v.Invalid):
            rollback.cases(swapped, ("read",), "fail")
        mutations = [
            [],
            baseline[1:],
            baseline[:-1],
            baseline + [baseline[-1]],
            baseline + [baseline[0]],
            [row for row in baseline if row.get("Action") != "output"],
            [row for row in baseline if row.get("Test") != "TestDraining/write"],
        ]
        for index, field, value in [
            (0, "Package", "foreign"),
            (1, "Action", "skip"),
            (1, "Action", "build-fail"),
            (1, "Action", "pass"),
            (2, "Action", "run"),
            (2, "Test", "TestDraining/read"),
            (2, "Output", "wrong reason\n"),
            (2, "Output", baseline[2]["Output"].replace("in_use=1", "in_use=0")),
            (2, "Output", baseline[2]["Output"] + "extra\n"),
            (2, "Output", baseline[2]["Output"].replace("mode=write", "mode=read")),
        ]:
            changed = copy.deepcopy(baseline)
            changed[index][field] = value
            mutations.append(changed)
        mutations.append(baseline + [baseline[2]])
        mutations.append(baseline + [{"Action": "bogus", "Package": rollback.PACKAGE}])
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(v.Invalid):
                rollback.cases(changed, ("write",), "fail")
        green = events(("read", "write"), "pass")
        for old, new in [
            ("rollback=1", "rollback=0"),
            ("in_use=0", "in_use=1"),
            ("writer=0", "writer=1"),
            ("opened=1", "opened=2"),
            ("closed=1", "closed=0"),
            ("mode=read", "mode=write"),
            ("\n", "\nextra\n"),
        ]:
            changed = copy.deepcopy(green)
            changed[2]["Output"] = changed[2]["Output"].replace(old, new)
            with self.subTest(old=old), self.assertRaises(v.Invalid):
                rollback.cases(changed, ("read", "write"), "pass")

    def test_command(self) -> None:
        """Authentic expected-red exits require complete hashed channels and native command ownership."""
        files = fixture()
        self.assertEqual(rollback.native(files, PREFIX)[1]["exit_code"], 1)
        record = v.decode(files[PREFIX + "record.json"])
        for field, value in [
            ("exit_code", 0),
            ("complete", False),
            ("cleanup", False),
            ("termination", "timeout"),
            ("executable_sha256", "0" * 64),
            ("id", "foreign"),
            ("argv", ["go", "version"]),
            ("environment", {"GOFLAGS": "foreign"}),
            ("finished_at", "2025-01-01T00:00:00Z"),
        ]:
            with self.subTest(field=field), self.assertRaises(v.Invalid):
                rollback.native({**files, PREFIX + "record.json": v.encode({**record, field: value})}, PREFIX)
        with self.assertRaises(v.Invalid):
            rollback.native({**files, PREFIX + "stdout.log": files[PREFIX + "stdout.log"] + b"changed"}, PREFIX)

    def test_lifecycle(self) -> None:
        """A known enclosing parser failure stays failed; live, foreign, cancelled or unknown outcomes are refused."""
        files = fixture()
        self.assertEqual(rollback.native(files, PREFIX)[0], {"fixture.txt": b"synthetic source"})
        failed = fixture(failed=True)
        self.assertEqual(rollback.native(failed, PREFIX, failed=True)[1]["exit_code"], 1)
        with self.assertRaises(v.Invalid):
            rollback.native(failed, PREFIX)
        changes = [
            ("terminal.json", "errors", ["unknown error"]),
            ("terminal.json", "interrupted", True),
            ("terminal.json", "remaining_owned", [7]),
            ("terminal.json", "cache_restored", False),
            ("terminal.json", "at", "2025-01-01T00:00:00Z"),
            ("cleanup.native.json", "original_exit_code", 1),
            ("cleanup.native.json", "source_verified", 0),
            ("cleanup.native.json", "cache_inode", 0),
            ("controller.json", "boot_id", "foreign"),
            ("controller.json", "inputs_sha256", "0" * 64),
            (PREFIX + "fixture.process.json", "boot_id", "foreign"),
            (PREFIX + "fixture.process.json", "cwd", "/foreign"),
            (PREFIX + "fixture.process.json", "argv", ["foreign"]),
        ]
        for name, field, value in changes:
            changed = {**v.decode(files[name]), field: value}
            with self.subTest(name=name, field=field), self.assertRaises(v.Invalid):
                rollback.native({**files, name: v.encode(changed)}, PREFIX)
        cleanup = v.decode(files["cleanup.native.json"])
        for field, value in [("MainPID", "7"), ("ControlGroup", "/live"), ("InvocationID", "foreign"), ("ExecMainStatus", "1")]:
            changed = {**cleanup, "unit": {**cleanup["unit"], field: value}}
            with self.subTest(field=field), self.assertRaises(v.Invalid):
                rollback.native({**files, "cleanup.native.json": v.encode(changed)}, PREFIX)
        with self.assertRaises(v.Invalid):
            rollback.native({**files, PREFIX + "extra.process.json": files[PREFIX + "fixture.process.json"]}, PREFIX)
        with self.assertRaises(v.Invalid):
            rollback.native({**files, "journal.native.jsonl": b""}, PREFIX)
        # The current collector has a different explicit cache/terminal format; legacy records keep their own checks.
        current = rollback.archive(v.read(ROOT / "build/results/assurance" / rollback.CURRENT, 64 * 1024**2), rollback.CURRENT)
        name = "storage-idle-lifecycle-current-1"
        commands = ("storage-lifecycle", "storage-termination", "storage-draining", "storage-borrowing", "lifecycle-reader-controls")
        source, records, outputs = consumers.native(current, name, commands=commands, collected=True)
        self.assertEqual(records["storage-draining"]["exit_code"], 0)
        self.assertEqual(records["storage-draining"]["resolved_environment"]["GOMAXPROCS"], "4")
        self.assertEqual(v.digest(source[rollback.FIXTURE]), rollback.COUNTEREXAMPLE)
        self.assertTrue(outputs["storage-draining"])
        for path, field, value in (
            ("terminal.json", "errors", ["unknown"]),
            ("terminal.json", "cache_restored", True),
            ("cache-return.native.json", "remaining_owned", [1]),
            ("cache-handoff.native.json", "owner", {}),
            ("controller.json", "boot_id", "foreign"),
        ):
            changed = {**current, path: v.encode({**v.decode(current[path]), field: value})}
            with self.subTest(current=path, field=field), self.assertRaises(v.Invalid):
                consumers.native(changed, name, commands=commands, collected=True)
        prefix = consumers.PREFIX + "lifecycle-reader-controls/"
        record = records["lifecycle-reader-controls"]
        for field, value in (("resolved_environment", {}), ("toolchain", {}), ("duration_ms", 1000000)):
            changed = {**current, prefix + "record.json": v.encode({**record, field: value})}
            with self.subTest(python=field), self.assertRaises(v.Invalid):
                consumers.native(changed, name, commands=commands, collected=True)

        # Synthetic declaration changes exercise expansion only; their bytes never pass the pinned archive boundary.
        inputs = v.decode(current["inputs.json"])
        inputs["auxiliary"][0]["environment"] = {"TMPDIR": "{run}/tmp"}
        owner = v.decode(current["controller.json"])
        owner["inputs_sha256"] = v.digest(v.encode(inputs))
        temporary = owner["cwd"] + "/source/build/commands/lifecycle-reader-controls/tmp"
        declared = {**record, "environment": {"TMPDIR": "{run}/tmp"}, "resolved_environment": {**record["resolved_environment"], "TMPDIR": temporary}}
        expanded = {
            **current,
            "inputs.json": v.encode(inputs),
            "controller.json": v.encode(owner),
            prefix + "record.json": v.encode(declared),
            **{path: v.encode({**v.decode(current[path]), "owner": owner}) for path in ("cache-handoff.native.json", "cache-return.native.json")},
        }
        self.assertEqual(
            consumers.native(expanded, name, commands=commands, collected=True)[1]["lifecycle-reader-controls"]["resolved_environment"]["TMPDIR"], temporary
        )
        displaced = {**declared, "resolved_environment": {**declared["resolved_environment"], "TMPDIR": temporary.replace("/source/build/", "/build/")}}
        with self.assertRaises(v.Invalid):
            consumers.native({**expanded, prefix + "record.json": v.encode(displaced)}, name, commands=commands, collected=True)

    def test_inputs(self) -> None:
        """Source inventory, Git mirror, cache handoff and service journal remain independently bound."""
        files = fixture()
        self.assertEqual(len(rollback.native(files, PREFIX)[0]), 1)
        for name, field, value in [
            ("git-mirror.native.json", "origin_source", {}),
            ("git-mirror.native.json", "source", {"files": []}),
            ("cache-handoff.native.json", "inode", 0),
            ("cache-handoff.native.json", "to", "/foreign"),
            ("cache-restored.native.json", "inode", 0),
            ("cache-restored.native.json", "path", "/foreign"),
            ("cache-restored.native.json", "remaining_owned", [7]),
            ("controller.json", "script_sha256", "0" * 64),
        ]:
            with self.subTest(name=name, field=field), self.assertRaises(v.Invalid):
                rollback.native({**files, name: v.encode({**v.decode(files[name]), field: value})}, PREFIX)
        for name in ["run.py", "source.tar.gz"]:
            with self.subTest(name=name), self.assertRaises(v.Invalid):
                rollback.native({**files, name: files[name] + b"changed"}, PREFIX)

    def test_overlay(self) -> None:
        """No helper, omitted file, foreign destination or different historical implementation may be overlaid."""
        owner = {"cwd": "/fixture"}
        before = {name: name.encode() for name in rollback.PRODUCTION}
        paths = {name: "source/build/storage-before/" + Path(name).name for name in before}
        replace = {"/fixture/source/" + name: "/fixture/" + path for name, path in paths.items()}
        files = {path: before[name] for name, path in paths.items()}
        files["source/build/storage-before/overlay.json"] = v.encode({"Replace": replace})
        self.assertEqual(rollback.overlay(files, owner, before), {name: v.digest(data) for name, data in before.items()})
        for changed in [{}, {**replace, "/fixture/source/helper.go": "/fixture/helper.go"}, {**replace, next(iter(replace)): "/foreign"}]:
            with self.subTest(changed=changed), self.assertRaises(v.Invalid):
                rollback.overlay({**files, "source/build/storage-before/overlay.json": v.encode({"Replace": changed})}, owner, before)
        for name, path in paths.items():
            with self.subTest(name=name), self.assertRaises(v.Invalid):
                rollback.overlay({**files, path: b"different implementation"}, owner, before)
        with self.assertRaises(v.Invalid):
            rollback.overlay(files, {"cwd": "/foreign"}, before)

    def test_sources(self) -> None:
        """A current-source claim requires the full nonempty compiler-owned closure and matching bytes."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "owned.go").write_bytes(b"owned")
            source, expected = {"owned.go": b"owned"}, {"owned.go": v.digest(b"owned")}
            self.assertIsNone(rollback.binding(root, source, expected))
            for original, bindings in [(source, {}), ({}, expected), ({"owned.go": b"changed"}, expected), (source, {"owned.go": "0" * 64})]:
                with self.subTest(bindings=bindings), self.assertRaises(v.Invalid):
                    rollback.binding(root, original, bindings)
            (root / "owned.go").write_bytes(b"changed")
            with self.assertRaises(v.Invalid):
                rollback.binding(root, source, expected)
        historical = rollback.archive(v.read(ROOT / "build/results/assurance" / rollback.GREEN, 64 * 1024**2), rollback.GREEN)
        current = rollback.archive(v.read(ROOT / "build/results/assurance" / rollback.CURRENT, 64 * 1024**2), rollback.CURRENT)
        before, after = (entry.unpack(value["source.tar.gz"]) for value in (historical, current))
        self.assertIsNone(consumers.sources(before, after))
        for path in (
            "polaris/internal/storage/store.go",
            "polaris/internal/storage/maintenance.go",
            "polaris/internal/storage/maintenance_test.go",
            "polaris/internal/storage/storage_test.go",
            "polaris/internal/storage/compatibility_test.go",
            "go.mod",
        ):
            with self.subTest(current_source=path), self.assertRaises(v.Invalid):
                consumers.sources(before, {**after, path: after[path] + b"\n"})
        with self.assertRaises(v.Invalid):
            consumers.sources(before, {**after, "polaris/internal/storage/unknown_test.go": b"package storage\n"})
        owner = {"cwd": "/fixture"}
        values = {
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
            "GOFLAGS": "-mod=readonly",
            "CGO_ENABLED": "1",
            "GOCACHE": "/fixture/source/build/cache/go",
            "TMPDIR": "/fixture/source/build/commands/example/tmp",
        }
        record = {"id": "example", "resolved_environment": values}
        self.assertEqual(rollback.environment(record, owner), {**values, "GOCACHE": "{root}/build/cache/go", "TMPDIR": "{run}/tmp"})
        for name in values:
            with self.subTest(name=name), self.assertRaises(v.Invalid):
                rollback.environment({**record, "resolved_environment": {**values, name: "foreign"}}, owner)

    def test_observations(self) -> None:
        """An assembled JSON claim must equal independent native reconstruction, not merely name a rule."""
        actual = {"cases": ["TestDraining/read", "TestDraining/write"], "trust": "local"}
        with patch.object(rollback, "reconcile", return_value=actual) as recompute:
            self.assertEqual(rollback.observations(v.encode(actual), rollback.CHECK, ROOT), ({"STORAGE-ASSURANCE": 2}, []))
            recompute.assert_called_once_with(ROOT)
            for changed in [{}, {**actual, "cases": []}, {**actual, "trust": "ci"}]:
                with self.subTest(changed=changed), self.assertRaises(v.Invalid):
                    rollback.observations(v.encode(changed), rollback.CHECK, ROOT)
        with patch.object(rollback, "reconcile", side_effect=KeyError("missing native facts")), self.assertRaises(v.Invalid):
            rollback.observations(v.encode(actual), rollback.CHECK, ROOT)

    def test_renewal(self) -> None:
        """Both current profiles retain the original causal failures and exact read/write resource histories."""
        result = rollback.reconcile(ROOT)
        self.assertEqual(result["current"]["compiler"], "1.27.2")
        self.assertEqual(result["current"]["fixture_sha256"], rollback.COUNTEREXAMPLE)
        self.assertEqual(set(result["current"]["profiles"]), {"ordinary", "race"})
        self.assertEqual(result["native"][rollback.WRITE]["command_exit_code"], 1)
        self.assertEqual(result["native"][rollback.WRITE]["runner_exit_code"], 1)
        self.assertEqual(result["native"][rollback.READ]["command_exit_code"], 1)
        self.assertEqual(result["native"][rollback.GREEN]["command_exit_code"], 0)
        self.assertEqual(result["current"]["previous"]["GOMAXPROCS"], "4")
        for profile in result["current"]["profiles"].values():
            self.assertEqual(profile["cases"], ["TestDraining/read", "TestDraining/write"])
            self.assertEqual(profile["GOMAXPROCS"], "2")
            self.assertIn("-parallel=4", profile["argv"])
        self.assertNotIn("-race", result["current"]["profiles"]["ordinary"]["argv"])
        self.assertIn("-race", result["current"]["profiles"]["race"]["argv"])

    def test_policy(self) -> None:
        """The exact two-case rule requires current core, oracle, cleanup and installed shipping-consumer protection."""
        config, _, _ = v.configuration(ROOT / "development.json")
        self.assertEqual(v.unique(config["checks"])[rollback.CHECK["id"]], rollback.CHECK)
        for field, value in [("native_tests", []), ("platforms", ["windows-amd64"]), ("argv", ["true"]), ("probes", []), ("extra", True), ("timeout_s", 3600)]:
            with self.subTest(field=field), self.assertRaises(v.Invalid):
                rollback.configuration({**rollback.CHECK, field: value})
        config = copy.deepcopy(config)
        config["components"] = [next(item for item in config["components"] if item["id"] == "polaris-storage")]
        obligations = v.expand(config)
        _, dependencies = v.dependency_order(obligations)
        key = "polaris-storage/DEV-REDGREEN/STORAGE-ASSURANCE/linux-amd64-cgo/full-rule"
        self.assertEqual(len(obligations), 74)
        self.assertEqual(obligations["polaris-storage/DEV-SCOPE/STORAGE-ASSURANCE/linux-amd64-cgo/source-inventory"]["checks"], ["gap-scope"])
        self.assertEqual(
            obligations[key]["requires"],
            [{"rule": rule, "contract": "STORAGE-ASSURANCE", "scenario": "full-rule"} for rule in ["DEV-CORE", "DEV-MATRIX", "DEV-ORACLE", "DEV-STOP"]],
        )
        required, pending = {key}, [key]
        while pending:
            for child in dependencies[pending.pop()]:
                if child not in required:
                    required.add(child)
                    pending.append(child)
        observations = {
            (check, obligations[name]["platform"], obligations[name]["contract"]): "passed" for name in required for check in obligations[name]["checks"]
        }
        self.assertIn(("gap-delivery-matrix", "linux-amd64-cgo", "STORAGE-ASSURANCE"), observations)
        now = v.stamp("2026-10-12T00:00:00Z")
        self.assertIn(key, v.decide(config, observations, [], [], now)["passed"])
        for coordinate in observations:
            for status in [None, "failed", "unknown", "skipped"]:
                changed = dict(observations)
                del changed[coordinate]
                if status is not None:
                    changed[coordinate] = status
                with self.subTest(coordinate=coordinate, status=status):
                    self.assertNotIn(key, v.decide(config, changed, [], [], now)["passed"])
