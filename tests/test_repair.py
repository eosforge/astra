"""Falsify Admission repair interpretation using synthetic records, never fabricated product evidence."""

import copy
import io
import json
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch

from tools import entry, repair, verify as v

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "github.com/eosforge/astra/internal/admission"
PREFIX = "command/"


def stream(rows: list[dict]) -> bytes:
    """Preserve the actual JSON-lines transport rather than pretty-printing individual frames."""
    return b"".join(json.dumps(row, separators=(",", ":")).encode() + b"\n" for row in rows)


def events(*, status: str = "fail", package: str = PACKAGE, names: set[str] | None = None) -> list[dict]:
    """Build explicitly synthetic nested-case streams with one package terminal and a target reason."""
    selected = repair.CASES if names is None else names
    parents = {name.rsplit("/", 1)[0] for name in selected if "/" in name}
    result = []
    for name in sorted(selected | parents):
        result.extend(
            [
                {"Action": "run", "Package": package, "Test": name},
                {"Action": "output", "Package": package, "Test": name, "Output": "replacement material published an identity\n"},
                {"Action": status, "Package": package, "Test": name},
            ]
        )
    return result + [{"Action": status, "Package": package}]


def fixture(*, modern: bool = False) -> dict[str, bytes]:
    """Construct a small native-shaped fixture; the pinned archive boundary cannot admit it as a real run."""
    raw = stream(events())
    record = {
        "id": "fixture",
        "platform": "linux-amd64-cgo",
        "argv": ["go", "test", "-json", "./internal/admission"],
        "environment": {},
        "resolved_environment": {},
        "executable": "/fixture/go",
        "executable_sha256": repair.GO,
        "toolchain": {"command": {"path": "/fixture/go", "sha256": repair.GO}},
        "duration_ms": 1,
        "exit_code": 1,
        "termination": "exited",
        "complete": True,
        "cleanup": True,
        "started_at": "2026-10-11T00:00:00Z",
        "finished_at": "2026-10-11T00:00:01Z",
        "stdout": {"path": "stdout.log", "bytes": len(raw), "sha256": v.digest(raw)},
        "stderr": {"path": "stderr.log", "bytes": 0, "sha256": v.digest(b"")},
    }
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as output:
        item = tarfile.TarInfo("fixture.txt")
        item.size = len(b"synthetic source")
        output.addfile(item, io.BytesIO(b"synthetic source"))
    inputs = {
        "archive_sha256": v.digest(archive.getvalue()),
        "files": {"fixture.txt": v.digest(b"synthetic source")},
        "source": {"files": [{"path": "fixture.txt", "sha256": v.digest(b"synthetic source")}], "commit": None},
    }
    owner = {
        "boot_id": "fixture-boot",
        "cwd": "/fixture",
        "identity": {"pid": 7, "start_ticks": "7"},
        "invocation_id": "fixture-invocation",
        "script_sha256": v.digest(b"synthetic runner"),
    }
    child = {"boot_id": owner["boot_id"], "identity": {"pid": 8, "start_ticks": "8", "parent": 7}, "argv": record["argv"], "cwd": "/fixture/source"}
    terminal = {"errors": [], "interrupted": False, "remaining_owned": [], "source_unchanged": True}
    cleanup = {
        "boot_id": owner["boot_id"],
        "retired": [owner["identity"], child["identity"]],
        "unit": {"MainPID": "0", "ControlGroup": "", "InvocationID": "", "ExecMainStatus": "0"},
    }
    files = {
        PREFIX + "record.json": v.encode(record),
        PREFIX + "stdout.log": raw,
        PREFIX + "stderr.log": b"",
        PREFIX + "fixture.process.json": v.encode(child),
        "source.tar.gz": archive.getvalue(),
        "run.py": b"synthetic runner",
    }
    if modern:
        inputs["source_archive_sha256"] = inputs.pop("archive_sha256")
        inputs.update({"run_sha256": owner["script_sha256"], "boot_id": owner["boot_id"]})
        owner["inputs_sha256"] = v.digest(v.encode(inputs))
        terminal = {"at": "2026-10-11T00:00:01Z", **terminal, "cache_restored": True}
        cleanup.update({"source_verified": 1, "original_exit_code": 0, "cache_inode": 713912})
        files.update(
            {
                "git-mirror.native.json": v.encode({"origin_source": inputs["source"], "source": inputs["source"]}),
                "cache-restored.native.json": v.encode({"inode": 713912, "path": "/original/go", "remaining_owned": []}),
                "cache-handoff.native.json": v.encode({"inode": 713912, "from": "/original/go", "to": "/fixture/source/build/cache/go"}),
            }
        )
        journal = ["Started astra-fixture.service - fixture", json.dumps(terminal), "astra-fixture.service: Deactivated successfully."]
        files["journal.native.jsonl"] = stream(
            [{"_BOOT_ID": "fixtureboot", "INVOCATION_ID": owner["invocation_id"], "MESSAGE": message} for message in journal]
        )
    files.update(
        {
            name: v.encode(value)
            for name, value in {"inputs.json": inputs, "controller.json": owner, "terminal.json": terminal, "cleanup.native.json": cleanup}.items()
        }
    )
    return files


class RepairTests(unittest.TestCase):
    """Exercise each refusal boundary independently of the immutable real product archives."""

    def test_policy(self) -> None:
        """A smaller denominator, foreign platform, changed command or relaxed configuration cannot qualify."""
        repair.configuration(repair.CHECK)
        config, _, _ = v.configuration(ROOT / "development.json")
        self.assertEqual(v.unique(config["checks"])[repair.CHECK["id"]], repair.CHECK)
        for field, value in (("native_tests", []), ("platforms", ["windows-amd64"]), ("timeout_s", 3600), ("argv", ["true"]), ("probes", []), ("extra", True)):
            with self.subTest(field=field), self.assertRaises(v.Invalid):
                repair.configuration({**repair.CHECK, field: value})

    def test_archives(self) -> None:
        """Empty, extra, unreviewed and rewritten archives supply no product observation."""
        for artifacts in ({}, {name: b"synthetic" for name in repair.ARCHIVES}, {**{name: b"" for name in repair.ARCHIVES}, "extra": b""}):
            with self.subTest(names=list(artifacts)), self.assertRaises(v.Invalid):
                repair.reconcile(ROOT, artifacts)
        for name in [*repair.ARCHIVES, "unknown"]:
            with self.subTest(name=name), self.assertRaisesRegex(v.Invalid, "repair-archive-integrity"):
                repair.archive(b"synthetic", name)

    def test_command(self) -> None:
        """Expected-red requires the real failure status, complete ownership and intact native channels."""
        files = fixture()
        record = v.decode(files[PREFIX + "record.json"])
        self.assertEqual(repair.command(files, PREFIX, 1), (record, events()))
        for field, value in (
            ("exit_code", 0),
            ("platform", "windows-amd64"),
            ("complete", False),
            ("cleanup", False),
            ("termination", "timeout"),
            ("executable_sha256", "0" * 64),
            ("finished_at", "2026-10-10T00:00:00Z"),
            ("toolchain", {"command": {"path": "/foreign", "sha256": repair.GO}}),
        ):
            with self.subTest(field=field), self.assertRaises(v.Invalid):
                repair.command({**files, PREFIX + "record.json": v.encode({**record, field: value})}, PREFIX, 1)
        for channel in ("stdout", "stderr"):
            with self.subTest(channel=channel), self.assertRaises(v.Invalid):
                repair.command({**files, PREFIX + channel + ".log": b"replaced"}, PREFIX, 1)
        for path in ("../stdout.log", "/stdout.log", "nested/stdout.log"):
            changed = {**record, "stdout": {**record["stdout"], "path": path}}
            with self.subTest(path=path), self.assertRaisesRegex(v.Invalid, "repair-channel-path"):
                repair.command({**files, PREFIX + "record.json": v.encode(changed)}, PREFIX, 1)
        changed = {**record, "stderr": {"path": "stderr.log", "bytes": 1, "sha256": v.digest(b"!")}}
        with self.assertRaisesRegex(v.Invalid, "repair-command-diagnostic"):
            repair.command({**files, PREFIX + "record.json": v.encode(changed), PREFIX + "stderr.log": b"!"}, PREFIX, 1)

    def test_cases(self) -> None:
        """Unrelated crashes, absent target reasons, duplicate terminals and empty selections are refused."""
        original = events()
        repair.cases(original, repair.CASES, "fail", "replacement material published an identity")
        damaged = [[], original[:-1], original + original[:1], original + original[-1:]]
        damaged += [[row for row in original if row.get("Action") != action] for action in ("run", "fail")]
        damaged += [[{**row, "Action": action} if row.get("Action") == "fail" else row for row in original] for action in ("skip", "build-fail", "pass")]
        damaged += [[{**row, "Output": "unrelated crash"} if row.get("Action") == "output" else row for row in original]]
        damaged += [[{**row, "Package": "foreign"} if index == 0 else row for index, row in enumerate(original)]]
        damaged += [original + [{"Action": "run", "Package": PACKAGE, "Test": "Unrelated"}, {"Action": "fail", "Package": PACKAGE, "Test": "Unrelated"}]]
        for rows in damaged:
            with self.subTest(rows=len(rows)), self.assertRaises(v.Invalid):
                repair.cases(rows, repair.CASES, "fail", "replacement material published an identity")
        for expected, status in ((set(), "fail"), (repair.CASES, "unknown"), ({"Absent"}, "fail")):
            with self.subTest(expected=expected, status=status), self.assertRaises(v.Invalid):
                repair.cases(original, expected, status)

    def test_packages(self) -> None:
        """A broad historical green must finish both recorded packages without mixing or losing terminals."""
        packages = {PACKAGE, "github.com/eosforge/astra/polaris"}
        rows = events(status="pass") + events(status="pass", package="github.com/eosforge/astra/polaris", names={"TestProcess/admission"})
        repair.cases(rows, {"TestProcess/admission"}, "pass", packages=packages)
        for selected in (rows[:-1], rows + [{"Action": "fail", "Package": PACKAGE}], [{**row, "Package": "foreign"} for row in rows]):
            with self.subTest(rows=len(selected)), self.assertRaises(v.Invalid):
                repair.cases(selected, {"TestProcess/admission"}, "pass", packages=packages)
        with self.assertRaises(v.Invalid):
            repair.cases(rows, {"TestProcess/admission"}, "pass")

    def test_lifecycle(self) -> None:
        """Source drift, live resources, reused PID identities and foreign command ownership invalidate reuse."""
        files = fixture()
        self.assertEqual(repair.native(files, PREFIX), {"fixture.txt": b"synthetic source"})
        changes = [
            ("inputs.json", "archive_sha256", "0" * 64),
            ("inputs.json", "files", {}),
            ("controller.json", "script_sha256", "0" * 64),
            ("cleanup.native.json", "boot_id", "foreign"),
            ("cleanup.native.json", "retired", []),
            ("terminal.json", "errors", ["lost"]),
            ("terminal.json", "interrupted", True),
            ("terminal.json", "remaining_owned", [7]),
            ("terminal.json", "source_unchanged", False),
            (PREFIX + "fixture.process.json", "boot_id", "foreign"),
            (PREFIX + "fixture.process.json", "argv", ["foreign"]),
            (PREFIX + "fixture.process.json", "cwd", "/foreign"),
        ]
        for name, field, value in changes:
            changed = {**v.decode(files[name]), field: value}
            with self.subTest(name=name, field=field), self.assertRaises(v.Invalid):
                repair.native({**files, name: v.encode(changed)}, PREFIX)
        state = v.decode(files["cleanup.native.json"])
        for field, value in (("MainPID", "7"), ("ControlGroup", "/live"), ("InvocationID", "foreign"), ("ExecMainStatus", "1")):
            changed = {**state, "unit": {**state["unit"], field: value}}
            with self.subTest(field=field), self.assertRaises(v.Invalid):
                repair.native({**files, "cleanup.native.json": v.encode(changed)}, PREFIX)
        with self.assertRaisesRegex(v.Invalid, "repair-command-owner"):
            repair.native({**files, PREFIX + "duplicate.process.json": files[PREFIX + "fixture.process.json"]}, PREFIX)

    def test_current(self) -> None:
        """Current collections additionally bind source mirrors, returned caches and actual service journals."""
        files = fixture(modern=True)
        self.assertEqual(repair.native(files, PREFIX), {"fixture.txt": b"synthetic source"})
        for name, field, value in (
            ("controller.json", "inputs_sha256", "0" * 64),
            ("cleanup.native.json", "source_verified", 0),
            ("cleanup.native.json", "original_exit_code", 1),
            ("cleanup.native.json", "cache_inode", 0),
            ("terminal.json", "cache_restored", False),
            ("cache-handoff.native.json", "inode", 0),
            ("cache-restored.native.json", "inode", 0),
            ("cache-restored.native.json", "path", "/foreign"),
            ("cache-restored.native.json", "remaining_owned", [7]),
            ("git-mirror.native.json", "origin_source", {}),
        ):
            changed = {**v.decode(files[name]), field: value}
            with self.subTest(name=name, field=field), self.assertRaises(v.Invalid):
                repair.native({**files, name: v.encode(changed)}, PREFIX)
        for journal in (b"", files["journal.native.jsonl"].splitlines(keepends=True)[0], files["journal.native.jsonl"].replace(b"fixtureboot", b"foreign")):
            with self.subTest(journal=journal[:30]), self.assertRaisesRegex(v.Invalid, "repair-native-journal"):
                repair.native({**files, "journal.native.jsonl": journal}, PREFIX)

    def test_observations(self) -> None:
        """Declared counts cannot replace independent facts, and missing material fails closed."""
        actual = {"repairs": {"cancellation": {"cases": ["one"]}, "replacement": {"cases": ["two", "three", "four", "five", "six"]}}}
        with patch.object(repair, "reconcile", return_value=actual):
            self.assertEqual(repair.observations(v.encode(actual), repair.CHECK, ROOT), ({"ADMISSION-ASSURANCE": 6}, []))
            for data in (b"{}", v.encode({**actual, "passed": True})):
                with self.subTest(data=data), self.assertRaisesRegex(v.Invalid, "repair-observation-mismatch"):
                    repair.observations(data, repair.CHECK, ROOT)
            self.assertEqual(v.parse_observations(v.encode(actual), repair.CHECK, ROOT), ({"ADMISSION-ASSURANCE": 6}, []))
        with patch.object(repair, "reconcile", side_effect=OSError("missing")), self.assertRaisesRegex(v.Invalid, "repair-facts-unavailable"):
            repair.observations(b"{}", repair.CHECK, ROOT)

    def test_renewal(self) -> None:
        """Real current greens retain old causal evidence and refuse changed native commands or omitted cases."""
        from tools import qualificationdata

        result = repair.reconcile(ROOT)
        self.assertEqual(set(result["current"]["module_changes"]), {"go.mod", "go.sum"})
        self.assertEqual(sum(len(item["cases"]) for item in result["repairs"].values()), 6)
        self.assertEqual(set(result["current"]["profiles"]), {"ordinary", "race"})
        self.assertNotEqual(result["current"]["historical_fixture_sha256"], result["current"]["current_fixture_sha256"])
        for profile in result["current"]["profiles"].values():
            self.assertEqual(profile["cases"], repair.CHECK["native_tests"])
            self.assertEqual(profile["GOMAXPROCS"], "2")
        name = next(iter(repair.RENEWED))
        raw = v.read(ROOT / "build/results/assurance/reuse-plan" / name, 64 * 1024**2)
        self.assertEqual(v.digest(raw), repair.RENEWED[name])
        files = qualificationdata.unpack(raw)
        bindings = {name: result["bindings"][name] for name in result["historical_bindings"]}
        fixture = result["current"]["historical_fixture_sha256"]
        prefix = "source/build/commands/root-ordinary-test/"
        record = v.decode(files[prefix + "record.json"])
        for changed in (record | {"cleanup": False}, record | {"duration_ms": 900001}, record | {"argv": ["true"]}):
            with self.subTest(record=changed["argv"]), self.assertRaisesRegex(v.Invalid, "repair-current-command"):
                repair.profiles(ROOT, files | {prefix + "record.json": v.encode(changed)}, bindings, fixture)
        terminal = v.decode(files["terminal.json"])
        with self.assertRaisesRegex(v.Invalid, "repair-current-native"):
            repair.profiles(ROOT, files | {"terminal.json": v.encode(terminal | {"errors": ["original failure"]})}, bindings, fixture)
        path = prefix + record["stdout"]["path"]
        self.assertIn(b"TestLoadReplacement/cert.pem", files[path])
        changed = files[path].replace(b"TestLoadReplacement/cert.pem", b"TestLoadReplacement/absent")
        reference = record["stdout"] | {"bytes": len(changed), "sha256": v.digest(changed)}
        with self.assertRaisesRegex(v.Invalid, "repair-case-missing-or-duplicate"):
            repair.profiles(ROOT, files | {path: changed, prefix + "record.json": v.encode(record | {"stdout": reference})}, bindings, fixture)

    def test_prerequisites(self) -> None:
        """Real source/oracle/cleanup and shipping-consumer obligations remain mandatory around the defect pair."""
        config, _, _ = v.configuration(ROOT / "development.json")
        config = copy.deepcopy(config)
        config["components"] = [next(item for item in config["components"] if item["id"] == "admission")]
        obligations = v.expand(config)
        _, dependencies = v.dependency_order(obligations)
        key = "admission/DEV-REDGREEN/ADMISSION-ASSURANCE/linux-amd64-cgo/full-rule"
        parents = {"DEV-CORE", "DEV-ORACLE", "DEV-STOP", "DEV-MATRIX"}
        self.assertEqual(len(obligations), 68)
        self.assertEqual(obligations[key]["requires"], [{"rule": rule, "contract": "ADMISSION-ASSURANCE", "scenario": "full-rule"} for rule in sorted(parents)])
        required, pending = {key}, [key]
        while pending:
            for child in dependencies[pending.pop()]:
                if child not in required:
                    required.add(child)
                    pending.append(child)
        observations = {
            (check, obligations[name]["platform"], obligations[name]["contract"]): "passed" for name in required for check in obligations[name]["checks"]
        }
        self.assertIn(("admission-gap-delivery-matrix", "linux-amd64-cgo", "ADMISSION-ASSURANCE"), observations)
        now = v.stamp("2026-10-12T00:00:00Z")
        self.assertIn(key, v.decide(config, observations, [], [], now)["passed"])
        for coordinate in observations:
            for status in (None, "failed", "unknown", "skipped"):
                changed = dict(observations)
                del changed[coordinate]
                if status is not None:
                    changed[coordinate] = status
                with self.subTest(coordinate=coordinate, status=status):
                    self.assertNotIn(key, v.decide(config, changed, [], [], now)["passed"])

    def test_consumer_profiles(self) -> None:
        """Project one complete declared consumer from real current root profiles without relabeling their argv or processor count."""
        name = "go-upgrade-contracts-current-3/native/evidence.tar.gz"
        raw = v.read(ROOT / "build/results/assurance/reuse-plan" / name, 64 * 1024**2)
        self.assertEqual(v.digest(raw), repair.RENEWED[name])
        files = entry.unpack(raw)
        config = v.decode(v.read(ROOT / "development.json"))
        expected = v.unique(config["checks"])["polaris-entry-qualification"]["native_tests"]
        package = "github.com/eosforge/astra/polaris"
        result = repair.profiles(ROOT, files, {}, "", inventory={package: expected})
        for profile in ("ordinary", "race"):
            observed = result["profiles"][profile]
            self.assertEqual(observed["GOMAXPROCS"], "2")
            self.assertEqual(observed["packages"][package]["expected"], sorted(expected))
            self.assertEqual(observed["packages"][package]["tests"], 50)
            self.assertIn("-parallel=2", observed["argv"])
            self.assertTrue(observed["record_sha256"] and observed["original_stdout_sha256"])
        for inventory in ({package: expected[:-1]}, {package: [*expected, expected[0]]}, {package + "/foreign": expected}):
            with self.subTest(inventory=list(inventory)), self.assertRaises(v.Invalid):
                repair.profiles(ROOT, files, {}, "", inventory=inventory)
        with self.assertRaisesRegex(v.Invalid, "repair-current-compiled-source"):
            repair.profiles(ROOT, files, {"go.mod": "0" * 64}, "", inventory={package: expected})
