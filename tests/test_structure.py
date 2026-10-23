"""Challenge the bounded Command structure adapter with missing, altered and uncovered native-profile inputs."""

from collections.abc import Iterator
import copy
import base64
import datetime as dt
import json
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import (
    admission,
    authority,
    batches,
    consumers,
    entry,
    independence,
    ingress,
    installation,
    idle,
    logic,
    queries,
    replies,
    retention,
    statements,
    states,
    storage,
    structure,
    transactions,
    watchdog,
)
from tools import verify as v

ROOT = Path(__file__).resolve().parents[1]


class EntryTests(unittest.TestCase):
    """Reject weakened entry policies, unsafe archives and changed inputs without running application tests."""

    def test_policy(self) -> None:
        """The scoped reader must retain all obligations and the exact native inventory."""
        config, _, _ = v.configuration(ROOT / "development.json", ROOT)
        self.assertEqual(len(v.expand(config)), 1370)
        native = next(item for item in config["checks"] if item["id"] == "storage-structure")
        structure.configuration(native)
        archived = copy.deepcopy(native)
        archived["environment"]["PATH"] = "{cache}/tools/go-1.27.1/bin:{cache}/tools/gcc-16.2.0/bin:/usr/bin:/bin"
        with self.assertRaisesRegex(v.Invalid, "structure-environment"):
            structure.configuration(archived)
        structure.configuration(archived, retained=True)
        with self.assertRaisesRegex(v.Invalid, "structure-environment"):
            structure.configuration(native, retained=True)
        with self.assertRaisesRegex(v.Invalid, "structure-retained-policy"):
            structure.configuration(native, retained=1)
        check = next(item for item in config["checks"] if item["id"] == "polaris-entry-qualification")
        self.assertEqual(structure.selection(check), structure.ENTRY)
        self.assertEqual(structure.domain(structure.ENTRY)["counts"], [135, 37, 53, 7])
        for field, value in (("native_tests", check["native_tests"][:-1]), ("platforms", ["windows-amd64"]), ("timeout_s", 3600), ("argv", ["true"])):
            altered = copy.deepcopy(check)
            altered[field] = value
            with self.subTest(field=field), self.assertRaises(v.Invalid):
                structure.configuration(altered)
        check = next(item for item in config["checks"] if item["id"] == "admission-independence")
        structure.configuration(check)
        self.assertEqual(structure.selection(check), structure.PACKAGE)
        key = "admission/DEV-COVERAGE/ADMISSION-ASSURANCE/linux-amd64-cgo/mcdc"
        self.assertEqual({name for name, row in v.expand(config).items() if check["id"] in row["checks"]}, {key})
        self.assertEqual(check["probes"][0]["minimum_hits"], 165)
        self.assertEqual(check["native_tests"][-1], "TestLoadMetadata")
        for minimum in (164, 166):
            changed = copy.deepcopy(check)
            changed["probes"][0]["minimum_hits"] = minimum
            with self.subTest(minimum=minimum), self.assertRaises(v.Invalid):
                structure.configuration(changed)
        for field, value in (("native_tests", check["native_tests"][:-1]), ("platforms", ["windows-amd64"]), ("timeout_s", 3600), ("argv", ["true"])):
            changed = copy.deepcopy(check)
            changed[field] = value
            with self.subTest(admission=field), self.assertRaises(v.Invalid):
                structure.configuration(changed)
        check = next(item for item in config["checks"] if item["id"] == "astrolabe-independence")
        structure.configuration(check)
        self.assertEqual(structure.selection(check), structure.ASTROLABE)
        self.assertEqual(len(check["native_tests"]), 468)
        obligations = v.expand(config)
        prefix = "astrolabe/DEV-COVERAGE/ASTROLABE-ASSURANCE/linux-amd64-cgo/"
        self.assertEqual({name for name, row in obligations.items() if check["id"] in row["checks"]}, {prefix + "mcdc"})
        self.assertEqual(obligations[prefix + "structure"]["checks"], ["astrolabe-structure"])
        self.assertEqual(obligations[prefix + "mutation"]["checks"], ["astrolabe-qualification"])
        for minimum in (333, 335, 366):
            changed = copy.deepcopy(check)
            changed["probes"][0]["minimum_hits"] = minimum
            with self.subTest(astrolabe=minimum), self.assertRaises(v.Invalid):
                structure.configuration(changed)
        for field, value in (
            ("native_tests", check["native_tests"][:-1]),
            ("native_tests", list(reversed(check["native_tests"]))),
            ("native_tests", [name.split(":", 1)[1] for name in check["native_tests"]]),
            ("platforms", ["windows-amd64"]),
            ("timeout_s", 3600),
            ("argv", ["true"]),
            ("expected_tests", ["structure"]),
        ):
            changed = copy.deepcopy(check)
            changed[field] = value
            with self.subTest(astrolabe=field), self.assertRaises(v.Invalid):
                structure.configuration(changed)
        check = next(item for item in config["checks"] if item["id"] == "astrolabe-structure")
        structure.configuration(check)
        self.assertEqual(check["argv"], ["python3", "-B", "tools/structure.py", "--collect", "--package", "astrolabe"])
        self.assertEqual(check["native_tests"], next(item["native_tests"] for item in config["checks"] if item["id"] == "astrolabe-independence"))
        self.assertEqual(structure.domain(structure.ASTROLABE, structural=True)["counts"], [818, 361, 715, 73])
        self.assertEqual({name for name, row in obligations.items() if check["id"] in row["checks"]}, {prefix + "structure"})
        for field, value in (("probes", [{"contract": "ASTROLABE-ASSURANCE", "test": "structure", "minimum_hits": count}]) for count in (1966, 1968, 1972)):
            changed = copy.deepcopy(check)
            changed[field] = value
            with self.subTest(structure=value), self.assertRaises(v.Invalid):
                structure.configuration(changed)
        for field, value in (("argv", check["argv"] + ["--independence"]), ("expected_tests", ["independence"]), ("native_tests", check["native_tests"][:-1])):
            changed = copy.deepcopy(check)
            changed[field] = value
            with self.subTest(structure=field), self.assertRaises(v.Invalid):
                structure.configuration(changed)

    def test_archive(self) -> None:
        """Archive names, type, capacity and pinned bytes cannot be supplied by an unchecked report."""

        def archive(names: list[str], *, link: bool = False, size: int = 1) -> bytes:
            """Create small parser fixtures; they are never marked as native application evidence."""
            result = io.BytesIO()
            with tarfile.open(fileobj=result, mode="w:gz") as output:
                for name in names:
                    item = tarfile.TarInfo(name)
                    item.size = size
                    if link:
                        item.type, item.linkname = tarfile.SYMTYPE, "outside"
                        output.addfile(item)
                    else:
                        output.addfile(item, io.BytesIO(b"x" * size))
            return result.getvalue()

        self.assertEqual(entry.unpack(archive(["nested/file"])), {"nested/file": b"x"})
        for names in (["../file"], ["/file"], ["a/../file"], ["a\\file"], ["C:file"], ["a", "a"], ["a", "A"], ["a//file"]):
            with self.subTest(names=names), self.assertRaisesRegex(v.Invalid, "entry-archive-member"):
                entry.unpack(archive(names))
        with self.assertRaisesRegex(v.Invalid, "entry-archive-member"):
            entry.unpack(archive(["a"], link=True))
        with patch.object(entry, "LIMIT", 1), self.assertRaisesRegex(v.Invalid, "entry-archive-member"):
            entry.unpack(archive(["a", "b"]))
        with self.assertRaisesRegex(v.Invalid, "entry-archive-integrity"):
            entry.retained(archive(["a"]), "0" * 64)
        with self.assertRaisesRegex(v.Invalid, "entry-input-inventory"):
            entry.reconcile(ROOT, {})
        with patch.object(idle, "current", return_value=True):
            self.assertEqual(entry.artifacts(ROOT), consumers.ACQUISITION)
            with self.assertRaisesRegex(v.Invalid, "entry-current-archive-integrity"):
                entry.renew(ROOT, {name: b"untrusted archive" for name in consumers.ACQUISITION})
            with tempfile.TemporaryDirectory() as directory:
                predecessor = Path(directory)
                self.assertEqual(entry.artifacts(predecessor), entry.MAINTENANCE)
                with self.assertRaisesRegex(v.Invalid, "entry-current-archive-integrity"):
                    entry.renew(predecessor, {name: b"untrusted archive" for name in entry.MAINTENANCE})

    def test_sources(self) -> None:
        """Changing a dependency, fixture, lockfile or adding source invalidates reuse; unrelated docs do not."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = {
                "polaris/main.go": b"entry",
                "polaris/main_test.go": b"fixture",
                "internal/command/flags.go": b"dependency",
                "tools/decisions/main.go": b"collector",
                "go.mod": b"module",
                "go.sum": b"sums",
                "dependencies.lock.json": b"locks",
            }
            for name, data in values.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            facts = {
                "inputs.json": v.encode({"files": {name: v.digest(data) for name, data in values.items()}}),
                entry.PREFIX
                + "typed/exports/exports.stdout.log": b"\n".join(
                    v.encode({"ImportPath": "github.com/eosforge/astra/" + name}) for name in ("polaris", "internal/command")
                ),
            }
            with patch.object(entry, "SOURCE", v.digest(b"entry")):
                self.assertEqual(set(entry.sources(root, facts)), set(values))
                (root / "README.md").write_bytes(b"unrelated")
                self.assertEqual(set(entry.sources(root, facts)), set(values))
                for name, data in values.items():
                    (root / name).write_bytes(data + b"changed")
                    with self.subTest(name=name), self.assertRaisesRegex(v.Invalid, "entry-source-drift"):
                        entry.sources(root, facts)
                    (root / name).write_bytes(data)
                (root / "polaris/added.go").write_bytes(b"new")
                with self.assertRaisesRegex(v.Invalid, "entry-source-inventory"):
                    entry.sources(root, facts)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = {
                "polaris/main.go": b"entry",
                "polaris/main_test.go": b"entry fixture",
                "polaris/internal/server/service.go": b"server dependency",
                "polaris/internal/storage/store.go": b"storage dependency",
                "polaris/internal/storage/maintenance.go": b"owned maintenance dependency",
                "tools/decisions/main.go": b"collector",
                "tools/decisions/runtime.go.in": b"trace fixture",
                "proto/orbit.proto": b"protocol",
                "go.mod": b"module",
                "go.sum": b"sums",
                "dependencies.lock.json": b"locks",
            }
            for name, data in values.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            exports = b"\n".join(
                json.dumps({"ImportPath": "github.com/eosforge/astra/" + name}).encode()
                for name in ("polaris", "polaris/internal/server", "polaris/internal/storage")
            )
            with patch.object(entry, "SOURCE", v.digest(values["polaris/main.go"])):
                self.assertEqual(entry.bindings(root, values, values, exports), {name: v.digest(data) for name, data in values.items()})
                for name, data in values.items():
                    for target in ("workspace", "current archive", "Race archive"):
                        current, reused = dict(values), dict(values)
                        if target == "workspace":
                            (root / name).write_bytes(data + b"changed")
                        else:
                            (current if target == "current archive" else reused)[name] = data + b"changed"
                        with self.subTest(file=name, target=target), self.assertRaisesRegex(v.Invalid, "entry-current-source-drift"):
                            entry.bindings(root, current, reused, exports)
                        (root / name).write_bytes(data)
                omitted = {name: data for name, data in values.items() if name != "polaris/internal/storage/maintenance.go"}
                for current, reused in ((omitted, values), (values, omitted)):
                    with self.assertRaisesRegex(v.Invalid, "entry-current-(?:input|reuse)-inventory"):
                        entry.bindings(root, current, reused, exports)
                (root / "polaris/internal/storage/added.go").write_bytes(b"new production dependency")
                with self.assertRaisesRegex(v.Invalid, "entry-current-input-inventory"):
                    entry.bindings(root, values, values, exports)

    def test_missing_bundle(self) -> None:
        """A claimed stdout pass cannot replace retained native archives and a bound current source."""
        config = v.decode(v.read(ROOT / "development.json"))
        check = next(item for item in config["checks"] if item["id"] == "polaris-entry-qualification")
        with self.assertRaisesRegex(v.Invalid, "structure-evidence-missing"):
            structure.observations(b'{"status":"passed"}', check, ROOT, None)
        with tempfile.TemporaryDirectory() as name:
            path = Path(name)
            v.write_new(path / "bundle.json", {"version": 4, "source": {}, "retained": {}})
            with self.assertRaisesRegex(v.Invalid, "entry-bundle-version-or-inventory"):
                structure.load(path, ROOT, check, {})
            admission = next(item for item in config["checks"] if item["id"] == "admission-independence")
            with self.assertRaisesRegex(v.Invalid, "entry-bundle-version-or-inventory"):
                structure.load(path, ROOT, admission, {})
            with self.assertRaisesRegex(v.Invalid, "structure-evidence-missing"):
                structure.observations(b'{"status":"passed"}', admission, ROOT, None)
            astrolabe = next(item for item in config["checks"] if item["id"] == "astrolabe-independence")
            with self.assertRaisesRegex(v.Invalid, "entry-bundle-version-or-inventory"):
                structure.load(path, ROOT, astrolabe, {})
            with self.assertRaisesRegex(v.Invalid, "structure-evidence-missing"):
                structure.observations(b'{"status":"passed"}', astrolabe, ROOT, None)
            structural = next(item for item in config["checks"] if item["id"] == "astrolabe-structure")
            with self.assertRaisesRegex(v.Invalid, "entry-bundle-version-or-inventory"):
                structure.load(path, ROOT, structural, {})
            with self.assertRaisesRegex(v.Invalid, "structure-evidence-missing"):
                structure.observations(b'{"status":"passed"}', structural, ROOT, None)
        with tempfile.TemporaryDirectory() as name:
            path = Path(name)
            v.write_new(path / "bundle.json", {"version": 5, "source": {}, "retained": {}})
            current = next(item for item in config["checks"] if item["id"] == "admission-structure")
            with self.assertRaisesRegex(v.Invalid, "entry-bundle-version-or-inventory"):
                structure.load(path, ROOT, current, {})
            with self.assertRaisesRegex(v.Invalid, "structure-evidence-missing"):
                structure.observations(b'{"status":"passed"}', current, ROOT, None)
            with self.assertRaisesRegex(v.Invalid, "entry-bundle-version-or-inventory"):
                structure.load(path, ROOT, astrolabe, {})
            with self.assertRaisesRegex(v.Invalid, "entry-bundle-version-or-inventory"):
                structure.load(path, ROOT, structural, {})


# Synthetic parser input with the compiler's frozen native block coordinates; never release evidence.
PROFILE = b"""mode: atomic
github.com/eosforge/astra/internal/command/flags.go:15.2,15.24 1 1
github.com/eosforge/astra/internal/command/flags.go:16.3,17.1 1 1
github.com/eosforge/astra/internal/command/flags.go:18.2,18.29 1 1
github.com/eosforge/astra/internal/command/flags.go:22.2,22.15 1 1
github.com/eosforge/astra/internal/command/flags.go:23.3,24.1 1 1
github.com/eosforge/astra/internal/command/flags.go:25.2,26.30 2 1
github.com/eosforge/astra/internal/command/flags.go:30.2,32.1 2 1
github.com/eosforge/astra/internal/command/flags.go:36.2,36.41 1 1
github.com/eosforge/astra/internal/command/flags.go:36.43,36.86 1 1
github.com/eosforge/astra/internal/command/flags.go:37.2,37.31 1 1
"""


def check() -> dict:
    """Load the actual declared Command scope rather than constructing a reduced policy."""
    return next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "command-boundaries")


def storage_trace() -> dict:
    """Provide only hashable source entries for statement-parser fixtures, without pretending to supply a native AST."""
    return {
        "files": [
            {"file": p.relative_to(ROOT).as_posix(), "sha256": v.file_digest(p)}
            for p in sorted((ROOT / structure.STORAGE).glob("*.go"))
            if not p.name.endswith("_test.go")
        ]
    }


class ServerTests(unittest.TestCase):
    """Challenge the fixed server denominator and assumptions without treating parser fixtures as application evidence."""

    def test_policy(self) -> None:
        """Only the existing structural duty may use this adapter; MC/DC and whole-rule obligations stay separate."""
        config, _, _ = v.configuration(ROOT / "development.json", ROOT)
        check = next(c for c in config["checks"] if c["id"] == "server-structure")
        self.assertEqual(structure.selection(check), structure.SERVER)
        self.assertEqual(structure.domain(structure.SERVER)["counts"], [648, 325, 424, 93])
        self.assertEqual(len(check["native_tests"]), 300)
        obligations = v.expand(config)
        prefix = "polaris-server/DEV-COVERAGE/POLARIS_SERVER-ASSURANCE/linux-amd64-cgo/"
        self.assertEqual(obligations[prefix + "structure"]["checks"], ["server-structure", "polaris-entry-qualification"])
        self.assertEqual(obligations[prefix + "mutation"]["checks"], ["polaris-server-qualification"])
        self.assertEqual(obligations[prefix + "full-rule"]["checks"], [])
        self.assertTrue(obligations[prefix + "full-rule"]["aggregate"])
        self.assertEqual(
            obligations[prefix + "full-rule"]["requires"],
            [
                {"rule": rule, "contract": "POLARIS_SERVER-ASSURANCE", "scenario": scenario}
                for rule, scenario in (
                    ("DEV-COVERAGE", "structure"),
                    ("DEV-COVERAGE", "mcdc"),
                    ("DEV-COVERAGE", "mutation"),
                    ("DEV-FAULT", "fault-matrix"),
                    ("DEV-MATRIX", "delivery-matrix"),
                )
            ],
        )
        self.assertEqual(obligations[prefix + "mcdc"]["checks"], ["server-independence", "polaris-entry-qualification"])
        observation = ("server-structure", "linux-amd64-cgo", "POLARIS_SERVER-ASSURANCE")
        now = dt.datetime(2026, 10, 8, tzinfo=dt.timezone.utc)
        passed = v.decide(config, {observation: "passed"}, [], [], now)
        self.assertEqual(passed["passed"], [], "Internal package coverage cannot qualify the additional owned entry program")
        self.assertEqual(passed["status"], "blocked")
        owner = v.inventory(config, ["polaris/main.go"])
        self.assertEqual(owner["components"]["polaris-server"], ["polaris/main.go"])
        entry = ("polaris-entry-qualification", observation[1], observation[2])
        self.assertEqual(v.decide(config, {observation: "passed", entry: "passed"}, [], [], now)["passed"], [prefix + "structure"])
        for state in (None, "failed", "unknown", "not-run", "interrupted"):
            gate = v.decide(config, {observation: state} if state else {}, [], [], now)
            self.assertIn(prefix + "structure", gate["missing"])
            self.assertNotIn(prefix + "structure", gate["passed"])
        for identity, field in (("server-structure", "native_tests"), ("polaris-server-boundaries", "expected_tests")):
            changed = copy.deepcopy(config)
            next(c for c in changed["checks"] if c["id"] == identity)[field].remove("TestReceive/cancel")
            with tempfile.TemporaryDirectory() as name:
                path = Path(name) / "development.json"
                path.write_bytes(v.encode(changed))
                with self.assertRaisesRegex(v.Invalid, "structure-native-inventory-policy"):
                    v.configuration(path, ROOT)

    def test_counters(self) -> None:
        """Keep all 447 native blocks and 648 statements; missing blocks, counters or production files cannot disappear."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        for path in (ROOT / structure.SERVER).glob("*.go"):
            if path.name.endswith("_test.go"):
                continue
            target = root / path.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            data = v.read(path)
            if path.name == "authority.go" and v.digest(data) != authority.SOURCE:
                data, _ = ingress.previous(data)
            target.write_bytes(data)
        trace = {
            "files": [
                {"file": p.relative_to(root).as_posix(), "sha256": v.file_digest(p)}
                for p in sorted((root / structure.SERVER).glob("*.go"))
                if not p.name.endswith("_test.go")
            ]
        }
        data = v.read(ROOT / "tests/fixtures/server.cover")
        result = structure.storage_counters(data, root, trace, package=structure.SERVER)
        self.assertEqual(result["raw"], {"blocks": 447, "statements": 648, "statements_hit": 648})
        self.assertEqual(result["unexplained"], [])
        lines = data.splitlines(keepends=True)
        line = next(line for line in lines[1:] if int(line.split()[-2]))
        missed = data.replace(line, line.rsplit(b" ", 1)[0] + b" 0\n", 1)
        ledger = structure.storage_counters(missed, root, trace, package=structure.SERVER)
        self.assertTrue(ledger["unexplained"])
        self.assertLess(ledger["raw"]["statements_hit"], 648)
        for altered in (b"".join(lines[:1] + lines[2:]), data + lines[1], data.replace(b"mode: atomic", b"mode: count")):
            with self.assertRaises(v.Invalid):
                structure.storage_counters(altered, root, trace, package=structure.SERVER)
        for altered in ({"files": trace["files"][:-1]}, {"files": [{**trace["files"][0], "sha256": "0" * 64}, *trace["files"][1:]]}):
            with self.assertRaises(v.Invalid):
                structure.storage_counters(data, root, altered, package=structure.SERVER)

    def test_terminals(self) -> None:
        """Missing, substituted, failed or skipped terminal names invalidate the same-size synthetic stream."""
        names = v.decode(v.read(ROOT / "tests/fixtures/server.tests.json"))

        def events(selected: list[str], failed: str | None = None) -> bytes:
            """Encode parser-only lifecycle facts with explicit schedule markers when selected."""
            rows = [{"Action": "start"}]
            for name in selected:
                rows.append({"Action": "run", "Test": name})
                if name in ("TestWatchdog/cleared", "TestWatchdog/extended"):
                    label = name.split("/")[1]
                    rows.append(
                        {"Action": "output", "Test": name, "Output": "WATCHDOG-SCHEDULE " + label + " complete " + ("1" if label == "cleared" else "2") + "\n"}
                    )
                rows.append({"Action": failed if name == selected[-1] and failed else "pass", "Test": name})
            rows.append({"Action": "pass"})
            return b"".join((json.dumps({"Package": watchdog.PACKAGE, **row}) + "\n").encode() for row in rows)

        for scheduled in (False, True):
            selected = names + sorted(watchdog.TESTS) if scheduled else names
            raw = events(selected)
            structure.terminals(raw, selected, package=structure.SERVER, schedule=scheduled)
            self.assertEqual(len(selected), 303 if scheduled else 300)
            for altered in (
                events(selected[:-1]),
                events(selected[:-1] + ["TestInvented"]),
                events(selected, "fail"),
                events(selected, "skip"),
                raw.rsplit(b"\n", 2)[0],
            ):
                with self.assertRaises(v.Invalid):
                    structure.terminals(altered, selected, package=structure.SERVER, schedule=scheduled)
            if scheduled:
                with self.assertRaisesRegex(v.Invalid, "structure-schedule-witness"):
                    structure.terminals(raw.replace(b"WATCHDOG-SCHEDULE", b"MISSING-SCHEDULE"), selected, package=structure.SERVER, schedule=True)

    def test_assumption(self) -> None:
        """A conditional impossible operand supplies no hit and must reject any native counterexample or dependency drift."""
        identity = structure.SERVER_ASSUMPTIONS[0][0]
        decisions = {
            identity: {
                "kind": "if",
                "text": "remote != nil && !current(remote)",
                "atoms": [{}, {}],
                "tree": [{"kind": "atom", "atom": 0}, {"kind": "atom", "atom": 1}, {"kind": "and", "left": 0, "right": 1}],
            }
        }
        rows = {identity: {("21", False): 2, ("22", True): 3}}
        raw = structure.boolean(decisions, rows, ())
        result = structure.boolean(decisions, rows, structure.SERVER_ASSUMPTIONS)
        self.assertEqual(raw["missing"], [{"id": identity, "atom": 0, "outcomes": [False]}])
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["totals"]["atoms"], {"raw": 4, "observed": 3, "literal_impossible": 0, "conditional": 1, "reachable_under_assumptions": 3})
        with self.assertRaisesRegex(v.Invalid, "structure-assumption-contradicted"):
            structure.boolean(decisions, {identity: {**rows[identity], ("10", False): 1}}, structure.SERVER_ASSUMPTIONS)
        paths = structure.dependency_paths(Path("unused/go"), {}, package=structure.SERVER, root=ROOT)
        self.assertEqual(set(paths), set(structure.SERVER_DEPENDENCIES))
        data = {name: v.read(path) for name, path in paths.items()}
        # The archived server argument still owns the predecessor's dependency bytes.
        # The acquisition revision must fail that guard, not silently inherit its credit.
        self.assertNotEqual(v.digest(data["astra/internal/admission/identity.go"]), structure.SERVER_DEPENDENCIES["astra/internal/admission/identity.go"])
        with self.assertRaisesRegex(v.Invalid, "structure-dependency-drift"):
            structure.reconcile(
                root=ROOT,
                source_sha256="0" * 64,
                tests=[],
                profiles=(),
                dependency=data,
                trace={},
                boolean_events=b"",
                control={},
                control_events=b"",
                package=structure.SERVER,
            )
        data["astra/internal/admission/identity.go"] = v.read(ROOT / "tests/fixtures/admission-identity.go.in")
        self.assertEqual({name: v.digest(value) for name, value in data.items()}, structure.SERVER_DEPENDENCIES)
        for name in data:
            with self.subTest(dependency=name), self.assertRaisesRegex(v.Invalid, "structure-dependency-drift"):
                structure.reconcile(
                    root=ROOT,
                    source_sha256="0" * 64,
                    tests=[],
                    profiles=(),
                    dependency={**data, name: data[name] + b"\n"},
                    trace={},
                    boolean_events=b"",
                    control={},
                    control_events=b"",
                    package=structure.SERVER,
                )
        plan = structure.plan(ROOT / "build/synthetic", package=structure.SERVER)
        self.assertEqual(len(plan), 8)
        self.assertEqual(
            [name for name, _, _ in plan],
            ["coverage", "typed/exports", "typed/collector", "typed/packages", "typed/tests", "control/collector", "control/packages", "control/tests"],
        )
        for name, argv, _ in plan:
            if argv[:2] == ["go", "test"]:
                self.assertIn("-parallel=1", argv)
                self.assertFalse(any(arg.startswith("-run") for arg in argv))
                if name == "typed/tests":
                    self.assertIn("-overlay=" + str(ROOT / "build/synthetic/typed/schedule/overlay.json"), argv)


class IndependenceTests(unittest.TestCase):
    """Reject incomplete or substituted proof bundles without crediting unrelated release obligations."""

    def test_policy(self) -> None:
        """Only a fully named Server MC/DC coordinate accepts the new collector, with unchanged native test scope."""
        config, _, _ = v.configuration(ROOT / "development.json", ROOT)
        check = next(c for c in config["checks"] if c["id"] == "server-independence")
        structure.configuration(check)
        self.assertEqual(len(check["native_tests"]), 300)
        self.assertEqual(check["probes"], [{"contract": "POLARIS_SERVER-ASSURANCE", "test": "independence", "minimum_hits": 210}])
        expected = "polaris-server/DEV-COVERAGE/POLARIS_SERVER-ASSURANCE/linux-amd64-cgo/mcdc"
        now = dt.datetime(2026, 10, 8, tzinfo=dt.timezone.utc)
        observation = (check["id"], structure.PLATFORM, "POLARIS_SERVER-ASSURANCE")
        self.assertEqual(v.decide(config, {observation: "passed"}, [], [], now)["passed"], [])
        entry = ("polaris-entry-qualification", observation[1], observation[2])
        self.assertEqual(v.decide(config, {observation: "passed", entry: "passed"}, [], [], now)["passed"], [expected])
        for status in (None, "failed", "unknown", "skipped", "not-run"):
            self.assertNotIn(expected, v.decide(config, {observation: "passed", entry: status}, [], [], now)["passed"])
        for status in (None, "failed", "unknown", "skipped", "not-run"):
            self.assertNotIn(expected, v.decide(config, {observation: status}, [], [], now)["passed"])
        for field, value in (("argv", check["argv"][:-1]), ("expected_tests", ["structure"]), ("platforms", ["windows-amd64"]), ("timeout_s", 2401)):
            with self.subTest(field=field), self.assertRaises(v.Invalid):
                structure.configuration({**check, field: value})
        changed = copy.deepcopy(check)
        changed["probes"][0]["minimum_hits"] = 209
        with self.assertRaises(v.Invalid):
            structure.configuration(changed)

        # Retained Storage evidence may satisfy its sole MC/DC obligation, never another platform or rule.
        native = next(item for item in config["checks"] if item["id"] == "storage-structure")
        retained = next(item for item in config["checks"] if item["id"] == "storage-independence")
        independence.configuration(retained, native)
        self.assertEqual(len(retained["native_tests"]), 262)
        self.assertEqual(retained["probes"], [{"contract": "STORAGE-ASSURANCE", "test": "independence", "minimum_hits": 273}])
        expected = "polaris-storage/DEV-COVERAGE/STORAGE-ASSURANCE/linux-amd64-cgo/mcdc"
        observation = (retained["id"], structure.PLATFORM, "STORAGE-ASSURANCE")
        decision = v.decide(config, {observation: "passed"}, [], [], now)
        self.assertEqual(decision["passed"], [expected])
        self.assertEqual(len(decision["required"]), 1370)
        self.assertEqual(decision["status"], "blocked")
        for status in (None, "failed", "unknown", "skipped", "not-run"):
            self.assertNotIn(expected, v.decide(config, {observation: status}, [], [], now)["passed"])
        for platform in ("windows-amd64", "linux-arm64", "linux-amd64"):
            self.assertNotIn(expected, v.decide(config, {(retained["id"], platform, observation[2]): "passed"}, [], [], now)["passed"])
        for field, value in (
            ("argv", retained["argv"][:-1]),
            ("expected_tests", ["structure"]),
            ("platforms", ["windows-amd64"]),
            ("native_tests", retained["native_tests"][:-1]),
            ("timeout_s", 121),
            ("log_bytes", retained["log_bytes"] + 1),
        ):
            with self.subTest(storage=field), self.assertRaises(v.Invalid):
                independence.configuration({**retained, field: value}, native)
        for minimum in (0, 265, 270, 271, 272, 274):
            changed = copy.deepcopy(retained)
            changed["probes"][0]["minimum_hits"] = minimum
            with self.subTest(minimum=minimum), self.assertRaises(v.Invalid):
                independence.configuration(changed, native)
        with self.assertRaisesRegex(v.Invalid, "storage-independence-evidence-missing"):
            v.parse_observations(b'{"passed":true,"hits":271}', retained, ROOT)

    def test_revisions(self) -> None:
        """Legacy shape remains explicit; the current policy cannot use its lower branch denominator."""
        current, old = structure.domain(), structure.domain(legacy=True)
        self.assertEqual(current["counts"], [279, 156, 355, 28])
        self.assertEqual(old["counts"], [277, 154, 355, 28])
        for field in ("forest", "edges"):
            self.assertNotEqual(current[field], old[field])
        self.assertEqual(current["assumptions"], old["assumptions"])
        altered = next(c for c in v.decode(v.read(ROOT / "development.json"))["checks"] if c["id"] == "admission-structure")
        altered["probes"][0]["minimum_hits"] = sum(old["counts"])
        with self.assertRaisesRegex(v.Invalid, "structure-configuration"):
            structure.configuration(altered)

    def test_plan(self) -> None:
        """Keep full native trajectories and both pair profiles; prerequisite compilation cannot replace executed tests."""
        output = ROOT / "build/synthetic"
        base = structure.plan(output, package=structure.SERVER)
        plan = structure.plan(output, package=structure.SERVER, independence=True)
        self.assertEqual(len(plan), 11)
        self.assertEqual(plan[1:9], base)
        self.assertEqual(plan[0][0], "compile")
        self.assertIn("-c", plan[0][1])
        self.assertEqual([entry[0] for entry in plan[-2:]], ["authority/baseline", "authority/race"])
        for (name, argv, timeout), profile in zip(plan[-2:], authority.PROFILES, strict=True):
            self.assertEqual(argv, ["go", *authority.command(output / "authority/overlay", profile)[1:]])
            self.assertEqual(timeout, 300)
            self.assertEqual("-race" in argv, profile == "race")
        with self.assertRaises(v.Invalid):
            structure.plan(output, package=structure.STORAGE, independence=True)

    def test_witnesses(self) -> None:
        """Challenge byte/hash binding and native-profile forwarding separately from the existing AST proof tests."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "build/run/structure"
            for name in (*(structure.SERVER + "/" + name for name in authority.SOURCES), authority.FIXTURE):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                data = v.read(ROOT / name)
                if name == installation.PATH:
                    # This forwarding fixture belongs to the preserved pre-ingress predicate geometry.
                    data, _ = ingress.previous(data)
                path.write_bytes(data)
            self.assertEqual({name: v.file_digest(root / structure.SERVER / name) for name in authority.SOURCES}, authority.SOURCES)
            overlay = directory / "authority/overlay"
            authority.generate(root, overlay)
            files = {name: structure.artifact(directory, overlay / name) for name in authority.contents(root, overlay)}
            records, streams = {}, {"typed/packages": v.encode({"ImportPath": authority.PACKAGE, "TestGoFiles": ["a_test.go", "b_test.go"]})}
            for profile in authority.PROFILES:
                name = "authority/" + profile
                path = directory / name
                path.mkdir()
                (path / "stderr.log").write_bytes(b"original " + profile.encode())
                records[name] = {"stderr": structure.artifact(path, path / "stderr.log")}
                streams[name] = b"native-shaped " + profile.encode()
            typed = {"trace": {"synthetic": True}, "events": b"typed"}
            # This return is deliberately synthetic: only adapter forwarding/denominator validation is under test here.
            report = {
                "status": "complete-under-declared-domains",
                "raw_conditions": 214,
                "supported_conditions": 210,
                "qualified_denominator": 210,
                "conditions": [{} for _ in range(210)],
                "literal_exclusions": [{}, {}, {}],
                "domain_exclusions": [{}],
                "unresolved": [],
            }
            with patch.object(authority, "correlate", return_value=report) as reader:
                self.assertEqual(structure.independence(directory, root, files, typed, records, streams), report)
                args = reader.call_args.args
                self.assertEqual(args[:4], (root, typed["trace"], b"typed", 2))
                self.assertEqual(set(args[4]), set(authority.PROFILES))
                for profile in authority.PROFILES:
                    self.assertEqual(args[4][profile]["stdout"], streams["authority/" + profile])
                    self.assertEqual(args[4][profile]["stderr"], b"original " + profile.encode())
                    self.assertEqual(args[4][profile]["record"], records["authority/" + profile])
                for field, value in (
                    ("status", "incomplete"),
                    ("raw_conditions", 213),
                    ("supported_conditions", 209),
                    ("qualified_denominator", 209),
                    ("conditions", []),
                    ("literal_exclusions", []),
                    ("domain_exclusions", []),
                    ("unresolved", [{}]),
                ):
                    reader.return_value = {**report, field: value}
                    with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "structure-independence-uncovered"):
                        structure.independence(directory, root, files, typed, records, streams)
                reader.return_value = report
                for changed in ({k: value for k, value in files.items() if k != "manifest.json"}, {**files, "invented": files["manifest.json"]}):
                    with self.assertRaises(v.Invalid):
                        structure.independence(directory, root, changed, typed, records, streams)
                for raw in (b"", v.encode({"ImportPath": "other"}), streams["typed/packages"] * 2):
                    with self.assertRaises(v.Invalid):
                        structure.independence(directory, root, files, typed, records, {**streams, "typed/packages": raw})
                path = overlay / "predicates.go.txt"
                path.write_bytes(v.read(path) + b"\n// substituted\n")
                changed = {**files, path.name: structure.artifact(directory, path)}
                with self.assertRaisesRegex(v.Invalid, "structure-authority-overlay"):
                    structure.independence(directory, root, changed, typed, records, streams)
        # This fixture challenges interpretation only; mocked native rows cannot qualify application execution.
        fixture = v.decode(v.read(ROOT / "tests/fixtures/storage-decisions.json"))
        native = {name: {(row["values"], row["result"]): row["hits"] for row in rows} for name, rows in fixture["vectors"].items()}

        def wire(value: dict) -> bytes:
            """Encode one native-shaped NDJSON event without pretty-print line breaks."""
            return (json.dumps(value, separators=(",", ":")) + "\n").encode()

        def validation(frames: dict | None = None, observed: dict | None = None, *, suffix: bytes = b"") -> list[dict]:
            """Use independent fixed receipt/vector fixtures while preserving the real input/pair interpretation."""
            selected = fixture["frames"] if frames is None else frames
            data = b"".join(
                wire(
                    {
                        "Action": "output",
                        "Package": "github.com/eosforge/astra/" + structure.STORAGE,
                        "Test": "TestDecisions/" + kind,
                        "Output": "STORAGE-DECISION " + json.dumps(frame, separators=(",", ":")) + "\n",
                    }
                )
                for kind, frame in selected.items()
            )
            with (
                patch.object(logic, "inventory", return_value=fixture["decisions"]),
                patch.object(logic, "observe", return_value=(native if observed is None else observed, 1)),
            ):
                return storage.validation({}, b"synthetic trace", data + suffix)

        proofs = validation()
        self.assertEqual(len(proofs), 28)
        self.assertEqual(len({(row["decision"], row["condition"]) for row in proofs}), 28)
        self.assertEqual(sum(row["criterion"] == "defined-domain-short-circuit-v1" for row in proofs), 1)
        for fault in ("missing", "conditions", "pair-bool", "input", "result", "claimed-values", "duplicate-row", "scan-type", "extra-field"):
            changed = copy.deepcopy(fixture["frames"])
            if fault == "missing":
                changed.pop("scope")
            elif fault == "conditions":
                changed["limits"]["conditions"].pop()
            elif fault == "pair-bool":
                changed["text"]["pairs"][0][0] = False
            elif fault == "input":
                changed["limits"]["rows"][0]["input"]["Scopes"] = 0
            elif fault == "result":
                changed["text"]["rows"][0]["result"] = False
            elif fault == "claimed-values":
                changed["text"]["rows"][0]["values"][0] = 1
            elif fault == "duplicate-row":
                changed["change"]["rows"][1]["name"] = changed["change"]["rows"][0]["name"]
            elif fault == "scan-type":
                changed["scan"]["rows"][0]["input"] = "AAAAAAAAAAc="
            elif fault == "extra-field":
                changed["scope"]["rows"][0]["input"]["fake"] = True
            with self.subTest(storage=fault), self.assertRaises(v.Invalid):
                validation(changed)
        with self.assertRaisesRegex(v.Invalid, "storage-validator-native-witness"):
            validation(observed={name: {} for name in native})
        for test, output in (("other", "STORAGE-DECISION {}\n"), ("TestDecisions/text", "STORAGE-DECISION {}\n"), ("TestDecisions/text", "STORAGE-DECISION {")):
            suffix = wire({"Action": "output", "Package": "github.com/eosforge/astra/" + structure.STORAGE, "Test": test, "Output": output})
            with self.subTest(test=test, output=output), self.assertRaises(v.Invalid):
                validation(suffix=suffix)
        scalar = {
            "id": "synthetic/length",
            "atoms": [{"text": "length == 0"}, {"text": "length > 64"}],
            "tree": [{"kind": "atom", "atom": 0}, {"kind": "atom", "atom": 1}, {"kind": "or", "children": [0, 1]}],
            "root": 2,
        }
        rows = {("20", True): 1, ("11", False): 1, ("12", True): 1}
        effects = storage.scalar_effect(scalar, rows, (0, 64), 0, 2**63 - 1, lambda value: [value == 0, value > 64])
        self.assertEqual({row["condition"] for row in effects}, {0, 1})
        self.assertTrue(all(row["inferred_not_native_hits"] for row in effects))
        self.assertIn({"values": "20", "result": True}, effects[0]["native_vectors"])
        self.assertEqual(storage.scalar_effect(scalar, {}, (0, 64), 0, 100, lambda value: [value == 0, value > 64]), [])
        self.assertEqual(storage.scalar_effect(scalar, {("20", True): 1}, (16, 32), 0, 64, lambda value: [value < 32, value > 16]), [])
        for bad, reason in (({("21", True): 1}, "storage-scalar-native-contradiction"), ({("11", False): 0}, "storage-scalar-native-hit")):
            with self.subTest(scalar=reason), self.assertRaisesRegex(v.Invalid, reason):
                storage.scalar_effect(scalar, bad, (0, 64), 0, 100, lambda value: [value == 0, value > 64])
        with self.assertRaisesRegex(v.Invalid, "storage-scalar-predicates"):
            storage.scalar_effect(scalar, rows, (0, 64), 0, 100, lambda _: [1, 0])
        with self.assertRaisesRegex(v.Invalid, "storage-scalar-domain"):
            storage.scalar_effect(scalar, rows, (0, 64), 100, 0, lambda value: [value == 0, value > 64])
        sql = v.decode(v.read(ROOT / "tests/fixtures/storage-states.json"))
        sql_rows = {name: {(row["values"], row["result"]): row["hits"] for row in rows} for name, rows in sql["vectors"].items()}
        sql_inputs = {"TestCorruption/" + name: rows for name, rows in sql["cases"].items()}

        def persisted(inputs: dict | None = None, observed: dict | None = None) -> list[dict]:
            """Challenge SQL interpretation with synthetic inputs and independently supplied native-shaped masks."""
            with (
                patch.object(logic, "inventory", return_value=sql["decisions"]),
                patch.object(logic, "observe", return_value=(sql_rows if observed is None else observed, 1)),
            ):
                return states.observations(ROOT, {}, b"synthetic state masks", sql_inputs if inputs is None else inputs)

        self.assertEqual(len(persisted()), 8)
        for fault in ("columns", "missing", "version", "integer", "coupled", "rejected-state"):
            changed = copy.deepcopy(sql_inputs)
            key = "TestCorruption/record-count-capacity"
            if fault == "columns":
                changed[key][0]["columns"].reverse()
            elif fault == "missing":
                changed[key].pop()
            elif fault == "version":
                changed[key][0]["rows"][0][2]["sha256"] = "0" * 64
            elif fault == "integer":
                changed[key][0]["rows"][0][3] = True
            elif fault == "coupled":
                for item in changed[key][1:]:
                    item["rows"][0][4] = 64 * 2**20 + 1
            elif fault == "rejected-state":
                changed[key][-1]["rows"][0][4] += 1
            with self.subTest(state=fault), self.assertRaises(v.Invalid):
                persisted(changed)
        with self.assertRaisesRegex(v.Invalid, "authority-pair-native-witness"):
            persisted(observed={name: {} for name in sql_rows})
        totals = v.decode(v.read(ROOT / "tests/fixtures/storage-totals.json"))
        total_rows = {name: {(row["values"], row["result"]): row["hits"] for row in rows} for name, rows in totals["vectors"].items()}

        def counted(inputs: dict | None = None, observed: dict | None = None, decisions: dict | None = None) -> list[dict]:
            """Synthetic full-table values challenge pure totals without replacing actual native evidence."""
            with (
                patch.object(logic, "inventory", return_value=totals["decisions"] if decisions is None else decisions),
                patch.object(logic, "observe", return_value=(total_rows if observed is None else observed, 1)),
            ):
                return states.totals({}, b"synthetic total masks", totals["cases"] if inputs is None else inputs)

        proofs = counted()
        self.assertEqual(len(proofs), 3)
        self.assertEqual({(row["decision"], row["condition"]) for row in proofs}, {(name, 1 if name.endswith("5291") else 0) for name in total_rows})
        for fault in ("columns", "missing", "unknown", "scope", "blob", "blob-type", "key", "rejected-state", "coupled", "meta-type"):
            changed = copy.deepcopy(totals["cases"])
            rows = changed["TestCorruption/record-under-bytes"]
            if fault == "columns":
                rows[3]["columns"].reverse()
            elif fault == "missing":
                rows.pop()
            elif fault == "unknown":
                rows[0]["unreported"] = True
            elif fault == "scope":
                rows[2]["rows"] = []
            elif fault == "blob":
                rows[3]["rows"][0][3]["sha256"] = "0" * 64
            elif fault == "blob-type":
                rows[3]["rows"][0][3]["bytes"] = True
            elif fault == "key":
                rows[3]["rows"][0][2]["hex"] = "00"
            elif fault == "rejected-state":
                rows[-3]["rows"][0][4] = 99
            elif fault == "coupled":
                for item in rows:
                    if item["query"] == states.QUERY and item != rows[2]:
                        item["rows"][0][3] = 1
            else:
                changed["TestCorruption/meta-scopes"][1]["rows"][0][5] = True
            with self.subTest(total=fault), self.assertRaises(v.Invalid):
                counted(changed)
        for name in total_rows:
            with self.subTest(total_native=name), self.assertRaises(v.Invalid):
                counted(observed={**total_rows, name: {}})
            changed = copy.deepcopy(totals["decisions"])
            changed[name]["text"] += " || true"
            with self.subTest(total_source=name), self.assertRaises(v.Invalid):
                counted(decisions=changed)
        sequences = v.decode(v.read(ROOT / "tests/fixtures/storage-sequences.json"))
        sequence_rows = {name: {(row["values"], row["result"]): row["hits"] for row in rows} for name, rows in sequences["vectors"].items()}

        def sequenced(inputs: dict | None = None, observed: dict | None = None, decisions: dict | None = None) -> list[dict]:
            """Synthetic damaged rows must preserve the evaluated prefix and complete replay/count arguments."""
            with (
                patch.object(logic, "inventory", return_value=sequences["decisions"] if decisions is None else decisions),
                patch.object(logic, "observe", return_value=(sequence_rows if observed is None else observed, 1)),
            ):
                return states.sequence({}, b"synthetic sequence masks", sequences["cases"] if inputs is None else inputs)

        proofs = sequenced()
        self.assertEqual(len(proofs), 4)
        self.assertEqual(
            {(row["decision"], row["condition"]) for row in proofs},
            {
                (structure.STORAGE + "/read.go:3910", 1),
                (structure.STORAGE + "/read.go:6637", 1),
                (structure.STORAGE + "/read.go:6637", 2),
                (structure.STORAGE + "/schema.go:6230", 1),
            },
        )
        for fault in (
            "missing",
            "unknown",
            "columns",
            "scope",
            "version",
            "integer",
            "blob",
            "blob-type",
            "rejected-state",
            "history-order",
            "history-type",
            "history-cost",
            "record-order",
            "coupled",
        ):
            changed = copy.deepcopy(sequences["cases"])
            frames = changed["TestCorruption/history-gap"]
            if fault == "missing":
                frames.pop()
            elif fault == "unknown":
                frames[0]["unknown"] = True
            elif fault == "columns":
                frames[2]["columns"].reverse()
            elif fault == "scope":
                frames[2]["rows"].pop()
            elif fault == "version":
                frames[2]["rows"][0][2]["sha256"] = "0" * 64
            elif fault == "integer":
                frames[2]["rows"][0][3] = True
            elif fault == "blob":
                frames[3]["rows"][0][3]["sha256"] = "0" * 64
            elif fault == "blob-type":
                frames[3]["rows"][0][3]["bytes"] = True
            elif fault == "rejected-state":
                frames[-1]["rows"].pop()
            elif fault == "history-order":
                frames[4]["rows"].reverse()
            elif fault == "history-type":
                frames[4]["rows"][0][6] = True
            elif fault == "history-cost":
                for frame in frames:
                    if frame["query"].startswith("SELECT * FROM history"):
                        frame["rows"][1][6] += 1
            elif fault == "record-order":
                frames[3]["rows"].reverse()
            else:
                for frame in changed["TestCorruption/record-under-count"][5:]:
                    if frame["query"] == states.QUERY:
                        frame["rows"][0][4] = 5
            with self.subTest(sequence=fault), self.assertRaises(v.Invalid):
                sequenced(changed)
        for name in sequence_rows:
            with self.subTest(sequence_native=name), self.assertRaises(v.Invalid):
                sequenced(observed={**sequence_rows, name: {}})
            with self.subTest(sequence_zero=name), self.assertRaises(v.Invalid):
                sequenced(observed={**sequence_rows, name: {key: 0 for key in sequence_rows[name]}})
            altered = copy.deepcopy(sequences["decisions"])
            altered[name]["text"] += " || true"
            with self.subTest(sequence_source=name), self.assertRaises(v.Invalid):
                sequenced(decisions=altered)
        closed = v.decode(v.read(ROOT / "tests/fixtures/storage-queries.json"))
        query_rows = {name: {(row["values"], row["result"]): row["hits"] for row in rows} for name, rows in closed["vectors"].items()}

        def queried(inputs: dict | None = None, observed: dict | None = None, decisions: dict | None = None) -> list[dict]:
            """Synthetic driver lifetimes challenge native error/data ordering without constituting an application run."""
            with (
                patch.object(logic, "inventory", return_value=closed["decisions"] if decisions is None else decisions),
                patch.object(logic, "observe", return_value=(query_rows if observed is None else observed, 1)),
            ):
                return queries.correlate(ROOT, {}, b"synthetic query masks", closed["cases"] if inputs is None else inputs)

        proof = queried()
        self.assertEqual(len(proof), 6)
        self.assertEqual({(row["decision"], row["condition"]) for row in proof}, {(name, 0) for name in query_rows})
        for point in closed["cases"]:
            for fault in ("missing", "unknown", "identity", "phase", "columns", "type", "next", "close", "result", "reordered"):
                changed = copy.deepcopy(closed["cases"])
                frames = changed[point]
                if fault == "missing":
                    frames.pop()
                elif fault == "unknown":
                    frames[0]["unknown"] = True
                elif fault == "identity":
                    frames[0]["point"] = "foreign-next"
                elif fault == "phase":
                    frames[0]["active"] = 0
                elif fault == "columns":
                    frames[0]["columns"] = []
                elif fault == "type":
                    frames[0]["values"][0]["type"] = "nil"
                elif fault == "next":
                    frames[0]["outcome"] = "error"
                elif fault == "close":
                    next(frame for frame in frames if frame["kind"] == "close")["outcome"] = "error"
                elif fault == "result":
                    frames[-1]["outcome"] = "nil"
                else:
                    frames.reverse()
                with self.subTest(query=point, fault=fault), self.assertRaises(v.Invalid):
                    queried(changed)
        for name in query_rows:
            with self.subTest(query_native=name), self.assertRaises(v.Invalid):
                queried(observed={**query_rows, name: {}})
            changed = copy.deepcopy(closed["decisions"])
            changed[name]["text"] += " || true"
            with self.subTest(query_source=name), self.assertRaises(v.Invalid):
                queried(decisions=changed)
        for fault in ("integer-boolean", "coupled", "changed-data", "bad-schema", "missing-point", "extra-point"):
            changed = copy.deepcopy(closed["cases"])
            if fault == "integer-boolean":
                changed["records-close"][0]["values"][0]["value"] = True
            elif fault == "coupled":
                for frame in changed["records-close"]:
                    if frame["kind"] == "next" and frame["active"]:
                        frame["values"][0]["value"] = 2
            elif fault == "changed-data":
                changed["meta-close"][0]["values"][1]["value"] = 0
            elif fault == "bad-schema":
                for frame in changed["schema-close"]:
                    if frame["kind"] == "next" and frame["outcome"] == "nil":
                        frame["values"][0]["hex"] = "00"
            elif fault == "missing-point":
                del changed["integrity-close"]
            else:
                changed["foreign-next"] = []
            with self.subTest(query=fault), self.assertRaises(v.Invalid):
                queried(changed)
        commits = v.decode(v.read(ROOT / "tests/fixtures/storage-transactions.json"))
        transaction_rows = {name: {(row["values"], row["result"]): row["hits"] for row in rows} for name, rows in commits["vectors"].items()}

        def transacted(inputs: dict | None = None, observed: dict | None = None, decisions: dict | None = None) -> list[dict]:
            """Copied illustrative shapes challenge the independent reader without receiving any native execution credit."""
            with (
                patch.object(logic, "inventory", return_value=commits["decisions"] if decisions is None else decisions),
                patch.object(logic, "observe", return_value=(transaction_rows if observed is None else observed, 1)),
            ):
                return transactions.correlate(ROOT, {}, b"synthetic transaction masks", commits["cases"] if inputs is None else inputs)

        proof = transacted()
        self.assertEqual(len(proof), 13)
        self.assertEqual(len({(row["decision"], row["condition"]) for row in proof}), 13)
        for point in transactions.CASES:
            for fault in ("missing", "extra", "field", "identity", "integer", "limit", "payload", "erase"):
                changed = copy.deepcopy(commits["cases"])
                frames = changed[point]
                if fault == "missing":
                    frames.pop()
                elif fault == "extra":
                    frames.append(copy.deepcopy(frames[0]))
                elif fault == "field":
                    frames[0]["unregistered"] = True
                elif fault == "identity":
                    frames[0]["point"] = "foreign-commit"
                elif fault == "integer":
                    frames[0]["before"]["state"]["Records"] = True
                elif fault == "limit":
                    frames[0]["before"]["limits"]["Bytes"] = -1
                elif fault == "payload":
                    frames[0]["request"]["Value"] = None
                else:
                    frames[0]["request"]["Erase"] = 0
                with self.subTest(transaction=point, fault=fault), self.assertRaises(v.Invalid):
                    transacted(changed)
        for name in transaction_rows:
            with self.subTest(transaction_native=name), self.assertRaises(v.Invalid):
                transacted(observed={**transaction_rows, name: {}})
            changed = copy.deepcopy(commits["decisions"])
            changed[name]["text"] += " || true"
            with self.subTest(transaction_source=name), self.assertRaises(v.Invalid):
                transacted(decisions=changed)
        for fault in (
            "cost",
            "version",
            "close",
            "truncated",
            "early-eof",
            "extra-row",
            "boolean-cost",
            "unknown-row",
            "duplicate",
            "outcome",
            "coupled",
            "receipt",
            "receipt-boolean",
            "empty-history",
        ):
            changed = copy.deepcopy(commits["cases"])
            frame = changed["history-count"][0]
            if fault in ("cost", "boolean-cost"):
                frame["prefix"][0]["cost"] = True if fault == "boolean-cost" else 67
            elif fault == "version":
                frame["prefix"][0]["version"] = "0000000000000002"
            elif fault == "close":
                frame["prefix"][-1]["outcome"] = "error"
            elif fault == "truncated":
                frame["prefix"].pop()
            elif fault == "early-eof":
                frame["prefix"][0] = {"kind": "next", "outcome": "eof"}
            elif fault == "extra-row":
                frame["prefix"].insert(1, copy.deepcopy(frame["prefix"][0]))
            elif fault == "unknown-row":
                frame["prefix"][0]["inferred"] = True
            elif fault == "duplicate":
                changed["history-negative"][1]["attempt"] = 0
            elif fault == "outcome":
                changed["scope-new-full"][0]["outcome"] = "nil"
            elif fault == "coupled":
                for item in changed["retry-key"]:
                    item["request"]["Value"] = "dg=="
            elif fault in ("receipt", "receipt-boolean"):
                changed["scopes-receipt"][0]["receipts"][0]["rows"] = True if fault == "receipt-boolean" else 0
            else:
                changed["retry-key"][0]["before"]["history"] = None
            with self.subTest(transaction=fault), self.assertRaises(v.Invalid):
                transacted(changed)
        predicates = transactions.observations(commits["cases"])
        self.assertEqual(set(predicates["scope-new-full"][0]), {"commit.go:2611"})
        self.assertEqual(set(predicates["negative-records"][0]), {"commit.go:2611", "commit.go:3304"})
        self.assertEqual(predicates["retry-same"][0]["commit.go:7097"], [False, False, True])
        policy = commits["selection"]
        revised = transactions.selection(policy)
        self.assertEqual(len(revised["probes"]), 23)
        self.assertEqual({key: value for key, value in revised.items() if key != "probes"}, {key: value for key, value in policy.items() if key != "probes"})
        for field in ("expected_tests", "probes", "package", "adapter"):
            changed = copy.deepcopy(policy)
            changed[field] = [] if isinstance(changed[field], list) else "foreign"
            with self.subTest(transaction_selection=field), self.assertRaises(v.Invalid):
                transactions.selection(changed)
        for probe in revised["probes"]:
            self.assertGreater(probe["minimum_hits"], 0)
        returned = v.decode(v.read(ROOT / "tests/fixtures/storage-replies.json"))
        reply_rows = {name: {(row["values"], row["result"]): row["hits"] for row in rows} for name, rows in returned["vectors"].items()}

        def responded(
            inputs: dict | None = None, admitted: list[dict] | None = None, observed: dict | None = None, decisions: dict | None = None
        ) -> list[dict]:
            """Synthetic copied reply shapes attack the reader; native credit requires separately authenticated complete streams."""
            with (
                patch.object(logic, "inventory", return_value=returned["decisions"] if decisions is None else decisions),
                patch.object(logic, "observe", return_value=(reply_rows if observed is None else observed, 1)),
            ):
                return replies.correlate(
                    ROOT, {}, b"synthetic returned masks", returned["cases"] if inputs is None else inputs, returned["guards"] if admitted is None else admitted
                )

        proof = responded()
        self.assertEqual(len(proof), 16)
        self.assertEqual(len({(row["decision"], row["condition"]) for row in proof}), 16)
        for point in replies.POINTS:
            for fault in ("missing", "extra", "unknown", "identity", "integer", "column", "next", "close", "result", "reordered"):
                changed = copy.deepcopy(returned["cases"])
                frames = changed[point]
                if fault == "missing":
                    frames.pop()
                elif fault == "extra":
                    frames.insert(1, copy.deepcopy(frames[0]))
                elif fault == "unknown":
                    frames[0]["unproven"] = True
                elif fault == "identity":
                    frames[0]["point"] = "foreign"
                elif fault == "integer":
                    frames[0]["state"]["Version"] = True
                elif fault == "column":
                    next(row for row in frames if row["kind"] == "next")["columns"] = ["other"]
                elif fault == "next":
                    next(row for row in frames if row["kind"] == "next")["outcome"] = True
                elif fault == "close":
                    next(row for row in frames if row["kind"] == "close")["outcome"] = "error"
                elif fault == "result":
                    next(row for row in frames if row["kind"] == "result")["outcome"] = "error"
                else:
                    frames.reverse()
                with self.subTest(reply=point, fault=fault), self.assertRaises(v.Invalid):
                    responded(changed)
        for name in reply_rows:
            with self.subTest(reply_source=name):
                altered = copy.deepcopy(returned["decisions"])
                altered[name]["text"] = "false"
                with self.assertRaises(v.Invalid):
                    responded(decisions=altered)
                altered = copy.deepcopy(reply_rows)
                altered[name] = {}
                with self.assertRaises(v.Invalid):
                    responded(observed=altered)
                altered[name] = {key: 0 for key in reply_rows[name]}
                with self.assertRaises(v.Invalid):
                    responded(observed=altered)
        for point, frames in returned["cases"].items():
            for index, frame in enumerate(frames):
                if frame["kind"] == "next" and frame["outcome"] == "nil":
                    changed = copy.deepcopy(returned["cases"])
                    changed[point][index]["values"][0] = {"type": "integer", "value": True}
                    with self.subTest(reply_value=point), self.assertRaises(v.Invalid):
                        responded(changed)
                    break
        for fault in (
            "missing-point",
            "extra-point",
            "phase",
            "null-payload",
            "blob-hash",
            "cost",
            "unsigned-coupling",
            "binding-coupling",
            "checkpoint-coupling",
            "foreign-shape",
        ):
            changed = copy.deepcopy(returned["cases"])
            if fault == "missing-point":
                del changed["snapshot-value"]
            elif fault == "extra-point":
                changed["unknown"] = []
            elif fault == "phase":
                changed["state-validation"][1]["active"] = True
            elif fault == "null-payload":
                next(row for row in changed["history-value"] if row["kind"] == "next" and row["active"])["values"][2] = {
                    "type": "blob",
                    "bytes": 0,
                    "hex": "",
                    "sha256": v.digest(b""),
                }
            elif fault == "blob-hash":
                next(row for row in changed["history-value"] if row["kind"] == "next")["values"][0]["sha256"] = "0" * 64
            elif fault == "cost":
                next(row for row in changed["history-value"] if row["kind"] == "next")["values"][4]["value"] = 66
            elif fault == "unsigned-coupling":
                changed["state-retained"][0]["state"]["Version"] = 1
            elif fault == "binding-coupling":
                next(row for row in changed["binding-galaxy"] if row["kind"] == "next" and row["active"])["values"][3]["hex"] = b"other".hex()
            elif fault == "checkpoint-coupling":
                row = next(row for row in changed["checkpoint-busy"] if row["kind"] == "next" and row["active"])
                row["values"][1]["value"] = row["values"][2]["value"] + 1
            else:
                next(row for row in changed["foreign-row"] if row["kind"] == "next" and row["active"])["values"][3]["value"] = 1
            with self.subTest(reply=fault), self.assertRaises(v.Invalid):
                responded(changed)
        for index in range(132):
            damaged = copy.deepcopy(returned["guards"])
            damaged.pop(index)
            with self.subTest(guard_missing=index), self.assertRaises(v.Invalid):
                responded(admitted=damaged)
            damaged = copy.deepcopy(returned["guards"])
            damaged[index]["version" if index < 3 else "count"] = True
            with self.subTest(guard_integer=index), self.assertRaises(v.Invalid):
                responded(admitted=damaged)
        for fault in ("unknown", "mutation", "coupled", "capacity", "order"):
            damaged = copy.deepcopy(returned["guards"])
            if fault == "unknown":
                damaged[0]["unknown"] = True
            elif fault == "mutation":
                damaged[1]["after_sha256"] = "0" * 64
            elif fault == "coupled":
                damaged[2]["entry_error"] = True
            elif fault == "capacity":
                damaged[-1]["reserved"] = 128 << 20
            else:
                damaged[-1], damaged[-2] = damaged[-2], damaged[-1]
            with self.subTest(guard=fault), self.assertRaises(v.Invalid):
                responded(admitted=damaged)
        for row in proof:
            self.assertNotEqual(row["before"]["result"], row["after"]["result"])
            self.assertEqual(sum(a != b for a, b in zip(row["before"]["values"], row["after"]["values"], strict=True)), 1)
        returns = v.decode(v.read(ROOT / "tests/fixtures/storage-returns.json"))
        return_rows = {name: {(row["values"], row["result"]): row["hits"] for row in rows} for name, rows in returns["vectors"].items()}

        def completed(cases: dict | None = None, observed: dict | None = None, decisions: dict | None = None, bindings: dict | None = None) -> list[dict]:
            """Copied native shapes test interpretation only; actual acceptance authenticates the original complete archive."""
            return storage.returned(
                returns["decisions"] if decisions is None else decisions,
                return_rows if observed is None else observed,
                returns["cases"] if cases is None else cases,
                returns["bindings"] if bindings is None else bindings,
            )

        proof = completed()
        self.assertEqual({(row["decision"], row["condition"]) for row in proof}, {(name, 0) for name in return_rows})
        for row in proof:
            self.assertNotEqual(row["before"]["result"], row["after"]["result"])
            self.assertEqual(sum(a != b for a, b in zip(row["before"]["values"], row["after"]["values"], strict=True)), 1)
        for name in storage.RETURN_CASES:
            for fault in ("missing", "status", "unknown", "markers", "duplicate"):
                changed = copy.deepcopy(returns["cases"])
                if fault == "missing":
                    del changed[name]
                elif fault == "status":
                    changed[name]["status"] = "skipped"
                elif fault == "unknown":
                    changed[name]["inferred"] = True
                elif fault == "markers":
                    changed[name]["markers"] = "unframed"
                else:
                    changed[name]["markers"].append("unobserved receipt")
                with self.subTest(return_case=name, fault=fault), self.assertRaises(v.Invalid):
                    completed(cases=changed)
        for name in returns["bindings"]:
            for fault in ("missing", "hash"):
                changed = dict(returns["bindings"])
                if fault == "missing":
                    del changed[name]
                else:
                    changed[name] = "0" * 64
                with self.subTest(return_source=name, fault=fault), self.assertRaises(v.Invalid):
                    completed(bindings=changed)
        for name, rows in return_rows.items():
            for fault in ("missing", "zero", "boolean", "before", "after", "coupled", "text", "tree"):
                changed_rows, changed_decisions = copy.deepcopy(return_rows), copy.deepcopy(returns["decisions"])
                if fault == "missing":
                    del changed_rows[name]
                elif fault in ("zero", "boolean"):
                    changed_rows[name] = {key: 0 if fault == "zero" else True for key in rows}
                elif fault in ("before", "after"):
                    pair = next(row for row in proof if row["decision"] == name)[fault]
                    del changed_rows[name][(authority.project(returns["decisions"][name], pair["values"])[0], pair["result"])]
                elif fault == "coupled":
                    changed_rows[name] = {("11", False): 1, ("22", True): 1}
                elif fault == "text":
                    changed_decisions[name]["text"] += " || true"
                else:
                    changed_decisions[name]["tree"][changed_decisions[name]["root"]]["kind"] = "or" if "&&" in changed_decisions[name]["text"] else "and"
                with self.subTest(return_decision=name, fault=fault), self.assertRaises(v.Invalid):
                    completed(observed=changed_rows, decisions=changed_decisions)
        batch = v.decode(v.read(ROOT / "tests/fixtures/storage-batches.json"))
        batch_rows = {name: {(row["values"], row["result"]): row["hits"] for row in rows} for name, rows in batch["vectors"].items()}

        def encoded(frames: list[dict] | None = None, observed: dict | None = None, decisions: dict | None = None) -> list[dict]:
            """Synthetic format receipts exercise the actual oracle; they never contribute native execution credit."""
            with (
                patch.object(logic, "inventory", return_value=batch["decisions"] if decisions is None else decisions),
                patch.object(logic, "observe", return_value=(batch_rows if observed is None else observed, 1)),
            ):
                return batches.observations({}, b"synthetic batch masks", batch["frames"] if frames is None else frames)

        proofs = encoded()
        self.assertEqual(len(proofs), 9)
        self.assertEqual(len({(row["decision"], row["condition"]) for row in proofs}), 9)
        for fault in (
            "missing",
            "duplicate",
            "kind",
            "outcome",
            "scope",
            "scope-extra",
            "version-bool",
            "wire",
            "wire-case",
            "change-bool",
            "payload-type",
            "payload-encoding",
            "key-encoding",
            "extra",
        ):
            changed = copy.deepcopy(batch["frames"])
            if fault == "missing":
                changed.pop()
            elif fault == "duplicate":
                changed[-1] = copy.deepcopy(changed[-2])
            elif fault == "kind":
                changed[0]["kind"] = []
            elif fault == "outcome":
                changed[0]["refused"] = True
            elif fault == "scope":
                changed[-1]["input"]["scope"]["Sector"] = "other"
            elif fault == "scope-extra":
                changed[-1]["input"]["scope"]["extra"] = 1
            elif fault == "version-bool":
                changed[0]["input"]["version"] = True
            elif fault == "wire":
                changed[0]["input"]["wire"] = "zz"
            elif fault == "wire-case":
                changed[0]["input"]["wire"] = changed[0]["input"]["wire"].upper()
            elif fault == "change-bool":
                changed[-1]["input"]["changes"][0]["Version"] = False
            elif fault == "payload-type":
                changed[-1]["input"]["changes"][0]["Value"] = 1
            elif fault == "payload-encoding":
                changed[-1]["input"]["changes"][0]["Value"] = "@@"
            elif fault == "key-encoding":
                changed[-1]["input"]["changes"][0]["Key"] = "\ud800"
            elif fault == "extra":
                changed[0]["extra"] = True
            with self.subTest(batch=fault), self.assertRaises(v.Invalid):
                encoded(changed)
        with self.assertRaisesRegex(v.Invalid, "batches-native-mask"):
            encoded(observed={name: {} for name in batch_rows})
        changed = copy.deepcopy(batch["decisions"])
        changed[batches.ROOTS["entry"]]["text"] = "true"
        with self.assertRaisesRegex(v.Invalid, "batches-source-decision"):
            encoded(decisions=changed)

        residual = v.decode(v.read(ROOT / "tests/fixtures/storage-retention.json"))
        native = {name: {(row["values"], row["result"]): row["hits"] for row in rows} for name, rows in residual["vectors"].items()}

        def retained(decisions: dict | None = None, observed: dict | None = None, frames: list[dict] | None = None, bindings: dict | None = None) -> dict:
            """Challenge exact residual-domain interpretation; this synthetic fixture grants no native product credit."""
            return retention.residual(
                residual["decisions"] if decisions is None else decisions,
                native if observed is None else observed,
                residual["frames"] if frames is None else frames,
                retention.BINDINGS if bindings is None else bindings,
            )

        report = retained()
        self.assertEqual((report["raw"], report["supported"], report["excluded"]), (14, 6, 8))
        coordinates = {(row["decision"], row["condition"]) for row in report["pairs"] + report["exclusions"]}
        self.assertEqual(len(coordinates), 14)
        self.assertEqual(sum(row["criterion"] == "defined-domain-short-circuit-v1" for row in report["pairs"]), 4)
        self.assertEqual(sum(row["reason"] == "literal-return-not-variable" for row in report["exclusions"]), 3)
        self.assertEqual(sum(row["reason"] == "source-coupled" for row in report["exclusions"]), 3)
        for row in report["exclusions"]:
            if row["reason"] == "source-coupled":
                self.assertLess(row["proof"]["admissible"], row["proof"]["assignments"])
                self.assertTrue(row["proof"]["relaxed_counterexample"])
        for name in retention.BINDINGS:
            for changed in ({key: value for key, value in retention.BINDINGS.items() if key != name}, {**retention.BINDINGS, name: "0" * 64}):
                with self.subTest(retention_binding=name), self.assertRaisesRegex(v.Invalid, "retention-source-bindings"):
                    retained(bindings=changed)
        for name in residual["decisions"]:
            changed = copy.deepcopy(residual["decisions"])
            changed[name]["text"] += " "
            with self.subTest(retention_source=name), self.assertRaisesRegex(v.Invalid, "retention-decision-binding"):
                retained(decisions=changed)
            for observed in ({key: value for key, value in native.items() if key != name}, {**native, name: {}}):
                with self.subTest(retention_missing=name), self.assertRaises(v.Invalid):
                    retained(observed=observed)
        for fault in (
            "missing",
            "duplicate",
            "test",
            "row",
            "index",
            "next-index",
            "next-calls",
            "retained",
            "limit",
            "values",
            "result",
            "extra",
            "bool-count",
        ):
            frames = copy.deepcopy(residual["frames"])
            if fault == "missing":
                frames.pop()
            elif fault == "duplicate":
                frames[-1] = copy.deepcopy(frames[-2])
            elif fault == "test":
                frames[0]["test"] = "other"
            elif fault == "row":
                frames[0]["rows"][0][1] = 67
            elif fault == "index":
                frames[0]["index"] = 1
            elif fault == "next-index":
                frames[1]["next_index"] = 2
            elif fault == "next-calls":
                frames[1]["next_calls"] = 1
            elif fault == "retained":
                frames[1]["retained"] = 0
            elif fault == "limit":
                frames[0]["history_limit"] = 0
            elif fault == "values":
                frames[1]["values"][2] = False
            elif fault == "result":
                frames[0]["result"] = False
            elif fault == "extra":
                frames[0]["extra"] = True
            else:
                frames[1]["next_calls"] = False
            with self.subTest(retention_frame=fault), self.assertRaisesRegex(v.Invalid, "retention-native-inputs"):
                retained(frames=frames)
        for suffix, vector in (("commit.go:2317", "20"), ("schema.go:7432", "112")):
            name = retention.PACKAGE + "/" + suffix
            with self.subTest(retention_assumption=suffix), self.assertRaisesRegex(v.Invalid, "retention-domain-contradiction"):
                retained(observed={**native, name: {**native[name], (vector, True): 1}})
        for suffix, vector, outcome in (
            ("lock_linux.go:636", "20", True),
            ("store.go:4000", "12", False),
            ("store.go:10634", "110", False),
            ("store.go:10634", "200", True),
        ):
            name = retention.PACKAGE + "/" + suffix
            with self.subTest(retention_guard=suffix, vector=vector), self.assertRaisesRegex(v.Invalid, "retention-guard-native-witness"):
                retained(observed={**native, name: {key: value for key, value in native[name].items() if key != (vector, outcome)}})
        for suffix, target in (("read.go:3910", 0), ("read.go:6637", 0), ("store.go:2674", 3)):
            name = retention.PACKAGE + "/" + suffix
            with self.subTest(retention_coupling=suffix), self.assertRaisesRegex(v.Invalid, "retention-coupling-vacuous"):
                retention.coupled(residual["decisions"][name], target, lambda values: True, native[name])


class StructureTests(unittest.TestCase):
    """Ensure statement completeness needs the exact source, compiler denominator and original artifact bytes."""

    def test_admission_mutation(self) -> None:
        """Every source-qualified mutation group is mandatory; no passing subset or failed native check qualifies the aggregate."""
        config, _, _ = v.configuration(ROOT / "development.json", ROOT)
        obligations = v.expand(config)
        target = "admission/DEV-COVERAGE/ADMISSION-ASSURANCE/linux-amd64-cgo/mutation"
        _, graph = v.dependency_order(obligations)
        dependencies = graph[target]
        self.assertEqual(len(dependencies), 8)
        checks = v.unique(config["checks"])
        expected = {
            "admission-mutants": ("mutations.json", 26),
            "admission-acquisition-mutants": ("acquisition-mutations.json", 7),
            "admission-security-mutants": ("security-mutations.json", 29),
            "admission-same-mutants": ("same-mutations.json", 9),
            "admission-conflict-mutants": ("conflicts-mutations.json", 18),
            "admission-loop-mutants": ("loops-mutations.json", 18),
            "admission-predicate-mutants": ("predicate-mutations.json", 31),
            "admission-numeric-mutants": ("numeric-mutations.json", 9),
            "admission-drain-mutants": ("drain-mutations.json", 5),
        }
        actual = {name for key in dependencies for name in obligations[key]["checks"]}
        self.assertEqual(actual, set(expected) | {"admission-structure"})
        self.assertEqual(sum(count for _, count in expected.values()), 152)
        for name, (filename, count) in expected.items():
            check = checks[name]
            self.assertEqual(check["manifest"], "internal/admission/" + filename)
            plan = v.decode(v.read(ROOT / check["manifest"]))
            self.assertEqual(len(plan["mutations"]), count)
            self.assertEqual(check["adapter"], "go-mutations")
            self.assertEqual(check["probes"][0]["minimum_hits"], count)
        base = v.decode(v.read(ROOT / checks["admission-mutants"]["manifest"]))
        self.assertEqual(
            base["fixtures"],
            [
                {"source": "tests/fixtures/admission-inspection.go.in", "target": "internal/admission/inspection_linux_amd64_test.go"},
                {"source": "tests/fixtures/admission-metadata.go.in", "target": "internal/admission/metadata_linux_amd64_test.go"},
            ],
        )
        guards = v.unique(base["mutations"])
        self.assertEqual(guards["identity-follow-link"]["test"], "TestLoadInspection")
        self.assertEqual(guards["identity-stat-kind"]["test"], "TestLoadMetadata")
        now = dt.datetime(2026, 10, 9, tzinfo=dt.timezone.utc)
        observations = {
            (name, obligations[key]["platform"], obligations[key]["contract"]): "passed" for key in dependencies for name in obligations[key]["checks"]
        }
        self.assertIn(target, v.decide(config, observations, [], [], now)["passed"])
        for observation in observations:
            for state in (None, "failed", "not-run"):
                changed = dict(observations)
                if state is None:
                    del changed[observation]
                else:
                    changed[observation] = state
                with self.subTest(check=observation[0], state=state):
                    self.assertNotIn(target, v.decide(config, changed, [], [], now)["passed"])

    def test_configuration(self) -> None:
        """Reject weakened probes, additional filters, duplicate domains and undeclared compiler profiles."""
        # Native discovery and the gate must agree even when a selected module acquires new tests.
        config = v.decode(v.read(ROOT / "development.json"))

        def names(suite: unittest.TestSuite) -> Iterator[str]:
            """Enumerate actual unittest leaves without executing any test or accepting an empty selection."""
            for item in suite:
                if isinstance(item, unittest.TestSuite):
                    yield from names(item)
                else:
                    yield item.id()

        for identity in ("tools-python", "tools-windows", "logic-python", "storage-inputs-python"):
            selected = next(item for item in config["checks"] if item["id"] == identity)
            discovered = list(names(unittest.TestLoader().loadTestsFromNames(selected["argv"][4:])))
            with self.subTest(selection=identity):
                self.assertTrue(discovered)
                self.assertEqual(len(discovered), len(set(discovered)))
                self.assertEqual(set(discovered), set(selected["expected_tests"]))
        original = check()
        statements.configuration(original)
        variant = copy.deepcopy(original)
        variant["argv"].insert(3, "-race")
        statements.configuration(variant)
        for field, value in [
            ("component", "other"),
            ("package", "other/command"),
            ("coverage", "other"),
            ("argv", original["argv"][:-1] + ["-run=TestDecisions", original["argv"][-1]]),
            ("argv", [item.replace("command.cover", "other.cover") for item in original["argv"]]),
            ("expected_tests", original["expected_tests"] + [original["expected_tests"][0]]),
            ("probes", [item for item in original["probes"] if item["contract"] != "COMMAND-ASSURANCE"]),
            ("probes", original["probes"] + [original["probes"][0]]),
        ]:
            changed = copy.deepcopy(original)
            changed[field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(v.Invalid, "command-structure-configuration"):
                statements.configuration(changed)

    def test_native_denominator(self) -> None:
        """Missing/zero/extra/conflicting counters cannot retain structural qualification."""
        original = check()
        self.assertEqual(statements.observations(PROFILE, original, ROOT), {"COMMAND-ASSURANCE": 12})
        lines = PROFILE.splitlines(keepends=True)
        cases = [
            (None, "command-profile-missing"),
            (b"mode: atomic\n", "go-profile-empty"),
            (b"".join(lines[:2] + lines[3:]), "command-profile-denominator"),
            (PROFILE.replace(b"15.2,15.24 1 1", b"15.2,15.24 1 0"), "command-profile-uncovered"),
            (PROFILE.replace(b"15.2,15.24 1 1", b"15.2,15.24 2 1"), "command-profile-denominator"),
            (PROFILE + lines[1].replace(b"1 1", b"2 1"), "go-profile-conflicting-block"),
            (PROFILE.replace(b"mode: atomic", b"mode: count"), "command-profile-denominator"),
            (PROFILE.replace(b"flags.go", b"other.go"), "go-profile-unregistered"),
            (PROFILE + b"github.com/eosforge/astra/internal/command/flags.go:38.1,38.2 1 1\n", "command-profile-denominator"),
        ]
        for data, cause in cases:
            with self.subTest(cause=cause), self.assertRaisesRegex(v.Invalid, cause):
                statements.observations(data, original, ROOT)
        profile = v.read(ROOT / "tests/fixtures/storage.cover")
        trace = storage_trace()
        expected = {"blocks": 401, "statements": 622, "statements_hit": 622}
        if idle.current(ROOT):
            # The old profile stays a historical parser fixture and cannot cover the new maintenance file.
            with self.assertRaisesRegex(v.Invalid, "go-profile-position: polaris/internal/storage/store.go"):
                structure.storage_counters(profile, ROOT, trace)
            files = idle.unpack(idle.artifacts(ROOT)[idle.CURRENT])
            bundle = v.decode(files[idle.PREFIX + "bundle.json"])
            profile = storage.reference(files, idle.PREFIX, bundle["profiles"]["parent"])
            expected = {"blocks": 412, "statements": 643, "statements_hit": 643}
        result = structure.storage_counters(profile, ROOT, trace)
        self.assertEqual(result["raw"], expected)
        self.assertEqual(result["unexplained"], [])
        lines = profile.splitlines(keepends=True)
        first = next(line for line in lines[1:] if int(line.split()[-2]) > 0)
        zeroed = profile.replace(first, first.rsplit(b" ", 1)[0] + b" 0\n", 1)
        result = structure.storage_counters(zeroed, ROOT, trace)
        self.assertTrue(result["unexplained"])
        self.assertLess(result["raw"]["statements_hit"], expected["statements"])
        for data, cause in (
            (b"".join(lines[:1] + lines[2:]), "structure-storage-profile-denominator"),
            (profile + lines[1], "structure-storage-profile-denominator"),
            (profile.replace(b"mode: atomic", b"mode: count"), "structure-storage-profile-denominator"),
            (profile.replace(b"batch.go:", b"lock_other.go:"), "go-profile-unregistered"),
        ):
            with self.subTest(storage=cause), self.assertRaisesRegex(v.Invalid, cause):
                structure.storage_counters(data, ROOT, trace)

    def test_source_scope(self) -> None:
        """A changed source or extra nested production file invalidates the frozen one-file denominator."""
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            directory = root / "internal/command"
            directory.mkdir(parents=True)
            path = directory / "flags.go"
            path.write_bytes((ROOT / "internal/command/flags.go").read_bytes())
            self.assertEqual(statements.observations(PROFILE, check(), root), {"COMMAND-ASSURANCE": 12})
            path.write_bytes(path.read_bytes() + b"\n")
            with self.assertRaisesRegex(v.Invalid, "command-structure-source"):
                statements.observations(PROFILE, check(), root)
            path.write_bytes((ROOT / "internal/command/flags.go").read_bytes())
            nested = directory / "nested"
            nested.mkdir()
            (nested / "extra.go").write_text("package nested\n", encoding="utf-8")
            with self.assertRaisesRegex(v.Invalid, "command-structure-scope"):
                statements.observations(PROFILE, check(), root)
        packed = v.read(ROOT / "build/results/assurance" / idle.SOURCE, 64 * 1024**2)
        self.assertEqual(v.digest(packed), idle.ARTIFACTS[idle.SOURCE])
        frozen = entry.unpack(packed)
        profile = v.read(ROOT / "tests/fixtures/storage.cover")
        self.assertEqual(profile, frozen["tests/fixtures/storage.cover"])
        historical = {
            name: data for name, data in frozen.items() if name.startswith(structure.STORAGE + "/") and name.endswith(".go") and not name.endswith("_test.go")
        }
        trace = {"files": [{"file": name, "sha256": v.digest(data)} for name, data in sorted(historical.items())]}
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for item in trace["files"]:
                target = root / item["file"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(historical[item["file"]])
            structure.storage_counters(profile, root, trace)
            target = root / structure.STORAGE / "store.go"
            target.write_bytes(target.read_bytes() + b"\n")
            with self.assertRaisesRegex(v.Invalid, "structure-storage-source-drift"):
                structure.storage_counters(profile, root, trace)
            target.write_bytes(historical[structure.STORAGE + "/store.go"])
            (target.parent / "extra.go").write_text("package storage\n", encoding="utf-8")
            with self.assertRaisesRegex(v.Invalid, "structure-storage-source-scope"):
                structure.storage_counters(profile, root, trace)
        # Synthetic closures challenge content binding without qualifying native execution.
        paths = {path.relative_to(ROOT).as_posix(): path for directory in (structure.STORAGE, "tools/decisions") for path in (ROOT / directory).glob("*.go")}
        paths.update({name: ROOT / name for name in ("tools/decisions/runtime.go.in", "go.mod", "go.sum", "tests/fixtures/storage.tests.json")})
        inputs = {"files": {name: v.file_digest(path) for name, path in paths.items()}}
        files = {"source/" + name: v.read(path) for name, path in paths.items()}
        metadata = v.encode({"ImportPath": "github.com/eosforge/astra/" + structure.STORAGE})
        self.assertEqual(storage.sources(ROOT, files, inputs, metadata), inputs["files"])
        for name in (structure.STORAGE + "/model.go", "go.sum", "tools/decisions/runtime.go.in"):
            with self.subTest(source=name), self.assertRaisesRegex(v.Invalid, "storage-current-source-drift"):
                storage.sources(ROOT, {**files, "source/" + name: b"altered"}, inputs, metadata)
        incomplete = copy.deepcopy(inputs)
        incomplete["files"].pop(structure.STORAGE + "/model.go")
        with self.assertRaisesRegex(v.Invalid, "storage-current-source-inventory"):
            storage.sources(ROOT, files, incomplete, metadata)
        with self.assertRaisesRegex(v.Invalid, "storage-production-closure"):
            storage.sources(ROOT, files, inputs, metadata + v.encode({"ImportPath": "github.com/eosforge/astra/internal/admission"}))

    def test_native_reference(self) -> None:
        """Require the resolved native command and verify profile bytes independently of successful test logs."""
        original = check()
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            path = directory / "command.cover"
            path.write_bytes(PROFILE)
            record = {
                "resolved_argv": [item.replace("{run}", str(directory)) for item in original["argv"]],
                "profile": {"path": path.name, "bytes": len(PROFILE), "sha256": v.digest(PROFILE)},
            }
            self.assertEqual(v.coverage(directory, record, original), PROFILE)
            for field, value in [
                ("resolved_argv", original["argv"]),
                ("resolved_argv", []),
                ("profile", {}),
                ("profile", {**record["profile"], "path": "other.cover"}),
            ]:
                modified = copy.deepcopy(record)
                modified[field] = value
                with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "command-profile-record"):
                    v.coverage(directory, modified, original)
            path.write_bytes(PROFILE + b"\n")
            with self.assertRaisesRegex(v.Invalid, "artifact-integrity"):
                v.coverage(directory, record, original)
            other = {key: value for key, value in original.items() if key != "coverage"}
            with self.assertRaisesRegex(v.Invalid, "unexpected-profile-record"):
                v.coverage(directory, record, other)
            self.assertIsNone(v.coverage(directory, {}, other))

        # Synthetic native envelopes challenge the reader; they never qualify application execution.
        name = "coverage"
        prefix = storage.PREFIX + name + "/"
        native = storage.NATIVE / "build/commands/structure/structure" / name
        environment = {"GOPROXY": "off", "GOMAXPROCS": "2"}
        child = {**environment, "TMPDIR": str(native / "tmp"), "ASTRA_TEST_LOG_DIR": str(native / "logs")}
        inputs = {"tools": {key: {"path": "/synthetic/" + key, "sha256": str(index) * 64} for index, key in enumerate(("go", "gcc", "g++"), 1)}}
        owner = {"boot_id": "12345678-1234-1234-1234-123456789012", "identity": {"pid": 12}}
        arguments = ["go", "test", "-json", "./polaris/internal/storage"]
        process = {"identity": {"pid": 13, "start_ticks": "123", "parent": 12}, "argv": arguments, "cwd": str(storage.NATIVE), "boot_id": owner["boot_id"]}
        stream = b"synthetic complete output\n"
        record = {
            "id": name,
            "argv": arguments,
            "platform": structure.PLATFORM,
            "environment": child,
            "resolved_environment": child,
            "executable": inputs["tools"]["go"]["path"],
            "executable_sha256": inputs["tools"]["go"]["sha256"],
            "toolchain": {"command": inputs["tools"]["go"], "CC": inputs["tools"]["gcc"], "CXX": inputs["tools"]["g++"]},
            "duration_ms": 1,
            "started_at": "2026-10-01T00:00:00Z",
            "finished_at": "2026-10-01T00:00:01Z",
            "exit_code": 0,
            "termination": "exited",
            "complete": True,
            "cleanup": True,
            "stdout": {"path": "stdout.log", "bytes": len(stream), "sha256": v.digest(stream)},
            "stderr": {"path": "stderr.log", "bytes": 0, "sha256": v.digest(b"")},
        }
        files = {
            prefix + "record.json": v.encode(record),
            prefix + "coverage.process.json": v.encode(process),
            prefix + "stdout.log": stream,
            prefix + "stderr.log": b"",
            "cleanup.native.json": v.encode({"retired": [process["identity"]]}),
        }
        self.assertEqual(storage.command(files, name, arguments, 60, environment, inputs, owner), (record, stream))
        for field, value in (
            ("argv", [*arguments, "-run=Subset"]),
            ("platform", "windows"),
            ("duration_ms", 60001),
            ("exit_code", 1),
            ("termination", "timeout"),
            ("complete", False),
            ("cleanup", False),
            ("resolved_environment", {**child, "GOPROXY": "direct"}),
            ("toolchain", {**record["toolchain"], "CC": inputs["tools"]["go"]}),
        ):
            with self.subTest(storage=field), self.assertRaises(v.Invalid):
                storage.command({**files, prefix + "record.json": v.encode({**record, field: value})}, name, arguments, 60, environment, inputs, owner)
        for field, value in (("cwd", "/different"), ("argv", []), ("boot_id", "different"), ("identity", {**process["identity"], "parent": 99})):
            with self.subTest(storage=field), self.assertRaisesRegex(v.Invalid, "storage-native-command"):
                storage.command(
                    {**files, prefix + "coverage.process.json": v.encode({**process, field: value})}, name, arguments, 60, environment, inputs, owner
                )
        for channel in ("stdout", "stderr"):
            with self.subTest(storage=channel), self.assertRaisesRegex(v.Invalid, "storage-artifact-integrity"):
                storage.command({**files, prefix + channel + ".log": b"altered"}, name, arguments, 60, environment, inputs, owner)
        for path in ("../stdout.log", "/stdout.log", "C:\\stdout.log", "./stdout.log"):
            with self.subTest(path=path), self.assertRaises(v.Invalid):
                storage.reference(files, prefix, {**record["stdout"], "path": path})
        with self.assertRaisesRegex(v.Invalid, "storage-retained-inventory-or-integrity"):
            storage.reconcile(ROOT, {})
        tools = {name: {"path": "/home/ubuntu/verdandi/build/tools/tool/bin/" + name} for name in ("go", "gcc", "g++")}
        policy = {"environment": {"ASTRA_CACHE_ROOT": "{cache}", "GOCACHE": "{root}/build/cache/go"}}
        expanded = storage.environment(policy, {"tools": tools, "cache_root": "/separate/retired/warm/source"})
        self.assertEqual(expanded, {"ASTRA_CACHE_ROOT": "/home/ubuntu/verdandi/build", "GOCACHE": str(storage.NATIVE / "build/cache/go")})
        with self.assertRaisesRegex(v.Invalid, "storage-native-tool-root"):
            storage.environment(policy, {"tools": {**tools, "gcc": {"path": "/different/tools/tool/bin/gcc"}}})

    def test_schema(self) -> None:
        """The closed configuration accepts the named capability and rejects unknown coverage identities/fields."""
        original = v.decode(v.read(ROOT / "development.json"))
        v.schema(original, "development")
        for field, value in [("coverage", "other"), ("coverage", True), ("coverage", None), ("profile", "command.cover")]:
            changed = copy.deepcopy(original)
            target = next(item for item in changed["checks"] if item["id"] == "command-boundaries")
            target[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "schema-invalid"):
                v.schema(changed, "development")

    def test_fixed_obligations(self) -> None:
        """Pin original qualification objects and every reviewed addition and prerequisite migration."""
        original = v.decode(v.read(ROOT / "development.json"))
        obligations = v.expand(original)
        self.assertEqual(len(obligations), 1370)
        # Preserve all original objects while fixing nine additions and two stricter backup prerequisites separately.
        backup = v.decode(v.read(ROOT / "tests/fixtures/obligations-backup.json"))
        self.assertEqual(v.file_digest(ROOT / "tests/fixtures/obligations-backup.json"), "f46daf3460b1d2df3810d6adeb4321188e4b9090a5ff6524242e3bccdbc5a829")
        self.assertEqual(backup["version"], 1)
        self.assertEqual(backup["original_obligations"], 1361)
        self.assertEqual(len(backup["added"]), 9)
        self.assertEqual(sum(item["contract"].startswith("BENCHMARKS-GATES-") for item in backup["added"].values()), 7)
        self.assertEqual(
            {item["contract"] for item in backup["added"].values() if item["component"] == "polaris-storage"},
            {"STORAGE-BACKUP-ONLINE", "STORAGE-BACKUP-RESTORE"},
        )
        for name, expected in backup["added"].items():
            self.assertEqual(obligations.pop(name), expected)
        self.assertEqual(
            set(backup["migrations"]),
            {f"polaris-storage/{rule}/STORAGE-ASSURANCE/linux-amd64-cgo/full-rule" for rule in ("DEV-OPERATE", "DEV-RELEASE")},
        )
        for name, migration in backup["migrations"].items():
            self.assertEqual(obligations[name], migration["after"])
            self.assertEqual({key: value for key, value in migration["after"].items() if key != "requires"}, migration["before"])
            self.assertEqual(len(migration["after"]["requires"]), 1)
            obligations[name] = copy.deepcopy(migration["before"])
        self.assertEqual(len(obligations), 1361)
        # Approved Comet scope and partition controls extend, never replace, the protected historical policy.
        current = v.decode(v.read(ROOT / "tests/fixtures/obligations-comet.json"))
        self.assertEqual(v.file_digest(ROOT / "tests/fixtures/obligations-comet.json"), "bc171570d89d9221b35731e4537697e6da59b43ebddf93d61f0a686fbcb04369")
        self.assertEqual(len(current["added"]), 102)
        self.assertEqual(sum(item["component"] == "comet-go" for item in current["added"].values()), 96)
        for name, expected in current["added"].items():
            self.assertEqual(obligations.pop(name), expected)
        self.assertEqual(len(obligations), 1259)
        evolution = v.decode(v.read(ROOT / "tests/fixtures/obligations-common.json"))
        self.assertEqual(v.file_digest(ROOT / "tests/fixtures/obligations-common.json"), "b257faa74a8e418c6af76767ac0b936ce65772592bac88a99dca0dd93abe32bb")
        boundaries = {name: expected for name, expected in evolution["added"].items() if expected["contract"].startswith("BOUNDARY-")}
        self.assertEqual(len(boundaries), 10)
        self.assertEqual({item["component"] for item in boundaries.values()}, {"verification"})
        for name, expected in boundaries.items():
            self.assertEqual(obligations.pop(name), expected)
        self.assertEqual(len(obligations), 1249)
        # New declared obligations are checked separately from the immutable original baseline.
        supplements = v.decode(v.read(ROOT / "tests/fixtures/obligations.json"))
        self.assertEqual(v.file_digest(ROOT / "tests/fixtures/obligations.json"), "fba322d85e355ce7ea2cb79ab9f2f9df31cbdf7092e3814e1229f4f1822b7257")
        self.assertEqual(len(supplements["added"]), 32)
        self.assertEqual(len(supplements["conjunctions"]), 3)
        for key, expected in supplements["added"].items():
            self.assertEqual(obligations[key], expected)
        qualification = v.decode(v.read(ROOT / "tests/fixtures/qualification.json"))
        self.assertEqual(v.file_digest(ROOT / "tests/fixtures/qualification.json"), "d1af60e9d6a432f0e0d1cf1a9eaf8b9bab13cdbfdb2e3ccc824a8ab246e0e890")
        self.assertEqual(qualification["version"], 1)
        self.assertEqual(qualification["original_objects_sha256"], "f69ee35f47ca9001bdecb12baf0fa6d66cc839951923b8404499dd946306f827")
        self.assertEqual(len(qualification["added"]), 98)
        self.assertEqual(len(qualification["migrations"]), 51)
        for key, expected in qualification["added"].items():
            self.assertEqual(obligations[key], expected)
        for key, migration in qualification["migrations"].items():
            self.assertEqual(obligations[key], migration["after"])
        inputs = {
            "INPUT-FEED-PAIRS": ("tests.test_feeds.FeedsTests.test_pairs", 20),
            "INPUT-FEED-ARGUMENTS": ("tests.test_feeds.FeedsTests.test_inputs", 209),
            "INPUT-FEED-MASKS": ("tests.test_feeds.FeedsTests.test_masks", 10),
            "INPUT-FEED-SOURCE": ("tests.test_feeds.FeedsTests.test_sources", 5),
            "INPUT-OPEN-PAIRS": ("tests.test_opening.OpeningTests.test_pairs", 48),
            "INPUT-OPEN-ARGUMENTS": ("tests.test_opening.OpeningTests.test_arguments", 98),
            "INPUT-OPEN-PATHS": ("tests.test_opening.OpeningTests.test_paths", 10),
            "INPUT-OPEN-MASKS": ("tests.test_opening.OpeningTests.test_native", 15),
        }
        check = next(check for check in original["checks"] if check["id"] == "storage-inputs-python")
        self.assertEqual({probe["contract"]: (probe["test"], probe["minimum_hits"]) for probe in check["probes"]}, inputs)
        self.assertEqual(set(check["expected_tests"]), {test for test, _ in inputs.values()})
        self.assertEqual(check["argv"], ["python3", "-B", "tools/observe.py", "python", "tests.test_feeds", "tests.test_opening"])
        cells = {f"tools/DEV-ORACLE/{contract}/{platform}/storage-input-controls" for contract in inputs for platform in ("linux-amd64-cgo", "windows-amd64")}
        self.assertEqual({key for key, item in obligations.items() if "storage-inputs-python" in item["checks"]}, cells)
        for key in cells:
            self.assertEqual(obligations[key]["checks"], ["storage-inputs-python"])
        windows = {"tools/DEV-CONTRACT/TOOLS-WINDOWS-ENV/windows-amd64/native-oracle"}
        self.assertEqual({key for key, item in obligations.items() if item["contract"] == "TOOLS-WINDOWS-ENV"}, windows)
        self.assertEqual(
            obligations[next(iter(windows))],
            {
                "checks": ["tools-windows-mutation-boundaries"],
                "contract": "TOOLS-WINDOWS-ENV",
                "platforms": ["windows-amd64"],
                "rule": "DEV-CONTRACT",
                "scenario": "native-oracle",
                "component": "tools",
                "platform": "windows-amd64",
            },
        )
        metrics = "astrolabe/DEV-CONTRACT/ASTROLABE-METRICS/linux-amd64-cgo/metrics-boundaries"
        self.assertEqual({key for key, item in obligations.items() if item["contract"] == "ASTROLABE-METRICS"}, {metrics})
        self.assertEqual(
            obligations[metrics],
            {
                "rule": "DEV-CONTRACT",
                "contract": "ASTROLABE-METRICS",
                "scenario": "metrics-boundaries",
                "checks": ["astrolabe-metrics"],
                "component": "astrolabe",
                "platform": "linux-amd64-cgo",
            },
        )
        entry = "astrolabe/DEV-CONTRACT/ASTROLABE-ENTRY/linux-amd64-cgo/entry-boundaries"
        self.assertEqual({key for key, item in obligations.items() if item["contract"] == "ASTROLABE-ENTRY"}, {entry})
        self.assertEqual(
            obligations[entry],
            {
                "rule": "DEV-CONTRACT",
                "contract": "ASTROLABE-ENTRY",
                "scenario": "entry-boundaries",
                "checks": ["astrolabe-entry", "astrolabe-process"],
                "component": "astrolabe",
                "platform": "linux-amd64-cgo",
            },
        )
        drain = "polaris-server/DEV-CONTRACT/POLARIS-DRAIN/linux-amd64-cgo/boundary-oracle"
        self.assertEqual(obligations[drain]["checks"], ["polaris-server-boundaries"])
        observed = ("polaris-server-boundaries", "linux-amd64-cgo", "POLARIS-DRAIN")
        decision = v.decide(original, {observed: "passed"}, [], [], dt.datetime(2026, 10, 7, tzinfo=dt.timezone.utc))
        self.assertEqual(decision["passed"], [drain])
        self.assertEqual(decision["status"], "blocked")
        environment = {"VERIFY-ENV-NAMESPACE", "VERIFY-ENV-CHILD", "VERIFY-ENV-DECLARED"}
        native = {f"verification/DEV-CONTRACT/{name}/linux-amd64-cgo/native-oracle" for name in environment}
        self.assertEqual({key for key, item in obligations.items() if item["contract"] in environment}, native)
        for key in native:
            self.assertEqual(obligations[key]["checks"], ["verification-python"])
        names = {"DELIVERY-HEADER", "DELIVERY-LOADER", "DELIVERY-SEQUENCE", "DELIVERY-CONTENTS", "DELIVERY-EXPORT", "SOAK-INSTALLED"}
        added = {
            f"tools/DEV-CONTRACT/{name}/{platform}/native-oracle"
            for name in names
            for platform in ("linux-amd64-cgo", "windows-amd64")
            if platform == "linux-amd64-cgo" or name not in {"DELIVERY-CONTENTS", "DELIVERY-EXPORT"}
        }
        self.assertEqual({key for key, item in obligations.items() if item["contract"] in names}, added)
        consumers = {f"tools/DEV-EVIDENCE/DELIVERY-CONSUMERS/{platform}/native-oracle" for platform in ("linux-amd64-cgo", "windows-amd64")}
        self.assertEqual({key for key, item in obligations.items() if item["contract"] == "DELIVERY-CONSUMERS"}, consumers)
        for key in consumers:
            self.assertEqual(obligations[key]["checks"], ["tools-python" if "/linux-amd64-cgo/" in key else "tools-windows"])
        pagination = {"star/DEV-CONTRACT/STAR_NATIVE-29/linux-amd64-cgo/native-oracle"}
        self.assertEqual({key for key, item in obligations.items() if item["contract"] == "STAR_NATIVE-29"}, pagination)
        self.assertEqual(obligations[next(iter(pagination))]["checks"], ["star-native"])
        # A bounded pagination pass cannot replace any model or whole-component qualification.
        now = dt.datetime(2026, 10, 7, tzinfo=dt.timezone.utc)
        coordinate = next(iter(pagination))
        observation = ("star-native", "linux-amd64-cgo", "STAR_NATIVE-29")
        gate = v.decide(original, {observation: "passed"}, [], [], now)
        self.assertEqual(set(gate["passed"]), pagination)
        self.assertEqual(gate["status"], "blocked")
        for state in (None, "failed", "unknown", "not-run", "interrupted", "wrong-platform", "wrong-contract"):
            observations = {observation: state} if state is not None else {}
            if state == "wrong-platform":
                observations = {("star-native", "windows-amd64", "STAR_NATIVE-29"): "passed"}
            elif state == "wrong-contract":
                observations = {("star-native", "linux-amd64-cgo", "STAR_NATIVE-28"): "passed"}
            with self.subTest(pagination=state):
                gate = v.decide(original, observations, [], [], now)
                self.assertIn(coordinate, gate["missing"])
                self.assertNotIn(coordinate, gate["passed"])
                self.assertEqual(gate["status"], "blocked")
        page_fault = {"star/DEV-CONTRACT/STAR_NATIVE-30/linux-amd64-cgo/native-oracle"}
        self.assertEqual({key for key, item in obligations.items() if item["contract"] == "STAR_NATIVE-30"}, page_fault)
        self.assertEqual(obligations[next(iter(page_fault))]["checks"], ["star-native"])
        dispatch_fault = {"star/DEV-CONTRACT/STAR_NATIVE-31/linux-amd64-cgo/native-oracle"}
        self.assertEqual({key for key, item in obligations.items() if item["contract"] == "STAR_NATIVE-31"}, dispatch_fault)
        self.assertEqual(obligations[next(iter(dispatch_fault))]["checks"], ["star-native"])
        catalog_rpc = {"star/DEV-CONTRACT/STAR_NATIVE-32/linux-amd64-cgo/native-oracle"}
        self.assertEqual({key for key, item in obligations.items() if item["contract"] == "STAR_NATIVE-32"}, catalog_rpc)
        self.assertEqual(obligations[next(iter(catalog_rpc))]["checks"], ["star-native"])
        authentication = {
            f"comet/DEV-ASYNC/COMET-AUTH-{mode.upper()}/{platform}/login-{mode}"
            for mode in ("session", "input", "protocol")
            for platform in ("linux-amd64-cgo", "windows-amd64")
        }
        self.assertEqual({key for key, item in obligations.items() if item["contract"].startswith("COMET-AUTH-")}, authentication)
        for key in authentication:
            self.assertEqual(obligations[key]["checks"], ["comet-windows" if "/windows-amd64/" in key else "comet-native"])
        baseline = copy.deepcopy(
            {
                key: item
                for key, item in obligations.items()
                if key
                not in added
                | native
                | consumers
                | pagination
                | page_fault
                | dispatch_fault
                | catalog_rpc
                | authentication
                | windows
                | {drain}
                | {entry, metrics}
                | set(supplements["added"])
                | set(qualification["added"])
            }
        )
        self.assertEqual(len(baseline), 1090)
        for key, migration in qualification["migrations"].items():
            baseline[key] = copy.deepcopy(migration["before"])
        for key, migration in supplements["conjunctions"].items():
            self.assertEqual(baseline[key], migration["after"])
            baseline[key] = copy.deepcopy(migration["before"])
        web = next(key for key, item in baseline.items() if item["contract"] == "ASTROLABE-BOUNDARY")
        self.assertEqual(baseline[web]["checks"], ["astrolabe-boundaries", "astrolabe-web"])
        baseline[web]["checks"] = ["astrolabe-boundaries"]
        # Pin exact executor migrations before comparing original contracts, platforms, dependencies and thresholds.
        server = "polaris-server/DEV-COVERAGE/POLARIS_SERVER-ASSURANCE/linux-amd64-cgo/structure"
        self.assertEqual({key for key, item in obligations.items() if "server-structure" in item["checks"]}, {server})
        self.assertEqual(baseline[server]["checks"], ["server-structure", "polaris-entry-qualification"])
        baseline[server]["checks"] = ["polaris-server-qualification"]
        independent = "polaris-server/DEV-COVERAGE/POLARIS_SERVER-ASSURANCE/linux-amd64-cgo/mcdc"
        self.assertEqual({key for key, item in obligations.items() if "server-independence" in item["checks"]}, {independent})
        self.assertEqual(baseline[independent]["checks"], ["server-independence", "polaris-entry-qualification"])
        baseline[independent]["checks"] = ["polaris-server-qualification"]
        astrolabe = "astrolabe/DEV-COVERAGE/ASTROLABE-ASSURANCE/linux-amd64-cgo/mcdc"
        self.assertEqual({key for key, item in obligations.items() if "astrolabe-independence" in item["checks"]}, {astrolabe})
        self.assertEqual(baseline[astrolabe]["checks"], ["astrolabe-independence"])
        baseline[astrolabe]["checks"] = ["astrolabe-qualification"]
        astrolabe_structure = "astrolabe/DEV-COVERAGE/ASTROLABE-ASSURANCE/linux-amd64-cgo/structure"
        self.assertEqual({key for key, item in obligations.items() if "astrolabe-structure" in item["checks"]}, {astrolabe_structure})
        self.assertEqual(baseline[astrolabe_structure]["checks"], ["astrolabe-structure"])
        baseline[astrolabe_structure]["checks"] = ["astrolabe-qualification"]
        admission = "admission/DEV-COVERAGE/ADMISSION-ASSURANCE/linux-amd64-cgo/mcdc"
        self.assertEqual({key for key, item in obligations.items() if "admission-independence" in item["checks"]}, {admission})
        self.assertEqual(baseline[admission]["checks"], ["admission-independence"])
        baseline[admission]["checks"] = ["admission-gap-mcdc"]
        security = "admission/DEV-ORACLE/ADMISSION-NODE-SENSITIVITY/linux-amd64-cgo/targeted-mutations"
        self.assertEqual({key for key, item in obligations.items() if "admission-security-mutants" in item["checks"]}, {security})
        self.assertEqual(baseline[security]["checks"], ["admission-mutants", "admission-security-mutants", "admission-acquisition-mutants"])
        baseline[security]["checks"] = ["admission-mutants"]
        mutation = "admission/DEV-COVERAGE/ADMISSION-ASSURANCE/linux-amd64-cgo/mutation"
        self.assertEqual(v.digest(v.encode(baseline[mutation])), "eb15e9646ae2da7efaf36dfd945b69f7442f1d78f84a06cf7c87fffb6b9575b8")
        baseline[mutation].pop("aggregate")
        baseline[mutation].pop("requires")
        baseline[mutation]["checks"] = ["admission-gap-mutation"]
        fault = "admission/DEV-FAULT/ADMISSION-ASSURANCE/linux-amd64-cgo/fault-matrix"
        self.assertEqual(v.digest(v.encode(baseline[fault])), "238a5e0ab17e19081b46ee6cd911a0542565f18587611da82bdb019ed895d760")
        baseline[fault].pop("aggregate")
        baseline[fault].pop("requires")
        baseline[fault]["checks"] = ["admission-gap-fault-matrix"]
        refresh = "admission/DEV-CONTRACT/ADMISSION-NODE-REFRESH/linux-amd64-cgo/refresh-receipts"
        self.assertEqual({key for key, item in obligations.items() if "admission-refresh-faults" in item["checks"]}, {refresh})
        self.assertEqual(baseline[refresh]["checks"], ["admission-model", "admission-refresh-faults"])
        baseline[refresh]["checks"] = ["admission-model"]
        moved = {f"tools/DEV-CONTRACT/TOOLS_PYTHON-{number}/windows-amd64/native-oracle" for number in (18, 62)}
        self.assertEqual({key for key, item in obligations.items() if "tools-windows-mutation-boundaries" in item["checks"]}, moved | windows)
        for key in moved:
            self.assertEqual(baseline[key]["checks"], ["tools-windows-mutation-boundaries"])
            baseline[key]["checks"] = ["tools-windows-linux-boundaries"]
        finite = "common/DEV-MODEL/COMMON-ASSURANCE/linux-amd64-cgo/finite-model"
        self.assertEqual({key for key, item in obligations.items() if "common-finite-model" in item["checks"]}, {finite})
        self.assertEqual(baseline[finite]["checks"], ["common-finite-model"])
        baseline[finite]["checks"] = ["common-qualification"]
        finite = "pulsar/DEV-MODEL/PULSAR-ASSURANCE/linux-amd64-cgo/finite-model"
        self.assertEqual({key for key, item in obligations.items() if "pulsar-finite-model" in item["checks"]}, {finite})
        self.assertEqual(baseline[finite]["checks"], ["pulsar-finite-model"])
        baseline[finite]["checks"] = ["pulsar-qualification"]
        finite = "star/DEV-MODEL/STAR-ASSURANCE/linux-amd64-cgo/finite-model"
        for identifier in ("almanac-finite-model", "catalog-finite-model", "ephemeris-finite-model"):
            self.assertEqual({key for key, item in obligations.items() if identifier in item["checks"]}, {finite})
        self.assertEqual(baseline[finite]["checks"], ["almanac-finite-model", "catalog-finite-model", "ephemeris-finite-model"])
        self.assertEqual(obligations["star/DEV-MODEL/STAR-ASSURANCE/linux-amd64-cgo/full-rule"]["checks"], ["star-qualification"])
        baseline[finite]["checks"] = ["star-qualification"]
        # Only these five explicitly implemented proof routes may differ from the original full-rule objects.
        prerequisites = [
            {"rule": rule, "contract": "COMMAND-ASSURANCE", "scenario": "full-rule"}
            for rule in ("DEV-CORE", "DEV-COVERAGE", "DEV-FAULT", "DEV-ASYNC", "DEV-NUMERIC", "DEV-MODEL")
        ]
        for rule in ("DEV-ORACLE", "DEV-REPLAY", "DEV-MATRIX", "DEV-IMPACT", "DEV-AUDIT"):
            key = f"command/{rule}/COMMAND-ASSURANCE/linux-amd64-cgo/full-rule"
            self.assertTrue(baseline[key]["aggregate"])
            self.assertEqual(baseline[key]["checks"], [])
            self.assertEqual(baseline[key]["requires"], prerequisites)
            baseline[key].pop("aggregate")
            baseline[key].pop("requires")
            baseline[key]["checks"] = ["command-qualification"]
        compatibility = "command/DEV-COMPAT/COMMAND-ASSURANCE/linux-amd64-cgo/full-rule"
        self.assertEqual(baseline[compatibility]["checks"], ["command-boundaries", "command-structure-race"])
        self.assertEqual(baseline[compatibility]["requires"], prerequisites)
        self.assertNotIn("aggregate", baseline[compatibility])
        baseline[compatibility].pop("requires")
        baseline[compatibility]["checks"] = ["command-qualification"]
        checks = v.unique(original["checks"])
        self.assertEqual({key for key, item in obligations.items() if "comet-core-model" in item["checks"]}, set())
        self.assertEqual(checks["tools-windows-mutation-boundaries"]["adapter"], "observed-cases")
        self.assertEqual(
            {probe["contract"] for probe in checks["tools-windows-mutation-boundaries"]["probes"]}, {"TOOLS_PYTHON-18", "TOOLS_PYTHON-62", "TOOLS-WINDOWS-ENV"}
        )
        self.assertEqual(checks["tools-windows-linux-boundaries"]["adapter"], "observed-cases")
        self.assertEqual(
            {probe["contract"] for probe in checks["tools-windows-linux-boundaries"]["probes"]}, {f"TOOLS_PYTHON-{number}" for number in (45, 46, 47, 48)}
        )
        # Freeze all original objects, rather than permitting one removal to conceal an unrelated addition.
        lifecycle = {
            key: item
            for key, item in baseline.items()
            if item["component"] == "admission" and item["scenario"] == "full-rule" and item["rule"] in {"DEV-ASYNC", "DEV-TIME", "DEV-RETRY", "DEV-STOP"}
        }
        self.assertEqual(len(lifecycle), 4)
        self.assertEqual(v.digest(v.encode(lifecycle)), "d80320919e2e4284b532c7cabbb6dac27447e8dc4cf5ee107e9b48a18ad8de33")
        for item in lifecycle.values():
            self.assertEqual(item.pop("aggregate"), True)
            self.assertTrue(item.pop("requires"))
            self.assertEqual(item["checks"], [])
            item["checks"] = ["admission-gap-" + item["rule"][4:].lower()]
        composed = {
            key: item
            for key, item in baseline.items()
            if item["component"] != "command"
            and item["scenario"] == "full-rule"
            and item["rule"] in {"DEV-COVERAGE", "DEV-FAULT", "DEV-MATRIX"}
            and item.get("aggregate")
        }
        self.assertEqual(len(composed), 46)
        # Pin the entire reviewed conjunction graph before normalizing its old placeholder executors.
        self.assertEqual(v.digest(v.encode(composed)), "996f31208da6dc69e99cac6be714b30ab7f6c26692f3d0f4a11d9917e6f3aed2")
        for item in composed.values():
            self.assertEqual(item.pop("aggregate"), True)
            self.assertTrue(item.pop("requires"))
            self.assertEqual(item["checks"], [])
            if item["component"] in {"polaris-storage", "admission"}:
                prefix = "admission-" if item["component"] == "admission" else ""
                item["checks"] = [prefix + "gap-" + item["rule"][4:].lower()]
            else:
                item["checks"] = [item["component"] + "-qualification"]
        self.assertEqual(v.digest(v.encode(baseline)), "f69ee35f47ca9001bdecb12baf0fa6d66cc839951923b8404499dd946306f827")
        for key in added:
            item = obligations[key]
            self.assertEqual(item["checks"], ["tools-python" if item["platform"] == "linux-amd64-cgo" else "tools-windows"])
        wal = "polaris-storage/DEV-FAULT/STORAGE-BOUNDARY/linux-amd64-cgo/native-wal-write-sync"
        self.assertEqual(obligations[wal]["checks"], ["storage-io"])
        self.assertEqual(obligations["polaris-storage/DEV-COVERAGE/STORAGE-ASSURANCE/linux-amd64-cgo/structure"]["checks"], ["storage-structure"])
        self.assertEqual(obligations["polaris-storage/DEV-COVERAGE/STORAGE-ASSURANCE/linux-amd64-cgo/mcdc"]["checks"], ["storage-independence"])
        command_proofs = {key for key, item in obligations.items() if item["contract"].startswith(("COMMAND-NUMERIC", "COMMAND-MODEL"))}
        self.assertEqual(
            command_proofs,
            {
                "command/DEV-NUMERIC/COMMAND-NUMERIC/linux-amd64-cgo/typed-source",
                "command/DEV-ORACLE/COMMAND-NUMERIC-CONTROLS/linux-amd64-cgo/typed-controls",
                "command/DEV-MODEL/COMMAND-MODEL/linux-amd64-cgo/finite-history",
                "command/DEV-ORACLE/COMMAND-MODEL-CONTROLS/linux-amd64-cgo/model-vectors",
            },
        )
        logs = {key for key, item in obligations.items() if item["contract"].startswith("PULSAR-LOG-")}
        self.assertEqual(
            logs,
            {
                f"tools/DEV-EVIDENCE/PULSAR-LOG-{name}/{platform}/native-oracle"
                for name in ("SUCCESS", "FAILURE", "COLLECTION", "PRIMARY")
                for platform in ("linux-amd64-cgo", "windows-amd64")
            },
        )
        typed = {key for key, value in obligations.items() if value["contract"] in {"GO-LOGIC-TYPING", "GO-LOGIC-TYPE-INTEGRITY", "GO-LOGIC-TYPE-BUNDLE"}}
        self.assertEqual(
            typed,
            {
                f"verification/DEV-EVIDENCE/{name}/linux-amd64-cgo/native-oracle"
                for name in ("GO-LOGIC-TYPING", "GO-LOGIC-TYPE-INTEGRITY", "GO-LOGIC-TYPE-BUNDLE")
            },
        )
        nodes = {key for key, value in obligations.items() if value["contract"].startswith("ADMISSION-NODE-")}
        self.assertEqual(
            nodes,
            {
                f"admission/{rule}/ADMISSION-NODE-{name}/linux-amd64-cgo/{scenario}"
                for name, rule, scenario in (
                    ("OPEN", "DEV-CONTRACT", "construction"),
                    ("STATE", "DEV-ASYNC", "message-ownership"),
                    ("REGISTER", "DEV-RETRY", "registration-receipts"),
                    ("REFRESH", "DEV-CONTRACT", "refresh-receipts"),
                    ("SCHEDULE", "DEV-ASYNC", "admission-overlap"),
                    ("RETRY", "DEV-RETRY", "registration-step-time"),
                    ("RUN", "DEV-TIME", "refresh-step-time"),
                    ("PAUSE", "DEV-TIME", "native-timer"),
                    ("TRANSPORT", "DEV-MATRIX", "tls-generated-rpc"),
                    ("SENSITIVITY", "DEV-ORACLE", "targeted-mutations"),
                    ("RESOLVER", "DEV-FAULT", "client-construction"),
                    ("FINITE", "DEV-MODEL", "loop-state-domain"),
                    ("TRANSITIONS", "DEV-MODEL", "publication-state-domain"),
                    ("DRAIN", "DEV-ASYNC", "native-cancellation"),
                )
            },
        )
        boundaries = {
            key
            for key, value in obligations.items()
            if value["contract"] in {"ADMISSION-DIRECTORY-BOUNDARIES", "ADMISSION-IDENTITY-RULES", "ADMISSION-IDENTITY-FILES", "ADMISSION-IDENTITY-FAULT"}
        }
        self.assertEqual(
            boundaries,
            {
                "admission/DEV-CONTRACT/ADMISSION-DIRECTORY-BOUNDARIES/linux-amd64-cgo/directory-boundaries",
                "admission/DEV-SECURITY/ADMISSION-IDENTITY-RULES/linux-amd64-cgo/identity-inputs",
                "admission/DEV-FAULT/ADMISSION-IDENTITY-FILES/linux-amd64-cgo/native-identity-files",
                "admission/DEV-FAULT/ADMISSION-IDENTITY-FAULT/linux-amd64-cgo/file-response-matrix",
            },
        )
        material = {key for key, value in obligations.items() if value["contract"].startswith("GO-MATERIAL-")}
        self.assertEqual(
            material,
            {
                f"verification/{rule}/GO-MATERIAL-{name}/linux-amd64-cgo/native-oracle"
                for name, rule in (
                    ("CONFIG", "DEV-GATE"),
                    ("AXIOMS", "DEV-ORACLE"),
                    ("MATRIX", "DEV-ORACLE"),
                    ("STREAM", "DEV-EVIDENCE"),
                    ("SOURCE", "DEV-EVIDENCE"),
                )
            },
        )
        equality = {
            key
            for key, value in obligations.items()
            if value["contract"].startswith("GO-EQUALITY-") or value["contract"] in {"ADMISSION-SAME", "ADMISSION-SAME-SENSITIVITY"}
        }
        self.assertEqual(
            equality,
            {
                "admission/DEV-COVERAGE/ADMISSION-SAME/linux-amd64-cgo/member-equality",
                "admission/DEV-ORACLE/ADMISSION-SAME-SENSITIVITY/linux-amd64-cgo/member-equality-mutations",
                *{
                    f"verification/{rule}/GO-EQUALITY-{name}/linux-amd64-cgo/native-oracle"
                    for name, rule in (
                        ("CONFIG", "DEV-GATE"),
                        ("AXIOMS", "DEV-ORACLE"),
                        ("PAIRS", "DEV-ORACLE"),
                        ("STREAM", "DEV-EVIDENCE"),
                        ("SOURCE", "DEV-EVIDENCE"),
                    )
                },
            },
        )
        conflicts = {
            key for key, value in obligations.items() if value["contract"] in {"ADMISSION-CONFLICTS", "ADMISSION-CREDENTIALS", "ADMISSION-CONFLICT-SENSITIVITY"}
        }
        self.assertEqual(
            conflicts,
            {
                "admission/DEV-CONTRACT/ADMISSION-CONFLICTS/linux-amd64-cgo/identity-conflicts",
                "admission/DEV-SECURITY/ADMISSION-CREDENTIALS/linux-amd64-cgo/signed-boundaries",
                "admission/DEV-ORACLE/ADMISSION-CONFLICT-SENSITIVITY/linux-amd64-cgo/directory-boundary-mutations",
            },
        )
        loops = {key for key, value in obligations.items() if value["contract"] == "ADMISSION-LOOP-SENSITIVITY"}
        self.assertEqual(loops, {"admission/DEV-ORACLE/ADMISSION-LOOP-SENSITIVITY/linux-amd64-cgo/node-loop-mutations"})
        models = {key for key, value in obligations.items() if value["contract"].startswith("GO-ADMISSION-MODEL-")}
        self.assertEqual(
            models,
            {
                f"verification/{rule}/GO-ADMISSION-MODEL-{name}/linux-amd64-cgo/native-oracle"
                for name, rule in (
                    ("CONFIG", "DEV-GATE"),
                    ("AXIOMS", "DEV-ORACLE"),
                    ("DOMAIN", "DEV-ORACLE"),
                    ("HISTORIES", "DEV-ORACLE"),
                    ("STREAM", "DEV-EVIDENCE"),
                    ("SOURCE", "DEV-EVIDENCE"),
                    ("GATE", "DEV-GATE"),
                )
            },
        )
        predicates = {
            key
            for key, value in obligations.items()
            if value["contract"].startswith("GO-PREDICATES-") or value["contract"] in {"ADMISSION-PREDICATES", "ADMISSION-PREDICATE-SENSITIVITY"}
        }
        self.assertEqual(
            predicates,
            {
                "admission/DEV-COVERAGE/ADMISSION-PREDICATES/linux-amd64-cgo/identity-format-pairs",
                "admission/DEV-ORACLE/ADMISSION-PREDICATE-SENSITIVITY/linux-amd64-cgo/identity-format-mutations",
                *{
                    f"verification/{rule}/GO-PREDICATES-{name}/linux-amd64-cgo/native-oracle"
                    for name, rule in (
                        ("CONFIG", "DEV-GATE"),
                        ("AXIOMS", "DEV-ORACLE"),
                        ("PAIRS", "DEV-ORACLE"),
                        ("STREAM", "DEV-EVIDENCE"),
                        ("SOURCE", "DEV-EVIDENCE"),
                    )
                },
            },
        )
        numeric = {
            key
            for key, value in obligations.items()
            if value["contract"].startswith("GO-NUMERIC-")
            or value["contract"].startswith("GATE-AGGREGATE")
            or value["contract"] in {"ADMISSION-NUMERIC", "ADMISSION-NUMERIC-SENSITIVITY"}
        }
        self.assertEqual(
            numeric,
            {
                "admission/DEV-NUMERIC/ADMISSION-NUMERIC/linux-amd64-cgo/integer-boundaries",
                "admission/DEV-ORACLE/ADMISSION-NUMERIC-SENSITIVITY/linux-amd64-cgo/integer-mutations",
                *{
                    f"verification/{rule}/GO-NUMERIC-{name}/linux-amd64-cgo/native-oracle"
                    for name, rule in (
                        ("CONFIGURATION", "DEV-GATE"),
                        ("AXIOMS", "DEV-ORACLE"),
                        ("WITNESSES", "DEV-ORACLE"),
                        ("STREAM", "DEV-EVIDENCE"),
                        ("SOURCE", "DEV-EVIDENCE"),
                        ("GATE", "DEV-GATE"),
                    )
                },
                *{f"verification/DEV-GATE/GATE-{name}/linux-amd64-cgo/native-oracle" for name in ("AGGREGATE", "AGGREGATE-SHAPE", "AGGREGATE-SCHEMA")},
            },
        )
        draining = {
            key for key, value in obligations.items() if value["contract"] in {"ADMISSION-NODE-DRAIN", "ADMISSION-DRAIN-SENSITIVITY", "GO-ADMISSION-FULL"}
        }
        self.assertEqual(
            draining,
            {
                "admission/DEV-ASYNC/ADMISSION-NODE-DRAIN/linux-amd64-cgo/native-cancellation",
                "admission/DEV-ORACLE/ADMISSION-DRAIN-SENSITIVITY/linux-amd64-cgo/cancellation-mutations",
                "verification/DEV-GATE/GO-ADMISSION-FULL/linux-amd64-cgo/native-oracle",
            },
        )
        isolation = {key for key, value in obligations.items() if value["contract"] == "COMMAND-ISOLATION"}
        self.assertEqual(isolation, {"command/DEV-CORE/COMMAND-ISOLATION/linux-amd64-cgo/effect-boundary"})
        self.assertEqual(
            len(
                set(obligations)
                - typed
                - nodes
                - boundaries
                - material
                - equality
                - conflicts
                - loops
                - models
                - predicates
                - numeric
                - draining
                - logs
                - isolation
                - command_proofs
                - added
                - native
                - consumers
                - pagination
                - page_fault
                - dispatch_fault
                - catalog_rpc
                - authentication
                - windows
                - {drain}
                - {wal}
                - {entry, metrics}
                - set(supplements["added"])
                - set(qualification["added"])
            ),
            1012,
        )
        item = obligations["command/DEV-COVERAGE/COMMAND-ASSURANCE/linux-amd64-cgo/structure"]
        self.assertEqual(item["checks"], ["command-boundaries", "command-structure-race"])
        for name in item["checks"]:
            configured = next(check for check in original["checks"] if check["id"] == name)
            statements.configuration(configured)
        other = obligations["command/DEV-FAULT/COMMAND-ASSURANCE/linux-amd64-cgo/fault-matrix"]
        self.assertEqual(other["checks"], ["command-boundaries", "command-structure-race"])


class LedgerTests(unittest.TestCase):
    """Independently enumerate a small truth table and refuse to convert missing evidence into infeasibility."""

    def setUp(self) -> None:
        """Use synthetic validated trees, with one AND, one conditional defense and one literal return."""
        self.decisions = {
            "and": {
                "kind": "if",
                "text": "left && right",
                "atoms": [{"text": "left"}, {"text": "right"}],
                "tree": [{"kind": "atom", "atom": 0}, {"kind": "atom", "atom": 1}, {"kind": "and", "children": [0, 1]}],
            },
            "error": {"kind": "if", "text": "error", "atoms": [{"text": "error"}], "tree": [{"kind": "atom", "atom": 0}]},
            "literal": {"kind": "return", "text": "true", "atoms": [{"text": "true"}], "tree": [{"kind": "atom", "atom": 0}]},
        }
        self.rows = {"and": {("10", False): 1, ("21", False): 1, ("22", True): 1}, "error": {("1", False): 1}, "literal": {("2", True): 1}}
        self.assumptions = (("error", 0, True, "synthetic-contract"),)

    def test_ledger(self) -> None:
        """Both raw denominators remain visible and only explicit impossible outcomes leave the qualified ones."""
        result = structure.boolean(self.decisions, self.rows, self.assumptions)
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["totals"]["roots"], {"raw": 6, "observed": 4, "literal_impossible": 1, "conditional": 1, "reachable_under_assumptions": 4})
        self.assertEqual(result["totals"]["atoms"], {"raw": 8, "observed": 6, "literal_impossible": 1, "conditional": 1, "reachable_under_assumptions": 6})
        self.assertEqual(result["roots"][1]["conditional"], [{"outcome": True, "reason": "synthetic-contract"}])
        self.assertEqual(result["roots"][2]["literal_impossible"], [False])

    def test_missing(self) -> None:
        """A missed operand is a gap even while its containing AND has both final outcomes."""
        self.rows["and"].pop(("21", False))
        result = structure.boolean(self.decisions, self.rows, self.assumptions)
        self.assertEqual(result["roots"][0]["missing"], [])
        self.assertEqual(result["missing"], [{"id": "and", "atom": 1, "outcomes": [False]}])
        self.rows["error"] = {}
        result = structure.boolean(self.decisions, self.rows, self.assumptions)
        self.assertIn({"id": "error", "atom": None, "outcomes": [False]}, result["missing"])
        self.assertIn({"id": "error", "atom": 0, "outcomes": [False]}, result["missing"])

    def test_assumptions(self) -> None:
        """Unknown, duplicated or type-forged coordinates cannot create blanket exclusions."""
        for assumption in (("absent", 0, True, "x"), ("and", 2, True, "x"), ("and", True, True, "x"), ("and", 0, 1, "x")):
            with self.assertRaisesRegex(v.Invalid, "structure-assumption-domain"):
                structure.boolean(self.decisions, self.rows, (assumption,))
        with self.assertRaisesRegex(v.Invalid, "structure-assumption-domain"):
            structure.boolean(self.decisions, self.rows, self.assumptions * 2)
        result = structure.boolean(self.decisions, self.rows, ())
        self.assertEqual(result["totals"]["roots"]["conditional"], 0)
        self.assertIn({"id": "error", "atom": None, "outcomes": [True]}, result["missing"])

    def test_contradiction(self) -> None:
        """An observed excluded outcome invalidates the assumption rather than improving the coverage ratio."""
        for identity, row in (("error", ("2", True)), ("literal", ("1", False))):
            rows = copy.deepcopy(self.rows)
            rows[identity][row] = 1
            with self.assertRaisesRegex(v.Invalid, "structure-assumption-contradicted"):
                structure.boolean(self.decisions, rows, self.assumptions)

    def test_negation(self) -> None:
        """Do not transfer an atom's conditional exclusion to an opposite root through a negation."""
        self.decisions["error"]["tree"].append({"kind": "not", "children": [0]})
        self.rows["error"] = {("1", True): 1}
        result = structure.boolean(self.decisions, self.rows, self.assumptions)
        self.assertEqual(result["roots"][1]["conditional"], [])
        self.assertEqual(result["roots"][1]["missing"], [False])
        self.assertEqual(result["atoms"][2]["conditional"], [{"outcome": True, "reason": "synthetic-contract"}])

    def test_no_literal_guess(self) -> None:
        """A guard with a constant spelling does not inherit the explicit literal-return classification."""
        self.decisions["literal"]["kind"] = "if"
        result = structure.boolean(self.decisions, self.rows, self.assumptions)
        self.assertEqual(result["totals"]["roots"]["literal_impossible"], 0)
        self.assertEqual(result["roots"][2]["missing"], [False])

    def test_controls(self) -> None:
        """Count finite entry/exhaustion and selected arms without inventing exits for unconditional loops."""
        report = {
            "edges": [
                {"id": "range", "kind": "range", "vectors": {"22": 1}},
                {"id": "for", "kind": "for", "vectors": {"12": 1, "21": 1}},
                {"id": "loop", "kind": "loop", "vectors": {"21": 1}},
                {"id": "arm", "kind": "select-arm", "vectors": {"2": 1}},
            ],
            "without_empty": ["range"],
        }
        result = structure.controls(report)
        self.assertEqual(result["required"], 6)
        self.assertEqual(result["observed"], 6)
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["without_empty"], ["range"])
        self.assertEqual(result["items"][2]["required"], ["body"])
        report["edges"][0]["vectors"] = {"21": 1}
        report["edges"][1]["vectors"] = {"12": 1}
        report["edges"][3]["vectors"] = {}
        result = structure.controls(report)
        self.assertEqual(result["required"], 6)
        self.assertEqual(result["observed"], 3)
        self.assertEqual(
            result["missing"], [{"id": "range", "outcomes": ["exhausted"]}, {"id": "for", "outcomes": ["body"]}, {"id": "arm", "outcomes": ["selected"]}]
        )


class AdapterTests(unittest.TestCase):
    """Challenge the structural gate's provenance and failure boundaries using explicitly synthetic facts."""

    def setUp(self) -> None:
        """Read the real frozen policy; temporary records exercise parsing only and never execute Go."""
        self.config = v.decode(v.read(ROOT / "development.json"))
        self.check = next(item for item in self.config["checks"] if item["id"] == "admission-structure")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.run = self.root / "build/run"
        self.directory = self.run / "structure"
        self.directory.mkdir(parents=True)
        for name in {**admission.SOURCES, **admission.MATERIAL}:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes())

    def test_configuration(self) -> None:
        """A reduced hit denominator, mixed platform or filtered command cannot retain this adapter's identity."""
        structure.configuration(self.check)
        archived = copy.deepcopy(self.check)
        archived["probes"][0]["minimum_hits"] = 818
        structure.configuration(archived)
        self.assertEqual(structure.revision(self.root, structure.PACKAGE)["counts"], [286, 158, 357, 28])
        self.assertEqual(structure.domain()["counts"], [279, 156, 355, 28])
        with self.assertRaisesRegex(v.Invalid, "structure-source-revision"):
            structure.domain(legacy=True, acquisition=True)
        model = next(item for item in self.config["checks"] if item["id"] == "admission-model")
        self.assertEqual(self.check["native_tests"], model["expected_tests"])
        for key, value in (
            ("argv", self.check["argv"] + ["--race"]),
            ("component", "other"),
            ("platforms", ["windows"]),
            ("expected_tests", ["other"]),
            ("native_tests", []),
            ("native_tests", ["TestOne", "TestOne"]),
            ("native_tests", [True]),
            ("probes", [dict(self.check["probes"][0], minimum_hits=813)]),
        ):
            changed = copy.deepcopy(self.check)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(v.Invalid):
                structure.configuration(changed)
        for key, value in (("GOFLAGS", "-race"), ("GOPROXY", "direct"), ("TMPDIR", "{root}/build/tmp"), ("GOARCH", "arm64")):
            changed = copy.deepcopy(self.check)
            changed["environment"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(v.Invalid, "structure-environment"):
                structure.configuration(changed)
        storage = next(c for c in self.config["checks"] if c["id"] == "storage-structure")
        structure.configuration(storage)
        self.assertEqual(
            storage["native_tests"], sorted(v.decode(v.read(ROOT / "tests/fixtures/storage.tests.json")) + list(idle.CASES) + list(idle.BACKUP_CASES))
        )
        examples = next(c for c in self.config["checks"] if c["id"] == "storage-examples")
        self.assertEqual(examples["expected_tests"], storage["native_tests"])
        historical = {**storage, "native_tests": sorted(v.decode(v.read(ROOT / "tests/fixtures/storage.tests.json")) + list(idle.CASES))}
        structure.configuration(historical)
        for field, value in (
            ("component", "admission"),
            ("argv", self.check["argv"]),
            ("adapter", "other-structure"),
            ("probes", [{**storage["probes"][0], "minimum_hits": 1480}]),
        ):
            with self.subTest(storage=field), self.assertRaises(v.Invalid):
                structure.configuration({**storage, field: value})
        changed = copy.deepcopy(self.config)
        next(c for c in changed["checks"] if c["id"] == "storage-structure")["native_tests"].pop()
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "development.json"
            path.write_bytes(v.encode(changed))
            with self.assertRaisesRegex(v.Invalid, "structure-native-inventory-policy"):
                v.configuration(path, ROOT)
        for missing in ("TestOnlineBackup", "TestBackupRestore", "TestAtomicity"):
            changed = copy.deepcopy(self.config)
            current = next(c for c in changed["checks"] if c["id"] == "storage-examples")
            self.assertIn(missing, current["expected_tests"])
            current["expected_tests"].remove(missing)
            current["probes"] = [probe for probe in current["probes"] if probe["test"] != missing]
            with tempfile.TemporaryDirectory() as name:
                path = Path(name) / "development.json"
                path.write_bytes(v.encode(changed))
                with self.subTest(missing=missing), self.assertRaisesRegex(v.Invalid, "structure-native-inventory-policy"):
                    v.configuration(path, ROOT)
        changed = copy.deepcopy(self.config)
        next(c for c in changed["checks"] if c["id"] == "storage-examples")["expected_tests"].append("TestFabricatedBackup")
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "development.json"
            path.write_bytes(v.encode(changed))
            with self.assertRaisesRegex(v.Invalid, "structure-native-inventory-policy"):
                v.configuration(path, ROOT)

    def test_schema(self) -> None:
        """Unknown native-test fields and evidence artifacts remain outside the closed schemas."""
        v.schema(self.config, "development")
        for change in (lambda c: c.update(native_tests=None), lambda c: c.update(native_tests=[1]), lambda c: c.update(native_test=[])):
            changed = copy.deepcopy(self.config)
            change(next(item for item in changed["checks"] if item["id"] == self.check["id"]))
            with self.assertRaisesRegex(v.Invalid, "schema-invalid"):
                v.schema(changed, "development")
        changed = copy.deepcopy(self.config)
        next(c for c in changed["checks"] if c["id"] == "storage-structure")["adapter"] = "future-structure"
        with self.assertRaisesRegex(v.Invalid, "schema-invalid"):
            v.schema(changed, "development")

    def test_plan(self) -> None:
        """All eight native commands are fixed before observations, with whole-package ordinary test selections."""
        plan = structure.plan(self.directory)
        self.assertEqual(
            [name for name, _, _ in plan],
            ["coverage", "typed/exports", "typed/collector", "typed/packages", "typed/tests", "control/collector", "control/packages", "control/tests"],
        )
        self.assertEqual(sum(arguments[:2] == ["go", "test"] for _, arguments, _ in plan), 3)
        for name, arguments, timeout in plan:
            self.assertLessEqual(timeout, 240)
            self.assertFalse(any(arg.startswith(("-run", "-race", "-skip", "-short", "-shuffle")) for arg in arguments))
            if arguments[:2] == ["go", "test"]:
                self.assertIn("-count=1", arguments)
                self.assertEqual(arguments[-1], "./internal/admission")
        self.assertIn(str(self.directory / "typed/exports/exports.stdout.log"), plan[2][1])
        storage = structure.plan(self.directory, package=structure.STORAGE)
        self.assertEqual([p[0] for p in storage], [p[0] for p in plan])
        for name, arguments, _ in storage:
            if arguments[:2] == ["go", "test"]:
                self.assertEqual(arguments[-1], "./polaris/internal/storage")
            if name.endswith("/collector"):
                self.assertEqual(arguments[arguments.index("-trace") + 1], structure.STORAGE)
        with self.assertRaisesRegex(v.Invalid, "structure-package"):
            structure.plan(self.directory, package="polaris/internal/storage/../other")
        environment = {"GOMODCACHE": str(self.root / "cache")}
        go = self.root / "go/bin/go"
        dependencies = structure.dependency_paths(go, environment, package=structure.STORAGE)
        self.assertEqual(dependencies["sqlite/sqlite3.go"], self.root / "cache/github.com/mattn/go-sqlite3@v1.14.52/sqlite3.go")
        self.assertEqual(dependencies["database/sql/sql.go"], self.root / "go/src/database/sql/sql.go")

    def test_limits(self) -> None:
        """A declared budget without finite host capacity, free memory or disk is not executable qualification."""
        limits = {
            "cpu_quota": 400000,
            "cpu_period": 100000,
            "memory_bytes": 2 * 1024**3,
            "tasks": 512,
            "available_bytes": 1536 * 1024**2,
            "disk_free_bytes": 8 * 1024**3,
        }
        structure.bounded(limits)
        for key, value in (
            ("cpu_quota", "max"),
            ("cpu_period", 0),
            ("cpu_quota", 1600000),
            ("cpu_quota", 100000),
            ("memory_bytes", 8 * 1024**3),
            ("available_bytes", 1),
            ("disk_free_bytes", 1),
            ("tasks", True),
        ):
            with self.subTest(key=key), self.assertRaises(v.Invalid):
                structure.bounded({**limits, key: value})
        with self.assertRaises(v.Invalid):
            structure.bounded({**limits, "note": "bounded"})

    def events(self, output: str = "", test: str = "TestNodeOpen") -> bytes:
        """Encode a complete single-test native-shaped stream with no claim of compiler execution."""
        return b"".join(
            (json.dumps({"Package": "github.com/eosforge/astra/internal/admission", **event}) + "\n").encode()
            for event in (
                {"Action": "start"},
                {"Action": "run", "Test": test},
                {"Action": "output", "Test": test, "Output": output},
                {"Action": "pass", "Test": test},
                {"Action": "pass"},
            )
        )

    def test_resolver(self) -> None:
        """An omitted, duplicated, malformed or foreign-test child profile is never filled in by the parent."""
        payload = b"mode: atomic\nsynthetic\n"
        line = "ADMISSION-RESOLVER-PROFILE " + base64.b64encode(payload).decode() + "\n"
        raw = self.events(line)
        self.assertEqual(structure.resolver(raw), payload)
        structure.terminals(raw, ["TestNodeOpen"])
        for data in (self.events(), self.events(line * 2), self.events(line, "TestOther"), self.events("ADMISSION-RESOLVER-PROFILE !\n")):
            with self.assertRaises(v.Invalid):
                structure.resolver(data)
        for data, tests in (
            (raw, ["TestOther"]),
            (raw, ["TestNodeOpen", "TestOther"]),
            (b"\n".join(raw.splitlines()[:-1]), ["TestNodeOpen"]),
            (raw.replace(b'"pass"', b'"skip"', 1), ["TestNodeOpen"]),
        ):
            with self.assertRaises(v.Invalid):
                structure.terminals(data, tests)
        cases = v.decode(v.read(ROOT / "tests/fixtures/storage.tests.json"))
        storage = next(c for c in self.config["checks"] if c["id"] == "storage-structure")

        def events(names: list[str]) -> bytes:
            """Build parser-only terminals; replacing one descendant must fail even if the total stays constant."""
            rows = [{"Action": "start"}]
            for name in names:
                rows.extend([{"Action": "run", "Test": name}, {"Action": "pass", "Test": name}])
            rows.append({"Action": "pass"})
            return b"".join((json.dumps({"Package": "github.com/eosforge/astra/" + structure.STORAGE, **row}) + "\n").encode() for row in rows)

        # Historical terminals remain valid only for their own declaration; current maintenance requires every added case.
        structure.terminals(events(cases), cases, package=structure.STORAGE)
        current = storage["native_tests"]
        self.assertEqual(set(current), set(cases) | set(idle.CASES) | set(idle.BACKUP_CASES))
        self.assertEqual(len(current), 259)
        structure.terminals(events(current), current, package=structure.STORAGE)
        omitted = [name for name in current if name != "TestCursorCompletion/result-set-control"]
        for names in (cases, omitted, omitted + ["TestCursorCompletion/fabricated"]):
            with self.assertRaisesRegex(v.Invalid, "structure-test-selection"):
                structure.terminals(events(names), storage["native_tests"], package=structure.STORAGE)

    def record(self) -> tuple[dict, dict, dict, dict]:
        """Create original-shaped native facts with real hashable files but no subprocess execution."""
        parent = self.directory / "coverage"
        parent.mkdir()
        tools = {}
        for name in ("go", "cc", "cxx"):
            path = self.root / name
            path.write_bytes(b"synthetic executable identity: " + name.encode())
            tools[name] = str(path)
        environment = {"PATH": str(self.root), "HOME": str(self.root), "LANG": "C.UTF-8", "CC": tools["cc"], "CXX": tools["cxx"]}
        child = {**environment, "TMPDIR": str(parent / "tmp"), "ASTRA_TEST_LOG_DIR": str(parent / "logs")}
        arguments = structure.plan(self.directory)[0][1]
        record = {
            "id": "coverage",
            "platform": structure.PLATFORM,
            "argv": arguments,
            "environment": child,
            "resolved_environment": child,
            "executable": tools["go"],
            "executable_sha256": v.file_digest(tools["go"]),
            "duration_ms": 1,
            "exit_code": 0,
            "termination": "exited",
            "complete": True,
            "cleanup": True,
            "started_at": "2026-10-04T00:00:00Z",
            "finished_at": "2026-10-04T00:00:01Z",
            "stdout": v.write_new(parent / "out.log", self.events()),
            "stderr": v.write_new(parent / "err.log", b""),
            "toolchain": {key: {"path": tools[name], "sha256": v.file_digest(tools[name])} for key, name in (("command", "go"), ("CC", "cc"), ("CXX", "cxx"))},
        }
        process = {
            "identity": {"pid": 10, "start_ticks": "99", "parent": 9, "session": 10, "state": "S"},
            "boot_id": "12345678-1234-1234-1234-123456789012",
            "argv": arguments,
            "cwd": str(self.root),
        }
        v.write_new(parent / "record.json", record)
        v.write_new(parent / "coverage.process.json", process)
        return environment, tools, record, process

    def test_native(self) -> None:
        """Reject forged success, narrowed commands, cache/platform changes, missing cleanup and source-tool drift."""
        environment, tools, record, process = self.record()
        arguments = record["argv"]
        parent = self.directory / "coverage"
        with patch.object(structure.shutil, "which", side_effect=lambda name, **_: tools["go"] if name == "go" else name):
            actual, data = structure.native(self.directory, self.root, "coverage", arguments, 240, environment)
            self.assertEqual(actual, record)
            self.assertEqual(data, self.events())
            for field, value in (
                ("exit_code", 1),
                ("exit_code", True),
                ("complete", False),
                ("cleanup", False),
                ("termination", "log-limit"),
                ("platform", "other"),
                ("argv", arguments + ["-run=TestOne"]),
                ("executable_sha256", "0" * 64),
                ("duration_ms", 240001),
                ("resolved_environment", {**record["resolved_environment"], "GOFLAGS": "-race"}),
            ):
                (parent / "record.json").write_bytes(v.encode({**record, field: value}))
                with self.subTest(field=field), self.assertRaises(v.Invalid):
                    structure.native(self.directory, self.root, "coverage", arguments, 240, environment)
            (parent / "record.json").write_bytes(v.encode(record))
            for field, value in (
                ("cwd", str(self.directory)),
                ("boot_id", "x" * 36),
                ("identity", {**process["identity"], "start_ticks": True}),
                ("identity", {**process["identity"], "pid": 0}),
                ("argv", arguments[:-1]),
            ):
                (parent / "coverage.process.json").write_bytes(v.encode({**process, field: value}))
                with self.subTest(field=field), self.assertRaises(v.Invalid):
                    structure.native(self.directory, self.root, "coverage", arguments, 240, environment)
            (parent / "coverage.process.json").write_bytes(v.encode(process))
            (parent / "out.log").write_bytes(b"changed")
            with self.assertRaisesRegex(v.Invalid, "artifact-integrity"):
                structure.native(self.directory, self.root, "coverage", arguments, 240, environment)

    def test_reference(self) -> None:
        """A summary cannot replace the mandatory artifact, and foreign checks cannot smuggle a structural record."""
        path = self.directory / "bundle.json"
        path.write_bytes(b"{}\n")
        record = {"structure": structure.artifact(self.run, path)}
        self.assertEqual(v.coverage(self.run, record, self.check), {"directory": self.run, "record": record})
        for changed in (
            {},
            {**record, "resolved_argv": []},
            {"structure": {**record["structure"], "path": "other.json"}},
            {"structure": {**record["structure"], "bytes": True}},
            {"structure": {**record["structure"], "sha256": "0" * 64}},
        ):
            with self.assertRaises(v.Invalid):
                v.coverage(self.run, changed, self.check)
        with self.assertRaisesRegex(v.Invalid, "unexpected-structure-record"):
            v.coverage(self.run, record, check())
        path.unlink()
        with self.assertRaisesRegex(v.Invalid, "structure-artifact-unreadable"):
            v.coverage(self.run, record, self.check)

    def test_gate(self) -> None:
        """Exercise real adapter dispatch/decision logic; the substituted ledger is explicitly parser-only data."""
        path = self.directory / "bundle.json"
        path.write_bytes(b"{}\n")
        record = {"structure": structure.artifact(self.run, path)}
        evidence = v.coverage(self.run, record, self.check)
        receipt = {"bundle_sha256": v.file_digest(path), "source_sha256": "1" * 64}
        ledger = {
            "status": "complete-under-assumptions",
            "source_sha256": "1" * 64,
            "statements": {"reachable_under_assumptions": {"statements_hit": 286}},
            "boolean": {"totals": {"roots": {"observed": 158}, "atoms": {"observed": 357}}},
            "controls": {"observed": 28},
        }
        key = "admission/DEV-COVERAGE/ADMISSION-ASSURANCE/linux-amd64-cgo/structure"
        now = dt.datetime.now(dt.timezone.utc)
        with patch.object(structure, "load", return_value=ledger) as loader:
            hits, failures = v.parse_observations(v.encode(receipt), self.check, self.root, evidence)
            self.assertEqual(hits, {"ADMISSION-ASSURANCE": 829})
            self.assertEqual(failures, [])
            loader.assert_called_once_with(self.directory, self.root, self.check, record)
            gate = v.decide(self.config, {(self.check["id"], structure.PLATFORM, "ADMISSION-ASSURANCE"): "passed"}, [], [], now)
            self.assertIn(key, gate["passed"])
            self.assertEqual(gate["status"], "blocked")
            self.assertIn(key.replace("/structure", "/mcdc"), gate["missing"])
            ledger["status"] = "incomplete"
            self.assertEqual(v.parse_observations(v.encode(receipt), self.check, self.root, evidence), ({}, ["structure-uncovered"]))
            ledger["status"] = "complete-under-assumptions"
            ledger["controls"]["observed"] -= 1
            with self.assertRaisesRegex(v.Invalid, "structure-denominator-drift"):
                v.parse_observations(v.encode(receipt), self.check, self.root, evidence)
        for forged in ({**receipt, "bundle_sha256": "2" * 64}, {**receipt, "status": "passed"}):
            with patch.object(structure, "load") as loader, self.assertRaises(v.Invalid):
                v.parse_observations(v.encode(forged), self.check, self.root, evidence)
            loader.assert_not_called()
        with self.assertRaisesRegex(v.Invalid, "structure-evidence-missing"):
            v.parse_observations(v.encode(receipt), self.check, self.root)
        with patch.object(structure, "load", side_effect=FileNotFoundError), self.assertRaisesRegex(v.Invalid, "structure-evidence-invalid"):
            v.parse_observations(v.encode(receipt), self.check, self.root, evidence)
        admission = next(c for c in self.config["checks"] if c["id"] == "admission-independence")
        ledger = {"status": "complete-under-assumptions", "source_sha256": "1" * 64, "independence": {"supported_conditions": 165}}
        with patch.object(structure, "load", return_value=ledger):
            self.assertEqual(v.parse_observations(v.encode(receipt), admission, self.root, evidence), ({"ADMISSION-ASSURANCE": 165}, []))
            coordinate = (admission["id"], structure.PLATFORM, "ADMISSION-ASSURANCE")
            gate = v.decide(self.config, {coordinate: "passed"}, [], [], now)
            self.assertEqual(gate["passed"], [key.replace("/structure", "/mcdc")])
            self.assertEqual(gate["status"], "blocked")
            ledger["status"] = "incomplete"
            self.assertEqual(v.parse_observations(v.encode(receipt), admission, self.root, evidence), ({}, ["structure-uncovered"]))
            for state in ("failed", "interrupted", "unknown"):
                self.assertIn(key.replace("/structure", "/mcdc"), v.decide(self.config, {coordinate: state}, [], [], now)["missing"])
        storage = next(c for c in self.config["checks"] if c["id"] == "storage-structure")
        ledger = {
            "status": "complete-under-assumptions",
            "source_sha256": "1" * 64,
            "statements": {"reachable_under_assumptions": {"statements_hit": 622}},
            "boolean": {"totals": {"roots": {"observed": 317}, "atoms": {"observed": 553}}},
            "controls": {"observed": 34},
        }
        with patch.object(structure, "load", return_value=ledger):
            self.assertEqual(v.parse_observations(v.encode(receipt), storage, self.root, evidence), ({"STORAGE-ASSURANCE": 1526}, []))
            key = "polaris-storage/DEV-COVERAGE/STORAGE-ASSURANCE/linux-amd64-cgo/structure"
            gate = v.decide(self.config, {(storage["id"], structure.PLATFORM, "STORAGE-ASSURANCE"): "passed"}, [], [], now)
            self.assertIn(key, gate["passed"])
            self.assertIn(key.replace("/structure", "/mcdc"), gate["missing"])
            self.assertEqual(gate["status"], "blocked")
            ledger["boolean"]["totals"]["atoms"]["observed"] = 540
            with self.assertRaisesRegex(v.Invalid, "structure-denominator-drift"):
                v.parse_observations(v.encode(receipt), storage, self.root, evidence)

    def test_no_restart(self) -> None:
        """An existing evidence directory is refused before starting or inspecting any test executable."""
        admission = next(c for c in self.config["checks"] if c["id"] == "admission-independence")
        with patch.object(v.subprocess, "Popen") as spawn, self.assertRaisesRegex(v.Invalid, "structure-reuse-only"):
            structure.collect(self.root, admission, self.directory)
        spawn.assert_not_called()
        with patch.object(v.subprocess, "Popen") as spawn, self.assertRaisesRegex(v.Invalid, "structure-execution-boundary"):
            v.execute(self.check, self.root, self.run, structure.PLATFORM)
        spawn.assert_not_called()
        with patch.object(v.subprocess, "Popen") as spawn, self.assertRaisesRegex(v.Invalid, "structure-execution-boundary"):
            v.execute(self.check, self.root, self.run, "windows")
        spawn.assert_not_called()

    def test_bundle(self) -> None:
        """Verify the eight-command join; only the separately tested AST/ledger readers are replaced by synthetic inputs."""
        source = {"kind": "synthetic-source"}
        source_data = v.encode(source)
        environment = {
            key: value.replace("{root}", str(self.root)).replace("{cache}", str(self.root / "build")).replace("{run}", str(self.run))
            for key, value in self.check["environment"].items()
        }
        environment.update(HOME=str(self.root), LANG="C.UTF-8")
        go = self.root / "build/tools/go-1.27.2/bin/go"
        tools = {"command": str(go), "CC": environment["CC"], "CXX": environment["CXX"]}
        for path in map(Path, tools.values()):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic binary")
        toolchain = {name: {"path": path, "sha256": v.file_digest(path)} for name, path in tools.items()}
        boot = "12345678-1234-1234-1234-123456789012"
        outer = {"started_at": "2026-10-04T00:00:00Z", "finished_at": "2026-10-04T00:01:00Z", "resolved_environment": environment}
        v.write_new(
            self.run / "admission-structure.process.json",
            {"identity": {"pid": 9, "start_ticks": "88"}, "boot_id": boot, "argv": self.check["argv"], "cwd": str(self.root)},
        )
        profile = b"synthetic profile\n"
        events = [{"Action": "start"}]
        for test in self.check["native_tests"]:
            events.append({"Action": "run", "Test": test})
            if test == "TestNodeOpen":
                events.append({"Action": "output", "Test": test, "Output": "ADMISSION-RESOLVER-PROFILE " + base64.b64encode(profile).decode() + "\n"})
            events.append({"Action": "pass", "Test": test})
        events.append({"Action": "pass"})
        stream = b"".join((json.dumps({"Package": "github.com/eosforge/astra/internal/admission", **event}) + "\n").encode() for event in events)
        for index, (name, arguments, _) in enumerate(structure.plan(self.directory)):
            parent = self.directory / name
            parent.mkdir(parents=True)
            child = {**environment, "TMPDIR": str(parent / "tmp"), "ASTRA_TEST_LOG_DIR": str(parent / "logs")}
            argv = [argument.replace("{root}", str(self.root)) for argument in arguments]
            process = {"identity": {"pid": 10 + index, "start_ticks": "99", "parent": 9}, "boot_id": boot, "argv": argv, "cwd": str(self.root)}
            v.write_new(parent / (parent.name + ".process.json"), process)
            record = {
                "id": parent.name,
                "platform": structure.PLATFORM,
                "argv": argv,
                "environment": child,
                "resolved_environment": child,
                "executable": str(go),
                "executable_sha256": v.file_digest(go),
                "toolchain": toolchain,
                "duration_ms": 1,
                "started_at": f"2026-10-04T00:00:{index * 2:02d}Z",
                "finished_at": f"2026-10-04T00:00:{index * 2 + 1:02d}Z",
                "exit_code": 0,
                "termination": "exited",
                "complete": True,
                "cleanup": True,
                "stdout": v.write_new(parent / "out.log", stream),
                "stderr": v.write_new(parent / "err.log", b""),
            }
            v.write_new(parent / "record.json", record)
        limits = {
            "cpu_quota": 400000,
            "cpu_period": 100000,
            "memory_bytes": 2 * 1024**3,
            "tasks": 512,
            "available_bytes": 1536 * 1024**2,
            "disk_free_bytes": 8 * 1024**3,
        }
        v.write_new(self.directory / "source.json", source_data)
        v.write_new(self.directory / "preflight.json", limits)
        v.write_new(self.directory / "coverage.profile", profile)
        v.write_new(self.directory / "resolver.profile", profile)
        bundle = {
            "version": 2,
            "source": structure.artifact(self.directory, self.directory / "source.json"),
            "coverage": structure.artifact(self.directory, self.directory / "coverage/record.json"),
            "preflight": structure.artifact(self.directory, self.directory / "preflight.json"),
            "profiles": {
                key: structure.artifact(self.directory, self.directory / path) for key, path in (("parent", "coverage.profile"), ("child", "resolver.profile"))
            },
            "dependencies": {},
        }
        for name in ("typed", "control"):
            parent = self.directory / name
            (parent / "overlay").mkdir()
            for path, data in (
                ("source.json", source_data),
                ("overlay/trace.json" if name == "typed" else "overlay/flow.json", b"{}"),
                ("overlay/overlay.json", b"{}"),
            ):
                v.write_new(parent / path, data)
            fields = {"source": "source.json", "trace": "overlay/trace.json" if name == "typed" else "overlay/flow.json", "overlay": "overlay/overlay.json"}
            fields.update({key: key + "/record.json" for key in (["exports"] if name == "typed" else []) + ["collector", "packages", "tests"]})
            nested = {
                "version": 2 if name == "typed" else 1,
                "directory": structure.PACKAGE,
                **{key: structure.artifact(parent, parent / path) for key, path in fields.items()},
                "generated": {},
            }
            v.write_new(parent / "bundle.json", nested)
            bundle[name] = structure.artifact(self.directory, parent / "bundle.json")
        for name in structure.DEPENDENCIES:
            for path in (go.parent.parent / "src" / name, self.directory / "_dependencies" / name):
                path.parent.mkdir(parents=True, exist_ok=True)
                v.write_new(path, name.encode())
            bundle["dependencies"][name] = structure.artifact(self.directory, path)
        v.write_new(self.directory / "bundle.json", bundle)
        original = {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        loaded = {"source_sha256": v.digest(source_data), "trace": {}, "events": stream}
        with (
            patch.object(v, "source", return_value=source),
            patch.object(structure.shutil, "which", side_effect=lambda name, **_: str(go) if name == "go" else name),
            patch.dict(structure.os.environ, {"ASTRA_CACHE_ROOT": str(self.root / "build")}),
            patch.object(structure.logic, "load", return_value=loaded) as reader,
            patch.object(structure, "reconcile", return_value={"synthetic": True}) as ledger,
        ):
            self.assertEqual(structure.load(self.directory, self.root, self.check, outer), {"synthetic": True})
            self.assertEqual(reader.call_count, 2)
            self.assertEqual(ledger.call_args.kwargs["profiles"], (profile, profile))
            self.assertEqual(ledger.call_args.kwargs["boolean_events"], stream)
            for fault in (
                "missing-record",
                "extra-attempt",
                "owner",
                "order",
                "command",
                "source",
                "dependency",
                "child",
                "fields",
                "version",
                "dependency-path",
            ):
                for path, data in original.items():
                    path.write_bytes(data)
                changed = copy.deepcopy(bundle)
                extra = self.directory / "retry/record.json"
                if extra.exists():
                    extra.unlink()
                if fault == "missing-record":
                    (self.directory / "control/tests/record.json").unlink()
                elif fault == "extra-attempt":
                    extra.parent.mkdir(exist_ok=True)
                    v.write_new(extra, {})
                elif fault == "owner":
                    path = self.directory / "coverage/coverage.process.json"
                    process = v.decode(path.read_bytes())
                    process["identity"]["parent"] = 8
                    path.write_bytes(v.encode(process))
                elif fault in {"order", "command"}:
                    path = self.directory / "control/tests/record.json"
                    record = v.decode(path.read_bytes())
                    if fault == "order":
                        record["started_at"] = "2026-10-04T00:00:00Z"
                    else:
                        record["argv"].insert(2, "-race")
                    path.write_bytes(v.encode(record))
                elif fault == "source":
                    (self.directory / "source.json").write_bytes(b"{}")
                elif fault == "dependency":
                    (go.parent.parent / "src" / next(iter(structure.DEPENDENCIES))).write_bytes(b"changed")
                elif fault == "child":
                    (self.directory / "resolver.profile").write_bytes(b"foreign child")
                    changed["profiles"]["child"] = structure.artifact(self.directory, self.directory / "resolver.profile")
                elif fault == "version":
                    changed["version"] = 1
                elif fault == "dependency-path":
                    name = next(iter(structure.DEPENDENCIES))
                    changed["dependencies"][name]["path"] = "dependencies/" + name
                else:
                    changed["status"] = "passed"
                (self.directory / "bundle.json").write_bytes(v.encode(changed))
                ledger.reset_mock()
                with self.subTest(fault=fault), self.assertRaises(v.Invalid):
                    structure.load(self.directory, self.root, self.check, outer)
                ledger.assert_not_called()
