"""Attack incomplete Admission consumer graphs, stale source reuse and truncated native regressions."""

import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tools import delivery, entry, installation, reach, statements, verify as v


def stream(rows: list[dict]) -> bytes:
    """Retain real JSON-line framing when deliberately damaging native test events."""
    return b"".join(json.dumps(row, separators=(",", ":")).encode() + b"\n" for row in rows)


class ReachTests(unittest.TestCase):
    """Native positive evidence is immutable; synthetic variants supply rejection controls only."""

    @classmethod
    def setUpClass(cls) -> None:
        """Reconcile the complete actual consumer collection once, without executing any Go or C++ workload."""
        cls.root = Path(__file__).resolve().parents[1]
        cls.receipt = reach.reconcile(cls.root)
        base = cls.root / "build/results/assurance/reuse-plan"
        old = entry.unpack(v.read(base / "storage-delivery-current-5/native/evidence.tar.gz", entry.LIMIT))
        cls.before = v.decode(old["inputs.json"])["files"]
        _, current, cls.new_graph, _ = delivery.compose(cls.root)
        cls.after = current["source"]
        _, cls.old_graph = delivery.receipt(old, "source/build/commands/control-plane-delivery/consumer-graph/")
        cls.files = reach.consumers.unpack(v.read(cls.root / "build/results/assurance" / reach.BASE / "evidence.tar.gz", entry.LIMIT), reach.ARCHIVE)
        cls.native = v.decode(cls.files["inputs.json"])["files"]
        for name, field in (("astrolabe-race", "events"), ("astrolabe-discovery", "discovery")):
            prefix = "source/build/commands/" + name + "/"
            record = v.decode(cls.files[prefix + "record.json"])
            setattr(cls, field, [v.decode(row) for row in cls.files[prefix + record["stdout"]["path"]].splitlines()])
        cls.snapshot = v.source(cls.root)
        cls.current = {row["path"]: row["sha256"] for row in cls.snapshot["files"] if row["sha256"] is not None}

    def test_current(self) -> None:
        """Require physical current input bindings, all six affected packages and both installed shipping consumers."""
        actual = self.receipt
        self.assertEqual(actual["trust"], "local")
        self.assertEqual(actual["platform"], "linux-amd64-cgo")
        self.assertEqual(actual["changed_go"], [installation.PATH])
        self.assertEqual(actual["graph"]["affected"], reach.AFFECTED)
        self.assertEqual(len(actual["graph"]["imports"]), 14)
        self.assertEqual(set(actual["graph"]["consumers"]), set(reach.MAINS))
        self.assertNotIn("polaris/internal/server", actual["graph"]["consumers"]["astrolabe"])
        self.assertGreater(len(actual["source_inputs"]), 75)
        for name, sha in actual["source_inputs"].items():
            self.assertEqual(sha, self.current[name])
            self.assertEqual(sha, v.file_digest(self.root / name))
        for package, (cases, parents, sha) in reach.NATIVE.items():
            self.assertEqual(actual["astrolabe_regression"]["packages"][package], {"cases": cases, "parents": parents, "tests_sha256": sha})
        self.assertEqual(sum(item["cases"] for item in actual["astrolabe_regression"]["packages"].values()), 432)
        self.assertEqual(sum(item["parents"] for item in actual["astrolabe_regression"]["packages"].values()), 74)
        self.assertEqual(actual["polaris_regressions"]["server"]["cases"], 300)
        self.assertEqual(actual["polaris_regressions"]["entry"]["tests"], 8)
        self.assertEqual(set(actual["delivery"]["consumers"]), set(reach.MAINS))
        self.assertEqual(actual["delivery"]["archives"], actual["current_delivery_archives"])

    def test_archive(self) -> None:
        """A synthetic pass, altered archive or stale native lifecycle cannot replace original complete facts."""
        original = v.read
        archive = self.root / "build/results/assurance" / reach.BASE / "evidence.tar.gz"
        for data in (original(archive, entry.LIMIT) + b" ", v.encode({"status": "passed"})):
            with (
                self.subTest(bytes=len(data)),
                patch.object(v, "read", side_effect=lambda path, *args: data if path == archive else original(path, *args)),
                self.assertRaises((v.Invalid, KeyError)),
            ):
                reach.consumer(self.root)
        mutations = [
            ("terminal.json", lambda d: d.update(cache_restored=False)),
            ("controller.json", lambda d: d.update(boot_id="foreign")),
            ("cleanup.native.json", lambda d: d["retired"].pop()),
            ("cache-restored.native.json", lambda d: d.update(inode=0)),
            ("source/build/commands/astrolabe-race/record.json", lambda d: d["argv"].insert(3, "-run=TestProcess")),
            ("source/build/commands/astrolabe-race/record.json", lambda d: d["resolved_environment"].update(GOPROXY="direct")),
        ]
        for path, mutate in mutations:
            files = dict(self.files)
            changed = v.decode(files[path])
            mutate(changed)
            files[path] = v.encode(changed)
            with self.subTest(path=path), self.assertRaises(v.Invalid):
                reach.acquisition(files)

    def test_native(self) -> None:
        """Incomplete actual discovery and missing, skipped or repeated Race terminals must fail closed."""
        self.assertEqual(reach.cases(stream(self.events), stream(self.discovery)), self.receipt["astrolabe_regression"]["packages"])
        for mode in ("missing", "skip", "fail", "duplicate", "foreign", "terminal", "discovery", "repeated-discovery", "empty-discovery"):
            rows = copy.deepcopy(self.events)
            discovery = copy.deepcopy(self.discovery)
            index = next(
                i for i, row in enumerate(rows) if row.get("Package") == reach.astrolabe.MODULE + "astrolabe" and row.get("Action") == "pass" and "Test" in row
            )
            if mode == "missing":
                del rows[index]
            elif mode == "duplicate":
                rows.append(rows[index])
            elif mode == "foreign":
                rows[index]["Package"] = "foreign"
            elif mode == "terminal":
                rows = [
                    row
                    for row in rows
                    if not (row.get("Package") == reach.astrolabe.MODULE + "astrolabe" and row.get("Action") == "pass" and "Test" not in row)
                ]
            elif mode in ("discovery", "repeated-discovery", "empty-discovery"):
                at = next(i for i, row in enumerate(discovery) if row.get("Output", "").startswith("Test") and "/" not in row["Output"])
                if mode == "discovery":
                    del discovery[at]
                elif mode == "repeated-discovery":
                    discovery.append(discovery[at])
                else:
                    discovery = []
            else:
                rows[index]["Action"] = mode
            with self.subTest(mode=mode), self.assertRaises(v.Invalid):
                reach.cases(stream(rows), stream(discovery))

    def test_graph(self) -> None:
        """Missing transitive imports, new consumers and incomplete or cyclic module discovery must fail closed."""
        self.assertEqual(reach.graphs(self.old_graph, self.new_graph), self.receipt["graph"])
        packages = statements.stream(self.new_graph)
        for mode in ("missing", "transitive", "cycle", "duplicate", "unknown", "incomplete", "consumer"):
            rows = copy.deepcopy(packages)
            index = next(i for i, row in enumerate(rows) if row["ImportPath"] == reach.astrolabe.MODULE + "astrolabe/internal/bridge")
            if mode == "missing":
                del rows[index]
            elif mode == "transitive":
                rows[index]["Imports"] = [name for name in rows[index]["Imports"] if name != reach.astrolabe.MODULE + reach.TARGET]
            elif mode == "cycle":
                rows[index]["Imports"].append(reach.astrolabe.MODULE + "astrolabe")
            elif mode == "duplicate":
                rows.append(rows[index])
            elif mode == "unknown":
                rows[index]["Imports"].append(reach.astrolabe.MODULE + "unknown")
            elif mode == "incomplete":
                rows[index]["Incomplete"] = True
            else:
                rows.append({"ImportPath": reach.astrolabe.MODULE + "new", "Name": "main", "Imports": [reach.astrolabe.MODULE + reach.TARGET]})
            with self.subTest(mode=mode), self.assertRaises(v.Invalid):
                reach.graphs(self.old_graph, b"\n".join(v.encode(row) for row in rows))

    def test_delta(self) -> None:
        """Equal current hashes cannot conceal an unreviewed producer change or a newly unmapped package."""
        for name in (
            "internal/admission/node.go",
            "astrolabe/main.go",
            installation.PATH,
            "polaris/internal/storage/store.go",
            "polaris/internal/storage/maintenance.go",
            "proto/astra.proto",
        ):
            after = {**self.after, name: "0" * 64}
            with self.subTest(path=name), patch.object(v, "source", return_value=self.snapshot), self.assertRaises(v.Invalid):
                reach.sources(self.root, self.before, after, self.native, self.receipt["graph"])
        after = {**self.after, "new/package.go": "0" * 64}
        before = {**self.before, "new/package.go": "0" * 64}
        snapshot = copy.deepcopy(self.snapshot)
        snapshot["files"].append({"path": "new/package.go", "sha256": "0" * 64})
        with patch.object(v, "source", return_value=snapshot), self.assertRaises(v.Invalid):
            reach.sources(self.root, before, after, self.native, self.receipt["graph"])

    def test_sources(self) -> None:
        """Reject changed live inputs and the historical omission of newly added Astrolabe tests."""
        with patch.object(v, "source", return_value=self.snapshot):
            self.assertEqual(reach.sources(self.root, self.before, self.after, self.native, self.receipt["graph"]), self.receipt["source_inputs"])
        for name in ("go.mod", "tests/fixtures/admission-v1.json", "astrolabe/process_test.go", "internal/generated/orbit/orbit.pb.go"):
            snapshot = copy.deepcopy(self.snapshot)
            next(row for row in snapshot["files"] if row["path"] == name)["sha256"] = "0" * 64
            with self.subTest(path=name), patch.object(v, "source", return_value=snapshot), self.assertRaises(v.Invalid):
                reach.sources(self.root, self.before, self.after, self.native, self.receipt["graph"])
        for name in ("astrolabe/extra_test.go", "proto/new.proto"):
            snapshot = copy.deepcopy(self.snapshot)
            snapshot["files"].append({"path": name, "sha256": "0" * 64})
            with self.subTest(added=name), patch.object(v, "source", return_value=snapshot), self.assertRaises(v.Invalid):
                reach.sources(self.root, self.before, self.after, self.native, self.receipt["graph"])
        with patch.object(v, "source", return_value=self.snapshot), self.assertRaises(v.Invalid):
            reach.sources(self.root, self.before, self.after, {**self.native, "astrolabe/main.go": "0" * 64}, self.receipt["graph"])
        native = dict(self.native)
        del native["astrolabe/origin_test.go"]
        with patch.object(v, "source", return_value=self.snapshot), self.assertRaises(v.Invalid):
            reach.sources(self.root, self.before, self.after, native, self.receipt["graph"])

    def test_policy(self) -> None:
        """Local consumer regressions cannot waive current Admission core, installed delivery or historical repair proof."""
        config = v.decode(v.read(self.root / "development.json"))
        reach.policy(config)
        self.assertEqual(len(reach.PREREQUISITES), 3)
        for mode in ("control", "probe", "owner", "core", "delivery", "repair"):
            changed = copy.deepcopy(config)
            check = next(item for item in changed["checks"] if item["id"] == "admission-gap-impact")
            component = next(item for item in changed["components"] if item["id"] == "admission")
            requirement = next(item for item in component["requirements"] if item["rule"] == "DEV-IMPACT")
            if mode == "control":
                check["expected_tests"].pop()
            elif mode == "probe":
                check["probes"] = []
            elif mode == "owner":
                check["component"] = "tools"
            else:
                requirement["requires"].pop({"core": 0, "delivery": 1, "repair": 2}[mode])
            with self.subTest(mode=mode), self.assertRaises(v.Invalid):
                reach.policy(changed)
