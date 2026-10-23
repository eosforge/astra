"""Check development-gate rejection and collector lifetimes; synthetic records are fixtures, never component acceptance evidence."""

from collections.abc import Sequence
import copy
import contextlib
import datetime as dt
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import verify as v

ROOT = Path(__file__).resolve().parents[1]


def fixture() -> dict:
    """Derive a small synthetic gate fixture; its reduced obligations are not production acceptance policy."""
    config = v.decode(v.read(ROOT / "development.json"))
    component = config["components"][0]
    config["components"] = [component]
    component["level"] = "L1"
    component["role"] = "component"
    component["evidence_trust"] = "local"
    component["convergence"] = {"metric": "fixture", "baseline": 1, "target": 0, "deadline": "2099-01-01T00:00:00Z", "approval_ref": "fixture-only"}
    component["requirements"] = [component["requirements"][0]]
    config["scope"] = {"components": [{key: copy.deepcopy(component[key]) for key in ("id", "level", "paths", "platforms")}], "exclusions": []}
    config["checks"] = [config["checks"][0]]
    check = config["checks"][0]
    # This reduced atomic-only fixture declares neither finite-model nor recovery qualification.
    check.pop("model", None)
    check.pop("recovery", None)
    check["expected_tests"] = ["TestVerification/atomic"]
    check["probes"] = [check["probes"][0]]
    return config


def events(check: dict, hits: int = 7) -> list[dict]:
    """Create an ordered synthetic Go event stream with an explicit contract-hit count."""
    package = check["package"]
    test = check["expected_tests"][0]
    return [
        {"Package": package, "Action": "start"},
        {"Package": package, "Action": "run", "Test": test},
        {
            "Package": package,
            "Action": "output",
            "Test": test,
            "Output": '    verification_test.go:19: ASTRA-CONTRACT {"contract":"STORAGE-ATOMIC","hits":' + str(hits) + "}\n",
        },
        {"Package": package, "Action": "pass", "Test": test},
        {"Package": package, "Action": "pass"},
    ]


def stream(entries: list[dict]) -> bytes:
    """Encode fixture events as native-shaped JSONL bytes without executing a check."""
    return b"".join((json.dumps(entry) + "\n").encode() for entry in entries)


def composition(platforms: Sequence[str] = ("linux", "windows")) -> dict:
    """Build a synthetic parent/child policy to test evaluation, never native acceptance evidence."""
    dependency = {"rule": "DEV-COVERAGE", "contract": "CHILD", "scenario": "structure"}
    return {
        "components": [
            {
                "id": "fixture",
                "platforms": list(platforms),
                "requirements": [
                    {"rule": "DEV-COVERAGE", "contract": "PARENT", "scenario": "full-rule", "checks": ["parent"], "requires": [dependency]},
                    {**dependency, "checks": ["child"]},
                ],
            }
        ],
        "checks": [{"id": "parent", "adapter": "observed-cases"}, {"id": "child", "adapter": "observed-cases"}],
    }


def coordinate(check: dict, item: dict, key: str) -> tuple[str, ...]:
    """Name a synthetic receipt at the exact scope declared by its adapter."""
    base = (check["id"], item["platform"], item["contract"])
    return (*base, key) if check["adapter"] == "retained-qualification" else base


class DependencyTests(unittest.TestCase):
    """Keep aggregate qualification dependent on each real child pass in the correct platform."""

    def test_backup_watermarks(self) -> None:
        """Both native profiles qualify each backup leaf; neither leaf alone qualifies operation or release."""
        from tools import idle

        policy, _, _ = v.configuration(ROOT / "development.json")
        obligations = v.expand(policy)
        checks = v.unique(policy["checks"])
        platform = "linux-amd64-cgo"
        scopes = {
            "STORAGE-BACKUP-ONLINE": ("DEV-OPERATE", "online-consistent-backup", "TestOnlineBackup", 11),
            "STORAGE-BACKUP-RESTORE": ("DEV-RELEASE", "quiesced-backup-restore", "TestBackupRestore", 18),
        }
        leaves = {contract: f"polaris-storage/{rule}/{contract}/{platform}/{scenario}" for contract, (rule, scenario, _, _) in scopes.items()}
        argv = [
            "go",
            "test",
            "-json",
            "-count=1",
            "-parallel=1",
            "-p=2",
            "-timeout=120s",
            "-run=^(TestOnlineBackup|TestBackupRestore)$",
            "./polaris/internal/storage",
        ]
        for name, arguments in (("storage-backup", argv), ("storage-backup-race", argv[:2] + ["-race"] + argv[2:])):
            check = checks[name]
            self.assertEqual(check["adapter"], "go-test-json")
            self.assertEqual(check["argv"], arguments)
            self.assertEqual(check["environment"]["GOMAXPROCS"], "2")
            self.assertEqual(check["expected_tests"], [value[2] for value in scopes.values()])
            self.assertEqual(check["probes"], [{"contract": contract, "test": value[2], "minimum_hits": value[3]} for contract, value in scopes.items()])
        # Extend the future full package run while preserving every historical native case.
        old = v.decode(v.read(ROOT / "tests/fixtures/storage.tests.json"))
        self.assertEqual(len(old), 247)
        self.assertEqual(set(checks["storage-examples"]["expected_tests"]), set(old) | set(idle.CASES) | {value[2] for value in scopes.values()})
        self.assertEqual(len(checks["storage-examples"]["expected_tests"]), 259)
        observed = {(name, platform, contract): "passed" for name in ("storage-backup", "storage-backup-race") for contract in scopes}
        now = v.stamp("2026-10-17T00:00:00Z")
        result = v.decide(policy, observed, [], [], now)
        self.assertEqual(set(result["passed"]), set(leaves.values()))
        self.assertEqual(result["status"], "blocked")
        for contract, (rule, scenario, _, _) in scopes.items():
            parent_key = f"polaris-storage/{rule}/STORAGE-ASSURANCE/{platform}/full-rule"
            parent = obligations[parent_key]
            self.assertEqual(parent["checks"], ["gap-" + rule.removeprefix("DEV-").lower()])
            self.assertEqual(checks[parent["checks"][0]]["adapter"], "retained-qualification")
            self.assertIn(parent_key, result["missing"])
            self.assertEqual(parent["requires"], [{"rule": rule, "contract": contract, "scenario": scenario}])
            self.assertEqual(obligations[leaves[contract]]["checks"], ["storage-backup", "storage-backup-race"])
        for coordinate in observed:
            for state in (None, "failed", "unknown", "skipped", "interrupted", "platform", "contract"):
                with self.subTest(coordinate=coordinate, state=state):
                    changed = dict(observed)
                    del changed[coordinate]
                    if state == "platform":
                        changed[(coordinate[0], "windows-amd64", coordinate[2])] = "passed"
                    elif state == "contract":
                        changed[(coordinate[0], coordinate[1], "STORAGE-UNRELATED")] = "passed"
                    elif state is not None:
                        changed[coordinate] = state
                    self.assertIn(leaves[coordinate[2]], v.decide(policy, changed, [], [], now)["missing"])

    def test_storage_compatibility(self) -> None:
        """First-release format acceptance requires both native profiles and every unchanged storage prerequisite."""
        config, _, _ = v.configuration(ROOT / "development.json")
        config = copy.deepcopy(config)
        config["components"] = [next(item for item in config["components"] if item["id"] == "polaris-storage")]
        obligations = v.expand(config)
        _, dependencies = v.dependency_order(obligations)
        key = "polaris-storage/DEV-COMPAT/STORAGE-ASSURANCE/linux-amd64-cgo/full-rule"
        item = obligations[key]
        self.assertEqual(item["checks"], ["gap-compat", "gap-compat-race"])
        self.assertEqual(
            item["requires"],
            [
                {"contract": "STORAGE-ASSURANCE", "rule": rule, "scenario": "full-rule"}
                for rule in ("DEV-CONTRACT", "DEV-COVERAGE", "DEV-RETRY", "DEV-SECURITY", "DEV-STOP")
            ],
        )
        checks = v.unique(config["checks"])
        for name in item["checks"]:
            check = checks[name]
            self.assertEqual(check["adapter"], "go-test-json")
            self.assertEqual(check["package"], "github.com/eosforge/astra/polaris/internal/storage")
            self.assertEqual("-race" in check["argv"], name.endswith("-race"))
            self.assertIn("-count=1", check["argv"])
            self.assertIn("-run=^TestCompatibility$", check["argv"])
            self.assertEqual(
                check["expected_tests"], ["TestCompatibility"] + ["TestCompatibility/" + case for case in ("single", "batch", "unknown", "truncated")]
            )
            self.assertEqual(
                check["probes"],
                [
                    {"contract": "STORAGE-ASSURANCE", "test": "TestCompatibility" + ("/" + case if case else ""), "minimum_hits": count}
                    for case, count in (("", 2), ("single", 25), ("batch", 30), ("unknown", 14), ("truncated", 15))
                ],
            )
        for name, digest in {
            "schema.sql": "1c9b57d3284af6e2ee93e888356bc2bb400a8fbc4c92619c67bd3a20e4d78aba",
            "single.sql": "9d61ede58c6f80574e900034018b8ab2df329d357aa5fe036a833874403e1306",
            "batch.sql": "1eaa55a20816cff14430e5f83091d9f246438498cae7fbf814f76870f31cd1dd",
        }.items():
            self.assertEqual(v.file_digest(ROOT / "polaris/internal/storage/testdata" / name), digest, "Frozen expectations cannot drift with the writer")
        leaves = self.receipts(obligations, dependencies, key, checks)
        leaves.update((name, "linux-amd64-cgo", "STORAGE-ASSURANCE") for name in item["checks"])
        self.assertEqual(len(leaves), 43)
        observed = {coordinate: "passed" for coordinate in leaves}
        now = v.stamp("2026-10-13T00:00:00Z")
        result = v.decide(config, observed, [], [], now)
        self.assertIn(key, result["passed"])
        self.assertEqual(result["status"], "blocked", "Synthetic format controls do not qualify the remaining component or release rules")
        for coordinate in sorted(leaves):
            for state in (None, "failed", "unknown", "platform"):
                with self.subTest(coordinate=coordinate, state=state):
                    changed = dict(observed)
                    del changed[coordinate]
                    if state == "platform":
                        changed[(coordinate[0], "windows-amd64", coordinate[2])] = "passed"
                    elif state is not None:
                        changed[coordinate] = state
                    self.assertNotIn(key, v.decide(config, changed, [], [], now)["passed"])

    def test_pulsar_candidates(self) -> None:
        """RPC qualification requires every independently scheduled candidate layout on the same platform."""
        policy, _, _ = v.configuration(ROOT / "development.json")
        check = next(row for row in policy["checks"] if row["id"] == "pulsar-native")
        layouts = ("0_0", "0_3", "3_0", "2_8", "8_2", "6_6", "1_1")
        expected = {f"PULSAR_NATIVE-{index}": f"cpp_pulsar_candidates_{layout}" for index, layout in enumerate(layouts, 5)}
        probes = {row["contract"]: row for row in check["probes"] if row["contract"] in expected}
        self.assertEqual({name: row["test"] for name, row in probes.items()}, expected)
        self.assertTrue(all(row["minimum_hits"] > 0 for row in probes.values()))
        self.assertLessEqual(set(expected.values()), set(check["expected_tests"]))
        now = dt.datetime(2026, 10, 12, tzinfo=dt.timezone.utc)
        observed = {("pulsar-native", "linux-amd64-cgo", contract): "passed" for contract in (*expected, "PULSAR_NATIVE-2")}
        parent = "pulsar/DEV-CONTRACT/PULSAR_NATIVE-2/linux-amd64-cgo/native-oracle"
        self.assertIn(parent, v.decide(policy, observed, [], [], now)["passed"])
        for contract in (*expected, "PULSAR_NATIVE-2"):
            coordinate = ("pulsar-native", "linux-amd64-cgo", contract)
            for state in (None, "failed", "unknown", "not-run", "interrupted", "skipped"):
                damaged = dict(observed)
                damaged.pop(coordinate)
                if state is not None:
                    damaged[coordinate] = state
                damaged[("pulsar-native", "windows-amd64", contract)] = "passed"
                with self.subTest(contract=contract, state=state):
                    result = v.decide(policy, damaged, [], [], now)
                    self.assertIn(parent, result["missing"])
                    self.assertNotIn(parent, result["passed"])

    def receipts(self, obligations: dict[str, dict], dependencies: dict[str, list[str]], key: str, checks: dict[str, dict]) -> set[tuple[str, ...]]:
        """Expand nested conjunctions to each mandatory native receipt, retaining checks on intermediate nodes."""
        pending, closure = list(dependencies[key]), set()
        while pending:
            child = pending.pop()
            if child not in closure:
                closure.add(child)
                pending.extend(dependencies[child])
        self.assertTrue(closure)
        leaves = {coordinate(checks[name], obligations[child], child) for child in closure for name in obligations[child]["checks"]}
        self.assertTrue(leaves)
        return leaves

    def test_aggregate(self) -> None:
        """Only explicit conjunctions can pass without an own marker; missing children and exemptions never pass parents."""
        config = composition()
        parent, child = config["components"][0]["requirements"]
        parent.update(aggregate=True, checks=[])
        top = {**copy.deepcopy(parent), "scenario": "top", "requires": [{key: parent[key] for key in ("rule", "contract", "scenario")}]}
        config["components"][0]["requirements"].insert(0, top)
        prefix = "fixture/DEV-COVERAGE/"
        now = dt.datetime.now(dt.timezone.utc)
        for state in (None, "failed", "not-run", "passed"):
            observed = {} if state is None else {("child", "linux", "CHILD"): state}
            result = v.decide(config, observed, [], [], now)
            self.assertEqual(prefix + "PARENT/linux/full-rule" in result["passed"], state == "passed")
            self.assertEqual(prefix + "PARENT/linux/top" in result["passed"], state == "passed")
            self.assertIn(prefix + "PARENT/windows/top", result["missing"])
        exception = {"id": "child", "obligation": prefix + "CHILD/linux/structure", "revoked": False, "expires_at": "2099-01-01T00:00:00Z"}
        result = v.decide(config, {}, [], [exception], now)
        self.assertIn(exception["obligation"], result["exceptions"])
        self.assertIn(prefix + "PARENT/linux/top", result["missing"])
        result = v.decide(config, {("child", p, "CHILD"): "passed" for p in ("linux", "windows")}, [], [], now)
        self.assertEqual(result["status"], "eligible")
        self.assertEqual(len(result["passed"]), 6)

        # The real configuration composes existing capability obligations without replacing their native oracles.
        policy = v.decode(v.read(ROOT / "development.json"))
        obligations = v.expand(policy)
        _, dependencies = v.dependency_order(obligations)
        components = v.unique(policy["components"])
        parents = {
            key: item
            for key, item in obligations.items()
            if item["component"] != "command"
            and item["scenario"] == "full-rule"
            and item["rule"] in {"DEV-COVERAGE", "DEV-FAULT", "DEV-MATRIX"}
            and item.get("aggregate")
        }
        comet = {
            f"comet-go/DEV-{rule}/COMET-GO-ASSURANCE/{platform}/full-rule"
            for rule in ("COVERAGE", "FAULT", "MATRIX")
            for platform in ("linux-amd64-cgo", "windows-amd64")
        }
        self.assertEqual({key for key, item in parents.items() if item["component"] == "comet-go"}, comet)
        self.assertEqual(len(parents.keys() - comet), 46)
        # These statuses are synthetic dependency controls, not observations or saved acceptance results.
        checks = v.unique(policy["checks"])
        observed = {coordinate(checks[name], item, key): "passed" for key, item in obligations.items() for name in item["checks"]}
        positive = v.decide(policy, observed, [], [], now)
        for key, item in parents.items():
            with self.subTest(obligation=key):
                self.assertIn(key, positive["passed"])
                self.assertFalse(item["checks"])
                children = [obligations[dependency] for dependency in dependencies[key]]
                if item["rule"] == "DEV-COVERAGE":
                    needed = {"structure"}
                    level = components[item["component"]]["level"]
                    if level in {"L2", "L3"}:
                        needed.update({"mcdc", "mutation", "fault-matrix", "delivery-matrix"})
                    if level == "L3":
                        needed.add("finite-model")
                else:
                    needed = {"fault-matrix" if item["rule"] == "DEV-FAULT" else "delivery-matrix"}
                self.assertLessEqual(needed, {child["scenario"] for child in children})
                same_rule = {
                    reference
                    for reference, child in obligations.items()
                    if child["component"] == item["component"]
                    and child["platform"] == item["platform"]
                    and child["rule"] == item["rule"]
                    and child["scenario"] != "full-rule"
                }
                self.assertLessEqual(same_rule, set(dependencies[key]))
                for leaf in self.receipts(obligations, dependencies, key, checks):
                    damaged = dict(observed)
                    damaged.pop(leaf)
                    self.assertIn(key, v.decide(policy, damaged, [], [], now)["missing"])

        # Storage whole-rule claims require the complete capability base and their
        # actual public boundaries. These synthetic states only test gate logic.
        common = {
            ("DEV-COVERAGE", "STORAGE-ASSURANCE", "full-rule"),
            ("DEV-FAULT", "STORAGE-ASSURANCE", "full-rule"),
            ("DEV-NUMERIC", "STORAGE-ASSURANCE", "full-rule"),
        }
        boundaries = {
            "DEV-CORE": {"STORAGE-ATOMIC", "STORAGE-READ", "STORAGE-SCHEDULE", "STORAGE-LIFETIME", "STORAGE-DRAINING", "STORAGE-BORROWING"},
            "DEV-CONTRACT": {"STORAGE-ATOMIC", "STORAGE-READ", "STORAGE-HISTORY", "STORAGE-ROLLBACK", "STORAGE-FINALIZE", "STORAGE-PANIC", "STORAGE-CRASH"},
            "DEV-SECURITY": {
                "STORAGE-NAMES",
                "STORAGE-CORRUPTION",
                "STORAGE-BOUNDARY",
                "STORAGE-RETAIN-SCAN",
                "STORAGE-READ-FAULT",
                "STORAGE-WRITE-DAMAGE",
                "STORAGE-BORROWING",
                "STORAGE-RETRY-IDENTITY",
            },
            "DEV-ORACLE": {"STORAGE-FINITE", "STORAGE-SCHEDULE", "STORAGE-ORACLE", "STORAGE-NUMERIC-SENSITIVITY", "STORAGE-NUMERIC-CONTROLS"},
            "DEV-ASYNC": {
                "STORAGE-LIFETIME",
                "STORAGE-DRAINING",
                "STORAGE-BORROWING",
                "STORAGE-TERMINATION",
                "STORAGE-SCHEDULE",
                "STORAGE-FINALIZE",
                "STORAGE-PANIC",
            },
            "DEV-STOP": {
                "STORAGE-LIFETIME",
                "STORAGE-DRAINING",
                "STORAGE-BORROWING",
                "STORAGE-TERMINATION",
                "STORAGE-SCHEDULE",
                "STORAGE-CRASH",
                "STORAGE-CONNECTION",
                "STORAGE-CHECKPOINT",
            },
            "DEV-MODEL": {"STORAGE-FINITE", "STORAGE-SCHEDULE", "STORAGE-ORACLE"},
        }
        for rule, contracts in boundaries.items():
            key = f"polaris-storage/{rule}/STORAGE-ASSURANCE/linux-amd64-cgo/full-rule"
            parent = obligations[key]
            with self.subTest(storage_rule=rule):
                self.assertTrue(parent.get("aggregate", False), "Storage qualification needs an executable conjunction, not an unresolved marker.")
                self.assertEqual(parent["checks"], [])
                children = [obligations[child] for child in dependencies[key]]
                needed = common if rule == "DEV-MODEL" else common | {("DEV-MODEL", "STORAGE-ASSURANCE", "full-rule")}
                self.assertLessEqual(needed, {(child["rule"], child["contract"], child["scenario"]) for child in children})
                self.assertLessEqual(contracts, {child["contract"] for child in children})
                same_rule = {
                    reference
                    for reference, child in obligations.items()
                    if child["component"] == "polaris-storage"
                    and child["platform"] == parent["platform"]
                    and child["rule"] == rule
                    and child["scenario"] != "full-rule"
                }
                self.assertLessEqual(same_rule, set(dependencies[key]))
                self.assertIn(key, positive["passed"])
                for leaf in self.receipts(obligations, dependencies, key, checks):
                    for state in (None, "failed", "unknown", "interrupted"):
                        damaged = dict(observed)
                        damaged.pop(leaf)
                        if state is not None:
                            damaged[leaf] = state
                        damaged[(leaf[0], "unrelated-platform", leaf[2])] = "passed"
                        self.assertIn(key, v.decide(policy, damaged, [], [], now)["missing"])
                result = v.decide(policy, {}, [], [], now)
                self.assertIn(key, result["missing"])
        self.assertEqual(len(obligations), 1370)
        capacity = obligations["polaris-storage/DEV-CAPACITY/STORAGE-ASSURANCE/linux-amd64-cgo/full-rule"]
        self.assertEqual(capacity["checks"], ["gap-capacity"])

    def test_admission_lifecycle(self) -> None:
        """Lifecycle conjunctions require every native leaf; synthetic positives never qualify product behavior."""
        policy = v.decode(v.read(ROOT / "development.json"))
        obligations = v.expand(policy)
        _, dependencies = v.dependency_order(obligations)
        rules = {"DEV-ASYNC", "DEV-TIME", "DEV-RETRY", "DEV-STOP"}
        parents = {
            key: item for key, item in obligations.items() if item["component"] == "admission" and item["scenario"] == "full-rule" and item["rule"] in rules
        }
        self.assertEqual(len(parents), 4)
        self.assertEqual(v.digest(v.encode(parents)), "d80320919e2e4284b532c7cabbb6dac27447e8dc4cf5ee107e9b48a18ad8de33")
        now = dt.datetime.now(dt.timezone.utc)
        checks = v.unique(policy["checks"])
        observed = {coordinate(checks[name], item, key): "passed" for key, item in obligations.items() for name in item["checks"]}
        positive = v.decide(policy, observed, [], [], now)
        for key, parent in parents.items():
            with self.subTest(obligation=key):
                self.assertIn(key, positive["passed"])
                self.assertTrue(parent["aggregate"])
                self.assertEqual(parent["checks"], [])
                required = {obligations[child]["rule"] for child in dependencies[key]}
                self.assertLessEqual({"DEV-COVERAGE", "DEV-MODEL", "DEV-FAULT"}, required)
                for leaf in self.receipts(obligations, dependencies, key, checks):
                    # A declaration, failed child or native receipt on the wrong platform cannot complete a parent.
                    for state in (None, "failed", "unknown"):
                        damaged = dict(observed)
                        damaged.pop(leaf)
                        if state is not None:
                            damaged[leaf] = state
                        damaged[(leaf[0], "unrelated-platform", leaf[2])] = "passed"
                        self.assertIn(key, v.decide(policy, damaged, [], [], now)["missing"])
        # Capacity stays unresolved: a single in-flight RPC does not bound all host waiters or physical memory.
        capacity = obligations["admission/DEV-CAPACITY/ADMISSION-ASSURANCE/linux-amd64-cgo/full-rule"]
        self.assertEqual(capacity["checks"], ["admission-gap-capacity"])
        self.assertEqual(v.unique(policy["checks"])[capacity["checks"][0]]["adapter"], "retained-qualification")

        # Whole rule composition must retain the complete native capability base,
        # plus each rule's actual boundaries. These statuses exercise the gate only.
        common = {
            ("DEV-COVERAGE", "ADMISSION-ASSURANCE", "full-rule"),
            ("DEV-MODEL", "ADMISSION-ASSURANCE", "full-rule"),
            ("DEV-FAULT", "ADMISSION-ASSURANCE", "full-rule"),
            ("DEV-NUMERIC", "ADMISSION-ASSURANCE", "full-rule"),
        }
        boundaries = {
            "DEV-CORE": {"ADMISSION-OWNERSHIP", "ADMISSION-NODE-OPEN", "ADMISSION-NODE-STATE", "ADMISSION-NODE-SCHEDULE", "ADMISSION-NODE-TRANSPORT"},
            "DEV-CONTRACT": {"ADMISSION-SCHEDULE", "ADMISSION-NODE-OPEN", "ADMISSION-NODE-REFRESH", "ADMISSION-DIRECTORY-BOUNDARIES", "ADMISSION-CONFLICTS"},
            "DEV-SECURITY": {
                "ADMISSION-IDENTITY-RULES",
                "ADMISSION-CREDENTIALS",
                "ADMISSION-IDENTITY-FILES",
                "ADMISSION-IDENTITY-FAULT",
                "ADMISSION-NODE-STATE",
            },
            "DEV-ORACLE": {
                "ADMISSION-NODE-SENSITIVITY",
                "ADMISSION-SAME-SENSITIVITY",
                "ADMISSION-CONFLICT-SENSITIVITY",
                "ADMISSION-LOOP-SENSITIVITY",
                "ADMISSION-PREDICATE-SENSITIVITY",
                "ADMISSION-NUMERIC-SENSITIVITY",
                "ADMISSION-DRAIN-SENSITIVITY",
            },
        }
        for rule, contracts in boundaries.items():
            key = f"admission/{rule}/ADMISSION-ASSURANCE/linux-amd64-cgo/full-rule"
            parent = obligations[key]
            with self.subTest(admission_rule=rule):
                self.assertTrue(parent.get("aggregate", False), "Whole-rule qualification needs an executable conjunction, not an unresolved marker.")
                self.assertEqual(parent["checks"], [])
                children = [obligations[child] for child in dependencies[key]]
                self.assertLessEqual(common, {(child["rule"], child["contract"], child["scenario"]) for child in children})
                self.assertLessEqual(contracts, {child["contract"] for child in children})
                same_rule = {
                    reference
                    for reference, child in obligations.items()
                    if child["component"] == "admission"
                    and child["platform"] == parent["platform"]
                    and child["rule"] == rule
                    and child["scenario"] != "full-rule"
                }
                self.assertLessEqual(same_rule, set(dependencies[key]))
                self.assertIn(key, positive["passed"])
                for leaf in self.receipts(obligations, dependencies, key, checks):
                    for state in (None, "failed", "unknown"):
                        damaged = dict(observed)
                        damaged.pop(leaf)
                        if state is not None:
                            damaged[leaf] = state
                        damaged[(leaf[0], "unrelated-platform", leaf[2])] = "passed"
                        self.assertIn(key, v.decide(policy, damaged, [], [], now)["missing"])

    def test_aggregate_shape(self) -> None:
        """Reject implicit, empty, mistyped or self-certified conjunctions, while an uncovered native platform stays missing."""
        for values in (
            {"checks": []},
            {"aggregate": True},
            {"aggregate": True, "checks": [], "requires": []},
            {"aggregate": False},
            {"aggregate": 1, "checks": []},
        ):
            config = composition()
            config["components"][0]["requirements"][0].update(values)
            with self.subTest(values=values), self.assertRaises(v.Invalid):
                v.dependency_order(v.expand(config))
        config = composition()
        config["checks"][1]["platforms"] = ["linux"]
        result = v.decide(config, {("child", "linux", "CHILD"): "passed"}, [], [], dt.datetime.now(dt.timezone.utc))
        self.assertIn("fixture/DEV-COVERAGE/CHILD/windows/structure", result["missing"])

    def test_aggregate_schema(self) -> None:
        """The formal schema requires a nonempty dependency list and forbids native checks on aggregate requirements."""
        config = v.decode(v.read(ROOT / "development.json"))
        requirement = config["components"][0]["requirements"][0]
        requirement.update(aggregate=True, checks=[], requires=[{key: requirement[key] for key in ("rule", "contract", "scenario")}])
        v.schema(config, "development")
        for values in ({"aggregate": False}, {"aggregate": 1}, {"checks": ["any"]}, {"requires": []}):
            altered = copy.deepcopy(config)
            altered["components"][0]["requirements"][0].update(values)
            with self.subTest(values=values), self.assertRaises(v.Invalid):
                v.schema(altered, "development")
        for name in ("aggregate", "requires"):
            altered = copy.deepcopy(config)
            del altered["components"][0]["requirements"][0][name]
            with self.subTest(name=name), self.assertRaises(v.Invalid):
                v.schema(altered, "development")

    def test_order(self) -> None:
        """Resolve a reversed long chain iteratively, with every child before its parent."""
        config = composition(("linux",))
        component = config["components"][0]
        component["requirements"] = [
            {
                "rule": "DEV-COVERAGE",
                "contract": "CHILD",
                "scenario": "s" + str(index),
                "checks": ["child"],
                **({"requires": [{"rule": "DEV-COVERAGE", "contract": "CHILD", "scenario": "s" + str(index - 1)}]} if index else {}),
            }
            for index in reversed(range(1200))
        ]
        ordered, required = v.dependency_order(v.expand(config))
        self.assertEqual([key.rsplit("/", 1)[-1] for key in ordered], ["s" + str(index) for index in range(1200)])
        self.assertEqual(required[ordered[0]], [])
        self.assertEqual(required[ordered[-1]], [ordered[-2]])

    def test_missing(self) -> None:
        """Unknown references and duplicate edges are rejected before native statuses can pass a parent."""
        for field in ("rule", "contract", "scenario"):
            config = composition()
            config["components"][0]["requirements"][0]["requires"][0][field] = "MISSING"
            with self.subTest(field=field), self.assertRaisesRegex(v.Invalid, "obligation-dependency-missing"):
                v.dependency_order(v.expand(config))
        config = composition()
        refs = config["components"][0]["requirements"][0]["requires"]
        refs.append(copy.deepcopy(refs[0]))
        with self.assertRaisesRegex(v.Invalid, "obligation-dependency-duplicate"):
            v.dependency_order(v.expand(config))

    def test_cycle(self) -> None:
        """Reject both self-dependence and mutual cycles instead of recursive evaluation or vacuous success."""
        for mutual in (False, True):
            config = composition()
            parent, child = config["components"][0]["requirements"]
            reference = {key: parent[key] for key in ("rule", "contract", "scenario")}
            if mutual:
                child["requires"] = [reference]
            else:
                parent["requires"] = [reference]
            with self.subTest(mutual=mutual), self.assertRaisesRegex(v.Invalid, "obligation-dependency-cycle"):
                v.dependency_order(v.expand(config))

    def test_fulfillment(self) -> None:
        """Own success cannot hide a missing, failed or unfinished child, and never crosses platforms."""
        config = composition()
        parent = "fixture/DEV-COVERAGE/PARENT/linux/full-rule"
        child = "fixture/DEV-COVERAGE/CHILD/linux/structure"
        now = dt.datetime.now(dt.timezone.utc)
        for state in (None, "failed", "not-run", "passed"):
            observations = {("parent", "linux", "PARENT"): "passed", ("parent", "windows", "PARENT"): "passed"}
            if state is not None:
                observations[("child", "linux", "CHILD")] = state
            result = v.decide(config, observations, [], [], now)
            with self.subTest(state=state):
                self.assertEqual(parent in result["passed"], state == "passed")
                self.assertEqual(child in result["passed"], state == "passed")
                self.assertIn("fixture/DEV-COVERAGE/PARENT/windows/full-rule", result["missing"])
                if state != "passed":
                    self.assertIn("dependency-not-passed:" + child, result["details"][parent])
        observations = {("child", platform, "CHILD"): "passed" for platform in ("linux", "windows")}
        self.assertIn(parent, v.decide(config, observations, [], [], now)["missing"])

    def test_exception(self) -> None:
        """A valid child exemption remains an exemption and cannot certify its parent as passed."""
        config = composition(("linux",))
        parent = "fixture/DEV-COVERAGE/PARENT/linux/full-rule"
        child = "fixture/DEV-COVERAGE/CHILD/linux/structure"
        exception = {"id": "child-waiver", "obligation": child, "revoked": False, "expires_at": "2099-01-01T00:00:00Z"}
        observations = {("parent", "linux", "PARENT"): "passed"}
        result = v.decide(config, observations, [], [exception], dt.datetime.now(dt.timezone.utc))
        self.assertEqual(result["exceptions"], [child])
        self.assertNotIn(parent, result["passed"])
        self.assertIn(parent, result["missing"])
        self.assertEqual(result["status"], "blocked")

    def test_schema(self) -> None:
        """Reject invalid dependencies and keep cached schema checks separate from fresh input validation."""
        config = v.decode(v.read(ROOT / "development.json"))
        requirement = config["components"][0]["requirements"][0]
        valid = {key: requirement[key] for key in ("rule", "contract", "scenario")}
        requirement["requires"] = [valid]
        v.schema(config, "development")
        for invalid in ([], [True], [valid, valid], [{"rule": "DEV-COVERAGE"}], [{**valid, "unchecked": True}]):
            requirement["requires"] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(v.Invalid):
                v.schema(config, "development")

        from jsonschema import Draft202012Validator
        from jsonschema.exceptions import SchemaError
        from referencing.exceptions import Unresolvable

        # Literal schema/value pairs are independent of the validator's cached results.
        if hasattr(v, "_check_schema"):
            self.addCleanup(v._check_schema.cache_clear)
        with tempfile.TemporaryDirectory() as directory, patch.object(v, "SCHEMAS", Path(directory)):
            path = Path(directory) / "fixture.schema.json"
            definition = {"type": "string", "$defs": {"value": {"type": "integer"}}}
            data = v.encode(definition)
            path.write_bytes(data)
            with patch.object(Draft202012Validator, "check_schema", wraps=Draft202012Validator.check_schema) as checked:
                v.schema("first", "fixture")
                v.schema("second", "fixture")
                with self.assertRaisesRegex(v.Invalid, "schema-invalid"):
                    v.schema(0, "fixture")
                self.assertEqual(checked.call_count, 1)
                v.schema(1, "fixture", ("$defs", "value"))
                v.schema(2, "fixture", ["$defs", "value"])
                with self.assertRaisesRegex(v.Invalid, "schema-invalid"):
                    v.schema("wrong", "fixture", ("$defs", "value"))
                self.assertEqual(checked.call_count, 2)

                # Filename, length and timestamps cannot hide changed schema bytes.
                original = path.stat()
                changed = v.encode({**definition, "type": "number"})
                self.assertEqual(len(data), len(changed))
                path.write_bytes(changed)
                os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
                self.assertEqual(path.stat().st_mtime_ns, original.st_mtime_ns)
                v.schema(3, "fixture")
                with self.assertRaisesRegex(v.Invalid, "schema-invalid"):
                    v.schema("formerly valid", "fixture")
                self.assertEqual(checked.call_count, 3)

                path.write_bytes(v.encode({"type": "invalid"}))
                for _ in range(2):
                    with self.assertRaises(SchemaError):
                        v.schema(None, "fixture")
                self.assertEqual(checked.call_count, 5)
                path.write_bytes(changed)
                with patch.dict(sys.modules, {"jsonschema": None}), self.assertRaisesRegex(v.Invalid, "schema-engine-unavailable"):
                    v.schema(3, "fixture")
                with patch.object(Draft202012Validator, "check_schema", side_effect=RuntimeError("replacement checker")):
                    with self.assertRaisesRegex(RuntimeError, "replacement checker"):
                        v.schema(3, "fixture")

                remote = "https://schema.invalid/unadmitted"
                path.write_bytes(v.encode({"anyOf": [{"type": "string"}, {"$ref": remote}]}))
                v.schema("local branch", "fixture")
                with patch.object(v, "reject", wraps=v.reject) as rejected:
                    for _ in range(2):
                        with self.assertRaises(Unresolvable):
                            v.schema(None, "fixture")
                    self.assertEqual(rejected.call_args_list, [unittest.mock.call("schema-remote-reference", remote)] * 2)
                self.assertEqual(checked.call_count, 6)
                path.unlink()
                with self.assertRaises(FileNotFoundError):
                    v.schema("local branch", "fixture")

                checked.reset_mock()
                for index in range(17):
                    path.write_bytes(v.encode({"type": "integer", "title": str(index)}))
                    v.schema(index, "fixture")
                v.schema(16, "fixture")
                self.assertEqual(checked.call_count, 17)
                path.write_bytes(v.encode({"type": "integer", "title": "0"}))
                v.schema(0, "fixture")
                with self.assertRaisesRegex(v.Invalid, "schema-invalid"):
                    v.schema("wrong", "fixture")
                self.assertEqual(checked.call_count, 18)
                oversized = v.encode({"type": "integer", "description": "x" * (128 * 1024)})
                path.write_bytes(oversized)
                for _ in range(2):
                    v.schema(0, "fixture")
                self.assertEqual(checked.call_count, 20)
                path.write_bytes(b'{"type":"integer","type":"string"}')
                with self.assertRaisesRegex(v.Invalid, "duplicate-key"):
                    v.schema(0, "fixture")
                self.assertEqual(checked.call_count, 20)


class ConfigurationTests(unittest.TestCase):
    """Check strict configuration parsing and complete, bounded obligation expansion."""

    def test_strict_json(self) -> None:
        """Reject duplicate keys, invalid syntax, non-finite values, and excessive nesting."""
        for value, reason in [
            (b'{"a":1,"a":2}', "duplicate-key"),
            (b"NaN", "non-finite"),
            (b"1e999", "non-finite"),
            (b'{"a":', "json-invalid"),
            (b"[" * 40 + b"0" + b"]" * 40, "json-depth"),
        ]:
            with self.subTest(value=value), self.assertRaisesRegex(v.Invalid, reason):
                v.decode(value)

    def test_json_size(self) -> None:
        """Reject JSON above the input byte budget."""
        with self.assertRaisesRegex(v.Invalid, "json-size"):
            v.decode(b" " * (v.LIMIT + 1))

    def test_path_boundary(self) -> None:
        """Reject absolute paths and traversal while allowing ordinary relative artifact paths."""
        with tempfile.TemporaryDirectory() as directory:
            for name in ["../x", "/x", "a/../x", "a//b", "C:/x", "a\\b", "."]:
                with self.subTest(name=name), self.assertRaises(v.Invalid):
                    v.inside(directory, name)
            self.assertEqual(v.inside(directory, "safe/file"), Path(directory) / "safe/file")

    def test_symlink_boundary(self) -> None:
        """Reject symlink components that could redirect evidence access outside its root."""
        if platform.system() != "Linux":
            self.skipTest("Linux symlink fixture")
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "link").symlink_to("/tmp", target_is_directory=True)
            with self.assertRaisesRegex(v.Invalid, "path-symlink"):
                v.inside(directory, "link/file")

    def test_real_configuration(self) -> None:
        """Validate the committed pilot configuration and its required rule and assurance-level identities."""
        config, registry, pins = v.configuration(ROOT / "development.json")
        self.assertGreater(len(v.expand(config)), 4)
        self.assertEqual(len(registry["rules"]), 29)
        self.assertEqual(len(pins["policy"]), 64)
        self.assertEqual(config["components"][0]["level"], "L3")
        # Exercise the documented script entry point; importing this module alone cannot detect adapter import failures.
        environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/verify.py"), "validate"], cwd=ROOT, env=environment, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

    def test_scope_boundaries(self) -> None:
        """Keep nested ownership, prefix lookalikes, and generated exclusions distinct."""
        config = v.decode(v.read(ROOT / "development.json"))
        result = v.inventory(config, ["polaris/main.go", "polaris/internal/storage/read.go", "polaris-extra/main.go", "common/src/generated/astra.pb.cc"])
        self.assertEqual(result["components"]["polaris-server"], ["polaris/main.go"])
        self.assertEqual(result["components"]["polaris-storage"], ["polaris/internal/storage/read.go"])
        self.assertEqual(result["unowned"], ["polaris-extra/main.go"])
        self.assertEqual(result["excluded"], ["common/src/generated/astra.pb.cc"])
        config["scope"]["components"][1]["paths"].append("common")
        with self.assertRaisesRegex(v.Invalid, "scope-path-duplicate"):
            v.inventory(config, [])

    def test_unborn_source(self) -> None:
        """Bind real file hashes without inventing a commit for an initialized source mirror."""
        with tempfile.TemporaryDirectory() as directory:
            env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
            subprocess.run(["git", "init", "-q", directory], env=env, check=True, timeout=30)
            (Path(directory) / "owned.txt").write_bytes(b"owned input")
            with patch.dict(os.environ, env, clear=True):
                actual = v.source(Path(directory))
            self.assertIsNone(actual["commit"])
            self.assertEqual(actual["files"], [{"path": "owned.txt", "sha256": v.digest(b"owned input")}])

    def test_scope_cannot_extrapolate_pilot(self) -> None:
        """Identify every maintained component lacking complete qualification configuration."""
        config = v.decode(v.read(ROOT / "development.json"))
        result = v.scope(config, ROOT)
        self.assertEqual(result["unowned"], [])
        self.assertEqual(result["empty"], [])
        self.assertEqual(result["status"], "complete")
        configured = {item["id"] for item in config["components"]}
        self.assertEqual(configured, {item["id"] for item in config["scope"]["components"]})
        self.assertEqual(len(configured), 16)
        self.assertEqual(result["unconfigured"], [])
        self.assertTrue(any(check["adapter"] == "unavailable" for check in config["checks"]))

    def test_critical_capabilities(self) -> None:
        """L2 still requires decision, fault, mutation and platform coverage; admission cannot silently become L2."""
        original = v.decode(v.read(ROOT / "development.json"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "development.json"
            for scenario in ("structure", "mcdc", "mutation", "fault-matrix", "delivery-matrix"):
                with self.subTest(scenario=scenario):
                    config = copy.deepcopy(original)
                    component = config["components"][0]
                    component.update(role="component", level="L2")
                    component["requirements"] = [item for item in component["requirements"] if item["scenario"] != scenario]
                    next(item for item in config["scope"]["components"] if item["id"] == component["id"])["level"] = "L2"
                    path.write_bytes(v.encode(config))
                    with self.assertRaisesRegex(v.Invalid, "capability-missing"):
                        v.configuration(path)
            config = copy.deepcopy(original)
            next(item for item in config["components"] if item["id"] == "admission")["level"] = "L2"
            next(item for item in config["scope"]["components"] if item["id"] == "admission")["level"] = "L2"
            path.write_bytes(v.encode(config))
            with self.assertRaisesRegex(v.Invalid, "minimum-level"):
                v.configuration(path)

    def test_requirement_platforms(self) -> None:
        """Validate explicit subsets without permitting empty, foreign, or incomplete platform obligations."""
        original = v.decode(v.read(ROOT / "development.json"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "development.json"
            for targets, reason in [
                ([], "schema"),
                (["linux-amd64-cgo", "linux-amd64-cgo"], "schema"),
                (["unknown"], "requirement-platform"),
                (["windows-amd64"], "requirement-platform"),
            ]:
                with self.subTest(targets=targets):
                    config = copy.deepcopy(original)
                    config["components"][0]["requirements"][0]["platforms"] = targets
                    path.write_bytes(v.encode(config))
                    with self.assertRaisesRegex(v.Invalid, reason):
                        v.configuration(path)
            for scenario, reason in [("structure", "capability-missing"), ("full-rule", "unmapped-obligation")]:
                with self.subTest(scenario=scenario):
                    config = copy.deepcopy(original)
                    component = next(item for item in config["components"] if item["id"] == "comet")
                    requirement = next(item for item in component["requirements"] if item["scenario"] == scenario)
                    requirement["platforms"] = ["linux-amd64-cgo"]
                    path.write_bytes(v.encode(config))
                    with self.assertRaisesRegex(v.Invalid, reason):
                        v.configuration(path)

    def test_native_platform_matrix(self) -> None:
        """Every platform-specific native Comet contract retains its intended execution cell exactly once."""
        config, _, _ = v.configuration(ROOT / "development.json")
        actual = [item for item in v.expand(config).values() if item["component"] == "comet" and item["scenario"] == "native-oracle"]
        expected = {(f"COMET_NATIVE-{index}", "linux-amd64-cgo") for index in range(1, 11)}
        expected.update((f"COMET_WINDOWS-{index}", "windows-amd64") for index in range(1, 7))
        self.assertEqual({(item["contract"], item["platform"]) for item in actual}, expected)
        self.assertEqual(len(actual), len(expected))
        self.assertTrue(all(item["checks"] for item in actual))

    def test_nested_go_commands(self) -> None:
        """Bind a nested native Go selection to its declared module, package and finite flags."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = root / "sdk/go"
            module.mkdir(parents=True)
            (module / "go.mod").write_text("module example.test/sdk\n\ngo 1.27.0\n", encoding="utf-8")
            component = {"paths": ["sdk/go"]}
            check = {
                "id": "nested-go",
                "package": "example.test/sdk",
                "argv": ["go", "-C", "sdk/go", "test", "-json", "-count=1", "-p=2", "-parallel=2", "-timeout=30s", "-run=^TestInput$", "."],
            }
            v.go_command(check, component, root)
            v.go_command(dict(check, argv=[*check["argv"][:-1], "-race", "."]), component, root)
            v.go_command(dict(check, argv=["go", "test", "-json", "-count=1", "./legacy"]), component, root)
            v.go_command(dict(check, argv=["go", "test", "-race", "-json", "-count=1", "./legacy"]), component, root)
            for arguments in (
                ["go", "test", "-race", "-json", "-count=2", "./legacy"],
                ["go", "test", "-race", "-count=1", "./legacy"],
                ["go", "test", "-race", "-json", "./legacy"],
            ):
                with self.subTest(root_argv=arguments), self.assertRaisesRegex(v.Invalid, "unsupported-go-command"):
                    v.go_command(dict(check, argv=arguments), component, root)
            for name in ["../sdk/go", "/sdk/go", "sdk\\go", "sdk/./go", "sdk//go", "sdk/go/.."]:
                with self.subTest(path=name), self.assertRaisesRegex(v.Invalid, "path-"):
                    v.go_command(dict(check, argv=["go", "-C", name, *check["argv"][3:]]), component, root)
            with self.assertRaisesRegex(v.Invalid, "go-module-owner"):
                v.go_command(check, {"paths": ["other"]}, root)
            with self.assertRaisesRegex(v.Invalid, "go-module-package"):
                v.go_command(dict(check, package="example.test/other"), component, root)
            for arguments in [
                ["go", "-C"],
                ["go", "-C=sdk/go", "test", "-json", "-count=1", "."],
                ["go", "-C", "sdk/go", "build", "-json", "-count=1", "."],
                [*check["argv"][:-1], "../other"],
                [*check["argv"][:-1], "./other", "."],
                [*check["argv"][:-1], "-count=2", "."],
                [*check["argv"][:-1], "-overlay=foreign.json", "."],
                [*check["argv"][:-1], "-exec=unowned", "."],
                [*check["argv"][:-1], "-C=elsewhere", "."],
                [argument for argument in check["argv"] if argument != "-count=1"],
            ]:
                with self.subTest(argv=arguments), self.assertRaisesRegex(v.Invalid, "(?:unsupported-go-command|go-module-command)"):
                    v.go_command(dict(check, argv=arguments), component, root)
            for manifest in ("go 1.27.0\n", "module example.test/sdk\nmodule example.test/sdk\n"):
                (module / "go.mod").write_text(manifest, encoding="utf-8")
                with self.subTest(manifest=manifest), self.assertRaisesRegex(v.Invalid, "go-module-package"):
                    v.go_command(check, component, root)
            (module / "go.mod").write_bytes(b"module \xff\n")
            with self.assertRaisesRegex(v.Invalid, "go-module-encoding"):
                v.go_command(check, component, root)
            (module / "go.mod").unlink()
            with self.assertRaisesRegex(v.Invalid, "go-module-owner"):
                v.go_command(check, component, root)

    def test_comet_go_input_matrix(self) -> None:
        """Keep both native platforms and every declared input oracle in the module's contract leaf."""
        config, _, _ = v.configuration(ROOT / "development.json")
        component = next(item for item in config["components"] if item["id"] == "comet-go")
        requirements = [item for item in component["requirements"] if item["contract"] == "COMET-GO-INPUT" and item["scenario"] == "behavior"]
        expected = {"linux-amd64-cgo": "comet-go-input-linux", "windows-amd64": "comet-go-input-windows"}
        self.assertEqual({item["platforms"][0]: item["checks"][0] for item in requirements}, expected)
        self.assertTrue(all(len(item["platforms"]) == len(item["checks"]) == 1 for item in requirements))
        inventories = []
        for platform, name in expected.items():
            check = next(item for item in config["checks"] if item["id"] == name)
            self.assertEqual(check["platforms"], [platform])
            self.assertEqual(check["argv"][:5], ["go", "-C", "comet/go", "test", "-json"])
            self.assertEqual(len(check["expected_tests"]), 29)
            self.assertEqual(len(check["probes"]), 29)
            self.assertEqual(sum(probe["minimum_hits"] for probe in check["probes"]), 114)
            self.assertEqual({probe["contract"] for probe in check["probes"]}, {"COMET-GO-INPUT"})
            self.assertEqual({probe["test"] for probe in check["probes"]}, set(check["expected_tests"]))
            inventories.append(check["expected_tests"])
        self.assertEqual(inventories[0], inventories[1])

    def test_nested_go_symlink(self) -> None:
        """A declared path cannot use a symlink to substitute another module manifest."""
        if platform.system() != "Linux":
            self.skipTest("Linux symlink fixture")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "real").mkdir()
            (root / "real/go.mod").write_text("module example.test/sdk\n", encoding="utf-8")
            (root / "sdk").symlink_to(root / "real", target_is_directory=True)
            check = {"id": "nested-go", "package": "example.test/sdk", "argv": ["go", "-C", "sdk", "test", "-json", "-count=1", "."]}
            with self.assertRaisesRegex(v.Invalid, "path-symlink"):
                v.go_command(check, {"paths": ["sdk"]}, root)
            (root / "sdk").unlink()
            (root / "sdk").mkdir()
            (root / "sdk/go.mod").symlink_to(root / "real/go.mod")
            with self.assertRaisesRegex(v.Invalid, "path-symlink"):
                v.go_command(check, {"paths": ["sdk"]}, root)

    def test_closed_shapes_and_semantics(self) -> None:
        """Reject malformed policy structure, unknown identities, coverage gaps, and online test settings."""
        original = v.decode(v.read(ROOT / "development.json"))

        def unobservable(config: dict) -> None:
            """Remove a required observation, independently of optional probes appended to the check."""
            check = next(item for item in config["checks"] if item["id"] == "storage-examples")
            component = next(item for item in config["components"] if item["id"] == "polaris-storage")
            self.assertTrue(any(item["contract"] == "STORAGE-ATOMIC" and check["id"] in item["checks"] for item in component["requirements"]))
            count = len(check["probes"])
            check["probes"] = [probe for probe in check["probes"] if probe["contract"] != "STORAGE-ATOMIC"]
            self.assertEqual(len(check["probes"]), count - 1)

        mutations = {
            "unknown-field": lambda c: c.update(typo=True),
            "missing-required": lambda c: c.pop("components"),
            "ungraded": lambda c: c["components"][0].pop("level"),
            "unknown-rule": lambda c: c["components"][0]["requirements"][0].update(rule="DEV-FAKE"),
            "duplicate-check": lambda c: c["checks"].append(c["checks"][0]),
            "duplicate-go-probe": lambda c: c["checks"][0]["probes"].append(copy.deepcopy(c["checks"][0]["probes"][0])),
            "conflicting-go-probe": lambda c: c["checks"][0]["probes"].append(dict(c["checks"][0]["probes"][0], minimum_hits=999)),
            "missing-matrix": lambda c: c["components"][0].update(platforms=[]),
            "empty-obligations": lambda c: c["components"][0].update(requirements=[]),
            "unknown-platform": lambda c: c["components"][0].update(platforms=["other"]),
            "downgrade": lambda c: c["components"][0].update(level="L1"),
            "missing-l3": lambda c: c["components"][0].update(requirements=c["components"][0]["requirements"][:-6]),
            "unknown-contract": lambda c: c["components"][0]["requirements"][0].update(contract="MISSING"),
            "unobservable": unobservable,
            "online": lambda c: c["checks"][0]["environment"].update(GOPROXY="direct"),
            "credential-environment": lambda c: c["checks"][0]["environment"].update(PRIVATE_TOKEN="fixture"),
            "cached-test": lambda c: c["checks"][0]["argv"].remove("-count=1"),
            "missing-scope": lambda c: c.pop("scope"),
            "scope-tier": lambda c: c["scope"]["components"][4].update(level="L1"),
            "scope-platform": lambda c: c["scope"]["components"][4].update(platforms=["other"]),
            "scope-field": lambda c: c["scope"]["components"][4].update(unchecked=True),
            "campaign-platform": lambda c: c["campaigns"][0].update(platform="invented"),
            "campaign-forward": lambda c: c["campaigns"][0]["steps"][0].update(requires=["recovery"]),
            "campaign-placeholder": lambda c: c["campaigns"][0]["steps"][0].update(argv=["{unapproved}"]),
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "development.json"
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    config = copy.deepcopy(original)
                    mutate(config)
                    path.write_bytes(v.encode(config))
                    with self.assertRaises(v.Invalid):
                        v.configuration(path)

    def test_aggregate_rule_coverage(self) -> None:
        """Reject omitted Storage, Admission, or Command obligations from their whole-rule conjunctions."""
        original = v.decode(v.read(ROOT / "development.json"))
        self.assertEqual(len(v.expand(v.configuration(ROOT / "development.json")[0])), 1370)
        cases = (
            ("polaris-storage", "DEV-TIME", "virtual-and-host-deadlines"),
            ("polaris-storage", "DEV-FAULT", "sql-recovery"),
            ("polaris-storage", "DEV-ORACLE", "sql-recovery-inputs"),
            ("polaris-storage", "DEV-OPERATE", "online-consistent-backup"),
            ("polaris-storage", "DEV-RELEASE", "quiesced-backup-restore"),
            ("admission", "DEV-MODEL", "two-principal-finite"),
            ("admission", "DEV-MODEL", "loop-state-domain"),
            ("admission", "DEV-MODEL", "publication-state-domain"),
            ("command", "DEV-CONTRACT", "boundary-oracle"),
            ("command", "DEV-ORACLE", "typed-controls"),
            ("command", "DEV-ORACLE", "model-vectors"),
            ("command", "DEV-MATRIX", "delivery-matrix"),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "development.json"
            for component, rule, scenario in cases:
                with self.subTest(component=component, rule=rule, scenario=scenario):
                    config = copy.deepcopy(original)
                    requirements = next(item for item in config["components"] if item["id"] == component)["requirements"]
                    parent = next(item for item in requirements if item["rule"] == rule and item["scenario"] == "full-rule")
                    parent["requires"] = [item for item in parent["requires"] if item["scenario"] != scenario]
                    path.write_bytes(v.encode(config))
                    # A sole prerequisite is rejected earlier by the closed schema's nonempty-list rule.
                    reason = (
                        "aggregate-rule-coverage" if parent["requires"] else r"schema-invalid: development: /components/0/requirements/\d+/requires: minItems"
                    )
                    with self.assertRaisesRegex(v.Invalid, reason):
                        v.configuration(path)

    def test_registry_and_closure(self) -> None:
        """Resolve declared dependencies and reject invented rule IDs or dependency cycles."""
        registry = v.decode(v.read(ROOT / "tools/rules.json"))
        self.assertIn("DEV-CONTRACT", v.closure(registry, ["DEV-ASYNC"]))
        with self.assertRaisesRegex(v.Invalid, "unknown-rule"):
            v.closure(registry, ["DEV-INVENTED"])
        registry["rules"][0]["depends_on"] = [registry["rules"][0]["id"]]
        with self.assertRaisesRegex(v.Invalid, "rule-cycle"):
            v.closure(registry, [registry["rules"][0]["id"]])

    def test_schema_not_template(self) -> None:
        """Reject a self-reported template verdict as executable evidence."""
        with self.assertRaises(v.Invalid):
            v.schema({"schema_version": 2, "run_id": "TEMPLATE-NOT-EXECUTED", "gate": {"status": "eligible"}}, "evidence")

    def test_frozen_output_not_reused(self) -> None:
        """Preserve an existing failure artifact when another write attempts to replace it."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fact.json"
            v.write_new(path, {"first": "failure"})
            with self.assertRaises(FileExistsError):
                v.write_new(path, {"second": "passed"})
            self.assertEqual(v.decode(v.read(path)), {"first": "failure"})


class AuthorityTests(unittest.TestCase):
    """Check external approval identity, temporal validity, and schema boundaries."""

    def test_external_pin_expiry_revocation_and_schema(self) -> None:
        """Require the approved artifact digest and input pins, rejecting expired or revoked authority."""
        config = v.decode(v.read(ROOT / "development.json"))
        pins = {"policy": "a" * 64, "rules": "b" * 64}
        record = {
            "schema_version": 1,
            "approval_ref": "SYNTHETIC-FIXTURE",
            "expires_at": "2099-01-01T00:00:00Z",
            "revoked": False,
            "pins": v.identities(pins, ROOT, config),
            "exceptions": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authority.json"
            data = v.encode(record)
            path.write_bytes(data)
            self.assertEqual(v.authority(path, v.digest(data), pins, ROOT, config)["approval_ref"], "SYNTHETIC-FIXTURE")
            with self.assertRaisesRegex(v.Invalid, "authority-hash"):
                v.authority(path, "0" * 64, pins, ROOT, config)
            for change in [
                {"expires_at": "2000-01-01T00:00:00Z"},
                {"revoked": True},
                {"invented_approval": True},
                {"pins": {**record["pins"], "policy": "0" * 64}},
            ]:
                with self.subTest(change=change):
                    data = v.encode({**record, **change})
                    path.write_bytes(data)
                    with self.assertRaises(v.Invalid):
                        v.authority(path, v.digest(data), pins, ROOT, config)

    def test_timestamp_requires_utc_and_valid_date(self) -> None:
        """Reject non-UTC, malformed, or impossible approval timestamps."""
        for value in ["2026-09-29", "2026-09-29T00:00:00", "2026-02-30T00:00:00Z"]:
            with self.subTest(value=value), self.assertRaises(v.Invalid):
                v.stamp(value)


class ObservationTests(unittest.TestCase):
    """Check that native event streams establish real, nonempty contract observations."""

    def setUp(self) -> None:
        """Select one synthetic check with known required tests and contract probes."""
        self.check = fixture()["checks"][0]

    def test_actual_contract_hits(self) -> None:
        """Sum independent test oracles only after each declared minimum has been reached."""
        observed, failures = v.go_observations(stream(events(self.check)), self.check)
        self.assertEqual(observed, {"STORAGE-ATOMIC": 7})
        self.assertEqual(failures, [])
        check = copy.deepcopy(self.check)
        check["expected_tests"].append("TestSecond")
        check["probes"].append({"contract": "STORAGE-ATOMIC", "test": "TestSecond", "minimum_hits": 3})
        rows = events(self.check)
        second = events(dict(self.check, expected_tests=["TestSecond"]), 3)[1:-1]
        rows[-1:-1] = second
        observed, failures = v.go_observations(stream(rows), check)
        self.assertEqual(observed, {"STORAGE-ATOMIC": 10}, "shared contract must retain both independent oracle counts")
        self.assertEqual(failures, [])
        first = self.check["probes"][0]["test"]
        self.assertEqual(v.go_observations(stream(rows), check, owner=first), ({"STORAGE-ATOMIC": 7}, []))
        self.assertEqual(v.go_observations(stream(rows), check, owner="TestSecond"), ({"STORAGE-ATOMIC": 3}, []))
        for count in (1, 2, 1000):
            # Excess hits in one oracle cannot replace another oracle's independent floor.
            first, last = (1000, count) if count < 3 else (6, count)
            values = events(self.check, first)
            values[-1:-1] = events(dict(self.check, expected_tests=["TestSecond"]), last)[1:-1]
            with self.subTest(first=first, second=last):
                self.assertIn("probe-budget:STORAGE-ATOMIC", v.go_observations(stream(values), check)[1])
                self.assertIn("probe-budget:STORAGE-ATOMIC", v.go_observations(stream(values), check, owner="TestSecond")[1])
        self.assertIn("undeclared-probe", v.go_observations(stream(rows), self.check)[1])
        self.assertTrue(v.go_observations(stream(events(self.check)), check)[1])
        for count in (3, 999):
            duplicate = copy.deepcopy(check)
            duplicate["probes"].append(dict(check["probes"][-1], minimum_hits=count))
            with self.subTest(duplicate=count), self.assertRaisesRegex(v.Invalid, "go-probe-duplicate"):
                v.go_observations(stream(rows), duplicate)

    def test_non_vacuity_and_failure(self) -> None:
        """Reject missing or insufficient hits and failed or incomplete test execution."""
        for kind in ("empty", "no-marker", "budget", "skipped", "failed", "missing-terminal", "missing-test", "failed-after-marker"):
            with self.subTest(kind=kind):
                rows = events(self.check)
                if kind == "empty":
                    rows = []
                elif kind == "no-marker":
                    rows.pop(2)
                elif kind == "budget":
                    rows = events(self.check, 6)
                elif kind in ("failed", "failed-after-marker", "skipped"):
                    rows[3]["Action"] = "skip" if kind == "skipped" else "fail"
                elif kind == "missing-terminal":
                    rows.pop()
                elif kind == "missing-test":
                    rows = [rows[0], rows[-1]]
                _, failures = v.go_observations(stream(rows), self.check)
                self.assertTrue(failures)

        # A parent's pass cannot stand in for any required real-wire subtest, even when other probes have enough hits.
        check = v.unique(v.decode(v.read(ROOT / "development.json"))["checks"])["polaris-server-boundaries"]
        names = """first-empty first-inventory protocol-zero protocol-future frame-small frame-large admission-empty
        signature-short signature-changed manager-role inventory-entry inventory-scope inventory-sector inventory-spectrum
        inventory-nul inventory-long inventory-duplicate inventory-pages inventory-capacity inventory-unknown inventory-ahead
        control-empty control-hello control-probe control-ready control-plan control-snapshot control-updates ack-scope
        ack-invalid ack-unknown ack-ahead inventory-unsolicited identity-duplicate cancel-ready""".split()
        required = {"TestStreamProtocol/" + name for name in names}
        self.assertEqual(len(required), 35)
        self.assertEqual({name for name in check["expected_tests"] if name.startswith("TestStreamProtocol/")}, required)
        self.assertIn("TestStreamProtocol", check["expected_tests"])
        batches = """empty empty-page scope-missing version-zero changes-empty complete-missing scope-change version-change
        complete-extra duplicate action-missing key-empty key-nul key-long sector-empty spectrum-empty scope-internal
        version-conflict valid-replace valid-large valid-retry""".split()
        batch_names = {"TestBatchTransport/" + name for name in batches}
        self.assertEqual(len(batch_names), 21)
        self.assertEqual({name for name in check["expected_tests"] if name.startswith("TestBatchTransport/")}, batch_names)
        self.assertIn("TestBatchTransport", check["expected_tests"])
        required |= batch_names
        # Recovery children need their own terminal facts; a passing enclosing test never supplies them.
        for parent, cases in {
            "TestAssessment": "ahead concurrent-ack duplicate freeze lost-ack lost-scope lost-version overlap partial pending send-failure unknown",
            "TestReconciliation": "ahead-authority ahead-sent cancelled caught-up new-scope replay replay-new-write replay-send-failure snapshot-absent snapshot-gap snapshot-send-failure unknown",
        }.items():
            children = {parent + "/" + case for case in cases.split()}
            self.assertEqual(len(children), 12)
            self.assertEqual({name for name in check["expected_tests"] if name.startswith(parent + "/")}, children)
            self.assertIn(parent, check["expected_tests"])
            required |= children
        # Each management boundary requires its own observed terminal event.
        for parent, cases in {
            "TestStartup": "nil empty valid opaque malformed secret-empty secret-long key-long closed",
            "TestManagement": "frozen replaced send-failure nil-scope invalid-scope closed capacity missing-auth wrong-role no-deadline long-deadline expired",
            "TestPreparation": "ahead closed cancelled capacity",
            "TestAuthorityLimits": "nil-store nil-directory below minimum maximum above",
        }.items():
            children = {parent + "/" + case for case in cases.split()}
            self.assertEqual({name for name in check["expected_tests"] if name.startswith(parent + "/")}, children)
            self.assertIn(parent, check["expected_tests"])
            required |= children
        # Outbound failures and redacted categories must also have complete child terminals.
        for parent, cases in {
            "TestEmission": "updates-empty updates-corrupt updates-cancelled updates-send updates-drain snapshot-cancelled snapshot-send snapshot-ack snapshot-drain snapshot-oversize manifest-send ready-send synchronize-closed restore-capacity",
            "TestFailure": "input version history uncertain capacity cancelled deadline corrupt closed binding unavailable unknown",
            "TestCommitInput": "request-nil scope-nil single-value-nil single-erase-nil single-erase-empty single-action-missing batch-entry-nil batch-value-nil batch-erase-nil batch-erase-empty batch-action-missing credential-invalid single-replaced batch-replaced single-version batch-version single-empty single-delete batch-empty batch-delete",
            "TestFlow": "initial-receive hello-send inventory-receive initial-closed hello-replaced manifest-send synchronize-closed snapshot-send initial-drain ready-send feed-update feed-update-send feed-new feed-new-send feed-control feed-closed feed-gap idle-eof idle-control idle-cancel",
            "TestSnapshotCancellation": "waiting ready",
            "TestRefusal": "batch-nil list-unauthenticated list-closed batch-unauthenticated batch-receive batch-prefix batch-receipt load-preparation",
            "TestControl": "next-eof inventory-duplicate send-cancelled send-oversize control-nil control-replaced budget-invalid budget-progress manifest-paged manifest-refused update-erase",
            "TestDeadline": "expiry cancel-before eof-before invalid-before expiry-cancel",
            "TestExpiration": "extended cleared expired",
            "TestBusyAssessment": "resumed refused overlap closed",
            "TestStoredDamage": "inventory initial history",
            "TestPageCapacity": "negative zero below minimum maximum above",
            "TestInventoryInput": "position-nil scope-nil nil empty partial",
            "TestDrainBudget": "sixteen seventeen",
            "TestSuffix": "grouped paged history",
            "TestCredentialBounds": "other-spectrum invalid-utf8 maximum above",
            "TestCreditCapacity": "below full invalid",
            "TestBatchRevocation": "first second eof",
            "TestRecoveryLimits": "snapshot new-scope",
            "TestReceive": "eof failure cancel",
            "TestReservation": "below one two",
            "TestAuthorityBatchIncomplete": "after cancel duplicate missing scope version",
        }.items():
            children = {parent + "/" + case for case in cases.split()}
            self.assertEqual({name for name in check["expected_tests"] if name.startswith(parent + "/")}, children)
            self.assertIn(parent, check["expected_tests"])
            required |= children
        self.assertIn("TestDeadlineCapacity", check["expected_tests"])
        required.add("TestDeadlineCapacity")
        self.assertIn("TestFallback", check["expected_tests"])
        required.add("TestFallback")
        self.assertIn("TestPeriodic", check["expected_tests"])
        required.add("TestPeriodic")
        self.assertIn("TestPendingAdmission", check["expected_tests"])
        required.add("TestPendingAdmission")
        package = check["package"]
        rows = [{"Package": package, "Action": "start"}]
        for name in check["expected_tests"]:
            rows.append({"Package": package, "Action": "run", "Test": name})
            for probe in check["probes"]:
                if probe["test"] == name:
                    output = "ASTRA-CONTRACT " + json.dumps({"contract": probe["contract"], "hits": probe["minimum_hits"]}) + "\n"
                    rows.append({"Package": package, "Action": "output", "Test": name, "Output": output})
            rows.append({"Package": package, "Action": "pass", "Test": name})
        rows.append({"Package": package, "Action": "pass"})
        self.assertEqual(v.go_observations(stream(rows), check)[1], [])
        for name in sorted(required):
            # Complete omission, lost terminal observation and explicit failure each preserve a successful parent frame.
            for mode in ("missing", "unfinished", "failed", "skipped"):
                with self.subTest(test=name, mode=mode):
                    values = copy.deepcopy(rows)
                    if mode == "missing":
                        values = [row for row in values if row.get("Test") != name]
                    elif mode == "unfinished":
                        values = [row for row in values if row.get("Test") != name or row["Action"] != "pass"]
                    else:
                        next(row for row in values if row.get("Test") == name and row["Action"] == "pass")["Action"] = "fail" if mode == "failed" else "skip"
                    self.assertIn("go-required-test:" + name, v.go_observations(stream(values), check)[1])

    def test_astrolabe_entry(self) -> None:
        """Every entry child is mandatory; successful parents and unrelated package checks cannot hide omissions."""
        config = v.decode(v.read(ROOT / "development.json"))
        check = v.unique(config["checks"])["astrolabe-entry"]
        groups = {
            "TestOptions": "minimum maximum below above listen advertise advertise-invalid super galaxy group identity account public canonical plain remote-plain plain-crosssite secure-crosssite tls-public origins-limit origins-overflow origins-empty origins-duplicate unknown positional help",
            "TestStartup": "metrics identity account node handler listener",
            "TestLifecycle": "http https cancel refusal",
            "TestEntryOrigins": "valid duplicate path empty",
            "TestRemote": "tls plain",
            "TestPublicOrigin": "valid invalid",
        }
        children = {parent + "/" + name for parent, names in groups.items() for name in names.split()}
        self.assertEqual(set(check["expected_tests"]), children | groups.keys() | {"TestParse"})
        self.assertIn("-run=^(TestParse|TestOptions|TestStartup|TestLifecycle|TestEntryOrigins|TestRemote|TestPublicOrigin)$", check["argv"])
        self.assertEqual(
            check["probes"], [{"contract": "ASTROLABE-ENTRY", "test": name, "minimum_hits": 1} for name in check["expected_tests"] if name in children]
        )
        self.assertIn("-race", check["argv"])
        package = check["package"]
        rows = [{"Package": package, "Action": "start"}]
        for name in check["expected_tests"]:
            rows.append({"Package": package, "Action": "run", "Test": name})
            if name in children:
                rows.append({"Package": package, "Action": "output", "Test": name, "Output": 'ASTRA-CONTRACT {"contract":"ASTROLABE-ENTRY","hits":1}\n'})
            rows.append({"Package": package, "Action": "pass", "Test": name})
        rows.append({"Package": package, "Action": "pass"})
        self.assertEqual(v.go_observations(stream(rows), check), ({"ASTROLABE-ENTRY": 44}, []))
        for name in check["expected_tests"]:
            for mode in ("missing", "unfinished", "failed", "skipped"):
                values = copy.deepcopy(rows)
                if mode == "missing":
                    values = [row for row in values if row.get("Test") != name]
                elif mode == "unfinished":
                    values = [row for row in values if row.get("Test") != name or row["Action"] != "pass"]
                else:
                    next(row for row in values if row.get("Test") == name and row["Action"] == "pass")["Action"] = "fail" if mode == "failed" else "skip"
                with self.subTest(test=name, mode=mode):
                    self.assertIn("go-required-test:" + name, v.go_observations(stream(values), check)[1])
        key = "astrolabe/DEV-CONTRACT/ASTROLABE-ENTRY/linux-amd64-cgo/entry-boundaries"
        now = dt.datetime(2026, 10, 9, tzinfo=dt.timezone.utc)
        decision = v.decide(config, {("astrolabe-entry", "linux-amd64-cgo", "ASTROLABE-ENTRY"): "passed"}, [], [], now)
        self.assertIn(key, decision["missing"])
        self.assertEqual(decision["status"], "blocked")

    def test_astrolabe_process(self) -> None:
        """Require every real-process boundary and both entry scopes before qualifying the shared contract."""
        config = v.decode(v.read(ROOT / "development.json"))
        check = v.unique(config["checks"])["astrolabe-process"]
        children = ["TestProcess/" + name for name in "help usage startup refusal terminate interrupt pending".split()]
        self.assertEqual(check["expected_tests"], ["TestProcess", *children])
        self.assertEqual(check["probes"], [{"contract": "ASTROLABE-ENTRY", "test": name, "minimum_hits": 1} for name in children])
        self.assertIn("-run=^TestProcess$", check["argv"])
        self.assertIn("-race", check["argv"])
        package = check["package"]
        rows = [{"Package": package, "Action": "start"}]
        for name in check["expected_tests"]:
            rows.append({"Package": package, "Action": "run", "Test": name})
            if name in children:
                rows.append({"Package": package, "Action": "output", "Test": name, "Output": 'ASTRA-CONTRACT {"contract":"ASTROLABE-ENTRY","hits":1}\n'})
            rows.append({"Package": package, "Action": "pass", "Test": name})
        rows.append({"Package": package, "Action": "pass"})
        self.assertEqual(v.go_observations(stream(rows), check), ({"ASTROLABE-ENTRY": 7}, []))
        for name in check["expected_tests"]:
            for mode in ("missing", "unfinished", "failed", "skipped"):
                values = copy.deepcopy(rows)
                if mode == "missing":
                    values = [row for row in values if row.get("Test") != name]
                elif mode == "unfinished":
                    values = [row for row in values if row.get("Test") != name or row["Action"] != "pass"]
                else:
                    next(row for row in values if row.get("Test") == name and row["Action"] == "pass")["Action"] = "fail" if mode == "failed" else "skip"
                with self.subTest(test=name, mode=mode):
                    self.assertIn("go-required-test:" + name, v.go_observations(stream(values), check)[1])
        key = "astrolabe/DEV-CONTRACT/ASTROLABE-ENTRY/linux-amd64-cgo/entry-boundaries"
        observations = {(name, "linux-amd64-cgo", "ASTROLABE-ENTRY"): "passed" for name in ("astrolabe-entry", "astrolabe-process")}
        now = dt.datetime(2026, 10, 9, tzinfo=dt.timezone.utc)
        self.assertEqual(v.decide(config, observations, [], [], now)["passed"], [key])
        for observed in observations:
            for state in ("missing", "failed", "not-run", "unknown", "interrupted"):
                changed = dict(observations)
                if state == "missing":
                    del changed[observed]
                else:
                    changed[observed] = state
                with self.subTest(observation=observed, state=state):
                    self.assertIn(key, v.decide(config, changed, [], [], now)["missing"])

    def test_astrolabe_metrics(self) -> None:
        """Reject every missing native metrics boundary and preserve the original transport selection."""
        config = v.decode(v.read(ROOT / "development.json"))
        checks = v.unique(config["checks"])
        check = checks["astrolabe-metrics"]
        groups = {
            "TestTargets": "valid empty-map disabled missing directory empty array scalar key value duplicate endpoint url scheme path escaped query empty-query fragment user host ending trailing limit overflow",
            "TestMetricValues": "valid comments no-newline missing duplicate columns no-value binary leading-zero negative plus decimal overflow scanner",
            "TestScrape": "valid limit status missing duplicate identity truncated overflow partial url cancel",
            "TestMonitor": "disabled cancel closed periodic redirect",
            "TestTargetsClosing": "empty prefix",
            "TestEmptyMetrics": "",
            "TestClosedView": "",
            "TestMappedRole": "ROLE_STAR ROLE_POLARIS",
            "TestCachedFailure": "fresh failed",
        }
        children = {parent + "/" + name for parent, names in groups.items() for name in names.split()}
        probes = children | {"TestEmptyMetrics", "TestClosedView"}
        minimum = {name: 11 if name == "TestClosedView" else 1 for name in probes}
        self.assertEqual(set(check["expected_tests"]), children | groups.keys())
        self.assertEqual(len(children), 61)
        self.assertEqual(
            check["probes"],
            [{"contract": "ASTROLABE-METRICS", "test": name, "minimum_hits": minimum[name]} for name in check["expected_tests"] if name in probes],
        )
        self.assertIn(
            "-run=^(TestTargets|TestMetricValues|TestScrape|TestMonitor|TestTargetsClosing|TestEmptyMetrics|TestClosedView|TestMappedRole|TestCachedFailure)$",
            check["argv"],
        )
        self.assertIn("-race", check["argv"])
        self.assertIn("-coverprofile={run}/metrics.cover", check["argv"])
        transport = checks["astrolabe-transport"]
        parents = "TestMetricDirectory TestMetricFreshness TestMetricParsing TestMetricReplacement TestMetricScrape TestMetricTargets TestObservation TestTransport TestTransportFailures TestTransportLoad TestTransportReplacement".split()
        parents += ["TestSelection", "TestCommitInput"]
        self.assertEqual(transport["expected_tests"], parents + ["TestCommitInput/nil", "TestCommitInput/mixed", "TestEmptyCommit"])
        self.assertIn("-run=^(" + "|".join([*parents, "TestEmptyCommit"]) + ")$", transport["argv"])
        self.assertEqual(
            transport["probes"][-4:],
            [
                {"contract": "ASTROLABE-TARGET", "minimum_hits": 30, "test": "TestSelection"},
                {"contract": "ASTROLABE-TRANSPORT", "minimum_hits": 6, "test": "TestCommitInput/nil"},
                {"contract": "ASTROLABE-TRANSPORT", "minimum_hits": 6, "test": "TestCommitInput/mixed"},
                {"contract": "ASTROLABE-TRANSPORT", "minimum_hits": 2, "test": "TestEmptyCommit"},
            ],
        )
        package = check["package"]
        rows = [{"Package": package, "Action": "start"}]
        for name in check["expected_tests"]:
            rows.append({"Package": package, "Action": "run", "Test": name})
            if name in probes:
                rows.append(
                    {
                        "Package": package,
                        "Action": "output",
                        "Test": name,
                        "Output": "ASTRA-CONTRACT " + json.dumps({"contract": "ASTROLABE-METRICS", "hits": minimum[name]}) + "\n",
                    }
                )
            rows.append({"Package": package, "Action": "pass", "Test": name})
        rows.append({"Package": package, "Action": "pass"})
        self.assertEqual(v.go_observations(stream(rows), check), ({"ASTROLABE-METRICS": 73}, []))
        for name in check["expected_tests"]:
            for mode in ("missing", "unfinished", "failed", "skipped"):
                values = copy.deepcopy(rows)
                if mode == "missing":
                    values = [row for row in values if row.get("Test") != name]
                elif mode == "unfinished":
                    values = [row for row in values if row.get("Test") != name or row["Action"] != "pass"]
                else:
                    next(row for row in values if row.get("Test") == name and row["Action"] == "pass")["Action"] = "fail" if mode == "failed" else "skip"
                with self.subTest(test=name, mode=mode):
                    self.assertIn("go-required-test:" + name, v.go_observations(stream(values), check)[1])
        key = "astrolabe/DEV-CONTRACT/ASTROLABE-METRICS/linux-amd64-cgo/metrics-boundaries"
        now = dt.datetime(2026, 10, 9, tzinfo=dt.timezone.utc)
        observed = ("astrolabe-metrics", "linux-amd64-cgo", "ASTROLABE-METRICS")
        result = v.decide(config, {observed: "passed"}, [], [], now)
        self.assertEqual(result["passed"], [key])
        self.assertEqual(result["status"], "blocked")
        for state in ("missing", "failed", "not-run", "unknown", "interrupted"):
            with self.subTest(state=state):
                self.assertIn(key, v.decide(config, {observed: state}, [], [], now)["missing"])

    def test_astrolabe_web(self) -> None:
        """Require every new Web boundary and retain the original login/configuration obligation."""
        config = v.decode(v.read(ROOT / "development.json"))
        checks = v.unique(config["checks"])
        check = checks["astrolabe-web"]
        groups = {
            "TestObject": "empty-object scalar-fields field-limit field-overflow empty utf8 top-array top-null duplicate key value nested array-forbidden array-empty array-objects array-wrong-field array-scalar array-nested array-duplicate wrong-end truncated trailing whitespace unknown-field",
            "TestAccountFile": "valid missing directory limit overflow json name salt-encoding hash-encoding salt-short salt-long hash-short hash-long",
            "TestBody": "valid limit overflow unlimited media media-syntax read json",
            "TestRouting": "nodes metrics no-origin missing-session duplicate-cookie short-cookie expired head unknown origin origin-syntax duplicate-origin write-origin write-header write-duplicate write-value busy session-method almanac-method credentials-method credentials-query",
            "TestPreflight": "get post delete empty-fields missing-method unknown-method duplicate-method header missing-origin",
            "TestFailure": "deadline-read deadline-write wrapped-read wrapped-write invalid-read invalid-write aborted-read aborted-write range-read range-write capacity-read capacity-write unauthenticated-read unauthenticated-write permission-read permission-write rpc-deadline-read rpc-deadline-write rpc-cancel-read rpc-cancel-write cancel-read cancel-write unknown-read unknown-write nil-read nil-write",
            "TestReceipt": "valid nil scope sector spectrum version refusal uncertain",
            "TestInventory": "empty valid nil incomplete overflow entry scope sector spectrum duplicate failure",
            "TestLoadFailures": "nil scope sector spectrum version empty changed after-complete entry key duplicate erase nil-action value zero credential-key credential-protobuf credential-empty credential-size no-page missing-complete late-error disconnected",
            "TestLoadBudget": "keys-limit keys-overflow bytes-limit bytes-overflow busy",
            "TestCookies": "lax crosssite empty expired",
            "TestSessionInput": "json unknown username-empty username-overflow password-empty password-overflow body-overflow",
            "TestSessionAdmission": "cancelled capacity absent expired",
            "TestSessionExpiry": "before exact after expired-replacement",
            "TestValueBoundary": "single/empty single/byte single/encoding single/padding single/limit single/overflow batch/empty batch/byte batch/encoding batch/padding batch/limit batch/overflow",
            "TestOriginLimit": "31 32 33",
            "TestSessionCollision": "retry exhausted",
            "TestAccountAccess": "permission symlink",
            "TestAccountAcquisition": "replacement stat read close",
            "TestRefusal": "query-spectrum-duplicate query-spectrum-empty query-spectrum-overflow sector-empty spectrum-empty batch-value batch-erase key-empty erase-false version-invalid version-zero credential-key-empty credential-version-invalid credential-version-zero credential-secret-overflow",
            "TestAccountSuffix": "valid salt hash unknown",
            "TestArrayNames": "first last",
            "TestInputField": "batch-key almanac-unknown credential-unknown credential-suffix",
            "TestSnapshotScope": "credential sector spectrum suffix",
            "TestSecureCrosssite": "secure insecure",
            "TestHeadOrigin": "HEAD POST",
            "TestQuerySize": "valid extra",
            "TestOriginPort": "https-443 http-443 http-80 https-80",
            "TestMediaSuffix": "valid invalid",
            "TestSessionEpoch": "missing present",
        }
        children = {parent + "/" + name for parent, names in groups.items() for name in names.split()}
        self.assertEqual(len(children), 233)
        minimum = {name: 7 if name.startswith("TestRefusal/") else 1 for name in children}
        minimum.update({"TestAccountAcquisition/" + name: count for name, count in (("replacement", 7), ("stat", 6), ("read", 5), ("close", 5))})
        minimum.update({"TestSessionEpoch/" + name: 6 for name in ("missing", "present")})
        self.assertEqual(set(check["expected_tests"]), children | groups.keys())
        self.assertEqual(
            check["probes"],
            [{"contract": "ASTROLABE-BOUNDARY", "test": name, "minimum_hits": minimum[name]} for name in check["expected_tests"] if name in children],
        )
        self.assertIn("-race", check["argv"])
        self.assertIn("-coverprofile={run}/web.cover", check["argv"])
        self.assertIn("-run=^(" + "|".join(groups) + ")$", check["argv"])
        original = checks["astrolabe-boundaries"]
        parents = "TestAccount TestBatchCommit TestCommit TestCredentialRead TestCredentials TestHTTPS TestLargeBatchCommit TestLogin TestOrigin TestSessionReplacement TestSessions TestSnapshot TestVerification".split()
        self.assertEqual(original["expected_tests"], parents)
        self.assertIn("-run=^(" + "|".join(parents) + ")$", original["argv"])
        package = check["package"]
        rows = [{"Package": package, "Action": "start"}]
        for name in check["expected_tests"]:
            rows.append({"Package": package, "Action": "run", "Test": name})
            if name in children:
                rows.append(
                    {
                        "Package": package,
                        "Action": "output",
                        "Test": name,
                        "Output": "ASTRA-CONTRACT " + json.dumps({"contract": "ASTROLABE-BOUNDARY", "hits": minimum[name]}) + "\n",
                    }
                )
            rows.append({"Package": package, "Action": "pass", "Test": name})
        rows.append({"Package": package, "Action": "pass"})
        self.assertEqual(v.go_observations(stream(rows), check), ({"ASTROLABE-BOUNDARY": 352}, []))
        for name in check["expected_tests"]:
            for mode in ("missing", "unfinished", "failed", "skipped"):
                values = copy.deepcopy(rows)
                if mode == "missing":
                    values = [row for row in values if row.get("Test") != name]
                elif mode == "unfinished":
                    values = [row for row in values if row.get("Test") != name or row["Action"] != "pass"]
                else:
                    next(row for row in values if row.get("Test") == name and row["Action"] == "pass")["Action"] = "fail" if mode == "failed" else "skip"
                with self.subTest(test=name, mode=mode):
                    self.assertIn("go-required-test:" + name, v.go_observations(stream(values), check)[1])
        key = next(key for key, item in v.expand(config).items() if item["contract"] == "ASTROLABE-BOUNDARY")
        now = dt.datetime(2026, 10, 9, tzinfo=dt.timezone.utc)
        observations = {(name, "linux-amd64-cgo", "ASTROLABE-BOUNDARY"): "passed" for name in ("astrolabe-boundaries", "astrolabe-web")}
        result = v.decide(config, observations, [], [], now)
        self.assertEqual(result["passed"], [key])
        self.assertEqual(result["status"], "blocked")
        for observation in observations:
            for state in ("missing", "failed", "not-run", "unknown", "interrupted"):
                changed = {**observations, observation: state}
                with self.subTest(observation=observation, state=state):
                    self.assertIn(key, v.decide(config, changed, [], [], now)["missing"])

    def test_malformed_native_stream(self) -> None:
        """Reject invalid event shapes, identities, ordering, and probe associations."""
        mutations = {
            "duplicate": lambda rows: rows.insert(3, rows[2]),
            "wrong-package": lambda rows: rows[0].update(Package="other"),
            "out-of-order": lambda rows: rows.pop(1),
            "late-output": lambda rows: rows.append(rows[2]),
            "invalid-hit": lambda rows: rows[2].update(Output='ASTRA-CONTRACT {"contract":"STORAGE-ATOMIC","hits":true}'),
            "zero-hit": lambda rows: rows[2].update(Output='ASTRA-CONTRACT {"contract":"STORAGE-ATOMIC","hits":0}'),
            "wrong-shape": lambda rows: rows[2].update(Output=[]),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), self.assertRaises(v.Invalid):
                rows = events(self.check)
                mutate(rows)
                v.go_observations(stream(rows), self.check)

    def test_truncated_json(self) -> None:
        """Reject a truncated native event instead of accepting its completed prefix as success."""
        with self.assertRaises(v.Invalid):
            v.go_observations(stream(events(self.check))[:-4], self.check)


class DecisionTests(unittest.TestCase):
    """Check obligation coverage and bounded exceptions independently of collection."""

    def setUp(self) -> None:
        """Create fixed synthetic obligations and a deterministic evaluation time."""
        self.config = fixture()
        self.now = dt.datetime(2026, 9, 29, tzinfo=dt.timezone.utc)
        self.key = next(iter(v.expand(self.config)))
        self.observation = ("storage-examples", "linux-amd64-cgo", "STORAGE-ATOMIC")

    def result(self, observations: dict | None = None, exceptions: list[dict] | None = None, hard: list[str] | None = None) -> dict:
        """Evaluate the fixture with explicit observations and optional exceptions or hard blockers."""
        return v.decide(self.config, observations or {}, hard or [], exceptions or [], self.now)

    def exception(self) -> dict:
        """Create one scoped synthetic exception with explicit expiry and revocation overrides."""
        return {"id": "fixture", "obligation": self.key, "expires_at": "2099-01-01T00:00:00Z", "revoked": False}

    def test_passed_and_missing(self) -> None:
        """Distinguish complete observed coverage from absent required obligations."""
        self.assertEqual(self.result()["status"], "blocked")
        self.assertEqual(self.result({self.observation: "passed"})["status"], "eligible")

    def test_missing_platform(self) -> None:
        """Block a missing platform even when another platform's check passed."""
        self.config["components"][0]["platforms"].append("second-platform")
        result = self.result({self.observation: "passed"})
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(len(result["missing"]), 1)

    def test_pass_does_not_override_other_required_failure(self) -> None:
        """Require every obligated check to pass; one success cannot mask another required failure."""
        self.config["components"][0]["requirements"][0]["checks"].append("other")
        self.config["checks"].append({**self.config["checks"][0], "id": "other"})
        result = self.result({self.observation: "passed", ("other", *self.observation[1:]): "failed"})
        self.assertEqual(result["missing"], [self.key])

    def test_status_matrix(self) -> None:
        """Check every two-check status pair against conjunction, exception, and hard-block axioms."""
        self.config["components"][0]["requirements"][0]["checks"].append("other")
        self.config["checks"].append({**self.config["checks"][0], "id": "other"})
        states = (None, "passed", "failed", "not-run", "blocked", "skipped", "interrupted", "unknown")
        for first in states:
            for second in states:
                observations = {key: state for key, state in ((self.observation, first), (("other", *self.observation[1:]), second)) if state is not None}
                passed = first == second == "passed"
                for mode in ("ordinary", "exception", "expired", "hard"):
                    with self.subTest(first=first, second=second, mode=mode):
                        exceptions = []
                        if mode in ("exception", "hard"):
                            exceptions = [self.exception()]
                        elif mode == "expired":
                            exceptions = [{**self.exception(), "expires_at": "2026-09-29T00:00:00Z"}]
                        exempt = not passed and mode in ("exception", "hard")
                        hard = ["fixture-integrity-failure"] if mode == "hard" else []
                        expected = "blocked" if hard or not (passed or exempt) else "eligible-with-exceptions" if exempt else "eligible"
                        result = self.result(observations, exceptions, hard)
                        self.assertEqual(result["status"], expected)
                        self.assertEqual(result["required"], [self.key])
                        self.assertEqual(result["passed"], [self.key] if passed else [])
                        self.assertEqual(result["exceptions"], [self.key] if exempt else [])
                        self.assertEqual(result["missing"], [] if passed or exempt else [self.key])
                        self.assertEqual(result["hard"], hard)

    def test_platform_selection(self) -> None:
        """Platform-specific cases never satisfy another platform and a missing variant remains blocked."""
        self.config["components"][0]["platforms"].append("windows-amd64")
        self.config["checks"][0]["platforms"] = ["linux-amd64-cgo"]
        self.assertEqual(self.result({self.observation: "passed"})["status"], "blocked")
        self.assertEqual(len(self.result({self.observation: "passed"})["missing"]), 1)
        self.config["checks"].append({**self.config["checks"][0], "id": "windows", "platforms": ["windows-amd64"]})
        self.config["components"][0]["requirements"][0]["checks"].append("windows")
        observed = {self.observation: "passed", ("windows", "windows-amd64", self.observation[2]): "passed"}
        self.assertEqual(self.result(observed)["status"], "eligible")

    def test_explicit_platforms(self) -> None:
        """An explicit requirement subset avoids invented cells without inferring scope from observed checks."""
        component = self.config["components"][0]
        component["platforms"].append("windows-amd64")
        component["requirements"][0]["platforms"] = ["linux-amd64-cgo"]
        self.config["checks"][0]["platforms"] = ["linux-amd64-cgo"]
        result = self.result({self.observation: "passed"})
        self.assertEqual(result["required"], [self.key])
        self.assertEqual(result["status"], "eligible")
        component["requirements"][0]["platforms"] = ["windows-amd64"]
        result = self.result({self.observation: "passed"})
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(len(result["missing"]), 1)
        self.assertEqual(next(iter(result["details"].values())), [])

    def test_exception_scope_expiry_and_revocation(self) -> None:
        """Apply only unexpired, unrevoked exceptions scoped to declared obligations."""
        self.assertEqual(self.result(exceptions=[self.exception()])["status"], "eligible-with-exceptions")
        for change in [{"expires_at": "2026-09-29T00:00:00Z"}, {"revoked": True}, {"obligation": "unknown"}]:
            with self.subTest(change=change):
                exception = {**self.exception(), **change}
                self.assertEqual(self.result(exceptions=[exception])["status"], "blocked")

    def test_hard_block_not_waived(self) -> None:
        """Keep hard evidence failures blocking even when an obligation has an exception."""
        self.assertEqual(self.result(exceptions=[self.exception()], hard=["source-changed"])["status"], "blocked")


class EvidenceTests(unittest.TestCase):
    """Check artifact integrity, source identity, trust requirements, and complete evidence coverage."""

    def setUp(self) -> None:
        """Build isolated synthetic source and evidence records with internally consistent digests."""
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.config = fixture()
        self.check = self.config["checks"][0]
        self.pins = {"policy": "a" * 64, "rules": "b" * 64}
        self.approved = {"pins": {"collector": "c" * 64}, "artifact_sha256": "d" * 64, "exceptions": []}
        self.source = {"commit": "fixture-only", "files": [{"path": "polaris/internal/storage/fixture.go", "sha256": "f" * 64}], "status": "fixture-only"}
        self.evidence = {
            "schema_version": 1,
            "run_id": "00000000-0000-4000-8000-000000000000",
            "kind": "native-local",
            "trust": "local",
            "platform": "linux-amd64-cgo",
            "system": "Linux",
            "machine": "x86_64",
            **self.pins,
            "collector": "c" * 64,
            "authority_sha256": "d" * 64,
            "authorization_ref": "SYNTHETIC-FIXTURE-NOT-PILOT",
            "started_at": "2026-09-29T00:00:00Z",
            "finished_at": "2026-09-29T00:00:01Z",
            "engine": {"python": "fixture", "jsonschema": "fixture"},
            "source_before": v.write_new(self.directory / "before.json", self.source),
            "source_after": v.write_new(self.directory / "after.json", self.source),
            "checks": [
                {
                    "id": "storage-examples",
                    "platform": "linux-amd64-cgo",
                    "argv": self.check["argv"],
                    "environment": self.check["environment"],
                    "resolved_environment": self.check["environment"],
                    "executable": "/fixture/go",
                    "executable_sha256": "e" * 64,
                    "toolchain": {"command": {"path": "/fixture/go", "sha256": "e" * 64}},
                    "started_at": "2026-09-29T00:00:00Z",
                    "finished_at": "2026-09-29T00:00:01Z",
                    "duration_ms": 1000,
                    "exit_code": 0,
                    "termination": "exited",
                    "complete": True,
                    "cleanup": True,
                    "stdout": v.write_new(self.directory / "stdout.log", stream(events(self.check))),
                    "stderr": v.write_new(self.directory / "stderr.log", b""),
                }
            ],
        }
        self.evidence["resources"] = {"cpus": 4, "available_bytes": 8 * 1024**3, "build_jobs": 4, "test_jobs": 4, "disk_free_bytes": 1024**3}

    def seal(self, directory: Path, evidence: dict) -> None:
        """Write synthetic fixture records; this helper cannot create native acceptance evidence."""
        evidence["records"] = []
        for index, record in enumerate(evidence["checks"]):
            path = directory / f"native-{index}.json"
            data = v.encode(record)
            path.write_bytes(data)
            evidence["records"].append({"path": path.name, "bytes": len(data), "sha256": v.digest(data)})
        (directory / "evidence.json").write_bytes(v.encode(evidence))

    def evaluate(self, directories: Path | list[Path] | None = None) -> dict:
        """Evaluate only the synthetic fixture with its explicit source-identity boundary."""
        self.seal(self.directory, self.evidence)
        with patch.object(v, "source", return_value=self.source):
            return v.gate(self.config, self.pins, self.approved, self.directory if directories is None else directories)

    def split(self) -> tuple[Path, dict]:
        """Require the same synthetic contract on a second platform, with a distinct original run identity."""
        second = self.directory / "second"
        second.mkdir()
        for name in ("before.json", "after.json", "stdout.log", "stderr.log"):
            (second / name).write_bytes((self.directory / name).read_bytes())
        target = "windows-amd64"
        self.config["components"][0]["platforms"].append(target)
        self.config["scope"]["components"][0]["platforms"].append(target)
        evidence = copy.deepcopy(self.evidence)
        evidence.update(run_id="00000000-0000-4000-8000-000000000001", platform=target, system="Windows", machine="AMD64")
        for record in evidence["checks"]:
            record["platform"] = target
        self.seal(second, evidence)
        return second, evidence

    def test_positive_fixture(self) -> None:
        """Require all platform cells, then join verified collections independently of their supplied order."""
        self.assertEqual(self.evaluate()["status"], "eligible")
        second, evidence = self.split()
        self.assertEqual(self.evaluate()["status"], "blocked")
        directories = [self.directory, second]
        forward = self.evaluate(directories)
        backward = self.evaluate(list(reversed(directories)))
        self.assertEqual(forward["status"], "eligible")
        self.assertEqual(forward["passed"], backward["passed"])
        self.assertEqual(len(forward["passed"]), 2)
        self.assertEqual({row["run_id"] for row in forward["evidence"]}, {self.evidence["run_id"], evidence["run_id"]})
        self.assertEqual(forward["evidence"][1]["sha256"], v.digest(v.read(second / "evidence.json")))
        # Different required checks may also be collected separately on one platform.
        self.config["components"][0]["platforms"].pop()
        self.config["scope"]["components"][0]["platforms"].pop()
        other = copy.deepcopy(self.check)
        other["id"] = "second-check"
        self.config["checks"].append(other)
        self.config["components"][0]["requirements"][0]["checks"].append(other["id"])
        evidence.update(platform="linux-amd64-cgo", system="Linux", machine="x86_64")
        evidence["checks"][0].update(id=other["id"], platform="linux-amd64-cgo")
        self.seal(second, evidence)
        self.assertEqual(self.evaluate()["status"], "blocked")
        self.assertEqual(self.evaluate(directories)["status"], "eligible")
        output = io.StringIO()
        with (
            patch.object(v, "source", return_value=self.source),
            patch.object(v, "configuration", return_value=(self.config, {}, self.pins)),
            patch.object(v, "authority", return_value=copy.deepcopy(self.approved)),
            contextlib.redirect_stdout(output),
        ):
            code = v.main(["gate", "--authority", str(self.directory / "fixture-authority.json"), "--authority-sha256", "d" * 64, *map(str, directories)])
        self.assertEqual(code, 0)
        report = v.decode(output.getvalue().encode())
        self.assertEqual(len(report["evidence"]), 2)
        self.assertEqual(report["evidence"], report["gate"]["evidence"])
        saved = list(self.directory.glob("gate-*.json"))
        self.assertEqual(len(saved), 1)
        self.assertEqual(v.decode(v.read(saved[0])), report)

    def test_scope_gap_blocks_passed_fixture(self) -> None:
        """A passing registered check cannot qualify unowned inputs or unregistered components."""
        self.config["scope"]["components"].append({"id": "other", "level": "L2", "paths": ["other"], "platforms": ["linux-amd64-cgo"]})
        result = self.evaluate()
        self.assertEqual(result["status"], "blocked")
        self.assertIn("scope-unconfigured:other", result["hard"])
        self.assertIn("scope-empty:other", result["hard"])
        self.source["files"].append({"path": "unowned.py", "sha256": "0" * 64})
        self.assertIn("scope-unowned:unowned.py", self.evaluate()["hard"])

    def test_native_failures_remain_blocking(self) -> None:
        """Block failed, interrupted, truncated, or unclean native execution records."""
        second, evidence = self.split()
        for changes in [
            {"exit_code": 1},
            {"complete": False},
            {"cleanup": False},
            {"termination": "interrupted"},
            {"termination": "timeout"},
            {"duration_ms": 999999},
        ]:
            with self.subTest(changes=changes):
                original = self.evidence["checks"][0].copy()
                self.evidence["checks"][0].update(changes)
                self.assertEqual(self.evaluate()["status"], "blocked")
                self.assertEqual(self.evaluate([self.directory, second])["status"], "blocked")
                self.evidence["checks"][0] = original
                evidence["checks"][0].update(changes)
                self.seal(second, evidence)
                self.assertEqual(self.evaluate([self.directory, second])["status"], "blocked")
                evidence["checks"][0] = dict(original, platform="windows-amd64")
                self.seal(second, evidence)

    def test_integrity_rejected(self) -> None:
        """Reject artifact bytes that no longer match their sealed reference."""
        second, _ = self.split()
        (second / "stdout.log").write_bytes(b"replaced")
        with self.assertRaisesRegex(v.Invalid, "artifact-integrity"):
            self.evaluate([self.directory, second])
        (self.directory / "stdout.log").write_bytes(b"replaced")
        with self.assertRaisesRegex(v.Invalid, "artifact-integrity"):
            self.evaluate()

    def test_duplicate_attempt_and_self_report_rejected(self) -> None:
        """Reject duplicate attempts and unsupported self-reported evidence forms."""
        second, evidence = self.split()
        for directories, cause in (
            ([], "evidence-bundle-count"),
            ([self.directory] * 257, "evidence-bundle-count"),
            ([self.directory] * 2, "duplicate-evidence-directory"),
        ):
            with self.subTest(cause=cause), self.assertRaisesRegex(v.Invalid, cause):
                self.evaluate(directories)
        original = copy.deepcopy(evidence)
        evidence["run_id"] = self.evidence["run_id"]
        self.seal(second, evidence)
        with self.assertRaisesRegex(v.Invalid, "duplicate-evidence-run"):
            self.evaluate([self.directory, second])
        evidence = copy.deepcopy(original)
        evidence.update(platform="linux-amd64-cgo", system="Linux", machine="x86_64")
        evidence["checks"][0]["platform"] = "linux-amd64-cgo"
        for code in (0, 1):
            evidence["checks"][0]["exit_code"] = code
            self.seal(second, evidence)
            for directories in ([self.directory, second], [second, self.directory]):
                with self.subTest(code=code, directories=directories), self.assertRaisesRegex(v.Invalid, "duplicate-evidence-check"):
                    self.evaluate(directories)
        self.evidence["checks"].append(copy.deepcopy(self.evidence["checks"][0]))
        with self.assertRaisesRegex(v.Invalid, "duplicate-or-unknown-check"):
            self.evaluate()
        self.evidence["checks"].pop()
        self.evidence["gate"] = {"status": "eligible"}
        with self.assertRaisesRegex(v.Invalid, "schema-invalid"):
            self.evaluate()

    def test_trust_and_convergence_gaps(self) -> None:
        """Keep insufficient evidence trust and unresolved convergence requirements visible as blockers."""
        second, evidence = self.split()
        self.config["components"][0]["evidence_trust"] = "ci"
        self.config["components"][0]["convergence"]["baseline"] = None
        result = self.evaluate()
        self.assertEqual(result["status"], "blocked")
        self.assertIn("trust-gap:polaris-storage", result["hard"])
        self.assertIn("convergence-unconfirmed:polaris-storage", result["hard"])
        result = self.evaluate([self.directory, second])
        self.assertIn("trust-gap:polaris-storage", result["hard"])
        self.assertIn("convergence-unconfirmed:polaris-storage", result["hard"])
        for field in ("policy", "rules", "collector", "authority_sha256"):
            original = evidence[field]
            evidence[field] = "0" * 64
            self.seal(second, evidence)
            with self.subTest(field=field):
                if field == "authority_sha256":
                    self.assertIn("authority-mismatch", self.evaluate([self.directory, second])["hard"])
                else:
                    with self.assertRaisesRegex(v.Invalid, "evidence-(policy|collector)"):
                        self.evaluate([self.directory, second])
            evidence[field] = original

    def test_actual_source_mismatch(self) -> None:
        """Reject evidence whose source identity differs from the workspace under evaluation."""
        second, evidence = self.split()
        changed = copy.deepcopy(self.source)
        changed["files"][0]["sha256"] = "0" * 64
        for name in ("source_before", "source_after"):
            evidence[name] = v.write_new(second / (name + ".json"), changed)
        self.seal(second, evidence)
        self.assertIn("source-changed", self.evaluate([self.directory, second])["hard"])
        self.seal(self.directory, self.evidence)
        with patch.object(v, "source", side_effect=[self.source, changed]):
            self.assertIn("source-changed", v.gate(self.config, self.pins, self.approved, self.directory)["hard"])
        self.source["commit"] = "changed"
        self.assertIn("source-changed", self.evaluate()["hard"])

    def test_missing_record_not_green(self) -> None:
        """Block missing raw execution records rather than trusting the summary alone."""
        second, _ = self.split()
        self.evidence["checks"] = []
        self.assertEqual(self.evaluate()["status"], "blocked")
        self.assertIn("no-native-executions", self.evaluate([self.directory, second])["hard"])


@unittest.skipUnless(platform.system() == "Linux", "Linux collector lifecycle")
class CollectorTests(unittest.TestCase):
    """Exercise isolated native collector lifecycle failures without treating fixture output as release evidence."""

    def test_process_exit_timeout_output_limit_and_orphan(self) -> None:
        # Enable subreaping in a separate collector for each case without adopting unrelated children of the test framework.
        """Distinguish exit, timeout, output overflow, and orphan cleanup in separately owned collectors."""
        script = """
import ctypes, json, pathlib, sys
from tools import verify as v
assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
root=pathlib.Path(sys.argv[1]); directory=root/'build'; directory.mkdir()
check={'id':'native','argv':[sys.executable,'-c',sys.argv[2]],'environment':{'SYNTHETIC_SECRET':'not-a-real-credential-collector-test'},'timeout_s':1,'log_bytes':1024}
record=v.execute(check,root,directory,'fixture')
print(json.dumps({'record':record,'remaining':v.owned_members()}))
"""
        cases = [
            ("import os; assert 'SYNTHETIC_SECRET' not in os.environ; print('complete')", "exited", True),
            ("import time; time.sleep(30)", "timeout", False),
            ("print('x'*2048)", "log-limit", False),
            ("import os,time; child=os.fork(); os._exit(0) if child else None; os.setsid(); time.sleep(30)", "timeout", False),
        ]
        for code, termination, complete in cases:
            with self.subTest(termination=termination, code=code), tempfile.TemporaryDirectory() as directory:
                result = subprocess.run([sys.executable, "-B", "-c", script, directory, code], cwd=ROOT, capture_output=True, timeout=15, check=True)
                value = json.loads(result.stdout)
                self.assertEqual(value["record"]["termination"], termination)
                self.assertEqual(value["record"]["complete"], complete)
                self.assertTrue(value["record"]["cleanup"])
                self.assertEqual(value["remaining"], [])
                self.assertNotIn(b"not-a-real-credential-collector-test", result.stdout)
                if complete:
                    self.assertEqual(value["record"]["exit_code"], 0)


class EnvironmentTests(unittest.TestCase):
    """Do not let campaign callers turn native evidence into a dump of inherited secrets."""

    def test_allowlist(self) -> None:
        """Preserve required offline tool inputs while removing credentials and implicit Python injection."""
        selected = {"PATH": "/tools", "ASTRA_CACHE_ROOT": "/cache", "GIT_INDEX_FILE": "/private-index", "GOPROXY": "off"}
        values = {**selected, "PRIVATE_TOKEN": "fixture", "AWS_SECRET_ACCESS_KEY": "fixture", "PYTHONPATH": "/untrusted"}
        self.assertEqual(v.public_environment(values), selected)
        self.assertIn("PRIVATE_TOKEN", values)

    def test_namespace(self) -> None:
        """Admit the canonical Windows system key without admitting mixed-case or secret names."""
        selected = {"SYSTEMROOT": "C:\\Windows", "PATH": "/tools", "CMAKE_GENERATOR": "fixture-generator", "CMAKE_GENERATOR_INSTANCE": "/fixture-tools"}
        values = {**selected, "SystemRoot": "wrong-case", "SYSTEMDRIVE": "Z:", "PRIVATE_TOKEN": "fixture", "PROGRAMFILES(X86)": "unregistered"}
        self.assertEqual(v.public_environment(values), selected)
        for field in ("environment", "resolved_environment"):
            v.schema(selected, "evidence", ("properties", "checks", "items", "properties", field))
            with self.assertRaises(v.Invalid):
                v.schema({"SystemRoot": "C:\\Windows"}, "evidence", ("properties", "checks", "items", "properties", field))
            with self.assertRaises(v.Invalid):
                v.schema({"PROGRAMFILES(X64)": "C:\\Tools"}, "evidence", ("properties", "checks", "items", "properties", field))
        v.schema({"PROGRAMFILES(X86)": "C:\\Tools"}, "evidence", ("properties", "checks", "items", "properties", "resolved_environment"))
        with self.assertRaises(v.Invalid):
            v.schema({"PROGRAMFILES(X86)": "C:\\Tools"}, "evidence", ("properties", "checks", "items", "properties", "environment"))

    def test_native_environment(self) -> None:
        """Require real child inputs to match the unchanged formal namespace with HOME absent."""
        inputs = {"PATH": os.environ.get("PATH", os.defpath)}
        if os.name == "nt":
            inputs["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
        (ROOT / "build/tmp").mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "build/tmp") as temporary, patch.dict(os.environ, inputs, clear=True):
            directory = Path(temporary) / "native"
            directory.mkdir()
            command = {
                "id": "environment",
                "argv": [
                    sys.executable,
                    "-B",
                    "-c",
                    "import ctypes,json,os\n"
                    "common=None\n"
                    "if os.name == 'nt':\n"
                    "    buffer=ctypes.create_unicode_buffer(260)\n"
                    "    status=ctypes.WinDLL('shell32').SHGetFolderPathW(None,35,None,0,buffer)\n"
                    "    assert status == 0, status\n"
                    "    common=buffer.value\n"
                    "print(json.dumps({'home': 'HOME' in os.environ, 'secret': 'PRIVATE_TOKEN' in os.environ, 'system': 'SYSTEMROOT' in os.environ, 'drive': os.environ.get('SYSTEMDRIVE'), 'common': common, 'generator': os.environ.get('CMAKE_GENERATOR'), 'instance': os.environ.get('CMAKE_GENERATOR_INSTANCE')}))",
                ],
                "environment": {
                    "PRIVATE_TOKEN": "not-a-real-secret",
                    "SYSTEMDRIVE": "Z:",
                    "CMAKE_GENERATOR": "fixture-generator",
                    "CMAKE_GENERATOR_INSTANCE": "/fixture-tools",
                },
                "timeout_s": 10,
                "log_bytes": 4096,
            }
            record = v.execute(command, ROOT, directory, "fixture")
            self.assertEqual(record["exit_code"], 0)
            self.assertTrue(record["complete"] and record["cleanup"])
            for field in ("environment", "resolved_environment"):
                v.schema(record[field], "evidence", ("properties", "checks", "items", "properties", field))
            self.assertNotIn("HOME", record["resolved_environment"])
            self.assertNotIn("SystemRoot", record["resolved_environment"])
            child = v.decode(v.reference(directory, record["stdout"]))
            expected = {
                "home": False,
                "secret": False,
                "system": os.name == "nt",
                "drive": Path(inputs["SYSTEMROOT"]).drive if os.name == "nt" else None,
                "common": child["common"],
                "generator": "fixture-generator",
                "instance": "/fixture-tools",
            }
            self.assertEqual(child, expected)
            if os.name == "nt":
                self.assertEqual(record["resolved_environment"]["SYSTEMDRIVE"], expected["drive"])
                self.assertTrue(child["common"] and Path(child["common"]).is_absolute() and Path(child["common"]).is_dir())
            else:
                self.assertIsNone(child["common"])
            self.assertNotIn(b"not-a-real-secret", v.encode(record))

    def test_empty_environment(self) -> None:
        """Reject a schema-invalid declared input before any child can produce a side effect."""
        (ROOT / "build/tmp").mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "build/tmp") as temporary:
            directory = Path(temporary) / "native"
            directory.mkdir()
            marker = directory / "launched"
            command = {
                "id": "environment",
                "argv": [sys.executable, "-B", "-c", "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('launched')", str(marker)],
                "environment": {"HOME": ""},
                "timeout_s": 10,
                "log_bytes": 4096,
            }
            with self.assertRaises(v.Invalid):
                v.execute(command, ROOT, directory, "fixture")
            self.assertFalse(marker.exists())
            self.assertFalse((directory / "environment.process.json").exists())

    def test_host_paths(self) -> None:
        """Preserve actual Windows folders and exclude them on other hosts, rejecting caller substitutions and secrets."""
        names = ("COMSPEC", "WINDIR", "PATHEXT", "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMDATA", "USERPROFILE", "APPDATA", "LOCALAPPDATA")
        expected = {name: os.environ[name] if os.name == "nt" else None for name in names}
        if os.name == "nt":
            self.assertTrue(all(expected.values()))
        else:
            self.assertTrue(all(value is None for value in expected.values()))
        inherited = {"PRIVATE_TOKEN": "not-a-real-host-secret"}
        if os.name != "nt":
            inherited.update(dict.fromkeys(names, "not-a-real-host-path"))
        (ROOT / "build/tmp").mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "build/tmp") as temporary, patch.dict(os.environ, inherited):
            directory = Path(temporary) / "native"
            directory.mkdir()
            command = {
                "id": "environment",
                "argv": [
                    "python3" if os.name == "nt" else sys.executable,
                    "-B",
                    "-c",
                    "import json,os,sys; print(json.dumps({name:os.environ.get(name) for name in json.loads(sys.argv[1])}))",
                    json.dumps((*names, "PRIVATE_TOKEN")),
                ],
                "environment": {**dict.fromkeys(names, "untrusted-host-path"), "PRIVATE_TOKEN": "not-a-real-caller-secret"},
                "timeout_s": 10,
                "log_bytes": 4096,
            }
            record = v.execute(command, ROOT, directory, "windows-amd64" if os.name == "nt" else "linux-amd64-cgo")
            self.assertEqual(record["exit_code"], 0)
            self.assertTrue(record["complete"] and record["cleanup"])
            self.assertEqual(v.decode(v.reference(directory, record["stdout"])), {**expected, "PRIVATE_TOKEN": None})
            self.assertEqual(record["executable"], sys.executable)
            self.assertEqual(record["executable_sha256"], v.file_digest(Path(sys.executable)))
            self.assertEqual(record["argv"][0], "python3" if os.name == "nt" else sys.executable)
            if os.name == "nt":
                self.assertEqual({name: record["resolved_environment"][name] for name in names}, expected)
            else:
                self.assertTrue(all(name not in record["resolved_environment"] for name in names))
            self.assertTrue(all(name not in record["environment"] for name in names))
            for field in ("environment", "resolved_environment"):
                v.schema(record[field], "evidence", ("properties", "checks", "items", "properties", field))
            self.assertNotIn(b"untrusted-host-path", v.encode(record))
            self.assertNotIn(b"not-a-real-host-secret", v.encode(record))
            self.assertNotIn(b"not-a-real-caller-secret", v.encode(record))
            self.assertNotIn(b"not-a-real-host-path", v.encode(record))


if __name__ == "__main__":
    unittest.main()
