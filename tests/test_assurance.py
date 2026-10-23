"""Check campaign dependency expansion without executing builds or accepting release evidence."""

import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import assurance, verify


class AssuranceTests(unittest.TestCase):
    """Keep prerequisites mandatory and partial campaigns distinct from full qualification."""

    def test_host(self) -> None:
        """A Linux arm64 run cannot be recorded as Linux x86_64 or Windows."""
        config = {"platforms": [{"id": "linux", "system": "Linux", "machine": "x86_64"}]}
        with patch.object(assurance.platform, "system", return_value="Linux"), patch.object(assurance.platform, "machine", return_value="x86_64"):
            assurance.host(config, {"platform": "linux"})
        for system, machine in (("Linux", "aarch64"), ("Windows", "AMD64")):
            with patch.object(assurance.platform, "system", return_value=system), patch.object(assurance.platform, "machine", return_value=machine):
                with self.assertRaises(verify.Invalid):
                    assurance.host(config, {"platform": "linux"})

    def test_prerequisites(self) -> None:
        """Selecting a benchmark includes its required build; misspelled and cyclic dependencies fail closed."""
        root = Path(__file__).resolve().parents[1]
        config = verify.decode(verify.read(root / "development.json"))
        campaign = config["campaigns"][0]
        chosen = assurance.select(campaign, ["performance"])
        self.assertEqual([item["id"] for item in chosen], ["release", "performance"])
        self.assertEqual(len(assurance.select(campaign, None)), len(campaign["steps"]))
        with self.assertRaises(verify.Invalid):
            assurance.select(campaign, ["invented"])
        changed = copy.deepcopy(campaign)
        changed["steps"][0]["requires"] = [changed["steps"][-1]["id"]]
        with self.assertRaises(verify.Invalid):
            assurance.select(changed, None)

    def fixture(self, root: Path) -> tuple[dict, dict, dict]:
        """Create synthetic planning inputs; these records never represent native acceptance evidence."""
        config = {
            "scope": {"components": [{"id": "core", "paths": ["src"]}], "exclusions": []},
            "checks": [{"id": "pending", "adapter": "unavailable"}],
            "components": [
                {
                    "id": "core",
                    "platforms": ["linux"],
                    "requirements": [{"rule": rule, "contract": "STATE", "scenario": "full-rule", "checks": ["pending"]} for rule in ("DEV-CORE", "DEV-FAULT")],
                }
            ],
        }
        (root / "development.json").write_bytes(verify.encode(config))
        record = root / "build/results/retained/record.json"
        record.parent.mkdir(parents=True)
        record.write_bytes(b'{"synthetic":true}\n')
        source = {"commit": "1" * 40, "status": " M src/state.py", "files": [{"path": "src/state.py", "sha256": "2" * 64}]}
        baseline = {
            "configuration_sha256": verify.file_digest(root / "development.json"),
            "source": source,
            "checks": [{"check": "old", "platform": "linux", "record": str(record), "record_sha256": verify.file_digest(record)}],
            "gate": {
                "status": "blocked",
                "required": sorted(verify.expand(config)),
                "passed": [],
                "missing": sorted(verify.expand(config)),
                "exceptions": [],
                "hard": ["authority-not-issued"],
            },
        }
        return config, baseline, copy.deepcopy(source)

    def test_review(self) -> None:
        """One missing executor groups multiple obligations; unchanged records never become a new gate pass."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, baseline, current = self.fixture(root)
            result = assurance.review(config, baseline, current, root)
            self.assertEqual(result["qualification"], "not-evaluated")
            self.assertEqual(result["execution"], "none")
            self.assertEqual(result["changed_files"], [])
            self.assertTrue(result["configuration_unchanged"])
            self.assertEqual(result["baseline_gate"], {"status": "blocked", "hard": ["authority-not-issued"]})
            self.assertEqual(len(result["work"]), 1)
            self.assertEqual(result["work"][0]["obligations"], baseline["gate"]["missing"])
            self.assertEqual(result["work"][0]["action"], "implement-proof")
            self.assertEqual(result["retained_records"], baseline["checks"])
            current["files"] = [{"path": "src/new.py", "sha256": "3" * 64}, {"path": "unknown.py", "sha256": "4" * 64}]
            # The commit and dirty-status text remain identical; additions and removals must still invalidate source identity.
            result = assurance.review(config, baseline, current, root)
            self.assertEqual(result["changed_files"], ["src/new.py", "src/state.py", "unknown.py"])
            self.assertEqual(result["changed_owners"]["components"], {"core": ["src/new.py", "src/state.py"]})
            self.assertEqual(result["changed_owners"]["unowned"], ["unknown.py"])
            self.assertEqual(baseline["source"]["files"], [{"path": "src/state.py", "sha256": "2" * 64}])
            (root / "development.json").write_bytes(b"{}")
            self.assertFalse(assurance.review(config, baseline, current, root)["configuration_unchanged"])
            # A strengthened requirement keeps its ID but must not inherit the old work-plan omission.
            key = baseline["gate"]["missing"].pop(0)
            baseline["gate"]["passed"] = [key]
            expanded = copy.deepcopy(config)
            expanded["checks"].append({"id": "entry", "adapter": "unavailable"})
            expanded["components"][0]["requirements"][0]["checks"].append("entry")
            (root / "development.json").write_bytes(verify.encode(expanded))
            reviewed = assurance.review(expanded, baseline, current, root)
            self.assertIn("entry", [item["check"] for item in reviewed["work"]], "Missing strengthened executor in plan")
            self.assertEqual(reviewed["policy_review"], [key])
            self.assertEqual(next(item for item in reviewed["work"] if item["check"] == "entry")["obligations"], [key])
            self.assertEqual(reviewed["baseline_counts"]["passed"], 1, "Policy review must not rewrite original outcomes")
            self.assertEqual(reviewed["qualification"], "not-evaluated")

    def test_review_source(self) -> None:
        """Source drift revisits retained passes and exceptions across owners without ordering new executions."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, baseline, current = self.fixture(root)
            config["checks"] = [{"id": "ready", "adapter": "observed-cases"}]
            for item in config["components"][0]["requirements"]:
                item["checks"] = ["ready"]
            config["scope"]["components"].append({"id": "consumer", "paths": ["use"]})
            config["components"].append(
                {
                    "id": "consumer",
                    "platforms": ["linux"],
                    "requirements": [{"rule": "DEV-CORE", "contract": "VIEW", "scenario": "full-rule", "checks": ["ready"]}],
                }
            )
            previous = verify.encode(config)
            (root / "development.json").write_bytes(previous)
            baseline["configuration_sha256"] = verify.digest(previous)
            baseline["checks"][0]["check"] = "ready"
            baseline["source"]["files"].append({"path": "use/client.py", "sha256": "3" * 64})
            current = copy.deepcopy(baseline["source"])
            expected = set(verify.expand(config))
            baseline["gate"]["required"] = sorted(expected)
            baseline["gate"]["exceptions"] = [sorted(expected)[-1]]
            baseline["gate"]["passed"] = sorted(expected - set(baseline["gate"]["exceptions"]))
            baseline["gate"]["missing"] = []
            original = copy.deepcopy(baseline)
            for drift in ("none", "edit", "add", "delete", "rename", "unowned", "commit", "index"):
                changed = copy.deepcopy(current)
                if drift == "edit":
                    changed["files"][0]["sha256"] = "4" * 64
                elif drift in ("add", "unowned"):
                    changed["files"].append({"path": "src/new.py" if drift == "add" else "unknown.py", "sha256": "4" * 64})
                elif drift == "delete":
                    changed["files"].pop(0)
                elif drift == "rename":
                    changed["files"][0]["path"] = "src/moved.py"
                elif drift == "commit":
                    changed["commit"] = "5" * 40
                elif drift == "index":
                    changed["status"] = "M  src/state.py"
                pending = expected if drift != "none" else set()
                for policy in (None, previous):
                    with self.subTest(drift=drift, policy=policy is not None):
                        result = assurance.review(config, baseline, changed, root, policy)
                        self.assertEqual(
                            {key for group in result["work"] for key in group["obligations"]},
                            pending,
                            "Changed inputs must not omit historical passes or exceptions from review",
                        )
                        self.assertEqual(result.get("source_review", []), sorted(pending))
                        self.assertEqual(result["batches"]["pending"], sorted(pending))
                        self.assertEqual([proof["action"] for proof in result["batches"]["proofs"]], ["replay-retained"] if pending else [])
                        self.assertEqual(result["policy_review"], [])
                        self.assertTrue(result["configuration_unchanged"])
                        self.assertEqual(result["qualification"], "not-evaluated")
                        self.assertEqual(result["execution"], "none")
            self.assertEqual(baseline, original, "Review must preserve the original evidence and gate outcomes")

    def test_review_integrity(self) -> None:
        """A forged record, duplicate coordinate, missing file or escaping path cannot enter the retained inventory."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, baseline, current = self.fixture(root)
            for damage in ("digest", "duplicate", "escape", "missing"):
                changed = copy.deepcopy(baseline)
                if damage == "digest":
                    changed["checks"][0]["record_sha256"] = "0" * 64
                elif damage == "duplicate":
                    changed["checks"].append(dict(changed["checks"][0]))
                else:
                    changed["checks"][0]["record"] = str(root / ("outside.json" if damage == "escape" else "build/results/absent.json"))
                with self.subTest(damage=damage), self.assertRaises((verify.Invalid, FileNotFoundError)):
                    assurance.review(config, changed, current, root)
            for damage in ("duplicate", "overlap", "omitted", "unknown"):
                changed = copy.deepcopy(baseline)
                if damage == "duplicate":
                    changed["gate"]["missing"].append(changed["gate"]["missing"][0])
                elif damage == "overlap":
                    changed["gate"]["passed"] = [changed["gate"]["missing"][0]]
                elif damage == "omitted":
                    changed["gate"]["missing"].pop()
                else:
                    changed["gate"]["exceptions"] = ["invented"]
                with self.subTest(partition=damage), self.assertRaises(verify.Invalid):
                    assurance.review(config, changed, current, root)

    def test_policy_slices(self) -> None:
        """Check, platform and component changes reach consumers without queuing unrelated configuration credits."""
        with tempfile.TemporaryDirectory() as directory:
            config, _, _ = self.fixture(Path(directory))
            config["platforms"] = [{"id": "linux", "system": "Linux", "machine": "x86_64"}]
            config["checks"].append({"id": "other", "adapter": "unavailable"})
            config["components"][0]["requirements"][1]["checks"] = ["other"]
            core, fault = sorted(verify.expand(config))
            for field, value in (
                ("argv", ["changed"]),
                ("environment", {"MODE": "changed"}),
                ("timeout_s", 60),
                ("expected_tests", ["Required"]),
                ("probes", [{"contract": "STATE", "minimum_hits": 3}]),
            ):
                changed = copy.deepcopy(config)
                changed["checks"][0][field] = value
                with self.subTest(check=field):
                    self.assertEqual(assurance.policy(changed, config), {core})
            for field, value in (("level", "L3"), ("evidence_trust", "ci"), ("contracts", ["NEW"]), ("applicability", {"DEV-CORE": "changed"})):
                changed = copy.deepcopy(config)
                changed["components"][0][field] = value
                with self.subTest(component=field):
                    self.assertEqual(assurance.policy(changed, config), {core, fault})
            changed = copy.deepcopy(config)
            changed["platforms"][0]["machine"] = "aarch64"
            self.assertEqual(assurance.policy(changed, config), {core, fault})
            for field in ("inputs", "rules", "future_policy"):
                changed = {**config, field: "changed"}
                with self.subTest(global_field=field):
                    self.assertEqual(assurance.policy(changed, config), {core, fault})
            changed = copy.deepcopy(config)
            changed["checks"].append({"id": "unused", "adapter": "unavailable"})
            changed["platforms"].append({"id": "unused", "system": "Windows", "machine": "AMD64"})
            self.assertEqual(assurance.policy(changed, config), set())
            changed["components"][0]["requirements"].pop()
            self.assertEqual(assurance.policy(changed, config), set(), "Removed requirements are reported separately, never credited")

    def test_policy_dependencies(self) -> None:
        """A prerequisite change propagates through aggregates; unknown dependencies and cycles fail closed."""
        with tempfile.TemporaryDirectory() as directory:
            config, _, _ = self.fixture(Path(directory))
            requirements = config["components"][0]["requirements"]
            for rule, prerequisite in (("DEV-MIDDLE", "DEV-CORE"), ("DEV-END", "DEV-MIDDLE")):
                requirements.append(
                    {
                        "rule": rule,
                        "contract": "STATE",
                        "scenario": "full-rule",
                        "aggregate": True,
                        "checks": [],
                        "requires": [{"rule": prerequisite, "contract": "STATE", "scenario": "full-rule"}],
                    }
                )
            changed = copy.deepcopy(config)
            changed["components"][0]["requirements"][0]["minimum"] = 2
            self.assertEqual({key.split("/")[1] for key in assurance.policy(changed, config)}, {"DEV-CORE", "DEV-MIDDLE", "DEV-END"})
            changed = copy.deepcopy(config)
            changed["components"][0]["requirements"][-1]["requires"][0]["rule"] = "DEV-FAULT"
            self.assertEqual({key.split("/")[1] for key in assurance.policy(changed, config)}, {"DEV-END"})
            for dependency in ("DEV-END", "UNKNOWN"):
                changed["components"][0]["requirements"][-1]["requires"][0]["rule"] = dependency
                with self.subTest(dependency=dependency), self.assertRaises(verify.Invalid):
                    assurance.policy(changed, config)

    def test_review_policy(self) -> None:
        """Only the original pinned policy narrows review; strengthened requirements retain their old outcomes."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, baseline, current = self.fixture(root)
            previous = verify.read(root / "development.json")
            baseline["gate"]["passed"] = baseline["gate"]["missing"]
            baseline["gate"]["missing"] = []
            changed = copy.deepcopy(config)
            changed["checks"].append({"id": "entry", "adapter": "unavailable"})
            changed["components"][0]["requirements"][0]["checks"].append("entry")
            (root / "development.json").write_bytes(verify.encode(changed))
            conservative = assurance.review(changed, baseline, current, root)
            result = assurance.review(changed, baseline, current, root, previous)
            self.assertEqual(len(conservative["policy_review"]), 2)
            self.assertEqual(result["policy_review"], [baseline["gate"]["passed"][0]])
            self.assertEqual(result["policy_comparison"], "itemwise")
            self.assertEqual(result["baseline_counts"]["passed"], 2)
            self.assertEqual(result["qualification"], "not-evaluated")
            self.assertEqual(result["execution"], "none")
            self.assertEqual(len(result["work"]), 2)
            with self.assertRaisesRegex(verify.Invalid, "review-policy-integrity"):
                assurance.review(changed, baseline, current, root, verify.encode(changed))
            baseline["gate"]["passed"].pop()
            baseline["gate"]["required"] = list(baseline["gate"]["passed"])
            with self.assertRaisesRegex(verify.Invalid, "review-policy-obligations"):
                assurance.review(changed, baseline, current, root, previous)

    def test_review_entry(self) -> None:
        """Pinned review is read-only, rejects source drift and cannot be used as a campaign execution shortcut."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, baseline, current = self.fixture(root)
            config["campaigns"] = [{"id": "system", "steps": []}]
            path = root / "baseline.json"
            path.write_bytes(verify.encode(baseline))
            arguments = ["--plan", "--baseline", str(path), "--sha256", verify.file_digest(path)]
            policy = root / "policy.json"
            policy.write_bytes(verify.read(root / "development.json"))
            with (
                patch.object(assurance.build, "ROOT", root),
                patch.object(verify, "configuration", return_value=(config, {}, {})),
                patch.object(verify, "source", return_value=current),
                patch.object(verify, "execute", side_effect=AssertionError("Planning must not execute")),
                patch.object(verify, "write_new", side_effect=AssertionError("Planning must not write evidence")),
            ):
                with patch("sys.stdout", new_callable=io.StringIO) as output:
                    self.assertEqual(assurance.main(arguments), 0)
                self.assertEqual(json.loads(output.getvalue())["review"]["qualification"], "not-evaluated")
                with patch("sys.stdout", new_callable=io.StringIO) as output:
                    self.assertEqual(assurance.main([*arguments, "--policy", str(policy)]), 0)
                self.assertEqual(json.loads(output.getvalue())["review"]["policy_comparison"], "itemwise")
                for invalid in (arguments[1:], arguments[:-2], [*arguments[:-1], "0" * 64], ["--plan", "--policy", str(policy)]):
                    with self.assertRaises(verify.Invalid):
                        assurance.main(invalid)
                after = {**current, "status": " M src/other.py"}
                with patch.object(verify, "source", side_effect=[current, after]), self.assertRaisesRegex(verify.Invalid, "review-source-changed"):
                    assurance.main(arguments)

    def test_batches(self) -> None:
        """A diamond uses one retained proof per platform and retains already credited prerequisites."""
        with tempfile.TemporaryDirectory() as directory:
            config, baseline, _ = self.fixture(Path(directory))
            config["checks"][0]["adapter"] = "observed-cases"
            component = config["components"][0]
            component["platforms"].append("windows")
            for rule, dependencies in (("DEV-MIDDLE", ["DEV-CORE", "DEV-FAULT"]), ("DEV-END", ["DEV-MIDDLE", "DEV-CORE"])):
                component["requirements"].append(
                    {
                        "rule": rule,
                        "contract": "STATE",
                        "scenario": "full-rule",
                        "aggregate": True,
                        "checks": [],
                        "requires": [{"rule": name, "contract": "STATE", "scenario": "full-rule"} for name in dependencies],
                    }
                )
            obligations = verify.expand(config)
            pending = {key for key in obligations if "/DEV-END/" in key}
            record = {**baseline["checks"][0], "check": "pending"}
            result = assurance.batches(config, obligations, pending, [record])
            self.assertEqual(len(result["proofs"]), 2)
            self.assertEqual([item["action"] for item in result["proofs"]], ["replay-retained", "locate-evidence"])
            self.assertEqual(result["proofs"][0]["record"], record)
            self.assertIsNone(result["proofs"][1]["record"], "Linux facts cannot supply Windows facts")
            self.assertEqual(set(result["pending"]) | set(result["prerequisites"]), set(obligations))
            self.assertEqual(len(result["prerequisites"]), 6)
            for proof in result["proofs"]:
                self.assertEqual(proof["obligations"], [])
                self.assertEqual(len(proof["prerequisites"]), 2)
                self.assertTrue(all("/" + proof["platform"] + "/" in key for key in proof["prerequisites"]))
            positions = {item["obligation"]: index for index, item in enumerate(result["decisions"])}
            self.assertEqual(len(positions), 4)
            for item in result["decisions"]:
                self.assertTrue(all(positions[dep] < positions[item["obligation"]] for dep in item["requires"] if dep in positions))
            self.assertEqual(result["unmapped"], [])
            self.assertEqual(assurance.batches(config, obligations, set(), [record])["proofs"], [])

    def test_batch_gaps(self) -> None:
        """Unavailable executors and filtered platform mappings remain gaps; invalid graphs cannot guide reuse."""
        with tempfile.TemporaryDirectory() as directory:
            config, baseline, _ = self.fixture(Path(directory))
            config["checks"][0]["platforms"] = ["linux"]
            config["components"][0]["platforms"].append("windows")
            obligations = verify.expand(config)
            record = {**baseline["checks"][0], "check": "pending"}
            result = assurance.batches(config, obligations, set(obligations), [record])
            self.assertEqual(len(result["proofs"]), 1)
            self.assertEqual(result["proofs"][0]["action"], "implement-proof", "Old evidence cannot implement an unavailable reader")
            self.assertEqual(result["proofs"][0]["record"], record)
            self.assertEqual(len(result["unmapped"]), 2)
            self.assertTrue(all("/windows/" in key for key in result["unmapped"]))
            self.assertEqual(result["decisions"], [])
            with self.assertRaisesRegex(verify.Invalid, "review-pending-unknown"):
                assurance.batches(config, obligations, {"invented"}, [record])
            with self.assertRaisesRegex(verify.Invalid, "review-duplicate-record"):
                assurance.batches(config, obligations, set(obligations), [record, record])
            key = next(iter(obligations))
            for rule in ("UNKNOWN", obligations[key]["rule"]):
                changed = copy.deepcopy(obligations)
                changed[key]["requires"] = [{"rule": rule, "contract": "STATE", "scenario": "full-rule"}]
                with self.subTest(dependency=rule), self.assertRaises(verify.Invalid):
                    assurance.batches(config, changed, set(), [])


class StorageTests(unittest.TestCase):
    """Falsify scoped rule composition; synthetic observations never serve as product evidence."""

    def route(self, rule: str) -> None:
        """Keep every existing qualified prerequisite and reject each missing or mismatched coordinate."""
        config, _, _ = verify.configuration(verify.ROOT / "development.json")
        config = copy.deepcopy(config)
        config["components"] = [next(item for item in config["components"] if item["id"] == "polaris-storage")]
        obligations = verify.expand(config)
        _, dependencies = verify.dependency_order(obligations)
        key = f"polaris-storage/{rule}/STORAGE-ASSURANCE/linux-amd64-cgo/full-rule"
        parents = {
            "DEV-ASYNC",
            "DEV-CONFIG",
            "DEV-CONTRACT",
            "DEV-CORE",
            "DEV-COVERAGE",
            "DEV-FAULT",
            "DEV-GATE",
            "DEV-IMPACT",
            "DEV-MATRIX",
            "DEV-MODEL",
            "DEV-NUMERIC",
            "DEV-ORACLE",
            "DEV-RETRY",
            "DEV-SECURITY",
            "DEV-STOP",
            "DEV-TIME",
        }
        item = obligations[key]
        self.assertEqual(len(obligations), 74)
        inventory = "polaris-storage/DEV-SCOPE/STORAGE-ASSURANCE/linux-amd64-cgo/source-inventory"
        self.assertEqual(obligations[inventory]["checks"], ["gap-scope"])
        self.assertEqual(item["checks"], ["gap-" + rule.removeprefix("DEV-").lower()])
        self.assertNotIn("aggregate", item)
        self.assertEqual(
            item["requires"],
            [{"rule": parent, "contract": "STORAGE-ASSURANCE", "scenario": "full-rule"} for parent in sorted(parents)],
        )
        required = set(dependencies[key])
        pending = list(required)
        while pending:
            for dependency in dependencies[pending.pop()]:
                if dependency not in required:
                    required.add(dependency)
                    pending.append(dependency)
        self.assertEqual(len(required), 58)
        self.assertEqual({obligations[name]["rule"] for name in required if obligations[name]["scenario"] == "full-rule"}, parents)
        observations = {
            (check, obligations[name]["platform"], obligations[name]["contract"]): "passed"
            for name in required | {key}
            for check in obligations[name]["checks"]
        }
        self.assertEqual(len(observations), 46)
        now = verify.stamp("2026-10-11T00:00:00Z")
        accepted = verify.decide(config, observations, [], [], now)
        self.assertIn(key, accepted["passed"])
        self.assertEqual(len(accepted["passed"]), 59)
        self.assertEqual(accepted["status"], "blocked", "Unrelated unmet rules and the other two routes still block the component")
        controls = 0
        for coordinate in sorted(observations):
            for state in (None, "failed", "not-run", "unknown", "interrupted", "skipped", "platform", "contract"):
                with self.subTest(rule=rule, coordinate=coordinate, state=state):
                    changed = dict(observations)
                    del changed[coordinate]
                    if state == "platform":
                        changed[(coordinate[0], "windows-amd64", coordinate[2])] = "passed"
                    elif state == "contract":
                        changed[(coordinate[0], coordinate[1], "STORAGE-UNRELATED")] = "passed"
                    elif state is not None:
                        changed[coordinate] = state
                    refused = verify.decide(config, changed, [], [], now)
                    self.assertNotIn(key, refused["passed"])
                    self.assertIn(key, refused["missing"])
                    controls += 1
        self.assertEqual(controls, 368)

    def test_replay(self) -> None:
        """Finite inputs, recorded histories, clocks and their independent oracles are all mandatory."""
        self.route("DEV-REPLAY")

    def test_failure(self) -> None:
        """Injected errors, isolation, recovery, cleanup and failure propagation cannot be replaced by a later pass."""
        self.route("DEV-FAILURE")

    def test_audit(self) -> None:
        """A risk argument cannot certify the component without every source-bound behavioral prerequisite."""
        self.route("DEV-AUDIT")


class AdmissionTests(unittest.TestCase):
    """Require complete Admission evidence before policy controls can discharge a full rule."""

    PARENTS = {
        "DEV-ASYNC",
        "DEV-CONTRACT",
        "DEV-CORE",
        "DEV-COVERAGE",
        "DEV-FAULT",
        "DEV-GATE",
        "DEV-MATRIX",
        "DEV-MODEL",
        "DEV-NUMERIC",
        "DEV-ORACLE",
        "DEV-RETRY",
        "DEV-SECURITY",
        "DEV-STOP",
        "DEV-TIME",
    }

    def route(self, rule: str) -> None:
        """Falsify each prerequisite coordinate; these synthetic facts never replace native behavior evidence."""
        config, _, _ = verify.configuration(verify.ROOT / "development.json")
        config = copy.deepcopy(config)
        config["components"] = [next(item for item in config["components"] if item["id"] == "admission")]
        obligations = verify.expand(config)
        _, dependencies = verify.dependency_order(obligations)
        key = f"admission/{rule}/ADMISSION-ASSURANCE/linux-amd64-cgo/full-rule"
        parents = self.PARENTS | ({"DEV-CONFIG"} if rule != "DEV-CONFIG" else set())
        item = obligations[key]
        refresh = "admission/DEV-CONTRACT/ADMISSION-NODE-REFRESH/linux-amd64-cgo/refresh-receipts"
        self.assertEqual(
            obligations[refresh],
            {
                "checks": ["admission-model", "admission-refresh-faults"],
                "contract": "ADMISSION-NODE-REFRESH",
                "rule": "DEV-CONTRACT",
                "scenario": "refresh-receipts",
                "component": "admission",
                "platform": "linux-amd64-cgo",
            },
        )
        self.assertEqual(len(obligations), 68)
        self.assertEqual(len(set(obligations) - {refresh}), 67)
        self.assertEqual(item["checks"], ["admission-gap-" + rule.removeprefix("DEV-").lower()])
        self.assertNotIn("aggregate", item)
        self.assertEqual(item["requires"], [{"rule": parent, "contract": "ADMISSION-ASSURANCE", "scenario": "full-rule"} for parent in sorted(parents)])
        registered = verify.unique(config["checks"])
        gate = registered["admission-gap-gate"]
        self.assertEqual(gate["adapter"], "observed-cases")
        self.assertEqual(gate["expected_tests"], registered["gap-gate"]["expected_tests"])
        self.assertEqual(gate["argv"], registered["gap-gate"]["argv"])
        self.assertEqual(gate["probes"], [{**probe, "contract": "ADMISSION-ASSURANCE"} for probe in registered["gap-gate"]["probes"]])
        required = set(dependencies[key])
        pending = list(required)
        while pending:
            for child in dependencies[pending.pop()]:
                if child not in required:
                    required.add(child)
                    pending.append(child)
        self.assertEqual(len(required), 52 if rule == "DEV-CONFIG" else 53)
        self.assertEqual({obligations[name]["rule"] for name in required if obligations[name]["scenario"] == "full-rule"}, parents)
        observations = {
            (check, obligations[name]["platform"], obligations[name]["contract"]): "passed"
            for name in required | {key}
            for check in obligations[name]["checks"]
        }
        self.assertEqual(len(observations), 41 if rule == "DEV-CONFIG" else 42)
        now = verify.stamp("2026-10-12T00:00:00Z")
        accepted = verify.decide(config, observations, [], [], now)
        self.assertIn(key, accepted["passed"])
        self.assertTrue(required <= set(accepted["passed"]))
        self.assertIn(refresh, accepted["passed"])
        for check in obligations[refresh]["checks"]:
            self.assertIn((check, "linux-amd64-cgo", "ADMISSION-NODE-REFRESH"), observations)
        self.assertEqual(accepted["status"], "blocked", "Scope, capacity, impact, supply, compatibility and protected release still need their own proof")
        controls = 0
        for coordinate in sorted(observations):
            for state in (None, "failed", "not-run", "unknown", "interrupted", "skipped", "platform", "contract"):
                with self.subTest(rule=rule, coordinate=coordinate, state=state):
                    changed = dict(observations)
                    del changed[coordinate]
                    if state == "platform":
                        changed[(coordinate[0], "windows-amd64", coordinate[2])] = "passed"
                    elif state == "contract":
                        changed[(coordinate[0], coordinate[1], "ADMISSION-UNRELATED")] = "passed"
                    elif state is not None:
                        changed[coordinate] = state
                    refused = verify.decide(config, changed, [], [], now)
                    self.assertNotIn(key, refused["passed"])
                    self.assertIn(key, refused["missing"])
                    controls += 1
        self.assertEqual(controls, 328 if rule == "DEV-CONFIG" else 336)

    def test_config(self) -> None:
        """The effective policy, real gate controls, startup inputs and shipping consumers are jointly required."""
        self.route("DEV-CONFIG")

    def test_replay(self) -> None:
        """Source-bound finite models, clocks, histories, numeric domains and native callers are mandatory."""
        self.route("DEV-REPLAY")

    def test_failure(self) -> None:
        """Errors, cancellation, cleanup, isolated state and actual recovery must all retain native evidence."""
        self.route("DEV-FAILURE")

    def test_audit(self) -> None:
        """Ownership and authorization counterexamples cannot qualify without their complete behavioral closure."""
        self.route("DEV-AUDIT")


if __name__ == "__main__":
    unittest.main()
