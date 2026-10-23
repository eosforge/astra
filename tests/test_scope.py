"""Verify real maintained-source ownership without treating a complete inventory as release acceptance."""

import copy
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import verify as v

# Product/maintenance boundaries are independent known vectors, not a second operational configuration.
ROOT = Path(__file__).resolve().parents[1]
PROBES = {
    "common": ("common/src/store.cpp", "L3", ["linux-amd64-cgo"]),
    "star": ("star/src/almanac.cpp", "L3", ["linux-amd64-cgo"]),
    "pulsar": ("pulsar/src/ledger.cpp", "L3", ["linux-amd64-cgo"]),
    "comet": ("comet/cpp/src/core.cpp", "L2", ["linux-amd64-cgo", "windows-amd64"]),
    "comet-go": ("comet/go/client.go", "L2", ["linux-amd64-cgo", "windows-amd64"]),
    "polaris-storage": ("polaris/internal/storage/batch.go", "L3", ["linux-amd64-cgo"]),
    "polaris-server": ("polaris/main.go", "L2", ["linux-amd64-cgo"]),
    "astrolabe": ("astrolabe/main.go", "L2", ["linux-amd64-cgo"]),
    "admission": ("internal/admission/identity.go", "L3", ["linux-amd64-cgo"]),
    "command": ("internal/command/flags.go", "L2", ["linux-amd64-cgo"]),
    "admin": ("admin/src/main.ts", "L2", ["windows-amd64"]),
    "verification": ("tools/verify.py", "L2", ["linux-amd64-cgo"]),
    "tools": ("tools/build.py", "L2", ["linux-amd64-cgo", "windows-amd64"]),
    "benchmarks": ("bench/comet.cpp", "L2", ["linux-amd64-cgo"]),
    "protocol": ("proto/astra.proto", "L2", ["linux-amd64-cgo"]),
    "documentation": ("docs/development.md", "L1", ["windows-amd64"]),
}
# One fixed selection is shared across component checks; prerequisite gates retain authority/trust requirements.
CASES = ("current", "ownership", "missing", "empty", "unowned", "source", "entries", "policy")
TESTS = ["tests.test_scope.ScopeTests.test_" + name for name in CASES]


class ScopeTests(unittest.TestCase):
    """Exercise all owned boundaries and authentic Git changes with explicit failed-scope controls."""

    @classmethod
    def setUpClass(cls) -> None:
        """Capture the real workspace once; synthetic negative variants remain visibly separate."""
        cls.config, _, _ = v.configuration(ROOT / "development.json", ROOT)
        cls.actual = v.source(ROOT)
        cls.ownership = v.scope(cls.config, ROOT)

    def test_current(self) -> None:
        """Every present maintained input has one owner and every declared component has real inputs."""
        self.assertEqual(self.ownership["source"], self.actual)
        self.assertEqual(v.source(ROOT), self.actual)
        self.assertEqual(self.ownership["status"], "complete")
        for field in ("unowned", "unconfigured", "empty"):
            self.assertEqual(self.ownership[field], [])
        declarations = v.unique(self.config["scope"]["components"])
        registered = v.unique(self.config["components"])
        self.assertEqual(set(declarations), set(PROBES))
        self.assertEqual(set(registered), set(PROBES))
        for name, (sentinel, level, platforms) in PROBES.items():
            with self.subTest(component=name):
                self.assertIn(sentinel, self.ownership["components"][name])
                self.assertTrue((ROOT / sentinel).is_file())
                self.assertEqual(declarations[name]["level"], level)
                self.assertEqual(declarations[name]["platforms"], platforms)
                self.assertEqual(registered[name]["paths"], declarations[name]["paths"])
        assigned = [name for names in self.ownership["components"].values() for name in names] + self.ownership["excluded"]
        present = {row["path"] for row in self.actual["files"] if row["sha256"] is not None}
        self.assertEqual(set(assigned), present)
        self.assertEqual(len(assigned), len(present))
        self.assertGreater(len(present), len(PROBES))
        self.assertIsInstance(self.actual["status"], str)

    def test_ownership(self) -> None:
        """Most-specific owners, generated bindings, deferred roles and similar prefixes stay distinct."""
        sentinels = [row[0] for row in PROBES.values()]
        excluded = [
            "common/src/generated/astra.pb.cc",
            "internal/generated/astra/astra.pb.go",
            "bench/generated/bench.pb.cc",
            "moon/main.cpp",
            "planet/main.cpp",
            "comet/go/internal/protocol/comet.pb.go",
            "comet/go/internal/protocol/comet_grpc.pb.go",
        ]
        unknown = ["polaris-extra/main.go", "internal/admission-extra/node.go", "common-extra/store.cpp", "comet/go-extra/client.go", "sentinel/main.cpp"]
        result = v.inventory(self.config, sentinels + excluded + unknown + sentinels)
        for name, (sentinel, _, _) in PROBES.items():
            self.assertEqual(result["components"][name], [sentinel])
        self.assertEqual(result["excluded"], sorted(excluded))
        self.assertEqual(result["unowned"], sorted(unknown))
        sdk = ["comet/go/README.md", "comet/go/internal/protocol/generation.json", "comet/go/system_test.go"]
        self.assertEqual(v.inventory(self.config, sdk)["components"]["comet-go"], sorted(sdk))
        for name in PROBES:
            changed = copy.deepcopy(self.config)
            changed["scope"]["components"].append(copy.deepcopy(next(row for row in changed["scope"]["components"] if row["id"] == name)))
            with self.subTest(component=name), self.assertRaisesRegex(v.Invalid, "duplicate-id"):
                v.inventory(changed, sentinels)

    def test_missing(self) -> None:
        """A removed component registration blocks a real complete inventory rather than inheriting another owner."""
        for name in PROBES:
            changed = copy.deepcopy(self.config)
            changed["components"] = [row for row in changed["components"] if row["id"] != name]
            with patch.object(v, "source", return_value=self.actual):
                result = v.scope(changed, ROOT)
            with self.subTest(component=name):
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(result["unconfigured"], [name])
                self.assertEqual(result["unowned"], [])

    def test_empty(self) -> None:
        """A component with no current maintained files cannot pass on a declaration or deleted inputs."""
        for name in PROBES:
            removed = set(self.ownership["components"][name])
            changed = copy.deepcopy(self.actual)
            for row in changed["files"]:
                if row["path"] in removed:
                    row["sha256"] = None
            with patch.object(v, "source", return_value=changed):
                result = v.scope(self.config, ROOT)
            with self.subTest(component=name):
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(result["empty"], [name])
                self.assertEqual(result["components"][name], [])

    def test_unowned(self) -> None:
        """Unregistered files and removed ownership roots remain hard scope gaps, including shared inputs."""
        for name in ("unregistered/main.go", "internal/admission-extra/node.go", "polaris-extra/main.go"):
            changed = copy.deepcopy(self.actual)
            changed["files"].append({"path": name, "sha256": v.digest(b"synthetic negative input")})
            with patch.object(v, "source", return_value=changed):
                result = v.scope(self.config, ROOT)
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["unowned"], [name])
        for name, (sentinel, _, _) in PROBES.items():
            changed = copy.deepcopy(self.config)
            changed["scope"]["components"] = [row for row in changed["scope"]["components"] if row["id"] != name]
            result = v.inventory(changed, [sentinel])
            with self.subTest(component=name):
                fallback = {"polaris-storage": "polaris-server", "verification": "tools"}.get(name)
                self.assertEqual(result["unowned"], [] if fallback else [sentinel])
                if fallback:
                    self.assertEqual(result["components"][fallback], [sentinel])

    def test_source(self) -> None:
        """Native Git queries bind untracked, index-only, modified, renamed and deleted bytes without a commit."""
        with tempfile.TemporaryDirectory(prefix="astra-scope-") as directory:
            root = Path(directory)
            environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}

            def git(*arguments: str) -> None:
                """Change only this test's isolated index; never commit, fetch or access a remote."""
                subprocess.run(["git", "-C", str(root), *arguments], env=environment, check=True, capture_output=True, timeout=30)

            with patch.dict(os.environ, environment, clear=True):
                git("init", "-q")
                path = root / "input.txt"
                path.write_bytes(b"first")
                initial = v.source(root)
                self.assertIsNone(initial["commit"])
                self.assertEqual(initial["files"], [{"path": "input.txt", "sha256": v.digest(b"first")}])
                self.assertIn("?? input.txt", initial["status"])
                git("add", "--", "input.txt")
                indexed = v.source(root)
                self.assertEqual(indexed["files"], initial["files"])
                self.assertNotEqual(indexed["status"], initial["status"])
                path.write_bytes(b"second")
                modified = v.source(root)
                self.assertEqual(modified["files"][0]["sha256"], v.digest(b"second"))
                self.assertNotEqual(modified, indexed)
                git("mv", "--", "input.txt", "renamed.txt")
                renamed = v.source(root)
                self.assertEqual(renamed["files"], [{"path": "renamed.txt", "sha256": v.digest(b"second")}])
                (root / "renamed.txt").unlink()
                deleted = v.source(root)
                self.assertEqual(deleted["files"], [{"path": "renamed.txt", "sha256": None}])
                self.assertNotEqual(deleted["status"], renamed["status"])

    def test_entries(self) -> None:
        """One standard pair and the approved SDK/deferred-component boundaries remain reachable."""
        agreements = v.read(ROOT / "AGENTS.md").decode()
        guide = v.read(ROOT / "docs/project.md").decode()
        for target in ("docs/development.md", "docs/coding.md", "docs/project.md"):
            self.assertIn("](" + target, agreements)
            self.assertTrue(v.inside(ROOT, target).is_file())
        self.assertEqual(self.config["standard"], "docs/development.md")
        self.assertEqual(self.config["design"], "docs/features/verification.md")
        self.assertIn("development-verification", guide)
        self.assertIn("features/verification.md", guide)
        self.assertIn("Explicit current requests/approved scope", agreements)
        exclusions = {name for row in self.config["scope"]["exclusions"] for name in row["paths"]}
        self.assertEqual(
            exclusions,
            {
                "common/src/generated",
                "internal/generated",
                "bench/generated",
                "moon",
                "planet",
                "comet/go/internal/protocol/comet.pb.go",
                "comet/go/internal/protocol/comet_grpc.pb.go",
            },
        )
        for entries in (self.config["scope"]["components"], self.config["components"]):
            self.assertEqual(next(row["paths"] for row in entries if row["id"] == "comet"), ["comet/cpp"])
            self.assertEqual(next(row["paths"] for row in entries if row["id"] == "comet-go"), ["comet/go"])
        for row in self.config["scope"]["exclusions"]:
            self.assertTrue(row["reason"].strip())
        self.assertNotIn("build", exclusions)

    def test_policy(self) -> None:
        """Scope observations retain same-component configuration and authority-enforcing gate prerequisites."""
        checks = v.unique(self.config["checks"])
        obligations = v.expand(self.config)
        for component in self.config["components"]:
            requirement = next(row for row in component["requirements"] if row["rule"] == "DEV-SCOPE" and row["scenario"] == "full-rule")
            inventory = next(row for row in component["requirements"] if row["rule"] == "DEV-SCOPE" and row["scenario"] == "source-inventory")
            self.assertTrue(requirement["aggregate"])
            self.assertEqual(requirement["checks"], [])
            self.assertEqual(
                requirement["requires"],
                [{"contract": requirement["contract"], "rule": "DEV-SCOPE", "scenario": "source-inventory"}]
                + [{"contract": requirement["contract"], "rule": rule, "scenario": "full-rule"} for rule in ("DEV-CONFIG", "DEV-GATE")],
            )
            self.assertEqual(len(inventory["checks"]), 1)
            check = checks[inventory["checks"][0]]
            self.assertEqual(check["component"], component["id"])
            self.assertEqual(check["adapter"], "observed-cases")
            self.assertEqual(check["expected_tests"], TESTS)
            self.assertEqual(check["argv"], ["python3", "-B", "tools/observe.py", "python", *TESTS])
            self.assertEqual(check["environment"], {})
            self.assertEqual(check["probes"], [{"contract": requirement["contract"], "minimum_hits": 80, "test": TESTS[0]}])
            self.assertEqual(check["timeout_s"], 120)
            self.assertEqual(check["log_bytes"], 8 * 1024 * 1024)
            for platform in component["platforms"]:
                key = "/".join((component["id"], "DEV-SCOPE", requirement["contract"], platform, "full-rule"))
                self.assertIn(key, obligations)
                self.assertEqual(obligations[key]["checks"], [])
                key = "/".join((component["id"], "DEV-SCOPE", requirement["contract"], platform, "source-inventory"))
                self.assertEqual(obligations[key]["checks"], inventory["checks"])
        # A remaining bounded leaf must not conceal removal of whole-rule coverage from one platform.
        with tempfile.TemporaryDirectory(prefix="astra-scope-policy-") as directory:
            path = Path(directory) / "development.json"
            for name in ("comet", "tools"):
                for rule in ("DEV-SCOPE", "DEV-CONFIG", "DEV-GATE", "DEV-COVERAGE"):
                    changed = copy.deepcopy(self.config)
                    component = next(row for row in changed["components"] if row["id"] == name)
                    requirement = next(row for row in component["requirements"] if row["rule"] == rule and row["scenario"] == "full-rule")
                    requirement["platforms"] = ["linux-amd64-cgo"]
                    path.write_bytes(v.encode(changed))
                    with self.subTest(component=name, rule=rule), self.assertRaisesRegex(v.Invalid, "unmapped-obligation"):
                        v.configuration(path, ROOT)
                changed = copy.deepcopy(self.config)
                component = next(row for row in changed["components"] if row["id"] == name)
                component["requirements"] = [row for row in component["requirements"] if (row["rule"], row["scenario"]) != ("DEV-SCOPE", "full-rule")]
                path.write_bytes(v.encode(changed))
                with self.subTest(component=name, removed=True), self.assertRaisesRegex(v.Invalid, "unmapped-obligation"):
                    v.configuration(path, ROOT)
