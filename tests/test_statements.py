"""Challenge Go counter import with independent weighted gaps, frozen sources and incomplete native streams."""

import copy
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import coverage, paths, statements, verify as v


class StatementTests(unittest.TestCase):
    """Synthetic counter fixtures test the importer; only real compiler campaigns provide coverage evidence."""

    def setUp(self) -> None:
        """Create one tiny module with an unbuilt source and separately identified generated/test files."""
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.module = "example.org/fixture"
        inputs = {
            "go.mod": "module example.org/fixture\n\ngo 1.27.0\n",
            "unit/state.go": "package unit\n\nfunc Read() int {\n    return 1\n}\n",
            "unit/empty.go": "package unit\n\ntype Empty struct{}\n",
            "unit/future_windows.go": "//go:build windows\n\npackage unit\n",
            "unit/state_test.go": "package unit\n",
            "wire/data.go": "// Code generated fixture. DO NOT EDIT.\npackage wire\n\nfunc Value() int { return 1 }\n",
        }
        for name, data in inputs.items():
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data.encode())
        self.source = {"commit": None, "status": "fixture", "files": [{"path": name, "sha256": v.file_digest(self.root / name)} for name in sorted(inputs)]}
        self.listing = [
            {
                "Dir": str(self.root / "unit"),
                "ImportPath": self.module + "/unit",
                "Module": {"Path": self.module, "Main": True, "Dir": str(self.root)},
                "GoFiles": ["state.go", "empty.go"],
                "IgnoredGoFiles": ["future_windows.go"],
                "TestGoFiles": ["state_test.go"],
            },
            {
                "Dir": str(self.root / "wire"),
                "ImportPath": self.module + "/wire",
                "Module": {"Path": self.module, "Main": True, "Dir": str(self.root)},
                "GoFiles": ["data.go"],
            },
        ]
        self.profile = (
            b"mode: atomic\n"
            b"example.org/fixture/unit/state.go:3.17,4.13 3 1\n"
            b"example.org/fixture/unit/state.go:4.5,4.13 2 0\n"
            b"example.org/fixture/unit/state.go:3.17,4.13 3 2\n"
            b"example.org/fixture/wire/data.go:4.18,4.28 1 0\n"
        )

    def metadata(self, listing: list[dict] | None = None) -> bytes:
        """Encode genuine go-list framing without treating it as JSON Lines."""
        return b"\n".join(v.encode(item) for item in (self.listing if listing is None else listing))

    def test_cached_dependency_coverage(self) -> None:
        """Real Go coverage must retain all main-module sources while excluding an imported local cache module."""
        go = shutil.which("go")
        if go is None:
            self.skipTest("Native coverage scope requires an existing Go executable")
        cache = self.root / "build"
        paths.isolate(cache)
        dependency = cache / "dependency"
        dependency.mkdir()
        (dependency / "go.mod").write_text("module example.org/cached\n\ngo 1.27.0\n", encoding="utf-8")
        (dependency / "value.go").write_text("package cached\nfunc Value() int { return 1 }\n", encoding="utf-8")
        (self.root / "go.mod").write_text(
            "module example.org/fixture\n\ngo 1.27.0\n\nrequire example.org/cached v0.0.0\nreplace example.org/cached => ./build/dependency\n", encoding="utf-8"
        )
        (self.root / "unit/import.go").write_text(
            'package unit\nimport "example.org/cached"\nfunc Imported() int { return cached.Value() }\n', encoding="utf-8"
        )
        (self.root / "unit/import_test.go").write_text(
            'package unit\nimport "testing"\nfunc TestImported(t *testing.T) { if Imported()!=1 { t.Fatal("wrong imported value") } }\n', encoding="utf-8"
        )
        env = dict(os.environ)
        env.update(
            GOTOOLCHAIN="local",
            GOPROXY="off",
            GOSUMDB="off",
            GOWORK="off",
            GOENV="off",
            GOFLAGS="-mod=readonly",
            CGO_ENABLED="0",
            GOMAXPROCS="2",
            GOPATH=str(cache / "deps/go"),
            GOMODCACHE=str(cache / "deps/go/pkg/mod"),
            GOCACHE=str(cache / "cache/go"),
        )

        def native(pattern: str, name: str) -> str:
            """Collect a fresh finite native profile with the same complete package selection."""
            profile = cache / name
            result = subprocess.run(
                [go, "test", "-count=1", "-p=2", "-parallel=1", "-covermode=atomic", "-coverpkg=" + pattern, "-coverprofile=" + str(profile), "./..."],
                cwd=self.root,
                env=env,
                capture_output=True,
                text=True,
                timeout=90,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return profile.read_text(encoding="utf-8")

        before = native("./...", "relative.cover")
        self.assertIn("example.org/cached/value.go:", before)
        after = native(self.module + "/...", "module.cover")
        self.assertNotIn("example.org/cached/", after)
        for name in ("unit/state.go", "unit/import.go", "wire/data.go"):
            self.assertIn(self.module + "/" + name + ":", after)

    def test_command_boundary_policy(self) -> None:
        """Only the named test and complete source-boundary denominator may supply this observation."""
        root = Path(__file__).resolve().parents[1]
        config = v.decode(v.read(root / "development.json"))
        for identifier in ("command-boundaries", "command-structure-race"):
            original = next(check for check in config["checks"] if check["id"] == identifier)
            statements.configuration(original)
            probe = next(item for item in original["probes"] if item["contract"] == "COMMAND-ISOLATION")
            self.assertEqual(probe, {"contract": "COMMAND-ISOLATION", "test": "TestDecisionInventory", "minimum_hits": 16})
            for field, value in (("test", "TestVerification"), ("minimum_hits", 15), ("minimum_hits", 17)):
                changed = copy.deepcopy(original)
                next(item for item in changed["probes"] if item["contract"] == "COMMAND-ISOLATION")[field] = value
                with self.assertRaisesRegex(v.Invalid, "command-structure-configuration"):
                    statements.configuration(changed)
            changed = copy.deepcopy(original)
            changed["probes"].append(copy.deepcopy(probe))
            with self.assertRaisesRegex(v.Invalid, "command-structure-configuration"):
                statements.configuration(changed)
            for contract, minimum in (("COMMAND-NUMERIC", 1), ("COMMAND-NUMERIC-CONTROLS", 19)):
                probe = next(item for item in original["probes"] if item["contract"] == contract)
                self.assertEqual(probe, {"contract": contract, "test": "TestNumeric", "minimum_hits": minimum})
                for field, value in (("test", "TestVerification"), ("minimum_hits", minimum - 1), ("minimum_hits", minimum + 1)):
                    changed = copy.deepcopy(original)
                    next(item for item in changed["probes"] if item["contract"] == contract)[field] = value
                    with self.assertRaisesRegex(v.Invalid, "command-structure-configuration"):
                        statements.configuration(changed)
            self.assertIn("TestCompatibility", original["expected_tests"])
            probe = next(item for item in original["probes"] if item["contract"] == "COMMAND-COMPATIBILITY")
            self.assertEqual(probe, {"contract": "COMMAND-COMPATIBILITY", "test": "TestCompatibility", "minimum_hits": 182})
            for field, value in (("test", "TestVerification"), ("minimum_hits", 181), ("minimum_hits", 183)):
                changed = copy.deepcopy(original)
                next(item for item in changed["probes"] if item["contract"] == "COMMAND-COMPATIBILITY")[field] = value
                with self.assertRaisesRegex(v.Invalid, "command-structure-configuration"):
                    statements.configuration(changed)
            changed = copy.deepcopy(original)
            changed["expected_tests"].remove("TestCompatibility")
            with self.assertRaisesRegex(v.Invalid, "command-structure-configuration"):
                statements.configuration(changed)
            changed = copy.deepcopy(original)
            changed["expected_tests"].remove("TestNumeric")
            with self.assertRaisesRegex(v.Invalid, "command-structure-configuration"):
                statements.configuration(changed)

    def test_command_boundary_dependencies(self) -> None:
        """A boundary marker cannot bypass native structure, behavior, failures or shipping consumers."""
        root = Path(__file__).resolve().parents[1]
        config = v.decode(v.read(root / "development.json"))
        obligations = v.expand(config)
        key = "command/DEV-CORE/COMMAND-ASSURANCE/linux-amd64-cgo/full-rule"
        parent = obligations[key]
        self.assertEqual(parent["checks"], ["command-boundaries", "command-structure-race"])
        expected = [
            ("DEV-CORE", "COMMAND-ISOLATION", "effect-boundary"),
            ("DEV-COVERAGE", "COMMAND-ASSURANCE", "structure"),
            ("DEV-COVERAGE", "COMMAND-DECISION-INVENTORY", "mcdc-inventory"),
            ("DEV-CONTRACT", "COMMAND-BOUNDARY", "boundary-oracle"),
            ("DEV-FAULT", "COMMAND-FAULT", "fault-observations"),
            ("DEV-MATRIX", "COMMAND-ASSURANCE", "delivery-matrix"),
        ]
        self.assertEqual(parent["requires"], [dict(rule=rule, contract=contract, scenario=scenario) for rule, contract, scenario in expected])
        dependencies = [f"command/{rule}/{contract}/linux-amd64-cgo/{scenario}" for rule, contract, scenario in expected]
        observations = {}
        for item in [parent, *(obligations[name] for name in dependencies)]:
            for check in item["checks"]:
                observations[(check, item["platform"], item["contract"])] = "passed"
        now = dt.datetime(2026, 10, 4, tzinfo=dt.timezone.utc)
        result = v.decide(config, observations, [], [], now)
        self.assertIn(key, result["passed"])
        self.assertEqual(result["status"], "blocked", "Synthetic boundary facts cannot complete whole-system acceptance")
        for dependency in dependencies:
            item = obligations[dependency]
            for check in item["checks"]:
                incomplete = dict(observations)
                incomplete.pop((check, item["platform"], item["contract"]))
                result = v.decide(config, incomplete, [], [], now)
                self.assertIn(key, result["missing"])
                self.assertIn("dependency-not-passed:" + dependency, result["details"][key])

    def test_command_effect_dependencies(self) -> None:
        """The complete behavior/effect boundary needs all independent native coordinates, not a lone marker."""
        root = Path(__file__).resolve().parents[1]
        config = v.decode(v.read(root / "development.json"))
        obligations = v.expand(config)
        parents = [f"command/{rule}/COMMAND-ASSURANCE/linux-amd64-cgo/full-rule" for rule in ("DEV-ASYNC", "DEV-TIME", "DEV-CONTRACT")]
        dependencies = [dict(rule=rule, contract="COMMAND-ASSURANCE", scenario="full-rule") for rule in ("DEV-CORE", "DEV-COVERAGE", "DEV-FAULT")]
        for key in parents:
            self.assertTrue(obligations[key]["aggregate"])
            self.assertEqual(obligations[key]["checks"], [])
            self.assertEqual(obligations[key]["requires"], dependencies)
        # Synthetic native statuses challenge only the decision engine; original runner artifacts supply acceptance facts.
        observations = {}
        for check in config["checks"]:
            if check["component"] == "command" and check["adapter"] != "unavailable":
                for probe in check["probes"]:
                    observations[(check["id"], "linux-amd64-cgo", probe["contract"])] = "passed"
        now = dt.datetime(2026, 10, 4, tzinfo=dt.timezone.utc)
        result = v.decide(config, observations, [], [], now)
        self.assertTrue(set(parents) <= set(result["passed"]))
        self.assertEqual(result["status"], "blocked", "Component effect evidence cannot certify containing services or release")
        # These thirteen native coordinates cover the transitive source, behavior, decision, mutation, failure and consumer requirements.
        required = {
            (check, "linux-amd64-cgo", contract)
            for check, contracts in (
                (
                    "command-boundaries",
                    ("COMMAND-ASSURANCE", "COMMAND-BOUNDARY", "COMMAND-MCDC", "COMMAND-DECISION-INVENTORY", "COMMAND-FAULT", "COMMAND-ISOLATION"),
                ),
                ("command-structure-race", ("COMMAND-ASSURANCE", "COMMAND-FAULT", "COMMAND-ISOLATION")),
                ("command-mutants", ("COMMAND-MUTATION",)),
                ("command-consumer-inventory", ("COMMAND-ASSURANCE",)),
                ("command-consumer-polaris", ("COMMAND-ASSURANCE",)),
                ("command-consumer-astrolabe", ("COMMAND-ASSURANCE",)),
            )
            for contract in contracts
        }
        self.assertEqual(len(required), 13)
        self.assertTrue(required <= set(observations))
        for coordinate in required:
            for status in ("failed", "not-run", "unknown"):
                incomplete = dict(observations)
                incomplete[coordinate] = status
                result = v.decide(config, incomplete, [], [], now)
                with self.subTest(coordinate=coordinate, status=status):
                    self.assertTrue(set(parents) <= set(result["missing"]))
        result = v.decide(config, {}, [], [], now)
        self.assertTrue(set(parents) <= set(result["missing"]), "Empty aggregate evidence must not pass")
        numeric = "command/DEV-NUMERIC/COMMAND-ASSURANCE/linux-amd64-cgo/full-rule"
        expected = dependencies + [
            {"rule": "DEV-NUMERIC", "contract": "COMMAND-NUMERIC", "scenario": "typed-source"},
            {"rule": "DEV-ORACLE", "contract": "COMMAND-NUMERIC-CONTROLS", "scenario": "typed-controls"},
        ]
        self.assertTrue(obligations[numeric]["aggregate"])
        self.assertEqual(obligations[numeric]["checks"], [])
        self.assertEqual(obligations[numeric]["requires"], expected)
        self.assertIn(numeric, v.decide(config, observations, [], [], now)["passed"])
        coordinates = required | {
            (check, "linux-amd64-cgo", contract)
            for check in ("command-boundaries", "command-structure-race")
            for contract in ("COMMAND-NUMERIC", "COMMAND-NUMERIC-CONTROLS")
        }
        self.assertEqual(len(coordinates), 17)
        for coordinate in coordinates:
            for status in ("failed", "not-run", "unknown"):
                incomplete = dict(observations)
                incomplete[coordinate] = status
                with self.subTest(numeric_coordinate=coordinate, status=status):
                    self.assertIn(numeric, v.decide(config, incomplete, [], [], now)["missing"])
        self.assertIn(numeric, v.decide(config, {}, [], [], now)["missing"], "No numeric evidence means no aggregate numeric pass")
        model = "command/DEV-MODEL/COMMAND-ASSURANCE/linux-amd64-cgo/full-rule"
        expected = dependencies + [
            {"rule": "DEV-MODEL", "contract": "COMMAND-MODEL", "scenario": "finite-history"},
            {"rule": "DEV-ORACLE", "contract": "COMMAND-MODEL-CONTROLS", "scenario": "model-vectors"},
        ]
        self.assertTrue(obligations[model]["aggregate"])
        self.assertEqual(obligations[model]["checks"], [])
        self.assertEqual(obligations[model]["requires"], expected)
        self.assertIn(model, v.decide(config, observations, [], [], now)["passed"])
        coordinates = required | {
            (check, "linux-amd64-cgo", contract)
            for check in ("command-boundaries", "command-structure-race")
            for contract in ("COMMAND-MODEL", "COMMAND-MODEL-CONTROLS")
        }
        self.assertEqual(len(coordinates), 17)
        for coordinate in coordinates:
            for status in ("failed", "not-run", "unknown"):
                incomplete = dict(observations)
                incomplete[coordinate] = status
                with self.subTest(model_coordinate=coordinate, status=status):
                    self.assertIn(model, v.decide(config, incomplete, [], [], now)["missing"])
        self.assertIn(model, v.decide(config, {}, [], [], now)["missing"], "No complete model means no aggregate model pass")

        # Impact and adversarial audit require the complete owned scope and both shipping consumers.
        boundaries = [
            f"command/{rule}/COMMAND-ASSURANCE/linux-amd64-cgo/full-rule"
            for rule in ("DEV-STOP", "DEV-RETRY", "DEV-CAPACITY", "DEV-FAILURE", "DEV-ORACLE", "DEV-REPLAY", "DEV-MATRIX", "DEV-IMPACT", "DEV-AUDIT")
        ]
        expected = [
            {"rule": rule, "contract": "COMMAND-ASSURANCE", "scenario": "full-rule"}
            for rule in ("DEV-CORE", "DEV-COVERAGE", "DEV-FAULT", "DEV-ASYNC", "DEV-NUMERIC", "DEV-MODEL")
        ]
        for key in boundaries:
            self.assertTrue(obligations[key]["aggregate"])
            self.assertEqual(obligations[key]["checks"], [])
            self.assertEqual(obligations[key]["requires"], expected)
        compatibility = "command/DEV-COMPAT/COMMAND-ASSURANCE/linux-amd64-cgo/full-rule"
        self.assertNotIn("aggregate", obligations[compatibility])
        self.assertEqual(obligations[compatibility]["checks"], ["command-boundaries", "command-structure-race"])
        self.assertEqual(obligations[compatibility]["requires"], expected)
        boundaries.append(compatibility)
        coordinates = required | {
            (check, "linux-amd64-cgo", contract)
            for check in ("command-boundaries", "command-structure-race")
            for contract in ("COMMAND-NUMERIC", "COMMAND-NUMERIC-CONTROLS", "COMMAND-MODEL", "COMMAND-MODEL-CONTROLS")
        }
        self.assertEqual(len(coordinates), 21)
        self.assertTrue(coordinates <= set(observations))
        self.assertTrue(set(boundaries) <= set(v.decide(config, observations, [], [], now)["passed"]))
        for coordinate in coordinates:
            for status in ("failed", "not-run", "unknown", "interrupted"):
                incomplete = dict(observations)
                incomplete[coordinate] = status
                with self.subTest(boundary_coordinate=coordinate, status=status):
                    result = v.decide(config, incomplete, [], [], now)
                    self.assertTrue(set(boundaries) <= set(result["missing"]))
        self.assertTrue(set(boundaries) <= set(v.decide(config, {}, [], [], now)["missing"]), "Owned-boundary claims need every native prerequisite")
        for coordinate in coordinates:
            incomplete = dict(observations)
            incomplete.pop(coordinate)
            for replacement in (None, (coordinate[0], "windows-amd64", coordinate[2]), (coordinate[0], coordinate[1], "COMMAND-WRONG-CONTRACT")):
                candidate = dict(incomplete)
                if replacement is not None:
                    candidate[replacement] = "passed"
                with self.subTest(absent_or_substituted=coordinate, replacement=replacement):
                    self.assertTrue(set(boundaries) <= set(v.decide(config, candidate, [], [], now)["missing"]))
        for rule in ("DEV-REDGREEN", "DEV-GATE", "DEV-RELEASE"):
            key = f"command/{rule}/COMMAND-ASSURANCE/linux-amd64-cgo/full-rule"
            self.assertEqual(obligations[key]["checks"], ["command-qualification"])
            self.assertIn(
                key,
                v.decide(config, observations, [], [], now)["missing"],
                "These proofs cannot fabricate historical fixes, protected trust or release authority",
            )

    def test_weighted_inventory(self) -> None:
        """Three of five owned statements hit; duplicates cannot inflate the denominator or conceal unbuilt files."""
        result = statements.summary(self.profile, self.metadata(), self.source, self.root)
        self.assertEqual(result["totals"]["owned"], {"files": 3, "statements": 5, "statements_hit": 3})
        self.assertEqual(result["totals"]["generated"], {"files": 1, "statements": 1, "statements_hit": 0})
        self.assertEqual(result["totals"]["test"], {"files": 1, "statements": 0, "statements_hit": 0})
        self.assertEqual(result["native_records"], 4)
        self.assertEqual(result["unique_blocks"], 3)
        self.assertEqual(result["scope"]["without_build_selection"], ["unit/future_windows.go"])
        self.assertEqual(result["scope"]["without_native_counters"], ["unit/empty.go"])
        self.assertEqual(result["scope"]["zero_statement_files"], ["unit/empty.go"])
        self.assertEqual(result["scope"]["untested_packages"], [self.module + "/wire"])
        self.assertEqual([item["statements"] for item in result["unhit"]], [2, 1])
        self.assertEqual(result["qualification"], "not-evaluated")

    def test_profile_modes(self) -> None:
        """Native set duplicates use union; count/atomic duplicates sum counts while preserving one statement block."""
        module, files = statements.sources(self.source, self.root)
        _, selected = statements.packages(self.metadata(), files, module, self.root)
        for mode in ("set", "count", "atomic"):
            with self.subTest(mode=mode):
                data = ("mode: " + mode + "\n" + "example.org/fixture/unit/state.go:3.17,4.13 3 1\n" * 2).encode()
                actual, blocks, records = statements.profile(data, files, selected)
                self.assertEqual(actual, mode)
                self.assertEqual(records, 2)
                self.assertEqual(len(blocks), 1)
                self.assertEqual(blocks[0]["statements"], 3)
                self.assertEqual(blocks[0]["count"], 1 if mode == "set" else 2)
        # The actual compiler emits empty switch-arm blocks with equal endpoints and zero statements.
        data = b"mode: atomic\nexample.org/fixture/unit/state.go:4.13,4.13 0 0\n"
        _, blocks, records = statements.profile(data, files, selected)
        self.assertEqual((records, blocks[0]["statements"], blocks[0]["count"]), (1, 0, 0))
        with self.assertRaisesRegex(v.Invalid, "go-profile-counter"):
            statements.profile(data.replace(b"0 0", b"1 0"), files, selected)

    def test_malformed_profiles(self) -> None:
        """Reject unknown sources, conflicting denominators, invalid coordinates, encodings and counter values."""
        invalid = [
            b"mode: unknown\n",
            b"mode: atomic\n",
            b"\xff",
            self.profile.replace(b"3 1", b"3 -1"),
            self.profile.replace(b"3 1", b"3 NaN"),
            self.profile.replace(b"3 1", b"3 9223372036854775808"),
            self.profile.replace(b"3.17,4.13", b"4.13,3.17"),
            self.profile.replace(b"3.17,4.13", b"3.17,40.13"),
            self.profile.replace(b"3.17,4.13", b"3.99,4.13"),
            self.profile.replace(b"3 2", b"4 2"),
            self.profile.replace(b"unit/state.go", b"unit/future_windows.go"),
            self.profile.replace(b"unit/state.go", b"unit/unregistered.go"),
            self.profile.replace(b"mode: atomic", b"mode: set"),
            self.profile + b"\n",
        ]
        for data in invalid:
            with self.subTest(data=data[:96]):
                with self.assertRaises(v.Invalid):
                    statements.summary(data, self.metadata(), self.source, self.root)
        with patch.object(statements, "LIMIT", 10):
            with self.assertRaisesRegex(v.Invalid, "go-profile-size"):
                statements.profile(self.profile, {}, {})

    def test_package_identity(self) -> None:
        """Build metadata cannot introduce external modules, path escapes, duplicate files or hidden build failures."""
        alterations = [
            ("Dir", str(self.root.parent)),
            ("ImportPath", "external.org/unit"),
            ("Incomplete", True),
            ("Error", {"Err": "broken"}),
            ("DepsErrors", [{"Err": "broken"}]),
            ("GoFiles", ["state.go", "state.go"]),
            ("GoFiles", ["../state.go"]),
            ("GoFiles", ["unregistered.go"]),
            ("GoFiles", ["state_test.go"]),
            ("GoFiles", "state.go"),
            ("Module", {"Path": self.module, "Main": False, "Dir": str(self.root)}),
        ]
        for field, value in alterations:
            with self.subTest(field=field, value=value):
                listing = copy.deepcopy(self.listing)
                listing[0][field] = value
                with self.assertRaises(v.Invalid):
                    statements.summary(self.profile, self.metadata(listing), self.source, self.root)
        with self.assertRaisesRegex(v.Invalid, "go-package-identity"):
            statements.summary(self.profile, self.metadata(self.listing * 2), self.source, self.root)
        for data in (b"", b"{} trailing", b"[]", b'{"Dir":1,"Dir":2}', b'{"Dir":NaN}', b"\xff"):
            with self.subTest(data=data):
                with self.assertRaises(v.Invalid):
                    statements.stream(data)
        with patch.object(statements, "LIMIT", 10):
            with self.assertRaisesRegex(v.Invalid, "go-packages-size"):
                statements.stream(self.metadata())

    def test_source_identity(self) -> None:
        """A changed owned file/module and a marker inside code cannot manufacture a generated-code exclusion."""
        target = self.root / "unit/state.go"
        old = target.read_bytes()
        target.write_bytes(old + b"// changed\n")
        with self.assertRaisesRegex(v.Invalid, "go-source-drift"):
            statements.summary(self.profile, self.metadata(), self.source, self.root)
        source = copy.deepcopy(self.source)
        target.write_bytes(b"package unit\n// Code generated fake. DO NOT EDIT.\n")
        next(item for item in source["files"] if item["path"] == "unit/state.go")["sha256"] = v.file_digest(target)
        _, files = statements.sources(source, self.root)
        self.assertEqual(files["unit/state.go"]["kind"], "owned")
        (self.root / "go.mod").write_bytes(b"module changed.org/fixture\n")
        with self.assertRaisesRegex(v.Invalid, "go-module-identity"):
            statements.sources(self.source, self.root)

    def events(self) -> list[dict]:
        """Emit an independent complete tested package and an explicitly untested generated package."""
        values = [
            {"Package": self.module + "/unit", "Action": "start"},
            {"Package": self.module + "/unit", "Action": "run", "Test": "TestRead"},
            {"Package": self.module + "/unit", "Action": "pass", "Test": "TestRead"},
            {"Package": self.module + "/unit", "Action": "pass"},
            {"Package": self.module + "/wire", "Action": "start"},
            {"Package": self.module + "/wire", "Action": "skip"},
        ]
        return values

    def test_native_terminals(self) -> None:
        """Zero exit without every package/test terminal is insufficient, and skipped real tests never pass."""
        groups = statements.summary(self.profile, self.metadata(), self.source, self.root)["packages"]
        encode = lambda values: b"\n".join(json.dumps(item).encode() for item in values)
        self.assertEqual(statements.terminals(encode(self.events()), groups), {self.module + "/unit": "pass", self.module + "/wire": "untested"})
        variations = [self.events()[:-1], self.events()[1:], self.events() + [self.events()[3]], self.events()[3:], self.events()[:4]]
        for action in ("skip", "fail", "unknown"):
            events = self.events()
            events[2]["Action"] = action
            variations.append(events)
        for events in variations:
            with self.subTest(events=events):
                with self.assertRaises(v.Invalid):
                    statements.terminals(encode(events), groups)

    def bundle(self) -> Path:
        """Assemble clearly synthetic executor records to challenge the real bundle boundary."""
        run = self.root / "build/native"
        run.mkdir(parents=True)
        value = {"version": 1, "source": v.write_new(run / "source.json", self.source), "profile": v.write_new(run / "all.cover", self.profile)}
        for kind, argv, data, times in (
            ("packages", ["fixture-go", "list", "-json", "./..."], self.metadata(), ("01", "02")),
            (
                "tests",
                [
                    "fixture-go",
                    "test",
                    "-json",
                    "-count=1",
                    "-coverpkg=" + self.module + "/...",
                    "-covermode=atomic",
                    "-coverprofile=" + str(run / "all.cover"),
                    "./...",
                ],
                b"\n".join(json.dumps(item).encode() for item in self.events()),
                ("03", "04"),
            ),
        ):
            directory = run / kind
            directory.mkdir()
            record = {
                "id": kind,
                "argv": argv,
                "complete": True,
                "cleanup": True,
                "exit_code": 0,
                "termination": "exited",
                "executable_sha256": "0" * 64,
                "platform": "fixture-only",
                "resolved_environment": {"CGO_ENABLED": "1", "TMPDIR": str(directory / "tmp")},
                "started_at": "2026-10-03T00:00:" + times[0] + "Z",
                "finished_at": "2026-10-03T00:00:" + times[1] + "Z",
                "stdout": v.write_new(directory / "stdout.log", data),
                "stderr": v.write_new(directory / "stderr.log", b""),
            }
            v.write_new(directory / (kind + ".process.json"), {"argv": argv, "cwd": str(self.root)})
            value[kind] = {**v.write_new(directory / "record.json", record), "path": kind + "/record.json"}
        v.write_new(run / "bundle.json", value)
        return run

    def test_collector(self) -> None:
        """Successful collection preserves raw gaps and local provenance without creating a gate pass."""
        run = self.bundle()
        output = self.root / "build/report"
        with patch.object(coverage.build, "ROOT", self.root), patch.object(v, "source", return_value=self.source), patch("builtins.print"):
            self.assertEqual(coverage.main(["--go", str(run), "--output", str(output)]), 0)
        result = v.decode(v.read(output / "summary.json"))
        self.assertEqual(result["qualification"], "not-evaluated")
        self.assertEqual(result["inputs"]["trust"], "local")
        self.assertEqual(result["totals"]["owned"]["statements_hit"], 3)
        self.assertEqual(result["scope"]["without_native_counters"], ["unit/empty.go"])

    def test_bundle_tampering(self) -> None:
        """Hash mismatches, narrowed commands, incomplete cleanup, unknown fields and source drift block import."""
        run = self.bundle()
        original = v.decode(v.read(run / "bundle.json"))
        alterations = [("cleanup", False), ("exit_code", 1), ("exit_code", False), ("termination", "timeout"), ("complete", False)]
        for index, (field, value) in enumerate(alterations):
            bundle = copy.deepcopy(original)
            record = v.decode(v.read(run / "tests/record.json"))
            record[field] = value
            name = field + str(index) + ".json"
            bundle["tests"] = {**v.write_new(run / "tests" / name, record), "path": "tests/" + name}
            (run / "bundle.json").write_bytes(v.encode(bundle))
            with patch.object(v, "source", return_value=self.source):
                with self.assertRaises(v.Invalid):
                    statements.collect(run, self.root / "build/report", self.root)
        for index, argument in enumerate(
            ("-run=TestRead", "-count=2", "-coverpkg=./unit", "-coverpkg=" + self.module + "/unit", "-coverpkg=other.org/module/...", "-tags=production")
        ):
            bundle = copy.deepcopy(original)
            record = v.decode(v.read(run / "tests/record.json"))
            if argument.startswith("-coverpkg="):
                record["argv"] = [argument if value.startswith("-coverpkg=") else value for value in record["argv"]]
            else:
                record["argv"].insert(-1, argument)
            name = "arguments" + str(index) + ".json"
            bundle["tests"] = {**v.write_new(run / "tests" / name, record), "path": "tests/" + name}
            (run / "tests/tests.process.json").write_bytes(v.encode({"argv": record["argv"], "cwd": str(self.root)}))
            (run / "bundle.json").write_bytes(v.encode(bundle))
            with patch.object(v, "source", return_value=self.source):
                with self.assertRaisesRegex(v.Invalid, "go-native-instrumentation"):
                    statements.collect(run, self.root / "build/report", self.root)
        (run / "tests/tests.process.json").write_bytes(v.encode({"argv": v.decode(v.read(run / "tests/record.json"))["argv"], "cwd": str(self.root)}))
        (run / "bundle.json").write_bytes(v.encode(original))
        for name in ("all.cover", "source.json", "packages/stdout.log", "tests/stdout.log", "tests/stderr.log"):
            path = run / name
            data = path.read_bytes()
            path.write_bytes(data + b"tampering")
            with patch.object(v, "source", return_value=self.source):
                with self.assertRaises(v.Invalid):
                    statements.collect(run, self.root / "build/report", self.root)
            path.write_bytes(data)
        with patch.object(v, "source", return_value={**self.source, "status": "changed"}):
            with self.assertRaisesRegex(v.Invalid, "go-workspace-drift"):
                statements.collect(run, self.root / "build/report", self.root)
        (run / "bundle.json").write_bytes(v.encode({**original, "passed": True}))
        with self.assertRaisesRegex(v.Invalid, "go-bundle-format"):
            statements.collect(run, self.root / "build/report", self.root)


if __name__ == "__main__":
    unittest.main()
