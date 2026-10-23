"""Challenge exact-coordinate retained qualification and reject promotion of finite native facets into full rules."""

from collections.abc import Iterator, Sequence
import copy
import datetime as dt
import io
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import (
    negatives,
    pairedproof,
    profiles,
    qualification,
    qualificationdata,
    release,
    verify as v,
)

ROOT = Path(__file__).resolve().parents[1]


def policy() -> dict:
    """Read registered obligations; synthetic observation maps below never supply native qualification."""
    return v.decode(v.read(ROOT / "development.json"))


class ClosureTests(unittest.TestCase):
    """Sealed source context cannot grant native execution credit or complete a normative rule."""

    @classmethod
    def setUpClass(cls) -> None:
        """Read the registered metadata once; no product binary or original producer is invoked."""
        from tools import nativeclosures

        cls.nativeclosures = nativeclosures
        cls.source = v.source(ROOT)
        cls.facts, cls.checked = nativeclosures.read(ROOT, cls.source)
        declared = v.decode(v.read(ROOT / nativeclosures.MANIFEST))
        cls.manifest = v.decode(v.read(ROOT / declared["inputs"]["manifest"]["path"]))
        cls.files = nativeclosures.archive(ROOT / declared["inputs"]["archive"]["path"], cls.manifest)

    def test_binding(self) -> None:
        """A source revision invalidates its exact closure; even current context grants no full-rule pass."""
        self.assertEqual(set(self.facts), {"star", "pulsar", "comet"})
        reader = qualification.Evaluator(ROOT)
        for component, fact in self.facts.items():
            self.assertEqual(reader.fact(component + "-native-closures"), fact)
            self.assertEqual(fact["state"], "retained-context-only")
            self.assertEqual(fact["all_fixed_mutation_coordinates"], 39)
            self.assertIn("not-killed", fact["original_native_outcomes"].values())
            self.assertIn("failed", fact["original_native_outcomes"].values())
            for rule in qualification.CRITERIA:
                self.assertEqual(qualification.support(fact, rule, platform="linux-amd64-cgo"), set())
                self.assertEqual(qualification.support(fact, rule, platform="windows-amd64"), set())
        changed = {**self.source, "files": [{**row, "sha256": "0" * 64} if row["path"] == "comet/cpp/src/core.cpp" else row for row in self.source["files"]]}
        facts = self.nativeclosures.inspect(self.files, changed)
        self.assertTrue(any("comet/cpp/src/core.cpp" in item["binding"]["changed"] for item in facts["comet"]["source_closures"]))
        sdk = self.files["linux-comet-tsan-mapping.json"]
        target = next(name for name, row in sdk["closures"].items() if row["status"] == "current")
        unknown = {**sdk, "closures": {**sdk["closures"], target: {**sdk["closures"][target], "unbound_compiled_inputs": ["unbound.a"]}}}
        facts = self.nativeclosures.inspect(self.files | {"linux-comet-tsan-mapping.json": unknown}, self.source)
        self.assertTrue(any(item["binding"]["status"] == "unbound-compiled-inputs" for item in facts["comet"]["source_closures"]))
        original_fact = reader.fact

        def context_only(name: str) -> dict:
            """Exercise the real new intake while unrelated facets retain explicit synthetic, unqualified inputs."""
            if name.endswith("-native-closures"):
                return original_fact(name)
            return {
                "facet": "unrelated-parser-control",
                "state": "source-review-required",
                "components": sorted(qualification.FACETS[name]),
                "platforms": ["linux-amd64-cgo"],
                "boundary": "Synthetic unrelated context; no native credit.",
            }

        with (
            patch.object(reader, "fact", side_effect=context_only),
            patch.object(
                qualificationdata, "performance", side_effect=AssertionError("Closure intake must not replay the independent performance interpretation")
            ) as unrelated,
        ):
            report = reader.report("comet-qualification")
            name = "comet-native-closures"
            self.assertIn(name, report["evidence"])
            self.assertTrue(all(row["status"] == "incomplete" for row in report["obligations"]))
            forged = {**report, "evidence": {**report["evidence"], name: {**report["evidence"][name], "state": "qualified-facet"}}}
            with self.assertRaisesRegex(v.Invalid, "qualification-report"):
                reader.observations(v.encode(forged), v.unique(reader.config["checks"])["comet-qualification"])
            unrelated.assert_not_called()
        reader.finish()

    def test_custody(self) -> None:
        """Reject foreign members, changed seals, erased failures and borrowed source inputs."""
        import io
        import tarfile

        ledger = self.files["fixed-mutation-coordinate-closure.json"]
        altered = {**ledger, "rows": [{**ledger["rows"][0], "current_scope": "forged-current"}] + ledger["rows"][1:]}
        with self.assertRaisesRegex(v.Invalid, "native-closures-mutation-summary"):
            self.nativeclosures.inspect(self.files | {"fixed-mutation-coordinate-closure.json": altered}, self.source)
        outcomes = self.files["native-outcomes.json"]
        altered = {**outcomes, "outcomes": {name: {**row, "status": "passed"} for name, row in outcomes["outcomes"].items()}}
        with self.assertRaisesRegex(v.Invalid, "native-closures-failure-preservation"):
            self.nativeclosures.inspect(self.files | {"native-outcomes.json": altered}, self.source)
        with self.assertRaisesRegex(v.Invalid, "native-closures-owned-input"):
            self.nativeclosures.binding({"../foreign.cpp": "0" * 64}, {})
        with self.assertRaisesRegex(v.Invalid, "native-closures-owned-input"):
            self.nativeclosures.binding({"comet/cpp/src/core.cpp": None}, {})
        with patch.object(v, "read", return_value=b"{}"):
            with self.assertRaisesRegex(v.Invalid, "native-closures-manifest-pin"):
                self.nativeclosures.read(ROOT, self.source)
        with tempfile.TemporaryDirectory(prefix="native-closure-control-", dir=ROOT / "build/results/assurance") as temporary:
            path = Path(temporary) / "foreign.tar.gz"
            with tarfile.open(path, "w:gz") as bundle:
                member = tarfile.TarInfo("../foreign.json")
                member.size = 2
                bundle.addfile(member, io.BytesIO(b"{}"))
            with self.assertRaisesRegex(v.Invalid, "native-closures-archive-member"):
                self.nativeclosures.archive(path, {"files": {"../foreign.json": {"bytes": 2, "sha256": v.digest(b"{}")}}})


class QualificationTests(unittest.TestCase):
    """Keep evidence support, per-rule decisions and protected whole-system eligibility separate."""

    def test_coordinates(self) -> None:
        """A passed contract token or one qualified rule cannot discharge another rule sharing that contract."""
        config = policy()
        component = copy.deepcopy(next(row for row in config["components"] if row["id"] == "star"))
        component["requirements"] = [row for row in component["requirements"] if row["rule"] in {"DEV-CAPACITY", "DEV-OPERATE"}]
        config["components"] = [component]
        keys = list(v.expand(config))
        self.assertEqual(len(keys), 2)
        now = dt.datetime.now(dt.timezone.utc)
        legacy = {("star-qualification", "linux-amd64-cgo", "STAR-ASSURANCE"): "passed"}
        self.assertEqual(v.decide(config, legacy, [], [], now)["passed"], [])
        one = legacy | {
            (
                "star-qualification",
                "linux-amd64-cgo",
                "STAR-ASSURANCE",
                keys[0],
            ): "passed"
        }
        self.assertEqual(v.decide(config, one, [], [], now)["passed"], [keys[0]])
        wrong = {("star-qualification", "windows-amd64", "STAR-ASSURANCE", keys[1]): "passed"}
        self.assertEqual(v.decide(config, wrong, [], [], now)["passed"], [])
        both = one | {
            (
                "star-qualification",
                "linux-amd64-cgo",
                "STAR-ASSURANCE",
                keys[1],
            ): "passed"
        }
        result = v.decide(config, both, ["synthetic-protected-authority-missing"], [], now)
        self.assertEqual(result["passed"], sorted(keys))
        self.assertEqual(result["status"], "blocked")

    def test_configuration(self) -> None:
        """The actual schema admits only the reviewed scope, budget and manifest declarations."""
        config, _, _ = v.configuration(ROOT / "development.json", ROOT)
        checks = v.unique(config["checks"])
        self.assertEqual(len(v.expand(config)), 1370)
        self.assertEqual(v.file_digest(ROOT / qualification.MANIFEST), qualification.MODEL)
        native = checks["verification-python"]
        suite = unittest.TestLoader().loadTestsFromNames(native["argv"][4:])

        def names(selection: unittest.TestSuite) -> Iterator[str]:
            """Yield test identifiers recursively from nested discovery suites."""
            for item in selection:
                if isinstance(item, unittest.TestSuite):
                    yield from names(item)
                else:
                    yield item.id()

        self.assertEqual(sorted(names(suite)), native["expected_tests"])
        for name in qualification.CHECKS:
            check = checks[name]
            qualification.configuration(check, config)
            for field, value in (
                ("manifest_sha256", "0" * 64),
                ("timeout_s", 901),
                (
                    "platforms",
                    (["linux-amd64-cgo"] if check["platforms"] == ["windows-amd64"] else ["windows-amd64"]),
                ),
                ("argv", check["argv"] + ["--accept-partial"]),
            ):
                with self.subTest(check=name, field=field), self.assertRaisesRegex(v.Invalid, "qualification-configuration"):
                    qualification.configuration({**check, field: value}, config)

    def test_source_association(self) -> None:
        """Explicit results-only association preserves original report identity and every incomplete criterion."""
        current = v.source(ROOT)
        before = copy.deepcopy(current)
        v.unique(before["files"], "path")["docs/validation.md"]["sha256"] = "0" * 64
        original = {
            "at": v.utc(),
            "executed": before,
            "after": current,
            "changed_after_interpretation": ["docs/validation.md"],
            "native_application_commands": 0,
        }
        with tempfile.TemporaryDirectory(prefix="qualification-association-", dir=ROOT / "build/results/assurance") as temporary:
            path = Path(temporary) / "association.json"
            path.write_bytes(v.encode(original))
            checksum = v.file_digest(path)
            with self.assertRaisesRegex(v.Invalid, "qualification-association-pin"):
                qualification.Evaluator(ROOT, association=path)
            reader = qualification.Evaluator(ROOT, association=path, association_sha256=checksum)
            self.assertEqual(reader.source, current)
            self.assertEqual(reader.evidence_source, before)
            check = v.unique(reader.config["checks"])["admission-gap-evidence"]
            # Synthetic facts exercise metadata plumbing only and cannot supply complete coverage or authority.
            fact = {
                "facet": "finite-resources",
                "state": "qualified-facet",
                "synthetic": True,
                "platforms": ["linux-amd64-cgo"],
            }
            with patch.object(reader, "fact", return_value=fact):
                report = reader.report(check["id"])
                self.assertEqual(report["source_sha256"], v.digest(v.encode(before)))
                states = reader.observations(v.encode(report), check)
                self.assertTrue(states and all(value.startswith("qualification-missing:") for value in states.values()))
                ordinary = qualification.Evaluator(ROOT)
                with patch.object(ordinary, "fact", return_value=fact), self.assertRaisesRegex(v.Invalid, "qualification-report-mismatch"):
                    ordinary.observations(v.encode(report), check)
            from tools import predicates, structure

            # Synthetic bundles isolate the metadata boundary; the native parser backend supplies no product credit here.
            directory = Path(temporary) / "admission"
            directory.mkdir()
            checks = {name: v.unique(reader.config["checks"])[name] for name in ("admission-structure", "admission-independence")}
            (directory / "inputs.json").write_bytes(v.encode({"source": before, "checks": checks}))
            fixtures = {}
            for name in checks:
                output = directory / name
                retained = output / "structure"
                retained.mkdir(parents=True)
                source_path = retained / "source.json"
                source_path.write_bytes(v.encode(before))
                bundle = {
                    "version": 5 if name == "admission-structure" else 4,
                    "source": structure.artifact(retained, source_path),
                    "retained": {},
                }
                for archive in predicates.archives(ROOT):
                    path_fixture = retained / "retained" / (archive + ".tar.gz")
                    path_fixture.parent.mkdir(exist_ok=True)
                    path_fixture.write_bytes(b"synthetic-metadata-control")
                    bundle["retained"][archive] = structure.artifact(retained, path_fixture)
                bundle_path = retained / "bundle.json"
                bundle_path.write_bytes(v.encode(bundle))
                stdout = v.encode(
                    {
                        "bundle_sha256": v.file_digest(bundle_path),
                        "source_sha256": v.digest(v.encode(before)),
                    }
                )
                (output / "stdout.json").write_bytes(stdout)
                record = {
                    "exit_code": 0,
                    "complete": True,
                    "cleanup": True,
                    "termination": "exited",
                    "stdout": structure.artifact(output, output / "stdout.json"),
                    "structure": structure.artifact(output, bundle_path),
                }
                (output / "observation-record.json").write_bytes(v.encode(record))
                fixtures[name] = (output, record, stdout)
            counts = structure.revision(ROOT, structure.PACKAGE)["counts"]

            def synthetic_backend(root: Path, archives: dict[str, bytes], *, structural: bool = False) -> dict:
                """Exercise both dispatch paths while keeping fabricated observations confined to this unit control."""
                return {
                    "status": "complete-under-assumptions",
                    "statements": {"reachable_under_assumptions": {"statements_hit": counts[0]}},
                    "boolean": {
                        "totals": {
                            "roots": {"observed": counts[1]},
                            "atoms": {"observed": counts[2]},
                        }
                    },
                    "controls": {"observed": counts[3]},
                    "independence": {"supported_conditions": 165},
                }

            original_pins = {name: v.file_digest(output / "structure/source.json") for name, (output, _, _) in fixtures.items()}
            with patch.object(predicates, "reconcile", side_effect=synthetic_backend):
                observed, _ = reader.admission_entries(directory)
                self.assertEqual(len(observed), 2)
                output, record, stdout = fixtures["admission-independence"]
                evidence = {"directory": output, "record": record}
                with self.assertRaisesRegex(v.Invalid, "entry-workspace-drift"):
                    v.parse_observations(stdout, checks["admission-independence"], ROOT, evidence)
                context = {"path": path, "sha256": checksum}
                evidence["source_association"] = context
                self.assertEqual(
                    v.parse_observations(stdout, checks["admission-independence"], ROOT, evidence),
                    ({"ADMISSION-ASSURANCE": 165}, []),
                )
                with self.assertRaisesRegex(v.Invalid, "association-pin"):
                    structure.load(
                        output / "structure",
                        ROOT,
                        checks["admission-independence"],
                        record,
                        source_association={**context, "sha256": "0" * 64},
                    )
                changed = copy.deepcopy(current)
                v.unique(changed["files"], "path")["go.mod"]["sha256"] = "0" * 64
                with patch.object(v, "source", side_effect=[current, changed]), self.assertRaisesRegex(v.Invalid, "entry-source-changed"):
                    structure.load(
                        output / "structure",
                        ROOT,
                        checks["admission-independence"],
                        record,
                        source_association=context,
                    )
                unsupported = v.unique(reader.config["checks"])["polaris-entry-qualification"]
                with self.assertRaisesRegex(v.Invalid, "source-association-scope"):
                    structure.load(
                        output / "structure",
                        ROOT,
                        unsupported,
                        record,
                        source_association=context,
                    )
            self.assertEqual(
                original_pins,
                {name: v.file_digest(output / "structure/source.json") for name, (output, _, _) in fixtures.items()},
            )
            reader.finish()

    def test_reports(self) -> None:
        """Explicitly synthetic facets exercise report plumbing; full rules retain every missing normative criterion."""
        reader = qualification.Evaluator(ROOT)
        kinds = {
            **{name + "-native-closures": "source-bound-native-context" for name in ("star", "pulsar", "comet")},
            "three-star-residence": "finite-resources",
            "paired-performance": "performance",
            "admission-race": "race",
            "storage-race": "race",
            "star-targeted-mutations": "targeted-mutations",
            "star-precision-mutation": "targeted-mutations",
            "go-component-race": "race",
            "comet-go-targeted-mutations": "targeted-mutations",
            "comet-go-windows-targeted-mutations": "targeted-mutations",
            "windows-sdk-residence": "finite-resources",
            "admission-native-trace": "retained-native-trace-links",
            "storage-native-trace": "retained-native-trace-links",
            "admission-native-supply": "retained-native-dependency-identities",
            "storage-native-supply": "retained-native-dependency-identities",
            "admission-native-compat": "retained-native-toolchain-context",
            **{
                name + "-source-ownership": "source-ownership"
                for name in (
                    "common",
                    "admin",
                    "verification",
                    "tools",
                    "benchmarks",
                    "protocol",
                    "documentation",
                )
            },
        }

        def synthetic(name: str) -> dict:
            """Create facet metadata for parser controls without claiming native execution credit."""
            return {
                "facet": kinds[name],
                "state": "retained-context-only" if name.endswith("-native-closures") else "qualified-facet",
                "components": sorted(qualification.FACETS[name]),
                "platforms": ["windows-amd64" if name in {"comet-go-windows-targeted-mutations", "windows-sdk-residence"} else "linux-amd64-cgo"],
                "boundary": "Synthetic parser controls; no native credit.",
                "applies_to": (
                    ["DEV-ASYNC", "DEV-CONTRACT", "DEV-COVERAGE", "DEV-EVIDENCE", "DEV-FAULT", "DEV-MODEL", "DEV-REDGREEN"]
                    if name.endswith("-native-closures")
                    else ["DEV-" + name.rsplit("-", 1)[-1].upper()] if "-native-" in name else []
                ),
            }

        with patch.object(reader, "fact", side_effect=synthetic):
            reports = {name: reader.report(name) for name in qualification.CHECKS}
            self.assertEqual(sum(len(row["obligations"]) for row in reports.values()), 521)
            for name, report in reports.items():
                self.assertTrue(all(row["status"] == "incomplete" and row["missing"] for row in report["obligations"]))
                states = reader.observations(v.encode(report), v.unique(reader.config["checks"])[name])
                self.assertTrue(all(state != "passed" for state in states.values()))
                forged = copy.deepcopy(report)
                forged["obligations"][0].update(status="passed", missing=[])
                with self.assertRaisesRegex(v.Invalid, "qualification-report-mismatch"):
                    reader.observations(v.encode(forged), v.unique(reader.config["checks"])[name])
                omitted = copy.deepcopy(report)
                omitted["obligations"].pop()
                with self.assertRaisesRegex(v.Invalid, "qualification-report-mismatch"):
                    reader.observations(v.encode(omitted), v.unique(reader.config["checks"])[name])
            star = reports["star-qualification"]["obligations"]
            capacity = next(row for row in star if "/DEV-CAPACITY/" in row["obligation"])
            self.assertIn("paired-performance", capacity["evidence"])
            mutation = next(row for row in star if row["obligation"].endswith("/mutation"))
            self.assertIn("star-targeted-mutations", mutation["evidence"])
            operating = reports["gap-operate"]["obligations"][0]
            self.assertIn("storage-race", operating["evidence"])
            sdk_mutation = next(
                row
                for row in reports["comet-go-qualification"]["obligations"]
                if "/linux-amd64-cgo/" in row["obligation"] and row["obligation"].endswith("/mutation")
            )
            self.assertIn("targeted-mutations", sdk_mutation["supported"])
            self.assertIn("complete-mutation-domain", sdk_mutation["missing"])
            windows = [row for row in reports["comet-go-qualification"]["obligations"] if "/windows-amd64/" in row["obligation"]]
            self.assertEqual(len(windows), 41)
            partial = [row for row in windows if row["supported"]]
            self.assertEqual(len(partial), 5)
            self.assertEqual(
                sorted(row["supported"] for row in partial),
                [["finite-resources"], ["finite-resources"], ["retained-native-content"], ["targeted-mutations"], ["targeted-mutations"]],
            )
            self.assertTrue(all(set(row["evidence"]) <= {"comet-go-windows-targeted-mutations", "windows-sdk-residence"} for row in partial))
            self.assertNotIn("paired-performance", reports["gap-capacity"]["evidence"])
            for name in release.CHECKS:
                report = reports[name]
                self.assertEqual(report["release_context"]["state"], "static-specification-linked")
                self.assertIsNone(report["release_context"]["protected_run"])
                self.assertEqual(report["release_context"]["qualification"], "not-issued")
                self.assertEqual(len(report["obligations"]), 1)
                self.assertEqual(report["obligations"][0]["supported"], [])
                changed = copy.deepcopy(report)
                changed["release_context"]["qualification"] = "protected"
                with self.assertRaisesRegex(v.Invalid, "qualification-report-mismatch"):
                    reader.observations(v.encode(changed), v.unique(reader.config["checks"])[name])
            context, _ = release.context(ROOT)
            self.assertEqual(len(context["supported_infeasible_defense_arguments"]), 2)
            self.assertEqual(len(context["unproved_infeasibility"]), 3)
            ledger = v.decode(v.read(ROOT / release.DEFENSES))
            self.assertTrue(
                all(row["retained"] and not row["excluded_from_native_denominator"] and row["native_hit_credit"] == 0 for row in ledger["boundaries"])
            )
            altered = copy.deepcopy(ledger)
            altered["boundaries"][0]["excluded_from_native_denominator"] = True
            original = v.read
            with patch.object(release, "DEFENSES_SHA256", v.digest(v.encode(altered))), patch.object(v, "read", wraps=v.read) as read:
                read.side_effect = lambda path, *args, **kwargs: v.encode(altered) if Path(path) == ROOT / release.DEFENSES else original(path, *args, **kwargs)
                with self.assertRaisesRegex(v.Invalid, "release-defense-credit"):
                    release.context(ROOT)
            for name in (
                "admission-gap-trace",
                "gap-trace",
                "admission-gap-supply",
                "gap-supply",
                "admission-gap-compat",
            ):
                row = reports[name]["obligations"][0]
                self.assertEqual(row["supported"], [])
                self.assertEqual(row["missing"], row["required"])
                self.assertTrue(any("-native-" in evidence for evidence in row["evidence"]))
            # Exercise the maintained bundle parser, not just direct report calls.
            from tests.test_verify import EvidenceTests

            fixture = EvidenceTests("test_positive_fixture")
            fixture.setUp()
            self.addCleanup(fixture.doCleanups)
            check = v.unique(reader.config["checks"])["star-qualification"]
            record = fixture.evidence["checks"][0]
            record.update(
                id=check["id"],
                argv=check["argv"],
                environment=check["environment"],
                resolved_environment=check["environment"],
            )
            for forged in (False, True):
                payload = copy.deepcopy(reports[check["id"]])
                if forged:
                    payload["obligations"][0].update(status="passed", missing=[])
                filename = "forged.json" if forged else "qualification.json"
                record["stdout"] = v.write_new(fixture.directory / filename, payload)
                fixture.seal(fixture.directory, fixture.evidence)
                with patch.object(qualification, "Evaluator", return_value=reader):
                    _, observed, _, hard, _ = v.bundle(
                        reader.config,
                        fixture.pins,
                        fixture.approved,
                        fixture.directory,
                        ROOT,
                        fixture.source,
                    )
                self.assertEqual(len(observed), len(payload["obligations"]))
                self.assertTrue(all(len(key) == 4 and value != "passed" for key, value in observed.items()))
                self.assertEqual("native-format:" + check["id"] in hard, forged)

    def test_archive(self) -> None:
        """Large pinned campaigns retain all members while traversal, links and case aliases remain forbidden."""

        def archive(names: list[tuple[str, bool]]) -> bytes:
            """Build an in-memory archive of regular files and optional escaping symlinks."""
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w:gz") as stream:
                for name, link in names:
                    item = tarfile.TarInfo(name)
                    if link:
                        item.type, item.linkname = tarfile.SYMTYPE, "outside"
                        stream.addfile(item)
                    else:
                        item.size = 1
                        stream.addfile(item, io.BytesIO(b"x"))
            return output.getvalue()

        self.assertEqual(
            len(qualificationdata.unpack(archive([(f"sample-{n}/record", False) for n in range(5000)]))),
            5000,
        )
        for names in (
            [("../outside", False)],
            [("/outside", False)],
            [("one", False), ("ONE", False)],
            [("symlink", True)],
        ):
            with self.subTest(names=names), self.assertRaisesRegex(v.Invalid, "qualification-archive-member"):
                qualificationdata.unpack(archive(names))
        reference = {"path": "stdout.log", "bytes": 1, "sha256": v.digest(b"x")}
        members = {"command/stdout.log": b"x"}
        self.assertEqual(pairedproof.reference(members, PurePosixPath("command"), reference, 1), b"x")
        for altered in (
            {"path": "../stdout.log"},
            {"path": "/stdout.log"},
            {"sha256": "0" * 64},
            {"bytes": 2},
        ):
            with self.assertRaisesRegex(v.Invalid, "qualification-performance"):
                pairedproof.reference(members, PurePosixPath("command"), reference | altered, 1)

    def test_evidence(self) -> None:
        """Local native content cannot supply protected custody, complete coverage or unrelated rule observations."""
        fact = {
            "facet": "finite-resources",
            "state": "qualified-facet",
            "platforms": ["linux-amd64-cgo"],
        }
        self.assertEqual(
            qualification.support(fact, "DEV-EVIDENCE"),
            {"finite-resources", "retained-native-content"},
        )
        self.assertEqual(qualification.support(fact, "DEV-CAPACITY"), {"finite-resources"})
        self.assertEqual(
            qualification.support(fact | {"state": "source-review-required"}, "DEV-EVIDENCE"),
            set(),
        )
        for name in ("admission-gap-evidence", "gap-evidence"):
            reader = qualification.Evaluator(ROOT)
            component = qualification.CHECKS[name]
            with patch.object(reader, "fact", return_value=fact | {"components": [component]}):
                report = reader.report(name)
                self.assertEqual(len(report["obligations"]), 1)
                row = report["obligations"][0]
                self.assertEqual(row["supported"], ["retained-native-content"])
                self.assertEqual(row["status"], "incomplete")
                self.assertEqual(
                    set(row["missing"]),
                    {
                        "complete-obligation-evidence-coverage",
                        "protected-authority",
                        "independent-collector-and-immutable-custody",
                    },
                )
                self.assertTrue(row["evidence"])
                check = v.unique(reader.config["checks"])[name]
                self.assertTrue(all(state.startswith("qualification-missing:") for state in reader.observations(v.encode(report), check).values()))
                forged = copy.deepcopy(report)
                forged["trust"] = "ci"
                forged["obligations"][0].update(status="passed", missing=[], supported=row["required"])
                with self.assertRaisesRegex(v.Invalid, "qualification-report-mismatch"):
                    reader.observations(v.encode(forged), check)
                # Synthetic command envelopes exercise adoption only; their partial reports grant no product pass.
                fixture = v.decode(v.read(ROOT / "tests/fixtures/retained-entries.json"))
                original = ROOT / fixture["directory"] / "admission-gap-delivery-matrix/record.json"
                record = v.decode(v.read(original))
                with tempfile.TemporaryDirectory(
                    prefix="evidence-entry-controls-",
                    dir=ROOT / "build/results/assurance",
                ) as temporary:
                    directory = Path(temporary)
                    receipt = v.write_new(
                        directory / "inputs.json",
                        {"source": reader.source, "checks": {name: check}},
                    )
                    output = directory / name
                    output.mkdir()
                    record.update(id=name, argv=[record["argv"][0], *check["argv"][1:]])
                    record["stdout"] = v.write_new(output / "stdout.log", v.encode(report))
                    record["stderr"] = v.write_new(output / "stderr.log", b"")
                    v.write_new(output / "record.json", record)
                    observed, records = reader.retained_entries(directory, receipt["sha256"])
                    self.assertTrue(observed and all(len(key) == 4 and value != "passed" for key, value in observed.items()))
                    self.assertEqual(records[name]["state"], "qualification-incomplete")
                    self.assertEqual(records[name]["observations"], {})
                    self.assertEqual(set(records[name]["obligations"]), {row["obligation"]})
                    reader.finish()
            with patch.object(reader, "fact", return_value=fact | {"state": "source-review-required"}):
                stale = reader.report(name)["obligations"][0]
                self.assertEqual(stale["supported"], [])
                self.assertIn("retained-native-content", stale["missing"])

    def test_component_platforms(self) -> None:
        """Linux facets cannot qualify Windows coordinates or turn bounded evidence into whole rules."""
        fact = {
            "facet": "finite-resources",
            "state": "qualified-facet",
            "platforms": ["linux-amd64-cgo"],
        }
        self.assertEqual(qualification.support(fact, "DEV-EVIDENCE", platform="windows-amd64"), set())
        for name, count in (
            ("polaris-server-qualification", 28),
            ("astrolabe-qualification", 28),
            ("comet-go-qualification", 82),
            ("command-qualification", 10),
            ("comet-qualification", 60),
            ("common-qualification", 30),
            ("admin-qualification", 30),
            ("verification-qualification", 30),
            ("tools-qualification", 60),
            ("benchmarks-qualification", 30),
            ("protocol-qualification", 30),
            ("documentation-qualification", 28),
        ):
            reader = qualification.Evaluator(ROOT)
            with patch.object(reader, "fact", return_value=fact):
                report = reader.report(name)
            self.assertEqual(len(report["obligations"]), count)
            self.assertEqual(report["native_application_commands"], 0)
            self.assertTrue(all(row["status"] == "incomplete" and row["missing"] for row in report["obligations"]))
            objects = v.expand(reader.config)
            windows = [row for row in report["obligations"] if objects[row["obligation"]]["platform"] == "windows-amd64"]
            self.assertEqual(
                len(windows),
                {
                    "comet-go-qualification": 41,
                    "comet-qualification": 30,
                    "admin-qualification": 30,
                    "tools-qualification": 30,
                    "documentation-qualification": 28,
                }.get(name, 0),
            )
            self.assertTrue(all(not row["supported"] and not row["evidence"] for row in windows))
        source = {row["path"]: row["sha256"] for row in v.source(ROOT)["files"] if row["sha256"] is not None}
        self.assertEqual(
            qualificationdata.source_binding(ROOT, source, build=True)["status"],
            "current",
        )
        altered = source | {"CMakeLists.txt": "0" * 64}
        self.assertEqual(qualificationdata.source_binding(ROOT, altered)["changed"], [])
        self.assertIn(
            "CMakeLists.txt",
            qualificationdata.source_binding(ROOT, altered, build=True)["changed"],
        )

    def test_component_race(self) -> None:
        """Retained root and nested-module outcomes keep their commands, package identities and source closure."""
        manifest = v.decode(v.read(ROOT / qualification.MANIFEST))["evidence"]["go-component-race"]
        raw = v.read(ROOT / manifest["path"], 64 * 1024**2)
        self.assertEqual(v.digest(raw), manifest["sha256"])
        files = qualificationdata.unpack(raw)
        with patch.object(
            v,
            "execute",
            side_effect=AssertionError("Evidence mapping must not execute a product"),
        ):
            result = qualificationdata.go_race(ROOT, files, manifest["packages"])
        self.assertEqual(result["binding"]["status"], "current")
        self.assertEqual(result["components"], ["astrolabe", "comet-go", "command", "polaris-server"])
        profiles = result["profiles"]
        self.assertEqual(sum(row["cases"] for row in profiles["root-race"]["packages"].values()), 741)
        self.assertEqual(sum(row["cases"] for row in profiles["sdk-race"]["packages"].values()), 248)
        for profile, field, value in (
            ("root-race", "argv", ["go", "test", "./..."]),
            ("sdk-race", "argv", profiles["root-race"]["argv"]),
            ("root-race", "duration_ms", 300001),
            (
                "root-race",
                "environment",
                profiles["root-race"]["environment"] | {"GOMAXPROCS": "4"},
            ),
        ):
            prefix = "source/build/commands/" + profile + "-test/"
            record = v.decode(files[prefix + "record.json"])
            record[field] = value
            with self.subTest(profile=profile, field=field), self.assertRaisesRegex(v.Invalid, "qualification-go-command"):
                qualificationdata.go_race(
                    ROOT,
                    files | {prefix + "record.json": v.encode(record)},
                    manifest["packages"],
                )
        package = "github.com/eosforge/astra/comet/go"
        omitted = copy.deepcopy(manifest["packages"])
        omitted["comet-go"][package].pop()
        with self.assertRaisesRegex(v.Invalid, "qualification-go-case-inventory"):
            qualificationdata.go_race(ROOT, files, omitted)
        source = v.source(ROOT)
        source["files"].append({"path": "comet/go/added_test.go", "sha256": "0" * 64})
        with patch.object(v, "source", return_value=source):
            stale = qualificationdata.go_race(ROOT, files, manifest["packages"])
        self.assertEqual(stale["binding"]["status"], "source-review-required")
        self.assertIn("comet/go/added_test.go", stale["binding"]["changed"])
        reader = qualification.Evaluator(ROOT)
        with patch.object(qualificationdata, "unpack", wraps=qualificationdata.unpack) as unpack:
            reader.fact("admission-race")
            reader.fact("go-component-race")
            self.assertEqual(unpack.call_count, 1)
            reader.manifest["evidence"]["go-component-race"]["sha256"] = "0" * 64
            reader.facts.pop("go-component-race")
            with self.assertRaisesRegex(v.Invalid, "qualification-shared-archive-pin"):
                reader.fact("go-component-race")

    def test_go_mutations(self) -> None:
        """Fixed native SDK negatives require exact ordinary completions, overlays, assertions and retired identities."""
        manifest = v.decode(v.read(ROOT / qualification.MANIFEST))["evidence"]["comet-go-targeted-mutations"]
        raw = v.read(ROOT / manifest["path"], 64 * 1024**2)
        self.assertEqual(v.digest(raw), manifest["sha256"])
        files = qualificationdata.unpack(raw)
        seal = v.decode(v.read(ROOT / manifest["seal"]))
        inputs = v.decode(files["inputs.json"])
        with patch.object(
            v,
            "execute",
            side_effect=AssertionError("Static mapping must not execute a product"),
        ):
            result = qualificationdata.go_mutations(ROOT, files, seal)
        self.assertEqual(result["binding"]["status"], "current")
        self.assertEqual((result["mutants"], result["named_assertion_failures"]), (34, 60))
        self.assertEqual((result["ordinary_tests"], result["ordinary_completions"]), (98, 248))
        self.assertEqual((result["native_commands"], result["native_identities_retired"]), (38, 39))
        self.assertEqual((result["native_package_count"], result["installed_go_files"]), (325, 15657))
        self.assertTrue(all(row["outcome"] == "killed" and row["assertions"] for row in result["outcomes"]))
        with self.assertRaisesRegex(v.Invalid, "qualification-go-mutation-archive"):
            qualificationdata.go_mutations(ROOT, files | {"unregistered": b"extra"}, seal)

        def altered(name: str, fields: Sequence[str | int], value: object) -> dict[str, bytes]:
            """Damage a decoded view after archive framing so the inner evidence oracle must reject it."""
            data = v.decode(files[name])
            target = data
            for field in fields[:-1]:
                target = target[field]
            target[fields[-1]] = value
            return {name: v.encode(data)}

        def reject(reason: str, views: dict[str, bytes] | None = None, *, changed_seal: dict | None = None) -> None:
            """Require the declared semantic rejection, never an incidental parser exception."""
            with self.assertRaisesRegex(v.Invalid, "qualification-go-mutations: " + reason):
                negatives.reconcile(
                    files | (views or {}),
                    inputs,
                    seal if changed_seal is None else changed_seal,
                )

        reject("producer failed or incomplete", changed_seal=seal | {"failed": True})
        for name, fields, value, reason in (
            (
                "terminal.json",
                ("errors",),
                ["damaged-view"],
                "producer failed or incomplete",
            ),
            ("terminal.json", ("interrupted",), True, "producer failed or incomplete"),
            (
                "terminal.json",
                ("remaining_owned",),
                [{"pid": 1}],
                "producer failed or incomplete",
            ),
            (
                "terminal.json",
                ("unchanged", "source"),
                False,
                "producer input stability",
            ),
            (
                "terminal.json",
                ("cache_returned",),
                False,
                "native cache or campaign deadline",
            ),
            (
                "terminal.json",
                ("resources", "cpu.max"),
                "300000 100000",
                "native whole-task limits",
            ),
            (
                "terminal.json",
                ("resources", "memory.max"),
                "3221225472",
                "native whole-task limits",
            ),
            (
                "terminal.json",
                ("resources", "memory.events"),
                "oom_kill 1",
                "native resource limit event",
            ),
            (
                "cleanup.native.json",
                ("state", "MainPID"),
                "1",
                "native domain retirement",
            ),
            (
                "cleanup.native.json",
                ("retired", 0, "retired"),
                False,
                "native process retirement identity",
            ),
            (
                "cache-handoff.native.json",
                ("inode",),
                -1,
                "exclusive cache handoff identity",
            ),
            (
                "cache-return.native.json",
                ("inode",),
                -1,
                "exclusive cache return identity",
            ),
            (
                "collection-cache.native.json",
                ("actual_original_inode_returned",),
                False,
                "native independent cache return",
            ),
            (
                "installed-go.json",
                ("version",),
                "go version go1.27.1 linux/amd64",
                "installed Go distribution identity",
            ),
            (
                "collection-inputs.native.json",
                ("mismatches",),
                ["changed"],
                "collector detected changed native inputs",
            ),
            (
                "native/go-version/record.json",
                ("executable_sha256",),
                "0" * 64,
                "native Go executable identity",
            ),
            (
                "native/baseline/record.json",
                ("resolved_environment", "GOTOOLCHAIN"),
                "auto",
                "native effective environment",
            ),
        ):
            with self.subTest(member=name, fields=fields):
                reject(reason, altered(name, fields, value))
        reject("native manager completion", {"journal.native.json": v.encode([])})
        reject("native module source identity", {"module/extra.go": b"package comet\n"})
        terminal = v.decode(files["terminal.json"])
        terminal["completed"].pop("go-version")
        reject("native command denominator", {"terminal.json": v.encode(terminal)})
        command = {}
        for suffix in ("record.json", "request.json", "baseline.process.json"):
            name = "native/baseline/" + suffix
            data = v.decode(files[name])
            data["argv"][data["argv"].index("-timeout=120s")] = "-timeout=121s"
            command[name] = v.encode(data)
        reject("native ordinary selection or deadline", command)
        record = v.decode(files["native/baseline/record.json"])
        output = "native/baseline/" + record["stdout"]["path"]
        events = [v.decode(line) for line in files[output].splitlines() if line.strip()]
        index = next(index for index, row in enumerate(events) if row.get("Action") == "pass" and "/" in row.get("Test", ""))
        events.pop(index)
        damaged = b"".join(v.encode(row).replace(b"\n", b" ") + b"\n" for row in events)
        record["stdout"].update(bytes=len(damaged), sha256=v.digest(damaged))
        reject(
            "native complete ordinary completion denominator",
            {output: damaged, "native/baseline/record.json": v.encode(record)},
        )
        identifier = result["outcomes"][0]["id"]
        reject(
            "native exact semantic overlay",
            {"overlays/" + identifier + "/" + identifier + ".go.txt": b"not the prescribed mutation"},
        )
        reject(
            "native semantic raw observation disagreement",
            altered("native/" + identifier + "/observation.json", ("outcome",), "survived"),
        )
        source = v.source(ROOT)
        source["files"].append({"path": "comet/go/unbound_test.go", "sha256": "0" * 64})
        with patch.object(v, "source", return_value=source):
            stale = qualificationdata.go_mutations(ROOT, files, seal)
        self.assertEqual(stale["binding"]["status"], "source-review-required")
        self.assertIn("comet/go/unbound_test.go", stale["binding"]["changed"])

    def test_windows_residence(self) -> None:
        """Original cross-host raw streams bind finite Windows samples without new host or application queries."""
        item = v.decode(v.read(ROOT / qualification.MANIFEST))["evidence"]["windows-sdk-residence"]
        raw = v.read(ROOT / item["path"], 32 * 1024**2)
        self.assertEqual(v.digest(raw), item["sha256"])
        files = qualificationdata.unpack(raw)
        seal = v.decode(v.read(ROOT / item["seal"]))
        supplemental = {name: v.read(ROOT / artifact["path"]) for name, artifact in item["inputs"].items()}
        with patch.object(v, "execute", side_effect=AssertionError("Residence mapping must not execute products")):
            result = qualificationdata.windows_residence(ROOT, files, seal, **supplemental)
        self.assertEqual(result["binding"]["status"], "current")
        self.assertEqual(result["seconds"], 7200)
        self.assertEqual(result["samples"], 1440)
        self.assertEqual(result["windows"], [240, 300, 300, 300, 300])
        self.assertEqual(result["native_fd_metric"], "handles")
        self.assertEqual(result["bounds"]["status"], "passed")
        self.assertEqual(result["windows_job"]["memory_bytes"], 805306368)
        self.assertEqual(result["aggregate_memory_bytes"], 2 * 1024**3)
        self.assertEqual(result["clock_samples"], 7268)
        with self.assertRaisesRegex(v.Invalid, "qualification-windows-residence: archive members"):
            qualificationdata.windows_residence(ROOT, files | {"unregistered": b"extra"}, seal, **supplemental)
        native = qualificationdata.unpack(files["linux/evidence.tar.gz"])

        def damaged(name: str, fields: Sequence[str | int], value: object) -> tuple[dict[str, bytes], dict]:
            """Repair outer framing so changed original material reaches the intended semantic guard."""
            data = v.decode(files[name])
            target = data
            for field in fields[:-1]:
                target = target[field]
            target[fields[-1]] = value
            altered = files | {name: v.encode(data)}
            inventory = {path: {"bytes": len(raw), "sha256": v.digest(raw)} for path, raw in altered.items() if path != "manifest.json"}
            manifest = v.decode(files["manifest.json"]) | {"files": inventory}
            altered["manifest.json"] = v.encode(manifest)
            return altered, seal | {"files": inventory, "manifest_sha256": v.digest(altered["manifest.json"])}

        with patch.object(qualificationdata, "unpack", return_value=native):
            for name, fields, value, reason in (
                ("runtime/sdk.process.json", ("executable_sha256",), "0" * 64, "Windows original image identity"),
                ("runtime/record.json", ("cleanup",), False, "Windows command completion"),
                ("runtime/resource.cohort.json", ("owner", "pid"), 1, "Windows resource owner identity"),
                ("runtime/resource.result.json", ("complete",), False, "Windows resource completion"),
                ("runtime/resource.bounds.json", ("residence", "steady_samples"), 1439, "Windows complete finite bounds"),
                ("bounded-runtime/controller/job.native.json", ("memory_bytes",), 1073741824, "Windows original ancestor limits"),
            ):
                damaged_files, damaged_seal = damaged(name, fields, value)
                with self.subTest(member=name, fields=fields), self.assertRaisesRegex(v.Invalid, "qualification-windows-residence: " + reason):
                    qualificationdata.windows_residence(ROOT, damaged_files, damaged_seal, **supplemental)
            changed = copy.deepcopy(v.source(ROOT))
            changed["files"].append({"path": "comet/go/unrecorded_resource_test.go", "sha256": "0" * 64})
            with patch.object(v, "source", return_value=changed):
                stale = qualificationdata.windows_residence(ROOT, files, seal, **supplemental)
            self.assertEqual(stale["binding"]["status"], "source-review-required")
            self.assertIn("comet/go/unrecorded_resource_test.go", stale["binding"]["changed"])
        reader = qualification.Evaluator(ROOT)
        with patch.object(qualificationdata, "windows_residence", return_value=result):
            fact = reader.fact("windows-sdk-residence")
            self.assertEqual(fact["platforms"], ["windows-amd64"])
            self.assertEqual(qualification.support(fact, "DEV-CAPACITY", platform="linux-amd64-cgo"), set())
        reader.finish()

    def test_windows_mutations(self) -> None:
        """Actual Windows raw failures retain their exact source, platform, limits and assertion denominator."""
        item = v.decode(v.read(ROOT / qualification.MANIFEST))["evidence"]["comet-go-windows-targeted-mutations"]
        raw = v.read(ROOT / item["path"], 8 * 1024**2)
        self.assertEqual(v.digest(raw), item["sha256"])
        files = qualificationdata.unpack(raw)
        seal = v.decode(v.read(ROOT / item["seal"]))
        source, installed = (v.read(ROOT / item["inputs"][name]["path"], 8 * 1024**2) for name in ("source", "installed"))
        with patch.object(v, "execute", side_effect=AssertionError("Windows evidence mapping must not execute products")):
            result = qualificationdata.windows_mutations(ROOT, files, seal, source, installed)
        self.assertEqual(result["binding"]["status"], "current")
        self.assertEqual((result["mutants"], result["named_assertion_failures"]), (34, 60))
        self.assertEqual((result["ordinary_tests"], result["ordinary_completions"]), (98, 248))
        self.assertEqual((result["native_commands"], result["native_identities_retired"], result["packaged_retired_identities"]), (38, 39, 58))
        self.assertEqual((result["native_package_count"], result["native_package_source_files"], result["installed_go_files"]), (326, 1598, 15657))
        self.assertEqual(result["native_limits"]["memory_bytes"], 2 * 1024**3)
        self.assertTrue(all(row["outcome"] == "killed" and row["assertions"] for row in result["outcomes"]))
        with self.assertRaisesRegex(v.Invalid, "qualification-windows-mutation-archive"):
            qualificationdata.windows_mutations(ROOT, files | {"unregistered": b"extra"}, seal, source, installed)
        with self.assertRaisesRegex(v.Invalid, "qualification-windows-mutation-inputs"):
            qualificationdata.windows_mutations(ROOT, files, seal, source, installed + b" ")
        prefix = "go-upgrade-comet-mutations-windows-current-1/"
        installation = v.decode(installed)

        def altered(name: str, fields: Sequence[str | int], value: object) -> dict[str, bytes]:
            """Damage the inner view so the expected semantic guard, rather than an archive hash, rejects it."""
            data = v.decode(files[name])
            target = data
            for field in fields[:-1]:
                target = target[field]
            target[fields[-1]] = value
            return files | {name: v.encode(data)}

        for name, fields, value, reason in (
            (prefix + "terminal.json", ("errors",), ["damaged-view"], "Windows producer failed or incomplete"),
            (prefix + "terminal.json", ("unchanged", "source"), False, "Windows producer input stability"),
            (prefix + "inputs.json", ("budget", "cpus"), 4, "Windows original execution budget"),
            (prefix + "controller.json", ("runner_sha256",), "0" * 64, "Windows owner inputs"),
            (prefix + "received.json", ("windows_retired", 0, "open_error"), 5, "Windows original process retirement"),
            ("readers/go2-comet-mutations-windows-run1/job.native.json", ("memory_bytes",), 3 * 1024**3, "Windows original ancestor limits"),
            (prefix + "native/baseline/record.json", ("platform",), "linux-amd64-cgo", "Windows native executable or platform"),
            (prefix + "native/baseline/record.json", ("cleanup",), False, "Windows native command incomplete or timed out"),
            (prefix + "native/baseline/record.json", ("started_at",), "2026-10-18T00:00:00Z", "Windows native serial order"),
            (prefix + "native/baseline/record.json", ("stdout", "sha256"), "0" * 64, "Windows native stream integrity"),
            (prefix + "package-closure/received.json", ("compiled_source_files",), 1599, "Windows native package closure"),
        ):
            with self.subTest(member=name, fields=fields), self.assertRaisesRegex(v.Invalid, "qualification-go-mutations: " + reason):
                negatives.windows(altered(name, fields, value), installation, seal)
        first = v.decode(files[prefix + "cases.json"])[0]["id"]
        overlay = prefix + "overlays/" + first + "/" + first + ".go.txt"
        with self.assertRaisesRegex(v.Invalid, "qualification-go-mutations: native exact semantic overlay"):
            negatives.windows(files | {overlay: b"unrelated replacement"}, installation, seal)
        current = v.source(ROOT)
        changed = copy.deepcopy(current)
        changed["files"].append({"path": "comet/go/unrecorded_test.go", "sha256": "0" * 64})
        with patch.object(v, "source", return_value=changed):
            stale = qualificationdata.windows_mutations(ROOT, files, seal, source, installed)
        self.assertEqual(stale["binding"]["status"], "source-review-required")
        self.assertIn("comet/go/unrecorded_test.go", stale["binding"]["changed"])
        reader = qualification.Evaluator(ROOT)
        fact = reader.fact("comet-go-windows-targeted-mutations")
        self.assertEqual(fact["platforms"], ["windows-amd64"])
        self.assertEqual(qualification.support(fact, "DEV-EVIDENCE", platform="linux-amd64-cgo"), set())
        reader.facts.pop("comet-go-windows-targeted-mutations")
        reader.manifest["evidence"]["comet-go-windows-targeted-mutations"]["inputs"]["installed"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(v.Invalid, "qualification-windows-mutation-pin"):
            reader.fact("comet-go-windows-targeted-mutations")
        failed_readers = [
            v.decode(raw) for name, raw in files.items() if name.startswith("readers/") and name.count("/") == 2 and name.endswith("/record.json")
        ]
        self.assertTrue(any(record["exit_code"] != 0 for record in failed_readers))
        reader.finish()

    def test_profiles(self) -> None:
        """Original native profiles retain source/oracle closure, serial limits, images and collector retirement."""
        native, custody, immutable, checked = profiles.load(ROOT, ROOT / profiles.MANIFEST, profiles.MODEL)
        consumer = v.source(ROOT)
        config = policy()
        with patch.object(
            v,
            "execute",
            side_effect=AssertionError("Profile ingestion must not execute products"),
        ):
            observed, result = profiles.inspect(ROOT, native, custody, immutable, config, consumer)
        self.assertEqual(set(result["profiles"]), set(profiles.CHECKS))
        self.assertTrue(observed and all(value == "passed" for value in observed.values()))
        self.assertEqual([result["profiles"][name]["tests"] for name in profiles.CHECKS], [47, 259])
        self.assertEqual(result["native_identities_retired"], 19)
        self.assertEqual(result["whole_memory_peak_bytes"], 786931712)
        self.assertIn("max 2649", result["controller_memory_events"])
        self.assertEqual(result["native_application_commands"], 0)
        self.assertTrue({"tests/fixtures/native-closures.json", "tools/nativeclosures.py"} <= set(result["producer_binding"]["changed_consumer_paths"]))
        self.assertEqual(len(checked), 4)
        mirror = copy.deepcopy(consumer)
        mirror["commit"] = None if consumer["commit"] is not None else "0" * 40
        mirrored, metadata = profiles.inspect(ROOT, native, custody, immutable, config, mirror)
        self.assertEqual(mirrored, observed)
        self.assertEqual(metadata["producer_source_sha256"], result["producer_source_sha256"])
        self.assertNotEqual(metadata["consumer_source_sha256"], result["consumer_source_sha256"])
        changed = copy.deepcopy(consumer)
        v.unique(changed["files"], "path")["tools/models.py"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(v.Invalid, "profile-producer-source"):
            profiles.inspect(ROOT, native, custody, immutable, config, changed)
        for name in ("tests/fixtures/unregistered.json", "tools/unregistered-reader.py"):
            changed = copy.deepcopy(consumer)
            changed["files"].append({"path": name, "sha256": "0" * 64})
            with self.subTest(unreviewed_consumer=name), self.assertRaisesRegex(v.Invalid, "profile-producer-source"):
                profiles.inspect(ROOT, native, custody, immutable, config, changed)
        changed = copy.deepcopy(consumer)
        changed["files"].append({"path": "internal/admission/added_test.go", "sha256": "0" * 64})
        with self.assertRaisesRegex(v.Invalid, "profile-producer-source"):
            profiles.inspect(ROOT, native, custody, immutable, config, changed)
        changed_config = copy.deepcopy(config)
        v.unique(changed_config["checks"])["admission-model"]["expected_tests"].pop()
        with self.assertRaisesRegex(v.Invalid, "profile-declaration-drift"):
            profiles.inspect(ROOT, native, custody, immutable, changed_config, consumer)
        with self.assertRaisesRegex(v.Invalid, "profile-manifest-pin"):
            profiles.load(ROOT, ROOT / profiles.MANIFEST, "0" * 64)

        def altered(name: str, fields: Sequence[str | int], value: object) -> tuple[dict[str, bytes], dict[str, bytes]]:
            """Repair native member framing so a damaged view reaches the intended semantic guard."""
            data = v.decode(native[name])
            target = data
            for field in fields[:-1]:
                target = target[field]
            target[fields[-1]] = value
            raw = v.encode(data)
            seal = v.decode(custody["sealed.native.json"])
            seal["files"][name] = {"bytes": len(raw), "sha256": v.digest(raw)}
            return native | {name: raw}, custody | {"sealed.native.json": v.encode(seal)}

        for name, fields, value, reason in (
            ("terminal.json", ("errors",), ["damaged-view"], "native-terminal"),
            ("terminal.json", ("interrupted",), True, "native-terminal"),
            ("terminal.json", ("remaining_owned",), [{"pid": 1}], "native-terminal"),
            (
                "terminal.json",
                ("whole_after", "memory.max"),
                "4294967296",
                "native-limits",
            ),
            ("terminal.json", ("whole_after", "memory.events"), "oom 1", "native-oom"),
            (
                "commands/admission-model/record.json",
                ("cleanup",),
                False,
                "native-result",
            ),
            (
                "commands/admission-model/record.json",
                ("duration_ms",),
                180001,
                "native-result",
            ),
            (
                "commands/admission-model/record.json",
                ("resolved_environment", "GOMAXPROCS"),
                "2",
                "native-environment",
            ),
            (
                "commands/storage-examples/record.json",
                ("started_at",),
                "2026-10-19T16:13:00Z",
                "serial-order",
            ),
            (
                "commands/admission-model/leaf.after.json",
                ("cgroup.procs",),
                "999",
                "leaf-retirement",
            ),
            (
                "commands/admission-model/test-images.native.json",
                ("errors",),
                ["missing"],
                "test-images",
            ),
            (
                "commands/admission-model/test-images.native.json",
                ("observed", 0, "sha256"),
                "0" * 64,
                "test-image-binding",
            ),
            (
                "commands/admission-model/record.json",
                ("stdout", "path"),
                "../outside",
                "stream-path",
            ),
            (
                "commands/admission-model/record.json",
                ("stdout", "sha256"),
                "0" * 64,
                "stream-integrity",
            ),
        ):
            damaged, outer = altered(name, fields, value)
            with self.subTest(member=name, fields=fields), self.assertRaisesRegex(v.Invalid, "profile-" + reason):
                profiles.inspect(ROOT, damaged, outer, immutable, config, consumer)
        retired = v.decode(custody["retirement.native.json"])
        retired["retired"].pop()
        with self.assertRaisesRegex(v.Invalid, "profile-retirement-inventory"):
            profiles.inspect(
                ROOT,
                native,
                custody | {"retirement.native.json": v.encode(retired)},
                immutable,
                config,
                consumer,
            )
        received = copy.deepcopy(immutable)
        received["collector_retired"]["current_start_ticks"] = received["collector_retired"]["identity"]["start_ticks"]
        with self.assertRaisesRegex(v.Invalid, "profile-collector-retirement"):
            profiles.inspect(ROOT, native, custody, received, config, consumer)

    def test_profile_inventory(self) -> None:
        """Only supplied native leaves contribute; a historical baseline or synthetic facet adds no passes."""
        reader = qualification.Evaluator(ROOT)
        fact = {
            "facet": "finite-resources",
            "state": "qualified-facet",
            "platforms": ["linux-amd64-cgo"],
        }
        with patch.object(reader, "fact", return_value=fact):
            report = reader.inventory(
                profile_entries=ROOT / profiles.MANIFEST,
                profile_entries_sha256=profiles.MODEL,
            )
        self.assertEqual(report["obligation_count"], 1370)
        self.assertEqual(len(report["local_gate"]["passed"]), 44)
        self.assertIsNone(report["admission_entries"])
        self.assertIsNone(report["verification_native"])
        self.assertIsNone(report["native_case_entries"])
        self.assertEqual(report["native_application_commands"], 0)
        self.assertEqual(report["protected_qualification"], "not-issued")
        objects = v.expand(reader.config)
        self.assertTrue(all(set(objects[key]["checks"]) <= set(profiles.CHECKS) for key in report["local_gate"]["passed"]))
        self.assertTrue(all(objects[key]["platform"] == "linux-amd64-cgo" for key in report["local_gate"]["passed"]))
        with self.assertRaisesRegex(v.Invalid, "qualification-profile-pin"):
            reader.inventory(profile_entries=ROOT / profiles.MANIFEST)
        with self.assertRaisesRegex(v.Invalid, "qualification-inventory-inputs"):
            reader.inventory()
        reader.finish()

    def test_native_context(self) -> None:
        """Finite native links and identities remain contextual evidence, with no approval or matrix completion."""
        native, custody, immutable, checked = profiles.load(ROOT, ROOT / profiles.MANIFEST, profiles.MODEL)
        current, config = v.source(ROOT), policy()
        with patch.object(
            v,
            "execute",
            side_effect=AssertionError("Context mapping must not execute products"),
        ):
            with patch.object(profiles, "load", return_value=(native, custody, immutable, checked)):
                facts, actual_checked = qualificationdata.native_context(ROOT, config, current)
                changed = copy.deepcopy(current)
                v.unique(changed["files"], "path")["internal/admission/node.go"]["sha256"] = "0" * 64
                with self.assertRaisesRegex(v.Invalid, "profile-producer-source"):
                    qualificationdata.native_context(ROOT, config, changed)
        self.assertEqual(actual_checked, checked)
        self.assertEqual(
            set(facts),
            {
                "admission/trace",
                "admission/supply",
                "admission/compat",
                "polaris-storage/trace",
                "polaris-storage/supply",
            },
        )
        original = qualificationdata.entry.unpack(native["source.tar.gz"])
        declared = v.decode(native["inputs.json"])
        dependencies = v.decode(native["dependencies.before.json"])
        for component, name, cases in (
            ("admission", "admission-model", 47),
            ("polaris-storage", "storage-examples", 259),
        ):
            trace, supply = (facts[component + "/" + aspect] for aspect in ("trace", "supply"))
            self.assertEqual(trace["native_cases"], cases)
            self.assertEqual(trace["binding"]["status"], "current")
            self.assertEqual(trace["approval"], "not-issued")
            probes = declared["checks"][name]["probes"]
            self.assertEqual(
                [(row["contract"], row["test"], row["declared_minimum_hits"]) for row in trace["links"]],
                [(row["contract"], row["test"], row["minimum_hits"]) for row in probes],
            )
            for link in trace["links"]:
                location = link["source"]
                raw = original[location["path"]]
                self.assertEqual(v.digest(raw), location["sha256"])
                self.assertTrue(raw.decode("utf-8").splitlines()[location["line"] - 1].startswith("func " + link["test"].split("/", 1)[0] + "("))
                self.assertTrue(link["native_test_passed"])
                self.assertGreaterEqual(link["native_contract_total_hits"], link["declared_minimum_hits"])
            self.assertEqual(supply["origin_license_security_approval"], "not-issued")
            self.assertEqual(
                supply["source_locks"],
                {name: v.digest(original[name]) for name in ("go.mod", "go.sum", "dependencies.lock.json")},
            )
            self.assertEqual(supply["native_tools"], declared["tools"])
            self.assertEqual(
                supply["native_dependency_trees"],
                {name: {"files": len(values), "sha256": v.digest(v.encode(values))} for name, values in dependencies.items()},
            )
        compat = facts["admission/compat"]
        record = v.decode(native["commands/admission-model/record.json"])
        self.assertEqual(compat["compatibility_matrix"], "incomplete")
        self.assertEqual(compat["native_platform"], "linux-amd64-cgo")
        self.assertEqual(compat["native_argv"], record["argv"])
        self.assertEqual(compat["native_toolchain"], record["toolchain"])
        reader = qualification.Evaluator(ROOT)
        with patch.object(qualificationdata, "native_context", return_value=(facts, checked)) as interpret:
            for name, component in qualification.FACETS.items():
                if reader.manifest["evidence"][name]["kind"] == "native-context":
                    fact = reader.fact(name)
                    self.assertEqual(set(fact["components"]), component)
                    self.assertEqual(fact["platforms"], ["linux-amd64-cgo"])
                    self.assertEqual(
                        qualification.support(fact, "DEV-TRACE", platform="windows-amd64"),
                        set(),
                    )
            self.assertEqual(interpret.call_count, 1)
            # Existing archive facets and manifest-only contexts must coexist in the shared-pin lookup.
            self.assertEqual(reader.fact("three-star-residence")["facet"], "finite-resources")
        for field, value in (
            ("manifest_sha256", "0" * 64),
            ("aspect", "supply"),
            ("component", "polaris-storage"),
            ("extra", True),
        ):
            item = reader.manifest["evidence"]["admission-native-trace"]
            reader.facts.pop("admission-native-trace", None)
            with patch.dict(item, {field: value}), self.assertRaisesRegex(v.Invalid, "qualification-native-context-manifest"):
                reader.fact("admission-native-trace")
        reader.finish()

    def test_source_audit(self) -> None:
        """Actual ownership observations remain scoped to unchanged owned files and their recorded native platform."""
        item = v.decode(v.read(ROOT / qualification.MANIFEST))["evidence"]["common-source-ownership"]
        raw = v.read(ROOT / item["path"], 64 * 1024**2)
        self.assertEqual(v.digest(raw), item["sha256"])
        files = qualificationdata.unpack(raw)
        seal = v.decode(v.read(ROOT / item["seal"]))
        retired = v.decode(v.read(ROOT / item["retired"]))
        config, current = policy(), v.source(ROOT)
        with patch.object(
            v,
            "execute",
            side_effect=AssertionError("Ownership mapping must not execute products"),
        ):
            facts = qualificationdata.source_audit(files, seal, retired, config, current)
        self.assertEqual(
            set(facts),
            {
                "common",
                "admin",
                "verification",
                "tools",
                "benchmarks",
                "protocol",
                "documentation",
            },
        )
        for name in ("common", "admin", "benchmarks", "protocol"):
            self.assertEqual(facts[name]["binding"]["status"], "current")
            self.assertEqual(facts[name]["native_cases"], 8)
            self.assertEqual(facts[name]["native_canonical_check"], "gap-scope")
            self.assertGreater(facts[name]["binding"]["files"], 0)
        for name, changed in (
            ("verification", "development.json"),
            ("tools", "tools/qualification.py"),
            ("documentation", "docs/features/verification.md"),
        ):
            self.assertEqual(facts[name]["binding"]["status"], "source-review-required")
            self.assertIn(changed, facts[name]["binding"]["changed"])
        altered = copy.deepcopy(current)
        altered["files"].append({"path": "common/src/unrecorded.cpp", "sha256": "0" * 64})
        result = qualificationdata.source_audit(files, seal, retired, config, altered)
        self.assertEqual(result["common"]["binding"]["status"], "source-review-required")
        self.assertIn("common/src/unrecorded.cpp", result["common"]["binding"]["changed"])
        altered = copy.deepcopy(current)
        v.unique(altered["files"], "path")["tools/verify.py"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(v.Invalid, "qualification-source-audit-reader"):
            qualificationdata.source_audit(files, seal, retired, config, altered)
        changed_config = copy.deepcopy(config)
        v.unique(changed_config["scope"]["components"])["common"]["paths"].append("unrecorded")
        with self.assertRaisesRegex(v.Invalid, "qualification-source-audit-scope"):
            qualificationdata.source_audit(files, seal, retired, changed_config, current)
        reader = qualification.Evaluator(ROOT)
        with patch.object(qualificationdata, "source_audit", wraps=qualificationdata.source_audit) as audit:
            common = reader.fact("common-source-ownership")
            reader.fact("protocol-source-ownership")
            self.assertEqual(audit.call_count, 1)
            self.assertEqual(common["platforms"], ["linux-amd64-cgo"])
            self.assertEqual(
                qualification.support(common, "DEV-EVIDENCE", platform="windows-amd64"),
                set(),
            )
            reader.manifest["evidence"]["protocol-source-ownership"]["retired_sha256"] = "0" * 64
            reader.facts.pop("protocol-source-ownership")
            with self.assertRaisesRegex(v.Invalid, "qualification-shared-archive-pin"):
                reader.fact("protocol-source-ownership")

    def test_residence(self) -> None:
        """Recompute real finite windows; changed budgets, omitted samples and self-reported passes cannot qualify."""
        manifest = v.decode(v.read(ROOT / qualification.MANIFEST))["evidence"]["three-star-residence"]
        raw = v.read(ROOT / manifest["path"], 64 * 1024**2)
        self.assertEqual(v.digest(raw), manifest["sha256"])
        files = qualificationdata.unpack(raw)
        result = qualificationdata.residence(ROOT, files)
        self.assertEqual(result["seconds"], 7200)
        self.assertEqual(result["samples"], 1434)
        self.assertEqual(result["windows"], [239, 299, 299, 299, 298])
        self.assertEqual(result["binding"]["status"], "current")
        self.assertEqual(len(result["owners"]), 7)
        self.assertEqual(set(result["component_owners"]), {"polaris-server", "astrolabe", "comet-go"})
        for member, fields, value, reason in (
            ("inputs.json", ("plan", "seconds"), 3600, "budget"),
            (
                "inputs.json",
                ("plan", "limits", "star", "rss", "maximum"),
                512 * 1024**2,
                "policy|limits",
            ),
            ("bounds.native.json", ("status",), "forged", "bounds"),
            ("terminal.json", ("errors",), ["failed"], "terminal"),
            (
                "cohort.native.json",
                ("identities", 1, "command", 0),
                "/wrong/control",
                "components",
            ),
        ):
            data = v.decode(files[member])
            target = data
            for field in fields[:-1]:
                target = target[field]
            target[fields[-1]] = value
            with self.subTest(member=member, fields=fields), self.assertRaisesRegex(v.Invalid, "qualification-residence-" + reason):
                qualificationdata.residence(ROOT, {**files, member: v.encode(data)})

    def test_mutations(self) -> None:
        """Current precision proof retains the real baseline, compiled replacement and independent semantic failure."""
        manifest = v.decode(v.read(ROOT / qualification.MANIFEST))["evidence"]["star-precision-mutation"]
        raw = v.read(ROOT / manifest["path"], 64 * 1024**2)
        self.assertEqual(v.digest(raw), manifest["sha256"])
        files = qualificationdata.unpack(raw)
        result = qualificationdata.mutations(ROOT, files, expected=1)
        self.assertEqual(result["binding"]["status"], "current")
        self.assertEqual((result["mutants"], result["baselines"]), (1, 1))
        self.assertEqual([item["status"] for item in result["outcomes"]], ["passed", "killed"])
        prefix = "mutation/expired-selection-guard-removed/"
        for name, value, reason in (
            (
                prefix + "source.cpp",
                files[prefix + "source.cpp"] + b"\n",
                "replacement",
            ),
            (
                prefix + "compile-artifact.json",
                v.encode({"path": "source.o", "bytes": 0, "sha256": "0" * 64}),
                "artifact",
            ),
            (
                prefix + "outcome.json",
                v.encode({"id": "wrong", "status": "killed", "recipe_sha256": "0" * 64}),
                "summary",
            ),
        ):
            with self.subTest(member=name), self.assertRaisesRegex(v.Invalid, "qualification-mutation-" + reason):
                qualificationdata.mutations(ROOT, files | {name: value}, expected=1)

    def test_retained_entries(self) -> None:
        """Actual delivery interpretations pass, failed repair readers remain failed, and historical source cannot adopt."""
        fixture = v.decode(v.read(ROOT / "tests/fixtures/retained-entries.json"))
        directory = ROOT / fixture["directory"]
        reader = qualification.Evaluator(ROOT)
        with self.assertRaisesRegex(v.Invalid, "qualification-entry-source"):
            reader.retained_entries(directory, fixture["inputs_sha256"])
        # Explicit historical parser context is not current workspace qualification; finish must refuse it.
        reader.source = reader.evidence_source = v.decode(v.read(directory / "inputs.json"))["source"]
        observed, records = reader.retained_entries(directory, fixture["inputs_sha256"])
        self.assertEqual(sum(state == "passed" for state in observed.values()), 2)
        self.assertEqual(sum(state == "retained-reader-failed" for state in observed.values()), 2)
        self.assertEqual(
            records["admission-gap-delivery-matrix"]["observations"],
            {"ADMISSION-ASSURANCE": 2},
        )
        self.assertEqual(records["gap-delivery-matrix"]["observations"], {"STORAGE-ASSURANCE": 1})
        with self.assertRaisesRegex(v.Invalid, "qualification-source-changed"):
            reader.finish()

    def test_entry_guards(self) -> None:
        """A forged command, incomplete reader or successful exit without valid native output cannot qualify."""
        fixture = v.decode(v.read(ROOT / "tests/fixtures/retained-entries.json"))
        original = ROOT / fixture["directory"]
        with tempfile.TemporaryDirectory(prefix="retained-entry-controls-", dir=ROOT / "build/results/assurance") as temporary:
            directory = Path(temporary)
            shutil.copyfile(original / "inputs.json", directory / "inputs.json")
            inputs = v.decode(v.read(directory / "inputs.json"))
            for name in inputs["checks"]:
                output = directory / name
                output.mkdir()
                record = v.decode(v.read(original / name / "record.json"))
                for filename in (
                    "record.json",
                    record["stdout"]["path"],
                    record["stderr"]["path"],
                ):
                    shutil.copyfile(original / name / filename, output / filename)
            target = directory / "admission-gap-delivery-matrix/record.json"
            record = v.decode(v.read(target))
            for changed, reason in (
                (record | {"id": "foreign"}, "command"),
                (record | {"argv": record["argv"] + ["--allow-empty"]}, "command"),
                (record | {"cleanup": False}, "incomplete"),
            ):
                target.write_bytes(v.encode(changed))
                reader = qualification.Evaluator(ROOT)
                reader.source = reader.evidence_source = inputs["source"]
                with self.subTest(reason=reason), self.assertRaisesRegex(v.Invalid, "qualification-entry-" + reason):
                    reader.retained_entries(directory, fixture["inputs_sha256"])
            data = b"{}\n"
            (target.parent / record["stdout"]["path"]).write_bytes(data)
            target.write_bytes(
                v.encode(
                    record
                    | {
                        "stdout": {
                            "path": record["stdout"]["path"],
                            "bytes": len(data),
                            "sha256": v.digest(data),
                        }
                    }
                )
            )
            reader = qualification.Evaluator(ROOT)
            reader.source = reader.evidence_source = inputs["source"]
            with self.assertRaises(v.Invalid):
                reader.retained_entries(directory, fixture["inputs_sha256"])
