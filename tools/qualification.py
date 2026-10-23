"""Map authenticated retained observations to exact obligation coordinates without recollecting applications."""

import argparse
import datetime as dt
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
from tools import (
    idle,
    independence,
    nativeclosures,
    profiles,
    qualificationdata,
    release,
    structure,
    verifierdata,
    verify as v,
)

MANIFEST = "tests/fixtures/qualifications.json"
MODEL = "43ca55b044f1e29d7556cc359bdfdd6de4d98a644e972582438beec035d8e4d9"
CHECKS = {
    "admission-gap-capacity": "admission",
    "admission-gap-operate": "admission",
    "admission-gap-evidence": "admission",
    "gap-capacity": "polaris-storage",
    "gap-operate": "polaris-storage",
    "gap-evidence": "polaris-storage",
    "star-qualification": "star",
    "pulsar-qualification": "pulsar",
    "polaris-server-qualification": "polaris-server",
    "comet-go-qualification": "comet-go",
    "astrolabe-qualification": "astrolabe",
    "command-qualification": "command",
    "comet-qualification": "comet",
    "common-qualification": "common",
    "admin-qualification": "admin",
    "verification-qualification": "verification",
    "tools-qualification": "tools",
    "benchmarks-qualification": "benchmarks",
    "protocol-qualification": "protocol",
    "documentation-qualification": "documentation",
    "admission-gap-trace": "admission",
    "gap-trace": "polaris-storage",
    "admission-gap-supply": "admission",
    "gap-supply": "polaris-storage",
    "admission-gap-compat": "admission",
    **release.CHECKS,
}
RETAINED = {
    "admission-gap-evidence": "retained-qualification",
    "gap-evidence": "retained-qualification",
    "admission-gap-delivery-matrix": "admission-delivery",
    "gap-delivery-matrix": "storage-delivery",
    "admission-gap-redgreen": "admission-repair",
    "gap-redgreen": "storage-repair",
}
FACETS = {
    **{name + "-native-closures": {name} for name in ("star", "pulsar", "comet")},
    "three-star-residence": {
        "admission",
        "polaris-storage",
        "star",
        "pulsar",
        "polaris-server",
        "astrolabe",
        "comet-go",
    },
    "paired-performance": {"star", "comet"},
    "admission-race": {"admission"},
    "storage-race": {"polaris-storage"},
    "star-targeted-mutations": {"star"},
    "star-precision-mutation": {"star"},
    "go-component-race": {"polaris-server", "astrolabe", "comet-go", "command"},
    "comet-go-targeted-mutations": {"comet-go"},
    "comet-go-windows-targeted-mutations": {"comet-go"},
    "windows-sdk-residence": {"comet-go"},
    **{
        name + "-source-ownership": {name}
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
    "admission-native-trace": {"admission"},
    "storage-native-trace": {"polaris-storage"},
    "admission-native-supply": {"admission"},
    "storage-native-supply": {"polaris-storage"},
    "admission-native-compat": {"admission"},
}
# Native finite facets support these rules without replacing their remaining normative scope.
CRITERIA = {
    "DEV-TRACE": ("approved-end-to-end-traceability",),
    "DEV-CORE": (
        "complete-core-contracts",
        "complete-mcdc",
        "complete-mutation-domain",
        "complete-fault-domain",
    ),
    "DEV-ASYNC": ("race", "complete-ownership-and-drain-domains"),
    "DEV-TIME": ("complete-clock-domain-and-numeric-contracts",),
    "DEV-CONTRACT": ("all-public-contracts-and-failure-guarantees",),
    "DEV-SECURITY": ("complete-threat-and-call-level-supply-analysis",),
    "DEV-CAPACITY": (
        "finite-resources",
        "performance",
        "complete-capacity-domain",
        "overload-and-queue-budgets",
        "aggregate-memory-disk-and-retention-budgets",
    ),
    "DEV-RETRY": ("complete-retry-and-idempotence-domains",),
    "DEV-ORACLE": ("complete-independent-oracle-provenance",),
    "DEV-REDGREEN": (
        "targeted-mutations",
        "complete-change-counterexamples-and-causal-repairs",
    ),
    "DEV-REPLAY": ("complete-replay-and-failure-preservation",),
    "DEV-NUMERIC": ("complete-numeric-and-quantization-domain",),
    "DEV-MODEL": ("complete-finite-model-domain-and-pruning",),
    "DEV-STOP": ("complete-shutdown-and-forced-termination-grid",),
    "DEV-IMPACT": ("complete-current-change-and-consumer-closure",),
    "DEV-GATE": ("complete-gate-policy-and-negative-controls",),
    "DEV-FAILURE": ("complete-causal-failure-disposition",),
    "DEV-AUDIT": ("independent-reproducible-full-rule-review",),
    "DEV-SUPPLY": ("complete-dependency-origin-license-and-security",),
    "DEV-COMPAT": ("complete-supported-generation-and-consumer-matrix",),
    "DEV-RELEASE": (
        "protected-authority",
        "qualified-candidate-and-rollout-rollback-recovery",
    ),
    "DEV-OPERATE": (
        "finite-resources",
        "race",
        "sustained-maintenance-disk-WAL-growth-and-tail-bounds",
        "operating-and-recovery-procedures",
    ),
    "DEV-EVIDENCE": (
        "retained-native-content",
        "complete-obligation-evidence-coverage",
        "protected-authority",
        "independent-collector-and-immutable-custody",
    ),
    "DEV-CONFIG": ("complete-effective-configuration-and-adoption-approvals",),
    "DEV-ADOPTION": ("accepted-protected-pilot-and-issued-adoption-date",),
    "DEV-FAULT": ("complete-fault-domain",),
    "DEV-MATRIX": ("complete-current-delivery-and-diagnostic-profile-matrix",),
}
COVERAGE = {
    "structure": ("complete-structural-denominator",),
    "mcdc": ("complete-mcdc",),
    "mutation": ("targeted-mutations", "complete-mutation-domain"),
}


def configuration(check: dict, config: dict) -> None:
    """Keep exact check identities, scopes and parser budgets; no generic success token qualifies a rule."""
    if (
        check["id"] not in CHECKS
        or check["adapter"] != "retained-qualification"
        or check["component"] != CHECKS[check["id"]]
        or check["argv"] != ["python3", "-B", "tools/qualification.py", "--check", check["id"]]
        or check["manifest"] != MANIFEST
        or check["manifest_sha256"] != MODEL
        or check["expected_tests"] != ["qualification"]
        or check["timeout_s"] != 900
        or check["log_bytes"] != 8 * 1024**2
        or check["platforms"] != v.unique(config["components"])[check["component"]]["platforms"]
        or any(probe["test"] != "qualification" or probe["minimum_hits"] != 1 for probe in check["probes"])
    ):
        v.reject("qualification-configuration")
    rows = [item for item in v.expand(config).values() if check["id"] in item["checks"]]
    if not rows or {item["contract"] for item in rows} != {item["contract"] for item in check["probes"]}:
        v.reject("qualification-configuration-scope")
    for item in rows:
        required(item)


def required(item: dict) -> tuple[str, ...]:
    """Retain each full-rule/scenario obligation rather than promoting a finite leaf into a component pass."""
    if item["rule"] == "DEV-COVERAGE":
        if item["scenario"] not in COVERAGE:
            v.reject("qualification-coverage-scenario")
        return COVERAGE[item["scenario"]]
    if item["rule"] not in CRITERIA:
        v.reject("qualification-rule", item["rule"])
    return CRITERIA[item["rule"]]


def support(fact: dict, rule: str, *, platform: str | None = None) -> set[str]:
    """Credit authenticated current native content without implying complete coverage, protected origin or custody."""
    if fact["state"] != "qualified-facet" or platform is not None and platform not in fact["platforms"]:
        return set()
    result = {fact["facet"]}
    if rule == "DEV-EVIDENCE":
        result.add("retained-native-content")
    return result


class Evaluator:
    """Share one immutable fact interpretation across an entire gate/inventory evaluation."""

    def __init__(
        self,
        root: Path,
        *,
        association: Path | None = None,
        association_sha256: str | None = None,
    ) -> None:
        """Load pinned qualification inputs and initialize empty evidence and closure caches."""
        self.root = root
        self.config, _, _ = v.configuration(root / "development.json", root)
        self.source = v.source(root)
        self.evidence_source = self.source
        self.association = None
        self.checked = {}
        if (association is None) != (association_sha256 is None):
            v.reject("qualification-association-pin")
        if association is not None:
            self.evidence_source, self.association, self.checked = verifierdata.association(root, association, association_sha256, self.source)
        raw = v.read(root / MANIFEST)
        if v.digest(raw) != MODEL:
            v.reject("qualification-manifest")
        self.manifest = v.decode(raw)
        if self.manifest["version"] != 1 or self.manifest["checks"] != CHECKS or set(self.manifest["evidence"]) != set(FACETS):
            v.reject("qualification-manifest-scope")
        self.facts = {}
        self.archives = {}
        self.source_audits = {}
        self.native_context = None
        self.closure_context = None
        self.release_context = None

    def fact(self, name: str) -> dict:
        """Read each pinned native archive once; retain results, original limits and source-review gaps."""
        if name in self.facts:
            return self.facts[name]
        item = self.manifest["evidence"][name]
        if item["kind"] == "native-closures":
            if (
                set(item) != {"kind", "component", "manifest", "manifest_sha256"}
                or item["manifest"] != nativeclosures.MANIFEST
                or item["manifest_sha256"] != nativeclosures.MODEL
                or name != item["component"] + "-native-closures"
                or FACETS[name] != {item["component"]}
            ):
                v.reject("qualification-native-closures-manifest")
            if self.closure_context is None:
                self.closure_context, checked = nativeclosures.read(self.root, self.source)
                self.checked.update(checked)
            result = self.closure_context[item["component"]]
            self.facts[name] = result
            return result
        if item["kind"] == "native-context":
            if (
                set(item) != {"kind", "component", "aspect", "manifest", "manifest_sha256"}
                or item["manifest"] != profiles.MANIFEST
                or item["manifest_sha256"] != profiles.MODEL
                or item["aspect"] not in {"trace", "supply", "compat"}
                or name != ("admission" if item["component"] == "admission" else "storage") + "-native-" + item["aspect"]
                or item["component"] not in FACETS[name]
            ):
                v.reject("qualification-native-context-manifest")
            if self.native_context is None:
                self.native_context, checked = qualificationdata.native_context(self.root, self.config, self.source)
                self.checked.update(checked)
            key = item["component"] + "/" + item["aspect"]
            if key not in self.native_context:
                v.reject("qualification-native-context-manifest")
            result = dict(self.native_context[key])
            profile_manifest = v.decode(v.read(self.root / profiles.MANIFEST))
            result.update(
                archive=profile_manifest["custody"]["path"],
                archive_sha256=profile_manifest["custody"]["sha256"],
                state=("qualified-facet" if result["binding"]["status"] == "current" else "source-review-required"),
                platforms=["linux-amd64-cgo"],
            )
            if set(result["components"]) != FACETS[name]:
                v.reject("qualification-facet-scope", name)
            self.facts[name] = result
            return result
        path = v.inside(self.root, item["path"])
        pins = {
            key: item[key]
            for key in (
                "path",
                "bytes",
                "sha256",
                "seal",
                "seal_sha256",
                "seal_hash_field",
            )
        }
        if item["kind"] == "source-audit":
            pins.update({key: item[key] for key in ("retired", "retired_sha256")})
        if item["kind"] in {"windows-mutations", "windows-residence"}:
            pins["inputs"] = item["inputs"]
        if item["path"] in self.archives:
            original, files, seal = self.archives[item["path"]]
            if original != pins:
                v.reject("qualification-shared-archive-pin")
        else:
            raw = v.read(path, 64 * 1024**2)
            if len(raw) != item["bytes"] or v.digest(raw) != item["sha256"]:
                v.reject("qualification-artifact", name)
            seal_raw = v.read(v.inside(self.root, item["seal"]), 16 * 1024**2)
            seal = v.decode(seal_raw)
            if v.digest(seal_raw) != item["seal_sha256"] or seal[item["seal_hash_field"]] != item["sha256"]:
                v.reject("qualification-seal", name)
            files = qualificationdata.unpack(raw)
            if sum(row.get("path") == item["path"] for row in self.manifest["evidence"].values()) > 1:
                self.archives[item["path"]] = pins, files, seal
        readers = {
            "residence": qualificationdata.residence,
            "storage-race": qualificationdata.storage_race,
            "admission-race": qualificationdata.admission_race,
            "mutations": qualificationdata.mutations,
        }
        if item["kind"] == "performance":
            result = qualificationdata.performance(self.root, files, seal)
        elif item["kind"] == "precision-mutation":
            result = qualificationdata.mutations(self.root, files, expected=1)
        elif item["kind"] == "go-components-race":
            result = qualificationdata.go_race(self.root, files, item["packages"])
        elif item["kind"] == "go-mutations":
            result = qualificationdata.go_mutations(self.root, files, seal)
        elif item["kind"] == "windows-mutations":
            supplemental = {}
            if set(item["inputs"]) != {"source", "installed"}:
                v.reject("qualification-windows-mutation-pin")
            for label, artifact in item["inputs"].items():
                raw = v.read(v.inside(self.root, artifact["path"]), 8 * 1024**2)
                if len(raw) != artifact["bytes"] or v.digest(raw) != artifact["sha256"]:
                    v.reject("qualification-windows-mutation-pin")
                supplemental[label] = raw
                self.checked[artifact["path"]] = artifact["sha256"]
            result = qualificationdata.windows_mutations(self.root, files, seal, supplemental["source"], supplemental["installed"])
        elif item["kind"] == "windows-residence":
            supplemental = {}
            if set(item["inputs"]) != {"producer_inputs", "producer_receipt"}:
                v.reject("qualification-windows-residence-pin")
            for label, artifact in item["inputs"].items():
                raw = v.read(v.inside(self.root, artifact["path"]), 8 * 1024**2)
                if len(raw) != artifact["bytes"] or v.digest(raw) != artifact["sha256"]:
                    v.reject("qualification-windows-residence-pin")
                supplemental[label] = raw
                self.checked[artifact["path"]] = artifact["sha256"]
            result = qualificationdata.windows_residence(self.root, files, seal, **supplemental)
        elif item["kind"] == "source-audit":
            if item["path"] not in self.source_audits:
                retired_raw = v.read(v.inside(self.root, item["retired"]))
                if v.digest(retired_raw) != item["retired_sha256"]:
                    v.reject("qualification-source-audit-retirement")
                self.source_audits[item["path"]] = qualificationdata.source_audit(files, seal, v.decode(retired_raw), self.config, self.source)
                self.checked[item["retired"]] = item["retired_sha256"]
            result = self.source_audits[item["path"]][item["component"]]
        else:
            result = readers[item["kind"]](self.root, files)
        result.update(
            archive=item["path"],
            archive_sha256=item["sha256"],
            state=("qualified-facet" if result["binding"]["status"] == "current" else "source-review-required"),
            platforms=["windows-amd64" if item["kind"] in {"windows-mutations", "windows-residence"} else "linux-amd64-cgo"],
        )
        if set(result["components"]) != FACETS[name]:
            v.reject("qualification-facet-scope", name)
        self.checked[item["path"]] = item["sha256"]
        self.checked[item["seal"]] = item["seal_sha256"]
        self.facts[name] = result
        return result

    def report(self, identifier: str) -> dict:
        """Compute separate support/missing criteria for every exact requirement coordinate."""
        checks = v.unique(self.config["checks"])
        if identifier not in CHECKS:
            v.reject("qualification-check")
        check = checks[identifier]
        configuration(check, self.config)
        component = check["component"]
        facts = {name: self.fact(name) for name in FACETS if component in FACETS[name]}
        rows = []
        for key, item in v.expand(self.config).items():
            if identifier not in item["checks"]:
                continue
            criteria = required(item)
            supported = {criterion for fact in facts.values() for criterion in support(fact, item["rule"], platform=item["platform"])}
            missing = sorted(set(criteria) - supported)
            rows.append(
                {
                    "obligation": key,
                    "status": "passed" if not missing else "incomplete",
                    "required": list(criteria),
                    "supported": sorted(set(criteria) & supported),
                    "missing": missing,
                    "evidence": [
                        name
                        for name, fact in facts.items()
                        if item["platform"] in fact["platforms"]
                        and (fact["facet"] in criteria or item["rule"] == "DEV-EVIDENCE" or item["rule"] in fact.get("applies_to", []))
                    ],
                }
            )
        report = {
            "version": 1,
            "check": identifier,
            "component": component,
            "manifest_sha256": MODEL,
            "policy_sha256": v.file_digest(self.root / "development.json"),
            "source_sha256": v.digest(v.encode(self.evidence_source)),
            "application_commands": 0,
            "native_application_commands": 0,
            "obligations": rows,
            "evidence": facts,
            "trust": "local",
            "boundary": "Successfully evaluating this report does not qualify every rule. Exact obligation statuses and all missing normative facets govern; no protected authority is issued.",
        }
        if identifier in release.CHECKS:
            if self.release_context is None:
                self.release_context, checked = release.context(self.root)
                self.checked.update(checked)
            report["release_context"] = self.release_context
        return report

    def observations(self, data: bytes, check: dict) -> dict[str, str]:
        """Independently recompute native facts; submitted JSON cannot promote or omit an obligation."""
        if check != v.unique(self.config["checks"])[check["id"]]:
            v.reject("qualification-check-mismatch")
        expected = self.report(check["id"])
        if v.decode(data) != expected:
            v.reject("qualification-report-mismatch")
        return {
            row["obligation"]: ("passed" if row["status"] == "passed" else "qualification-missing:" + ",".join(row["missing"]))
            for row in expected["obligations"]
        }

    def admission_entries(self, directory: Path) -> tuple[dict, dict]:
        """Consume the actual two formal Admission entries through the normal verifying adapter."""
        boundary = self.root / "build/results/assurance"
        if not directory.resolve().is_relative_to(boundary.resolve()):
            v.reject("qualification-entry-boundary")
        inputs = v.decode(v.read(directory / "inputs.json"))
        if inputs["source"] != self.evidence_source or set(inputs["checks"]) != {
            "admission-structure",
            "admission-independence",
        }:
            v.reject("qualification-entry-source")
        checks = v.unique(self.config["checks"])
        observations, records = {}, {}
        for name, hits in (
            ("admission-structure", 829),
            ("admission-independence", 165),
        ):
            output = directory / name
            check = checks[name]
            if inputs["checks"][name] != check:
                v.reject("qualification-entry-policy")
            record = v.decode(v.read(output / "observation-record.json"))
            if record["exit_code"] != 0 or not record["complete"] or not record["cleanup"] or record["termination"] != "exited":
                v.reject("qualification-entry-command")
            stdout = v.reference(output, record["stdout"], check["log_bytes"])
            evidence = {"directory": output, "record": record}
            if self.association is not None:
                evidence["source_association"] = {
                    "path": self.root / self.association["path"],
                    "sha256": self.association["sha256"],
                }
            counts, missing = v.parse_observations(stdout, check, self.root, evidence)
            if missing or counts != {"ADMISSION-ASSURANCE": hits}:
                v.reject("qualification-entry-observations")
            observations[name, "linux-amd64-cgo", "ADMISSION-ASSURANCE"] = "passed"
            records[name] = {
                "directory": str(output),
                "record_sha256": v.file_digest(output / "observation-record.json"),
                "observations": counts,
            }
        return observations, records

    def inventory(
        self,
        admission: Path | None = None,
        *,
        verifier: Path | None = None,
        verifier_sha256: str | None = None,
        verifier_seal_sha256: str | None = None,
        verifier_retired_sha256: str | None = None,
        entries: Path | None = None,
        entries_sha256: str | None = None,
        case_entries: Path | None = None,
        case_entries_sha256: str | None = None,
        profile_entries: Path | None = None,
        profile_entries_sha256: str | None = None,
    ) -> dict:
        """Attach real formal observations and partial qualification reports to all unchanged 1,370 objects."""
        if (profile_entries is None) != (profile_entries_sha256 is None):
            v.reject("qualification-profile-pin")
        if admission is None and profile_entries is None:
            v.reject("qualification-inventory-inputs")
        observations, admission_records = self.admission_entries(admission) if admission is not None else ({}, None)
        reports = {name: self.report(name) for name in CHECKS}
        objects = v.expand(self.config)
        for name, report in reports.items():
            for key, state in self.observations(v.encode(report), v.unique(self.config["checks"])[name]).items():
                item = objects[key]
                observations[name, item["platform"], item["contract"], key] = state
        # The existing complete current proof supplies both Storage dimensions from one interpretation.
        if admission is not None:
            proof = idle.reconcile(self.root, independence.artifacts(self.root))
            ledger = proof["current_structure"]
            values = [
                ledger["statements"]["compiler_weights"]["obligations"]["statements_hit"],
                ledger["boolean"]["totals"]["roots"]["observed"],
                ledger["boolean"]["totals"]["atoms"]["observed"],
                ledger["controls"]["observed"],
            ]
            if sum(values) != 1558 or not proof["supported_conditions"] == proof["qualified_denominator"] == 273:
                v.reject("qualification-storage-observations")
            for name in ("storage-structure", "storage-independence"):
                observations[name, "linux-amd64-cgo", "STORAGE-ASSURANCE"] = "passed"
        verification = None
        if verifier is not None:
            if verifier_sha256 is None or verifier_seal_sha256 is None or verifier_retired_sha256 is None:
                v.reject("qualification-verifier-pins")
            verification, checked = verifierdata.read(
                self.root,
                verifier,
                verifier_sha256,
                verifier_seal_sha256,
                verifier_retired_sha256,
            )
            observations.update(
                verifierdata.observations(
                    verification,
                    self.evidence_source,
                    v.unique(self.config["checks"])["verification-python"],
                )
            )
            self.checked.update(checked)
            verification = {key: value for key, value in verification.items() if key not in {"source", "check"}}
        retained_entries = None
        if entries is not None:
            observed, retained_entries = self.retained_entries(entries, entries_sha256)
            observations.update(observed)
        native_entries = None
        if case_entries is not None:
            if case_entries_sha256 is None:
                v.reject("qualification-case-entry-pin")
            observed, native_entries, checked = verifierdata.entries(
                self.root,
                case_entries,
                case_entries_sha256,
                self.evidence_source,
                self.config,
            )
            observations.update(observed)
            self.checked.update(checked)
        profile_proof = None
        if profile_entries is not None:
            observed, profile_proof, checked = profiles.read(
                self.root,
                profile_entries,
                profile_entries_sha256,
                self.config,
                self.evidence_source,
            )
            if observations.keys() & observed.keys():
                v.reject("qualification-profile-overlap")
            observations.update(observed)
            self.checked.update(checked)
        local = v.decide(self.config, observations, [], [], dt.datetime.now(dt.timezone.utc))
        rows = []
        for key, item in objects.items():
            support = [row for report in reports.values() for row in report["obligations"] if row["obligation"] == key]
            rows.append(
                {
                    "obligation": key,
                    "checks": item["checks"],
                    "local_state": ("qualified" if key in local["passed"] else "incomplete" if support else "not-reconciled"),
                    "missing": local["details"].get(key, []),
                    "qualification": support,
                }
            )
        self.finish()
        return {
            "version": 1,
            "source": self.source,
            "source_association": self.association,
            "policy_sha256": v.file_digest(self.root / "development.json"),
            "obligations": rows,
            "obligation_count": len(rows),
            "admission_entries": admission_records,
            "qualification_checks": reports,
            "verification_native": verification,
            "retained_entries": retained_entries,
            "native_case_entries": native_entries,
            "profile_entries": profile_proof,
            "inventory_scope": ("formal-core-and-supplied-entries" if admission is not None else "supplied-native-profiles-and-retained-facets"),
            "local_gate": local,
            "native_application_commands": 0,
            "protected_qualification": "not-issued",
            "boundary": "Only the explicitly supplied current native leaves and registered retained qualification facets contribute. Historical baseline passes are not imported. Unreconciled objects and incomplete full rules remain open; no protected authority is issued.",
        }

    def retained_entries(self, directory: Path, checksum: str | None) -> tuple[dict, dict]:
        """Adopt actual portable native-evidence readers while retaining their failed outcomes and native scopes."""
        if not directory.resolve().is_relative_to((self.root / "build/results/assurance").resolve()):
            v.reject("qualification-entry-boundary")
        raw = v.read(v.inside(directory, "inputs.json"))
        if checksum is None or v.digest(raw) != checksum:
            v.reject("qualification-entry-pin")
        inputs = v.decode(raw)
        if inputs["source"] != self.evidence_source:
            v.reject("qualification-entry-source")
        if not inputs["checks"] or not set(inputs["checks"]) <= RETAINED.keys():
            v.reject("qualification-entry-selection")
        checks = v.unique(self.config["checks"])
        self.checked[(directory / "inputs.json").relative_to(self.root).as_posix()] = checksum
        observed, records = {}, {}
        for name, declared in inputs["checks"].items():
            check = checks[name]
            if declared != check or check["adapter"] != RETAINED[name] or check["platforms"] != ["linux-amd64-cgo"]:
                v.reject("qualification-entry-policy")
            output = v.inside(directory, name)
            record_raw = v.read(v.inside(output, "record.json"))
            record = v.decode(record_raw)
            v.schema(record, "evidence", ("properties", "checks", "items"))
            if record["id"] != name or record["argv"][1:] != check["argv"][1:] or record["platform"] not in {"linux-amd64-cgo", "windows-amd64"}:
                v.reject("qualification-entry-command")
            if record["duration_ms"] > check["timeout_s"] * 1000 or not record["complete"] or not record["cleanup"] or record["termination"] != "exited":
                v.reject("qualification-entry-incomplete")
            stdout, stderr = (v.reference(output, record[field], check["log_bytes"]) for field in ("stdout", "stderr"))
            counts, missing, states = {}, [], None
            if record["exit_code"] == 0 and not stderr:
                if check["adapter"] == "retained-qualification":
                    states = self.observations(stdout, check)
                else:
                    counts, missing = v.parse_observations(stdout, check, self.root)
                    if missing or counts != {probe["contract"]: probe["minimum_hits"] for probe in check["probes"]}:
                        v.reject("qualification-entry-observations")
            state = "passed" if record["exit_code"] == 0 and not stderr else "retained-reader-failed"
            if check["adapter"] == "retained-qualification":
                objects = {key: item for key, item in v.expand(self.config).items() if name in item["checks"]}
                states = states if states is not None else {key: state for key in objects}
                if state == "passed" and any(value != "passed" for value in states.values()):
                    state = "qualification-incomplete"
                for key, value in states.items():
                    observed[name, objects[key]["platform"], objects[key]["contract"], key] = value
            else:
                for probe in check["probes"]:
                    observed[name, "linux-amd64-cgo", probe["contract"]] = state
            records[name] = {
                "state": state,
                "observations": counts,
                "record_sha256": v.digest(record_raw),
                "receiving_platform": record["platform"],
                "native_platform": "linux-amd64-cgo",
            }
            if states is not None:
                records[name]["obligations"] = states
            self.checked[(output / "record.json").relative_to(self.root).as_posix()] = v.digest(record_raw)
            for field, data in (("stdout", stdout), ("stderr", stderr)):
                self.checked[(output / record[field]["path"]).relative_to(self.root).as_posix()] = v.digest(data)
        return observed, records

    def finish(self) -> None:
        """Reject changed archives or source during the shared interpretation window."""
        if v.source(self.root) != self.source:
            v.reject("qualification-source-changed")
        if any(v.file_digest(v.inside(self.root, name)) != sha for name, sha in self.checked.items()):
            v.reject("qualification-artifact-changed")


def main(arguments: list[str] | None = None) -> int:
    """Evaluate existing evidence only; an incomplete qualification report is a successful evaluation, never a pass."""
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", choices=list(CHECKS))
    mode.add_argument("--inventory", type=Path, metavar="ADMISSION_ENTRIES")
    mode.add_argument("--profile-inventory", type=Path, metavar="REGISTERED_PROFILE_MANIFEST")
    parser.add_argument("--profiles", type=Path)
    parser.add_argument("--profiles-sha256")
    parser.add_argument("--verifier", type=Path, metavar="ORIGINAL_NATIVE_DIRECTORY")
    parser.add_argument("--verifier-sha256")
    parser.add_argument("--verifier-seal-sha256")
    parser.add_argument("--verifier-retired-sha256")
    parser.add_argument("--entries", type=Path)
    parser.add_argument("--entries-sha256")
    parser.add_argument("--case-entries", type=Path)
    parser.add_argument("--case-entries-sha256")
    parser.add_argument("--source-association", type=Path)
    parser.add_argument("--source-association-sha256")
    args = parser.parse_args(arguments)
    try:
        profile_entries = args.profile_inventory or args.profiles
        if (args.profiles is not None and args.inventory is None) or (profile_entries is None) != (args.profiles_sha256 is None):
            v.reject("qualification-profile-arguments")
        if (args.verifier is not None and args.inventory is None) or any(
            (args.verifier is None) != (value is None)
            for value in (
                args.verifier_sha256,
                args.verifier_seal_sha256,
                args.verifier_retired_sha256,
            )
        ):
            v.reject("qualification-verifier-arguments")
        if (args.entries is not None and args.inventory is None) or ((args.entries is None) != (args.entries_sha256 is None)):
            v.reject("qualification-entry-arguments")
        if (args.case_entries is not None and args.inventory is None) or ((args.case_entries is None) != (args.case_entries_sha256 is None)):
            v.reject("qualification-case-entry-arguments")
        if (args.source_association is not None and args.inventory is None) or ((args.source_association is None) != (args.source_association_sha256 is None)):
            v.reject("qualification-association-arguments")
        reader = Evaluator(
            ROOT,
            association=args.source_association,
            association_sha256=args.source_association_sha256,
        )
        report = (
            reader.report(args.check)
            if args.check
            else reader.inventory(
                args.inventory,
                verifier=args.verifier,
                verifier_sha256=args.verifier_sha256,
                verifier_seal_sha256=args.verifier_seal_sha256,
                verifier_retired_sha256=args.verifier_retired_sha256,
                entries=args.entries,
                entries_sha256=args.entries_sha256,
                case_entries=args.case_entries,
                case_entries_sha256=args.case_entries_sha256,
                profile_entries=profile_entries,
                profile_entries_sha256=args.profiles_sha256,
            )
        )
        reader.finish()
        print(v.encode(report).decode(), end="")
        return 0
    except (
        OSError,
        v.Invalid,
        KeyError,
        TypeError,
        ValueError,
        StopIteration,
        tarfile.TarError,
    ) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
