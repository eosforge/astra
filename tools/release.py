"""Bind static release preparation to retained evidence without issuing release authority."""

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
from tools import verify as v

SPECIFICATION = "tests/fixtures/release.json"
SPECIFICATION_SHA256 = "adb636b9e67ae63b928352ed1e3a438db079fc14a78bf8599f47b2b87a2d35d1"
DEFENSES = "tests/fixtures/defenses.json"
DEFENSES_SHA256 = "d22f9111fb97f5e960f614a7df4a08969a3e141a95c43569bad03cd9049e9554"
CHECKS = {
    "admission-gap-adoption": "admission",
    "admission-gap-release": "admission",
    "gap-adoption": "polaris-storage",
    "gap-release": "polaris-storage",
}


def require(condition: bool, reason: str) -> None:
    """Reject a changed binding instead of accepting a declaration as an observation."""
    if not condition:
        v.reject("release-" + reason)


def pinned(root: Path, name: str, checksum: str, maximum: int = 1024**2) -> dict:
    """Read one reviewed local model by content, with no network or execution fallback."""
    raw = v.read(v.inside(root, name), maximum)
    require(v.digest(raw) == checksum, "model-pin")
    return v.decode(raw)


def context(root: Path) -> tuple[dict, dict]:
    """Link the CI specification and retain all five native gaps with honest proof states."""
    spec = pinned(root, SPECIFICATION, SPECIFICATION_SHA256)
    expected = {name: {"component": component, "rule": "DEV-ADOPTION" if name.endswith("adoption") else "DEV-RELEASE"} for name, component in CHECKS.items()}
    require(
        spec["version"] == 1
        and spec["checks"] == expected
        and spec["provider"] == "github-actions"
        and spec["repository"] == "eosforge/astra"
        and spec["event"] == "workflow_dispatch"
        and spec["origin_reader"]["path"] == "tools/actions.py"
        and spec["origin_reader"]["capability"] == "provider-origin-only",
        "ci-specification",
    )
    require(
        spec["observed_protected_run"] is None
        and all(spec[key] is None for key in ("workflow_path", "workflow_sha256", "repository_id", "protected_environment", "artifact_retention_days"))
        and spec["provider_origin_is_release_authority"] is False
        and spec["dispatch_authorized"] is False
        and spec["qualification"] == "not-issued",
        "ci-authority",
    )
    require(v.file_digest(root / spec["origin_reader"]["path"]) == spec["origin_reader"]["sha256"], "origin-reader")
    ledger = pinned(root, DEFENSES, DEFENSES_SHA256)
    require(ledger["version"] == 1 and ledger["component"] == "comet-go", "defense-model")
    require(ledger["statement_denominators"] == {"windows-amd64": 1810, "linux-amd64-cgo": 1812}, "defense-denominator")
    checked = {SPECIFICATION: SPECIFICATION_SHA256, DEFENSES: DEFENSES_SHA256, spec["origin_reader"]["path"]: spec["origin_reader"]["sha256"]}
    for name, checksum in ledger["source_bindings"].items():
        require(name.startswith("comet/go/") and v.file_digest(v.inside(root, name)) == checksum, "defense-source")
        checked[name] = checksum
    retained = {}
    for label, reference in ledger["evidence"].items():
        require(reference["path"].startswith("build/results/assurance/"), "evidence-boundary")
        raw = v.read(v.inside(root, reference["path"]), 32 * 1024**2)
        require(len(raw) == reference["bytes"] and v.digest(raw) == reference["sha256"], "evidence-pin")
        checked[reference["path"]] = reference["sha256"]
        if label.endswith(".json"):
            retained[label] = v.decode(raw)
    seal = retained["sealed.native.json"]
    review_seal = retained["review.sealed.native.json"]
    require(seal["archive_sha256"] == ledger["evidence"]["evidence.tar.gz"]["sha256"] and seal["native"]["immutable"] is True, "native-custody")
    require(
        review_seal["archive_sha256"] == ledger["evidence"]["review-evidence.tar.gz"]["sha256"]
        and review_seal["native_evidence_archive_sha256"] == seal["archive_sha256"]
        and review_seal["native"]["immutable"] is True,
        "review-custody",
    )
    review = retained["read-only-review-1/residual-blocks.json"]
    require(
        review["source_bindings"] == ledger["source_bindings"]
        and review["coverage_mapping_sha256"] == ledger["evidence"]["mapping-1/coverage-to-obligations.json"]["sha256"],
        "defense-review",
    )
    source_rows = {row["range"]: row for row in review["remaining_blocks_per_platform"]}
    require(len(ledger["boundaries"]) == len(source_rows) == 5 and len({row["id"] for row in ledger["boundaries"]}) == 5, "defense-scope")
    supported, unproved = [], []
    for row in ledger["boundaries"]:
        original = source_rows.get(row["range"])
        require(original is not None and row["statements"] == original["statements"], "defense-range")
        require(row["source_sha256"] == ledger["source_bindings"][row["source_path"]], "defense-source")
        require(row["retained"] is True and row["excluded_from_native_denominator"] is False and row["native_hit_credit"] == 0, "defense-credit")
        require(row["platforms"] == ["linux-amd64-cgo", "windows-amd64"], "defense-platform")
        infeasible = original["classification"] == "normal-control-flow-unreachable-defense"
        require(row["classification"] == ("source-bound-infeasible-defense" if infeasible else original["classification"]), "defense-classification")
        require(row["proof_status"] == ("source-control-flow-argument" if infeasible else "infeasibility-not-proven"), "defense-proof")
        (supported if infeasible else unproved).append(row["id"])
    require(len(supported) == 2 and len(unproved) == 3, "defense-proof-scope")
    return (
        {
            "state": "static-specification-linked",
            "specification": SPECIFICATION,
            "specification_sha256": SPECIFICATION_SHA256,
            "provider": spec["provider"],
            "repository": spec["repository"],
            "origin_capability": spec["origin_reader"]["capability"],
            "required_protected_bindings": spec["required_protected_bindings"],
            "protected_run": None,
            "defense_ledger": DEFENSES,
            "defense_ledger_sha256": DEFENSES_SHA256,
            "supported_infeasible_defense_arguments": supported,
            "unproved_infeasibility": unproved,
            "native_denominators_unchanged": True,
            "qualification": "not-issued",
            "boundary": "Static CI linkage and retained local content supply no protected authority, qualified release candidate, protected pilot or issued adoption date. No unproved defense receives an exclusion or native hit.",
        },
        checked,
    )


def closure(root: Path, output: Path) -> dict:
    """Emit the complete current static inventory and an unsigned candidate-signoff checklist."""
    from tools import profiles, qualification

    require(output.resolve().is_relative_to((root / "build/results/assurance").resolve()), "output-boundary")
    output.mkdir(exist_ok=False)
    reader = qualification.Evaluator(root)
    inventory = reader.inventory(profile_entries=root / profiles.MANIFEST, profile_entries_sha256=profiles.MODEL)
    reader.finish()
    linkage, checked = context(root)
    require(all(v.file_digest(v.inside(root, name)) == checksum for name, checksum in checked.items()), "context-changed")
    v.write_new(output / "obligation-inventory.json", inventory)
    old_path = root / "build/results/assurance/reuse-plan/comet-go-isolated-coverage-current-1/inventory-1/obligation-inventory.json"
    old = v.decode(v.read(old_path))
    require([row["obligation"] for row in inventory["obligations"]] == [row["obligation"] for row in old["obligations"]], "obligation-drift")
    entries = {name: inventory["qualification_checks"][name] for name in CHECKS}
    require(all(len(report["obligations"]) == 1 and report["obligations"][0]["status"] == "incomplete" for report in entries.values()), "static-promotion")
    for name, report in entries.items():
        v.write_new(output / (name + ".json"), report)
    objects = v.expand(reader.config)
    unavailable = {name for name, check in v.unique(reader.config["checks"]).items() if check["adapter"] == "unavailable"}
    referenced = sorted(name for name in unavailable if any(name in item["checks"] for item in objects.values()))
    gate = inventory["local_gate"]
    checklist = [
        {
            "id": "retained-defenses",
            "status": "partial",
            "required": "Five source-bound boundary records, unchanged business source and native denominators",
            "missing": ["Infeasibility is not proved for three guards", "Full structure and source-feasible MC/DC remain incomplete"],
        },
        {
            "id": "formal-release-adoption-entries",
            "status": "implemented-static",
            "required": "Four exact retained-qualification adapters and immutable-context binding",
            "missing": ["Protected authority and qualified candidate", "Protected pilot and issued adoption date"],
        },
        {
            "id": "protected-github-actions",
            "status": "not-observed",
            "required": linkage["required_protected_bindings"],
            "missing": ["No protected workflow/run/custody or policy approval is supplied"],
        },
        {
            "id": "changed-interpreter-verification",
            "status": "not-run",
            "required": "Affected negative controls and applicable interpreter renewal",
            "missing": ["Static-only authorization supplies no current execution of changed release adapters or controls"],
        },
        {
            "id": "complete-obligation-gate",
            "status": gate["status"],
            "required": "Every one of the unchanged 1370 exact obligations and hard trust prerequisites",
            "missing": [str(len(gate["missing"])) + " objects are unresolved in this supplied-input scope"],
        },
        {
            "id": "candidate-and-signature",
            "status": "not-issued",
            "required": "Protected source/distribution identity, independent review, rollout/rollback/recovery and explicit signature authority",
            "missing": ["No cryptographic signature, signed commit, tag, push or publication is performed"],
        },
    ]
    result = {
        "version": 1,
        "at": v.utc(),
        "source": reader.source,
        "policy_sha256": v.file_digest(root / "development.json"),
        "preparation": "static-adapters-and-ci-specification-linked",
        "release_decision": "blocked",
        "signature": "not-issued",
        "ci_linkage": linkage,
        "release_adoption_entries": {
            name: {"report_sha256": v.file_digest(output / (name + ".json")), "obligation": report["obligations"][0]} for name, report in entries.items()
        },
        "current_inventory": {
            "sha256": v.file_digest(output / "obligation-inventory.json"),
            "scope": inventory["inventory_scope"],
            "obligations": len(objects),
            "passed": len(gate["passed"]),
            "unresolved": len(gate["missing"]),
            "gate": gate["status"],
        },
        "preceding_inventory": {
            "sha256": v.file_digest(old_path),
            "passed": len(old["local_gate"]["passed"]),
            "unresolved": len(old["local_gate"]["missing"]),
            "scope": "Earlier interpreter/source and supplied leaves; preserved, not imported as a current full-verifier pass",
        },
        "unavailable": {"definitions": len(unavailable), "referenced": referenced},
        "signoff_checklist": checklist,
        "native_application_commands": 0,
        "physical_product_service_starts": 0,
        "tests_or_builds": 0,
        "workflow_dispatches": 0,
        "protected_qualification": "not-issued",
        "boundary": "Release Candidate Closure is an unsigned preparation checklist, not an acceptance or signature. Adapter implementation removes unavailable configuration gaps; complete evidence and protected signoff remain independently required.",
    }
    require(v.source(root) == reader.source, "source-changed")
    v.write_new(output / "release-candidate-closure.json", result)
    return result


def main(arguments: list[str] | None = None) -> int:
    """Run only a bounded local static interpretation; never provision or dispatch CI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--closure", type=Path, required=True)
    args = parser.parse_args(arguments)
    try:
        report = closure(ROOT, args.closure)
        print(v.encode(report).decode(), end="")
        return 0
    except (OSError, v.Invalid, KeyError, TypeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
