"""Expose sealed native source associations as context, without issuing qualification criteria."""

from collections import Counter
from pathlib import Path, PurePosixPath
import tarfile

from tools import verify as v

MANIFEST = "tests/fixtures/native-closures.json"
MODEL = "ea1a8a6e6479930c4f7af33568cc9d6e2bb60ab331f05929253d4fda63c18504"
COMPONENTS = {"star", "pulsar", "comet"}
MEMBERS = {
    "historical-mapping.json",
    "current-release-mapping.json",
    "linux-comet-tsan-mapping.json",
    "pulsar-retained-mapping.json",
    "pulsar-tsan-current-mapping.json",
    "fixed-mutation-coordinate-closure.json",
    "native-outcomes.json",
}


def require(value: object, reason: str) -> None:
    """A missing or malformed context stays distinct from a failed native test."""
    if not value:
        v.reject("native-closures-" + reason)


def archive(path: Path, manifest: dict) -> dict[str, dict]:
    """Read selected metadata only, checking every regular member against its sealed manifest."""
    files, seen, total = {}, set(), 0
    expected = set(manifest["files"]) | {"manifest.json"}
    with tarfile.open(path, "r|gz") as bundle:
        for member in bundle:
            name = PurePosixPath(member.name)
            total += member.size
            require(
                member.isfile()
                and name.as_posix() == member.name
                and not name.is_absolute()
                and ".." not in name.parts
                and "\\" not in member.name
                and ":" not in member.name
                and member.name.casefold() not in seen
                and member.name in expected
                and 0 <= member.size <= 128 * 1024**2
                and total <= 512 * 1024**2,
                "archive-member",
            )
            seen.add(member.name.casefold())
            if member.name == "manifest.json":
                raw = bundle.extractfile(member).read(member.size + 1)
                require(v.decode(raw) == manifest, "embedded-manifest")
                continue
            item = manifest["files"][member.name]
            require(member.size == item["bytes"], "member-size")
            label = member.name.removeprefix("directed/")
            if label in MEMBERS:
                raw = bundle.extractfile(member).read(member.size + 1)
                require(len(raw) == item["bytes"] and v.digest(raw) == item["sha256"], "member-pin")
                files[label] = v.decode(raw, maximum=32 * 1024**2)
    require(seen == {name.casefold() for name in expected} and set(files) == MEMBERS, "archive-inventory")
    return files


def binding(owned: dict, current: dict) -> dict:
    """Compare the owned compiled closure itemwise; no new code may inherit an old overall pass."""
    require(isinstance(owned, dict) and bool(owned), "owned-closure")
    for name, checksum in owned.items():
        path = PurePosixPath(name)
        require(
            path.as_posix() == name
            and not path.is_absolute()
            and ".." not in path.parts
            and "\\" not in name
            and ":" not in name
            and isinstance(checksum, str)
            and len(checksum) == 64
            and all(character in "0123456789abcdef" for character in checksum),
            "owned-input",
        )
    changed = {name: {"executed": checksum, "current": current.get(name)} for name, checksum in owned.items() if current.get(name) != checksum}
    return {"status": "source-review-required" if changed else "current", "files": len(owned), "changed": changed}


def inspect(files: dict[str, dict], source: dict) -> dict[str, dict]:
    """Recompute source associations while retaining native failures, partial domains and trust limits."""
    current = {row["path"]: row["sha256"] for row in source["files"]}
    require(len(current) == len(source["files"]), "source-inventory")
    results = {component: [] for component in COMPONENTS}

    def append(component: str, label: str, closure: dict, archive_sha256: str) -> None:
        """Append a closure binding, marking current inputs with unresolved compilation evidence."""
        association = binding(closure["owned"], current)
        unresolved = closure["unbound_compiled_inputs"]
        require(isinstance(unresolved, list), "unbound-inputs")
        if association["status"] == "current" and unresolved:
            association["status"] = "unbound-compiled-inputs"
        results[component].append({"scope": label, "binding": association, "archive_sha256": archive_sha256, "unbound_compiled_inputs": unresolved})

    history = files["historical-mapping.json"]
    require(history["native_application_commands"] == history["tests_executed"] == 0, "mapping-execution")
    for group in ("ephemeris-diagnostics-tsan-current-1", "ephemeris-precision-tsan-current-2", "cpp-pulsar-faults-current-1", "cpp-tsan-completion-current-2"):
        item = history["histories"][group]
        for target, closure in item["closures"].items():
            component = "pulsar" if closure["target"].startswith("pulsar_") else "comet" if closure["target"].startswith("comet_") else "star"
            append(component, group + "/" + target, closure, item["archive_sha256"])
    release = files["current-release-mapping.json"]
    for target, closure in release["closures"].items():
        if not target.endswith("comet_beacon_test"):
            append("star", "release/" + target, closure, release["archive_sha256"])
    sdk = files["linux-comet-tsan-mapping.json"]
    for target, closure in sdk["closures"].items():
        append("comet", "tsan/" + target, closure, sdk["archive_sha256"])
    pulsar = files["pulsar-retained-mapping.json"]
    require(pulsar["native_application_commands"] == pulsar["tests_executed"] == 0, "mapping-execution")
    for label, item in pulsar["entries"].items():
        results["pulsar"].append(
            {
                "scope": label,
                "binding": binding(item["owned_compiled_closure"], current),
                "archive_sha256": item["archive_sha256"],
                "unbound_compiled_inputs": [],
            }
        )
    item = files["pulsar-tsan-current-mapping.json"]
    require(item["native_application_commands"] == 0, "mapping-execution")
    results["pulsar"].append(
        {
            "scope": "pulsar-allocation-current-11/tsan",
            "binding": binding(item["owned_compiled_closure"], current),
            "archive_sha256": item["archive_sha256"],
            "unbound_compiled_inputs": [],
        }
    )

    ledger = files["fixed-mutation-coordinate-closure.json"]
    require(ledger["mapped"] == len(ledger["rows"]) == 39 and ledger["definitions_unchanged"] is True, "mutation-inventory")
    require(
        len({row["id"] for row in ledger["rows"]}) == 39 and dict(Counter(row["current_scope"] for row in ledger["rows"])) == ledger["statuses"],
        "mutation-summary",
    )
    outcomes = files["native-outcomes.json"]
    require(
        outcomes["actual_native_test_processes"] == 7
        and outcomes["explicit_native_commands"] == 22
        and outcomes["physical_product_service_starts"] == outcomes["downloads_or_installs"] == 0,
        "native-scope",
    )
    for cohort in outcomes["preserved_cohorts"].values():
        require(all(row["complete"] and row["cleanup"] for row in cohort["terminal"]["entries"].values()), "native-cleanup")
    preserved = {name: row["status"] for name, row in outcomes["outcomes"].items()}
    require("not-killed" in preserved.values() and "failed" in preserved.values(), "failure-preservation")
    result = {}
    for component, closures in results.items():
        result[component] = {
            "facet": "source-bound-native-context",
            "components": [component],
            "platforms": ["linux-amd64-cgo"],
            "state": "retained-context-only",
            "binding": {"status": "itemwise", "counts": dict(Counter(row["binding"]["status"] for row in closures))},
            "source_closures": closures,
            "fixed_mutation_coordinates": [row for row in ledger["rows"] if row["obligation"].split("/", 1)[0] in {component, "common"}],
            "all_fixed_mutation_coordinates": 39,
            "original_native_outcomes": preserved,
            "native_application_commands": 0,
            "criteria_supported": [],
            "applies_to": ["DEV-ASYNC", "DEV-CONTRACT", "DEV-COVERAGE", "DEV-EVIDENCE", "DEV-FAULT", "DEV-MODEL", "DEV-REDGREEN"],
            "trust": "local",
            "boundary": "Pinned metadata associations are contextual only. The original native output, failed parents, source changes and unbound inputs retain their own identities. These associations discharge no normative criterion, current native entry, complete component domain or protected release duty.",
        }
    return result


def read(root: Path, source: dict) -> tuple[dict[str, dict], dict[str, str]]:
    """Bind the registered local custody and expose its associations without executing embedded code."""
    raw = v.read(root / MANIFEST)
    require(v.digest(raw) == MODEL, "manifest-pin")
    declared = v.decode(raw)
    require(
        set(declared) == {"version", "components", "inputs"}
        and declared["version"] == 1
        and set(declared["components"]) == COMPONENTS
        and len(declared["components"]) == 3,
        "manifest-scope",
    )
    inputs = declared["inputs"]
    require(set(inputs) == {"archive", "manifest", "custody"}, "input-inventory")
    checked, paths = {}, {}
    for label, item in inputs.items():
        require(set(item) == {"path", "bytes", "sha256"}, "input-shape")
        path = v.inside(root, item["path"])
        require(path.resolve().is_relative_to((root / "build/results/assurance").resolve()), "input-boundary")
        require(path.stat().st_size == item["bytes"] and v.file_digest(path) == item["sha256"], "input-pin")
        checked[item["path"]], paths[label] = item["sha256"], path
    manifest = v.decode(v.read(paths["manifest"]))
    custody = v.decode(v.read(paths["custody"]))
    require(
        custody["immutable"] is True and custody["trust"] == "local" and custody["protected_qualification"] == custody["signature"] == "not-issued",
        "custody-scope",
    )
    for label, name in (("archive", "evidence.tar.gz"), ("manifest", "manifest.json")):
        require(
            custody["files"][name]["sha256"] == inputs[label]["sha256"]
            and custody["files"][name]["bytes"] == inputs[label]["bytes"]
            and "i" in custody["files"][name]["flags"],
            "custody-pin",
        )
    result = inspect(archive(paths["archive"], manifest), source)
    for fact in result.values():
        fact.update(archive=inputs["archive"]["path"], archive_sha256=inputs["archive"]["sha256"])
    return result, checked
