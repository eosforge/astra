"""Validate strict configuration, collect native Linux evidence, and evaluate obligations without installing dependencies."""

from collections.abc import Iterable
import argparse
from collections import deque
from collections.abc import Callable
import ctypes
import datetime as dt
from functools import lru_cache
import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time
import uuid

# Stable project and schema roots; none depend on the invoking terminal's working directory.
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
    # Lazy adapters must share this validator's exception identity when invoked as a script.
    sys.modules.setdefault("tools.verify", sys.modules[__name__])
SCHEMAS = Path(__file__).with_name("schemas")
# Maximum bytes per ordinary JSON artifact; larger raw logs have separately declared budgets.
LIMIT = 8 * 1024 * 1024
# Ordering compares required and observed provenance; names alone do not establish trust.
TRUST = {"local": 0, "ci": 1, "release": 2}


class Invalid(ValueError):
    """Reject input or evidence with a stable reason code, distinct from a test failure."""


def reject(code: str, detail: str = "") -> None:
    """Raise a stable evidence-validation reason with optional diagnostic detail."""
    raise Invalid(f"{code}: {detail}")


def digest(data: bytes) -> str:
    """Return the SHA-256 identity of already captured bytes."""
    return hashlib.sha256(data).hexdigest()


def encode(value: object) -> bytes:
    """Encode deterministic UTF-8 JSON, rejecting non-finite numbers."""
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def decode(data: bytes, *, maximum: int = LIMIT) -> dict | list | str | int | float | bool | None:
    """Parse bounded JSON and reject duplicate keys, excessive depth, and non-finite values."""
    if len(data) > maximum:
        reject("json-size")

    def pairs(entries: list[tuple[str, object]]) -> dict[str, object]:
        """Construct an object only when every key occurs once."""
        result = {}
        for key, value in entries:
            if key in result:
                reject("duplicate-key", key)
            result[key] = value
        return result

    def walk(value: object, depth: int = 0) -> None:
        """Reject excessive nesting and non-finite values after parsing."""
        if depth > 32:
            reject("json-depth")
        if isinstance(value, float) and not math.isfinite(value):
            reject("non-finite")
        if isinstance(value, dict):
            for child in value.values():
                walk(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                walk(child, depth + 1)

    try:
        result = json.loads(data, object_pairs_hook=pairs, parse_constant=lambda value: reject("non-finite", value))
        walk(result)
        return result
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        reject("json-invalid", type(error).__name__)


def read(path: str | Path, maximum: int = LIMIT) -> bytes:
    """Read at most the declared byte budget and reject oversized evidence."""
    with Path(path).open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        reject("file-size", str(path))
    return data


def stamp(value: str) -> dt.datetime:
    """Parse an explicit UTC timestamp and reject malformed or impossible dates."""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value):
        reject("timestamp", value)
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        reject("timestamp", value)


def utc() -> str:
    """Format current wall time for human-correlatable evidence metadata."""
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def inside(root: Path, name: str) -> Path:
    """Resolve a relative evidence path without traversal, absolute paths, or symlink components."""
    path = PurePosixPath(name)
    if not name or "\\" in name or ":" in name or path.is_absolute() or any(part in ("", ".", "..") for part in name.split("/")):
        reject("path-invalid", name)
    root = Path(root).resolve()
    target = root.joinpath(*path.parts)
    current = root
    for part in path.parts:
        current /= part
        if current.is_symlink():
            reject("path-symlink", name)
    if not target.resolve().is_relative_to(root):
        reject("path-escape", name)
    return target


def write_new(path: str | Path, value: object) -> dict[str, str | int]:
    """Create and flush a new artifact exclusively, returning its byte count and digest."""
    data = value if isinstance(value, bytes) else encode(value)
    with Path(path).open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return {"path": Path(path).name, "bytes": len(data), "sha256": digest(data)}


@lru_cache(maxsize=16)
def _check_schema(data: bytes, fields: tuple[str, ...], checker: Callable[[object], None]) -> None:
    """Remember successful meta-validation by exact bytes, field selection and checker identity."""
    definition = decode(data)
    for field in fields:
        definition = definition[field]
    checker(definition)


def schema(value: object, name: str, fields: tuple[str, ...] = ()) -> None:
    """Validate against a local closed schema using the existing engine, with remote resolution forbidden."""
    try:
        from jsonschema import Draft202012Validator
        from referencing import Registry
    except ImportError:
        reject("schema-engine-unavailable", "requires existing jsonschema with Draft202012Validator; no automatic installation")
    data = read(SCHEMAS / f"{name}.schema.json")
    definition = decode(data)
    fields = tuple(fields)
    for field in fields:
        definition = definition[field]
    # Local $defs suffice; an empty registry and rejecting callback prevent implicit network resolution.
    registry = Registry(retrieve=lambda uri: reject("schema-remote-reference", uri))
    # Retain at most 16 small byte strings; each call still parses and validates fresh objects.
    if len(data) <= 128 * 1024:
        _check_schema(data, fields, Draft202012Validator.check_schema)
    else:
        Draft202012Validator.check_schema(definition)
    validator = Draft202012Validator(definition, registry=registry)
    error = next(validator.iter_errors(value), None)
    if error is not None:
        reject("schema-invalid", f"{name}: /{'/'.join(map(str, error.absolute_path))}: {error.validator}")


def unique(items: Iterable[dict], field: str = "id") -> dict:
    """Index declared records by one field and reject duplicate identities."""
    result = {}
    for item in items:
        key = item[field]
        if key in result:
            reject("duplicate-id", key)
        result[key] = item
    return result


def closure(registry: dict, requested: Iterable[str]) -> list[str]:
    """Resolve rule dependencies while rejecting unknown IDs and cycles."""
    rules = unique(registry["rules"])
    visited, active = set(), set()

    def visit(name: str) -> None:
        """Visit one rule with separate active and completed sets to detect dependency cycles."""
        if name not in rules:
            reject("unknown-rule", name)
        if name in active:
            reject("rule-cycle", name)
        if name in visited:
            return
        active.add(name)
        for dependency in rules[name]["depends_on"]:
            visit(dependency)
        active.remove(name)
        visited.add(name)

    for name in requested:
        visit(name)
    return sorted(visited)


def expand(config: dict) -> dict[str, dict]:
    """Expand component requirements across platforms into uniquely identified obligations."""
    result = {}
    checks = unique(config["checks"])
    for component in config["components"]:
        for requirement in component["requirements"]:
            aggregate = requirement.get("aggregate", False)
            if "aggregate" in requirement and aggregate is not True:
                reject("obligation-aggregate-shape")
            if aggregate and (requirement["checks"] or not requirement.get("requires")):
                reject("obligation-aggregate-shape")
            if not aggregate and not requirement["checks"]:
                reject("obligation-empty-proof")
            for target in requirement.get("platforms", component["platforms"]):
                key = "/".join((component["id"], requirement["rule"], requirement["contract"], target, requirement["scenario"]))
                if key in result:
                    reject("duplicate-obligation", key)
                selected = [name for name in requirement["checks"] if target in checks[name].get("platforms", component["platforms"])]
                result[key] = {**requirement, "checks": selected, "component": component["id"], "platform": target}
    return result


def dependency_order(obligations: dict[str, dict]) -> tuple[list[str], dict[str, list[str]]]:
    """Resolve same-component, same-platform prerequisite obligations without recursive trust or implicit exemptions."""
    required, successors, remaining = {}, {key: [] for key in obligations}, {}
    for key, item in obligations.items():
        if item.get("aggregate") is True and (item["checks"] or not item.get("requires")):
            reject("obligation-aggregate-shape", key)
        required[key] = [
            "/".join((item["component"], reference["rule"], reference["contract"], item["platform"], reference["scenario"]))
            for reference in item.get("requires", [])
        ]
        if len(required[key]) != len(set(required[key])):
            reject("obligation-dependency-duplicate", key)
        remaining[key] = len(required[key])
        for dependency in required[key]:
            if dependency not in obligations:
                reject("obligation-dependency-missing", key + " -> " + dependency)
            successors[dependency].append(key)
    ready = deque(key for key, count in remaining.items() if count == 0)
    ordered = []
    while ready:
        key = ready.popleft()
        ordered.append(key)
        for successor in successors[key]:
            remaining[successor] -= 1
            if remaining[successor] == 0:
                ready.append(successor)
    if len(ordered) != len(obligations):
        reject("obligation-dependency-cycle")
    return ordered, required


def inventory(config: dict, names: Iterable[str]) -> dict:
    """Assign each owned input exactly once using explicit, most-specific path boundaries."""
    components = unique(config["scope"]["components"])
    paths = {}
    for component in components.values():
        for name in component["paths"]:
            if name in paths:
                reject("scope-path-duplicate", name)
            paths[name] = component["id"]
    for exclusion in config["scope"]["exclusions"]:
        for name in exclusion["paths"]:
            if name in paths:
                reject("scope-path-duplicate", name)
            paths[name] = None
    result = {"components": {name: [] for name in components}, "excluded": [], "unowned": []}
    for name in sorted(set(names)):
        matches = [path for path in paths if name == path or name.startswith(path + "/")]
        if not matches:
            result["unowned"].append(name)
            continue
        owner = paths[max(matches, key=len)]
        if owner is None:
            result["excluded"].append(name)
        else:
            result["components"][owner].append(name)
    return result


def scope(config: dict, root: Path) -> dict:
    """Audit maintained inputs and qualification registrations without treating tests as whole-system acceptance."""
    actual = source(root)
    assigned = inventory(config, [item["path"] for item in actual["files"] if item["sha256"] is not None])
    registered = unique(config["components"])
    declared = unique(config["scope"]["components"])
    missing = sorted(set(declared) - set(registered))
    empty = sorted(name for name, files in assigned["components"].items() if not files)
    return {
        **assigned,
        "source": actual,
        "unconfigured": missing,
        "empty": empty,
        "status": "blocked" if missing or empty or assigned["unowned"] else "complete",
    }


def go_command(check: dict, component: dict, root: Path) -> None:
    """Keep nested-module tests inside their declared owner and one native package."""
    arguments = check["argv"]
    if arguments[:2] == ["go", "-C"]:
        if len(arguments) < 7 or arguments[3:5] != ["test", "-json"]:
            reject("unsupported-go-command", check["id"])
        name = arguments[2]
        module = inside(root, name)
        if name not in component["paths"] or not (module / "go.mod").is_file():
            reject("go-module-owner", check["id"])
        try:
            manifest = read(inside(root, name + "/go.mod")).decode("utf-8")
        except UnicodeError:
            reject("go-module-encoding", check["id"])
        declared = re.findall(r"(?m)^module ([^\s]+)\s*$", manifest)
        if declared != [check["package"]]:
            reject("go-module-package", check["id"])
        # The first nested consumer needs only ordinary/race root-package tests.
        # Do not admit extra packages, alternate binaries, overlays or tool hooks.
        flags = arguments[5:-1]
        names = [value.split("=", 1)[0] for value in flags]
        if (
            arguments[-1] != "."
            or len(names) != len(set(names))
            or any(value != "-race" and re.fullmatch(r"-(?:count|p|parallel|timeout|run)=[^\r\n]+", value) is None for value in flags)
            or "-count=1" not in flags
        ):
            reject("go-module-command", check["id"])
        arguments = ["go", *arguments[3:]]
    if (arguments[:3] != ["go", "test", "-json"] and arguments[:4] != ["go", "test", "-race", "-json"]) or "-count=1" not in arguments:
        reject("unsupported-go-command", check["id"])


def configuration(path: str | Path, root: Path = ROOT) -> tuple[dict, dict, dict[str, str]]:
    """Validate policy structure, rule mappings, offline checks, and obligation completeness."""
    raw = read(path)
    config = decode(raw)
    schema(config, "development")
    rules_raw = read(inside(root, config["rules"]))
    registry = decode(rules_raw)
    schema(registry, "rules")
    rules = unique(registry["rules"])
    closure(registry, rules)
    platforms = unique(config["platforms"])
    checks = unique(config["checks"])
    components = unique(config["components"])
    for campaign in unique(config["campaigns"]).values():
        if campaign["platform"] not in platforms:
            reject("campaign-platform", campaign["id"])
        prior = set()
        for step in unique(campaign["steps"]).values():
            if not set(step["requires"]) <= prior:
                reject("campaign-dependency", step["id"])
            if any(set(re.findall(r"\{[^{}]*\}", value)) - {"{root}", "{cache}", "{python}", "{run}"} for value in step["argv"]):
                reject("campaign-placeholder", step["id"])
            prior.add(step["id"])
    declared = unique(config["scope"]["components"])
    inventory(config, [])
    for item in declared.values():
        if not set(item["platforms"]) <= platforms.keys():
            reject("scope-platform", item["id"])
        for name in item["paths"]:
            inside(root, name)
    for item in config["scope"]["exclusions"]:
        for name in item["paths"]:
            inside(root, name)
    for component in components.values():
        declaration = declared.get(component["id"])
        if declaration is None or any(component[key] != declaration[key] for key in ("level", "paths", "platforms")):
            reject("scope-component-mismatch", component["id"])
        if component["role"] in {"storage-core", "admission-core"} and component["level"] != "L3":
            reject("minimum-level", component["id"])
        if set(component["applicability"]) != set(rules):
            reject("rule-mapping-incomplete", component["id"])
        applicable = {key for key, value in component["applicability"].items() if value["status"] == "applicable"}
        if not set(registry["global"]) <= applicable:
            reject("global-rule-excluded", component["id"])
        closure(registry, applicable | set(registry["global"]))
        if not set(component["platforms"]) <= platforms.keys():
            reject("unknown-platform", component["id"])
        contracts = unique(component["contracts"])
        mapped = {target: set() for target in component["platforms"]}
        full = {target: set() for target in component["platforms"]}
        for requirement in component["requirements"]:
            targets = requirement.get("platforms", component["platforms"])
            if not set(targets) <= set(component["platforms"]):
                reject("requirement-platform", component["id"] + "/" + requirement["contract"])
            if requirement["rule"] not in rules:
                reject("unknown-rule", requirement["rule"])
            if requirement["rule"] not in applicable or requirement["contract"] not in contracts:
                reject("invalid-requirement", component["id"])
            for target in targets:
                mapped[target].add(requirement["rule"])
                if requirement["scenario"] == "full-rule":
                    full[target].add(requirement["rule"])
            for key in requirement["checks"]:
                if key not in checks or checks[key]["component"] != component["id"]:
                    reject("unknown-check", key)
                check = checks[key]
                if check["adapter"] != "unavailable" and requirement["contract"] not in {probe["contract"] for probe in check["probes"]}:
                    reject("unobservable-contract", requirement["contract"])
        if component["level"] in {"L2", "L3"}:
            needed = {"structure", "mcdc", "mutation", "fault-matrix", "delivery-matrix"}
            if component["level"] == "L3":
                needed.add("finite-model")
            for target in component["platforms"]:
                scenarios = {item["scenario"] for item in component["requirements"] if target in item.get("platforms", component["platforms"])}
                if not needed <= scenarios:
                    reject("capability-missing", component["id"] + "/" + target)
        if (
            any(covered != applicable for covered in mapped.values())
            or any(covered != applicable for covered in full.values())
            or {item["contract"] for item in component["requirements"]} != set(contracts)
        ):
            reject("unmapped-obligation", component["id"])
        for name in component["paths"]:
            inside(root, name)
        convergence = component["convergence"]
        if convergence["deadline"] is not None:
            stamp(convergence["deadline"])
    dependency_order(expand(config))
    for check in checks.values():
        if check["component"] not in components:
            reject("unknown-component", check["id"])
        if not set(check.get("platforms", components[check["component"]]["platforms"])) <= set(components[check["component"]]["platforms"]):
            reject("check-platform-out-of-scope", check["id"])
        if check["adapter"] != "unavailable":
            if check["adapter"] == "go-test-json":
                go_probes(check)
            else:
                unique(check["probes"], "contract")
            if not {probe["test"] for probe in check["probes"]} <= set(check["expected_tests"]):
                reject("probe-test-missing", check["id"])
            if public_environment(check["environment"]) != check["environment"]:
                reject("undeclared-environment-key", check["id"])
        if check["adapter"] == "retained-qualification":
            from tools import qualification

            qualification.configuration(check, config)
        if check["adapter"] == "storage-independence":
            from tools import independence

            independence.configuration(check, checks.get("storage-structure", {}))
            continue
        if check["adapter"] in {"admission-delivery", "storage-delivery"}:
            from tools import delivery

            delivery.configuration(check)
        if check["adapter"] == "admission-repair":
            from tools import repair

            repair.configuration(check)
        if check["adapter"] == "storage-repair":
            from tools import rollback

            rollback.configuration(check)
        if check["adapter"] == "observed-cases":
            python = check["argv"][:3] == ["python3", "-B", "tools/observe.py"] and check["argv"][3:4] in (["python"], ["ctest"])
            node = check["argv"][:8] == [
                "node",
                "--import",
                "./admin/scripts/observe.mjs",
                "--test",
                "--test-concurrency=1",
                "--test-reporter",
                "./admin/scripts/report.mjs",
                "admin/tests/*.test.mjs",
            ]
            if not python and not node:
                reject("unsupported-observation-command", check["id"])
            if "model" in check:
                from tools import models

                models.configuration(check)
            if "faults" in check:
                from tools import faults

                faults.configuration(check)
            if check["id"] == "common-native" or "boundaries" in check or any(probe["contract"] == "COMMON_NATIVE-16" for probe in check["probes"]):
                from tools import boundary

                boundary.configuration(check)
        if check["adapter"] == "go-test-json":
            go_command(check, components[check["component"]], root)
            if public_environment(check["environment"]) != check["environment"]:
                reject("undeclared-environment-key", check["id"])
            for key, value in {"GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": "-mod=readonly"}.items():
                if check["environment"].get(key) != value:
                    reject("offline-environment", key)
            if "model" in check:
                from tools import models

                models.configuration(check)
            if "coverage" in check:
                from tools import statements

                statements.configuration(check)
            if "faults" in check:
                from tools import faults

                faults.configuration(check)
            if "decisions" in check:
                from tools import equality, predicates

                (predicates if check["decisions"] == "admission-predicates-v2" else equality).configuration(check)
            if "numeric" in check:
                from tools import numeric

                numeric.configuration(check)
            if "recovery" in check:
                from tools import retry

                retry.recovery_configuration(check)
        if check["adapter"] == "go-mutations":
            from tools import mutate

            manifest = decode(read(inside(root, check["manifest"])))
            planned = mutate.plan(manifest, root)
            if check["argv"] != ["python3", "-B", "tools/mutate.py", "--manifest", check["manifest"]]:
                reject("unsupported-mutation-command", check["id"])
            if check["expected_tests"] != ["mutations"] or any(
                probe["test"] != "mutations" or probe["minimum_hits"] != len(planned) for probe in check["probes"]
            ):
                reject("mutation-denominator", check["id"])
            if check["environment"].get("TMPDIR") != "{run}/tmp":
                reject("mutation-temporary-ownership", check["id"])
        if check["adapter"] in {
            "admission-structure",
            "admission-independence",
            "storage-structure",
            "server-structure",
            "server-independence",
            "polaris-entry-qualification",
            "astrolabe-independence",
            "astrolabe-structure",
        }:
            from tools import structure

            structure.configuration(check)
            package = structure.selection(check)
            if package in {structure.ENTRY, structure.ASTROLABE}:
                continue
            model = checks.get(
                "admission-model" if package == structure.PACKAGE else "polaris-server-boundaries" if package == structure.SERVER else "storage-examples", {}
            )
            expected = model.get("expected_tests")
            if package in {structure.STORAGE, structure.SERVER}:
                storage = package == structure.STORAGE
                cases = decode(read(root / ("tests/fixtures/storage.tests.json" if storage else "tests/fixtures/server.tests.json")))
                allowed = list(cases) if isinstance(cases, list) else []
                if storage and check["probes"][0]["minimum_hits"] == 1558:
                    from tools import idle

                    allowed += list(idle.CASES)
                # Current campaigns require both backup cases; archived campaigns retain their exact declarations.
                backup = storage and {"storage-backup", "storage-backup-race"} <= checks.keys()
                if backup:
                    allowed += ["TestOnlineBackup", "TestBackupRestore"]
                if (
                    not isinstance(cases, list)
                    or len(cases) != (247 if storage else 300)
                    or digest(encode(cases))
                    != (
                        "ce57df5ffffd86ce48eea17d0ee4546bd1db92204e8d54b92369a02cf02e730e"
                        if storage
                        else "f3fc71d718ada189100a7f9c079f3c3b451dbae3a049a51ad60bc72ea817fe99"
                    )
                    or not isinstance(expected, list)
                    or not set(expected) <= set(allowed)
                    or backup
                    and set(expected) != set(allowed)
                    or not storage
                    and set(expected) != set(cases)
                ):
                    reject("structure-native-inventory-policy")
                expected = cases
                if storage and check["probes"][0]["minimum_hits"] == 1558:
                    from tools import idle

                    expected = sorted(cases + list(idle.CASES))
                    if backup and len(check["native_tests"]) == 259:
                        expected = sorted(expected + list(idle.BACKUP_CASES))
            if check["adapter"] == "admission-independence" and isinstance(expected, list):
                expected = expected + ["TestAdmissionEdges"]
                if check["probes"][0]["minimum_hits"] == 165:
                    expected = expected + ["TestLoadMetadata"]
            if check["native_tests"] != expected:
                reject("structure-native-inventory-policy")
    for name in config["inputs"] + [config["design"], config["standard"]]:
        inside(root, name)
    obligations = expand(config)
    _, dependencies = dependency_order(obligations)
    for key, item in obligations.items():
        if item.get("aggregate") and item["scenario"] == "full-rule":
            siblings = {
                other
                for other, candidate in obligations.items()
                if other != key and all(candidate[field] == item[field] for field in ("component", "rule", "platform"))
            }
            missing = siblings - set(dependencies[key])
            if missing:
                reject("aggregate-rule-coverage", key + ":" + ",".join(sorted(missing)[:8]))
    return config, registry, {"policy": digest(raw), "rules": digest(rules_raw)}


def source(root: Path) -> dict:
    # Bind the owned Astra workspace, including untracked, deleted, and index state; exclude ignored caches from source identity.
    """Capture commit, index, dirty files, and content identities for the actual owned workspace."""

    def git(*args: str) -> bytes:
        """Run a bounded read-only Git query against the selected source root."""
        return subprocess.check_output(["git", "-C", str(root), *args], timeout=30)

    names = git("ls-files", "-z", "--cached", "--others", "--exclude-standard").decode("utf-8").split("\0")
    files = []
    for name in sorted(set(filter(None, names))):
        path = inside(root, name)
        files.append({"path": name, "sha256": file_digest(path) if path.is_file() else None})
    head = subprocess.run(["git", "-C", str(root), "rev-parse", "--verify", "--quiet", "HEAD"], capture_output=True, timeout=30)
    if head.returncode not in (0, 1):
        reject("source-head-unavailable")
    # An initialized mirror can have no commit. Preserve that fact instead of fabricating an upstream identity.
    return {
        "commit": head.stdout.decode().strip() if head.returncode == 0 else None,
        "status": git("status", "--porcelain=v1", "-z", "--", ".").decode(),
        "files": files,
    }


def file_digest(path: str | Path) -> str:
    """Stream an artifact into SHA-256 without assuming its size fits in memory."""
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def authority(path: str | Path, expected: str, pins: dict[str, str], root: Path, config: dict) -> dict:
    """Verify externally pinned approval bytes, expiry, revocation, and input identities."""
    raw = read(path)
    if digest(raw) != expected:
        reject("authority-hash")
    value = decode(raw)
    schema(value, "authority")
    if stamp(value["expires_at"]) <= dt.datetime.now(dt.timezone.utc) or value["revoked"]:
        reject("authority-expired-or-revoked")
    actual = identities(pins, root, config)
    if actual != value["pins"]:
        reject("authority-pins")
    for exception in value["exceptions"]:
        stamp(exception["expires_at"])
    unique(value["exceptions"])
    return value


def identities(pins: dict[str, str], root: Path, config: dict) -> dict[str, str]:
    """Bind policy, collector, schemas, design, and development standard to their actual bytes."""
    actual = {
        **pins,
        "collector": file_digest(Path(__file__)),
        "design": file_digest(inside(root, config["design"])),
        "standard": file_digest(inside(root, config["standard"])),
    }
    actual["schemas"] = digest(encode({p.name: file_digest(p) for p in sorted(SCHEMAS.glob("*.schema.json"))}))
    return actual


def go_probes(check: dict) -> dict[tuple[str, str], dict]:
    """Bind each Go oracle to one test/contract pair; distinct tests may jointly cover a contract."""
    result = {}
    for probe in check["probes"]:
        key = (probe["test"], probe["contract"])
        if key in result:
            reject("go-probe-duplicate", str(key))
        result[key] = probe
    return result


def go_observations(data: bytes, check: dict, *, owner: str | None = None) -> tuple[dict[str, int], list[str]]:
    """Validate every declared Go oracle, optionally projecting returned counts to one owning test."""
    declared = go_probes(check)
    tests, probes = {}, {}
    package_started = False
    package_passed = False
    failures = []
    for line in data.splitlines():
        event = decode(line)
        if not isinstance(event, dict) or event.get("Package") != check["package"]:
            reject("go-package")
        action, test = event.get("Action"), event.get("Test")
        if not isinstance(action, str) or (test is not None and not isinstance(test, str)):
            reject("go-event-shape")
        if action not in {"start", "run", "pause", "cont", "pass", "fail", "skip", "output", "bench"}:
            reject("go-action", action)
        if package_passed:
            reject("go-event-after-terminal")
        if action in ("fail", "skip"):
            failures.append(f"{action}:{test or check['package']}")
        if not test:
            if action == "start":
                if package_started:
                    reject("go-duplicate-package")
                package_started = True
            if action == "pass":
                if not package_started or package_passed:
                    reject("go-terminal-order")
                package_passed = True
            continue
        if action == "run":
            if test in tests:
                reject("go-duplicate-test", test)
            tests[test] = "running"
        elif action in ("pass", "fail", "skip"):
            if tests.get(test) != "running":
                reject("go-test-order", test)
            tests[test] = action
        elif action == "output":
            output = event.get("Output", "")
            if not isinstance(output, str):
                reject("go-output-shape")
            marker = re.fullmatch(r"\s*(?:[^\n]+\.go:\d+: )?ASTRA-CONTRACT (\{[^\n]*\})\s*", output)
            if marker:
                probe = decode(marker.group(1).encode())
                if not isinstance(probe, dict) or set(probe) != {"contract", "hits"}:
                    reject("probe-shape")
                if not isinstance(probe["contract"], str):
                    reject("probe-contract")
                if type(probe["hits"]) is not int or probe["hits"] < 1:
                    reject("probe-empty")
                key = (test, probe["contract"])
                if key in probes or tests.get(test) != "running":
                    reject("probe-duplicate-or-late")
                probes[key] = probe["hits"]
    if not package_passed:
        failures.append("go-package-incomplete")
    if any(state != "pass" for state in tests.values()):
        failures.append("go-test-incomplete")
    for test in check["expected_tests"]:
        if tests.get(test) != "pass":
            failures.append(f"go-required-test:{test}")
    observed = {}
    for key, probe in declared.items():
        count = probes.get(key, 0)
        if count < probe["minimum_hits"]:
            failures.append(f"probe-budget:{probe['contract']}")
        elif owner is None or key[0] == owner:
            observed[probe["contract"]] = observed.get(probe["contract"], 0) + count
    if set(probes) - set(declared):
        failures.append("undeclared-probe")
    return observed, failures


def case_observations(data: bytes, check: dict) -> tuple[dict[str, int], list[str]]:
    """Reconcile ordered, nonempty assertion observations with native CTest XML when present."""
    tests, counts = {}, {}
    started = completed = False
    native = None
    node_counts, node_states = {}, {}
    engine = None
    failures = []
    for line in data.splitlines():
        if line.startswith(b"ASTRA-NODE "):
            value = decode(line[len(b"ASTRA-NODE ") :])
            if (
                not isinstance(value, dict)
                or set(value) != {"test", "hits"}
                or not isinstance(value["test"], str)
                or type(value["hits"]) is not int
                or value["hits"] < 0
            ):
                reject("node-counter-shape")
            if not started or completed or value["test"] in node_counts:
                reject("node-counter-order")
            node_counts[value["test"]] = value["hits"]
        elif line.startswith(b"ASTRA-NODE-TERMINAL "):
            value = decode(line[len(b"ASTRA-NODE-TERMINAL ") :])
            if (
                not isinstance(value, dict)
                or set(value) != {"type", "data"}
                or value["type"] not in ("test:pass", "test:fail")
                or not isinstance(value["data"], dict)
            ):
                reject("node-terminal-shape")
            name = value["data"].get("name")
            if not isinstance(name, str) or not started or completed or name in node_states:
                reject("node-terminal-order")
            node_states[name] = "skipped" if value["data"].get("skip") or value["data"].get("todo") else "passed" if value["type"] == "test:pass" else "failed"
        elif line.startswith(b"ASTRA-CTEST "):
            if native is not None or not started or completed:
                reject("case-native-order")
            raw = decode(line[len(b"ASTRA-CTEST ") :], maximum=check["log_bytes"])
            from tools import junit

            native = junit.cases(junit.decode(raw, check["expected_tests"], check["log_bytes"], exact=False))
        elif line.startswith(b"ASTRA-OBSERVE "):
            value = decode(line[len(b"ASTRA-OBSERVE ") :])
            if not isinstance(value, dict) or completed:
                reject("case-event-after-terminal-or-shape")
            action = value.get("event")
            if action == "start":
                if set(value) != {"event", "engine"} or started or value["engine"] not in ("unittest", "ctest", "node"):
                    reject("case-start")
                started, engine = True, value["engine"]
            elif action == "begin":
                name = value.get("test")
                if set(value) != {"event", "test"} or not started or not isinstance(name, str) or not name or name in tests:
                    reject("case-begin")
                tests[name] = "running"
            elif action == "end":
                name, hits = value.get("test"), value.get("hits")
                if set(value) != {"event", "test", "status", "hits"} or not isinstance(name, str) or tests.get(name) != "running":
                    reject("case-end-order")
                if value["status"] not in ("passed", "failed", "skipped") or type(hits) is not int or hits < 0:
                    reject("case-end-shape")
                tests[name], counts[name] = value["status"], hits
            elif action == "complete":
                if set(value) != {"event", "cases"} or not started or type(value["cases"]) is not int or value["cases"] != len(tests) or not tests:
                    reject("case-complete")
                completed = True
            else:
                reject("case-action")
    if not completed or any(state == "running" for state in tests.values()):
        failures.append("case-stream-incomplete")
    if set(tests) != set(check["expected_tests"]):
        failures.append("case-selection-mismatch")
    if any(state != "passed" for state in tests.values()):
        failures.append("case-not-passed")
    if "argv" in check:
        expected_engine = "node" if check["argv"][0] == "node" else "ctest" if check["argv"][3] == "ctest" else "unittest"
        if engine != expected_engine:
            reject("case-engine-mismatch")
    if engine == "ctest":
        if native is None or native != {name: {"status": status, "hits": counts.get(name, 0)} for name, status in tests.items()}:
            reject("case-native-mismatch")
    elif engine == "node":
        if node_states != tests or node_counts != counts:
            reject("case-node-native-mismatch")
    elif native is not None:
        reject("case-native-unexpected")
    if engine != "node" and (node_counts or node_states):
        reject("case-node-native-unexpected")
    observed = {}
    for probe in check["probes"]:
        hits = counts.get(probe["test"], 0)
        if hits < probe["minimum_hits"]:
            failures.append("probe-budget:" + probe["contract"])
        else:
            observed[probe["contract"]] = hits
    return observed, failures


def parse_observations(data: bytes, check: dict, root: Path = ROOT, profile: bytes | dict | None = None) -> tuple[dict[str, int], list[str]]:
    """Select only an explicitly implemented parser; an arbitrary success message never qualifies."""
    if check["adapter"] == "retained-qualification":
        from tools import qualification

        reader = qualification.Evaluator(root)
        states = reader.observations(data, check)
        reader.finish()
        return (
            ({probe["contract"]: len(states) for probe in check["probes"]}, [])
            if all(state == "passed" for state in states.values())
            else ({}, ["qualification-incomplete"])
        )
    if check["adapter"] == "storage-independence":
        from tools import independence

        return independence.observations(data, check, root, profile)
    if check["adapter"] in {"admission-delivery", "storage-delivery"}:
        from tools import delivery

        return delivery.observations(data, check, root)
    if check["adapter"] == "admission-repair":
        from tools import repair

        return repair.observations(data, check, root)
    if check["adapter"] == "storage-repair":
        from tools import rollback

        return rollback.observations(data, check, root)
    if check["adapter"] == "go-test-json":
        observed, failures = go_observations(data, check)
        if "model" in check and not failures:
            from tools import models

            # Compatibility shares the contract, but cannot supply or inflate the finite model's observations.
            native = go_observations(data, check, owner="TestFinite")[0] if check["model"] == "storage-commit-v1" else observed
            for contract, hits in models.observations(data, check, root).items():
                if native.get(contract) != hits:
                    reject("model-observation-mismatch", contract)
        if "coverage" in check and not failures:
            from tools import statements

            for contract, hits in statements.observations(profile, check, root).items():
                if observed.get(contract) != hits:
                    reject("command-structure-observation", contract)
        if "faults" in check and not failures:
            from tools import faults

            for contract, hits in faults.observations(data, check, root).items():
                if observed.get(contract) != hits:
                    reject("command-fault-observation", contract)
        if "decisions" in check and not failures:
            from tools import equality, predicates

            reader = predicates if check["decisions"] == "admission-predicates-v2" else equality
            for contract, hits in reader.observations(data, check, root).items():
                if observed.get(contract) != hits:
                    reject("equality-observation", contract)
        if "numeric" in check and not failures:
            from tools import numeric

            for contract, hits in numeric.observations(data, check, root).items():
                if observed.get(contract) != hits:
                    reject("numeric-observation", contract)
        if "recovery" in check and not failures:
            from tools import retry

            retry.recovery(data, check, root)
        return observed, failures
    if check["adapter"] == "observed-cases":
        observed, failures = case_observations(data, check)
        if "faults" in check and not failures:
            from tools import faults

            for contract, hits in faults.observations(data, check, root).items():
                if observed.get(contract) != hits:
                    reject("allocation-observation-mismatch", contract)
        if "model" in check and not failures:
            from tools import models

            if observed != models.observations(data, check, root):
                reject("model-observation-mismatch")
        if not failures and (
            check.get("id") == "common-native" or "boundaries" in check or any(probe["contract"] == "COMMON_NATIVE-16" for probe in check["probes"])
        ):
            from tools import boundary

            for contract, hits in boundary.observations(data, check, root).items():
                if observed.get(contract) != hits:
                    reject("boundary-observation-mismatch", contract)
        return observed, failures
    if check["adapter"] == "go-mutations":
        from tools import mutate

        return mutate.observations(data, check, root)
    if check["adapter"] in {
        "admission-structure",
        "admission-independence",
        "storage-structure",
        "server-structure",
        "server-independence",
        "polaris-entry-qualification",
        "astrolabe-independence",
        "astrolabe-structure",
    }:
        from tools import structure

        return structure.observations(data, check, root, profile)
    reject("unsupported-observation-adapter", check["adapter"])


def reference(directory: Path, item: dict, maximum: int = LIMIT) -> bytes:
    """Read an owned artifact only when its size and digest match the evidence reference."""
    data = read(inside(directory, item["path"]), maximum)
    if len(data) != item["bytes"] or digest(data) != item["sha256"]:
        reject("artifact-integrity", item["path"])
    return data


def coverage(directory: Path, record: dict, check: dict) -> dict | bytes | None:
    """Bind native counters or a structural bundle to the owning record before parsing observations."""
    if check["adapter"] in {
        "admission-structure",
        "admission-independence",
        "storage-structure",
        "storage-independence",
        "server-structure",
        "server-independence",
        "polaris-entry-qualification",
        "astrolabe-independence",
        "astrolabe-structure",
    }:
        from tools import structure

        if "profile" in record or "resolved_argv" in record or "structure" not in record:
            reject("structure-artifact-record")
        structure.reference(directory, record["structure"], "structure/bundle.json")
        return {"directory": directory, "record": record}
    if "structure" in record:
        reject("unexpected-structure-record")
    if "coverage" in check:
        expected = [argument.replace("{run}", str(directory)) for argument in check["argv"]]
        if record.get("resolved_argv") != expected or record.get("profile", {}).get("path") != "command.cover":
            reject("command-profile-record")
        return reference(directory, record["profile"], check["log_bytes"])
    if "profile" in record or "resolved_argv" in record:
        reject("unexpected-profile-record")
    return None


def decide(config: dict, observations: dict[tuple[str, ...], str], hard: list[str], exceptions: list[dict], now: dt.datetime) -> dict:
    """Resolve passed and exempt obligations; missing coverage or hard failures remain blocking."""
    obligations = expand(config)
    ordered, required = dependency_order(obligations)
    checks = unique(config["checks"])
    passed, exempt, details = set(), [], {}
    for key in ordered:
        item = obligations[key]
        states = [
            observations.get(
                (
                    (check, item["platform"], item["contract"], key)
                    if checks[check]["adapter"] == "retained-qualification"
                    else (check, item["platform"], item["contract"])
                ),
                "not-run",
            )
            for check in item["checks"]
        ]
        missing_dependencies = [dependency for dependency in required[key] if dependency not in passed]
        if (states or item.get("aggregate") is True) and all(state == "passed" for state in states) and not missing_dependencies:
            passed.add(key)
        else:
            details[key] = states + ["dependency-not-passed:" + dependency for dependency in missing_dependencies]
    for exception in exceptions:
        if exception["obligation"] not in obligations:
            hard.append("exception-out-of-scope:" + exception["id"])
        elif not exception["revoked"] and stamp(exception["expires_at"]) > now and exception["obligation"] not in passed:
            exempt.append(exception["obligation"])
    missing = sorted(set(obligations) - set(passed) - set(exempt))
    state = "blocked" if missing or hard else "eligible-with-exceptions" if exempt else "eligible"
    return {
        "status": state,
        "required": sorted(obligations),
        "passed": sorted(passed),
        "exceptions": sorted(set(exempt)),
        "missing": missing,
        "hard": sorted(set(hard)),
        "details": details,
    }


def bundle(config: dict, pins: dict, approved: dict, directory: Path, root: Path, actual: dict) -> tuple[dict, dict, set, list, str]:
    """Verify one original collection without deciding obligations that may depend on other collections."""
    raw = read(directory / "evidence.json")
    evidence = decode(raw)
    schema(evidence, "evidence")
    hard = []
    if not evidence["checks"]:
        hard.append("no-native-executions")
    if evidence["policy"] != pins["policy"] or evidence["rules"] != pins["rules"]:
        reject("evidence-policy")
    if evidence["collector"] != approved["pins"]["collector"]:
        reject("evidence-collector")
    if evidence["kind"] != "native-local" or evidence["trust"] != "local":
        reject("unsupported-provenance")
    before = decode(reference(directory, evidence["source_before"]))
    after = decode(reference(directory, evidence["source_after"]))
    if before != after or before != actual:
        hard.append("source-changed")
    if stamp(evidence["finished_at"]) < stamp(evidence["started_at"]):
        hard.append("time-order")
    checks = unique(config["checks"])
    records = {}
    observations = {}
    qualification_reader = None
    if len(evidence["records"]) != len(evidence["checks"]):
        reject("native-record-count")
    for record, native in zip(evidence["checks"], evidence["records"]):
        if decode(reference(directory, native)) != record:
            reject("native-record-mismatch")
        key = (record["id"], record["platform"])
        if key in records or record["id"] not in checks:
            reject("duplicate-or-unknown-check", record["id"])
        records[key] = record
        check = checks[record["id"]]
        if (
            check["adapter"]
            not in {
                "go-test-json",
                "observed-cases",
                "go-mutations",
                "admission-structure",
                "admission-independence",
                "storage-structure",
                "storage-independence",
                "server-structure",
                "server-independence",
                "polaris-entry-qualification",
                "astrolabe-independence",
                "astrolabe-structure",
                "admission-delivery",
                "storage-delivery",
                "admission-repair",
                "storage-repair",
                "retained-qualification",
            }
            or record["platform"] != evidence["platform"]
        ):
            reject("record-mapping")
        component = unique(config["components"])[check["component"]]
        if record["platform"] not in check.get("platforms", component["platforms"]):
            reject("record-check-platform")
        if record["argv"] != check["argv"] or record["environment"] != check["environment"]:
            reject("command-mismatch")
        if stamp(record["finished_at"]) < stamp(record["started_at"]):
            hard.append("check-time-order:" + record["id"])
        out = reference(directory, record["stdout"], check["log_bytes"])
        reference(directory, record["stderr"], check["log_bytes"])
        failures = []
        if record["exit_code"] != 0 or record["termination"] != "exited":
            failures.append("execution-failed")
        if not record["complete"] or record["duration_ms"] > check["timeout_s"] * 1000:
            failures.append("execution-incomplete")
            hard.append("evidence-incomplete:" + record["id"])
        if not record["cleanup"]:
            hard.append("cleanup-unverified:" + record["id"])
        try:
            native_profile = coverage(directory, record, check)
            if check["adapter"] == "retained-qualification":
                from tools import qualification

                if qualification_reader is None:
                    qualification_reader = qualification.Evaluator(root)
                coordinates = qualification_reader.observations(out, check)
                observed, parser_failures = {}, []
            else:
                observed, parser_failures = parse_observations(out, check, root, native_profile)
            failures.extend(parser_failures)
        except Invalid as error:
            observed = {}
            failures.append(str(error))
            hard.append("native-format:" + record["id"])
        if any(reason in failures for reason in ("go-package-incomplete", "go-test-incomplete", "case-stream-incomplete")):
            hard.append("native-stream-incomplete:" + record["id"])
        if check["adapter"] == "retained-qualification":
            for coordinate, item in expand(config).items():
                if record["id"] in item["checks"] and item["platform"] == record["platform"]:
                    observations[(record["id"], record["platform"], item["contract"], coordinate)] = (
                        ";".join(failures) if failures else coordinates.get(coordinate, "qualification-obligation-missing")
                    )
            continue
        for probe in check["probes"]:
            observations[(record["id"], record["platform"], probe["contract"])] = (
                "passed" if not failures and probe["contract"] in observed else ";".join(failures)
            )
    if qualification_reader is not None:
        qualification_reader.finish()
    platforms = unique(config["platforms"])
    target = platforms.get(evidence["platform"])
    if target is None or evidence["system"] != target["system"] or evidence["machine"] != target["machine"]:
        hard.append("platform-mismatch")
    if evidence["authority_sha256"] != approved["artifact_sha256"]:
        hard.append("authority-mismatch")
    if evidence["resources"]["build_jobs"] != 4 or evidence["resources"]["test_jobs"] != 4:
        hard.append("pilot-parallel-budget")
    for component in config["components"]:
        if TRUST[evidence["trust"]] < TRUST[component["evidence_trust"]]:
            hard.append("trust-gap:" + component["id"])
    return evidence, observations, set(records), hard, digest(raw)


def gate(config: dict, pins: dict[str, str], approved: dict, directory: str | Path | list[str | Path] | tuple[str | Path, ...], root: Path = ROOT) -> dict:
    """Join distinct, fully verified collections for the same frozen inputs; never select a successful retry."""
    directories = list(directory) if isinstance(directory, (list, tuple)) else [directory]
    if not 1 <= len(directories) <= 256:
        reject("evidence-bundle-count")
    directories = [Path(path).resolve() for path in directories]
    if len(set(directories)) != len(directories):
        reject("duplicate-evidence-directory")
    ownership = scope(config, root)
    actual = ownership["source"]
    hard = ["scope-unconfigured:" + name for name in ownership["unconfigured"]]
    hard.extend("scope-unowned:" + name for name in ownership["unowned"])
    hard.extend("scope-empty:" + name for name in ownership["empty"])
    observations, records, runs, inputs = {}, set(), set(), []
    for path in directories:
        evidence, observed, found, failures, checksum = bundle(config, pins, approved, path, root, actual)
        if evidence["run_id"] in runs:
            reject("duplicate-evidence-run", evidence["run_id"])
        if records & found:
            reject("duplicate-evidence-check", repr(sorted(records & found)))
        runs.add(evidence["run_id"])
        records.update(found)
        observations.update(observed)
        hard.extend(failures)
        inputs.append({"path": str(path), "run_id": evidence["run_id"], "platform": evidence["platform"], "sha256": checksum})
    # Binding the initial snapshot alone would miss a source edit while later bundles were read.
    if source(root) != actual:
        hard.append("source-changed")
    now = dt.datetime.now(dt.timezone.utc)
    for component in config["components"]:
        convergence = component["convergence"]
        if convergence["baseline"] is None or convergence["deadline"] is None or convergence["approval_ref"] is None:
            hard.append("convergence-unconfirmed:" + component["id"])
        elif stamp(convergence["deadline"]) <= now:
            hard.append("convergence-expired:" + component["id"])
    for check in config["checks"]:
        if check["adapter"] == "unavailable":
            for item in expand(config).values():
                if check["id"] in item["checks"]:
                    observations[(check["id"], item["platform"], item["contract"])] = "unavailable:" + check["reason"]
    return {**decide(config, observations, hard, approved["exceptions"], now), "evidence": inputs}


def proc_identity(pid: int) -> dict[str, str | int] | None:
    """Read Linux process identity and ancestry, returning no identity when the process has exited."""
    path = Path("/proc") / str(pid)
    try:
        parts = (path / "stat").read_text().rsplit(") ", 1)[1].split()
        return {"pid": pid, "start_ticks": parts[19], "parent": int(parts[1]), "session": int(parts[3]), "state": parts[0]}
    except FileNotFoundError:
        return None


def owned_members() -> list[dict[str, str | int]]:
    # Collection spawns children serially; the subreaper adopts descendants orphaned through double fork or setsid.
    """Enumerate descendants owned by this collector, including reparented children."""
    identities = {}
    for entry in Path("/proc").iterdir():
        if entry.name.isdecimal():
            identity = proc_identity(int(entry.name))
            if identity:
                identities[identity["pid"]] = identity
    owned = {os.getpid()}
    while True:
        added = {pid for pid, identity in identities.items() if identity["parent"] in owned} - owned
        if not added:
            break
        owned.update(added)
    return [identity for pid, identity in identities.items() if pid in owned and pid != os.getpid()]


def drain(process: subprocess.Popen) -> bool:
    # Signal only identity-checked members of this new session; pidfds prevent PID reuse between verification and signaling.
    """Terminate and reap owned descendants with identity checks and bounded escalation."""
    for signum, budget in ((signal.SIGTERM, 2), (signal.SIGKILL, 3)):
        deadline = time.monotonic() + budget
        while True:
            process.poll()
            members = owned_members()
            if not members:
                process.wait(timeout=1)
                return True
            for member in members:
                if member["state"] == "Z":
                    if member["parent"] == os.getpid() and member["pid"] != process.pid:
                        try:
                            os.waitpid(member["pid"], os.WNOHANG)
                        except ChildProcessError:
                            pass
                    continue
                try:
                    handle = os.pidfd_open(member["pid"])
                    try:
                        current = proc_identity(member["pid"])
                        if current and current["start_ticks"] == member["start_ticks"]:
                            signal.pidfd_send_signal(handle, signum)
                    finally:
                        os.close(handle)
                except ProcessLookupError:
                    pass
            process.poll()
            if time.monotonic() >= deadline:
                break
            time.sleep(0.02)
    process.poll()
    return not owned_members()


def public_environment(values: dict[str, str]) -> dict[str, str]:
    """Admit only explicit nonsecret tool inputs; never forward or record arbitrary host credentials or startup hooks."""
    allowed = {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "TZ",
        "LD_LIBRARY_PATH",
        "CC",
        "CXX",
        "CMAKE_BUILD_PARALLEL_LEVEL",
        "CMAKE_GENERATOR",
        "CMAKE_GENERATOR_INSTANCE",
        "GOPATH",
        "GOMODCACHE",
        "GOCACHE",
        "GOMAXPROCS",
        "CGO_ENABLED",
        "GOOS",
        "GOARCH",
        "GOTOOLCHAIN",
        "GOWORK",
        "GOPROXY",
        "GOSUMDB",
        "GOFLAGS",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "PYTHONDONTWRITEBYTECODE",
        "TMPDIR",
        "ASTRA_CACHE_ROOT",
        "ASTRA_TEST_LOG_DIR",
        "ASTRA_TEST_MIN_FREE_MIB",
        "ASAN_OPTIONS",
        "UBSAN_OPTIONS",
        "TSAN_OPTIONS",
        "SYSTEMROOT",
        "INCLUDE",
        "LIB",
        "LIBPATH",
    }
    return {key: value for key, value in values.items() if key in allowed}


def execute(check: dict, root: Path, directory: Path, target: str, cancelled: Callable[[], bool] = lambda: False) -> dict:
    """Capture one authorized command's native output and exit status, then drain all owned processes."""
    if check.get("adapter") == "storage-repair":
        from tools import rollback

        rollback.configuration(check)
        if target != "linux-amd64-cgo":
            reject("rollback-execution-platform")
    if check.get("adapter") == "admission-repair":
        from tools import repair

        repair.configuration(check)
        if target != "linux-amd64-cgo":
            reject("repair-execution-platform")
    if check.get("adapter") == "storage-independence":
        from tools import independence, structure

        native = next(item for item in decode(read(root / "development.json"))["checks"] if item["id"] == "storage-structure")
        independence.configuration(check, native)
        if target != structure.PLATFORM or (directory / "structure").exists():
            reject("storage-independence-execution-boundary")
    if check.get("adapter") in {"admission-delivery", "storage-delivery"}:
        from tools import delivery

        delivery.configuration(check)
        if target != "linux-amd64-cgo":
            reject("delivery-execution-platform")
    if check.get("adapter") in {
        "admission-structure",
        "admission-independence",
        "storage-structure",
        "server-structure",
        "server-independence",
        "polaris-entry-qualification",
        "astrolabe-independence",
        "astrolabe-structure",
    }:
        from tools import structure

        structure.configuration(check)
        if target != structure.PLATFORM or (directory / "structure").exists():
            reject("structure-execution-boundary")
    requested = public_environment(check["environment"])
    schema(requested, "evidence", ("properties", "checks", "items", "properties", "environment"))
    environment = {"PATH": os.environ.get("PATH", os.defpath), "LANG": "C.UTF-8"}
    if os.environ.get("HOME"):
        environment["HOME"] = os.environ["HOME"]
    environment.update(requested)
    # Expand only controlled project/cache/run paths; use no shell and inherit no arbitrary GOFLAGS or download proxies.
    cache = str(Path(os.environ.get("ASTRA_CACHE_ROOT", root / "build")).resolve())
    environment = {key: value.replace("{root}", str(root)).replace("{cache}", cache).replace("{run}", str(directory)) for key, value in environment.items()}
    environment.update({"GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": "-mod=readonly"})
    if os.name == "nt":
        # Windows system DLL selection is required by native children; compiler injection flags remain unforwarded.
        environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
        # Shell known-folder expansion and MSBuild FileTracker require the host Windows volume; never accept a caller override.
        environment["SYSTEMDRIVE"] = Path(environment["SYSTEMROOT"]).drive
        # Native SDK discovery and FileTracker also require these nonsecret host directories; arbitrary startup hooks remain excluded.
        for name in ("COMSPEC", "WINDIR", "PATHEXT", "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMDATA", "USERPROFILE", "APPDATA", "LOCALAPPDATA"):
            if os.environ.get(name):
                environment[name] = os.environ[name]
        environment["TMPDIR"] = str(directory / "tmp")
        environment["TEMP"] = environment["TMP"] = environment["TMPDIR"]
    schema(environment, "evidence", ("properties", "checks", "items", "properties", "resolved_environment"))
    for key in ("GOCACHE", "TMPDIR"):
        if key in environment:
            path = Path(environment[key]).resolve()
            if not path.is_relative_to(root / "build"):
                reject("cache-path", key)
            if key == "TMPDIR" and path != directory / "tmp":
                reject("temporary-ownership")
            path.mkdir(parents=True, exist_ok=True)
    # Windows' symbolic Python entry uses this admitted interpreter, never an unrelated PATH shim or Store alias.
    executable = sys.executable if os.name == "nt" and check["argv"][0] == "python3" else shutil.which(check["argv"][0], path=environment["PATH"])
    if not executable:
        reject("executable-missing", check["argv"][0])
    toolchain = {"command": {"path": executable, "sha256": file_digest(executable)}}
    arguments = check["argv"]
    if "coverage" in check:
        from tools import statements

        statements.configuration(check)
        if (directory / "command.cover").exists():
            reject("command-profile-existing")
        arguments = [argument.replace("{run}", str(directory)) for argument in arguments]
    for name in ("CC", "CXX"):
        if name in environment:
            tool = shutil.which(environment[name], path=environment["PATH"])
            if not tool:
                reject("executable-missing", name)
            toolchain[name] = {"path": tool, "sha256": file_digest(tool)}
    paths = {name: directory / f"{check['id']}.{name}.log" for name in ("stdout", "stderr")}
    outputs = {name: path.open("xb") for name, path in paths.items()}
    started = time.monotonic()
    started_at = utc()
    process, native = None, None
    reason, complete, cleanup = "exited", True, False
    selected = selectors.DefaultSelector()
    sizes = {name: 0 for name in paths}
    try:
        if os.name == "nt":
            from tools import windows

            native = windows.capture(
                [executable, *arguments[1:]],
                root,
                environment,
                outputs,
                timeout=check["timeout_s"],
                log_bytes=check["log_bytes"],
                cancelled=cancelled,
                identify=lambda identity: write_new(
                    directory / f"{check['id']}.process.json",
                    {"identity": identity, "argv": [executable, *arguments[1:]], "cwd": str(root)},
                ),
            )
            reason, complete, cleanup = (native[name] for name in ("termination", "complete", "cleanup"))
        else:
            process = subprocess.Popen(
                arguments, cwd=root, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
            )
            identity = proc_identity(process.pid)
            write_new(
                directory / f"{check['id']}.process.json",
                {"identity": identity, "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(), "argv": arguments, "cwd": str(root)},
            )
            for name in paths:
                pipe = getattr(process, name)
                os.set_blocking(pipe.fileno(), False)
                selected.register(pipe, selectors.EVENT_READ, name)
            while selected.get_map() or process.poll() is None:
                if cancelled():
                    reason, complete = "interrupted", False
                    break
                if time.monotonic() - started > check["timeout_s"]:
                    reason, complete = "timeout", False
                    break
                for key, _ in selected.select(0.1):
                    block = os.read(key.fd, 65536)
                    if not block:
                        selected.unregister(key.fileobj)
                        continue
                    remaining = check["log_bytes"] - sizes[key.data]
                    outputs[key.data].write(block[:remaining])
                    sizes[key.data] += min(remaining, len(block))
                    if len(block) > remaining:
                        reason, complete = "log-limit", False
                        break
                if not complete:
                    break
    except KeyboardInterrupt:
        reason, complete = "interrupted", False
    finally:
        if process is not None:
            cleanup = drain(process)
            process.stdout.close()
            process.stderr.close()
        if cleanup and "TMPDIR" in environment:
            temporary = Path(environment["TMPDIR"])
            try:
                if (
                    temporary.is_symlink()
                    or temporary.is_junction()
                    or temporary.resolve() != directory / "tmp"
                    or (os.name != "nt" and not shutil.rmtree.avoids_symlink_attacks)
                ):
                    cleanup = False
                else:
                    shutil.rmtree(temporary)
            except OSError:
                cleanup = False
        selected.close()
        for stream in outputs.values():
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
    record = {
        "id": check["id"],
        "platform": target,
        "argv": check["argv"],
        "environment": requested,
        "resolved_environment": environment,
        "executable": executable,
        "executable_sha256": file_digest(executable),
        "toolchain": toolchain,
        "started_at": started_at,
        "finished_at": utc(),
        "duration_ms": round((time.monotonic() - started) * 1000),
        "exit_code": native["exit_code"] if native is not None else process.returncode,
        "termination": reason,
        "complete": complete,
        "cleanup": cleanup,
    }
    for name, path in paths.items():
        record[name] = {"path": path.name, "bytes": path.stat().st_size, "sha256": file_digest(path)}
    if "coverage" in check:
        record["resolved_argv"] = arguments
        path = inside(directory, "command.cover")
        if path.exists():
            data = read(path)
            record["profile"] = {"path": path.name, "bytes": len(data), "sha256": digest(data)}
    if check.get("adapter") in {
        "admission-structure",
        "admission-independence",
        "storage-structure",
        "storage-independence",
        "server-structure",
        "server-independence",
        "polaris-entry-qualification",
        "astrolabe-independence",
        "astrolabe-structure",
    }:
        path = inside(directory, "structure/bundle.json")
        if path.exists():
            record["structure"] = structure.artifact(directory, path)
    return record


def collect(config: dict, pins: dict[str, str], approved: dict, root: Path, output: Path, target: str, chosen: list[str], authorization: str) -> Path:
    """Collect explicitly selected checks in a fresh run directory with source and resource identity."""
    if platform.system() != "Linux" or not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        reject("collector-platform", "Linux with pidfd required; other platforms not silently substituted")
    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(36, 1, 0, 0, 0) != 0:
        reject("collector-subreaper", str(ctypes.get_errno()))
    targets = unique(config["platforms"])
    if target not in targets or (platform.system(), platform.machine()) != (targets[target]["system"], targets[target]["machine"]):
        reject("collector-platform")
    checks = unique(config["checks"])
    if len(chosen) != len(set(chosen)) or not chosen:
        reject("check-selection")
    for name in chosen:
        if name not in checks or checks[name]["adapter"] not in {
            "go-test-json",
            "observed-cases",
            "go-mutations",
            "admission-structure",
            "admission-independence",
            "storage-structure",
            "storage-independence",
            "server-structure",
            "server-independence",
            "polaris-entry-qualification",
            "astrolabe-independence",
            "astrolabe-structure",
            "admission-delivery",
            "storage-delivery",
            "admission-repair",
            "storage-repair",
            "retained-qualification",
        }:
            reject("unsupported-check", name)
        component = unique(config["components"])[checks[name]["component"]]
        if target not in checks[name].get("platforms", component["platforms"]):
            reject("collector-check-platform", name)
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from tools.build import parallel, resources

    cpus, memory = resources()
    builds, cases = parallel(cpus, memory, "release", 4, 4)
    capacity = {"cpus": cpus, "available_bytes": memory, "build_jobs": builds, "test_jobs": cases, "disk_free_bytes": shutil.disk_usage(root).free}
    if memory is None or builds < 4 or cases < 4 or capacity["disk_free_bytes"] < 1024**3:
        reject("resource-preflight", "fixed jobs4/test-jobs4 pilot budget unavailable; reapprove changed policy, no implicit override")
    run_id = str(uuid.uuid4())
    directory = Path(output) / run_id
    directory.mkdir(parents=True, exist_ok=False)
    evidence = {
        "schema_version": 1,
        "run_id": run_id,
        "kind": "native-local",
        "trust": "local",
        "platform": target,
        "system": platform.system(),
        "machine": platform.machine(),
        "policy": pins["policy"],
        "rules": pins["rules"],
        "collector": approved["pins"]["collector"],
        "authority_sha256": approved["artifact_sha256"],
        "authorization_ref": authorization,
        "started_at": utc(),
        "checks": [],
        "records": [],
        "resources": capacity,
        "engine": {"python": platform.python_version(), "jsonschema": importlib.metadata.version("jsonschema")},
    }
    evidence["source_before"] = write_new(directory / "source-before.json", source(root))
    stopped = False

    def stop(*_: object) -> None:
        """Record cancellation for the collector loop without performing cleanup in the signal handler."""
        nonlocal stopped
        stopped = True

    previous = {signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGINT)}
    for signum in previous:
        signal.signal(signum, stop)
    try:
        for name in chosen:
            if stopped:
                break
            record = execute(checks[name], root, directory, target, lambda: stopped)
            evidence["checks"].append(record)
            evidence["records"].append(write_new(directory / f"{name}.record.json", record))
            if not record["complete"] or record["exit_code"] != 0 or not record["cleanup"]:
                break
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        evidence["finished_at"] = utc()
        evidence["source_after"] = write_new(directory / "source-after.json", source(root))
        write_new(directory / "evidence.json", evidence)
    return directory


def main(argv: list[str] | None = None) -> int:
    """Dispatch validation, authorized collection, or evidence evaluation with distinct exit statuses."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--config", default="development.json")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("validate")
    sub.add_parser("audit")
    for action in ("collect", "gate"):
        command = sub.add_parser(action)
        command.add_argument("--authority", type=Path, required=True)
        command.add_argument("--authority-sha256", required=True)
        if action == "collect":
            command.add_argument("--platform", required=True)
            command.add_argument("--check", action="append", required=True)
            command.add_argument("--authorization", required=True)
        else:
            command.add_argument("directory", type=Path, nargs="+")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        config, registry, pins = configuration(inside(root, args.config), root)
        if args.action == "audit":
            result = scope(config, root)
            result["unavailable"] = [check["id"] for check in config["checks"] if check["adapter"] == "unavailable"]
            result["obligations"] = list(expand(config))
            if result["unavailable"]:
                result["status"] = "blocked"
            print(encode(result).decode())
            return 2 if result["status"] == "blocked" or result["unavailable"] else 0
        if args.action == "validate":
            print(
                encode(
                    {
                        "status": "valid",
                        "pins": identities(pins, root, config),
                        "obligations": list(expand(config)),
                        "loaded_rules": closure(registry, [r["id"] for r in registry["rules"]]),
                    }
                ).decode()
            )
            return 0
        approved = authority(args.authority, args.authority_sha256, pins, root, config)
        approved["artifact_sha256"] = args.authority_sha256
        output = inside(root, "build/results/verification")
        if args.authority.resolve().is_relative_to(output.resolve()):
            reject("authority-in-evidence")
        if args.action == "collect":
            directory = collect(config, pins, approved, root, output, args.platform, args.check, args.authorization)
            print(directory)
            records = decode(read(directory / "evidence.json"))["checks"]
            return 0 if len(records) == len(args.check) and all(c["complete"] and c["cleanup"] and c["exit_code"] == 0 for c in records) else 2
        directories = [path.resolve() for path in args.directory]
        result = gate(config, pins, approved, directories, root)
        report = {
            "evaluated_at": utc(),
            "policy_sha256": pins["policy"],
            "authority_sha256": args.authority_sha256,
            "evidence": result["evidence"],
            "gate": result,
        }
        write_new(directories[0] / f"gate-{uuid.uuid4()}.json", report)
        print(encode(report).decode())
        return {"eligible": 0, "eligible-with-exceptions": 10, "blocked": 2}[result["status"]]
    except (Invalid, OSError, subprocess.SubprocessError) as error:
        print(encode({"status": "invalid", "reason": str(error)}).decode(), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
