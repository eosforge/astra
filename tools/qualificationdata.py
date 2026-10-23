"""Interpret pinned retained native campaigns for named qualification facets without starting applications."""

import io
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import tarfile
import tempfile

from tools import (
    delivery,
    entry,
    mutate,
    negatives,
    pairedproof,
    profiles,
    statements,
    storagecompiler,
    structure,
    verifierdata,
    verify as v,
)
from bench import compare


def unpack(raw: bytes) -> dict[str, bytes]:
    """Admit the fixed large campaign envelope while preserving regular-file and path checks."""
    files, folded, total = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for member in archive:
            name, path = member.name, PurePosixPath(member.name)
            total += member.size
            if (
                not member.isfile()
                or not name
                or path.is_absolute()
                or path.as_posix() != name
                or ".." in path.parts
                or "\\" in name
                or ":" in name
                or name.casefold() in folded
                or not 0 <= member.size <= 128 * 1024**2
                or len(files) >= 32768
                or total > 768 * 1024**2
            ):
                v.reject("qualification-archive-member", name)
            folded.add(name.casefold())
            data = archive.extractfile(member).read(member.size + 1)
            if len(data) != member.size:
                v.reject("qualification-archive-truncated", name)
            files[name] = data
    return files


def source_binding(root: Path, original: dict[str, str], *, cpp: bool = False, build: bool = False) -> dict:
    """Compare the actual runtime source closure; verification-only revisions do not replace production bytes."""

    def selected(name: str) -> bool:
        """Select source and optional build inputs for the requested native qualification scope."""
        path = PurePosixPath(name)
        if build and (path.name == "CMakeLists.txt" or path.suffix == ".cmake" or name == "tools/build.py"):
            return True
        if name.startswith(("build/", "docs/", "tools/")):
            return False
        if cpp:
            return path.suffix in {
                ".cpp",
                ".h",
                ".hpp",
                ".proto",
            } and not name.startswith("tests/")
        if name in {
            "go.mod",
            "go.sum",
            "dependencies.lock.json",
            "bench/performance.json",
            "tests/soak.py",
            "tests/services.py",
            "tests/resources.py",
        }:
            return True
        if path.suffix == ".go":
            return name.startswith("comet/go/") or not path.name.endswith("_test.go") and not name.startswith("tests/")
        return path.suffix in {".cpp", ".h", ".hpp", ".proto"} and not name.startswith("tests/") or name.startswith("bench/") and path.suffix == ".py"

    before = {name: sha for name, sha in original.items() if selected(name)}
    after = {row["path"]: row["sha256"] for row in v.source(root)["files"] if row["sha256"] is not None and selected(row["path"])}
    changes = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
    return {
        "status": "current" if not changes else "source-review-required",
        "files": len(before),
        "changed": changes,
    }


def go_binding(root: Path, original: dict[str, str]) -> dict:
    """Bind every owned Go source/test, module lock and protocol, including added or removed files."""

    def selected(name: str) -> bool:
        """Select non-build Go, protocol, and dependency inputs for the qualification scope."""
        path = PurePosixPath(name)
        return not name.startswith("build/") and (path.suffix in {".go", ".proto"} or path.name in {"go.mod", "go.sum", "dependencies.lock.json"})

    before = {name: checksum for name, checksum in original.items() if selected(name)}
    after = {row["path"]: row["sha256"] for row in v.source(root)["files"] if row["sha256"] is not None and selected(row["path"])}
    changes = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
    return {
        "status": "source-review-required" if changes else "current",
        "files": len(before),
        "changed": changes,
    }


def streams(files: dict[str, bytes], prefix: str, *, expected_exit: int = 0) -> tuple[dict, bytes, bytes]:
    """Require complete native records and exact stdout/stderr bytes, including intentional mutant failures."""
    record = v.decode(files[prefix + "record.json"])
    v.schema(record, "evidence", ("properties", "checks", "items"))
    if record["exit_code"] != expected_exit or not record["complete"] or not record["cleanup"] or record["termination"] != "exited":
        v.reject("qualification-native-command", prefix)
    result = []
    for field in ("stdout", "stderr"):
        item = record[field]
        path = PurePosixPath(item["path"])
        if path.is_absolute() or ".." in path.parts or "\\" in item["path"] or path.as_posix() != item["path"]:
            v.reject("qualification-native-stream-path")
        data = files[prefix + item["path"]]
        if len(data) != item["bytes"] or v.digest(data) != item["sha256"]:
            v.reject("qualification-native-stream")
        result.append(data)
    return record, *result


def source_audit(files: dict[str, bytes], seal: dict, retired: dict, config: dict, current: dict) -> dict[str, dict]:
    """Project authenticated source-ownership content without qualifying a component's runtime or full rules."""
    proof = verifierdata.inspect(files, seal, retired)
    original = entry.unpack(files["source.tar.gz"])
    before_config = v.decode(original["development.json"])
    declared = v.unique(before_config["checks"])["gap-scope"]
    cases = [
        "tests.test_scope.ScopeTests.test_" + name
        for name in (
            "current",
            "ownership",
            "missing",
            "empty",
            "unowned",
            "source",
            "entries",
            "policy",
        )
    ]
    if (
        proof["check"] != declared
        or declared["argv"] != ["python3", "-B", "tools/observe.py", "python", *cases]
        or set(declared["expected_tests"]) != set(cases)
        or proof["cases"] != 8
        or before_config["scope"] != config["scope"]
    ):
        v.reject("qualification-source-audit-scope")
    before = {name: v.digest(data) for name, data in original.items()}
    after = {row["path"]: row["sha256"] for row in current["files"] if row["sha256"] is not None}
    for name in ("tools/verify.py", "tools/observe.py", "tests/test_scope.py"):
        if before.get(name) != after.get(name):
            v.reject("qualification-source-audit-reader", name)
    old_inventory, new_inventory = v.inventory(before_config, list(before)), v.inventory(config, list(after))
    if old_inventory["unowned"] or new_inventory["unowned"]:
        v.reject("qualification-source-audit-ownership")
    old_components, new_components = v.unique(before_config["components"]), v.unique(config["components"])
    result = {}
    for component in (
        "common",
        "admin",
        "verification",
        "tools",
        "benchmarks",
        "protocol",
        "documentation",
    ):
        fields = ("id", "paths", "level", "platforms")
        if {key: old_components[component][key] for key in fields} != {key: new_components[component][key] for key in fields}:
            v.reject("qualification-source-audit-component", component)
        old_names, new_names = (
            old_inventory["components"][component],
            new_inventory["components"][component],
        )
        if not old_names or not new_names:
            v.reject("qualification-source-audit-empty", component)
        changed = sorted(name for name in set(old_names) | set(new_names) if before.get(name) != after.get(name))
        result[component] = {
            "facet": "source-ownership",
            "components": [component],
            "binding": {
                "status": "source-review-required" if changed else "current",
                "files": len(old_names),
                "current_files": len(new_names),
                "changed": changed,
            },
            "native_cases": proof["cases"],
            "native_executed_step": proof["executed_step"],
            "native_canonical_check": declared["id"],
            "native_record_sha256": proof["record_sha256"],
            "native_source_sha256": v.digest(v.encode(proof["source"])),
            "owned_source_sha256": v.digest(v.encode({name: before[name] for name in old_names})),
            "boundary": "Retained Linux source-ownership observations only. This is not a current component source-check pass, runtime/platform validation, semantic coverage, MC/DC, performance, protected custody or release qualification. Owned-input changes keep this facet under source review.",
        }
    return result


def native_context(root: Path, config: dict, current: dict) -> tuple[dict[str, dict], dict[str, str]]:
    """Link finite native contracts, dependency identities and tool context without issuing full-rule approval."""
    native, custody, immutable, checked = profiles.load(root, root / profiles.MANIFEST, profiles.MODEL)
    _, proof = profiles.inspect(root, native, custody, immutable, config, current)
    inputs = v.decode(native["inputs.json"])
    original = entry.unpack(native["source.tar.gz"])
    original_hashes = {name: v.digest(data) for name, data in original.items()}
    binding = go_binding(root, original_hashes)
    dependencies = v.decode(native["dependencies.before.json"])
    identities = {name: {"files": len(values), "sha256": v.digest(v.encode(values))} for name, values in dependencies.items()}
    locks = {name: original_hashes[name] for name in ("go.mod", "go.sum", "dependencies.lock.json")}
    facts = {}
    for component, name in (
        ("admission", "admission-model"),
        ("polaris-storage", "storage-examples"),
    ):
        check = inputs["checks"][name]
        profile = proof["profiles"][name]
        package = check["argv"][-1].removeprefix("./")
        locations = {}
        for path, data in original.items():
            if PurePosixPath(path).parent.as_posix() != package or not path.endswith("_test.go"):
                continue
            text = data.decode("utf-8")
            for match in re.finditer(r"(?m)^func (Test[A-Za-z0-9_]+)\(", text):
                if match[1] in locations:
                    v.reject("qualification-native-context-test-duplicate", match[1])
                locations[match[1]] = {
                    "path": path,
                    "line": text.count("\n", 0, match.start()) + 1,
                    "sha256": original_hashes[path],
                }
        links = []
        for probe in check["probes"]:
            base = probe["test"].split("/", 1)[0]
            if base not in locations or probe["test"] not in check["expected_tests"]:
                v.reject("qualification-native-context-test-link", probe["test"])
            links.append(
                {
                    "contract": probe["contract"],
                    "test": probe["test"],
                    "declared_minimum_hits": probe["minimum_hits"],
                    "native_contract_total_hits": profile["observations"][probe["contract"]],
                    "native_test_passed": True,
                    "source": locations[base],
                }
            )
        shared = {
            "components": [component],
            "binding": binding,
            "native_profile": name,
            "native_record_sha256": profile["record_sha256"],
            "native_cases": profile["tests"],
            "producer_source_sha256": proof["producer_source_sha256"],
        }
        facts[component + "/trace"] = shared | {
            "facet": "retained-native-trace-links",
            "applies_to": ["DEV-TRACE"],
            "links": links,
            "approval": "not-issued",
            "boundary": "Only the exact finite native profile's declared contract/test/source links. Contract hit totals are aggregate native observations, not per-probe counts. This supplies no approved package-wide/end-to-end trace qualification.",
        }
        facts[component + "/supply"] = shared | {
            "facet": "retained-native-dependency-identities",
            "applies_to": ["DEV-SUPPLY"],
            "source_locks": locks,
            "native_dependency_trees": identities,
            "native_tools": inputs["tools"],
            "origin_license_security_approval": "not-issued",
            "boundary": "Exact source-lock/tool/cache identities were stable before/after the two native profiles. The cache inventory is not a complete call graph, origin attestation, license admission or vulnerability clearance.",
        }
        if component == "admission":
            record = v.decode(native["commands/" + name + "/record.json"])
            facts[component + "/compat"] = shared | {
                "facet": "retained-native-toolchain-context",
                "applies_to": ["DEV-COMPAT"],
                "native_argv": record["argv"],
                "native_toolchain": record["toolchain"],
                "native_platform": record["platform"],
                "compatibility_matrix": "incomplete",
                "boundary": "One original Linux/CGO toolchain and finite profile only. This is not the complete supported-generation, installed-consumer, upgrade/downgrade or cross-platform compatibility matrix.",
            }
    return facts, checked


def residence(root: Path, files: dict[str, bytes]) -> dict:
    """Recompute every original finite resource window and retain all seven real owner identities."""
    inputs = v.decode(files["inputs.json"])
    source = entry.unpack(files["source.tar.gz"])
    if {name: v.digest(data) for name, data in source.items()} != inputs["files"]:
        v.reject("qualification-residence-source")
    terminal = v.decode(files["terminal.json"])
    if (
        terminal["errors"]
        or terminal["interrupted"]
        or terminal["remaining_owned"]
        or not all(terminal[key] for key in ("source_unchanged", "products_unchanged", "protected_unchanged"))
    ):
        v.reject("qualification-residence-terminal")
    record, _, _ = streams(files, "source/build/commands/cluster/")
    plan = inputs["plan"]
    if (
        plan["seconds"] != 7200
        or plan["windows"] != [[0, 1200], [1200, 2700], [2700, 4200], [4200, 5700], [5700, 7200]]
        or (
            plan["warmup"],
            plan["minimum_samples"],
            plan["minimum_measured_samples"],
            plan["maximum_gap"],
        )
        != (1, 230, 280, 15)
        or record["duration_ms"] < 7200000
    ):
        v.reject("qualification-residence-budget")
    binding, policy = (v.decode(files[name]) for name in ("cohort.native.json", "policy.native.json"))
    identities = binding["identities"]
    if {role: sum(row["role"] == role for row in identities) for role in ("star", "sdk", "control")} != {"star": 3, "sdk": 1, "control": 3}:
        v.reject("qualification-residence-cohort")
    control = {PurePosixPath(row["command"][0]).name: row for row in identities if row["role"] == "control"}
    sdk = [row for row in identities if row["role"] == "sdk"]
    if set(control) != {"pulsar", "polaris", "astrolabe"} or len(sdk) != 1 or PurePosixPath(sdk[0]["command"][0]).name != "comet-go-system":
        v.reject("qualification-residence-components")
    expected = []
    for row in identities:
        identity = row["identity"]
        scope = {
            "pid": identity["pid"],
            "started": int(identity["start_ticks"]),
            "log": row["log"],
        }
        if scope not in binding["owners"]:
            v.reject("qualification-residence-owner")
        expected.append({**scope, **plan["limits"][row["role"]]})
    if policy != {"warmup": 1, "processes": expected} or v.digest(v.encode(policy)) != binding["policy_sha256"]:
        v.reject("qualification-residence-policy")
    for role, memory in (("star", 256), ("sdk", 512), ("control", 128)):
        if plan["limits"][role] != {
            "rss": {"maximum": memory * 1024**2, "rise": 8 * 1024**2},
            "fds": {"maximum": 256, "rise": 4},
            "threads": {"maximum": 256 if role == "sdk" else 64, "rise": 4},
        }:
            v.reject("qualification-residence-limits")
    selected = {"started", "sample", "sampling_exit", "steady", "completed"}
    projection = b"".join(line + b"\n" for line in files["recovery/events.jsonl"].splitlines() if v.decode(line)["event"] in selected)
    if projection != files["resource.events.jsonl"]:
        v.reject("qualification-residence-projection")
    result = delivery.bounds(
        projection,
        policy=policy,
        owners=binding["owners"],
        **{key: plan[key] for key in ("seconds", "windows", "maximum_gap", "minimum_samples")},
    )
    if result != v.decode(files["bounds.native.json"]) or result["status"] != "passed" or result["violations"]:
        v.reject("qualification-residence-bounds")
    if any(row["samples"] < 280 for row in result["residence"]["windows"][1:]):
        v.reject("qualification-residence-samples")
    return {
        "facet": "finite-resources",
        "components": [
            "admission",
            "polaris-storage",
            "star",
            "pulsar",
            "polaris-server",
            "astrolabe",
            "comet-go",
        ],
        "binding": source_binding(root, inputs["files"]),
        "seconds": 7200,
        "owners": binding["owners"],
        "samples": result["residence"]["steady_samples"],
        "windows": [row["samples"] for row in result["residence"]["windows"]],
        "component_owners": {
            "polaris-server": control["polaris"]["identity"],
            "astrolabe": control["astrolabe"]["identity"],
            "comet-go": sdk[0]["identity"],
        },
        "boundary": "Finite seven-owner RSS/FD/thread maxima and rise only; queue/disk/WAL/saturation and indefinite operation remain independent.",
    }


def go_race(root: Path, files: dict[str, bytes], packages: dict) -> dict:
    """Project complete named Linux packages from original root and independent SDK Race commands."""
    inputs = v.decode(files["inputs.json"])
    source = entry.unpack(files["source.tar.gz"])
    if {name: v.digest(data) for name, data in source.items()} != inputs["files"]:
        v.reject("qualification-go-source")
    terminal = v.decode(files["terminal.json"])
    cleanup = v.decode(files["cleanup.native.json"])
    if terminal["errors"] or terminal["interrupted"] or terminal["remaining_owned"] or not terminal["cache_returned"] or cleanup["failed"]:
        v.reject("qualification-go-terminal")
    if cleanup["unit"]["MainPID"] != "0" or cleanup["unit"]["ControlGroup"] or not cleanup["retired"]:
        v.reject("qualification-go-retirement")
    expected = {
        "polaris-server": (
            "root-race",
            {"github.com/eosforge/astra/polaris/internal/server": 300},
        ),
        "astrolabe": (
            "root-race",
            {
                "github.com/eosforge/astra/astrolabe": 59,
                "github.com/eosforge/astra/astrolabe/internal/bridge": 97,
                "github.com/eosforge/astra/astrolabe/internal/web": 276,
            },
        ),
        "comet-go": ("sdk-race", {"github.com/eosforge/astra/comet/go": 248}),
        "command": ("root-race", {"github.com/eosforge/astra/internal/command": 9}),
    }
    if set(packages) != set(expected):
        v.reject("qualification-go-components")
    profiles = {}
    for profile in ("root-race", "sdk-race"):
        prefix = "source/build/commands/" + profile + "-test/"
        record, stdout, stderr = streams(files, prefix)
        native_root = "/home/ubuntu/verdandi/astra/build/results/assurance/go-upgrade-contracts-current-3/source"
        module = native_root + ("/comet/go" if profile == "sdk-race" else "")
        argv = [
            inputs["linux_go"],
            "-C",
            module,
            "test",
            "-race",
            "-p=2",
            "-parallel=2",
            "-count=1",
            "-timeout=300s",
            "-skip=^TestSystemThreeStars$",
            "-json",
            "./...",
        ]
        if (
            record["argv"] != argv
            or record["duration_ms"] > 300000
            or record["platform"] != "linux-amd64-cgo"
            or record["executable_sha256"] != inputs["linux_go_sha256"]
            or "DATA RACE" in stderr.decode(errors="replace")
            or any(
                record["environment"].get(key) != value
                for key, value in {
                    "GOMAXPROCS": "2",
                    "CGO_ENABLED": "1",
                    "GOPROXY": "off",
                    "GOSUMDB": "off",
                    "GOTOOLCHAIN": "local",
                    "GOWORK": "off",
                    "GOFLAGS": "-mod=readonly",
                }.items()
            )
        ):
            v.reject("qualification-go-command", profile)
        events = [(line, v.decode(line)) for line in stdout.splitlines()]
        profiles[profile] = {
            "argv": argv,
            "environment": record["environment"],
            "duration_ms": record["duration_ms"],
            "record_sha256": v.digest(files[prefix + "record.json"]),
            "packages": {},
        }
        for component, (owner, counts) in expected.items():
            if owner != profile:
                continue
            if set(packages[component]) != set(counts):
                v.reject("qualification-go-package-scope", component)
            for package, count in counts.items():
                tests = packages[component][package]
                if not isinstance(tests, list) or len(tests) != count or tests != sorted(set(tests)):
                    v.reject("qualification-go-case-inventory", package)
                projected = b"".join(line + b"\n" for line, event in events if event.get("Package") == package)
                actual = {event["Test"] for _, event in events if event.get("Package") == package and event.get("Action") == "pass" and event.get("Test")}
                if actual != set(tests):
                    v.reject("qualification-go-case-terminals", package)
                statements.terminals(projected, {package: {"tests": count}})
                profiles[profile]["packages"][package] = {
                    "component": component,
                    "cases": count,
                    "tests": tests,
                }
    return {
        "facet": "race",
        "components": sorted(expected),
        "binding": go_binding(root, inputs["files"]),
        "compiler": "1.27.2",
        "profiles": profiles,
        "boundary": "Original GOMAXPROCS=2, 300-second Linux Race package selections only. Examples without tests and the separately built three-Star system scenario are not unit-test or Windows Race credit. Complete ownership, fault, mutation and protected provenance remain independent.",
    }


def go_mutations(root: Path, files: dict[str, bytes], seal: dict) -> dict:
    """Reconstruct a fixed SDK negative set and preserve its source and finite Linux scope."""
    inventory = {name: {"bytes": len(data), "sha256": v.digest(data)} for name, data in files.items()}
    if inventory != seal["files"]:
        v.reject("qualification-go-mutation-archive")
    inputs = v.decode(files["inputs.json"])
    source = entry.unpack(files["source.tar.gz"])
    original = {row["path"]: row["sha256"] for row in inputs["source"]["files"] if row["sha256"] is not None}
    if v.digest(files["source.tar.gz"]) != inputs["source_archive_sha256"] or {name: v.digest(data) for name, data in source.items()} != original:
        v.reject("qualification-go-mutation-source")
    module = {
        name.removeprefix("comet/go/"): checksum
        for name, checksum in original.items()
        if name.startswith("comet/go/") and (PurePosixPath(name).suffix == ".go" or PurePosixPath(name).name in {"go.mod", "go.sum"})
    }
    if module != inputs["module"]:
        v.reject("qualification-go-mutation-module")
    result = negatives.reconcile(files, inputs, seal)
    return {
        "facet": "targeted-mutations",
        "components": ["comet-go"],
        "binding": go_binding(root, original),
        "mutants": result["fixed_mutants"],
        "baselines": 1,
        "ordinary_tests": result["ordinary_tests"],
        "ordinary_completions": result["ordinary_completions"],
        "named_assertion_failures": result["named_assertion_failures"],
        "native_commands": result["native_commands"],
        "native_identities_retired": result["native_identities_retired"],
        "native_package_count": result["native_package_count"],
        "native_package_source_files": len(result["native_package_source_files"]),
        "installed_go_files": result["installed_go_files"],
        "memory_peak_bytes": result["memory_peak_bytes"],
        "cache_returned": result["cache_returned"],
        "outcomes": result["observations"],
        "boundary": "Only the 34 fixed Linux semantic negatives and their complete 98/248 ordinary baseline. No whole-component mutation denominator, MC/DC, fault-domain, Windows, protected custody or release qualification follows.",
    }


def windows_mutations(root: Path, files: dict[str, bytes], seal: dict, source_raw: bytes, installed_raw: bytes) -> dict:
    """Bind the original Windows native campaign and its fixed supplemental identities without any host recapture."""
    inventory = v.decode(files["manifest.json"])
    if {name: {"bytes": len(raw), "sha256": v.digest(raw)} for name, raw in files.items() if name != "manifest.json"} != inventory:
        v.reject("qualification-windows-mutation-archive")
    prefix = "go-upgrade-comet-mutations-windows-current-1/"
    inputs = v.decode(files[prefix + "inputs.json"])
    if (
        len(files) != seal["archive_regular_members"]
        or v.digest(files[prefix + "received.json"]) != seal["mutation_received_sha256"]
        or v.digest(files[prefix + "package-closure/received.json"]) != seal["package_closure_received_sha256"]
        or v.digest(source_raw) != inputs["main_source_archive_sha256"]
        or v.digest(installed_raw) != inputs["install_receipt_sha256"]
    ):
        v.reject("qualification-windows-mutation-inputs")
    source = entry.unpack(source_raw)
    original = {row["path"]: row["sha256"] for row in inputs["source"]["files"] if row["sha256"] is not None}
    module = {name.removeprefix(prefix + "module/"): v.digest(raw) for name, raw in files.items() if name.startswith(prefix + "module/")}
    if (
        {name: v.digest(raw) for name, raw in source.items()} != original
        or module != inputs["module"]
        or {"comet/go/" + name: checksum for name, checksum in module.items()}
        != {
            name: sha
            for name, sha in original.items()
            if name.startswith("comet/go/") and (PurePosixPath(name).suffix == ".go" or PurePosixPath(name).name in {"go.mod", "go.sum"})
        }
        or v.digest(files[prefix + "tested-module.tar.gz"]) != inputs["module_archive_sha256"]
    ):
        v.reject("qualification-windows-mutation-source")
    result = negatives.windows(files, v.decode(installed_raw), seal)
    return {
        "facet": "targeted-mutations",
        "components": ["comet-go"],
        "binding": go_binding(root, original),
        "mutants": result["fixed_mutants"],
        "ordinary_tests": result["ordinary_tests"],
        "ordinary_completions": result["ordinary_completions"],
        "named_assertion_failures": result["named_assertion_failures"],
        "native_commands": result["native_commands"],
        "native_identities_retired": result["native_identities_retired"],
        "native_package_count": result["native_package_count"],
        "native_package_source_files": result["native_package_source_files"],
        "installed_go_files": result["installed_go_files"],
        "native_limits": result["native_limits"],
        "packaged_retired_identities": result["packaged_retired_identities"],
        "outcomes": result["observations"],
        "boundary": "Only the 34 original Windows semantic negatives and their complete 98/248 ordinary baseline, under original local Job limits. The 1,598-file package closure binds recorded source identities; no current installation/host recapture, full mutation domain, MC/DC, Race, resource qualification or protected release is inferred. Original fuzz and failed preparation/reader attempts stay archived without additional credit.",
    }


def windows_residence(root: Path, files: dict[str, bytes], seal: dict, producer_inputs: bytes, producer_receipt: bytes) -> dict:
    """Reconcile the already received cross-host interval and native Windows resource samples without host queries."""

    def require(condition: bool, reason: str) -> None:
        """Reject a named original evidence boundary without accepting incidental parser errors."""
        if not condition:
            v.reject("qualification-windows-residence", reason)

    def read(name: str) -> dict:
        """Read only the caller's authenticated original material."""
        return v.decode(files[name])

    manifest = read("manifest.json")
    inventory = {name: {"bytes": len(raw), "sha256": v.digest(raw)} for name, raw in files.items() if name != "manifest.json"}
    require(
        manifest["version"] == 1 and inventory == manifest["files"] == seal["files"] and v.digest(files["manifest.json"]) == seal["manifest_sha256"],
        "archive members",
    )
    require(
        manifest["new_product_data_collected"]
        == manifest["native_application_commands"]
        == seal["native_application_commands"]
        == seal["new_product_data_collected"]
        == 0,
        "static collection boundary",
    )
    native = unpack(files["linux/evidence.tar.gz"])
    native_seal, received, prepared, plan = (read(name) for name in ("linux/sealed.native.json", "received.json", "preparation.json", "plan.json"))
    require(
        v.digest(files["linux/evidence.tar.gz"]) == native_seal["sha256"] == received["native_archive_sha256"] and len(native) == native_seal["files"],
        "native archive identity",
    )
    require(
        {name: {"bytes": len(raw), "sha256": v.digest(raw)} for name, raw in native.items() if name != "manifest.json"}
        == v.decode(native["manifest.json"])["files"],
        "native archive members",
    )
    inputs, terminal, cleanup, owner = (v.decode(native[name]) for name in ("inputs.json", "terminal.json", "cleanup.native.json", "controller.json"))
    require(
        terminal == native_seal["terminal"]
        and cleanup == native_seal["cleanup"]
        and not terminal["errors"]
        and not terminal["resource_errors"]
        and not terminal["interrupted"]
        and not terminal["remaining_owned"]
        and terminal["source_unchanged"]
        and terminal["products_unchanged"]
        and terminal["fixture_removed"],
        "native producer completion",
    )
    require(
        owner["script_sha256"] == inputs["run_sha256"] == v.digest(native["run.py"]) and owner["inputs_sha256"] == v.digest(native["inputs.json"]),
        "native producer inputs",
    )
    require(
        cleanup["original_exit_code"] == 0
        and cleanup["unit"]["MainPID"] == "0"
        and not cleanup["unit"]["ControlGroup"]
        and cleanup["boot_id"] == owner["boot_id"] == inputs["boot_id"],
        "native producer retirement",
    )
    collector = read("linux/collector-retirement.native.json")
    require(
        collector["retired"]
        and collector["state"]["MainPID"] == "0"
        and not collector["state"]["ControlGroup"]
        and collector["owner"] == v.decode(native["collector.process.json"]),
        "native collector retirement",
    )
    require(inputs["plan"] == plan and v.digest(files["plan.json"]) == inputs["plan_sha256"] == prepared["plan_sha256"], "original plan identity")
    require(
        plan["seconds"] == 7200
        and plan["observation_windows"] == [[0, 1200], [1200, 2700], [2700, 4200], [4200, 5700], [5700, 7200]]
        and plan["warmup"] == 1
        and plan["maximum_gap"] == 15
        and plan["minimum_samples"] == 230
        and plan["minimum_measured_samples"] == 280
        and plan["aggregate_memory_bytes"] == plan["windows"]["memory_bytes"] + plan["linux"]["memory_bytes"] == 2 * 1024**3
        and plan["topology"] == {"local_writers": 3, "records_per_domain": 48, "stars": 3, "tls": True, "value_bytes": 2048, "workers": 96},
        "original resource and topology policy",
    )
    original = entry.unpack(native["source.tar.gz"])
    hashes = {name: v.digest(raw) for name, raw in original.items()}
    require(
        v.digest(native["source.tar.gz"]) == inputs["main_source_archive_sha256"] and hashes == inputs["main_files"] == prepared["files"],
        "original source bytes",
    )
    require(
        inputs["source"] == prepared["source"]
        and set(inputs["files"]) == set(hashes)
        and inputs["source_changes"]
        == {name: {"native": inputs["files"][name], "current": checksum} for name, checksum in hashes.items() if inputs["files"][name] != checksum}
        and set(inputs["source_changes"]) <= {"docs/validation.md"},
        "original source association",
    )
    require(
        prepared["sdk_sources"]
        == {name: checksum for name, checksum in hashes.items() if name.startswith("comet/go/") and name.endswith((".go", "go.mod", "go.sum"))},
        "original SDK source inventory",
    )
    records = {}
    for folder, identifier in (("commands/relay-controls", "native-relay-controls"), ("commands", "windows-fault-cluster")):
        record, request, process = (v.decode(native[folder + "/" + name]) for name in ("record.json", "request.json", identifier + ".process.json"))
        require(
            record["id"] == identifier
            and record["argv"] == request["argv"] == process["argv"]
            and process["identity"] in cleanup["retired"]
            and record["platform"] == "linux-amd64"
            and record["exit_code"] == 0
            and record["complete"]
            and record["cleanup"]
            and record["termination"] == "exited",
            "native command completion",
        )
        require({key: record[key] for key in terminal["completed"][identifier]} == terminal["completed"][identifier], "native command terminal identity")
        for channel in ("stdout", "stderr"):
            item = record[channel]
            path = PurePosixPath(item["path"])
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in item["path"] and path.as_posix() == item["path"], "native stream path")
            raw = native[folder + "/" + item["path"]]
            require(len(raw) == item["bytes"] and v.digest(raw) == item["sha256"], "native stream integrity")
        records[identifier] = record
    require(set(terminal["completed"]) == set(records), "native command denominator")
    cluster = records["windows-fault-cluster"]
    require(cluster["argv"][cluster["argv"].index("--steady-seconds") + 1] == "7200" and cluster["duration_ms"] >= 7200000, "native interval")
    relay = v.decode(native["relay.terminal.json"])
    sdk, record, completed, end = (read("runtime/" + name) for name in ("sdk.process.json", "record.json", "windows.completed.json", "terminal.json"))
    binary = prepared["windows_product"]
    compiled = read("windows-compiled.json")
    compiler_inputs, compiler_received = v.decode(producer_inputs), v.decode(producer_receipt)
    require(
        binary["metadata"].splitlines()[0].endswith(": go1.27.2")
        and "golang.org/x/net\tv0.60.0\t" in binary["metadata"]
        and compiled["binary_sha256"] == binary["sha256"]
        and v.digest(producer_inputs) == prepared["windows_producer_inputs_sha256"] == compiler_received["inputs_sha256"]
        and v.digest(producer_receipt) == compiled["producer_receipt_sha256"] == prepared["windows_producer_receipt_sha256"]
        and compiled["source_archive_sha256"] == compiler_inputs["source_archive_sha256"]
        and compiler_inputs["source"] == compiler_received["source"]
        and compiler_received["selections"]["sdk-ordinary"]["products"]["comet-go-system-ordinary"] == binary
        and {name: sha for name, sha in compiler_inputs["files"].items() if name in prepared["sdk_sources"]} == prepared["sdk_sources"],
        "Windows original compiler binding",
    )
    require(
        v.digest(files["windows-build/comet-go-system.exe"]) == binary["sha256"] == sdk["executable_sha256"] == received["sdk_binary_sha256"]
        and len(files["windows-build/comet-go-system.exe"]) == binary["bytes"],
        "Windows original image identity",
    )
    require(
        PureWindowsPath(sdk["argv"][0]).name == "comet-go-system.exe"
        and sdk["argv"] == record["argv"]
        and record["argv"][1:] == ["-test.v", "-test.run=^TestSystemThreeStars$", "-test.timeout=7680s", "-test.count=1"],
        "Windows original selection",
    )
    require(
        record["exit_code"] == 0
        and record["complete"]
        and record["cleanup"]
        and record["termination"] == "exited"
        and not end["errors"]
        and not end["cancelled"]
        and end["source_unchanged"]
        and end["binary_unchanged"]
        and end["secret_removed"],
        "Windows command completion",
    )
    require(
        completed == v.decode(native["windows.completed.json"]) == relay["windows_terminal"]
        and completed["record_sha256"] == v.digest(files["runtime/record.json"])
        and not relay["errors"],
        "Windows cross-host completion",
    )
    transfers = read("runtime/transfers.json")
    require(transfers["complete"], "Windows stream transfer completion")
    for channel in ("stdout", "stderr"):
        parts = [row for row in transfers["chunks"] if row["name"].startswith(channel + "-")]
        raw = bytearray()
        require(len(parts) == completed["counts"][channel], "Windows stream chunk denominator")
        for number, part in enumerate(parts):
            data = native["mailbox/" + part["name"]]
            require(
                part["name"] == f"{channel}-{number:06d}.bin"
                and part["offset"] == len(raw)
                and part["bytes"] == len(data)
                and 0 < len(data) <= 65536
                and part["sha256"] == v.digest(data),
                "Windows stream chunk identity",
            )
            raw.extend(data)
        require(
            bytes(raw) == files["runtime/" + channel + ".log"]
            and record[channel + "_sha256"] == v.digest(raw)
            and completed["streams"][channel] == relay["streams"][channel] == {"bytes": len(raw), "sha256": v.digest(raw)},
            "Windows stream identity",
        )
    output = files["runtime/stdout.log"]
    require(
        not files["runtime/stderr.log"]
        and output.startswith(b"=== RUN   TestSystemThreeStars\n")
        and output.endswith(b"\nPASS\n")
        and output.count(b"--- PASS: TestSystemThreeStars (") == 1
        and b"SKIP" not in output
        and b"FAIL" not in output,
        "Windows native successful terminal",
    )
    phases = []
    for line in output.splitlines():
        if line.startswith(b"{"):
            row = v.decode(line)
            if row["event"].startswith(("go_authority_", "go_mesh_")) or row["event"] in {"mesh_steady", "mesh_replicated"}:
                phases.append(row)
    require(
        [(row["event"], row["cycle"], row["star"]) for row in phases if row["event"].startswith("go_mesh_")]
        == [("go_mesh_" + stage, number, number) for number in range(3) for stage in ("ready", "failover", "recovered")],
        "Windows original three-source phases",
    )
    require(
        [row for row in phases if row["event"] == "mesh_steady"] == [{"event": "mesh_steady", "cycles": 3, "seconds": 7200, "records": 48, "workers": 96}],
        "Windows original workload",
    )
    replicated = [row for row in phases if row["event"] == "mesh_replicated"]
    require(
        len(replicated) == 1 and replicated[0]["records"] == 48 and replicated[0]["rounds"] == received["rounds"] >= 2, "Windows complete replication terminal"
    )
    cohort, policy, result = (read("runtime/resource." + name + ".json") for name in ("cohort", "policy", "result"))
    require(
        cohort["identity"] == sdk["identity"]
        and cohort["native_fd_metric"] == "handles"
        and cohort["owner"]["pid"] == sdk["identity"]["pid"]
        and cohort["owner"]["started"] == sdk["identity"]["creation_time"]
        and cohort["steady"]["sdk_pid"] == sdk["identity"]["pid"]
        and cohort["steady"]["seconds"] == 7200,
        "Windows resource owner identity",
    )
    require(
        policy == {"warmup": 1, "processes": [{**cohort["owner"], **plan["limits"]["sdk"]}]} and cohort["policy_sha256"] == v.digest(v.encode(policy)),
        "Windows original resource policy",
    )
    require(result["seconds"] == 7200 and result["complete"] and not result["errors"] and not result["long_qualified"], "Windows resource completion")
    assessed = delivery.bounds(
        files["runtime/resource.events.jsonl"],
        policy=policy,
        seconds=7200,
        windows=plan["observation_windows"],
        owners=[cohort["owner"]],
        maximum_gap=15,
        minimum_samples=230,
    )
    require(
        assessed == read("runtime/resource.bounds.json") == received["assessments"]["windows"]
        and assessed["status"] == "passed"
        and not assessed["violations"]
        and result["bounds_sha256"] == v.digest(files["runtime/resource.bounds.json"])
        and result["samples"] == assessed["residence"]["steady_samples"]
        and all(window["samples"] >= 280 for window in assessed["residence"]["windows"][1:]),
        "Windows complete finite bounds",
    )
    budget_inputs, budget_end, job, budget_record = (
        read(name)
        for name in (
            "bounded-runtime/inputs.json",
            "bounded-runtime/terminal.json",
            "bounded-runtime/controller/job.native.json",
            "bounded-runtime/controller/record.json",
        )
    )
    require(
        budget_inputs["source"] == prepared["source"]
        and budget_inputs["runner_sha256"] == v.digest(files["bounded.py"]) == inputs["windows_budget_runner_sha256"]
        and budget_inputs["runtime_sha256"] == v.digest(files["runtime.py"]) == inputs["windows_runtime_sha256"],
        "Windows original budget source",
    )
    require(
        budget_inputs["budget"]
        == {
            "memory_bytes": plan["windows"]["memory_bytes"],
            "processes": plan["windows"]["processes"],
            "cpu_rate": max(1, min(10000, 40000 // budget_inputs["cpus"])),
        }
        and job
        == {
            "flags": 0x2208,
            "processes": plan["windows"]["processes"],
            "memory_bytes": plan["windows"]["memory_bytes"],
            "cpu_flags": 5,
            "cpu_rate": budget_inputs["budget"]["cpu_rate"],
        },
        "Windows original ancestor limits",
    )
    require(
        budget_end["completed"] == ["controller"]
        and budget_end["source_unchanged"]
        and not budget_end["cancelled"]
        and budget_record["exit_code"] == 0
        and budget_record["complete"]
        and budget_record["cleanup"]
        and budget_record["termination"] == "exited",
        "Windows original ancestor completion",
    )
    identities = [sdk["identity"], read("runtime/controller.json")["identity"], read("bounded-runtime/controller/process.json")["identity"]]
    for number in range(3):
        process, end = (read(f"runtime/forward-{number}/{name}.json") for name in ("process", "terminal"))
        require(
            end["exit_code"] == 0 and end["active"] == 0 and process["helper_sha256"] == read("windows-inputs.json")["forward_helper_sha256"],
            "Windows recorded forwarding cleanup",
        )
        identities.append(process["identity"])
    require(
        len({(row["pid"], row["creation_time"]) for row in identities}) == 6 and identities == received["windows_retired"],
        "Windows recorded retirement identities",
    )
    counters = terminal["resources"]
    require(
        v.decode(native["resources.native.json"])["limits"]
        == {"memory.max": str(plan["linux"]["memory_bytes"]), "memory.swap.max": "0", "cpu.max": "400000 100000", "pids.max": "512"}
        and int(counters["memory.peak"]) <= plan["linux"]["memory_bytes"]
        and counters["memory.high"] == str(plan["linux"]["memory_high_bytes"])
        and all(int(row.split()[1]) == 0 for row in counters["memory.events"].splitlines() if row.split()[0] in {"high", "max", "oom", "oom_kill"}),
        "original Linux peer resource prerequisites",
    )
    clocks = [v.decode(line) for line in native["clock.native.jsonl"].splitlines()]
    require(
        len(clocks) >= cluster["duration_ms"] // 1000 - 2
        and all(
            row["modes"] == row["return"] == 0
            and not row["fields"]["status"] & (64 | 4096)
            and max(row["fields"]["maxerror"], row["fields"]["esterror"]) * 1000
            + abs(row["fields"]["offset"]) * (1 if row["fields"]["status"] & 8192 else 1000)
            + row["window_ns"]
            < 500000000
            for row in clocks
        ),
        "original peer kernel clock prerequisites",
    )
    runtime, go = source_binding(root, hashes, build=True), go_binding(root, hashes)
    changed = sorted(set(runtime["changed"]) | set(go["changed"]))
    return {
        "facet": "finite-resources",
        "components": ["comet-go"],
        "binding": {"status": "source-review-required" if changed else "current", "changed": changed, "runtime": runtime, "go": go},
        "seconds": 7200,
        "native_sdk_identity": sdk["identity"],
        "native_sdk_binary_sha256": binary["sha256"],
        "native_fd_metric": "handles",
        "samples": assessed["residence"]["steady_samples"],
        "windows": [row["samples"] for row in assessed["residence"]["windows"]],
        "bounds": assessed,
        "windows_job": job,
        "aggregate_memory_bytes": plan["aggregate_memory_bytes"],
        "clock_samples": len(clocks),
        "retirement_basis": "Original complete command/ancestor/forwarding cleanup and six identities recorded by the earlier local receiver; no current OS process query.",
        "boundary": "Original finite 7200-second Windows SDK RSS, native handle and thread maxima/rise under the recorded three-source workload and cross-host limits. Repackaged raw bytes add no product observation. No Windows Race/suspension, throughput/tail, whole capacity/operation, indefinite leak freedom, protected custody or release qualification follows.",
    }


def performance(root: Path, files: dict[str, bytes], seal: dict) -> dict:
    """Recompute all physical samples and the unchanged paired/capacity gates, without selecting successful subsets."""
    inputs = v.decode(files["campaign-inputs.json"])
    rows, resources = pairedproof.reconcile(files, inputs, seal)
    reports = [compare.evaluate(inputs["policy"], item) for item in rows]
    if len(reports) != 4 or any(not item["regression"]["passed"] or not item["capacity"]["passed"] for item in reports):
        v.reject("qualification-performance-gates")
    return {
        "facet": "performance",
        "components": ["star", "comet"],
        "binding": source_binding(root, inputs["files"], build=True),
        "client_api": "comet-cpp",
        "physical_executions": 512,
        "formal_executions": 384,
        "warmup_executions": 128,
        "cases": [
            {
                "case": item["case"],
                "capacity": item["capacity"],
                "regression": item["regression"],
            }
            for item in reports
        ],
        "root_peak_bytes": resources["root_cgroup_peak_bytes"],
        "boundary": "Four original fixed three-Star workload gates through the public C++ SDK, under their declared statistical assumptions. SDK-version-isolated regression, complete capacity domains, Windows performance and protected release remain independent.",
    }


def storage_race(root: Path, files: dict[str, bytes]) -> dict:
    """Use the maintained complete current Storage ordinary/Race reader unchanged."""
    result = storagecompiler.race_profiles(root, files)
    return {
        "facet": "race",
        "components": ["polaris-storage"],
        "binding": {"status": "current", "changed": []},
        "compiler": "1.27.2",
        "cases": result["current_cases"],
        "profiles": result["profiles"],
        "boundary": "Exactly the current 259-case ordinary/Race package selection; no C++ TSan or whole-component fault/mutation credit.",
    }


def admission_race(root: Path, files: dict[str, bytes]) -> dict:
    """Project the unchanged Admission package from the retained complete current root Race run."""
    prefix = "source/build/commands/root-race-test/"
    record, stdout, stderr = streams(files, prefix)
    if "-race" not in record["argv"] or "-timeout=300s" not in record["argv"] or "DATA RACE" in stderr.decode(errors="replace"):
        v.reject("qualification-admission-race-command")
    cfg = v.decode(v.read(root / "development.json"))
    check = next(item for item in cfg["checks"] if item["id"] == "admission-model")
    events = [(line, v.decode(line)) for line in stdout.splitlines()]
    package = "github.com/eosforge/astra/internal/admission"
    projected = b"".join(line + b"\n" for line, row in events if row.get("Package") == package)
    structure.terminals(projected, check["expected_tests"])
    if len(check["expected_tests"]) != 47:
        v.reject("qualification-admission-race-tests")
    inputs = v.decode(files["inputs.json"])
    source = entry.unpack(files["source.tar.gz"])
    names = {path.relative_to(root).as_posix() for directory in ("internal/admission", "internal/generated") for path in (root / directory).rglob("*.go")}
    names |= {"go.mod", "go.sum", "dependencies.lock.json"}
    changes = sorted(name for name in names if name not in source or v.digest(source[name]) != v.file_digest(root / name))
    return {
        "facet": "race",
        "components": ["admission"],
        "binding": {
            "status": "source-review-required" if changes else "current",
            "changed": changes,
        },
        "cases": 47,
        "compiler": "1.27.2",
        "record_sha256": v.digest(files[prefix + "record.json"]),
        "boundary": "47 complete current package terminals projected from the root Race selection; no skipped system scenario is credited.",
    }


def mutations(root: Path, files: dict[str, bytes], *, expected: int = 4) -> dict:
    """Require complete baselines, exact compiled replacements and named failures for a fixed Star selection."""
    inputs = v.decode(files["inputs.json"])
    declared = v.decode(files["mutation/inputs.json"])
    manifest = declared["manifest"]
    if inputs["manifest"] != manifest:
        v.reject("qualification-mutation-scope")
    original = entry.unpack(files["original-source.tar.gz"])
    if {name: v.digest(data) for name, data in original.items()} != inputs["original_files"]:
        v.reject("qualification-mutation-source")
    temporary = root / "build/tmp"
    temporary.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="qualification-oracles-", dir=temporary) as directory:
        shadow = Path(directory)
        for item in manifest["mutations"]:
            for field in ("file", "oracle"):
                name = item[field]
                target = v.inside(shadow, name)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(original[name])
        planned = mutate.cpp_plan(manifest, shadow)
    if len(planned) != expected:
        v.reject("qualification-mutation-scope")
    terminal = v.decode(files["terminal.json"])
    if terminal["errors"] or terminal["interrupted"] or terminal["remaining_owned"]:
        v.reject("qualification-mutation-terminal")
    groups, outcomes = {}, []
    for item in planned:

        class Oracle:
            """Bind the original compiler path to its authenticated original oracle bytes."""

            def __str__(self) -> str:
                """Expose the oracle path using the recorded build root."""
                return inputs["root"] + "/" + item["oracle"]

            def read_text(self, *, encoding: str) -> str:
                """Decode the authenticated original oracle bytes with the requested encoding."""
                return original[item["oracle"]].decode(encoding)

        group = (item["file"], item["test"], item["oracle"])
        baseline = "baseline-" + item["id"]
        for name, plain in ((baseline, True), (item["id"], False)):
            if plain and group in groups:
                continue
            prefix = "mutation/" + name + "/"
            replacement = original[item["file"]] if plain else item["replacement"].encode()
            if files[prefix + "source.cpp"] != replacement:
                v.reject("qualification-mutation-replacement", name)
            recipe = v.decode(files[prefix + "recipe.json"])
            if recipe["production"] != item["source_sha256"] or recipe["oracle"] != item["oracle_sha256"]:
                v.reject("qualification-mutation-recipe", name)
            for step in ("compile", "link"):
                command, _, _ = streams(files, prefix + step + "/")
                if command["argv"] != recipe[step]:
                    v.reject("qualification-mutation-command", name)
                artifact = v.decode(files[prefix + step + "-artifact.json"])
                target = "source.o" if step == "compile" else "program"
                data = files[prefix + target]
                if artifact != {
                    "path": target,
                    "bytes": len(data),
                    "sha256": v.digest(data),
                }:
                    v.reject("qualification-mutation-artifact", name)
            record, stdout, stderr = streams(files, prefix + "test/", expected_exit=0 if plain else 1)
            state = mutate.cpp_outcome(record, stdout, stderr, Oracle(), baseline=plain)
            if state != ("passed" if plain else "killed"):
                v.reject("qualification-mutation-outcome", name)
            outcome = v.decode(files[prefix + "outcome.json"])
            if outcome != {
                "id": name,
                "status": state,
                "recipe_sha256": v.digest(files[prefix + "recipe.json"]),
            }:
                v.reject("qualification-mutation-summary", name)
            if plain:
                groups[group] = name
            outcomes.append({"id": name, "status": state})
    return {
        "facet": "targeted-mutations",
        "components": ["star"],
        "binding": source_binding(root, inputs["original_files"], cpp=True),
        "mutants": len(planned),
        "baselines": len(groups),
        "outcomes": outcomes,
        "boundary": manifest["scope"],
    }
