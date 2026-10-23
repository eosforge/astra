"""Bind Admission impact to complete native module graphs, unchanged consumers and actual shipping recovery."""

from pathlib import Path, PurePosixPath
import re

from tools import astrolabe, consumers, delivery, entry, impact, installation, repair, statements, verify as v

TARGET = "internal/admission"
MAINS = ("polaris", "astrolabe")
AFFECTED = sorted([TARGET, "polaris", "polaris/internal/server", *astrolabe.PACKAGES])
BASE = "reuse-plan/admission-impact-consumers-current-1/native/"
ARCHIVE = "c2da2d1cb0baaec8dcfc2ae91ebb8e642ccdd430bb3301de630d55efd7744a0b"
NATIVE = {
    "astrolabe": (59, 8, "f517abdb6a72f3490e5461a8c856b7f32f23344ef5785430ebab4dd7302ef67c"),
    "astrolabe/internal/bridge": (97, 23, "7d09c0f2a1b45e5c97a932662100b362111dfd20a99d8296b2a6449d4a71525e"),
    "astrolabe/internal/web": (276, 43, "faf9a2c1e0ef4422991ce7f8711de01ec7653795d344a76b364de80c2cdb8843"),
}
ARTIFACTS = {
    **impact.ARTIFACTS,
    **{f"reuse-plan/storage-delivery-current-{number}/native/evidence.tar.gz": sha for number, sha in delivery.CURRENT.items()},
    "reuse-plan/" + installation.NAME: installation.ARCHIVE,
    BASE + "evidence.tar.gz": ARCHIVE,
}
PREREQUISITES = [
    {"rule": "DEV-CORE", "contract": "ADMISSION-ASSURANCE", "scenario": "full-rule"},
    {"rule": "DEV-MATRIX", "contract": "ADMISSION-ASSURANCE", "scenario": "delivery-matrix"},
    {"rule": "DEV-REDGREEN", "contract": "ADMISSION-ASSURANCE", "scenario": "full-rule"},
]
TESTS = [
    "tests.test_reach.ReachTests." + name for name in ("test_current", "test_archive", "test_native", "test_graph", "test_delta", "test_sources", "test_policy")
]


def graphs(before: bytes, after: bytes) -> dict:
    """Reject missing/transitively changed consumers using both complete native module listings."""
    old = delivery.consumers(before, TARGET, MAINS)
    new = delivery.consumers(after, TARGET, MAINS)

    def imports(data: bytes) -> dict[str, list[str]]:
        """Read module-local import edges from the recorded Go package stream."""
        return {
            row["ImportPath"].removeprefix(astrolabe.MODULE): sorted(
                name.removeprefix(astrolabe.MODULE) for name in row.get("Imports", []) if name.startswith(astrolabe.MODULE)
            )
            for row in statements.stream(data)
        }

    left, right = imports(before), imports(after)
    affected = {TARGET}
    while True:
        expanded = affected | {name for name, children in right.items() if affected.intersection(children)}
        if expanded == affected:
            break
        affected = expanded
    if old != new or left != right or sorted(affected) != AFFECTED or old["packages"] != 14:
        v.reject("reach-consumer-graph")
    if "polaris/internal/server" in new["consumers"]["astrolabe"]:
        v.reject("reach-foreign-consumer")
    return {"affected": AFFECTED, "imports": right, "consumers": new["consumers"], "before_sha256": v.digest(before), "after_sha256": v.digest(after)}


def sources(root: Path, before: dict[str, str], after: dict[str, str], native: dict[str, str], graph: dict) -> dict[str, str]:
    """Bind all module Go inputs and protocol/test data; permit only the already-reviewed Server repair."""
    current = {row["path"]: row["sha256"] for row in v.source(root)["files"] if row["sha256"] is not None}
    go = lambda files: {name for name in files if name.endswith(".go")}
    upgraded = consumers.acquisition(root) == consumers.ACQUISITION
    historical_before, historical_after = go(before), go(after)
    extension = historical_after - historical_before
    permitted = {"polaris/internal/storage/" + name for name in ("compatibility_test.go", "maintenance.go", "maintenance_test.go")}
    if upgraded and extension == permitted and not historical_before - historical_after:
        pairs = {
            "polaris/internal/storage/store.go": (
                "7c914530e29059161f9665f867c1ce7f114cdec5c0be7bad43fdcbba3dfd0f16",
                "1b6854d0ebf89d2d2ba16cc282794b5e3486aee542eeb54e1fe1a496eda87279",
            ),
            "polaris/internal/storage/storage_test.go": (
                "62d9c0a4aa7d82bc9a8d93353e62d773d27aa16bfda722437157f4714c090ef2",
                "94396613748dc1846f66f6755eb562b313fb62b8c4ea28f7402461851291f3c2",
            ),
        }
        added = {
            "polaris/internal/storage/compatibility_test.go": "57b1b9dbb3fb51332b0c807f7408dcad93181913833d3ea6d6734d20b835b09f",
            "polaris/internal/storage/maintenance.go": "6db7bce0a96825f996cc3d50f3b5a12c7b205b51266b21987642ea319fcf3314",
            "polaris/internal/storage/maintenance_test.go": "219006b05a23f979a0afa6528f9544e5dbc03858e2c6493fc3042f30b72f1bd1",
        }
        if any((before[name], after[name]) != pair for name, pair in pairs.items()) or any(after[name] != sha for name, sha in added.items()):
            v.reject("reach-historical-extension")
        for name in historical_before:
            if name.startswith("astrolabe/") and before[name] != after[name]:
                v.reject("reach-historical-extension", name)
    elif historical_before != historical_after:
        v.reject("reach-go-inventory")
    if not upgraded and go(current) != historical_after:
        v.reject("reach-go-inventory")
    changes = {name for name in historical_before & historical_after if before[name] != after[name]}
    if (changes - {"polaris/internal/storage/store.go", "polaris/internal/storage/storage_test.go"} if extension else changes) != {installation.PATH} or (
        before[installation.PATH],
        after[installation.PATH],
    ) != (installation.ORIGINAL, installation.SOURCE):
        v.reject("reach-production-delta")
    directories = {PurePosixPath(name).parent.as_posix() for name in go(after)}
    if directories != graph["imports"].keys():
        v.reject("reach-unmapped-package")
    boundary = lambda files: {
        name
        for name in files
        if name.startswith("proto/")
        or name in {"go.mod", "go.sum", "dependencies.lock.json", "tools/generate.py", "tests/fixtures/admission-v1.json"}
        or any(name.startswith("tests/fixtures/" + folder + "/") for folder in ("star-a", "star-b", "expired", "pulsar"))
    }
    required = boundary(after)
    if not {"go.mod", "go.sum", "dependencies.lock.json", "tools/generate.py", "tests/fixtures/admission-v1.json"} <= required:
        v.reject("reach-empty-boundary")
    if boundary(before) != required or not upgraded and boundary(current) != required or any(before[name] != after[name] for name in required):
        v.reject("reach-boundary-inventory")
    names = go(after) | required
    if not upgraded and any(current.get(name) != after[name] for name in names):
        v.reject("reach-current-source")
    selected = set(graph["consumers"]["astrolabe"])
    owned = {name for name in go(after) if PurePosixPath(name).parent.as_posix() in selected} | required
    if any(native.get(name) != after[name] for name in owned):
        v.reject("reach-native-consumer-source")
    if upgraded:
        proof = impact.reconcile(root)
        linked = set(graph["imports"]) - {"tools/decisions"}
        _, review = consumers.rebinding(root, after, linked, reviewed=proof["sources"], extra=required)
        return review["bindings"]
    return {name: after[name] for name in sorted(names)}


def cases(stream: bytes, discovery: bytes) -> dict:
    """Require native full discovery and every current Race terminal, including nested cases and all three packages."""
    rows = [v.decode(row) for row in stream.splitlines()]
    listed = [v.decode(row) for row in discovery.splitlines()]
    packages = {astrolabe.MODULE + package for package in NATIVE}
    for frames in (rows, listed):
        if not frames or {row.get("Package") for row in frames} != packages or any(row.get("Action") in {"fail", "skip", "build-fail"} for row in frames):
            v.reject("reach-native-packages")
        if any(sum(row.get("Package") == package and row.get("Action") == "pass" and "Test" not in row for row in frames) != 1 for package in packages):
            v.reject("reach-native-package-terminal")
    result = {}
    for package, (count, parents, sha) in NATIVE.items():
        qualified = astrolabe.MODULE + package
        expected = sorted(row["Test"] for row in rows if row.get("Package") == qualified and row.get("Action") == "pass" and "Test" in row)
        if len(expected) != count or sum("/" not in name for name in expected) != parents or v.digest(v.encode(expected)) != sha:
            v.reject("reach-native-case-inventory", package)
        found = sorted(row["Output"].strip() for row in listed if row["Package"] == qualified and re.fullmatch(r"Test[A-Za-z0-9_]+\n", row.get("Output", "")))
        if not found or len(found) != len(set(found)) or found != sorted(name for name in expected if "/" not in name):
            v.reject("reach-native-discovery", package)
        astrolabe.terminals(stream, qualified, expected)
        result[package] = {"cases": count, "parents": parents, "tests_sha256": sha}
    return result


def acquisition(files: dict[str, bytes]) -> tuple[dict[str, str], dict]:
    """Authenticate native commands, offline tools, dirty inputs, cancellation draining and independent discovery."""
    records, outputs = {}, {}
    for name, flags in (("astrolabe-discovery", ["-list", "."]), ("astrolabe-race", [])):
        prefix = "source/build/commands/" + name + "/"
        source = repair.native(files, prefix)
        record, _ = repair.command(files, prefix, 0)
        argv = ["go", "test", "-json", "-race", *flags, "-count=1", "-parallel=1", "-p=2", "-timeout=180s", "./astrolabe/..."]
        if record["argv"] != argv:
            v.reject("reach-native-command", name)
        for key, value in {
            "GOOS": "linux",
            "GOARCH": "amd64",
            "CGO_ENABLED": "1",
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
            "GOFLAGS": "-mod=readonly",
            "GOMAXPROCS": "2",
        }.items():
            if record["resolved_environment"].get(key) != value:
                v.reject("reach-native-environment", key)
        for key, sha in {
            "CC": "5ba72afdc29ac57b805ee21e48babe16b31385c03caf91fdd4336483c5a84195",
            "CXX": "1d90c88f14873d7a56f015f31ebe1b72a24942fe379d63eac35d18c1d22970f1",
        }.items():
            if record["toolchain"][key]["sha256"] != sha:
                v.reject("reach-native-toolchain", key)
        records[name] = record
        outputs[name] = files[prefix + record["stdout"]["path"]]
    if len(v.decode(files["cleanup.native.json"])["retired"]) != 3:
        v.reject("reach-native-retirement")
    if v.stamp(records["astrolabe-discovery"]["finished_at"]) > v.stamp(records["astrolabe-race"]["started_at"]):
        v.reject("reach-native-command-order")
    return {name: v.digest(data) for name, data in source.items()}, {
        "archive_sha256": ARCHIVE,
        "records": {
            name: {"record_sha256": v.digest(v.encode(record)), "duration_ms": record["duration_ms"], "stdout_sha256": v.digest(outputs[name])}
            for name, record in records.items()
        },
        "packages": cases(outputs["astrolabe-race"], outputs["astrolabe-discovery"]),
    }


def consumer(root: Path) -> tuple[dict[str, str], dict]:
    """Reparse the fixed current Race archive; derived reports cannot substitute for original native facts."""
    raw = v.read(root / "build/results/assurance" / BASE / "evidence.tar.gz", entry.LIMIT)
    return acquisition(consumers.unpack(raw, ARCHIVE))


def reconcile(root: Path) -> dict:
    """Join authenticated compiler, full consumer regressions and installed recovery without rerunning products."""
    facts, inputs, packages, archives = delivery.compose(root)
    # Candidate payloads are no longer needed once their source and consumer graph have been authenticated.
    del facts
    raw = v.read(root / "build/results/assurance/reuse-plan/storage-delivery-current-5/native/evidence.tar.gz", entry.LIMIT)
    if v.digest(raw) != delivery.CURRENT[5]:
        v.reject("reach-before-integrity")
    original = entry.unpack(raw)
    plan = v.decode(original["inputs.json"])
    _, before = delivery.receipt(original, "source/build/commands/control-plane-delivery/consumer-graph/")
    graph = graphs(before, packages)
    del raw, original
    native, retained = consumer(root)
    bindings = sources(root, plan["files"], inputs["source"], native, graph)
    current = impact.reconcile(root)
    shipping = delivery.reconcile(root)
    upgraded = consumers.acquisition(root) == consumers.ACQUISITION
    if current["checks"]["server"]["cases"] != 300 or set(shipping["consumers"]) != set(MAINS):
        v.reject("reach-current-consumers")
    if not upgraded and shipping["archives"] != archives:
        v.reject("reach-current-consumers")
    if upgraded and (not shipping["source"] or any(bindings.get(name) != sha for name, sha in shipping["source"].items())):
        v.reject("reach-current-installed-source")
    current_profiles = None
    if consumers.acquisition(root) == consumers.ACQUISITION:
        name = "go-upgrade-contracts-current-3/native/evidence.tar.gz"
        raw = v.read(root / "build/results/assurance/reuse-plan" / name, 64 * 1024**2)
        if v.digest(raw) != repair.RENEWED[name]:
            v.reject("reach-current-profiles")
        native_files = consumers.unpack(v.read(root / "build/results/assurance" / BASE / "evidence.tar.gz", entry.LIMIT), ARCHIVE)
        prefix = "source/build/commands/astrolabe-race/"
        record = v.decode(native_files[prefix + "record.json"])
        events = [v.decode(line) for line in native_files[prefix + record["stdout"]["path"]].splitlines()]
        inventory = {
            astrolabe.MODULE
            + package: sorted(
                row["Test"] for row in events if row.get("Package") == astrolabe.MODULE + package and row.get("Action") == "pass" and "Test" in row
            )
            for package in NATIVE
        }
        current_profiles = repair.profiles(
            root, entry.unpack(raw), {name: sha for name, sha in bindings.items() if not name.endswith(".md")}, "", inventory=inventory
        )
    return {
        "trust": "local",
        "platform": "linux-amd64-cgo",
        "graph": graph,
        "source_inputs": bindings,
        "astrolabe_regression": retained,
        "current_profiles": current_profiles,
        "polaris_regressions": current["checks"],
        "delivery": shipping,
        "archives": archives,
        "current_delivery_archives": shipping["archives"],
        "changed_go": [installation.PATH],
        "boundary": "Current Admission impact and complete affected Linux/CGO consumers only. Fresh Astrolabe full discovery/Race binds its complete owned closure and fixtures. Admission core and both historical repairs remain mandatory separate prerequisites. No current Astrolabe structural, mutation, fault, protected CI, performance, residence or release qualification is inferred.",
    }


def policy(config: dict) -> None:
    """Require complete reader controls and current core, shipping and historical-repair prerequisites."""
    check = next(item for item in config["checks"] if item["id"] == "admission-gap-impact")
    if (
        check["adapter"] != "observed-cases"
        or check["component"] != "admission"
        or check["argv"] != ["python3", "-B", "tools/observe.py", "python", *TESTS]
        or check["expected_tests"] != TESTS
        or check["probes"] != [{"contract": "ADMISSION-ASSURANCE", "test": TESTS[0], "minimum_hits": 75}]
    ):
        v.reject("reach-policy-check")
    component = next(item for item in config["components"] if item["id"] == "admission")
    required = next(item for item in component["requirements"] if item["rule"] == "DEV-IMPACT" and item["scenario"] == "full-rule")
    if required["checks"] != ["admission-gap-impact"] or required.get("requires") != PREREQUISITES:
        v.reject("reach-policy-prerequisites")
