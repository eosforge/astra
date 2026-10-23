"""Bind Storage impact to exact before/after sources, compiler ownership and sealed consumer regressions."""

from pathlib import Path, PurePosixPath
import re

from tools import astrolabe, consumers as refreshed, entry, installation, server, statements, verify as v

BASE = "reuse-plan/storage-consumers-current-2/native/"
ARCHIVE = "af576e5c51ceee6520e77cfecef74526cf24edb7603b6ad9d55bc886b855a040"
ARTIFACTS = {
    BASE + "evidence.tar.gz": ARCHIVE,
    BASE + "sealed.native.json": "c53eb6821bb97a3c8c4388157876bb0b7d49f9d8f200ce0d8d40625539a3760b",
    "reuse-plan/material-2/evidence.tar.gz": astrolabe.BASELINE,
    "reuse-plan/entry-closure/evidence.tar.gz": entry.ARCHIVES["entry-closure"],
    **refreshed.ARTIFACTS,
}
MODULE = "github.com/eosforge/astra/"
STORAGE = "polaris/internal/storage"
TESTS = [
    "tests.test_impact.ImpactTests." + name
    for name in ("test_current", "test_archive", "test_native", "test_graph", "test_delta", "test_sources", "test_policy")
]
PREREQUISITES = [
    {"rule": "DEV-CORE", "contract": "STORAGE-ASSURANCE", "scenario": "full-rule"},
    {"rule": "DEV-MATRIX", "contract": "STORAGE-ASSURANCE", "scenario": "delivery-matrix"},
]


def retained(artifacts: dict[str, bytes]) -> tuple[dict[str, bytes], dict[str, bytes], dict[str, bytes], dict]:
    """Authenticate original immutable archives; synthesized receipts are never an input to qualification."""
    if set(artifacts) != set(ARTIFACTS) or any(v.digest(artifacts[name]) != digest for name, digest in ARTIFACTS.items()):
        v.reject("impact-archive-integrity")
    files = entry.unpack(artifacts[BASE + "evidence.tar.gz"])
    seal, manifest, inputs = (v.decode(data) for data in (artifacts[BASE + "sealed.native.json"], files["manifest.json"], files["inputs.json"]))
    if seal["sha256"] != ARCHIVE or seal["bytes"] != len(artifacts[BASE + "evidence.tar.gz"]) or seal["trust"] != "local":
        v.reject("impact-native-seal")
    if manifest["trust"] != "local" or set(manifest["files"]) != set(files) - {"manifest.json"}:
        v.reject("impact-native-manifest")
    for name, item in manifest["files"].items():
        if item != {"bytes": len(files[name]), "sha256": v.digest(files[name])}:
            v.reject("impact-native-member", name)
    current = entry.unpack(files["source.tar.gz"])
    if v.digest(files["source.tar.gz"]) != inputs["source_archive_sha256"] or {name: v.digest(data) for name, data in current.items()} != inputs["files"]:
        v.reject("impact-native-source")
    origin = inputs["source"]
    mirror = v.decode(files["git-mirror.native.json"])
    if (
        {row["path"]: row["sha256"] for row in origin["files"] if row["sha256"] is not None} != inputs["files"]
        or mirror["origin_source"] != origin
        or mirror["source"]["commit"] is not None
        or {row["path"]: row["sha256"] for row in mirror["source"]["files"]} != inputs["files"]
    ):
        v.reject("impact-dirty-source-identity")
    old = entry.unpack(artifacts["reuse-plan/material-2/evidence.tar.gz"])
    original = {name.removeprefix("source/"): data for name, data in old.items() if name.startswith("source/")}
    return files, original, current, seal


def graph(data: bytes) -> dict[str, list[str]]:
    """Use actual compiler imports, rejecting duplicate/incomplete owned packages and unresolved owned edges."""
    result = {}
    for item in statements.stream(data):
        if item.get("Incomplete") or item.get("DepsErrors") or item.get("Error"):
            v.reject("impact-compiler-incomplete")
        name = item["ImportPath"]
        if not name.startswith(MODULE) or " [" in name or name.endswith(".test"):
            continue
        name = name.removeprefix(MODULE)
        if name in result:
            v.reject("impact-compiler-duplicate", name)
        result[name] = sorted(value.removeprefix(MODULE) for value in item.get("Imports", []) if value.startswith(MODULE))
    if STORAGE not in result or any(set(values) - result.keys() for values in result.values()):
        v.reject("impact-compiler-owned-boundary")
    return result


def closure(dependencies: dict[str, list[str]]) -> list[str]:
    """Conservatively select whole transitive consumer packages, including joint units if imports cycle."""
    affected = {STORAGE}
    while True:
        addition = {name for name, values in dependencies.items() if affected.intersection(values)}
        if addition <= affected:
            return sorted(affected)
        affected.update(addition)


def delta(original: dict[str, bytes], current: dict[str, bytes], directories: set[str]) -> list[str]:
    """Admit only reviewed connection lifetimes and the separately authenticated ingress hash pair."""
    names = lambda files: {
        name for name in files if name.endswith(".go") and not name.endswith("_test.go") and PurePosixPath(name).parent.as_posix() in directories
    }
    from tools import idle

    maintenance = idle.WORKER in current
    if names(current) != names(original) | ({idle.WORKER} if maintenance else set()):
        v.reject("impact-production-add-delete-rename")
    expected = dict(original)
    read, schema, store = (STORAGE + "/" + name + ".go" for name in ("read", "schema", "store"))
    transaction = b"\ttx := store.write.WithContext(ctx).Begin()"
    if expected[store].count(transaction) != 1:
        v.reject("impact-reviewed-call-boundary", store)
    # Preserve the comment bytes from the authenticated archive, without embedding its language here.
    opening = expected[store].split(transaction, 1)[0].rsplit(b"\n", 2)[-2] + b"\n"
    if not opening.startswith(b"\t// ") or expected[store].count(opening + transaction) != 1:
        v.reject("impact-reviewed-call-boundary", store)
    replacements = [
        (
            read,
            b"\treturn store.read.WithContext(ctx).Transaction(read)",
            b"\t// Keep lifecycle admission until native cancellation rollback returns the borrowed connection.\n\tdb, conn, err := session(ctx, store.readSQL, store.read)\n\tif err != nil {\n\t\treturn err\n\t}\n\tdefer conn.Close()\n\treturn db.Transaction(read)",
        ),
        (
            schema,
            b"\treturn store.read.WithContext(ctx).Transaction(func(tx *gorm.DB) error {",
            b"\t// Recovery must also join native cancellation rollback before failed construction releases its database lock.\n\tdb, conn, err := session(ctx, store.readSQL, store.read)\n\tif err != nil {\n\t\treturn err\n\t}\n\tdefer conn.Close()\n\treturn db.Transaction(func(tx *gorm.DB) error {",
        ),
        (
            store,
            opening + transaction,
            b"\t// Own the connection until any database/sql cancellation rollback has actually finished.\n\tdb, conn, err := session(ctx, store.writeSQL, store.write)\n\tif err != nil {\n\t\treturn err\n\t}\n\tdefer conn.Close()\n"
            + opening
            + b"\ttx := db.Begin()",
        ),
        (
            store,
            b"// maintain ",
            b"// session reserves a connection for one operation while preserving its context and immutable ORM configuration.\n// Conn.Close waits for the transaction's actual release, even when a concurrent rollback already reports ErrTxDone.\nfunc session(ctx context.Context, pool *sql.DB, db *gorm.DB) (*gorm.DB, *sql.Conn, error) {\n\tconn, err := pool.Conn(ctx)\n\tif err != nil {\n\t\t// Preserve caller cancellation and deadlines before SQL starts; the service maps these stable context errors.\n\t\tif errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {\n\t\t\treturn nil, nil, err\n\t\t}\n\t\treturn nil, nil, ErrUnavailable\n\t}\n\tcurrent := db.WithContext(ctx)\n\tcurrent.Statement.ConnPool = conn\n\treturn current, conn, nil\n}\n\n// maintain ",
        ),
    ]
    for name, before, after in replacements:
        if expected[name].count(before) != 1:
            v.reject("impact-reviewed-call-boundary", name)
        expected[name] = expected[name].replace(before, after, 1)
    changes = [read, schema, store]
    if maintenance:
        if v.digest(current[idle.WORKER]) != idle.SOURCES[idle.WORKER]:
            v.reject("impact-unreviewed-maintenance")
        idle.source_guard(expected[store], current[store])
        expected[store], expected[idle.WORKER] = current[store], current[idle.WORKER]
        changes.append(idle.WORKER)
    if current[installation.PATH] != original[installation.PATH]:
        if v.digest(original[installation.PATH]) != installation.ORIGINAL or v.digest(current[installation.PATH]) != installation.SOURCE:
            v.reject("impact-unreviewed-ingress-delta")
        expected[installation.PATH] = current[installation.PATH]
        changes.append(installation.PATH)
    for name in sorted(names(current)):
        if current[name] != expected[name]:
            v.reject("impact-unreviewed-production-delta", name)
    return sorted(changes)


def sources(root: Path, original: dict[str, bytes], current: dict[str, bytes], before: dict, after: dict) -> dict:
    """Bind compiled package/oracle inputs and unchanged protocol/data boundaries; unknown mappings fail closed."""
    if before != after or closure(after) != ["polaris", "polaris/internal/server", STORAGE]:
        v.reject("impact-consumer-graph-drift")
    directories = set(after)
    changes = delta(original, current, directories)
    # All potential legal private Storage consumers under Polaris must be represented, even if unused by main.
    private = {PurePosixPath(name).parent.as_posix() for name in current if name.startswith("polaris/") and name.endswith(".go")}
    if private - directories:
        v.reject("impact-unmapped-private-consumer")
    boundary = {name for name in original if name.startswith(("proto/", "internal/generated/"))} | {"go.mod", "go.sum", "dependencies.lock.json"}
    if {name for name in current if name.startswith(("proto/", "internal/generated/"))} != boundary - {"go.mod", "go.sum", "dependencies.lock.json"}:
        v.reject("impact-protocol-inventory")
    for name in boundary:
        if current.get(name) != original.get(name):
            v.reject("impact-protocol-data-change", name)
    review = None
    if (root / "development.json").is_file() and refreshed.acquisition(root) == refreshed.ACQUISITION:
        current, review = refreshed.rebinding(root, current, directories)
        if graph(review["compiler_graph"]) != after:
            v.reject("impact-current-compiler-graph")
    # The standalone scanner is not linked into these consumers; its producer stays frozen in the original archive.
    expected = {name for name in current if name.endswith(".go") and PurePosixPath(name).parent.as_posix() in directories}
    actual = {path.relative_to(root).as_posix() for name in directories for path in v.inside(root, name).glob("*.go")}
    if actual != expected:
        v.reject("impact-current-source-inventory")
    # The immutable archive binds producer tools; later interpreter edits do not change its compiled Go inputs.
    expected |= boundary | {"tools/decisions/runtime.go.in", "tests/fixtures/storage.tests.json"}
    bindings = {}
    for name in sorted(expected):
        data = v.read(v.inside(root, name))
        if current.get(name) != data:
            v.reject("impact-current-source-drift", name)
        bindings[name] = v.digest(data)
    return {
        "changes": changes,
        "sources": bindings,
        "unchanged_boundaries": sorted(boundary),
        "affected": closure(after),
        "source_review": None if review is None else {key: value for key, value in review.items() if key not in {"bindings", "compiler_graph"}},
    }


def consumers(files: dict[str, bytes], seal: dict) -> tuple[dict, bytes]:
    """Reconstruct native discovery, Race completion, tool identities and cancellation draining from original facts."""
    inputs, owner, cleanup, terminal = (v.decode(files[name]) for name in ("inputs.json", "controller.json", "cleanup.native.json", "terminal.json"))
    boot = "fcd14352-65a1-438d-bca3-a98551636e54"
    if (
        cleanup["boot_id"] != owner["boot_id"]
        or owner["boot_id"] != inputs["boot_id"]
        or owner["boot_id"] != boot
        or v.digest(files["run.py"]) != inputs["run_sha256"]
        or owner["script_sha256"] != inputs["run_sha256"]
        or owner["inputs_sha256"] != v.digest(files["inputs.json"])
        or terminal != seal["terminal"]
        or terminal["errors"]
        or terminal["interrupted"]
        or terminal["remaining_owned"]
        or not terminal["cache_restored"]
        or cleanup["unit"]["MainPID"] != "0"
        or cleanup["unit"]["ControlGroup"]
        or owner["identity"] not in cleanup["retired"]
    ):
        v.reject("impact-native-lifecycle")
    journal = [v.decode(line) for line in files["journal.native.jsonl"].splitlines()]
    if (
        not journal
        or any(
            row["_BOOT_ID"] != boot.replace("-", "") or (row.get("INVOCATION_ID") or row.get("_SYSTEMD_INVOCATION_ID")) != owner["invocation_id"]
            for row in journal
        )
        or not any(row["MESSAGE"] == "astra-storage-consumers-current-2.service: Deactivated successfully." for row in journal)
        or not any(row["MESSAGE"].startswith('{"at":') and v.decode(row["MESSAGE"].encode()) == terminal for row in journal)
    ):
        v.reject("impact-native-journal")
    selections = inputs["selections"]
    if [item["id"] for item in selections] != ["exports", "server-list", "server-race", "entry-list", "entry-race"]:
        v.reject("impact-native-selection")
    results, exports = {}, b""
    for selection in selections:
        name = selection["id"]
        prefix = "source/build/commands/" + name + "/"
        plan, record, process = (v.decode(files[prefix + item]) for item in ("plan.json", "record.json", name + ".process.json"))
        native_root = owner["cwd"] + "/source"
        argv = [value.replace("{run}", native_root + "/build/commands/" + name) for value in selection["argv"]]
        if (
            record["platform"] != "linux-amd64-cgo"
            or record["exit_code"] != 0
            or record["termination"] != "exited"
            or not record["complete"]
            or not record["cleanup"]
            or process["boot_id"] != boot
            or process["cwd"] != native_root
            or process["identity"] not in cleanup["retired"]
            or not (process["argv"] == record["argv"] == plan["argv"] == argv)
            or record["executable_sha256"] != "30969f97169d7f43fe6a085873d75613adc21e30818a8c61d95bd27275df4624"
        ):
            v.reject("impact-native-command", name)
        for key, digest in {
            "CC": "5ba72afdc29ac57b805ee21e48babe16b31385c03caf91fdd4336483c5a84195",
            "CXX": "1d90c88f14873d7a56f015f31ebe1b72a24942fe379d63eac35d18c1d22970f1",
        }.items():
            if record["toolchain"][key]["sha256"] != digest:
                v.reject("impact-native-toolchain", key)
        for key, value in {
            "GOOS": "linux",
            "GOARCH": "amd64",
            "CGO_ENABLED": "1",
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
            "GOFLAGS": "-mod=readonly",
        }.items():
            if record["resolved_environment"][key] != value:
                v.reject("impact-native-environment", key)
        output = server.reference(files, prefix, record["stdout"])
        server.reference(files, prefix, record["stderr"])
        if name == "exports":
            exports = output
            graph(exports)
            continue
        events = [v.decode(line) for line in output.splitlines()]
        package = MODULE + ("polaris/internal/server" if name.startswith("server-") else "polaris")
        if not events or any(row.get("Action") in ("fail", "skip") or row.get("Package") != package for row in events):
            v.reject("impact-native-test-failure", name)
        key = name.split("-", 1)[0]
        if name.endswith("-list"):
            expected = sorted(row["Output"].strip() for row in events if re.fullmatch(r"(?:Test|Example|Fuzz)[A-Za-z0-9_]*\n", row.get("Output", "")))
            if not expected or len(expected) != len(set(expected)):
                v.reject("impact-native-discovery", name)
            results[key] = {"expected": expected}
        else:
            cases = sorted(row["Test"] for row in events if row.get("Action") == "pass" and "Test" in row and "/" not in row["Test"])
            if cases != results[key]["expected"] or len([row for row in events if row.get("Action") == "pass" and "Test" not in row]) != 1:
                v.reject("impact-native-test-inventory", name)
            profile = files[prefix + "coverage.out"]
            if not profile.startswith(b"mode: atomic\n") or v.digest(profile) != terminal["checks"][name]["coverage_sha256"]:
                v.reject("impact-native-profile", name)
            results[key].update({"tests": len(cases), "duration_ms": record["duration_ms"], "coverage_sha256": v.digest(profile)})
    if {name: item["tests"] for name, item in results.items()} != {"server": 47, "entry": 8} or len(cleanup["retired"]) != 6:
        v.reject("impact-native-denominator")
    return results, exports


def policy(config: dict) -> None:
    """Require the exact reader controls plus full core and real delivery verification, without treating local Race as release proof."""
    check = next(item for item in config["checks"] if item["id"] == "gap-impact")
    if (
        check["adapter"] != "observed-cases"
        or check["component"] != "polaris-storage"
        or check["argv"] != ["python3", "-B", "tools/observe.py", "python", *TESTS]
        or check["expected_tests"] != TESTS
        or check["probes"] != [{"contract": "STORAGE-ASSURANCE", "test": TESTS[0], "minimum_hits": 55}]
    ):
        v.reject("impact-policy-check")
    component = next(item for item in config["components"] if item["id"] == "polaris-storage")
    requirement = next(item for item in component["requirements"] if item["rule"] == "DEV-IMPACT" and item["scenario"] == "full-rule")
    if requirement["checks"] != ["gap-impact"] or requirement.get("requires") != PREREQUISITES:
        v.reject("impact-policy-prerequisites")


def reconcile(root: Path, artifacts: dict[str, bytes] | None = None) -> dict:
    """Produce a scoped impact receipt; approval still depends on the separately executed current core/delivery prerequisites."""
    if artifacts is None:
        artifacts = {name: v.read(root / "build/results/assurance" / name, 128 * 1024**2) for name in ARTIFACTS}
    files, original, current, seal = retained(artifacts)
    results, exports = consumers(files, seal)
    current, results, exports = refreshed.refresh(artifacts, current, files, results)
    old = entry.unpack(artifacts["reuse-plan/entry-closure/evidence.tar.gz"])
    before = graph(old[entry.PREFIX + "typed/exports/exports.stdout.log"])
    bindings = sources(root, original, current, before, graph(exports))
    profiles = None
    if bindings["source_review"] is not None:
        from tools import repair

        name = "go-upgrade-contracts-current-3/native/evidence.tar.gz"
        raw = v.read(root / "build/results/assurance/reuse-plan" / name, 64 * 1024**2)
        if v.digest(raw) != repair.RENEWED[name]:
            v.reject("impact-current-profiles")
        declared = v.unique(v.decode(current["development.json"])["checks"])
        inventory = {
            MODULE + "polaris": declared["polaris-entry-qualification"]["native_tests"],
            MODULE + "polaris/internal/server": v.decode(current["tests/fixtures/server.tests.json"]),
        }
        profiles = repair.profiles(
            root, entry.unpack(raw), {name: sha for name, sha in bindings["sources"].items() if not name.endswith(".md")}, "", inventory=inventory
        )
    return {
        "trust": "local",
        "baseline_native_archive_sha256": ARCHIVE,
        "native_archives": refreshed.ARTIFACTS,
        "checks": results,
        "current_profiles": profiles,
        **bindings,
    }
