"""Rebind Storage predicate proofs to the reviewed idle-maintenance source revision."""

import io
import os
from pathlib import Path, PurePosixPath
import re
import tarfile
import tempfile

from tools import logic, storage, structure, verify as v

# Exact native inputs identify this revision; unfamiliar edits retain the original source-drift refusal.
STORE = "polaris/internal/storage/store.go"
WORKER = "polaris/internal/storage/maintenance.go"
SOURCES = {
    STORE: "1b6854d0ebf89d2d2ba16cc282794b5e3486aee542eeb54e1fe1a496eda87279",
    WORKER: "6db7bce0a96825f996cc3d50f3b5a12c7b205b51266b21987642ea319fcf3314",
}
SOURCE = "reuse-plan/storage-binding-native-1/native/source.tar.gz"
CURRENT = "reuse-plan/storage-idle-structure-2/native/evidence.tar.gz"
RACE = "reuse-plan/storage-idle-regression-1/native/evidence.tar.gz"
OPERATORS = "reuse-plan/storage-idle-operators-1/native/evidence.tar.gz"
BACKUP_FILE = "polaris/internal/storage/backup_test.go"
BACKUP = "reuse-plan/storage-backup-full-current-1/evidence.tar.gz"
BACKUP_DIGEST = "93b0286d2a5d073858b88115ef9e429078e33abbd852c1d92d0f8b51c5c7565f"
ACQUISITION = "reuse-plan/storage-backup-structure-current-1/evidence.tar.gz"
ACQUISITION_DIGEST = "ec1624f196bf812f6085c8f4f25c278c98118179ed9d31569a5c8830e489287e"
BACKUP_TESTS = "a8d66ab5edd3c86ec21d86ad48587150a5b93e83b955258fb9f14413a7c1c3a0"
BACKUP_CASES = ("TestOnlineBackup", "TestBackupRestore")
ARTIFACTS = {
    SOURCE: "85667b770ee11bb60d780f584cb917f1c1b2e4ee6100c2a0a2b2b444a37178bb",
    CURRENT: "bbaa9dc6c4338a4fc2df994d1d8ee3b25cce64003f0b8fdda9e779448c3c4057",
    RACE: "60bc752b35379511c49db7680b173cbbe0df69ff9b1f9b664f1cad5c55d1d272",
    OPERATORS: "115443072e2c19582cbe31cef0342c9716d5e83ac9f195c31f5ded29ef7a664c",
}
PREFIX = "source/build/commands/raw-structure/structure/"
# The declaration was frozen before native execution, including helpers and all data-driven descendants.
TESTS = "acb7eec7cab2f0860ba745e74a42569b090d8e21cbec1b78fe4cc3e47424f847"
# Separately qualified compatibility cases and the five new maintenance cases extend the frozen base declaration.
CASES = (
    "TestCompatibility",
    "TestCompatibility/batch",
    "TestCompatibility/single",
    "TestCompatibility/truncated",
    "TestCompatibility/unknown",
    "TestIdleCheckpoint",
    "TestMaintenanceClose",
    "TestMaintenanceDeadline",
    "TestMaintenanceFailure",
    "TestMaintenancePoison",
)
DIRECTORY = PurePosixPath("/home/ubuntu/verdandi/astra/build/results/assurance/storage-idle-structure-2/source")
GEOMETRY = {
    "counts": [643, 321, 557, 37],
    "forest": "fb75649a693d1d2f10b8b229f1e7ff372fbc5a0757f0cbdfb6d560c07dd2fa6c",
    "edges": "2977cec20eeef55666463ce84f4a83496f43583ec10f1bdf466000ffa00b0707",
    "profile": "4fdeca4ed52287bfa27ae4fa6b6389c24760b0618a8bfd1fd267ee22d336e015",
}


def current(root: Path) -> bool:
    """Select only the exact two-file production change, without accepting a prefix or version label."""
    return all((root / name).is_file() and v.file_digest(root / name) == digest for name, digest in SOURCES.items())


def artifacts(root: Path) -> dict[str, bytes]:
    """Read fixed immutable references within the existing ignored evidence root."""
    values = {name: v.read(v.inside(root / "build/results/assurance", name), 64 * 1024**2) for name in ARTIFACTS}
    if any(v.digest(values[name]) != digest for name, digest in ARTIFACTS.items()):
        v.reject("idle-artifact-integrity")
    if (root / BACKUP_FILE).is_file():
        values[BACKUP] = v.read(v.inside(root / "build/results/assurance", BACKUP), 16 * 1024**2)
        if v.digest(values[BACKUP]) != BACKUP_DIGEST:
            v.reject("idle-backup-artifact-integrity")
        values[ACQUISITION] = v.read(v.inside(root / "build/results/assurance", ACQUISITION), 16 * 1024**2)
        if v.digest(values[ACQUISITION]) != ACQUISITION_DIGEST:
            v.reject("idle-acquisition-artifact-integrity")
    from tools import storagecompiler

    if storagecompiler.upgraded(root):
        values.update(storagecompiler.artifacts(root))
    return values


def references(root: Path) -> dict[str, str]:
    """Reuse the same verified semantic and current native inputs for structural qualification."""
    from tools import independence

    return {name: v.digest(data) for name, data in independence.artifacts(root).items()}


def unpack(data: bytes, *, source: bool = False) -> dict[str, bytes]:
    """Keep archive paths, counts and total allocation bounded before interpreting any member."""
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            total += member.size
            if (
                not member.isfile()
                or path.is_absolute()
                or ".." in path.parts
                or member.name in files
                or member.size > 64 * 1024**2
                or total > 256 * 1024**2
                or len(files) >= 4096
            ):
                v.reject("idle-archive-boundary")
            files[member.name] = archive.extractfile(member).read()
    if source:
        if len(files) != 969:
            v.reject("idle-predecessor-source-inventory")
        return files
    manifest = v.decode(files.get("manifest.json", b""))
    if manifest.get("trust") != "local" or set(manifest["files"]) != files.keys() - {"manifest.json"}:
        v.reject("idle-native-manifest")
    for name, item in manifest["files"].items():
        if item != {"bytes": len(files[name]), "sha256": v.digest(files[name])}:
            v.reject("idle-native-member", name)
    terminal = v.decode(files["terminal.json"])
    regression = v.digest(data) == ARTIFACTS[RACE] and terminal["errors"] == [
        "Invalid: file-size: /home/ubuntu/verdandi/astra/build/results/assurance/storage-idle-regression-1/source/build/commands/storage-idle-race/storage-idle-race.stdout.log"
    ]
    if terminal["interrupted"] or terminal["remaining_owned"] or terminal["errors"] and not regression:
        v.reject("idle-native-terminal")
    return files


def stream(files: dict[str, bytes], prefix: str, record: dict) -> bytes:
    """Require original successful native commands and complete stream identities."""
    if record["exit_code"] != 0 or not record["complete"] or not record["cleanup"] or record["termination"] != "exited":
        v.reject("idle-native-command")
    result = b""
    for field in ("stdout", "stderr"):
        item = record[field]
        path = PurePosixPath(item["path"])
        if path.is_absolute() or ".." in path.parts:
            v.reject("idle-native-stream-path")
        data = files[prefix + path.as_posix()]
        if len(data) != item["bytes"] or len(data) > 32 * 1024**2 or v.digest(data) != item["sha256"]:
            v.reject("idle-native-stream")
        if field == "stdout":
            result = data
    return result


def lifecycle(root: Path, values: dict[str, bytes]) -> None:
    """Bind the unchanged full Race product and both strengthened lifecycle witnesses to this revision."""
    full = unpack(values[RACE])
    inputs = v.decode(full["inputs.json"])
    if any(inputs["files"].get(name) != digest for name, digest in SOURCES.items()):
        v.reject("idle-race-source")
    check = inputs["auxiliary"][1]
    prefix = "source/build/commands/" + check["id"] + "/"
    record = v.decode(full[prefix + "record.json"])
    if record["argv"] != check["argv"] or "-race" not in record["argv"] or len(check["expected_tests"]) != 257:
        v.reject("idle-race-scope")
    _, failures = v.go_observations(stream(full, prefix, record), check)
    if failures:
        v.reject("idle-race-observation")
    operators = unpack(values[OPERATORS])
    inputs = v.decode(operators["inputs.json"])
    for name in (*SOURCES, "polaris/internal/storage/maintenance_test.go"):
        if inputs["files"].get(name) != v.file_digest(root / name):
            v.reject("idle-lifecycle-source", name)
    prefix = "source/build/commands/operators/operators/positive/"
    record = v.decode(operators[prefix + "record.json"])
    check = {
        "package": "github.com/eosforge/astra/polaris/internal/storage",
        "expected_tests": ["TestMaintenanceDeadline", "TestMaintenanceClose"],
        "probes": [
            {"test": "TestMaintenanceDeadline", "contract": "STORAGE-TIME", "minimum_hits": 6},
            {"test": "TestMaintenanceClose", "contract": "STORAGE-LIFETIME", "minimum_hits": 8},
        ],
    }
    _, failures = v.go_observations(stream(operators, prefix, record), check)
    if failures or "-race" not in record["argv"]:
        v.reject("idle-lifecycle-observation")


def reconcile(root: Path, values: dict[str, bytes]) -> dict:
    """Replay prior semantic ancestry, then require complete current vector and source projections."""
    from tools import independence

    if current(root):
        from tools import storagecompiler

        if storagecompiler.upgraded(root):
            return storagecompiler.reconcile(root, values)

    if not current(root) or not ARTIFACTS.keys() <= values.keys() or any(v.digest(values[name]) != digest for name, digest in ARTIFACTS.items()):
        v.reject("idle-input-binding")
    old_values = {name: data for name, data in values.items() if name not in ARTIFACTS and name not in {BACKUP, ACQUISITION}}
    original = unpack(values[SOURCE], source=True)
    source_guard(original[STORE], v.read(root / STORE))
    lifecycle(root, values)
    parent = root / "build/tmp"
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="storage-proof-", dir=parent) as temporary:
        shadow = Path(temporary)
        for name, data in original.items():
            target = v.inside(shadow, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            v.write_new(target, data)
        for name, data in old_values.items():
            target = v.inside(shadow / "build/results/assurance", name)
            target.parent.mkdir(parents=True, exist_ok=True)
            origin = v.inside(root / "build/results/assurance", name)
            if v.file_digest(origin) != v.digest(data):
                v.reject("idle-predecessor-reference-raced")
            os.link(origin, target)
        proof = independence.reconcile(shadow, old_values)
    old = storage.retained(old_values[storage.BASE + "evidence.tar.gz"], v.decode(old_values[storage.BASE + "sealed.native.json"]), storage.ARCHIVE)
    typed = v.decode(old[storage.PREFIX + "typed/overlay/trace.json"])
    old_record = v.decode(old[storage.PREFIX + "typed/tests/record.json"])
    old_data = stream(old, storage.PREFIX + "typed/tests/", old_record)
    now = unpack(values[CURRENT])
    inputs = v.decode(now["inputs.json"])
    package = {name: digest for name, digest in inputs["files"].items() if PurePosixPath(name).parent.as_posix() == structure.STORAGE and name.endswith(".go")}
    actual = {path.relative_to(root).as_posix() for path in (root / structure.STORAGE).glob("*.go")}
    supplement = None
    if set(package) != actual:
        if actual != set(package) | {BACKUP_FILE} or BACKUP not in values or v.digest(values[BACKUP]) != BACKUP_DIGEST:
            v.reject("idle-compilation-source")
        from tools import entry

        supplement = backup(root, package, now, entry.unpack(values[BACKUP]))
        actual.remove(BACKUP_FILE)
    if set(package) != actual or any(v.file_digest(root / name) != digest for name, digest in package.items() if not name.endswith("/maintenance_test.go")):
        v.reject("idle-compilation-source")
    trace = v.decode(now[PREFIX + "typed/overlay/trace.json"])
    record = v.decode(now[PREFIX + "typed/tests/record.json"])
    data = stream(now, PREFIX + "typed/tests/", record)
    if old_record["executable_sha256"] != record["executable_sha256"] or any(
        old_record["toolchain"][name]["sha256"] != record["toolchain"][name]["sha256"] for name in ("CC", "CXX", "command")
    ):
        v.reject("idle-native-compiler")
    old_exports, exports = typed["typing"]["exports"], trace["typing"]["exports"]
    if set(old_exports) != set(exports) or any(
        (old_exports[name]["bytes"], old_exports[name]["sha256"]) != (exports[name]["bytes"], exports[name]["sha256"]) for name in exports
    ):
        v.reject("idle-compiler-export-source")
    before = {item["file"]: item["sha256"] for item in typed["files"]}
    after = {item["file"]: item["sha256"] for item in trace["files"]}
    actual = {path.relative_to(root).as_posix() for path in (root / structure.STORAGE).glob("*.go") if not path.name.endswith("_test.go")}
    if (
        actual != set(after)
        or set(after) != set(before) | {WORKER}
        or any(v.file_digest(root / name) != digest for name, digest in after.items())
        or any(digest != after[name] for name, digest in before.items() if name != STORE)
    ):
        v.reject("idle-production-source")
    for name in ("go.mod", "go.sum"):
        if original[name] != v.read(root / name):
            v.reject("idle-module-source", name)
    for name, digest in structure.STORAGE_DEPENDENCIES.items():
        if v.digest(now[PREFIX + "_dependencies/" + name]) != digest:
            v.reject("idle-native-dependency", name)
    old_rows, old_processes = logic.observe(typed, old_data, "github.com/eosforge/astra/" + structure.STORAGE, 247)
    rows, processes = logic.observe(trace, data, "github.com/eosforge/astra/" + structure.STORAGE, 257)
    if processes != old_processes or processes != 32:
        v.reject("idle-native-process-scope")
    result = project(proof, typed, trace, old_rows, rows)
    result.update(
        {
            "source_sha256": trace["source_sha256"],
            "source_bindings": after,
            "trust": "local",
            "platform": structure.PLATFORM,
            "basis": "Unmodified semantic ancestor replay, exact reviewed owner-only source additions, identical prior typed predicate trees with all preceding native vectors, and two current single-atom independent pairs. This qualifies predicate independence only; lifecycle, fault, mutation, numerical, installation and protected trust keep separate obligations.",
            "archives": ARTIFACTS,
            "compiler_exports_reused": len(exports),
        }
    )
    if supplement is not None:
        result["backup_supplement"] = supplement
        if ACQUISITION not in values or v.digest(values[ACQUISITION]) != ACQUISITION_DIGEST:
            v.reject("idle-acquisition-artifact-integrity")
        from tools import entry

        ledger, fresh_trace, fresh_rows = acquisition(root, entry.unpack(values[ACQUISITION]))
        mapping = predicates(trace["files"], fresh_trace["files"], set(), rows, fresh_rows)
        if len(mapping) != 162:
            v.reject("idle-acquisition-predicate-scope")
        result["mapping"] = {old: mapping[new] for old, new in result["mapping"].items()}
        result["new_pairs"] = [{**pair, "decision": mapping[pair["decision"]]} for pair in result["new_pairs"]]
        result["exclusions"] = [{**item, "decision": mapping[item["decision"]]} for item in result["exclusions"]]
        result["source_sha256"] = fresh_trace["source_sha256"]
        result["current_structure"] = ledger
        result["current_acquisition"] = {
            "archive": ACQUISITION,
            "archive_sha256": ACQUISITION_DIGEST,
            "preserved_predicates": len(mapping),
            "current_cases": 259,
            "new_condition_hits": 0,
        }
    return result


def backup(root: Path, package: dict[str, str], compiled: dict[str, bytes], files: dict[str, bytes]) -> dict:
    """Bind the sole test-only addition to complete current native profiles without inventing historical hits."""
    from tools import entry

    inputs, owner, cleanup, terminal = (v.decode(files[name]) for name in ("inputs.json", "owner.json", "cleanup.native.json", "terminal.json"))
    source = entry.unpack(files["source.tar.gz"])
    current = {name: digest for name, digest in inputs["files"].items() if PurePosixPath(name).parent.as_posix() == structure.STORAGE and name.endswith(".go")}
    actual = {path.relative_to(root).as_posix() for path in (root / structure.STORAGE).glob("*.go")}
    if (
        set(current) != set(package) | {BACKUP_FILE}
        or actual != set(current)
        or v.digest(files["source.tar.gz"]) != inputs["source_archive_sha256"]
        or {name: v.digest(data) for name, data in source.items()} != inputs["files"]
        or any(v.file_digest(v.inside(root, name)) != digest for name, digest in inputs["files"].items())
        or any(current[name] != digest for name, digest in package.items() if not name.endswith("/maintenance_test.go"))
    ):
        v.reject("idle-backup-compilation-source")
    check = inputs["full_package_check"]
    old = sorted(
        row["Test"]
        for line in compiled[PREFIX + "coverage/coverage.stdout.log"].splitlines()
        if (row := v.decode(line)).get("Action") == "pass" and "Test" in row
    )
    configured = next(item for item in v.decode(v.read(root / "development.json"))["checks"] if item["id"] == "storage-examples")
    if (
        len(old) != 257
        or v.digest(v.encode(old)) != TESTS
        or check != configured
        or check["expected_tests"] != sorted(old + ["TestOnlineBackup", "TestBackupRestore"])
    ):
        v.reject("idle-backup-test-declaration")
    if (
        owner["inputs_sha256"] != v.digest(files["inputs.json"])
        or owner["script_sha256"] != inputs["driver_sha256"]
        or inputs["driver_sha256"] != v.digest(files["run.py"])
        or inputs["enter_sha256"] != v.digest(files["enter.py"])
        or cleanup["boot_id"] != owner["boot_id"]
        or cleanup["original_invocation_id"] != owner["invocation_id"]
        or cleanup["original_failed"]
        or cleanup["remaining_owned"]
        or cleanup["unit"]["MainPID"] != "0"
        or cleanup["unit"]["ControlGroup"]
        or terminal["errors"]
        or terminal["interrupted"]
        or terminal["remaining_owned"]
        or not terminal["cache_returned"]
        or not terminal["inputs_unchanged"]
        or len(cleanup["retired"]) != 3
        or cleanup["retired"][0]["identity"] != owner["identity"]
        or any(row["status"] not in {"absent", "reused"} or row["current_start_ticks"] == row["identity"]["start_ticks"] for row in cleanup["retired"])
    ):
        v.reject("idle-backup-native-owner")
    journal = v.decode(files["journal.native.json"])
    messages = [row.get("MESSAGE", "") for row in journal]
    if (
        any(
            row.get("_BOOT_ID") != owner["boot_id"].replace("-", "")
            or (row.get("INVOCATION_ID") or row.get("_SYSTEMD_INVOCATION_ID")) != owner["invocation_id"]
            for row in journal
        )
        or terminal not in [v.decode(message.encode()) for message in messages if message.startswith("{")]
        or "astra-storage-backup-full-native-current-1.service: Deactivated successfully." not in messages
    ):
        v.reject("idle-backup-native-journal")
    dependencies = v.decode(files["dependencies.before.json"])
    previous = v.decode(compiled[PREFIX + "coverage/record.json"])
    go = "/home/ubuntu/verdandi/build/tools/go-1.27.1/bin/go"
    compiler = "/home/ubuntu/verdandi/build/tools/gcc-16.2.0"
    if (
        files["dependencies.before.json"] != files["dependencies.after.json"]
        or set(dependencies) != set(inputs["dependency_roots"])
        or len(dependencies) != 9
        or dependencies[go.removesuffix("/bin/go")]["bin/go"] != previous["executable_sha256"]
        or any(dependencies[compiler]["bin/" + name] != previous["toolchain"][tool]["sha256"] for tool, name in (("CC", "gcc"), ("CXX", "g++")))
    ):
        v.reject("idle-backup-native-compiler")
    plans = {item["id"]: item for item in inputs["commands"]}
    if (
        len(inputs["commands"]) != 2
        or set(plans) != {"ordinary", "race"}
        or len(terminal["records"]) != 2
        or {row["id"] for row in terminal["records"]} != set(plans)
    ):
        v.reject("idle-backup-native-profiles")
    if (
        owner["whole_limits"]["memory.max"] != "2147483648"
        or owner["whole_limits"]["cpu.max"] != "300000 100000"
        or terminal["whole_resources"]["memory.max"] != "2147483648"
        or any(value != "0" for _, value in (row.split() for row in terminal["whole_resources"]["memory.events"].splitlines()))
        or dict(row.split() for row in terminal["whole_resources"]["pids.events"].splitlines())["max"] != "0"
    ):
        v.reject("idle-backup-native-resources")
    profiles = {}
    for name, plan in plans.items():
        prefix = "commands/" + name + "/"
        record, request, process, execution, before, after = (
            v.decode(files[prefix + item])
            for item in ("record.json", "request.json", name + ".process.json", "exec.native.json", "leaf.before.json", "leaf.after.json")
        )
        v.schema(record, "evidence", ("properties", "checks", "items"))
        arguments = [
            go,
            "test",
            "-json",
            *(["-race"] if name == "race" else []),
            "-count=1",
            "-parallel=4",
            "-p=4",
            "-timeout=180s",
            "./polaris/internal/storage",
        ]
        leaf = owner["group"] + "/" + name
        if (
            plan["argv"] != arguments
            or plan["timeout_s"] != (300 if name == "race" else 240)
            or request["timeout_s"] != plan["timeout_s"]
            or request["log_bytes"] != 16 * 1024**2
            or record["argv"] != request["argv"]
            or record["argv"] != process["argv"]
            or record["argv"] != ["/usr/bin/python3", "-B", inputs["native_root"] + "/enter.py", "--enter", leaf, "--", *arguments]
            or record["exit_code"] != 0
            or not record["complete"]
            or not record["cleanup"]
            or record["termination"] != "exited"
            or record["duration_ms"] > plan["timeout_s"] * 1000
            or record["environment"] != request["environment"]
            or record["resolved_environment"] != record["environment"] | {"HOME": "/home/ubuntu", "LANG": "C.UTF-8"}
            or any(
                record["resolved_environment"].get(key) != value
                for key, value in {
                    "GOMAXPROCS": "4",
                    "CGO_ENABLED": "1",
                    "GOFLAGS": "-mod=readonly",
                    "GOPROXY": "off",
                    "GOSUMDB": "off",
                    "GOTOOLCHAIN": "local",
                    "GOWORK": "off",
                }.items()
            )
        ):
            v.reject("idle-backup-native-command")
        if next(row for row in terminal["records"] if row["id"] == name) != {
            key: record[key] for key in ("id", "exit_code", "complete", "cleanup", "termination", "duration_ms")
        }:
            v.reject("idle-backup-native-command")
        if any(
            record["resolved_environment"].get(tool) != compiler + "/bin/" + binary
            or record["toolchain"][tool] != {"path": compiler + "/bin/" + binary, "sha256": dependencies[compiler]["bin/" + binary]}
            for tool, binary in (("CC", "gcc"), ("CXX", "g++"))
        ):
            v.reject("idle-backup-native-compiler")
        if (
            execution["declared_go_argv"] != arguments
            or len(execution["observed"]) != 1
            or execution["observed"][0]["argv"] != arguments
            or execution["observed"][0]["executable"] != go
            or execution["observed"][0]["cgroup"] != leaf
            or any(execution["observed"][0]["identity"][key] != process["identity"][key] for key in ("pid", "start_ticks", "parent", "session"))
            or process["identity"] not in [row["identity"] for row in cleanup["retired"]]
            or process["identity"]["parent"] != owner["identity"]["pid"]
            or process["boot_id"] != owner["boot_id"]
            or process["cwd"] != inputs["native_root"] + "/source"
        ):
            v.reject("idle-backup-native-exec")
        if (
            any(
                before[key] != value or after[key] != value
                for key, value in {
                    "memory.high": "1342177280",
                    "memory.max": "1610612736",
                    "memory.swap.max": "0",
                    "cpu.max": "200000 100000",
                    "pids.max": "256",
                }.items()
            )
            or after["cgroup.procs"]
            or dict(row.split() for row in after["cgroup.events"].splitlines())["populated"] != "0"
            or any(value != "0" for _, value in (row.split() for row in after["memory.events"].splitlines()))
            or dict(row.split() for row in after["pids.events"].splitlines())["max"] != "0"
        ):
            v.reject("idle-backup-native-resources")
        data = stream(files, prefix, record)
        if record["stdout"]["path"] != name + ".stdout.log" or record["stderr"]["path"] != name + ".stderr.log" or record["stderr"]["bytes"]:
            v.reject("idle-backup-native-stream")
        hits, failures = v.go_observations(data, check)
        passed = sorted(row["Test"] for line in data.splitlines() if (row := v.decode(line)).get("Action") == "pass" and "Test" in row)
        if failures or passed != check["expected_tests"]:
            v.reject("idle-backup-native-tests")
        profiles[name] = {
            "tests": len(passed),
            "observed": hits,
            "record_sha256": v.digest(files[prefix + "record.json"]),
            "duration_ms": record["duration_ms"],
        }
    return {
        "test_file": BACKUP_FILE,
        "test_sha256": current[BACKUP_FILE],
        "archive": BACKUP,
        "archive_sha256": BACKUP_DIGEST,
        "historical_cases": 257,
        "current_cases": 259,
        "profiles": profiles,
        "new_structure_or_mcdc_hits": 0,
        "basis": "Exactly one reviewed test-only addition, unchanged production/prior tests and identical native compilers; complete current ordinary/Race package observations. Historical instrumented counters and condition pairs retain their original denominators and identities.",
    }


def commands(files: dict[str, bytes]) -> dict[str, bytes]:
    """Bind all eight native children to their predeclared limits, environment, compiler and retired owner."""
    inputs, controller, cleanup = (v.decode(files[name + ".json"]) for name in ("inputs", "controller", "cleanup.native"))
    check = inputs["auxiliary"][0]
    prefix = "source/build/commands/raw-structure/"
    outer = v.decode(files[prefix + "record.json"])
    owner = v.decode(files[prefix + "raw-structure.process.json"])
    if (
        controller["inputs_sha256"] != v.digest(files["inputs.json"])
        or controller["script_sha256"] != v.digest(files["run.py"])
        or controller["identity"] not in cleanup["retired"]
        or controller["boot_id"] != inputs["boot_id"]
        or controller["boot_id"] != cleanup["boot_id"]
        or cleanup["original_exit_code"] != 0
        or cleanup["unit"]["MainPID"] != "0"
        or cleanup["unit"]["ControlGroup"]
        or cleanup["unit"]["Result"] != "success"
        or cleanup["unit"]["ExecMainStatus"] != "0"
        or check["id"] != "raw-structure"
        or outer["argv"] != check["argv"]
        or owner["argv"] != check["argv"]
        or owner["cwd"] != str(DIRECTORY)
        or owner["identity"] not in cleanup["retired"]
        or owner["identity"]["parent"] != controller["identity"]["pid"]
        or owner["boot_id"] != controller["boot_id"]
        or outer["duration_ms"] > check["timeout_s"] * 1000
    ):
        v.reject("idle-structure-owner")
    stream(files, prefix, outer)
    planned = structure.plan(DIRECTORY / "build/commands/raw-structure/structure", package=structure.STORAGE)
    if {name.removeprefix(PREFIX).removesuffix("/record.json") for name in files if name.startswith(PREFIX) and name.endswith("/record.json")} != {
        name for name, _, _ in planned
    }:
        v.reject("idle-structure-command-inventory")
    environment = outer["resolved_environment"]
    requested = {
        key: value.replace("{root}", str(DIRECTORY))
        .replace("{cache}", "/home/ubuntu/verdandi/build")
        .replace("{run}", str(DIRECTORY / "build/commands/raw-structure"))
        for key, value in check["environment"].items()
    }
    if environment != {**requested, "HOME": "/home/ubuntu", "LANG": "C.UTF-8"} or outer["environment"] != check["environment"]:
        v.reject("idle-structure-environment")
    streams = {}
    previous = outer["started_at"]
    for name, arguments, timeout in planned:
        prefix = PREFIX + name + "/"
        record = v.decode(files[prefix + "record.json"])
        v.schema(record, "evidence", ("properties", "checks", "items"))
        process = v.decode(files[prefix + PurePosixPath(name).name + ".process.json"])
        identity = process["identity"]
        child = {
            **environment,
            "TMPDIR": str(DIRECTORY / "build/commands/raw-structure/structure" / name / "tmp"),
            "ASTRA_TEST_LOG_DIR": str(DIRECTORY / "build/commands/raw-structure/structure" / name / "logs"),
        }
        tools = {key: outer["toolchain"][key] for key in ("CC", "CXX")}
        tools["command"] = {
            "path": "/home/ubuntu/verdandi/build/tools/go-1.27.1/bin/go",
            "sha256": "30969f97169d7f43fe6a085873d75613adc21e30818a8c61d95bd27275df4624",
        }
        if (
            record["id"] != PurePosixPath(name).name
            or record["argv"] != [item.replace("{root}", str(DIRECTORY)) for item in arguments]
            or record["platform"] != structure.PLATFORM
            or record["environment"] != child
            or record["resolved_environment"] != child
            or record["toolchain"] != tools
            or record["executable"] != tools["command"]["path"]
            or record["executable_sha256"] != tools["command"]["sha256"]
            or record["duration_ms"] > timeout * 1000
            or process["argv"] != record["argv"]
            or process["cwd"] != str(DIRECTORY)
            or process["boot_id"] != owner["boot_id"]
            or identity not in cleanup["retired"]
            or identity.get("parent") != owner["identity"]["pid"]
            or type(identity.get("pid")) is not int
            or identity["pid"] <= 0
            or not isinstance(identity.get("start_ticks"), str)
            or not identity["start_ticks"].isdecimal()
            or int(identity["start_ticks"]) <= 0
        ):
            v.reject("idle-structure-command", name)
        if not v.stamp(previous) <= v.stamp(record["started_at"]) <= v.stamp(record["finished_at"]) <= v.stamp(outer["finished_at"]):
            v.reject("idle-structure-command-order")
        previous = record["finished_at"]
        streams[name] = stream(files, prefix, record)
    return streams


def outcomes(root: Path, files: dict[str, bytes]) -> dict:
    """Reconstruct the native structural ledger without crediting a supplied success summary."""
    bundle = v.decode(files[PREFIX + "bundle.json"])
    logic.fields(bundle, ("version", "source", "coverage", "profiles", "typed", "control", "dependencies", "qualification"), "idle-structure-bundle")
    if bundle["version"] != 2 or bundle["qualification"] != "not-evaluated":
        v.reject("idle-structure-bundle-version")
    source = storage.reference(files, PREFIX, bundle["source"])
    inputs = v.decode(files["inputs.json"])
    for name in inputs["files"]:
        if name.startswith("tools/decisions/") and name.endswith((".go", ".go.in")):
            if v.file_digest(root / name) != inputs["files"][name]:
                v.reject("idle-native-collector-source", name)
    source_directory = DIRECTORY
    native_directory = source_directory / "build/commands/raw-structure/structure"
    streams = commands(files)
    if storage.reference(files, PREFIX, bundle["coverage"]) != files[PREFIX + "coverage/record.json"] or set(bundle["profiles"]) != {"parent"}:
        v.reject("idle-structure-coverage-record")
    loaded = {}
    for name in ("typed", "control"):
        prefix = PREFIX + name + "/"
        item = v.decode(storage.reference(files, PREFIX, bundle[name]))
        trace = v.decode(storage.reference(files, prefix, item["trace"]))
        reported = [row for row in v.decode(streams[name + "/collector"])["files"] if PurePosixPath(row["file"]).parent.as_posix() == structure.STORAGE]
        report = v.decode(streams[name + "/collector"])
        if (
            item["directory"] != structure.STORAGE
            or trace["files"] != reported
            or storage.reference(files, prefix, item["source"]) != source
            or report["source_sha256"] != v.digest(source)
        ):
            v.reject("idle-structure-overlay-source", name)
        replacements = v.decode(storage.reference(files, prefix, item["overlay"]))["Replace"]
        generated = {row["file"] for row in trace["files"]} | {structure.STORAGE + "/zz_astra_probe.go", structure.STORAGE + "/zz_astra_probe_test.go"}
        if set(item["generated"]) != generated or set(replacements) != {str(source_directory / path) for path in generated}:
            v.reject("idle-structure-overlay-inventory", name)
        for original, reference in item["generated"].items():
            replacement = native_directory / name / reference["path"]
            if replacements[str(source_directory / original)] != str(replacement):
                v.reject("idle-structure-overlay-path", original)
            storage.reference(files, prefix, reference)
        for field in ("collector", "packages", "tests") + (("exports",) if name == "typed" else ()):
            if storage.reference(files, prefix, item[field]) != files[prefix + field + "/record.json"]:
                v.reject("idle-structure-nested-record", field)
        loaded[name] = trace
    events = [v.decode(line) for line in streams["coverage"].splitlines()]
    declaration = sorted(row["Test"] for row in events if row.get("Action") == "pass" and "Test" in row)
    if len(declaration) != 257 or v.digest(v.encode(declaration)) != TESTS:
        v.reject("idle-structure-test-declaration")
    structure.terminals(streams["coverage"], declaration, package=structure.STORAGE)
    dependencies = {name: storage.reference(files, PREFIX, reference) for name, reference in bundle["dependencies"].items()}
    result = structure.reconcile(
        root=root,
        source_sha256=v.digest(source),
        tests=declaration,
        profiles=(storage.reference(files, PREFIX, bundle["profiles"]["parent"]),),
        dependency=dependencies,
        trace=loaded["typed"],
        boolean_events=streams["typed/tests"],
        control=loaded["control"],
        control_events=streams["control/tests"],
        package=structure.STORAGE,
    )
    return result


def acquisition(root: Path, files: dict[str, bytes], *, compiler: str = "1.27.1") -> tuple[dict, dict, dict]:
    """Recompute current structural observations from the sealed native acquisition and its actual inputs."""
    from tools import entry

    if compiler not in {"1.27.1", "1.27.2"}:
        v.reject("idle-acquisition-compiler")
    upgraded = compiler == "1.27.2"
    native_name = "go-upgrade-storage-structure-native-current-2" if upgraded else "storage-backup-structure-native-current-1"

    inputs, owner, cleanup, terminal = (v.decode(files[name]) for name in ("inputs.json", "owner.json", "cleanup.native.json", "terminal.json"))
    source = entry.unpack(files["source.tar.gz"])
    actual = v.decode(files["source.native.before.json"])
    collectors = {path.relative_to(root).as_posix() for path in (root / "tools/decisions").iterdir() if path.name.endswith((".go", ".go.in"))}
    expected = (
        {path.relative_to(root).as_posix() for path in (root / structure.STORAGE).rglob("*") if path.is_file()}
        | collectors
        | {".gitignore", "go.mod", "go.sum", "dependencies.lock.json"}
    )
    if (
        len(source) != 78
        or set(source) != expected
        or v.digest(files["source.tar.gz"]) != inputs["source_archive_sha256"]
        or {name: v.digest(data) for name, data in source.items()} != inputs["files"]
        or source[".gitignore"] != b"build/\n"
        or any(v.file_digest(v.inside(root, name)) != digest for name, digest in inputs["files"].items() if name != ".gitignore")
        or files["source.native.before.json"] != files["source.native.after.json"]
        or actual["commit"] is not None
        or len(actual["files"]) != 78
        or {row["path"]: row["sha256"] for row in actual["files"]} != inputs["files"]
        or files["git.native.HEAD"] != b"ref: refs/heads/fixture\n"
        or b"[remote " in files["git.native.config"]
    ):
        v.reject("idle-acquisition-source")
    if (
        owner["inputs_sha256"] != v.digest(files["inputs.json"])
        or owner["script_sha256"] != inputs["driver_sha256"]
        or inputs["driver_sha256"] != v.digest(files["run.py"])
        or inputs["enter_sha256"] != v.digest(files["enter.py"])
        or cleanup["boot_id"] != owner["boot_id"]
        or cleanup["original_invocation_id"] != owner["invocation_id"]
        or cleanup["original_failed"]
        or cleanup["remaining_owned"]
        or cleanup["unit"]["MainPID"] != "0"
        or cleanup["unit"]["ControlGroup"]
        or terminal["errors"]
        or terminal["interrupted"]
        or terminal["remaining_owned"]
        or not terminal["inputs_unchanged"]
        or not terminal["cache_returned"]
        or len(cleanup["retired"]) != 10
        or cleanup["retired"][0]["identity"] != owner["identity"]
        or any(row["status"] not in {"absent", "reused"} or row["current_start_ticks"] == row["identity"]["start_ticks"] for row in cleanup["retired"])
    ):
        v.reject("idle-acquisition-owner")
    journal = v.decode(files["journal.native.json"])
    messages = [row.get("MESSAGE", "") for row in journal]
    if (
        any(
            row.get("_BOOT_ID") != owner["boot_id"].replace("-", "")
            or (row.get("INVOCATION_ID") or row.get("_SYSTEMD_INVOCATION_ID")) != owner["invocation_id"]
            for row in journal
        )
        or terminal not in [v.decode(message.encode()) for message in messages if message.startswith("{")]
        or "astra-" + native_name + ".service: Deactivated successfully." not in messages
    ):
        v.reject("idle-acquisition-journal")
    dependencies = v.decode(files["dependencies.before.json"])
    gcc = "/home/ubuntu/verdandi/build/tools/gcc-16.2.0"
    go = "/home/ubuntu/verdandi/build/tools/go-" + compiler + "/bin/go"
    go_sha = (
        "548d3c32f83fa81152f543eb1526be7884cfe0526eb5e9ce29d3eca14786e7e0" if upgraded else "30969f97169d7f43fe6a085873d75613adc21e30818a8c61d95bd27275df4624"
    )
    if (
        files["dependencies.before.json"] != files["dependencies.after.json"]
        or set(dependencies) != set(inputs["dependency_roots"])
        or len(dependencies) != 9
        or dependencies[go.removesuffix("/bin/go")]["bin/go"] != go_sha
    ):
        v.reject("idle-acquisition-compiler")

    def counters(text: str) -> dict[str, int]:
        """Interpret native cgroup counters without treating absent values as zero."""
        return {key: int(value) for key, value in (row.split() for row in text.splitlines())}

    if (
        owner["whole_limits"]["memory.max"] != "2147483648"
        or owner["whole_limits"]["cpu.max"] != "300000 100000"
        or terminal["whole_resources"]["memory.max"] != "2147483648"
        or any(counters(terminal["whole_resources"]["memory.events"]).values())
        or counters(terminal["whole_resources"]["pids.events"])["max"]
    ):
        v.reject("idle-acquisition-resources")
    prefix = "commands/raw-structure/structure/"
    native_root = inputs["native_root"] + "/source"
    directory = PurePosixPath(native_root) / "build/commands/raw-structure/structure"
    planned = structure.plan(directory, package=structure.STORAGE)
    if (
        [(item["id"], item["argv"][1:], item["timeout_s"]) for item in inputs["commands"]] != [(name, argv[1:], timeout) for name, argv, timeout in planned]
        or any(item["argv"][0] != go for item in inputs["commands"])
        or {name.removeprefix(prefix).removesuffix("/record.json") for name in files if name.startswith(prefix) and name.endswith("/record.json")}
        != {name for name, _, _ in planned}
        or len(terminal["records"]) != 8
    ):
        v.reject("idle-acquisition-command-inventory")
    setup = v.decode(files["commands/git-init/record.json"])
    setup_owner = v.decode(files["commands/git-init/git-init.process.json"])
    if (
        setup["argv"] != ["/usr/bin/git", "-c", "init.templateDir=", "-c", "init.defaultBranch=fixture", "init", "--quiet", native_root]
        or setup["executable_sha256"] != inputs["git_sha256"]
        or setup_owner["argv"] != setup["argv"]
        or setup_owner["cwd"] != native_root
        or setup_owner["boot_id"] != owner["boot_id"]
        or setup_owner["identity"] not in [row["identity"] for row in cleanup["retired"]]
        or setup_owner["identity"]["parent"] != owner["identity"]["pid"]
    ):
        v.reject("idle-acquisition-git")
    stream(files, "commands/git-init/", setup)
    streams, records = {}, {}
    previous = setup["finished_at"]
    for command in inputs["commands"]:
        name, identifier = command["id"], PurePosixPath(command["id"]).name
        location = prefix + name + "/"
        record, request, process, execution, before, after = (
            v.decode(files[location + item])
            for item in ("record.json", "request.json", identifier + ".process.json", "exec.native.json", "leaf.before.json", "leaf.after.json")
        )
        v.schema(record, "evidence", ("properties", "checks", "items"))
        argv = [value.replace("{root}", native_root) for value in command["argv"]]
        leaf = owner["group"] + "/" + name.replace("/", "-")
        if (
            record["id"] != identifier
            or record["argv"] != request["argv"]
            or record["argv"] != process["argv"]
            or record["argv"] != ["/usr/bin/python3", "-B", inputs["native_root"] + "/enter.py", "--enter", leaf, "--", *argv]
            or record["platform"] != structure.PLATFORM
            or request["timeout_s"] != command["timeout_s"]
            or record["duration_ms"] > command["timeout_s"] * 1000
            or not v.stamp(previous) <= v.stamp(record["started_at"]) <= v.stamp(record["finished_at"])
            or terminal["records"][len(records)]
            != {"id": name, **{key: record[key] for key in ("exit_code", "complete", "cleanup", "termination", "duration_ms")}}
            or record["environment"] != request["environment"]
            or record["resolved_environment"] != record["environment"] | {"HOME": "/home/ubuntu", "LANG": "C.UTF-8"}
            or any(
                record["resolved_environment"].get(key) != value
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
            v.reject("idle-acquisition-command")
        if any(
            record["toolchain"][tool] != {"path": gcc + "/bin/" + binary, "sha256": dependencies[gcc]["bin/" + binary]}
            or record["resolved_environment"].get(tool) != gcc + "/bin/" + binary
            for tool, binary in (("CC", "gcc"), ("CXX", "g++"))
        ):
            v.reject("idle-acquisition-compiler")
        if (
            process["cwd"] != native_root
            or process["boot_id"] != owner["boot_id"]
            or process["identity"] not in [row["identity"] for row in cleanup["retired"]]
            or process["identity"]["parent"] != owner["identity"]["pid"]
            or execution["declared_argv"] != argv
            or len(execution["observed"]) != 1
            or execution["observed"][0]["argv"] != argv
            or execution["observed"][0]["executable"] != go
            or execution["observed"][0]["cgroup"] != leaf
            or any(execution["observed"][0]["identity"][key] != process["identity"][key] for key in ("pid", "start_ticks", "parent", "session"))
        ):
            v.reject("idle-acquisition-exec")
        if (
            any(
                before[key] != value or after[key] != value
                for key, value in {
                    "memory.high": "1342177280",
                    "memory.max": "1610612736",
                    "memory.swap.max": "0",
                    "cpu.max": "200000 100000",
                    "pids.max": "256",
                }.items()
            )
            or after["cgroup.procs"]
            or counters(after["cgroup.events"])["populated"]
            or any(counters(after["memory.events"]).values())
            or counters(after["pids.events"])["max"]
        ):
            v.reject("idle-acquisition-resources")
        streams[name] = stream(files, location, record)
        if (
            request["log_bytes"] != 32 * 1024**2
            or record["stdout"]["path"] != identifier + ".stdout.log"
            or record["stderr"]["path"] != identifier + ".stderr.log"
            or record["stderr"]["bytes"]
        ):
            v.reject("idle-acquisition-stream")
        records[name] = {"record_sha256": v.digest(files[location + "record.json"]), "duration_ms": record["duration_ms"]}
        previous = record["finished_at"]
    check = inputs["full_package_check"]
    configured = next(item for item in v.decode(v.read(root / "development.json"))["checks"] if item["id"] == "storage-examples")
    if check != configured or len(check["expected_tests"]) != 259 or v.digest(v.encode(check["expected_tests"])) != BACKUP_TESTS:
        v.reject("idle-acquisition-test-declaration")
    for name in ("coverage", "typed/tests", "control/tests"):
        observed, failures = v.go_observations(streams[name], check)
        if failures:
            v.reject("idle-acquisition-tests")
        structure.terminals(streams[name], check["expected_tests"], package=structure.STORAGE)
        records[name]["observed"] = observed
    if files[prefix + "source.json"] != files["source.native.before.json"]:
        v.reject("idle-acquisition-source")
    trace, control = (v.decode(files[prefix + name + "/overlay/" + filename]) for name, filename in (("typed", "trace.json"), ("control", "flow.json")))
    source_sha = v.digest(files[prefix + "source.json"])
    for name, manifest in (("typed", trace), ("control", control)):
        report = v.decode(streams[name + "/collector"])
        if (
            report["source_sha256"] != source_sha
            or report["qualification"] != "not-evaluated"
            or manifest["files"] != [row for row in report["files"] if PurePosixPath(row["file"]).parent.as_posix() == structure.STORAGE]
        ):
            v.reject("idle-acquisition-overlay")
        overlay = v.decode(files[prefix + name + "/overlay/overlay.json"])["Replace"]
        generated = {row["file"] for row in manifest["files"]} | {structure.STORAGE + "/zz_astra_probe.go", structure.STORAGE + "/zz_astra_probe_test.go"}
        if set(overlay) != {native_root + "/" + relative for relative in generated}:
            v.reject("idle-acquisition-overlay")
        for replacement in overlay.values():
            relative = PurePosixPath(replacement).relative_to(directory)
            if relative.parts[:2] != (name, "overlay") or prefix + relative.as_posix() not in files:
                v.reject("idle-acquisition-overlay")
    ledger = structure.reconcile(
        root=root,
        source_sha256=source_sha,
        tests=check["expected_tests"],
        profiles=(files[prefix + "coverage.profile"],),
        dependency={name: files[prefix + "_dependencies/" + name] for name in structure.STORAGE_DEPENDENCIES},
        trace=trace,
        boolean_events=streams["typed/tests"],
        control=control,
        control_events=streams["control/tests"],
        package=structure.STORAGE,
        compiler=compiler,
    )
    ledger["native_profiles"] = records
    rows, processes = logic.observe(trace, streams["typed/tests"], check["package"], 259)
    if processes != 32:
        v.reject("idle-acquisition-processes")
    return ledger, trace, rows


def structural(root: Path, values: dict[str, bytes]) -> dict:
    """Recompute all current native outcome denominators after validating semantic/type provenance."""
    proof = reconcile(root, values)
    result = proof.get("current_structure")
    if result is None:
        result = outcomes(root, unpack(values[CURRENT]))
    result.update(
        {
            "sources": proof["source_bindings"],
            "application_commands": 0,
            "compiler_exports_reused": proof["compiler_exports_reused"],
            "qualification": "Current local structural outcomes only; MC/DC and whole-component/release obligations remain separate.",
        }
    )
    if "backup_supplement" in proof:
        result["backup_supplement"] = proof["backup_supplement"]
        result["current_acquisition"] = proof["current_acquisition"]
    return result


def source_guard(before: bytes, after: bytes) -> None:
    """Permit only the reviewed owner additions and comment translations, preserving every prior statement."""
    if not v.digest(before) == "7c914530e29059161f9665f867c1ce7f114cdec5c0be7bad43fdcbba3dfd0f16":
        v.reject("idle-source-projection")
    if not v.digest(after) == "1b6854d0ebf89d2d2ba16cc282794b5e3486aee542eeb54e1fe1a496eda87279":
        v.reject("idle-source-projection")
    data = after.decode()
    additions = [
        "\tcancel    context.CancelFunc // Stop the Store-owned maintenance task before closing its SQL pools.\n\tdone      <-chan struct{}    // Closed only after maintenance has released its timer and connection.\n",
        "\t// Initialization has its own deadline; recurring maintenance belongs to the returned Store's lifetime.\n\tmaintenance, cancel := context.WithCancel(context.Background())\n\tdone := make(chan struct{})\n\tstore.cancel, store.done = cancel, done\n\tgo func() {\n\t\tdefer close(done)\n\t\tstore.maintenance(maintenance)\n\t}()\n",
        "\t// Maintenance never takes life: Close can cancel and join it while admission remains exclusively closed.\n\tif store.cancel != nil {\n\t\tstore.cancel()\n\t\t<-store.done\n\t}\n",
    ]
    for addition in additions:
        if not data.count(addition) == 1:
            v.reject("idle-source-projection")
        data = data.replace(addition, "")
    # Read old comments from the authenticated source; the final comparison remains byte-for-byte.
    original = before.decode()
    translations = [
        (
            "// maintain attempts a bounded passive checkpoint at WAL pressure without truncating the reusable file.\n// Fully checkpointed retained space permits admission; incomplete or failed work remains unavailable.\n",
            r"(?m)^// maintain [^\n]+\n// [^\n]+\n(?=func \(store \*Store\) maintain\()",
        ),
        (
            "\t// Incomplete work is retried by foreground admission or the Store-owned maintenance task.\n",
            r"(?m)^\t// [^\n]+\n(?=\tvar progress struct \{)",
        ),
    ]
    for newer, pattern in translations:
        older = re.findall(pattern, original)
        if len(older) != 1 or data.count(newer) != 1:
            v.reject("idle-source-projection")
        data = data.replace(newer, older[0])
    if not data.encode() == before:
        v.reject("idle-source-projection")


def predicates(before: list, after: list, added: set, previous: dict, observed: dict) -> dict:
    """Map only ordered identical typed predicates with complete prior-vector containment."""
    mapping = {}
    for file in before:
        matches = [item for item in after if item["file"] == file["file"]]
        if len(matches) != 1:
            v.reject("idle-source-projection")
        selected = [item for item in matches[0]["decisions"] if item["id"] not in added]
        if len(file["decisions"]) != len(selected):
            v.reject("idle-source-projection")
        for first, second in zip(file["decisions"], selected):

            def shape(item: dict) -> dict:
                """Positions may move; typed Boolean structure and operand identities may not."""
                return {key: item[key] for key in ["kind", "text", "tree", "root"]} | {"atoms": [atom["text"] for atom in item["atoms"]]}

            if shape(first) != shape(second):
                v.reject("idle-source-projection")
            if not set(previous[first["id"]]) <= set(observed[second["id"]]):
                v.reject("idle-source-projection")
            if first["id"] in mapping or second["id"] in mapping.values():
                v.reject("idle-source-projection")
            mapping[first["id"]] = second["id"]
    return mapping


def project(proof: dict, oldtrace: dict, trace: dict, oldrows: dict, rows: dict) -> dict:
    """Transfer a condition only after preserving its tree and every preceding native vector."""
    old = logic.inventory(oldtrace)
    current = logic.inventory(trace)
    added = {
        identity
        for identity, item in current.items()
        if identity.startswith("polaris/internal/storage/maintenance.go:") or item["text"] == "store.cancel != nil"
    }
    if len(added) != 2 or len(old) != 160 or len(current) != 162:
        v.reject("idle-source-projection")
    mapping = predicates(oldtrace["files"], trace["files"], added, oldrows, rows)
    old_coordinates = {(identity, index) for identity, item in old.items() for index in range(len(item["atoms"]))}
    exclusions = {(item["decision"], item["condition"]) for item in proof["exclusions"]}
    if not len(old_coordinates) == proof["raw_conditions"] == 279:
        v.reject("idle-source-projection")
    if not (len(exclusions) == 8 and exclusions <= old_coordinates):
        v.reject("idle-source-projection")
    if not len(old_coordinates - exclusions) == proof["supported_conditions"] == proof["qualified_denominator"] == 271:
        v.reject("idle-source-projection")
    supported = {(mapping[identity], index) for identity, index in old_coordinates - exclusions}
    excluded = {(mapping[identity], index) for identity, index in exclusions}
    for pair in proof["new_pairs"]:
        identity = mapping[pair["decision"]]
        if any((item["values"], item["result"]) not in rows[identity] for item in pair["native_vectors"]):
            v.reject("idle-semantic-witness", pair["decision"])
    pairs = []
    for identity in sorted(added):
        item = current[identity]
        if not (len(item["atoms"]) == 1 and item["tree"] == [{"kind": "atom", "atom": 0}] and (item["root"] == 0)):
            v.reject("idle-source-projection")
        if not (("1", False) in rows[identity] and ("2", True) in rows[identity]):
            v.reject("idle-source-projection")
        supported.add((identity, 0))
        pairs.append(
            {
                "decision": identity,
                "condition": 0,
                "before": {"vector": "1", "result": False},
                "after": {"vector": "2", "result": True},
                "criterion": "single-observed-typed-atom-v1",
            }
        )
    coordinates = {(identity, index) for identity, item in current.items() for index in range(len(item["atoms"]))}
    if not (len(coordinates) == 281 and (not supported & excluded) and (coordinates == supported | excluded)):
        v.reject("idle-source-projection")
    return {
        "supported_conditions": len(supported),
        "qualified_denominator": len(coordinates - excluded),
        "raw_conditions": len(coordinates),
        "reused_conditions": len(old_coordinates - exclusions),
        "new_pairs": pairs,
        "exclusions": [{**item, "preceding_decision": item["decision"], "decision": mapping[item["decision"]]} for item in proof["exclusions"]],
        "mapping": mapping,
    }
