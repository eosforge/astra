"""Authenticate identical rollback schedules on archived faulty and current repaired Storage implementations."""

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile

from tools import consumers, entry, repair, statements, storage, storagecompiler, verify as v

PACKAGE = "github.com/eosforge/astra/polaris/internal/storage"
FIXTURE = "polaris/internal/storage/draining_test.go"
COUNTEREXAMPLE = "632a72e643fe30cfabef6cf284e1e1595403964350d99f9c089f358e3a7c30ac"
ORIGINAL = "reuse-plan/storage-draining-red-current-1/native/evidence.tar.gz"
WRITE = "reuse-plan/storage-rollback-red-current-2/native/evidence.tar.gz"
READ = "reuse-plan/storage-rollback-red-current-3/native/evidence.tar.gz"
GREEN = "reuse-plan/storage-rollback-green-current-1/native/evidence.tar.gz"
ANCESTOR = "reuse-plan/storage-binding-native-1/native/source.tar.gz"
CURRENT = "reuse-plan/storage-idle-lifecycle-current-1/native/evidence.tar.gz"
ARCHIVES = {
    **storage.ARTIFACTS,
    ORIGINAL: "204ea9fee49fa0b3d1a558a4705ff04c54f9bebf96eefd50964b0c66ee56e063",
    WRITE: "cf0aa363a8d141d3ed7db6ba6197e902429fcf4106c8333bf236d1357ef4ec7a",
    READ: "e953e599ebac2ca7a7da18b3692795257e4326335fa90bf9a66541b01908691b",
    GREEN: "d98cb93436f5776937e985b867118d715a5e2b8be72cf7223b4627f7945f640b",
    ANCESTOR: "85667b770ee11bb60d780f584cb917f1c1b2e4ee6100c2a0a2b2b444a37178bb",
    CURRENT: "1bf5bba56116c5a18bda56e994c5efbc574329936a8be0e4f4d70cfb551251f4",
}
PRODUCTION = tuple("polaris/internal/storage/" + stem + ".go" for stem in ("read", "schema", "store"))
CHECK = {
    "id": "gap-redgreen",
    "adapter": "storage-repair",
    "component": "polaris-storage",
    "argv": ["python3", "-B", "-m", "tools.rollback"],
    "environment": {"PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": "{run}/tmp"},
    "expected_tests": ["counterexamples"],
    "native_tests": ["TestDraining/read", "TestDraining/write"],
    "platforms": ["linux-amd64-cgo"],
    "probes": [{"contract": "STORAGE-ASSURANCE", "test": "counterexamples", "minimum_hits": 2}],
    "timeout_s": 120,
    "log_bytes": 1024 * 1024,
}


def configuration(check: dict) -> None:
    """Keep the native platform, two public-operation schedules and evidence-only command fixed."""
    if check != CHECK:
        v.reject("rollback-configuration")


def archive(raw: bytes, name: str) -> dict[str, bytes]:
    """Refuse unknown or altered originals before their contents can supply any product credit."""
    if name not in ARCHIVES or v.digest(raw) != ARCHIVES[name]:
        v.reject("rollback-archive-integrity")
    # The original source-only baseline predates member manifests; its reviewed archive digest binds every byte.
    if name in {ORIGINAL, ANCESTOR}:
        return entry.unpack(raw)
    return consumers.unpack(raw, ARCHIVES[name])


def cases(frames: list[dict], modes: tuple[str, ...], status: str) -> None:
    """Require complete native terminals and the precise defect or drained-resource observation."""
    if not modes or len(set(modes)) != len(modes) or set(modes) - {"read", "write"} or status not in {"pass", "fail"}:
        v.reject("rollback-case-inventory")
    expected = {"TestDraining", *("TestDraining/" + mode for mode in modes)}
    if not frames or any(
        row.get("Package") != PACKAGE
        or row.get("Action") not in {"start", "run", "output", "pass", "fail"}
        or row.get("Action") in ({"pass", "fail"} - {status})
        for row in frames
    ):
        v.reject("rollback-case-package-or-status")
    runs = [row["Test"] for row in frames if row.get("Action") == "run" and "Test" in row]
    finished = [row["Test"] for row in frames if row.get("Action") == status and "Test" in row]
    if set(runs) != expected or len(runs) != len(expected) or sorted(runs) != sorted(finished):
        v.reject("rollback-case-incomplete")
    if sum(row.get("Action") == status and "Test" not in row for row in frames) != 1:
        v.reject("rollback-package-incomplete")
    marker = "STORAGE-ROLLBACK-NOT-DRAINED" if status == "fail" else "STORAGE-DRAINED"
    marked = [row for row in frames if marker in row.get("Output", "")]
    if len(marked) != len(modes):
        v.reject("rollback-case-observation-count")
    for mode in modes:
        selected = [row for row in marked if row.get("Test") == "TestDraining/" + mode]
        if len(selected) != 1 or selected[0].get("Action") != "output":
            v.reject("rollback-case-attribution")
        error = "almanac storage unavailable" if mode == "write" else "sql: transaction has already been committed or rolled back"
        resources = "error=" + error + " in_use=1" if status == "fail" else "rollback=1 in_use=0 writer=0 opened=1 closed=1"
        pattern = re.compile(r"\s*(?:[^\n]+\.go:\d+: )?" + re.escape(marker + " mode=" + mode + " " + resources) + r"\n")
        if not pattern.fullmatch(selected[0]["Output"]):
            v.reject("rollback-case-resources-or-reason")


def native(files: dict[str, bytes], prefix: str, *, failed: bool = False) -> tuple[dict, dict, list, dict]:
    """Preserve the known failed write observer while authenticating its complete expected-red child."""
    inputs, owner, terminal, cleanup = (v.decode(files[name]) for name in ("inputs.json", "controller.json", "terminal.json", "cleanup.native.json"))
    source = entry.unpack(files["source.tar.gz"])
    expected = 1 if failed else 0
    service = cleanup["unit"]
    if (
        v.digest(files["source.tar.gz"]) != inputs["source_archive_sha256"]
        or {name: v.digest(data) for name, data in source.items()} != inputs["files"]
        or {row["path"]: row["sha256"] for row in inputs["source"]["files"] if row["sha256"] is not None} != inputs["files"]
        or v.digest(files["run.py"]) != owner["script_sha256"]
        or owner["script_sha256"] != inputs["run_sha256"]
        or owner["inputs_sha256"] != v.digest(files["inputs.json"])
        or owner["boot_id"] != cleanup["boot_id"]
        or owner["boot_id"] != inputs["boot_id"]
        or terminal["errors"] != (["AssertionError: "] if failed else [])
        or terminal["interrupted"] is not False
        or terminal["remaining_owned"]
        or terminal["cache_restored"] is not True
        or service["MainPID"] != "0"
        or service["ControlGroup"]
        or service["InvocationID"] not in ("", owner["invocation_id"])
        or service["ExecMainStatus"] != str(expected)
        or cleanup["original_exit_code"] != expected
        or cleanup["source_verified"] != len(source)
        or cleanup["cache_inode"] != 713912
        or len(inputs["auxiliary"]) != 1
        or inputs["selections"]
    ):
        v.reject("rollback-native-inputs-or-outcome")
    mirror, handed, returned = (v.decode(files[name]) for name in ("git-mirror.native.json", "cache-handoff.native.json", "cache-restored.native.json"))
    if (
        mirror["origin_source"] != inputs["source"]
        or {row["path"]: row["sha256"] for row in mirror["source"]["files"]} != inputs["files"]
        or handed["inode"] != 713912
        or returned["inode"] != 713912
        or returned["path"] != handed["from"]
        or returned["remaining_owned"]
        or handed["to"] != owner["cwd"] + "/source/build/cache/go"
    ):
        v.reject("rollback-native-mirror-or-cache")
    active = [name for name in files if name.startswith(prefix) and name.endswith(".process.json")]
    if len(active) != 1:
        v.reject("rollback-native-child")
    process = v.decode(files[active[0]])
    record, frames = repair.command(files, prefix, 0 if prefix.endswith("after/") else 1)
    spec = inputs["auxiliary"][0]
    if (
        process["boot_id"] != owner["boot_id"]
        or process["identity"]["parent"] != owner["identity"]["pid"]
        or cleanup["retired"] != [owner["identity"], process["identity"]]
        or owner["identity"]["pid"] == process["identity"]["pid"]
        or not all(str(item["start_ticks"]).isdigit() and isinstance(item["pid"], int) and item["pid"] > 0 for item in cleanup["retired"])
        or process["argv"] != record["argv"]
        or process["cwd"] != owner["cwd"] + "/source"
        or record["argv"] != spec["argv"]
        or record["environment"] != spec["environment"]
        or record["id"] != spec["id"]
        or v.stamp(record["finished_at"]) > v.stamp(terminal["at"])
    ):
        v.reject("rollback-native-child-binding")
    journal = [v.decode(row) for row in files["journal.native.jsonl"].splitlines()]
    unit = "astra-" + PurePosixPath(owner["cwd"]).name + ".service"
    if (
        not journal
        or any(
            row.get("_BOOT_ID") != owner["boot_id"].replace("-", "")
            or (row.get("INVOCATION_ID") or row.get("_SYSTEMD_INVOCATION_ID")) != owner["invocation_id"]
            for row in journal
        )
        or sum(row.get("MESSAGE", "").startswith("Started " + unit + " - ") for row in journal) != 1
        or [v.decode(row["MESSAGE"]) for row in journal if row.get("MESSAGE", "").startswith('{"at":')] != [terminal]
        or not any(("status=1/" in row.get("MESSAGE", "")) if failed else row.get("MESSAGE") == unit + ": Deactivated successfully." for row in journal)
    ):
        v.reject("rollback-native-journal")
    return source, record, frames, owner


def binding(root: Path, source: dict[str, bytes], expected: dict[str, str]) -> None:
    """Compare the compiler-proven full owned closure, including tests and module dependencies."""
    if not expected:
        v.reject("rollback-source-empty")
    for name, sha in expected.items():
        if name not in source or v.digest(source[name]) != sha or v.read(v.inside(root, name)) != source[name]:
            v.reject("rollback-current-source-drift", name)


def overlay(files: dict[str, bytes], owner: dict, before: dict[str, bytes]) -> dict[str, str]:
    """Require all three retained historical files and only their exact compiler overlay replacements."""
    directory = owner["cwd"] + "/source"
    names = {name: "source/build/storage-before/" + PurePosixPath(name).name for name in PRODUCTION}
    expected = {directory + "/" + name: owner["cwd"] + "/" + path for name, path in names.items()}
    if v.decode(files["source/build/storage-before/overlay.json"]) != {"Replace": expected}:
        v.reject("rollback-overlay-inventory")
    if any(name not in before or files.get(path) != before[name] for name, path in names.items()):
        v.reject("rollback-overlay-source")
    return {name: v.digest(before[name]) for name in names}


def environment(record: dict, owner: dict) -> dict:
    """Normalize only owned run roots; every other admitted runtime and toolchain input must match."""
    root = owner["cwd"] + "/source"
    command = root + "/build/commands/" + record["id"]
    result = {key: value.replace(command, "{run}").replace(root, "{root}") for key, value in record["resolved_environment"].items()}
    if any(
        result.get(key) != value
        for key, value in {
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
            "GOFLAGS": "-mod=readonly",
            "CGO_ENABLED": "1",
            "GOCACHE": "{root}/build/cache/go",
            "TMPDIR": "{run}/tmp",
        }.items()
    ):
        v.reject("rollback-environment-boundary")
    return result


def historical(root: Path, artifacts: dict[str, bytes]) -> dict:
    """Keep the original complete qualification and identical native before/after schedules unchanged."""
    qualified = storage.reconcile(root, {name: artifacts[name] for name in storage.ARTIFACTS})
    before = entry.unpack(archive(artifacts[ORIGINAL], ORIGINAL)["source.tar.gz"])
    bindings = qualified["sources"]
    sources, records, observations, owners = {}, {}, {}, {}
    for name, suffix, failed, modes, status in (
        (WRITE, "before", True, ("write",), "fail"),
        (READ, "before", False, ("read",), "fail"),
        (GREEN, "after", False, ("read", "write"), "pass"),
    ):
        files = archive(artifacts[name], name)
        source, record, frames, owner = native(files, "source/build/commands/storage-rollback-" + suffix + "/", failed=failed)
        binding(root, source, bindings)
        if v.digest(source[FIXTURE]) != COUNTEREXAMPLE:
            v.reject("rollback-counterexample-source")
        cases(frames, modes, status)
        expected = [
            "go",
            "test",
            "-json",
            "-race",
            "-count=1",
            "-parallel=1",
            "-p=2",
            "-timeout=30s",
            "-run=" + ("^TestDraining$/^read$" if name == READ else "^TestDraining$"),
        ]
        if suffix == "before":
            expected.append("-overlay=" + owner["cwd"] + "/source/build/storage-before/overlay.json")
            old = overlay(files, owner, before)
        expected.append("./polaris/internal/storage")
        if record["argv"] != expected:
            v.reject("rollback-command-schedule")
        sources[name], records[name], owners[name] = source, record, owner
        observations[name] = {
            "command_exit_code": record["exit_code"],
            "duration_ms": record["duration_ms"],
            "record_sha256": v.digest(files["source/build/commands/storage-rollback-" + suffix + "/record.json"]),
            "runner_exit_code": 1 if failed else 0,
            "cases": ["TestDraining/" + mode for mode in modes],
        }
    if any(
        environment(records[name], owners[name]) != environment(records[GREEN], owners[GREEN]) or records[name]["toolchain"] != records[GREEN]["toolchain"]
        for name in (WRITE, READ)
    ):
        v.reject("rollback-execution-environment-drift")
    if any(before[name] == sources[GREEN][name] for name in PRODUCTION):
        v.reject("rollback-production-pair")
    return {
        "version": 1,
        "trust": "local",
        "cases": ["TestDraining/read", "TestDraining/write"],
        "counterexample_sha256": COUNTEREXAMPLE,
        "before": old,
        "after": {name: bindings[name] for name in PRODUCTION},
        "bindings": bindings,
        "native": observations,
        "archives": ARCHIVES,
        "new_application_commands": 0,
        "boundary": "Two identical controlled public-operation counterexamples under the same native Race toolchain and normalized admitted environment. The historical write observer remains failed; only its complete expected-red child is reused. Exact generated historical files and overlay maps are retained. Current complete compiler-owned source qualification is independently reused. No generic defect-freedom, protected CI or release claim.",
    }


@contextmanager
def ancestor(root: Path, artifacts: dict[str, bytes]) -> Iterator[Path]:
    """Interpret the original structural proof against its actual frozen source, never a rewritten workspace."""
    from tools import idle

    if not idle.current(root):
        yield root
        return
    source = archive(artifacts[ANCESTOR], ANCESTOR)
    if len(source) != 969:
        v.reject("rollback-ancestor-inventory")
    idle.source_guard(source[idle.STORE], v.read(root / idle.STORE))
    directory = root / "build/tmp"
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rollback-ancestor-", dir=directory) as temporary:
        shadow = Path(temporary)
        for name, data in source.items():
            path = v.inside(shadow, name)
            path.parent.mkdir(parents=True, exist_ok=True)
            v.write_new(path, data)
        yield shadow


def current(root: Path, artifacts: dict[str, bytes], prior: dict) -> dict:
    """Require actual current Race draining, identical causal code and every current compiled/oracle input."""
    from tools import draining

    files = archive(artifacts[CURRENT], CURRENT)
    name = PurePosixPath(CURRENT).parts[1]
    commands = ("storage-lifecycle", "storage-termination", "storage-draining", "storage-borrowing", "lifecycle-reader-controls")
    source, records, outputs = consumers.native(files, name, commands=commands, collected=True)
    previous = entry.unpack(archive(artifacts[GREEN], GREEN)["source.tar.gz"])
    consumers.sources(previous, source)
    check = next(item for item in v.decode(v.read(root / "development.json"))["checks"] if item["id"] == "storage-draining")
    inputs = v.decode(files["inputs.json"])
    if check != next(item for item in inputs["selections"] if item["id"] == "storage-draining") or v.digest(source[FIXTURE]) != COUNTEREXAMPLE:
        v.reject("rollback-current-counterexample")
    consumers.cases(outputs["storage-draining"], PACKAGE, check["expected_tests"])
    if draining.observations(outputs["storage-draining"], check, root) != {"STORAGE-DRAINING": 2}:
        v.reject("rollback-current-history")
    names = set(prior["bindings"]) | {path for path in source if PurePosixPath(path).parent.as_posix() == "polaris/internal/storage" and path.endswith(".go")}
    names |= {path for path in source if path.startswith("polaris/internal/storage/testdata/")} | {"dependencies.lock.json"}
    actual = {path.relative_to(root).as_posix() for path in (root / "polaris/internal/storage").glob("*.go")}
    if actual != {path for path in names if PurePosixPath(path).parent.as_posix() == "polaris/internal/storage" and path.endswith(".go")}:
        v.reject("rollback-current-source-inventory")
    bindings = {path: v.digest(source[path]) for path in names}
    binding(root, source, bindings)
    record = records["storage-draining"]
    return {
        "archive_sha256": ARCHIVES[CURRENT],
        "bindings": bindings,
        "fixture_sha256": COUNTEREXAMPLE,
        "cases": ["TestDraining/read", "TestDraining/write"],
        "command_exit_code": record["exit_code"],
        "duration_ms": record["duration_ms"],
        "argv": record["argv"],
        "GOMAXPROCS": record["resolved_environment"]["GOMAXPROCS"],
        "boundary": "Current-source extension uses the declared 60-second host timeout and four Go processors. The unchanged historical same-environment causal pair remains separately required; neither environment is rewritten into the other.",
    }


def renewal(root: Path, artifacts: dict[str, bytes], prior: dict) -> dict:
    """Retain the original causal pair and authenticate the exact current ordinary/Race draining extension."""
    from tools import qualificationdata

    files = qualificationdata.unpack(artifacts[storagecompiler.RACE])
    observed = storagecompiler.race_profiles(root, files)
    source = entry.unpack(files["source.tar.gz"])
    historical = archive(artifacts[CURRENT], CURRENT)
    commands = ("storage-lifecycle", "storage-termination", "storage-draining", "storage-borrowing", "lifecycle-reader-controls")
    previous, records, outputs = consumers.native(historical, PurePosixPath(CURRENT).parts[1], commands=commands, collected=True)
    causal = entry.unpack(archive(artifacts[GREEN], GREEN)["source.tar.gz"])
    consumers.sources(causal, previous)
    cases(statements.stream(outputs["storage-draining"]), ("read", "write"), "pass")
    if v.digest(source[FIXTURE]) != COUNTEREXAMPLE or any(source[name] != previous[name] for name in (*PRODUCTION, FIXTURE)):
        v.reject("rollback-renewed-causal-source")
    # New package/oracle additions are authenticated by the complete current compiler receipt, not silently ignored.
    compiled = previous | source
    names = set(prior["bindings"]) | set(source) - {".gitignore"}
    bindings = {name: v.digest(compiled[name]) for name in names}
    binding(root, compiled, bindings)
    profiles = {}
    package = {PACKAGE: {"TestDraining/read", "TestDraining/write"}}
    for profile in ("ordinary", "race"):
        prefix = "commands/" + profile + "/"
        record = v.decode(files[prefix + "record.json"])
        output = files[prefix + record["stdout"]["path"]]
        selected = repair.project(output, package)
        cases(selected, ("read", "write"), "pass")
        execution = v.decode(files[prefix + "exec.native.json"])
        profiles[profile] = {
            "record_sha256": observed["profiles"][profile]["record_sha256"],
            "argv": execution["declared_argv"],
            "GOMAXPROCS": record["resolved_environment"]["GOMAXPROCS"],
            "duration_ms": record["duration_ms"],
            "cases": prior["cases"],
        }
    return {
        "archive_sha256": storagecompiler.RACE_SHA,
        "compiler": "1.27.2",
        "bindings": bindings,
        "fixture_sha256": COUNTEREXAMPLE,
        "cases": prior["cases"],
        "profiles": profiles,
        "previous": {
            "archive_sha256": ARCHIVES[CURRENT],
            "argv": records["storage-draining"]["argv"],
            "GOMAXPROCS": records["storage-draining"]["resolved_environment"]["GOMAXPROCS"],
        },
        "boundary": "The original same-environment defect pair and later four-processor lifecycle extension retain their actual identities. Current Go 1.27.2 uses both complete 259-case two-processor profiles and the same two causal histories; no direct four-processor command or new red run is inferred.",
    }


def reconcile(root: Path, artifacts: dict[str, bytes] | None = None) -> dict:
    """Join original causal counterexamples and the independently collected current ownership extension."""
    from tools import idle

    upgraded = storagecompiler.upgraded(root)
    expected = ARCHIVES | {storagecompiler.RACE: storagecompiler.RACE_SHA} if upgraded else ARCHIVES
    if artifacts is None:
        artifacts = {name: v.read(root / "build/results/assurance" / name, 64 * 1024**2) for name in expected}
    if set(artifacts) != set(expected) or any(v.digest(raw) != expected[name] for name, raw in artifacts.items()):
        v.reject("rollback-artifact-inventory")
    with ancestor(root, artifacts) as shadow:
        result = historical(shadow, artifacts)
    if idle.current(root):
        extension = renewal(root, artifacts, result) if upgraded else current(root, artifacts, result)
        result.update(
            version=2,
            historical_after=result["after"],
            after={path: extension["bindings"][path] for path in PRODUCTION},
            bindings=extension["bindings"],
            current=extension,
            archives=expected,
        )
    return result


def observations(data: bytes, check: dict, root: Path) -> tuple[dict, list]:
    """Recompute from authentic native channels before accepting any assembled repair summary."""
    configuration(check)
    try:
        actual = reconcile(root)
    except (OSError, KeyError, TypeError, ValueError) as error:
        v.reject("rollback-facts-unavailable", type(error).__name__)
    if v.decode(data) != actual:
        v.reject("rollback-observation-mismatch")
    return {"STORAGE-ASSURANCE": len(actual["cases"])}, []


def main() -> int:
    """Emit source-bound interpretation while preserving every original expected-red exit code."""
    try:
        if len(sys.argv) != 1:
            v.reject("rollback-arguments")
        print(v.encode(reconcile(Path.cwd())).decode(), end="")
        return 0
    except (v.Invalid, OSError, KeyError, TypeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
