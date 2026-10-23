"""Rebind unchanged Storage proofs to authenticated current compiler execution without changing their obligations."""

import copy
from pathlib import Path, PurePosixPath
import tempfile

from tools import entry, idle, logic, structure, verify as v

ACQUISITION = "reuse-plan/go-upgrade-storage-structure-current-2/evidence.tar.gz"
ACQUISITION_SHA = "294ef8ed6b28167f1dd5d9213af4891e3774d6f16853db279d19c8259792be10"
RACE = "reuse-plan/go-upgrade-storage-race-current-2/evidence.tar.gz"
RACE_SHA = "53adc26d9f38322ab70404dcc0d55ee61d2bf2fe81d1faa1cadf9b1ad5e2f668"
ARTIFACTS = {ACQUISITION: ACQUISITION_SHA, RACE: RACE_SHA}
GO = "/home/ubuntu/verdandi/build/tools/go-1.27.2/bin/go"
GO_SHA = "548d3c32f83fa81152f543eb1526be7884cfe0526eb5e9ce29d3eca14786e7e0"
DEPENDENCIES_SHA = "dd1042b7acb3a51f6b0090b68cff0c5f072940262898fa309a8ff951a5a47f23"
SCANNER_SHA = "63f270944289ac68e552cc224c9182a6b6b85f6139c0fc328ea41a42f827e2e6"
PREFIX = "commands/raw-structure/structure/"


def upgraded(root: Path) -> bool:
    """Select the actual declared compiler; unfamiliar versions cannot fall back to historical credit."""
    policy = v.decode(v.read(root / "development.json"))
    check = next(item for item in policy["checks"] if item["id"] == "storage-examples")
    path = check.get("environment", {}).get("PATH", "")
    versions = [version for version in ("1.27.1", "1.27.2") if "/go-" + version + "/bin:" in path]
    if len(versions) != 1:
        v.reject("storage-compiler-policy")
    return versions[0] == "1.27.2"


def artifacts(root: Path) -> dict[str, bytes]:
    """Read only the exact current native records after compiler selection."""
    result = {name: v.read(v.inside(root / "build/results/assurance", name), 32 * 1024**2) for name in ARTIFACTS}
    if any(v.digest(result[name]) != sha for name, sha in ARTIFACTS.items()):
        v.reject("storage-compiler-artifact")
    return result


def review(root: Path, original: dict[str, bytes], names: set[str]) -> dict[str, str]:
    """Bind retained semantic inputs to the fixed current compiler acquisition, without granting new mutation or coverage observations."""
    raw = v.read(root / "build/results/assurance" / ACQUISITION, 32 * 1024**2)
    if not upgraded(root) or v.digest(raw) != ACQUISITION_SHA:
        v.reject("storage-compiler-review-acquisition")
    files = entry.unpack(raw)
    receipt(root, files)
    current = entry.unpack(files["source.tar.gz"])
    package = structure.STORAGE + "/"
    previous = {name for name in original if name.startswith(package) and name.endswith(".go")}
    compiled = {name for name in current if name.startswith(package) and name.endswith(".go")}
    additions = compiled - previous
    if previous - compiled or additions - {package + "backup_test.go", package + "compatibility_test.go"}:
        v.reject("storage-compiler-review-inventory")
    if not previous <= names or not {"go.mod", "go.sum"} <= names or not names <= original.keys():
        v.reject("storage-compiler-review-inputs")
    result = {}
    for name in sorted(names):
        before = original[name]
        after = current[name] if name in current else v.read(v.inside(root, name))
        if name == "go.mod":
            valid = before.count(b"golang.org/x/net v0.59.0") == 1 and before.replace(b"golang.org/x/net v0.59.0", b"golang.org/x/net v0.60.0") == after
        elif name == "go.sum":
            old, new = (body.splitlines() for body in (before, after))
            valid = [line for line in old if not line.startswith(b"golang.org/x/net ")] == [line for line in new if not line.startswith(b"golang.org/x/net ")]
            valid = valid and all(len([line for line in lines if line.startswith(b"golang.org/x/net ")]) == 2 for lines in (old, new))
            valid = (
                valid
                and len([line for line in old if line.startswith(b"golang.org/x/net v0.59.0 ") or line.startswith(b"golang.org/x/net v0.59.0/go.mod ")]) == 2
            )
            valid = (
                valid
                and len([line for line in new if line.startswith(b"golang.org/x/net v0.60.0 ") or line.startswith(b"golang.org/x/net v0.60.0/go.mod ")]) == 2
            )
        elif name in {package + "numeric.json", package + "numeric_linux_amd64_test.go"}:
            valid = before.count(b"go1.27.1") == 1 and before.replace(b"go1.27.1", b"go1.27.2") == after
        else:
            valid = before == after
        if not valid:
            v.reject("storage-compiler-review-delta", name)
        result[name] = v.digest(after)
    result.update({name: v.digest(current[name]) for name in additions})
    return result


def receipt(root: Path, files: dict[str, bytes], *, race: bool = False) -> tuple[dict, dict, dict]:
    """Validate the same complete compilation, dependency, lifetime and physical-resource boundary for both current campaigns."""
    inputs, owner, cleanup, terminal = (v.decode(files[name]) for name in ("inputs.json", "owner.json", "cleanup.native.json", "terminal.json"))
    source = entry.unpack(files["source.tar.gz"])
    collectors = {path.relative_to(root).as_posix() for path in (root / "tools/decisions").iterdir() if path.name.endswith((".go", ".go.in"))}
    expected = (
        {path.relative_to(root).as_posix() for path in (root / structure.STORAGE).rglob("*") if path.is_file()}
        | collectors
        | {".gitignore", "go.mod", "go.sum", "dependencies.lock.json"}
    )
    native_name = "go-upgrade-storage-race-native-current-2" if race else "go-upgrade-storage-structure-native-current-2"
    if (
        len(source) != 78
        or set(source) != expected
        or source[".gitignore"] != b"build/\n"
        or {name: v.digest(data) for name, data in source.items()} != inputs["files"]
        or v.digest(files["source.tar.gz"]) != inputs["source_archive_sha256"]
        or any(v.file_digest(root / name) != sha for name, sha in inputs["files"].items() if name != ".gitignore")
        or inputs["native_root"] != "/home/ubuntu/verdandi/astra/build/results/assurance/" + native_name
        or files["source.native.before.json"] != files["source.native.after.json"]
        or files["git.native.HEAD"] != b"ref: refs/heads/fixture\n"
        or b"[remote " in files["git.native.config"]
    ):
        v.reject("storage-compiler-source")
    actual = v.decode(files["source.native.before.json"])
    if actual["commit"] is not None or {row["path"]: row["sha256"] for row in actual["files"]} != inputs["files"]:
        v.reject("storage-compiler-source")
    if (
        owner["inputs_sha256"] != v.digest(files["inputs.json"])
        or owner["script_sha256"] != inputs["driver_sha256"]
        or inputs["driver_sha256"] != v.digest(files["run.py"])
        or inputs["enter_sha256"] != v.digest(files["enter.py"])
        or inputs["variant_files"] != {"expected-dependencies.json": DEPENDENCIES_SHA, "streamhash.py": SCANNER_SHA}
        or any(v.digest(files[name]) != sha for name, sha in inputs["variant_files"].items())
        or files["dependencies.before.json"] != files["dependencies.after.json"]
        or v.decode(files["dependencies.before.json"]) != v.decode(files["expected-dependencies.json"])
    ):
        v.reject("storage-compiler-inputs")
    dependencies = v.decode(files["dependencies.before.json"])
    if set(dependencies) != set(inputs["dependency_roots"]) or len(dependencies) != 9 or dependencies[GO.removesuffix("/bin/go")]["bin/go"] != GO_SHA:
        v.reject("storage-compiler-dependencies")
    if (
        cleanup["boot_id"] != owner["boot_id"]
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
        or len(cleanup["retired"]) != (5 if race else 10)
        or cleanup["retired"][0]["identity"] != owner["identity"]
        or any(row["status"] not in {"absent", "reused"} or row["current_start_ticks"] == row["identity"]["start_ticks"] for row in cleanup["retired"])
    ):
        v.reject("storage-compiler-owner")
    journal = v.decode(files["journal.native.json"])
    if (
        any(
            row.get("_BOOT_ID") != owner["boot_id"].replace("-", "")
            or (row.get("INVOCATION_ID") or row.get("_SYSTEMD_INVOCATION_ID")) != owner["invocation_id"]
            for row in journal
        )
        or terminal not in [v.decode(row["MESSAGE"].encode()) for row in journal if row.get("MESSAGE", "").startswith("{")]
        or "astra-" + native_name + ".service: Deactivated successfully." not in [row.get("MESSAGE") for row in journal]
    ):
        v.reject("storage-compiler-journal")
    for name, limits in (
        ("whole_limits", {"memory.high": "1879048192", "memory.max": "2147483648", "cpu.max": "300000 100000", "pids.max": "2048"}),
        ("controller_limits", {"memory.high": "402653184", "memory.max": "469762048", "cpu.max": "100000 100000", "pids.max": "32"}),
    ):
        limits["memory.swap.max"] = "0"
        if any(state[key] != value for state in (owner[name], terminal[name.replace("_limits", "_resources")]) for key, value in limits.items()):
            v.reject("storage-compiler-resources")
    for name in ("whole_resources", "controller_resources"):
        if any(int(value) for field in ("memory.events", "pids.events") for _, value in (line.split() for line in terminal[name][field].splitlines())):
            v.reject("storage-compiler-resources")
    handed, returned = (v.decode(files[name]) for name in ("cache-handoff.json", "cache-return.json"))
    if (
        handed["from"] != inputs["cache"]
        or handed["to"] != inputs["native_root"] + "/source/build/cache/go"
        or returned["path"] != inputs["cache"]
        or handed["inode"] != returned["inode"]
        or returned["inode"] != 713912
        or handed["device"] != returned["device"]
        or returned["device"] != 64512
        or returned["remaining_owned"]
    ):
        v.reject("storage-compiler-cache")
    setup, process = (v.decode(files["commands/git-init/" + name]) for name in ("record.json", "git-init.process.json"))
    if (
        setup["argv"] != ["/usr/bin/git", "-c", "init.templateDir=", "-c", "init.defaultBranch=fixture", "init", "--quiet", inputs["native_root"] + "/source"]
        or setup["executable_sha256"] != inputs["git_sha256"]
        or process["argv"] != setup["argv"]
        or process["cwd"] != inputs["native_root"] + "/source"
        or process["boot_id"] != owner["boot_id"]
        or process["identity"] not in [row["identity"] for row in cleanup["retired"]]
        or process["identity"]["parent"] != owner["identity"]["pid"]
    ):
        v.reject("storage-compiler-git")
    idle.stream(files, "commands/git-init/", setup)
    return inputs, owner, cleanup


def race_profiles(root: Path, files: dict[str, bytes]) -> dict:
    """Require both exact 259-case current-runtime profiles and bind the separate compile prerequisite."""
    inputs, owner, cleanup = receipt(root, files, race=True)
    check = next(row for row in v.decode(v.read(root / "development.json"))["checks"] if row["id"] == "storage-examples")
    ordinary = [GO, *check["argv"][1:]]
    plans = [
        (
            "compile-race",
            [GO, "test", "-race", "-c", "-p=2", "-o", inputs["native_root"] + "/source/build/commands/compile-race/storage.test", "./" + structure.STORAGE],
            300,
        ),
        ("ordinary", ordinary, 240),
        ("race", ordinary[:3] + ["-race"] + ordinary[3:], 300),
    ]
    if (
        inputs["full_package_check"] != check
        or len(check["expected_tests"]) != 259
        or v.digest(v.encode(check["expected_tests"])) != idle.BACKUP_TESTS
        or [(row["id"], row["argv"], row["timeout_s"]) for row in inputs["commands"]] != plans
    ):
        v.reject("storage-compiler-race-plan")
    expected_records = {"commands/git-init/record.json"} | {"commands/" + name + "/record.json" for name, _, _ in plans}
    if {name for name in files if name.endswith("/record.json")} != expected_records:
        v.reject("storage-compiler-race-plan")
    setup = v.decode(files["commands/git-init/record.json"])
    idle.stream(files, "commands/git-init/", setup)
    if setup["executable_sha256"] != inputs["git_sha256"] or setup["argv"] != [
        "/usr/bin/git",
        "-c",
        "init.templateDir=",
        "-c",
        "init.defaultBranch=fixture",
        "init",
        "--quiet",
        inputs["native_root"] + "/source",
    ]:
        v.reject("storage-compiler-race-owner")
    binary = files.get("commands/compile-race/storage.test")
    if not isinstance(binary, bytes) or not binary.startswith(b"\x7fELF"):
        v.reject("storage-compiler-race-compile")
    streams = {}
    previous = setup["finished_at"]
    terminal = v.decode(files["terminal.json"])
    if len(terminal["records"]) != 3:
        v.reject("storage-compiler-race-plan")
    dependencies = v.decode(files["dependencies.before.json"])
    for index, (name, argv, timeout) in enumerate(plans):
        prefix = "commands/" + name + "/"
        record, request, process, execution, before, after = (
            v.decode(files[prefix + item])
            for item in ("record.json", "request.json", name + ".process.json", "exec.native.json", "leaf.before.json", "leaf.after.json")
        )
        v.schema(record, "evidence", ("properties", "checks", "items"))
        leaf = owner["group"] + "/" + name
        if (
            record["id"] != name
            or record["argv"] != request["argv"]
            or record["argv"] != process["argv"]
            or record["argv"] != ["/usr/bin/python3", "-B", inputs["native_root"] + "/enter.py", "--enter", leaf, "--", *argv]
            or request["timeout_s"] != timeout
            or record["duration_ms"] > timeout * 1000
            or request["log_bytes"] != 16 * 1024**2
            or not v.stamp(previous) <= v.stamp(record["started_at"]) <= v.stamp(record["finished_at"])
            or record["environment"] != request["environment"]
            or record["resolved_environment"] != record["environment"] | {"HOME": "/home/ubuntu", "LANG": "C.UTF-8"}
            or any(
                record["environment"].get(key) != value
                for key, value in {
                    "PATH": GO.removesuffix("/go") + ":/home/ubuntu/verdandi/build/tools/gcc-16.2.0/bin:/usr/bin:/bin",
                    "GOMAXPROCS": "2",
                    "GOFLAGS": "-mod=readonly",
                    "CGO_ENABLED": "1",
                    "GOPROXY": "off",
                    "GOSUMDB": "off",
                    "GOTOOLCHAIN": "local",
                    "GOWORK": "off",
                    "GOCACHE": inputs["native_root"] + "/source/build/cache/go",
                    "GOMODCACHE": "/home/ubuntu/verdandi/build/deps/go/pkg/mod",
                    "GOPATH": "/home/ubuntu/verdandi/build/deps/go",
                    "TMPDIR": inputs["native_root"] + "/source/build/commands/" + name + "/tmp",
                    "LD_LIBRARY_PATH": "/home/ubuntu/verdandi/build/tools/gcc-16.2.0/lib64",
                }.items()
            )
        ):
            v.reject("storage-compiler-race-command")
        if terminal["records"][index] != {"id": name, **{key: record[key] for key in ("exit_code", "complete", "cleanup", "termination", "duration_ms")}}:
            v.reject("storage-compiler-race-command")
        compiler = "/home/ubuntu/verdandi/build/tools/gcc-16.2.0"
        if any(
            record["toolchain"][tool] != {"path": compiler + "/bin/" + binary, "sha256": dependencies[compiler]["bin/" + binary]}
            or record["environment"].get(tool) != compiler + "/bin/" + binary
            for tool, binary in (("CC", "gcc"), ("CXX", "g++"))
        ):
            v.reject("storage-compiler-race-compiler")
        if (
            process["cwd"] != inputs["native_root"] + "/source"
            or process["boot_id"] != owner["boot_id"]
            or process["identity"] not in [row["identity"] for row in cleanup["retired"]]
            or process["identity"]["parent"] != owner["identity"]["pid"]
        ):
            v.reject("storage-compiler-race-owner")
        if (
            execution["declared_argv"] != argv
            or len(execution["observed"]) != 1
            or execution["observed"][0]["argv"] != argv
            or execution["observed"][0]["executable"] != GO
            or execution["observed"][0]["cgroup"] != leaf
            or any(execution["observed"][0]["identity"][key] != process["identity"][key] for key in ("pid", "start_ticks", "parent", "session"))
        ):
            v.reject("storage-compiler-race-exec")
        if (
            any(
                state[key] != value
                for state in (before, after)
                for key, value in {
                    "memory.high": "1342177280",
                    "memory.max": "1610612736",
                    "memory.swap.max": "0",
                    "cpu.max": "200000 100000",
                    "pids.max": "256",
                }.items()
            )
            or after["cgroup.procs"]
            or any(int(value) for field in ("memory.events", "pids.events") for _, value in (line.split() for line in after[field].splitlines()))
        ):
            v.reject("storage-compiler-race-resources")
        output = idle.stream(files, prefix, record)
        if (
            record["stdout"]["path"] != name + ".stdout.log"
            or record["stderr"]["path"] != name + ".stderr.log"
            or record["stderr"]["bytes"]
            or record["stdout"]["bytes"] > 16 * 1024**2
        ):
            v.reject("storage-compiler-race-stream")
        if name != "compile-race":
            streams[name] = output, v.digest(files[prefix + "record.json"])
        previous = record["finished_at"]
    # Reject incomplete metadata before decoding either large native test stream.
    profiles = {}
    for name, (output, digest) in streams.items():
        hits, failures = v.go_observations(output, check)
        structure.terminals(output, check["expected_tests"], package=structure.STORAGE)
        if failures:
            v.reject("storage-compiler-race-tests")
        profiles[name] = {"tests": 259, "observed": hits, "record_sha256": digest}
    return {
        "archive": RACE,
        "archive_sha256": RACE_SHA,
        "compiler": "1.27.2",
        "profiles": profiles,
        "compile_sha256": v.digest(binary),
        "current_cases": 259,
        "new_structure_or_mcdc_hits": 0,
    }


def reconcile(root: Path, values: dict[str, bytes]) -> dict:
    """Replay the exact legacy proof, then require complete current source/vector/physical evidence."""
    if not upgraded(root) or any(name not in values or v.digest(values[name]) != sha for name, sha in ARTIFACTS.items()):
        v.reject("storage-compiler-artifact")
    legacy = {name: data for name, data in values.items() if name not in ARTIFACTS}
    historical = entry.unpack(legacy[idle.ACQUISITION])
    compiled = entry.unpack(historical["source.tar.gz"])
    current = entry.unpack(values[ACQUISITION])
    current_inputs, _, _ = receipt(root, current)
    current_source = entry.unpack(current["source.tar.gz"])
    for name, data in compiled.items():
        now = current_source[name]
        if name in {"polaris/internal/storage/numeric.json", "polaris/internal/storage/numeric_linux_amd64_test.go"}:
            valid = data.count(b"go1.27.1") == 1 and data.replace(b"go1.27.1", b"go1.27.2") == now
        elif name == "go.mod":
            valid = data.replace(b"golang.org/x/net v0.59.0", b"golang.org/x/net v0.60.0") == now
        elif name == "go.sum":
            valid = v.digest(now) == current_inputs["files"][name]
        else:
            valid = data == now
        if not valid:
            v.reject("storage-compiler-source-delta", name)
    parent = root / "build/tmp"
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="storage-compiler-legacy-", dir=parent) as temporary:
        shadow = Path(temporary)
        for name, data in compiled.items():
            target = v.inside(shadow, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            v.write_new(target, data)
        policy = v.decode(v.read(root / "development.json"))
        check = v.decode(historical["inputs.json"])["full_package_check"]
        policy["checks"] = [check if item["id"] == "storage-examples" else item for item in policy["checks"]]
        v.write_new(shadow / "development.json", policy)
        for name, data in legacy.items():
            origin = v.inside(root / "build/results/assurance", name)
            if v.file_digest(origin) != v.digest(data):
                v.reject("storage-compiler-legacy-reference")
            target = v.inside(shadow / "build/results/assurance", name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.hardlink_to(origin)
        proof = idle.reconcile(shadow, legacy)
    ledger, trace, rows = idle.acquisition(root, current, compiler="1.27.2")
    prefix = "commands/raw-structure/structure/"
    old_trace = v.decode(historical[prefix + "typed/overlay/trace.json"])
    old_record = v.decode(historical[prefix + "typed/tests/record.json"])
    old_rows, processes = logic.observe(
        old_trace, idle.stream(historical, prefix + "typed/tests/", old_record), "github.com/eosforge/astra/" + structure.STORAGE, 259
    )
    mapping = idle.predicates(old_trace["files"], trace["files"], set(), old_rows, rows)
    inventory = logic.inventory(trace)
    coordinates = {(identity, index) for identity, item in inventory.items() for index in range(len(item["atoms"]))}
    exclusions = {(mapping[item["decision"]], item["condition"]) for item in proof["exclusions"]}
    if (
        processes != 32
        or len(mapping) != 162
        or not len(coordinates) == proof["raw_conditions"] == 281
        or len(exclusions) != 8
        or not exclusions <= coordinates
        or not len(coordinates - exclusions) == proof["supported_conditions"] == proof["qualified_denominator"] == 273
    ):
        v.reject("storage-compiler-condition-scope")
    result = copy.deepcopy(proof)
    result["legacy_backup_supplement"] = result.pop("backup_supplement", None)
    result.update(
        compiler="1.27.2",
        source_sha256=trace["source_sha256"],
        source_bindings={row["file"]: row["sha256"] for row in trace["files"]},
        current_structure=ledger,
        compiler_exports_reused=0,
        legacy_compiler_exports_reused=proof["compiler_exports_reused"],
        current_acquisition={
            "archive": ACQUISITION,
            "archive_sha256": ACQUISITION_SHA,
            "preserved_predicates": 162,
            "current_cases": 259,
            "new_condition_hits": 0,
        },
        backup_supplement=race_profiles(root, entry.unpack(values[RACE])),
        archives=ARTIFACTS,
    )
    result["mapping"] = {old: mapping[new] for old, new in proof["mapping"].items()}
    result["new_pairs"] = [{**pair, "decision": mapping[pair["decision"]]} for pair in proof["new_pairs"]]
    result["exclusions"] = [{**item, "decision": mapping[item["decision"]]} for item in proof["exclusions"]]
    result["basis"] = (
        "Exact legacy proof replay plus unchanged production/dependency sources, all preceding current typed vectors, fixed source-block obligations and complete current-runtime ordinary/Race profiles. Native compiler counts stay separate. No exclusion, threshold, condition or required rule is removed; protected provenance and whole-system release remain separate."
    )
    return result
