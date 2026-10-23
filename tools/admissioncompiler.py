"""Interpret Admission's fixed current native campaigns without replaying applications or changing obligations."""

from pathlib import Path, PurePosixPath

from tools import entry, idle, predicates, statements, structure, verify as v

GEOMETRY = "go-upgrade-admission-structure-current-1"
PAIRS = "go-upgrade-admission-pairs-current-2"
ARTIFACTS = {
    GEOMETRY: "4d0389c54db71d8cd9bf0a1e259797426b51f0e27be7813fa9e2ee38f04f9971",
    PAIRS: "373622213a32fd7e5ee525c62fe8c86585109a349c3360c9b293c3da55e669c3",
}
GO = "/home/ubuntu/verdandi/build/tools/go-1.27.2/bin/go"
GO_SHA = "548d3c32f83fa81152f543eb1526be7884cfe0526eb5e9ce29d3eca14786e7e0"
PREFIX = "commands/raw-structure/structure/"


def upgraded(root: Path) -> bool:
    """Select the declared Admission compiler without accepting an unknown runtime as historical credit."""
    policy = v.decode(v.read(root / "development.json"))
    check = next(row for row in policy["checks"] if row["id"] == "admission-model")
    path = check.get("environment", {}).get("PATH", "")
    versions = [version for version in ("1.27.1", "1.27.2") if "/go-" + version + "/bin:" in path]
    if len(versions) != 1:
        v.reject("admission-compiler-policy")
    return versions[0] == "1.27.2"


def receipt(root: Path, files: dict[str, bytes], *, pairs: bool = False) -> tuple[dict, dict[str, bytes]]:
    """Check actual source closure, native command streams, compiler identity, lifetime and resource limits."""
    inputs, owner, cleanup, terminal = (v.decode(files[name]) for name in ("inputs.json", "owner.json", "cleanup.native.json", "terminal.json"))
    source = entry.unpack(files["source.tar.gz"])
    directories = ("internal/admission", "internal/generated/astra", "internal/generated/orbit", "tools/decisions")
    fixtures = ("star-a", "star-b", "pulsar", "expired")
    expected = {path.relative_to(root).as_posix() for name in directories for path in (root / name).rglob("*") if path.is_file()}
    expected |= {path.relative_to(root).as_posix() for name in fixtures for path in (root / "tests/fixtures" / name).rglob("*") if path.is_file()}
    expected |= {".gitignore", "go.mod", "go.sum", "dependencies.lock.json", "tests/fixtures/admission-v1.json"}
    native = "/home/ubuntu/verdandi/astra/build/results/assurance/" + (
        "go-upgrade-admission-pairs-native-current-2" if pairs else "go-upgrade-admission-structure-native-current-1"
    )
    if (
        len(source) != 73
        or set(source) != expected
        or source[".gitignore"] != b"build/\n"
        or {name: v.digest(data) for name, data in source.items()} != inputs["files"]
        or v.digest(files["source.tar.gz"]) != inputs["source_archive_sha256"]
        or any(v.file_digest(root / name) != digest for name, digest in inputs["files"].items() if name != ".gitignore")
        or inputs["native_root"] != native
        or files["source.native.before.json"] != files["source.native.after.json"]
        or {row["path"]: row["sha256"] for row in v.decode(files["source.native.before.json"])["files"]} != inputs["files"]
        or files["git.native.HEAD"] != b"ref: refs/heads/fixture\n"
        or b"[remote " in files["git.native.config"]
    ):
        v.reject("admission-compiler-source")
    if (
        owner["inputs_sha256"] != v.digest(files["inputs.json"])
        or owner["script_sha256"] != inputs["driver_sha256"]
        or inputs["driver_sha256"] != v.digest(files["run.py"])
        or inputs["enter_sha256"] != v.digest(files["enter.py"])
        or any(v.digest(files[name]) != digest for name, digest in inputs["variant_files"].items())
        or files["dependencies.before.json"] != files["dependencies.after.json"]
        or v.decode(files["dependencies.before.json"]) != v.decode(files["expected-dependencies.json"])
    ):
        v.reject("admission-compiler-inputs")
    dependencies = v.decode(files["dependencies.before.json"])
    if len(dependencies) != 9 or set(dependencies) != set(inputs["dependency_roots"]) or dependencies[GO.removesuffix("/bin/go")]["bin/go"] != GO_SHA:
        v.reject("admission-compiler-dependencies")
    identities = [row["identity"] for row in cleanup["retired"]]
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
        or len(identities) != (3 if pairs else 10)
        or identities[0] != owner["identity"]
        or any(row["status"] not in {"absent", "reused"} or row["current_start_ticks"] == row["identity"]["start_ticks"] for row in cleanup["retired"])
    ):
        v.reject("admission-compiler-owner")
    for scope, limits in (
        ("whole", {"memory.high": "1879048192", "memory.max": "2147483648", "cpu.max": "300000 100000", "pids.max": "512" if pairs else "2048"}),
        ("controller", {"memory.high": "402653184", "memory.max": "469762048", "cpu.max": "100000 100000", "pids.max": "32"}),
    ):
        limits["memory.swap.max"] = "0"
        if any(state[key] != value for state in (owner[scope + "_limits"], terminal[scope + "_resources"]) for key, value in limits.items()):
            v.reject("admission-compiler-resources")
        if any(
            int(value)
            for field in ("memory.events", "pids.events")
            for _, value in (line.split() for line in terminal[scope + "_resources"][field].splitlines())
        ):
            v.reject("admission-compiler-resources")
    handed, returned = (v.decode(files[name]) for name in ("cache-handoff.json", "cache-return.json"))
    if (
        handed["from"] != returned["path"]
        or returned["path"] != inputs["cache"]
        or handed["to"] != native + "/source/build/cache/go"
        or handed["inode"] != returned["inode"]
        or returned["inode"] != 713912
        or handed["device"] != returned["device"]
        or returned["device"] != 64512
        or returned["remaining_owned"]
    ):
        v.reject("admission-compiler-cache")
    directory = PurePosixPath(native + "/source/build/commands/raw-structure/structure")
    plan = (
        [
            (
                "acquisition-pairs",
                [
                    GO,
                    "test",
                    "-json",
                    "-count=1",
                    "-p=2",
                    "-parallel=2",
                    "-timeout=60s",
                    "-run=^(TestAdmissionEdges|TestLoadMetadata)$",
                    "-overlay=" + native + "/variants/overlay.json",
                    "./internal/admission",
                ],
                120,
            )
        ]
        if pairs
        else [(name, [GO, *argv[1:]], timeout) for name, argv, timeout in structure.plan(directory)]
    )
    stages = {name: "build/commands/" + (name if pairs else "raw-structure/structure/" + name) for name, _, _ in plan}
    if inputs["commands"] != [{"id": name, "argv": argv, "timeout_s": timeout, "expected_exit_code": 0, "stage": stages[name]} for name, argv, timeout in plan]:
        v.reject("admission-compiler-plan")
    streams = {}
    for name, argv, timeout in plan:
        prefix = "commands/" + stages[name].removeprefix("build/commands/") + "/"
        identifier = name.rpartition("/")[2]
        record, request, process, execution, before, after = (
            v.decode(files[prefix + member])
            for member in ("record.json", "request.json", identifier + ".process.json", "exec.native.json", "leaf.before.json", "leaf.after.json")
        )
        actual = [value.replace("{root}", native + "/source") for value in argv]
        leaf = owner["group"] + "/" + name.replace("/", "-")
        if (
            record["argv"] != request["argv"]
            or record["argv"] != process["argv"]
            or record["argv"] != ["/usr/bin/python3", "-B", native + "/enter.py", "--enter", leaf, "--", *actual]
            or record["executable_sha256"] != inputs["preflight"]["tools"]["python"]["sha256"]
            or record["toolchain"]["command"]["sha256"] != inputs["preflight"]["tools"]["python"]["sha256"]
            or any(record["toolchain"][key]["sha256"] != inputs["preflight"]["tools"][tool]["sha256"] for key, tool in (("CC", "gcc"), ("CXX", "g++")))
            or record["platform"] != structure.PLATFORM
            or request["timeout_s"] != timeout
            or record["duration_ms"] > timeout * 1000
            or request["log_bytes"] != (4 if pairs else 32) * 1024**2
            or process["cwd"] != native + "/source"
            or process["boot_id"] != owner["boot_id"]
            or process["identity"] not in identities
            or process["identity"]["parent"] != owner["identity"]["pid"]
            or execution["declared_argv"] != actual
            or len(execution["observed"]) != 1
            or execution["observed"][0]["argv"] != actual
            or execution["observed"][0]["executable"] != GO
            or execution["observed"][0]["cgroup"] != leaf
            or any(execution["observed"][0]["identity"][key] != process["identity"][key] for key in ("pid", "start_ticks", "parent", "session"))
            or record["environment"] != request["environment"]
            or any(
                record["environment"][key] != value
                for key, value in {
                    "PATH": "/home/ubuntu/verdandi/build/tools/go-1.27.2/bin:/home/ubuntu/verdandi/build/tools/gcc-16.2.0/bin:/usr/bin:/bin",
                    "GOMAXPROCS": "2",
                    "GOPROXY": "off",
                    "GOSUMDB": "off",
                    "GOTOOLCHAIN": "local",
                    "GOWORK": "off",
                    "GOFLAGS": "-mod=readonly",
                    "CGO_ENABLED": "1",
                }.items()
            )
            or any(
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
            or any(int(value) for field in ("memory.events", "pids.events") for _, value in (line.split() for line in after[field].splitlines()))
        ):
            v.reject("admission-compiler-command", name)
        if any(record[field]["bytes"] > request["log_bytes"] for field in ("stdout", "stderr")):
            v.reject("admission-compiler-stream", name)
        streams[name] = idle.stream(files, prefix, record)
    return inputs, streams


def reconcile(root: Path, archives: dict[str, bytes], *, structural: bool = False) -> dict:
    """Recompute current source-bound structure or all 165 supported conditions from complete native inputs."""
    if set(archives) != set(ARTIFACTS):
        v.reject("predicates-archive-inventory")
    if any(v.digest(data) != ARTIFACTS[name] for name, data in archives.items()):
        v.reject("predicates-archive-integrity")
    geometry, extra = (entry.unpack(archives[name]) for name in (GEOMETRY, PAIRS))
    inputs, streams = receipt(root, geometry)
    additional, added = receipt(root, extra, pairs=True)
    if inputs["files"] != additional["files"] or geometry[PREFIX + "typed/overlay/trace.json"] != extra["variants/trace.json"]:
        v.reject("admission-compiler-pair-binding")
    for name, digest in (("admission.go.in", predicates.EDGE), ("admission-metadata.go.in", predicates.METADATA)):
        if v.digest(extra["variants/" + name]) != digest or v.file_digest(root / "tests/fixtures" / name) != digest:
            v.reject("predicates-fixture-drift", name)
    bindings = predicates.sources(root, inputs["files"], statements.stream(streams["typed/exports"]))
    trace = v.decode(geometry[PREFIX + "typed/overlay/trace.json"])
    dependency = {name: geometry[PREFIX + "_dependencies/" + name] for name in structure.DEPENDENCIES}
    tests = inputs["full_package_check"]["expected_tests"]
    if len(tests) != 47:
        v.reject("admission-compiler-test-scope")
    if structural:
        structure.terminals(streams["coverage"], tests)
        result = structure.reconcile(
            root=root,
            source_sha256=trace["source_sha256"],
            tests=tests,
            profiles=(geometry[PREFIX + "coverage.profile"], structure.resolver(streams["coverage"])),
            dependency=dependency,
            trace=trace,
            boolean_events=streams["typed/tests"],
            control=v.decode(geometry[PREFIX + "control/overlay/flow.json"]),
            control_events=streams["control/tests"],
            compiler="1.27.2",
        )
    else:
        report = predicates.qualified(
            root, trace, streams["typed/tests"], tests, dependency, added["acquisition-pairs"], extra[PREFIX + "_dependencies/net/netip/netip.go"]
        )
        result = {"status": report["status"], "independence": report}
    result.update(
        compiler="1.27.2",
        archives=ARTIFACTS,
        sources=bindings,
        application_commands=0,
        compiler_exports_reused=0,
        qualification="Current local Linux source-bound observations under declared assumptions; protected component and release qualification remain separate.",
    )
    return result
