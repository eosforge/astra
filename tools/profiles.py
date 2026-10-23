"""Adopt two immutable native Go profiles without treating historical verifier results as current."""

from pathlib import Path, PurePosixPath

from tools import entry, verify as v

MANIFEST = "tests/fixtures/profiles.json"
MODEL = "72fd1995e4a2b064c90654d64d0ffeb51ce10fb8adcb6476b285b67aafa8e497"
CHECKS = ["admission-model", "storage-examples"]
DRIVER = "9764489b8b91a553ecfb40dab936ac3ab7835628523a1bf16e5918c8ac4cee68"
WHOLE = {"memory.high": "max", "memory.max": "3221225472", "memory.swap.max": "0", "pids.max": "256", "cpu.max": "400000 100000"}
CONTROLLER = {"memory.high": "max", "memory.max": "536870912", "memory.swap.max": "0", "pids.max": "32", "cpu.max": "100000 100000"}
# Only reviewed consumers and their input manifests may differ; producer code, fixtures and oracles remain exact.
CONSUMERS = {
    "development.json",
    "docs/features/verification.md",
    "docs/validation.md",
    "tests/fixtures/native-closures.json",
    "tests/fixtures/profiles.json",
    "tests/fixtures/qualifications.json",
    "tests/fixtures/defenses.json",
    "tests/fixtures/release.json",
    "tests/test_qualification.py",
    "tests/test_verify.py",
    "tools/negatives.py",
    "tools/nativeclosures.py",
    "tools/profiles.py",
    "tools/qualification.py",
    "tools/qualificationdata.py",
    "tools/release.py",
}


def require(condition: bool, reason: str) -> None:
    """Reject incomplete custody, native observations or producer adoption with a stable cause."""
    if not condition:
        v.reject("profile-" + reason)


def members(files: dict[str, bytes], inventory: dict) -> None:
    """Bind every regular archive member rather than trusting a successful summary."""
    require({name: {"bytes": len(data), "sha256": v.digest(data)} for name, data in files.items()} == inventory, "archive-members")


def limits(state: dict, expected: dict) -> None:
    """Retain exact original caps and distinguish observed max events from OOM or exceeded limits."""
    require(all(state[key] == value for key, value in expected.items()), "native-limits")
    if "memory.peak" in state:
        require(0 <= int(state["memory.peak"]) <= int(expected["memory.max"]), "native-memory-peak")
    events = dict(row.split() for row in state.get("memory.events", "").splitlines())
    require(all(int(events.get(key, "0")) == 0 for key in ("oom", "oom_kill", "oom_group_kill")), "native-oom")
    require(not any(int(row.split()[1]) for row in state.get("pids.events", "").splitlines()), "native-process-limit")


def inspect(root: Path, native: dict[str, bytes], custody: dict[str, bytes], immutable: dict, config: dict, consumer: dict) -> tuple[dict, dict]:
    """Reconstruct raw profile outcomes; producer identity and current parser identity remain separate."""
    seal = v.decode(custody["sealed.native.json"])
    require(not seal["failed"], "producer-failed")
    members(native, seal["files"])
    inputs, owner, terminal = (v.decode(native[name]) for name in ("inputs.json", "owner.json", "terminal.json"))
    require(inputs["execution_order"] == CHECKS and set(inputs["checks"]) == set(CHECKS), "selection")
    require(inputs["maximum_concurrent_checks"] == 1 and inputs["execution_timeout_s"] == 180, "execution-budget")
    require(inputs["downloads_or_installs"] == 0 and inputs["then_read_only"], "execution-boundary")
    require(v.digest(native["native.py"]) == inputs["driver_sha256"] == owner["script_sha256"] == DRIVER, "driver")
    require(owner["inputs_sha256"] == v.digest(native["inputs.json"]), "owner-inputs")
    for name, key in (
        ("authorization.json", "authorization_sha256"),
        ("approved-plan.json", "approved_plan_sha256"),
        ("source.tar.gz", "source_archive_sha256"),
    ):
        require(v.digest(native[name]) == inputs[key], "producer-input")
    plan = v.decode(native["approved-plan.json"])
    require(plan["execution_order"] == CHECKS and plan["maximum_concurrent_checks"] == 1 and plan["required_gomaxprocs"] == "4", "approved-plan")
    original = entry.unpack(native["source.tar.gz"])
    before = {row["path"]: row["sha256"] for row in inputs["source"]["files"]}
    require(
        {name: v.digest(data) for name, data in original.items()}
        == inputs["files"]
        == {name: checksum for name, checksum in before.items() if checksum is not None},
        "source-archive",
    )
    after = {row["path"]: row["sha256"] for row in consumer["files"]}
    changed = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
    require(not (set(changed) - CONSUMERS), "producer-source")
    original_config = v.decode(original["development.json"])
    require(v.expand(original_config) == v.expand(config), "obligation-drift")
    checks = v.unique(config["checks"])
    require(all(checks[name] == inputs["checks"][name] == v.unique(original_config["checks"])[name] for name in CHECKS), "declaration-drift")
    require(not terminal["errors"] and not terminal["interrupted"] and not terminal["remaining_owned"] and terminal["inputs_unchanged"], "native-terminal")
    require(native["dependencies.before.json"] == native["dependencies.after.json"], "dependency-drift")
    dependencies = v.decode(native["dependencies.before.json"])
    require(set(dependencies) == set(inputs["dependency_roots"]), "dependency-roots")
    for name in ("go", "gcc", "g++"):
        tool = inputs["tools"][name]
        roots = [base for base in dependencies if PurePosixPath(tool["path"]).is_relative_to(base)]
        require(len(roots) == 1 and dependencies[roots[0]][PurePosixPath(tool["path"]).relative_to(roots[0]).as_posix()] == tool["sha256"], "toolchain-binding")
    for stage in (owner, terminal):
        for prefix, policy in (("whole", WHOLE), ("controller", CONTROLLER)):
            limits(stage[prefix + ("_before" if stage is owner else "_after")], policy)
    retirement = v.decode(custody["retirement.native.json"])
    require(retirement["boot_id"] == owner["boot_id"] and retirement["producer_invocation_id"] == owner["invocation_id"], "retirement-owner")
    require(
        retirement["unit"]["MainPID"] == "0"
        and not retirement["unit"]["ControlGroup"]
        and retirement["unit"]["Result"] == "success"
        and retirement["unit"]["ExecMainStatus"] == "0",
        "producer-retirement",
    )
    require(all("i" in flags for flags in retirement["archive_flags"].values()), "immutable-flags")
    collector = retirement["collector"]
    require(v.digest(custody["custody.py"]) == collector["script_sha256"], "collector-code")
    limits(collector["limits"], CONTROLLER)
    received = immutable["collector_retired"]
    require(
        received["identity"] == collector["identity"]
        and received["current_start_ticks"] != collector["identity"]["start_ticks"]
        and received["unit"]["MainPID"] == "0"
        and not received["unit"]["ControlGroup"],
        "collector-retirement",
    )
    journal = [v.decode(line) for line in custody["journal.native.jsonl"].splitlines() if line.strip()]
    require(
        any(
            row.get("_PID") == "1"
            and row.get("_UID") == "0"
            and row.get("_EXE") == "/usr/lib/systemd/systemd"
            and row.get("_BOOT_ID") == owner["boot_id"].replace("-", "")
            and (row.get("INVOCATION_ID") or row.get("_SYSTEMD_INVOCATION_ID")) == owner["invocation_id"]
            and row.get("MESSAGE") == "astra-formal-profiles-native-current-1.service: Deactivated successfully."
            for row in journal
        ),
        "native-completion",
    )
    identities = [owner["identity"]]
    observations, profiles = {}, {}
    previous = None
    for name in CHECKS:
        check = checks[name]
        prefix = "commands/" + name + "/"
        record, request, actual, images = (
            v.decode(native[prefix + suffix]) for suffix in ("record.json", "request.json", "exec.native.json", "test-images.native.json")
        )
        process = v.decode(native[prefix + name + ".process.json"])
        v.schema(record, "evidence", ("properties", "checks", "items"))
        require(request == check | {"timeout_s": 180}, "native-request")
        require(
            record["id"] == name
            and record["platform"] == "linux-amd64-cgo"
            and record["argv"] == actual["argv"] == process["argv"] == check["argv"]
            and record["environment"] == check["environment"],
            "native-command",
        )
        require(
            record["complete"] and record["cleanup"] and record["termination"] == "exited" and record["exit_code"] == 0 and record["duration_ms"] <= 180000,
            "native-result",
        )
        require(
            actual["identity"] == process["identity"]
            and actual["identity"]["parent"] == owner["identity"]["pid"]
            and set(actual["uid"]) == {"1000"}
            and actual["cgroup"] == owner["group"] + "/" + name,
            "native-identity",
        )
        identities.append(actual["identity"])
        require(
            record["executable"] == actual["executable"] == inputs["tools"]["go"]["path"] and record["executable_sha256"] == inputs["tools"]["go"]["sha256"],
            "native-executable",
        )
        environment = {}
        native_root = inputs["native_root"] + "/source"
        for key, value in check["environment"].items():
            environment[key] = (
                value.replace("{root}", native_root).replace("{cache}", "/home/ubuntu/verdandi/build").replace("{run}", native_root + "/build/commands/" + name)
            )
        require(record["resolved_environment"] == {"LANG": "C.UTF-8"} | environment and environment["GOMAXPROCS"] == "4", "native-environment")
        require(
            record["toolchain"]
            == {
                "command": {"path": inputs["tools"]["go"]["path"], "sha256": inputs["tools"]["go"]["sha256"]},
                **{key: {"path": inputs["tools"][tool]["path"], "sha256": inputs["tools"][tool]["sha256"]} for key, tool in (("CC", "gcc"), ("CXX", "g++"))},
            },
            "native-toolchain",
        )
        started, finished = v.stamp(record["started_at"]), v.stamp(record["finished_at"])
        require(started <= finished and (previous is None or previous <= started), "serial-order")
        previous = finished
        for when in ("before", "after"):
            state = v.decode(native[prefix + "leaf." + when + ".json"])
            limits(state, WHOLE)
            require(not state["cgroup.procs"], "leaf-retirement")
        require(not images["errors"] and images["observed"], "test-images")
        for image in images["observed"]:
            require(image["cgroup"] == actual["cgroup"] and v.digest(native[image["product"]]) == image["sha256"], "test-image-binding")
            identities.append(image["identity"])
        require(any("-test.timeout=3m0s" in image["argv"] and "-test.parallel=4" in image["argv"] for image in images["observed"]), "test-image-profile")
        stdout, stderr = (reference(native, prefix, record[field]) for field in ("stdout", "stderr"))
        require(not stderr, "native-stderr")
        counts, missing = v.parse_observations(stdout, check, root)
        require(not missing and set(counts) == {probe["contract"] for probe in check["probes"]}, "native-observations")
        events = [v.decode(line) for line in stdout.splitlines() if line.strip()]
        passed = [row["Test"] for row in events if row.get("Action") == "pass" and row.get("Test")]
        require(len(passed) == len(set(passed)) and set(passed) == set(check["expected_tests"]), "native-case-inventory")
        observations.update({(name, "linux-amd64-cgo", contract): "passed" for contract in counts})
        profiles[name] = {
            "record_sha256": v.digest(native[prefix + "record.json"]),
            "tests": len(passed),
            "duration_ms": record["duration_ms"],
            "observations": counts,
            "execution_timeout_s": 180,
            "state": "passed",
        }
    require(
        terminal["records"]
        == [
            {
                key: v.decode(native["commands/" + name + "/record.json"])[key]
                for key in ("id", "exit_code", "termination", "complete", "cleanup", "duration_ms")
            }
            for name in CHECKS
        ],
        "native-records",
    )
    expected = {(row["pid"], row["start_ticks"]) for row in identities}
    retired = retirement["retired"]
    require(len(retired) == len(expected) and {(row["identity"]["pid"], row["identity"]["start_ticks"]) for row in retired} == expected, "retirement-inventory")
    require(
        all(
            row["status"] in {"absent", "reused"} and (row["current"] is None or row["current"]["start_ticks"] != row["identity"]["start_ticks"])
            for row in retired
        ),
        "retired-identities",
    )
    require(
        (collector["identity"]["pid"], collector["identity"]["start_ticks"]) not in expected and collector["invocation_id"] != owner["invocation_id"],
        "collector-independence",
    )
    return observations, {
        "profiles": profiles,
        "producer_source_sha256": v.digest(v.encode(inputs["source"])),
        "consumer_source_sha256": v.digest(v.encode(consumer)),
        "producer_binding": {"status": "current", "changed_consumer_paths": changed, "unchanged_source_entries": len(before.keys() - CONSUMERS)},
        "native_identities_retired": len(expected),
        "maximum_concurrent_checks": 1,
        "whole_memory_peak_bytes": int(terminal["whole_after"]["memory.peak"]),
        "controller_memory_events": terminal["controller_after"]["memory.events"],
        "native_application_commands": 0,
        "trust": "local-root-immutable; protected authority not issued",
        "boundary": "Only the two original native Go profiles are adopted. Historical full Python verification and other baseline passes are not imported. Original controller max events remain factual and supply no finite-resource qualification.",
    }


def reference(files: dict[str, bytes], prefix: str, item: dict) -> bytes:
    """Require a bounded, canonical, authenticated native stream path."""
    path = PurePosixPath(item["path"])
    require(
        not path.is_absolute() and path.as_posix() == item["path"] and ".." not in path.parts and "\\" not in item["path"] and ":" not in item["path"],
        "stream-path",
    )
    data = files[prefix + item["path"]]
    require(len(data) == item["bytes"] <= 32 * 1024**2 and v.digest(data) == item["sha256"], "stream-integrity")
    return data


def load(root: Path, path: Path, checksum: str) -> tuple[dict, dict, dict, dict]:
    """Read only the registered immutable bundle and its independently received collector retirement."""
    require(path.resolve() == (root / MANIFEST).resolve() and checksum == MODEL, "manifest-pin")
    raw = v.read(path)
    require(v.digest(raw) == MODEL, "manifest-pin")
    manifest = v.decode(raw)
    require(
        set(manifest) == {"version", "checks", "custody", "seal", "immutable"} and manifest["version"] == 1 and manifest["checks"] == CHECKS, "manifest-scope"
    )
    checked, values = {MANIFEST: MODEL}, {}
    for name in ("custody", "seal", "immutable"):
        item = manifest[name]
        data = v.read(v.inside(root, item["path"]), 32 * 1024**2)
        require(len(data) == item["bytes"] and v.digest(data) == item["sha256"], "artifact-pin")
        checked[item["path"]] = item["sha256"]
        values[name] = data
    seal, immutable = (v.decode(values[name]) for name in ("seal", "immutable"))
    require(not seal["failed"] and seal["sha256"] == manifest["custody"]["sha256"] and seal["bytes"] == len(values["custody"]), "custody-seal")
    custody = entry.unpack(values["custody"])
    members(custody, seal["files"])
    native_seal = v.decode(custody["sealed.native.json"])
    require(v.digest(custody["evidence.tar.gz"]) == native_seal["sha256"] and len(custody["evidence.tar.gz"]) == native_seal["bytes"], "native-seal")
    require(immutable["product_commands"] == 0, "collector-execution")
    require(
        set(immutable["files"]) == {"custody.tar.gz", "custody.sealed.json", "evidence.tar.gz", "sealed.native.json", "retirement.native.json"},
        "immutable-inventory",
    )
    for name, item in immutable["files"].items():
        data = values["custody"] if name == "custody.tar.gz" else values["seal"] if name == "custody.sealed.json" else custody[name]
        require(
            len(data) == item["bytes"] and v.digest(data) == item["sha256"] and item["uid"] == 0 and item["mode"] == "0o444" and "i" in item["flags"],
            "immutable-reception",
        )
    return entry.unpack(custody["evidence.tar.gz"]), custody, immutable, checked


def read(root: Path, path: Path, checksum: str, config: dict, consumer: dict) -> tuple[dict, dict, dict]:
    """Return scoped native observations and pinned proof metadata to the maintained inventory."""
    native, custody, immutable, checked = load(root, path, checksum)
    observed, proof = inspect(root, native, custody, immutable, config, consumer)
    proof["custody_sha256"] = checked[v.decode(v.read(path))["custody"]["path"]]
    return observed, proof, checked
