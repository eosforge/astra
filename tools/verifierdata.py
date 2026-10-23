"""Interpret the fixed native verifier controller's original executions without replaying product applications."""

from pathlib import Path, PurePosixPath

from tools import entry, verify as v

DRIVER = "e3b2e817b9bd7c9eeab22c4fe2de21f04ea80a2a4e21a6feb7e122f9c353e711"
ENTER = "0fab678035cc0e74701e374e1ab8786f27d13e6ac88cce301596ecd56f681fa6"
COLLECTOR = "1d0abb45c201fd09bedfafcf953aa8fab8b7cc761ccdde96c88ddedab3a86f15"
WHOLE = {"memory.high": "1879048192", "memory.max": "2147483648", "cpu.max": "300000 100000", "pids.max": "2048", "memory.swap.max": "0"}
CONTROLLER = {"memory.high": "402653184", "memory.max": "469762048", "cpu.max": "100000 100000", "pids.max": "32", "memory.swap.max": "0"}
WORKLOAD = {"memory.high": "1342177280", "memory.max": "1610612736", "cpu.max": "200000 100000", "pids.max": "256", "memory.swap.max": "0"}
COLLECTION = {"memory.high": "402653184", "memory.max": "536870912", "cpu.max": "100000 100000", "pids.max": "64", "memory.swap.max": "0"}
# Only these explicit logical aliases may share one identical physical selection.
ALIASES = {
    "gap-scope": {"admission-gap-scope"},
    "gap-gate": {"admission-gap-gate"},
}


def require(value: object, reason: str) -> None:
    """Keep every malformed, incomplete or out-of-scope observation blocking."""
    if not value:
        v.reject("verifier-" + reason)


def interpreter(check: dict) -> bool:
    """Select the registered empty-environment Python observer interface with its exact case selectors."""
    return (
        check["adapter"] == "observed-cases"
        and not check["environment"]
        and check["argv"][:4] == ["python3", "-B", "tools/observe.py", "python"]
        and bool(check["argv"][4:])
        and bool(check["expected_tests"])
        and all(selector.startswith("tests.") for selector in check["argv"][4:])
        and all(any(test == selector or test.startswith(selector + ".") for selector in check["argv"][4:]) for test in check["expected_tests"])
    )


def eligible(config: dict) -> set[str]:
    """Keep the original registered interpreter declarations; component suites have separate case inventories."""
    return {name for name, check in v.unique(config["checks"]).items() if interpreter(check)}


def association(root: Path, path: Path, checksum: str, current: dict) -> tuple[dict, dict, dict[str, str]]:
    """Bind an explicit results-only documentation review without changing any original native source identity."""
    root = root.resolve()
    boundary = (root / "build/results/assurance").resolve()
    require(path.is_absolute() and path.resolve().is_relative_to(boundary), "association-boundary")
    path = v.inside(boundary, path.relative_to(boundary).as_posix())
    raw = v.read(path, 1024**2)
    require(v.digest(raw) == checksum, "association-pin")
    record = v.decode(raw)
    require(set(record) == {"at", "executed", "after", "changed_after_interpretation", "native_application_commands"}, "association-shape")
    v.stamp(record["at"])
    require(type(record["native_application_commands"]) is int and record["native_application_commands"] == 0, "association-execution")
    before = record["executed"]
    require(record["after"] == current and set(before) == set(current), "association-current")
    require(
        {key: value for key, value in before.items() if key != "files"} == {key: value for key, value in current.items() if key != "files"}, "association-git"
    )
    old, new = (v.unique(value["files"], "path") for value in (before, current))
    changed = sorted(name for name in old.keys() | new.keys() if old.get(name) != new.get(name))
    require(
        old.keys() == new.keys()
        and changed == record["changed_after_interpretation"] == ["docs/validation.md"]
        and [row["path"] for row in before["files"]] == [row["path"] for row in current["files"]],
        "association-scope",
    )
    original = old[changed[0]]
    require(
        set(original) == {"path", "sha256"}
        and isinstance(original["sha256"], str)
        and len(original["sha256"]) == 64
        and all(character in "0123456789abcdef" for character in original["sha256"])
        and new[changed[0]]["sha256"] is not None,
        "association-document",
    )
    relative = path.relative_to(root).as_posix()
    return (
        before,
        {
            "path": relative,
            "sha256": checksum,
            "executed_source_sha256": v.digest(v.encode(before)),
            "current_source_sha256": v.digest(v.encode(current)),
            "changed_paths": changed,
            "trust": "local",
        },
        {relative: checksum},
    )


def reference(files: dict[str, bytes], directory: str, item: dict) -> bytes:
    """Read only a complete authenticated relative stream member."""
    name = item["path"]
    path = PurePosixPath(name)
    require(
        bool(name) and not path.is_absolute() and path.as_posix() == name and ".." not in path.parts and "\\" not in name and ":" not in name, "reference-path"
    )
    raw = files[directory + name]
    require(len(raw) == item["bytes"] <= 32 * 1024**2 and v.digest(raw) == item["sha256"], "reference-integrity")
    return raw


def limits(state: dict[str, str], expected: dict[str, str]) -> None:
    """Require the original effective kernel limits and absence of pressure/limit events."""
    require(all(state[key] == value for key, value in expected.items()), "native-limits")
    for field in ("memory.events", "pids.events"):
        if field in state:
            require(not any(int(row.split()[1]) for row in state[field].splitlines()), "native-limit-event")


def inspect(files: dict[str, bytes], seal: dict, retired: dict) -> dict:
    """Recover factual native observations; current-source adoption is a separate mandatory step."""
    require(set(files) == set(seal["files"]), "archive-inventory")
    require(seal["trust"] == "local", "archive-trust")
    require(all(item == {"bytes": len(files[name]), "sha256": v.digest(files[name])} for name, item in seal["files"].items()), "archive-integrity")
    manifest = v.decode(files["manifest.json"])
    require(manifest == {"trust": "local", "files": {name: item for name, item in seal["files"].items() if name != "manifest.json"}}, "archive-manifest")
    inputs, owner, cleanup, terminal = (v.decode(files[name]) for name in ("inputs.json", "owner.json", "cleanup.native.json", "terminal.json"))
    require(v.digest(files["run.py"]) == inputs["driver_sha256"] == owner["script_sha256"] == DRIVER, "controller-code")
    require(v.digest(files["enter.py"]) == inputs["enter_sha256"] == ENTER and v.digest(files["collect.py"]) == COLLECTOR, "collector-code")
    require(
        owner["inputs_sha256"] == v.digest(files["inputs.json"]) and all(v.digest(files[name]) == sha for name, sha in inputs["variant_files"].items()),
        "controller-inputs",
    )
    require(v.digest(files["source.tar.gz"]) == inputs["source_archive_sha256"], "source-archive")
    source = entry.unpack(files["source.tar.gz"])
    require({name: v.digest(data) for name, data in source.items()} == inputs["files"] and len(source) == inputs["budget"]["source_files"], "source-files")
    require({row["path"]: row["sha256"] for row in inputs["source"]["files"] if row["sha256"] is not None} == inputs["files"], "main-source")
    require(files["source.native.before.json"] == files["source.native.after.json"], "native-source-changed")
    actual = v.decode(files["source.native.before.json"])
    require(actual["commit"] is None and {row["path"]: row["sha256"] for row in actual["files"]} == inputs["files"], "native-source")
    require(files["git.native.HEAD"] == b"ref: refs/heads/fixture\n" and b"[remote " not in files["git.native.config"], "native-source-git")
    require(
        files["dependencies.before.json"] == files["dependencies.after.json"] and files["artifacts.before.json"] == files["artifacts.after.json"],
        "dependency-or-artifact-changed",
    )
    require(v.decode(files["artifacts.before.json"]) == inputs["artifacts"], "artifact-inputs")
    dependencies = v.decode(files["dependencies.before.json"])
    require(set(dependencies) == set(inputs["preflight"]["dependency_roots"]) | {"executables"}, "dependency-inventory")
    require(dependencies["executables"] == {name: item["sha256"] for name, item in inputs["preflight"]["tools"].items()}, "tool-identity")
    require(terminal == seal["terminal"] and cleanup == seal["cleanup"] and not terminal["errors"] and not terminal["interrupted"], "terminal")
    require(terminal["inputs_unchanged"] and terminal["cache_unchanged"] and not terminal["remaining_owned"], "terminal-ownership")
    require(
        not cleanup["original_failed"] and not cleanup["original_errors"] and not cleanup["remaining_owned"] and cleanup["cache_unchanged"], "producer-cleanup"
    )
    require(cleanup["boot_id"] == owner["boot_id"] and cleanup["original_invocation_id"] == owner["invocation_id"], "producer-owner")
    require(cleanup["unit"]["MainPID"] == "0" and not cleanup["unit"]["ControlGroup"], "producer-retirement")
    expected_owners = [owner["identity"]] + [
        v.decode(data)["identity"] for name, data in files.items() if name.startswith("commands/") and name.endswith(".process.json")
    ]
    require(
        len(expected_owners) == len({(row["pid"], row["start_ticks"]) for row in expected_owners}) == len(cleanup["retired"]), "producer-identity-inventory"
    )
    require(
        all(
            row["identity"] in expected_owners and row["status"] in {"absent", "reused"} and row["current_start_ticks"] != row["identity"]["start_ticks"]
            for row in cleanup["retired"]
        ),
        "producer-identities",
    )
    require(len({(row["identity"]["pid"], row["identity"]["start_ticks"]) for row in cleanup["retired"]}) == len(expected_owners), "duplicate-retirement")
    collector = v.decode(files["collector-owner.native.json"])
    require(
        retired["retired"] and retired["owner"] == seal["collector_owner"] == collector and collector["boot_id"] == owner["boot_id"], "collector-retirement"
    )
    require(
        retired["state"]["MainPID"] == "0"
        and not retired["state"]["ControlGroup"]
        and retired["state"]["Result"] == "success"
        and retired["state"]["ExecMainStatus"] == "0",
        "collector-retirement",
    )
    require((collector["pid"], collector["start_ticks"]) not in {(row["pid"], row["start_ticks"]) for row in expected_owners}, "collector-independence")
    limits(collector["limits"], COLLECTION)
    limits(seal["collector_resources"], COLLECTION)
    for prefix, expected in (("whole", WHOLE), ("controller", CONTROLLER)):
        limits(owner[prefix + "_limits"], expected)
        limits(terminal[prefix + "_resources"], expected)
    journal = v.decode(files["journal.native.json"])
    require(
        journal
        and all(
            row.get("_BOOT_ID") == owner["boot_id"].replace("-", "")
            and (row.get("INVOCATION_ID") or row.get("_SYSTEMD_INVOCATION_ID")) == owner["invocation_id"]
            for row in journal
        ),
        "native-journal",
    )
    messages = [row.get("MESSAGE", "") for row in journal]
    require(terminal in [v.decode(message.encode()) for message in messages if message.startswith("{")], "terminal-journal")
    require("astra-" + PurePosixPath(inputs["native_root"]).name + ".service: Deactivated successfully." in messages, "native-completion")
    check = inputs["check"]
    policy = v.decode(source["development.json"])
    require(
        inputs["policy_pins"]["policy"] == v.digest(source["development.json"]) and check == v.unique(policy["checks"]).get(check.get("id")), "check-policy"
    )
    require(check["id"] in eligible(policy), "check-scope")
    prefix = "commands/verification-python/"
    record, request, process, execution, before, after = (
        v.decode(files[prefix + name])
        for name in ("record.json", "request.json", "verification-python.process.json", "exec.native.json", "leaf.before.json", "leaf.after.json")
    )
    v.schema(record, "evidence", ("properties", "checks", "items"))
    tools = inputs["preflight"]["tools"]
    argv = [tools["python"]["path"], *check["argv"][1:]]
    leaf = owner["group"] + "/verification-python"
    wrapped = ["/usr/bin/python3", "-B", inputs["native_root"] + "/enter.py", "--enter", leaf, "--", *argv]
    require(record["argv"] == request["argv"] == process["argv"] == wrapped, "native-command")
    require(record["executable_sha256"] == tools["python"]["sha256"], "native-executable")
    require(execution["declared_argv"] == argv and len(execution["observed"]) == 1, "exec-observation")
    observed_exec = execution["observed"][0]
    require(observed_exec["argv"] == argv and observed_exec["executable"] == argv[0] and observed_exec["cgroup"] == leaf, "exec-observation")
    require(
        all(observed_exec["identity"][key] == process["identity"][key] for key in ("pid", "start_ticks", "parent", "session"))
        and process["identity"]["parent"] == owner["identity"]["pid"],
        "exec-identity",
    )
    require(process["cwd"] == inputs["native_root"] + "/source", "exec-directory")
    environment = {
        "PATH": str(PurePosixPath(tools["ctest"]["path"]).parent) + ":/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": inputs["native_root"] + "/source/build/commands/verification-python/tmp",
    }
    require(record["environment"] == request["environment"] == environment, "exec-environment")
    require(
        record["resolved_environment"]
        == environment
        | {"HOME": "/home/ubuntu", "LANG": "C.UTF-8", "GOFLAGS": "-mod=readonly", "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOWORK": "off"},
        "exec-environment",
    )
    require(request["timeout_s"] == check["timeout_s"] and request["log_bytes"] == check["log_bytes"] <= 32 * 1024**2, "exec-budget")
    require(
        record["exit_code"] == 0
        and record["complete"]
        and record["cleanup"]
        and record["termination"] == "exited"
        and record["duration_ms"] <= check["timeout_s"] * 1000,
        "native-command",
    )
    require(terminal["records"] == [{key: record[key] for key in ("id", "exit_code", "complete", "cleanup", "termination", "duration_ms")}], "native-summary")
    limits(before, WORKLOAD)
    limits(after, WORKLOAD)
    require(not after["cgroup.procs"] and dict(row.split() for row in after["cgroup.events"].splitlines())["populated"] == "0", "workload-retirement")
    stdout, stderr = (reference(files, prefix, record[channel]) for channel in ("stdout", "stderr"))
    events = [v.decode(line[len(b"ASTRA-OBSERVE ") :]) for line in stdout.splitlines() if line.startswith(b"ASTRA-OBSERVE ")]
    begins = [row["test"] for row in events if row["event"] == "begin"]
    ends = [row for row in events if row["event"] == "end"]
    require(
        events and events[0] == {"event": "start", "engine": "unittest"} and events[-1] == {"event": "complete", "cases": len(check["expected_tests"])},
        "case-completion",
    )
    require(begins == [row["test"] for row in ends] and sorted(begins) == sorted(check["expected_tests"]) and len(begins) == len(set(begins)), "case-inventory")
    require(all(row["status"] == "passed" and type(row["hits"]) is int and row["hits"] > 0 for row in ends), "case-status")
    counts, failures = v.case_observations(stdout, check)
    require(not failures and set(counts) == {probe["contract"] for probe in check["probes"]}, "contract-observations")
    summary = "Ran " + str(len(ends)) + (" test" if len(ends) == 1 else " tests")
    require(summary in stderr.decode() and stderr.decode().rstrip().endswith("OK"), "case-summary")
    return {
        "source": inputs["source"],
        "check": check,
        "observations": counts,
        "cases": len(ends),
        "platform": "linux-amd64-cgo",
        "record_sha256": v.digest(files[prefix + "record.json"]),
        "executed_step": record["id"],
        "duration_ms": record["duration_ms"],
        "producer_identities": len(expected_owners),
        "trust": "local",
    }


def observations(proof: dict, source: dict, check: dict) -> dict[tuple[str, str, str], str]:
    """Adopt only an identical current source and declaration; historical parser fixtures cannot pass today's check."""
    require(proof["source"] == source, "adoption-source")
    require(proof["check"] == check and interpreter(check), "adoption-check")
    require(proof["platform"] == "linux-amd64-cgo" and proof["cases"] == len(check["expected_tests"]), "adoption-scope")
    require(set(proof["observations"]) == {item["contract"] for item in check["probes"]}, "adoption-contracts")
    require(
        all(
            type(proof["observations"][item["contract"]]) is int and proof["observations"][item["contract"]] >= item["minimum_hits"] for item in check["probes"]
        ),
        "adoption-counts",
    )
    return {(check["id"], proof["platform"], contract): "passed" for contract in proof["observations"]}


def alias(proof: dict, source: dict, canonical: dict, target: dict) -> tuple[dict[tuple[str, str, str], str], dict[str, int]]:
    """Reuse one real execution only for a registered identical selection, preserving its original step and contract mapping."""
    observations(proof, source, canonical)
    require(target["id"] in ALIASES.get(canonical["id"], set()), "alias-check")
    require(
        {key: value for key, value in canonical.items() if key not in {"id", "component", "probes"}}
        == {key: value for key, value in target.items() if key not in {"id", "component", "probes"}},
        "alias-declaration",
    )
    require(
        len(canonical["probes"]) == len(target["probes"]) == 1
        and {key: value for key, value in canonical["probes"][0].items() if key != "contract"}
        == {key: value for key, value in target["probes"][0].items() if key != "contract"},
        "alias-probe",
    )
    count = proof["observations"][canonical["probes"][0]["contract"]]
    return {(target["id"], proof["platform"], target["probes"][0]["contract"]): "passed"}, {target["probes"][0]["contract"]: count}


def entries(root: Path, path: Path, checksum: str, source: dict, config: dict) -> tuple[dict[tuple[str, str, str], str], dict[str, dict], dict[str, str]]:
    """Read explicitly pinned exact-selector executions; a full-suite summary cannot stand in for these native commands."""
    boundary = (root / "build/results/assurance").resolve()
    require(path.resolve().is_relative_to(boundary), "entries-boundary")
    path = v.inside(boundary, path.relative_to(boundary).as_posix())
    raw = v.read(path)
    require(v.digest(raw) == checksum, "entries-pin")
    manifest = v.decode(raw)
    require(set(manifest) == {"version", "source", "entries"} and manifest["version"] == 1 and manifest["source"] == source, "entries-source")
    rows = manifest["entries"]
    registered = eligible(config) - {"verification-python"}
    require(isinstance(rows, list) and 0 < len(rows) <= len(registered), "entries-inventory")
    checks = v.unique(config["checks"])
    seen, observed, reports = set(), {}, {}
    checked = {path.relative_to(root).as_posix(): checksum}
    for row in rows:
        require(set(row) == {"check", "directory", "targets", "archive_sha256", "seal_sha256", "retired_sha256"}, "entry-shape")
        name, targets = row["check"], row["targets"]
        require(name in registered and name not in seen and isinstance(targets, list) and targets, "entry-selection")
        require(len(targets) == len(set(targets)) and name in targets and set(targets) <= {name, *ALIASES.get(name, set())}, "entry-targets")
        seen.add(name)
        directory = v.inside(boundary, row["directory"])
        proof, bindings = read(root, directory, row["archive_sha256"], row["seal_sha256"], row["retired_sha256"])
        observed.update(observations(proof, source, checks[name]))
        checked.update(bindings)
        target_counts = {name: proof["observations"]}
        for target in targets:
            if target != name:
                states, counts = alias(proof, source, checks[name], checks[target])
                observed.update(states)
                target_counts[target] = counts
        reports[name] = {
            "directory": row["directory"],
            "archive_sha256": row["archive_sha256"],
            "record_sha256": proof["record_sha256"],
            "executed_step": proof["executed_step"],
            "cases": proof["cases"],
            "duration_ms": proof["duration_ms"],
            "targets": target_counts,
            "trust": proof["trust"],
        }
    return observed, reports, checked


def read(root: Path, directory: Path, archive_sha256: str, seal_sha256: str, retired_sha256: str) -> tuple[dict, dict[str, str]]:
    """Read explicitly pinned original evidence and bind local sidecars before interpreting any native outcome."""
    root = root.resolve()
    directory = directory.resolve()
    boundary = (root / "build/results/assurance").resolve()
    require(directory.resolve().is_relative_to(boundary), "evidence-boundary")
    checked = {}
    values = {}
    for name, maximum in (("evidence.tar.gz", 16 * 1024**2), ("sealed.native.json", 1024**2), ("collector-retired.json", 1024**2), ("inputs.json", 1024**2)):
        path = v.inside(directory, name)
        raw = v.read(path, maximum)
        checked[path.relative_to(root).as_posix()] = v.digest(raw)
        values[name] = raw
    require(
        v.digest(values["evidence.tar.gz"]) == archive_sha256
        and v.digest(values["sealed.native.json"]) == seal_sha256
        and v.digest(values["collector-retired.json"]) == retired_sha256,
        "evidence-pin",
    )
    seal = v.decode(values["sealed.native.json"])
    require(seal["sha256"] == archive_sha256 and seal["bytes"] == len(values["evidence.tar.gz"]), "evidence-seal")
    files = entry.unpack(values["evidence.tar.gz"])
    require(files["inputs.json"] == values["inputs.json"], "input-sidecar")
    proof = inspect(files, seal, v.decode(values["collector-retired.json"]))
    return proof, checked
