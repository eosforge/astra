"""Reconstruct retained Linux/Windows SDK semantic negatives without native execution or host queries."""

import json
from pathlib import PurePath, PurePosixPath, PureWindowsPath
import re

from tools import mutate, statements, verify as v


def require(condition: bool, reason: str) -> None:
    """Reject a specific evidence boundary without turning an incidental exception into a valid rejection."""
    if not condition:
        v.reject("qualification-go-mutations", reason)


def counters(text: str) -> dict[str, int]:
    """Retain all actually named kernel events rather than silently dropping an unfamiliar counter."""
    return {name: int(value) for name, value in (row.split() for row in text.splitlines())}


def windows(bundle: dict[str, bytes], installed: dict, seal: dict) -> dict:
    """Interpret the sealed original Windows campaign without querying current installations or processes."""
    prefix = "go-upgrade-comet-mutations-windows-current-1/"
    files = {name.removeprefix(prefix): raw for name, raw in bundle.items() if name.startswith(prefix)}

    def read(name: str) -> dict | list:
        """Decode only the supplied original campaign namespace."""
        require(name in files, "missing native artifact")
        return v.decode(files[name])

    inputs, owner, terminal, received = (read(name) for name in ("inputs.json", "controller.json", "terminal.json", "received.json"))
    require(not terminal["errors"] and not terminal["interrupted"], "Windows producer failed or incomplete")
    require(terminal["unchanged"] == {"source": True, "module": True, "dependencies": True, "toolchain": True}, "Windows producer input stability")
    budget = {"build_jobs": 2, "concurrent_cases": 1, "cpus": 2, "memory_bytes": 2147483648, "processes": 64, "test_parallel": 1, "wall_seconds": 900}
    require(inputs["budget"] == budget and 0 < terminal["duration_s"] < 900, "Windows original execution budget")
    require(owner["inputs_sha256"] == v.digest(files["inputs.json"]) and owner["runner_sha256"] == inputs["run_sha256"], "Windows owner inputs")
    native = PureWindowsPath(owner["cwd"])
    require(native.name == prefix.rstrip("/") and native.parent.name == "reuse-plan", "Windows native path ownership")
    root = native.parents[4]
    retired = read("received.json")["windows_retired"]
    identities = {(row["identity"]["pid"], row["identity"]["creation_time"]) for row in retired}
    all_retired = v.decode(bundle["retirement.json"])["retired"]
    all_identities = {(row["identity"]["pid"], row["identity"]["creation_time"]) for row in all_retired}
    require(
        len(retired) == len(identities) == 39
        and len(all_retired) == len(all_identities) == seal["retired_identities"] == 58
        and identities <= all_identities
        and all(row["retired"] and row.get("open_error") == 87 for row in retired + all_retired),
        "Windows original process retirement",
    )
    reader = "readers/go2-comet-mutations-windows-run1/"
    outer, request, process, original_limits, launch = (
        v.decode(bundle[reader + name])
        for name in ("record.json", "request.json", "go2-comet-mutations-windows-run1.process.json", "job.native.json", "inputs.json")
    )
    require(
        outer["exit_code"] == 0
        and outer["complete"]
        and outer["cleanup"]
        and outer["termination"] == "exited"
        and outer["argv"] == request["argv"] == process["argv"]
        and request["timeout_s"] == 900,
        "Windows original owner command",
    )
    require(v.digest(bundle[reader + "worker.py"]) == inputs["run_sha256"] == launch["script_sha256"], "Windows original runner source")
    require(
        v.digest(bundle["readers/go2-comet-mutations-windows-receive1/worker.py"]) == inputs["receiver_sha256"]
        and launch["source"] == inputs["source"] == received["source"] == seal["source"],
        "Windows original source association",
    )
    cpus = read("resources.before.json")["cpus"]
    require(
        original_limits == {"cpu_flags": 5, "cpu_rate": max(1, 20000 // cpus), "flags": 8712, "memory_bytes": 2147483648, "processes": 64}
        and launch["budget"] == {"cpu_rate": original_limits["cpu_rate"], "memory_bytes": 2147483648, "processes": 64},
        "Windows original ancestor limits",
    )
    require(installed["version"] == "go version go1.27.2 windows/amd64" and len(installed["files"]) == 15657, "Windows installed distribution")
    require(installed["files"]["bin/go.exe"]["sha256"] == inputs["go_sha256"], "Windows Go executable identity")
    dependencies, manifest, cases = (read(name) for name in ("dependencies.json", "manifest.json", "cases.json"))
    require(
        v.digest(files["dependencies.json"]) == inputs["dependencies_sha256"] and len(dependencies) == 6 and "golang.org/x/net@v0.60.0" in dependencies,
        "Windows dependency identities",
    )
    require(
        v.digest(files["manifest.json"]) == inputs["manifest_sha256"] and v.digest(files["cases.json"]) == inputs["cases_sha256"],
        "Windows fixed recipe identity",
    )
    require(
        len(cases) == len(manifest["mutations"]) == inputs["cases"] == 34 and len({case["id"] for case in cases}) == 34, "Windows fixed mutation denominator"
    )
    identifiers = ["go-version", "module-verify", "packages", "baseline", *[case["id"] for case in cases]]
    require(
        set(terminal["completed"]) == set(identifiers) == {name.split("/")[1] for name in files if name.startswith("native/")},
        "Windows native command denominator",
    )
    environment = {
        "PATH": "C:/Program Files/Go/bin;C:/Program Files/Git/cmd;C:/Windows/System32",
        "CGO_ENABLED": "0",
        "GOCACHE": inputs["compile_cache"],
        "GOMODCACHE": inputs["module_cache"],
        "GOMAXPROCS": "2",
        "GOOS": "windows",
        "GOARCH": "amd64",
        "PYTHONDONTWRITEBYTECODE": "1",
        "GOTOOLCHAIN": "local",
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOWORK": "off",
        "GOFLAGS": "-mod=readonly",
    }
    records, outputs, previous = {}, {}, None
    seen = {(owner["identity"]["pid"], owner["identity"]["creation_time"])}
    require(seen <= identities, "Windows original process retirement")
    for identifier in identifiers:
        folder = "native/" + identifier + "/"
        record, request, process = (read(folder + name) for name in ("record.json", "request.json", identifier + ".process.json"))
        v.schema(record, "evidence", ("properties", "checks", "items"))
        require(record["id"] == request["id"] == identifier and record["argv"] == request["argv"] == process["argv"], "Windows native command identity")
        require(
            record["platform"] == "windows-amd64" and record["executable"] == inputs["go"] and record["executable_sha256"] == inputs["go_sha256"],
            "Windows native executable or platform",
        )
        require(
            record["complete"] and record["cleanup"] and record["termination"] == "exited" and 0 <= record["duration_ms"] < request["timeout_s"] * 1000,
            "Windows native command incomplete or timed out",
        )
        started, finished = v.stamp(record["started_at"]), v.stamp(record["finished_at"])
        require(started <= finished and (previous is None or previous <= started), "Windows native serial order")
        previous = finished
        require({key: record[key] for key in terminal["completed"][identifier]} == terminal["completed"][identifier], "Windows native terminal disagreement")
        expected = environment | {"TMPDIR": str(native / folder / "tmp")}
        require(
            request["environment"] == record["environment"] == expected
            and all(record["resolved_environment"].get(key) == value for key, value in expected.items())
            and all(PureWindowsPath(record["resolved_environment"][key]) == native / folder / "tmp" for key in ("TEMP", "TMP")),
            "Windows native environment",
        )
        require(record["toolchain"] == {"command": {"path": inputs["go"], "sha256": inputs["go_sha256"]}}, "Windows native toolchain")
        identity = (process["identity"]["pid"], process["identity"]["creation_time"])
        require(identity in identities - seen and PureWindowsPath(process["cwd"]) == root, "Windows physical process identity")
        seen.add(identity)
        for field in ("stdout", "stderr"):
            item = record[field]
            path = PurePosixPath(item["path"])
            require(
                not path.is_absolute() and ".." not in path.parts and "\\" not in item["path"] and path.as_posix() == item["path"], "Windows native stream path"
            )
            raw = files[folder + item["path"]]
            require(len(raw) == item["bytes"] and v.digest(raw) == item["sha256"], "Windows native stream integrity")
            require(field != "stderr" or not raw, "Windows native command stderr")
        records[identifier], outputs[identifier] = record, files[folder + record["stdout"]["path"]]
    require(seen == identities, "Windows complete process denominator")
    require(
        outputs["go-version"] == b"go version go1.27.2 windows/amd64\n" and records["go-version"]["argv"] == [inputs["go"], "version"],
        "Windows native Go version",
    )
    require(
        outputs["module-verify"] == b"all modules verified\n"
        and records["module-verify"]["argv"] == [inputs["go"], "-C", str(native / "module"), "mod", "verify"],
        "Windows native module verification",
    )
    require(all(records[name]["exit_code"] == 0 for name in identifiers[:4]), "Windows native positive command failed")
    require(
        records["baseline"]["argv"]
        == [
            inputs["go"],
            "-C",
            str(native / "module"),
            "test",
            "-json",
            "-count=1",
            "-p=2",
            "-parallel=1",
            "-timeout=120s",
            "-run=^(" + "|".join(inputs["expected"]) + ")$",
            ".",
        ]
        and read("native/baseline/request.json")["timeout_s"] == 300,
        "Windows native ordinary selection",
    )
    events = statements.stream(outputs["baseline"])
    passed = sorted(row["Test"] for row in events if row.get("Action") == "pass" and row.get("Test"))
    require(
        len(passed) == len(set(passed)) == inputs["expected_completions"] == 248
        and len(inputs["expected"]) == 98
        and [name for name in passed if "/" not in name] == inputs["expected"]
        and not any(row.get("Action") in {"skip", "fail", "build-fail"} for row in events),
        "Windows complete ordinary baseline",
    )
    require(
        read("baseline.json") | {"at": None}
        == {"at": None, "passed": True, "tests": 98, "completions": 248, "record_sha256": v.digest(files["native/baseline/record.json"])},
        "Windows native baseline receipt",
    )
    require(records["packages"]["argv"] == [inputs["go"], "-C", str(native / "module"), "list", "-deps", "-json", "."], "Windows native package selection")
    decoder, cursor, packages = json.JSONDecoder(), 0, []
    text = outputs["packages"].decode("utf-8")
    while cursor < len(text):
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if cursor == len(text):
            break
        package, cursor = decoder.raw_decode(text, cursor)
        packages.append(package)
    require(
        packages == read("packages.native.json") and len({row["ImportPath"] for row in packages}) == len(packages) == 326, "Windows native package metadata"
    )
    bound, sdk, tests, dependency_names = {}, {}, {}, set()
    for package in packages:
        require(not package.get("Error") and not package.get("DepsErrors") and not package.get("Incomplete"), "Windows native package error")
        directory = PureWindowsPath(package["Dir"])
        if directory.is_relative_to(native / "module"):
            origin, expected, kind = native / "module", inputs["module"], "sdk"
        elif directory.is_relative_to(PureWindowsPath(installed["install"]) / "src"):
            origin, expected, kind = (
                PureWindowsPath(installed["install"]),
                {name: row["sha256"] for name, row in installed["files"].items()},
                "standard-library",
            )
        else:
            names = [name for name in dependencies if directory.is_relative_to(PureWindowsPath(inputs["module_cache"]) / name)]
            require(len(names) == 1, "Windows native package source escape")
            name = names[0]
            origin, expected, kind = PureWindowsPath(inputs["module_cache"]) / name, dependencies[name], "dependency"
            dependency_names.add(name)
        bound_files = {}
        for field in ("GoFiles", "CgoFiles", "SFiles", "CFiles", "HFiles", "SysoFiles", "EmbedFiles"):
            for name in package.get(field, []):
                target = directory / name
                require(target.is_relative_to(origin), "Windows native package source escape")
                relative = target.relative_to(origin).as_posix()
                require(relative in expected, "Windows unbound native package source")
                bound_files[relative] = expected[relative]
                if kind == "sdk" and field == "GoFiles":
                    sdk[relative] = expected[relative]
        if kind == "sdk":
            for name in package.get("TestGoFiles", []) + package.get("XTestGoFiles", []):
                target = directory / name
                require(target.is_relative_to(origin), "Windows native test source escape")
                relative = target.relative_to(origin).as_posix()
                require(relative in inputs["module"], "Windows unbound native test source")
                tests[relative] = inputs["module"][relative]
        bound[package["ImportPath"]] = {"kind": kind, "directory": str(directory), "files": bound_files, "module": package.get("Module")}
    closure = read("package-closure/received.json")
    require(
        closure["source"] == inputs["source"]
        and closure["parent_received_sha256"] == v.digest(files["received.json"])
        and closure["original_record_sha256"] == v.digest(files["native/packages/record.json"])
        and closure["raw_metadata_sha256"] == v.digest(outputs["packages"])
        and closure["packages"] == bound
        and closure["sdk_production_files"] == sdk
        and len(sdk) == 24
        and closure["sdk_test_files"] == tests
        and len(tests) == 35
        and closure["dependency_trees"] == sorted(dependency_names)
        and len(dependency_names) == 6
        and closure["compiled_source_files"] == sum(len(row["files"]) for row in bound.values()) == 1598
        and closure["application_executions"] == 0,
        "Windows native package closure",
    )
    observations = semantic(files, inputs, manifest, cases, records, outputs, native)
    require(observations == terminal["observations"] == received["observations"], "Windows native semantic terminal disagreement")
    require(
        received["fixed_mutants"] == 34
        and received["named_assertion_failures"] == sum(len(row["assertions"]) for row in observations) == 60
        and received["native_commands"] == 38,
        "Windows native finite result denominator",
    )
    return {
        "ordinary_tests": 98,
        "ordinary_completions": 248,
        "fixed_mutants": 34,
        "named_assertion_failures": 60,
        "observations": observations,
        "native_commands": 38,
        "native_identities_retired": len(identities),
        "native_package_count": len(bound),
        "native_package_source_files": 1598,
        "installed_go_files": len(installed["files"]),
        "native_limits": original_limits,
        "packaged_retired_identities": len(all_identities),
    }


def semantic(files: dict[str, bytes], inputs: dict, manifest: dict, cases: list, records: dict, outputs: dict, native: PurePath) -> list:
    """Recompute exact overlays and original named assertion failures with the platform's original path syntax."""

    def read(name: str) -> dict | list:
        """Decode only supplied original native artifacts."""
        require(name in files, "missing native artifact")
        return v.decode(files[name])

    observations = []
    for change, case in zip(manifest["mutations"], cases):
        identifier = case["id"]
        require(change["id"] == identifier and change["test"] == case["test"], "native semantic case identity")
        original = files[change["file"]].decode()
        require(original.count(change["before"]) == 1, "native semantic replacement anchor")
        replacement = original.replace(change["before"], change["after"], 1).encode()
        prefix = "overlays/" + identifier + "/"
        mapping, target = prefix + identifier + ".json", prefix + identifier + ".go.txt"
        require(
            files[target] == replacement
            and v.digest(replacement) == case["replacement_sha256"]
            and read(mapping) == {"Replace": {str(native / change["file"]): str(native / target)}},
            "native exact semantic overlay",
        )
        record = records[identifier]
        require(
            record["argv"]
            == [
                inputs["go"],
                "-C",
                str(native / "module"),
                "test",
                "-json",
                "-count=1",
                "-p=2",
                "-parallel=1",
                "-timeout=" + case["go_timeout"],
                "-run=^" + change["test"] + "$",
                "-overlay=" + str(native / mapping),
                ".",
            ]
            and read("native/" + identifier + "/request.json")["timeout_s"] == case["outer_timeout_s"],
            "native semantic selection or deadline",
        )
        raw = outputs[identifier]
        outcome = mutate.outcome(record, raw, manifest["import"], change["test"])
        expected = {(row["test"], row["file"], row["line"]) for row in case["expected_assertion_sites"]}
        require(
            all(v.digest(files["module/" + row["file"]]) == row["test_file_sha256"] for row in case["expected_assertion_sites"]),
            "native assertion source identity",
        )
        assertions = []
        for event in (v.decode(line) for line in raw.splitlines() if line.strip()):
            if event.get("Action") != "output" or event.get("Test", "").split("/", 1)[0] != change["test"]:
                continue
            match = re.search(r"([A-Za-z0-9_]+_test\.go):([1-9][0-9]*):\s*(.*)", event.get("Output", ""))
            if match and (event["Test"], match.group(1), int(match.group(2))) in expected:
                assertions.append({"test": event["Test"], "file": match.group(1), "line": int(match.group(2)), "message": match.group(3)})
        require(outcome == "killed" and bool(assertions), "native mutant lacks prescribed semantic assertion")
        actual = {
            "id": identifier,
            "test": change["test"],
            "outcome": outcome,
            "assertions": assertions,
            "record_sha256": v.digest(files["native/" + identifier + "/record.json"]),
            "duration_ms": record["duration_ms"],
        }
        require(actual == read("native/" + identifier + "/observation.json"), "native semantic raw observation disagreement")
        observations.append(actual)
    require(observations == read("terminal.json")["observations"], "native semantic terminal disagreement")
    return observations


def reconcile(files: dict[str, bytes], inputs: dict, seal: dict) -> dict:
    """Evaluate immutable native facts independently of controller outcome summaries and archive framing."""

    def read(name: str) -> dict | list:
        """Decode one already framed native artifact without accessing native host paths."""
        require(name in files, "missing native artifact")
        return v.decode(files[name])

    terminal, owner = read("terminal.json"), read("controller.json")
    require(not seal["failed"] and not terminal["errors"] and not terminal["interrupted"] and not terminal["remaining_owned"], "producer failed or incomplete")
    require(terminal["unchanged"] == {"source": True, "module": True, "dependencies": True, "toolchain": True}, "producer input stability")
    require(terminal["cache_returned"] and terminal["duration_s"] < inputs["budget"]["wall_seconds"], "native cache or campaign deadline")
    require(read("inputs.json") == inputs and files["inputs.json"] == v.encode(inputs), "frozen native inputs")
    require(
        v.digest(files["run.py"]) == inputs["run_sha256"] and v.digest(files["collector.py"]) == inputs["collector_sha256"], "native execution source identity"
    )
    require(owner["runner_sha256"] == inputs["run_sha256"] and owner["inputs_sha256"] == v.digest(files["inputs.json"]), "native owner input identity")
    native = PurePosixPath(inputs["native_base"])
    root = PurePosixPath(inputs["source_root"])
    require(native.is_relative_to(root / "build") and PurePosixPath(inputs["compile_cache"]) == root / "build/cache/go", "protected execution path ownership")
    unit = "astra-" + native.name + ".service"
    group = "/sys/fs/cgroup/system.slice/" + unit
    require(
        owner["cgroup"] == group and owner["boot_id"] == inputs["boot_id"] and owner["invocation_id"] == seal["producer_invocation_id"],
        "native manager identity",
    )
    limits = {"cpu.max": "200000 100000", "memory.high": "2147483648", "memory.max": "2147483648", "memory.swap.max": "0", "pids.max": "64"}
    require(owner["limits"] == limits and all(terminal["resources"][name] == value for name, value in limits.items()), "native whole-task limits")
    require(0 < int(terminal["resources"]["memory.peak"]) <= 2147483648, "native memory high-water limit")
    require(
        not any(counters(terminal["resources"]["memory.events"]).values()) and not any(counters(terminal["resources"]["pids.events"]).values()),
        "native resource limit event",
    )
    cleanup = read("cleanup.native.json")
    require(
        not cleanup["failed"] and not cleanup["remaining_owned"] and cleanup["state"]["MainPID"] == "0" and not cleanup["state"]["ControlGroup"],
        "native domain retirement",
    )
    retired = {(row["identity"]["pid"], row["identity"]["start_ticks"]) for row in cleanup["retired"]}
    require(
        len(retired) == len(cleanup["retired"])
        and all(row["retired"] and row["current_start_ticks"] != row["identity"]["start_ticks"] for row in cleanup["retired"]),
        "native process retirement identity",
    )
    require(cleanup["retired"] == seal["retired"], "native retirement seal identity")
    journal = read("journal.native.json")
    require(
        any(
            row.get("MESSAGE") == unit + ": Deactivated successfully."
            and row.get("_PID") == "1"
            and row.get("_UID") == "0"
            and row.get("_EXE") == "/usr/lib/systemd/systemd"
            and row.get("_BOOT_ID") == owner["boot_id"].replace("-", "")
            and (row.get("INVOCATION_ID") or row.get("_SYSTEMD_INVOCATION_ID")) == owner["invocation_id"]
            for row in journal
        ),
        "native manager completion",
    )
    handoff, returned = read("cache-handoff.native.json"), read("cache-return.native.json")
    cache_received = read("collection-cache.native.json")
    require(
        cache_received
        == {
            "returned_claim": True,
            "actual_original_inode_returned": True,
            "prior_empty_restored": True,
            "existing_cache": inputs["existing_compile_cache"],
            "leased_cache": inputs["compile_cache"],
        },
        "native independent cache return",
    )
    require(
        handoff
        == {
            "from": inputs["existing_compile_cache"],
            "to": inputs["compile_cache"],
            "inode": inputs["existing_cache_inode"],
            "device": inputs["existing_cache_device"],
            "prior_empty_preserved": inputs["preexisting_empty_cache"],
            "owner": owner["identity"],
        },
        "exclusive cache handoff identity",
    )
    require(
        returned
        == {
            "path": inputs["existing_compile_cache"],
            "inode": inputs["existing_cache_inode"],
            "device": inputs["existing_cache_device"],
            "prior_empty_restored": inputs["preexisting_empty_cache"],
            "remaining_owned": [],
        },
        "exclusive cache return identity",
    )
    installed = read("installed-go.json")
    require(
        v.digest(files["installed-go.json"]) == inputs["install_receipt_sha256"]
        and installed["version"] == "go version go1.27.2 linux/amd64"
        and len(installed["files"]) == 15657,
        "installed Go distribution identity",
    )
    require(installed["files"]["bin/go"]["sha256"] == inputs["go_sha256"], "installed Go command identity")
    dependencies = read("dependencies.json")
    require(
        v.digest(files["dependencies.json"]) == inputs["dependencies_sha256"] and len(dependencies) == 6 and "golang.org/x/net@v0.60.0" in dependencies,
        "native module dependency identity",
    )
    inventory = read("collection-inputs.native.json")
    require(not inventory["failed"] and not inventory["producer_failed"] and not inventory["mismatches"], "collector detected changed native inputs")
    require(
        inventory["toolchain"] == installed["files"] and inventory["dependencies"] == dependencies and inventory["module"] == inputs["module"],
        "collector source or dependency denominator",
    )
    expected_bindings = {str(root / row["path"]): row["sha256"] for row in inputs["source"]["files"] if row["sha256"] is not None}
    expected_bindings |= {
        str(native / name): inputs[key]
        for name, key in (
            ("run.py", "run_sha256"),
            ("tested-module.tar.gz", "module_archive_sha256"),
            ("manifest.json", "manifest_sha256"),
            ("cases.json", "cases_sha256"),
            ("dependencies.json", "dependencies_sha256"),
            ("installed-go.json", "install_receipt_sha256"),
        )
    }
    expected_bindings |= inputs["native_compiler_bindings"]
    require(inventory["expected"] == expected_bindings, "native independent binding denominator")
    module = {name.removeprefix("module/"): v.digest(data) for name, data in files.items() if name.startswith("module/")}
    require(module == inputs["module"] and v.digest(files["tested-module.tar.gz"]) == inputs["module_archive_sha256"], "native module source identity")
    manifest, cases = read("manifest.json"), read("cases.json")
    require(
        v.digest(files["manifest.json"]) == inputs["manifest_sha256"] and v.digest(files["cases.json"]) == inputs["cases_sha256"],
        "fixed semantic recipe identity",
    )
    require(
        len(cases) == len(manifest["mutations"]) == inputs["cases"] == 34 and len({row["id"] for row in cases}) == 34, "fixed semantic mutation denominator"
    )
    identifiers = ["go-version", "module-verify", "packages", "baseline", *[row["id"] for row in cases]]
    require(set(terminal["completed"]) == set(identifiers), "native command denominator")
    require({name.split("/")[1] for name in files if name.startswith("native/")} == set(identifiers), "native raw command denominator")
    records, outputs, seen = {}, {}, {(owner["identity"]["pid"], owner["identity"]["start_ticks"])}
    require(seen <= retired, "native controller retirement missing")
    base_environment = inputs["environment"] | {
        "CGO_ENABLED": "1",
        "GOCACHE": inputs["compile_cache"],
        "GOMODCACHE": inputs["module_cache"],
        "GOMAXPROCS": "2",
        "GOOS": "linux",
        "GOARCH": "amd64",
        "PYTHONDONTWRITEBYTECODE": "1",
        "GOTOOLCHAIN": "local",
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOWORK": "off",
        "GOFLAGS": "-mod=readonly",
    }
    for identifier in identifiers:
        prefix = "native/" + identifier + "/"
        record, request, process = (read(prefix + name) for name in ("record.json", "request.json", identifier + ".process.json"))
        v.schema(record, "evidence", ("properties", "checks", "items"))
        require(record["id"] == request["id"] == identifier and record["argv"] == request["argv"] == process["argv"], "native command identity")
        require(
            record["executable"] == inputs["go"] and record["executable_sha256"] == inputs["go_sha256"] and record["platform"] == "linux-amd64-cgo",
            "native Go executable identity",
        )
        require(
            record["complete"] and record["cleanup"] and record["termination"] == "exited" and record["duration_ms"] < request["timeout_s"] * 1000,
            "native command incomplete or timed out",
        )
        require({key: record[key] for key in terminal["completed"][identifier]} == terminal["completed"][identifier], "native raw terminal disagreement")
        environment = base_environment | {"TMPDIR": str(native / "native" / identifier / "tmp")}
        require(request["environment"] == record["environment"] == environment, "native requested environment")
        require(record["resolved_environment"] == {"HOME": "/home/ubuntu", "LANG": "C.UTF-8"} | environment, "native effective environment")
        toolchain = {"command": {"path": inputs["go"], "sha256": inputs["go_sha256"]}} | {
            name: {"path": environment[name], "sha256": inputs["native_compiler_bindings"][environment[name]]} for name in ("CC", "CXX")
        }
        require(record["toolchain"] == toolchain, "native compiler executable identity")
        identity = (process["identity"]["pid"], process["identity"]["start_ticks"])
        require(
            process["cwd"] == str(root)
            and process["boot_id"] == inputs["boot_id"]
            and process["identity"]["parent"] == owner["identity"]["pid"]
            and identity in retired - seen,
            "native physical process identity",
        )
        seen.add(identity)
        require(
            all(
                prefix + record[name]["path"] in files
                and len(files[prefix + record[name]["path"]]) == record[name]["bytes"]
                and v.digest(files[prefix + record[name]["path"]]) == record[name]["sha256"]
                for name in ("stdout", "stderr")
            ),
            "native raw stream identity",
        )
        outputs[identifier] = files[prefix + record["stdout"]["path"]]
        require(not files[prefix + record["stderr"]["path"]], "native command stderr")
        records[identifier] = record
    require(seen == retired and len(seen) == 39, "native complete process denominator")
    require(outputs["go-version"] == b"go version go1.27.2 linux/amd64\n" and records["go-version"]["argv"] == [inputs["go"], "version"], "native Go version")
    require(
        outputs["module-verify"] == b"all modules verified\n"
        and records["module-verify"]["argv"] == [inputs["go"], "-C", str(native / "module"), "mod", "verify"],
        "native module verification",
    )
    require(records["packages"]["argv"] == [inputs["go"], "-C", str(native / "module"), "list", "-deps", "-json", "."], "native package discovery command")
    require(all(records[name]["exit_code"] == 0 for name in identifiers[:4]), "native positive command failed")
    baseline = records["baseline"]
    require(
        baseline["argv"]
        == [
            inputs["go"],
            "-C",
            str(native / "module"),
            "test",
            "-json",
            "-count=1",
            "-p=2",
            "-parallel=1",
            "-timeout=120s",
            "-run=^(" + "|".join(inputs["expected"]) + ")$",
            ".",
        ]
        and read("native/baseline/request.json")["timeout_s"] == 300,
        "native ordinary selection or deadline",
    )
    events = statements.stream(outputs["baseline"])
    passed = sorted(row["Test"] for row in events if row.get("Action") == "pass" and "Test" in row)
    require(
        len(passed) == len(set(passed)) == inputs["expected_completions"] == 248
        and passed == inputs["expected_completion_names"]
        and [name for name in passed if "/" not in name] == inputs["expected"],
        "native complete ordinary completion denominator",
    )
    require(not any(row.get("Action") in {"skip", "fail", "build-fail"} for row in events), "native ordinary skip or failure")
    decoder, cursor, packages = json.JSONDecoder(), 0, []
    text = outputs["packages"].decode()
    while cursor < len(text):
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if cursor == len(text):
            break
        package, cursor = decoder.raw_decode(text, cursor)
        packages.append(package)
    require(packages == read("packages.native.json") and len({row["ImportPath"] for row in packages}) == len(packages), "native package graph identity")
    allowed = {str(native / "module" / name): sha for name, sha in inputs["module"].items()}
    allowed |= {str(PurePosixPath(installed["install"]) / name): row["sha256"] for name, row in installed["files"].items()}
    allowed |= {str(PurePosixPath(inputs["module_cache"]) / module / name): sha for module, values in dependencies.items() for name, sha in values.items()}
    compiled = {}
    for package in packages:
        require(not package.get("Error") and not package.get("DepsErrors") and not package.get("Incomplete"), "native package graph error")
        directory = PurePosixPath(package["Dir"])
        require(
            any(
                directory.is_relative_to(path)
                for path in (
                    native / "module",
                    PurePosixPath(installed["install"]) / "src",
                    *[PurePosixPath(inputs["module_cache"]) / name for name in dependencies],
                )
            ),
            "native package source escape",
        )
        for field in (
            "GoFiles",
            "CgoFiles",
            "CFiles",
            "CXXFiles",
            "MFiles",
            "HFiles",
            "FFiles",
            "SFiles",
            "SwigFiles",
            "SwigCXXFiles",
            "SysoFiles",
            "EmbedFiles",
        ):
            for name in package.get(field, []):
                path = str(directory / name)
                require(path in allowed, "unbound native package source")
                compiled[path] = allowed[path]
    require(any(row["ImportPath"] == manifest["import"] and row["Dir"] == str(native / "module") for row in packages), "native SDK import identity")
    observations = semantic(files, inputs, manifest, cases, records, outputs, native)
    manager = read("dispatch.native.json")
    require(manager["argv"] == inputs["manager_argv"] and manager["exit_code"] == 0, "native actual manager return")
    require(
        manager["stderr"].startswith("Running as unit: " + unit + "; invocation ID: " + owner["invocation_id"] + "\n")
        and "Finished with result: success" in manager["stderr"]
        and "Main processes terminated with: code=exited, status=0/SUCCESS" in manager["stderr"],
        "native actual manager completion",
    )
    rows = [v.decode(line) for line in manager["stdout"].splitlines() if line.strip()]
    expected_rows = [{"baseline": "passed", "tests": len(inputs["expected"]), "completions": len(passed), "duration_ms": baseline["duration_ms"]}]
    expected_rows += [
        {"id": row["id"], "outcome": row["outcome"], "named_assertions": len(row["assertions"]), "duration_ms": row["duration_ms"]} for row in observations
    ]
    expected_rows += [
        {
            "completed_commands": len(records),
            "mutants_observed": len(observations),
            "killed": len(observations),
            "errors": [],
            "duration_s": terminal["duration_s"],
        }
    ]
    require(rows == expected_rows and len(rows) == 36, "native actual manager command stream")
    return {
        "ordinary_tests": len(inputs["expected"]),
        "ordinary_completions": len(passed),
        "fixed_mutants": len(observations),
        "named_assertion_failures": sum(len(row["assertions"]) for row in observations),
        "observations": observations,
        "native_commands": len(records),
        "native_identities_retired": len(retired),
        "native_package_count": len(packages),
        "native_package_source_files": compiled,
        "installed_go_files": len(installed["files"]),
        "memory_peak_bytes": int(terminal["resources"]["memory.peak"]),
        "cache_returned": True,
    }
