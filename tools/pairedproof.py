"""Recompute the original 512-execution performance interpretation from authenticated archive members."""

import io
from pathlib import PurePosixPath
import statistics
import tarfile

from bench import cgroups, compare, paired, run
from tools import verify as v


def require(condition: bool, message: str) -> None:
    """Reject incomplete, inconsistent or weakened evidence with its affected boundary."""
    if not condition:
        v.reject("qualification-performance", message)


def counters(text: str) -> dict[str, int]:
    """Preserve every native counter, including newly named memory throttle events."""
    return {name: int(value) for name, value in (row.split() for row in text.splitlines())}


def reference(files: dict[str, bytes], directory: PurePosixPath, item: dict, maximum: int) -> bytes:
    """Resolve a bounded native stream inside its authenticated regular-member archive."""
    name = item["path"]
    path = PurePosixPath(name)
    require(
        bool(name) and not path.is_absolute() and path.as_posix() == name and ".." not in path.parts and "\\" not in name and ":" not in name, "stream path"
    )
    data = files[(directory / path).as_posix()]
    require(len(data) <= maximum and len(data) == item["bytes"] and v.digest(data) == item["sha256"], "stream integrity")
    return data


def diagnostics(evidence: list[dict], trace: list[dict]) -> dict:
    """Describe drift, ordering and adjacent blocks without adding acceptance thresholds or claiming independence."""

    def commit(pair: dict, side: str) -> float:
        """Read the commit throughput metric for one side of a measured pair."""
        return next(row["operations_per_second"] for row in pair[side]["metrics"] if row["metric"] == "comet.commit")

    def adjacent(values: list[float]) -> float | None:
        """Return lag-one correlation, or absence when either series has insufficient variation."""
        if len(values) < 3 or len(set(values[:-1])) == 1 or len(set(values[1:])) == 1:
            return None
        return statistics.correlation(values[:-1], values[1:])

    cases = []
    for item in evidence:
        formal = [pair for pair in item["pairs"] if pair["phase"] == "measurement"]
        changes = [commit(pair, "candidate") / commit(pair, "baseline") - 1 for pair in formal]
        blocks = [statistics.median(changes[start : start + 4]) for start in range(0, len(changes), 4)]
        cases.append(
            {
                "case": item["case"],
                "consecutive_four_pair_medians": blocks,
                "adjacent_block_pearson": adjacent(blocks),
                "consecutive_quarter_medians": [statistics.median(changes[start : start + 12]) for start in range(0, 48, 12)],
                "median_by_first_side": {
                    side: statistics.median(change for pair, change in zip(formal, changes) if pair["order"][0] == side) for side in ("baseline", "candidate")
                },
                "side_first_to_last_quarter": {
                    side: [statistics.median(commit(pair, side) for pair in formal[start : start + 12]) for start in range(0, 48, 12)]
                    for side in ("baseline", "candidate")
                },
            }
        )
    cpu, cpu_anomalies = [], []
    for before, after in zip(trace, trace[1:]):
        left, right = ([int(value) for value in item["host_cpu"].split()[1:9]] for item in (before, after))
        elapsed = after["monotonic_ns"] - before["monotonic_ns"]
        require(elapsed > 0, "nonmonotonic native time counters")
        delta = [b - a for a, b in zip(left, right)]
        total = sum(delta)
        if total <= 0 or any(value < 0 for value in delta):
            cpu_anomalies.append({"utc_ns": after["utc_ns"], "host_cpu_delta": delta})
            continue
        cpu.append(
            {
                "host_busy_fraction": (total - delta[3] - delta[4]) / total,
                "host_iowait_fraction": delta[4] / total,
                "host_steal_fraction": delta[7] / total,
                "campaign_cpu_equivalent": (counters(after["root"]["cpu.stat"])["usage_usec"] - counters(before["root"]["cpu.stat"])["usage_usec"])
                / (elapsed / 1000),
                "clock_elapsed_difference_us": (after["utc_ns"] - before["utc_ns"] - elapsed) / 1000,
            }
        )
    return {
        "cases": cases,
        "host_available_minimum_bytes": min(item["host"]["available"] for item in trace),
        "cpu_and_clock": {
            name: {"minimum": min(row[name] for row in cpu), "median": statistics.median(row[name] for row in cpu), "maximum": max(row[name] for row in cpu)}
            for name in (cpu[0] if cpu else {})
        },
        "cpu_counter_anomalies": cpu_anomalies,
        "boundary": "Descriptive observations only. Twelve block medians cannot prove stationarity, independence or nominal confidence-interval coverage. No sample is excluded and no numerical gate changes in response to these diagnostics.",
    }


def reconcile(files: dict[str, bytes], inputs: dict, seal: dict) -> tuple[list[dict], dict]:
    """Use source, commands, raw SDK output, per-service identity and kernel counters as independent sample inputs."""
    received = PurePosixPath("evidence")

    def read(path: PurePosixPath) -> bytes:
        """Resolve only already authenticated regular archive members."""
        return files[path.relative_to(received).as_posix()]

    def digest(path: PurePosixPath) -> str:
        """Hash immutable member bytes rather than a second filesystem lookup."""
        return v.digest(read(path))

    terminal = v.decode(read(received / "terminal.json"))
    require(
        not seal["failed"] and not terminal["errors"] and not terminal["interrupted"] and not terminal["remaining_owned"] and terminal["inputs_unchanged"],
        "producer failed or incomplete",
    )
    require(len(terminal["records"]) == 512, "physical execution denominator")
    require(paired.schedule(inputs["policy"], inputs["cases"]) == inputs["schedule"], "changed fixed schedule")
    require(digest(received / "campaign-run.py") == inputs["run_sha256"], "controller source identity")
    require(digest(received / "artifacts.native.json") == inputs["artifacts_sha256"], "raw artifact identity")
    with tarfile.open(fileobj=io.BytesIO(read(received / "source.tar.gz")), mode="r:gz") as archive:
        require({member.name: v.digest(archive.extractfile(member).read()) for member in archive} == inputs["files"], "frozen source identity")
        policy_bytes = archive.extractfile("bench/performance.json").read()
        require(v.digest(policy_bytes) == inputs["policy_sha256"] and v.decode(policy_bytes) == inputs["policy"], "policy/source identity")
    native_root = PurePosixPath(inputs["source_root"])
    native_base = PurePosixPath("/home/ubuntu/verdandi/astra/build/results/assurance/go-upgrade-performance-current-1")
    native_output = native_root / "build/results" / native_base.name
    deployment = inputs["policy"]["deployment"]
    artifact = v.decode(read(received / "artifacts.native.json"))
    cohort = {
        "baseline": {name: row["sha256"] for name, row in inputs["baseline"].items()},
        "candidate": {name: row["sha256"] for name, row in inputs["candidate"].items()},
    }
    require(artifact["files"] == cohort["candidate"] and artifact["baseline"] == cohort["baseline"], "artifact cohort disagreement")
    collector_identity = v.decode(read(received / "collection-identities.native.json"))
    require(not collector_identity["mismatches"] and not collector_identity["producer_failed"], "collector detected changed inputs/runtime")
    owner = v.decode(read(received / "controller.json"))
    require(
        owner["script_sha256"] == inputs["run_sha256"]
        and owner["inputs_sha256"] == digest(received / "campaign-inputs.json")
        and owner["boot_id"] == inputs["boot_id"]
        and owner["invocation_id"] == seal["producer_invocation_id"],
        "controller input/native invocation identity",
    )
    journal = v.decode(read(received / "journal.native.json"))
    require(
        any(
            row.get("MESSAGE") == "astra-go-upgrade-performance-current-1.service: Deactivated successfully."
            and (row.get("INVOCATION_ID") or row.get("_SYSTEMD_INVOCATION_ID")) == owner["invocation_id"]
            and row.get("_BOOT_ID") == owner["boot_id"].replace("-", "")
            for row in journal
        ),
        "missing original native producer completion",
    )
    identities = {name: v.digest(v.encode({"artifacts": files, "runtime": artifact["runtime"]})) for name, files in cohort.items()}
    evidence = [{"case": case, "pairs": []} for case in inputs["cases"]]
    peaks = {role: {"cgroup_bytes": 0, "rss_hwm_bytes": 0} for role in cgroups.ROLES}
    completed = [received / name for name in files if PurePosixPath(name).match("commands/sample-*/record.json")]
    require(len(completed) == 512, "missing or extra native records")
    root_peak = 0
    formal_times: list[list[int]] = [[] for _ in inputs["cases"]]
    active_windows = []
    manager_names = {"INVOCATION_ID", "JOURNAL_STREAM", "LOGNAME", "MEMORY_PRESSURE_WATCH", "MEMORY_PRESSURE_WRITE", "SHELL", "SYSTEMD_EXEC_PID", "USER"}
    first_request = v.decode(read(received / "commands/sample-0000/command.json"))["environment"]
    manager = {key: first_request[key] for key in manager_names}
    require(
        manager["INVOCATION_ID"] == owner["invocation_id"]
        and manager["SYSTEMD_EXEC_PID"] == str(owner["identity"]["pid"])
        and manager["USER"] == manager["LOGNAME"] == "ubuntu"
        and manager["SHELL"] == "/bin/bash"
        and manager["MEMORY_PRESSURE_WATCH"] == "/sys/fs/cgroup/system.slice/astra-go-upgrade-performance-current-1.service/memory.pressure"
        and all(part.isdecimal() for part in manager["JOURNAL_STREAM"].split(":"))
        and len(manager["JOURNAL_STREAM"].split(":")) == 2,
        "declared outer manager identity",
    )
    retired = {(row["pid"], row["start_ticks"]) for row in seal["retired"]}
    seen = {(owner["identity"]["pid"], owner["identity"]["start_ticks"])}
    require(seen <= retired, "controller retirement identity missing")
    for index, entry in enumerate(inputs["schedule"]):
        name = "sample-" + str(index).zfill(4)
        stage = received / "commands" / name
        native_stage = native_output / name
        record = v.decode(read(stage / "record.json"))
        request = v.decode(read(stage / "command.json"))
        case = inputs["cases"][entry["case"]]
        require(v.decode(read(stage / "entry.json")) == entry and v.decode(read(stage / "case.json")) == case, "sample identity/workload")
        binaries = PurePosixPath(next(iter(inputs["baseline"].values()))["path"]).parent if entry["side"] == "baseline" else native_base / "candidate/bin"
        expected = [
            "/usr/bin/python3",
            "-B",
            "-m",
            "bench.paired",
            "--policy",
            str(native_root / "bench/performance.json"),
            "--case",
            str(native_stage / "case.json"),
            "--binaries",
            str(binaries),
            "--output",
            str(native_stage / "measurement"),
        ]
        require(record["argv"] == request["argv"] == expected, "changed native command")
        process = v.decode(read(stage / (name + ".process.json")))
        process_key = (process["identity"]["pid"], process["identity"]["start_ticks"])
        require(
            process["argv"] == expected
            and process["cwd"] == str(native_root)
            and process["boot_id"] == inputs["boot_id"]
            and process["identity"]["parent"] == owner["identity"]["pid"]
            and process_key in retired - seen,
            "physical process identity or retirement",
        )
        seen.add(process_key)
        public = {key: value for key, value in request["environment"].items() if key not in manager_names}
        require(
            {key: request["environment"][key] for key in manager_names} == manager
            and record["environment"] == record["resolved_environment"] == public
            and public["TMPDIR"] == str(native_stage / "tmp"),
            "changed environment/temporary owner",
        )
        require(record["exit_code"] == 0 and record["complete"] and record["cleanup"] and record["termination"] == "exited", "unsuccessful sample")
        active_windows.append((round(v.stamp(record["started_at"]).timestamp() * 10**9), round(v.stamp(record["finished_at"]).timestamp() * 10**9)))
        require(
            terminal["records"][index] == entry | {key: record[key] for key in ("exit_code", "complete", "cleanup", "termination", "duration_ms")},
            "terminal/native record disagreement",
        )
        stdout = reference(files, stage.relative_to(received), record["stdout"], 16 * 1024**2)
        reference(files, stage.relative_to(received), record["stderr"], 16 * 1024**2)
        measurement = stage / "measurement"
        result = v.decode(read(measurement / "sample.json"))
        sample_terminal = v.decode(read(measurement / "sample.terminal.json"))
        require(
            v.decode(stdout) == result == sample_terminal["result"] and not sample_terminal["errors"] and result["case"] == case,
            "SDK/result/native stream disagreement",
        )
        raw = read(measurement / "comet.log").decode("utf-8")
        metrics = run.observations(raw, case)
        rows = [v.decode(line) for line in raw.encode().splitlines() if line.startswith(b"{")]
        writes = next(row["writes"] for row in rows if row.get("topology") == "distributed-writers-v1")
        require(metrics == result["metrics"] and writes == result["writes"], "raw SDK counters differ")
        native = v.decode(read(measurement / "cgroups.terminal.json"))
        require(not native["errors"] and set(native["roles"]) == set(cgroups.ROLES), "incomplete six-service/SDK native domain")
        expected_root_limits = {
            "memory.high": str(deployment["memory_high_bytes"]),
            "memory.max": str(deployment["memory_maximum_bytes"]),
            "memory.swap.max": "0",
            "pids.max": "2048",
            "cpu.max": f"{deployment['vcpus'] * 100000} 100000",
        }
        require(all(native["root"][key] == value for key, value in expected_root_limits.items()), "wrong native root limits")
        root_peak = max(root_peak, int(native["root"]["memory.peak"]))
        require(not any(counters(native["root"]["memory.events"]).values()) and not counters(native["root"]["pids.events"])["max"], "root limit event")
        require(not counters(native["root"]["cpu.stat"])["nr_throttled"], "root CPU quota throttle")
        require(int(native["root"]["memory.peak"]) <= deployment["memory_high_bytes"], "whole-test-tree ceiling")
        endpoints = []
        for node in range(3):
            events = [v.decode(line) for line in read(measurement / ("star-" + str(node) + ".log")).splitlines() if line.startswith(b"{")]
            listening = [item["fields"]["endpoint"] for item in events if item.get("event") == "comet_listening"]
            require(len(listening) == 1 and any(item.get("event") == "business_ready" for item in events), "missing native Star readiness")
            endpoints.extend(listening)
        require(len(set(endpoints)) == 3 and all(endpoint.startswith("127.0.0.1:") for endpoint in endpoints), "wrong native SDK endpoints")
        for role in cgroups.ROLES:
            actor = native["roles"][role]
            owned = v.decode(read(measurement / (role + ".identity.json")))
            launch = v.decode(read(measurement / (role + ".launch.json")))
            identity_key = (owned["identity"]["pid"], owned["identity"]["start_ticks"])
            require(
                identity_key in retired - seen and owned["identity"]["parent"] == process["identity"]["pid"],
                "missing, repeated or unrelated service process identity",
            )
            seen.add(identity_key)
            executable = binaries / ("star" if role.startswith("star-") else "comet_bench" if role == "comet" else role)
            require(owned["identity"] == actor["identity"] and owned["executable"] == str(executable), "service identity/executable")
            require(owned["argv"] == launch["command"] and owned["argv"][0] == str(executable), "service argv")
            if role == "comet":
                expected_sdk = [
                    str(executable),
                    ",".join(endpoints),
                    str(native_root / "tests/fixtures/star-b/ca.pem") if case["tls"] else "-",
                    case["domain"],
                    *(str(case[key]) for key in ("records", "bytes", "attr", "watchers", "writers", "seconds", "ttl", "rate")),
                ]
                require(owned["argv"] == expected_sdk, "actual SDK workload arguments")
            require(
                owned["cgroup"] == launch["cgroup"]
                and owned["cgroup"] == "/sys/fs/cgroup/system.slice/astra-go-upgrade-performance-current-1.service/measurement-" + role,
                "service cgroup ownership",
            )
            require(actor["retired"] and actor["populated"] == 0 and not actor["accounting"]["cgroup.procs"], "service residue")
            require(
                not any(counters(actor["accounting"]["memory.events"]).values()) and not counters(actor["accounting"]["pids.events"])["max"],
                "service native limit event",
            )
            require(not counters(actor["accounting"]["cpu.stat"])["nr_throttled"], "service CPU quota throttle")
            require(
                all(actor["accounting"][key] == launch["limits"][key] == owned["limits"][key] for key in cgroups.LIMITS), "limit changed after service launch"
            )
            require(
                actor["accounting"]["memory.swap.max"] == "0"
                and actor["accounting"]["memory.high"] == "max"
                and actor["accounting"]["pids.max"] == "256"
                and actor["accounting"]["cpu.max"] == "max 100000",
                "wrong service limit policy",
            )
            peak = int(actor["accounting"]["memory.peak"])
            peaks[role]["cgroup_bytes"] = max(peaks[role]["cgroup_bytes"], peak)
            if role != "comet":
                require(
                    int(actor["accounting"]["memory.max"]) == deployment["service_peak_maximum_bytes"] // seal["page_bytes"] * seal["page_bytes"],
                    "wrong pre-exec service memory ceiling",
                )
                require(peak <= deployment["service_peak_maximum_bytes"], "service cgroup peak")
            else:
                require(actor["accounting"]["memory.max"] == "max", "SDK must remain within its whole-tree ceiling")
        traces = v.decode(read(measurement / "resources.json"))
        require(
            bool(traces)
            and all(set(cgroups.ROLES) - {"comet"} <= set(trace["processes"]) <= set(cgroups.ROLES) for trace in traces)
            and set().union(*(set(trace["processes"]) for trace in traces)) == set(cgroups.ROLES),
            "missing actual RSS/process trace",
        )
        for trace in traces:
            for role, observed in trace["processes"].items():
                peaks[role]["rss_hwm_bytes"] = max(peaks[role]["rss_hwm_bytes"], observed["hwm"])
                if role != "comet":
                    require(observed["hwm"] <= deployment["service_peak_maximum_bytes"], "service physical RSS high-water ceiling")
        pair = entry["pair"]
        selected = evidence[entry["case"]]["pairs"]
        if len(selected) == pair:
            selected.append({"index": pair, "phase": entry["phase"], "order": entry["order"]})
        require(len(selected) == pair + 1 and entry["side"] not in selected[pair], "duplicate/misordered pair side")
        selected[pair][entry["side"]] = {"artifact_sha256": identities[entry["side"]], "writes": writes, "metrics": metrics}
        if entry["phase"] == "measurement":
            formal_times[entry["case"]].append(index)
    trace = [v.decode(line) for line in read(received / "resources.jsonl").splitlines()]
    require(len(trace) >= 2, "missing continuous native trace")
    root_limits = {
        "memory.high": str(deployment["memory_high_bytes"]),
        "memory.max": str(deployment["memory_maximum_bytes"]),
        "memory.swap.max": "0",
        "pids.max": "2048",
        "cpu.max": f"{deployment['vcpus'] * 100000} 100000",
    }
    require(all(all(item["root"][name] == value for name, value in root_limits.items()) for item in trace), "continuous root limits changed")
    active_trace = [item for item in trace if any(start <= item["utc_ns"] <= end for start, end in active_windows)]
    require(
        bool(active_trace)
        and all(item["clock"]["result"] >= 0 and not item["clock"]["status"] & 64 and item["clock"]["maxerror"] <= 500000 for item in active_trace),
        "unqualified active native clock trace",
    )
    require(all(any(start <= item["utc_ns"] <= end for item in trace) for start, end in active_windows), "missing sample clock exposure")
    require(
        len({item["host"]["total"] for item in trace}) == 1 and len({(item["host"]["swap_in"], item["host"]["swap_out"]) for item in trace}) == 1,
        "changing host memory/paging",
    )
    require(
        all(not any(counters(item["root"]["memory.events"]).values()) and not counters(item["root"]["pids.events"])["max"] for item in trace),
        "continuous native limit event",
    )
    require(all(not counters(item["root"]["cpu.stat"])["nr_throttled"] for item in trace), "continuous CPU quota throttle")
    root_peak = max(root_peak, max(int(item["root"]["memory.peak"]) for item in trace))
    require(root_peak <= deployment["memory_high_bytes"], "continuous memory ceiling")
    return evidence, {
        "root_cgroup_peak_bytes": root_peak,
        "roles": peaks,
        "continuous_samples": len(trace),
        "active_clock_samples": len(active_trace),
        "formal_physical_indices": formal_times,
        "cleared_manager_environment": manager,
        "diagnostics": diagnostics(evidence, trace),
    }
