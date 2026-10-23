"""Compare legacy Redis C++ and Comet C++ with a shared workload using existing artifacts, without builds or downloads."""

from __future__ import annotations

from collections.abc import Iterator
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import uuid
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("measure", ROOT / "bench/run.py")
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)


@contextmanager
def server(arguments: argparse.Namespace | SimpleNamespace) -> Iterator[None]:
    """Own a private Redis container by default; external mode requires an existing lifecycle owner."""
    if arguments.redis:
        if not arguments.redis_pid:
            raise ValueError("External Redis requires its owned process PID")
        yield
        return
    docker = (["sudo", "-n"] if arguments.sudo else []) + ["docker"]
    name = "astra-baseline-" + uuid.uuid4().hex[:12]
    port = measure.port()
    try:
        subprocess.run(
            [
                *docker,
                "run",
                "--pull=never",
                "--rm",
                "-d",
                "--name",
                name,
                "--label",
                "astra.baseline=" + name,
                "--network",
                "host",
                "--memory",
                "512m",
                "--memory-swap",
                "512m",
                "redis:8.8.0",
                "redis-server",
                "--bind",
                "127.0.0.1",
                "--port",
                str(port),
                "--save",
                "",
                "--appendonly",
                "no",
            ],
            check=True,
            timeout=30,
            stdout=subprocess.PIPE,
        )
        arguments.redis = f"127.0.0.1:{port}"
        arguments.redis_pid = int(
            subprocess.check_output(
                [*docker, "inspect", "--format", "{{.State.Pid}}", name],
                text=True,
                timeout=10,
            )
        )
        deadline = time.monotonic() + 10
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1) as connection:
                    connection.sendall(b"*1\r\n$4\r\nPING\r\n")
                    if connection.recv(128) == b"+PONG\r\n":
                        break
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError("Owned Redis failed to start")
            time.sleep(0.05)
        yield
    finally:
        # A timed-out run may already have created the container; verify this run's unique name and label before reclaiming it.
        state = subprocess.run([*docker, "inspect", name], capture_output=True, text=True, timeout=10)
        if state.returncode == 0:
            container = json.loads(state.stdout)[0]
            if container["Config"].get("Labels", {}).get("astra.baseline") != name:
                raise RuntimeError("Container ownership mismatch; refusing cleanup")
            subprocess.run(
                [*docker, "rm", "--force", container["Id"]],
                check=True,
                timeout=15,
                stdout=subprocess.PIPE,
            )
        elif "No such" not in state.stderr:
            raise RuntimeError("Cannot verify owned container cleanup: " + state.stderr)


def command(binary: Path, endpoint: str, case: dict) -> list[str]:
    """Use one argument order with shared parsing and relationship validation for both adapters."""
    return [
        str(binary),
        endpoint,
        case["domain"],
        case["mode"],
        *[
            str(case[name])
            for name in (
                "records",
                "groups",
                "fanout",
                "clients",
                "writers",
                "bytes",
                "attr",
                "seconds",
                "ttl",
                "rate",
                "poll",
            )
        ],
        "v1",
        *([str(case["legacy_view_ms"])] if "legacy_view_ms" in case else []),
    ]


def topology(case: dict) -> dict:
    """Require three Stars for standard baselines; smaller topologies are explicit diagnostics with writes and subscriptions on every node."""
    count = case.get("stars", 3)
    if type(count) is not int or not 1 <= count <= 8:
        raise ValueError("stars must be an integer in 1..8")
    if count < 3 and case.get("diagnostic") is not True:
        raise ValueError("Standard baseline requires at least three Stars")
    if (
        case["clients"] < count
        or case["clients"] % count
        or case["writers"] < count
        or case["writers"] % count
        or case["records"] < case["clients"]
        or case["records"] % case["clients"]
        or case["fanout"] < count
    ):
        raise ValueError("Every Star must receive writes and every Scope must be watched across all Stars")
    return dict(case, stars=count)


def comet(arguments: argparse.Namespace, case: dict, directory: Path) -> list[dict]:
    """Pass all real Star addresses to the probe instead of reducing a multi-node fixture to first-node writes."""
    fixture = dict(case, tls=False, watchers=case["fanout"])
    return measure.cluster(
        arguments.binaries,
        fixture,
        directory,
        lambda endpoints: command(arguments.binaries / "baseline_comet", ",".join(endpoints), case),
    )


def redis(arguments: argparse.Namespace, case: dict, directory: Path) -> list[dict]:
    """Use only the operator's explicitly selected private Redis; verify loopback and a live owner before clearing data."""
    host, port = arguments.redis.rsplit(":", 1)
    if host != "127.0.0.1" or not Path(f"/proc/{arguments.redis_pid}").exists():
        raise RuntimeError("Expected owned loopback Redis process")
    # The outer owner must create this service with --pull=never and remove it in finally; never target a business database.
    with socket.create_connection((host, int(port)), timeout=5) as connection:
        connection.sendall(b"*1\r\n$8\r\nFLUSHALL\r\n")
        if connection.recv(128) != b"+OK\r\n":
            raise RuntimeError("Dedicated Redis reset failed")
    traces = []
    log = directory / "redis-sdk.log"
    with log.open("w") as stream:
        process = measure.popen(
            command(arguments.legacy, arguments.redis, case),
            cwd=ROOT,
            env=measure.environment(),
            stdout=stream,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 180
            while process.poll() is None:
                sample = measure.resources(
                    [
                        ("sdk", process),
                        ("redis", SimpleNamespace(pid=arguments.redis_pid)),
                    ]
                )
                traces.append(sample)
                if sample["available"] < 128 * 1024 * 1024 or time.monotonic() > deadline:
                    raise RuntimeError("Legacy sample exceeded memory/time budget")
                time.sleep(0.2)
            if process.returncode:
                raise measure.ProbeFailure(f"Legacy probe failed: {log.read_text()[-3000:]}")
            return [json.loads(line) for line in log.read_text().splitlines() if line.startswith('{"metric":')]
        finally:
            measure.stop_process(process)
            (directory / "resources.json").write_text(json.dumps(traces, indent=2))


def run(arguments: argparse.Namespace) -> None:
    """Alternate sample order and run each side separately so they do not compete for the VM's CPU or memory."""
    # Reject idle topologies before creating output or starting Stars; record standard versus diagnostic node counts explicitly.
    cases = [topology(case) for case in json.loads(arguments.cases.read_text())]
    arguments.output.mkdir(parents=True, exist_ok=False)
    identity = {
        "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cpus": os.cpu_count(),
        "affinity": sorted(os.sched_getaffinity(0)),
        "kernel": os.uname().release,
        "resources": measure.resources(),
        "binaries": {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (
                arguments.legacy,
                *(arguments.binaries / name for name in ("baseline_comet", "star", "pulsar", "polaris", "astrolabe")),
            )
        },
    }
    (arguments.output / "identity.json").write_text(json.dumps(identity, indent=2))
    results = []
    try:
        for number, case in enumerate(cases):
            for repeat in range(arguments.repeat):
                for implementation in (("redis", "comet") if (number + repeat) % 2 == 0 else ("comet", "redis")):
                    directory = arguments.output / f"case-{number}-round-{repeat}-{implementation}"
                    directory.mkdir()
                    before = measure.resources()
                    result = dict(
                        case=case,
                        number=number,
                        round=repeat,
                        implementation=implementation,
                        before=before,
                    )
                    print(
                        json.dumps({"start": directory.name, "parameters": case}),
                        flush=True,
                    )
                    try:
                        if implementation == "redis":
                            values = redis(arguments, case, directory)
                        else:
                            values = comet(arguments, case, directory)
                        result["measurements"] = values
                        if {value["metric"] for value in values} != ({"commit", "visible", "sampler"} if case["mode"] == "visible" else {"commit", "sampler"}):
                            raise RuntimeError("Incomplete probe output")
                        result["passed"] = True
                    except measure.ProbeFailure as failure:
                        result.update(passed=False, error=str(failure))
                    except Exception as failure:
                        result.update(passed=False, error=str(failure))
                        raise
                    finally:
                        after = measure.resources()
                        tracefile = directory / "resources.json"
                        traces = json.loads(tracefile.read_text()) if tracefile.exists() else []
                        result.update(
                            after=after,
                            stable_memory=len({sample["total"] for sample in [before, *traces, after]}) == 1
                            and before["swap_in"] == after["swap_in"]
                            and before["swap_out"] == after["swap_out"],
                        )
                        results.append(result)
                        (arguments.output / "results.json").write_text(json.dumps(results, indent=2))
                        print(json.dumps(result), flush=True)
    finally:
        (arguments.output / "results.json").write_text(json.dumps(results, indent=2))
    if any(not result["passed"] for result in results):
        raise measure.ProbeFailure("One or more workload samples failed; see results.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--legacy", type=Path, required=True)
    parser.add_argument("--redis", help="Externally owned private empty Redis loopback endpoint; ALL data will be cleared")
    parser.add_argument("--redis-pid", type=int)
    parser.add_argument("--sudo", action="store_true", help="Run Docker through explicitly authorized sudo -n")
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeat", type=int, choices=range(1, 6), default=3)
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, measure.terminate)
    arguments = parser.parse_args()
    with server(arguments):
        run(arguments)
