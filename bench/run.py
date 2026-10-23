"""Measure native storage and real multi-Star/Comet workloads using existing Release artifacts, without builds or downloads."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from types import SimpleNamespace
import argparse
import base64
from contextlib import ExitStack
import hashlib
from http.cookiejar import CookieJar
import json
import math
import os
from pathlib import Path
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.support import popen, stop_process
from tests.test_comet_process import port
from tests.test_pulsar import wait, terminate
from tools.build import environment


class ProbeFailure(RuntimeError):
    """Distinguish a probe's explicit workload failure from environment or cleanup failures."""


def observations(text: str, case: dict) -> list[dict]:
    """Require native nonempty metrics and, for system qualification, proven writes at every Star."""
    records = [json.loads(line) for line in text.splitlines() if line.startswith("{")]
    metrics = [item for item in records if "metric" in item]
    if not metrics or any(type(item.get("count")) is not int or item["count"] <= 0 for item in metrics):
        raise ProbeFailure("Empty benchmark observations cannot qualify")
    if case.get("qualification"):
        topology = [item for item in records if item.get("topology") == "distributed-writers-v1"]
        if len(topology) != 1:
            raise ProbeFailure("Missing native distributed-writer topology")
        writes = topology[0].get("writes", [])
        if len(writes) != case["stars"] or any(type(value) is not int or value <= 0 for value in writes):
            raise ProbeFailure("Every Star must confirm at least one local write")
        if (
            len(metrics) != 2
            or {item["metric"] for item in metrics} != {"comet.commit", "comet.visible"}
            or any(item["count"] != sum(writes) for item in metrics)
        ):
            raise ProbeFailure("Topology and completed-operation counters disagree")
        for item in metrics:
            values = [item.get(name) for name in ("seconds", "operations_per_second", "p50_us", "p95_us", "p99_us", "p999_us")]
            if (
                type(item.get("samples")) is not int
                or item["samples"] != item["count"]
                or any(type(value) not in (int, float) or not math.isfinite(value) or value <= 0 for value in values)
            ):
                raise ProbeFailure("Missing or invalid native latency observations")
            if values[2:] != sorted(values[2:]) or not math.isclose(values[1], item["count"] / values[0], rel_tol=0.0001):
                raise ProbeFailure("Native latency or throughput counters disagree")
    return metrics


def scenario(case: dict) -> None:
    """Reject malformed or expired-before-measurement workloads before starting a cluster."""
    limits = {
        "records": (1, 500),
        "bytes": (16, 4096),
        "attr": (0, 65536),
        "watchers": (1, 50),
        "writers": (1, 32),
        "seconds": (2, 30),
        "ttl": (1000, 600000),
        "rate": (0, 10000),
        "stars": (1, 16),
    }
    if any(type(case.get(key)) is not int or not low <= case[key] <= high for key, (low, high) in limits.items()):
        raise ProbeFailure("Invalid network benchmark bounds")
    if (
        case.get("domain") not in ("catalog", "ephemeris")
        or any(type(case.get(key, False)) is not bool for key in ("tls", "auth", "qualification"))
        or case["writers"] > case["records"]
    ):
        raise ProbeFailure("Invalid network benchmark domain or topology")
    if case["domain"] == "catalog" and case["ttl"] < (case["seconds"] + 120) * 1000:
        raise ProbeFailure("Catalog TTL does not cover initialization, measurement and draining")
    if case.get("qualification") and (case["stars"] < 3 or case["writers"] < case["stars"] or case["watchers"] < case["stars"]):
        raise ProbeFailure("System qualification requires local writers and readers on at least three Stars")


def resources(processes: Iterable[tuple[str, subprocess.Popen | SimpleNamespace]] = ()) -> dict:
    """Sample actual Linux memory, paging, and owned processes rather than treating a dynamic maximum as allocated memory."""
    memory = {key: int(value.split()[0]) * 1024 for key, value in (line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())}
    vm = dict(line.split() for line in Path("/proc/vmstat").read_text().splitlines())
    values = {
        "time": time.monotonic(),
        "total": memory["MemTotal"],
        "available": memory["MemAvailable"],
        "swap_used": memory["SwapTotal"] - memory["SwapFree"],
        "swap_in": int(vm["pswpin"]),
        "swap_out": int(vm["pswpout"]),
        "processes": {},
    }
    for name, process in processes:
        try:
            status = dict(line.split(":", 1) for line in Path(f"/proc/{process.pid}/status").read_text().splitlines())
            stat = Path(f"/proc/{process.pid}/stat").read_text().rsplit(")", 1)[1].split()
            values["processes"][name] = {
                "rss": int(status.get("VmRSS", "0").split()[0]) * 1024,
                "hwm": int(status.get("VmHWM", "0").split()[0]) * 1024,
                "threads": int(status["Threads"]),
                "cpu_seconds": (int(stat[11]) + int(stat[12])) / os.sysconf("SC_CLK_TCK"),
            }
        except (FileNotFoundError, ProcessLookupError):
            pass
    return values


def cluster(
    binaries: Path,
    case: dict,
    output: Path,
    probe: Callable[[list[str]], list[str]] | None = None,
    *,
    launcher: Callable[..., subprocess.Popen] | None = None,
    monitor: Callable[[], dict] | None = None,
) -> list[dict]:
    """Own a fresh cluster for each sample and close its processes and databases in finally, leaving other deployments alone."""
    deadline = time.monotonic() + 180
    traces = []
    fixtures = ROOT / "tests/fixtures"
    temporary = ROOT / "build/tmp"
    temporary.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="measure-", dir=temporary) as directory, ExitStack() as stack:
        directory = Path(directory)
        identity = directory / "identity"
        shutil.copytree(fixtures / "pulsar", identity)
        accounts = json.loads((identity / "accounts.json").read_text())
        for account in accounts:
            if account["username"] == "stars":
                account["roles"] = ["star", "polaris", "astrolabe"]
        (identity / "accounts.json").write_text(json.dumps(accounts))
        owned = []

        def start(name: str, command: list[str | Path]) -> tuple[subprocess.Popen, Path]:
            """Launch one cluster-owned process with a retained log and registered cleanup."""
            log = output / f"{name}.log"
            stream = stack.enter_context(log.open("w", encoding="utf-8"))
            options = dict(cwd=ROOT, env=environment(jobs=len(os.sched_getaffinity(0))), stdout=stream, stderr=subprocess.STDOUT)
            command = [str(part) for part in command]
            process = popen(command, **options) if launcher is None else launcher(name, command, **options)
            stack.callback(stop_process, process)
            owned.append((name, process))
            return process, log

        def ready(process: subprocess.Popen, log: Path, predicate: Callable[[dict], bool]) -> dict:
            """Wait for a service readiness event while preserving early exits and timeout failures."""
            return wait(process, log, predicate, seconds=45, overall_deadline=deadline)

        pulse, pulse_log = start(
            "pulsar",
            [
                binaries / "pulsar",
                "--listen=127.0.0.1:0",
                "--pulse-listen=127.0.0.1:0",
                "--galaxy=alpha",
                f"--identity={identity}",
                f"--state={directory / 'members.db'}",
                "--init=true",
            ],
        )
        admission = ready(pulse, pulse_log, lambda item: item.get("event") == "started")["fields"]["admission"]
        ready(
            pulse,
            pulse_log,
            lambda item: item.get("event") == "clock_status" and item["fields"].get("synchronized") is True,
        )
        authority, authority_log = start(
            "polaris",
            [
                binaries / "polaris",
                f"--listen=127.0.0.1:{port()}",
                f"--super={admission}",
                "--galaxy=alpha",
                f"--identity={fixtures / 'star-a'}",
                f"--state={directory / 'polaris.db'}",
                "--init=true",
            ],
        )
        ready(authority, authority_log, lambda item: item.get("msg") == "Polaris ready")

        # Every current benchmark retains the complete control plane, including unauthenticated business traffic.
        credential = None
        if case.get("auth", False):
            credential = directory / "comet.secret"
            secret = os.urandom(32)
            credential.write_bytes(secret)
            credential.chmod(0o600)
        password = os.urandom(16).hex()
        salt = os.urandom(16)
        account = directory / "account.json"
        account.write_text(
            json.dumps({"username": "admin", "salt": salt.hex(), "hash": hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000, 32).hex()})
        )
        account.chmod(0o600)
        origin = f"https://127.0.0.1:{port()}"
        admin, admin_log = start(
            "astrolabe",
            [
                binaries / "astrolabe",
                f"--listen={origin.removeprefix('https://')}",
                f"--super={admission}",
                "--galaxy=alpha",
                f"--identity={fixtures / 'star-a'}",
                f"--account={account}",
                f"--public={origin}",
            ],
        )
        ready(admin, admin_log, lambda item: item.get("msg") == "Astrolabe management listener ready")

        # Install credentials through the real management API; ordinary samples leave business authentication disabled.
        if case.get("auth", False):
            browser = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPCookieProcessor(CookieJar()),
                urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(fixtures / "star-a/ca.pem"))),
            )

            def request(path: str, value: dict | None = None) -> bytes:
                """Send a bounded request through the fixture's authenticated management API."""
                message = urllib.request.Request(
                    origin + path,
                    data=json.dumps(value).encode() if value is not None else None,
                    headers={
                        "Origin": origin,
                        "X-Astra-Request": "1",
                        "Content-Type": "application/json",
                    },
                )
                with browser.open(message, timeout=5) as response:
                    if response.status != 200:
                        raise RuntimeError("Management setup failed")
                    return response.read(2 * 1024 * 1024)

            request("/api/session", {"username": "admin", "password": password})
            until = time.monotonic() + 15
            while True:
                try:
                    request("/api/almanac")
                    break
                except urllib.error.HTTPError as failure:
                    if failure.code not in (502, 503, 504) or time.monotonic() >= until:
                        raise
                    time.sleep(0.1)
            confirmed = json.loads(
                request(
                    "/api/credentials",
                    {
                        "key": "performance",
                        "secret": base64.b64encode(secret).decode(),
                        "version": "1",
                    },
                )
            )
            if confirmed.get("effect") != "committed":
                raise RuntimeError("Credential commit not confirmed")

        endpoints = []
        for index in range(case["stars"]):
            node, log = start(
                f"star-{index}",
                [
                    binaries / "star",
                    f"--listen=127.0.0.1:{port()}",
                    "--comet=127.0.0.1:0",
                    f"--auth={'true' if case.get('auth', False) else 'false'}",
                    f"--tls={'true' if case['tls'] else 'false'}",
                    f"--identity={fixtures / 'star-b'}",
                    *([f"--comet-identity={fixtures / 'star-b'}"] if case["tls"] else []),
                    f"--super={admission}",
                    "--galaxy=alpha",
                ],
            )
            endpoints.append(ready(node, log, lambda item: item.get("event") == "comet_listening")["fields"]["endpoint"])
            ready(node, log, lambda item: item.get("event") == "business_ready")

        # Readiness can precede completion of initial history work. Drain before starting the SDK; each case still checks actual target visibility.
        time.sleep(0.3)
        command = [
            binaries / "comet_bench",
            ",".join(endpoints),
            fixtures / "star-b/ca.pem" if case["tls"] else "-",
            case["domain"],
            case["records"],
            case["bytes"],
            case["attr"],
            case["watchers"],
            case["writers"],
            case["seconds"],
            case["ttl"],
            case["rate"],
        ]
        if credential is not None:
            command.append(credential)
        if probe is not None:
            command = probe(endpoints)
        probe, log = start("comet", command)
        try:
            while probe.poll() is None:
                sample = resources(owned)
                if monitor is not None:
                    sample["cgroups"] = monitor()
                traces.append(sample)
                if sample["available"] < 128 * 1024 * 1024:
                    raise RuntimeError("Insufficient actual memory; stopped owned benchmark before OOM")
                if time.monotonic() >= deadline or any(process.poll() is not None for _, process in owned[:-1]):
                    raise RuntimeError("Service exited or bounded measurement timed out")
                time.sleep(0.2)
            if probe.returncode != 0:
                raise ProbeFailure(f"SDK benchmark failed: {log.read_text()[-2000:]}")
            if command[0] == binaries / "comet_bench":
                return observations(log.read_text(), case)
            return [json.loads(line) for line in log.read_text().splitlines() if line.startswith('{"metric":')]
        finally:
            (output / "resources.json").write_text(json.dumps(traces, indent=2))


def run(arguments: argparse.Namespace) -> None:
    """Run performance scenarios sequentially; correctness-test parallelism does not apply to samples sharing one VM."""
    binaries = arguments.binaries.resolve()
    output = arguments.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    state = resources()
    identity = {
        "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cpus": os.cpu_count(),
        "affinity": sorted(os.sched_getaffinity(0)),
        "kernel": os.uname().release,
        "resources": state,
        "binaries": {},
    }
    native = "star_almanac_bench" if arguments.almanac else "star_native_bench"
    names = (native,) if arguments.native else ("pulsar", "polaris", "star", "comet_bench", "astrolabe")
    for name in names:
        identity["binaries"][name] = hashlib.sha256((binaries / name).read_bytes()).hexdigest()
    (output / "identity.json").write_text(json.dumps(identity, indent=2))
    results = []
    cases = (
        json.loads(arguments.cases.read_text())
        if arguments.cases
        else [
            dict(
                domain="catalog",
                records=48,
                bytes=2048,
                attr=256,
                watchers=3,
                writers=12,
                seconds=5,
                ttl=180000,
                rate=0,
                stars=3,
                tls=False,
                qualification=True,
            )
        ]
    )
    try:
        for number, case in enumerate(cases):
            if not arguments.native:
                scenario(case)
            for repeat in range(arguments.repeat):
                directory = output / f"case-{number}-round-{repeat}"
                directory.mkdir()
                print(
                    json.dumps({"case": number, "round": repeat, "parameters": case}),
                    flush=True,
                )
                before = resources()
                if arguments.native:
                    log = directory / "native.log"
                    traces = []
                    with log.open("w", encoding="utf-8") as stream:
                        process = popen(
                            [
                                binaries / native,
                                str(case["records"]),
                                str(case["bytes"]),
                            ],
                            cwd=ROOT,
                            stdout=stream,
                            stderr=subprocess.STDOUT,
                            env=environment(),
                        )
                        try:
                            until = time.monotonic() + 120
                            while process.poll() is None:
                                sample = resources([("native", process)])
                                traces.append(sample)
                                if sample["available"] < 128 * 1024 * 1024 or time.monotonic() >= until:
                                    raise RuntimeError("Native sample exceeded resource/time budget")
                                time.sleep(0.02)
                            if process.returncode != 0:
                                raise RuntimeError(f"Native benchmark failed: {log.read_text()[-2000:]}")
                        finally:
                            stop_process(process)
                            (directory / "resources.json").write_text(json.dumps(traces, indent=2))
                    measurements = [json.loads(line) for line in log.read_text().splitlines()]
                else:
                    measurements = cluster(binaries, case, directory)
                after = resources()
                traces = json.loads((directory / "resources.json").read_text()) if (directory / "resources.json").exists() else []
                totals = {sample["total"] for sample in [before, *traces, after]}
                stable = len(totals) == 1 and before["swap_in"] == after["swap_in"] and before["swap_out"] == after["swap_out"]
                results.append(
                    dict(
                        case=case,
                        round=repeat,
                        stable_memory=stable,
                        before=before,
                        after=after,
                        measurements=measurements,
                    )
                )
                print(
                    json.dumps(
                        {
                            "completed": number,
                            "round": repeat,
                            "stable_memory": stable,
                            "measurements": measurements,
                        }
                    ),
                    flush=True,
                )
    finally:
        (output / "results.json").write_text(json.dumps(results, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cases", type=Path)
    parser.add_argument("--repeat", type=int, choices=range(1, 6), default=3)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--native", action="store_true")
    mode.add_argument("--almanac", action="store_true")
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, terminate)
    arguments = parser.parse_args()
    arguments.native = arguments.native or arguments.almanac
    run(arguments)
