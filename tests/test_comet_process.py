"""Exercise real infrastructure: durable Almanac recovery, dynamic multi-Star replication, and Comet failover."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING
import argparse
import base64
from contextlib import ExitStack
from functools import partial
import hashlib
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tests.support import popen, stop_process
from tests.test_pulsar import events, failure_logs, terminate, wait

if TYPE_CHECKING:
    from tests.soak import Recorder


def port() -> int:
    """Choose a fixed test deployment port; fail on startup contention instead of rewriting admitted addresses."""
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def run(
    binaries: Path, polaris: Path, astrolabe: Path, soak: Recorder | None = None, *, comet_go: Path | None = None, comet_go_residence: bool = False
) -> None:
    """Use explicitly built artifacts without downloads or builds; this fixture owns every process and database."""
    for executable in (
        binaries / "pulsar",
        binaries / "star",
        binaries / "comet_process_probe",
        binaries / "comet_mesh_probe",
        polaris,
        astrolabe,
    ):
        if not executable.is_file():
            raise RuntimeError(f"Missing explicitly built process executable: {executable.name}")
    if comet_go is not None and not comet_go.is_file():
        raise RuntimeError("Missing explicitly built Comet Go system-test executable")
    if comet_go_residence and (
        comet_go is None or soak is None or not soak.persistent or soak.faults != 0 or soak.steady not in (0, 7200) or soak.records != 16 or soak.interval != 0
    ):
        raise RuntimeError(
            "Go residence requires its existing binary, persistent 48-record work and exactly 0 or 7200 steady seconds without separate fault intervals"
        )
    root = ROOT / "build/tmp"
    root.mkdir(parents=True, exist_ok=True)
    deadline = (
        float("inf")
        if soak and soak.steady is None
        else time.monotonic()
        + 390
        + (420 if comet_go else 0)
        + (soak.faults + soak.steady + 240 + (3 * soak.interval if soak.persistent else 0) if soak else 0)
    )
    ordinary = partial(wait, overall_deadline=deadline)
    fixtures = ROOT / "tests/fixtures"
    with tempfile.TemporaryDirectory(prefix="comet-process-", dir=root) as temporary, failure_logs(Path(temporary)), ExitStack() as stack:
        directory = Path(temporary)
        identity = directory / "pulsar-identity"
        shutil.copytree(fixtures / "pulsar", identity)
        accounts = json.loads((identity / "accounts.json").read_text(encoding="utf-8"))
        for account in accounts:
            if account["username"] == "stars":
                account["roles"] = ["star", "polaris", "astrolabe"]
        (identity / "accounts.json").write_text(json.dumps(accounts), encoding="utf-8")
        password = "integration-admin-password"
        salt = os.urandom(16)
        account_file = directory / "account.json"
        account_file.write_text(
            json.dumps(
                {
                    "username": "admin",
                    "salt": salt.hex(),
                    "hash": hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000, 32).hex(),
                }
            ),
            encoding="utf-8",
        )
        account_file.chmod(0o600)
        secret = os.urandom(32)
        secret_file = directory / "comet.secret"
        secret_file.write_bytes(secret)
        secret_file.chmod(0o600)
        owned = []

        def wait_for(process: subprocess.Popen, log: Path, predicate: Callable[[dict], bool], seconds: float = 20, *, exited: bool = False) -> dict:
            """Wait for a structured event while checking owned-service health and the current scenario deadline."""
            if soak is None and not exited:
                return ordinary(process, log, predicate, seconds=seconds)
            until = min(deadline, time.monotonic() + seconds)
            while time.monotonic() < until:
                if soak:
                    soak.check(owned)
                if process.poll() is not None and not exited:
                    raise RuntimeError(f"Owned process exited before expected event: {log.name}")
                for value in reversed(events(log)):
                    if predicate(value):
                        return value
                time.sleep(0.05)
            raise TimeoutError(f"Owned service did not reach expected state: {log.name}")

        def finished(process: subprocess.Popen, seconds: float | None) -> int:
            """Await a finite native probe while enforcing the scenario budget and optional soak checks."""
            until = min(deadline, time.monotonic() + seconds) if seconds is not None else deadline
            while process.poll() is None and time.monotonic() < until:
                if soak:
                    soak.check(owned)
                time.sleep(0.1)
            if process.poll() is None:
                raise TimeoutError("Owned native probe did not finish")
            return process.returncode

        def start(name: str, command: list[str | Path], *, environment: dict[str, str] | None = None) -> tuple[subprocess.Popen, Path]:
            """Start a fixture-owned process with a unique log and immediately register cleanup."""
            log = directory / f"{len(owned)}-{name}.log"
            # Children inherited the descriptors; close parent copies immediately so long runs do not accumulate old log handles.
            with log.open("w", encoding="utf-8") as output:
                process = popen(command, cwd=ROOT, env=environment, stdout=output, stderr=subprocess.STDOUT)
            stack.callback(stop_process, process)
            owned.append((process, log))
            if soak:
                soak.expect(process, name)
            return process, log

        def stop(process: subprocess.Popen) -> None:
            """Retire an expected resident and require it to terminate cleanly within the shutdown budget."""
            if soak:
                soak.retire(process)
            process.terminate()
            if process.wait(timeout=10) != 0:
                raise RuntimeError("Owned process did not exit cleanly")

        pulse, pulse_log = start(
            "pulsar",
            [
                binaries / "pulsar",
                "--listen=127.0.0.1:0",
                "--pulse-listen=127.0.0.1:0",
                "--galaxy=alpha",
                f"--identity={identity}",
                f"--state={directory / 'membership.db'}",
                "--init=true",
            ],
        )
        addresses = wait_for(pulse, pulse_log, lambda value: value.get("event") == "started")["fields"]
        wait_for(
            pulse,
            pulse_log,
            lambda value: value.get("event") == "clock_status" and value["fields"].get("synchronized") is True,
        )
        authority_port = port()

        def publisher(initialize: bool) -> subprocess.Popen:
            """Start or reopen the fixture's durable Polaris authority and wait for readiness."""
            process, log = start(
                "polaris",
                [
                    polaris,
                    f"--listen=127.0.0.1:{authority_port}",
                    f"--super={addresses['admission']}",
                    "--galaxy=alpha",
                    f"--identity={fixtures / 'star-a'}",
                    f"--state={directory / 'polaris.db'}",
                    f"--init={'true' if initialize else 'false'}",
                ],
            )
            wait_for(process, log, lambda value: value.get("msg") == "Polaris ready")
            return process

        authority = publisher(True)
        star_port, comet_port, metrics_port = port(), port(), port()
        if len({star_port, comet_port, metrics_port}) != 3:
            raise RuntimeError("Fixture selected duplicate Star ports")
        metrics_file = directory / "metrics.json"
        metrics_file.write_text(
            json.dumps({f"127.0.0.1:{star_port}": f"http://127.0.0.1:{metrics_port}/metrics"}),
            encoding="utf-8",
        )
        admin_port = port()
        origin = f"https://127.0.0.1:{admin_port}"
        management, management_log = start(
            "astrolabe",
            [
                astrolabe,
                f"--listen=127.0.0.1:{admin_port}",
                f"--super={addresses['admission']}",
                "--galaxy=alpha",
                f"--identity={fixtures / 'star-a'}",
                f"--account={account_file}",
                f"--public={origin}",
                f"--metrics={metrics_file}",
            ],
        )
        wait_for(
            management,
            management_log,
            lambda value: value.get("msg") == "Astrolabe management listener ready",
        )
        context = ssl.create_default_context(cafile=str(fixtures / "star-a/ca.pem"))
        browser = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(CookieJar()),
            urllib.request.HTTPSHandler(context=context),
        )

        def request(method: str, path: str, value: dict | None = None) -> tuple[int, bytes]:
            """Send an authenticated management request and bound both successful and error response bodies."""
            body = None if value is None else json.dumps(value).encode()
            message = urllib.request.Request(
                origin + path,
                data=body,
                method=method,
                headers={
                    "Origin": origin,
                    "X-Astra-Request": "1",
                    "Content-Type": "application/json",
                },
            )
            try:
                with browser.open(message, timeout=5) as response:
                    data = response.read(2 * 1024 * 1024 + 1)
                    if len(data) > 2 * 1024 * 1024:
                        raise RuntimeError("Management fixture response exceeded bound")
                    return response.status, data
            except urllib.error.HTTPError as failure:
                return failure.code, failure.read(4096)

        status, _ = request("POST", "/api/session", {"username": "admin", "password": password})
        if status != 200:
            raise RuntimeError("Management login failed")

        def available(path: str, check: Callable[[bytes], bool]) -> bytes:
            """Wait for a management read predicate while preserving control-process and deadline failures."""
            until = min(deadline, time.monotonic() + 50)
            while time.monotonic() < until:
                status, body = request("GET", path)
                if status == 200 and check(body):
                    return body
                if status not in (200, 502, 503, 504):
                    raise RuntimeError(f"Unexpected management read status: {status}")
                if any(process.poll() is not None for process in (management, pulse, authority)):
                    raise RuntimeError("Control process exited during availability wait")
                time.sleep(0.1)
            raise TimeoutError("Management authority did not recover")

        available("/api/almanac", lambda _: True)

        def write(path: str, value: dict) -> None:
            # Write exactly once and fail immediately; retries must not mask uncertain COMMIT outcomes or control-plane errors.
            """Require one management mutation to confirm persistence without retrying an uncertain result."""
            status, body = request("POST", path, value)
            if status != 200 or json.loads(body).get("effect") != "committed":
                raise RuntimeError(f"Management commit did not confirm persistence: HTTP {status}")

        write(
            "/api/credentials",
            {
                "key": "integration",
                "secret": base64.b64encode(secret).decode(),
                "version": "1",
            },
        )
        redacted = available("/api/credentials", lambda data: b'"complete":true' in data)
        if b'"redacted":true' not in redacted or base64.b64encode(secret) in redacted or secret in redacted:
            raise RuntimeError("Credential management did not preserve redaction")

        def update(version: int, value: bytes | None) -> None:
            """Publish an explicit Almanac version, distinguishing deletion from an empty value."""
            data = {
                "sector": "integration",
                "spectrum": "main",
                "key": "key",
                "version": str(version),
            }
            data.update({"erase": True} if value is None else {"value": base64.b64encode(value).decode()})
            write("/api/almanac", data)

        update(1, b"one")

        def node(name: str, internal: int, external: int) -> tuple[subprocess.Popen, Path, str]:
            """Start one real TLS Star at fixed business ports and return its public SDK endpoint."""
            process, log = start(
                name,
                [
                    binaries / "star",
                    f"--listen=127.0.0.1:{internal}",
                    f"--comet=127.0.0.1:{external}",
                    # Management scrapes only A. Random metrics listeners on B/C could occupy fixed business ports before they bind.
                    *([f"--metrics=127.0.0.1:{metrics_port}"] if internal == star_port else []),
                    "--auth=true",
                    "--tls=true",
                    f"--comet-identity={fixtures / 'star-b'}",
                    f"--identity={fixtures / 'star-b'}",
                    f"--super={addresses['admission']}",
                    "--galaxy=alpha",
                    f"--status-interval-seconds={60 if soak else 1}",
                ],
            )
            endpoint = wait_for(process, log, lambda value: value.get("event") == "comet_listening")["fields"]["endpoint"]
            return process, log, endpoint

        star, star_log, endpoint = node("star-a", star_port, comet_port)

        def probe(target: int) -> tuple[subprocess.Popen, Path]:
            """Start the public Comet reader probe for a finite target version."""
            return start(
                "comet",
                [
                    binaries / "comet_process_probe",
                    endpoint,
                    fixtures / "star-b/ca.pem",
                    secret_file,
                    "integration",
                    "main",
                    str(target),
                ],
            )

        reader, reader_log = probe(4)
        if soak:
            soak.retire(reader)  # This finite probe exits normally at version 4; its exit code is checked below.

        def view(version: int, value: bytes | None) -> None:
            """Require the reader's observed version, presence, and bytes to match the expected snapshot."""
            wait_for(
                reader,
                reader_log,
                lambda event: event.get("event") == "view"
                and event.get("version") == version
                and event.get("present") == (value is not None)
                and event.get("value") == ("" if value is None else value.hex()),
                seconds=45,
            )

        view(1, b"one")
        observed = available(
            "/api/metrics",
            lambda data: any(not sample["stale"] and sample.get("values", {}).get("astra_ready") == "1" for sample in json.loads(data)["samples"]),
        )
        if secret in observed or base64.b64encode(secret) in observed:
            raise RuntimeError("Metrics exposed credential material")
        update(2, b"two")
        view(2, b"two")
        stop(authority)
        cached, cached_log = probe(2)
        if soak:
            soak.retire(cached)
        if cached.wait(timeout=15) != 0 or not any(
            event.get("event") == "view" and event.get("version") == 2 and event.get("value") == b"two".hex() for event in events(cached_log)
        ):
            raise RuntimeError("Star could not serve its complete cache during authority outage")
        authority = publisher(False)

        def persisted(data: bytes) -> bool:
            """Recognize a complete restored version-two Almanac snapshot with the expected record."""
            rows = [json.loads(line) for line in data.splitlines()]
            return (
                bool(rows)
                and rows[-1].get("complete") is True
                and rows[-1].get("position", {}).get("version") == "2"
                and any(row.get("key") == "key" and row.get("value") == base64.b64encode(b"two").decode() for row in rows)
            )

        available("/api/almanac?sector=integration&spectrum=main", persisted)
        update(3, None)
        view(3, None)
        update(4, b"")
        # A process may emit its final frame before exiting normally; a live-only wait would misclassify success.
        if reader.wait(timeout=20) != 0 or not any(
            event.get("event") == "view" and event.get("version") == 4 and event.get("present") is True and event.get("value") == ""
            for event in events(reader_log)
        ):
            raise RuntimeError("Native Reader did not install empty-value final commit or clean up")
        # All three Stars use real processes and separate ports. Native probes use public TLS and the SDK, not private stubs.
        second_port, second_comet_port = port(), port()
        if len({star_port, comet_port, metrics_port, second_port, second_comet_port}) != 5:
            raise RuntimeError("Fixture selected duplicate mesh ports")
        second, second_log, second_endpoint = node("star-b", second_port, second_comet_port)
        wait_for(
            second,
            second_log,
            lambda value: value.get("event") == "business_ready",
            seconds=45,
        )
        third_port, third_comet_port = port(), port()
        if (
            len(
                {
                    star_port,
                    comet_port,
                    metrics_port,
                    second_port,
                    second_comet_port,
                    third_port,
                    third_comet_port,
                }
            )
            != 7
        ):
            raise RuntimeError("Fixture selected duplicate third Star ports")
        third, third_log, third_endpoint = node("star-c", third_port, third_comet_port)
        wait_for(
            third,
            third_log,
            lambda value: value.get("event") == "business_ready",
            seconds=45,
        )
        nodes = [
            (star, star_port, comet_port, endpoint),
            (second, second_port, second_comet_port, second_endpoint),
            (third, third_port, third_comet_port, third_endpoint),
        ]
        if comet_go is not None:
            # Use a file for arbitrary credential bytes; environment strings cannot carry embedded NULs.
            control = directory / "comet-go-control"
            control.mkdir()
            settings = dict(os.environ)
            for name in tuple(settings):
                if name.startswith("COMET_SYSTEM_"):
                    del settings[name]
            settings.update(
                COMET_SYSTEM_ENABLE="1",
                COMET_SYSTEM_ENDPOINTS=",".join(item[3] for item in nodes),
                COMET_SYSTEM_KEY="integration",
                COMET_SYSTEM_SECRET_FILE=str(secret_file),
                COMET_SYSTEM_CA=(fixtures / "star-b/ca.pem").read_text(encoding="utf-8"),
                COMET_SYSTEM_ANONYMOUS="false",
                COMET_SYSTEM_PLAINTEXT="false",
                COMET_SYSTEM_CONTROL=str(control),
            )
            if comet_go_residence:
                settings["COMET_SYSTEM_RESIDENCE_SECONDS"] = str(soak.steady)
            timeout = 480 + (soak.steady if comet_go_residence else 0)
            go, go_log = start(
                "comet-go",
                [comet_go, "-test.v", "-test.run=^TestSystemThreeStars$", f"-test.timeout={timeout}s", "-test.count=1"],
                environment=settings,
            )
            if soak:
                soak.retire(go)

            def signal_go(action: str, index: int) -> None:
                """Publish one complete phase handshake atomically; never expose an empty partial file."""
                name = f"{action}-{index}"
                pending, target = control / (name + ".tmp"), control / name
                if pending.exists() or target.exists():
                    raise RuntimeError("Duplicate Comet Go fixture handshake")
                pending.write_text(name + "\n", encoding="utf-8", newline="\n")
                pending.replace(target)

            def go_authority(event: str) -> None:
                """Require an observed authority phase from the same running Go process."""
                wait_for(go, go_log, lambda value: value.get("event") == event and value.get("cycle") == 0, seconds=50)
                if soak:
                    soak.record("comet_go_authority", phase=event, sdk_pid=go.pid)

            go_authority("go_authority_ready")
            update(5, b"go-before")
            signal_go("authority-before", 0)
            go_authority("go_authority_before")
            if soak:
                soak.retire(authority)
            authority_pid = authority.pid
            authority.kill()
            authority_exit = authority.wait(timeout=10)
            if authority_exit == 0:
                raise RuntimeError("Go authority crash unexpectedly reported clean shutdown")
            if soak:
                soak.record("comet_go_authority_crash", pid=authority_pid, exit_code=authority_exit)
            signal_go("authority-stopped", 0)
            go_authority("go_authority_cached")
            authority = publisher(False)
            if soak:
                soak.record("comet_go_authority_restart", previous_pid=authority_pid, pid=authority.pid, initialize=False)

            def go_persisted(data: bytes) -> bool:
                """Require the acknowledged v5 content to survive the actual authority crash."""
                rows = [json.loads(line) for line in data.splitlines()]
                return (
                    bool(rows)
                    and rows[-1].get("complete") is True
                    and rows[-1].get("position", {}).get("version") == "5"
                    and any(row.get("key") == "key" and row.get("value") == base64.b64encode(b"go-before").decode() for row in rows)
                )

            available("/api/almanac?sector=integration&spectrum=main", go_persisted)
            update(6, None)
            signal_go("authority-deleted", 0)
            go_authority("go_authority_deleted")
            update(7, b"")
            signal_go("authority-empty", 0)
            go_authority("go_authority_empty")
            update(8, b"go-after")
            signal_go("authority-restored", 0)
            go_authority("go_authority_restored")

            for index in range(3):
                wait_for(
                    go,
                    go_log,
                    lambda value: value.get("event") == "go_mesh_ready" and value.get("cycle") == index and value.get("star") == index,
                    seconds=80,
                )
                victim, internal, external, endpoint = nodes[index]
                if soak:
                    soak.retire(victim)
                victim.kill()
                if victim.wait(timeout=10) == 0:
                    raise RuntimeError("Go crash fixture unexpectedly reported clean shutdown")
                signal_go("crashed", index)
                wait_for(
                    go,
                    go_log,
                    lambda value: value.get("event") == "go_mesh_failover" and value.get("cycle") == index and value.get("star") == index,
                    seconds=80,
                )
                restored, _, address = node(f"go-star-{index}-restarted", internal, external)
                if address != endpoint:
                    raise RuntimeError("Go restart did not preserve the deployment endpoint")
                nodes[index] = (restored, internal, external, address)
                signal_go("restored", index)
                wait_for(
                    go,
                    go_log,
                    lambda value: value.get("event") == "go_mesh_recovered" and value.get("cycle") == index and value.get("star") == index,
                    seconds=80,
                    exited=index == 2 and not comet_go_residence,
                )
                if soak:
                    soak.record("comet_go_recovered", cycle=index + 1, star=index, sdk_pid=go.pid)
            if comet_go_residence:
                wait_for(
                    go,
                    go_log,
                    lambda value: value.get("event") == "mesh_steady"
                    and value.get("cycles") == 3
                    and value.get("seconds") == soak.steady
                    and value.get("records") == 48
                    and value.get("workers") == 96,
                    exited=soak.steady == 0,
                )
                soak.record("steady", seconds=soak.steady, sdk_pid=go.pid)
                signal_go("residence-start", 0)
                if soak.steady:
                    soak.watch(go_log)
            if finished(go, soak.steady + 100 if comet_go_residence else 15) != 0:
                raise RuntimeError("Comet Go three-Star system test failed")
            events(go_log)  # Also enforce the native log bound and sanitizer diagnostic rejection.
            lines = go_log.read_text(encoding="utf-8").splitlines()
            if (
                "=== RUN   TestSystemThreeStars" not in lines
                or not any(line.startswith("--- PASS: TestSystemThreeStars (") for line in lines)
                or "PASS" not in lines
                or any("--- SKIP:" in line or "--- FAIL:" in line for line in lines)
            ):
                raise RuntimeError("Comet Go system test did not report one real unskipped pass")
            if soak:
                soak.record("comet_go", sdk_pid=go.pid, nodes=3, test="TestSystemThreeStars")
            if comet_go_residence:
                if not any(
                    value.get("event") == "mesh_replicated" and value.get("records") == 48 and type(value.get("rounds")) is int and value["rounds"] >= 2
                    for value in events(go_log)
                ):
                    raise RuntimeError("Go residence did not complete the declared workload")
                for process in (*[item[0] for item in nodes], management, authority, pulse):
                    stop(process)
                soak.check(owned, force=True)
                soak.record("completed", cycles=3)
                print("PASS retained Comet Go owners, authority and A/B/C faults, three-source residence and owned cleanup")
                return
        # The C++ oracle consumes the prescribed final write, never a baseline inferred from current server output.
        baseline = ["--authority-version", "8" if comet_go is not None else "4", "--authority-value", "go-after" if comet_go is not None else ""]
        if soak and soak.persistent:
            mesh, mesh_log = start(
                "sequence",
                [
                    binaries / "comet_mesh_probe",
                    *(item[3] for item in nodes),
                    fixtures / "star-b/ca.pem",
                    secret_file,
                    str(soak.interval),
                    "sequence",
                    str(soak.records),
                    "0",
                    "0",
                    "forever" if soak.steady is None else str(soak.steady),
                    *baseline,
                ],
            )
            soak.retire(mesh)
            soak.record("sequence", sdk_pid=mesh.pid)
            for index in range(3):
                wait_for(
                    mesh,
                    mesh_log,
                    lambda value: value.get("event") == "mesh_ready" and value.get("cycle") == index and value.get("star") == index,
                    seconds=soak.interval + 75,
                )
                victim, internal, external, endpoint = nodes[index]
                soak.retire(victim)
                victim.kill()
                if victim.wait(timeout=10) == 0:
                    raise RuntimeError("Crash fixture unexpectedly reported clean shutdown")
                wait_for(
                    mesh,
                    mesh_log,
                    lambda value: value.get("event") == "mesh_failover" and value.get("cycle") == index and value.get("star") == index,
                    seconds=80,
                )
                restored, _, address = node(f"star-{index}-restarted", internal, external)
                if address != endpoint:
                    raise RuntimeError("Restart did not preserve the deployment endpoint")
                nodes[index] = (restored, internal, external, address)
                wait_for(
                    mesh,
                    mesh_log,
                    lambda value: value.get("event") == "mesh_recovered" and value.get("cycle") == index and value.get("star") == index,
                    seconds=100,
                    exited=index == 2 and soak.steady == 0,
                )
                soak.record("recovered", cycle=index + 1, star=index, sdk_pid=mesh.pid)
            cycle = 3
            wait_for(mesh, mesh_log, lambda value: value.get("event") == "mesh_steady" and value.get("cycles") == 3, exited=soak.steady == 0)
            soak.record("steady", seconds=soak.steady, sdk_pid=mesh.pid)
            if soak.steady is None or soak.steady:
                soak.watch(mesh_log)
            if (
                finished(mesh, None if soak.steady is None else soak.steady + 100) != 0
                or soak.steady is None
                or not any(event.get("event") == "mesh_sequence_completed" and event.get("cycles") == 3 for event in events(mesh_log))
            ):
                raise RuntimeError("Persistent SDK sequence did not confirm all cycles and cleanup")
        else:
            limit = time.monotonic() + (soak.faults if soak else 0)
            cycle = 0
            while True:
                index = cycle % 3
                selected = nodes[index:] + nodes[:index]  # Rotate the failed node while keeping the other two sources resident.
                hold = min(soak.interval, max(0, int(limit - time.monotonic()))) if soak else 0
                mesh, mesh_log = start(
                    "mesh",
                    [
                        binaries / "comet_mesh_probe",
                        *(item[3] for item in selected),
                        fixtures / "star-b/ca.pem",
                        secret_file,
                        str(hold),
                        "failure",
                        str(soak.records if soak else 1),
                        str(cycle),
                        *baseline,
                    ],
                )
                if soak:
                    soak.retire(mesh)  # Stage assertions check this finite probe's normal exit; it is not a resident service.
                wait_for(
                    mesh,
                    mesh_log,
                    lambda value: value.get("event") == "mesh_ready",
                    seconds=hold + 75,
                )
                victim = selected[0][0]
                if soak:
                    soak.retire(victim)
                victim.kill()  # Simulate abrupt loss without first unregistering or shutting down gracefully.
                if victim.wait(timeout=10) == 0:
                    raise RuntimeError("Crash fixture unexpectedly reported clean shutdown")
                wait_for(
                    mesh,
                    mesh_log,
                    lambda value: value.get("event") == "mesh_failover",
                    seconds=80,
                )
                restored, _, address = node(f"star-{index}-restarted", selected[0][1], selected[0][2])
                if address != selected[0][3]:
                    raise RuntimeError("Restart did not preserve the deployment endpoint")
                nodes[index] = (restored, selected[0][1], selected[0][2], address)
                if finished(mesh, 100) != 0 or not any(event.get("event") == "mesh_recovered" for event in events(mesh_log)):
                    raise RuntimeError("Multi-Star native recovery or resource cleanup failed")
                cycle += 1
                if soak:
                    soak.record("recovered", cycle=cycle, star=index)
                if cycle >= (3 if soak else 1) and time.monotonic() >= limit:
                    break

            if soak and (soak.steady is None or soak.steady):
                soak.record("steady", seconds=soak.steady)
                mesh, mesh_log = start(
                    "steady",
                    [
                        binaries / "comet_mesh_probe",
                        *(item[3] for item in nodes),
                        fixtures / "star-b/ca.pem",
                        secret_file,
                        "forever" if soak.steady is None else str(soak.steady),
                        "steady",
                        str(soak.records),
                        str(cycle),
                    ],
                )
                soak.retire(mesh)
                soak.watch(mesh_log)
                if (
                    finished(mesh, None if soak.steady is None else soak.steady + 100) != 0
                    or soak.steady is None
                    or not any(event.get("event") == "mesh_replicated" for event in events(mesh_log))
                ):
                    raise RuntimeError("Resident three-source steady state failed")

        for process in (*[item[0] for item in nodes], management, authority, pulse):
            stop(process)
        if soak is None:
            for _, log in owned:
                events(log)  # Short runs scan full logs; long runs use incremental checks without the short-run 8 MiB limit.
        if soak:
            soak.check(owned, force=True)
            soak.record("completed", cycles=cycle)
        print("PASS real Almanac persistence and native multi-Star replication, crash, failover, trusted restart, TTL and owned cleanup")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--polaris", type=Path, required=True)
    parser.add_argument("--astrolabe", type=Path, required=True)
    parser.add_argument("--comet-go", type=Path, help="Existing Comet Go test executable; runs its three-Star case against this owned TLS fixture")
    arguments = parser.parse_args()
    previous = signal.signal(signal.SIGTERM, terminate)
    try:
        run(
            arguments.binaries.resolve(),
            arguments.polaris.resolve(),
            arguments.astrolabe.resolve(),
            comet_go=arguments.comet_go.resolve() if arguments.comet_go else None,
        )
    finally:
        signal.signal(signal.SIGTERM, previous)
