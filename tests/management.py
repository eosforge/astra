"""Own real management services for a bounded, externally driven browser acceptance run."""

from __future__ import annotations

import argparse
from contextlib import ExitStack
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tests.support import popen, stop_process
from tests.test_comet_process import port
from tests.test_pulsar import wait as wait_event
from tools import verify


def run(binaries: Path, output: Path, origin: str, seconds: int) -> None:
    """Retain logs and process identities; reclaim only the fixture's temporary databases."""
    output.mkdir(parents=True, exist_ok=False)
    fixtures = ROOT / "tests/fixtures"
    programs = {name: binaries / name for name in ("pulsar", "polaris", "astrolabe")}
    if not all(path.is_file() for path in programs.values()):
        raise RuntimeError("Missing explicitly built management executable")
    source = {
        str(path.relative_to(ROOT)): verify.file_digest(path)
        for path in [
            Path(__file__),
            ROOT / "tests/support.py",
            ROOT / "tests/test_comet_process.py",
        ]
    }
    started = time.monotonic()
    wait = partial(wait_event, overall_deadline=started + seconds)
    processes, errors, exits = [], [], []
    stopped = False

    def stop(*_: object) -> None:
        """Request cooperative shutdown without signalling a reused or unrelated PID."""
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    verify.write_new(
        output / "controller.json",
        {
            "identity": verify.proc_identity(os.getpid()),
            "argv": sys.argv,
            "cwd": str(Path.cwd()),
        },
    )
    verify.write_new(
        output / "inputs.json",
        {
            "source": source,
            "binaries": {name: verify.file_digest(path) for name, path in programs.items()},
            "origin": origin,
            "timeout_s": seconds,
        },
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with tempfile.TemporaryDirectory(prefix="management-", dir=output) as temporary, ExitStack() as stack:
            directory = Path(temporary)
            identity = directory / "identity"
            shutil.copytree(fixtures / "pulsar", identity)
            accounts = json.loads((identity / "accounts.json").read_text())
            for account in accounts:
                if account["username"] == "stars":
                    account["roles"] = ["polaris", "astrolabe"]
            (identity / "accounts.json").write_text(json.dumps(accounts))
            salt = os.urandom(16)
            account = directory / "account.json"
            account.write_text(
                json.dumps(
                    {
                        "username": "admin",
                        "salt": salt.hex(),
                        "hash": hashlib.pbkdf2_hmac("sha256", b"integration-admin-password", salt, 600000, 32).hex(),
                    }
                )
            )
            account.chmod(0o600)

            def start(name: str, args: list[str]) -> tuple[subprocess.Popen, Path]:
                """Register cleanup immediately after each owned child is created."""
                log = output / (name + ".log")
                with log.open("x", encoding="utf-8") as stream:
                    process = popen(
                        [programs[name], *args],
                        cwd=ROOT,
                        stdout=stream,
                        stderr=subprocess.STDOUT,
                    )
                stack.callback(lambda child=process: (stop_process(child) if child.poll() is None else None))
                processes.append((name, process))
                verify.write_new(
                    output / (name + ".json"),
                    {
                        "identity": verify.proc_identity(process.pid),
                        "argv": [str(programs[name]), *args],
                        "cwd": str(ROOT),
                    },
                )
                return process, log

            pulse, log = start(
                "pulsar",
                [
                    f"--listen=127.0.0.1:{port()}",
                    "--pulse-listen=127.0.0.1:0",
                    "--galaxy=alpha",
                    f"--identity={identity}",
                    f"--state={directory / 'membership.db'}",
                    "--init=true",
                ],
            )
            admission = wait(pulse, log, lambda item: item.get("event") == "started")["fields"]["admission"]
            wait(
                pulse,
                log,
                lambda item: item.get("event") == "clock_status" and item["fields"].get("synchronized") is True,
            )
            authority, log = start(
                "polaris",
                [
                    f"--listen=127.0.0.1:{port()}",
                    f"--super={admission}",
                    "--galaxy=alpha",
                    f"--identity={fixtures / 'star-a'}",
                    f"--state={directory / 'polaris.db'}",
                    "--init=true",
                ],
            )
            wait(authority, log, lambda item: item.get("msg") == "Polaris ready")
            endpoint = port()
            manager, log = start(
                "astrolabe",
                [
                    f"--listen=127.0.0.1:{endpoint}",
                    f"--super={admission}",
                    "--galaxy=alpha",
                    f"--identity={fixtures / 'star-a'}",
                    f"--account={account}",
                    f"--public={origin}",
                    "--http=true",
                ],
            )
            wait(
                manager,
                log,
                lambda item: item.get("msg") == "Astrolabe management listener ready",
            )
            # A separate readiness session is never installed in the browser. Reads alone may poll.
            request = urllib.request.Request(
                f"http://127.0.0.1:{endpoint}/api/session",
                data=json.dumps({"username": "admin", "password": "integration-admin-password"}).encode(),
                headers={
                    "Origin": origin,
                    "X-Astra-Request": "1",
                    "Content-Type": "application/json",
                },
            )
            with opener.open(request, timeout=5) as response:
                token = response.headers["Set-Cookie"].split(";", 1)[0]
                assert response.status == 200
            until = time.monotonic() + 45
            while True:
                request = urllib.request.Request(
                    f"http://127.0.0.1:{endpoint}/api/almanac",
                    headers={"X-Astra-Request": "1", "Cookie": token},
                )
                try:
                    with opener.open(request, timeout=5) as response:
                        assert response.status == 200
                    break
                except urllib.error.HTTPError as error:
                    if error.code not in (502, 503, 504) or time.monotonic() >= until:
                        raise
                    time.sleep(0.1)
            request = urllib.request.Request(
                f"http://127.0.0.1:{endpoint}/api/session",
                method="DELETE",
                headers={"Origin": origin, "X-Astra-Request": "1", "Cookie": token},
            )
            with opener.open(request, timeout=5) as response:
                assert response.status == 204
            verify.write_new(
                output / "ready.json",
                {
                    "port": endpoint,
                    "origin": origin,
                    "controller": verify.proc_identity(os.getpid()),
                },
            )
            while not stopped and not (output / "finish").exists():
                if any(process.poll() is not None for _, process in processes):
                    raise RuntimeError("Owned service exited during browser acceptance")
                if time.monotonic() - started >= seconds:
                    raise TimeoutError("Browser completion did not arrive within the fixed budget")
                time.sleep(0.1)
            for name, process in reversed(processes):
                process.terminate()
                code = process.wait(timeout=10)
                exits.append({"name": name, "exit_code": code})
                if code != 0:
                    raise RuntimeError("Owned service failed graceful shutdown: " + name)
            if not stopped:
                with sqlite3.connect(f"file:{directory / 'polaris.db'}?mode=ro", uri=True) as database:
                    scope = database.execute("SELECT hex(version),records,bytes FROM scopes WHERE sector='default' AND spectrum='main'").fetchall()
                    records = database.execute("SELECT key FROM records WHERE sector='default' AND spectrum='main'").fetchall()
                    integrity = database.execute("PRAGMA quick_check").fetchone()
                verify.write_new(
                    output / "durable.json",
                    {"scope": scope, "keys": records, "integrity": integrity},
                )
                if scope != [("0000000000000003", 0, 0)] or records or integrity != ("ok",):
                    raise AssertionError("Browser final snapshot differs from the reopened durable database")
    except Exception as error:
        errors.append(type(error).__name__ + ": " + str(error))
    finally:
        verify.write_new(
            output / "terminal.json",
            {
                "errors": errors,
                "interrupted": stopped,
                "exits": exits,
                "cleanup": all(process.poll() is not None for _, process in processes),
                "source_unchanged": all(verify.file_digest(ROOT / name) == digest for name, digest in source.items()),
                "duration_s": time.monotonic() - started,
                "finished_at": verify.utc(),
            },
        )
    if errors or stopped:
        raise RuntimeError("Management acceptance did not complete; inspect preserved evidence")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--seconds", type=int, default=600)
    args = parser.parse_args()
    if not 30 <= args.seconds <= 900 or not args.origin.startswith("http://127.0.0.1:"):
        parser.error("An explicit loopback browser origin and bounded 30..900 second budget are required")
    run(args.binaries.resolve(), args.output.resolve(), args.origin, args.seconds)
