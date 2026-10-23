"""Exercise real Pulsar, Polaris, Astrolabe, and three Stars using existing artifacts, without builds or downloads."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build import environment
from tests.test_comet_process import run
from tests.test_pulsar import terminate
from tests.support import binary_digest
from tests import resources


class Recorder:
    """Sample on one thread and track each PID separately so restarts cannot merge RSS histories."""

    def __init__(self, output: Path, faults: int, steady: int | None, interval: int, records: int = 16, persistent: bool = False) -> None:
        """Create a fresh evidence directory and initialize resource limits and per-process progress tracking."""
        self.output = output
        self.faults = faults
        self.steady = steady
        self.interval = interval
        self.records = records
        self.persistent = persistent
        self.expected = {}
        self.offsets = {}
        self.progress = {}
        self.last = 0.0
        self.output.mkdir(parents=True, exist_ok=False)

    def record(self, event: str, **values: object) -> None:
        """Write one observation per JSONL line; distinguish successful checks from requested stops."""
        value = {
            "event": event,
            "utc": time.time(),
            "elapsed": time.monotonic(),
            **values,
        }
        with (self.output / "events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(value) + "\n")
        if event != "sample":
            print(json.dumps(value), flush=True)

    def expect(self, process: subprocess.Popen, name: str) -> None:
        """Register a resident process whose unexpected exit must fail the run."""
        self.expected[process.pid] = (process, name)

    def retire(self, process: subprocess.Popen) -> None:
        """Remove a finite or deliberately stopped process from resident-liveness expectations."""
        self.expected.pop(process.pid, None)

    def watch(self, log: Path) -> None:
        """Require resident SDK business rounds to progress; liveness cannot hide deadlock, and total runtime is unlimited."""
        self.progress[log] = {"round": None, "updated": time.monotonic()}

    def observe(self, log: Path, added: bytes, now: float) -> None:
        """Consume complete progress lines only; duplicate tails cannot extend deadlines, and resident rounds must increase."""
        if log not in self.progress:
            return
        progress = self.progress[log]
        for line in added.splitlines():
            try:
                event = json.loads(line)
            except (ValueError, UnicodeError):
                continue
            if not isinstance(event, dict) or event.get("event") != "mesh_progress":
                continue
            current = event.get("round")
            if type(current) is not int or current < 1 or (progress["round"] is not None and current < progress["round"]):
                raise RuntimeError("Resident workload progress moved backwards")
            if progress["round"] is None or current > progress["round"]:
                progress.update(round=current, updated=now)
        if now - progress["updated"] > 180:
            raise RuntimeError("Resident workload made no confirmed progress for 180 seconds")

    def check(self, owned: list[tuple[subprocess.Popen, Path]], *, force: bool = False) -> None:
        """Read native resources and new log bytes at most every five seconds; preserve diagnostics and failures."""
        now = time.monotonic()
        if not force and now - self.last < 5:
            return
        self.last = now
        for process, name in self.expected.values():
            if process.poll() is not None:
                raise RuntimeError(f"Resident service exited unexpectedly: {name}, code={process.returncode}")
        memory = resources.memory()
        if memory["available"] < 128 * 1024 * 1024:
            raise RuntimeError("Soak stopped below 128 MiB available host memory")
        samples = []
        total = 0
        for process, log in owned:
            size = log.stat().st_size
            total += size
            if size > 128 * 1024 * 1024 or total > 512 * 1024 * 1024:
                raise RuntimeError("Soak log budget exhausted, evidence is incomplete")
            offset = self.offsets.get(log, 0)
            with log.open("rb") as stream:
                stream.seek(max(0, offset - 64))  # Retain diagnostic prefixes crossing read boundaries, including split sanitizer markers.
                added = stream.read(size - stream.tell())
                self.observe(log, added, now)
                if any(
                    marker in added
                    for marker in (
                        b"ThreadSanitizer:",
                        b"AddressSanitizer:",
                        b"LeakSanitizer:",
                        b"runtime error:",
                    )
                ):
                    (self.output / log.name).write_bytes(added[-8192:])
                    raise RuntimeError(f"Sanitizer diagnostic in {log.name}")
                if size != offset:
                    stream.seek(max(0, size - 8192))
                    (self.output / log.name).write_bytes(stream.read(8192))
            self.offsets[log] = size
            if process.poll() is not None:
                continue
            try:
                samples.append({"pid": process.pid, "log": log.name, **resources.sample(process)})
            except (FileNotFoundError, ProcessLookupError, PermissionError) as failure:
                # Native inspection may become inaccessible while a finite child is exiting. Confirm exit through its owning Popen;
                # permission failures for a live child and every unexpected resident exit remain failures.
                code = process.poll()
                if process.pid in self.expected:
                    raise RuntimeError("Resident service disappeared during resource sampling")
                if code is None:
                    # Exit-time diagnostics may become inaccessible before the owner can reap the child.
                    # Bound this final drain; a still-running inaccessible child remains a sampling failure.
                    try:
                        code = process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        raise failure
                self.record("sampling_exit", pid=process.pid, log=log.name, exit_code=code)
        self.record(
            "sample",
            available=memory["available"],
            swap=memory["swap"],
            logs=total,
            processes=samples,
            progress={log.name: value["round"] for log, value in self.progress.items()},
        )


def runtime(installed: bool) -> dict[str, str]:
    """Keep installed-artifact validation independent of the workspace's compiler runtime."""
    if installed:
        if any(name in os.environ for name in ("LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT")):
            raise RuntimeError("Installed artifact validation forbids loader overrides")
        return dict(os.environ)
    return environment(jobs=min(4, len(os.sched_getaffinity(0))))


def parse(arguments: list[str] | None = None) -> argparse.Namespace:
    """Validate explicit soak duration, resource, and recovery settings before starting infrastructure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--installed", action="store_true", help="Use packaged runtimes without workspace library paths or loader overrides")
    parser.add_argument("--comet-go", type=Path, help="Existing Comet Go test executable for a finite three-Star case before C++ recovery cycles")
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New evidence directory; existing directories are rejected",
    )
    parser.add_argument(
        "--fault-seconds",
        type=int,
        default=7200,
        help="Rotate through all three Stars at least once; finish the active cycle at the time limit",
    )
    duration = parser.add_mutually_exclusive_group()
    duration.add_argument(
        "--steady-seconds",
        type=int,
        default=43200,
        help="One resident three-source SDK workload after fault cycles",
    )
    duration.add_argument(
        "--until-stopped",
        action="store_true",
        help="No steady duration limit; stop explicitly with SIGINT/SIGTERM, failures still stop and preserve evidence",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Steady writes before each crash, 0..3600 seconds",
    )
    parser.add_argument(
        "--records",
        type=int,
        default=16,
        help="Per-Star Publishers and Beacons, 1..16 each",
    )
    parser.add_argument(
        "--persistent",
        action="store_true",
        help="Keep all SDK Client owners through exactly three fault cycles and steady work; requires --fault-seconds 0",
    )
    parser.add_argument(
        "--comet-go-residence",
        action="store_true",
        help="Retain 48 Go SDK records through all faults and the finite 7200-second envelope; 0 seconds is a short control",
    )
    options = parser.parse_args(arguments)
    if options.until_stopped:
        options.steady_seconds = None
    if (
        not 0 <= options.fault_seconds <= 604800
        or (options.steady_seconds is not None and not 0 <= options.steady_seconds <= 604800)
        or (options.steady_seconds is not None and options.fault_seconds + options.steady_seconds > 604800)
        or not 0 <= options.interval <= 3600
        or not 1 <= options.records <= 16
        or (options.persistent and options.fault_seconds != 0)
        or (options.persistent and options.steady_seconds is not None and options.steady_seconds + 3 * options.interval > 604800)
    ):
        parser.error("Total duration must be 0..604800 seconds, interval 0..3600 and records 1..16")
    if options.comet_go_residence and (
        options.comet_go is None
        or not options.persistent
        or options.fault_seconds != 0
        or options.steady_seconds not in (0, 7200)
        or options.records != 16
        or options.interval != 0
    ):
        parser.error("Go residence requires --comet-go, --persistent, --fault-seconds 0, --interval 0, --records 16 and --steady-seconds 0 or 7200")
    return options


def main(arguments: list[str] | None = None) -> None:
    """Run the selected existing-artifact soak and record completion, failure, or interruption separately."""
    options = parse(arguments)
    if sys.platform != "linux":
        raise RuntimeError("This resource-qualified soak runner requires Linux /proc")
    binaries = options.binaries.resolve()
    names = (
        "star",
        "pulsar",
        "polaris",
        "astrolabe",
        "comet_process_probe",
        "comet_mesh_probe",
    )
    digests = {name: binary_digest(binaries / name) for name in names}
    if options.comet_go:
        digests["comet_go"] = binary_digest(options.comet_go.resolve())
    recorder = Recorder(
        options.output.resolve(),
        options.fault_seconds,
        options.steady_seconds,
        options.interval,
        options.records,
        options.persistent,
    )
    recorder.record(
        "started",
        faults=options.fault_seconds,
        steady=options.steady_seconds,
        interval=options.interval,
        records=options.records,
        persistent=options.persistent,
        comet_go_residence=options.comet_go_residence,
        binaries=digests,
    )
    # Set only this process's and its children's environment, preserving the explicitly selected sanitizer settings.
    previous_environment = os.environ.copy()
    previous_signal = signal.signal(signal.SIGTERM, terminate)
    try:
        os.environ.update(runtime(options.installed))
        run(
            binaries,
            binaries / "polaris",
            binaries / "astrolabe",
            recorder,
            comet_go=options.comet_go.resolve() if options.comet_go else None,
            comet_go_residence=options.comet_go_residence,
        )
    except BaseException as failure:
        recorder.record(
            ("interrupted" if isinstance(failure, (KeyboardInterrupt, SystemExit)) else "failed"),
            reason=type(failure).__name__,
        )
        raise
    finally:
        signal.signal(signal.SIGTERM, previous_signal)
        os.environ.clear()
        os.environ.update(previous_environment)


if __name__ == "__main__":
    main()
