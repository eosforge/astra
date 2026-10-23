"""Apply Linux cgroup v2 limits before benchmark service execution and retain native accounting after draining."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import time

from tests.support import popen, stop_process
from tools import verify as v

LIMITS = ("memory.high", "memory.max", "memory.swap.max", "pids.max", "cpu.max")
COUNTERS = (
    "memory.current",
    "memory.peak",
    "memory.events",
    "memory.events.local",
    "memory.stat",
    "memory.pressure",
    "pids.current",
    "pids.peak",
    "pids.events",
    "cpu.stat",
    "cpu.pressure",
    "cgroup.events",
    "cgroup.procs",
)
ROLES = ("pulsar", "polaris", "astrolabe", "star-0", "star-1", "star-2", "comet")


def location(pid: int | str = "self") -> Path:
    """Resolve this process's unified native cgroup without accepting a caller-supplied escape path."""
    lines = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
    return Path("/sys/fs/cgroup") / next(line[3:] for line in lines if line.startswith("0::")).lstrip("/")


def read(group: Path) -> dict[str, str]:
    """Retain kernel accounting, including cache charges, separately from sampled process RSS."""
    return {name: (group / name).read_text().strip() for name in (*LIMITS, *COUNTERS)}


def values(text: str) -> dict[str, int]:
    """Decode named native counters without inferring missing values as zero."""
    return {name: int(value) for name, value in (row.split() for row in text.splitlines())}


def configure(group: Path, limits: dict[str, str]) -> None:
    """Write and read back every native limit before a tested child can enter the group."""
    for name, value in limits.items():
        (group / name).write_text(value)
    actual = {name: (group / name).read_text().strip() for name in limits}
    if actual != limits:
        raise RuntimeError(f"Ineffective native limits: {actual!r} != {limits!r}")


def delegate(group: Path, deployment: dict) -> Path:
    """Move only this controller into its leaf and enable the already-delegated service controllers."""
    if location() != group or (group / "cgroup.procs").read_text().split() != [str(os.getpid())]:
        raise RuntimeError("Campaign cgroup must initially contain only its current controller")
    expected = {
        "memory.high": str(deployment["memory_high_bytes"]),
        "memory.max": str(deployment["memory_maximum_bytes"]),
        "memory.swap.max": "0",
        "pids.max": "2048",
        "cpu.max": f"{deployment['vcpus'] * 100000} 100000",
    }
    if any((group / name).read_text().strip() != value for name, value in expected.items()):
        raise RuntimeError("Whole-test-tree limits must already be effective before delegation")
    owner = group / "owner"
    owner.mkdir()
    (owner / "cgroup.procs").write_text(str(os.getpid()))
    (group / "cgroup.subtree_control").write_text("+cpu +memory +pids")
    if not {"cpu", "memory", "pids"} <= set((group / "cgroup.subtree_control").read_text().split()) or location() != owner:
        raise RuntimeError("Native service controllers were not delegated")
    return owner


class Domain:
    """Own one physical sample's seven leaves and preserve their limits, process identities and terminal counters."""

    def __init__(self, group: Path, deployment: dict, output: Path) -> None:
        """Retain the delegated group and round the service memory cap down to whole pages."""
        self.root, self.deployment, self.output = group, deployment, output
        self.members: dict[str, tuple[Path, object, dict]] = {}
        self.page = os.sysconf("SC_PAGE_SIZE")
        self.service_limit = deployment["service_peak_maximum_bytes"] // self.page * self.page

    def launch(self, role: str, command: list[str], **options: object) -> object:
        """Enter a bounded leaf in a small exec wrapper before any service or SDK code executes."""
        if role not in ROLES or role in self.members:
            raise RuntimeError("Unexpected or repeated service role")
        self.check()
        group = self.root / (self.output.name + "-" + role)
        group.mkdir()
        maximum = str(self.service_limit) if role != "comet" else "max"
        limits = {"memory.high": "max", "memory.max": maximum, "memory.swap.max": "0", "pids.max": "256", "cpu.max": "max 100000"}
        configure(group, limits)
        v.write_new(
            self.output / (role + ".launch.json"),
            {
                "command": command,
                "cwd": str(options["cwd"]),
                "environment": options["env"],
                "cgroup": str(group),
                "limits": read(group),
                "requested_service_maximum_bytes": self.deployment["service_peak_maximum_bytes"],
            },
        )
        process = None
        identity = {}
        self.members[role] = (group, process, identity)
        try:
            process = popen([sys.executable, "-B", "-m", "bench.cgroups", "--enter", str(group), "--", *command], **options)
            identity = v.proc_identity(process.pid)
            self.members[role] = (group, process, identity)
            deadline = time.monotonic() + 10
            while process.poll() is None:
                if location(process.pid) == group and Path(f"/proc/{process.pid}/exe").resolve() == Path(command[0]).resolve():
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError("Service did not enter its native limit before execution")
                time.sleep(0.01)
            else:
                raise RuntimeError(f"Service wrapper exited before identity reconciliation: {role} {process.returncode}")
            v.write_new(
                self.output / (role + ".identity.json"),
                {
                    "identity": identity,
                    "executable": str(Path(f"/proc/{process.pid}/exe").resolve()),
                    "argv": Path(f"/proc/{process.pid}/cmdline").read_bytes().decode().rstrip("\0").split("\0"),
                    "cgroup": str(location(process.pid)),
                    "limits": read(group),
                },
            )
            self.check()
            return process
        except BaseException:
            if process is not None:
                stop_process(process)
            raise

    def check(self) -> dict:
        """Fail on any memory pressure/limit event or process limit, including events between RSS samples."""
        snapshots = {"whole-test-tree": read(self.root)} | {name: read(group) for name, (group, _, _) in self.members.items()}
        for name, state in snapshots.items():
            expected = {
                "memory.high": str(self.deployment["memory_high_bytes"]) if name == "whole-test-tree" else "max",
                "memory.max": (
                    str(self.deployment["memory_maximum_bytes"]) if name == "whole-test-tree" else ("max" if name == "comet" else str(self.service_limit))
                ),
                "memory.swap.max": "0",
                "pids.max": "2048" if name == "whole-test-tree" else "256",
                "cpu.max": f"{self.deployment['vcpus'] * 100000} 100000" if name == "whole-test-tree" else "max 100000",
            }
            if any(state[key] != value for key, value in expected.items()):
                raise RuntimeError("Native limits changed in " + name)
            events = values(state["memory.events"])
            if any(events[key] for key in ("high", "max", "oom", "oom_kill", "oom_group_kill")) or values(state["pids.events"])["max"]:
                raise RuntimeError(f"Native memory/process limit event in {name}: {events}")
            maximum = self.deployment["memory_high_bytes"] if name == "whole-test-tree" else self.deployment["service_peak_maximum_bytes"]
            if name != "comet" and int(state["memory.peak"]) > maximum:
                raise RuntimeError(f"Native memory ceiling exceeded in {name}")
        return {name: {key: value for key, value in state.items() if key not in ("memory.stat", "cgroup.procs")} for name, state in snapshots.items()}

    def close(self) -> dict:
        """Seal all seven dead leaves; force cleanup only within this domain's proven native groups."""
        facts, errors = {}, []
        for role, (group, process, identity) in reversed(list(self.members.items())):
            if process is not None and process.poll() is None:
                stop_process(process)
            if values((group / "cgroup.events").read_text())["populated"]:
                errors.append("Unexpected descendants in " + role)
                (group / "cgroup.kill").write_text("1")
                until = time.monotonic() + 5
                while values((group / "cgroup.events").read_text())["populated"] and time.monotonic() < until:
                    time.sleep(0.02)
            actual = v.proc_identity(identity["pid"]) if identity else None
            if actual is not None and actual["start_ticks"] == identity["start_ticks"]:
                errors.append("Process identity remains in " + role)
            facts[role] = {
                "identity": identity,
                "accounting": read(group),
                "populated": values((group / "cgroup.events").read_text())["populated"],
                "retired": actual is None or actual["start_ticks"] != identity.get("start_ticks"),
            }
        try:
            self.check()
        except RuntimeError as error:
            errors.append(str(error))
        v.write_new(self.output / "cgroups.terminal.json", {"roles": facts, "root": read(self.root), "errors": errors})
        for group, _, _ in self.members.values():
            if not values((group / "cgroup.events").read_text())["populated"]:
                group.rmdir()
        if errors or set(facts) != set(ROLES):
            raise RuntimeError("Incomplete native domain: " + repr(errors))
        return facts


def main() -> None:
    """Enroll only this wrapper process in its preconfigured delegated leaf, then replace it with the tested executable."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enter", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    current = location()
    group = args.enter.resolve()
    if current.name != "owner" or group.parent != current.parent or group == current or not args.command or args.command[0] != "--":
        raise RuntimeError("Exec wrapper cannot leave its delegated campaign tree")
    before = read(group)
    if before["cgroup.procs"] or before["memory.swap.max"] != "0" or not before["pids.max"].isdecimal() or not 1 <= int(before["pids.max"]) <= 256:
        raise RuntimeError("Child leaf is occupied or unbounded")
    (group / "cgroup.procs").write_text(str(os.getpid()))
    if location() != group:
        raise RuntimeError("Child cgroup enrollment failed")
    os.execv(args.command[1], args.command[1:])


if __name__ == "__main__":
    main()
