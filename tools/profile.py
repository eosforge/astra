"""Read Astra probes from exited processes offline using only the standard library; never start services or builds."""

from __future__ import annotations

from collections.abc import Callable, Iterable
import argparse
from array import array
import hashlib
import json
import math
import mmap
import os
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
HEADER = struct.Struct("<16Q")
ENTRY = struct.Struct("<9QII")
MAGIC = 0x4153545241505246
MACRO = re.compile(r'ASTRA_PROFILE_(?:SCOPE|BEGIN|COUNT|VALUE|CONSUME)\([^"\n]*"([^"\n]+)"')
FUNCTIONS = ("clock", "storage", "rpc", "replication", "watch", "sdk", "core", "test")


def identify(name: str) -> int:
    """Hash fixed site names with the same FNV-1a algorithm as the C++ consteval implementation."""
    value = 14695981039346656037
    for byte in name.encode("utf-8"):
        value = ((value ^ byte) * 1099511628211) & ((1 << 64) - 1)
    return value


def inventory(root: Path) -> dict[int, dict]:
    """Scan handwritten probe sites and reject name-hash collisions without executing C++ or tests."""
    result = {}
    for directory in ("common", "star", "pulsar", "comet/cpp"):
        for path in sorted((root / directory).rglob("*")):
            if path.suffix not in {".hpp", ".cpp"} or "generated" in path.parts:
                continue
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            for number, line in enumerate(data.decode("utf-8").splitlines(), 1):
                for match in MACRO.finditer(line):
                    name = match[1]
                    site = identify(name)
                    row = result.setdefault(site, {"name": name, "locations": []})
                    if row["name"] != name:
                        raise ValueError("Probe label hash collision")
                    row["locations"].append({"path": path.relative_to(root).as_posix(), "line": number, "sha256": digest})
    return result


def distribution(values: Iterable[int]) -> dict[str, int | float | bool] | None:
    """Report exact sample order statistics; a sparse P99.9 sample is not a population tail estimate."""
    ordered = sorted(values)
    if not ordered:
        return None
    return {
        "count": len(ordered),
        "sum": sum(ordered),
        "mean": sum(ordered) / len(ordered),
        **{name: ordered[max(0, math.ceil(fraction * len(ordered)) - 1)] for name, fraction in (("p50", 0.5), ("p95", 0.95), ("p99", 0.99), ("p999", 0.999))},
        "max": ordered[-1],
        "min": ordered[0],
        "tail_samples_sufficient": len(ordered) >= 10000,
    }


def analyze(path: Path, sites: dict[int, dict], trace: Callable[[dict], None] | None = None, clock: Callable[[dict], None] | None = None) -> dict:
    """Map one exited process's file and resolve parents by slot, without a million-entry Python parent map."""
    groups = {}
    with path.open("rb") as stream:
        if path.stat().st_size < HEADER.size:
            raise ValueError(f"{path.name}: truncated header")
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            magic, version, width, capacity, count, missed, errors, sample, cpu, *reserved = HEADER.unpack_from(data)
            if magic != MAGIC or version not in (1, 2) or width != ENTRY.size:
                raise ValueError(f"{path.name}: unsupported profile format")
            # v1 has no feature selection; v2 reuses reserved header bytes. Other reserved bytes must remain zero, not guessed extensions.
            selected, seconds = (255, 0) if version == 1 else reserved[:2]
            if any(reserved if version == 1 else reserved[2:]) or not 1 <= selected <= 255 or not 0 <= seconds <= 86400:
                raise ValueError(f"{path.name}: invalid profile selection")
            if (
                not capacity
                or capacity % 64
                or count % 64
                or capacity > (len(data) - HEADER.size) // ENTRY.size
                or not 1 <= sample <= 65536
                or cpu not in (0, 1)
            ):
                raise ValueError(f"{path.name}: invalid header bounds")
            spans = counters = intervals = holes = 0
            for slot in range(min(count, capacity)):
                entry = ENTRY.unpack_from(data, HEADER.size + slot * ENTRY.size)
                if not any(entry):
                    holes += 1
                    continue  # Unused tail slots can also be interrupted spans; they do not prove clean process exit.
                start, elapsed, own, used, exclusive, number, parent, site, value, thread, flags = entry
                if site not in sites or not thread or flags not in ((0, 1, 2, 4) if version == 1 else (0, 1, 2, 4, 10)) or own > elapsed or exclusive > used:
                    raise ValueError(f"{path.name}: invalid record at slot {slot}")
                kind = "value" if flags == 10 else "counter" if flags == 2 else "interval" if flags == 4 else "span"
                if flags == 10 and value >= (1 << 63):
                    value -= 1 << 64  # Decode signed two's-complement values instead of displaying negative offsets as huge positives.
                if kind == "span":
                    if number != slot + 1 or flags != cpu or value or (not cpu and (used or exclusive)):
                        raise ValueError(f"{path.name}: invalid span at slot {slot}")
                    spans += 1
                else:
                    if (
                        number
                        or used
                        or exclusive
                        or (kind in ("counter", "value") and (elapsed or own or not parent))
                        or (kind == "interval" and (parent or value or own != elapsed))
                    ):
                        raise ValueError(f"{path.name}: invalid event at slot {slot}")
                    counters += kind in ("counter", "value")
                    intervals += kind == "interval"
                parent_name = None
                if parent:
                    if parent > slot:
                        raise ValueError(f"{path.name}: invalid parent position")
                    ancestor = ENTRY.unpack_from(data, HEADER.size + (parent - 1) * ENTRY.size)
                    if (
                        ancestor[5] != parent
                        or ancestor[9] != thread
                        or ancestor[10] not in (0, 1)
                        or ancestor[0] > start
                        or start + elapsed > ancestor[0] + ancestor[1]
                        or ancestor[7] not in sites
                    ):
                        raise ValueError(f"{path.name}: missing or invalid parent for slot {slot}")
                    parent_name = sites[ancestor[7]]["name"]
                key = (site, parent_name, kind)
                group = groups.get(key)
                if group is None:
                    group = {
                        "wall_ns": array("Q"),
                        "own_ns": array("Q"),
                        "cpu_ns": array("Q"),
                        "cpu_own_ns": array("Q"),
                        "values": array("q" if kind == "value" else "Q"),
                    }
                    groups[key] = group
                if kind in ("counter", "value"):
                    group["values"].append(value)
                    # Preserve each raw clock value and its span; aggregate means would hide the ordering of error spikes and backward steps.
                    if clock and sites[site]["name"].startswith("clock."):
                        clock(
                            {
                                "process": path.stem,
                                "thread": thread,
                                "observed_ns": start,
                                "span": parent,
                                "scope": parent_name,
                                "name": sites[site]["name"],
                                "value": value,
                            }
                        )
                else:
                    group["wall_ns"].append(elapsed)
                    group["own_ns"].append(own)
                    if kind == "span" and cpu:
                        group["cpu_ns"].append(used)
                        group["cpu_own_ns"].append(exclusive)
                if trace:
                    trace(
                        {
                            "name": sites[site]["name"],
                            "cat": kind,
                            "ph": "i" if kind in ("counter", "value") else "X",
                            "pid": path.stem,
                            "tid": thread,
                            "ts": start / 1000,
                            "dur": elapsed / 1000,
                            "s": "t",
                            "args": {"id": number, "parent": parent, "value": value},
                        }
                    )
    rows = []
    for (site, parent, kind), values in groups.items():
        rows.append(
            {"name": sites[site]["name"], "parent": parent, "kind": kind, **{metric: distribution(samples) for metric, samples in values.items() if samples}}
        )
    return {
        "file": path.name,
        "format": version,
        "functions": [name for bit, name in enumerate(FUNCTIONS) if selected & (1 << bit)],
        "seconds": seconds,
        "sample": sample,
        "cpu": bool(cpu),
        "reserved": count,
        "capacity": capacity,
        "unused_slots": holes,
        "missed": missed,
        "errors": errors,
        "spans": spans,
        "counters": counters,
        "intervals": intervals,
        "complete": not (missed or errors or count > capacity),
        "groups": sorted(rows, key=lambda row: row.get("own_ns", {}).get("sum", 0), reverse=True),
    }


def main() -> int:
    """Export a static inventory or analyze completed probe files without running the measured program."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?")
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--inventory", type=Path, help="Write only the static probe-site inventory without running tests")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--trace", type=Path, help="Optional Chrome Trace JSON, which may exceed the binary input size")
    parser.add_argument("--clock", type=Path, help="Also export clock values as JSONL; order same-host processes by observed_ns, not file slots")
    options = parser.parse_args()
    sites = inventory(options.source.resolve())
    if options.inventory:
        options.inventory.write_text(json.dumps(sites, ensure_ascii=False, indent=2), encoding="utf-8")
    if options.directory is None:
        if not options.inventory:
            parser.error("directory or --inventory is required")
        return 0
    if not options.output:
        parser.error("--output is required with directory")
    paths = sorted(options.directory.glob("*.profile"))
    if not paths:
        parser.error("No profile files; initialization or collection was not successful")
    # Stream output items without constructing another complete timeline in memory; offline export does not affect measured services.
    reports = []
    with (
        options.trace.open("w", encoding="utf-8") if options.trace else open(os.devnull, "w", encoding="utf-8") as output,
        options.clock.open("w", encoding="utf-8") if options.clock else open(os.devnull, "w", encoding="utf-8") as clock_output,
    ):
        output.write('{"traceEvents":[')
        first = True

        def emit(record: dict) -> None:
            """Append one trace event with valid comma separation and bounded additional memory."""
            nonlocal first
            output.write(("" if first else ",") + json.dumps(record, ensure_ascii=False))
            first = False

        def emit_clock(record: dict) -> None:
            """Append a raw clock observation as one JSONL record."""
            clock_output.write(json.dumps(record, ensure_ascii=False) + "\n")

        for path in paths:
            reports.append(analyze(path, sites, emit if options.trace else None, emit_clock if options.clock else None))
        output.write("]}")
    report = {
        "scope": "sampled synchronous spans and separate asynchronous intervals; not request end-to-end latency",
        "requires_successful_process_exit": True,
        "sites": sites,
        "processes": reports,
    }
    options.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Analyzed {len(reports)} process files; complete={all(item['complete'] for item in reports)}")
    return 0 if all(item["complete"] for item in reports) else 1


if __name__ == "__main__":
    raise SystemExit(main())
