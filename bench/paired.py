"""Execute one predeclared paired-campaign sample under existing whole-tree and per-service native limits."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import sys

from bench import cgroups, compare, run
from tools import verify as v


def schedule(configuration: dict, cases: list[dict]) -> list[dict]:
    """Expand every approved warmup and formal pair, preserving both physical orders without retries."""
    compare.policy(configuration)
    qualified = v.decode(v.read(Path(__file__).with_name("qualification.json")))
    if cases != qualified:
        raise ValueError("Paired campaign must retain all four qualified workloads in their fixed order")
    sampling = configuration["sampling"]
    entries = []
    for case in range(len(cases)):
        for pair in range(sampling["warmup_pairs"] + sampling["measurement_pairs"]):
            order = ["baseline", "candidate"] if pair % 2 == 0 else ["candidate", "baseline"]
            for side in order:
                entries.append(
                    {
                        "index": len(entries),
                        "case": case,
                        "pair": pair,
                        "phase": "warmup" if pair < sampling["warmup_pairs"] else "measurement",
                        "side": side,
                        "order": order,
                    }
                )
    return entries


def execute(configuration: dict, case: dict, binaries: Path, output: Path) -> dict:
    """Require real six-service ownership, positive local writes and clean native accounting for one execution."""
    compare.policy(configuration)
    if case not in v.decode(v.read(Path(__file__).with_name("qualification.json"))):
        raise ValueError("Sample differs from its approved workload")
    current = cgroups.location()
    group = current.parent
    deployment = configuration["deployment"]
    expected = {
        "memory.high": str(deployment["memory_high_bytes"]),
        "memory.max": str(deployment["memory_maximum_bytes"]),
        "memory.swap.max": "0",
        "pids.max": "2048",
        "cpu.max": f"{deployment['vcpus'] * 100000} 100000",
    }
    if current.name != "owner" or any((group / name).read_text().strip() != value for name, value in expected.items()):
        raise RuntimeError("Paired sample requires its preconfigured delegated whole-test-tree domain")
    if len(os.sched_getaffinity(0)) != deployment["vcpus"]:
        raise RuntimeError("Native CPU allocation differs from the approved deployment")
    output.mkdir(parents=True, exist_ok=False)
    domain = cgroups.Domain(group, deployment, output)
    errors = []
    result = None
    try:
        metrics = run.cluster(binaries, case, output, launcher=domain.launch, monitor=domain.check)
        rows = [json.loads(line) for line in (output / "comet.log").read_text().splitlines() if line.startswith("{")]
        writes = next(row["writes"] for row in rows if row.get("topology") == "distributed-writers-v1")
        result = {"case": case, "writes": writes, "metrics": metrics}
    except BaseException as error:
        errors.append(type(error).__name__ + ": " + str(error))
        raise
    finally:
        try:
            domain.close()
        except BaseException as error:
            errors.append("cleanup: " + type(error).__name__ + ": " + str(error))
        v.write_new(output / "sample.terminal.json", {"errors": errors, "result": result, "qualification": "not-evaluated"})
    if errors:
        raise RuntimeError("Paired sample accounting failed: " + repr(errors))
    v.write_new(output / "sample.json", result)
    return result


def main() -> None:
    """Run only one explicit physical sample; the independently frozen controller owns its campaign schedule."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, run.terminate)
    result = execute(v.decode(v.read(args.policy)), v.decode(v.read(args.case)), args.binaries.resolve(), args.output.resolve())
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
