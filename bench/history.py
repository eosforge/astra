"""Select historical throughput references from complete native three-Star evidence without running workloads."""

from __future__ import annotations

import argparse
from pathlib import Path
import statistics

from bench.run import observations, scenario
from tools import verify as v


def load(path: Path) -> object:
    """Read bounded, duplicate-free JSON using the evidence parser."""
    return v.decode(v.read(path))


def require(condition: bool, reason: str) -> None:
    """Reject incomplete or contradictory historical facts rather than selecting around them."""
    if not condition:
        raise ValueError(reason)


def command(argv: list[str], option: str) -> str:
    """Extract one required argument without accepting repeated or missing options."""
    require(argv.count(option) == 1 and argv.index(option) + 1 < len(argv), "Missing or repeated benchmark option: " + option)
    return argv[argv.index(option) + 1]


def stable(samples: list[dict]) -> bool:
    """Recompute memory stability from the full trace, retaining transient changes and paging."""
    require(bool(samples), "Missing resource observations")
    for sample in samples:
        require(all(type(sample.get(key)) is int and sample[key] >= 0 for key in ("total", "swap_in", "swap_out")), "Invalid resource counters")
        require(sample["total"] > 0, "Missing physical memory capacity")
    require(all(left["time"] <= right["time"] for left, right in zip(samples, samples[1:])), "Resource time regressed")
    require(
        all(left[key] <= right[key] for left, right in zip(samples, samples[1:]) for key in ("swap_in", "swap_out")),
        "Paging counters regressed",
    )
    return all(len({sample[key] for sample in samples}) == 1 for key in ("total", "swap_in", "swap_out"))


def campaign(run: Path) -> dict:
    """Reconcile one frozen campaign's native command, summary, workload logs, resources, and input identity."""
    run = run.resolve()
    paths = {}

    def document(path: Path) -> object:
        """Bind every consumed JSON artifact to its repository-independent evidence-relative path."""
        require(path.resolve().is_relative_to(run), "Evidence path escaped the selected run")
        value = load(path)
        paths[path.relative_to(run).as_posix()] = v.file_digest(path)
        return value

    inputs = document(run / "inputs.json")
    terminal = document(run / "terminal.json")
    require(
        terminal.get("source_unchanged") is True and terminal.get("interrupted") is False and terminal.get("remaining_owned") == [],
        "Incomplete source or cleanup",
    )
    require(terminal.get("errors") == [], "Campaign has unresolved execution errors")
    require(isinstance(inputs.get("files"), dict) and bool(inputs["files"]), "Missing dirty-source manifest")
    sources = {
        name: inputs["files"].get(name) for name in ("bench/run.py", "bench/comet.cpp", "bench/measure.hpp", "bench/delivery.hpp", "bench/qualification.json")
    }
    # Old campaigns keep header-only identities; outlined measurement code must bind both implementation files.
    implementations = ("bench/measure.cpp", "bench/delivery.cpp")
    if any(name in inputs["files"] for name in implementations):
        sources.update({name: inputs["files"].get(name) for name in implementations})
    require(
        all(isinstance(value, str) and len(value) == 64 and set(value) <= set("0123456789abcdef") for value in sources.values()),
        "Missing measurement source identity",
    )

    stages = list((run / "source/build/results/assurance").glob("stage-performance/record.json"))
    require(len(stages) == 1, "Missing unique native performance command")
    record = document(stages[0])
    require(record.get("exit_code") == 0 and record.get("complete") is True and record.get("cleanup") is True, "Performance command did not finish cleanly")
    require(record.get("termination") == "exited" and record.get("platform") == "linux-amd64-cgo", "Unsupported native command boundary")
    require(
        [entry for entry in terminal["records"] if entry.get("id") == record["id"]]
        == [{"id": record["id"], "expected_exit": 0, "actual_exit": 0, "complete": True, "cleanup": True}],
        "Terminal and performance command disagree",
    )
    output = []
    for name in ("stdout", "stderr"):
        data = v.reference(stages[0].parent, record[name], 32 * 1024 * 1024)
        paths[(stages[0].parent / record[name]["path"]).relative_to(run).as_posix()] = v.digest(data)
        if name == "stdout":
            output = [v.decode(line) for line in data.splitlines() if line.strip()]
    require(bool(output) and len(output) % 2 == 0, "Incomplete native benchmark events")
    argv = record["argv"]
    repeat = int(command(argv, "--repeat"))
    require(1 <= repeat <= 5 and "bench/run.py" in argv and "--native" not in argv and "--almanac" not in argv, "Unsupported benchmark command")
    require(command(argv, "--cases") == "bench/qualification.json", "Different workload family")
    marker = "/source/"
    location = command(argv, "--output")
    require(location.count(marker) == 1, "Ambiguous frozen benchmark location")
    directory = run / "source" / location.split(marker, 1)[1]
    identity = document(directory / "identity.json")
    results = document(directory / "results.json")
    require(len(results) * 2 == len(output) and len(results) % repeat == 0, "Missing or extra completed rounds")
    require(
        type(identity.get("cpus")) is int and identity["cpus"] > 0 and bool(identity.get("affinity")) and bool(identity.get("kernel")), "Missing host identity"
    )
    require(set(identity.get("binaries", {})) == {"star", "pulsar", "polaris", "astrolabe", "comet_bench"}, "Missing binary identity")
    require(
        all(isinstance(value, str) and len(value) == 64 and set(value) <= set("0123456789abcdef") for value in identity["binaries"].values()),
        "Invalid binary identity",
    )
    accepted, excluded = [], []
    cases = set()
    for index, result in enumerate(results):
        number, round_ = divmod(index, repeat)
        start, finish = output[index * 2 : index * 2 + 2]
        case = result["case"]
        scenario(case)
        require(case.get("qualification") is True, "Historical single-writer data is not distributed qualification")
        require(start == {"case": number, "round": round_, "parameters": case} and result["round"] == round_, "Scenario order disagrees with native events")
        require(
            finish == {"completed": number, "round": round_, "stable_memory": result["stable_memory"], "measurements": result["measurements"]},
            "Summary differs from native output",
        )
        key = v.encode(case).decode()
        if round_ == 0:
            require(key not in cases, "Duplicate benchmark scenario")
            cases.add(key)
        else:
            require(case == results[index - 1]["case"], "Workload changed between rounds")
        sample = directory / f"case-{number}-round-{round_}"
        log = sample / "comet.log"
        data = v.read(log)
        paths[log.relative_to(run).as_posix()] = v.digest(data)
        metrics = observations(data.decode("utf-8"), case)
        require(metrics == result["measurements"], "Native workload and summary disagree")
        trace = document(sample / "resources.json")
        require(bool(trace), "Missing in-flight resource trace")
        unchanged = stable([result["before"], *trace, result["after"]])
        require(type(result["stable_memory"]) is bool and unchanged == result["stable_memory"], "Resource flag disagrees with counters")
        item = {"case": case, "round": round_, "measurements": metrics, "log": log.relative_to(run).as_posix()}
        if unchanged:
            accepted.append({**item, "memory_bytes": result["before"]["total"]})
        else:
            excluded.append({**item, "reason": "memory-change-or-paging"})
    return {
        "run": run.name,
        "head": inputs.get("head"),
        "sources": sources,
        "identity": identity,
        "artifacts": paths,
        "accepted": accepted,
        "excluded": excluded,
    }


def select(campaigns: list[dict]) -> list[dict]:
    """Pick the highest actual stable throughput per comparable scenario, retaining its paired latency observations."""
    groups = {}
    identities = set()
    for run in campaigns:
        manifest = run["artifacts"]["inputs.json"]
        identity = (manifest, tuple((name, value) for name, value in sorted(run["artifacts"].items()) if name.endswith("/record.json")))
        require(identity not in identities, "Duplicate native campaign supplied")
        identities.add(identity)
        for sample in run["accepted"]:
            # These historical fields establish a comparison cohort, not a claim of isolated CPU scheduling.
            cohort = {key: run["identity"][key] for key in ("cpus", "affinity", "kernel")}
            cohort.update(memory_bytes=sample["memory_bytes"], sources=run["sources"], case=sample["case"])
            row = {"run": run["run"], "inputs_sha256": manifest, **sample}
            groups.setdefault(v.encode(cohort).decode(), []).append(row)
    require(bool(groups), "No complete stable distributed samples")
    rows = []
    for key, samples in sorted(groups.items()):

        def throughput(sample: dict) -> float:
            """Select measured commit throughput; never synthesize an unattained combination of extrema."""
            return next(metric["operations_per_second"] for metric in sample["measurements"] if metric["metric"] == "comet.commit")

        best = max(samples, key=throughput)
        rows.append(
            {
                "cohort": v.decode(key.encode()),
                "best": best,
                "stable_samples": len(samples),
                "median_operations_per_second": statistics.median(throughput(sample) for sample in samples),
                "range_operations_per_second": [min(map(throughput, samples)), max(map(throughput, samples))],
            }
        )
    return rows


def main() -> None:
    """Write a new derived reference; never modify history, infer CI trust, or declare release eligibility."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    runs = [campaign(path) for path in args.run]
    result = {
        "schema_version": 1,
        "trust": "local",
        "qualification": "not-evaluated",
        "selection": "highest-observed-stable-throughput-with-paired-latencies",
        "collector_sha256": v.file_digest(Path(__file__)),
        "baselines": select(runs),
        "campaigns": runs,
    }
    v.write_new(args.output, result)


if __name__ == "__main__":
    main()
