"""Compare paired baseline samples only within matching scenarios and rounds, excluding memory growth or paging on either side."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics


def summarize(results: list[dict]) -> list[dict]:
    """Retain round counts and ranges without merging quantile samples or presenting short windows as an SLA."""
    groups = {}
    for result in results:
        key = json.dumps(result["case"], sort_keys=True)
        rounds = groups.setdefault(key, {})
        pair = rounds.setdefault(result["round"], {})
        if result["implementation"] in pair:
            raise ValueError("Duplicate implementation in a paired round")
        pair[result["implementation"]] = result
    output = []
    for key, rounds in groups.items():
        pairs = [
            pair for pair in rounds.values() if set(pair) == {"redis", "comet"} and all(value["passed"] and value["stable_memory"] for value in pair.values())
        ]
        row = dict(case=json.loads(key), paired_rounds=len(pairs), total_rounds=len(rounds), implementations={}, failures={})
        for implementation in ("redis", "comet"):
            row["failures"][implementation] = sum(implementation in pair and not pair[implementation]["passed"] for pair in rounds.values())
            values = [pair[implementation] for pair in pairs]
            metrics = {}
            for name in ("commit", "visible"):
                samples = [metric for value in values for metric in value["measurements"] if metric["metric"] == name]
                if samples:
                    fields = ("operations_per_second", "p50_us", "p95_us", "p99_us", "p999_us")
                    metrics[name] = {field: statistics.median(sample[field] for sample in samples) for field in fields}
                    metrics[name]["throughput_range"] = [
                        min(sample["operations_per_second"] for sample in samples),
                        max(sample["operations_per_second"] for sample in samples),
                    ]
            row["implementations"][implementation] = metrics
        if pairs:
            row["comet_redis_throughput_ratio"] = (
                row["implementations"]["comet"]["commit"]["operations_per_second"] / row["implementations"]["redis"]["commit"]["operations_per_second"]
            )
        output.append(row)
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    arguments = parser.parse_args()
    print(json.dumps(summarize(json.loads(arguments.results.read_text(encoding="utf-8"))), indent=2, ensure_ascii=False))
