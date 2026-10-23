"""Evaluate prospective numerical gates from reconciled pairs; collection and release provenance remain separate."""

from __future__ import annotations

import argparse
from decimal import Decimal, localcontext
import json
import math
from pathlib import Path
import random
import statistics

from bench.run import observations, scenario
from tools import verify as v


def fields(value: object, names: set[str]) -> None:
    """Reject missing or unknown structural fields at the numerical boundary."""
    if not isinstance(value, dict) or set(value) != names:
        raise ValueError("Unexpected performance fields: " + str(names))


def number(value: object) -> Decimal:
    """Retain decimal JSON spellings for inclusive cutoffs, rejecting booleans and nonfinite inputs."""
    if type(value) not in (int, float):
        raise ValueError("Invalid finite performance number")
    try:
        finite = math.isfinite(value)
    except OverflowError as error:
        raise ValueError("Performance number exceeds finite machine range") from error
    if not finite:
        raise ValueError("Invalid finite performance number")
    return Decimal(str(value))


def policy(value: object) -> dict:
    """Validate numerical policy and the explicitly approved whole-process-tree memory ceilings."""
    fields(value, {"version", "approval", "sampling", "regression", "capacity", "deployment"})
    if type(value["version"]) is not int or value["version"] != 1:
        raise ValueError("Unsupported performance policy")
    fields(value["approval"], {"request", "resource_request", "window"})
    if any(not isinstance(item, str) or not item for item in value["approval"].values()):
        raise ValueError("Missing performance approval reference")
    sample = value["sampling"]
    fields(sample, {"warmup_pairs", "measurement_pairs", "order", "block_pairs", "bootstrap_resamples", "seed", "confidence"})
    bounds = {"warmup_pairs": (1, 1000), "measurement_pairs": (8, 1000), "block_pairs": (2, 100), "bootstrap_resamples": (1000, 100000), "seed": (0, 2**32 - 1)}
    if any(type(sample[name]) is not int or not low <= sample[name] <= high for name, (low, high) in bounds.items()):
        raise ValueError("Invalid fixed sampling budget")
    if sample["order"] != "alternating-baseline-candidate" or sample["measurement_pairs"] % sample["block_pairs"] or sample["block_pairs"] % 2:
        raise ValueError("Incomplete balanced measurement blocks")
    if number(sample["confidence"]) != Decimal("0.95"):
        raise ValueError("Unsupported confidence level")
    regression = value["regression"]
    fields(regression, {"median_minimum", "confidence_lower_minimum"})
    if not Decimal(-1) < number(regression["confidence_lower_minimum"]) <= number(regression["median_minimum"]) <= 0:
        raise ValueError("Invalid regression thresholds")
    capacity = value["capacity"]
    fields(capacity, {"throughput_minimum", "latency_maximum_us"})
    fields(capacity["throughput_minimum"], {"catalog/plain", "catalog/tls", "ephemeris/plain", "ephemeris/tls"})
    fields(capacity["latency_maximum_us"], {"comet.commit", "comet.visible"})
    if any(number(item) <= 0 for item in capacity["throughput_minimum"].values()):
        raise ValueError("Invalid throughput floor")
    for limits in capacity["latency_maximum_us"].values():
        fields(limits, {"p95_us", "p99_us"})
        if not 0 < number(limits["p95_us"]) <= number(limits["p99_us"]):
            raise ValueError("Invalid latency ceilings")
    deployment = value["deployment"]
    fields(
        deployment,
        {
            "vcpus",
            "host_memory_maximum_bytes",
            "services",
            "memory_high_bytes",
            "memory_maximum_bytes",
            "service_peak_maximum_bytes",
            "resource_scope",
        },
    )
    fields(deployment["services"], {"star", "pulsar", "polaris", "astrolabe"})
    integers = [
        deployment[name] for name in ("vcpus", "host_memory_maximum_bytes", "memory_high_bytes", "memory_maximum_bytes", "service_peak_maximum_bytes")
    ] + list(deployment["services"].values())
    if any(type(item) is not int or item <= 0 for item in integers) or deployment["services"] != {"star": 3, "pulsar": 1, "polaris": 1, "astrolabe": 1}:
        raise ValueError("Invalid deployment budget")
    if (
        not deployment["service_peak_maximum_bytes"]
        <= deployment["memory_high_bytes"]
        <= deployment["memory_maximum_bytes"]
        <= deployment["host_memory_maximum_bytes"]
    ):
        raise ValueError("Invalid aggregate memory ceilings")
    if deployment["resource_scope"] != "whole-test-tree-ceilings":
        raise ValueError("Missing explicit whole-test-tree ceiling scope")
    return value


def interval(changes: list[Decimal], sample: dict) -> tuple[Decimal, Decimal]:
    """Resample fixed consecutive balanced blocks and return the two-sided 95% percentile interval.

    Four-pair blocks preserve local A/B ordering and within-block dependence. Coverage
    assumes comparable, approximately independent blocks; native environment checks
    must justify that assumption. This function does not establish it from timing data.
    """
    width = sample["block_pairs"]
    if len(changes) != sample["measurement_pairs"] or len(changes) % width:
        raise ValueError("Incomplete confidence input")
    blocks = [changes[start : start + width] for start in range(0, len(changes), width)]
    generator = random.Random(sample["seed"])
    medians = sorted(
        statistics.median([value for _ in blocks for value in blocks[generator.randrange(len(blocks))]]) for _ in range(sample["bootstrap_resamples"])
    )

    def percentile(probability: Decimal) -> Decimal:
        """Use linear interpolation between ordered resamples, with no tail clipping or retries."""
        position = probability * (len(medians) - 1)
        index = int(position)
        fraction = position - index
        return medians[index] + fraction * (medians[min(index + 1, len(medians) - 1)] - medians[index])

    return percentile(Decimal("0.025")), percentile(Decimal("0.975"))


def side(value: object, case: dict) -> dict:
    """Require positive writes at every Star and internally consistent native metric values."""
    fields(value, {"artifact_sha256", "writes", "metrics"})
    digest = value["artifact_sha256"]
    if not isinstance(digest, str) or len(digest) != 64 or set(digest) - set("0123456789abcdef"):
        raise ValueError("Missing fixed artifact identity")
    if not isinstance(value["writes"], list) or not isinstance(value["metrics"], list):
        raise ValueError("Invalid numerical observation containers")
    for metric in value["metrics"]:
        fields(metric, {"metric", "count", "samples", "seconds", "operations_per_second", "p50_us", "p95_us", "p99_us", "p999_us"})
        for name in ("seconds", "operations_per_second", "p50_us", "p95_us", "p99_us", "p999_us"):
            number(metric[name])
    log = "\n".join(json.dumps(row, allow_nan=False) for row in [{"topology": "distributed-writers-v1", "writes": value["writes"]}, *value["metrics"]])
    metrics = observations(log, case)
    return {item["metric"]: item for item in metrics}


def evaluate(configuration: dict, evidence: dict) -> dict:
    """Keep paired regression and absolute throughput/tails as separate numerical decisions.

    Evidence must already be reconciled against native logs, commands, source and
    artifact manifests by the caller. Passing these calculations alone cannot qualify
    the collection, deployment resource envelope, independence or a release.
    """
    policy(configuration)
    fields(evidence, {"case", "pairs"})
    case, pairs = evidence["case"], evidence["pairs"]
    scenario(case)
    sampling = configuration["sampling"]
    if case not in v.decode(v.read(Path(__file__).with_name("qualification.json"))) or not isinstance(pairs, list):
        raise ValueError("Different qualified workload")
    if len(pairs) != sampling["warmup_pairs"] + sampling["measurement_pairs"]:
        raise ValueError("Incomplete fixed pair budget")
    candidates, changes, artifacts = [], [], None
    with localcontext() as context:
        context.prec = 50
        for index, pair in enumerate(pairs):
            fields(pair, {"index", "phase", "order", "baseline", "candidate"})
            expected_phase = "warmup" if index < sampling["warmup_pairs"] else "measurement"
            expected_order = ["baseline", "candidate"] if index % 2 == 0 else ["candidate", "baseline"]
            if type(pair["index"]) is not int or pair["index"] != index or pair["phase"] != expected_phase or pair["order"] != expected_order:
                raise ValueError("Changed pair identity, phase or execution order")
            baseline, candidate = (side(pair[name], case) for name in ("baseline", "candidate"))
            identity = tuple(pair[name]["artifact_sha256"] for name in ("baseline", "candidate"))
            if artifacts is None:
                artifacts = identity
            if identity != artifacts:
                raise ValueError("Artifacts changed between pairs")
            if expected_phase == "measurement":
                changes.append(number(candidate["comet.commit"]["operations_per_second"]) / number(baseline["comet.commit"]["operations_per_second"]) - 1)
                candidates.append(candidate)
        median = statistics.median(changes)
        lower, upper = interval(changes, sampling)
        regression = configuration["regression"]
        relative = {
            "median": float(median),
            "confidence_interval": [float(lower), float(upper)],
            "passed": median >= number(regression["median_minimum"]) and lower >= number(regression["confidence_lower_minimum"]),
        }
        name = case["domain"] + ("/tls" if case["tls"] else "/plain")
        throughput = statistics.median(number(item["comet.commit"]["operations_per_second"]) for item in candidates)
        floor = number(configuration["capacity"]["throughput_minimum"][name])
        excursions = [
            {"pair": sampling["warmup_pairs"] + index, "metric": metric, "quantile": quantile, "observed_us": item[metric][quantile], "limit_us": maximum}
            for index, item in enumerate(candidates)
            for metric, limits in configuration["capacity"]["latency_maximum_us"].items()
            for quantile, maximum in limits.items()
            if number(item[metric][quantile]) > number(maximum)
        ]
        absolute = {
            "throughput_median": float(throughput),
            "throughput_minimum": float(floor),
            "latency_excursions": excursions,
            "passed": throughput >= floor and not excursions,
        }
    return {
        "case": case,
        "warmup_pairs": sampling["warmup_pairs"],
        "measurement_pairs": len(changes),
        "artifacts": dict(zip(("baseline", "candidate"), artifacts)),
        "regression": relative,
        "capacity": absolute,
        "qualification": "not-evaluated",
        "resource_scope": configuration["deployment"]["resource_scope"],
    }


def main() -> None:
    """Read bounded duplicate-free inputs and write one numerical report without launching workloads."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    result = evaluate(v.decode(v.read(arguments.policy)), v.decode(v.read(arguments.evidence)))
    v.write_new(arguments.output, result)
    raise SystemExit(int(not (result["regression"]["passed"] and result["capacity"]["passed"])))


if __name__ == "__main__":
    main()
