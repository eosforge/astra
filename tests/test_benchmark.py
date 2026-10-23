"""Reject apparently successful benchmark processes that did not execute the required distributed workload."""

import json
from pathlib import Path
import unittest

from bench.run import ProbeFailure, observations, scenario


class BenchmarkTests(unittest.TestCase):
    """Use synthetic outputs solely to exercise admission and non-vacuity checks."""

    def test_distributed_denominator(self) -> None:
        """One busy Star cannot hide two idle peers behind an aggregate throughput number."""
        case = {"qualification": True, "stars": 3}
        metrics = [
            {"metric": name, "count": 6, "samples": 6, "seconds": 2, "operations_per_second": 3, "p50_us": 1, "p95_us": 2, "p99_us": 3, "p999_us": 4}
            for name in ("comet.commit", "comet.visible")
        ]

        def log(writes: list[int]) -> str:
            """Encode a fixture's topology and observed completion counts."""
            return "\n".join(json.dumps(item) for item in [{"topology": "distributed-writers-v1", "writes": writes}, *metrics])

        self.assertEqual(observations(log([1, 2, 3]), case), metrics)
        for writes in ([6, 0, 0], [3, 3], [1, 1, 1], [True, 2, 3]):
            with self.assertRaises(ProbeFailure):
                observations(log(writes), case)
        for text in ("", "\n".join(map(json.dumps, metrics)), log([1, 2, 3]) + "\n" + log([1, 2, 3])):
            with self.assertRaises(ProbeFailure):
                observations(text, case)
        with self.assertRaises(ProbeFailure):
            observations(log([1, 2, 3]) + "\n" + json.dumps(metrics[0]), case)
        for field, value in (("samples", 0), ("seconds", float("nan")), ("operations_per_second", 9), ("p50_us", 100), ("p99_us", None)):
            original = metrics[0][field]
            metrics[0][field] = value
            with self.assertRaises(ProbeFailure):
                observations(log([1, 2, 3]), case)
            metrics[0][field] = original

    def test_scenarios(self) -> None:
        """Every shipped network workload fits the native probe, including its unrenewed Catalog TTL."""
        root = Path(__file__).resolve().parents[1] / "bench"
        for name in ("network.json", "auth.json", "concurrency.json", "qualification.json"):
            for case in json.loads((root / name).read_text()):
                scenario(case)
        case = json.loads((root / "qualification.json").read_text())[0]
        for field, value in (("ttl", 30000), ("writers", 1), ("watchers", 1), ("stars", 2), ("bytes", True), ("domain", "typo")):
            with self.assertRaises(ProbeFailure):
                scenario({**case, field: value})


if __name__ == "__main__":
    unittest.main()
