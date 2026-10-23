"""Test prospective numerical performance gates with synthetic controls, never benchmark or release evidence."""

from collections.abc import Callable
import copy
from decimal import Decimal
import json
from pathlib import Path
import statistics
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from bench import compare
from bench import paired
from bench import run as measure
from bench.run import ProbeFailure
from tools import verify as v


class ComparisonTests(unittest.TestCase):
    """Protect fixed exposure, paired estimation, independent cutoffs and explicit resource scope."""

    def setUp(self) -> None:
        """Load the approved numerical policy and actual maintained workload without changing either."""
        root = Path(__file__).resolve().parents[1]
        self.policy = v.decode(v.read(root / "bench/performance.json"))
        self.case = v.decode(v.read(root / "bench/qualification.json"))[1]

    def side(self, throughput: float, artifact: str) -> dict:
        """Create consistent positive three-writer observations solely for gate controls."""
        count = int(throughput * 10)
        writes = [count // 3, count // 3, count - 2 * (count // 3)]
        metrics = [
            {
                "metric": metric,
                "count": count,
                "samples": count,
                "seconds": count / throughput,
                "operations_per_second": throughput,
                "p50_us": 10,
                "p95_us": 100,
                "p99_us": 200,
                "p999_us": 300,
            }
            for metric in ("comet.commit", "comet.visible")
        ]
        return {"artifact_sha256": artifact * 64, "writes": writes, "metrics": metrics}

    def evidence(self, baseline: float = 5000, candidate: float = 5000) -> dict:
        """Include every warmup and measured pair in the fixed alternating order."""
        pairs = [
            {
                "index": index,
                "phase": "warmup" if index < 16 else "measurement",
                "order": ["baseline", "candidate"] if index % 2 == 0 else ["candidate", "baseline"],
                "baseline": self.side(baseline, "a"),
                "candidate": self.side(candidate, "b"),
            }
            for index in range(64)
        ]
        return {"case": self.case, "pairs": pairs}

    def test_policy(self) -> None:
        """Unknown fields, nonfinite values and incoherent budgets cannot acquire default acceptance."""
        self.assertEqual(compare.policy(self.policy), self.policy)
        invalid = [
            ((), "unknown", 1),
            (("sampling",), "measurement_pairs", True),
            (("sampling",), "measurement_pairs", 47),
            (("sampling",), "block_pairs", 3),
            (("sampling",), "bootstrap_resamples", 0),
            (("sampling",), "confidence", 0.90),
            (("regression",), "median_minimum", float("nan")),
            (("regression",), "confidence_lower_minimum", 0),
            (("deployment",), "resource_scope", "approved"),
            (("deployment",), "service_peak_maximum_bytes", True),
        ]
        for path, name, value in invalid:
            document = copy.deepcopy(self.policy)
            target = document
            for key in path:
                target = target[key]
            target[name] = value
            with self.subTest(path=path, name=name), self.assertRaises(ValueError):
                compare.policy(document)
        self.assertEqual(self.policy["deployment"]["resource_scope"], "whole-test-tree-ceilings")
        services = sum(self.policy["deployment"]["services"].values())
        self.assertLess(services * self.policy["deployment"]["service_peak_maximum_bytes"], self.policy["deployment"]["memory_high_bytes"])
        for name, value in (("memory_high_bytes", 3758096385), ("memory_maximum_bytes", 8589934593), ("service_peak_maximum_bytes", 2684354561)):
            document = copy.deepcopy(self.policy)
            document["deployment"][name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                compare.policy(document)

    def test_paired_estimator(self) -> None:
        """Median of matched changes must not be replaced by the ratio of unrelated cohort medians."""
        evidence = self.evidence()
        baseline, candidate = [1000, 100000, 1000000], [2000, 50000, 1000000]
        for index, pair in enumerate(evidence["pairs"][16:]):
            pair["baseline"] = self.side(baseline[index % 3], "a")
            pair["candidate"] = self.side(candidate[index % 3], "b")
        result = compare.evaluate(self.policy, evidence)
        self.assertEqual(result["regression"]["median"], 0)
        self.assertEqual(statistics.median(candidate) / statistics.median(baseline) - 1, -0.5)
        self.assertEqual(result["measurement_pairs"], 48)
        self.assertEqual(result["qualification"], "not-evaluated")
        self.assertEqual(result["resource_scope"], "whole-test-tree-ceilings")

    def test_regression_cutoffs(self) -> None:
        """The inclusive -5% median and -10% confidence limits are independently mandatory."""
        result = compare.evaluate(self.policy, self.evidence(5000, 4750))
        self.assertEqual(result["regression"]["median"], -0.05)
        self.assertEqual(result["regression"]["confidence_interval"], [-0.05, -0.05])
        self.assertTrue(result["regression"]["passed"])
        self.assertFalse(compare.evaluate(self.policy, self.evidence(5000, 4745))["regression"]["passed"])
        evidence = self.evidence()
        for pair in evidence["pairs"][16:40]:
            pair["candidate"] = self.side(4500, "b")
        result = compare.evaluate(self.policy, evidence)
        self.assertEqual(result["regression"]["median"], -0.05)
        self.assertEqual(result["regression"]["confidence_interval"][0], -0.10)
        self.assertTrue(result["regression"]["passed"])
        evidence = self.evidence()
        for pair in evidence["pairs"][16:32]:
            pair["candidate"] = self.side(4000, "b")
        result = compare.evaluate(self.policy, evidence)
        self.assertEqual(result["regression"]["median"], 0)
        self.assertLess(result["regression"]["confidence_interval"][0], -0.10)
        self.assertFalse(result["regression"]["passed"])
        self.assertTrue(result["capacity"]["passed"])

    def test_capacity_and_tails(self) -> None:
        """Absolute throughput and every measured tail stay independent of a favorable ratio or warmup."""
        result = compare.evaluate(self.policy, self.evidence(4499, 4499))
        self.assertTrue(result["regression"]["passed"])
        self.assertFalse(result["capacity"]["passed"])
        evidence = self.evidence(4500, 4500)
        for pair in evidence["pairs"]:
            for metric in pair["candidate"]["metrics"]:
                limit = self.policy["capacity"]["latency_maximum_us"][metric["metric"]]
                metric.update(p95_us=limit["p95_us"], p99_us=limit["p99_us"], p999_us=10000)
        self.assertTrue(compare.evaluate(self.policy, evidence)["capacity"]["passed"])
        evidence["pairs"][0]["candidate"]["metrics"][1]["p99_us"] = 9000
        self.assertTrue(compare.evaluate(self.policy, evidence)["capacity"]["passed"])
        evidence["pairs"][16]["candidate"]["metrics"][1]["p99_us"] = 8000.1
        result = compare.evaluate(self.policy, evidence)
        self.assertFalse(result["capacity"]["passed"])
        self.assertEqual(
            result["capacity"]["latency_excursions"], [{"pair": 16, "metric": "comet.visible", "quantile": "p99_us", "observed_us": 8000.1, "limit_us": 8000}]
        )

    def test_pair_integrity(self) -> None:
        """Missing pairs, changed identities, wrong order and vacuous native counters must fail closed."""
        mutations = [
            lambda rows: rows.pop(),
            lambda rows: rows[16].update(index=15),
            lambda rows: rows[16].update(phase="warmup"),
            lambda rows: rows[16].update(order=["candidate", "baseline"]),
            lambda rows: rows[16]["candidate"].update(artifact_sha256="c" * 64),
            lambda rows: rows[0]["baseline"].update(writes=[15000, 0, 35000]),
            lambda rows: rows[16]["candidate"]["metrics"].pop(),
            lambda rows: rows[16]["candidate"]["metrics"][0].update(count=0),
            lambda rows: rows[16]["candidate"]["metrics"][0].update(p99_us=float("nan")),
        ]
        for index, mutate in enumerate(mutations):
            evidence = self.evidence()
            mutate(evidence["pairs"])
            with self.subTest(mutation=index), self.assertRaises((ValueError, ProbeFailure)):
                compare.evaluate(self.policy, evidence)
        evidence = self.evidence()
        evidence["case"] = {**evidence["case"], "writers": 1}
        with self.assertRaises(ProbeFailure):
            compare.evaluate(self.policy, evidence)

    def test_fixed_interval(self) -> None:
        """Fixed balanced blocks and seed reproduce uncertainty without sampling until favorable."""
        sample = self.policy["sampling"]
        values = [Decimal("-0.1")] * 48
        self.assertEqual(compare.interval(values, sample), (Decimal("-0.1"), Decimal("-0.1")))
        values = [Decimal(index) / 100 for index in range(-24, 24)]
        self.assertEqual(compare.interval(values, sample), compare.interval(values, sample))
        with self.assertRaises(ValueError):
            compare.interval(values[:-1], sample)
        cases = v.decode(v.read(Path(__file__).resolve().parents[1] / "bench/qualification.json"))
        rows = paired.schedule(self.policy, cases)
        self.assertEqual(len(rows), 512)
        self.assertEqual([item["index"] for item in rows], list(range(512)))
        for case in range(4):
            selected = [item for item in rows if item["case"] == case]
            self.assertEqual(sum(item["phase"] == "warmup" for item in selected), 32)
            self.assertEqual(sum(item["phase"] == "measurement" for item in selected), 96)
            for pair in range(64):
                observed = [item["side"] for item in selected if item["pair"] == pair]
                self.assertEqual(observed, ["baseline", "candidate"] if pair % 2 == 0 else ["candidate", "baseline"])
        with self.assertRaises(ValueError):
            paired.schedule(self.policy, cases[:-1])

    def test_control_plane_presence(self) -> None:
        """The approved six-service topology includes Astrolabe in ordinary plaintext and TLS samples."""
        root = Path(__file__).resolve().parents[1]
        (root / "build/tmp").mkdir(parents=True, exist_ok=True)
        for tls in (False, True):
            case = {**self.case, "tls": tls}
            started, closed = [], []

            def launch(arguments: list[str], **options: object) -> SimpleNamespace:
                """Record synthetic service ownership and supply only the fake SDK's valid metric stream."""
                name = Path(options["stdout"].name).stem
                started.append(name)
                if name == "comet":
                    side = self.side(5000, "b")
                    rows = [{"topology": "distributed-writers-v1", "writes": side["writes"]}, *side["metrics"]]
                    options["stdout"].write("\n".join(json.dumps(row) for row in rows))
                    options["stdout"].flush()
                return SimpleNamespace(name=name, pid=10000 + len(started), returncode=0, poll=lambda: 0 if name == "comet" else None)

            def ready(process: SimpleNamespace, log: Path, predicate: Callable[[dict], bool], **_: object) -> dict:
                """Provide declared readiness events without opening real listeners or bypassing ownership cleanup."""
                events = [
                    {"event": "started", "fields": {"admission": "127.0.0.1:1"}},
                    {"event": "clock_status", "fields": {"synchronized": True}},
                    {"msg": "Polaris ready"},
                    {"msg": "Astrolabe management listener ready"},
                    {"event": "comet_listening", "fields": {"endpoint": "127.0.0.1:" + str(process.pid)}},
                    {"event": "business_ready"},
                ]
                return next(event for event in events if predicate(event))

            with tempfile.TemporaryDirectory(prefix="performance-topology-", dir=root / "build/tmp") as temporary:
                output = Path(temporary)
                with (
                    patch.object(measure, "popen", side_effect=launch),
                    patch.object(measure, "wait", side_effect=ready),
                    patch.object(measure, "stop_process", side_effect=lambda process: closed.append(process.name)),
                    patch.object(measure.time, "sleep"),
                    patch.object(measure.os, "sched_getaffinity", return_value=set(range(16)), create=True),
                ):
                    metrics = measure.cluster(output / "binaries", case, output)
                self.assertEqual(len(metrics), 2)
                self.assertEqual(started, ["pulsar", "polaris", "astrolabe", "star-0", "star-1", "star-2", "comet"])
                self.assertEqual(closed, list(reversed(started)))


if __name__ == "__main__":
    unittest.main()
