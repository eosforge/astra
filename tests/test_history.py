"""Exercise historical performance selection against contradictory, incomplete, and incomparable native evidence."""

import copy
from pathlib import Path
import tempfile
import unittest

from bench import history
from bench.run import ProbeFailure
from tools import verify as v


class HistoryTests(unittest.TestCase):
    """Synthetic native artifacts test the parser only; they are never performance or release evidence."""

    def fixture(self, root: Path) -> tuple[Path, Path, Path]:
        """Create two complete paired rounds with a deliberate throughput/latency tradeoff."""
        run = root / "run"
        directory = run / "source/build/results/assurance/matrix/benchmarks"
        stage = run / "source/build/results/assurance/stage-performance"
        stage.mkdir(parents=True)
        directory.mkdir(parents=True)
        sources = {name: "a" * 64 for name in ("bench/run.py", "bench/comet.cpp", "bench/measure.hpp", "bench/delivery.hpp", "bench/qualification.json")}
        self.write(run / "inputs.json", {"head": "1" * 40, "files": sources})
        self.write(
            run / "terminal.json",
            {
                "source_unchanged": True,
                "interrupted": False,
                "remaining_owned": [],
                "errors": [],
                "records": [{"id": "performance", "expected_exit": 0, "actual_exit": 0, "complete": True, "cleanup": True}],
            },
        )
        self.write(
            directory / "identity.json",
            {
                "cpus": 16,
                "affinity": [0, 1],
                "kernel": "fixture",
                "binaries": {name: "b" * 64 for name in ("star", "pulsar", "polaris", "astrolabe", "comet_bench")},
            },
        )
        case = {
            "domain": "catalog",
            "records": 48,
            "bytes": 2048,
            "attr": 256,
            "watchers": 3,
            "writers": 12,
            "seconds": 10,
            "ttl": 180000,
            "rate": 0,
            "stars": 3,
            "tls": False,
            "qualification": True,
        }
        events, results = [], []
        for round_ in range(2):
            sample = directory / f"case-0-round-{round_}"
            sample.mkdir()
            count = 30 * (round_ + 1)
            metrics = [
                {
                    "metric": name,
                    "count": count,
                    "samples": count,
                    "seconds": 10,
                    "operations_per_second": count / 10,
                    "p50_us": 1,
                    "p95_us": 2,
                    "p99_us": 3 + round_,
                    "p999_us": 5,
                }
                for name in ("comet.commit", "comet.visible")
            ]
            log = [{"topology": "distributed-writers-v1", "writes": [count // 3] * 3}, *metrics]
            (sample / "comet.log").write_bytes(b"\n".join(v.encode(item).replace(b"\n", b"") for item in log))
            before = {"time": round_ * 20, "total": 8192, "swap_in": 0, "swap_out": 0}
            after = {**before, "time": before["time"] + 12}
            self.write(sample / "resources.json", [{**before, "time": before["time"] + 1}, {**before, "time": before["time"] + 11}])
            result = {"case": case, "round": round_, "stable_memory": True, "before": before, "after": after, "measurements": metrics}
            results.append(result)
            events.extend([{"case": 0, "round": round_, "parameters": case}, {"completed": 0, "round": round_, "stable_memory": True, "measurements": metrics}])
        self.write(directory / "results.json", results)
        record = {
            "id": "performance",
            "exit_code": 0,
            "complete": True,
            "cleanup": True,
            "termination": "exited",
            "platform": "linux-amd64-cgo",
            "argv": [
                "python3",
                "-B",
                "bench/run.py",
                "--repeat",
                "2",
                "--cases",
                "bench/qualification.json",
                "--output",
                "/frozen/source/build/results/assurance/matrix/benchmarks",
            ],
        }
        for name, data in (("stdout", b"\n".join(v.encode(item).replace(b"\n", b"") for item in events)), ("stderr", b"")):
            path = stage / f"performance.{name}.log"
            path.write_bytes(data)
            record[name] = {"path": path.name, "bytes": len(data), "sha256": v.digest(data)}
        self.write(stage / "record.json", record)
        return run, directory, stage

    @staticmethod
    def write(path: Path, value: object) -> None:
        """Overwrite only the current isolated fixture to construct a specific invalid input."""
        path.write_bytes(v.encode(value))

    def test_peak_preserves_paired_latency(self) -> None:
        """Selecting maximum throughput must retain that round's worse tail, not another round's minimum."""
        with tempfile.TemporaryDirectory() as temporary:
            run, _, _ = self.fixture(Path(temporary))
            evidence = history.campaign(run)
            rows = history.select([evidence])
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["best"]["round"], 1)
            self.assertEqual(rows[0]["best"]["measurements"][0]["p99_us"], 4)
            self.assertEqual(rows[0]["median_operations_per_second"], 4.5)
            self.assertEqual(rows[0]["stable_samples"], 2)
            self.assertEqual(len(evidence["artifacts"]), 11)

    def test_cohorts_and_duplicate_campaign(self) -> None:
        """Different workloads, hosts or measuring code cannot win the same comparison cohort."""
        with tempfile.TemporaryDirectory() as temporary:
            run, _, _ = self.fixture(Path(temporary))
            original = history.campaign(run)
            with self.assertRaises(ValueError):
                history.select([original, original])
            for kind in ("host", "source", "case", "memory"):
                other = copy.deepcopy(original)
                other["artifacts"]["inputs.json"] = "c" * 64
                if kind == "host":
                    other["identity"]["cpus"] = 8
                elif kind == "source":
                    other["sources"]["bench/comet.cpp"] = "d" * 64
                else:
                    for sample in other["accepted"]:
                        if kind == "case":
                            sample["case"]["tls"] = True
                        else:
                            sample["memory_bytes"] = 4096
                self.assertEqual(len(history.select([original, other])), 2)
            other = copy.deepcopy(original)
            other["accepted"] = []
            with self.assertRaises(ValueError):
                history.select([other])

    def test_measurement_implementation_identity(self) -> None:
        """Keep header-only history readable while separating changed measurement bodies and rejecting partial identities."""
        with tempfile.TemporaryDirectory() as temporary:
            run, _, _ = self.fixture(Path(temporary))
            original = history.campaign(run)
            path = run / "inputs.json"
            inputs = history.load(path)
            inputs["files"]["bench/measure.cpp"] = "c" * 64
            self.write(path, inputs)
            with self.assertRaisesRegex(ValueError, "Missing measurement source identity"):
                history.campaign(run)
            inputs["files"]["bench/delivery.cpp"] = "d" * 64
            self.write(path, inputs)
            outlined = history.campaign(run)
            self.assertEqual(len(history.select([original, outlined])), 2)
            inputs["files"]["bench/measure.cpp"] = "e" * 64
            self.write(path, inputs)
            changed = history.campaign(run)
            self.assertEqual(len(history.select([outlined, changed])), 2)

    def test_resource_instability(self) -> None:
        """A transient memory change and paging cannot be hidden by equal final capacity or a true flag."""
        values = [{"time": i, "total": 8, "swap_in": 0, "swap_out": 0} for i in range(3)]
        self.assertTrue(history.stable(values))
        changed = copy.deepcopy(values)
        changed[1]["total"] = 9
        self.assertFalse(history.stable(changed))
        changed = copy.deepcopy(values)
        changed[-1]["swap_in"] = 1
        self.assertFalse(history.stable(changed))
        for key in ("time", "swap_in", "swap_out"):
            changed = copy.deepcopy(values)
            changed[1][key] = 5
            with self.assertRaises(ValueError):
                history.stable(changed)
        with self.assertRaises(ValueError):
            history.stable([])

    def test_native_integrity(self) -> None:
        """Reject log replacement, aggregate edits, missing rounds, idle peers and false stability flags."""
        for change in ("stdout", "summary", "missing", "topology", "resources", "flag"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                run, directory, stage = self.fixture(Path(temporary))
                if change == "stdout":
                    (stage / "performance.stdout.log").write_bytes(b"{}")
                elif change in ("summary", "missing", "flag"):
                    path = directory / "results.json"
                    values = history.load(path)
                    if change == "missing":
                        values.pop()
                    elif change == "flag":
                        values[0]["stable_memory"] = False
                    else:
                        values[0]["measurements"][0]["operations_per_second"] = 100
                    self.write(path, values)
                elif change == "topology":
                    path = directory / "case-0-round-0/comet.log"
                    lines = path.read_bytes().splitlines()
                    topology = v.decode(lines[0])
                    self.assertEqual(topology["writes"], [10, 10, 10])
                    topology["writes"] = [30, 0, 0]
                    lines[0] = v.encode(topology).replace(b"\n", b"")
                    path.write_bytes(b"\n".join(lines))
                else:
                    path = directory / "case-0-round-0/resources.json"
                    values = history.load(path)
                    values[0]["total"] += 1
                    self.write(path, values)
                with self.assertRaises((ValueError, v.Invalid, ProbeFailure)):
                    history.campaign(run)

    def test_command_and_terminal(self) -> None:
        """Clean summary text cannot override failure, cancellation, source drift, or an escaping output path."""
        for target, field, value in (
            ("record", "exit_code", 1),
            ("record", "cleanup", False),
            ("record", "complete", False),
            ("terminal", "interrupted", True),
            ("terminal", "source_unchanged", False),
            ("terminal", "remaining_owned", [12]),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                run, _, stage = self.fixture(Path(temporary))
                path = stage / "record.json" if target == "record" else run / "terminal.json"
                data = history.load(path)
                data[field] = value
                self.write(path, data)
                with self.assertRaises(ValueError):
                    history.campaign(run)
        with tempfile.TemporaryDirectory() as temporary:
            run, _, stage = self.fixture(Path(temporary))
            path = stage / "record.json"
            data = history.load(path)
            data["argv"][-1] = "/frozen/source/../../escape"
            self.write(path, data)
            with self.assertRaises(ValueError):
                history.campaign(run)


if __name__ == "__main__":
    unittest.main()
