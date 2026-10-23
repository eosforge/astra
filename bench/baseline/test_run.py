"""Check baseline-runner failure cleanup without starting real services."""

import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location("baseline", Path(__file__).with_name("run.py"))
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)
report_spec = importlib.util.spec_from_file_location("report", Path(__file__).with_name("report.py"))
report = importlib.util.module_from_spec(report_spec)
report_spec.loader.exec_module(report)


class RunnerTest(unittest.TestCase):
    """Check shared workload arguments, topology selection, and exact container ownership on failure."""

    def test_arguments(self) -> None:
        """Keep argument counts and version contracts identical between adapters, differing only in programs and endpoints."""
        case = json.loads(Path(__file__).with_name("cases.json").read_text())[0]
        first = baseline.command("comet", "127.0.0.1:1", case)
        second = baseline.command("redis", "127.0.0.1:2", case)
        self.assertEqual(len(first), 16)
        self.assertEqual(first[2:], second[2:])
        self.assertEqual(first[-1], "v1")
        self.assertEqual(baseline.command("redis", "127.0.0.1:2", dict(case, legacy_view_ms=10))[-2:], ["v1", "10"])

    def test_external_requires_owner(self) -> None:
        """Reject an external endpoint without its owner's PID before touching a database."""
        arguments = SimpleNamespace(redis="127.0.0.1:1", redis_pid=None)
        with self.assertRaises(ValueError), baseline.server(arguments):
            self.fail("Missing owner accepted")

    def test_standard_topology(self) -> None:
        """Default to three nodes; smaller diagnostic topologies require explicit selection without silent workload changes."""
        case = dict(clients=6, writers=6, records=96, fanout=3)
        self.assertEqual(baseline.topology(case)["stars"], 3)
        for count in (1, 2):
            with self.subTest(stars=count), self.assertRaises(ValueError):
                baseline.topology(dict(case, stars=count))
            self.assertEqual(baseline.topology(dict(case, stars=count, diagnostic=True))["stars"], count)
        for changes in (dict(clients=1), dict(clients=4), dict(writers=2), dict(writers=4), dict(fanout=2), dict(records=95), dict(stars=0), dict(stars=True)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                baseline.topology(dict(case, **changes))

    def test_comet_routes_every_endpoint(self) -> None:
        """Require three fixture Stars and pass every address to the probe without actually starting services."""
        case = baseline.topology(json.loads(Path(__file__).with_name("cases.json").read_text())[0])
        arguments = SimpleNamespace(binaries=Path("binaries"))
        with patch.object(baseline.measure, "cluster", return_value=[]) as cluster:
            self.assertEqual(baseline.comet(arguments, case, Path("output")), [])
        self.assertEqual(cluster.call_args.args[1]["stars"], 3)
        command = cluster.call_args.args[3](["127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3"])
        self.assertEqual(command[1], "127.0.0.1:1,127.0.0.1:2,127.0.0.1:3")

    def test_standard_matrix(self) -> None:
        """Cover three nodes throughout the standard matrix, including merged single-Scope and parallel multi-Scope workloads."""
        cases = [baseline.topology(case) for case in json.loads(Path(__file__).with_name("cases.json").read_text())]
        self.assertTrue(all(case["stars"] >= 3 and not case.get("diagnostic", False) for case in cases))
        for domain in ("catalog", "ephemeris"):
            self.assertTrue(any(case["domain"] == domain and case["groups"] == 1 for case in cases))
            self.assertTrue(any(case["domain"] == domain and case["groups"] >= 3 for case in cases))
            for clients in (3, 6):
                self.assertTrue(
                    any(case["domain"] == domain and case["writers"] == 24 and case["clients"] == clients and case["mode"] == "receipt" for case in cases)
                )

    def test_external_lifecycle(self) -> None:
        """Leave Docker and cleanup to the caller in externally owned mode."""
        arguments = SimpleNamespace(redis="127.0.0.1:1", redis_pid=100)
        with patch.object(baseline.subprocess, "run") as execute:
            with baseline.server(arguments):
                pass
            execute.assert_not_called()

    def exercise(self, timeout: bool) -> None:
        """Reclaim the exact container after workload failure or an ambiguous run timeout that still created it."""
        arguments = SimpleNamespace(redis=None, redis_pid=None, sudo=False)
        name = "astra-baseline-aaaaaaaaaaaa"
        identity = "owned-container-id"
        calls = []

        def execute(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            """Emulate Docker startup and inspection, including timeout after a container was created."""
            calls.append(command)
            if command[1] == "run" and timeout:
                raise subprocess.TimeoutExpired(command, 30)
            if command[1] == "inspect":
                state = [dict(Id=identity, Config=dict(Labels={"astra.baseline": name}))]
                return subprocess.CompletedProcess(command, 0, json.dumps(state), "")
            return subprocess.CompletedProcess(command, 0, "", "")

        connection = MagicMock()
        connection.__enter__.return_value.recv.return_value = b"+PONG\r\n"
        with (
            patch.object(baseline.uuid, "uuid4", return_value=SimpleNamespace(hex="a" * 32)),
            patch.object(baseline.measure, "port", return_value=12345),
            patch.object(baseline.socket, "create_connection", return_value=connection),
            patch.object(baseline.subprocess, "run", side_effect=execute),
            patch.object(baseline.subprocess, "check_output", return_value="100"),
        ):
            expected = subprocess.TimeoutExpired if timeout else RuntimeError
            with self.assertRaises(expected), baseline.server(arguments):
                raise RuntimeError("Injected workload failure")
        self.assertIn("--pull=never", calls[0])
        self.assertEqual(calls[-1], ["docker", "rm", "--force", identity])

    def test_failure_cleanup(self) -> None:
        """Reclaim the owned container when a workload fails after successful startup."""
        self.exercise(False)

    def test_ambiguous_start_cleanup(self) -> None:
        """Resolve and reclaim a container even when its startup command timed out."""
        self.exercise(True)

    def test_paired_statistics(self) -> None:
        """Exclude the entire pair when either side pages; the stable half cannot support a valid comparison."""
        rows = []
        for repeat in range(2):
            for implementation in ("redis", "comet"):
                metric = dict(metric="commit", operations_per_second=100, p50_us=1, p95_us=2, p99_us=3, p999_us=4)
                rows.append(
                    dict(
                        case=dict(mode="receipt"),
                        round=repeat,
                        implementation=implementation,
                        passed=True,
                        stable_memory=not (repeat == 1 and implementation == "redis"),
                        measurements=[metric],
                    )
                )
        result = report.summarize(rows)
        self.assertEqual(result[0]["paired_rounds"], 1)
        self.assertEqual(result[0]["comet_redis_throughput_ratio"], 1)
        with self.assertRaises(ValueError):
            report.summarize(rows + rows[:1])


if __name__ == "__main__":
    unittest.main()
