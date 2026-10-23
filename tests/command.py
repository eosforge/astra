"""Explicitly consume the command wrapper through shipping Go entries without starting a service."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from tests.support import popen, temporary_directory
from tools import verify as v

# Match the ordinary build's actual noninstrumented Go executable destinations.
ROOT = Path(__file__).resolve().parents[1]
CONSUMERS = ("polaris", "astrolabe")


class CommandTests(unittest.TestCase):
    """Check native entry receipts and reject an incomplete shipping-consumer inventory."""

    def setUp(self) -> None:
        """Require existing Linux artifacts and isolate every relative deployment path."""
        self.assertEqual(sys.platform, "linux", "Command delivery currently supports Linux")
        self.temporary = temporary_directory("command-consumers-")
        owned = Path(self.temporary.__enter__())
        self.addCleanup(self.temporary.__exit__, None, None, None)
        # Keep the fixture's ownership marker outside the application's initially empty cwd.
        self.directory = owned / "consumer"
        self.directory.mkdir()
        self.logs = Path(os.environ.get("ASTRA_TEST_LOG_DIR", ROOT / "build/results/logs")) / self._testMethodName
        self.logs.mkdir(parents=True, exist_ok=False)
        self.sequence = 0

    def execute(self, arguments: list[str | Path], *, directory: Path) -> tuple[int, dict[str, bytes]]:
        """Retain native output/exit facts, then drain each owned child before checking its result."""
        number = self.sequence
        self.sequence += 1
        streams = {name: self.logs / f"{number}.{name}.log" for name in ("stdout", "stderr")}
        with streams["stdout"].open("xb") as output, streams["stderr"].open("xb") as errors:
            process = popen(arguments, directory, stdout=output, stderr=errors, stdin=subprocess.DEVNULL)
            identity = v.proc_identity(process.pid)
            v.write_new(
                self.logs / f"{number}.process.json",
                {
                    "identity": identity,
                    "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                    "argv": list(map(str, arguments)),
                    "cwd": str(directory),
                },
            )
            try:
                code = process.wait(timeout=30)
            finally:
                cleanup = v.drain(process)
            self.assertTrue(cleanup, "The consumer's owned process tree did not drain")
        record = {"argv": list(map(str, arguments)), "cwd": str(directory), "pid": process.pid, "exit_code": code}
        values = {}
        for name, path in streams.items():
            raw = path.read_bytes()
            self.assertLessEqual(len(raw), 8 * 1024**2, "Native consumer output exceeded the declared per-stream budget")
            record[name] = {"path": path.name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            values[name] = raw
        with (self.logs / f"{number}.json").open("x", encoding="utf-8", newline="\n") as target:
            json.dump(record, target, indent=2)
            target.write("\n")
        return code, values

    def test_inventory(self) -> None:
        """The native Go build graph names exactly the two shipping direct command consumers."""
        code, streams = self.execute(["go", "list", "-mod=readonly", "-json", "./..."], directory=ROOT)
        self.assertEqual(code, 0, streams["stderr"].decode("utf-8", errors="replace"))
        decoder = json.JSONDecoder()
        remaining = streams["stdout"].decode("utf-8")
        packages = []
        while remaining.strip():
            package, end = decoder.raw_decode(remaining.lstrip())
            packages.append(package)
            remaining = remaining.lstrip()[end:]
        self.assertGreater(len(packages), 0, "Empty native package discovery")
        consumers = [package for package in packages if "github.com/eosforge/astra/internal/command" in package.get("Imports", [])]
        self.assertEqual({package["ImportPath"] for package in consumers}, {f"github.com/eosforge/astra/{name}" for name in CONSUMERS})
        for package in consumers:
            self.assertEqual(package["Name"], "main")
            self.assertNotIn("Error", package)
            self.assertNotIn("DepsErrors", package)

    def consume(self, service: str, boolean: str) -> None:
        """Independently specify standard help, boolean, duplicate and invalid-input receipts."""
        binary = ROOT / "build/cmake/release" / service
        self.assertTrue(binary.is_file(), "A missing release artifact is not a skipped consumer")
        # Valid numeric inputs avoid hiding a broken duplicate guard behind endpoint validation.
        rows = [
            (["-h"], 0, f"Usage of {service}:"),
            (["--help"], 0, f"Usage of {service}:"),
            ([f"--{boolean}", "--help"], 0, f"Usage of {service}:"),
            ([f"--{boolean}=false", "--help"], 0, f"Usage of {service}:"),
            (["--listen=127.0.0.1:19001", "--help"], 0, f"Usage of {service}:"),
            (["--listen=127.0.0.1:19001", "--listen=127.0.0.1:19002"], 2, "duplicate option"),
            ([f"--{boolean}", f"--{boolean}=false"], 2, "duplicate option"),
            ([f"--{boolean}=false", f"--{boolean}=true"], 2, "duplicate option"),
            ([f"--{boolean}=invalid"], 2, "invalid boolean value"),
            (["--listen"], 2, "flag needs an argument"),
            (["--unknown-command-option=1"], 2, "flag provided but not defined"),
        ]
        self.assertEqual(len(rows), 11, "The fixed native CLI scenario matrix must not become empty or shrink silently")
        for arguments, expected, marker in rows:
            with self.subTest(service=service, arguments=arguments):
                code, streams = self.execute([binary, *arguments], directory=self.directory)
                self.assertEqual(code, expected)
                self.assertEqual(streams["stdout"], b"", "CLI parsing must not enter the service lifecycle or emit a startup log")
                self.assertIn(marker.encode(), streams["stderr"])
                self.assertFalse(any(self.directory.iterdir()), "Parsing must not create credentials, authority data or other deployment state")

    def test_polaris(self) -> None:
        """Consume the actual authority executable, including native --init boolean behavior."""
        self.consume("polaris", "init")

    def test_astrolabe(self) -> None:
        """Consume the actual management executable, including native --http boolean behavior."""
        self.consume("astrolabe", "http")
