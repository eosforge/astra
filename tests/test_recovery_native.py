"""Attack the independent SQL recovery reader using authenticated native observations."""

import base64
import copy
import json
from pathlib import Path
import unittest

from tools import recovery, storage, verify as v


class NativeRecoveryTests(unittest.TestCase):
    """Edited native-shaped streams are negative controls and never receive product credit."""

    def test_attribution(self) -> None:
        """Reject foreign package/site ownership, missing terminals, skips and a vacuous assertion count."""
        root = Path(__file__).resolve().parents[1]
        directory = root / "build/results/assurance/reuse-plan/storage-fault-cycles-current-3/native"
        seal = v.decode(v.read(directory / "sealed.native.json"))
        files = storage.retained(v.read(directory / "evidence.tar.gz", 64 * 1024**2), seal, "c794b5523fcc1e691bbff62b57139b67eac976cd5a2c5996f3d635d1b83446ba")
        prefix = "source/build/commands/storage-sql-recovery/"
        record = v.decode(files[prefix + "record.json"])
        stream = files[prefix + record["stdout"]["path"]]
        baseline = next(
            v.decode(line.removeprefix(b"ASTRA-MUTATION "), maximum=32 * 1024**2) for line in stream.splitlines() if b'"baseline-TestFaultCycles"' in line
        )
        data = base64.b64decode(baseline["stdout"], validate=True)
        self.assertEqual(recovery.observations(data), {"sites": 8, "failures": 32, "recoveries": 16, "observations": 48, "parent_assertions": 9})
        entries = [v.decode(line) for line in data.splitlines()]
        first = next(index for index, entry in enumerate(entries) if "STORAGE-SQL-FAULT " in entry.get("Output", ""))
        count = next(index for index, entry in enumerate(entries) if entry.get("Test") == recovery.TEST and "ASTRA-CONTRACT " in entry.get("Output", ""))
        passed = next(index for index, entry in enumerate(entries) if entry.get("Action") == "pass" and entry.get("Test", "").startswith(recovery.TEST + "/"))
        terminal = next(index for index, entry in enumerate(entries) if entry.get("Action") == "pass" and entry.get("Test") == recovery.TEST)
        for attack in ("package", "owner", "site", "counter", "skip", "terminal"):
            changed = copy.deepcopy(entries)
            if attack == "package":
                changed[first]["Package"] = "foreign"
            elif attack == "owner":
                changed[first]["Test"] = recovery.TEST + "/foreign"
            elif attack == "site":
                before, encoded = changed[first]["Output"].split("STORAGE-SQL-FAULT ", 1)
                frame = v.decode(encoded.strip())
                frame["site"] = "foreign"
                changed[first]["Output"] = before + "STORAGE-SQL-FAULT " + json.dumps(frame) + "\n"
            elif attack == "counter":
                before = changed[count]["Output"].split("ASTRA-CONTRACT ", 1)[0]
                changed[count]["Output"] = before + 'ASTRA-CONTRACT {"contract":"STORAGE-SQL-FAULT","hits":0}\n'
            elif attack == "skip":
                changed[passed]["Action"] = "skip"
            else:
                changed.pop(terminal)
            with self.subTest(attack=attack), self.assertRaises(v.Invalid):
                recovery.observations(b"\n".join(json.dumps(entry).encode() for entry in changed))

    def test_policy(self) -> None:
        """Make native-reader negative controls a prerequisite rather than an optional local check."""
        root = Path(__file__).resolve().parents[1]
        config, _, _ = v.configuration(root / "development.json", root)
        obligations = v.expand(config)
        prefix = "polaris-storage/"
        fault = obligations[prefix + "DEV-FAULT/STORAGE-SQL-FAULT/linux-amd64-cgo/sql-recovery"]
        self.assertEqual(fault["requires"], [{"rule": "DEV-ORACLE", "contract": "STORAGE-SQL-FAULT", "scenario": "sql-recovery-inputs"}])
        oracle = obligations[prefix + "DEV-ORACLE/STORAGE-SQL-FAULT/linux-amd64-cgo/sql-recovery-inputs"]
        self.assertEqual(oracle["checks"], ["storage-sql-inputs-python"])
        check = next(item for item in config["checks"] if item["id"] == "storage-sql-inputs-python")
        self.assertEqual(
            check["expected_tests"],
            [
                "tests.test_recovery.RecoveryTests.test_matrix",
                "tests.test_recovery.RecoveryTests.test_policy",
                "tests.test_recovery_native.NativeRecoveryTests.test_attribution",
                "tests.test_recovery_native.NativeRecoveryTests.test_policy",
            ],
        )
