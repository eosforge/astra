"""Defend SQL fault-cycle identities, native attribution and the mandatory supplemental check."""

import copy
from pathlib import Path
import unittest

from tools import mutate, recovery, verify as v


class RecoveryTests(unittest.TestCase):
    """Keep synthetic parser controls separate from real fault-injection evidence."""

    def test_matrix(self) -> None:
        """Challenge missing failures, false recovery, leaked resources and unchanged post-recovery state."""
        rows = []
        for site in recovery.SITES:
            for cycle in range(2):
                common = {"site": site, "cycle": cycle, "events": 0, "writer": 0, "readers": 0, "writers": 0, "version": 0}
                for attempt in range(2):
                    outcome = "version" if site == "scope-update" else "corrupt" if site == "meta-update" else "unavailable"
                    rows.append(
                        {
                            **common,
                            "phase": "failure",
                            "outcome": outcome,
                            "attempt": attempt,
                            "reached": 1,
                            "before": str(cycle) * 64,
                            "after": str(cycle) * 64,
                        }
                    )
                rows.append(
                    {**common, "phase": "recovery", "outcome": "nil", "version": 1 if site == "scope-insert" else cycle * 2 + 2, "events": 1, "records": 2}
                )
        self.assertEqual(recovery.frames(rows), {"sites": 8, "failures": 32, "recoveries": 16, "observations": 48})
        for index, field, value in [
            (0, "reached", 0),
            (0, "writer", 1),
            (0, "before", "x" * 64),
            (1, "after", "f" * 64),
            (2, "events", 0),
            (2, "records", 1),
            (2, "version", 2),
            (3, "cycle", 0),
            (0, "version", False),
        ]:
            changed = copy.deepcopy(rows)
            changed[index][field] = value
            with self.subTest(index=index, field=field), self.assertRaises(v.Invalid):
                recovery.frames(changed)
        for index, outcome in ((0, "nil"), (36, "unavailable"), (42, "version")):
            changed = copy.deepcopy(rows)
            changed[index]["outcome"] = outcome
            with self.subTest(index=index, outcome=outcome), self.assertRaisesRegex(v.Invalid, "recovery-error-class"):
                recovery.frames(changed)
        for changed in (rows[:-1], rows + rows[:1], rows[:1] + rows[:1] + rows[2:]):
            with self.assertRaises(v.Invalid):
                recovery.frames(changed)

    def test_policy(self) -> None:
        """Require the unchanged damage operator and a distinct complete matrix that depends on SQL recovery."""
        root = Path(__file__).resolve().parents[1]
        config, _, _ = v.configuration(root / "development.json", root)
        check = next(item for item in config["checks"] if item["id"] == "storage-sql-recovery")
        manifest = v.decode(v.read(root / check["manifest"]))
        core = v.decode(v.read(root / "polaris/internal/storage/core-mutations.json"))
        original = next(item for item in core["mutations"] if item["id"] == "ignore-write-error")
        self.assertEqual(manifest["mutations"], [{**original, "test": recovery.TEST}])
        self.assertEqual(len(mutate.plan(manifest, root)), 1)
        self.assertEqual(manifest["fixtures"], [{"source": "tests/fixtures/failures.go.in", "target": "polaris/internal/storage/failures_test.go"}])
        obligations = v.expand(config)
        target = "polaris-storage/DEV-FAULT/STORAGE-SQL-FAULT/linux-amd64-cgo/sql-recovery"
        self.assertEqual(obligations[target]["checks"], [check["id"]])
        full = obligations["polaris-storage/DEV-FAULT/STORAGE-ASSURANCE/linux-amd64-cgo/fault-matrix"]
        self.assertEqual(full["checks"], ["gap-fault-matrix"])
        self.assertEqual(next(item for item in config["checks"] if item["id"] == "gap-fault-matrix")["adapter"], "observed-cases")
        self.assertEqual(full["requires"], [{"rule": "DEV-FAULT", "contract": "STORAGE-SQL-FAULT", "scenario": "sql-recovery"}])
