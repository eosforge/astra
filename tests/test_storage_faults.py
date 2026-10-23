"""Validate the complete finite Storage fault inventory against retained native facts and adversarial streams."""

import copy
import json
from pathlib import Path
import unittest

from tools import idle, storage, storage_faults as faults, verify as v


class StorageFaultTests(unittest.TestCase):
    """Native failures and source changes block qualification; edited streams remain negative controls only."""

    @classmethod
    def setUpClass(cls) -> None:
        """Authenticate the immutable native corpus once for this bounded reader invocation."""
        cls.root = Path(__file__).resolve().parents[1]
        cls.plan = faults.inventory(v.read(cls.root / faults.MANIFEST))
        cls.receipt = faults.reconcile(cls.root)

    def test_current(self) -> None:
        """One effective assertion per declared, actually completed native coordinate."""
        expected = [(case, group["contract"], "passed") for group in self.plan["groups"] for case in group["cases"]]
        self.assertEqual(len(self.receipt["cells"]), len(expected))
        for actual, wanted in zip(self.receipt["cells"], expected, strict=True):
            self.assertEqual((actual["test"], actual["contract"], actual["status"]), wanted)
        if idle.current(self.root):
            original, supplement = self.receipt["native_archives"].values()
            self.assertEqual((original["cases"], supplement["cases"]), (188, 2))
            self.assertEqual((original["program_exit_code"], original["controller_exit_code"]), (0, 1))
            self.assertEqual((supplement["program_exit_code"], supplement["controller_exit_code"]), (0, 0))
            self.assertEqual(original["original_failures"], ["go-required-test:TestNativeIO/write", "go-required-test:TestNativeIO/sync", "undeclared-probe"])

    def test_controls(self) -> None:
        """Reject missing/duplicate/foreign cases, skips, vacuous markers and invalid native lifetimes."""
        original = [v.decode(line) for line in self.receipt["raw"].splitlines()]
        case = "TestReadFault/list"
        terminal = next(index for index, item in enumerate(original) if item.get("Test") == case and item.get("Action") == "pass")
        begin = next(index for index, item in enumerate(original) if item.get("Test") == case and item.get("Action") == "run")
        marker = next(index for index, item in enumerate(original) if item.get("Test") == "TestReadFault" and "ASTRA-CONTRACT " in item.get("Output", ""))
        for attack in (
            "missing",
            "duplicate",
            "failed",
            "skipped",
            "foreign-package",
            "foreign-owner",
            "missing-marker",
            "zero-hits",
            "boolean-hits",
            "wrong-contract",
            "duplicate-marker",
            "missing-begin",
            "reversed-lifetime",
            "unknown-case",
            "truncated-output",
        ):
            changed = copy.deepcopy(original)
            if attack == "missing":
                changed.pop(terminal)
            elif attack == "duplicate":
                changed.insert(terminal, copy.deepcopy(changed[terminal]))
            elif attack in {"failed", "skipped"}:
                changed[terminal]["Action"] = "fail" if attack == "failed" else "skip"
            elif attack == "foreign-package":
                changed[terminal]["Package"] = "foreign"
            elif attack == "foreign-owner":
                changed[marker]["Test"] = "TestReadFault/list"
            elif attack == "missing-marker":
                changed.pop(marker)
            elif attack in {"zero-hits", "boolean-hits", "wrong-contract"}:
                prefix = changed[marker]["Output"].split("ASTRA-CONTRACT ", 1)[0]
                contract = "foreign" if attack == "wrong-contract" else "STORAGE-READ-FAULT"
                hits = True if attack == "boolean-hits" else 0 if attack == "zero-hits" else 9
                changed[marker]["Output"] = prefix + "ASTRA-CONTRACT " + json.dumps({"contract": contract, "hits": hits}) + "\n"
            elif attack == "duplicate-marker":
                changed.insert(marker, copy.deepcopy(changed[marker]))
            elif attack == "missing-begin":
                changed.pop(begin)
            elif attack == "reversed-lifetime":
                changed[begin], changed[terminal] = changed[terminal], changed[begin]
            elif attack == "unknown-case":
                changed[terminal]["Test"] = "TestReadFault/undeclared"
            else:
                changed[marker]["Output"] = changed[marker]["Output"].rstrip("\n")
            with self.subTest(attack=attack), self.assertRaises(v.Invalid):
                faults.observations(b"\n".join(json.dumps(item).encode() for item in changed), self.plan)
        if idle.current(self.root):
            changed = [item for item in original if not item.get("Test", "").startswith("TestNativeIO")]
            with self.assertRaises(v.Invalid):
                faults.observations(b"\n".join(json.dumps(item).encode() for item in changed), self.plan)

    def test_inputs(self) -> None:
        """Reject changed expectation bytes, corrupt native archives and elevated trust labels."""
        data = v.read(self.root / faults.MANIFEST)
        for changed in (
            data + b" ",
            data.replace(b'"version": 2', b'"version": 3') if self.plan["version"] == 2 else data.replace(b'"version": 1', b'"version": 2'),
            b"{}",
        ):
            with self.assertRaises(v.Invalid):
                faults.inventory(changed)
        directory = self.root / "build/results/assurance" / storage.BASE
        raw = v.read(directory / "evidence.tar.gz", 64 * 1024**2)
        seal = v.decode(v.read(directory / "sealed.native.json"))
        with self.assertRaises(v.Invalid):
            storage.retained(raw[:-1] + bytes([raw[-1] ^ 1]), seal, storage.ARCHIVE)
        with self.assertRaises(v.Invalid):
            storage.retained(raw, {**seal, "trust": "ci"}, storage.ARCHIVE)
        self.assertIn("polaris/internal/storage/store.go", self.receipt["sources"])
        self.assertIn("polaris/internal/storage/opening_test.go", self.receipt["sources"])
        self.assertEqual(self.receipt["original_entry"]["exit_code"], 0 if idle.current(self.root) else 1)
        if idle.current(self.root):
            for name in faults.ARCHIVES:
                directory = self.root / "build/results/assurance/reuse-plan" / name / "native"
                raw = v.read(directory / "evidence.tar.gz", 64 * 1024**2)
                seal = v.decode(v.read(directory / "sealed.native.json"))
                with self.subTest(archive=name), self.assertRaises(v.Invalid):
                    faults.acquired(self.root, name, archive=raw + b"corrupt")
                for field, value in (("trust", "ci"), ("files", 0), ("cleanup", {}), ("terminal", {})):
                    with self.subTest(archive=name, field=field), self.assertRaises(v.Invalid):
                        faults.acquired(self.root, name, seal={**seal, field: value})

    def test_policy(self) -> None:
        """The original unavailable policy and any omitted recovery/reader check must fail closed."""
        config, _, _ = v.configuration(self.root / "development.json", self.root)
        self.assertIsNone(faults.policy(config, self.plan))
        for attack in ("unavailable", "controls", "probe", "recovery"):
            changed = copy.deepcopy(config)
            check = next(item for item in changed["checks"] if item["id"] == "gap-fault-matrix")
            if attack == "unavailable":
                check["adapter"] = "unavailable"
            elif attack == "controls":
                check["expected_tests"] = check["expected_tests"][:1]
            elif attack == "probe":
                check["probes"][0]["minimum_hits"] = 1
            else:
                component = next(item for item in changed["components"] if item["id"] == "polaris-storage")
                requirement = next(item for item in component["requirements"] if item["rule"] == "DEV-FAULT" and item["scenario"] == "fault-matrix")
                requirement.pop("requires")
            with self.subTest(attack=attack), self.assertRaises(v.Invalid):
                faults.policy(changed, self.plan)
