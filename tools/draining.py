"""Verify exact native cancellation-finalization ownership histories, including original attribution and complete production binding."""

from pathlib import Path
import re

from tools import lifecycle, storage_numeric, verify as v

HITS = 2
CASES = ("write", "read")
BORROWS = tuple((owner, fault) for owner in ("write", "read", "validation") for fault in ("closed", "cancelled", "expired"))


def configuration(check: dict) -> None:
    """Require both public-operation histories and their actual child-success counter."""
    if (
        check.get("model") != "storage-draining-v1"
        or check["component"] != "polaris-storage"
        or check["package"] != storage_numeric.PACKAGE
        or check["argv"]
        != ["go", "test", "-json", "-race", "-count=1", "-parallel=1", "-p=2", "-timeout=60s", "-run=^TestDraining$", "./polaris/internal/storage"]
        or check["expected_tests"] != ["TestDraining", *("TestDraining/" + mode for mode in CASES)]
        or v.encode(check["probes"]) != v.encode([{"contract": "STORAGE-DRAINING", "test": "TestDraining", "minimum_hits": HITS}])
    ):
        v.reject("draining-configuration")


def observations(data: bytes, check: dict, root: Path) -> dict[str, int]:
    """Reject partial, duplicated, wrongly attributed or undrained native resource observations."""
    configuration(check)
    lifecycle.proof(root)
    expected = {"TestDraining/" + mode: mode for mode in CASES}
    rows = {name: [] for name in expected}
    pattern = re.compile(r"\s*(?:[^\n]+\.go:\d+: )?STORAGE-DRAINED mode=(write|read) rollback=1 in_use=0 writer=0 opened=1 closed=1\n")
    for line in data.splitlines():
        event = v.decode(line)
        if not isinstance(event, dict):
            v.reject("draining-event")
        text = event.get("Output", "")
        if not isinstance(text, str):
            v.reject("draining-output")
        if "STORAGE-DRAINED " not in text:
            continue
        name = event.get("Test")
        match = pattern.fullmatch(text)
        if event.get("Action") != "output" or event.get("Package") != check["package"] or name not in expected or not match:
            v.reject("draining-attribution-or-resources")
        rows[name].append(match.group(1))
    if rows != {name: [mode] for name, mode in expected.items()}:
        v.reject("draining-native-history")
    return {"STORAGE-DRAINING": HITS}


def borrowing(check: dict) -> None:
    """Require all native pre-SQL refusal boundaries without changing cancellation or durable-state semantics."""
    if (
        check.get("model") != "storage-borrowing-v1"
        or check["component"] != "polaris-storage"
        or check["package"] != storage_numeric.PACKAGE
        or check["argv"] != ["go", "test", "-json", "-count=1", "-parallel=1", "-p=2", "-timeout=60s", "-run=^TestBorrowing$", "./polaris/internal/storage"]
        or check["expected_tests"] != ["TestBorrowing", *("TestBorrowing/" + owner + "/" + fault for owner, fault in BORROWS)]
        or v.encode(check["probes"]) != v.encode([{"contract": "STORAGE-BORROWING", "test": "TestBorrowing", "minimum_hits": len(BORROWS)}])
    ):
        v.reject("borrowing-configuration")


def borrowed(data: bytes, check: dict, root: Path) -> dict[str, int]:
    """Reject a missing owner/fault pair, partial recovery or resources retained after refused acquisition."""
    borrowing(check)
    lifecycle.proof(root)
    expected = {"TestBorrowing/" + owner + "/" + fault: (owner, fault) for owner, fault in BORROWS}
    rows = {name: [] for name in expected}
    pattern = re.compile(
        r"\s*(?:[^\n]+\.go:\d+: )?STORAGE-BORROWING owner=(write|read|validation) fault=(closed|cancelled|expired) entered=0 in_use=0 published=0 version=1 records=1\n"
    )
    for line in data.splitlines():
        event = v.decode(line)
        if not isinstance(event, dict):
            v.reject("borrowing-event")
        text = event.get("Output", "")
        if not isinstance(text, str):
            v.reject("borrowing-output")
        if "STORAGE-BORROWING owner=" not in text:
            continue
        name = event.get("Test")
        match = pattern.fullmatch(text)
        if event.get("Action") != "output" or event.get("Package") != check["package"] or name not in expected or not match:
            v.reject("borrowing-attribution-or-resources")
        rows[name].append(match.groups())
    if rows != {name: [pair] for name, pair in expected.items()}:
        v.reject("borrowing-native-history")
    return {"STORAGE-BORROWING": len(BORROWS)}
