"""Verify complete native Storage close-error combinations without claiming arbitrary failed I/O releases its handle."""

from pathlib import Path

from tools import equality, lifecycle, storage_numeric, verify as v

HITS = 132
CASES = tuple("TestTermination/" + str(mask) for mask in range(8))


def configuration(check: dict) -> None:
    """Freeze all eight native error combinations and the healthy control in one Race command."""
    if (
        check.get("model") != "storage-termination-v1"
        or check["component"] != "polaris-storage"
        or check["package"] != storage_numeric.PACKAGE
        or check["argv"]
        != ["go", "test", "-json", "-race", "-count=1", "-parallel=1", "-p=2", "-timeout=60s", "-run=^TestTermination$", "./polaris/internal/storage"]
        or check["expected_tests"] != ["TestTermination", *CASES]
        or v.encode(check["probes"]) != v.encode([{"contract": "STORAGE-TERMINATION", "test": "TestTermination", "minimum_hits": HITS}])
    ):
        v.reject("termination-configuration")


def expected(mask: int) -> dict:
    """Every combination must retain one complete durable record and release both owned connections."""
    if type(mask) is not int or not 0 <= mask < 8:
        v.reject("termination-case")
    return {"mask": mask, "opened": [1, 1], "closed": [1, 1], "pools": 0, "feeds": 0, "version": 1, "records": 1}


def proof(root: Path) -> dict:
    """Reuse the pinned actual teardown ordering, retaining the narrower receipt-fault boundary."""
    return {
        **lifecycle.proof(root),
        "boundary": "Eight actual SQLite close-receipt/closed-file combinations with late admission and durable reopen. SQL receipt faults occur after native release; no claim that every failed OS close releases a handle or that hardware I/O always drains within a hard deadline.",
    }


def observations(data: bytes, check: dict, root: Path) -> dict[str, int]:
    """Reject missing, duplicate, wrongly attributed or partial resource/state observations."""
    configuration(check)
    proof(root)
    groups = {name: [] for name in CASES}
    for line in data.splitlines():
        event = v.decode(line)
        if not isinstance(event, dict):
            v.reject("termination-event")
        output = event.get("Output", "")
        if not isinstance(output, str):
            v.reject("termination-output")
        if "STORAGE-TERMINATION " not in output:
            continue
        name = event.get("Test")
        if event.get("Action") != "output" or event.get("Package") != check["package"] or name not in groups:
            v.reject("termination-attribution")
        groups[name].append(line)
    for mask, name in enumerate(CASES):
        rows = equality.frames(b"\n".join(groups[name]) + b"\n", check["package"], test=name, marker="STORAGE-TERMINATION ", maximum=1)
        if v.encode(rows) != v.encode([expected(mask)]):
            v.reject("termination-native-history", name)
    return {"STORAGE-TERMINATION": HITS}
