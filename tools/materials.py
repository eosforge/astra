"""Reconcile the native-backed identity file matrix with exact refusal prefixes, closed handles and disarmed recovery."""

from pathlib import Path
import re

from tools import verify as v

# Bind the accepted file-boundary implementation; the registration step fills its actual source digest.
SOURCE = "37e195bcb9412502763e761740705d08e4ec57cd038d911f13068a97ec6e3612"
FAULTS = ("lstat", "nonregular", "open", "stat", "restat", "read", "partial", "close")
TESTS = {
    "TestDirectoryOracle",
    "TestDirectoryModel",
    "TestDirectorySchedules",
    "TestDirectoryOwnership",
    "TestDirectoryReplacement",
    "TestDirectoryBoundaries",
    "TestAuthorize",
    "TestDirectoryConcurrent",
    "TestIdentity",
    "TestSharedVectors",
    "TestNodeOpen",
    "TestNodeState",
    "TestNodeRegistration",
    "TestNodeRefresh",
    "TestNodeSerialization",
    "TestNodeJoin",
    "TestNodeRun",
    "TestNodePause",
    "TestNodeTransport",
    "TestNodeOracle",
    "TestNodeModel",
    "TestNodeTransitionsOracle",
    "TestNodeTransitions",
    "TestDirectoryConstruction",
    "TestIdentityRules",
    "TestLoadBoundaries",
    "TestLoadFault",
    "TestSame",
    "TestPredicates",
    "TestNumeric",
    "TestNodeDrain",
    "TestDirectoryConflicts",
    "TestAdmissionCredentials",
}
# Historical native receipts retain their original inventory; current campaigns also require every cancellation case.
CANCELLATION = {
    "TestNodeCancellation",
    *("TestNodeCancellation/" + name for name in ("cancelled", "unavailable", "refused", "identity", "committed", "remote")),
}
ACQUISITION = {
    "TestOpen",
    "TestLoadReplacement",
    *("TestLoadReplacement/" + name for name in ("ca.pem", "cert.pem", "key.pem", "admission.pub", "login.json")),
}


def configuration(check: dict) -> None:
    """Require the complete configured Admission suite and a single exact file-matrix capability."""
    if check.get("faults") == "admission-refresh-v1":
        if (
            check["component"] != "admission"
            or check["package"] != "github.com/eosforge/astra/internal/admission"
            or check["argv"]
            != [
                "go",
                "test",
                "-json",
                "-count=1",
                "-parallel=1",
                "-p=2",
                "-timeout=45s",
                "-overlay=tests/fixtures/admission-refresh.json",
                "-run=^TestRefreshFaults$",
                "./internal/admission",
            ]
            or check["expected_tests"] != ["TestRefreshFaults"]
            or v.encode(check["probes"]) != v.encode([{"contract": "ADMISSION-NODE-REFRESH", "test": "TestRefreshFaults", "minimum_hits": 106}])
        ):
            v.reject("refresh-configuration")
        return
    probe = next((p for p in check["probes"] if p["contract"] == "ADMISSION-IDENTITY-FAULT"), None)
    if (
        check.get("faults") != "admission-files-v1"
        or check["component"] != "admission"
        or check["package"] != "github.com/eosforge/astra/internal/admission"
        or check["argv"] != ["go", "test", "-json", "-count=1", "-parallel=4", "-p=4", "-timeout=180s", "./internal/admission"]
        or len(check["expected_tests"]) != len(set(check["expected_tests"]))
        or set(check["expected_tests"]) not in (TESTS, TESTS | CANCELLATION, TESTS | CANCELLATION | ACQUISITION)
        or v.encode(probe) != v.encode({"contract": "ADMISSION-IDENTITY-FAULT", "test": "TestLoadFault", "minimum_hits": 1501})
    ):
        v.reject("material-configuration")
    if ACQUISITION & set(check["expected_tests"]):
        required = [{"contract": "ADMISSION-IDENTITY-FILES", "test": "TestOpen", "minimum_hits": 7}]
        required.extend(
            {"contract": "ADMISSION-IDENTITY-FAULT", "test": name, "minimum_hits": 6} for name in sorted(ACQUISITION) if name.startswith("TestLoadReplacement/")
        )
        if any(sum(v.encode(actual) == v.encode(probe) for actual in check["probes"]) != 1 for probe in required):
            v.reject("material-acquisition-probes")


def expected(fault: str, slot: int, phase: int) -> dict:
    """Derive the accepted prefix from the material order and the failed operation's ownership boundary."""
    inspected, attempted, opened = slot + 1, slot + 1, slot + 1
    if phase == 2:
        inspected = attempted = opened = 5
    elif fault in {"lstat", "nonregular"}:
        attempted = opened = slot
    elif fault == "open":
        opened = slot
    return {
        "fault": fault,
        "slot": slot,
        "phase": phase,
        "inspected": inspected,
        "attempted": attempted,
        "opened": opened,
        "closed": opened,
        "result": "loaded" if phase == 2 else "rejected",
    }


def frames(data: bytes, package: str, test: str, marker: str) -> list[dict]:
    """Join native output fragments without accepting another package or test's matrix."""
    result, pending = [], {}
    for line in data.splitlines():
        event = v.decode(line)
        if not isinstance(event, dict):
            v.reject("material-output-shape")
        if event.get("Action") != "output":
            continue
        name, output = event.get("Test", ""), event.get("Output", "")
        if not isinstance(name, str) or not isinstance(output, str):
            v.reject("material-output-shape")
        text = pending.get(name, "") + output
        if len(text.encode()) > 65536:
            v.reject("material-line-budget")
        lines = text.split("\n")
        pending[name] = lines.pop()
        for part in lines:
            match = re.search(re.escape(marker) + r" (.*)$", part)
            if match is None:
                continue
            if name != test or event.get("Package") != package:
                v.reject("material-test-identity")
            result.append(v.decode(match.group(1).encode()))
    if any(pending.values()):
        v.reject("material-stream-tail")
    return result


def refresh(data: bytes, check: dict, root: Path) -> dict[str, int]:
    """Require two complete refusals and same-object recovery, retaining terminal replacement refusal."""
    from tools import admission

    selected = admission.scope(root)
    if selected is None or any(not admission.matches(root, name, selected) for name in selected):
        v.reject("refresh-source")
    if (
        v.file_digest(root / "tests/fixtures/admission-refresh.go.in") != "d3d7c7fc82d3617227741e96a77981ecc2450d5f9dc3a6f470423f4569a5e6db"
        or v.decode(v.read(root / "tests/fixtures/admission-refresh.json"))
        != {"Replace": {"internal/admission/refresh_fault_test.go": "tests/fixtures/admission-refresh.go.in"}}
        or (root / "internal/admission/refresh_fault_test.go").exists()
    ):
        v.reject("refresh-fixture")
    rows = frames(data, check["package"], "TestRefreshFaults", "ADMISSION-REFRESH-FAULT")
    wanted = []
    for scenario, refusal in enumerate((14, 16, 2, 16, 2)):
        for phase in range(3):
            wanted.append(
                {
                    "scenario": scenario,
                    "phase": phase,
                    "code": 0 if phase == 2 and scenario != 3 else refusal,
                    "calls": (1 if phase == 2 else 0) if scenario == 4 else phase + 1,
                    "permits": 0,
                    "member": True,
                    "hello": True,
                    "request": True,
                    "directory": True,
                }
            )
    if v.encode(rows) != v.encode(wanted):
        v.reject("refresh-matrix")
    return {"ADMISSION-NODE-REFRESH": 1 + 7 * len(rows)}


def observations(data: bytes, check: dict, root: Path) -> dict[str, int]:
    """Reject summary-only, reordered, missing, repeated or changed cells despite a positive assertion marker."""
    configuration(check)
    if check.get("faults") == "admission-refresh-v1":
        return refresh(data, check, root)
    from tools import admission

    if v.file_digest(v.inside(root, "internal/admission/identity.go")) != SOURCE:
        if any(not admission.matches(root, name, admission.MATERIAL) for name in admission.MATERIAL):
            v.reject("material-source")
    rows = frames(data, check["package"], "TestLoadFault", "ADMISSION-IDENTITY-FAULT")
    wanted = [expected(fault, slot, phase) for fault in FAULTS for slot in range(5) for phase in range(3)]
    if v.encode(rows) != v.encode(wanted):
        v.reject("material-matrix")
    # One native fixture check plus result/prefix checks, inspection identities and two checks per physical handle.
    hits = 1 + sum(2 + row["inspected"] + 2 * row["opened"] for row in rows)
    if hits != 1501:
        v.reject("material-assertion-domain")
    # The generic Go reader separately requires six native assertions in each of the five
    # replacement cases. Include those declared observations without changing the 120-cell matrix.
    if ACQUISITION <= set(check["expected_tests"]):
        hits += 5 * 6
    return {"ADMISSION-IDENTITY-FAULT": hits}
