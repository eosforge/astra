"""Reconcile the finite Command failure matrix with native state, callback and process-exit observations."""

from pathlib import Path
import re

from tools import verify as v

SOURCE = "a85cf555ec0387a915624a672fc6037362b6b3c6277684f458f747db9c7a1979"
SITES = (
    ("set-error", "set-panic", "set-reentry", "string-panic", "boolean-panic")
    + tuple("parser/" + mode + "/" + fault for mode in ("continue", "panic", "exit") for fault in ("unknown", "missing", "invalid", "duplicate", "help"))
    + ("output-error",)
)


def configuration(check: dict) -> None:
    """Require the entire native suite and frozen failure capability rather than an arbitrary hit marker."""
    if check.get("faults") == "star-allocation-v1":
        from tools import allocation

        return allocation.configuration(check)
    if check.get("faults") in {"admission-files-v1", "admission-refresh-v1"}:
        from tools import materials

        return materials.configuration(check)
    argv = [
        "go",
        "test",
        "-json",
        "-count=1",
        "-p=2",
        "-parallel=1",
        "-timeout=180s",
        "-covermode=atomic",
        "-coverprofile={run}/command.cover",
        "./internal/command",
    ]
    raced = argv[:3] + ["-race"] + argv[3:]
    probe = next((item for item in check["probes"] if item["contract"] == "COMMAND-FAULT"), None)
    tests = {"TestDecisions", "TestDecisionInventory", "TestParse", "TestVerification", "TestFault"}
    if any(item["contract"] == "COMMAND-NUMERIC" for item in check["probes"]):
        tests.add("TestNumeric")
    if check.get("model") == "command-state-v1":
        tests.update(("TestModel", "TestModelOracle"))
    if any(item["contract"] == "COMMAND-COMPATIBILITY" for item in check["probes"]):
        tests.add("TestCompatibility")
    if (
        check.get("faults") != "command-faults-v1"
        or check["component"] != "command"
        or check["package"] != "github.com/eosforge/astra/internal/command"
        or check.get("coverage") != "command-structure-v1"
        or check["argv"] not in (argv, raced)
        or len(check["expected_tests"]) != len(tests)
        or set(check["expected_tests"]) != tests
        or v.encode(probe) != v.encode({"contract": "COMMAND-FAULT", "test": "TestFault", "minimum_hits": 63})
    ):
        v.reject("fault-configuration")


def expected(site: str, phase: int) -> dict:
    """Derive outcomes from single-attempt admission and the standard flag error-mode contract."""
    state = {"result": "ok", "calls": 1, "consumed": site.startswith("set-"), "prefix": 0, "value": 0, "returned": True}
    if site in SITES[:5]:
        if phase < 2:
            state["result"] = "panic" if site.endswith("panic") else "error"
            state["returned"] = state["result"] != "panic"
        return state
    state.update(calls=0, consumed=True, prefix=7, value=9)
    if phase == 2:
        if site.startswith("parser/exit/"):
            state["result"] = "exit-ok"
        return state
    state.update(result="error", consumed=False, value=0)
    if site == "output-error":
        state.update(result="help", calls=1)
        return state
    _, mode, fault = site.split("/")
    if fault in ("invalid", "duplicate"):
        state["consumed"] = True
    if fault == "duplicate":
        state["value"] = 9
    if fault == "help":
        state["result"] = "help"
    if mode == "panic":
        state.update(result="panic", returned=False)
    elif mode == "exit":
        state.update(result="exit-ok" if fault == "help" else "exit-error", returned=False)
    return state


def observations(data: bytes, check: dict, root: Path) -> dict[str, int]:
    """Reject omitted, duplicated, reordered or altered fault cells despite an unchanged success counter."""
    if check.get("faults") == "star-allocation-v1":
        from tools import allocation

        return allocation.observations(data, check, root)
    if check.get("faults") in {"admission-files-v1", "admission-refresh-v1"}:
        from tools import materials

        return materials.observations(data, check, root)
    configuration(check)
    directory = v.inside(root, "internal/command")
    owned = sorted(path.relative_to(directory).as_posix() for path in directory.rglob("*.go") if not path.name.endswith("_test.go"))
    if owned != ["flags.go"] or v.file_digest(directory / "flags.go") != SOURCE:
        v.reject("fault-source-inventory")
    frames, pending = [], {}
    for line in data.splitlines():
        event = v.decode(line)
        if event.get("Action") != "output":
            continue
        name, output = event.get("Test", ""), event.get("Output", "")
        if not isinstance(name, str) or not isinstance(output, str):
            v.reject("fault-output-shape")
        text = pending.get(name, "") + output
        if len(text.encode()) > 65536:
            v.reject("fault-line-budget")
        lines = text.split("\n")
        pending[name] = lines.pop()
        for part in lines:
            match = re.search(r"COMMAND-FAULT (.*)$", part)
            if match is None:
                continue
            if name != "TestFault" or event.get("Package") != check["package"]:
                v.reject("fault-test-identity")
            frames.append(v.decode(match.group(1).encode()))
    if any(pending.values()):
        v.reject("fault-stream-tail")
    wanted = [{"id": site, "phase": phase, "state": expected(site, phase)} for site in SITES for phase in range(3)]
    if v.encode(frames) != v.encode(wanted):
        v.reject("fault-matrix")
    return {"COMMAND-FAULT": len(wanted)}
