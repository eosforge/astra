"""Reconstruct the SDK Almanac page-stream domain from complete native public observations."""

from pathlib import Path
from tools import models
from tools import verify as v

# Fixed public alphabet: empty reset, set, erase, atomic two-page apply, abandoned reset, old version, duplicate key.
DOMAIN = {"histories": 2401, "depth": 4, "operations": 7, "pruning": 0}
LINUX = ("table", "projection", "selection", "subscription", "sampling", "lifetime", "publisher", "client", "beacon", "catalog_fault")
WINDOWS = ("sampling", "publisher", "projection", "selection", "subscription", "lifetime")
CORE = ("retired", "count", "session", "directory", "ready", "complete")
AUTH = ("session", "input", "protocol")


def require(actual: object, expected: object, cause: str) -> None:
    """Compare canonical JSON so null, false and floating-point identities cannot impersonate public values."""
    if v.encode(actual) != v.encode(expected):
        v.reject("projection-model-" + cause)


def configuration(check: dict) -> None:
    """Preserve the complete existing platform suites and every probe while requiring their actual model traces."""
    windows = check["id"] == "comet-windows"
    names, label, platform = (WINDOWS, "WINDOWS", "windows-amd64") if windows else (LINUX, "NATIVE", "linux-amd64-cgo")
    tests = ["cpp_comet_" + name for name in names] + ["cpp_comet_core_" + name for name in CORE] + ["cpp_comet_admission"]
    tests += ["cpp_comet_authentication_" + name for name in AUTH]
    tests += ["cpp_comet_batch"]
    if windows:
        tests += ["cpp_comet_options", "cpp_comet_core_model"]
    probes = [{"contract": "COMET_" + label + "-" + str(index), "minimum_hits": 1, "test": "cpp_comet_" + name} for index, name in enumerate(names, start=1)]
    probes += [{"contract": "COMET-PROJECTION-MODEL", "minimum_hits": 1, "test": "cpp_comet_projection"}]
    probes += [{"contract": "COMET-CORE-" + name.upper(), "minimum_hits": 6, "test": "cpp_comet_core_" + name} for name in CORE]
    probes += [{"contract": "COMET-ADMISSION-" + name, "minimum_hits": 8, "test": "cpp_comet_admission"} for name in ("FAULT", "LIMIT")]
    probes += [{"contract": "COMET-AUTH-" + name.upper(), "minimum_hits": 20, "test": "cpp_comet_authentication_" + name} for name in AUTH]
    argv = ["python3", "-B", "tools/observe.py", "ctest", "--build", "build/Comet/qualification" if windows else "build/cmake/release"]
    argv += [value for test in tests[: len(names)] for value in ("--case", test)]
    argv += ["--config", "Release"] if windows else []
    argv += [value for test in tests[len(names) :] for value in ("--case", test)]
    if (
        check.get("model") != "comet-projection-v1"
        or check["id"] not in ("comet-native", "comet-windows")
        or check["component"] != "comet"
        or check["adapter"] != "observed-cases"
        or check.get("platforms") != [platform]
        or check["argv"] != argv
        or check["expected_tests"] != tests
        or check["probes"] != probes
        or check["log_bytes"] != 32 * 1024**2
        or check["timeout_s"] != 3600
        or check["environment"] != {}
    ):
        v.reject("projection-model-configuration")


def snapshot(records: dict[str, str], version: int) -> list:
    """Express complete public values from a plain map; native pages, hashes and version predicates are not reused."""
    return [version, "star-model", "routes", "main", "", "ready", False, len(records), [[key, value] for key, value in sorted(records.items())]]


def trace(operations: list[int], ordinal: int) -> tuple[dict, int]:
    """Derive every partial/complete/error result and retained view before reading any native output."""
    records, version, states, retained = {}, 1, [], []
    initial, hits = snapshot(records, version), 1
    view_hits = lambda view: 6 + 2 * len(view[-1])
    for operation in operations:
        old = snapshot(records, version)
        retained.append(old)
        receipts = []
        if operation in (3, 4, 6):
            receipts.append(["partial", old])
            hits += 1 + view_hits(old)
        if operation in (0, 1, 2, 3):
            if operation == 0:
                records.clear()
            elif operation == 1:
                records["a"] = "A"
            elif operation == 2:
                records.pop("a", None)
            else:
                records.update({"a": "A", "b": "B"})
            version += 1
            current = snapshot(records, version)
            receipts.append(["complete", current])
            hits += 1 + view_hits(current)
        elif operation in (5, 6):
            receipts.append(["version" if operation == 5 else "protocol", old])
            hits += 1
        current = snapshot(records, version)
        states.append({"operation": operation, "receipts": receipts, "current": current, "retained": list(retained)})
        hits += view_hits(current) + sum(view_hits(view) for view in retained)
    return {"ordinal": ordinal, "initial": initial, "states": states}, hits


def frames(data: bytes, check: dict) -> list[dict]:
    """Select exactly one projection case from the original complete platform suite and retain its entire fixed domain."""
    return models.native(data, check, test="cpp_comet_projection", algorithm="comet-projection-v1", rows=DOMAIN["histories"] + 2, prefix="projection-model")


def observations(data: bytes, check: dict, root: Path = v.ROOT) -> dict[str, int]:
    """Refuse summary-only success; all platform cases, histories, retained snapshots and native counters must agree."""
    configuration(check)
    observed, failures = v.case_observations(data, check)
    if failures:
        v.reject("projection-model-case-failed")
    rows = frames(data, check)
    start = rows[0]
    if not isinstance(start["value"], dict):
        v.reject("projection-model-domain")
    before = start["value"].get("before")
    if type(before) is not int or before <= 0:
        v.reject("projection-model-outside-counter")
    require(start, {"model": "comet-projection-v1", "event": "start", "value": {**DOMAIN, "before": before}}, "domain")
    hits = 2  # The unchanged full-domain assertion and successful output-health assertion.
    for ordinal in range(DOMAIN["histories"]):
        remaining, operations = ordinal, []
        for _ in range(DOMAIN["depth"]):
            operations.append(remaining % DOMAIN["operations"])
            remaining //= DOMAIN["operations"]
        value, count = trace(operations, ordinal)
        require(rows[ordinal + 1], {"model": "comet-projection-v1", "event": "history", "value": value}, "history")
        hits += count
    require(rows[-1], {"model": "comet-projection-v1", "event": "finish", "value": {"histories": 2401, "transitions": 9604, "checks": hits}}, "terminal")
    require(observed.get("COMET-PROJECTION-MODEL"), before + hits, "counter")
    return observed
