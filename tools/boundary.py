"""Verify complete Common adapter/configuration frames and the independent Store model before native gate credit."""

from pathlib import Path
import re
import xml.etree.ElementTree as ET

from tools import junit, store, verify as v

# This independently declared domain must not be inferred from a possibly incomplete native trace.
NAMES = (
    "elapsed-native",
    "elapsed-failure",
    "elapsed-negative-seconds",
    "elapsed-negative-nanos",
    "elapsed-invalid-nanos",
    "elapsed-overflow",
    "elapsed-zero",
    "elapsed-fraction",
    "elapsed-maximum",
    "precision-native",
    "timer-create",
    "resolution-failure",
    "resolution-seconds",
    "resolution-zero",
    "resolution-negative",
    "resolution-large",
    "timer-arm",
    "timer-read-error",
    "timer-read-short",
    "timer-read-zero",
    "timer-expired",
    "timer-retry",
    "resolution-maximum",
    "timer-cancel",
    "random-native",
    "random-empty",
    "random-short",
    "random-interrupted",
    "random-zero",
    "random-failure",
    "random-prefix-failure",
    "random-prefix-zero",
    "signals-native",
    "signals-interrupt",
    "signals-terminate",
    "signals-pipe",
    "address-ipv4-normalization",
    "address-ipv6-normalization",
    "endpoint-predicates",
    "identifier-segments",
    "pulsar-hostname-predicates",
    "member-bindings",
)
CASE = "cpp_platform_boundary"
PREFIX = "COMMON-NATIVE "
LIMIT = 32 * 1024**2
CONFIG = (
    "bare",
    "short",
    "missing",
    "disguised",
    "group",
    "advertise",
    "metrics-role",
    "metrics-invalid",
    "metrics-private",
    "metrics-public",
    "metrics-reordered",
    "metrics-normalized",
    "galaxy",
    "listen",
    "super",
    "oversized",
    "metrics-separate",
    "metrics-public-separate",
    "metrics-zero",
    "metrics-both-zero",
    "after-refusal",
)
SNAPSHOTS = ("cache", "failure", "replacement", "failure-replacement", "exhaustion", "segment")
DOMAINS = {CASE: (PREFIX, NAMES), "cpp_core": ("COMMON-CONFIG ", CONFIG), "cpp_store_fault": ("COMMON-SNAPSHOT ", SNAPSHOTS)}
MINIMUM = {CASE: 1605, "cpp_core": 100, "cpp_store_fault": 57254}


def require(value: object, reason: str) -> None:
    """Reject incomplete evidence without manufacturing native observations."""
    if not value:
        v.reject(reason)


def frames(rows: list[dict], case: str = CASE) -> dict[str, int | bool]:
    """Reject omitted, duplicate, reordered, foreign or incorrectly typed terminal frames."""
    require(
        len(NAMES) == len(set(NAMES)) == 42 and len(CONFIG) == len(set(CONFIG)) == 21 and len(SNAPSHOTS) == len(set(SNAPSHOTS)) == 6,
        "platform-reader-domain",
    )
    require(case in DOMAINS, "platform-reader-case")
    names = DOMAINS[case][1]
    expected = [{"case": name} for name in names] + [{"complete": True}]
    require(v.encode(rows) == v.encode(expected), "platform-case-domain")
    return {"cases": len(names), "complete": True}


def document(root: ET.Element, name: str = CASE) -> tuple[dict, list[dict]]:
    """Require exactly the intended testcase with native success, nonempty assertions and complete frames."""
    require(name in DOMAINS, "platform-reader-case")
    root = junit.xml(ET.tostring(root, encoding="utf-8"), [name], LIMIT)
    case = root[0]
    require(case.get("status") == "run", "platform-case-status")
    require(all(child.tag in {"properties", "system-out"} for child in case), "platform-case-terminal")
    require(len(case.findall("properties")) <= 1, "platform-case-properties")
    require(len(case.findall("system-out")) == 1, "platform-case-output")
    observed = junit.cases(root)
    require(observed[name]["status"] == "passed" and observed[name]["hits"] >= MINIMUM[name], "platform-case-assertions")
    output = case.findtext("system-out") or ""
    require(
        not re.search(
            r"ERROR: (?:AddressSanitizer|LeakSanitizer)|SUMMARY: (?:AddressSanitizer|UndefinedBehaviorSanitizer)|runtime error:|AddressSanitizer:DEADLYSIGNAL|WARNING: ThreadSanitizer",
            output,
        ),
        "platform-sanitizer",
    )
    prefix = DOMAINS[name][0]
    rows = []
    for line in output.splitlines(keepends=True):
        if prefix.strip() not in line:
            continue
        require(line.startswith(prefix) and line.endswith("\n") and len(line.encode()) <= 64 * 1024, "platform-case-line")
        rows.append(v.decode(line[len(prefix) :].encode(), maximum=64 * 1024))
    return {"observed": observed[name], "domain": frames(rows, name)}, rows


REGRESSION = (
    "cpp_platform",
    "cpp_core",
    "cpp_clock",
    "cpp_store",
    "cpp_store_fault",
    "cpp_store_ttl",
    "cpp_store_clock",
    "cpp_store_model",
    "cpp_wheel",
    "cpp_wheel_allocation",
    "cpp_identity",
    "cpp_session",
    "cpp_admission",
    "cpp_connect",
    "cpp_process",
    CASE,
)


def configuration(check: dict) -> None:
    """Freeze the complete original Common selection and the stronger named native capabilities."""
    argv = ["python3", "-B", "tools/observe.py", "ctest", "--build", "build/cmake/release"]
    for name in REGRESSION[:-1]:
        argv.extend(["--case", name])
    argv.append("--case=" + CASE)
    probes = {(item["contract"], item["test"]): item["minimum_hits"] for item in check.get("probes", [])}
    expected = {("COMMON_NATIVE-" + str(index), name): 1 for index, name in enumerate(REGRESSION, 1)}
    expected[("COMMON_NATIVE-2", "cpp_core")] = 100
    expected[("COMMON_NATIVE-16", CASE)] = 1605
    expected[("COMMON-MODEL", "cpp_store_model")] = 1
    require(check.get("id") == "common-native" and check.get("component") == "common" and check.get("adapter") == "observed-cases", "boundary-check-owner")
    require(check.get("boundaries") == "common-native-v1" and check.get("platforms") == ["linux-amd64-cgo"], "boundary-check-capability")
    require(check.get("argv") == argv and check.get("expected_tests") == list(REGRESSION), "boundary-check-selection")
    require(
        probes == expected and len(probes) == len(check.get("probes", [])) and all(type(value) is int for value in probes.values()), "boundary-check-probes"
    )
    require(check.get("environment") == {} and check.get("log_bytes") == LIMIT and check.get("timeout_s") == 3600, "boundary-check-budget")


def observations(data: bytes, check: dict, root: Path = v.ROOT) -> dict[str, int]:
    """Keep each owning case separate; scalar successes cannot replace frames or finite histories."""
    configuration(check)
    native = junit.document(data, check)
    results = {}
    for name, contract in ((CASE, "COMMON_NATIVE-16"), ("cpp_core", "COMMON_NATIVE-2"), ("cpp_store_fault", "COMMON_NATIVE-5")):
        selected = ET.Element("testsuite")
        selected.append(next(case for case in native if case.get("name") == name))
        result, _ = document(selected, name)
        results[contract] = result["observed"]["hits"]
    cases = junit.cases(native)
    require(cases["cpp_store_model"]["status"] == "passed", "boundary-store-terminal")
    results["COMMON-MODEL"] = store.replay(store.frames(data, check))
    require(cases["cpp_store_model"]["hits"] == results["COMMON-MODEL"], "boundary-store-counter")
    return results
