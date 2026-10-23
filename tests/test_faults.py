"""Attack the Command matrix parser with synthetic controls; these fixtures are not product acceptance evidence."""

import copy
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

from tools import allocation, command, faults, verify as v
from tests.test_structure import PROFILE

ROOT = Path(__file__).resolve().parents[1]


def pack(value: dict) -> bytes:
    """Encode exactly one compact JSON value for a native JSONL event or log frame."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def configured() -> dict:
    """Load the actual matrix policy, without reducing component tiers or requirements."""
    return next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "command-boundaries")


def rows() -> list[dict]:
    """Supply the declared parser domain; independent fixed axioms below anchor its expected semantics."""
    return [{"id": site, "phase": phase, "state": faults.expected(site, phase)} for site in faults.SITES for phase in range(3)]


def native(frames: list[dict], name: str = "TestFault", package: str | None = None) -> bytes:
    """Encode native-shaped output events for negative controls, never claiming execution."""
    package = package or configured()["package"]
    return b"".join(
        pack({"Package": package, "Action": "output", "Test": name, "Output": "    fault_test.go:1: COMMAND-FAULT " + pack(item).decode() + "\n"}) + b"\n"
        for item in frames
    )


def allocation_check() -> dict:
    """Load the actual unchanged full-suite inventory for the two strengthened native fault cases."""
    return next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "star-native")


def allocation_rows(domain: str) -> tuple[list[dict], int]:
    """Create explicitly synthetic positive envelopes, anchored separately to literal public semantics."""
    rows = [{"event": "start", "domain": domain, "sweeps": [list(item) for item in allocation.SWEEPS[domain]]}]
    count = 6
    for operation, _ in allocation.SWEEPS[domain]:
        for point in range(3):
            failed = point < 2
            key = ("old" if operation == "batch" else "key").encode().hex() if domain == "catalog" else "00000000000040008000000000000001"
            before, after, frozen = allocation.expected(domain, operation, key, failed, "00000000000040008000000000000002")
            rows.append(
                {
                    "event": "attempt",
                    "operation": operation,
                    "point": point,
                    "injected": failed,
                    "propagated": failed,
                    "before": before[0],
                    "after": after,
                    "frozen": frozen,
                }
            )
            count += (9 if failed else 6) if operation == "batch" else 9 if operation == "expire" else 13 if failed else 11 if operation == "create" else 10
    rows.append({"event": "finish", "domain": domain})
    return rows, count


def allocation_text(rows: list[dict], count: int) -> str:
    """Encode synthetic frames without presenting them as native product executions."""
    return "".join("ASTRA-ALLOCATION " + pack(row).decode() + "\n" for row in rows) + "ASTRA-CHECKS " + pack({"hits": count}).decode() + "\n"


def page_native(failures: int = 1) -> tuple[str, int]:
    """Construct synthetic reader controls with literal oracle costs, never native product evidence."""
    costs = {
        "catalog": {"first": 61, "middle": 52, "last": 43, "point": 22, "zero": 22, "missing": 16, "empty": 16, "delta": 44, "tail": 35},
        "ephemeris": {"first": 67, "middle": 57, "last": 47, "point": 24, "zero": 24, "missing": 16, "empty": 16, "delta": 46, "tail": 36},
    }
    order = [(domain, case, cost) for domain, cases in costs.items() for case, cost in cases.items()]
    order += [
        ("catalog", "dense", 11),
        ("ephemeris", "dense", 15),
        ("almanac", "empty", 4),
        ("almanac", "point", 7),
        ("almanac", "dense", 16),
        ("almanac", "construction", 5),
    ]
    frames, count = [], 26
    for domain, case, cost in order:
        for point in range(failures + 1):
            frames.append("ASTRA-PAGE-FAULT " + pack({"domain": domain, "case": case, "point": point, "injected": point < failures}).decode() + "\n")
            count += cost + (2 if point < failures else 0)
    frames.append("ASTRA-PAGE-FAULT-SUMMARY " + pack({"scenarios": 24, "attempts": 24 * (failures + 1), "failures": 24 * failures}).decode() + "\n")
    frames.append("ASTRA-CHECKS " + pack({"hits": count}).decode() + "\n")
    return "".join(frames), count


def dispatch_native(failures: int = 1) -> tuple[str, int]:
    """Author finite synthetic replication traces independently of the production reader."""
    frames, count = ["ASTRA-DISPATCH-HEALTHY 12\n"], 523
    cases = ("empty", "delta", "first", "last", "dense", "expired")
    for domain, costs in (("catalog", (11, 49, 58, 58, 40, 36)), ("ephemeris", (11, 60, 58, 58, 40, 20))):
        for case, cost in zip(cases, costs, strict=True):
            for point in range(failures + 1):
                frame = {"domain": domain, "case": case, "point": point}
                frames.append("ASTRA-DISPATCH-BEGIN " + pack(frame).decode() + "\n")
                frames.append("ASTRA-DISPATCH-END " + pack({**frame, "injected": point < failures}).decode() + "\n")
                count += cost
    frames.append("ASTRA-CHECKS " + pack({"hits": count}).decode() + "\n")
    return "".join(frames), count


def rpc_native() -> str:
    """Author the synthetic RPC case denominator without using the reader's expected list."""
    rows = [{"group": "lifecycle", "cases": 1}]
    for name, count in (("publish", 21), ("renew", 12), ("limits", 0), ("query", 5)):
        rows.extend([{"group": name, "case": index} for index in range(count)] if count else [{"group": name, "cases": 1}])
    rows.extend([{"group": "admission", "cases": 8}, {"group": "streaming", "cases": 1}])
    rows.extend({"group": group, "cases": count} for group, count in (("configuration", 6), ("refusals", 8), ("capacity", 2), ("exhaustion", 2)))
    rows.extend({"group": group, "case": index} for group in ("exceptions", "cleanup") for index in range(2))
    return (
        "".join("ASTRA-CATALOG " + pack(row).decode() + "\n" for row in rows)
        + 'PASS Catalog public RPC boundaries and atomic batches\nASTRA-CHECKS {"hits":500}\n'
    )


def ephemeris_native() -> str:
    """Use independent exception and boundary inventories to attack the Ephemeris result reader."""
    return "\n".join(
        (
            "ASTRA-EPHEMERIS-EXCEPTION 1 0",
            "ASTRA-EPHEMERIS-EXCEPTION 1 1",
            "ASTRA-EPHEMERIS-EXCEPTION 1 2",
            "ASTRA-EPHEMERIS-EXCEPTION 1 3",
            "ASTRA-EPHEMERIS-EXCEPTION 2 0",
            "ASTRA-EPHEMERIS-EXCEPTION 2 1",
            "ASTRA-EPHEMERIS-EXCEPTION 2 2",
            "ASTRA-EPHEMERIS-EXCEPTION 2 3",
            *(f"ASTRA-EPHEMERIS-BOUNDARY create {index}" for index in range(21)),
            *(f"ASTRA-EPHEMERIS-BOUNDARY update {index}" for index in range(12)),
            *(f"ASTRA-EPHEMERIS-BOUNDARY renew {index}" for index in range(11)),
            *(f"ASTRA-EPHEMERIS-BOUNDARY remove {index}" for index in range(10)),
            *(f"ASTRA-EPHEMERIS-BOUNDARY versions {index}" for index in range(5)),
            *(f"ASTRA-EPHEMERIS-BOUNDARY limits {index}" for index in range(5)),
            *(f"ASTRA-EPHEMERIS-BOUNDARY configuration {index}" for index in range(4)),
            *(f"ASTRA-EPHEMERIS-BOUNDARY cleanup {index}" for index in range(2)),
            "Ephemeris RPC tests passed",
            'ASTRA-CHECKS {"hits":200}',
            "",
        )
    )


def allocation_native(changed: list[dict] | None = None) -> bytes:
    """Supply the entire synthetic native XML suite so malformed state reaches the independent oracle."""
    xml = ET.Element("testsuite")
    counts = {}
    for name in allocation.CASES:
        case = ET.SubElement(xml, "testcase", name=name)
        count, output = 1, 'ASTRA-CHECKS {"hits":1}\n'
        if name == "cpp_pagination":
            count, output = 492381, 'ASTRA-CHECKS {"hits":492381}\n'
        if name == "cpp_pagination_fault":
            output, count = page_native()
        if name == "cpp_dispatch_fault":
            output, count = dispatch_native()
        if name == "cpp_catalog_rpc":
            output, count = rpc_native(), 500
        if name == "cpp_ephemeris_rpc":
            output, count = ephemeris_native(), 200
        if name in ("cpp_catalog_fault", "cpp_ephemeris_fault"):
            rows, count = allocation_rows("catalog" if name == "cpp_catalog_fault" else "ephemeris")
            output = allocation_text(changed if changed is not None and name == "cpp_catalog_fault" else rows, count)
        counts[name] = count
        ET.SubElement(case, "system-out").text = output
    events = [b'ASTRA-OBSERVE {"event":"start","engine":"ctest"}\n']
    for name, count in counts.items():
        events.append(b"ASTRA-OBSERVE " + pack({"event": "begin", "test": name}) + b"\n")
        events.append(b"ASTRA-OBSERVE " + pack({"event": "end", "test": name, "status": "passed", "hits": count}) + b"\n")
    events.append(b"ASTRA-CTEST " + pack(ET.tostring(xml, encoding="unicode")) + b"\n")
    events.append(b"ASTRA-OBSERVE " + pack({"event": "complete", "cases": len(counts)}) + b"\n")
    return b"".join(events)


class FaultTests(unittest.TestCase):
    """Require the complete fixed denominator, original inputs and every independently observable state field."""

    def test_admission(self) -> None:
        """The complete owned failure surface is conjunctive; a successful file or refresh subset cannot qualify it."""
        config, _, _ = v.configuration(ROOT / "development.json", ROOT)
        obligations = v.expand(config)
        target = "admission/DEV-FAULT/ADMISSION-ASSURANCE/linux-amd64-cgo/fault-matrix"
        _, graph = v.dependency_order(obligations)
        expected = {
            "ADMISSION-ASSURANCE",
            "ADMISSION-IDENTITY-FILES",
            "ADMISSION-IDENTITY-FAULT",
            "ADMISSION-IDENTITY-RULES",
            "ADMISSION-CREDENTIALS",
            "ADMISSION-DIRECTORY-BOUNDARIES",
            "ADMISSION-CONFLICTS",
            "ADMISSION-NODE-OPEN",
            "ADMISSION-NODE-RESOLVER",
            "ADMISSION-NODE-REGISTER",
            "ADMISSION-NODE-REFRESH",
            "ADMISSION-NODE-SCHEDULE",
            "ADMISSION-NODE-RETRY",
            "ADMISSION-NODE-RUN",
            "ADMISSION-NODE-PAUSE",
            "ADMISSION-NODE-TRANSPORT",
            "ADMISSION-NODE-DRAIN",
            "ADMISSION-NODE-FINITE",
            "ADMISSION-NODE-TRANSITIONS",
            "ADMISSION-FINITE",
            "ADMISSION-SCHEDULE",
            "ADMISSION-NUMERIC",
        }
        dependencies = graph[target]
        self.assertEqual(len(dependencies), len(expected))
        self.assertEqual({obligations[key]["contract"] for key in dependencies}, expected)
        self.assertIn("admission/DEV-COVERAGE/ADMISSION-ASSURANCE/linux-amd64-cgo/structure", dependencies)
        self.assertNotIn("admission-gap-fault-matrix", v.unique(config["checks"]))
        observations = {
            (name, obligations[key]["platform"], obligations[key]["contract"]): "passed" for key in dependencies for name in obligations[key]["checks"]
        }
        self.assertEqual(len(observations), 23)
        now = dt.datetime(2026, 10, 9, tzinfo=dt.timezone.utc)
        gate = v.decide(config, observations, [], [], now)
        self.assertIn(target, gate["passed"])
        self.assertEqual(gate["status"], "blocked")
        for key in observations:
            for state in (None, "failed", "not-run", "unknown", "interrupted"):
                changed = dict(observations)
                if state is None:
                    del changed[key]
                else:
                    changed[key] = state
                with self.subTest(check=key[0], contract=key[2], state=state):
                    self.assertNotIn(target, v.decide(config, changed, [], [], now)["passed"])
        for wrong in ("platform", "contract"):
            changed = {
                (name, "windows-amd64" if wrong == "platform" else platform, "ADMISSION-ASSURANCE" if wrong == "contract" else contract): state
                for (name, platform, contract), state in observations.items()
            }
            with self.subTest(substitution=wrong):
                self.assertNotIn(target, v.decide(config, changed, [], [], now)["passed"])

    def test_configuration(self) -> None:
        """Changed capabilities, filters, suites and zero/boolean counters cannot preserve admission."""
        check = configured()
        faults.configuration(check)
        for key, value in (
            ("faults", "other"),
            ("faults", None),
            ("coverage", None),
            ("component", "other"),
            ("package", "other"),
            ("argv", check["argv"][:-1]),
            ("expected_tests", check["expected_tests"][:-1]),
            ("expected_tests", check["expected_tests"] + ["TestFault"]),
            ("probes", [probe for probe in check["probes"] if probe["contract"] != "COMMAND-FAULT"]),
        ):
            changed = copy.deepcopy(check)
            changed[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(v.Invalid, "fault-configuration"):
                faults.configuration(changed)

        star = allocation_check()
        faults.configuration(star)
        for key, value in (
            ("faults", "other"),
            ("component", "other"),
            ("argv", star["argv"][:-2]),
            ("expected_tests", star["expected_tests"][:-1]),
            ("adapter", "go-test-json"),
        ):
            changed = copy.deepcopy(star)
            changed[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(v.Invalid, "allocation-configuration"):
                allocation.configuration(changed)
        for count in (62, 0, True, 63.0):
            changed = copy.deepcopy(check)
            next(probe for probe in changed["probes"] if probe["contract"] == "COMMAND-FAULT")["minimum_hits"] = count
            with self.subTest(count=count), self.assertRaisesRegex(v.Invalid, "fault-configuration"):
                faults.configuration(changed)
        for count in (1, 492380, 0, True, 492381.0):
            changed = copy.deepcopy(star)
            next(probe for probe in changed["probes"] if probe["contract"] == "STAR_NATIVE-29")["minimum_hits"] = count
            with self.subTest(pagination_count=count), self.assertRaisesRegex(v.Invalid, "allocation-configuration"):
                allocation.configuration(changed)
        for contract, minimum in (("STAR_NATIVE-22", 200), ("STAR_NATIVE-30", 1), ("STAR_NATIVE-31", 1), ("STAR_NATIVE-32", 500)):
            for count in (0, True, float(minimum), minimum - 1, minimum + 1):
                changed = copy.deepcopy(star)
                next(probe for probe in changed["probes"] if probe["contract"] == contract)["minimum_hits"] = count
                with self.subTest(contract=contract, fault_count=count), self.assertRaisesRegex(v.Invalid, "allocation-configuration"):
                    allocation.configuration(changed)

    def test_rpc(self) -> None:
        """Missing, duplicated and reordered successes cannot qualify a partial RPC fixture."""
        text = rpc_native()
        lines = text.splitlines()
        self.assertEqual(len(lines), 52)
        self.assertEqual(allocation.rpc(text), 500)
        for index in range(50):
            for changed in (lines[:index] + lines[index + 1 :], lines[:index] + [lines[index]] + lines[index:]):
                with self.subTest(index=index), self.assertRaisesRegex(v.Invalid, "catalog-rpc-cases"):
                    allocation.rpc("\n".join(changed))
        for index in range(49):
            changed = lines.copy()
            changed[index], changed[index + 1] = changed[index + 1], changed[index]
            with self.subTest(swap=index), self.assertRaisesRegex(v.Invalid, "catalog-rpc-cases"):
                allocation.rpc("\n".join(changed))
        for count in (0, 499, True, "500"):
            changed = lines[:-1] + ["ASTRA-CHECKS " + pack({"hits": count}).decode()]
            with self.subTest(count=count), self.assertRaisesRegex(v.Invalid, "catalog-rpc-checks"):
                allocation.rpc("\n".join(changed))

        lines = ephemeris_native().splitlines()
        self.assertEqual(len(lines), 80)
        self.assertEqual(allocation.rpc(ephemeris_native(), "ephemeris"), 200)
        # Every missing or duplicated row, including terminal rows, must be rejected.
        for index in range(len(lines)):
            variants = (lines[:index] + lines[index + 1 :], lines[:index] + [lines[index]] + lines[index:])
            for changed in variants:
                with self.subTest(ephemeris=index), self.assertRaisesRegex(v.Invalid, "ephemeris-rpc-"):
                    allocation.rpc("\n".join(changed), "ephemeris")
        for index in range(len(lines) - 3):
            changed = lines.copy()
            changed[index], changed[index + 1] = changed[index + 1], changed[index]
            with self.subTest(ephemeris_swap=index), self.assertRaisesRegex(v.Invalid, "ephemeris-rpc-cases"):
                allocation.rpc("\n".join(changed), "ephemeris")
        for count in (0, 199, True, "200", 200.0):
            changed = lines[:-1] + ["ASTRA-CHECKS " + pack({"hits": count}).decode()]
            with self.subTest(ephemeris_count=count), self.assertRaisesRegex(v.Invalid, "ephemeris-rpc-checks"):
                allocation.rpc("\n".join(changed), "ephemeris")
        for extra in ("unrecognized", "ASTRA-EPHEMERIS-EXCEPTION 3 0", "ASTRA-EPHEMERIS-EXCEPTION 1 4"):
            with self.subTest(ephemeris_extra=extra), self.assertRaisesRegex(v.Invalid, "ephemeris-rpc-cases"):
                allocation.rpc(extra + "\n" + ephemeris_native(), "ephemeris")
        with self.assertRaisesRegex(v.Invalid, "rpc-domain"):
            allocation.rpc(ephemeris_native(), "unknown")

    def test_axioms(self) -> None:
        """Anchor the oracle to single-attempt admission, callback propagation and documented standard exit modes."""
        self.assertEqual(len(faults.SITES), len(set(faults.SITES)))
        self.assertEqual(len(faults.SITES), 21)
        empty = {"result": "ok", "calls": 1, "consumed": False, "prefix": 0, "value": 0, "returned": True}
        self.assertEqual(faults.expected("set-error", 0), {**empty, "result": "error", "consumed": True})
        self.assertEqual(faults.expected("set-panic", 0), {**empty, "result": "panic", "consumed": True, "returned": False})
        self.assertEqual(faults.expected("string-panic", 1), {**empty, "result": "panic", "returned": False})
        self.assertEqual(faults.expected("set-reentry", 2), {**empty, "consumed": True})
        self.assertEqual(faults.expected("parser/continue/duplicate", 0), {**empty, "result": "error", "calls": 0, "consumed": True, "prefix": 7, "value": 9})
        self.assertEqual(faults.expected("parser/exit/unknown", 0), {**empty, "result": "exit-error", "calls": 0, "prefix": 7, "returned": False})
        self.assertEqual(faults.expected("parser/exit/help", 0), {**empty, "result": "exit-ok", "calls": 0, "prefix": 7, "returned": False})
        self.assertEqual(faults.expected("output-error", 0), {**empty, "result": "help", "prefix": 7})

        before, after, frozen = allocation.expected("catalog", "update", "6b6579", True)
        self.assertEqual(before[0][0], [1, 1, [["initial", "scope", "6b6579", [1, [2] * 12, 2_000_000_000]]]])
        self.assertEqual(after[0][0], [2, 1, [["initial", "scope", "6b6579", [2, [3] * 16, 2_000_000_000]]]])
        self.assertEqual(frozen[1], [1, 1, [["6b6579", [1, [2] * 12]]]])
        before, after, _ = allocation.expected("catalog", "expire", "6b6579", True)
        self.assertEqual(len(before), 2)
        self.assertEqual(after[0][0], [1, 1, [["initial", "scope", "6b6579", [1, None, None]]]])
        self.assertEqual(after[1:], [[2, 0, []], [0, 0, []]])
        identity = "00000000000040008000000000000001"
        _, after, _ = allocation.expected("ephemeris", "expire", identity, True)
        self.assertEqual(after[0][0], [2, 0, []])
        self.assertEqual(after[0][1][-1], [2, "erase", "initial", "scope", identity, None])
        _, after, _ = allocation.expected("catalog", "batch", "6f6c64", True)
        self.assertEqual(after[1][0:2], [3, 2])
        self.assertEqual([row[4] for row in after[0][1]], ["6f6c64", "6f6c64", "6e6577"])

    def test_matrix(self) -> None:
        """Missing, duplicated, reordered or numerically forged observations fail at the unchanged denominator."""
        check, frames = configured(), rows()
        self.assertEqual(faults.observations(native(frames), check, ROOT), {"COMMAND-FAULT": 63})
        changed = copy.deepcopy(frames)
        changed[0]["state"]["consumed"] = 1
        other = copy.deepcopy(frames)
        other[-1]["state"]["prefix"] = 0
        for variant in ([], frames[:-1], frames + frames[:1], frames[1:] + frames[:1], changed, other):
            with self.subTest(size=len(variant)), self.assertRaisesRegex(v.Invalid, "fault-matrix"):
                faults.observations(native(variant), check, ROOT)

        for domain in allocation.SWEEPS:
            frames, count = allocation_rows(domain)
            self.assertEqual(allocation.trace(allocation_text(frames, count), domain), count)
            variants = [frames[:-1], frames[1:], frames[:1] + frames[2:], frames[:2] + frames[1:], frames[:1] + frames[2:3] + frames[1:2] + frames[3:]]
            for path, value in (
                ([1, "point"], True),
                ([1, "injected"], False),
                ([1, "propagated"], False),
                ([1, "before", 0, 0], 2),
                ([1, "after", 0, 0, 1], 7),
                ([1, "frozen", 1, 0], 2),
                ([1, "after", 0, 1, 0, 1], "erase"),
            ):
                changed = copy.deepcopy(frames)
                target = changed
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                variants.append(changed)
            for variant in variants:
                with self.subTest(domain=domain), self.assertRaisesRegex(v.Invalid, "allocation-"):
                    allocation.trace(allocation_text(variant, count), domain)
            with self.assertRaisesRegex(v.Invalid, "allocation-checks"):
                allocation.trace(allocation_text(frames, count + 1), domain)

        # The finite paging domain cannot pass with counters alone, empty exposure, or a truncated sweep.
        for failures, expected in ((1, 1478), (2, 2228)):
            text, count = page_native(failures)
            self.assertEqual(count, expected)
            self.assertEqual(allocation.pages(text), expected)
        text, _ = page_native()
        lines = text.splitlines(keepends=True)
        variants = [
            "",
            text.rstrip(),
            "".join(lines[:-1]),
            "".join(lines[:-2]),
            "".join(lines[1:]),
            "".join(lines[:2] + lines[:1] + lines[2:]),
            "".join(lines[2:4] + lines[:2] + lines[4:]),
            text.replace('"point":0', '"point":true', 1),
            text.replace('"injected":true', '"injected":1', 1),
            text.replace('"injected":true', '"injected":false', 1),
            text.replace('"scenarios":24', '"scenarios":23'),
            text.replace('"hits":1478', '"hits":1479'),
            text.replace('"hits":1478', '"hits":1478.0'),
            text.replace('"domain":"catalog"', '"domain":"unknown"', 1),
            text.replace("ASTRA-PAGE-FAULT ", "noise ASTRA-PAGE-FAULT ", 1),
            lines[-1],
            page_native(0)[0],
            "".join(lines[:-4] + lines[-2:]),
            "".join(lines[:-4] + lines[-2:])
            .replace('"scenarios":24', '"scenarios":23')
            .replace('"attempts":48', '"attempts":46')
            .replace('"failures":24', '"failures":23')
            .replace('"hits":1478', '"hits":1465'),
            text.replace('"case":"construction","point":0', '"case":"construction","point":1'),
            text.replace('"case":"construction","point":0,"injected":true', '"case":"construction","point":0,"injected":false'),
            text.replace('"case":"construction"', '"case":"dense"'),
        ]
        for ordinal, variant in enumerate(variants):
            with self.subTest(page_trace=ordinal), self.assertRaisesRegex(v.Invalid, "allocation-page-"):
                allocation.pages(variant)

        for failures, expected in ((1, 1521), (2, 2020), (255, 128267)):
            text, count = dispatch_native(failures)
            self.assertEqual(count, expected)
            self.assertEqual(allocation.dispatch(text), expected)
        text, _ = dispatch_native()
        lines = text.splitlines(keepends=True)
        variants = [
            "",
            text.rstrip(),
            "".join(lines[1:]),
            "".join(lines[:-1]),
            "".join(lines[:2] + lines[3:]),
            "".join(lines[:1] + lines[3:]),
            "".join(lines[:1] + lines[1:3] + lines[1:]),
            "".join(lines[:1] + lines[3:5] + lines[1:3] + lines[5:]),
            text.replace("HEALTHY 12", "HEALTHY 11"),
            text.replace('"point":0', '"point":true', 1),
            text.replace('"point":0', '"point":0.0', 1),
            text.replace('"point":0', '"point":0,"point":0', 1),
            text.replace('"injected":true', '"injected":1', 1),
            text.replace('"injected":true', '"injected":false', 1),
            text.replace('"hits":1521', '"hits":1522'),
            text.replace('"hits":1521', '"hits":1521.0'),
            text.replace('"domain":"catalog"', '"domain":"other"', 1),
            text.replace('"case":"empty"', '"case":"delta"', 2),
            text.replace("ASTRA-DISPATCH-BEGIN ", "noise ASTRA-DISPATCH-BEGIN ", 1),
            text.replace("ASTRA-DISPATCH-END ", "ASTRA-DISPATCH-BEGIN ", 1),
            text + lines[-1],
            lines[-1],
            dispatch_native(0)[0],
            dispatch_native(255)[0].replace('"injected":false', '"injected":true'),
            dispatch_native(256)[0],
        ]
        for ordinal, variant in enumerate(variants):
            with self.subTest(dispatch_trace=ordinal), self.assertRaisesRegex(v.Invalid, "allocation-dispatch-"):
                allocation.dispatch(variant)

    def test_stream(self) -> None:
        """Fragmented real log lines reassemble; wrong ownership, invalid JSON and unfinished output do not pass."""
        check = configured()
        data = native(rows())
        self.assertEqual(faults.observations(data, check, ROOT), {"COMMAND-FAULT": 63})
        fragmented = []
        for line in data.splitlines():
            event = v.decode(line)
            original = event["Output"]
            for part in (original[:19], original[19:]):
                fragmented.append(pack({**event, "Output": part}) + b"\n")
        self.assertEqual(faults.observations(b"".join(fragmented), check, ROOT), {"COMMAND-FAULT": 63})
        for damaged, cause in (
            (native(rows(), name="TestOther"), "fault-test-identity"),
            (native(rows(), package="other"), "fault-test-identity"),
            (data + pack({"Action": "output", "Test": "TestFault", "Output": "unfinished"}) + b"\n", "fault-stream-tail"),
            (pack({"Action": "output", "Output": "x" * 65537}) + b"\n", "fault-line-budget"),
            (b"{\n", "json-invalid"),
        ):
            with self.subTest(cause=cause), self.assertRaisesRegex(v.Invalid, cause):
                faults.observations(damaged, check, ROOT)

        data = allocation_native()
        observed, failures = v.parse_observations(data, allocation_check(), ROOT)
        self.assertEqual(failures, [])
        self.assertEqual(
            {key: observed[key] for key in ("STAR_NATIVE-6", "STAR_NATIVE-11", "STAR_NATIVE-22", "STAR_NATIVE-30", "STAR_NATIVE-31", "STAR_NATIVE-32")},
            allocation.observations(data, allocation_check(), ROOT),
        )
        for variant in (b"", data + data, data.replace(b"cpp_catalog_fault", b"cpp_catalog_other"), data.replace(b"ASTRA-CTEST ", b"ASTRA-OTHER ")):
            with self.assertRaisesRegex(v.Invalid, "allocation-"):
                allocation.observations(variant, allocation_check(), ROOT)
        damaged = data.replace(b"ASTRA-DISPATCH-HEALTHY 12", b"ASTRA-DISPATCH-HEALTHY 11")
        # A successful CTest envelope and its positive count cannot hide an incomplete native domain.
        self.assertEqual(v.case_observations(damaged, allocation_check())[1], [])
        with self.assertRaisesRegex(v.Invalid, "allocation-dispatch-terminal"):
            v.parse_observations(damaged, allocation_check(), ROOT)
        damaged = data.replace(b"ASTRA-EPHEMERIS-EXCEPTION 2 3", b"ASTRA-EPHEMERIS-EXCEPTION 2 2")
        self.assertEqual(v.case_observations(damaged, allocation_check())[1], [])
        with self.assertRaisesRegex(v.Invalid, "ephemeris-rpc-cases"):
            v.parse_observations(damaged, allocation_check(), ROOT)

    def test_scope(self) -> None:
        """Changed implementation and newly owned nested files invalidate the fixed callback/callable inventory."""
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            directory = root / "internal/command"
            directory.mkdir(parents=True)
            path = directory / "flags.go"
            original = (ROOT / "internal/command/flags.go").read_bytes()
            path.write_bytes(original)
            self.assertEqual(faults.observations(native(rows()), configured(), root), {"COMMAND-FAULT": 63})
            path.write_bytes(original + b"\n")
            with self.assertRaisesRegex(v.Invalid, "fault-source-inventory"):
                faults.observations(native(rows()), configured(), root)
            path.write_bytes(original)
            (directory / "nested").mkdir()
            (directory / "nested/extra.go").write_text("package nested\n", encoding="utf-8")
            with self.assertRaisesRegex(v.Invalid, "fault-source-inventory"):
                faults.observations(native(rows()), configured(), root)

    def test_gate(self) -> None:
        """A passed native-shaped test and a positive marker cannot replace its missing fault matrix."""
        check = configured()
        package = check["package"]
        events = [{"Package": package, "Action": "start"}]
        for test in check["expected_tests"]:
            events.append({"Package": package, "Action": "run", "Test": test})
            for probe in check["probes"]:
                if probe["test"] == test:
                    events.append(
                        {
                            "Package": package,
                            "Action": "output",
                            "Test": test,
                            "Output": "ASTRA-CONTRACT " + pack({"contract": probe["contract"], "hits": probe["minimum_hits"]}).decode() + "\n",
                        }
                    )
            if test == "TestModel":
                # Supply only synthetic model frames so this negative check reaches the independent fault boundary.
                for kind, actions in command.domain():
                    events.append(
                        {
                            "Package": package,
                            "Action": "output",
                            "Test": test,
                            "Output": "ASTRA-COMMAND-MODEL "
                            + pack({"kind": kind, "history": actions, "states": command.history(actions, kind)}).decode()
                            + "\n",
                        }
                    )
            events.append({"Package": package, "Action": "pass", "Test": test})
        events.append({"Package": package, "Action": "pass"})
        data = b"".join(pack(item) + b"\n" for item in events)
        self.assertEqual(v.go_observations(data, check)[1], [])
        with self.assertRaisesRegex(v.Invalid, "fault-matrix"):
            v.parse_observations(data, check, ROOT, PROFILE)
        position = next(index for index, event in enumerate(events) if event.get("Test") == "TestFault" and event["Action"] == "pass")
        events[position:position] = [v.decode(line) for line in native(rows()).splitlines()]
        completed = b"".join(pack(item) + b"\n" for item in events)
        self.assertEqual(v.parse_observations(completed, check, ROOT, PROFILE)[1], [])

        frames, _ = allocation_rows("catalog")
        frames[1]["frozen"][1][0] = 2
        data = allocation_native(frames)
        self.assertEqual(v.case_observations(data, allocation_check())[1], [])
        with self.assertRaisesRegex(v.Invalid, "allocation-state"):
            v.parse_observations(data, allocation_check(), ROOT)

    def test_fixed_obligations(self) -> None:
        """Retain original obligations and require complete native denominators before broad coverage or fault admission."""
        config = v.decode(v.read(ROOT / "development.json"))
        obligations = v.expand(config)
        self.assertEqual(len(obligations), 1370)
        # Reverse only the separately pinned additions/migrations before checking every original object below.
        backup = v.decode(v.read(ROOT / "tests/fixtures/obligations-backup.json"))
        self.assertEqual(v.file_digest(ROOT / "tests/fixtures/obligations-backup.json"), "f46daf3460b1d2df3810d6adeb4321188e4b9090a5ff6524242e3bccdbc5a829")
        self.assertEqual(backup["version"], 1)
        self.assertEqual(backup["original_obligations"], 1361)
        self.assertEqual(len(backup["added"]), 9)
        self.assertEqual(sum(item["contract"].startswith("BENCHMARKS-GATES-") for item in backup["added"].values()), 7)
        self.assertEqual(
            {item["contract"] for item in backup["added"].values() if item["component"] == "polaris-storage"},
            {"STORAGE-BACKUP-ONLINE", "STORAGE-BACKUP-RESTORE"},
        )
        for name, expected in backup["added"].items():
            self.assertEqual(obligations.pop(name), expected)
        self.assertEqual(
            set(backup["migrations"]),
            {f"polaris-storage/{rule}/STORAGE-ASSURANCE/linux-amd64-cgo/full-rule" for rule in ("DEV-OPERATE", "DEV-RELEASE")},
        )
        for name, migration in backup["migrations"].items():
            self.assertEqual(obligations[name], migration["after"])
            self.assertEqual({key: value for key, value in migration["after"].items() if key != "requires"}, migration["before"])
            self.assertEqual(len(migration["after"]["requires"]), 1)
            obligations[name] = copy.deepcopy(migration["before"])
        self.assertEqual(len(obligations), 1361)
        # Approved Comet scope and partition controls extend, never replace, the protected historical policy.
        current = v.decode(v.read(ROOT / "tests/fixtures/obligations-comet.json"))
        self.assertEqual(v.file_digest(ROOT / "tests/fixtures/obligations-comet.json"), "bc171570d89d9221b35731e4537697e6da59b43ebddf93d61f0a686fbcb04369")
        self.assertEqual(len(current["added"]), 102)
        self.assertEqual(sum(item["component"] == "comet-go" for item in current["added"].values()), 96)
        for name, expected in current["added"].items():
            self.assertEqual(obligations.pop(name), expected)
        self.assertEqual(len(obligations), 1259)
        # Pin every later addition and exact changed object before recovering the protected historical denominator.
        evolution = v.decode(v.read(ROOT / "tests/fixtures/obligations-common.json"))
        self.assertEqual(v.file_digest(ROOT / "tests/fixtures/obligations-common.json"), "b257faa74a8e418c6af76767ac0b936ce65772592bac88a99dca0dd93abe32bb")
        self.assertEqual(len(evolution["added"]), 108)
        self.assertEqual(evolution["origin"]["historical_obligations"], 1151)
        for name, expected in evolution["added"].items():
            self.assertEqual(obligations.pop(name), expected)
        for name, migration in evolution["changed"].items():
            self.assertEqual(obligations[name], migration["after"])
            obligations[name] = copy.deepcopy(migration["before"])
        self.assertEqual(v.digest(v.encode(obligations)), evolution["origin"]["historical_sha256"])
        self.assertEqual(len(obligations), 1151)
        # Preserve the original hash while pinning every additional current obligation and prerequisite route.
        supplements = v.decode(v.read(ROOT / "tests/fixtures/obligations.json"))
        self.assertEqual(v.file_digest(ROOT / "tests/fixtures/obligations.json"), "fba322d85e355ce7ea2cb79ab9f2f9df31cbdf7092e3814e1229f4f1822b7257")
        self.assertEqual(len(supplements["added"]), 32)
        self.assertEqual(len(supplements["conjunctions"]), 3)
        for key, expected in supplements["added"].items():
            self.assertEqual(obligations[key], expected)
        windows = {"tools/DEV-CONTRACT/TOOLS-WINDOWS-ENV/windows-amd64/native-oracle"}
        self.assertEqual({key for key, item in obligations.items() if item["contract"] == "TOOLS-WINDOWS-ENV"}, windows)
        self.assertEqual(
            obligations[next(iter(windows))],
            {
                "checks": ["tools-windows-mutation-boundaries"],
                "contract": "TOOLS-WINDOWS-ENV",
                "platforms": ["windows-amd64"],
                "rule": "DEV-CONTRACT",
                "scenario": "native-oracle",
                "component": "tools",
                "platform": "windows-amd64",
            },
        )
        consumers = {
            "tools/DEV-EVIDENCE/DELIVERY-CONSUMERS/linux-amd64-cgo/native-oracle": "tools-python",
            "tools/DEV-EVIDENCE/DELIVERY-CONSUMERS/windows-amd64/native-oracle": "tools-windows",
        }
        self.assertEqual({key for key, item in obligations.items() if item["contract"] == "DELIVERY-CONSUMERS"}, set(consumers))
        for key, check in consumers.items():
            self.assertEqual(obligations[key]["checks"], [check])
        metrics = "astrolabe/DEV-CONTRACT/ASTROLABE-METRICS/linux-amd64-cgo/metrics-boundaries"
        self.assertEqual({key for key, item in obligations.items() if item["contract"] == "ASTROLABE-METRICS"}, {metrics})
        self.assertEqual(
            obligations[metrics],
            {
                "rule": "DEV-CONTRACT",
                "contract": "ASTROLABE-METRICS",
                "scenario": "metrics-boundaries",
                "checks": ["astrolabe-metrics"],
                "component": "astrolabe",
                "platform": "linux-amd64-cgo",
            },
        )
        entry = "astrolabe/DEV-CONTRACT/ASTROLABE-ENTRY/linux-amd64-cgo/entry-boundaries"
        self.assertEqual({key for key, item in obligations.items() if item["contract"] == "ASTROLABE-ENTRY"}, {entry})
        self.assertEqual(
            obligations[entry],
            {
                "rule": "DEV-CONTRACT",
                "contract": "ASTROLABE-ENTRY",
                "scenario": "entry-boundaries",
                "checks": ["astrolabe-entry", "astrolabe-process"],
                "component": "astrolabe",
                "platform": "linux-amd64-cgo",
            },
        )
        environment = {"VERIFY-ENV-NAMESPACE", "VERIFY-ENV-CHILD", "VERIFY-ENV-DECLARED"}
        native = {f"verification/DEV-CONTRACT/{name}/linux-amd64-cgo/native-oracle" for name in environment}
        self.assertEqual({key for key, item in obligations.items() if item["contract"] in environment}, native)
        for key in native:
            self.assertEqual(obligations[key]["checks"], ["verification-python"])
        names = {"DELIVERY-HEADER", "DELIVERY-LOADER", "DELIVERY-SEQUENCE", "DELIVERY-CONTENTS", "DELIVERY-EXPORT", "SOAK-INSTALLED"}
        added = {
            f"tools/DEV-CONTRACT/{name}/{platform}/native-oracle"
            for name in names
            for platform in ("linux-amd64-cgo", "windows-amd64")
            if platform == "linux-amd64-cgo" or name not in {"DELIVERY-CONTENTS", "DELIVERY-EXPORT"}
        }
        self.assertEqual({key for key, item in obligations.items() if item["contract"] in names}, added)
        pagination = {"star/DEV-CONTRACT/STAR_NATIVE-29/linux-amd64-cgo/native-oracle"}
        self.assertEqual({key for key, item in obligations.items() if item["contract"] == "STAR_NATIVE-29"}, pagination)
        self.assertEqual(obligations[next(iter(pagination))]["checks"], ["star-native"])
        page_fault = {"star/DEV-CONTRACT/STAR_NATIVE-30/linux-amd64-cgo/native-oracle"}
        self.assertEqual({key for key, item in obligations.items() if item["contract"] == "STAR_NATIVE-30"}, page_fault)
        self.assertEqual(obligations[next(iter(page_fault))]["checks"], ["star-native"])
        dispatch_fault = {"star/DEV-CONTRACT/STAR_NATIVE-31/linux-amd64-cgo/native-oracle"}
        self.assertEqual({key for key, item in obligations.items() if item["contract"] == "STAR_NATIVE-31"}, dispatch_fault)
        self.assertEqual(obligations[next(iter(dispatch_fault))]["checks"], ["star-native"])
        catalog_rpc = {"star/DEV-CONTRACT/STAR_NATIVE-32/linux-amd64-cgo/native-oracle"}
        self.assertEqual({key for key, item in obligations.items() if item["contract"] == "STAR_NATIVE-32"}, catalog_rpc)
        self.assertEqual(obligations[next(iter(catalog_rpc))]["checks"], ["star-native"])
        drain = {"polaris-server/DEV-CONTRACT/POLARIS-DRAIN/linux-amd64-cgo/boundary-oracle"}
        self.assertEqual({key for key, item in obligations.items() if item["contract"] == "POLARIS-DRAIN"}, drain)
        self.assertEqual(obligations[next(iter(drain))]["checks"], ["polaris-server-boundaries"])
        authentication = {
            f"comet/DEV-ASYNC/COMET-AUTH-{mode.upper()}/{platform}/login-{mode}"
            for mode in ("session", "input", "protocol")
            for platform in ("linux-amd64-cgo", "windows-amd64")
        }
        self.assertEqual({key for key, item in obligations.items() if item["contract"].startswith("COMET-AUTH-")}, authentication)
        for key in authentication:
            self.assertEqual(obligations[key]["checks"], ["comet-windows" if "/windows-amd64/" in key else "comet-native"])
        baseline = copy.deepcopy(
            {
                key: item
                for key, item in obligations.items()
                if key
                not in added
                | native
                | pagination
                | page_fault
                | dispatch_fault
                | catalog_rpc
                | authentication
                | windows
                | drain
                | set(consumers)
                | {entry, metrics}
                | set(supplements["added"])
            }
        )
        self.assertEqual(len(baseline), 1090)
        for key, migration in supplements["conjunctions"].items():
            self.assertEqual(baseline[key], migration["after"])
            baseline[key] = copy.deepcopy(migration["before"])
        web = next(key for key, item in baseline.items() if item["contract"] == "ASTROLABE-BOUNDARY")
        self.assertEqual(baseline[web]["checks"], ["astrolabe-boundaries", "astrolabe-web"])
        baseline[web]["checks"] = ["astrolabe-boundaries"]
        # Restore only exact implemented executor routes; every original qualification object remains fixed.
        server = "polaris-server/DEV-COVERAGE/POLARIS_SERVER-ASSURANCE/linux-amd64-cgo/structure"
        self.assertEqual({key for key, item in obligations.items() if "server-structure" in item["checks"]}, {server})
        self.assertEqual(baseline[server]["checks"], ["server-structure", "polaris-entry-qualification"])
        baseline[server]["checks"] = ["polaris-server-qualification"]
        independent = "polaris-server/DEV-COVERAGE/POLARIS_SERVER-ASSURANCE/linux-amd64-cgo/mcdc"
        self.assertEqual({key for key, item in obligations.items() if "server-independence" in item["checks"]}, {independent})
        self.assertEqual(baseline[independent]["checks"], ["server-independence", "polaris-entry-qualification"])
        baseline[independent]["checks"] = ["polaris-server-qualification"]
        for scenario, check in (("structure", "astrolabe-structure"), ("mcdc", "astrolabe-independence")):
            key = f"astrolabe/DEV-COVERAGE/ASTROLABE-ASSURANCE/linux-amd64-cgo/{scenario}"
            self.assertEqual({name for name, item in obligations.items() if check in item["checks"]}, {key})
            self.assertEqual(baseline[key]["checks"], [check])
            baseline[key]["checks"] = ["astrolabe-qualification"]
        admission = "admission/DEV-COVERAGE/ADMISSION-ASSURANCE/linux-amd64-cgo/mcdc"
        self.assertEqual({key for key, item in obligations.items() if "admission-independence" in item["checks"]}, {admission})
        self.assertEqual(baseline[admission]["checks"], ["admission-independence"])
        baseline[admission]["checks"] = ["admission-gap-mcdc"]
        security = "admission/DEV-ORACLE/ADMISSION-NODE-SENSITIVITY/linux-amd64-cgo/targeted-mutations"
        self.assertEqual({key for key, item in obligations.items() if "admission-security-mutants" in item["checks"]}, {security})
        self.assertEqual(baseline[security]["checks"], ["admission-mutants", "admission-security-mutants", "admission-acquisition-mutants"])
        baseline[security]["checks"] = ["admission-mutants"]
        mutation = "admission/DEV-COVERAGE/ADMISSION-ASSURANCE/linux-amd64-cgo/mutation"
        self.assertEqual(v.digest(v.encode(baseline[mutation])), "eb15e9646ae2da7efaf36dfd945b69f7442f1d78f84a06cf7c87fffb6b9575b8")
        baseline[mutation].pop("aggregate")
        baseline[mutation].pop("requires")
        baseline[mutation]["checks"] = ["admission-gap-mutation"]
        fault = "admission/DEV-FAULT/ADMISSION-ASSURANCE/linux-amd64-cgo/fault-matrix"
        self.assertEqual(v.digest(v.encode(baseline[fault])), "238a5e0ab17e19081b46ee6cd911a0542565f18587611da82bdb019ed895d760")
        baseline[fault].pop("aggregate")
        baseline[fault].pop("requires")
        baseline[fault]["checks"] = ["admission-gap-fault-matrix"]
        refresh = "admission/DEV-CONTRACT/ADMISSION-NODE-REFRESH/linux-amd64-cgo/refresh-receipts"
        self.assertEqual({key for key, item in obligations.items() if "admission-refresh-faults" in item["checks"]}, {refresh})
        self.assertEqual(baseline[refresh]["checks"], ["admission-model", "admission-refresh-faults"])
        baseline[refresh]["checks"] = ["admission-model"]
        moved = {f"tools/DEV-CONTRACT/TOOLS_PYTHON-{number}/windows-amd64/native-oracle" for number in (18, 62)}
        self.assertEqual({key for key, item in obligations.items() if "tools-windows-mutation-boundaries" in item["checks"]}, moved | windows)
        for key in moved:
            self.assertEqual(baseline[key]["checks"], ["tools-windows-mutation-boundaries"])
            baseline[key]["checks"] = ["tools-windows-linux-boundaries"]
        finite = "common/DEV-MODEL/COMMON-ASSURANCE/linux-amd64-cgo/finite-model"
        self.assertEqual({key for key, item in obligations.items() if "common-finite-model" in item["checks"]}, {finite})
        self.assertEqual(baseline[finite]["checks"], ["common-finite-model"])
        baseline[finite]["checks"] = ["common-qualification"]
        finite = "pulsar/DEV-MODEL/PULSAR-ASSURANCE/linux-amd64-cgo/finite-model"
        self.assertEqual({key for key, item in obligations.items() if "pulsar-finite-model" in item["checks"]}, {finite})
        self.assertEqual(baseline[finite]["checks"], ["pulsar-finite-model"])
        baseline[finite]["checks"] = ["pulsar-qualification"]
        finite = "star/DEV-MODEL/STAR-ASSURANCE/linux-amd64-cgo/finite-model"
        for identifier in ("almanac-finite-model", "catalog-finite-model", "ephemeris-finite-model"):
            self.assertEqual({key for key, item in obligations.items() if identifier in item["checks"]}, {finite})
        self.assertEqual(baseline[finite]["checks"], ["almanac-finite-model", "catalog-finite-model", "ephemeris-finite-model"])
        self.assertEqual(obligations["star/DEV-MODEL/STAR-ASSURANCE/linux-amd64-cgo/full-rule"]["checks"], ["star-qualification"])
        baseline[finite]["checks"] = ["star-qualification"]
        # Only these five explicitly implemented proof routes may differ from the original full-rule objects.
        prerequisites = [
            {"rule": rule, "contract": "COMMAND-ASSURANCE", "scenario": "full-rule"}
            for rule in ("DEV-CORE", "DEV-COVERAGE", "DEV-FAULT", "DEV-ASYNC", "DEV-NUMERIC", "DEV-MODEL")
        ]
        for rule in ("DEV-ORACLE", "DEV-REPLAY", "DEV-MATRIX", "DEV-IMPACT", "DEV-AUDIT"):
            key = f"command/{rule}/COMMAND-ASSURANCE/linux-amd64-cgo/full-rule"
            self.assertTrue(baseline[key]["aggregate"])
            self.assertEqual(baseline[key]["checks"], [])
            self.assertEqual(baseline[key]["requires"], prerequisites)
            baseline[key].pop("aggregate")
            baseline[key].pop("requires")
            baseline[key]["checks"] = ["command-qualification"]
        compatibility = "command/DEV-COMPAT/COMMAND-ASSURANCE/linux-amd64-cgo/full-rule"
        self.assertEqual(baseline[compatibility]["checks"], ["command-boundaries", "command-structure-race"])
        self.assertEqual(baseline[compatibility]["requires"], prerequisites)
        self.assertNotIn("aggregate", baseline[compatibility])
        baseline[compatibility].pop("requires")
        baseline[compatibility]["checks"] = ["command-qualification"]
        checks = v.unique(config["checks"])
        self.assertEqual(checks["tools-windows-mutation-boundaries"]["adapter"], "observed-cases")
        self.assertEqual(
            {probe["contract"] for probe in checks["tools-windows-mutation-boundaries"]["probes"]}, {"TOOLS_PYTHON-18", "TOOLS_PYTHON-62", "TOOLS-WINDOWS-ENV"}
        )
        self.assertEqual(checks["tools-windows-linux-boundaries"]["adapter"], "observed-cases")
        self.assertEqual(
            {probe["contract"] for probe in checks["tools-windows-linux-boundaries"]["probes"]}, {f"TOOLS_PYTHON-{number}" for number in (45, 46, 47, 48)}
        )
        lifecycle = {
            key: item
            for key, item in baseline.items()
            if item["component"] == "admission" and item["scenario"] == "full-rule" and item["rule"] in {"DEV-ASYNC", "DEV-TIME", "DEV-RETRY", "DEV-STOP"}
        }
        self.assertEqual(len(lifecycle), 4)
        self.assertEqual(v.digest(v.encode(lifecycle)), "d80320919e2e4284b532c7cabbb6dac27447e8dc4cf5ee107e9b48a18ad8de33")
        for item in lifecycle.values():
            self.assertEqual(item.pop("aggregate"), True)
            self.assertTrue(item.pop("requires"))
            self.assertEqual(item["checks"], [])
            item["checks"] = ["admission-gap-" + item["rule"][4:].lower()]
        composed = {
            key: item
            for key, item in baseline.items()
            if item["component"] != "command"
            and item["scenario"] == "full-rule"
            and item["rule"] in {"DEV-COVERAGE", "DEV-FAULT", "DEV-MATRIX"}
            and item.get("aggregate")
        }
        self.assertEqual(len(composed), 46)
        # Pin the entire reviewed conjunction graph before normalizing its old placeholder executors.
        self.assertEqual(v.digest(v.encode(composed)), "996f31208da6dc69e99cac6be714b30ab7f6c26692f3d0f4a11d9917e6f3aed2")
        for item in composed.values():
            self.assertEqual(item.pop("aggregate"), True)
            self.assertTrue(item.pop("requires"))
            self.assertEqual(item["checks"], [])
            if item["component"] in {"polaris-storage", "admission"}:
                prefix = "admission-" if item["component"] == "admission" else ""
                item["checks"] = [prefix + "gap-" + item["rule"][4:].lower()]
            else:
                item["checks"] = [item["component"] + "-qualification"]
        # Pin the complete original objects so equal-size substitutions cannot weaken the fault requirements.
        self.assertEqual(v.digest(v.encode(baseline)), "f69ee35f47ca9001bdecb12baf0fa6d66cc839951923b8404499dd946306f827")
        for key in added:
            item = obligations[key]
            self.assertEqual(item["checks"], ["tools-python" if item["platform"] == "linux-amd64-cgo" else "tools-windows"])
        wal = "polaris-storage/DEV-FAULT/STORAGE-BOUNDARY/linux-amd64-cgo/native-wal-write-sync"
        self.assertEqual(obligations[wal]["checks"], ["storage-io"])
        command_proofs = {key for key, item in obligations.items() if item["contract"].startswith(("COMMAND-NUMERIC", "COMMAND-MODEL"))}
        self.assertEqual(
            command_proofs,
            {
                "command/DEV-NUMERIC/COMMAND-NUMERIC/linux-amd64-cgo/typed-source",
                "command/DEV-ORACLE/COMMAND-NUMERIC-CONTROLS/linux-amd64-cgo/typed-controls",
                "command/DEV-MODEL/COMMAND-MODEL/linux-amd64-cgo/finite-history",
                "command/DEV-ORACLE/COMMAND-MODEL-CONTROLS/linux-amd64-cgo/model-vectors",
            },
        )
        logs = {key for key, item in obligations.items() if item["contract"].startswith("PULSAR-LOG-")}
        self.assertEqual(
            logs,
            {
                f"tools/DEV-EVIDENCE/PULSAR-LOG-{name}/{platform}/native-oracle"
                for name in ("SUCCESS", "FAILURE", "COLLECTION", "PRIMARY")
                for platform in ("linux-amd64-cgo", "windows-amd64")
            },
        )
        typed = {key for key, value in obligations.items() if value["contract"] in {"GO-LOGIC-TYPING", "GO-LOGIC-TYPE-INTEGRITY", "GO-LOGIC-TYPE-BUNDLE"}}
        self.assertEqual(
            typed,
            {
                f"verification/DEV-EVIDENCE/{name}/linux-amd64-cgo/native-oracle"
                for name in ("GO-LOGIC-TYPING", "GO-LOGIC-TYPE-INTEGRITY", "GO-LOGIC-TYPE-BUNDLE")
            },
        )
        nodes = {key for key, value in obligations.items() if value["contract"].startswith("ADMISSION-NODE-")}
        self.assertEqual(
            nodes,
            {
                f"admission/{rule}/ADMISSION-NODE-{name}/linux-amd64-cgo/{scenario}"
                for name, rule, scenario in (
                    ("OPEN", "DEV-CONTRACT", "construction"),
                    ("STATE", "DEV-ASYNC", "message-ownership"),
                    ("REGISTER", "DEV-RETRY", "registration-receipts"),
                    ("REFRESH", "DEV-CONTRACT", "refresh-receipts"),
                    ("SCHEDULE", "DEV-ASYNC", "admission-overlap"),
                    ("RETRY", "DEV-RETRY", "registration-step-time"),
                    ("RUN", "DEV-TIME", "refresh-step-time"),
                    ("PAUSE", "DEV-TIME", "native-timer"),
                    ("TRANSPORT", "DEV-MATRIX", "tls-generated-rpc"),
                    ("SENSITIVITY", "DEV-ORACLE", "targeted-mutations"),
                    ("RESOLVER", "DEV-FAULT", "client-construction"),
                    ("FINITE", "DEV-MODEL", "loop-state-domain"),
                    ("TRANSITIONS", "DEV-MODEL", "publication-state-domain"),
                    ("DRAIN", "DEV-ASYNC", "native-cancellation"),
                )
            },
        )
        boundaries = {
            key
            for key, value in obligations.items()
            if value["contract"] in {"ADMISSION-DIRECTORY-BOUNDARIES", "ADMISSION-IDENTITY-RULES", "ADMISSION-IDENTITY-FILES", "ADMISSION-IDENTITY-FAULT"}
        }
        self.assertEqual(
            boundaries,
            {
                "admission/DEV-CONTRACT/ADMISSION-DIRECTORY-BOUNDARIES/linux-amd64-cgo/directory-boundaries",
                "admission/DEV-SECURITY/ADMISSION-IDENTITY-RULES/linux-amd64-cgo/identity-inputs",
                "admission/DEV-FAULT/ADMISSION-IDENTITY-FILES/linux-amd64-cgo/native-identity-files",
                "admission/DEV-FAULT/ADMISSION-IDENTITY-FAULT/linux-amd64-cgo/file-response-matrix",
            },
        )
        material = {key for key, value in obligations.items() if value["contract"].startswith("GO-MATERIAL-")}
        self.assertEqual(
            material,
            {
                f"verification/{rule}/GO-MATERIAL-{name}/linux-amd64-cgo/native-oracle"
                for name, rule in (
                    ("CONFIG", "DEV-GATE"),
                    ("AXIOMS", "DEV-ORACLE"),
                    ("MATRIX", "DEV-ORACLE"),
                    ("STREAM", "DEV-EVIDENCE"),
                    ("SOURCE", "DEV-EVIDENCE"),
                )
            },
        )
        equality = {
            key
            for key, value in obligations.items()
            if value["contract"].startswith("GO-EQUALITY-") or value["contract"] in {"ADMISSION-SAME", "ADMISSION-SAME-SENSITIVITY"}
        }
        self.assertEqual(
            equality,
            {
                "admission/DEV-COVERAGE/ADMISSION-SAME/linux-amd64-cgo/member-equality",
                "admission/DEV-ORACLE/ADMISSION-SAME-SENSITIVITY/linux-amd64-cgo/member-equality-mutations",
                *{
                    f"verification/{rule}/GO-EQUALITY-{name}/linux-amd64-cgo/native-oracle"
                    for name, rule in (
                        ("CONFIG", "DEV-GATE"),
                        ("AXIOMS", "DEV-ORACLE"),
                        ("PAIRS", "DEV-ORACLE"),
                        ("STREAM", "DEV-EVIDENCE"),
                        ("SOURCE", "DEV-EVIDENCE"),
                    )
                },
            },
        )
        conflicts = {
            key for key, value in obligations.items() if value["contract"] in {"ADMISSION-CONFLICTS", "ADMISSION-CREDENTIALS", "ADMISSION-CONFLICT-SENSITIVITY"}
        }
        self.assertEqual(
            conflicts,
            {
                "admission/DEV-CONTRACT/ADMISSION-CONFLICTS/linux-amd64-cgo/identity-conflicts",
                "admission/DEV-SECURITY/ADMISSION-CREDENTIALS/linux-amd64-cgo/signed-boundaries",
                "admission/DEV-ORACLE/ADMISSION-CONFLICT-SENSITIVITY/linux-amd64-cgo/directory-boundary-mutations",
            },
        )
        loops = {key for key, value in obligations.items() if value["contract"] == "ADMISSION-LOOP-SENSITIVITY"}
        self.assertEqual(loops, {"admission/DEV-ORACLE/ADMISSION-LOOP-SENSITIVITY/linux-amd64-cgo/node-loop-mutations"})
        models = {key for key, value in obligations.items() if value["contract"].startswith("GO-ADMISSION-MODEL-")}
        self.assertEqual(
            models,
            {
                f"verification/{rule}/GO-ADMISSION-MODEL-{name}/linux-amd64-cgo/native-oracle"
                for name, rule in (
                    ("CONFIG", "DEV-GATE"),
                    ("AXIOMS", "DEV-ORACLE"),
                    ("DOMAIN", "DEV-ORACLE"),
                    ("HISTORIES", "DEV-ORACLE"),
                    ("STREAM", "DEV-EVIDENCE"),
                    ("SOURCE", "DEV-EVIDENCE"),
                    ("GATE", "DEV-GATE"),
                )
            },
        )
        predicates = {
            key
            for key, value in obligations.items()
            if value["contract"].startswith("GO-PREDICATES-") or value["contract"] in {"ADMISSION-PREDICATES", "ADMISSION-PREDICATE-SENSITIVITY"}
        }
        self.assertEqual(
            predicates,
            {
                "admission/DEV-COVERAGE/ADMISSION-PREDICATES/linux-amd64-cgo/identity-format-pairs",
                "admission/DEV-ORACLE/ADMISSION-PREDICATE-SENSITIVITY/linux-amd64-cgo/identity-format-mutations",
                *{
                    f"verification/{rule}/GO-PREDICATES-{name}/linux-amd64-cgo/native-oracle"
                    for name, rule in (
                        ("CONFIG", "DEV-GATE"),
                        ("AXIOMS", "DEV-ORACLE"),
                        ("PAIRS", "DEV-ORACLE"),
                        ("STREAM", "DEV-EVIDENCE"),
                        ("SOURCE", "DEV-EVIDENCE"),
                    )
                },
            },
        )
        numeric = {
            key
            for key, value in obligations.items()
            if value["contract"].startswith("GO-NUMERIC-")
            or value["contract"].startswith("GATE-AGGREGATE")
            or value["contract"] in {"ADMISSION-NUMERIC", "ADMISSION-NUMERIC-SENSITIVITY"}
        }
        self.assertEqual(
            numeric,
            {
                "admission/DEV-NUMERIC/ADMISSION-NUMERIC/linux-amd64-cgo/integer-boundaries",
                "admission/DEV-ORACLE/ADMISSION-NUMERIC-SENSITIVITY/linux-amd64-cgo/integer-mutations",
                *{
                    f"verification/{rule}/GO-NUMERIC-{name}/linux-amd64-cgo/native-oracle"
                    for name, rule in (
                        ("CONFIGURATION", "DEV-GATE"),
                        ("AXIOMS", "DEV-ORACLE"),
                        ("WITNESSES", "DEV-ORACLE"),
                        ("STREAM", "DEV-EVIDENCE"),
                        ("SOURCE", "DEV-EVIDENCE"),
                        ("GATE", "DEV-GATE"),
                    )
                },
                *{f"verification/DEV-GATE/GATE-{name}/linux-amd64-cgo/native-oracle" for name in ("AGGREGATE", "AGGREGATE-SHAPE", "AGGREGATE-SCHEMA")},
            },
        )
        draining = {
            key for key, value in obligations.items() if value["contract"] in {"ADMISSION-NODE-DRAIN", "ADMISSION-DRAIN-SENSITIVITY", "GO-ADMISSION-FULL"}
        }
        self.assertEqual(
            draining,
            {
                "admission/DEV-ASYNC/ADMISSION-NODE-DRAIN/linux-amd64-cgo/native-cancellation",
                "admission/DEV-ORACLE/ADMISSION-DRAIN-SENSITIVITY/linux-amd64-cgo/cancellation-mutations",
                "verification/DEV-GATE/GO-ADMISSION-FULL/linux-amd64-cgo/native-oracle",
            },
        )
        isolation = {key for key, value in obligations.items() if value["contract"] == "COMMAND-ISOLATION"}
        self.assertEqual(isolation, {"command/DEV-CORE/COMMAND-ISOLATION/linux-amd64-cgo/effect-boundary"})
        self.assertEqual(
            len(
                set(obligations)
                - typed
                - nodes
                - boundaries
                - material
                - equality
                - conflicts
                - loops
                - models
                - predicates
                - numeric
                - draining
                - logs
                - isolation
                - command_proofs
                - added
                - native
                - pagination
                - page_fault
                - dispatch_fault
                - catalog_rpc
                - authentication
                - windows
                - drain
                - set(consumers)
                - {wal}
                - {entry, metrics}
                - set(supplements["added"])
            ),
            1012,
        )
        key = "command/DEV-FAULT/COMMAND-ASSURANCE/linux-amd64-cgo/"
        self.assertEqual(obligations[key + "fault-matrix"]["checks"], ["command-boundaries", "command-structure-race"])
        self.assertEqual(obligations[key + "full-rule"]["checks"], ["command-boundaries", "command-structure-race"])
        self.assertEqual(
            obligations[key + "full-rule"]["requires"],
            [
                {"rule": "DEV-COVERAGE", "contract": "COMMAND-ASSURANCE", "scenario": "structure"},
                {"rule": "DEV-FAULT", "contract": "COMMAND-FAULT", "scenario": "fault-observations"},
            ],
        )
        self.assertEqual(
            obligations["command/DEV-COVERAGE/COMMAND-ASSURANCE/linux-amd64-cgo/full-rule"]["requires"],
            [
                {"rule": "DEV-COVERAGE", "contract": "COMMAND-ASSURANCE", "scenario": "structure"},
                {"rule": "DEV-COVERAGE", "contract": "COMMAND-MCDC", "scenario": "mcdc"},
                {"rule": "DEV-COVERAGE", "contract": "COMMAND-DECISION-INVENTORY", "scenario": "mcdc-inventory"},
                {"rule": "DEV-COVERAGE", "contract": "COMMAND-MUTATION", "scenario": "mutation"},
            ],
        )
        self.assertEqual(obligations["command/DEV-GATE/COMMAND-ASSURANCE/linux-amd64-cgo/full-rule"]["checks"], ["command-qualification"])
        self.assertEqual(
            obligations["command/DEV-FAULT/COMMAND-FAULT/linux-amd64-cgo/fault-observations"]["checks"], ["command-boundaries", "command-structure-race"]
        )


if __name__ == "__main__":
    unittest.main()
