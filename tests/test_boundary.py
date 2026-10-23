"""Challenge Common gate framing and case attribution; all constructed streams are parser controls, not product evidence."""

from collections.abc import Iterable, Iterator
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from tools import boundary, junit, store
from tools import verify as v

ROOT = Path(__file__).resolve().parents[1]


def configuration() -> dict:
    """Read the actual whole-Common command rather than reducing its native selection for these tests."""
    return next(item for item in v.decode(v.read(ROOT / "development.json"))["checks"] if item["id"] == "common-native")


def frames(prefix: str, names: Iterable[str]) -> str:
    """Encode a bounded synthetic sequence with an explicit typed terminal."""
    return "".join(prefix + json.dumps({"case": name}, separators=(",", ":")) + "\n" for name in names) + prefix + '{"complete":true}\n'


def case(name: str, text: str, hits: int) -> ET.Element:
    """Create one synthetic owning testcase with exactly one assertion receipt."""
    result = ET.Element("testcase", name=name, status="run")
    ET.SubElement(result, "system-out").text = text + "ASTRA-CHECKS " + json.dumps({"hits": hits}, separators=(",", ":")) + "\n"
    return result


def stream(suite: ET.Element) -> bytes:
    """Use the production bounded CTest envelope while retaining synthetic provenance in the test."""
    selected = [item.get("name") for item in suite]
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    result = b"ASTRA-OBSERVE " + encode({"event": "start", "engine": "ctest"}) + b"\n"
    result += b"ASTRA-CTEST " + encode(junit.payload(ET.tostring(suite, encoding="utf-8"), selected)) + b"\n"
    observations = junit.cases(suite)
    for name in selected:
        result += b"ASTRA-OBSERVE " + encode({"event": "begin", "test": name}) + b"\n"
        result += b"ASTRA-OBSERVE " + encode({"event": "end", "test": name, **observations[name]}) + b"\n"
    return result + b"ASTRA-OBSERVE " + encode({"event": "complete", "cases": len(selected)}) + b"\n"


class BoundaryTests(unittest.TestCase):
    """Keep complete frames, actual assertion counts and the Store reference domain conjunctive."""

    @classmethod
    def setUpClass(cls) -> None:
        """Construct the finite parser fixture once; reference-model axioms remain in ModelTests."""
        cls.rows = [{"model": "store-state-v1", "event": "start", "value": store.DOMAIN}]
        cls.hits = 1
        for ordinal in range(4096):
            state, frozen, states = store.State(), [], []
            remaining = ordinal
            for _ in range(4):
                value, count = store.transition(state, frozen, remaining % 8)
                remaining //= 8
                states.append(value)
                cls.hits += count
            cls.rows.append({"model": "store-state-v1", "event": "history", "value": {"ordinal": ordinal, "states": states}})
        cls.rows.append({"model": "store-state-v1", "event": "finish", "value": {"histories": 4096, "transitions": 16384}})
        cls.model = "".join("ASTRA-MODEL " + json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in cls.rows)

    def suite(self) -> ET.Element:
        """Populate each declared native owner; no neighboring output supplies the selected case's frames."""
        suite = ET.Element("testsuite")
        for name in boundary.REGRESSION:
            text, hits = "", 1
            if name in boundary.DOMAINS:
                prefix, names = boundary.DOMAINS[name]
                text, hits = frames(prefix, names), {boundary.CASE: 1605, "cpp_core": 100, "cpp_store_fault": 57254}[name]
            elif name == "cpp_store_model":
                text, hits = self.model, self.hits
            suite.append(case(name, text, hits))
        return suite

    def document(self, text: str | None = None, hits: int = 1605) -> ET.Element:
        """Build only the owning boundary XML for fast framing/refusal controls."""
        suite = ET.Element("testsuite")
        suite.append(case(boundary.CASE, frames(boundary.PREFIX, boundary.NAMES) if text is None else text, hits))
        return suite

    def test_domain(self) -> None:
        """Anchor every current scenario identity independently of the parser's own table."""
        expected = (
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
        self.assertEqual(boundary.NAMES, expected)
        self.assertEqual(len(set(expected)), 42)
        self.assertEqual(len(boundary.REGRESSION), 16)
        result, rows = boundary.document(self.document())
        self.assertEqual(result, {"domain": {"cases": 42, "complete": True}, "observed": {"status": "passed", "hits": 1605}})
        self.assertEqual(rows[-1], {"complete": True})
        self.assertEqual(boundary.SNAPSHOTS, ("cache", "failure", "replacement", "failure-replacement", "exhaustion", "segment"))
        self.assertEqual(boundary.DOMAINS["cpp_store_fault"], ("COMMON-SNAPSHOT ", boundary.SNAPSHOTS))
        self.assertEqual(boundary.MINIMUM["cpp_store_fault"], 57254)
        snapshot = ET.Element("testsuite")
        snapshot.append(case("cpp_store_fault", frames("COMMON-SNAPSHOT ", boundary.SNAPSHOTS), 57254))
        result, rows = boundary.document(snapshot, "cpp_store_fault")
        self.assertEqual(result, {"domain": {"cases": 6, "complete": True}, "observed": {"status": "passed", "hits": 57254}})
        self.assertEqual(
            rows, [{"case": name} for name in ("cache", "failure", "replacement", "failure-replacement", "exhaustion", "segment")] + [{"complete": True}]
        )

    def test_frames(self) -> None:
        """Reject empty, omitted, reordered, repeated, foreign and incorrectly typed domains."""
        original = [{"case": name} for name in boundary.NAMES] + [{"complete": True}]
        damaged = [
            [],
            original[:-1],
            original + original,
            original[:4] + original[5:],
            original[1:2] + original[:1] + original[2:],
            [{"case": "foreign"}] + original[1:],
            original[:-1] + [{"complete": 1}],
            original[:-1] + [{"complete": False}],
            original[:-1] + [{"complete": True, "extra": 1}],
        ]
        for rows in damaged:
            with self.subTest(rows=len(rows)), self.assertRaises(v.Invalid):
                boundary.frames(rows)
        with self.assertRaisesRegex(v.Invalid, "platform-reader-case"):
            boundary.frames(original, "cpp_foreign")
        snapshots = [{"case": name} for name in ("cache", "failure", "replacement", "failure-replacement", "exhaustion", "segment")] + [{"complete": True}]
        for rows in (
            [],
            snapshots[:-1],
            snapshots + snapshots,
            snapshots[:1] + snapshots[2:],
            snapshots[1:2] + snapshots[:1] + snapshots[2:],
            [{"case": "foreign"}] + snapshots[1:],
            snapshots[:-1] + [{"complete": 1}],
            snapshots[:-1] + [{"complete": False}],
            snapshots[:-1] + [{"complete": True, "extra": 1}],
        ):
            with self.subTest(snapshot_rows=len(rows)), self.assertRaises(v.Invalid):
                boundary.frames(rows, "cpp_store_fault")

    def test_documents(self) -> None:
        """Reject scalar-only successes, undercounts and malformed or partial native lines."""
        valid = frames(boundary.PREFIX, boundary.NAMES)
        for text, hits in [
            ("", 1605),
            (valid, 1604),
            (valid, 0),
            (valid[:-1], 1605),
            (valid.replace(boundary.PREFIX, " " + boundary.PREFIX, 1), 1605),
            (valid.replace('{"case":"elapsed-native"}', '{"case":"elapsed-native","case":"elapsed-native"}', 1), 1605),
        ]:
            with self.subTest(hits=hits, text=len(text)), self.assertRaises(v.Invalid):
                boundary.document(self.document(text, hits))
        wrong = self.document()
        wrong[0].set("name", "cpp_core")
        with self.assertRaises(v.Invalid):
            boundary.document(wrong)
        valid = frames("COMMON-SNAPSHOT ", ("cache", "failure", "replacement", "failure-replacement", "exhaustion", "segment"))
        for text, hits in (("", 57254), (valid, 57253), (valid, 0), (valid[:-1], 57254), (valid.replace("COMMON-SNAPSHOT ", " COMMON-SNAPSHOT ", 1), 57254)):
            value = ET.Element("testsuite")
            value.append(case("cpp_store_fault", text, hits))
            with self.subTest(snapshot_hits=hits, text=len(text)), self.assertRaises(v.Invalid):
                boundary.document(value, "cpp_store_fault")

    def test_terminal(self) -> None:
        """Failed/skipped cases, duplicate output and sanitizer diagnostics cannot qualify a complete sequence."""
        for name in (boundary.CASE, "cpp_store_fault"):
            for kind in ("failure", "error", "skipped", "status", "duplicate", "sanitizer"):
                value = self.document()
                if name == "cpp_store_fault":
                    value = ET.Element("testsuite")
                    value.append(
                        case(name, frames("COMMON-SNAPSHOT ", ("cache", "failure", "replacement", "failure-replacement", "exhaustion", "segment")), 57254)
                    )
                if kind in {"failure", "error", "skipped"}:
                    ET.SubElement(value[0], kind)
                elif kind == "status":
                    value[0].set("status", "fail")
                elif kind == "duplicate":
                    value[0].append(copy.deepcopy(value[0].find("system-out")))
                else:
                    value[0].find("system-out").text += "runtime error: synthetic parser control\n"
                with self.subTest(owner=name, kind=kind), self.assertRaises(v.Invalid):
                    boundary.document(value, name)

    def test_configuration(self) -> None:
        """Reject capability, command, selection, platform, resource and probe weakening."""
        original = configuration()
        boundary.configuration(original)
        damaged = []
        for key, value in (
            ("boundaries", "foreign"),
            ("component", "star"),
            ("id", "foreign"),
            ("platforms", ["windows-amd64"]),
            ("expected_tests", original["expected_tests"][:-1]),
            ("timeout_s", 7200),
            ("log_bytes", 64 * 1024**2),
            ("environment", {"EXTRA": "1"}),
        ):
            damaged.append({**original, key: value})
        value = copy.deepcopy(original)
        value["argv"][-1] = "--case=cpp_foreign"
        damaged.append(value)
        for minimum in (1, 1604, 1605.0):
            value = copy.deepcopy(original)
            next(item for item in value["probes"] if item["test"] == boundary.CASE)["minimum_hits"] = minimum
            damaged.append(value)
        value = copy.deepcopy(original)
        value["probes"].append(copy.deepcopy(value["probes"][-1]))
        damaged.append(value)
        damaged.append({key: value for key, value in original.items() if key != "boundaries"})
        for value in damaged:
            with self.subTest(keys=list(value)), self.assertRaises(v.Invalid):
                boundary.configuration(value)
        self.assertEqual(len(original["expected_tests"]), 16)

    def test_schema(self) -> None:
        """The closed schema admits only the declared boundary capability on observed native cases."""
        value = configuration()
        v.schema(value, "development", ("properties", "checks", "items"))
        for key, data in (("boundaries", "unknown"), ("boundaries", True), ("boundary", "common-native-v1")):
            with self.subTest(key=key, data=data), self.assertRaises(v.Invalid):
                v.schema({**value, key: data}, "development", ("properties", "checks", "items"))
        with self.assertRaises(v.Invalid):
            v.schema({key: item for key, item in value.items() if key != "boundaries"}, "development", ("properties", "checks", "items"))
        self.assertEqual(value["boundaries"], "common-native-v1")

    def test_projection(self) -> None:
        """Native case selection is complete and one owner's frames cannot be borrowed by another."""
        value = configuration()
        observed = boundary.observations(stream(self.suite()), value)
        self.assertEqual(observed, {"COMMON_NATIVE-16": 1605, "COMMON_NATIVE-2": 100, "COMMON_NATIVE-5": 57254, "COMMON-MODEL": self.hits})
        for name in (boundary.CASE, "cpp_core", "cpp_store_fault", "cpp_store_model"):
            suite = self.suite()
            owner = next(item for item in suite if item.get("name") == name)
            neighbor = next(item for item in suite if item.get("name") == "cpp_clock")
            neighbor.find("system-out").text += "".join(
                line for line in owner.find("system-out").text.splitlines(keepends=True) if not line.startswith("ASTRA-CHECKS ")
            )
            owner.find("system-out").text = 'ASTRA-CHECKS {"hits":1605}\n'
            with self.subTest(owner=name), self.assertRaises(v.Invalid):
                boundary.observations(stream(suite), value)

    def test_model(self) -> None:
        """The extracted replay retains the full Store domain and exact original public-state comparisons."""
        self.assertEqual(store.replay(self.rows), self.hits)
        for kind in ("empty", "truncated", "duplicate", "ordinal", "state", "terminal"):
            rows = list(self.rows)
            if kind == "empty":
                rows = []
            elif kind == "truncated":
                rows.pop()
            elif kind == "duplicate":
                rows.insert(1, rows[1])
            else:
                index = -1 if kind == "terminal" else 1
                rows[index] = copy.deepcopy(rows[index])
                if kind == "ordinal":
                    rows[index]["value"]["ordinal"] = 1
                elif kind == "state":
                    rows[index]["value"]["states"][0]["version"] = 999
                else:
                    rows[index]["value"]["histories"] = 4095
            with self.subTest(kind=kind), self.assertRaises(v.Invalid):
                store.replay(rows)

    def test_dispatch(self) -> None:
        """The actual evaluator invokes boundary verification and refuses disagreeing projected counts."""
        value, data = configuration(), stream(self.suite())
        with patch.object(boundary, "observations", wraps=boundary.observations) as observe:
            result, failures = v.parse_observations(data, value)
        self.assertFalse(failures)
        self.assertEqual(observe.call_count, 1)
        self.assertEqual(result["COMMON_NATIVE-16"], 1605)
        with self.assertRaises(v.Invalid):
            v.parse_observations(data, {key: item for key, item in value.items() if key != "boundaries"})
        for contract, count in (("COMMON_NATIVE-16", 1606), ("COMMON_NATIVE-2", 101), ("COMMON_NATIVE-5", 57255), ("COMMON-MODEL", self.hits + 1)):
            with self.subTest(contract=contract), patch.object(boundary, "observations", return_value={contract: count}), self.assertRaises(v.Invalid):
                v.parse_observations(data, value)

    def test_discovery(self) -> None:
        """The configured verification command, expected names and probes all include these real methods."""
        config = v.decode(v.read(ROOT / "development.json"))
        check = next(item for item in config["checks"] if item["id"] == "verification-python")
        names = sorted("tests.test_boundary.BoundaryTests." + name for name in dir(type(self)) if name.startswith("test_"))
        self.assertEqual(len(names), 10)
        self.assertIn("tests.test_boundary", check["argv"])
        self.assertEqual(sorted(name for name in check["expected_tests"] if name.startswith("tests.test_boundary.")), names)
        probes = [item for item in check["probes"] if item["test"] in names]
        self.assertEqual(sorted(item["test"] for item in probes), names)
        self.assertEqual(
            {item["contract"]: item["test"].rsplit(".", 1)[1] for item in probes},
            {
                "BOUNDARY-DOMAIN": "test_domain",
                "BOUNDARY-FRAMES": "test_frames",
                "BOUNDARY-DOCUMENTS": "test_documents",
                "BOUNDARY-TERMINAL": "test_terminal",
                "BOUNDARY-CONFIGURATION": "test_configuration",
                "BOUNDARY-SCHEMA": "test_schema",
                "BOUNDARY-PROJECTION": "test_projection",
                "BOUNDARY-MODEL": "test_model",
                "BOUNDARY-DISPATCH": "test_dispatch",
                "BOUNDARY-DISCOVERY": "test_discovery",
            },
        )
        self.assertTrue(all(item["minimum_hits"] == 1 for item in probes))
        component = next(item for item in config["components"] if item["id"] == "verification")
        contracts = {item["id"] for item in component["contracts"]}
        for probe in probes:
            self.assertIn(probe["contract"], contracts)
            self.assertIn(
                {"rule": "DEV-GATE", "contract": probe["contract"], "scenario": "native-oracle", "checks": ["verification-python"]},
                component["requirements"],
            )
        suite = unittest.defaultTestLoader.loadTestsFromNames(check["argv"][4:])

        def discovered(group: unittest.TestSuite) -> Iterator[str]:
            """Enumerate the real loader's full selection without executing test bodies or setup hooks."""
            for item in group:
                if isinstance(item, unittest.TestSuite):
                    yield from discovered(item)
                else:
                    yield item.id()

        self.assertEqual(sorted(discovered(suite)), sorted(check["expected_tests"]))


if __name__ == "__main__":
    unittest.main()
