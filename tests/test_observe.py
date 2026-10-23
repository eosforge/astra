"""Attack native-case observation boundaries and assert that oracle counts reflect executed checks."""

import contextlib
import io
import json
from pathlib import Path
import platform
import sys
import tempfile
import unittest

from tools import build, junit, observe, verify as v


def stream(events: list[dict]) -> bytes:
    """Encode explicitly synthetic parser fixtures, never real acceptance evidence."""
    return b"".join(b"ASTRA-OBSERVE " + json.dumps(event, separators=(",", ":")).encode() + b"\n" for event in events)


def events(hits: int = 3, status: str = "passed") -> list[dict]:
    """Declare one complete synthetic case with native-shaped terminal observations."""
    return [
        {"event": "start", "engine": "unittest"},
        {"event": "begin", "test": "case"},
        {"event": "end", "test": "case", "hits": hits, "status": status},
        {"event": "complete", "cases": 1},
    ]


class ObservationTests(unittest.TestCase):
    """Reject false positives, partial records, hidden failures and translated native mismatches."""

    def check(self) -> dict:
        """Use one declared synthetic oracle with a nonempty native assertion budget."""
        return {
            "adapter": "observed-cases",
            "expected_tests": ["case"],
            "probes": [{"contract": "CONTRACT", "test": "case", "minimum_hits": 2}],
            "log_bytes": 1048576,
        }

    def test_order(self) -> None:
        """Require unique starts/cases/terminals and reject unknown fields or post-terminal output."""
        for sequence in (
            events()[1:],
            events() + events(),
            events()[:-1] + [{"event": "complete", "cases": 0}],
            [events()[0], events()[2]],
            [events()[0], {"event": "begin", "test": "case", "claim": "passed"}],
            [{"event": "invented"}],
        ):
            with self.subTest(sequence=sequence), self.assertRaises(v.Invalid):
                v.case_observations(stream(sequence), self.check())
        hits, failures = v.case_observations(stream(events()), self.check())
        self.assertEqual((hits, failures), ({"CONTRACT": 3}, []))

    def test_non_vacuity(self) -> None:
        """Zero assertions, skips and missing required cases cannot be credited as passes."""
        for hits, status in ((0, "passed"), (1, "passed"), (3, "skipped"), (3, "failed")):
            with self.subTest(hits=hits, status=status):
                self.assertTrue(v.case_observations(stream(events(hits, status)), self.check())[1])
        for hits in (True, -1, 2.5):
            with self.subTest(hits=hits), self.assertRaises(v.Invalid):
                v.case_observations(stream(events(hits)), self.check())
        self.assertIn("case-stream-incomplete", v.case_observations(stream(events()[:-1]), self.check())[1])
        check = self.check()
        check["expected_tests"].append("forgotten")
        self.assertIn("case-selection-mismatch", v.case_observations(stream(events()), check)[1])

        # Synthetic native-shaped fixtures challenge the real pagination registration, not its implementation.
        config = v.decode(v.read(build.ROOT / "development.json"))
        check = next(item for item in config["checks"] if item["id"] == "star-native")
        step = next(item for item in config["campaigns"][0]["steps"] if item["id"] == "star-native")
        self.assertEqual(step["argv"][6:], check["argv"][6:])
        probe = next(item for item in check["probes"] if item["contract"] == "STAR_NATIVE-29")
        self.assertEqual(probe, {"contract": "STAR_NATIVE-29", "minimum_hits": 492381, "test": "cpp_pagination"})
        for count, status, absent in (
            (492381, "passed", False),
            (492380, "passed", False),
            (0, "passed", False),
            (492381, "failed", False),
            (492381, "skipped", False),
            (492381, "passed", True),
        ):
            selected = [name for name in check["expected_tests"] if not (absent and name == "cpp_pagination")]
            rows, xml = [], []
            for name in selected:
                hits, state = (count, status) if name == "cpp_pagination" else ({"cpp_catalog_rpc": 500, "cpp_ephemeris_rpc": 200}.get(name, 1), "passed")
                rows.extend([{"event": "begin", "test": name}, {"event": "end", "test": name, "hits": hits, "status": state}])
                marker = "<failure/>" if state == "failed" else "<skipped/>" if state == "skipped" else ""
                xml.append(f'<testcase name="{name}">{marker}<system-out>ASTRA-CHECKS {{"hits":{hits}}}\n</system-out></testcase>')
            raw = ("<testsuite>" + "".join(xml) + "</testsuite>").encode()
            encoded = junit.payload(raw, selected)
            data = stream([{"event": "start", "engine": "ctest"}]) + b"ASTRA-CTEST " + json.dumps(encoded).encode() + b"\n"
            data += stream(rows + [{"event": "complete", "cases": len(selected)}])
            with self.subTest(pagination_hits=count, status=status, absent=absent):
                observed, failures = v.case_observations(data, check)
                if count == 492381 and status == "passed" and not absent:
                    self.assertEqual(failures, [])
                    self.assertEqual(observed["STAR_NATIVE-29"], count)
                else:
                    self.assertTrue(failures)

    def test_ctest(self) -> None:
        """Reparse the raw XML and reject mismatched counts, duplicates, entities and malformed output."""
        raw = '<testsuite><testcase name="case"><system-out>ASTRA-CHECKS {"hits":3}\n</system-out></testcase></testsuite>'
        records = events()
        records[0]["engine"] = "ctest"
        native = b"ASTRA-CTEST " + json.dumps(raw).encode() + b"\n"
        self.assertEqual(v.case_observations(stream(records[:1]) + native + stream(records[1:]), self.check()), ({"CONTRACT": 3}, []))
        with self.assertRaisesRegex(v.Invalid, "case-native-mismatch"):
            v.case_observations(stream(records), self.check())
        records[2]["hits"] = 4
        with self.assertRaisesRegex(v.Invalid, "case-native-mismatch"):
            v.case_observations(stream(records[:1]) + native + stream(records[1:]), self.check())
        for value in (
            b"<!DOCTYPE testsuite><testsuite/>",
            b"<broken",
            b"<testsuites/>",
            raw.replace('name="case"', 'name=""').encode(),
            raw.replace("3}", "true}").encode(),
            raw.replace("ASTRA-CHECKS", "[This part of the test output was removed since it exceeds the threshold of 1024 bytes.]\nASTRA-CHECKS").encode(),
        ):
            with self.subTest(value=value), self.assertRaises(v.Invalid):
                observe.ctest_cases(value)
        failed = raw.replace("<system-out>", "<failure/><system-out>")
        self.assertEqual(observe.ctest_cases(failed.encode())["case"]["status"], "failed")
        encoded = junit.payload(raw.encode(), ["case"])
        records[2]["hits"] = 3
        transported = b"ASTRA-CTEST " + json.dumps(encoded).encode() + b"\n"
        self.assertEqual(v.case_observations(stream(records[:1]) + transported + stream(records[1:]), self.check()), ({"CONTRACT": 3}, []))
        for field, value in (
            ("format", "invented"),
            ("bytes", True),
            ("bytes", encoded["bytes"] - 1),
            ("bytes", junit.SUITE + 1),
            ("cases", True),
            ("cases", 2),
            ("data", "!"),
            ("sha256", "0" * 64),
        ):
            changed = {**encoded, field: value}
            with self.subTest(field=field, value=value), self.assertRaises(v.Invalid):
                junit.decode(changed, ["case"], self.check()["log_bytes"])
        for changed in ({**encoded, "unknown": 1}, {key: value for key, value in encoded.items() if key != "sha256"}):
            with self.subTest(changed=changed), self.assertRaises(v.Invalid):
                junit.decode(changed, ["case"], self.check()["log_bytes"])
        import base64
        import zlib

        for packed in (base64.b64decode(encoded["data"])[:-1], base64.b64decode(encoded["data"]) + b"trailing", zlib.compress(b"x" * 4096)):
            changed = {**encoded, "data": base64.b64encode(packed).decode()}
            with self.subTest(packed_bytes=len(packed)), self.assertRaises(v.Invalid):
                junit.decode(changed, ["case"], self.check()["log_bytes"])
        with self.assertRaises(v.Invalid):
            junit.decode(encoded, ["case"], 1)
        for selection in (["other"], ["case", "case"]):
            with self.subTest(selection=selection), self.assertRaises(v.Invalid):
                junit.decode(encoded, selection, self.check()["log_bytes"])
        # Scale only transport bounds in this synthetic boundary fixture, retaining all actual native requirements.
        larger = (
            "<testsuite>"
            + "".join(f'<testcase name="{name}"><system-out>{"x" * 650}\nASTRA-CHECKS {{"hits":3}}\n</system-out></testcase>' for name in ("left", "right"))
            + "</testsuite>"
        )
        with unittest.mock.patch.object(junit, "CASE", 1024), unittest.mock.patch.object(junit, "SUITE", 4096):
            self.assertGreater(len(larger.encode()), junit.CASE)
            with self.assertRaises(v.Invalid):
                junit.decode(larger, ["left", "right"], 1024)
            packed = junit.payload(larger.encode(), ["left", "right"])
            self.assertLess(len(json.dumps(packed).encode()), 1024)
            self.assertEqual(junit.cases(junit.decode(packed, ["left", "right"], 1024)), {name: {"status": "passed", "hits": 3} for name in ("left", "right")})
            oversized = larger.replace("x" * 650, "x" * 2000)
            with self.assertRaises(v.Invalid):
                junit.payload(oversized.encode(), ["left", "right"])

    @unittest.skipUnless(platform.system() == "Linux", "Existing native Linux CTest")
    def test_ctest_selection(self) -> None:
        """Real CTest must select exactly two literal names and execute their oracles, without a build."""
        root = Path(__file__).resolve().parents[1] / "build/ctest-fixtures"
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as directory:
            fixture = Path(directory)
            script = fixture / "oracle.py"
            # A real passing test must retain its terminal counter beyond CTest's default 1 KiB limit.
            script.write_text("print('diagnostic ' * 1024)\nprint('ASTRA-CHECKS {\"hits\":1}')\n", encoding="utf-8")
            # caseXa exposes an unescaped dot; other names expose missing anchors/selection.
            cases = ["case.a", "case_b"]
            text = "".join(f'add_test("{name}" "{sys.executable}" "-B" "{script}")\n' for name in [*cases, "caseXa", "other"])
            (fixture / "CTestTestfile.cmake").write_text(text, encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = observe.ctest(fixture, cases, 2)
            self.assertEqual(result, 0, output.getvalue())
            check = {
                "adapter": "observed-cases",
                "expected_tests": cases,
                "probes": [{"contract": name, "test": name, "minimum_hits": 1} for name in cases],
                "log_bytes": 1048576,
            }
            self.assertEqual(v.case_observations(output.getvalue().encode(), check), ({name: 1 for name in cases}, []))
            self.assertNotIn("[This part of the test output was removed", output.getvalue())

    def test_ctest_configuration(self) -> None:
        """A configuration-dependent real CTest fixture fails without selection and passes only the requested variant."""
        parent = build.ROOT / "build/tmp"
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="ctest-config-", dir=parent) as temporary:
            directory = Path(temporary)
            executable = str(Path(sys.executable)).replace("\\", "/")
            script = directory / "oracle.py"
            script.write_text("print('ASTRA-CHECKS {\"hits\":1}')\n", encoding="utf-8")
            (directory / "CTestTestfile.cmake").write_text(
                'if(CTEST_CONFIGURATION_TYPE STREQUAL "Release")\n'
                f'add_test(variant "{executable}" "-B" "{script.as_posix()}")\n'
                f'else()\nadd_test(variant "{executable}" "-c" "raise SystemExit(1)")\nendif()\n',
                encoding="utf-8",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(observe.ctest(directory, ["variant"], 1), 2)
            self.assertEqual(
                [
                    row
                    for row in [json.loads(line[14:]) for line in output.getvalue().splitlines() if line.startswith("ASTRA-OBSERVE ")]
                    if row.get("event") == "end"
                ][0]["status"],
                "failed",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(observe.ctest(directory, ["variant"], 1, "Release"), 0)
            translated = [json.loads(line[14:]) for line in output.getvalue().splitlines() if line.startswith("ASTRA-OBSERVE ")]
            self.assertEqual(next(row for row in translated if row.get("event") == "end")["hits"], 1)
            with self.assertRaisesRegex(v.Invalid, "ctest-configuration"):
                observe.ctest(directory, ["variant"], 1, "unknown")

    def test_node(self) -> None:
        """Translated Node passes must match native terminals and actual assertion observations."""
        rows = events()
        rows[0]["engine"] = "node"
        native = b'ASTRA-NODE {"test":"case","hits":3}\nASTRA-NODE-TERMINAL {"type":"test:pass","data":{"name":"case"}}\n'
        full = stream(rows[:1]) + native + stream(rows[1:])
        self.assertEqual(v.case_observations(full, self.check()), ({"CONTRACT": 3}, []))
        check = {**self.check(), "argv": ["python3", "-B", "tools/observe.py", "python", "tests.fixture"]}
        with self.assertRaisesRegex(v.Invalid, "case-engine-mismatch"):
            v.case_observations(full, check)
        for malformed in (full.replace(b"test:pass", b"test:fail"), full.replace(b'"hits":3}', b'"hits":2}', 1), stream(rows), full + native):
            with self.subTest(malformed=malformed), self.assertRaises(v.Invalid):
                v.case_observations(malformed, self.check())

    def test_assertions(self) -> None:
        """Successful, failed, nested and context assertions retain native semantics and exact outer counts."""
        counter = [0]
        token = observe.ACTIVE.set(counter)
        originals = observe.assertions()
        case = unittest.TestCase()
        try:
            case.assertEqual({"x": [1]}, {"x": [1]})
            if counter[0] != 1:
                raise AssertionError(counter)
            try:
                case.assertEqual(1, 2)
            except AssertionError:
                pass
            if counter[0] != 1:
                raise AssertionError("A failed assertion was counted")
            manager = case.assertRaises(ValueError)
            if counter[0] != 1:
                raise AssertionError("Context creation was counted")
            with manager as capture:
                raise ValueError("expected")
            if str(capture.exception) != "expected" or counter[0] != 2:
                raise AssertionError("Context matching or count changed")
            with case.assertLogs("fixture", level="WARNING"):
                import logging

                logging.getLogger("fixture").warning("observed")
            if counter[0] != 3:
                raise AssertionError("Log context was not observed at exit")
            mock = unittest.mock.Mock()
            mock.assert_not_called()
            mock("observed")
            try:
                mock.assert_not_called()
            except AssertionError:
                pass
            mock.assert_called_once_with("observed")
            if counter[0] != 5:
                raise AssertionError("Mock assertions changed semantics or counted nested/failed calls")
        finally:
            for (owner, name), method in originals.items():
                setattr(owner, name, method)
            observe.ACTIVE.reset(token)
        self.assertEqual(counter, [5])

    def test_subtest_failure(self) -> None:
        """A parent completing after a failed subtest still emits failed, rather than an invented pass."""

        class Broken(unittest.TestCase):
            """An intentionally failing native framework fixture."""

            def test_case(self) -> None:
                """Continue after an assertion failure, exercising native subtest behavior."""
                with self.subTest(index=1):
                    self.assertEqual(1, 2)
                self.assertTrue(True)

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = unittest.TextTestRunner(stream=io.StringIO(), resultclass=observe.Result).run(unittest.TestSuite([Broken("test_case")]))
        self.assertFalse(result.wasSuccessful())
        observed = [json.loads(line[len("ASTRA-OBSERVE ") :]) for line in output.getvalue().splitlines()]
        self.assertEqual(observed[-1]["status"], "failed")


if __name__ == "__main__":
    unittest.main()
