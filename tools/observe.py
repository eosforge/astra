"""Emit actual unittest/CTest observations with successful assertion counts; no output is an acceptance decision."""

from collections.abc import Callable
from contextlib import AbstractContextManager
from types import TracebackType
import argparse
import contextvars
import functools
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
import xml.etree.ElementTree as xml

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import junit, verify as v

# A test owns only assertions executed within its context; unrelated background threads are not credited.
ACTIVE = contextvars.ContextVar("assertion-owner", default=None)
DEPTH = contextvars.ContextVar("assertion-depth", default=0)


def emit(event: str, **values: object) -> None:
    """Write an ordered observation while leaving ordinary native diagnostics intact."""
    print("ASTRA-OBSERVE " + json.dumps({"event": event, **values}, separators=(",", ":")), flush=True)


def hit() -> None:
    """Credit one completed outer assertion to its executing test."""
    current = ACTIVE.get()
    if current is not None:
        current[0] += 1


class Context:
    """Observe a successful exception/warning context without changing its matching or suppression behavior."""

    def __init__(self, original: AbstractContextManager[object]) -> None:
        """Retain the native unittest context until its actual exit."""
        self.original = original

    def __enter__(self) -> object:
        """Return the original result object, preserving access to exception and warning details."""
        return self.original.__enter__()

    def __exit__(self, kind: type[BaseException] | None, value: BaseException | None, trace: TracebackType | None) -> bool | None:
        """Count only a normally completed native expectation, never construction of a context."""
        result = self.original.__exit__(kind, value, trace)
        if kind is None or result:
            hit()
        return result


def assertions() -> dict[tuple[type, str], Callable[..., object]]:
    """Temporarily wrap existing unittest assertions; return originals for unconditional restoration."""
    originals = {}

    def wrap(method: Callable[..., object]) -> Callable[..., object]:
        """Preserve assertion results and exceptions while avoiding helper/delegation double counting."""

        @functools.wraps(method)
        def invoke(*args: object, **kwargs: object) -> object:
            """Observe only a successful outermost assertion call."""
            depth = DEPTH.get()
            token = DEPTH.set(depth + 1)
            try:
                result = method(*args, **kwargs)
            finally:
                DEPTH.reset(token)
            if depth == 0:
                if hasattr(result, "__enter__") and hasattr(result, "__exit__"):
                    return Context(result)
                hit()
            return result

        return invoke

    for owner in (unittest.TestCase, unittest.mock.NonCallableMock):
        for name, method in vars(owner).items():
            if name.startswith("assert") and callable(method):
                originals[(owner, name)] = method
                setattr(owner, name, wrap(method))
    return originals


class Result(unittest.TextTestResult):
    """Emit one terminal observation per actual test, keeping skips/failures and non-vacuity visible."""

    def startTest(self, test: unittest.TestCase) -> None:
        """Assign a fresh assertion scope before the native test setup and execution."""
        self.counter = [0]
        self.token = ACTIVE.set(self.counter)
        self.state = "passed"
        emit("begin", test=test.id())
        super().startTest(test)

    def addError(self, test: unittest.TestCase, error: tuple[type[BaseException], BaseException, TracebackType | None]) -> None:
        """Preserve errors as failures even if later cleanup succeeds."""
        self.state = "failed"
        super().addError(test, error)

    def addFailure(self, test: unittest.TestCase, error: tuple[type[BaseException], BaseException, TracebackType | None]) -> None:
        """Preserve assertion failures and their native traceback."""
        self.state = "failed"
        super().addFailure(test, error)

    def addSkip(self, test: unittest.TestCase, reason: str) -> None:
        """A skipped test has no passing observation."""
        self.state = "skipped"
        super().addSkip(test, reason)

    def addExpectedFailure(self, test: unittest.TestCase, error: tuple[type[BaseException], BaseException, TracebackType | None]) -> None:
        """Expected failures do not qualify a required contract."""
        self.state = "failed"
        super().addExpectedFailure(test, error)

    def addUnexpectedSuccess(self, test: unittest.TestCase) -> None:
        """Unexpected successes retain the native framework's failure classification."""
        self.state = "failed"
        super().addUnexpectedSuccess(test)

    def addSubTest(
        self, test: unittest.TestCase, subtest: unittest.TestCase, error: tuple[type[BaseException], BaseException, TracebackType | None] | None
    ) -> None:
        """Retain a failed subtest even when its parent method reaches the end."""
        if error is not None:
            self.state = "failed"
        super().addSubTest(test, subtest, error)

    def stopTest(self, test: unittest.TestCase) -> None:
        """Seal counts after teardown, then remove the assertion owner."""
        emit("end", test=test.id(), status=self.state, hits=self.counter[0])
        ACTIVE.reset(self.token)
        super().stopTest(test)


def python(names: list[str]) -> int:
    """Run named existing unittest suites with native result and assertion instrumentation."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(names)
    emit("start", engine="unittest")
    original = assertions()
    try:
        result = unittest.TextTestRunner(resultclass=Result, verbosity=2).run(suite)
    finally:
        for (owner, name), method in original.items():
            setattr(owner, name, method)
    emit("complete", cases=result.testsRun)
    return 0 if result.wasSuccessful() and result.testsRun else 2


def ctest_cases(data: bytes) -> dict[str, dict[str, str | int]]:
    """Parse actual CTest JUnit terminal records without treating a test count or exit zero as oracle hits."""
    if len(data) > 32 * 1024 * 1024 or b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        v.reject("ctest-xml-budget-or-entity")
    try:
        root = xml.fromstring(data)
    except xml.ParseError as error:
        v.reject("ctest-xml", str(error))
    if root.tag != "testsuite":
        v.reject("ctest-xml-root")
    result = {}
    for case in root:
        if case.tag != "testcase":
            v.reject("ctest-xml-case")
        name = case.attrib.get("name")
        if not name or name in result:
            v.reject("ctest-case-duplicate-or-empty")
        output = case.find("system-out")
        if output is not None and "[This part of the test output was removed since it exceeds the threshold of " in (output.text or ""):
            v.reject("ctest-output-truncated")
        marks = re.findall(r"^ASTRA-CHECKS (\{[^\n]*\})\s*$", output.text or "", re.MULTILINE) if output is not None else []
        counts = [v.decode(mark.encode()) for mark in marks]
        if len(counts) > 1 or any(set(count) != {"hits"} or type(count["hits"]) is not int or count["hits"] < 0 for count in counts):
            v.reject("ctest-counter-shape")
        result[name] = {
            "status": "failed" if case.find("failure") is not None else "skipped" if case.find("skipped") is not None else "passed",
            "hits": counts[0]["hits"] if counts else 0,
        }
    return result


def ctest(directory: Path, cases: list[str], jobs: int, configuration: str | None = None) -> int:
    """Run only declared CTest cases in the existing build, retaining complete JUnit bytes in native output."""
    if not directory.is_dir() or not cases or len(cases) != len(set(cases)):
        v.reject("ctest-selection")
    if configuration not in (None, "Debug", "Release"):
        v.reject("ctest-configuration")
    with tempfile.TemporaryDirectory(prefix="ctest-observations-", dir=directory) as temporary:
        output = Path(temporary) / "native.xml"
        # CTest uses CMake's regular expressions, which do not support non-capturing groups.
        pattern = "^(" + "|".join(re.escape(name) for name in cases) + ")$"
        emit("start", engine="ctest")
        process = subprocess.run(
            [
                "ctest",
                "--test-dir",
                str(directory),
                *(["-C", configuration] if configuration else []),
                "--no-tests=error",
                "--parallel",
                str(jobs),
                "--output-on-failure",
                # CTest otherwise truncates passing output before the final assertion counter.
                "--test-output-size-passed",
                str(32 * 1024 * 1024),
                "--test-output-size-failed",
                str(32 * 1024 * 1024),
                "--output-junit",
                str(output),
                "-R",
                pattern,
            ]
        )
        if not output.is_file():
            v.reject("ctest-no-terminal")
        raw = output.read_bytes()
        # The gate reparses the original XML, rather than trusting these translated terminal events.
        encoded = junit.payload(raw, cases)
        print("ASTRA-CTEST " + json.dumps(encoded, separators=(",", ":")), flush=True)
        actual = junit.cases(junit.decode(encoded, cases, 32 * 1024**2))
        for name, value in actual.items():
            emit("begin", test=name)
            emit("end", test=name, **value)
        emit("complete", cases=len(actual))
        return 0 if process.returncode == 0 and set(actual) == set(cases) else 2


def main(arguments: list[str] | None = None) -> int:
    """Dispatch actual suites; starting a build or installing dependencies is outside this adapter."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="engine", required=True)
    py = sub.add_parser("python")
    py.add_argument("names", nargs="+")
    cpp = sub.add_parser("ctest")
    cpp.add_argument("--build", type=Path, required=True)
    cpp.add_argument("--case", action="append", required=True)
    cpp.add_argument("--jobs", type=int, choices=range(1, 5), default=4)
    cpp.add_argument("--config", choices=("Debug", "Release"))
    args = parser.parse_args(arguments)
    return python(args.names) if args.engine == "python" else ctest(args.build.resolve(), args.case, args.jobs, args.config)


if __name__ == "__main__":
    sys.exit(main())
