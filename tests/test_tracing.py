"""Check Python counter denominators independently from the application's verification results."""

from collections.abc import Iterator
from pathlib import Path
from contextlib import contextmanager
import sys
import tempfile
import trace
import unittest

from tools import tracing, verify


@contextmanager
def trace_scope() -> Iterator[None]:
    """Restore any enclosing line collector even when a native observation assertion fails."""
    previous = sys.gettrace()
    try:
        yield
    finally:
        sys.settrace(previous)


class TracingTests(unittest.TestCase):
    """Keep never-called functions/files and reject counters detached from declared source."""

    def test_unexecuted(self) -> None:
        """A called branch cannot conceal the alternative or a function/file never executed."""
        directory = Path(__file__).resolve().parents[1] / "build/tmp"
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=directory, prefix="python-counters-") as temporary:
            root = Path(temporary).resolve()
            text = "def choose(value):\n    if value:\n        return 1\n    return 2\ndef unused():\n    return 3\n"
            (root / "active.py").write_text(text)
            (root / "missing.py").write_text("def absent():\n    return 4\n")
            counts = {(str(root / "active.py"), line): 1 for line in (1, 2, 3, 5)}
            files = tracing.summarize(root, ["active.py", "missing.py"], counts)
            self.assertEqual(files[0]["uncovered"], [4, 6])
            self.assertEqual(files[0]["hit"], 4)
            self.assertEqual(files[1]["hit"], 0)
            self.assertEqual(files[1]["uncovered"], [1, 2])
            namespace = {"__file__": str(root / "active.py")}
            tracer = trace.Trace(count=True, trace=False)
            previous = sys.gettrace()
            try:
                tracer.runfunc(exec, compile(text, str(root / "active.py"), "exec"), namespace)
                self.assertEqual(tracer.runfunc(namespace["choose"], True), 1)
            finally:
                sys.settrace(previous)
            native = tracing.summarize(root, ["active.py", "missing.py"], tracer.results().counts)
            self.assertEqual(native[0]["uncovered"], [4, 6])
            self.assertEqual(native[1]["hit"], 0)
            for name, line, count in (("unknown.py", 1, 1), ("active.py", 100, 1), ("active.py", 2, -1)):
                with self.subTest(name=name, line=line, count=count), self.assertRaises(verify.Invalid):
                    tracing.summarize(root, ["active.py", "missing.py"], {(str(root / name), line): count})

    def test_edges(self) -> None:
        """Real short-circuit opcodes retain their unexecuted alternative and are covered only by actual later calls."""
        directory = Path(__file__).resolve().parents[1] / "build/tmp"
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=directory, prefix="python-edges-") as temporary:
            root = Path(temporary).resolve()
            path = root / "choice.py"
            text = "def choose(a,b):\n    if a and b:\n        return 1\n    return 2\ndef unused(c):\n    if c:\n        return 3\n    return 4\n"
            path.write_text(text)
            namespace = {}
            exec(compile(text, str(path), "exec"), namespace)
            branches = tracing.Branches(root, ["choice.py"])
            tracer = trace.Trace(count=True, trace=False)
            with branches, trace_scope():
                self.assertEqual(tracer.runfunc(namespace["choose"], True, True), 1)
                initial = branches.summary()
                self.assertEqual((initial["edges"], initial["hit"], initial["errors"]), (6, 2, []))
                self.assertEqual(tracer.runfunc(namespace["choose"], False, True), 2)
                self.assertEqual(tracer.runfunc(namespace["choose"], True, False), 2)
                final = branches.summary()
                self.assertEqual((final["edges"], final["hit"], final["errors"]), (6, 4, []))
                self.assertTrue(all(not any(row["edges"].values()) for row in final["rows"] if row["function"] == "unused"))

    def test_loop_and_exception(self) -> None:
        """Observe both finite-loop exits without repeating truth conversion or turning a raised conversion into an edge."""
        directory = Path(__file__).resolve().parents[1] / "build/tmp"
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=directory, prefix="python-loop-") as temporary:
            root = Path(temporary).resolve()
            path = root / "loop.py"
            text = "def loop(values):\n    total=0\n    for value in values:\n        total+=value\n    return total\ndef choose(value):\n    if value:\n        return 1\n    return 0\n"
            path.write_text(text)
            namespace = {}
            exec(compile(text, str(path), "exec"), namespace)
            branches = tracing.Branches(root, ["loop.py"])
            tracer = trace.Trace(count=True, trace=False)

            class Value:
                """Count actual truth conversions and inject an independent conversion failure."""

                def __init__(self, failure: bool) -> None:
                    """Select the exact declared conversion outcome."""
                    self.calls, self.failure = 0, failure

                def __bool__(self) -> bool:
                    """Never permit a collector to repeat the production conversion for its own prediction."""
                    self.calls += 1
                    if self.failure:
                        raise ValueError("conversion")
                    return True

            with branches, trace_scope():
                self.assertEqual(tracer.runfunc(namespace["loop"], [1, 2]), 3)
                self.assertEqual(tracer.runfunc(namespace["loop"], []), 0)
                value = Value(False)
                self.assertEqual(tracer.runfunc(namespace["choose"], value), 1)
                self.assertEqual(value.calls, 1)
                failed = Value(True)
                with self.assertRaisesRegex(ValueError, "conversion"):
                    tracer.runfunc(namespace["choose"], failed)
                self.assertEqual(failed.calls, 1)
                summary = branches.summary()
                self.assertEqual((summary["edges"], summary["hit"], summary["errors"]), (4, 3, []))

    def test_code_identity(self) -> None:
        """Dynamically replaced bytecode at an owned filename cannot masquerade as the original source."""
        directory = Path(__file__).resolve().parents[1] / "build/tmp"
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=directory, prefix="python-drift-") as temporary:
            root = Path(temporary).resolve()
            path = root / "drift.py"
            path.write_text("def choose(value):\n    if value:\n        return 1\n    return 0\n")
            namespace = {}
            exec(compile("def choose(value):\n    return 99\n", str(path), "exec"), namespace)
            branches = tracing.Branches(root, ["drift.py"])
            tracer = trace.Trace(count=True, trace=False)
            with branches, trace_scope():
                self.assertEqual(tracer.runfunc(namespace["choose"], True), 99)
                self.assertEqual(branches.summary()["errors"], ["unmapped-code:drift.py"])
                self.assertEqual(branches.summary()["hit"], 0)


if __name__ == "__main__":
    unittest.main()
