"""Collect native Python line and conditional-opcode edges without claiming statement coverage or MC/DC."""

import argparse
import dis
from pathlib import Path
import sys
import trace
import types
import unittest

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import build, verify as v


def lines(code: types.CodeType) -> set[int]:
    """Retain every positive bytecode-associated source line, including functions that never execute."""
    result = {line for _, line in dis.findlinestarts(code) if line is not None and line > 0}
    for value in code.co_consts:
        if isinstance(value, types.CodeType):
            result.update(lines(value))
    return result


def summarize(root: Path, names: list[str], counts: dict) -> list[dict]:
    """Reconcile each owned source file with interpreter events, preserving all zero-hit files."""
    observed = {}
    for (filename, line), count in counts.items():
        path = Path(filename).resolve()
        if path.is_relative_to(root) and not path.is_relative_to(root / "build"):
            name = path.relative_to(root).as_posix()
            if name not in names or type(line) is not int or type(count) is not int or line <= 0 or count < 0:
                v.reject("python-counter-unregistered", name)
            observed.setdefault(name, {})[line] = observed.setdefault(name, {}).get(line, 0) + count
    result = []
    for name in sorted(names):
        code = compile((root / name).read_bytes(), str(root / name), "exec")
        possible = lines(code)
        actual = observed.get(name, {})
        if set(actual) - possible:
            v.reject("python-counter-unmapped", name)
        result.append(
            {
                "file": name,
                "lines": len(possible),
                "hit": sum(actual.get(line, 0) > 0 for line in possible),
                "counts": actual,
                "uncovered": sorted(possible - {line for line, count in actual.items() if count > 0}),
            }
        )
    return result


class Branches:
    """Inventory original bytecode and observe taken/fallthrough edges, retaining never-executed code."""

    def __init__(self, root: Path, names: list[str]) -> None:
        """Compile only owned inputs for a fixed denominator; never rewrite or execute their source."""
        self.root = root.resolve()
        self.names = {str((self.root / name).resolve()): name for name in names}
        self.codes = {}
        self.rows = []
        self.errors = set()
        self.registered = {}
        self.tool = None
        for filename, name in sorted(self.names.items()):
            self.scan(compile(Path(filename).read_bytes(), filename, "exec"), name, ())

    def scan(self, code: types.CodeType, name: str, nesting: tuple[int, ...]) -> None:
        """Keep both static destinations of each conditional opcode, including empty loops and short circuiting."""
        instructions = list(dis.get_instructions(code, adaptive=False))
        branches = {}
        for index, instruction in enumerate(instructions):
            conditional = instruction.opname.startswith(("POP_JUMP_IF_", "JUMP_IF_")) or instruction.opname in ("FOR_ITER", "SEND")
            if not conditional:
                if instruction.opcode in dis.hasjump and instruction.opname not in ("JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT", "JUMP_FORWARD"):
                    self.errors.add("unsupported-opcode:" + instruction.opname)
                continue
            if index + 1 == len(instructions) or type(instruction.argval) is not int:
                self.errors.add("invalid-branch:" + name)
                continue
            destinations = [instruction.argval, instructions[index + 1].offset]
            if len(set(destinations)) != 2:
                self.errors.add("ambiguous-branch:" + name)
            row = {
                "file": name,
                "function": code.co_qualname,
                "first_line": code.co_firstlineno,
                "nesting": list(nesting),
                "offset": instruction.offset,
                "opcode": instruction.opname,
                "line": instruction.positions.lineno,
                "static_destinations": destinations,
                "edges": {"left": 0, "right": 0},
            }
            branches[instruction.offset] = row
            self.rows.append(row)
        key = (str(Path(code.co_filename).resolve()), code)
        if key in self.codes:
            self.errors.add("ambiguous-code:" + name)
        self.codes[key] = branches
        for index, value in enumerate(code.co_consts):
            if isinstance(value, types.CodeType):
                self.scan(value, name, (*nesting, index))

    def begin(self, code: types.CodeType, offset: int) -> None:
        """Bind runtime code to the original bytecode before subscribing to its actual branch events."""
        if id(code) in self.registered:
            return
        filename = str(Path(code.co_filename).resolve())
        if filename not in self.names:
            return
        branches = self.codes.get((filename, code))
        if branches is None:
            self.errors.add("unmapped-code:" + self.names[filename])
            return
        self.registered[id(code)] = (code, branches)
        sys.monitoring.set_local_events(self.tool, code, sys.monitoring.events.BRANCH_LEFT | sys.monitoring.events.BRANCH_RIGHT)

    def branch(self, code: types.CodeType, offset: int, destination: int, side: str) -> None:
        """Count native interpreter outcomes without predicting truth conversion or evaluating an operand twice."""
        item = self.registered.get(id(code))
        if item is None or offset not in item[1] or type(destination) is not int or destination < 0:
            self.errors.add("unmapped-native-branch:" + code.co_filename + ":" + str(offset))
            return
        item[1][offset]["edges"][side] += 1

    def __enter__(self) -> "Branches":
        """Acquire a free monitoring slot, leaving existing debugger/profiler/collector slots untouched."""
        monitoring = getattr(sys, "monitoring", None)
        if monitoring is None or not hasattr(monitoring.events, "BRANCH_LEFT") or not sys._is_gil_enabled():
            v.reject("python-branch-engine", "CPython 3.14+ with the GIL and native branch events required")
        self.tool = next((tool for tool in (1, 3, 4, 5) if monitoring.get_tool(tool) is None), None)
        if self.tool is None:
            v.reject("python-monitoring-in-use")
        monitoring.use_tool_id(self.tool, "astra-branches")
        try:
            monitoring.register_callback(self.tool, monitoring.events.PY_START, self.begin)
            monitoring.register_callback(self.tool, monitoring.events.PY_RESUME, self.begin)
            monitoring.register_callback(
                self.tool, monitoring.events.BRANCH_LEFT, lambda code, offset, destination: self.branch(code, offset, destination, "left")
            )
            monitoring.register_callback(
                self.tool, monitoring.events.BRANCH_RIGHT, lambda code, offset, destination: self.branch(code, offset, destination, "right")
            )
            monitoring.set_events(self.tool, monitoring.events.PY_START | monitoring.events.PY_RESUME)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, kind: type[BaseException] | None, value: BaseException | None, traceback: types.TracebackType | None) -> None:
        """Disable owned events and release only this slot after normal or exceptional termination."""
        if self.tool is None:
            return
        monitoring = sys.monitoring
        try:
            monitoring.set_events(self.tool, 0)
            for code, _ in self.registered.values():
                monitoring.set_local_events(self.tool, code, 0)
            for event in (monitoring.events.PY_START, monitoring.events.PY_RESUME, monitoring.events.BRANCH_LEFT, monitoring.events.BRANCH_RIGHT):
                monitoring.register_callback(self.tool, event, None)
        finally:
            monitoring.free_tool_id(self.tool)
            self.tool = None

    def summary(self) -> dict:
        """Report literal bytecode edge counts and instrumentation gaps without granting an acceptance tier."""
        return {
            "unit": "CPython conditional bytecode destinations; not source decisions, reachable-branch exclusions or MC/DC",
            "edges": sum(len(row["edges"]) for row in self.rows),
            "hit": sum(count > 0 for row in self.rows for count in row["edges"].values()),
            "errors": sorted(self.errors),
            "rows": self.rows,
        }


def main(arguments: list[str] | None = None) -> int:
    """Run the existing unittest discovery under the standard interpreter tracer; preserve source identity and failures."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(arguments)
    root, output = build.ROOT.resolve(), args.output.resolve()
    if not output.is_relative_to(root / "build"):
        v.reject("python-coverage-output-boundary")
    output.mkdir(parents=True, exist_ok=False)
    before = v.source(root)
    config = v.decode(v.read(root / "development.json"))
    owned = v.inventory(config, [item["path"] for item in before["files"] if item["sha256"] is not None])
    if owned["unowned"]:
        v.reject("python-coverage-unowned")
    names = [name for files in owned["components"].values() for name in files if name.endswith(".py")]
    if not names:
        v.reject("python-coverage-empty")
    tracer = trace.Trace(count=True, trace=False, ignoredirs=[sys.base_prefix, str(root / "build")])
    branches = Branches(root, names)

    def execute() -> unittest.TestResult:
        """Include test discovery/imports and execution in interpreter events, without tracing child interpreters."""
        suite = unittest.defaultTestLoader.discover(str(root / "tests"), pattern="test_*.py", top_level_dir=str(root))
        return unittest.TextTestRunner(verbosity=2).run(suite)

    with branches:
        result = tracer.runfunc(execute)
    actual = summarize(root, names, tracer.results().counts)
    unchanged = before == v.source(root)
    collected = result.wasSuccessful() and result.testsRun > 0 and unchanged and not branches.errors
    v.write_new(output / "source.json", before)
    v.write_new(
        output / "summary.json",
        {
            "status": "collected" if collected else "blocked",
            "qualification": "not-evaluated",
            "unit": "CPython bytecode-associated source lines, not statements, branches or MC/DC",
            "scope": "Source-line counts cover the calling thread; native branch counts cover owned code in all interpreter threads. Child interpreters and native programs require separate collectors",
            "tests": result.testsRun,
            "skipped": len(result.skipped),
            "source_unchanged": unchanged,
            "files": actual,
            "branches": branches.summary(),
        },
    )
    return 0 if collected else 2


if __name__ == "__main__":
    sys.exit(main())
