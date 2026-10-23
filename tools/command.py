"""Recompute the declared Command callback histories from first-attempt admission and independent prefix counts."""

from collections.abc import Iterator
from pathlib import Path
import re

from tools import statements, verify as v


def configuration(check: dict) -> None:
    """Bind the model to complete ordinary/Race suites and source/coverage/fault prerequisites."""
    statements.configuration(check)
    if check.get("model") != "command-state-v1" or check.get("faults") != "command-faults-v1":
        v.reject("command-model-configuration")


def domain() -> Iterator[tuple[int, list[int]]]:
    """Enumerate four delegate classes and every unpruned prefix through four events in native preorder."""

    def visit(prefix: list[int]) -> Iterator[list[int]]:
        """Yield every action prefix up to length four in depth-first order."""
        yield prefix
        if len(prefix) < 4:
            for action in range(6):
                yield from visit(prefix + [action])

    for kind in range(4):
        for prefix in visit([]):
            yield kind, prefix


def history(actions: list[int], kind: int) -> list[list]:
    """Derive the first write and prefix counts rather than mirroring mutable wrapper control flow."""
    first = next((index for index, action in enumerate(actions) if action >= 2), None)
    result = []
    for index, action in enumerate(actions):
        consumed = first is not None and first <= index
        delegated = consumed and kind != 0
        text = ("", "\0µ🙂")[first % 2] if delegated else ""
        nested = "duplicate option" if delegated and actions[first] == 5 else ""
        reads = sum(value == 0 for value in actions[: index + 1]) if kind != 0 else 0
        queries = sum(value == 1 for value in actions[: index + 1]) if kind >= 2 else 0
        if action == 0:
            outcome = "string:" + text
        elif action == 1:
            outcome = "bool:" + ("true" if kind == 3 else "false")
        elif index != first:
            outcome = "duplicate option"
        else:
            outcome = "panic" if kind == 0 or action == 4 else "rejected" if action == 3 else "ok"
        result.append([outcome, reads, int(delegated), queries, consumed, text, nested])
    return result


def frames(data: bytes) -> list[dict]:
    """Require complete bounded test-owned native lines; fragmented JSON is reassembled before decoding."""
    buffers, result = {}, []
    for line in data.splitlines():
        event = v.decode(line)
        if not isinstance(event, dict):
            v.reject("command-model-envelope")
        if event.get("Action") != "output":
            continue
        name = event.get("Test", "")
        if not isinstance(name, str) or not isinstance(event.get("Output"), str):
            v.reject("command-model-output")
        text = buffers.get(name, "") + event.get("Output", "")
        if len(text.encode()) > 128 * 1024:
            v.reject("command-model-line-budget")
        parts = text.split("\n")
        buffers[name] = parts.pop()
        for part in parts:
            marker = re.search(r"ASTRA-COMMAND-MODEL (.*)$", part)
            if marker is None:
                continue
            if name != "TestModel":
                v.reject("command-model-test-identity")
            row = v.decode(marker.group(1).encode())
            if not isinstance(row, dict) or set(row) != {"kind", "history", "states"}:
                v.reject("command-model-frame-shape")
            if type(row["kind"]) is not int or not 0 <= row["kind"] < 4:
                v.reject("command-model-kind")
            if (
                not isinstance(row["history"], list)
                or len(row["history"]) > 4
                or any(type(action) is not int or not 0 <= action < 6 for action in row["history"])
            ):
                v.reject("command-model-actions")
            result.append(row)
            if len(result) > 6220:
                v.reject("command-model-frame-budget")
    if any("ASTRA-COMMAND-MODEL" in text for text in buffers.values()):
        v.reject("command-model-incomplete-line")
    return result


def observations(data: bytes, check: dict, root: Path = v.ROOT) -> dict[str, int]:
    """Reject missing, reordered or mismatching actual histories before accepting native model counters."""
    configuration(check)
    source = v.inside(root, "internal/command")
    if sorted(path.relative_to(source).as_posix() for path in source.rglob("*.go") if not path.name.endswith("_test.go")) != ["flags.go"]:
        v.reject("command-model-source-scope")
    if v.file_digest(source / "flags.go") != "a85cf555ec0387a915624a672fc6037362b6b3c6277684f458f747db9c7a1979":
        v.reject("command-model-source")
    actual = frames(data)
    if len(actual) != 6220:
        v.reject("command-model-domain-incomplete")
    for row, (kind, actions) in zip(actual, domain(), strict=True):
        expected = {"kind": kind, "history": actions, "states": history(actions, kind)}
        if v.encode(row) != v.encode(expected):
            v.reject("command-model-value")
    if sum(len(row["history"]) for row in actual) != 23640:
        v.reject("command-model-transition-count")
    return {"COMMAND-MODEL": len(actual), "COMMAND-MODEL-CONTROLS": 10}
