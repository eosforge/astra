"""Validate complete native query lifetimes and source-bound close-error input witnesses without inventing skipped hits."""

from pathlib import Path
import re

from tools import authority, logic, storage, structure, verify as v

# A successful row precedes its actual native close receipt, then the public operation's result.
POINTS = {
    "integrity-close": ("schema.go:3986", ["quick_check"], 1, True),
    "schema-close": ("schema.go:4289", ["sql"], 4, True),
    "meta-close": ("schema.go:4809", ["id", "format", "galaxy", "username", "advertise", "scopes", "bytes"], 1, False),
    "records-close": ("schema.go:6230", ["records", "bytes"], 1, False),
    "retained-close": ("schema.go:6814", ["count", "bytes"], 1, False),
    "checkpoint-close": ("store.go:11041", ["busy", "log", "checkpointed"], 1, False),
}
EXPRESSIONS = {
    "schema.go:3986": 'err != nil || integrity != "ok"',
    "schema.go:4289": "err != nil || len(definitions) != len(schema)",
    "schema.go:4809": "err != nil || meta.Format != 1",
    "schema.go:6230": "err != nil || actual.Records != state.Records || actual.Bytes != state.Bytes",
    "schema.go:6814": "err != nil || retained.Count != state.Retained || retained.Bytes != state.Backlog",
    "store.go:11041": "err != nil || progress.Busy != 0 || progress.Log > progress.Checkpointed",
}
GORM = {
    "callbacks/query.go": "4bf8b7b650bae87976e45baa1525121a9fa087290685afed963a7b98384cd137",
    "scan.go": "4ab60fcb86fa7aed67195eeef1d9cc812f55c86c050355ca9d4e77489b0fd027",
    "finisher_api.go": "e2153d1143549a990073e483094a2198f4116d82bf5ef5d00c7dc8e1eba4bf85",
}


def value(item: object) -> int | bytes:
    """Decode only the typed native SQL values admitted by the fixture, preserving integer and blob identity."""
    if not isinstance(item, dict):
        v.reject("queries-value")
    kind = item.get("type")
    if kind == "integer":
        logic.fields(item, ("type", "value"), "queries-integer")
        if type(item["value"]) is not int or not -(2**63) <= item["value"] < 2**63:
            v.reject("queries-integer")
        return item["value"]
    if kind == "text":
        logic.fields(item, ("type", "hex"), "queries-text")
        if not isinstance(item["hex"], str):
            v.reject("queries-text")
        try:
            result = bytes.fromhex(item["hex"])
        except ValueError:
            v.reject("queries-text-encoding")
        if result.hex() != item["hex"]:
            v.reject("queries-text-encoding")
        return result
    v.reject("queries-value-type")


def groups(point: str, frames: list) -> list[list]:
    """Require one healthy control and two complete reached failures, each closing its actual native cursor once."""
    if point not in POINTS or not isinstance(frames, list) or not 6 <= len(frames) <= 64:
        v.reject("queries-frames")
    _, columns, count, eof = POINTS[point]
    result, current = [], []
    for frame in frames:
        logic.fields(frame, ("point", "active", "kind", "columns", "values", "outcome"), "queries-frame")
        active = len(result) != 0
        if frame["point"] != point or type(frame["active"]) is not bool or frame["active"] != active or not isinstance(frame["values"], list):
            v.reject("queries-attribution")
        kind, outcome = frame["kind"], frame["outcome"]
        if kind == "next":
            if len(current) >= count + int(eof) or frame["columns"] != columns or len(frame["values"]) != len(columns):
                v.reject("queries-row-order")
            expected = "nil" if len(current) < count else "eof"
            if outcome != expected:
                v.reject("queries-row-outcome")
            # EOF's reused driver buffer is never interpreted as an additional row.
            current.append([value(item) for item in frame["values"]] if outcome == "nil" else None)
        elif kind == "close":
            if len(current) != count + int(eof) or frame["columns"] is not None or frame["values"] or outcome != ("error" if active else "nil"):
                v.reject("queries-close")
            current.append("closed")
        elif kind == "result":
            if (
                len(current) != count + int(eof) + 1
                or current[-1] != "closed"
                or frame["columns"] is not None
                or frame["values"]
                or outcome != ("error" if active else "nil")
            ):
                v.reject("queries-result")
            result.append(current[:count])
            current = []
        else:
            v.reject("queries-kind")
    if current or len(result) != 3:
        v.reject("queries-completion")
    # The decoder admits only exact ints and bytes, with Boolean integers rejected;
    # compare these values directly rather than serializing decoded byte strings as JSON.
    if point != "checkpoint-close" and (result[0] != result[1] or result[1] != result[2]):
        v.reject("queries-changed-data")
    return result


def predicates(root: Path, point: str, rows: list, error: bool) -> list[bool]:
    """Derive untouched nontarget predicates from actual values and the admitted fixture's immutable initial state."""
    if point == "integrity-close":
        return [error, rows[0][0] != b"ok"]
    if point == "schema-close":
        source = v.read(root / structure.STORAGE / "schema.go").decode()
        declaration = source.split("var schema = []string{", 1)[1].split("\n}", 1)[0]
        expected = re.findall(r"`([^`]+)`", declaration)
        if len(expected) != 4 or {b" ".join(row[0].split()) for row in rows} != {b" ".join(item.encode().split()) for item in expected}:
            v.reject("queries-schema")
        return [error, len(rows) != len(expected)]
    row = rows[0]
    if point == "meta-close":
        if row != [1, 1, b"test", b"polaris", b"127.0.0.1:45101", 1, 2]:
            v.reject("queries-meta")
        return [error, row[1] != 1]
    if any(type(item) is not int for item in row):
        v.reject("queries-scalar")
    if point == "records-close":
        return [error, row[0] != 1, row[1] != 2]
    if point == "retained-close":
        return [error, row[0] != 1, row[1] != 66]
    if point == "checkpoint-close":
        if any(item < 0 for item in row):
            v.reject("queries-checkpoint")
        return [error, row[0] != 0, row[1] > row[2]]
    v.reject("queries-point")


def correlate(root: Path, trace: dict, events: bytes, inputs: dict) -> list[dict]:
    """Join six completed-query error effects with both actual old same-production masks; enclosing readers authenticate origins."""
    decisions = logic.inventory(trace)
    native, _ = logic.observe(trace, events, "github.com/eosforge/astra/" + structure.STORAGE, 247)
    if any(decisions.get(structure.STORAGE + "/" + name, {}).get("text") != expression for name, expression in EXPRESSIONS.items()):
        v.reject("queries-source")
    if not isinstance(inputs, dict) or set(inputs) != set(POINTS):
        v.reject("queries-points")
    proofs = []
    for point, (suffix, _, _, _) in POINTS.items():
        rows = groups(point, inputs[point])
        identity = structure.STORAGE + "/" + suffix
        before = predicates(root, point, rows[0], False)
        after = predicates(root, point, rows[1], True)
        if predicates(root, point, rows[2], True) != after:
            v.reject("queries-repeat")
        sides = {}
        for name, values in (("before", before), ("after", after)):
            _, result = authority.project(decisions[identity], values)
            sides[name] = {"values": values, "result": result}
        proof = authority.correlate_pair(decisions[identity], {"decision": identity, "condition": 0, **sides}, set(native[identity]))
        proofs.append(
            {
                **proof,
                "point": point,
                "inputs_sha256": v.digest(v.encode(inputs[point])),
                "basis": "Actual healthy/failed native row, close and operation receipts plus pinned GORM result-copy/close-error ordering; no skipped operand execution hit is inferred.",
            }
        )
    return proofs
