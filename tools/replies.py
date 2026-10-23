"""Reconcile actual post-substitution SQL replies and admission inputs without inventing skipped execution hits."""

from pathlib import Path
import re

from tools import authority, logic, queries, structure, transactions, verify as v

# Each named mechanism changes one predicate while preserving all other inputs relevant to its decision.
POINTS = {
    "snapshot-value": ("read.go:3910", 2, ["key", "value"], 1),
    "history-value": ("read.go:6637", 3, ["version", "key", "value", "erase", "cost"], 1),
    "state-retained": ("read.go:5624", 0, ["sector", "spectrum", "version", "records", "bytes", "retained", "backlog"], 1),
    "state-backlog": ("read.go:5624", 3, ["sector", "spectrum", "version", "records", "bytes", "retained", "backlog"], 1),
    "state-validation": ("schema.go:5601", 6, ["sector", "spectrum", "version", "records", "bytes", "retained", "backlog"], 1),
    "state-version": ("schema.go:5601", 1, ["sector", "spectrum", "version", "records", "bytes", "retained", "backlog"], 1),
    "binding-galaxy": ("schema.go:4872", 0, ["id", "format", "galaxy", "username", "advertise", "scopes", "bytes"], 1),
    "binding-username": ("schema.go:4872", 1, ["id", "format", "galaxy", "username", "advertise", "scopes", "bytes"], 1),
    "retained-count": ("schema.go:6814", 1, ["count", "bytes"], 1),
    "scope-capacity": ("schema.go:5291", 0, ["sector", "spectrum", "version", "records", "bytes", "retained", "backlog"], 2),
    "foreign-row": ("schema.go:7432", 0, ["table", "rowid", "parent", "fkid"], 0),
    "foreign-next": ("schema.go:7432", 1, ["table", "rowid", "parent", "fkid"], 0),
    "checkpoint-busy": ("store.go:11041", 1, ["busy", "log", "checkpointed"], 1),
}
EXPRESSIONS = {
    "read.go:3910": "err != nil || !text(record.Key, 1024) || record.Value == nil || len(record.Value) > 1<<20",
    "read.go:5624": "state.Retained < 0 || uint64(state.Retained) > uint64(state.Version) || state.Retained > store.limits.History || state.Backlog < 0 || state.Backlog > store.limits.Backlog",
    "read.go:6637": "err != nil || position == state.Version || change.Version != position+1 || change.Value == nil || cost != int64(64+len(change.Key)+len(change.Value))",
    "schema.go:4872": "meta.Galaxy != binding.Galaxy || meta.Username != binding.Username || meta.Advertise != binding.Advertise",
    "schema.go:5291": "int64(len(scopes)) > store.limits.Scopes || meta.Scopes != int64(len(scopes)) || meta.Bytes > store.limits.Total",
    "schema.go:5601": "!scope.Scope.Valid() || state.Version == 0 || state.Records > store.limits.Records || state.Bytes > store.limits.Bytes || state.Retained > store.limits.History || state.Backlog > store.limits.Backlog || state.Retained < 0 || uint64(state.Retained) > uint64(state.Version)",
    "schema.go:6814": "err != nil || retained.Count != state.Retained || retained.Bytes != state.Backlog",
    "schema.go:7432": "invalid || err != nil || closed != nil",
    "store.go:11041": "err != nil || progress.Busy != 0 || progress.Log > progress.Checkpointed",
    "commit.go:890": "!scope.Valid() || change.Version == 0 || err != nil",
    "feed.go:1983": "len(store.feeds) >= 128 || limit > (128<<20)-store.feedBytes",
}


def scalar(item: object) -> int | bytes | None:
    """Decode exact native SQL types, keeping NULL distinct from an empty blob."""
    if not isinstance(item, dict):
        v.reject("replies-value")
    if item.get("type") == "nil":
        logic.fields(item, ("type",), "replies-nil")
        return None
    if item.get("type") != "blob":
        return queries.value(item)
    logic.fields(item, ("type", "bytes", "sha256", "hex"), "replies-blob")
    transactions.integer(item["bytes"], 0, 4096)
    if not isinstance(item["hex"], str) or not re.fullmatch("(?:[0-9a-f]{2})*", item["hex"]):
        v.reject("replies-blob")
    data = bytes.fromhex(item["hex"])
    if len(data) != item["bytes"] or v.digest(data) != item["sha256"]:
        v.reject("replies-blob-identity")
    return data


def context(point: str, active: bool) -> dict:
    """Prescribe the fixture's independent seed and allowed input variation before reading native observations."""
    size = 1 if point == "history-value" else 786433 if point == "checkpoint-busy" else 2
    retained = 0 if point == "state-version" else 1
    version = 2**64 - 1 if point in ("state-retained", "state-validation") else 1
    limits = {
        "Scopes": 1 if point == "scope-capacity" and active else 4096,
        "Records": 65536,
        "Bytes": 67108864,
        "Total": 268435456,
        "History": 0 if point == "state-version" else 1000,
        "Backlog": 8388608,
        "Timeout": 5000000000,
        "WAL": 1048576 if point == "checkpoint-busy" else 134217728,
    }
    return {
        "point": point,
        "kind": "context",
        "active": active,
        "state": {"Version": version, "Records": 1, "Bytes": size, "Retained": retained, "Backlog": size + 64 if retained else 0},
        "meta": {
            "Format": 1,
            "Galaxy": "test",
            "Username": "polaris",
            "Advertise": "127.0.0.1:45101",
            "Scopes": 2 if point == "scope-capacity" else 1,
            "Bytes": 4 if point == "scope-capacity" else size,
        },
        "limits": limits,
        "binding": {"Galaxy": "test", "Username": "polaris", "Advertise": "127.0.0.1:45101"},
        "scope": {"Sector": "inspection", "Spectrum": "reply"},
        "cursor": version - 1 if point in ("state-retained", "state-validation") else 1 if point == "state-version" else 0,
    }


def groups(point: str, frames: list[dict]) -> list[dict]:
    """Require three complete context/next/close/result lifetimes, with only actually returned rows decoded."""
    if point not in POINTS or not isinstance(frames, list) or not 12 <= len(frames) <= 24:
        v.reject("replies-frames")
    _, _, columns, count = POINTS[point]
    result, current, closed, ended = [], None, False, False
    for frame in frames:
        if not isinstance(frame, dict):
            v.reject("replies-frame")
        active = bool(result)
        if frame.get("kind") == "context":
            if current is not None or v.encode(frame) != v.encode(context(point, active)):
                v.reject("replies-context")
            current, closed, ended = {"context": frame, "rows": [], "next": None}, False, False
            continue
        logic.fields(frame, ("point", "active", "kind", "columns", "values", "outcome"), "replies-frame")
        if (
            current is None
            or frame["point"] != point
            or type(frame["active"]) is not bool
            or frame["active"] != active
            or not isinstance(frame["values"], list)
        ):
            v.reject("replies-attribution")
        kind, outcome = frame["kind"], frame["outcome"]
        if kind == "next":
            if closed or ended or frame["columns"] != columns or len(frame["values"]) != len(columns) or outcome not in ("nil", "eof", "error"):
                v.reject("replies-row")
            current["next"] = outcome
            if outcome == "nil":
                current["rows"].append([scalar(item) for item in frame["values"]])
                if len(current["rows"]) > (1 if point == "foreign-row" and active else count):
                    v.reject("replies-row-count")
            else:
                ended = True
        elif kind == "close":
            if closed or current["next"] is None or frame["columns"] is not None or frame["values"] or outcome != "nil":
                v.reject("replies-close")
            closed = True
        elif kind == "result":
            if not closed or frame["columns"] is not None or frame["values"] or outcome != ("error" if active else "nil"):
                v.reject("replies-result")
            expected = 1 if point == "foreign-row" and active else count
            if len(current["rows"]) != expected:
                v.reject("replies-row-count")
            eof = (
                point in ("scope-capacity", "state-validation", "state-version", "foreign-row", "foreign-next")
                or not active
                and point in ("snapshot-value", "history-value")
            )
            terminal = "error" if point == "foreign-next" and active else "eof" if eof and not (point == "foreign-row" and active) else "nil"
            if current["next"] != terminal:
                v.reject("replies-next-completion")
            result.append(current)
            current = None
        else:
            v.reject("replies-kind")
    if current is not None or len(result) != 3:
        v.reject("replies-completion")
    if point != "checkpoint-busy" and result[1] != result[2]:
        v.reject("replies-repeat")
    return result


def predicates(point: str, lifetime: dict) -> list[bool]:
    """Interpret returned data through independent scalar rules, retaining the underlying atom of a source negation."""
    ctx, rows = lifetime["context"], lifetime["rows"]
    state, limits = ctx["state"], ctx["limits"]
    active = ctx["active"]
    if point.startswith("foreign-"):
        if rows != ([[b"records", None, b"scopes", 0]] if point == "foreign-row" and active else []):
            v.reject("replies-foreign-row")
        return [bool(rows), lifetime["next"] == "error", False]
    row = rows[0]
    if point == "snapshot-value":
        if row != [b"k", None if active else b"v"]:
            v.reject("replies-snapshot")
        return [False, True, row[1] is None, len(row[1] or b"") > 1 << 20]
    if point == "history-value":
        if row != [bytes.fromhex("0000000000000001"), b"k", None if active else b"", 0, 65]:
            v.reject("replies-history")
        return [
            False,
            ctx["cursor"] == state["Version"],
            int.from_bytes(row[0], "big") != ctx["cursor"] + 1,
            row[2] is None,
            row[4] != 64 + len(row[1]) + len(row[2] or b""),
        ]
    if point.startswith("state-") or point == "scope-capacity":
        for index, item in enumerate(rows):
            expected = [
                b"inspection",
                b"reply" if index == 0 else b"second",
                state["Version"].to_bytes(8, "big"),
                1,
                state["Bytes"],
                state["Retained"],
                state["Backlog"],
            ]
            if active and point in ("state-retained", "state-validation"):
                expected[5] = -1
            elif active and point == "state-backlog":
                expected[6] = -1
            elif active and point == "state-version":
                expected[2] = bytes(8)
            if item != expected:
                v.reject("replies-state")
        version, retained, backlog = int.from_bytes(row[2], "big"), row[5], row[6]
        if point == "scope-capacity":
            return [len(rows) > limits["Scopes"], ctx["meta"]["Scopes"] != len(rows), ctx["meta"]["Bytes"] > limits["Total"]]
        if point in ("state-validation", "state-version"):
            return [
                True,
                version == 0,
                row[3] > limits["Records"],
                row[4] > limits["Bytes"],
                retained > limits["History"],
                backlog > limits["Backlog"],
                retained < 0,
                retained % 2**64 > version,
            ]
        return [retained < 0, retained % 2**64 > version, retained > limits["History"], backlog < 0, backlog > limits["Backlog"]]
    if point.startswith("binding-"):
        expected = [1, 1, b"test", b"polaris", b"127.0.0.1:45101", 1, 2]
        if active:
            expected[2 if point == "binding-galaxy" else 3] = b"other"
        if row != expected:
            v.reject("replies-binding")
        return [row[2] != ctx["binding"]["Galaxy"].encode(), row[3] != ctx["binding"]["Username"].encode(), row[4] != ctx["binding"]["Advertise"].encode()]
    if point == "retained-count":
        if row != [2 if active else 1, 66]:
            v.reject("replies-retained")
        return [False, row[0] != state["Retained"], row[1] != state["Backlog"]]
    if point == "checkpoint-busy":
        if any(type(item) is not int or item < 0 for item in row) or row[0] != int(active) or row[1] > row[2]:
            v.reject("replies-checkpoint")
        return [False, row[0] != 0, row[1] > row[2]]
    v.reject("replies-point")


def guards(frames: list[dict]) -> dict[str, list[bool]]:
    """Require the complete three-input commit product and all 129 consecutive native subscription receipts."""
    if not isinstance(frames, list) or len(frames) != 132:
        v.reject("replies-guards")
    result = {}
    for point, frame in zip(("valid", "scope", "version"), frames[:3], strict=True):
        logic.fields(frame, ("kind", "point", "scope", "change", "entry_error", "version", "outcome", "before_sha256", "after_sha256"), "replies-commit")
        expected = {
            "kind": "commit",
            "point": point,
            "scope": {"Sector": "" if point == "scope" else "guard", "Spectrum": "reply"},
            "change": {"Version": 0 if point == "version" else 1, "Key": "k", "Value": "dg==", "Erase": False},
            "entry_error": False,
            "version": 1 if point == "valid" else 0,
            "outcome": "nil" if point == "valid" else "input",
        }
        if v.encode({name: frame[name] for name in expected}) != v.encode(expected):
            v.reject("replies-commit-inputs")
        if any(not isinstance(frame[name], str) or not re.fullmatch("[0-9a-f]{64}", frame[name]) for name in ("before_sha256", "after_sha256")):
            v.reject("replies-commit-state")
        if (frame["before_sha256"] != frame["after_sha256"]) != (point == "valid"):
            v.reject("replies-commit-mutation")
        result[point] = [bool(frame["scope"]["Sector"]), frame["change"]["Version"] == 0, frame["entry_error"]]
    for index, frame in enumerate(frames[3:]):
        count = min(index, 128)
        expected = {
            "kind": "feed",
            "index": index,
            "count": count,
            "reserved": count,
            "limit": 1,
            "items": 1,
            "outcome": "nil" if index < 128 else "capacity",
            "after_count": min(index + 1, 128),
            "after_reserved": min(index + 1, 128),
        }
        if v.encode(frame) != v.encode(expected):
            v.reject("replies-feed-inputs")
    result["feed-before"] = [frames[-2]["count"] >= 128, frames[-2]["limit"] > (128 << 20) - frames[-2]["reserved"]]
    result["feed-after"] = [frames[-1]["count"] >= 128, frames[-1]["limit"] > (128 << 20) - frames[-1]["reserved"]]
    return result


def correlate(root: Path, trace: dict, events: bytes, inputs: dict, admitted: list) -> list[dict]:
    """Join sixteen total-input effects to original source-bound native masks; enclosing reception authenticates collection and cleanup."""
    decisions = logic.inventory(trace)
    native, _ = logic.observe(trace, events, "github.com/eosforge/astra/" + structure.STORAGE, 247)
    if any(decisions.get(structure.STORAGE + "/" + name, {}).get("text") != expression for name, expression in EXPRESSIONS.items()):
        v.reject("replies-source")
    if not isinstance(inputs, dict) or set(inputs) != set(POINTS):
        v.reject("replies-points")
    identities = {structure.STORAGE + "/" + name for name in EXPRESSIONS}
    if any(not native.get(name) or any(type(hits) is not int or hits <= 0 for hits in native[name].values()) for name in identities):
        v.reject("replies-native-counts")
    candidates = []
    for point, (suffix, condition, _, _) in POINTS.items():
        rows = groups(point, inputs[point])
        before, after = predicates(point, rows[0]), predicates(point, rows[1])
        if predicates(point, rows[2]) != after:
            v.reject("replies-repeat-predicates")
        candidates.append((point, suffix, condition, before, after, inputs[point]))
    data = guards(admitted)
    candidates.extend((point, "commit.go:890", index, data["valid"], data[point], admitted[:3]) for point, index in (("scope", 0), ("version", 1)))
    candidates.append(("feeds", "feed.go:1983", 0, data["feed-before"], data["feed-after"], admitted[3:]))
    proofs = []
    for point, suffix, condition, before, after, actual in candidates:
        identity = structure.STORAGE + "/" + suffix
        sides = {
            name: {"values": values, "result": authority.project(decisions[identity], values)[1]} for name, values in (("before", before), ("after", after))
        }
        proof = authority.correlate_pair(decisions[identity], {"decision": identity, "condition": condition, **sides}, set(native[identity]))
        proofs.append(
            {
                **proof,
                "point": point,
                "inputs_sha256": v.digest(v.encode(actual)),
                "basis": "Actual post-substitution native reply/context or admission inputs; pure scalar predicates preserve source negations. Both original masks remain mandatory, and skipped operands receive no execution hits.",
            }
        )
    return proofs
