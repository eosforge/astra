"""Validate native Storage transaction inputs and derive only source-bound, total-input condition witnesses."""

import base64
from pathlib import Path

from tools import authority, logic, structure, verify as v

# These are fixed boundary mechanisms, not names inferred from a successful output.
CASES = (
    "scopes-receipt",
    "meta-receipt",
    "retry-same",
    "retry-key",
    "retry-erase",
    "retry-value",
    "scope-existing-full",
    "scope-new-full",
    "scope-new-space",
    "capacity-fit",
    "capacity-records",
    "capacity-bytes",
    "negative-records",
    "history-off",
    "history-within",
    "history-count",
    "history-bytes",
    "history-both",
    "history-zero-prefix",
    "history-short-prefix",
    "history-negative",
    "history-excess",
)
FAILURES = {
    "scope-new-full": "capacity",
    "capacity-records": "capacity",
    "capacity-bytes": "capacity",
    "negative-records": "corrupt",
    "history-zero-prefix": "corrupt",
    "history-short-prefix": "corrupt",
    "history-negative": "corrupt",
    "history-excess": "corrupt",
}
EXPRESSIONS = {
    "commit.go:2611": "!exists && meta.Scopes >= store.limits.Scopes",
    "commit.go:3304": "state.Records < 0 || state.Bytes < 0",
    "commit.go:3448": "state.Records > store.limits.Records || state.Bytes > store.limits.Bytes || meta.Bytes+state.Bytes-previous > store.limits.Total",
    "commit.go:5064": "result.Error != nil || result.RowsAffected != 1",
    "commit.go:5404": "result.Error != nil || result.RowsAffected != 1",
    "commit.go:7097": "actual.Key != expected.Key || actual.Erase != expected.Erase || !bytes.Equal(actual.Value, expected.Value)",
    "commit.go:7697": "store.limits.History == 0 || cost > store.limits.Backlog",
    "commit.go:8303": "state.Retained <= store.limits.History && state.Backlog <= store.limits.Backlog",
    "commit.go:9427": "through == 0 || state.Retained > store.limits.History || state.Backlog < 0 || state.Backlog > store.limits.Backlog",
}


def selection(check: dict) -> dict:
    """Repair only the missing child declarations while preserving the frozen command, case inventory and parent budget."""
    expected = ["TestTransactionInputs", *("TestTransactionInputs/" + name for name in CASES)]
    parent = {"contract": "STORAGE-BOUNDARY", "test": "TestTransactionInputs", "minimum_hits": 22}
    if (
        check.get("expected_tests") != expected
        or check.get("probes") != [parent]
        or check.get("adapter") != "go-test-json"
        or check.get("package") != "github.com/eosforge/astra/polaris/internal/storage"
    ):
        v.reject("transactions-selection")
    probes = [parent]
    for point in CASES:
        hits = (
            14
            if point.endswith("-receipt")
            else 8 if point.startswith("retry-") else 13 if point in FAILURES and FAILURES[point] == "corrupt" else 10 if point in FAILURES else 6
        )
        probes.append({"contract": "STORAGE-BOUNDARY", "test": "TestTransactionInputs/" + point, "minimum_hits": hits})
    return {**check, "probes": probes}


def integer(value: object, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    """Reject Boolean coercion and numeric values outside the captured SQL/Go domain."""
    if type(value) is not int or not minimum <= value <= maximum:
        v.reject("transactions-integer")
    return value


def payload(value: object) -> bytes:
    """Decode canonical captured byte strings without treating SQL null as an empty value."""
    if not isinstance(value, str):
        v.reject("transactions-payload")
    try:
        data = base64.b64decode(value, validate=True)
    except ValueError:
        v.reject("transactions-payload")
    if base64.b64encode(data).decode() != value or len(data) > 4096:
        v.reject("transactions-payload")
    return data


def change(row: dict, *, cost: bool = False) -> None:
    """Validate an actual copied mutation or persisted history row, including all identity fields."""
    logic.fields(row, ("Version", "Key", "Value", "Erase", *(("Cost",) if cost else ())), "transactions-change")
    integer(row["Version"], 0, 2**64 - 1)
    if type(row["Erase"]) is not bool or not isinstance(row["Key"], str) or row["Key"] not in ("k", "z"):
        v.reject("transactions-change")
    payload(row["Value"])
    if cost:
        integer(row["Cost"], 1)


def snapshot(row: dict) -> None:
    """Check exact native row shapes and fixed fixture environment before evaluating pure predicates."""
    logic.fields(row, ("state", "exists", "meta", "records", "history", "limits"), "transactions-snapshot")
    if type(row["exists"]) is not bool:
        v.reject("transactions-exists")
    logic.fields(row["state"], ("Version", "Records", "Bytes", "Retained", "Backlog"), "transactions-state")
    for name, value in row["state"].items():
        integer(value, 0, 2**64 - 1 if name == "Version" else 2**63 - 1)
    logic.fields(row["meta"], ("Format", "Galaxy", "Username", "Advertise", "Scopes", "Bytes"), "transactions-meta")
    if {name: row["meta"][name] for name in ("Format", "Galaxy", "Username", "Advertise")} != {
        "Format": 1,
        "Galaxy": "test",
        "Username": "polaris",
        "Advertise": "127.0.0.1:45101",
    }:
        v.reject("transactions-binding")
    integer(row["meta"]["Scopes"])
    integer(row["meta"]["Bytes"])
    logic.fields(row["limits"], ("Scopes", "Records", "Bytes", "Total", "History", "Backlog", "Timeout", "WAL"), "transactions-limits")
    for name, value in row["limits"].items():
        integer(value, 0 if name in ("History", "Backlog") else 1)
    if row["limits"]["Timeout"] != 5_000_000_000 or row["limits"]["WAL"] != 134217728 or row["limits"]["Total"] != 268435456:
        v.reject("transactions-limits")
    for name in ("records", "history"):
        if row[name] is not None and (not isinstance(row[name], list) or len(row[name]) > 4):
            v.reject("transactions-rows")
    keys = []
    for item in row["records"] or []:
        logic.fields(item, ("Key", "Value"), "transactions-record")
        if item["Key"] not in ("k", "z"):
            v.reject("transactions-record")
        payload(item["Value"])
        keys.append(item["Key"])
    if keys != sorted(set(keys)):
        v.reject("transactions-record-order")
    versions = []
    for item in row["history"] or []:
        change(item, cost=True)
        versions.append(item["Version"])
    if versions != sorted(set(versions)):
        v.reject("transactions-history-order")
    if not row["exists"] and (any(row["state"].values()) or row["records"] or row["history"]):
        v.reject("transactions-absent-state")


def billing(frame: dict) -> dict[str, list[bool]]:
    """Recompute final record/payload accounting from the exact native old records and actual request."""
    before, request = frame["before"], frame["request"]
    state, meta, limits = before["state"], before["meta"], before["limits"]
    records, size = state["Records"], state["Bytes"]
    previous = next((item for item in before["records"] or [] if item["Key"] == request["Key"]), None)
    if previous is not None:
        records -= 1
        size -= len(previous["Key"].encode()) + len(payload(previous["Value"]))
    if not request["Erase"]:
        records += 1
        size += len(request["Key"].encode()) + len(payload(request["Value"]))
    output = {"commit.go:2611": [before["exists"], meta["Scopes"] >= limits["Scopes"]]}
    if not before["exists"] and meta["Scopes"] >= limits["Scopes"]:
        return output
    output["commit.go:3304"] = [records < 0, size < 0]
    if any(output["commit.go:3304"]):
        return output
    output["commit.go:3448"] = [records > limits["Records"], size > limits["Bytes"], meta["Bytes"] + size - state["Bytes"] > limits["Total"]]
    return output


def retention(frame: dict) -> dict[str, list[bool]]:
    """Follow the actual consumed SQL prefix, preserving skipped Next as undefined rather than manufacturing its result."""
    before, request = frame["before"], frame["request"]
    state, limits = before["state"], before["limits"]
    cost = 64 + len(request["Key"].encode()) + len(payload(request["Value"]))
    output = {"commit.go:7697": [limits["History"] == 0, cost > limits["Backlog"]]}
    prefix = frame["prefix"]
    if prefix is not None and (not isinstance(prefix, list) or len(prefix) > 6):
        v.reject("transactions-prefix")
    if any(output["commit.go:7697"]):
        if prefix:
            v.reject("transactions-disabled-prefix")
        return output
    retained, backlog = state["Retained"] + 1, state["Backlog"] + cost
    output["commit.go:8303"] = [retained <= limits["History"], backlog <= limits["Backlog"]]
    if all(output["commit.go:8303"]):
        if prefix:
            v.reject("transactions-unneeded-prefix")
        return output
    if not prefix or prefix[-1] != {"kind": "close", "outcome": "nil"}:
        v.reject("transactions-prefix-close")
    expected = [*(before["history"] or []), {**request, "Cost": cost}]
    expected.sort(key=lambda item: item["Version"])
    expected = expected[:retained]
    position, through, ended = 0, 0, False
    for item in prefix[:-1]:
        if ended or not (retained > limits["History"] or backlog > limits["Backlog"]):
            v.reject("transactions-prefix-unreached")
        if item == {"kind": "next", "outcome": "eof"}:
            if position != len(expected):
                v.reject("transactions-prefix-early-eof")
            ended = True
            continue
        logic.fields(item, ("kind", "outcome", "version", "cost"), "transactions-prefix-row")
        if item["kind"] != "next" or item["outcome"] != "nil" or position >= len(expected):
            v.reject("transactions-prefix-row")
        integer(item["cost"], 1)
        if item["version"] != expected[position]["Version"].to_bytes(8, "big").hex() or item["cost"] != expected[position]["Cost"]:
            v.reject("transactions-prefix-content")
        through = expected[position]["Version"]
        retained -= 1
        backlog -= item["cost"]
        position += 1
    if (retained > limits["History"] or backlog > limits["Backlog"]) and not ended:
        v.reject("transactions-prefix-truncated")
    output["commit.go:9427"] = [through == 0, retained > limits["History"], backlog < 0, backlog > limits["Backlog"]]
    return output


def observations(inputs: dict) -> dict[str, list[dict[str, list[bool]]]]:
    """Validate complete per-case receipts and return source-bound predicate values for reached pure decisions only."""
    if not isinstance(inputs, dict) or set(inputs) != set(CASES):
        v.reject("transactions-cases")
    observed = {}
    for point in CASES:
        frames = inputs[point]
        receipts = point.endswith("-receipt")
        wanted = "version" if point in ("retry-key", "retry-erase", "retry-value") else FAILURES.get(point, "nil")
        count = 1 if receipts or wanted == "nil" and point != "retry-same" else 2
        if not isinstance(frames, list) or len(frames) != count:
            v.reject("transactions-completion")
        values = []
        for index, frame in enumerate(frames):
            fields = (
                ("point", "before", "request", "receipts")
                if receipts
                else ("point", "attempt", "before", "request", "version", "outcome", *(() if point.startswith("retry-") else ("prefix",)))
            )
            logic.fields(frame, fields, "transactions-frame")
            if frame["point"] != point:
                v.reject("transactions-attribution")
            snapshot(frame["before"])
            change(frame["request"])
            if receipts:
                rows = frame["receipts"]
                if not isinstance(rows, list) or len(rows) != 3:
                    v.reject("transactions-receipts")
                suffix = "commit.go:5064" if point == "scopes-receipt" else "commit.go:5404"
                actual = []
                for number, row in enumerate(rows):
                    logic.fields(row, ("rows", "error", "injected", "sql"), "transactions-receipt")
                    if (
                        type(row["error"]) is not bool
                        or type(row["injected"]) is not bool
                        or row["error"] != (number < 2)
                        or row["injected"] != row["error"]
                        or type(row["rows"]) is not int
                        or row["rows"] != 1
                        or not isinstance(row["sql"], str)
                        or not row["sql"].startswith("UPDATE " + point.split("-")[0] + " SET")
                    ):
                        v.reject("transactions-receipt")
                    actual.append({suffix: [row["error"], row["rows"] != 1]})
                values.extend(actual)
                continue
            if type(frame["attempt"]) is not int or frame["attempt"] != index or frame["outcome"] != wanted:
                v.reject("transactions-outcome")
            integer(frame["version"], 0, 2**64 - 1)
            if frame["version"] != (frame["request"]["Version"] if wanted == "nil" else 0):
                v.reject("transactions-version")
            if point.startswith("retry-"):
                history = frame["before"]["history"]
                if not history or len(history) != 1 or history[0]["Version"] != frame["request"]["Version"]:
                    v.reject("transactions-retry-history")
                actual, expected = history[0], frame["request"]
                values.append(
                    {
                        "commit.go:7097": [
                            actual["Key"] != expected["Key"],
                            actual["Erase"] != expected["Erase"],
                            # Unary ! is an AST node; the atom retains equality's polarity.
                            payload(actual["Value"]) == payload(expected["Value"]),
                        ]
                    }
                )
            else:
                current = billing(frame)
                # Accounting/capacity rejection precedes retain; do not credit unreachable history decisions.
                if wanted == "nil" or point.startswith("history-"):
                    current.update(retention(frame))
                values.append(current)
        if not receipts and len(frames) == 2 and any(frames[0][name] != frames[1][name] for name in frames[0] if name != "attempt"):
            v.reject("transactions-repeat")
        observed[point] = values
    return observed


def correlate(root: Path, trace: dict, events: bytes, inputs: dict) -> list[dict]:
    """Require both original native masks and actual total-input single-predicate effects for thirteen named boundaries."""
    decisions = logic.inventory(trace)
    native, _ = logic.observe(trace, events, "github.com/eosforge/astra/" + structure.STORAGE, 247)
    if any(decisions.get(structure.STORAGE + "/" + name, {}).get("text") != text for name, text in EXPRESSIONS.items()):
        v.reject("transactions-source")
    observed = observations(inputs)
    targets = (
        ("commit.go:5064", 0, "scopes-receipt", 2, "scopes-receipt", 0),
        ("commit.go:5404", 0, "meta-receipt", 2, "meta-receipt", 0),
        ("commit.go:7097", 0, "retry-same", 0, "retry-key", 0),
        ("commit.go:7097", 1, "retry-same", 0, "retry-erase", 0),
        ("commit.go:2611", 0, "scope-existing-full", 0, "scope-new-full", 0),
        ("commit.go:3304", 0, "capacity-fit", 0, "negative-records", 0),
        ("commit.go:3448", 0, "capacity-fit", 0, "capacity-records", 0),
        ("commit.go:3448", 1, "capacity-fit", 0, "capacity-bytes", 0),
        ("commit.go:7697", 0, "history-within", 0, "history-off", 0),
        ("commit.go:8303", 0, "history-within", 0, "history-count", 0),
        ("commit.go:9427", 0, "history-count", 0, "history-zero-prefix", 0),
        ("commit.go:9427", 1, "history-count", 0, "history-short-prefix", 0),
        ("commit.go:9427", 2, "history-count", 0, "history-negative", 0),
    )
    proofs = []
    for suffix, target, before, first, after, second in targets:
        identity = structure.STORAGE + "/" + suffix
        sides = {}
        for name, point, index in (("before", before, first), ("after", after, second)):
            values = observed[point][index][suffix]
            _, result = authority.project(decisions[identity], values)
            sides[name] = {"values": values, "result": result}
        proof = authority.correlate_pair(decisions[identity], {"decision": identity, "condition": target, **sides}, set(native[identity]))
        proofs.append(
            {
                **proof,
                "cases": [before, after],
                "inputs_sha256": v.digest(v.encode({point: inputs[point] for point in (before, after)})),
                "basis": "Actual native transaction inputs, completed update receipts and consumed SQL history prefixes; skipped cursor calls acquire no values or execution hits.",
            }
        )
    return proofs
