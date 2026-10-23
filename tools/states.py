"""Correlate source-bound native persisted Scope inputs with Storage's actual pure state guards."""

from pathlib import Path

from tools import authority, logic, storage, structure, verify as v

COLUMNS = ["sector", "spectrum", "version", "records", "bytes", "retained", "backlog"]
QUERY = "SELECT * FROM scopes ORDER BY sector,spectrum"
CASES = {
    "scope-invalid": (("schema.go:5601", 0),),
    "record-count-capacity": (("schema.go:5601", 2), ("read.go:3265", 0)),
    "record-byte-capacity": (("schema.go:5601", 3),),
    "history-count-capacity": (("schema.go:5601", 4), ("read.go:5624", 2)),
    "history-byte-capacity": (("schema.go:5601", 5),),
    "history-version-count": (("read.go:5624", 1),),
}


def state(row: list) -> dict:
    """Decode exact captured SQL values, checking blob identity and preserving invalid text bytes."""
    if not isinstance(row, list) or len(row) != len(COLUMNS):
        v.reject("states-row")
    values = dict(zip(COLUMNS, row, strict=True))
    for field in ("sector", "spectrum"):
        item = values[field]
        logic.fields(item, ("type", "hex"), "states-text")
        if item["type"] != "text":
            v.reject("states-text")
        data = bytes.fromhex(item["hex"])
        if data.hex() != item["hex"]:
            v.reject("states-text-encoding")
        values[field] = data
    item = values["version"]
    logic.fields(item, ("type", "bytes", "sha256", "hex"), "states-version")
    data = bytes.fromhex(item["hex"])
    if item["type"] != "blob" or item["bytes"] != 8 or len(data) != 8 or data.hex() != item["hex"] or item["sha256"] != v.digest(data):
        v.reject("states-version")
    values["version"] = int.from_bytes(data, "big")
    if any(type(values[field]) is not int for field in ("records", "bytes", "retained", "backlog")):
        v.reject("states-integer")
    return values


def predicates(identity: str, row: dict) -> list[bool]:
    """Derive the admitted fixture's default-bound state predicates independently of production outcomes."""
    valid = all(all(storage.text_input(row[field], 128)) for field in ("sector", "spectrum"))
    version, records, size, retained, backlog = (row[field] for field in ("version", "records", "bytes", "retained", "backlog"))
    if identity.endswith("schema.go:5601"):
        return [valid, version == 0, records > 65536, size > 64 * 2**20, retained > 1000, backlog > 8 * 2**20, retained < 0, retained % 2**64 > version]
    if identity.endswith("read.go:3265"):
        return [records > 65536, size > 64 * 2**20]
    if identity.endswith("read.go:5624"):
        return [retained < 0, retained % 2**64 > version, retained > 1000, backlog < 0, backlog > 8 * 2**20]
    v.reject("states-decision")


def observations(root: Path, trace: dict, events: bytes, inputs: dict) -> list[dict]:
    """Require real before/damaged/rejected SQL snapshots and both observed diagnostic masks for every pair."""
    # The admitted test calls fixture(t, Default()); these exact immutable defaults
    # are inferred source inputs, not claimed SQL columns or process-memory budgets.
    source = v.read(root / structure.STORAGE / "model.go")
    default = b"return Limits{Scopes: 4096, Records: 65536, Bytes: 64 << 20, Total: 256 << 20, History: 1000, Backlog: 8 << 20, Timeout: 5 * time.Second, WAL: 128 << 20}"
    if (
        source.count(default) != 1
        or v.file_digest(root / structure.STORAGE / "corruption_test.go") != "ee6c96db8b5a8f00d3e826d139c449f1d0895422d07fca1b56a22437271fe829"
    ):
        v.reject("states-fixture-defaults")
    decisions = logic.inventory(trace)
    native, _ = logic.observe(trace, events, "github.com/eosforge/astra/" + structure.STORAGE, 247)
    proofs = []
    for case, targets in CASES.items():
        selected = [item for item in inputs["TestCorruption/" + case] if item["query"] == QUERY]
        if len(selected) != 5 or any(item["columns"] != COLUMNS or not isinstance(item["rows"], list) or len(item["rows"]) != 2 for item in selected):
            v.reject("states-snapshot-domain", case)
        if any(item["rows"] != selected[1]["rows"] for item in selected[2:]):
            v.reject("states-mutated-rejected-state", case)
        before, after = state(selected[0]["rows"][0]), state(selected[1]["rows"][0])
        for suffix, target in targets:
            identity = structure.STORAGE + "/" + suffix
            decision = decisions[identity]
            sides = {}
            for name, value in (("before", before), ("after", after)):
                values = predicates(identity, value)
                _, outcome = authority.project(decision, values)
                sides[name] = {"values": values, "result": outcome}
            proof = authority.correlate_pair(decision, {"decision": identity, "condition": target, **sides}, set(native[identity]))
            proofs.append(
                {
                    **proof,
                    "case": "TestCorruption/" + case,
                    "sql_snapshots_sha256": v.digest(v.encode(selected)),
                    "bounds_basis": "Exact unchanged Default fixture inputs, separately bound from captured SQL columns.",
                    "basis": "Immutable normalized native SQL fields across the original rejected operation/reopen, independent byte/integer predicates and both original same-production diagnostic masks.",
                }
            )
    if len(proofs) != 8:
        v.reject("states-coverage")
    return proofs


def sequence(trace: dict, events: bytes, inputs: dict) -> list[dict]:
    """Join complete native SQL inputs with observed successful scan/query prefixes and pure sequence predicates."""
    decisions = logic.inventory(trace)
    native, _ = logic.observe(trace, events, "github.com/eosforge/astra/" + structure.STORAGE, 247)
    expected = {
        "read.go:3910": "err != nil || !text(record.Key, 1024) || record.Value == nil || len(record.Value) > 1<<20",
        "read.go:6637": "err != nil || position == state.Version || change.Version != position+1 || change.Value == nil || cost != int64(64+len(change.Key)+len(change.Value))",
        "schema.go:6230": "err != nil || actual.Records != state.Records || actual.Bytes != state.Bytes",
    }
    if any(decisions.get(structure.STORAGE + "/" + name, {}).get("text") != expression for name, expression in expected.items()):
        v.reject("states-sequence-source")

    def text(value: dict) -> bytes:
        """Decode exact SQLite text bytes without normalizing an invalid key into valid Unicode."""
        logic.fields(value, ("type", "hex"), "states-sequence-text")
        if value["type"] != "text" or not isinstance(value["hex"], str):
            v.reject("states-sequence-text")
        data = bytes.fromhex(value["hex"])
        if data.hex() != value["hex"]:
            v.reject("states-sequence-text-encoding")
        return data

    def blob(value: dict) -> bytes:
        """Require actual bounded non-null blob content, count and digest rather than an inferred nil value."""
        logic.fields(value, ("type", "hex", "bytes", "sha256"), "states-sequence-blob")
        if value["type"] != "blob" or type(value["bytes"]) is not int or not 0 <= value["bytes"] <= 4096 or not isinstance(value["hex"], str):
            v.reject("states-sequence-blob")
        data = bytes.fromhex(value["hex"])
        if len(data) != value["bytes"] or data.hex() != value["hex"] or v.digest(data) != value["sha256"]:
            v.reject("states-sequence-blob-integrity")
        return data

    queries = {
        "scopes": (QUERY, COLUMNS),
        "records": ("SELECT * FROM records ORDER BY sector,spectrum,key", ["sector", "spectrum", "key", "value"]),
        "history": ("SELECT * FROM history ORDER BY sector,spectrum,version", ["sector", "spectrum", "version", "key", "value", "erase", "cost"]),
    }
    required = (
        ("record-empty-key", "read.go:3910", 1),
        ("history-extra", "read.go:6637", 1),
        ("history-gap", "read.go:6637", 2),
        ("record-under-count", "schema.go:6230", 1),
    )
    proofs = []
    for case, suffix, target in required:
        frames = inputs.get("TestCorruption/" + case)
        if not isinstance(frames, list) or len(frames) != 25:
            v.reject("states-sequence-snapshots")
        for frame in frames:
            logic.fields(frame, ("query", "columns", "rows"), "states-sequence-frame")
        selected = {}
        for kind, (query, columns) in queries.items():
            values = [frame for frame in frames if frame["query"] == query]
            if len(values) != 5 or any(frame["columns"] != columns or not isinstance(frame["rows"], list) for frame in values):
                v.reject("states-sequence-columns")
            if any(v.encode(frame["rows"]) != v.encode(values[1]["rows"]) for frame in values[2:]):
                v.reject("states-sequence-mutated-rejection")
            selected[kind] = values
        sides = {}
        for index, side in enumerate(("before", "after")):
            scope_rows = selected["scopes"][index]["rows"]
            if len(scope_rows) != 2:
                v.reject("states-sequence-scope-domain")
            scope = state(scope_rows[0])
            if scope["sector"] != b"s" or scope["spectrum"] != b"p" or scope["version"] != 3 or scope["retained"] != 3 or scope["backlog"] != 198:
                v.reject("states-sequence-scope")
            records = []
            for row in selected["records"][index]["rows"]:
                if not isinstance(row, list) or len(row) != 4:
                    v.reject("states-sequence-record")
                sector, spectrum, key = map(text, row[:3])
                value = blob(row[3])
                if (sector, spectrum) == (b"s", b"p"):
                    records.append((key, value))
            if len(records) != 2 or records != sorted(records):
                v.reject("states-sequence-record-order")
            if suffix.endswith("3910"):
                key, value = records[0]
                values = [False, all(storage.text_input(key, 1024)), False, len(value) > 1 << 20]
            elif suffix.endswith("6230"):
                if any(not all(storage.text_input(key, 1024)) for key, _ in records):
                    v.reject("states-sequence-key-domain")
                values = [False, len(records) != scope["records"], sum(len(key) + len(value) for key, value in records) != scope["bytes"]]
            else:
                history = []
                for row in selected["history"][index]["rows"]:
                    if not isinstance(row, list) or len(row) != 7 or type(row[5]) is not int or row[5] not in (0, 1) or type(row[6]) is not int:
                        v.reject("states-sequence-history")
                    sector, spectrum, key = (text(row[position]) for position in (0, 1, 3))
                    encoded, value = blob(row[2]), blob(row[4])
                    if len(encoded) != 8 or not all(storage.text_input(key, 1024)) or row[5] != 0:
                        v.reject("states-sequence-history-domain")
                    if (sector, spectrum) == (b"s", b"p"):
                        history.append((int.from_bytes(encoded, "big"), key, value, row[6]))
                if history != sorted(history) or len(history) != (3 if index == 0 else 4 if case == "history-extra" else 2):
                    v.reject("states-sequence-history-order")
                position = 0
                for version, key, value, cost in history:
                    values = [False, position == scope["version"], version != position + 1, False, cost != 64 + len(key) + len(value)]
                    if any(values):
                        break
                    position = version
            identity = structure.STORAGE + "/" + suffix
            mask, result = authority.project(decisions[identity], values)
            # Error=false is an actually evaluated prefix in each matching original mask,
            # never reconstructed from a SQL blob or used to qualify an error predicate.
            if mask[0] != "1" or (mask, result) not in native[identity] or native[identity][(mask, result)] <= 0:
                v.reject("states-sequence-prefix")
            sides[side] = {"values": values, "result": result}
        identity = structure.STORAGE + "/" + suffix
        proof = authority.correlate_pair(decisions[identity], {"decision": identity, "condition": target, **sides}, set(native[identity]))
        proofs.append(
            {
                **proof,
                "case": "TestCorruption/" + case,
                "sql_snapshots_sha256": v.digest(v.encode(selected)),
                "basis": "Original evaluated successful scan/query prefixes plus complete immutable SQL rows, exact replay origin and independently derived key/sequence/count predicates. No error, nil, cursor or skipped-operand execution hit is invented.",
            }
        )
    return proofs


def totals(trace: dict, events: bytes, inputs: dict) -> list[dict]:
    """Correlate three pure byte/count predicates with complete native SQL snapshots and original masks."""
    decisions = logic.inventory(trace)
    native, _ = logic.observe(trace, events, "github.com/eosforge/astra/" + structure.STORAGE, 247)
    expected = {
        "read.go:4098": "total > state.Bytes || int64(len(result.Records)) >= state.Records",
        "read.go:4380": "total != state.Bytes || int64(len(result.Records)) != state.Records",
        "schema.go:5291": "int64(len(scopes)) > store.limits.Scopes || meta.Scopes != int64(len(scopes)) || meta.Bytes > store.limits.Total",
    }
    if any(decisions.get(structure.STORAGE + "/" + name, {}).get("text") != expression for name, expression in expected.items()):
        v.reject("states-total-source")
    queries = {
        "scopes": (QUERY, COLUMNS),
        "records": ("SELECT * FROM records ORDER BY sector,spectrum,key", ["sector", "spectrum", "key", "value"]),
        "meta": ("SELECT * FROM meta ORDER BY id", ["id", "format", "galaxy", "username", "advertise", "scopes", "bytes"]),
    }
    required = (("record-under-bytes", "read.go:4098", 0), ("record-over-bytes", "read.go:4380", 0), ("meta-scopes", "schema.go:5291", 1))
    proofs = []
    for case, suffix, target in required:
        frames = inputs.get("TestCorruption/" + case)
        if not isinstance(frames, list) or len(frames) != 25:
            v.reject("states-total-snapshots")
        for frame in frames:
            logic.fields(frame, ("query", "columns", "rows"), "states-total-frame")
        selected = {}
        for kind, (query, columns) in queries.items():
            values = [frame for frame in frames if frame["query"] == query]
            if len(values) != 5 or any(frame["columns"] != columns or not isinstance(frame["rows"], list) for frame in values):
                v.reject("states-total-columns")
            if any(frame["rows"] != values[1]["rows"] for frame in values[2:]):
                v.reject("states-total-mutated-rejection")
            selected[kind] = values
        if any(len(frame["rows"]) != 2 for frame in selected["scopes"]):
            v.reject("states-total-scope-domain")
        scope_states = [state(frame["rows"][0]) for frame in selected["scopes"][:2]]
        sides = {}
        for index, name in enumerate(("before", "after")):
            scope = scope_states[index]
            if scope["sector"] != b"s" or scope["spectrum"] != b"p":
                v.reject("states-total-scope")
            if suffix.startswith("schema"):
                meta = selected["meta"][index]["rows"]
                if len(meta) != 1 or len(meta[0]) != 7 or any(type(meta[0][position]) is not int for position in (0, 1, 5, 6)):
                    v.reject("states-total-meta")
                # The unchanged admitted fixture uses Default's 4096 scopes and 256 MiB total.
                values = [len(selected["scopes"][index]["rows"]) > 4096, meta[0][5] != len(selected["scopes"][index]["rows"]), meta[0][6] > 256 * 2**20]
            else:
                records = selected["records"][index]["rows"]
                own = []
                for row in records:
                    if not isinstance(row, list) or len(row) != 4:
                        v.reject("states-total-record")
                    prefix = []
                    for field in row[:3]:
                        logic.fields(field, ("type", "hex"), "states-total-text")
                        if field["type"] != "text" or not isinstance(field["hex"], str):
                            v.reject("states-total-text")
                        value = bytes.fromhex(field["hex"])
                        if value.hex() != field["hex"]:
                            v.reject("states-total-text-encoding")
                        prefix.append(value)
                    blob = row[3]
                    logic.fields(blob, ("type", "bytes", "sha256", "hex"), "states-total-blob")
                    if blob["type"] != "blob" or type(blob["bytes"]) is not int or not 0 <= blob["bytes"] <= 4096:
                        v.reject("states-total-blob")
                    data = bytes.fromhex(blob["hex"])
                    if (
                        len(data) != blob["bytes"]
                        or data.hex() != blob["hex"]
                        or v.digest(data) != blob["sha256"]
                        or not all(storage.text_input(prefix[2], 1024))
                    ):
                        v.reject("states-total-record-value")
                    if prefix[:2] == [b"s", b"p"]:
                        own.append((prefix[2], len(data)))
                if len(own) != 2 or own != sorted(own):
                    v.reject("states-total-record-order")
                total = sum(len(key) + size for key, size in own)
                if suffix.endswith("4098"):
                    values = [total > scope["bytes"], len(own) - 1 >= scope["records"]]
                else:
                    values = [total != scope["bytes"], len(own) != scope["records"]]
            _, result = authority.project(decisions[structure.STORAGE + "/" + suffix], values)
            sides[name] = {"values": values, "result": result}
        identity = structure.STORAGE + "/" + suffix
        proof = authority.correlate_pair(decisions[identity], {"decision": identity, "condition": target, **sides}, set(native[identity]))
        proofs.append(
            {
                **proof,
                "case": "TestCorruption/" + case,
                "sql_snapshots_sha256": v.digest(v.encode(selected)),
                "basis": "Complete immutable native scopes, records and meta SQL values; independently counted and byte-summed inputs and both original same-production masks. No scan-error, cursor-error or missing-value assumption receives credit.",
            }
        )
    return proofs
