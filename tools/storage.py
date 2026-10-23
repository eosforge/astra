"""Reconstruct current Storage structure from sealed native commands, their actual delegate and consumed compiler exports."""

from collections.abc import Callable, Iterable
from pathlib import Path, PurePosixPath
import base64
import json

from tools import authority, entry, logic, statements, structure, verify as v

BASE = "reuse-plan/storage-structure-repair-current-2/native/"
EXPORTS = "reuse-plan/storage-structure-exports-current-1/"
ARCHIVE = "99ff210ba1eee23f806bd6f77882b5c86b02c9a32f9e5d0c5e5a881cd9262479"
EXPORTED = "599eb0dec04c0c4b1fd9c045a6c0553ea34daefc6d7dfa6c83e2077ae88ae75b"
ARTIFACTS = {
    BASE + "evidence.tar.gz": ARCHIVE,
    BASE + "sealed.native.json": "2027cfc3fbb229ee324720253cf1ac4702aa6d3a55657a688955fbb5cef41089",
    EXPORTS + "evidence.tar.gz": EXPORTED,
    EXPORTS + "sealed.native.json": "dc906a32fdecabb4b258790c6ff0fb551b237014e1f64d44c732372465d594e9",
    EXPORTS + "retirement.native.json": "134a191467c11994207d111698f41768d8f12f01c124dda8f2f4dc31db9596b3",
}
NATIVE = PurePosixPath("/home/ubuntu/verdandi/astra/build/results/assurance/storage-structure-repair-current-2/source")
PREFIX = "source/build/commands/structure/structure/"
DELEGATE = "65a14b49af390440cf75dafe9756e305fe75a577217ef6bc95594c9f53d4b4cc"

# These predicates encode public input/resource contracts, not values copied from production results.
VALIDATORS = {
    "text": (
        "len(value) > 0 && len(value) <= maximum && !strings.ContainsRune(value, 0) && utf8.ValidString(value)",
        ["nonempty", "bounded", "nul-free", "utf8"],
        [[0, 1], [0, 2], [0, 3], [0, 4]],
        5,
    ),
    "scope": ("text(scope.Sector, 128) && text(scope.Spectrum, 128)", ["sector", "spectrum"], [[0, 1], [0, 2]], 3),
    "limits": (
        "limits.Scopes > 0 && limits.Scopes <= 16384 && limits.Records > 0 && limits.Records <= 1<<20 && limits.Bytes > 0 && limits.Bytes <= 1<<30 && limits.Total >= limits.Bytes && limits.Total <= 4<<30 && limits.History >= 0 && limits.History <= 65536 && limits.Backlog >= 0 && limits.Backlog <= 64<<20 && limits.Timeout > 0 && limits.Timeout <= 30*time.Second && limits.WAL >= 1<<20 && limits.WAL <= 4<<30",
        [
            "scopes-positive",
            "scopes-bounded",
            "records-positive",
            "records-bounded",
            "bytes-positive",
            "bytes-bounded",
            "total-covers-scope",
            "total-bounded",
            "history-nonnegative",
            "history-bounded",
            "backlog-nonnegative",
            "backlog-bounded",
            "timeout-positive",
            "timeout-bounded",
            "wal-minimum",
            "wal-bounded",
        ],
        [[2 * index, 2 * index + 1] for index in range(16)],
        32,
    ),
    "scan": ("!ok || len(bytes) != 8", ["wrong-type", "wrong-size"], [[0, 2], [1, 2]], 3),
    "change": (
        "text(change.Key, 1024) && len(change.Value) <= 1<<20 && (!change.Erase || len(change.Value) == 0)",
        ["key", "payload-bounded", "set", "empty"],
        [[0, 1], [0, 2], [0, 3], [3, 4]],
        5,
    ),
}

# These exact fixtures establish concrete error identities after native work and cleanup.
RETURN_BINDINGS = {
    "store.go": "7c914530e29059161f9665f867c1ce7f114cdec5c0be7bad43fdcbba3dfd0f16",
    "opening_test.go": "0d650bd3bdaface718bee99cadad62d8201ce9d0245fda7ac0bfb9fbdefe5158",
    "transaction_test.go": "b35f1c8ba7a9e59c0c6b90005ff326f8ac99dd5d9b7bbc500d8fee8794946eda",
    "borrowing_test.go": "9cf605c2ef186c908a1045009bbbcdf4dbf78de105ba5f52044e790ae05665ea",
    "verification_test.go": "d387fcdd4575a9cde8aabb392d4e113d64b2207a714be1858507cf6dd1ffc792",
    "database/sql/sql.go": "5d5ec3cd3519e1d4a388a372e29ddeaedea45dde86845cb4e9002a5ef52f27f0",
}
RETURN_CASES = (
    "TestWriteFault/open-control",
    "TestWriteFault/open-directory-sync",
    "TestVerification/rollback",
    "TestFinalization/rollback-after",
    "TestFinalization",
    "TestBorrowing",
    *(f"TestBorrowing/{owner}/{fault}" for owner in ("write", "read", "validation") for fault in ("closed", "cancelled", "expired")),
)


def text_input(data: bytes, maximum: int) -> list[bool]:
    """Derive text-contract predicates from exact encoded bytes, independently of Go output."""
    try:
        data.decode("utf-8", errors="strict")
        valid = True
    except UnicodeDecodeError:
        valid = False
    return [len(data) > 0, len(data) <= maximum, b"\0" not in data, valid]


def validator_input(kind: str, row: dict) -> tuple[list, list, bool]:
    """Reconstruct semantic and source-atom values from a native input; preserve Scan's undefined type/length domain."""
    value = row["input"]
    if kind == "text":
        logic.fields(value, ("bytes", "maximum"), "storage-text-input")
        if not isinstance(value["bytes"], str) or type(value["maximum"]) is not int or value["maximum"] != 4:
            v.reject("storage-text-input")
        data = bytes.fromhex(value["bytes"])
        if data.hex() != value["bytes"]:
            v.reject("storage-text-encoding")
        semantic = text_input(data, value["maximum"])
        atoms = [semantic[0], semantic[1], not semantic[2], semantic[3]]
        return semantic, atoms, all(semantic)
    if kind == "scope":
        logic.fields(value, ("Sector", "Spectrum"), "storage-scope-input")
        if any(not isinstance(part, str) for part in value.values()):
            v.reject("storage-scope-input")
        semantic = [all(text_input(value[field].encode("utf-8"), 128)) for field in ("Sector", "Spectrum")]
        return semantic, semantic, all(semantic)
    if kind == "limits":
        fields = ("Scopes", "Records", "Bytes", "Total", "History", "Backlog", "Timeout", "WAL")
        logic.fields(value, fields, "storage-limits-input")
        if any(type(number) is not int or not -(2**63) <= number < 2**63 for number in value.values()):
            v.reject("storage-limits-input")
        semantic = [
            value["Scopes"] > 0,
            value["Scopes"] <= 16384,
            value["Records"] > 0,
            value["Records"] <= 2**20,
            value["Bytes"] > 0,
            value["Bytes"] <= 2**30,
            value["Total"] >= value["Bytes"],
            value["Total"] <= 2**32,
            value["History"] >= 0,
            value["History"] <= 65536,
            value["Backlog"] >= 0,
            value["Backlog"] <= 64 * 2**20,
            value["Timeout"] > 0,
            value["Timeout"] <= 30_000_000_000,
            value["WAL"] >= 2**20,
            value["WAL"] <= 2**32,
        ]
        return semantic, semantic, all(semantic)
    if kind == "scan":
        # JSON erases the Go []byte/string distinction. The unchanged typed fixture
        # fixes these three input identities; no arbitrary string is inferred to be a BLOB.
        expected = {"0": "12345678", "1": "AQIDBAUGBw==", "2": "AAAAAAAAAAc="}
        if row["name"] not in expected or value != expected[row["name"]]:
            v.reject("storage-scan-input-type")
        correct_type = row["name"] != "0"
        wrong_size = len(base64.b64decode(value, validate=True)) != 8 if correct_type else None
        semantic, atoms = [not correct_type, wrong_size], [correct_type, wrong_size]
        return semantic, atoms, not correct_type or wrong_size is True
    if kind == "change":
        logic.fields(value, ("key", "bytes", "erase"), "storage-change-input")
        if not isinstance(value["key"], str) or type(value["bytes"]) is not int or value["bytes"] < 0 or type(value["erase"]) is not bool:
            v.reject("storage-change-input")
        semantic = [all(text_input(value["key"].encode("utf-8"), 1024)), value["bytes"] <= 2**20, not value["erase"], value["bytes"] == 0]
        atoms = [semantic[0], semantic[1], value["erase"], semantic[3]]
        return semantic, atoms, semantic[0] and semantic[1] and (semantic[2] or semantic[3])
    v.reject("storage-validator-kind")


def validation(trace: dict, events: bytes, inputs: bytes) -> list[dict]:
    """Correlate all 28 independently recomputed validator predicates with actual same-source native masks."""
    decisions = logic.inventory(trace)
    rows, _ = logic.observe(trace, events, "github.com/eosforge/astra/" + structure.STORAGE, 247)
    buffers, frames = {}, {}
    for line in inputs.splitlines():
        event = v.decode(line)
        if event.get("Package") != "github.com/eosforge/astra/" + structure.STORAGE:
            v.reject("storage-validator-package")
        if event.get("Action") != "output":
            continue
        name, output = event.get("Test", ""), event.get("Output", "")
        if not isinstance(name, str) or not isinstance(output, str):
            v.reject("storage-validator-output")
        value = buffers.get(name, "") + output
        if len(value.encode()) > 65536:
            v.reject("storage-validator-line-budget")
        parts = value.split("\n")
        buffers[name] = parts.pop()
        for part in parts:
            marker = "STORAGE-DECISION "
            if marker not in part:
                continue
            if name == "TestConnectionFault/release":
                continue  # Its pragma tuples require their own independent source-bound oracle.
            if part.count(marker) != 1 or name not in {"TestDecisions/" + kind for kind in VALIDATORS}:
                v.reject("storage-validator-attribution")
            kind = name.removeprefix("TestDecisions/")
            if kind in frames:
                v.reject("storage-validator-duplicate")
            frames[kind] = v.decode(part.split(marker, 1)[1].encode())
    if set(frames) != set(VALIDATORS) or any("STORAGE-DECISION" in value for value in buffers.values()):
        v.reject("storage-validator-incomplete")
    proofs = []
    for kind, frame in frames.items():
        expression, conditions, pairs, count = VALIDATORS[kind]
        logic.fields(frame, ("id", "conditions", "rows", "pairs", "basis"), "storage-validator-frame")
        selected = [decision for decision in decisions.values() if decision["text"] == expression]
        if (
            frame["id"] != kind
            or frame["conditions"] != conditions
            or v.encode(frame["pairs"]) != v.encode(pairs)
            or not isinstance(frame["rows"], list)
            or len(frame["rows"]) != count
            or len(selected) != 1
        ):
            v.reject("storage-validator-domain", kind)
        decision = selected[0]
        if len(decision["atoms"]) != len(conditions):
            v.reject("storage-validator-denominator", kind)
        actual, names = [], set()
        for row in frame["rows"]:
            logic.fields(row, ("name", "values", "result", "input"), "storage-validator-row")
            if not isinstance(row["name"], str) or row["name"] in names:
                v.reject("storage-validator-row-identity", kind)
            names.add(row["name"])
            semantic, atoms, result = validator_input(kind, row)
            if v.encode(row["values"]) != v.encode(semantic) or type(row["result"]) is not bool or row["result"] != result:
                v.reject("storage-validator-input-or-result", kind)
            vector, outcome = authority.project(decision, atoms)
            if outcome != result or (vector, outcome) not in rows[decision["id"]]:
                v.reject("storage-validator-native-witness", kind)
            actual.append({"values": atoms, "result": result})
        for target, (before, after) in enumerate(pairs):
            pair = {"decision": decision["id"], "condition": target, "before": actual[before], "after": actual[after]}
            if kind != "scan" or target != 0:
                proof = authority.correlate_pair(decision, pair, set(rows[decision["id"]]))
            else:
                if pair["before"] != {"values": [False, None], "result": True} or pair["after"] != {"values": [True, False], "result": False}:
                    v.reject("storage-scan-domain")
                # Only this frozen failed type assertion has an undefined length.
                # Completing from the healthy side is algebra, never a skipped operand hit.
                if logic.cube(decision, "11") is not True or logic.cube(decision, "21") is not False:
                    v.reject("storage-scan-guard-completion")
                proof = {
                    **pair,
                    "criterion": "defined-domain-short-circuit-v1",
                    "native_vectors": [{"values": "10", "result": True}, {"values": "21", "result": False}],
                }
            proofs.append(
                {
                    **proof,
                    "test": "TestDecisions/" + kind,
                    "input_sha256": v.digest(v.encode(frame)),
                    "basis": "Independent byte, field, integer and typed-fixture contracts recomputed from native input receipts; source forest and all native commands require enclosing authentication.",
                }
            )
    if len(proofs) != 28 or len({(item["decision"], item["condition"]) for item in proofs}) != 28:
        v.reject("storage-validator-coverage")
    return proofs


def pragmas(root: Path, trace: dict, events: bytes, inputs: bytes) -> list[dict]:
    """Bind independently validated pragma response tuples to the actual three-condition native decision."""
    from tools import equality, settings

    selected = [event for event in statements.stream(inputs) if "Test" not in event or event["Test"] in settings.CASES]
    data = b"".join((json.dumps(event, separators=(",", ":")) + "\n").encode() for event in selected)
    settings.observations(data, root)
    decisions = [decision for decision in logic.inventory(trace).values() if decision["text"] == "err != nil || closed != nil || value[0] != expected"]
    if len(decisions) != 1 or decisions[0]["id"] != structure.STORAGE + "/schema.go:3189":
        v.reject("storage-pragma-root")
    decision = decisions[0]
    native, _ = logic.observe(trace, events, "github.com/eosforge/astra/" + structure.STORAGE, 247)
    frames = equality.frames(data, settings.PACKAGE, test=settings.TEST, marker="STORAGE-DECISION ", maximum=4)
    proofs = []
    for frame in frames:
        for target, (before, after) in enumerate(frame["pairs"]):
            pair = {
                "decision": decision["id"],
                "condition": target,
                **{
                    name: {"values": frame["rows"][index]["values"], "result": frame["rows"][index]["result"]}
                    for name, index in (("before", before), ("after", after))
                },
            }
            proof = authority.correlate_pair(decision, pair, set(native[decision["id"]]))
            proofs.append(
                {
                    **proof,
                    "input_sha256": v.digest(v.encode(frame)),
                    "query": frame["id"],
                    "basis": "Unchanged native steps/closes and independently fixed pragma expectations; no skipped predicate is called a native hit.",
                }
            )
    if len(proofs) != 12 or {pair["condition"] for pair in proofs} != {0, 1, 2}:
        v.reject("storage-pragma-coverage")
    return proofs


def scalar_effect(decision: dict, rows: dict, points: tuple[int, ...], minimum: int, maximum: int, predicates: Callable[[int], Iterable[bool]]) -> list[dict]:
    """Infer only uniquely constrained skipped values from an exhaustive integer truth partition, never missing native masks."""
    if minimum >= maximum or any(type(point) is not int or not minimum <= point <= maximum for point in points):
        v.reject("storage-scalar-domain")
    representatives = sorted({minimum, maximum, *(value for point in points for value in (point - 1, point, point + 1) if minimum <= value <= maximum)})
    totals = {tuple(predicates(value)) for value in representatives}
    if any(len(values) != len(decision["atoms"]) or any(type(value) is not bool for value in values) for values in totals):
        v.reject("storage-scalar-predicates")
    completed = []
    for (mask, result), hits in rows.items():
        if type(hits) is not int or hits <= 0:
            v.reject("storage-scalar-native-hit")
        candidates = [values for values in totals if authority.project(decision, list(values)) == (mask, result)]
        if not candidates:
            v.reject("storage-scalar-native-contradiction")
        if len(candidates) == 1:
            completed.append((candidates[0], result, mask))
    proofs = []
    for target in range(len(decision["atoms"])):
        for before, outcome, mask in completed:
            if outcome:
                continue
            found = next(
                (
                    (after, other)
                    for after, result, other in completed
                    if result
                    and before[target] != after[target]
                    and all(first == second for index, (first, second) in enumerate(zip(before, after, strict=True)) if index != target)
                ),
                None,
            )
            if found is None:
                continue
            after, other = found
            proofs.append(
                {
                    "decision": decision["id"],
                    "condition": target,
                    "criterion": "source-constrained-unique-completion-v1",
                    "before": {"values": list(before), "result": False},
                    "after": {"values": list(after), "result": True},
                    "native_vectors": [{"values": mask, "result": False}, {"values": other, "result": True}],
                    "inferred_not_native_hits": True,
                    "partition": {
                        "minimum": minimum,
                        "maximum": maximum,
                        "boundaries": list(points),
                        "representatives": representatives,
                        "truth_vectors": len(totals),
                    },
                    "basis": "Every predicate is a comparison of one immutable integer to a declared constant. Between consecutive constants all comparisons are constant; representatives exhaust the overapproximation. Both actual masks have exactly one compatible complete truth vector, and only the target differs.",
                }
            )
            break
    return proofs


def names(root: Path, trace: dict, events: bytes) -> list[dict]:
    """Bind name length/rune truth partitions to the exact immutable-local implementation and original native observations."""
    if v.file_digest(root / structure.STORAGE / "store.go") != "7c914530e29059161f9665f867c1ce7f114cdec5c0be7bad43fdcbba3dfd0f16":
        v.reject("storage-name-source")
    decisions = logic.inventory(trace)
    observed, _ = logic.observe(trace, events, "github.com/eosforge/astra/" + structure.STORAGE, 247)
    domains = (
        (structure.STORAGE + "/store.go:11360", "len(value) == 0 || len(value) > 64", (0, 64), 0, 2**63 - 1, lambda value: [value == 0, value > 64]),
        (
            structure.STORAGE + "/store.go:11450",
            "!(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '.' || char == '_' || char == '-')",
            (ord("a"), ord("z"), ord("A"), ord("Z"), ord("0"), ord("9"), ord("."), ord("_"), ord("-")),
            -(2**31),
            2**31 - 1,
            lambda value: [
                value >= ord("a"),
                value <= ord("z"),
                value >= ord("A"),
                value <= ord("Z"),
                value >= ord("0"),
                value <= ord("9"),
                value == ord("."),
                value == ord("_"),
                value == ord("-"),
            ],
        ),
    )
    proofs = []
    for identity, expression, points, minimum, maximum, predicates in domains:
        decision = decisions[identity]
        if decision["text"] != expression:
            v.reject("storage-name-expression")
        proofs += scalar_effect(decision, observed[identity], points, minimum, maximum, predicates)
    return proofs


def feeds(root: Path, trace: dict, events: bytes, rows: list[dict]) -> list[dict]:
    """Join exact native numeric inputs and queue snapshots to four independently reconstructed feed predicates."""
    from tools import storage_numeric as numeric

    if v.file_digest(
        root / structure.STORAGE / "numeric_linux_amd64_test.go"
    ) != "198a081ce7ec498aed25ac72feae0c2f3d8925165433e23eaf918b3ce2b32a9f" or v.encode(rows) != v.encode(numeric.expected(root)):
        v.reject("storage-feed-fixture-inputs")
    decisions = logic.inventory(trace)
    native, _ = logic.observe(trace, events, numeric.PACKAGE, 247)
    admission, capacity = (structure.STORAGE + "/feed.go:" + offset for offset in ("1615", "4062"))
    if (
        decisions.get(admission, {}).get("text") != "limit < 1 || limit > 16<<20 || items < 1 || items > 65536"
        or decisions.get(capacity, {}).get("text") != "len(feed.queue) == feed.items || cost > feed.limit-feed.bytes"
    ):
        v.reject("storage-feed-source-decision")
    candidates = {admission: [], capacity: []}
    previous = {}
    for index, row in enumerate(rows):
        if row["kind"] == "subscription":
            values = [row["limit"] < 1, row["limit"] > 16 * 2**20, row["items"] < 1, row["items"] > 65536]
            candidates[admission].append({"values": values, "result": not row["accepted"], "rows": [index]})
        elif row["kind"] == "feed-cost":
            key = row["limit"], row["items"]
            old = previous.get(key)
            if old is None or not old[1]["refused"]:
                queued, charged = (0, 0) if old is None else (old[1]["queued"], old[1]["bytes"])
                # The pinned fixture pushes only the immutable {sector:n,spectrum:x,key:k,empty payload} event.
                values = [queued == row["items"], 131 > row["limit"] - charged]
                candidates[capacity].append({"values": values, "result": row["refused"], "rows": ([old[0]] if old is not None else []) + [index]})
            previous[key] = index, row
    proofs = []
    for identity, conditions in ((admission, (0, 1, 2)), (capacity, (0,))):
        decision = decisions[identity]
        for target in conditions:
            selected = None
            for before in candidates[identity]:
                for after in candidates[identity]:
                    if (
                        before["result"] == after["result"]
                        or before["values"][target] == after["values"][target]
                        or any(a != b for index, (a, b) in enumerate(zip(before["values"], after["values"], strict=True)) if index != target)
                    ):
                        continue
                    selected = before, after
                    break
                if selected is not None:
                    break
            if selected is None:
                v.reject("storage-feed-independent-input-missing", identity + "/" + str(target))
            before, after = selected
            proof = authority.correlate_pair(
                decision,
                {
                    "decision": identity,
                    "condition": target,
                    "before": {key: before[key] for key in ("values", "result")},
                    "after": {key: after[key] for key in ("values", "result")},
                },
                set(native[identity]),
            )
            proofs.append(
                {
                    **proof,
                    "input_rows": {"before": before["rows"], "after": after["rows"]},
                    "inputs_sha256": v.digest(v.encode(rows)),
                    "basis": "Complete unchanged native numeric transcript, immutable public bounds/event fixture, preceding actual queue counters and both same-production masks; skipped values receive no native hit credit.",
                }
            )
    return proofs


def opening(trace: dict, events: bytes, frames: list[dict]) -> list[dict]:
    """Reconstruct nine fixed deployment-input effects without crediting the coupled parse-error predicate."""
    from ipaddress import ip_address

    try:
        encoded = v.encode(frames)
    except (UnicodeError, ValueError, TypeError):
        v.reject("storage-open-input-encoding")
    identity = structure.STORAGE + "/store.go:2674"
    decisions = logic.inventory(trace)
    expression = '!limits.valid() || !name(binding.Galaxy) || !name(binding.Username) || err != nil || endpoint.String() != binding.Advertise || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() || endpoint.Addr().Is4In6() || endpoint.Addr().Zone() != "" || path == ""'
    if decisions.get(identity, {}).get("text") != expression:
        v.reject("storage-open-source-decision")
    native, _ = logic.observe(trace, events, "github.com/eosforge/astra/" + structure.STORAGE, 247)
    names = ("valid", "limits", "galaxy", "username", "parse", "canonical", "port", "unspecified", "multicast", "mapped", "zone", "path")
    if not isinstance(frames, list) or len(frames) != len(names):
        v.reject("storage-open-input-count")
    defaults = {
        "Scopes": 4096,
        "Records": 65536,
        "Bytes": 64 * 2**20,
        "Total": 256 * 2**20,
        "History": 1000,
        "Backlog": 8 * 2**20,
        "Timeout": 5_000_000_000,
        "WAL": 128 * 2**20,
    }
    endpoints = {
        "parse": "invalid",
        "canonical": "[2001:0db8::1]:45101",
        "port": "127.0.0.1:0",
        "unspecified": "0.0.0.0:45101",
        "multicast": "224.0.0.1:45101",
        "mapped": "[::ffff:127.0.0.1]:45101",
        "zone": "[fe80::1%eth0]:45101",
    }
    candidates = {}
    for expected_name, frame in zip(names, frames, strict=True):
        logic.fields(frame, ("name", "input", "refused", "filesystem"), "storage-open-frame")
        if frame["name"] != expected_name or type(frame["refused"]) is not bool or type(frame["filesystem"]) is not int or frame["filesystem"] < 0:
            v.reject("storage-open-input-identity")
        name, value = frame["name"], frame["input"]
        logic.fields(value, ("path", "binding", "limits"), "storage-open-input")
        binding, limits, path = value["binding"], value["limits"], value["path"]
        expected_binding = {
            "Galaxy": "" if name == "galaxy" else "guard",
            "Username": "" if name == "username" else "polaris",
            "Advertise": endpoints.get(name, "127.0.0.1:45101"),
        }
        expected_limits = {**defaults, "Scopes": 0} if name == "limits" else defaults
        if v.encode(binding) != v.encode(expected_binding) or v.encode(limits) != v.encode(expected_limits) or not isinstance(path, str):
            v.reject("storage-open-argument-domain")
        if name == "path":
            if path != "":
                v.reject("storage-open-path")
        elif (
            not PurePosixPath(path).is_absolute()
            or PurePosixPath(path).name != "database"
            or ".." in PurePosixPath(path).parts
            or chr(92) in path
            or ":" in path
        ):
            v.reject("storage-open-path")
        _, _, valid_limits = validator_input("limits", {"input": limits})
        allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        valid_names = [1 <= len(binding[key].encode()) <= 64 and all(char in allowed for char in binding[key]) for key in ("Galaxy", "Username")]
        endpoint = binding["Advertise"]
        parsed = name != "parse"
        if parsed:
            host, port_text = endpoint.rsplit(":", 1)
            bracketed = host.startswith("[")
            host = host[1:-1] if bracketed else host
            host, _, zone = host.partition("%")
            address, port = ip_address(host), int(port_text)
            mapped = getattr(address, "ipv4_mapped", None)
            canonical = "::ffff:" + str(mapped) if mapped is not None else str(address)
            canonical += "%" + zone if zone else ""
            canonical = ("[" + canonical + "]" if bracketed else canonical) + ":" + str(port)
            unspecified = int(address) == 0 and not zone
            multicast = (mapped if mapped is not None else address).is_multicast
        else:
            # These are the defined zero AddrPort values, not inferred successful parsing.
            canonical, port, zone, mapped, unspecified, multicast = "invalid AddrPort", 0, "", None, False, False
        values = [valid_limits, *valid_names, not parsed, canonical != endpoint, port == 0, unspecified, multicast, mapped is not None, bool(zone), path == ""]
        mask, outcome = authority.project(decisions[identity], values)
        if (mask, outcome) not in native[identity] or outcome != frame["refused"] or (frame["filesystem"] == 0) != frame["refused"]:
            v.reject("storage-open-native-outcome")
        candidates[name] = {"values": values, "result": outcome}
    targets = {"limits": 0, "galaxy": 1, "username": 2, "canonical": 4, "port": 5, "unspecified": 6, "multicast": 7, "mapped": 8, "zone": 9}
    proofs = []
    for name, target in targets.items():
        proof = authority.correlate_pair(
            decisions[identity], {"decision": identity, "condition": target, "before": candidates["valid"], "after": candidates[name]}, set(native[identity])
        )
        proofs.append(
            {
                **proof,
                "cases": ["valid", name],
                "inputs_sha256": v.digest(encoded),
                "basis": "Twelve actual unchanged-engine Open inputs, independent public resource/name/address grammar and original same-production masks. Parse-error/zero-endpoint coupling is not an independent effect; skipped values receive no native hit credit.",
            }
        )
    return proofs


def returned(decisions: dict, observed: dict, cases: dict, bindings: dict) -> list[dict]:
    """Correlate reached error returns with pinned fixture semantics and original native vectors.

    The enclosing receiver must authenticate all source, dependency and complete
    test streams. These source-conditioned witnesses are not new executions or
    values guessed for an arbitrary skipped expression.
    """
    if not all(isinstance(value, dict) for value in (decisions, observed, cases, bindings)) or bindings != RETURN_BINDINGS or set(cases) != set(RETURN_CASES):
        v.reject("storage-return-bindings-or-cases")
    for case in cases.values():
        logic.fields(case, ("status", "markers"), "storage-return-case")
        if case["status"] != "passed" or not isinstance(case["markers"], list) or any(not isinstance(line, str) for line in case["markers"]):
            v.reject("storage-return-terminal")
    expected = {
        "TestWriteFault/open-control": ["STORAGE-OPEN point=control hits=0 opened=4 closed=4"],
        "TestWriteFault/open-directory-sync": ["STORAGE-OPEN point=directory-sync hits=2 opened=8 closed=8 files=4 released=4"],
        "TestVerification/rollback": ['ASTRA-CONTRACT {"contract":"STORAGE-ROLLBACK","hits":7}'],
        "TestFinalization/rollback-after": [],
        "TestFinalization": ['ASTRA-CONTRACT {"contract":"STORAGE-FINALIZE","hits":239}'],
        "TestBorrowing": ['ASTRA-CONTRACT {"contract":"STORAGE-BORROWING","hits":9}'],
        **{
            f"TestBorrowing/{owner}/{fault}": [f"STORAGE-BORROWING owner={owner} fault={fault} entered=0 in_use=0 published=0 version=1 records=1"]
            for owner in ("write", "read", "validation")
            for fault in ("closed", "cancelled", "expired")
        },
    }
    if any(case["markers"] != expected[name] for name, case in cases.items()):
        v.reject("storage-return-observations")
    effects = (
        (
            "store.go:5255",
            "synced != nil || closed != nil",
            [False, False],
            [True, False],
            "Completed native directory Close releases every acquired descriptor; the selected sync-only wrapper then returns nil from Close and EIO from Sync.",
        ),
        (
            "store.go:9215",
            "rollback != nil && !errors.Is(rollback, sql.ErrTxDone)",
            [False, False],
            [True, False],
            "The ordinary triggered rollback has an uncancelled owner and succeeds. The reached rollback-after wrapper first completes that native rollback, then returns a fresh error distinct from sql.ErrTxDone. The second atom is errors.Is before AST negation.",
        ),
        (
            "store.go:9996",
            "errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)",
            [False, False],
            [True, False],
            "The pinned SQL acquisition returns its closed-pool error or the original cancelled context error. The canonical cancellation and deadline errors remain distinct; every owner confirms rejection before SQL and complete recovery.",
        ),
    )
    pairs = []
    for suffix, expression, before, after, reason in effects:
        identity = structure.STORAGE + "/" + suffix
        decision = decisions.get(identity)
        if decision is None or decision["text"] != expression:
            v.reject("storage-return-source", identity)
        native = observed.get(identity)
        if not isinstance(native, dict) or any(type(hits) is not int or hits <= 0 for hits in native.values()):
            v.reject("storage-return-masks", identity)
        pair = authority.correlate_pair(
            decision,
            {
                "decision": identity,
                "condition": 0,
                "before": {"values": before, "result": authority.project(decision, before)[1]},
                "after": {"values": after, "result": authority.project(decision, after)[1]},
            },
            set(native),
        )
        pairs.append({**pair, "basis": reason, "cases": list(RETURN_CASES), "source_bindings": bindings})
    return pairs


def reference(files: dict[str, bytes], prefix: str, item: dict) -> bytes:
    """Resolve exact bounded original members without extracting or rewriting native paths."""
    logic.fields(item, ("path", "bytes", "sha256"), "storage-artifact")
    name = item["path"]
    if not isinstance(name, str) or not name or PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts or "\\" in name or ":" in name:
        v.reject("storage-artifact-path")
    if PurePosixPath(name).as_posix() != name or prefix + name not in files:
        v.reject("storage-artifact-member")
    data = files[prefix + name]
    if type(item["bytes"]) is not int or item["bytes"] != len(data) or item["sha256"] != v.digest(data):
        v.reject("storage-artifact-integrity")
    return data


def retained(data: bytes, seal: dict, expected: str) -> dict[str, bytes]:
    """Authenticate every member against the reviewed native seal, retaining its original outcome."""
    if v.digest(data) != expected or seal.get("archive_sha256") != expected or seal.get("bytes") != len(data) or seal.get("trust") != "local":
        v.reject("storage-archive-integrity")
    files = entry.unpack(data)
    if not isinstance(seal.get("files"), dict) or set(files) != set(seal["files"]):
        v.reject("storage-archive-inventory")
    if any(item != {"bytes": len(files[name]), "sha256": v.digest(files[name])} for name, item in seal["files"].items()):
        v.reject("storage-member-integrity")
    return files


def additions(root: Path, original: set[str]) -> set[str]:
    """Bind the separately verified compatibility test without crediting it to historical experiments."""
    name = "polaris/internal/storage/compatibility_test.go"
    path = v.inside(root, name)
    if name in original or not path.is_file():
        return set()
    # This exact file declares only TestCompatibility: no package initializer, TestMain or mutable global state.
    if v.file_digest(path) != "57b1b9dbb3fb51332b0c807f7408dcad93181913833d3ea6d6734d20b835b09f":
        v.reject("storage-compatibility-source", name)
    return {name}


def sources(root: Path, files: dict[str, bytes], inputs: dict, exports: bytes) -> dict[str, str]:
    """Require the complete current compilation and test closure, including inactive code and the embedded probe runtime."""
    prefix = "github.com/eosforge/astra/"
    directories = {item["ImportPath"].removeprefix(prefix) for item in statements.stream(exports) if item["ImportPath"].startswith(prefix)}
    if directories != {structure.STORAGE}:
        v.reject("storage-production-closure")
    directories.add("tools/decisions")
    original = {name for name in inputs["files"] if name.endswith(".go") and PurePosixPath(name).parent.as_posix() in directories} | {
        "tools/decisions/runtime.go.in",
        "go.mod",
        "go.sum",
        "tests/fixtures/storage.tests.json",
    }
    # The offline Go compiler consumes go.mod/go.sum and pinned installed tools;
    # the auxiliary cross-language lock file was not an input to this campaign.
    actual = {path.relative_to(root).as_posix() for directory in directories for path in v.inside(root, directory).glob("*.go")}
    actual -= additions(root, original)
    if actual != {name for name in original if name.endswith(".go")}:
        v.reject("storage-current-source-inventory")
    result = {}
    for name in sorted(original):
        data = v.read(v.inside(root, name))
        if "source/" + name not in files or files["source/" + name] != data or inputs["files"].get(name) != v.digest(data):
            v.reject("storage-current-source-drift", name)
        result[name] = v.digest(data)
    return result


def environment(check: dict, inputs: dict) -> dict[str, str]:
    """Expand policy paths from the actual tool installation, independently of the warm compilation-cache handoff."""
    roots = {str(PurePosixPath(inputs["tools"][name]["path"]).parents[3]) for name in ("go", "gcc", "g++")}
    if len(roots) != 1:
        v.reject("storage-native-tool-root")
    cache = roots.pop()
    return {
        key: value.replace("{root}", str(NATIVE)).replace("{cache}", cache).replace("{run}", str(NATIVE / "build/commands/structure"))
        for key, value in check["environment"].items()
    }


def command(files: dict[str, bytes], name: str, arguments: list[str], timeout: int, environment: dict, inputs: dict, owner: dict) -> tuple[dict, bytes]:
    """Validate each actual original command, complete stream, resource budget and retired native child identity."""
    prefix = PREFIX + name + "/"
    record = v.decode(files[prefix + "record.json"])
    v.schema(record, "evidence", ("properties", "checks", "items"))
    process = v.decode(files[prefix + PurePosixPath(name).name + ".process.json"])
    expected = [item.replace("{root}", str(NATIVE)) for item in arguments]
    child = {
        **environment,
        "TMPDIR": str(NATIVE / "build/commands/structure/structure" / name / "tmp"),
        "ASTRA_TEST_LOG_DIR": str(NATIVE / "build/commands/structure/structure" / name / "logs"),
    }
    tools = {key: inputs["tools"][value] for key, value in (("command", "go"), ("CC", "gcc"), ("CXX", "g++"))}
    cleanup = v.decode(files["cleanup.native.json"])
    identity = process["identity"]
    if (
        record["id"] != PurePosixPath(name).name
        or record["argv"] != expected
        or record["environment"] != child
        or record["resolved_environment"] != child
        or record["toolchain"] != tools
        or record["executable"] != tools["command"]["path"]
        or record["executable_sha256"] != tools["command"]["sha256"]
        or record["platform"] != structure.PLATFORM
        or record["duration_ms"] > timeout * 1000
        or record["termination"] != "exited"
        or record["exit_code"] != 0
        or record["complete"] is not True
        or record["cleanup"] is not True
        or process["argv"] != record["argv"]
        or process["cwd"] != str(NATIVE)
        or process["boot_id"] != owner["boot_id"]
        or identity not in cleanup["retired"]
        or identity.get("parent") != owner["identity"]["pid"]
        or type(identity.get("pid")) is not int
        or identity["pid"] <= 0
        or not isinstance(identity.get("start_ticks"), str)
        or not identity["start_ticks"].isdecimal()
        or int(identity["start_ticks"]) <= 0
    ):
        v.reject("storage-native-command", name)
    data = {}
    for channel in ("stdout", "stderr"):
        data[channel] = reference(files, prefix, record[channel])
    return record, data["stdout"]


def reconcile(root: Path, artifacts: dict[str, bytes]) -> dict:
    """Recompute actual denominators after authenticating the failed delegate and all eight successful native children."""
    if set(artifacts) != set(ARTIFACTS) or any(v.digest(artifacts[name]) != digest for name, digest in ARTIFACTS.items()):
        v.reject("storage-retained-inventory-or-integrity")
    seal = v.decode(artifacts[BASE + "sealed.native.json"])
    files = retained(artifacts[BASE + "evidence.tar.gz"], seal, ARCHIVE)
    exported = retained(artifacts[EXPORTS + "evidence.tar.gz"], v.decode(artifacts[EXPORTS + "sealed.native.json"]), EXPORTED)
    inputs, controller, cleanup, terminal = (v.decode(files[name + ".json"]) for name in ("inputs", "controller", "cleanup.native", "terminal"))
    check = next(item for item in v.decode(v.read(root / "development.json"))["checks"] if item["id"] == "storage-structure")
    if check != inputs["native_check"] or any(
        files.get("source/" + name) is None or v.digest(files["source/" + name]) != digest for name, digest in inputs["files"].items()
    ):
        v.reject("storage-original-inputs")
    # The fixed archive digests and exact recorded declaration bind this replay to its original Go 1.27.1 inputs.
    structure.configuration(check, retained=True)
    if (
        controller["inputs_sha256"] != v.digest(files["inputs.json"])
        or controller["script_sha256"] != v.digest(files["run.py"])
        or inputs["files"].get("_structure.py") != DELEGATE
    ):
        v.reject("storage-delegate-source")
    unit = cleanup["unit"]
    if (
        seal["outcome"] != "failed"
        or controller["identity"] not in cleanup["retired"]
        or controller["boot_id"] != cleanup["boot_id"]
        or controller["boot_id"] != inputs["boot_id"]
        or unit != {"MainPID": "0", "ControlGroup": "", "ExecMainStatus": "1", "InvocationID": controller["invocation_id"], "Result": "exit-code"}
        or terminal["interrupted"] is not False
        or terminal["remaining_owned"]
        or terminal["errors"]
        != ["AssertionError: Official collection or outcome coverage incomplete; retain the original command and inspect its ledger/streams."]
    ):
        v.reject("storage-native-retirement")
    prefix = "source/build/commands/structure/"
    outer = v.decode(files[prefix + "record.json"])
    owner = v.decode(files[prefix + "structure.process.json"])
    actual = outer["resolved_environment"]
    requested = environment(check, inputs)
    if (
        set(actual) != set(requested) | {"HOME", "LANG"}
        or actual["LANG"] != "C.UTF-8"
        or any(actual.get(key) != value for key, value in requested.items())
        or outer["id"] != "structure"
        or outer["argv"] != ["python3", "-B", "_structure.py"]
        or owner["argv"] != outer["argv"]
        or owner["cwd"] != str(NATIVE)
        or owner["boot_id"] != controller["boot_id"]
        or owner["identity"] not in cleanup["retired"]
        or owner["identity"].get("parent") != controller["identity"]["pid"]
        or outer["exit_code"] != 1
        or outer["termination"] != "exited"
        or outer["complete"] is not True
        or outer["cleanup"] is not True
    ):
        v.reject("storage-delegate-owner")
    error = reference(files, prefix, outer["stderr"])
    reference(files, prefix, outer["stdout"])
    if (
        b"FileNotFoundError: [Errno 2] No such file or directory:" not in error
        or str(NATIVE / "build/commands/structure/storage-structure.process.json").encode() not in error
    ):
        v.reject("storage-original-failure")
    bundle = v.decode(files[PREFIX + "bundle.json"])
    logic.fields(bundle, ("version", "source", "coverage", "profiles", "typed", "control", "dependencies", "preflight"), "storage-bundle")
    if bundle["version"] != 2:
        v.reject("storage-bundle-version")
    structure.bounded(v.decode(reference(files, PREFIX, bundle["preflight"])))
    source = reference(files, PREFIX, bundle["source"])
    plan = structure.plan(NATIVE / "build/commands/structure/structure", package=structure.STORAGE)
    if {name.removeprefix(PREFIX).removesuffix("/record.json") for name in files if name.startswith(PREFIX) and name.endswith("/record.json")} != {
        name for name, _, _ in plan
    }:
        v.reject("storage-native-command-inventory")
    streams, records, previous = {}, {}, outer["started_at"]
    for name, arguments, timeout in plan:
        record, data = command(files, name, arguments, timeout, actual, inputs, owner)
        if not v.stamp(previous) <= v.stamp(record["started_at"]) <= v.stamp(record["finished_at"]) <= v.stamp(outer["finished_at"]):
            v.reject("storage-native-order", name)
        previous = record["finished_at"]
        records[name], streams[name] = record, data
    structure.terminals(streams["coverage"], check["native_tests"], package=structure.STORAGE)
    bindings = sources(root, files, inputs, streams["typed/exports"])
    loaded = {}
    for name in ("typed", "control"):
        nested = v.decode(reference(files, PREFIX, bundle[name]))
        start = PREFIX + name + "/"
        trace = v.decode(reference(files, start, nested["trace"]))
        report = v.decode(streams[name + "/collector"])
        reported = [file for file in report["files"] if PurePosixPath(file["file"]).parent.as_posix() == structure.STORAGE]
        if (
            nested["directory"] != structure.STORAGE
            or reference(files, start, nested["source"]) != source
            or trace["files"] != reported
            or report["source_sha256"] != v.digest(source)
        ):
            v.reject("storage-native-overlay-binding", name)
        replacements = v.decode(reference(files, start, nested["overlay"]))["Replace"]
        helpers = {structure.STORAGE + "/zz_astra_probe.go", structure.STORAGE + "/zz_astra_probe_test.go"}
        if set(nested["generated"]) != {file["file"] for file in trace["files"]} | helpers or set(replacements) != {
            str(NATIVE / file) for file in nested["generated"]
        }:
            v.reject("storage-native-overlay-inventory", name)
        for original, item in nested["generated"].items():
            data = reference(files, start, item)
            replacement = str(NATIVE / "build/commands/structure/structure" / name / item["path"])
            if replacements[str(NATIVE / original)] != replacement or files["source/" + str(PurePosixPath(replacement).relative_to(NATIVE))] != data:
                v.reject("storage-native-overlay-path", original)
        for field in ("collector", "packages", "tests") + (("exports",) if name == "typed" else ()):
            if reference(files, start, nested[field]) != files[start + field + "/record.json"]:
                v.reject("storage-native-nested-record", field)
        structure.terminals(streams[name + "/tests"], check["native_tests"], package=structure.STORAGE)
        loaded[name] = trace
    receipt = v.decode(exported["receipt.native.json"])
    retirement = v.decode(artifacts[EXPORTS + "retirement.native.json"])
    if (
        receipt["original_archive_sha256"] != ARCHIVE
        or receipt["trace_sha256"] != v.digest(v.encode(loaded["typed"]))
        or receipt["boot_id"] != controller["boot_id"]
        or retirement
        != {
            "archive_sha256": EXPORTED,
            "boot_id": receipt["boot_id"],
            "receipt_sha256": v.digest(exported["receipt.native.json"]),
            "retired": receipt["identity"],
            "retirement_verified": True,
        }
    ):
        v.reject("storage-export-retirement")
    typing = loaded["typed"]["typing"]
    if set(receipt["exports"]) != set(typing["exports"]) or typing["metadata_sha256"] != v.digest(streams["typed/exports"]):
        v.reject("storage-export-inventory")
    metadata = {item["ImportPath"]: item for item in statements.stream(streams["typed/exports"])}
    for name, item in receipt["exports"].items():
        path = item["native_path"]
        if (
            typing["exports"][name] != {"path": path, "bytes": item["bytes"], "sha256": item["sha256"]}
            or metadata[name]["Export"] != path
            or not PurePosixPath(path).is_relative_to(NATIVE / "build/cache/go")
        ):
            v.reject("storage-export-binding", name)
        reference(exported, "", {key: item[key] for key in ("path", "bytes", "sha256")})
    report = structure.reconcile(
        root=root,
        source_sha256=v.digest(source),
        tests=check["native_tests"],
        profiles=(reference(files, PREFIX, bundle["profiles"]["parent"]),),
        dependency={name: reference(files, PREFIX, item) for name, item in bundle["dependencies"].items()},
        trace=loaded["typed"],
        boolean_events=streams["typed/tests"],
        control=loaded["control"],
        control_events=streams["control/tests"],
        package=structure.STORAGE,
    )
    return {
        **report,
        "sources": bindings,
        "original_entry": {"archive_sha256": ARCHIVE, "exit_code": outer["exit_code"], "reason": "actual-delegate-owner-filename"},
        "compiler_exports": {"archive_sha256": EXPORTED, "files": len(receipt["exports"]), "bytes": sum(item["bytes"] for item in receipt["exports"].values())},
        "application_commands": 0,
        "qualification": "Current unchanged Storage structure at local trust. Original entry remains failed; MC/DC, whole-rule, performance and protected release remain separate.",
    }
