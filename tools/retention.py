"""Qualify the final Storage condition domains without manufacturing skipped operand hits."""

from collections.abc import Callable
import base64
import itertools
from pathlib import Path

from tools import authority, logic, structure, verify as v

PACKAGE = structure.STORAGE
BINDINGS = {
    "polaris/internal/storage/commit.go": "49153eefce9c8c490bad43374c2f7fe69460a2059eb9d7ff0927ddd2c2d204cd",
    "polaris/internal/storage/lock_linux.go": "58cd2bd20c3b8854a52b5fa088b8b653685fcc4fed0dc4807a646f877dc35cd4",
    "polaris/internal/storage/read.go": "c81b9b809a7ecd67b8599cf61526b3aa752accae66bc8b715c7fea2a1efab926",
    "polaris/internal/storage/schema.go": "8049a032034b1e1b37f136636a9c1029a07ce0345cb9b7fb348d876ce333f8ab",
    "polaris/internal/storage/store.go": "7c914530e29059161f9665f867c1ce7f114cdec5c0be7bad43fdcbba3dfd0f16",
    "polaris/internal/storage/model.go": "c9a311552d7bb80540c1fff71116228109b19105a63ebd6a04aca92dc1f45e4e",
    "database/sql/convert.go": "9a1a10b4b5489853b618c8eaed8f79f2df87edd970a61b6ef45be1466906da21",
    "database/sql/sql.go": "5d5ec3cd3519e1d4a388a372e29ddeaedea45dde86845cb4e9002a5ef52f27f0",
    "net/netip/netip.go": "32295f4761825d8c6fdade4dad093b08683bdd1945010bee8a90a298e18cf208",
    "os/error.go": "f073f7fb0bad2cd69df450956b4a267b5ecfb519a9089d44fe6b6e2d6f766e18",
    "os/stat.go": "fcf9bc032dc2a30b40329299db15940192cad00c8092f256c257054a95db0ac3",
    "os/stat_unix.go": "fa12fa05805074520f72342648764d156193805d6ddfa663af938145769a204a",
    "sqlite3/method-set": "06e8144687c5d6421ad28188039b467eae52b6e8212b2f89b69658c10881a57e",
}
EXPRESSIONS = {
    "commit.go:2317": "state.Version == Version(math.MaxUint64) || change.Version != state.Version+1",
    "commit.go:8972": "(state.Retained > store.limits.History || state.Backlog > store.limits.Backlog) && rows.Next()",
    "lock_linux.go:636": "err != nil || !info.Mode().IsRegular()",
    "read.go:3910": "err != nil || !text(record.Key, 1024) || record.Value == nil || len(record.Value) > 1<<20",
    "read.go:6637": "err != nil || position == state.Version || change.Version != position+1 || change.Value == nil || cost != int64(64+len(change.Key)+len(change.Value))",
    "schema.go:7432": "invalid || err != nil || closed != nil",
    "store.go:10634": "os.IsNotExist(err) || err == nil && info.Size() < store.limits.WAL",
    "store.go:11406": "false",
    "store.go:11597": "false",
    "store.go:11618": "true",
    "store.go:2674": '!limits.valid() || !name(binding.Galaxy) || !name(binding.Username) || err != nil || endpoint.String() != binding.Advertise || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() || endpoint.Addr().Is4In6() || endpoint.Addr().Zone() != "" || path == ""',
    "store.go:4000": "err != nil || !info.Mode().IsRegular()",
}


def sources(root: Path, dependencies: dict[str, bytes]) -> dict[str, str]:
    """Bind every relevant production byte and the complete pinned native Go method set."""
    expected = {name for name in BINDINGS if not name.startswith((PACKAGE + "/", "sqlite3/"))}
    if not isinstance(dependencies, dict) or {name for name in dependencies if not name.startswith("sqlite3/")} != expected:
        v.reject("retention-dependency-inventory")
    methods = {name: v.digest(data) for name, data in dependencies.items() if name.startswith("sqlite3/")}
    if len(methods) != 44 or any(not isinstance(data, bytes) for data in dependencies.values()):
        v.reject("retention-native-method-inventory")
    actual = {name: v.digest(data) for name, data in dependencies.items() if name in expected}
    actual.update({name: v.file_digest(root / name) for name in BINDINGS if name.startswith(PACKAGE + "/")})
    actual["sqlite3/method-set"] = v.digest(v.encode(methods))
    if actual != BINDINGS:
        v.reject("retention-source-drift")
    return actual


def inputs(decision: dict, frames: list[dict]) -> list[dict]:
    """Derive two independent limit pairs from exact native rows, cursor position and actual Next calls."""
    wanted = []
    rows = [[base64.b64encode(bytes(7) + bytes([version])).decode(), 66] for version in (1, 2)]
    for point, history, backlog in (("count", 1, 1024), ("backlog", 8, 66)):
        for index in (0, 1):
            retained, size = 2 - index, (2 - index) * 66
            values = [retained > history, size > backlog, True]
            wanted.append(
                {
                    "test": "TestRetentionInputs/" + point,
                    "retained": retained,
                    "backlog": size,
                    "history_limit": history,
                    "backlog_limit": backlog,
                    "rows": rows,
                    "index": index,
                    "next_index": 1,
                    "next_calls": 1 - index,
                    "values": values,
                    "result": index == 0,
                }
            )
    if v.encode(frames) != v.encode(wanted) or decision["id"] != PACKAGE + "/commit.go:8972" or decision["text"] != EXPRESSIONS["commit.go:8972"]:
        v.reject("retention-native-inputs")
    observed = {authority.project(decision, frame["values"]) for frame in frames}
    result = []
    for target, first, second in ((0, frames[0], frames[1]), (1, frames[2], frames[3])):
        pair = {
            "decision": decision["id"],
            "condition": target,
            "before": {"values": first["values"], "result": first["result"]},
            "after": {"values": second["values"], "result": second["result"]},
        }
        result.append(
            {
                **authority.correlate_pair(decision, pair, observed),
                "basis": "The unchanged condition consumes real SQLite rows frozen into a bounded private memory cursor. Availability is derived from its immutable rows and index; skipped Next remains zero in the execution vector.",
                "test": first["test"],
            }
        )
    return result


def guarded(decisions: dict, observed: dict) -> list[dict]:
    """Accept only four registered metadata-error guards, including the universally masked absent size."""
    cases = (
        ("lock_linux.go:636", 0, [False, True], [True, None]),
        ("store.go:4000", 0, [False, True], [True, None]),
        ("store.go:10634", 1, [False, True, True], [False, False, None]),
        ("store.go:10634", 0, [False, False, None], [True, False, None]),
    )
    pairs = []
    for suffix, target, before, after in cases:
        decision = decisions[PACKAGE + "/" + suffix]
        native = observed[decision["id"]]
        vectors = []
        for values in (before, after):
            vector, outcome = authority.project(decision, values)
            if (vector, outcome) not in native or vector[target] == "0":
                v.reject("retention-guard-native-witness")
            vectors.append({"values": vector, "result": outcome})
        if vectors[0]["result"] == vectors[1]["result"]:
            v.reject("retention-guard-no-effect")
        fixed = ["0" if left is None else "2" if left else "1" for left in before]
        for values, row in zip((before, after), vectors, strict=True):
            completion = fixed.copy()
            completion[target] = "2" if values[target] else "1"
            if logic.cube(decision, completion) is not row["result"]:
                v.reject("retention-guard-completion")
        pairs.append(
            {
                "decision": decision["id"],
                "condition": target,
                "before": {"values": before, "result": vectors[0]["result"]},
                "after": {"values": after, "result": vectors[1]["result"]},
                "native_vectors": vectors,
                "criterion": "defined-domain-short-circuit-v1",
                "basis": "Pinned Unix Stat/Lstat return nil FileInfo on error. IsNotExist implies a nonnil error; Size is undefined, and the false err==nil guard masks every completion. No absent field is evaluated or given a native hit.",
            }
        )
    return pairs


def coupled(decision: dict, target: int, relation: Callable[[tuple[bool, ...]], bool], native: dict) -> dict:
    """Exhaust this fixed decision's Boolean overapproximation and require a relaxed counterexample."""
    total, allowed = {}, {}
    for values in itertools.product((False, True), repeat=len(decision["atoms"])):
        vector = "".join("2" if value else "1" for value in values)
        row = vector, logic.cube(decision, vector)
        total[row] = 1
        if relation(values):
            allowed[row] = 1
    if not allowed or len(allowed) == len(total) or {row[1] for row in allowed} != {False, True}:
        v.reject("retention-coupling-vacuous")
    witnesses, _, complete = logic.candidates(decision, allowed, logic.COMPARISONS, certify=True)
    relaxed, _, relaxed_complete = logic.candidates(decision, total, logic.COMPARISONS, certify=True)
    if not complete or not relaxed_complete or target in witnesses or target not in relaxed:
        v.reject("retention-coupling-proof")
    for vector, outcome in native:
        if not any(result is outcome and all(a == "0" or a == b for a, b in zip(vector, values, strict=True)) for values, result in allowed):
            v.reject("retention-coupling-native-contradiction")
    return {"assignments": len(total), "admissible": len(allowed), "relaxed_counterexample": relaxed[target]}


def residual(decisions: dict, observed: dict, frames: list[dict], bindings: dict) -> dict:
    """Disposition all fourteen fixed residual coordinates; never alter their raw denominator or qualify unrelated rules."""
    if bindings != BINDINGS:
        v.reject("retention-source-bindings")
    for suffix, expression in EXPRESSIONS.items():
        identity = PACKAGE + "/" + suffix
        decision = decisions.get(identity)
        native = observed.get(identity)
        if decision is None or decision["text"] != expression or not isinstance(native, dict) or not native:
            v.reject("retention-decision-binding", identity)
        if any(type(hits) is not int or hits <= 0 or logic.evaluate(decision, vector) is not result for (vector, result), hits in native.items()):
            v.reject("retention-native-vector", identity)
    pairs = guarded(decisions, observed) + inputs(decisions[PACKAGE + "/commit.go:8972"], frames)
    excluded = []
    for suffix in ("store.go:11406", "store.go:11597", "store.go:11618"):
        decision = decisions[PACKAGE + "/" + suffix]
        if decision["kind"] != "return" or len(decision["atoms"]) != 1:
            v.reject("retention-literal-binding")
        excluded.append({"decision": decision["id"], "condition": 0, "reason": "literal-return-not-variable"})
    for identity, target, impossible, reason in structure.STORAGE_ASSUMPTIONS:
        if any(vector[target] == ("2" if impossible else "1") for vector, _ in observed[identity]):
            v.reject("retention-domain-contradiction")
        excluded.append({"decision": identity, "condition": target, "reason": reason, **structure.STORAGE_REASONS[reason]})
    for suffix, target, relation, reason in (
        (
            "store.go:2674",
            3,
            lambda values: not values[3] or values[5],
            "Pinned ParseAddrPort errors return zero AddrPort; its zero port already rejects the endpoint.",
        ),
        (
            "read.go:3910",
            0,
            lambda values: not values[0] or not values[1] or values[2],
            "Sequential Scan into a zero Record leaves an invalid key or nil payload on every failure; there is no native RowsColumnScanner override.",
        ),
        (
            "read.go:6637",
            0,
            lambda values: not values[0] or values[3] or values[4],
            "Sequential Scan fails before a nonnil value or leaves cost zero. The source-bound (64 MiB)+1024 SQLite row cap on amd64 prevents 64+len(key)+len(value) overflow; zero cost is unequal.",
        ),
    ):
        decision = decisions[PACKAGE + "/" + suffix]
        proof = coupled(decision, target, relation, observed[decision["id"]])
        excluded.append(
            {
                "decision": decision["id"],
                "condition": target,
                "reason": "source-coupled",
                "assumption": reason,
                "invalidated_by": "Changed production, dependency, method-set, scan order, destination initialization, native row bound or platform identity.",
                "proof": proof,
            }
        )
    return {"pairs": pairs, "exclusions": excluded, "supported": len(pairs), "excluded": len(excluded), "raw": 14, "bindings": bindings}
