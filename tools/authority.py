"""Generate, execute and verify source-bound authority input pairs without claiming skipped-condition hits."""

import argparse
import base64
import ctypes
from pathlib import Path
import signal
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import build, equality, logic, verify as v

# Frozen production scope; input-pair semantics depend on these exact uncommitted source bytes.
SOURCE = "343c868721dc64bfd8dabd917d55e16283adebe562a4b810683121348d3224be"
CACHE = "1f7d34e07e0b4294a668fbfdb4e86e797c4b70264726a3e43af2b433cb692450"
PACKAGE = "github.com/eosforge/astra/polaris/internal/server"
FIXTURE = "tests/fixtures/authority.go.in"
PROFILES = ("baseline", "race")
LOG_BYTES = 4 * 1024**2
SOURCES = {
    "authority.go": SOURCE,
    "cache.go": CACHE,
    "window.go": "1cff18acf241738c7dc5f556c0e3191472ca895d839872b3b9d9b322cef27d19",
    "stream.go": "cb32fe961c3d2704a29001ca1a5c45a70f7a2c02189d9cc7b959788a040793a3",
}
GUARDS = {
    "dependencies": ("authority.go", 2233, "store == nil || directory == nil"),
    "budget": ("authority.go", 2363, "snapshotBytes < cache.reserve || snapshotBytes > 1<<30"),
    "scope": ("authority.go", 8987, 'scope.Sector != "__auth" || scope.Spectrum != "comet"'),
    "key": ("authority.go", 9132, "len(change.Key) == 0 || len(change.Key) > 128 || !utf8.ValidString(change.Key) || strings.ContainsRune(change.Key, 0)"),
    "frame": ("authority.go", 12354, "maximum < 1024 || maximum > 8<<20"),
    "window": ("window.go", 1233, "len(transfer.credits) != 0 && (len(transfer.credits) >= 128 || cost > 8<<20-transfer.bytes)"),
    "release": ("window.go", 2428, "item.scope == scope && item.version <= version"),
    "ready": ("stream.go", 28137, "!present || installed < minimum"),
    "inventory": ("stream.go", 11298, "duplicate || !scope.Valid()"),
    "ack": ("stream.go", 22919, "!scope.Valid() || !exists || storage.Version(position.Version) > sent"),
    "floor": ("stream.go", 23863, "!exists || version < minimum"),
    "sent": ("stream.go", 24160, "!exists || version > sent"),
    "assessment": ("stream.go", 24851, "transfer.probe != nil || transfer.actual != nil"),
    "authority": ("stream.go", 26355, "!exists || version > current || version > transfer.sent[scope]"),
    "repair": ("stream.go", 26830, "expected && (!present || after < minimum)"),
    "batch": ("authority.go", 4888, "complete || page == nil || page.Scope == nil || page.Version == 0 || len(page.Changes) == 0"),
    "commit-scope": ("authority.go", 5882, "request == nil || request.Scope == nil || (request.Change == nil) == (len(request.Changes) == 0)"),
    "hello": ("stream.go", 12087, "hello == nil || hello.ProtocolMajor != 1 || hello.MaxFrameBytes < 1024 || hello.MaxFrameBytes > 8<<20"),
    "snapshot-prefix": ("authority.go", 12954, "len(page.Entries) != 0 && size+cost > min(maximum, 256<<10)"),
    "updates-prefix": ("stream.go", 21217, "len(page.Patches) != 0 && size+cost > min(transfer.maximum, 256<<10)"),
    "payload": (
        "authority.go",
        9467,
        "len(change.Value) <= 8192 && proto.Unmarshal(change.Value, &value) == nil && len(value.Secret) > 0 && len(value.Secret) <= 4096",
    ),
    "batch-position": ("authority.go", 5166, "!proto.Equal(request.Scope, page.Scope) || request.Version != page.Version"),
    "packet": ("stream.go", 22430, "packet == nil || !transfer.owner.node.Directory().Current(transfer.remote)"),
    "deadline": ("authority.go", 2975, "!ok || time.Until(deadline) <= 0 || time.Until(deadline) > 30*time.Second"),
    "prepared": ("cache.go", 3772, "entry.err == nil && entry.snapshot.Version < minimum"),
    "initial": ("stream.go", 14271, "!exists || version > current"),
    "probe": ("stream.go", 23405, "inventory != nil && transfer.probe != nil"),
    "suffix": ("stream.go", 16442, "begin < len(events) && events[begin].Scope == scope && len(changes) < 128"),
    "manifest-prefix": ("stream.go", 18173, "len(page.Positions) != 0 && size+cost > min(transfer.maximum, 256<<10)"),
}

# These pairs preserve undefined dereferences explicitly; they are separate from total-input independence.
GUARDED = {
    "batch-null": ("authority.go", 4888, 1, [False, False, False, False, False], [False, True, None, None, None]),
    "commit-null": ("authority.go", 5882, 0, [False, False, False], [True, None, None]),
    "batch-erase": ("authority.go", 6822, 0, [False, False], [True, None]),
    "single-erase": ("authority.go", 7882, 0, [False, False], [True, None]),
    "position-null": ("stream.go", 10972, 0, [False, False], [True, None]),
    "hello-null": ("stream.go", 12087, 0, [False, False, False, False], [True, None, None, None]),
    "ack-null": ("stream.go", 22725, 0, [True, True], [False, None]),
    "suffix-end": ("stream.go", 16442, 0, [True, True, True], [False, None, True]),
}

# Undefined means a Go dereference/index has no value, not that its evaluation was merely skipped.
DOMAINS = {
    "batch-null": ("complete || page == nil || page.Scope == nil || page.Version == 0 || len(page.Changes) == 0", "nil-page-fields"),
    "commit-null": ("request == nil || request.Scope == nil || (request.Change == nil) == (len(request.Changes) == 0)", "nil-request-fields"),
    "batch-erase": ("action == nil || action.Erase == nil", "nil-erase-wrapper"),
    "single-erase": ("action == nil || action.Erase == nil", "nil-erase-wrapper"),
    "position-null": ("position == nil || position.Scope == nil", "nil-position-field"),
    "hello-null": ("hello == nil || hello.ProtocolMajor != 1 || hello.MaxFrameBytes < 1024 || hello.MaxFrameBytes > 8<<20", "nil-hello-fields"),
    "ack-null": ("position != nil && position.Scope != nil", "nil-position-field"),
    "suffix-end": ("begin < len(events) && events[begin].Scope == scope && len(changes) < 128", "exhausted-event-index"),
}


def project(decision: dict, values: list) -> tuple[str, bool]:
    """Project defined input values through a validated AST without evaluating an undefined operand."""
    if not isinstance(values, list) or len(values) != len(decision["atoms"]) or any(value is not None and type(value) is not bool for value in values):
        v.reject("authority-projection-values")
    visited = set()

    def visit(index: int) -> bool:
        """Preserve native evaluation order and keep absent fields out of the execution vector."""
        node = decision["tree"][index]
        if node["kind"] == "atom":
            atom = node["atom"]
            if values[atom] is None:
                v.reject("authority-projection-undefined")
            visited.add(atom)
            return values[atom]
        left = visit(node["children"][0])
        if node["kind"] == "not":
            return not left
        return left and visit(node["children"][1]) if node["kind"] == "and" else left or visit(node["children"][1])

    result = visit(decision["root"])
    vector = "".join(("2" if value else "1") if index in visited else "0" for index, value in enumerate(values))
    if logic.evaluate(decision, vector) != result:
        v.reject("authority-projection-result")
    return vector, result


def correlate_pair(decision: dict, pair: dict, observed: set, *, guard: str | None = None) -> dict:
    """Verify one total-input or specifically registered partial-domain independence witness.

    Partial-domain certification keeps every jointly defined nontarget value fixed.
    It is limited to the eight source-bound nil/index guards; arbitrary masked or
    coupled predicates cannot acquire this criterion by substituting null values.
    The caller must validate native provenance and the complete production forest.
    """
    logic.fields(pair, ("decision", "condition", "before", "after"), "authority-pair")
    target = pair["condition"]
    if pair["decision"] != decision["id"] or type(target) is not int or not 0 <= target < len(decision["atoms"]):
        v.reject("authority-pair-identity")
    for side in ("before", "after"):
        logic.fields(pair[side], ("values", "result"), "authority-pair-side")
        if type(pair[side]["result"]) is not bool:
            v.reject("authority-pair-result")
    before, after = (pair[side]["values"] for side in ("before", "after"))
    vectors = []
    for side in ("before", "after"):
        vector, result = project(decision, pair[side]["values"])
        if (vector, result) not in observed or vector[target] == "0" or result != pair[side]["result"]:
            v.reject("authority-pair-native-witness")
        vectors.append({"values": vector, "result": result})
    if before[target] == after[target] or pair["before"]["result"] == pair["after"]["result"]:
        v.reject("authority-pair-no-effect")
    if guard is None:
        if any(value is None for values in (before, after) for value in values):
            v.reject("authority-pair-total-domain")
        basis = "total-input-single-condition-v1"
    else:
        if guard not in DOMAINS:
            v.reject("authority-pair-undefined-domain")
        name, offset, condition, first, second = GUARDED[guard]
        if (
            decision["id"] != f"polaris/internal/server/{name}:{offset}"
            or decision["text"] != DOMAINS[guard][0]
            or target != condition
            or v.encode(before) != v.encode(first)
            or v.encode(after) != v.encode(second)
        ):
            v.reject("authority-pair-undefined-binding")
        basis = "defined-domain-short-circuit-v1"
    if any(left != right for index, (left, right) in enumerate(zip(before, after, strict=True)) if index != target and right is not None):
        v.reject("authority-pair-coupled-change")
    # This completion checks the algebraic effect, not an execution of an absent field.
    completed = [left if right is None else right for left, right in zip(before, after, strict=True)]
    for values, side in ((before, "before"), (completed, "after")):
        if logic.cube(decision, "".join("2" if value else "1" for value in values)) != pair[side]["result"]:
            v.reject("authority-pair-completion")
    return {
        **pair,
        "criterion": basis,
        "undefined_domain": DOMAINS[guard][1] if guard else None,
        "native_vectors": vectors,
    }


def correlate(root: Path, trace: dict, data: bytes, test_files: int, profiles: dict) -> dict:
    """Recompute the finite Server independence ledger from native streams, retaining unresolved conditions.

    The enclosing receiver verifies sealed archives, compiler/overlay identity,
    commands and retirement. This pure interpretation does not establish trust,
    full-component qualification, or formal gate eligibility.
    """
    from tools import structure

    scope = structure.domain(structure.SERVER)
    if v.digest(v.encode(trace.get("files"))) != scope["forest"] or trace.get("version") != 2:
        v.reject("authority-correlation-forest")
    for row in trace["files"]:
        if v.file_digest(root / row["file"]) != row["sha256"]:
            v.reject("authority-correlation-source")
    if set(profiles) != set(PROFILES):
        v.reject("authority-correlation-profiles")
    inputs = {}
    for name, profile in profiles.items():
        logic.fields(profile, ("stdout", "stderr", "record"), "authority-native-profile")
        inputs[name] = outcome(profile["stdout"], profile["stderr"], profile["record"], root)
    if v.encode(inputs["baseline"]) != v.encode(inputs["race"]):
        v.reject("authority-correlation-profile-drift")
    inventory = logic.inventory(trace)
    report = logic.summary(trace, data, PACKAGE, test_files)
    if report["totals"]["atoms"] != 214 or report["independence"]["search_incomplete"] or report["totals"]["search_incomplete"]:
        v.reject("authority-correlation-denominator-or-budget")
    rows = {row["id"]: row for row in report["decisions"]}
    covered = {
        (row["id"], atom["index"]): {"criterion": "universal-common-cube-v1", "witness": atom["independent"]}
        for row in rows.values()
        for atom in row["atoms"]
        if atom["independent"] is not None
    }
    trace_count = len(covered)
    proofs, guarded_proofs = [], []
    seen = set()
    for group, target in (("pairs", proofs), ("guarded", guarded_proofs)):
        for index, pair in enumerate(inputs["baseline"][group]):
            identity, condition = pair["decision"], pair["condition"]
            key = identity, condition
            if key in seen:
                v.reject("authority-correlation-duplicate")
            seen.add(key)
            actual = {(row["values"], row["result"]) for row in rows[identity]["vectors"] if row["hits"] > 0}
            proof = correlate_pair(inventory[identity], pair, actual, guard=list(GUARDED)[index] if group == "guarded" else None)
            target.append(proof)
            covered.setdefault(key, {"criterion": proof["criterion"], "witness": proof})
    authenticated = authentication(root, inventory["polaris/internal/server/stream.go:9185"], rows["polaris/internal/server/stream.go:9185"])
    excluded, unresolved = [], []
    for identity, decision in inventory.items():
        literal = decision["kind"] == "return" and decision["text"] in ("true", "false")
        for index, atom in enumerate(decision["atoms"]):
            key = identity, index
            if literal:
                expected = decision["text"] == "true"
                if key in covered or any(row["result"] != expected for row in rows[identity]["vectors"]):
                    v.reject("authority-correlation-constant-contradiction")
                excluded.append({"decision": identity, "condition": index, "text": atom["text"], "reason": "literal-return-not-variable"})
            elif key not in covered and key != (authenticated["decision"], authenticated["condition"]):
                unresolved.append({"decision": identity, "condition": index, "text": atom["text"]})
    return {
        "qualification": "not-evaluated",
        "status": "incomplete" if unresolved else "complete-under-declared-domains",
        "raw_conditions": report["totals"]["atoms"],
        "trace_independent": trace_count,
        "total_input_pairs": proofs,
        "guarded_pairs": guarded_proofs,
        "supported_conditions": len(covered),
        "conditions": [{"decision": identity, "condition": index, **value} for (identity, index), value in sorted(covered.items())],
        "literal_exclusions": excluded,
        "domain_exclusions": [authenticated],
        "qualified_denominator": report["totals"]["atoms"] - len(excluded) - 1,
        "unresolved": unresolved,
        "inputs": {
            "trace": v.digest(v.encode(trace)),
            "typed_stdout": v.digest(data),
            **{name: v.digest(profile["stdout"]) for name, profile in profiles.items()},
        },
        "boundary": "The raw denominator retains three literals and one source-conditioned authentication exclusion. The manifest pair includes explicit persisted corruption, not healthy-write reachability. Partial-domain proofs never create skipped operand hits. This ledger does not itself grant full-component MC/DC, protected trust or release eligibility.",
    }


def authentication(root: Path, decision: dict, observed: dict) -> dict:
    """Bind the sole private-worker admission assumption and reject any native counterexample.

    The complete Server forest is verified by correlate; concrete dependency
    implementations are pinned separately here. Native valid/invalid signature
    controls supplement, rather than prove, the reviewed call-graph argument.
    """
    from tools import structure

    if (
        decision["id"] != "polaris/internal/server/stream.go:9185"
        or decision["text"] != "transfer.remote != nil && !transfer.owner.node.Directory().Current(transfer.remote)"
    ):
        v.reject("authority-authentication-binding")
    for path, digest in structure.SERVER_DEPENDENCIES.items():
        if v.file_digest(root / path.removeprefix("astra/")) != digest:
            v.reject("authority-authentication-dependency")
    vectors = observed.get("vectors", [])
    if not vectors or any(type(row.get("hits")) is not int or row["hits"] <= 0 or row.get("values") not in ("21", "22") for row in vectors):
        v.reject("authority-authentication-contradiction")
    return {
        "decision": decision["id"],
        "condition": 0,
        "reason": "authenticated-send",
        "dependencies": structure.SERVER_DEPENDENCIES,
        **structure.SERVER_REASONS["authenticated-send"],
        "alternative": "Native invalid-signature rejection precedes any send; valid signature reaches exactly one controlled Hello send and retires registration/deadline ownership in ordinary and Race profiles.",
    }


def guarded() -> list[dict]:
    """Fix nonnil/defined input controls without inventing values for unavailable fields."""
    return [{"guard": guard, "before": {"present": True, "accepted": True}, "after": {"present": False, "accepted": False}} for guard in GUARDED]


def payloads() -> tuple[bytes, ...]:
    """Freeze protocol field-one vectors and legal field-100 padding independently of the Go encoder."""
    secret = b"\x0a\x01\x01"
    return secret + b"\xa2\x06\xf9\x3f" + bytes(8185), secret + b"\xa2\x06\xfa\x3f" + bytes(8186), secret, secret + b"\0", b""


def expected() -> list[dict]:
    """Construct exact authority and delivery boundaries from fixed public and protocol contracts."""
    rows = []

    def pair(guard: str, condition: int, before: dict | int | str | bool, after: dict | int | str | bool, accepted: bool = True) -> None:
        """Keep literal before/after expectations separate from collected native results."""
        rows.append(
            {
                "guard": guard,
                "condition": condition,
                "before": {"input": before, "accepted": accepted},
                "after": {"input": after, "accepted": not accepted},
            }
        )

    for condition, field in enumerate(("store", "directory")):
        before = {"store": True, "directory": True, "budget": 3146112}
        pair("dependencies", condition, before, {**before, field: False})
    for condition, values in enumerate(((3146112, 3146111), (1073741824, 1073741825))):
        pair("budget", condition, {"store": True, "directory": True, "budget": values[0]}, {"store": True, "directory": True, "budget": values[1]})
    for condition, (field, value) in enumerate((("sector", "business"), ("spectrum", "other"))):
        before = {"sector": "__auth", "spectrum": "comet", "key": "", "erase": True}
        pair("scope", condition, before, {**before, field: value}, False)
    for condition, values in enumerate(((b"a", b""), (b"a" * 128, b"a" * 129), (b"a", b"\xff"), (b"a", b"\0"))):
        before = {"sector": "__auth", "spectrum": "comet", "key": base64.b64encode(values[0]).decode(), "erase": True}
        pair("key", condition, before, {**before, "key": base64.b64encode(values[1]).decode()})
    for condition, values in enumerate(((1024, 1023), (8388608, 8388609))):
        pair("frame", condition, values[0], values[1])
    for condition, before, after in (
        (0, {"count": 0, "cost": 8388609}, {"count": 1, "cost": 8388609}),
        (1, {"count": 127, "cost": 1}, {"count": 128, "cost": 1}),
        (2, {"count": 1, "cost": 8388544}, {"count": 1, "cost": 8388545}),
    ):
        pair("window", condition, before, after)
    pair("release", 0, {"spectrum": "q", "version": 0, "ack": 0}, {"spectrum": "p", "version": 0, "ack": 0}, False)
    pair("release", 1, {"spectrum": "p", "version": 1, "ack": 0}, {"spectrum": "p", "version": 1, "ack": 1}, False)
    pair("ready", 0, {"present": False, "version": 0, "minimum": 0}, {"present": True, "version": 0, "minimum": 0}, False)
    pair("ready", 1, {"present": True, "version": 0, "minimum": 1}, {"present": True, "version": 1, "minimum": 1}, False)
    pair("inventory", 0, {"duplicate": False, "sector": "s"}, {"duplicate": True, "sector": "s"})
    pair("inventory", 1, {"duplicate": False, "sector": "s"}, {"duplicate": False, "sector": ""})
    pair("ack", 1, {"present": False, "sent": 0, "version": 0}, {"present": True, "sent": 0, "version": 0}, False)
    pair("ack", 2, {"present": True, "sent": 0, "version": 0}, {"present": True, "sent": 0, "version": 1})
    pair("floor", 0, {"present": False, "version": 0, "minimum": 0}, {"present": True, "version": 0, "minimum": 0}, False)
    pair("floor", 1, {"present": True, "version": 0, "minimum": 1}, {"present": True, "version": 1, "minimum": 1}, False)
    pair("sent", 0, {"present": False, "sent": 0, "version": 0}, {"present": True, "sent": 0, "version": 0}, False)
    pair("sent", 1, {"present": True, "sent": 0, "version": 0}, {"present": True, "sent": 0, "version": 1})
    pair("assessment", 0, {"probe": False, "actual": False}, {"probe": True, "actual": False})
    pair("assessment", 1, {"probe": False, "actual": False}, {"probe": False, "actual": True})
    pair("authority", 0, {"known": False, "sent": 1, "version": 0}, {"known": True, "sent": 1, "version": 0}, False)
    pair("authority", 1, {"known": True, "sent": 2, "version": 1}, {"known": True, "sent": 2, "version": 2})
    pair("authority", 2, {"known": True, "sent": 0, "version": 0}, {"known": True, "sent": 0, "version": 1})
    pair(
        "repair", 0, {"expected": False, "present": False, "version": 0, "minimum": 0}, {"expected": True, "present": False, "version": 0, "minimum": 0}, False
    )
    pair("repair", 1, {"expected": True, "present": False, "version": 0, "minimum": 0}, {"expected": True, "present": True, "version": 0, "minimum": 0})
    pair("repair", 2, {"expected": True, "present": True, "version": 0, "minimum": 1}, {"expected": True, "present": True, "version": 1, "minimum": 1})
    for condition, field, value in ((0, "complete", True), (2, "scope", False), (3, "version", 0)):
        before = {"complete": False, "scope": True, "version": 1}
        pair("batch", condition, before, {**before, field: value})
    pair("commit-scope", 1, True, False)
    pair("hello", 1, {"major": 1, "maximum": 1024}, {"major": 2, "maximum": 1024})
    pair("hello", 2, {"major": 1, "maximum": 1024}, {"major": 1, "maximum": 1023})
    for guard in ("snapshot-prefix", "updates-prefix"):
        before = {"prefix": False, "bytes": 262144, "maximum": 8388608}
        pair(guard, 0, before, {**before, "prefix": True}, False)
    values = payloads()
    for condition, first, second in ((0, 0, 1), (1, 2, 3), (2, 2, 4)):
        pair("payload", condition, base64.b64encode(values[first]).decode(), base64.b64encode(values[second]).decode())
    pair("batch-position", 0, True, False)
    pair("packet", 0, True, False)
    before = {"present": True, "sent": 0, "version": 0, "sector": "s"}
    pair("ack", 0, before, {**before, "sector": ""})
    pair("deadline", 0, {"present": True, "seconds": 5}, {"present": False, "seconds": 5})
    pair("deadline", 1, {"present": True, "seconds": 5}, {"present": True, "seconds": 0})
    pair("prepared", 0, False, True, False)
    pair("initial", 0, False, True, False)
    pair("probe", 0, True, False)
    pair("suffix", 1, True, False)
    pair("manifest-prefix", 0, False, True, False)
    return rows


def operands(guard: str, value: dict | int | str | bool) -> tuple[bool, ...]:
    """Derive total input predicates only; never run a skipped production decoder, dereference or time read."""
    if guard == "dependencies":
        return not value["store"], not value["directory"]
    if guard == "budget":
        return value["budget"] < 3146112, value["budget"] > 1073741824
    if guard == "scope":
        return value["sector"] != "__auth", value["spectrum"] != "comet"
    if guard == "key":
        raw = base64.b64decode(value["key"], validate=True)
        try:
            raw.decode("utf-8", errors="strict")
            valid = True
        except UnicodeDecodeError:
            valid = False
        return not raw, len(raw) > 128, not valid, b"\0" in raw
    if guard == "frame":
        return value < 1024, value > 8388608
    if guard == "window":
        return value["count"] != 0, value["count"] >= 128, value["cost"] > 8388608 - 64 * value["count"]
    if guard == "release":
        return value["spectrum"] == "p", value["version"] <= value["ack"]
    if guard == "ready":
        return not value["present"], value["version"] < value["minimum"]
    if guard == "inventory":
        return value["duplicate"], value["sector"] == ""
    if guard == "ack":
        return value.get("sector", "s") == "", not value["present"], value["version"] > value["sent"]
    if guard == "floor":
        return not value["present"], value["version"] < value["minimum"]
    if guard == "sent":
        return not value["present"], value["version"] > value["sent"]
    if guard == "assessment":
        return value["probe"], value["actual"]
    if guard == "authority":
        return not value["known"], value["version"] > int(value["known"]), value["version"] > value["sent"]
    if guard == "repair":
        return value["expected"], not value["present"], value["version"] < value["minimum"]
    if guard == "batch":
        return value["complete"], False, not value["scope"], value["version"] == 0, False
    if guard == "commit-scope":
        return False, not value, False
    if guard == "hello":
        return False, value["major"] != 1, value["maximum"] < 1024, value["maximum"] > 8388608
    if guard in ("snapshot-prefix", "updates-prefix"):
        if value["bytes"] != 262144 or value["maximum"] != 8388608:
            raise ValueError("Paging proof requires its exact literal payload and negotiated capacity")
        # The payload alone equals the soft limit; positive protocol overhead makes either page cost strictly larger.
        return value["prefix"], True
    if guard == "payload":
        raw = base64.b64decode(value, validate=True)
        vectors = payloads()
        if raw not in vectors:
            raise ValueError("Credential proof requires an exact literal wire vector")
        # Tag zero is invalid after the already decoded one-byte secret. Native checks independently bind that decoder behavior.
        return len(raw) <= 8192, raw != vectors[3], bool(raw), True
    if guard == "batch-position":
        return not value, False
    if guard == "packet":
        return not value, False
    if guard == "deadline":
        if type(value.get("present")) is not bool or type(value.get("seconds")) is not int or value["seconds"] not in (0, 5):
            raise ValueError("Deadline proof requires the frozen virtual instant and zero/five-second vectors")
        return not value["present"], value["seconds"] <= 0, value["seconds"] > 30
    if guard == "prepared":
        return value, True
    if guard == "initial":
        return not value, False
    if guard == "probe":
        return value, True
    if guard == "suffix":
        if type(value) is not bool:
            raise ValueError("Suffix proof requires exactly two adjacent events and a Boolean scope selection")
        return True, value, True
    if guard == "manifest-prefix":
        if type(value) is not bool:
            raise ValueError("Manifest proof requires the fixed 1024-byte corrupted name and 1024-byte negotiated limit")
        return value, True
    raise ValueError("Unknown authority guard")


def decision(guard: str, terms: tuple[bool, ...]) -> bool:
    """Apply the declared pure decision shape without conflating admission with acknowledgement."""
    if guard in ("window", "repair"):
        return terms[0] and (terms[1] or terms[2])
    if guard in ("release", "snapshot-prefix", "updates-prefix", "payload", "prepared", "probe", "suffix", "manifest-prefix"):
        return all(terms)
    return any(terms)


def independent(row: dict) -> bool:
    """Require a single changed condition, opposite decisions and the fixed acceptance orientation."""
    before, after = (operands(row["guard"], row[side]["input"]) for side in ("before", "after"))
    changes = [index for index, (first, second) in enumerate(zip(before, after, strict=True)) if first != second]
    accepted = [decision(row["guard"], before), decision(row["guard"], after)]
    if row["guard"] not in ("scope", "release", "repair", "snapshot-prefix", "updates-prefix", "payload", "prepared", "probe", "suffix", "manifest-prefix"):
        accepted = [not result for result in accepted]
    return changes == [row["condition"]] and accepted[0] != accepted[1] and accepted == [row[side]["accepted"] for side in ("before", "after")]


def vector(row: dict, side: str) -> dict:
    """Bind derived total inputs to raw source atoms, retaining each explicit source negation."""
    terms = operands(row["guard"], row[side]["input"])
    atoms = list(terms)
    if row["guard"] == "key":
        atoms[2] = not atoms[2]
    if row["guard"] == "ready":
        atoms[0] = not atoms[0]
    if row["guard"] == "inventory":
        atoms[1] = not atoms[1]
    if row["guard"] == "ack":
        atoms[0], atoms[1] = not atoms[0], not atoms[1]
    if row["guard"] in ("floor", "sent", "authority"):
        atoms[0] = not atoms[0]
    if row["guard"] == "repair":
        atoms[1] = not atoms[1]
    if row["guard"] == "batch-position":
        atoms[0] = not atoms[0]
    if row["guard"] == "packet":
        atoms[1] = not atoms[1]
    if row["guard"] in ("deadline", "initial"):
        atoms[0] = not atoms[0]
    return {"values": atoms, "result": decision(row["guard"], terms)}


def observations(data: bytes, root: Path) -> dict:
    """Require source identity, complete native lifecycle and all exact input pairs before deriving a scoped ledger."""
    sources = {name: v.read(root / "polaris/internal/server" / name) for name in SOURCES}
    if any(v.digest(sources[name]) != digest for name, digest in SOURCES.items()):
        v.reject("authority-pairs-source")
    for guard, (name, offset, text) in GUARDS.items():
        fragment = text.encode()
        # The initial-plan condition is also the prefix of the longer reconciliation condition.
        occurrences = 2 if guard == "initial" else 1
        if sources[name][offset : offset + len(fragment)] != fragment or sources[name].count(fragment) != occurrences:
            v.reject("authority-pairs-binding")
    started, complete, state = False, False, None
    for line in data.splitlines():
        event = v.decode(line)
        if not isinstance(event, dict) or event.get("Package") != PACKAGE or complete:
            v.reject("authority-pairs-stream")
        action, test = event.get("Action"), event.get("Test")
        if test not in (None, "TestPredicates"):
            v.reject("authority-pairs-test")
        if action == "start":
            if started or test is not None:
                v.reject("authority-pairs-start")
            started = True
            continue
        if not started:
            v.reject("authority-pairs-start")
        if action == "run":
            if test != "TestPredicates" or state is not None:
                v.reject("authority-pairs-test-start")
            state = "running"
        elif action == "output":
            if not isinstance(event.get("Output"), str) or test is not None and state != "running":
                v.reject("authority-pairs-output-order")
        elif action == "pass":
            if test is None:
                if state != "passed":
                    v.reject("authority-pairs-test-terminal")
                complete = True
            elif state != "running":
                v.reject("authority-pairs-test-terminal")
            else:
                state = "passed"
        else:
            v.reject("authority-pairs-action")
    if not complete:
        v.reject("authority-pairs-terminal")
    rows = equality.frames(data, PACKAGE, test="TestPredicates", marker="AUTHORITY-PREDICATES ", maximum=56)
    if v.encode(rows) != v.encode(expected()) or not all(independent(row) for row in rows):
        v.reject("authority-pairs-inputs")
    controls = equality.frames(data, PACKAGE, test="TestPredicates", marker="AUTHORITY-GUARDED ", maximum=8)
    if v.encode(controls) != v.encode(guarded()):
        v.reject("authority-guarded-inputs")
    admitted = equality.frames(data, PACKAGE, test="TestPredicates", marker="AUTHORITY-AUTHENTICATION ", maximum=2)
    if v.encode(admitted) != v.encode(
        [{"valid": False, "send_calls": 0, "remote": False, "retired": True}, {"valid": True, "send_calls": 1, "remote": True, "retired": True}]
    ):
        v.reject("authority-authentication-inputs")
    return {
        "qualification": "not-evaluated",
        "source_sha256": SOURCE,
        "sources": SOURCES,
        "pairs": [
            {
                "decision": "polaris/internal/server/" + GUARDS[row["guard"]][0] + ":" + str(GUARDS[row["guard"]][1]),
                "condition": row["condition"],
                "before": vector(row, "before"),
                "after": vector(row, "after"),
            }
            for row in rows
        ],
        "guarded": [
            {
                "decision": "polaris/internal/server/" + name + ":" + str(offset),
                "condition": condition,
                "before": {"values": before, "result": guard in ("ack-null", "suffix-end")},
                "after": {"values": after, "result": guard not in ("ack-null", "suffix-end")},
            }
            for guard, (name, offset, condition, before, after) in GUARDED.items()
        ],
        "authentication": admitted,
        "boundary": "Finite total-input independence and separate guarded-input observations. Null values denote undefined fields, never executed or invented Boolean values. Guarded pairs require separate AST correlation and short-circuit justification; no full-component MC/DC or release qualification.",
    }


def contents(root: Path, output: Path) -> dict[str, bytes]:
    """Construct only a fixture overlay, preserving every production source byte."""
    if not output.is_relative_to(root / "build") or output == root / "build":
        v.reject("authority-pairs-output")
    virtual = root / "polaris/internal/server/predicates_test.go"
    if virtual.exists():
        v.reject("authority-pairs-existing-test")
    fixture = v.read(root / FIXTURE)
    if fixture.count(b"func TestPredicates(") != 1 or b"package server" not in fixture:
        v.reject("authority-pairs-fixture")
    if any(v.file_digest(root / "polaris/internal/server" / name) != digest for name, digest in SOURCES.items()):
        v.reject("authority-pairs-source")
    files = {
        "predicates.go.txt": fixture,
        "overlay.json": v.encode({"Replace": {str(virtual): str(output / "predicates.go.txt")}}),
    }
    files["manifest.json"] = v.encode(
        {
            "source": {name: v.file_digest(root / name) for name in (*("polaris/internal/server/" + name for name in SOURCES), FIXTURE)},
            "files": {name: v.digest(data) for name, data in files.items()},
            "pairs": expected(),
            "guarded": guarded(),
            "qualification": "not-evaluated",
        }
    )
    return files


def generate(root: Path, output: Path) -> dict:
    """Write a fresh source-bound fixture plan without executing a test."""
    root, output = root.resolve(), output.resolve()
    files = contents(root, output)
    output.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        v.write_new(output / name, data)
    return v.decode(files["manifest.json"])


def command(output: Path, profile: str) -> list[str]:
    """Select the complete input, guarded-domain and authentication fixture in both configurations."""
    if profile not in PROFILES:
        v.reject("authority-pairs-profile")
    return (
        [str(build.CACHE / "tools/go-1.27.2/bin/go"), "test"]
        + (["-race"] if profile == "race" else [])
        + [
            "-json",
            "-count=1",
            "-p=2",
            "-parallel=1",
            "-timeout=60s",
            "-run=^TestPredicates$",
            "-overlay=" + str(output / "overlay.json"),
            "./polaris/internal/server",
        ]
    )


def outcome(data: bytes, errors: bytes, record: dict, root: Path) -> dict:
    """Require complete normal process retirement before interpreting any input witness."""
    if (
        record.get("complete") is not True
        or record.get("cleanup") is not True
        or record.get("termination") != "exited"
        or type(record.get("exit_code")) is not int
        or record["exit_code"] != 0
    ):
        v.reject("authority-pairs-incomplete")
    if any(marker in data + errors for marker in (b"WARNING: DATA RACE", b"panic:", b"fatal error:")):
        v.reject("authority-pairs-runtime")
    return observations(data, root)


def inspect(root: Path, output: Path) -> dict:
    """Rebuild frozen fixture bytes and derive each scoped pair from original native streams."""
    root, output = root.resolve(), output.resolve()
    for name, expected_bytes in contents(root, output).items():
        if v.read(v.inside(root, (output / name).relative_to(root).as_posix())) != expected_bytes:
            v.reject("authority-pairs-overlay-drift")
    profiles = {}
    for profile in PROFILES:
        directory = output / "records" / profile
        record = v.decode(v.read(directory / "record.json"))
        v.schema(record, "evidence", ("properties", "checks", "items"))
        if record["id"] != profile or record["platform"] != "linux-amd64-cgo" or record["argv"] != command(output, profile):
            v.reject("authority-pairs-command")
        for key, value in {"GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": "-mod=readonly"}.items():
            if record["resolved_environment"].get(key) != value:
                v.reject("authority-pairs-environment")
        profiles[profile] = outcome(v.reference(directory, record["stdout"], LOG_BYTES), v.reference(directory, record["stderr"], LOG_BYTES), record, root)
    return {"profiles": profiles, "qualification": "not-evaluated", "trust": "local"}


def run(root: Path, output: Path) -> int:
    """Run a finite plan within the authorized owner's resource limits and retain failures before interpretation."""
    if sys.platform != "linux" or ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0):
        v.reject("authority-pairs-linux-subreaper-required")
    generate(root, output)
    source = v.source(root)
    v.write_new(output / "inputs.json", source)
    stopped = False

    def cancel(*_: object) -> None:
        """Let the native executor drain its active group before this owner returns."""
        nonlocal stopped
        stopped = True

    handlers = {number: signal.signal(number, cancel) for number in (signal.SIGTERM, signal.SIGINT)}
    errors, results = [], None
    try:
        environment = build.environment(jobs=2)
        for profile in PROFILES:
            if stopped or v.source(root) != source:
                v.reject("authority-pairs-interrupted-or-source-drift")
            directory = output / "records" / profile
            directory.mkdir(parents=True)
            plan = {
                "id": profile,
                "argv": command(output, profile),
                "environment": {**environment, "TMPDIR": str(directory / "tmp")},
                "timeout_s": 300,
                "log_bytes": LOG_BYTES,
            }
            v.write_new(directory / "plan.json", plan)
            record = v.execute(plan, root, directory, "linux-amd64-cgo", lambda: stopped)
            v.write_new(directory / "record.json", record)
            outcome(v.reference(directory, record["stdout"], LOG_BYTES), v.reference(directory, record["stderr"], LOG_BYTES), record, root)
        results = inspect(root, output)
    except (OSError, ValueError, v.Invalid) as error:
        errors.append(str(error))
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)
    unchanged, remaining = v.source(root) == source, v.owned_members()
    complete = results is not None and not errors and not stopped and unchanged and not remaining
    result = {
        "status": "completed" if complete else "interrupted" if stopped else "blocked",
        "results": results,
        "errors": errors,
        "source_unchanged": unchanged,
        "remaining_owned": remaining,
    }
    v.write_new(output / "result.json", result)
    print(v.encode(result).decode())
    return 0 if complete else 2


def main() -> int:
    """Default to generation; executing either native profile requires the current task's testing permission."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--inspect", action="store_true")
    args = parser.parse_args()
    if args.run:
        return run(args.root.resolve(), args.output.resolve())
    print(v.encode(inspect(args.root, args.output) if args.inspect else generate(args.root, args.output)).decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
