"""Reconstruct local Ephemeris registers, authoritative endings and jointly ordered public observations."""

from pathlib import Path
import copy
from dataclasses import dataclass, field

from tools import models
from tools import verify as v

# Opaque fixed-capability inputs are literal anchors; this state oracle does not qualify identity derivation.
KEYS = ("04beceaf988446038c15a7eab10d1dd1", "f710824f3f6d40eea6d946de1329ee16")
DOMAIN = {
    "keys": list(KEYS),
    "operations": 9,
    "depth": 4,
    "histories": 6561,
    "pruning": 0,
    "pairs": 256,
    "starts": 4,
    "pair_operations": 8,
    "reads": 64,
    "serializations": 2,
}
OPERATIONS = (0, 1, 2, 3, 4, 5, 7, 8)
SCOPE = ["model", "ephemeris"]
SECOND = 1_000_000_000
CREATED = [[KEYS[0], 0, 1, 1000, [1]], [KEYS[1], 0, 1, 1000, [2]]]


def require(actual: object, expected: object, cause: str) -> None:
    """Compare canonical JSON exactly, including scalar types and nullable versus empty payloads."""
    if v.encode(actual) != v.encode(expected):
        v.reject("ephemeris-model-" + cause)


def request(operation: int) -> tuple[int, int, int, tuple]:
    """Decode only the fixed input alphabet; native receipts never define expected transitions."""
    return (
        int(operation in (4, 5)),
        1 if operation in (3, 7) else 2 if operation == 5 else 0,
        0 if operation == 8 else 2 if operation in (1, 7) else 1,
        () if operation == 4 else (2,) if operation in (1, 2) else (1,),
    )


@dataclass
class State:
    """Ordinary immutable-value registers and independent visible/source logs, without native ownership or wheels."""

    records: dict[int, tuple] = field(default_factory=dict)
    history: list[tuple[int, int, list]] = field(default_factory=list)
    exports: list[tuple[int, list, int | None]] = field(default_factory=list)
    now: int = SECOND
    position: int = 0
    cursor: int = 0

    @classmethod
    def create(cls) -> "State":
        """Anchor two independent creations in their declared order, with separate initial sequence registers."""
        state = cls()
        for index in range(len(KEYS)):
            key = index
            row = ((index + 3,), (index + 1,), 2 * SECOND, 0, 0, 1000, 1)
            state.records[key] = row
            state.export([[*SCOPE, key, "record", state.record(row)]])
            state.commit([[key, [list(row[0]), list(row[1])]]])
        return state

    @staticmethod
    def record(row: tuple) -> list:
        """Represent all native fields explicitly; empty Data is a live value, never absence."""
        return [list(row[0]), list(row[1]), *row[2:]]

    def snapshot(self) -> list:
        """Keep fixed Attr and current Data in sorted public roots independently of source positions."""
        return [self.cursor, [[key, list(row[0]), list(row[1])] for key, row in sorted(self.records.items())]]

    def source(self) -> list:
        """Expose every sequence, deadline and immutable registration field of the complete current source."""
        return [self.position, [[*SCOPE, key, self.record(row)] for key, row in sorted(self.records.items())]]

    def export(self, rows: list, visible_first: int | None = None) -> None:
        """Keep only same-tick expiry ordering unspecified and link it to the same public deletion order."""
        if rows:
            first = self.position + 1
            self.position += len(rows)
            self.exports.append((first, rows, visible_first))

    def commit(self, changes: list) -> None:
        """Visible content advances per changed key; unrelated sequence acknowledgments do not advance it."""
        if changes:
            first = self.cursor + 1
            self.cursor += len(changes)
            self.history.append((first, self.cursor, changes))

    def step(self, operation: int) -> str:
        """Apply missing-record precedence, independent orders, idempotent retries and explicit virtual expiry."""
        if operation == 6:
            self.now += SECOND // 2
            ended = [key for key, row in sorted(self.records.items()) if row[2] <= self.now]
            self.export([[*SCOPE, key, "erase", None] for key in ended], self.cursor + 1)
            for key in ended:
                del self.records[key]
            self.commit([[key, None] for key in ended])
            return "tick"
        key, kind, order, data = request(operation)
        old = self.records.get(key)
        if old is None:
            return "ended"
        if kind == 2:
            del self.records[key]
            self.export([[*SCOPE, key, "erase", None]])
            self.commit([[key, None]])
            return "ok"
        if order == 0:
            return "input"
        previous = old[4 if kind == 1 else 3]
        if order < previous:
            return "obsolete"
        if order == previous:
            return "conflict" if kind == 0 and data != old[1] else "ok"
        row = (old[0], old[1] if kind == 1 else data, max(old[2], self.now + SECOND), order if kind == 0 else old[3], order if kind == 1 else old[4], 1000, 1)
        self.records[key] = row
        self.export([[*SCOPE, key, "renew" if kind == 1 else "data", self.record(row)]])
        if kind == 0 and data != old[1]:
            self.commit([[key, [list(old[0]), list(data)]]])
        return "ok"

    def ordered(self) -> list:
        """Supply one explicit synthetic history order for reader tests, not expected native scheduling."""
        return [[position, key, value, 0, 0] for first, _, changes in self.history for position, (key, value) in enumerate(changes, first)]

    def replay(self, ordered: list) -> list:
        """Every permitted suffix uses the same complete event order; expiry is not an atomic publication."""
        return [[since, "input" if since > self.cursor else [row for row in ordered if row[0] > since]] for since in range(self.cursor + 2)]

    def log(self, replay: object) -> bool:
        """Allow permutations only inside a known expiry batch and bind all cursor suffixes to it."""
        if not isinstance(replay, list) or len(replay) != self.cursor + 2 or not isinstance(replay[0], list) or len(replay[0]) != 2:
            return False
        rows = replay[0][1]
        if not isinstance(rows, list) or len(rows) != self.cursor:
            return False
        for first, last, changes in self.history:
            actual = {}
            for position, row in enumerate(rows[first - 1 : last], first):
                if not isinstance(row, list) or len(row) != 5 or type(row[1]) is not int or row[1] in actual:
                    return False
                if v.encode([row[0], row[3], row[4]]) != v.encode([position, 0, 0]):
                    return False
                actual[row[1]] = row[2]
            if v.encode(actual) != v.encode(dict(changes)):
                return False
        return v.encode(replay) == v.encode(self.replay(rows))

    def exported(self) -> list:
        """Provide one synthetic ordering for literal control construction."""
        return [[position, *row] for first, rows, _ in self.exports for position, row in enumerate(rows, first)]

    def export_log(self, actual: object, replay: list) -> bool:
        """Check complete source fields and order, including the exact public order of authoritative expiry."""
        if not isinstance(actual, list) or len(actual) != self.position:
            return False
        visible = replay[0][1]
        for first, rows, visible_first in self.exports:
            segment = actual[first - 1 : first - 1 + len(rows)]
            supplied = {}
            for position, row in enumerate(segment, first):
                if not isinstance(row, list) or len(row) != 6 or type(row[3]) is not int or row[3] in supplied or v.encode(row[0]) != v.encode(position):
                    return False
                supplied[row[3]] = row[1:]
            if v.encode(supplied) != v.encode({row[2]: row for row in rows}):
                return False
            if visible_first is not None and [row[3] for row in segment] != [row[1] for row in visible[visible_first - 1 : visible_first - 1 + len(rows)]]:
                return False
        return True

    def verify_hits(self, frozen: list) -> int:
        """Recompute the unchanged native VERIFY traversal's successful assertions from independent state."""
        hits = 4 + 3 * len(self.records) + sum(1 + len(root[1]) for root in frozen)
        for since in range(self.cursor + 2):
            hits += 1 if since > self.cursor else 1 + self.cursor - since + sum(2 + int(since < first) for first, last, _ in self.history if last > since)
        return hits


def configuration(check: dict) -> None:
    """Pin this partial Star capability to its complete original Linux case and bounded command."""
    if (
        check.get("model") != "ephemeris-state-v1"
        or check["id"] != "ephemeris-finite-model"
        or check["component"] != "star"
        or check["adapter"] != "observed-cases"
        or check.get("platforms") != ["linux-amd64-cgo"]
        or check["argv"] != ["python3", "-B", "tools/observe.py", "ctest", "--build", "build/ephemeris-model", "--jobs", "1", "--case", "cpp_ephemeris_model"]
        or check["expected_tests"] != ["cpp_ephemeris_model"]
        or check["probes"] != [{"contract": "STAR-ASSURANCE", "minimum_hits": 1, "test": "cpp_ephemeris_model"}]
    ):
        v.reject("ephemeris-model-configuration")


def frames(data: bytes, check: dict) -> list[dict]:
    """Require all 6,561 histories and 256 pairs in one complete native CTest envelope."""
    return models.native(
        data, check, test="cpp_ephemeris_model", algorithm="ephemeris-state-v1", rows=DOMAIN["histories"] + DOMAIN["pairs"] + 2, prefix="ephemeris-model"
    )


def validate(actual: dict, state: State, frozen: list, *, operation: int | None = None, receipt: str | None = None) -> None:
    """Reconcile all public/source registers, complete logs and preserved roots without native expectations."""
    expected = {"current": state.snapshot(), "source": state.source(), "frozen": frozen}
    if operation is not None:
        expected.update(operation=operation, receipt=receipt, now=state.now)
    if not isinstance(actual, dict) or set(actual) != set(expected) | {"replay", "exports"}:
        v.reject("ephemeris-model-state-shape")
    for key, value in expected.items():
        require(actual[key], value, "state-" + key)
    if not state.log(actual["replay"]):
        v.reject("ephemeris-model-replay")
    if not state.export_log(actual["exports"], actual["replay"]):
        v.reject("ephemeris-model-exports")


def initial(prefix: int) -> State:
    """Build all four starts, retaining separate update and renewal registers and an ended principal."""
    state = State.create()
    for operation in ([], [0], [1, 7], [5])[prefix]:
        state.step(operation)
    return state


def candidate(seed: State, operations: list[int], order: tuple[int, int]) -> tuple[list, list[State]]:
    """Construct both whole-operation serializations independently of native results."""
    state, receipts, prefixes = copy.deepcopy(seed), [None, None], [copy.deepcopy(seed)]
    for index in order:
        receipts[index] = state.step(operations[index])
        prefixes.append(copy.deepcopy(state))
    return receipts, prefixes


def assessment(actual: dict, receipts: list, prefixes: list[State]) -> tuple[bool, int]:
    """Follow native short-circuit counting separately from stronger complete source-event acceptance."""
    if v.encode(actual["receipts"]) != v.encode(receipts):
        return False, 0
    final, root = prefixes[-1], actual["current"]
    if root[0] != final.cursor:
        return False, 0
    hits = len(root[1])
    if v.encode(root) != v.encode(final.snapshot()):
        return False, hits
    hits += len(actual["source"][1])
    if v.encode(actual["source"]) != v.encode(final.source()) or not final.log(actual["replay"]):
        return False, hits
    previous, allowed = prefixes[0].cursor, [state.snapshot() for state in prefixes]
    for root in actual["frozen"]:
        if root[0] < previous:
            return False, hits
        previous = root[0]
        hits += len(root[1])
        if not any(v.encode(root) == v.encode(value) for value in allowed):
            return False, hits
    return True, hits


def pair(actual: dict, ordinal: int) -> int:
    """Accept exactly one joint explanation, never borrowing captures or exports from the opposite order."""
    fields = {"ordinal", "prefix", "operations", "created", "initial", "receipts", "current", "source", "exports", "replay", "frozen"}
    if not isinstance(actual, dict) or set(actual) != fields:
        v.reject("ephemeris-model-pair-shape")
    prefix = ordinal // 64
    operations = [OPERATIONS[ordinal // 8 % 8], OPERATIONS[ordinal % 8]]
    seed = initial(prefix)
    for key, value in {"ordinal": ordinal, "prefix": prefix, "operations": operations, "created": CREATED}.items():
        require(actual[key], value, "pair-input")
    validate(actual["initial"], seed, [])
    if (
        not isinstance(actual["receipts"], list)
        or len(actual["receipts"]) != 2
        or not isinstance(actual["frozen"], list)
        or len(actual["frozen"]) != DOMAIN["reads"]
    ):
        v.reject("ephemeris-model-pair-observations")
    for root in [actual["current"]] + actual["frozen"]:
        if not isinstance(root, list) or len(root) != 2 or type(root[0]) is not int or root[0] < 0 or not isinstance(root[1], list):
            v.reject("ephemeris-model-root-shape")
    if not isinstance(actual["source"], list) or len(actual["source"]) != 2 or not isinstance(actual["source"][1], list):
        v.reject("ephemeris-model-source-shape")
    hits = 2 + (0, 1, 2, 1)[prefix] + DOMAIN["reads"] + 2
    native = accepted = None
    for order in ((0, 1), (1, 0)):
        receipts, prefixes = candidate(seed, operations, order)
        matched, count = assessment(actual, receipts, prefixes)
        if native is None:
            hits += count
        if matched:
            if native is None:
                native = prefixes[-1]
            if prefixes[-1].export_log(actual["exports"], actual["replay"]):
                accepted = prefixes[-1]
    if native is None or accepted is None:
        v.reject("ephemeris-model-joint-serialization")
    validate({key: actual[key] for key in ("current", "source", "exports", "replay")} | {"frozen": []}, accepted, [])
    require(accepted.verify_hits([]), native.verify_hits([]), "pair-native-count-equivalence")
    return hits + native.verify_hits([]) + sum(1 + len(root[1]) for root in actual["frozen"])


def observations(data: bytes, check: dict, root: Path = v.ROOT) -> dict[str, int]:
    """Reconstruct the whole original finite domain and exact successful CHECK count, with no pruning."""
    configuration(check)
    observed, failures = v.case_observations(data, check)
    if failures:
        v.reject("ephemeris-model-case-failed")
    rows = frames(data, check)
    require(rows[0], {"model": "ephemeris-state-v1", "event": "start", "value": DOMAIN}, "domain")
    hits = 4  # Distinct keys, both original domain totals, and the sole new output-health assertion.
    for ordinal in range(DOMAIN["histories"]):
        row = rows[ordinal + 1]
        if row["event"] != "history" or not isinstance(row["value"], dict) or set(row["value"]) != {"ordinal", "created", "initial", "states"}:
            v.reject("ephemeris-model-history-shape")
        require(row["value"]["ordinal"], ordinal, "ordinal")
        require(row["value"]["created"], CREATED, "created")
        states = row["value"]["states"]
        if not isinstance(states, list) or len(states) != DOMAIN["depth"]:
            v.reject("ephemeris-model-depth")
        state, frozen, remaining = State.create(), [], ordinal
        validate(row["value"]["initial"], state, [])
        hits += 2
        for actual in states:
            operation = remaining % DOMAIN["operations"]
            remaining //= DOMAIN["operations"]
            frozen.append(state.snapshot())
            receipt = state.step(operation)
            validate(actual, state, frozen, operation=operation, receipt=receipt)
            hits += int(operation != 6) + state.verify_hits(frozen)
    for ordinal, row in enumerate(rows[DOMAIN["histories"] + 1 : -1]):
        if row["event"] != "pair":
            v.reject("ephemeris-model-pair-order")
        hits += pair(row["value"], ordinal)
    require(
        rows[-1],
        {"model": "ephemeris-state-v1", "event": "finish", "value": {"histories": 6561, "transitions": 26244, "pairs": 256, "snapshots": 16384}},
        "terminal",
    )
    require(observed, {"STAR-ASSURANCE": hits}, "counter")
    return observed
