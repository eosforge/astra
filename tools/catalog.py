"""Reconstruct Catalog floors, leases, source logs and complete joint public serializations."""

from pathlib import Path
import copy
from dataclasses import dataclass, field

from tools import models
from tools import verify as v

# The existing exhaustive native domain is fixed; no sampled or pruned replacement is accepted.
DOMAIN = {
    "keys": ["a", "b"],
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
OPERATIONS = (0, 1, 2, 3, 4, 5, 6, 8)
SCOPE = ["model", "catalog"]
SECOND = 1_000_000_000


def require(actual: object, expected: object, cause: str) -> None:
    """Compare exact JSON bytes so bool/float identities, extra fields and absent values cannot pass."""
    if v.encode(actual) != v.encode(expected):
        v.reject("catalog-model-" + cause)


def request(operation: int) -> tuple[list, int, bool]:
    """Translate the declared alphabet independently of the native fixture's input helper."""
    entries = (
        [["a", (2,)], ["b", (2,)]]
        if operation in (3, 5)
        else (
            [["a", (1,)], ["a", (1,)]]
            if operation == 8
            else [["b" if operation == 2 else "a", () if operation == 2 else (2,) if operation in (1, 6) else (1,)]]
        )
    )
    return entries, 2 if operation in (1, 3, 5) else 1, operation in (4, 5)


@dataclass
class State:
    """Plain value/floor registers and separate chronological source/visible logs; no native tree helpers."""

    records: dict[str, tuple[int, tuple[int, ...] | None, int | None]] = field(default_factory=dict)
    history: list[tuple[int, int, list, bool]] = field(default_factory=list)
    exports: list = field(default_factory=list)
    now: int = SECOND
    position: int = 0
    cursor: int = 0

    def snapshot(self) -> list:
        """Keep empty payloads visible while excluding expired floors from the public view."""
        return [self.cursor, [[key, version, list(body)] for key, (version, body, _) in sorted(self.records.items()) if body is not None]]

    def source(self) -> list:
        """Retain complete version floors and nullable deadlines, even when no public body survives."""
        return [
            self.position,
            [[*SCOPE, key, version, None if body is None else list(body), deadline] for key, (version, body, deadline) in sorted(self.records.items())],
        ]

    def commit(self, changes: list, atomic: bool = True) -> None:
        """Count visible keys separately from exported facts and retain each atomic recovery boundary."""
        if changes:
            first = self.cursor + 1
            self.cursor += len(changes)
            self.history.append((first, self.cursor, changes, atomic))

    def step(self, operation: int) -> str:
        """Validate a whole request before committing; local expiry preserves floors without exporting it."""
        if operation == 7:
            self.now += SECOND
            changes = []
            for key, (version, body, deadline) in sorted(self.records.items()):
                if deadline is not None and deadline <= self.now:
                    self.records[key] = version, None, None
                    changes.append([key, None])
            self.commit(changes, False)
            return "tick"
        if operation == 8:
            return "input"
        entries, version, renewal = request(operation)
        for key, body in entries:
            old = self.records.get(key)
            if renewal:
                if old is not None and old[0] != version:
                    return "version"
                if old is None or old[1] is None:
                    return "ended"
            elif old is not None:
                if version < old[0]:
                    return "version"
                if version == old[0] and old[1] is not None and old[1] != body:
                    return "conflict"
        changes = []
        for key, body in entries:
            old = self.records.get(key, (0, None, None))
            if not renewal and (old[1] is None or old[0] != version or old[1] != body):
                changes.append([key, [version, list(body)]])
            deadline = self.now + (2 if renewal else 1) * SECOND
            if old[0] == version and old[2] is not None:
                deadline = max(old[2], deadline)
            body = old[1] if renewal else body
            self.records[key] = version, body, deadline
            self.position += 1
            self.exports.append([self.position, *SCOPE, key, "renew" if renewal else "record", [version, list(body), deadline]])
        self.commit(changes)
        return "ok"

    def ordered(self) -> list:
        """Provide one synthetic order for fixture tests; real native ordering is separately validated."""
        return [
            [position, key, value, first if atomic else 0, last if atomic else 0]
            for first, last, changes, atomic in self.history
            for position, (key, value) in enumerate(changes, first)
        ]

    def replay(self, ordered: list) -> list:
        """Use one validated complete key order consistently for every permitted cursor suffix."""
        return [
            [
                since,
                (
                    "input"
                    if since > self.cursor
                    else (
                        "history"
                        if any(atomic and first <= since < last for first, last, _, atomic in self.history)
                        else [row for row in ordered if row[0] > since]
                    )
                ),
            ]
            for since in range(self.cursor + 2)
        ]

    def log(self, replay: object) -> bool:
        """Allow only unspecified ordering within a known batch; never borrow a suffix from another order."""
        if not isinstance(replay, list) or len(replay) != self.cursor + 2 or not isinstance(replay[0], list) or len(replay[0]) != 2:
            return False
        rows = replay[0][1]
        if not isinstance(rows, list) or len(rows) != self.cursor:
            return False
        for first, last, changes, atomic in self.history:
            segment = rows[first - 1 : last]
            expected = {key: value for key, value in changes}
            actual = {}
            for position, row in enumerate(segment, first):
                if not isinstance(row, list) or len(row) != 5 or type(row[1]) is not str or row[1] in actual:
                    return False
                if v.encode([row[0], row[3], row[4]]) != v.encode([position, first if atomic else 0, last if atomic else 0]):
                    return False
                actual[row[1]] = row[2]
            if v.encode(actual) != v.encode(expected):
                return False
        return v.encode(replay) == v.encode(self.replay(rows))

    def verify_hits(self, frozen: list) -> int:
        """Count the original successful native assertions, including each source row and cursor batch."""
        hits = 4 + len(self.snapshot()[1]) + 2 * len(self.records) + sum(1 + len(root[1]) for root in frozen)
        for since in range(self.cursor + 2):
            if since > self.cursor or any(atomic and first <= since < last for first, last, _, atomic in self.history):
                hits += 1
            else:
                hits += 2 + self.cursor - since + sum(2 + int(since < first) for first, last, _, _ in self.history if last > since)
        return hits


def configuration(check: dict) -> None:
    """Pin this partial Star model to its original complete Linux case and exact bounded command."""
    if (
        check.get("model") != "catalog-state-v1"
        or check["id"] != "catalog-finite-model"
        or check["component"] != "star"
        or check["adapter"] != "observed-cases"
        or check.get("platforms") != ["linux-amd64-cgo"]
        or check["argv"] != ["python3", "-B", "tools/observe.py", "ctest", "--build", "build/catalog-model", "--jobs", "1", "--case", "cpp_catalog_model"]
        or check["expected_tests"] != ["cpp_catalog_model"]
        or check["probes"] != [{"contract": "STAR-ASSURANCE", "minimum_hits": 1, "test": "cpp_catalog_model"}]
    ):
        v.reject("catalog-model-configuration")


def frames(data: bytes, check: dict) -> list[dict]:
    """Require every sequential/pair frame from the single original CTest case."""
    return models.native(
        data, check, test="cpp_catalog_model", algorithm="catalog-state-v1", rows=DOMAIN["histories"] + DOMAIN["pairs"] + 2, prefix="catalog-model"
    )


def validate(actual: dict, state: State, frozen: list, *, operation: int | None = None, receipt: str | None = None) -> None:
    """Reconcile complete public/source/frozen observations and every exact cursor, without native expectations."""
    expected = {"current": state.snapshot(), "source": state.source(), "exports": state.exports, "frozen": frozen}
    if operation is not None:
        expected.update(operation=operation, receipt=receipt, now=state.now)
    if not isinstance(actual, dict) or set(actual) != set(expected) | {"replay"}:
        v.reject("catalog-model-state-shape")
    for key, value in expected.items():
        require(actual[key], value, "state-" + key)
    if not state.log(actual["replay"]):
        v.reject("catalog-model-replay")


def initial(prefix: int) -> State:
    """Build all four declared starts, including the expired two-key floor state."""
    state = State()
    for operation in ([], [0], [3], [3, 7])[prefix]:
        state.step(operation)
    return state


def candidate(seed: State, operations: list[int], order: tuple[int, int]) -> tuple[list, list[State]]:
    """Enumerate both whole-operation orders independently; emitted outcomes do not define transitions."""
    state, receipts, prefixes = copy.deepcopy(seed), [None, None], [copy.deepcopy(seed)]
    for index in order:
        receipts[index] = state.step(operations[index])
        prefixes.append(copy.deepcopy(state))
    return receipts, prefixes


def assessment(actual: dict, receipts: list, prefixes: list[State]) -> tuple[bool, int]:
    """Reconstruct native short-circuit counts while checking the same complete candidate for all readers."""
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
    """Reject joint-history mixtures even when both writer orders have identical final visible payloads."""
    fields = {"ordinal", "prefix", "operations", "initial", "receipts", "current", "source", "exports", "replay", "frozen"}
    if not isinstance(actual, dict) or set(actual) != fields:
        v.reject("catalog-model-pair-shape")
    prefix = ordinal // 64
    operations = [OPERATIONS[ordinal // 8 % 8], OPERATIONS[ordinal % 8]]
    seed = initial(prefix)
    for field, value in {"ordinal": ordinal, "prefix": prefix, "operations": operations}.items():
        require(actual[field], value, "pair-input")
    validate(actual["initial"], seed, [])
    if (
        not isinstance(actual["receipts"], list)
        or len(actual["receipts"]) != 2
        or not isinstance(actual["frozen"], list)
        or len(actual["frozen"]) != DOMAIN["reads"]
    ):
        v.reject("catalog-model-pair-observations")
    for root in [actual["current"]] + actual["frozen"]:
        if not isinstance(root, list) or len(root) != 2 or type(root[0]) is not int or root[0] < 0 or not isinstance(root[1], list):
            v.reject("catalog-model-root-shape")
    if not isinstance(actual["source"], list) or len(actual["source"]) != 2 or not isinstance(actual["source"][1], list):
        v.reject("catalog-model-source-shape")
    hits = (0, 1, 1, 1)[prefix] + DOMAIN["reads"] + 2
    native = None
    accepted = None
    for order in ((0, 1), (1, 0)):
        receipts, prefixes = candidate(seed, operations, order)
        matched, count = assessment(actual, receipts, prefixes)
        # The unchanged native CHECK traversal selects by public/source state and replay. Its counter
        # can choose the first order even when only the other order explains the stronger exported log.
        if native is None:
            hits += count
        if matched:
            if native is None:
                native = prefixes[-1]
            if v.encode(actual["exports"]) == v.encode(prefixes[-1].exports):
                accepted = prefixes[-1]
    if native is None or accepted is None:
        v.reject("catalog-model-joint-serialization")
    fields = {key: actual[key] for key in ("current", "source", "exports", "replay")}
    validate(dict(fields, frozen=[]), accepted, [])
    require(accepted.verify_hits([]), native.verify_hits([]), "pair-native-count-equivalence")
    return hits + native.verify_hits([]) + sum(1 + len(root[1]) for root in actual["frozen"])


def observations(data: bytes, check: dict, root: Path = v.ROOT) -> dict[str, int]:
    """Qualify complete original traces and their exact CHECK count; the whole Star remains separate."""
    configuration(check)
    observed, failures = v.case_observations(data, check)
    if failures:
        v.reject("catalog-model-case-failed")
    rows = frames(data, check)
    require(rows[0], {"model": "catalog-state-v1", "event": "start", "value": DOMAIN}, "domain")
    hits = 3  # Original sequential/pair totals and the sole new output-health assertion.
    for ordinal in range(DOMAIN["histories"]):
        row = rows[ordinal + 1]
        if row["event"] != "history" or not isinstance(row["value"], dict) or set(row["value"]) != {"ordinal", "states"}:
            v.reject("catalog-model-history-shape")
        require(row["value"]["ordinal"], ordinal, "ordinal")
        states = row["value"]["states"]
        if not isinstance(states, list) or len(states) != DOMAIN["depth"]:
            v.reject("catalog-model-depth")
        state, frozen, remaining = State(), [], ordinal
        for actual in states:
            operation = remaining % DOMAIN["operations"]
            remaining //= DOMAIN["operations"]
            frozen.append(state.snapshot())
            receipt = state.step(operation)
            validate(actual, state, frozen, operation=operation, receipt=receipt)
            hits += int(operation != 7) + state.verify_hits(frozen)
    for ordinal, row in enumerate(rows[DOMAIN["histories"] + 1 : -1]):
        if row["event"] != "pair":
            v.reject("catalog-model-pair-order")
        hits += pair(row["value"], ordinal)
    require(
        rows[-1],
        {"model": "catalog-state-v1", "event": "finish", "value": {"histories": 6561, "transitions": 26244, "pairs": 256, "snapshots": 16384}},
        "terminal",
    )
    require(observed, {"STAR-ASSURANCE": hits}, "counter")
    return observed
