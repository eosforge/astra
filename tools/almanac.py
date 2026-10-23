"""Reconstruct complete Almanac authority histories and joint public writer serializations."""

from pathlib import Path
import copy
from dataclasses import dataclass, field

from tools import models
from tools import verify as v

# Freeze the complete existing native domain rather than filtering a representative subset.
DOMAIN = {
    "keys": ["a", "b", "c"],
    "operations": 9,
    "depth": 4,
    "histories": 6561,
    "capacity": 2,
    "pruning": 0,
    "pairs": 256,
    "starts": 4,
    "pair_operations": 8,
    "reads": 64,
    "serializations": 2,
}


@dataclass
class State:
    """Plain immutable payload registers and authority log, independent of native COW pages and locks."""

    values: dict[str, tuple[int, ...]] = field(default_factory=dict)
    version: int = 0
    baseline: int = 0
    history: list[tuple[int, str, tuple[int, ...] | None]] = field(default_factory=list)

    def snapshot(self) -> list:
        """Keep version, logical accounting and complete sorted values, distinguishing empty from absent."""
        return [
            self.version,
            len(self.values),
            sum(len(key) + len(value) for key, value in self.values.items()),
            [[key, list(value)] for key, value in sorted(self.values.items())],
        ]

    def replay(self) -> list:
        """Read every stale, valid and future cursor through complete authority versions."""
        return [
            [
                since,
                (
                    "version"
                    if since > self.version
                    else (
                        "history"
                        if since < self.baseline
                        else [
                            self.version,
                            [
                                [version, key, None if value is None else list(value)]
                                for version, key, value in sorted(self.history, key=lambda row: (row[0], row[1]))
                                if version > since
                            ],
                        ]
                    )
                ),
            ]
            for since in range(self.version + 2)
        ]

    def apply(self, version: int, changes: list[tuple[str, tuple[int, ...] | None]], *, reset: bool = False) -> bool | str:
        """Validate authority and capacity before installing any candidate or consuming its version."""
        if (not reset and version == 0) or (reset and version < self.version):
            return "version"
        if version <= self.version:
            return False
        if not reset and version != self.version + 1:
            return "version"
        candidate = {} if reset else self.values.copy()
        for key, value in changes:
            if value is None:
                candidate.pop(key, None)
            else:
                candidate[key] = value
        if len(candidate) > DOMAIN["capacity"]:
            return "capacity"
        self.values, self.version = candidate, version
        if reset:
            self.baseline, self.history = version, []
        else:
            self.history.extend((version, key, value) for key, value in changes)
        return True

    def step(self, operation: int) -> bool | str:
        """Apply the declared sequential alphabet, including duplicate/gap rejection and stale retry."""
        if operation == 4:
            return "input"
        if operation == 5:
            return "version"
        if operation == 6:
            return False if self.version else "version"
        if operation == 7:
            return self.apply(self.version + 3, [("a", (9,))], reset=True)
        changes = (
            [("a", (2,)), ("b", None)]
            if operation == 3
            else [("c" if operation == 8 else "b" if operation == 1 else "a", None if operation == 2 else () if operation == 1 else (1,))]
        )
        return self.apply(self.version + 1, changes)

    def verify_hits(self, frozen: list) -> int:
        """Reconstruct the unchanged successful native CHECK calls, including each old root and cursor."""
        return 2 + len(self.values) + sum(1 + len(root[3]) for root in frozen) + self.version + 2 + self.version - self.baseline + 1


def require(actual: object, expected: object, cause: str) -> None:
    """Compare canonical JSON bytes; bool/float ordinals, unknown fields and partial roots cannot pass."""
    if v.encode(actual) != v.encode(expected):
        v.reject("almanac-model-" + cause)


def configuration(check: dict) -> None:
    """Bind this partial Star capability to its complete Linux native case and exact observation runner."""
    if (
        check.get("model") != "almanac-state-v1"
        or check["id"] != "almanac-finite-model"
        or check["component"] != "star"
        or check["adapter"] != "observed-cases"
        or check.get("platforms") != ["linux-amd64-cgo"]
        or check["argv"] != ["python3", "-B", "tools/observe.py", "ctest", "--build", "build/almanac-model", "--jobs", "1", "--case", "cpp_almanac_model"]
        or check["expected_tests"] != ["cpp_almanac_model"]
        or check["probes"] != [{"contract": "STAR-ASSURANCE", "minimum_hits": 1, "test": "cpp_almanac_model"}]
    ):
        v.reject("almanac-model-configuration")


def frames(data: bytes, check: dict) -> list[dict]:
    """Require all sequential and pair frames from the one original bounded CTest case."""
    return models.native(
        data, check, test="cpp_almanac_model", algorithm="almanac-state-v1", rows=DOMAIN["histories"] + DOMAIN["pairs"] + 2, prefix="almanac-model"
    )


def transition(state: State, frozen: list, operation: int) -> tuple[dict, int]:
    """Construct one expected complete transition from independent input and retained public roots."""
    frozen.append(state.snapshot())
    receipt = state.step(operation)
    return {"operation": operation, "receipt": receipt, "current": state.snapshot(), "frozen": copy.deepcopy(frozen), "replay": state.replay()}, 1 + int(
        operation == 7
    ) + state.verify_hits(frozen)


def initial(prefix: int) -> State:
    """Reconstruct all four predefined pair starts, retaining the reset's real baseline."""
    state = State()
    for operation in ([], [0], [3], [3, 7])[prefix]:
        state.step(operation)
    return state


def request(operation: int, version: int) -> tuple[int, list[tuple[str, tuple[int, ...] | None]], bool]:
    """Fix each writer's requested authority before executing either serialization."""
    return (
        (version + 1, [("a", (1,))], False),
        (version + 1, [("b", ())], False),
        (version + 1, [("a", (2,)), ("b", (2,))], False),
        (version + 1, [("a", None), ("b", None)], False),
        (version + 2, [("a", (9,)), ("b", (9,))], True),
        (version + 2, [("a", (3,))], False),
        (version, [("a", (99,))], False),
        (version + 1, [("c", (1,))], False),
    )[operation]


def candidate(seed: State, operations: list[int], order: tuple[int, int]) -> tuple[list, list[State]]:
    """Replay one legal writer order; no production state or emitted winner selects its transitions."""
    state, receipts, prefixes = copy.deepcopy(seed), [None, None], [copy.deepcopy(seed)]
    for index in order:
        version, changes, reset = request(operations[index], seed.version)
        receipts[index] = state.apply(version, changes, reset=reset)
        prefixes.append(copy.deepcopy(state))
    return receipts, prefixes


def assessment(actual: dict, receipts: list, prefixes: list[State]) -> tuple[bool, int]:
    """Mirror only native short-circuit CHECK counts while proving complete joint public serialization."""
    if v.encode(actual["receipts"]) != v.encode(receipts):
        return False, 0
    final = prefixes[-1]
    current = actual["current"]
    if current[0] != final.version:
        return False, 0
    hits = len(current[3])
    if v.encode(current[3]) != v.encode(final.snapshot()[3]) or v.encode(actual["replay"][:-1]) != v.encode(final.replay()[:-1]):
        return False, hits
    previous = prefixes[0].version
    allowed = [state.snapshot() for state in prefixes]
    for root in actual["frozen"]:
        if root[0] < previous:
            return False, hits
        previous = root[0]
        hits += len(root[3])
        if not any(v.encode(root) == v.encode(value) for value in allowed):
            return False, hits
    return True, hits


def pair(actual: dict, ordinal: int) -> int:
    """Reject mixed opposite-order prefixes even when final maps or acknowledgment values coincide."""
    fields = {"ordinal", "prefix", "operations", "initial", "receipts", "current", "replay", "frozen"}
    if not isinstance(actual, dict) or set(actual) != fields:
        v.reject("almanac-model-pair-shape")
    prefix, left, right = ordinal // 64, ordinal // 8 % 8, ordinal % 8
    operations = [left, right]
    seed = initial(prefix)
    for field, value in {"ordinal": ordinal, "prefix": prefix, "operations": operations, "initial": [seed.snapshot(), seed.replay()]}.items():
        require(actual[field], value, "pair-input")
    if (
        not isinstance(actual["receipts"], list)
        or len(actual["receipts"]) != 2
        or not isinstance(actual["frozen"], list)
        or len(actual["frozen"]) != DOMAIN["reads"]
    ):
        v.reject("almanac-model-pair-observations")
    for root in [actual["current"]] + actual["frozen"]:
        if not isinstance(root, list) or len(root) != 4 or any(type(item) is not int or item < 0 for item in root[:3]) or not isinstance(root[3], list):
            v.reject("almanac-model-root-shape")
    if not isinstance(actual["replay"], list):
        v.reject("almanac-model-replay-shape")
    hits = 1 + (0, 1, 1, 3)[prefix] + 4 * operations.count(4) + DOMAIN["reads"] + 2
    for order in ((0, 1), (1, 0)):
        receipts, prefixes = candidate(seed, operations, order)
        matched, count = assessment(actual, receipts, prefixes)
        hits += count
        if matched:
            final = prefixes[-1]
            require(actual["current"], final.snapshot(), "pair-state")
            require(actual["replay"], final.replay(), "pair-replay")
            return hits + final.verify_hits([]) + sum(len(root[3]) + 2 for root in actual["frozen"])
    v.reject("almanac-model-joint-serialization")


def observations(data: bytes, check: dict, root: Path = v.ROOT) -> dict[str, int]:
    """Validate all native histories and sampled roots before accepting the unchanged assertion counter."""
    configuration(check)
    observed, failures = v.case_observations(data, check)
    if failures:
        v.reject("almanac-model-case-failed")
    rows = frames(data, check)
    require(rows[0], {"model": "almanac-state-v1", "event": "start", "value": DOMAIN}, "domain")
    hits = 2  # Native pair-domain total and the sole new output-health CHECK.
    for ordinal in range(DOMAIN["histories"]):
        state, frozen, states, remaining = State(), [], [], ordinal
        hits += 1  # Original empty-baseline installation assertion.
        for _ in range(DOMAIN["depth"]):
            value, count = transition(state, frozen, remaining % DOMAIN["operations"])
            remaining //= DOMAIN["operations"]
            states.append(value)
            hits += count
        require(rows[ordinal + 1], {"model": "almanac-state-v1", "event": "history", "value": {"ordinal": ordinal, "states": states}}, "state")
    for ordinal, row in enumerate(rows[DOMAIN["histories"] + 1 : -1]):
        if row["event"] != "pair":
            v.reject("almanac-model-pair-order")
        hits += pair(row["value"], ordinal)
    require(
        rows[-1],
        {"model": "almanac-state-v1", "event": "finish", "value": {"histories": 6561, "transitions": 26244, "pairs": 256, "snapshots": 16384}},
        "terminal",
    )
    require(observed, {"STAR-ASSURANCE": hits}, "counter")
    return observed
