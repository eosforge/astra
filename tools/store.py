"""Reconstruct every public Store state in its unpruned four-step finite domain."""

from pathlib import Path
from dataclasses import dataclass, field

from tools import models
from tools import verify as v

# The domain is fixed before native execution; empty bytes and absent records are distinct.
DOMAIN = {
    "keys": ["a", "b"],
    "operations": 8,
    "depth": 4,
    "histories": 4096,
    "capacity": 2,
    "initial_ns": 1000000000,
    "tick_ns": 1000000,
    "retention": "maximum",
    "pruning": 0,
}


@dataclass
class State:
    """Independent map and ordered batch log; no index, wheel or production helper is shared."""

    values: dict[str, tuple[tuple[int, ...], int | None]] = field(default_factory=dict)
    version: int = 0
    floor: int = 0
    now: int = DOMAIN["initial_ns"]
    history: list[list] = field(default_factory=list)

    def apply(self, operation: int) -> None:
        """Apply one declared input using only assignment, deletion and deadline comparison."""
        changes = []
        if operation in (3, 4):
            key = "a" if operation == 3 else "b"
            if key in self.values:
                del self.values[key]
                changes.append([0, key, None, None, True])
        elif operation in (5, 7):
            if operation == 5:
                self.now += DOMAIN["tick_ns"]
            for key, (_, deadline) in sorted(self.values.items()):
                if deadline is not None and deadline <= self.now:
                    del self.values[key]
                    changes.append([0, key, None, None, True])
        else:
            key = "a" if operation < 2 else "b"
            payload = () if operation == 2 else (operation + 1,)
            deadline = self.now + DOMAIN["tick_ns"] if operation in (1, 6) else None
            self.values[key] = (payload, deadline)
            changes.append([0, key, list(payload), deadline, False])
        if changes:
            self.version += 1
            for change in changes:
                change[0] = self.version
            self.history.append(changes)
            if len(self.history) > DOMAIN["capacity"]:
                self.floor = self.history.pop(0)[0][0]

    def snapshot(self) -> list:
        """Return complete ordered public values, preserving version, empty payload and absolute deadline."""
        return [self.version, [[key, list(payload), deadline] for key, (payload, deadline) in sorted(self.values.items())]]

    def replay(self) -> list:
        """Materialize every legal, stale and future cursor through complete retained batches."""
        return [
            [
                since,
                since < self.floor or since > self.version,
                self.version,
                [] if since < self.floor or since > self.version else [change[:] for batch in self.history if batch[0][0] > since for change in batch],
            ]
            for since in range(self.version + 2)
        ]


def configuration(check: dict) -> None:
    """Bind the importer to the sole native Store case, platform, input domain and existing observation runner."""
    if (
        check.get("model") != "store-state-v1"
        or check["id"] != "common-finite-model"
        or check["component"] != "common"
        or check["adapter"] != "observed-cases"
        or check.get("platforms") != ["linux-amd64-cgo"]
        or check["argv"] != ["python3", "-B", "tools/observe.py", "ctest", "--build", "build/store-model", "--jobs", "1", "--case", "cpp_store_model"]
        or check["expected_tests"] != ["cpp_store_model"]
        or check["probes"] != [{"contract": "COMMON-ASSURANCE", "minimum_hits": 1, "test": "cpp_store_model"}]
    ):
        v.reject("store-model-configuration")


def require(actual: object, expected: object, cause: str) -> None:
    """Compare canonical JSON bytes, preventing booleans or floats from impersonating integers."""
    if v.encode(actual) != v.encode(expected):
        v.reject("store-model-" + cause)


def frames(data: bytes, check: dict) -> list[dict]:
    """Read only original CTest XML, rejecting foreign case attribution, partial lines and incomplete domains."""
    return models.native(data, check, test="cpp_store_model", algorithm="store-state-v1", rows=DOMAIN["histories"] + 2, prefix="store-model")


def transition(state: State, frozen: list, operation: int) -> tuple[dict, int]:
    """Construct one expected public transition and its original successful CHECK count."""
    frozen.append(state.snapshot())
    state.apply(operation)
    snapshot = state.snapshot()
    checks = 2 + len(snapshot[1]) + sum(1 + len(view[1]) for view in frozen) + 2 * (state.version + 2)
    return {"operation": operation, "version": state.version, "current": snapshot, "frozen": frozen[:], "replay": state.replay()}, checks


def replay(rows: list[dict]) -> int:
    """Reconstruct the complete native history domain without relying on a containing check's counters."""
    if len(rows) != DOMAIN["histories"] + 2:
        v.reject("store-model-domain-incomplete")
    require(rows[0], {"model": "store-state-v1", "event": "start", "value": DOMAIN}, "domain")
    hits = 1  # Native output-health assertion; model transitions retain their existing CHECK calls.
    for ordinal, row in enumerate(rows[1:-1]):
        state, frozen, states = State(), [], []
        remaining = ordinal
        for _ in range(DOMAIN["depth"]):
            value, count = transition(state, frozen, remaining % DOMAIN["operations"])
            remaining //= DOMAIN["operations"]
            states.append(value)
            hits += count
        require(row, {"model": "store-state-v1", "event": "history", "value": {"ordinal": ordinal, "states": states}}, "state")
    require(rows[-1], {"model": "store-state-v1", "event": "finish", "value": {"histories": 4096, "transitions": 16384}}, "terminal")
    return hits


def observations(data: bytes, check: dict, root: Path = v.ROOT) -> dict[str, int]:
    """Validate every actual state and original counter before qualifying the one finite-domain capability."""
    configuration(check)
    observed, failures = v.case_observations(data, check)
    if failures:
        v.reject("store-model-case-failed")
    hits = replay(frames(data, check))
    require(observed, {"COMMON-ASSURANCE": hits}, "counter")
    return observed
