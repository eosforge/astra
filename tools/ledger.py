"""Reconstruct bounded durable registration from complete native public values."""

from pathlib import Path
from dataclasses import dataclass, field

from tools import models
from tools import verify as v

# The full alphabet and capacities are fixed before execution; no receipt or history is pruned.
DOMAIN = {"principals": [1, 2], "capacities": [1, 2], "starts": 2, "operations": 7, "depth": 3, "histories": 686, "pruning": 0}


def member(principal: int, identifier: str, epoch: int) -> list:
    """Encode all Member fields from literal fixture axioms, without using a production codec."""
    return ["alpha", identifier, f"{principal + 1:02x}" + "00" * 31, ["127.0.0.1", 7401 + principal, False, False], epoch, "star", "default"]


@dataclass
class State:
    """Ordinary identity/request registers and immutable value copies, independent of SQLite and atomic roots."""

    capacity: int
    members: dict[int, tuple[str, int]] = field(default_factory=dict)
    requests: dict[str, tuple[int, int]] = field(default_factory=dict)
    first: list[str | None] = field(default_factory=lambda: [None, None])
    credentials: list[list] = field(default_factory=list)
    frozen: list[list] = field(default_factory=list)

    def directory(self) -> list:
        """Return every current member under its complete canonical principal key."""
        return [[value[2], value] for principal, entry in sorted(self.members.items()) for value in [member(principal, *entry)]]

    def projection(self, operation: int, outcome: str, callback: list | None = None) -> dict:
        """Reconstruct all public credential checks, fixed-principal queries and retained directory roots."""
        view = self.directory()
        credentials = []
        for value in self.credentials:
            current = any(row[1] == value for row in view)
            credentials.append([value, current, view if current else None])
        queries = [
            [member(principal, *self.members.get(principal, ("unregistered", 1))), view if principal in self.members else None] for principal in range(2)
        ]
        return {
            "operation": operation,
            "outcome": outcome,
            "prepared": callback is not None,
            "threw": outcome == "throw",
            "prepare": callback,
            "credentials": credentials,
            "queries": queries,
            "frozen": self.frozen[:],
        }

    def checks(self) -> int:
        """Count only the unchanged native validity, full-directory and preserved-root assertions."""
        return sum(2 + int(any(row[1] == value for row in self.directory())) for value in self.credentials) + 2 + len(self.members) + len(self.frozen)

    def step(self, operation: int, depth: int) -> tuple[dict, int]:
        """Apply one registration/receipt/rollback/reopen input using the declared independent registers."""
        if operation == 6:
            return self.projection(operation, "reopen"), self.checks()
        principal = int(operation in (1, 3))
        retry = operation in (2, 3)
        request = self.first[principal] or "" if retry else chr(ord("a") + depth * 2 + principal) * (31 if operation == 4 else 32)
        previous = self.members.get(principal)
        accepted, expected = False, ("attempt-" + str(depth), 1 if previous is None else previous[1] + 1)
        outcome = "configuration" if len(request) != 32 else "capacity"
        if retry and request:
            accepted = previous is not None and previous[1] == self.requests[request][1]
            expected = previous
            outcome = "conflict"
        elif not retry and operation != 4:
            accepted = len(self.requests) < DOMAIN["starts"] and (previous is not None or len(self.members) < self.capacity)
        callback = None
        if accepted:
            pending = self.members.copy()
            pending[principal] = expected
            intended = [[value[2], value] for key, entry in sorted(pending.items()) for value in [member(key, *entry)]]
            callback = [member(principal, *expected), intended]
            outcome = "throw" if operation == 5 else "ok"
            if outcome == "ok":
                self.members[principal] = expected
                if not retry:
                    self.requests[request] = (principal, expected[1])
                    if self.first[principal] is None:
                        self.first[principal] = request
                self.credentials.append(member(principal, *expected))
                self.frozen.append(self.directory())
        checks = 2 + int(outcome != "throw") + int(accepted) + int(outcome == "ok") + self.checks()
        return self.projection(operation, outcome, callback), checks


def configuration(check: dict) -> None:
    """Bind this capability to the sole native Ledger case, exact platform, alphabet and runner."""
    if (
        check.get("model") != "ledger-state-v1"
        or check["id"] != "pulsar-finite-model"
        or check["component"] != "pulsar"
        or check["adapter"] != "observed-cases"
        or check.get("platforms") != ["linux-amd64-cgo"]
        or check["argv"] != ["python3", "-B", "tools/observe.py", "ctest", "--build", "build/ledger-model", "--jobs", "1", "--case", "cpp_pulsar_model"]
        or check["expected_tests"] != ["cpp_pulsar_model"]
        or check["probes"] != [{"contract": "PULSAR-ASSURANCE", "minimum_hits": 1, "test": "cpp_pulsar_model"}]
    ):
        v.reject("ledger-model-configuration")


def require(actual: object, expected: object, cause: str) -> None:
    """Compare canonical JSON bytes; booleans, floats, omitted fields and reordered roots are not equivalent."""
    if v.encode(actual) != v.encode(expected):
        v.reject("ledger-model-" + cause)


def frames(data: bytes, check: dict) -> list[dict]:
    """Require exactly one bound CTest case and every original complete model frame."""
    return models.native(data, check, test="cpp_pulsar_model", algorithm="ledger-state-v1", rows=DOMAIN["histories"] + 2, prefix="ledger-model")


def observations(data: bytes, check: dict, root: Path = v.ROOT) -> dict[str, int]:
    """Reconstruct every native result and reopen before qualifying this one sequential finite coordinate."""
    configuration(check)
    observed, failures = v.case_observations(data, check)
    if failures:
        v.reject("ledger-model-case-failed")
    rows = frames(data, check)
    require(rows[0], {"model": "ledger-state-v1", "event": "start", "value": DOMAIN}, "domain")
    hits = 1  # The sole new native output-health assertion.
    for ordinal, row in enumerate(rows[1:-1]):
        state = State(1 + ordinal // 343)
        remaining, states = ordinal % 343, []
        for depth in range(DOMAIN["depth"]):
            projection, count = state.step(remaining % DOMAIN["operations"], depth)
            remaining //= DOMAIN["operations"]
            states.append(projection)
            hits += count
        reopened, count = state.step(6, DOMAIN["depth"])
        hits += count
        require(
            row,
            {"model": "ledger-state-v1", "event": "history", "value": {"ordinal": ordinal, "capacity": state.capacity, "states": states, "reopened": reopened}},
            "state",
        )
    require(rows[-1], {"model": "ledger-state-v1", "event": "finish", "value": {"histories": 686, "transitions": 2058, "reopens": 686}}, "terminal")
    require(observed, {"PULSAR-ASSURANCE": hits}, "counter")
    return observed
