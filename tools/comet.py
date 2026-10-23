"""Independently reconstruct bounded SDK Core ownership, quota and weak-directory observations."""

from pathlib import Path
import copy
from dataclasses import dataclass, field

from tools import models
from tools import verify as v

# Fixed before execution: this is Core bookkeeping only, not the complete SDK/RPC/reader/writer model.
DOMAIN = {
    "limits": [[1, 2], [2, 1]],
    "operations": 9,
    "depth": 4,
    "histories": 13122,
    "pruning": 0,
    "controls": 4,
    "prefixes": [[], [0], [1], [0, 2], [1, 2], [0, 3]],
    "pairs": 48,
    "reads": 64,
    "serializations": 2,
}


@dataclass
class State:
    """Plain application intents and ordered identities; no native allocator, lock or directory helper is reused."""

    limits: list[int]
    items: dict[int, list[bool]] = field(default_factory=dict)
    directory: list[int] = field(default_factory=list)
    queue: list[int] = field(default_factory=list)
    owners: int = 1
    closing: bool = False
    owned: bool = True

    def snapshot(self, *, intents: bool = True) -> dict:
        """Expose complete accounting and ordered weak identities, retaining expired slots as zero."""
        result = {
            "core": [
                self.owners,
                self.closing,
                self.closing,
                [key if key in self.items else 0 for key in self.directory],
                [key if key in self.items else 0 for key in self.queue],
            ]
        }
        if intents:
            result["items"] = [[key, *value[:4]] for key, value in sorted(self.items.items())]
        return result

    def release(self) -> None:
        """Return one actual owner; zero permanently closes admission without pretending RPC drain completed."""
        self.owners -= 1
        if not self.owners:
            self.closing = True

    def prepare(self, key: int, streaming: bool) -> None:
        """Input preparation creates no admitted owner, queue slot or Core-side resource."""
        self.items[key] = [streaming, False, False, False, False]

    def accept(self, key: int) -> str:
        """Classify admission using independent active/retained sets after legitimate retired-object maintenance."""
        if self.closing:
            return "closed"
        retired = {identity for identity in self.directory + self.queue if identity not in self.items or self.items[identity][3]}
        for identity in retired & self.items.keys():
            self.items[identity][4] = False
        self.directory = [identity for identity in self.directory if identity not in retired]
        self.queue = [identity for identity in self.queue if identity not in retired]
        streaming = self.items[key][0]
        retained = [identity for identity in self.directory if self.items[identity][0] == streaming]
        active = [identity for identity in retained if not self.items[identity][2]]
        limit = self.limits[0 if streaming else 1]
        if len(active) >= limit or len(retained) >= 2 * limit:
            return "busy"
        self.items[key][1] = self.items[key][4] = True
        self.owners += 1
        self.directory.append(key)
        self.queue.append(key)
        return "ok"

    def step(self, operation: int, key: int) -> str:
        """Apply declared inputs to application obligations; a refused candidate is still a live application object."""
        if operation < 2:
            self.prepare(key, operation == 0)
            return self.accept(key)
        if operation == 6:
            self.closing = True
        elif operation == 7:
            if self.owned:
                self.owned = False
                self.release()
        elif operation == 8:
            return "idle"
        else:
            for identity, item in sorted(self.items.items()):
                if (operation == 2 and (not item[1] or item[2])) or (operation == 3 and (not item[1] or item[3])):
                    continue
                if operation in (2, 3, 4) and item[1] and not item[2]:
                    item[2] = True
                    self.release()
                if operation == 3:
                    item[3] = True
                elif operation == 4:
                    del self.items[identity]
                elif operation == 5 and item[4] and identity not in self.queue:
                    self.queue.append(identity)
                break
        return "none"


def require(actual: object, expected: object, cause: str) -> None:
    """Canonical comparison rejects bool/float identities, missing bookkeeping, extra fields and partial lists."""
    if v.encode(actual) != v.encode(expected):
        v.reject("comet-model-" + cause)


def configuration(check: dict) -> None:
    """Bind both native platforms to the exact transport-free case, observed domain and partial contract anchor."""
    if (
        check.get("model") != "comet-core-v1"
        or check["id"] != "comet-core-model"
        or check["component"] != "comet"
        or check["adapter"] != "observed-cases"
        or check.get("platforms") != ["linux-amd64-cgo", "windows-amd64"]
        or check["argv"] != ["python3", "-B", "tools/observe.py", "ctest", "--build", "build/comet-model", "--jobs", "1", "--case", "cpp_comet_core_model"]
        or check["expected_tests"] != ["cpp_comet_core_model"]
        or check["probes"] != [{"contract": "COMET-ASSURANCE", "minimum_hits": 1, "test": "cpp_comet_core_model"}]
    ):
        v.reject("comet-model-configuration")


def frames(data: bytes, check: dict) -> list[dict]:
    """Use original complete CTest XML, retaining every unpruned history, control and overlap observation."""
    return models.native(
        data,
        check,
        test="cpp_comet_core_model",
        algorithm="comet-core-v1",
        rows=DOMAIN["histories"] + DOMAIN["controls"] + DOMAIN["pairs"] + 2,
        prefix="comet-model",
    )


def history(operations: list[int], limits: list[int], ordinal: int) -> dict:
    """Reconstruct all receipts and complete post-states from fixed inputs, without inspecting native outputs."""
    state, states = State(limits), []
    initial = state.snapshot()
    for key, operation in enumerate(operations, start=1):
        receipt = state.step(operation, key)
        states.append({"operation": operation, "receipt": receipt, **state.snapshot()})
    return {"ordinal": ordinal, "limits": limits, "initial": initial, "states": states}


def candidate(seed: State, operations: list[int], key: int, order: tuple[int, int]) -> tuple[list[str], list[State]]:
    """Replay one complete serial admission order; each candidate already exists before overlap starts."""
    state = copy.deepcopy(seed)
    for index, operation in enumerate(operations):
        state.prepare(key + index, operation == 0)
    receipts, prefixes = [None, None], [copy.deepcopy(state)]
    for index in order:
        receipts[index] = state.accept(key + index)
        prefixes.append(copy.deepcopy(state))
    return receipts, prefixes


def assessment(actual: dict, receipts: list[str], prefixes: list[State]) -> bool:
    """Require one order to explain both receipts, full final state and the entire monotonically observed prefix stream."""
    if v.encode(actual["receipts"]) != v.encode(receipts) or v.encode(actual["current"]) != v.encode(prefixes[-1].snapshot()):
        return False
    allowed = [v.encode(state.snapshot(intents=False)) for state in prefixes]
    previous = 0
    for sample in actual["samples"]:
        matching = [index for index in range(previous, len(allowed)) if v.encode(sample) == allowed[index]]
        if not matching:
            return False
        previous = matching[0]
    return True


def pair(actual: dict, ordinal: int) -> None:
    """Reject mixed opposite-order observations, invented queue order and post-close admissions."""
    if not isinstance(actual, dict) or set(actual) != {"ordinal", "limits", "prefix", "operations", "initial", "receipts", "current", "samples"}:
        v.reject("comet-model-pair-shape")
    limits = DOMAIN["limits"][ordinal // 24]
    prefix = DOMAIN["prefixes"][ordinal // 4 % 6]
    operations = [ordinal // 2 % 2, ordinal % 2]
    seed = State(limits)
    for key, operation in enumerate(prefix, start=1):
        seed.step(operation, key)
    for name, value in {"ordinal": ordinal, "limits": limits, "prefix": prefix, "operations": operations, "initial": seed.snapshot(intents=False)}.items():
        require(actual[name], value, "pair-input")
    if not isinstance(actual["samples"], list) or len(actual["samples"]) != DOMAIN["reads"]:
        v.reject("comet-model-pair-observations")
    if not any(assessment(actual, *candidate(seed, operations, len(prefix) + 1, order)) for order in ((0, 1), (1, 0))):
        v.reject("comet-model-joint-serialization")


def observations(data: bytes, check: dict, root: Path = v.ROOT) -> dict[str, int]:
    """Qualify only the complete native Core domain; these observations cannot discharge the whole SDK finite/full rule."""
    configuration(check)
    observed, failures = v.case_observations(data, check)
    if failures:
        v.reject("comet-model-case-failed")
    rows = frames(data, check)
    require(rows[0], {"model": "comet-core-v1", "event": "start", "value": DOMAIN}, "domain")
    position, hits = 1, 1  # Output-health CHECK, independently followed by each real factory/bounded capture CHECK.
    for ordinal in range(DOMAIN["histories"]):
        remaining, operations = ordinal % 6561, []
        for _ in range(DOMAIN["depth"]):
            operations.append(remaining % DOMAIN["operations"])
            remaining //= DOMAIN["operations"]
        value = history(operations, DOMAIN["limits"][ordinal // 6561], ordinal)
        require(rows[position], {"model": "comet-core-v1", "event": "history", "value": value}, "history")
        position += 1
        hits += 2 + DOMAIN["depth"]
    transitions = 0
    for ordinal in range(DOMAIN["controls"]):
        limits, operation = DOMAIN["limits"][ordinal // 2], ordinal % 2
        capacity = limits[operation]
        operations = ([operation] * capacity + [2] * capacity) * 2 + [operation, 3, operation, 5, 7]
        require(rows[position], {"model": "comet-core-v1", "event": "control", "value": history(operations, limits, ordinal)}, "control")
        position += 1
        transitions += len(operations)
        hits += 2 + len(operations)
    for ordinal in range(DOMAIN["pairs"]):
        if rows[position]["event"] != "pair":
            v.reject("comet-model-pair-order")
        pair(rows[position]["value"], ordinal)
        position += 1
        hits += 3 + DOMAIN["reads"]
    require(
        rows[-1],
        {
            "model": "comet-core-v1",
            "event": "finish",
            "value": {"histories": 13122, "transitions": 52488, "controls": 4, "control_transitions": transitions, "pairs": 48, "reads": 3072},
        },
        "terminal",
    )
    require(observed, {"COMET-ASSURANCE": hits}, "counter")
    return observed
