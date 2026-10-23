"""Reconstruct finite public models and decode their bounded native observation envelopes."""

from pathlib import Path
import base64
import itertools
import re
import struct

from tools import verify as v

# Fixed public-operation alphabet: -2 preserves a register, -1 erases, and 0/1 assign its payload.
ACTIONS = ((0, -2), (1, -2), (-2, 0), (-2, 1), (-1, -2), (-2, -1), (0, 1), (-1, 0), (1, -1))
INITIALS = ((-1, -1), (0, -1), (-1, 1), (0, 1))
RELATIONS = ((1, 1), (1, 2), (2, 1))


def configuration(check: dict) -> None:
    """Bind this capability to its actual platform/package, full domain, anchors and native command."""
    if check.get("model") == "storage-borrowing-v1":
        from tools import draining

        return draining.borrowing(check)
    if check.get("model") == "storage-draining-v1":
        from tools import draining

        return draining.configuration(check)
    if check.get("model") == "storage-termination-v1":
        from tools import termination

        return termination.configuration(check)
    if check.get("model") == "storage-lifetime-v1":
        from tools import lifecycle

        return lifecycle.configuration(check)
    if check.get("model") == "storage-retry-v1":
        from tools import retry

        return retry.configuration(check)
    if check.get("model") == "comet-projection-v1":
        from tools import projection

        return projection.configuration(check)
    if check.get("model") == "comet-core-v1":
        from tools import comet

        return comet.configuration(check)
    if check.get("model") == "store-state-v1":
        from tools import store

        return store.configuration(check)
    if check.get("model") == "ledger-state-v1":
        from tools import ledger

        return ledger.configuration(check)
    if check.get("model") == "almanac-state-v1":
        from tools import almanac

        return almanac.configuration(check)
    if check.get("model") == "catalog-state-v1":
        from tools import catalog

        return catalog.configuration(check)
    if check.get("model") == "ephemeris-state-v1":
        from tools import ephemeris

        return ephemeris.configuration(check)
    if check.get("model") == "command-state-v1":
        from tools import command

        return command.configuration(check)
    if check.get("model") == "admission-state-v1":
        from tools import admission

        return admission.configuration(check)
    required = {
        "STORAGE-FINITE": ("TestFinite", 13123),
        "STORAGE-ASSURANCE": ("TestFinite", 2187),
        "STORAGE-SCHEDULE": ("TestSchedules", 1),
        "STORAGE-ORACLE": ("TestOracle", 18),
    }
    actual = {(item["contract"], item["test"]): item["minimum_hits"] for item in check["probes"]}
    if (
        check["model"] != "storage-commit-v1"
        or check.get("recovery") != "storage-recovery-v1"
        or check["component"] != "polaris-storage"
        or check["package"] != "github.com/eosforge/astra/polaris/internal/storage"
        or not {"TestFinite", "TestOracle", "TestSchedules"} <= set(check["expected_tests"])
        or len(actual) != len(check["probes"])
        or any(actual.get((contract, test)) != minimum for contract, (test, minimum) in required.items())
        or check["argv"] != ["go", "test", "-json", "-count=1", "-parallel=4", "-p=4", "-timeout=180s", "./polaris/internal/storage"]
    ):
        v.reject("model-configuration")


def native(data: bytes, check: dict, *, test: str, algorithm: str, rows: int, prefix: str) -> list[dict]:
    """Decode one bound CTest case without sharing any domain transition or expected public value."""
    from tools import junit

    try:
        cases = junit.document(data, check).findall("testcase")
    except v.Invalid as error:
        code = str(error).split(":", 1)[0]
        cause = "native-missing" if code == "ctest-payload-count" else "case" if code == "ctest-case-selection" else "native-shape"
        v.reject(prefix + "-" + cause, str(error))
    names = [case.get("name") for case in cases]
    if len(names) != len(check["expected_tests"]) or set(names) != set(check["expected_tests"]) or names.count(test) != 1:
        v.reject(prefix + "-case")
    output = cases[names.index(test)].find("system-out")
    if output is None or not output.text:
        v.reject(prefix + "-output")
    result = []
    for line in output.text.splitlines(keepends=True):
        if "ASTRA-MODEL" not in line:
            continue
        if not line.startswith("ASTRA-MODEL ") or not line.endswith("\n") or len(line.encode()) > 64 * 1024:
            v.reject(prefix + "-line")
        try:
            row = v.decode(line[len("ASTRA-MODEL ") :].encode(), maximum=64 * 1024)
        except v.Invalid as error:
            v.reject(prefix + "-line", str(error))
        if not isinstance(row, dict) or set(row) != {"model", "event", "value"} or row["model"] != algorithm:
            v.reject(prefix + "-frame")
        result.append(row)
        if len(result) > rows:
            v.reject(prefix + "-frame-budget")
    if len(result) != rows:
        v.reject(prefix + "-domain-incomplete")
    return result


def normalize(value: object) -> object:
    """Project only nil/empty Go slices with identical public semantics, retaining all keys and order."""
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        return {
            key: ([] if key in {"Records", "Changes"} and item is None else "" if key == "Value" and item is None else normalize(item))
            for key, item in value.items()
        }
    return value


def same(actual: object, expected: object) -> bool:
    """Compare canonical bytes so JSON booleans/floats cannot impersonate integer versions or ordinals."""
    return v.encode(normalize(actual)) == v.encode(normalize(expected))


def require(actual: object, expected: object, cause: str) -> None:
    """Reject one exact trace discrepancy, without accepting a partially matching result."""
    if not same(actual, expected):
        v.reject("model-" + cause)


def entries(action: tuple[int, int], version: int = 0) -> list[dict]:
    """Translate the independent register alphabet into public changes, preserving erase versus empty set."""
    return [
        {"Version": version, "Key": key, "Value": "AQ==" if value == 1 else "", "Erase": value == -1} for key, value in zip(("a", "b"), action) if value != -2
    ]


def batch(action: tuple[int, int]) -> str:
    """Encode the documented AB02 layout directly, sharing neither Go's encoder nor Entries decoder."""
    changes = entries(action)
    data = b"AB02" + struct.pack(">Q", len(changes))
    for change in changes:
        key = change["Key"].encode()
        value = base64.b64decode(change["Value"], validate=True)
        data += struct.pack(">HIB", len(key), len(value), int(change["Erase"])) + key + value
    return base64.b64encode(data).decode("ascii")


def state(log: list[tuple[int, int]], sector: str, ordinal: int, retained: int | None = None) -> tuple[dict, dict]:
    """Fold accepted requests into a simple map and ordered log; physical SQL structures are irrelevant."""
    records = {}
    for action in log:
        for key, value in zip(("a", "b"), action):
            if value == -1:
                records.pop(key, None)
            elif value != -2:
                records[key] = "AQ==" if value == 1 else ""
    snapshot = {
        "Sector": sector,
        "Spectrum": str(ordinal),
        "Version": len(log),
        "Records": [{"Key": key, "Value": value} for key, value in sorted(records.items())],
    }
    floor = 0 if retained is None else max(0, len(log) - retained)
    history = {
        "Version": len(log),
        "Changes": [{"Version": index + 1, "Key": "", "Value": batch(action), "Erase": False} for index, action in enumerate(log) if index >= floor],
    }
    return snapshot, history


def frames(data: bytes) -> dict[str, list[dict]]:
    """Reassemble bounded Output fragments before parsing a long native Go log line."""
    buffers, result = {}, {"TestFinite": [], "TestSchedules": []}
    for line in data.splitlines():
        event = v.decode(line)
        if event.get("Action") != "output":
            continue
        name = event.get("Test", "")
        output = buffers.get(name, "") + event.get("Output", "")
        if len(output.encode()) > 128 * 1024:
            v.reject("model-line-budget")
        parts = output.split("\n")
        buffers[name] = parts.pop()
        for part in parts:
            marker = re.search(r"ASTRA-MODEL (.*)$", part)
            if marker is None:
                continue
            if name not in result:
                v.reject("model-test-identity")
            item = v.decode(marker.group(1).encode())
            if not isinstance(item, dict) or set(item) != {"model", "event", "value"} or item["model"] != "storage-commit-v1":
                v.reject("model-frame-shape")
            result[name].append(item)
            if len(result[name]) > 2189:
                v.reject("model-frame-budget")
    if any("ASTRA-MODEL" in value for value in buffers.values()):
        v.reject("model-incomplete-line")
    return result


def observations(data: bytes, check: dict, root: Path = v.ROOT) -> dict[str, int]:
    """Check every native sequence and pair, returning only a complete finite-domain observation count."""
    if check.get("model") == "storage-borrowing-v1":
        from tools import draining

        return draining.borrowed(data, check, root)
    if check.get("model") == "storage-draining-v1":
        from tools import draining

        return draining.observations(data, check, root)
    if check.get("model") == "storage-termination-v1":
        from tools import termination

        return termination.observations(data, check, root)
    if check.get("model") == "storage-lifetime-v1":
        from tools import lifecycle

        return lifecycle.observations(data, check, root)
    if check.get("model") == "storage-retry-v1":
        from tools import retry

        return retry.observations(data, check, root)
    if check.get("model") == "comet-projection-v1":
        from tools import projection

        return projection.observations(data, check, root)
    if check.get("model") == "comet-core-v1":
        from tools import comet

        return comet.observations(data, check, root)
    if check.get("model") == "store-state-v1":
        from tools import store

        return store.observations(data, check, root)
    if check.get("model") == "ledger-state-v1":
        from tools import ledger

        return ledger.observations(data, check, root)
    if check.get("model") == "almanac-state-v1":
        from tools import almanac

        return almanac.observations(data, check, root)
    if check.get("model") == "catalog-state-v1":
        from tools import catalog

        return catalog.observations(data, check, root)
    if check.get("model") == "ephemeris-state-v1":
        from tools import ephemeris

        return ephemeris.observations(data, check, root)
    if check.get("model") == "command-state-v1":
        from tools import command

        return command.observations(data, check, root)
    if check.get("model") == "admission-state-v1":
        from tools import admission

        return admission.observations(data, check, root)
    configuration(check)
    streams = frames(data)
    serial, pairs = streams["TestFinite"], streams["TestSchedules"]
    if len(serial) != 2189 or len(pairs) != 974:
        v.reject("model-domain-incomplete")

    def value(item: dict, event: str) -> dict:
        """Return an observation value only when its event matches the required order."""
        if item["event"] != event:
            v.reject("model-event-order")
        return item["value"]

    require(value(serial[0], "sequence-start"), {"operations": [entries(action) for action in ACTIONS], "depth": 3, "history": 2}, "sequence-domain")
    position = 1
    for ordinal, sequence in enumerate(itertools.product(range(9), repeat=3)):
        log = []
        for step, index in enumerate(sequence):
            version = step + 1
            log.append(ACTIONS[index])
            snapshot, history = state(log, "finite", ordinal, retained=2)
            expected = {
                "case": ordinal,
                "sequence": sequence,
                "step": step,
                "commit": {"version": version, "error": ""},
                "retry": {"version": version, "error": ""},
                "gap": {"version": 0, "error": "version"},
                "snapshot": snapshot,
                "history": history,
                "floor": max(0, version - 2),
                "stale": {"history": {"Version": 0, "Changes": []}, "error": "history"} if version > 2 else None,
            }
            require(value(serial[position], "step"), expected, "sequence-result")
            position += 1
    require(value(serial[-1], "sequence-finish"), {"sequences": 729, "transitions": 2187}, "sequence-finish")
    require(value(pairs[0], "pair-start"), {"actions": ACTIONS, "initials": INITIALS, "relations": RELATIONS, "reads": 16}, "pair-domain")
    fields = {"case", "initial", "actions", "versions", "receipts", "frozen", "snapshot", "history", "views", "histories"}
    for ordinal, (initial, first, second, relation) in enumerate(itertools.product(INITIALS, ACTIONS, ACTIONS, RELATIONS)):
        item = value(pairs[ordinal + 1], "pair")
        if not isinstance(item, dict) or set(item) != fields:
            v.reject("model-pair-shape")
        seed = [tuple(-2 if value == -1 else value for value in initial)] if initial != (-1, -1) else []
        versions = tuple(len(seed) + offset for offset in relation)
        for field, expected in {"case": ordinal, "initial": initial, "actions": (first, second), "versions": versions}.items():
            require(item[field], expected, "pair-input")
        require(item["frozen"], state(seed, "schedules", ordinal)[0], "retained-snapshot")
        if not isinstance(item["views"], list) or len(item["views"]) != 16 or not isinstance(item["histories"], list) or len(item["histories"]) != 16:
            v.reject("model-observation-count")
        matched = False
        for order in ((0, 1), (1, 0)):
            log, prefixes, receipts = list(seed), [state(seed, "schedules", ordinal)], [None, None]
            for writer in order:
                requested, action = versions[writer], (first, second)[writer]
                accepted = requested == len(log) + 1 or 0 < requested <= len(log) and log[requested - 1] == action
                if requested == len(log) + 1:
                    log.append(action)
                receipts[writer] = {"version": requested if accepted else 0, "error": "" if accepted else "version"}
                prefixes.append(state(log, "schedules", ordinal))
            valid = same(item["receipts"], receipts) and same(item["snapshot"], prefixes[-1][0]) and same(item["history"], prefixes[-1][1])
            last = len(seed)
            for view, history in zip(item["views"], item["histories"]):
                found_view = any(same(view, prefix[0]) for prefix in prefixes)
                found_history = any(same(history, prefix[1]) for prefix in prefixes)
                monotonic = (
                    isinstance(view, dict)
                    and isinstance(history, dict)
                    and type(view.get("Version")) is int
                    and type(history.get("Version")) is int
                    and view["Version"] >= last
                    and history["Version"] >= view["Version"]
                )
                valid = valid and found_view and found_history and monotonic
                if monotonic:
                    last = history["Version"]
            matched = matched or valid
        if not matched:
            v.reject("model-joint-serialization")
    require(value(pairs[-1], "pair-finish"), {"histories": 972, "observations": 15552}, "pair-finish")
    return {"STORAGE-ASSURANCE": 2187}
