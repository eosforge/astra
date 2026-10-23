"""Reconstruct finite Admission state histories from native public observations, independently of Go's models."""

from collections.abc import Iterator
import base64
import hashlib
import itertools
from pathlib import Path

from tools import materials, verify as v

SOURCES = {
    "internal/admission/node.go": "46e8948bbcde2f2dd05184d0631e202566dc44a47f604a938b32231e44d3eaa4",
    "internal/admission/directory.go": "935437c56a04d51978c2d2508b0c09b8f1dc51f03e58a6af089f926858ec068b",
    "internal/admission/identity.go": "37e195bcb9412502763e761740705d08e4ec57cd038d911f13068a97ec6e3612",
    "internal/generated/orbit/orbit.pb.go": "3f4a4e5cd64402a71710a2a737d04436fde70276e9ac889404c8380c314dab7b",
}
# The cancellation repair changes only Join's result for a cancelled owner. The finite retry domain
# uses context.Background(), and directory/publication transitions and numeric expressions are unchanged.
# Both exact versions remain readable; this does not relabel old native input or artifact identities.
NODE = "375da6dfab3ad7e58f8314e339c271e4ab3a8b50050a53cec765b2980249148c"
# The acquisition repair changes only file admission before decoding. Native red/green evidence
# verifies its refusal paths; unchanged finite directory/retry models still require their own histories.
# Keep SOURCES unchanged for readers whose historical compiler coordinates remain fixed.
MATERIAL = {
    "internal/admission/identity.go": "d172cc85f0e6a6099699b0c4a3cea3813cbf5e7e04d7be23ffca464be56ea09b",
    "internal/admission/file_linux.go": "c099b58c8159d55be312ba7a8c8ef280821516a4832e769937b10177c348f8e1",
    "internal/admission/file_other.go": "170bdbc9e29057e44e9b9b352ae1b0f1ed67d881814377e08700152a643f6bc1",
}
KINDS = {
    "directory": ("TestDirectoryModel", 11664),
    "pair": ("TestDirectorySchedules", 3240),
    "retry": ("TestNodeModel", 594),
    "publication": ("TestNodeTransitions", 4374),
}
PROBES = {
    "ADMISSION-FINITE": ("TestDirectoryModel", 34992),
    "ADMISSION-ASSURANCE": ("TestDirectoryModel", 306026),
    "ADMISSION-SCHEDULE": ("TestDirectorySchedules", 3240),
    "ADMISSION-NODE-FINITE": ("TestNodeModel", 12971),
    "ADMISSION-NODE-TRANSITIONS": ("TestNodeTransitions", 39417),
}
INITIALS = ((0, 0), (1, 0), (2, 0), (0, 1), (0, 2))
# Lists, verified single-member observations and five malformed lists; this is a protocol alphabet, not a branch inventory.
ACTIONS = (
    (0, 0, False),
    (1, 0, False),
    (2, 0, False),
    (0, 1, False),
    (0, 2, False),
    (1, 1, False),
    (1, 2, False),
    (2, 1, False),
    (2, 2, False),
    (1, 0, True),
    (2, 0, True),
    (0, 1, True),
    (0, 2, True),
)


def same(actual: object, expected: object) -> bool:
    """Compare exact JSON types as well as values, rejecting booleans or floats substituted for integer identities."""
    return v.encode(actual) == v.encode(expected)


def matches(root: Path, name: str, selected: dict[str, str] | None = None) -> bool:
    """Match reviewed bytes within one explicit source catalog, without advancing historical geometry."""
    selected = SOURCES if selected is None else selected
    accepted = {selected[name]}
    if name == "internal/admission/node.go":
        accepted.add(NODE)
    path = v.inside(root, name)
    return path.is_file() and v.file_digest(path) in accepted


def scope(root: Path) -> dict[str, str] | None:
    """Select a complete owned inventory; callers must then verify every selected source digest."""
    owned = {p.relative_to(root).as_posix() for p in (root / "internal/admission").rglob("*.go") if not p.name.endswith("_test.go")}
    for selected in (SOURCES, {**SOURCES, **MATERIAL}):
        if owned == {name for name in selected if name.startswith("internal/admission/")}:
            return selected
    return None


def configuration(check: dict) -> None:
    """Keep the complete Admission suite, finite domain and minimum observations fixed before reading results."""
    materials.configuration(check)
    probes = {p["contract"]: (p["test"], p["minimum_hits"]) for p in check["probes"]}
    if (
        check.get("model") != "admission-state-v1"
        or any(not same(probes.get(name), value) for name, value in PROBES.items())
        or any(sum(p["contract"] == name for p in check["probes"]) != 1 for name in PROBES)
    ):
        v.reject("admission-model-configuration")


def directory(state: tuple[int, int], action: int, capacity: int) -> tuple[tuple[int, int], bool]:
    """Specify merge-by-maximum, stale verified-peer refusal and atomic capacity rejection over two epoch registers."""
    if action >= len(ACTIONS):
        return state, False
    a, b, verified = ACTIONS[action]
    incoming = (a, b)
    if verified and any(0 < value < old for value, old in zip(incoming, state)):
        return state, False
    result = tuple(max(value, old) for value, old in zip(incoming, state))
    return (result, True) if sum(value != 0 for value in result) <= capacity else (state, False)


def member(epoch: int, *, index: int = 0, role: int = 1) -> dict:
    """Encode only documented public member fields without importing generated Go/protobuf helpers."""
    if index:
        principal = bytes(31) + bytes([index])
        identity, address = f"node-{index:02}-{epoch:02}", f"127.0.0.1:{7400 + index}"
    else:
        principal = hashlib.sha256(b"stars\0alpha\0" + b"127.0.0.1:7443").digest()
        identity, address = "local" if epoch == 1 else "newer", "127.0.0.1:7443"
    return {
        "galaxy": "alpha",
        "id": base64.b64encode(identity.encode()).decode(),
        "principal": base64.b64encode(principal).decode(),
        "advertise": address,
        "epoch": epoch,
        "role": role,
        "group": "default",
    }


def members(state: tuple[int, int]) -> list[dict]:
    """Return the independently ordered complete two-principal directory view."""
    return [member(epoch, index=index + 1) for index, epoch in enumerate(state) if epoch]


def retry(role: int, refresh: bool, prefix: int, suffix: int) -> dict:
    """Derive bounded backoff and terminal receipts arithmetically, independently of Go's literal transition tables."""
    values = [0] * prefix + [suffix // 9, suffix // 3 % 3, suffix % 3]
    delay, cap = (30_000_000_000, 120_000_000_000) if refresh else (500_000_000, 30_000_000_000)
    waits, receipts, calls, result, admitted = [], [], 0, 1, refresh
    for value in values:
        if refresh:
            waits.append(delay)
        calls += 1
        if refresh:
            receipts.append((14, 0, 7)[value])
        if value == 2:
            result = 7
            break
        if value == 1 and not refresh:
            result, admitted = 0, True
            break
        if not refresh:
            waits.append(delay)
        delay = 30_000_000_000 if value == 1 else min(2 * delay, cap)
    else:
        if refresh:
            waits.append(delay)
    return {
        "role": role,
        "refresh": refresh,
        "prefix": prefix,
        "suffix": suffix,
        "calls": calls,
        "delays": waits or None,
        "callbacks": receipts or None,
        "result": result,
        "admitted": admitted,
    }


def publication(ready: bool, epoch: int, action: int) -> tuple[bool, int, int, int, int]:
    """Apply protocol clauses to credential availability and the highest known epoch, without Go's five-state table."""
    if action >= 7:
        incoming = 2 if action == 7 else 1
        return ready, max(epoch, incoming), 3 if incoming < epoch else 0, 0, 0
    if action < 3:
        if ready:
            return ready, epoch, 0, 0, 0
        if action == 0 and epoch < 2:
            return True, 1, 0, 1, 0
        return ready, epoch, 1 if action == 1 else 2, 1, 0
    if not ready:
        return ready, epoch, 1, 0, 0
    result = 1 if action == 4 else 2 if action == 6 else 3 if action == 5 or epoch == 2 else 0
    return ready, epoch, result, 0, 1


def expected(kind: str) -> Iterator[dict | list[dict]]:
    """Enumerate the entire fixed domain in native order; pairs retain both legal serializations."""
    if kind == "directory":
        for capacity in (1, 2):
            for sequence, actions in enumerate(itertools.product(range(18), repeat=3)):
                state, receipts = (0, 0), []
                for action in actions:
                    state, accepted = directory(state, action, capacity)
                    receipts.append({"accepted": accepted, "members": members(state)})
                yield {"capacity": capacity, "sequence": sequence, "receipts": receipts}
    elif kind == "pair":
        for capacity, initial, first, second in itertools.product((1, 2), INITIALS, range(18), range(18)):
            alternatives = []
            for order in ((0, 1), (1, 0)):
                state, accepted = initial, [False, False]
                for index in order:
                    state, accepted[index] = directory(state, (first, second)[index], capacity)
                alternatives.append(
                    {"capacity": capacity, "initial": list(initial), "first": first, "second": second, "accepted": accepted, "members": members(state)}
                )
            yield alternatives
    elif kind == "retry":
        for role in (3, 4):
            for refresh in (False, True):
                for prefix, suffix in itertools.product(range(3 if refresh else 8), range(27)):
                    yield retry(role, refresh, prefix, suffix)
    elif kind == "publication":
        for role in (3, 4):
            for sequence, actions in enumerate(itertools.product(range(9), repeat=3)):
                ready, epoch = False, 0
                for step, action in enumerate(actions):
                    ready, epoch, result, registers, lists = publication(ready, epoch, action)
                    yield {
                        "role": role,
                        "sequence": sequence,
                        "step": step,
                        "result": result,
                        "registers": registers,
                        "lists": lists,
                        "member": member(1, role=role) if ready else None,
                        "directory": [member(epoch, role=role)] if epoch else [],
                        "hello": ready,
                        "context": ready,
                        "current": [epoch == 1, epoch == 2],
                    }
    else:
        v.reject("admission-model-kind")


def frames(data: bytes, package: str) -> dict[str, list[dict]]:
    """Reassemble bounded native lines with strict domain/test ownership, duplicate-marker and truncation checks."""
    buffers, result = {}, {name: [] for name in KINDS}
    for line in data.splitlines():
        event = v.decode(line)
        if not isinstance(event, dict) or event.get("Package") != package:
            v.reject("admission-model-package")
        if event.get("Action") != "output":
            continue
        test, output = event.get("Test", ""), event.get("Output", "")
        if not isinstance(test, str) or not isinstance(output, str):
            v.reject("admission-model-output")
        value = buffers.get(test, "") + output
        if len(value.encode()) > 65536:
            v.reject("admission-model-line-budget")
        lines = value.split("\n")
        buffers[test] = lines.pop()
        for part in lines:
            marker = "ADMISSION-MODEL "
            if marker not in part:
                continue
            if part.count(marker) != 1:
                v.reject("admission-model-marker")
            item = v.decode(part.split(marker, 1)[1].encode())
            if not isinstance(item, dict) or set(item) != {"kind", "value"} or not isinstance(item["kind"], str) or item["kind"] not in KINDS:
                v.reject("admission-model-shape")
            kind = item["kind"]
            if test != KINDS[kind][0]:
                v.reject("admission-model-test")
            result[kind].append(item["value"])
            if len(result[kind]) > KINDS[kind][1]:
                v.reject("admission-model-row-budget")
    if any("ADMISSION-MODEL" in tail for tail in buffers.values()):
        v.reject("admission-model-truncated")
    return result


def domain(kind: str, rows: list[dict]) -> None:
    """Require every exact input/result in one declared domain, accepting only legal complete pair histories."""
    if kind not in KINDS or len(rows) != KINDS[kind][1]:
        v.reject("admission-model-domain", kind)
    for actual, wanted in zip(rows, expected(kind), strict=True):
        if not any(same(actual, value) for value in (wanted if kind == "pair" else [wanted])):
            v.reject("admission-model-history", kind)


def reconcile(rows: dict[str, list[dict]]) -> dict[str, int]:
    """Reject any missing, extra, altered or illegal history before reconstructing actual assertion counts."""
    if rows.keys() != KINDS.keys():
        v.reject("admission-model-domains")
    for kind in KINDS:
        domain(kind, rows[kind])
    serial = (
        2
        + len(rows["directory"])
        + sum(6 + 2 * len(receipt["members"]) + (not receipt["accepted"]) for row in rows["directory"] for receipt in row["receipts"])
    )
    pairs = 1 + sum(7 + 3 * len(row["members"]) for row in rows["pair"])
    retries = 1 + sum(8 + int(row["refresh"]) + 2 * row["calls"] + len(row["delays"] or []) + len(row["callbacks"] or []) for row in rows["retry"])
    states = 1 + 2 * 1458 + sum(8 + row["registers"] + row["lists"] for row in rows["publication"])
    return {
        "ADMISSION-FINITE": serial,
        "ADMISSION-ASSURANCE": serial,
        "ADMISSION-SCHEDULE": pairs,
        "ADMISSION-NODE-FINITE": retries,
        "ADMISSION-NODE-TRANSITIONS": states,
    }


def observations(data: bytes, check: dict, root: Path) -> dict[str, int]:
    """Bind finite-model observations to the complete native suite and unchanged modeled implementation."""
    configuration(check)
    selected = scope(root)
    if selected is None:
        v.reject("admission-model-source-scope")
    for name in selected:
        if not matches(root, name, selected):
            v.reject("admission-model-source", name)
    return reconcile(frames(data, check["package"]))
