"""Reconcile all nine independent member-equality pairs against frozen source and native input values."""

import base64
import copy
from pathlib import Path

from tools import verify as v

SOURCE = "935437c56a04d51978c2d2508b0c09b8f1dc51f03e58a6af089f926858ec068b"
FIELDS = ("galaxy", "id", "principal", "advertise", "epoch", "role", "group")


def configuration(check: dict) -> None:
    """Require the declared finite function scope, both-result assertions and an unfiltered named native test."""
    if (
        check.get("decisions") != "admission-same-v1"
        or check["component"] != "admission"
        or check["package"] != "github.com/eosforge/astra/internal/admission"
        or check["argv"] != ["go", "test", "-json", "-count=1", "-parallel=1", "-p=4", "-timeout=180s", "-run=^TestSame$", "./internal/admission"]
        or check["expected_tests"] != ["TestSame"]
        or v.encode(check["probes"]) != v.encode([{"contract": "ADMISSION-SAME", "test": "TestSame", "minimum_hits": 18}])
    ):
        v.reject("equality-configuration")


def member() -> dict:
    """Construct the explicit semantic baseline, sharing neither Go's equality helper nor its protobuf cloning."""
    return {
        "galaxy": "alpha",
        "id": "bG9jYWw=",
        "principal": base64.b64encode(bytes([1] * 32)).decode(),
        "advertise": "127.0.0.1:7443",
        "epoch": 1,
        "role": 1,
        "group": "default",
    }


def expected(condition: int) -> dict:
    """Change one operand presence or one business field, leaving every other observable input identical."""
    before = {"a": member(), "b": member(), "result": True}
    after = copy.deepcopy(before)
    after["result"] = False
    if condition < 2:
        after["a" if condition == 0 else "b"] = None
    else:
        values = ("beta", "b3RoZXI=", base64.b64encode(bytes([2] + [1] * 31)).decode(), "127.0.0.1:7444", 2, 3, "other")
        after["b"][FIELDS[condition - 2]] = values[condition - 2]
    return {"case": condition, "before": before, "after": after}


def frames(data: bytes, package: str, *, test: str = "TestSame", marker: str = "ADMISSION-SAME ", maximum: int = 9) -> list[dict]:
    """Reassemble bounded native fragments and reject foreign, malformed or truncated pair observations."""
    buffers, rows = {}, []
    for line in data.splitlines():
        event = v.decode(line)
        if not isinstance(event, dict) or event.get("Package") != package:
            v.reject("equality-package")
        if event.get("Action") != "output":
            continue
        name, output = event.get("Test", ""), event.get("Output", "")
        if not isinstance(name, str) or not isinstance(output, str):
            v.reject("equality-output")
        value = buffers.get(name, "") + output
        if len(value.encode()) > 65536:
            v.reject("equality-line-budget")
        parts = value.split("\n")
        buffers[name] = parts.pop()
        for part in parts:
            if marker not in part:
                continue
            if name != test or part.count(marker) != 1:
                v.reject("equality-test")
            rows.append(v.decode(part.split(marker, 1)[1].encode()))
            if len(rows) > maximum:
                v.reject("equality-row-budget")
    if any(marker.strip() in value for value in buffers.values()):
        v.reject("equality-truncated")
    return rows


def observations(data: bytes, check: dict, root: Path) -> dict[str, int]:
    """Require every real input pair and result; synthetic parser cases never supply execution evidence."""
    configuration(check)
    if v.digest(v.read(v.inside(root, "internal/admission/directory.go"))) != SOURCE:
        v.reject("equality-source")
    rows = frames(data, check["package"])
    if v.encode(rows) != v.encode([expected(condition) for condition in range(9)]):
        v.reject("equality-pairs")
    return {"ADMISSION-SAME": 2 * len(rows)}
