"""Reconcile domain integer range proofs and native boundary histories over each complete frozen production scope."""

from pathlib import Path

from tools import admission, equality, verify as v

EPOCHS = (1, 2, 2**31 - 1, 2**31, 2**32 - 1, 2**32, 2**63 - 1, 2**63, 2**64 - 2, 2**64 - 1)
HITS = 1046


def configuration(check: dict) -> None:
    """Require the declared native integer boundary suite and complete expected witness budget."""
    if check.get("numeric") in {"storage-integers-v1", "storage-source-v1"}:
        from tools import storage_numeric

        storage_numeric.configuration(check)
        return
    if (
        check.get("numeric") != "admission-integers-v1"
        or check["component"] != "admission"
        or check["package"] != "github.com/eosforge/astra/internal/admission"
        or check["argv"] != ["go", "test", "-json", "-count=1", "-parallel=1", "-p=4", "-timeout=180s", "-run=^TestNumeric$", "./internal/admission"]
        or check["expected_tests"] != ["TestNumeric"]
        or v.encode(check["probes"]) != v.encode([{"contract": "ADMISSION-NUMERIC", "test": "TestNumeric", "minimum_hits": HITS}])
    ):
        v.reject("numeric-configuration")


def bounds(root: Path) -> dict:
    """Verify the exact source/representation assumptions before deriving integer intervals with unbounded arithmetic."""
    selected = admission.scope(root)
    if selected is None:
        v.reject("numeric-scope")
    for relative in selected:
        if not admission.matches(root, relative, selected):
            v.reject("numeric-source", relative)
    # These literal source anchors name every computed numerical operation, including the random bound and its conversion.
    node = (root / "internal/admission/node.go").read_text(encoding="utf-8")
    for anchor in (
        "delay := 500 * time.Millisecond",
        "delay = min(delay*2, 30*time.Second)",
        "delay := 30 * time.Second",
        "delay = 30 * time.Second",
        "delay = min(delay*2, 2*time.Minute)",
        "time.NewTimer(delay + time.Duration(randv2.Int64N(int64(delay/5)+1)))",
    ):
        if node.count(anchor) != 1:
            v.reject("numeric-anchor", anchor)
    # Public loops are the only production callers of pause. Their complete reachable delay sets are independently modeled.
    join = (500_000_000, 1_000_000_000, 2_000_000_000, 4_000_000_000, 8_000_000_000, 16_000_000_000, 30_000_000_000)
    refresh = (30_000_000_000, 60_000_000_000, 120_000_000_000)
    values = []
    for delay in sorted(set(join + refresh)):
        random = delay // 5 + 1
        upper = delay + random - 1
        if not (0 < random <= upper <= 2**63 - 1 and delay * 2 <= 2**63 - 1):
            v.reject("numeric-overflow")
        values.append({"delay_ns": delay, "doubled_ns": delay * 2, "random_exclusive": random, "wait_max_ns": upper})
    return {
        "int_bits": 64,
        "epoch_bits": 64,
        "duration_bits": 64,
        "epochs": "unsigned comparisons without arithmetic or narrowing",
        "rounding": "positive integer division truncates toward zero; inclusive jitter upper bound is floor(delay/5)",
        "delays": values,
        "maximum_material_bytes": 5 * 16384,
        "maximum_members": 16384,
        "frame_bytes": 8 * 2**20,
        "outgoing_bytes": 4096,
        "rpc_deadlines_ns": [5_000_000_000, 10_000_000_000],
        "floating_operations": 0,
    }


def expected() -> list[dict]:
    """Specify the full-width transition grid and exact accepted/refused limits independently of Go's tests."""
    rows = [{"kind": "representation", "int": 64, "epoch": 64, "duration": 64}]
    for capacity in (-(2**63), -1, 0, 1, 16384, 16385, 2**63 - 1):
        accepted = capacity in (1, 16384)
        rows.append({"kind": "capacity", "input": capacity, "accepted": accepted, "maximum": capacity if accepted else 0})
    for install in (False, True):
        for old in EPOCHS:
            for new in EPOCHS:
                rows.append(
                    {
                        "kind": "epoch",
                        "install": install,
                        "old": old,
                        "next": new,
                        "accepted": install or new >= old,
                        "epoch": max(old, new),
                        "current": new >= old,
                    }
                )
    rows.extend({"kind": "id", "length": size, "accepted": size <= 128} for size in (1, 128, 129))
    rows.extend(
        {"kind": "port", "input": port, "accepted": port in ("1", "65535"), "value": int(port) if port in ("1", "65535") else 0}
        for port in ("0", "1", "65535", "65536")
    )
    rows.extend({"kind": "payload", "length": size, "accepted": size == 1024} for size in (1024, 1025))
    for name in ("ca.pem", "cert.pem", "key.pem", "login.json"):
        rows.extend({"kind": "material", "name": name, "length": size, "accepted": size == 16384} for size in (16384, 16385))
    return [{"kind": "numeric", "value": row} for row in rows]


def observations(data: bytes, check: dict, root: Path) -> dict[str, int]:
    """Bind every native outcome plus range assumptions; marker totals alone cannot satisfy numeric qualification."""
    if check.get("numeric") in {"storage-integers-v1", "storage-source-v1"}:
        from tools import storage_numeric

        return storage_numeric.observations(data, check, root)
    configuration(check)
    bounds(root)
    rows = equality.frames(data, check["package"], test="TestNumeric", marker="ADMISSION-NUMERIC ", maximum=225)
    if v.encode(rows) != v.encode(expected()):
        v.reject("numeric-witnesses")
    return {"ADMISSION-NUMERIC": HITS}
