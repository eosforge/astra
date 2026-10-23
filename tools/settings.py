"""Reconcile finite native pragma-response independence without qualifying all Storage decisions."""

from pathlib import Path

from tools import equality, verify as v

SOURCE = "8049a032034b1e1b37f136636a9c1029a07ce0345cb9b7fb348d876ce333f8ab"
PACKAGE = "github.com/eosforge/astra/polaris/internal/storage"
TEST = "TestConnectionFault/release"
VALUES = {"PRAGMA journal_mode": "wal", "PRAGMA synchronous": 2, "PRAGMA foreign_keys": 1, "PRAGMA wal_autocheckpoint": 1000}
CONDITIONS = ["iteration-error", "finalization-error", "wrong-value"]
CASES = ["TestConnectionFault", TEST] + [
    "TestConnectionFault/" + query.replace(" ", "_") + "/" + point for query in VALUES for point in ("next", "close", "both")
]


def expected(query: str) -> dict:
    """Derive four immutable receipt tuples and three single-condition effect pairs from the pragma contract."""
    wanted = VALUES[query]
    rows = []
    for point in ("", "next", "close", "value"):
        values = [point == "next", point == "close", point == "value"]
        rows.append(
            {
                "name": point,
                "values": values,
                "result": any(values),
                "input": {
                    "query": query,
                    "point": point,
                    "native": wanted,
                    "value": None if point == "value" else wanted,
                    "next_error": point == "next",
                    "close_error": point == "close",
                    "steps": 1,
                    "closes": 1,
                    "native_step": True,
                    "native_close": True,
                },
            }
        )
    return {
        "id": "configuration/" + query,
        "conditions": CONDITIONS,
        "rows": rows,
        "pairs": [[0, 1], [0, 2], [0, 3]],
        "basis": "immutable semantic inputs; scan type/length uses short-circuit masking",
    }


def observations(data: bytes, root: Path) -> dict:
    """Require complete native receipt inputs, healthy operations, pair effects and exact production source identity."""
    if v.digest(v.read(v.inside(root, "polaris/internal/storage/schema.go"))) != SOURCE:
        v.reject("settings-source")
    check = {"package": PACKAGE, "expected_tests": CASES, "probes": [{"contract": "STORAGE-CONNECTION", "test": "TestConnectionFault", "minimum_hits": 13}]}
    _, failures = v.go_observations(data, check)
    if failures:
        v.reject("settings-native-terminals", ",".join(failures))
    rows = equality.frames(data, PACKAGE, test=TEST, marker="STORAGE-DECISION ", maximum=4)
    observed = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or row["id"] in observed:
            v.reject("settings-identity")
        observed[row["id"]] = row
    required = {"configuration/" + query: expected(query) for query in VALUES}
    if v.encode(observed) != v.encode(required):
        v.reject("settings-receipt-pairs")
    return {
        "source_sha256": SOURCE,
        "root": "configure: err != nil || closed != nil || value[0] != expected",
        "conditions": 3,
        "pragma_inputs": 4,
        "receipt_tuples": 16,
        "independent_pairs": 12,
        "masking": "none; every other semantic predicate stays equal",
        "qualification": "finite pragma-response decision only; not whole-Storage MC/DC or physical I/O faults",
    }
