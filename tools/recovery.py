"""Reconcile reached native SQL failures and renewed recovery cycles against an independent finite matrix."""

from tools import verify as v

SITES = ("scope-insert", "record-insert", "record-update", "record-delete", "history-insert", "history-delete", "scope-update", "meta-update")
PACKAGE = "github.com/eosforge/astra/polaris/internal/storage"
TEST = "TestFaultCycles"


def frames(values: list[dict]) -> dict:
    """Reject missing coordinates, partial rollback, leaked ownership and false recovery receipts."""
    expected = [
        (site, cycle, phase, attempt) for site in SITES for cycle in range(2) for phase, attempt in (("failure", 0), ("failure", 1), ("recovery", None))
    ]
    if len(values) != len(expected):
        v.reject("recovery-matrix")
    digests = {}
    for frame, (site, cycle, phase, attempt) in zip(values, expected):
        common = {"site", "cycle", "phase", "outcome", "version", "events", "writer", "readers", "writers"}
        fields = common | ({"attempt", "reached", "before", "after"} if phase == "failure" else {"records"})
        if not isinstance(frame, dict) or set(frame) != fields or (frame["site"], frame["cycle"], frame["phase"]) != (site, cycle, phase):
            v.reject("recovery-attribution")
        numbers = fields - {"site", "phase", "outcome", "before", "after"}
        if any(type(frame[key]) is not int for key in numbers) or any(frame[key] != 0 for key in ("writer", "readers", "writers")):
            v.reject("recovery-ownership")
        if phase == "failure":
            wanted = "version" if site == "scope-update" else "corrupt" if site == "meta-update" else "unavailable"
            if frame["outcome"] != wanted:
                v.reject("recovery-error-class")
            if frame["attempt"] != attempt or frame["reached"] != 1 or frame["version"] != 0 or frame["events"] != 0:
                v.reject("recovery-failure")
            digest = frame["before"]
            if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest) or frame["after"] != digest:
                v.reject("recovery-rollback")
            coordinate = (site, cycle)
            if coordinate in digests and digests[coordinate] != digest:
                v.reject("recovery-persistent-failure")
            digests[coordinate] = digest
        elif frame["outcome"] != "nil" or frame["version"] != (1 if site == "scope-insert" else cycle * 2 + 2) or frame["events"] != 1 or frame["records"] != 2:
            v.reject("recovery-receipt")
    if any(digests[(site, 0)] == digests[(site, 1)] for site in SITES):
        v.reject("recovery-renewed-state")
    return {
        "sites": len(SITES),
        "failures": sum(row["phase"] == "failure" for row in values),
        "recoveries": sum(row["phase"] == "recovery" for row in values),
        "observations": len(values),
    }


def observations(data: bytes) -> dict:
    """Bind every matrix row to the named passing native subtest and require its nonempty parent assertion count."""
    entries = [v.decode(line) for line in data.splitlines() if line.strip()]
    values, counters, ended = [], [], []
    for entry in entries:
        if entry.get("Package") != PACKAGE:
            v.reject("recovery-package")
        name = entry.get("Test", "")
        if entry.get("Action") in {"pass", "fail", "skip"} and name:
            ended.append((name, entry["Action"]))
        output = entry.get("Output", "")
        if "STORAGE-SQL-FAULT " in output:
            frame = v.decode(output.split("STORAGE-SQL-FAULT ", 1)[1].strip())
            if name != TEST + "/" + frame.get("site", ""):
                v.reject("recovery-native-attribution")
            values.append(frame)
        if "ASTRA-CONTRACT " in output and name == TEST:
            counters.append(v.decode(output.split("ASTRA-CONTRACT ", 1)[1].strip()))
    if ended != [(TEST + "/" + site, "pass") for site in SITES] + [(TEST, "pass")]:
        v.reject("recovery-native-completion")
    if counters != [{"contract": "STORAGE-SQL-FAULT", "hits": 9}]:
        v.reject("recovery-native-counter")
    return {**frames(values), "parent_assertions": counters[0]["hits"]}
