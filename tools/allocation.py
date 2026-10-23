"""Reconstruct contiguous native allocation sweeps from independent literal maps and source logs."""

from pathlib import Path
import copy
import re

from tools import verify as v

CASES = (
    "cpp_native",
    "cpp_preparation",
    "cpp_origin",
    "cpp_scene",
    "cpp_origin_fault",
    "cpp_catalog_fault",
    "cpp_catalog_state",
    "cpp_catalog_replica",
    "cpp_ephemeris_state",
    "cpp_ephemeris_replica",
    "cpp_ephemeris_fault",
    "cpp_almanac",
    "cpp_almanac_fault",
    "cpp_almanac_model",
    "cpp_library",
    "cpp_metrics",
    "cpp_exchange",
    "cpp_dispatch",
    "cpp_access",
    "cpp_gateway",
    "cpp_broadcast",
    "cpp_ephemeris_rpc",
    "cpp_edition",
    "cpp_readout",
    "cpp_receiver",
    "cpp_intake",
    "cpp_catalog_model",
    "cpp_ephemeris_model",
    "cpp_pagination",
    "cpp_pagination_fault",
    "cpp_dispatch_fault",
    "cpp_catalog_rpc",
)
SWEEPS = {
    "catalog": (("batch", 256), ("create", 128), ("update", 128), ("renew", 128), ("expire", 128)),
    "ephemeris": (("create", 128), ("update", 128), ("renew", 128), ("remove", 128), ("expire", 128)),
}


def configuration(check: dict) -> None:
    """Retain the full Star suite, command, allocation probes and bounded pagination threshold."""
    argv = ["python3", "-B", "tools/observe.py", "ctest", "--build", "build/cmake/release"]
    argv += ["--case=" + case for case in CASES]
    probes = {p["contract"]: p for p in check["probes"]}
    if (
        check.get("faults") != "star-allocation-v1"
        or check["component"] != "star"
        or check["adapter"] != "observed-cases"
        or check["argv"] != argv
        or check["expected_tests"] != list(CASES)
        or any(
            v.encode(probes.get(contract)) != v.encode({"contract": contract, "test": test, "minimum_hits": hits})
            for contract, test, hits in (
                ("STAR_NATIVE-6", "cpp_catalog_fault", 1),
                ("STAR_NATIVE-11", "cpp_ephemeris_fault", 1),
                ("STAR_NATIVE-22", "cpp_ephemeris_rpc", 200),
                ("STAR_NATIVE-29", "cpp_pagination", 492381),
                ("STAR_NATIVE-30", "cpp_pagination_fault", 1),
                ("STAR_NATIVE-31", "cpp_dispatch_fault", 1),
                ("STAR_NATIVE-32", "cpp_catalog_rpc", 500),
            )
        )
    ):
        v.reject("allocation-configuration")


def uuid(value: object) -> None:
    """Validate the original binary UUIDv4 alphabet directly, without calling the production validator."""
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{32}", value) or value[12] != "4" or value[16] not in "89ab":
        v.reject("allocation-identity")


def initial(domain: str, operation: str, key: str) -> tuple[list, list]:
    """Anchor each fresh fixture to one literal row and one original source event."""
    sector, spectrum = ("batch", "fault") if operation == "batch" else ("initial", "scope")
    row = [1, [1 if operation == "batch" else 2] * 12, 2_000_000_000] if domain == "catalog" else [[1] * 12, [2] * 12, 2_000_000_000, 0, 0, 1000, 0]
    source = [1, 1, [[sector, spectrum, key, row]]]
    event = [1, "record", sector, spectrum, key, row]
    return source, [event]


def image(domain: str, operation: str, key: str, created: str | None = None) -> tuple[list, list, list]:
    """Apply only the declared successful operation to an ordinary row dictionary and ordered log."""
    source, events = initial(domain, operation, key)
    sector, spectrum = source[2][0][:2]
    original = source[2][0][3]
    rows = {(sector, spectrum, key): copy.deepcopy(original)}
    changed = copy.deepcopy(original)
    first_cursor, second_cursor = 1, 0
    if operation == "batch":
        changed[0] = 2
        rows[(sector, spectrum, key)] = changed
        rows[(sector, spectrum, "new".encode().hex())] = copy.deepcopy(changed)
        for name in (key, "new".encode().hex()):
            events.append([len(events) + 1, "record", sector, spectrum, name, copy.deepcopy(changed)])
        first_cursor = 3
    elif operation == "create":
        target = "key".encode().hex() if domain == "catalog" else created
        rows[("target", "scope", target)] = copy.deepcopy(original)
        events.append([2, "record", "target", "scope", target, copy.deepcopy(original)])
        second_cursor = 1
    elif operation == "update":
        if domain == "catalog":
            changed[:2] = [2, [3] * 16]
        else:
            changed[1], changed[3] = [3] * 16, 1
        rows[(sector, spectrum, key)] = changed
        events.append([2, "record" if domain == "catalog" else "data", sector, spectrum, key, copy.deepcopy(changed)])
        first_cursor = 2
    elif operation == "renew":
        changed[2 if domain == "catalog" else 4] = 3_000_000_000 if domain == "catalog" else 1
        rows[(sector, spectrum, key)] = changed
        events.append([2, "renew", sector, spectrum, key, copy.deepcopy(changed)])
    elif operation in ("remove", "expire"):
        if domain == "catalog":
            rows[(sector, spectrum, key)] = [1, None, None]
        else:
            del rows[(sector, spectrum, key)]
            events.append([2, "erase", sector, spectrum, key, None])
        first_cursor = 2
    else:
        v.reject("allocation-operation")
    native = [len(events), len(rows), [[*address, row] for address, row in sorted(rows.items())]]

    def view(address: tuple[str, str], cursor: int) -> list:
        """Build complete visible roots directly, preserving absence versus an empty byte buffer."""
        content = []
        for (own_sector, own_spectrum, name), row in sorted(rows.items()):
            if (own_sector, own_spectrum) != address:
                continue
            if domain == "catalog" and row[1] is not None:
                content.append([name, row[:2]])
            elif domain == "ephemeris":
                content.append([name, row[:2]])
        return [cursor, len(content), content]

    return [native, events], view((sector, spectrum), first_cursor), view(("target", "scope"), second_cursor)


def expected(domain: str, operation: str, key: str, failed: bool, created: str | None = None) -> tuple[list[list], list, list]:
    """Derive permitted failed boundaries, prescribed healthy recovery and immutable roots independently."""
    source, events = initial(domain, operation, key)
    row = source[2][0][3]
    frozen = [source, [1, 1, [[key, row[:2]]]]]
    healthy = list(image(domain, operation, key, created))
    before = [[source, events]] if failed else [healthy[0]]
    after = healthy
    if failed and operation == "expire" and domain == "catalog":
        # Local expiry may finish its source floor before the separate merged projection fails.
        before.append(healthy[0])
    elif failed and operation not in ("expire", "batch"):
        after = list(image(domain, "update", key))
    return before, after, frozen


def trace(data: str, domain: str) -> int:
    """Require every consecutive injected point and its first healthy completion within the original bound."""
    frames = []
    for line in data.splitlines(keepends=True):
        if "ASTRA-ALLOCATION" not in line:
            continue
        if not line.startswith("ASTRA-ALLOCATION ") or not line.endswith("\n") or len(line.encode()) > 65536:
            v.reject("allocation-line")
        try:
            frames.append(v.decode(line[len("ASTRA-ALLOCATION ") :].encode(), maximum=65536))
        except v.Invalid as error:
            v.reject("allocation-line", str(error))
    sweeps = SWEEPS[domain]
    start = {"event": "start", "domain": domain, "sweeps": [list(item) for item in sweeps]}
    finish = {"event": "finish", "domain": domain}
    if not frames or v.encode(frames[0]) != v.encode(start) or v.encode(frames[-1]) != v.encode(finish):
        v.reject("allocation-terminal")
    cursor, checks = 1, len(sweeps) + 1
    for operation, bound in sweeps:
        completed = False
        for point in range(bound):
            if cursor >= len(frames) - 1:
                v.reject("allocation-incomplete")
            item = frames[cursor]
            cursor += 1
            if not isinstance(item, dict) or set(item) != {"event", "operation", "point", "injected", "propagated", "before", "after", "frozen"}:
                v.reject("allocation-frame")
            if v.encode({k: item[k] for k in ("event", "operation", "point")}) != v.encode({"event": "attempt", "operation": operation, "point": point}):
                v.reject("allocation-order")
            failed = item["injected"]
            if type(failed) is not bool or type(item["propagated"]) is not bool or failed != item["propagated"] or point == 0 and not failed:
                v.reject("allocation-injection")
            try:
                key = ("old" if operation == "batch" else "key").encode().hex()
                created = None
                if domain == "ephemeris":
                    key = item["frozen"][0][2][0][2]
                    uuid(key)
                    if operation == "create" and not failed:
                        targets = [row for row in item["before"][0][2] if row[:2] == ["target", "scope"]]
                        if len(targets) != 1:
                            v.reject("allocation-created")
                        created = targets[0][2]
                        uuid(created)
                        if created == key:
                            v.reject("allocation-created")
                before, after, frozen = expected(domain, operation, key, failed, created)
            except (IndexError, KeyError, TypeError) as error:
                v.reject("allocation-state-shape", str(error))
            if (
                not any(v.encode(item["before"]) == v.encode(value) for value in before)
                or v.encode(item["after"]) != v.encode(after)
                or v.encode(item["frozen"]) != v.encode(frozen)
            ):
                v.reject("allocation-state")
            if operation == "batch":
                checks += 9 if failed else 6
            elif operation == "expire":
                checks += 9
            else:
                checks += 13 if failed else 11 if operation == "create" else 10
            if not failed:
                completed = True
                break
        if not completed:
            v.reject("allocation-budget")
    if cursor != len(frames) - 1:
        v.reject("allocation-extra")
    counters = [v.decode(line[len("ASTRA-CHECKS ") :].encode()) for line in data.splitlines() if line.startswith("ASTRA-CHECKS ")]
    if len(counters) != 1 or v.encode(counters[0]) != v.encode({"hits": checks}):
        v.reject("allocation-checks")
    return checks


def pages(data: str) -> int:
    """Require all finite page-failure sweeps and independently reconstruct their executed checks."""
    frames, summaries, counters = [], [], []
    for line in data.splitlines(keepends=True):
        for marker, output in (("ASTRA-PAGE-FAULT ", frames), ("ASTRA-PAGE-FAULT-SUMMARY ", summaries), ("ASTRA-CHECKS ", counters)):
            if marker.strip() not in line:
                continue
            # The summary shares the shorter marker prefix but belongs to its own record type.
            if marker == "ASTRA-PAGE-FAULT " and "ASTRA-PAGE-FAULT-SUMMARY" in line:
                continue
            if not line.startswith(marker) or not line.endswith("\n") or len(line.encode()) > 4096:
                v.reject("allocation-page-line")
            output.append(v.decode(line[len(marker) :].encode(), maximum=4096))
    original = ("first", "middle", "last", "point", "zero", "missing", "empty", "delta", "tail")
    scenarios = [(domain, case) for domain in ("catalog", "ephemeris") for case in original]
    scenarios += [("catalog", "dense"), ("ephemeris", "dense"), ("almanac", "empty"), ("almanac", "point"), ("almanac", "dense"), ("almanac", "construction")]
    cursor, checks, failures = 0, 26, 0  # One completion assertion per scenario and two whole-run assertions.
    for domain, case in scenarios:
        if domain == "almanac":
            cost = {"empty": 4, "point": 7, "dense": 16, "construction": 5}[case]
        elif case == "dense":
            cost = 11 if domain == "catalog" else 15
        else:
            row = 8 if domain == "catalog" else 9
            if case in ("empty", "missing"):
                counts = [5]
            elif case in ("first", "middle", "last"):
                counts = [row] * 3
            elif case in ("delta", "tail"):
                counts = [row, 10]
            else:
                counts = [row]
            skipped = 2 if case == "last" else 1 if case in ("middle", "tail") else 0
            preparation = 3 if case in ("first", "middle", "last") else 0
            # Original pages, retried cursor and independently frozen cursor have distinct traversals.
            cost = preparation + 4 + sum(counts[:skipped]) + skipped + 2 * sum(counts[skipped:]) + 2 * (len(counts) - skipped)
        completed = False
        for point in range(128):
            if cursor >= len(frames):
                v.reject("allocation-page-incomplete")
            frame = frames[cursor]
            cursor += 1
            if not isinstance(frame, dict) or set(frame) != {"domain", "case", "point", "injected"}:
                v.reject("allocation-page-frame")
            if (
                frame["domain"] != domain
                or frame["case"] != case
                or type(frame["point"]) is not int
                or frame["point"] != point
                or type(frame["injected"]) is not bool
            ):
                v.reject("allocation-page-order")
            checks += cost + (2 if frame["injected"] else 0)
            if frame["injected"]:
                failures += 1
            else:
                if not point:
                    v.reject("allocation-page-vacuous")
                completed = True
                break
        if not completed:
            v.reject("allocation-page-budget")
    if cursor != len(frames) or v.encode(summaries) != v.encode([{"scenarios": 24, "attempts": cursor, "failures": failures}]):
        v.reject("allocation-page-terminal")
    if v.encode(counters) != v.encode([{"hits": checks}]):
        v.reject("allocation-page-checks")
    return checks


def dispatch(data: str) -> int:
    """Reconcile complete replication sweeps, healthy baselines and literal retry-path assertions."""
    lines = [line for line in data.splitlines(keepends=True) if line.strip()]
    if (
        not 2 <= len(lines) <= 12 * 256 * 2 + 2
        or any(not line.endswith("\n") or len(line.encode()) > 4096 for line in lines)
        or lines[0] != "ASTRA-DISPATCH-HEALTHY 12\n"
        or not lines[-1].startswith("ASTRA-CHECKS ")
    ):
        v.reject("allocation-dispatch-terminal")
    # Counts include fresh source construction and every literal packet, cursor, ACK and budget check.
    costs = {
        "catalog": {"empty": 11, "delta": 49, "first": 58, "last": 58, "dense": 40, "expired": 36},
        "ephemeris": {"empty": 11, "delta": 60, "first": 58, "last": 58, "dense": 40, "expired": 20},
    }
    checks = 523  # Twelve complete healthy fixtures, twelve outer assertions and twelve sweep completions.
    cursor = 1
    for domain, cases in costs.items():
        for case, cost in cases.items():
            completed = False
            for point in range(256):
                if cursor + 2 > len(lines) - 1:
                    v.reject("allocation-dispatch-incomplete")
                frames = []
                for offset, marker in enumerate(("ASTRA-DISPATCH-BEGIN ", "ASTRA-DISPATCH-END ")):
                    line = lines[cursor + offset]
                    if not line.startswith(marker):
                        v.reject("allocation-dispatch-line")
                    try:
                        frames.append(v.decode(line[len(marker) :].encode(), maximum=4096))
                    except v.Invalid as error:
                        v.reject("allocation-dispatch-frame", str(error))
                first, last = frames
                expected = {"domain": domain, "case": case, "point": point}
                if v.encode(first) != v.encode(expected):
                    v.reject("allocation-dispatch-order")
                if not isinstance(last, dict) or set(last) != set(expected) | {"injected"} or type(last["injected"]) is not bool:
                    v.reject("allocation-dispatch-frame")
                if v.encode({key: last[key] for key in expected}) != v.encode(expected):
                    v.reject("allocation-dispatch-order")
                cursor += 2
                checks += cost
                if not last["injected"]:
                    if point == 0:
                        v.reject("allocation-dispatch-vacuous")
                    completed = True
                    break
            if not completed:
                v.reject("allocation-dispatch-budget")
    if cursor != len(lines) - 1:
        v.reject("allocation-dispatch-extra")
    try:
        counter = v.decode(lines[-1][len("ASTRA-CHECKS ") :].encode(), maximum=4096)
    except v.Invalid as error:
        v.reject("allocation-dispatch-checks", str(error))
    if v.encode(counter) != v.encode({"hits": checks}):
        v.reject("allocation-dispatch-checks")
    return checks


def rpc(text: str, domain: str = "catalog") -> int:
    """Require complete ordered RPC scenarios, the terminal marker and the declared assertion floor."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if domain == "ephemeris":
        expected = [f"ASTRA-EPHEMERIS-EXCEPTION {fault} {operation}" for fault in (1, 2) for operation in range(4)]
        expected += [
            f"ASTRA-EPHEMERIS-BOUNDARY {group} {index}"
            for group, count in (
                ("create", 21),
                ("update", 12),
                ("renew", 11),
                ("remove", 10),
                ("versions", 5),
                ("limits", 5),
                ("configuration", 4),
                ("cleanup", 2),
            )
            for index in range(count)
        ]
        if len(lines) != len(expected) + 2 or lines[:-2] != expected or lines[-2] != "Ephemeris RPC tests passed":
            v.reject("ephemeris-rpc-cases")
        match = re.fullmatch(r'ASTRA-CHECKS \{"hits":([0-9]+)\}', lines[-1])
        if match is None or int(match[1]) < 200:
            v.reject("ephemeris-rpc-checks")
        return int(match[1])
    if domain != "catalog":
        v.reject("rpc-domain")
    expected = [{"group": "lifecycle", "cases": 1}]
    expected += [{"group": "publish", "case": index} for index in range(21)]
    expected += [{"group": "renew", "case": index} for index in range(12)]
    expected += [{"group": "limits", "cases": 1}]
    expected += [{"group": "query", "case": index} for index in range(5)]
    expected += [{"group": "admission", "cases": 8}, {"group": "streaming", "cases": 1}]
    expected += [
        {"group": "configuration", "cases": 6},
        {"group": "refusals", "cases": 8},
        {"group": "capacity", "cases": 2},
        {"group": "exhaustion", "cases": 2},
    ]
    expected += [{"group": "exceptions", "case": index} for index in range(2)]
    expected += [{"group": "cleanup", "case": index} for index in range(2)]
    if len(lines) != len(expected) + 2 or lines[-2] != "PASS Catalog public RPC boundaries and atomic batches":
        v.reject("catalog-rpc-cases")
    for line, row in zip(lines, expected):
        if not line.startswith("ASTRA-CATALOG ") or v.encode(v.decode(line.removeprefix("ASTRA-CATALOG ").encode())) != v.encode(row):
            v.reject("catalog-rpc-cases")
    match = re.fullmatch(r'ASTRA-CHECKS \{"hits":([0-9]+)\}', lines[-1])
    if match is None or int(match[1]) < 500:
        v.reject("catalog-rpc-checks")
    return int(match[1])


def observations(data: bytes, check: dict, root: Path | None = None) -> dict[str, int]:
    """Bind complete native XML cases to both independently reconstructed allocation domains."""
    configuration(check)
    from tools import junit

    try:
        cases = junit.document(data, check).findall("testcase")
    except v.Invalid as error:
        v.reject("allocation-native", str(error))
    names = [item.get("name") for item in cases]
    if len(names) != len(CASES) or set(names) != set(CASES):
        v.reject("allocation-cases")
    result = {}
    for case, domain, contract in (("cpp_catalog_fault", "catalog", "STAR_NATIVE-6"), ("cpp_ephemeris_fault", "ephemeris", "STAR_NATIVE-11")):
        output = cases[names.index(case)].find("system-out")
        if output is None or not output.text:
            v.reject("allocation-output")
        result[contract] = trace(output.text, domain)
    output = cases[names.index("cpp_pagination_fault")].find("system-out")
    if output is None or not output.text:
        v.reject("allocation-page-output")
    result["STAR_NATIVE-30"] = pages(output.text)
    output = cases[names.index("cpp_dispatch_fault")].find("system-out")
    if output is None or not output.text:
        v.reject("allocation-dispatch-output")
    result["STAR_NATIVE-31"] = dispatch(output.text)
    output = cases[names.index("cpp_catalog_rpc")].find("system-out")
    if output is None or not output.text:
        v.reject("catalog-rpc-output")
    result["STAR_NATIVE-32"] = rpc(output.text)
    output = cases[names.index("cpp_ephemeris_rpc")].find("system-out")
    if output is None or not output.text:
        v.reject("ephemeris-rpc-output")
    result["STAR_NATIVE-22"] = rpc(output.text, "ephemeris")
    return result
