"""Reconstruct Storage's integer boundary witnesses and complete pinned production-range assumptions independently."""

from pathlib import Path, PurePosixPath
import base64
import json
import re

from tools import equality, verify as v

PLATFORM = "linux-amd64-cgo"
PACKAGE = "github.com/eosforge/astra/polaris/internal/storage"
DIRECTORY = "polaris/internal/storage"
HITS = 447
SOURCE_HITS = 884
CONTROL_HITS = 24
SOURCE_PACKAGE = "github.com/eosforge/astra/tools/decisions"
SOURCE_TESTS = (
    "TestBoundary",
    "TestControls",
    "TestExpressions",
    "TestFlatTree",
    "TestFlow",
    "TestFlowInventory",
    "TestFlowRejection",
    "TestFlowScope",
    "TestManifest",
    "TestNumberControls",
    "TestNumbers",
    "TestPartitionArguments",
    "TestPartitionNative",
    "TestStorageNumbers",
    "TestTrace",
    "TestTraceRecoverOutsideDecisions",
    "TestTraceRecoverSpans",
    "TestTraceRejection",
    "TestTraceScope",
    "TestTree",
    "TestTyping",
    "TestTypingImports",
    "TestTypingInactive",
    "TestTypingRejection",
)
# These source-specific scopes cover every numerical use, including declarations and operations with non-numeric results.
SCOPES = {
    "<package>": "declarations",
    "Store.CommitBatch": "codec",
    "validChange": "codec",
    "Change.Entries": "codec",
    "Store.Commit": "versions",
    "Store.commit": "accounting",
    "confirm": "versions",
    "Store.retain": "history",
    "boolint": "accounting",
    "Store.Subscribe": "feeds",
    "Feed.Close": "feeds",
    "Feed.Take": "feeds",
    "Feed.push": "feeds",
    "Feed.stop": "feeds",
    "system.open": "operating-system",
    "lock": "operating-system",
    "Version.Value": "versions",
    "Version.Scan": "versions",
    "Scope.Valid": "text",
    "Default": "configuration",
    "Limits.valid": "configuration",
    "text": "text",
    "Store.readOnly": "configuration",
    "Store.List": "queries",
    "Store.Version": "versions",
    "Store.snapshot": "queries",
    "Store.Since": "versions",
    "Store.history": "history",
    "connection": "configuration",
    "configure": "configuration",
    "Store.validate": "queries",
    "open": "operating-system",
    "database": "configuration",
    "Store.Close": "feeds",
    "Store.maintain": "operating-system",
    "name": "text",
}
VERSIONS = (0, 1, 2, 2**31 - 1, 2**31, 2**32 - 1, 2**32, 2**63 - 1, 2**63, 2**64 - 2, 2**64 - 1)
FIELDS = (
    ("scopes", 1, 16384),
    ("records", 1, 2**20),
    ("bytes", 1, 2**30),
    ("total", 1, 2**32),
    ("history", 0, 65536),
    ("backlog", 0, 64 * 2**20),
    ("timeout", 1, 30_000_000_000),
    ("wal", 2**20, 2**32),
)


def revision(root: Path) -> tuple[int, int, dict]:
    """Retain the old range proof only for its old source; the exact maintenance revision adds two duration uses."""
    from tools import idle

    return (884, 4194, {**SCOPES, "Store.maintenance": "configuration"}) if idle.current(root) else (882, 4114, SCOPES)


def configuration(check: dict) -> None:
    """Reject changes to native package selection, witness identity or the preset successful-assertion budget."""
    if check.get("numeric") == "storage-source-v1":
        if (
            check["component"] != "polaris-storage"
            or check["package"] != SOURCE_PACKAGE
            or check["argv"] != ["go", "test", "-json", "-count=1", "-parallel=1", "-p=2", "-timeout=300s", "./tools/decisions"]
            or check["expected_tests"] != list(SOURCE_TESTS)
            or v.encode(check["probes"])
            != v.encode(
                [
                    {"contract": "STORAGE-NUMERIC-CONTROLS", "test": "TestNumberControls", "minimum_hits": CONTROL_HITS},
                    {
                        "contract": "STORAGE-NUMERIC-SOURCE",
                        "test": "TestStorageNumbers",
                        "minimum_hits": (
                            check["probes"][1]["minimum_hits"] if len(check["probes"]) == 2 and check["probes"][1]["minimum_hits"] in (882, 884) else -1
                        ),
                    },
                ]
            )
        ):
            v.reject("storage-numeric-source-configuration")
        return
    if (
        check.get("numeric") != "storage-integers-v1"
        or check["component"] != "polaris-storage"
        or check["package"] != PACKAGE
        or check["argv"] != ["go", "test", "-json", "-count=1", "-parallel=1", "-p=2", "-timeout=180s", "-run=^TestNumeric$", "./polaris/internal/storage"]
        or check["expected_tests"] != ["TestNumeric"]
        or v.encode(check["probes"]) != v.encode([{"contract": "STORAGE-NUMERIC", "test": "TestNumeric", "minimum_hits": HITS}])
    ):
        v.reject("storage-numeric-configuration")


def manifest(root: Path) -> dict:
    """Bind the complete owned production set, including inactive code, without certifying unexecuted platforms."""
    directory = root / DIRECTORY
    policy = v.decode(v.read(directory / "numeric.json"))
    if (
        set(policy) != {"schema_version", "platform", "sources", "runtime_version", "runtime_sources", "allocation_bits", "assumptions"}
        or policy["schema_version"] != 1
        or policy["platform"] != PLATFORM
        or policy["runtime_version"] != "go1.27.2"
        or policy["allocation_bits"] != 48
    ):
        v.reject("storage-numeric-manifest")
    selected = {path.name: path for path in directory.glob("*.go") if not path.name.endswith("_test.go")}
    if not selected or set(selected) != set(policy["sources"]) or len(selected) != (11 if revision(root)[0] == 884 else 10):
        v.reject("storage-numeric-source-scope")
    for name, path in selected.items():
        if path.is_symlink() or not re.fullmatch(r"[a-z_]+\.go", name) or v.file_digest(path) != policy["sources"][name]:
            v.reject("storage-numeric-source", name)
    if set(policy["runtime_sources"]) != {
        "runtime/malloc.go",
        "internal/goarch/goarch.go",
        "internal/goarch/zgoarch_amd64.go",
        "internal/goos/goos.go",
        "internal/goos/zgoos_linux.go",
    } or any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in policy["runtime_sources"].values()):
        v.reject("storage-numeric-runtime-scope")
    if (
        not isinstance(policy["assumptions"], list)
        or len(policy["assumptions"]) != 4
        or any(not isinstance(text, str) or not text.strip() for text in policy["assumptions"])
    ):
        v.reject("storage-numeric-assumptions")
    return policy


def bounds(root: Path) -> dict:
    """Derive conservative intervals using Python integers over the exact reviewed source and allocator assumptions."""
    policy = manifest(root)
    source = {name: (root / DIRECTORY / name).read_text(encoding="utf-8") for name in policy["sources"]}
    anchors = {
        "model.go": (
            "binary.BigEndian.AppendUint64(nil, uint64(version))",
            "!ok || len(bytes) != 8",
            "limits.Scopes <= 16384",
            "limits.Records <= 1<<20",
            "limits.Bytes <= 1<<30",
            "limits.Total <= 4<<30",
            "limits.History <= 65536",
            "limits.Backlog <= 64<<20",
            "limits.Timeout <= 30*time.Second",
        ),
        "batch.go": (
            "count > uint64(len(data)/8)",
            "make([]Change, 0, int(count))",
            "key > len(data) || uint64(length) > uint64(len(data)-key)",
            "value := int(length)",
            "len(change.Value) <= 1<<20",
            "uint16(len(change.Key))",
            "uint32(len(change.Value))",
        ),
        "commit.go": (
            "if change.Version <= state.Version",
            "state.Version == Version(math.MaxUint64) || change.Version != state.Version+1",
            "event.Value = bytes.Clone(change.Value)",
            "state.Bytes += int64(len(entry.Key) + len(entry.Value))",
            "meta.Bytes+state.Bytes-previous",
            "state.Retained++",
            "state.Backlog += cost",
        ),
        "read.go": (
            "int(state.Records) + 1",
            "after > state.Version",
            "state.Retained < 0 || uint64(state.Retained) > uint64(state.Version)",
            "state.Version-Version(state.Retained)",
            "position == state.Version || change.Version != position+1",
            "int(state.Retained) + 1",
        ),
        "feed.go": ("limit > 16<<20", "items > 65536", "len(store.feeds) >= 128", "limit > (128<<20)-store.feedBytes", "cost > feed.limit-feed.bytes"),
        "schema.go": (
            "conn.SetLimit(sqlite3.SQLITE_LIMIT_LENGTH, (64<<20)+1024)",
            "int(store.limits.Scopes) + 1",
            "state.Retained < 0 || uint64(state.Retained) > uint64(state.Version)",
            "state.Version-Version(state.Retained)",
            "total += actual.Bytes",
        ),
        "store.go": (
            "endpoint.Port() == 0",
            "if !limits.valid()",
            "maximum := 4",
            "maximum = 1",
            "info.Size() < store.limits.WAL",
            "progress.Busy != 0 || progress.Log > progress.Checkpointed",
            "char >= 'a' && char <= 'z'",
        ),
        "files.go": ("return os.OpenFile(path, flags, mode)",),
        "lock_linux.go": ("file.Stat()", "info.Mode().IsRegular()", "unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)"),
    }
    if "maintenance.go" in source:
        anchors["maintenance.go"] = ("time.NewTicker(time.Second)", "context.WithTimeout(ctx, store.limits.Timeout)")
    for name, wanted in anchors.items():
        for text in wanted:
            if text not in source[name]:
                v.reject("storage-numeric-anchor", name + ":" + text)
    if source["commit.go"].index("if change.Version <= state.Version") > source["commit.go"].index("state.Version == Version(math.MaxUint64)") or source[
        "commit.go"
    ].index("event.Value = bytes.Clone(change.Value)") > source["commit.go"].index("previous := state.Bytes"):
        v.reject("storage-numeric-guard-order")
    allocation = 2 ** policy["allocation_bits"]
    signed = 2**63 - 1
    intervals = {
        "batch_count_before_narrowing": signed // 8,
        "admitted_entry_count": allocation // 56,
        "scope_records_during_commit": 2**20 + allocation // 56,
        "scope_bytes_during_commit": 2**30 + allocation,
        "signed_history_cost": 64 + 1024 + allocation,
        "signed_feed_cost": 128 + 2 * 128 + 1024 + allocation,
        "global_replacement_intermediate": 2**32 + 2**30,
        "history_before_eviction": 65537,
        "backlog_before_eviction": 2 * 64 * 2**20,
        "snapshot_scan_total": (2**20 + 1) * (1024 + 2**20),
        "history_scan_total": 65537 * (64 + 1024 + 64 * 2**20 + 1024),
        "reopen_scope_total": 16384 * 2**30,
        "query_scope_limit": 16385,
        "query_record_limit": 2**20 + 1,
        "query_history_limit": 65537,
        "timeout_ns": 30_000_000_000,
        "feed_reservations": 128 * 2**20,
        "raw_history_cost_before_validation": 64 + 2 * ((64 << 20) + 1024),
        "key_value_sum_before_validation": 2 * allocation,
        "native_file_descriptor": 2**31 - 1,
        "unicode_scalar": 0x10FFFF,
        "native_port": 65535,
        "decoded_key_before_validation": 65535,
        "decoded_length_before_validation": 2**32 - 1,
        "batch_entry_allocation_product": (allocation // 8) * 56,
    }
    if "maintenance.go" in source:
        intervals.update(maintenance_period_ns=1_000_000_000, maintenance_timeout_ns=30_000_000_000)
    if any(not 0 <= value <= signed for value in intervals.values()):
        v.reject("storage-numeric-overflow-proof")
    return {
        "platform": PLATFORM,
        "int_bits": 64,
        "version_bits": 64,
        "duration_bits": 64,
        "allocation_max_bytes": allocation,
        "change_bytes": 56,
        "interval_upper_bounds": intervals,
        "floating_operations": 0,
        "sources": policy["sources"],
        "runtime_sources": policy["runtime_sources"],
        "assumptions": policy["assumptions"],
    }


def proof(root: Path) -> dict:
    """Bind all native numerical owners to source-specific interval, conversion, unit and guard obligations."""
    limits = bounds(root)
    source = {name: (root / DIRECTORY / name).read_text(encoding="utf-8") for name in limits["sources"]}
    orders = (
        ("batch.go", "if !validChange(change)", "uint16(len(change.Key))"),
        ("batch.go", "if count == 0 || count > uint64(len(data)/8)", "make([]Change, 0, int(count))"),
        ("batch.go", "if len(data) < 7", "binary.BigEndian.Uint16(data[:2])"),
        ("batch.go", "if key > len(data) || uint64(length) > uint64(len(data)-key)", "value := int(length)"),
        ("commit.go", "if store.limits.History == 0 || cost > store.limits.Backlog", "state.Retained++"),
        ("commit.go", "if !exists && meta.Scopes >= store.limits.Scopes", "meta.Scopes++"),
        ("feed.go", "limit > (128<<20)-store.feedBytes", "store.feedBytes += limit"),
        ("feed.go", "if _, exists := feed.store.feeds[feed]; exists", "feed.store.feedBytes -= feed.limit"),
        ("feed.go", "cost > feed.limit-feed.bytes", "feed.bytes += cost"),
        ("read.go", "state.Records > store.limits.Records", "int(state.Records) + 1"),
        ("read.go", "uint64(state.Retained) > uint64(state.Version)", "state.Version-Version(state.Retained)"),
        ("schema.go", "uint64(state.Retained) > uint64(state.Version)", "state.Version-Version(state.Retained)"),
        ("lock_linux.go", "file.Stat()", "int(file.Fd())"),
    )
    for name, guard, operation in orders:
        if guard not in source[name] or operation not in source[name] or source[name].index(guard) >= source[name].index(operation):
            v.reject("storage-numeric-proof-order", name + ":" + operation)
    allocation, signed, unsigned = limits["allocation_max_bytes"], 2**63 - 1, 2**64 - 1
    # Independent interval arithmetic covers the extrema; runtime-fatal allocation rejection is not a successful commit.
    arithmetic = {
        "entry-header-division": {"divisor": 8, "range": [0, allocation // 8], "rounding": "nonnegative integer floor"},
        "entry-allocation-product": {"range": [0, (allocation // 8) * 56], "maximum": signed},
        "encoding-key-conversion": {"range": [1, 1024], "maximum": 2**16 - 1},
        "encoding-value-conversion": {"range": [0, 2**20], "maximum": 2**32 - 1},
        "decoding-key-conversion": {"range": [0, 2**16 - 1], "maximum": signed},
        "decoding-value-conversion": {"range": [0, 2**32 - 1], "maximum": signed},
        "version-increment": {"input": [0, unsigned - 1], "increment": 1, "range": [1, unsigned], "maximum": unsigned},
        "version-suffix-subtraction": {"constraint": "0 <= retained <= version <= MaxUint64", "range": [0, unsigned], "maximum": unsigned},
        "slice-endpoint": {"constraint": "0 <= key <= remaining and 0 <= value <= remaining-key", "range": [0, allocation], "maximum": signed},
        "global-accounting": {"constraint": "0 <= previous <= meta and new scope <= 1 GiB before global addition", "range": [0, 5 * 2**30], "maximum": signed},
        "feed-subtraction": {"constraint": "0 <= charged <= limit <= 16 MiB", "range": [0, 16 * 2**20], "maximum": signed},
        "feed-reservation": {"constraint": "new limit <= 128 MiB-reserved; membership precedes release", "range": [0, 128 * 2**20], "maximum": signed},
    }
    for name, item in arithmetic.items():
        lower, upper = item["range"]
        if not 0 <= lower <= upper <= item.get("maximum", signed) or item.get("divisor", 1) <= 0:
            v.reject("storage-numeric-proof-interval", name)
    families = {
        "declarations": "Native type checking establishes representable constants and exact integer declarations; there are no owned floating operations.",
        "configuration": "Limits retain signed 64-bit counts/bytes and nanosecond durations; checked maxima precede query narrowing and borrowed timer/SQLite calls. Constants for pools, pragmas and SQLite limits fit their native API representations.",
        "codec": "Validated keys/values precede uint16/uint32 encoding. Nonzero counts are bounded by remaining/8 before int conversion or allocation. Seven-byte headers precede extraction; remaining-key guards precede value conversion and key+value slicing. Builtin allocation checks reject oversized products before any durable mutation.",
        "versions": "Version is an unsigned 64-bit register encoded as exactly eight big-endian BLOB bytes. Dynamic SQL types cannot narrow it. Replay precedes increment; a maximum cursor cannot advance. Nonnegative retained<=version precedes unsigned suffix subtraction.",
        "accounting": "Consistent admitted state and unique batch keys prevent negative removal prefixes. Successful immutable cloning bounds aggregate additions; local capacity rejection precedes global replacement arithmetic. New-scope admission precedes increment, and boolint is exactly 0 or 1.",
        "history": "Cost and zero-history checks precede count/backlog growth. One inserted item yields at most 65537 records and twice the bounded backlog before eviction. Only validated positive-cost rows enter totals; bounded scans and valid prefixes keep subtraction nonnegative. SQL integer-overflow/scan errors reject the transaction rather than become floating or wrapped state.",
        "feeds": "Positive per-feed limits and remaining aggregate budget precede reservation. Exclusive membership precedes release. Positive event cost is checked against limit-current before addition; Take/stop/Close reset counters without subtracting an unowned reservation.",
        "queries": "Validated count maxima precede int+1 query limits. Per-row key/value checks precede accounting; bounded query counts and positive validated rows bound totals. Startup reconciles native COUNT/SUM, snapshot and history before admitting state; SQL or dynamic-type failures propagate rejection.",
        "operating-system": "Mode/flag values are bit fields without numerical rescaling. A successfully opened, stat-checked, privately owned Linux descriptor fits the signed kernel fd domain before uintptr-to-int conversion. Ports retain uint16. WAL sizes/checkpoint values are compared as signed int64, never narrowed or arithmetically combined.",
        "text": "Lengths retain native nonnegative int; byte limits are explicit. Range decodes Unicode scalar/rune-error values into int32, and ASCII name decisions only compare those values with representable literals, without arithmetic or normalization.",
    }
    owners = revision(root)[2]
    if "maintenance.go" in source:
        # No duration conversion or arithmetic is added: a positive one-second constant and the validated nanosecond limit are borrowed.
        families[
            "configuration"
        ] += " The owned maintenance period is exactly 1,000,000,000 ns; its attempt duration retains the validated 1..30,000,000,000 ns interval. Both time.Duration arguments fit signed 64-bit without conversion or addition."
    if set(owners.values()) != set(families):
        v.reject("storage-numeric-proof-family")
    return {
        "limits": limits,
        "arithmetic": arithmetic,
        "families": families,
        "owners": owners,
        "guard_pairs": len(orders),
        "units": "bytes, entry counts, opaque unsigned versions, nanoseconds, Unicode scalars and native bit fields; no rescaling across domains",
    }


def expected(root: Path) -> list[dict]:
    """Specify ordered native witnesses from fixed mathematical ranges and literal public behavior, never a previous implementation output."""
    policy = manifest(root)
    rows = [
        {"kind": "representation", "int": 64, "version": 64, "duration": 64, "change_bytes": 56},
        {"kind": "runtime", "version": "go1.27.2", "files": policy["runtime_sources"]},
        {
            "kind": "defaults",
            "value": {
                "Scopes": 4096,
                "Records": 65536,
                "Bytes": 64 * 2**20,
                "Total": 256 * 2**20,
                "History": 1000,
                "Backlog": 8 * 2**20,
                "Timeout": 5_000_000_000,
                "WAL": 128 * 2**20,
            },
        },
    ]
    for name, minimum, maximum in FIELDS:
        for index, value in enumerate((-(2**63), -1, 0, minimum - 1, minimum, maximum, maximum + 1, 2**63 - 1)):
            rows.append({"kind": "limit", "field": name, "index": index, "input": value, "accepted": minimum <= value <= maximum})
    rows.extend(
        {"kind": "total", "bytes": size, "total": total, "accepted": total >= size}
        for size, total in ((1, 1), (1, 2), (2, 1), (2**30, 2**30), (2**30, 2**30 - 1))
    )
    rows.extend({"kind": "codec", "input": value, "hex": f"{value:016x}", "decoded": value} for value in reversed(VERSIONS))
    rows.extend({"kind": "ordered", "index": index, "version": value, "type": "blob", "bytes": 8} for index, value in enumerate(VERSIONS))
    rows.extend({"kind": "scan-rejection", "index": index, "retained": 2**64 - 1, "corrupt": True} for index in range(8))
    rows.extend(
        {"kind": "batch-count", "input": value, "accepted": value == 1, "entries": int(value == 1)}
        for value in (0, 1, 2, 2**31, 2**32, 2**32 + 1, 2**63, 2**64 - 1)
    )
    rows.extend({"kind": "batch-length", "input": value, "accepted": value == 0, "entries": int(value == 0)} for value in (0, 1, 2**20, 2**31, 2**32 - 1))
    for limit in (-(2**63), -1, 0, 1, 16 * 2**20, 16 * 2**20 + 1, 2**63 - 1):
        for items in (-(2**63), -1, 0, 1, 65536, 65537, 2**63 - 1):
            accepted = 1 <= limit <= 16 * 2**20 and 1 <= items <= 65536
            rows.append({"kind": "subscription", "limit": limit, "items": items, "accepted": accepted, "reserved": limit if accepted else 0})
    rows.extend({"kind": "budget", "count": count, "bytes": count * 16 * 2**20} for count in range(1, 9))
    for limit in (130, 131, 262):
        for items in (1, 2):
            capacity = min(items, limit // 131)
            for step in range(1, 4):
                accepted = step <= capacity
                rows.append(
                    {
                        "kind": "feed-cost",
                        "limit": limit,
                        "items": items,
                        "step": step,
                        "bytes": step * 131 if accepted else 0,
                        "queued": step if accepted else 0,
                        "refused": not accepted,
                    }
                )
    rows.extend(
        {"kind": "authority-version", "target": value, "version": value, "records": 1, "key": "k", "value": "v"}
        for value in (2**31 - 1, 2**31, 2**32 - 1, 2**32, 2**63 - 1, 2**63, 2**64 - 1)
    )
    rows.append({"kind": "batch-wide", "entries": 129, "last": "k128", "version": 17})
    return rows


def observations(data: bytes, check: dict, root: Path) -> dict[str, int]:
    """Require the full ordered native boundary transcript together with source/range proof, not aggregate green markers."""
    configuration(check)
    if check.get("numeric") == "storage-source-v1":
        return source_observations(data, check, root)
    bounds(root)
    rows = equality.frames(data, PACKAGE, test="TestNumeric", marker="STORAGE-NUMERIC ", maximum=256)
    if v.encode(rows) != v.encode(expected(root)):
        v.reject("storage-numeric-witnesses")
    return {"STORAGE-NUMERIC": HITS}


def source_observations(data: bytes, check: dict, root: Path) -> dict[str, int]:
    """Reconcile the complete typed denominator, original exports and every source range before giving inventory credit."""
    configuration(check)
    count, scanned, owners = revision(root)
    if check["probes"][1]["minimum_hits"] != count:
        v.reject("storage-numeric-source-configuration")
    policy = manifest(root)
    geometry = v.decode(v.read(root / DIRECTORY / "numeric-source.json"))
    if (
        not isinstance(geometry, dict)
        or set(geometry) != {"version", "scanned", "nodes", "sha256", "scopes"}
        or any(type(geometry[key]) is not int for key in ("version", "scanned", "nodes"))
        or geometry["version"] != 1
        or geometry["scanned"] != scanned
        or geometry["nodes"] != count
        or not isinstance(geometry["scopes"], dict)
        or any(type(value) is not int or value < 1 for value in geometry["scopes"].values())
    ):
        v.reject("storage-numeric-geometry-policy")
    rows = equality.frames(data, SOURCE_PACKAGE, test="TestStorageNumbers", marker="STORAGE-NUMERIC-SOURCE ", maximum=2048)
    if (
        not rows
        or not isinstance(rows[0], dict)
        or set(rows[0])
        != {
            "kind",
            "version",
            "source",
            "source_sha256",
            "os",
            "architecture",
            "runtime",
            "typing",
            "scanned",
            "nodes",
            "qualification",
        }
    ):
        v.reject("storage-numeric-source-header")
    header = rows[0]
    if (
        any(type(header[key]) is not int for key in ("version", "scanned", "nodes"))
        or header["kind"] != "header"
        or header["version"] != 1
        or header["scanned"] != geometry["scanned"]
        or header["nodes"] != count
        or (header["os"], header["architecture"], header["runtime"], header["qualification"]) != ("linux", "amd64", policy["runtime_version"], "not-evaluated")
    ):
        v.reject("storage-numeric-source-representation")
    expected_source = {
        "commit": None,
        "status": "",
        "files": [{"path": DIRECTORY + "/" + name, "sha256": digest} for name, digest in sorted(policy["sources"].items())],
    }
    if v.encode(header["source"]) != v.encode(expected_source) or header["source_sha256"] != v.digest(
        json.dumps(expected_source, separators=(",", ":"), ensure_ascii=False).encode()
    ):
        v.reject("storage-numeric-source-identity")
    typing = header["typing"]
    if not isinstance(typing, dict) or set(typing) != {"metadata_sha256", "package", "files", "inactive", "results", "constants", "exports"}:
        v.reject("storage-numeric-source-typing")
    active = [DIRECTORY + "/" + name for name in sorted(policy["sources"]) if name != "lock_other.go"]
    if (
        typing["package"] != PACKAGE
        or typing["files"] != active
        or typing["inactive"] != [DIRECTORY + "/lock_other.go"]
        or typing["results"] != {}
        or typing["constants"] != []
    ):
        v.reject("storage-numeric-source-selection")
    chunks, nodes, phase = [], [], "metadata"
    for row in rows[1:]:
        if not isinstance(row, dict):
            v.reject("storage-numeric-source-row")
        if row.get("kind") == "metadata" and phase == "metadata":
            if set(row) != {"kind", "index", "data"} or type(row["index"]) is not int or row["index"] != len(chunks):
                v.reject("storage-numeric-metadata-order")
            try:
                chunk = base64.b64decode(row["data"], validate=True)
            except (TypeError, ValueError):
                v.reject("storage-numeric-metadata-encoding")
            if not 0 < len(chunk) <= 4096 or chunks and len(chunks[-1]) != 4096:
                v.reject("storage-numeric-metadata-framing")
            chunks.append(chunk)
        elif row.get("kind") == "node":
            phase = "nodes"
            if set(row) != {"kind", "index", "value"} or type(row["index"]) is not int or row["index"] != len(nodes):
                v.reject("storage-numeric-node-order")
            nodes.append(row["value"])
        else:
            v.reject("storage-numeric-source-row")
    metadata = b"".join(chunks)
    if not metadata or len(metadata) > 32 * 1024**2 or v.digest(metadata) != typing["metadata_sha256"]:
        v.reject("storage-numeric-metadata-identity")
    try:
        text = metadata.decode("utf-8")
    except UnicodeError:
        v.reject("storage-numeric-metadata-encoding")
    packages, position = {}, 0
    decoder = json.JSONDecoder()
    while position < len(text):
        if text[position].isspace():
            position += 1
            continue
        try:
            _, end = decoder.raw_decode(text, position)
        except ValueError:
            v.reject("storage-numeric-metadata-json")
        package = v.decode(text[position:end].encode())
        if (
            not isinstance(package, dict)
            or not isinstance(package.get("ImportPath"), str)
            or not package["ImportPath"]
            or package["ImportPath"] in packages
            or package.get("Error") is not None
            or package.get("DepsErrors") not in (None, [])
            or package.get("Incomplete") is not None
            and type(package["Incomplete"]) is not bool
            or package.get("Incomplete") is True
        ):
            v.reject("storage-numeric-metadata-package")
        packages[package["ImportPath"]] = package
        position = end
    selected = packages.get(PACKAGE, {})
    if selected.get("GoFiles") != [Path(name).name for name in active] or selected.get("IgnoredGoFiles") != ["lock_other.go"] or selected.get("CgoFiles"):
        v.reject("storage-numeric-metadata-selection")
    if not isinstance(selected.get("Dir"), str):
        v.reject("storage-numeric-metadata-directory")
    directory = PurePosixPath(selected["Dir"])
    if not directory.is_absolute() or not str(directory).endswith("/" + DIRECTORY) or str(directory) != selected["Dir"] or ".." in directory.parts:
        v.reject("storage-numeric-metadata-directory")
    cache = directory.parents[2] / "build/cache/go"
    exports = typing["exports"]
    if not isinstance(exports, dict) or not exports or len(exports) > 4096:
        v.reject("storage-numeric-export-denominator")
    total = 0
    for name, item in exports.items():
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "bytes"} or type(item["bytes"]) is not int or not 0 < item["bytes"] <= 64 * 1024**2:
            v.reject("storage-numeric-export-shape")
        if not isinstance(item["path"], str) or not isinstance(item["sha256"], str):
            v.reject("storage-numeric-export-shape")
        path = PurePosixPath(item["path"])
        if (
            not path.is_relative_to(cache)
            or ".." in path.parts
            or item["path"] != packages.get(name, {}).get("Export")
            or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
        ):
            v.reject("storage-numeric-export-origin")
        total += item["bytes"]
    if total > 256 * 1024**2 or len(nodes) != count or v.digest(v.encode(nodes)) != geometry["sha256"]:
        v.reject("storage-numeric-source-denominator")
    observed, scopes, previous = set(), {}, None
    for node in nodes:
        if not isinstance(node, dict) or set(node) != {"file", "line", "column", "begin", "end", "scope", "kind", "type", "text"} or node["file"] not in active:
            v.reject("storage-numeric-node-shape")
        if any(type(node[key]) is not int for key in ("line", "column", "begin", "end")) or node["scope"] not in owners:
            v.reject("storage-numeric-node-scope")
        source = (root / node["file"]).read_bytes()
        begin, end = node["begin"], node["end"]
        if not 0 <= begin < end <= len(source) or source[begin:end].decode("utf-8") != node["text"]:
            v.reject("storage-numeric-node-position")
        if node["line"] != source[:begin].count(b"\n") + 1 or node["column"] != begin - source[:begin].rfind(b"\n"):
            v.reject("storage-numeric-node-coordinates")
        key = (node["file"], begin, end, node["kind"])
        if key in observed or previous is not None and key < previous:
            v.reject("storage-numeric-node-duplicate-or-order")
        observed.add(key)
        previous = key
        scopes[node["scope"]] = scopes.get(node["scope"], 0) + 1
    if scopes != geometry["scopes"] or set(scopes) != set(owners):
        v.reject("storage-numeric-scope-denominator")
    proof(root)
    return {"STORAGE-NUMERIC-CONTROLS": CONTROL_HITS, "STORAGE-NUMERIC-SOURCE": count}
