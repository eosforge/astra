"""Verify reached Storage shutdown histories against independently declared outcomes and complete source identity."""

from pathlib import Path

from tools import equality, storage_numeric, verify as v

HITS = 58
CASES = ("commit", "cancel", "feed")


def configuration(check: dict) -> None:
    """Require the full native Race selection, including every controlled lifecycle case."""
    if (
        check.get("model") != "storage-lifetime-v1"
        or check["component"] != "polaris-storage"
        or check["package"] != storage_numeric.PACKAGE
        or check["argv"]
        != ["go", "test", "-json", "-race", "-count=1", "-parallel=1", "-p=2", "-timeout=60s", "-run=^TestLifecycle$", "./polaris/internal/storage"]
        or check["expected_tests"] != ["TestLifecycle", *("TestLifecycle/" + mode for mode in CASES)]
        or v.encode(check["probes"]) != v.encode([{"contract": "STORAGE-LIFETIME", "test": "TestLifecycle", "minimum_hits": HITS}])
    ):
        v.reject("lifecycle-configuration")


def proof(root: Path) -> dict:
    """Bind actual lifecycle/notification ordering without claiming native I/O can always satisfy an arbitrary hard deadline."""
    policy = storage_numeric.manifest(root)
    source = {name: (root / storage_numeric.DIRECTORY / name).read_text(encoding="utf-8") for name in ("store.go", "commit.go", "read.go", "feed.go")}
    anchors = {
        "store.go": (
            "store.life.Lock()",
            "defer store.life.Unlock()",
            "store.closed = true",
            "store.notify.Lock()",
            "store.readSQL.Close()",
            "store.writeSQL.Close()",
            "store.file.Close()",
            "db, conn, err := session(ctx, store.writeSQL, store.write)",
            "defer conn.Close()",
            "tx := db.Begin()",
            "current.Statement.ConnPool = conn",
        ),
        "commit.go": (
            "store.life.RLock()",
            "defer store.life.RUnlock()",
            "if store.closed",
            "ctx, cancel := context.WithTimeout(ctx, store.limits.Timeout)",
            "case store.writer <- struct{}{}:",
            "case <-ctx.Done():",
            "defer func() { <-store.writer }()",
        ),
        "read.go": (
            "store.life.RLock()",
            "defer store.life.RUnlock()",
            "if store.closed",
            "defer cancel()",
            "session(ctx, store.readSQL, store.read)",
            "defer conn.Close()",
            "db.Transaction(read)",
        ),
        "feed.go": (
            "store.life.RLock()",
            "store.notify.Lock()",
            "feed.store.notify.Lock()",
            "feed.mutex.Lock()",
            "feed.stop(ErrClosed)",
            "delete(feed.store.feeds, feed)",
            "feed.queue = nil",
            "close(feed.changed)",
        ),
    }
    for name, values in anchors.items():
        if any(value not in source[name] for value in values):
            v.reject("lifecycle-source-order", name)
    close = source["store.go"].split("func (store *Store) Close() error {", 1)[1].split("// Changed", 1)[0]
    ordered = (
        "store.life.Lock()",
        "store.closed = true",
        "store.notify.Lock()",
        "feed.stop(ErrClosed)",
        "store.notify.Unlock()",
        "store.readSQL.Close()",
        "store.writeSQL.Close()",
        "store.file.Close()",
    )
    maintenance = "maintenance.go" in policy["sources"]
    if maintenance:
        ordered = ordered[:-3] + ("store.cancel()", "<-store.done") + ordered[-3:]
    positions = [close.index(anchor) for anchor in ordered]
    if positions != sorted(positions):
        v.reject("lifecycle-source-order", "Close")
    return {
        "sources": policy["sources"],
        "locks": "Lifecycle borrow/exclusive close precedes notification ownership; notification precedes feed mutex. Take/Ready do not acquire notification ownership while holding the feed mutex.",
        "admission": "Valid later Commit/CommitBatch, List/Version/Load/Since and Subscribe calls share their lifecycle guard; readonly Limits and terminal Changed/Feed methods retain their documented independent semantics.",
        "drain": "Each admitted transaction retains an explicit SQL connection until its actual finalization returns, including asynchronous cancellation rollback. Close joins lifecycle borrows before notifying feeds and closing pools/file. "
        + (
            "It cancels and joins its sole maintenance task after notification release and before pool destruction; that task never takes the lifecycle lock. "
            if maintenance
            else "This component starts no independent worker; "
        )
        + "database/sql and SQLite retain their native dependency obligations.",
        "boundary": "Three reached native Race schedules only, with context/lock observations that do not supply production synchronization. This is not the complete lifecycle/fault matrix, forced-process death, hardware I/O progress or containing-service shutdown qualification.",
    }


def expected(mode: str) -> dict:
    """Derive allowed durable versions from the declared commit/cancel boundary, never current implementation output."""
    if mode not in CASES:
        v.reject("lifecycle-case")
    committed = mode == "commit"
    return {
        "mode": mode,
        "late": 0 if mode == "feed" else 3,
        "queued_cancelled": mode != "feed",
        "drained": True,
        "version": int(committed),
        "records": 2 * int(committed),
    }


def observations(data: bytes, check: dict, root: Path) -> dict[str, int]:
    """Require each reached wait, cancelled admission, complete shutdown and recovered durable outcome."""
    configuration(check)
    proof(root)
    groups = {"TestLifecycle/" + mode: [] for mode in CASES}
    for line in data.splitlines():
        event = v.decode(line)
        if not isinstance(event, dict):
            v.reject("lifecycle-event")
        text = event.get("Output", "")
        if not isinstance(text, str):
            v.reject("lifecycle-output")
        if "STORAGE-LIFETIME " not in text:
            continue
        name = event.get("Test")
        if event.get("Action") != "output" or event.get("Package") != check["package"] or name not in groups:
            v.reject("lifecycle-attribution")
        groups[name].append(line)
    for mode in CASES:
        name = "TestLifecycle/" + mode
        rows = equality.frames(b"\n".join(groups[name]) + b"\n", check["package"], test=name, marker="STORAGE-LIFETIME ", maximum=1)
        if v.encode(rows) != v.encode([expected(mode)]):
            v.reject("lifecycle-native-history", mode)
    return {"STORAGE-LIFETIME": HITS}
