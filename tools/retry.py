"""Reconcile authority retry intent against literal public contracts and complete source identity."""

from pathlib import Path
import re

from tools import equality, storage_numeric, verify as v

HITS = 176
CASES = ("identical", "nil-empty", "explicit-entry-version", "changed-byte", "changed-key", "empty-to-delete", "reordered", "omitted", "additional")
FINALIZATION = ("begin", "commit-before", "commit-after", "commit-cancel", "rollback-after", "cancel-record")
RECOVERY_SOURCES = {
    "transaction_test.go": "b35f1c8ba7a9e59c0c6b90005ff326f8ac99dd5d9b7bbc500d8fee8794946eda",
    "crash_test.go": "1a9dd27c6e7acca542e95154d7c14fd75c68c9520fe917bb6fe63d70c8c6a8f0",
    "io_linux_amd64_test.go": "a6cedd4618beb11e9f609a7a3022f121f2699dd2b485be90a7c0e06b64d9203e",
}


def requirements() -> list[dict]:
    """Keep the complete owned retry rule's original coordinate and all its independently required boundaries."""
    return [
        {"rule": rule, "contract": contract, "scenario": scenario}
        for rule, contract, scenario in (
            ("DEV-CONTRACT", "STORAGE-ATOMIC", "bounded-example"),
            ("DEV-RETRY", "STORAGE-RETRY", "bounded-example"),
            ("DEV-RETRY", "STORAGE-RETRY-IDENTITY", "intent-window-grid"),
            ("DEV-FAULT", "STORAGE-ROLLBACK", "bounded-example"),
            ("DEV-COMPAT", "STORAGE-HISTORY", "bounded-example"),
            ("DEV-ORACLE", "STORAGE-FINITE", "two-key-finite-model"),
            ("DEV-MODEL", "STORAGE-SCHEDULE", "two-writer-pair-histories"),
            ("DEV-ORACLE", "STORAGE-ORACLE", "fixed-journal-axioms"),
            ("DEV-MODEL", "STORAGE-ASSURANCE", "finite-model"),
            ("DEV-FAULT", "STORAGE-FINALIZE", "transaction-finalization"),
            ("DEV-FAULT", "STORAGE-PANIC", "transaction-panic"),
            ("DEV-FAULT", "STORAGE-CRASH", "process-death"),
            ("DEV-FAULT", "STORAGE-CORRUPTION", "persisted-corruption"),
            ("DEV-CONTRACT", "STORAGE-READ", "read-boundaries"),
            ("DEV-FAULT", "STORAGE-WRITE-FAULT", "write-preparation"),
            ("DEV-FAULT", "STORAGE-WRITE-DAMAGE", "write-accounting-rejection"),
            ("DEV-FAULT", "STORAGE-BOUNDARY", "public-resource-boundaries"),
            ("DEV-FAULT", "STORAGE-RETAIN-SCAN", "retained-prefix-type"),
            ("DEV-FAULT", "STORAGE-CHECKPOINT", "wal-checkpoint"),
            ("DEV-FAULT", "STORAGE-BOUNDARY", "native-wal-write-sync"),
            ("DEV-NUMERIC", "STORAGE-ASSURANCE", "full-rule"),
        )
    ]


def recovery_configuration(check: dict) -> None:
    """Bind complete native recovery witnesses to either the full package or its real WAL selection."""
    mode = check.get("recovery")
    full = mode == "storage-recovery-v1"
    command = (
        ["go", "test", "-json", "-count=1", "-parallel=4", "-p=4", "-timeout=180s", "./polaris/internal/storage"]
        if full
        else ["go", "test", "-json", "-count=1", "-p=2", "-timeout=120s", "-run", "^TestNativeIO$", "./polaris/internal/storage"]
    )
    required = {
        ("TestNativeIO/write", "STORAGE-BOUNDARY"): 18,
        ("TestNativeIO/sync", "STORAGE-BOUNDARY"): 18,
    }
    if full:
        required.update({("TestFinalization", "STORAGE-FINALIZE"): 200, ("TestCrash", "STORAGE-CRASH"): 1})
    probes = {(item["test"], item["contract"]): item["minimum_hits"] for item in check.get("probes", [])}
    if (
        mode not in {"storage-recovery-v1", "storage-wal-v1"}
        or check.get("adapter") != "go-test-json"
        or check.get("component") != "polaris-storage"
        or check.get("package") != storage_numeric.PACKAGE
        or check.get("argv") != command
        or not {"TestNativeIO", "TestNativeIO/write", "TestNativeIO/sync"} <= set(check.get("expected_tests", []))
        or any(probes.get(key) != count for key, count in required.items())
        or full
        and not {"TestFinalization", "TestCrash"} <= set(check.get("expected_tests", []))
    ):
        v.reject("retry-recovery-configuration")


def recovery(data: bytes, check: dict, root: Path) -> dict[str, int]:
    """Require each actual injection/reopen/death boundary, rather than infer fault completeness from an assertion total."""
    recovery_configuration(check)
    proof(root)
    for name, digest in RECOVERY_SOURCES.items():
        if v.file_digest(root / storage_numeric.DIRECTORY / name) != digest:
            v.reject("retry-recovery-source", name)
    full = check["recovery"] == "storage-recovery-v1"
    expected = {"TestNativeIO/" + point: [point, point] for point in ("write", "sync")}
    if full:
        expected.update({"TestFinalization/" + point: [1, 2] for point in FINALIZATION})
        expected.update({"TestCrash/" + point: [point] for point in ("prefix", "prepared", "durable")})
    observed = {key: [] for key in expected}
    prefix = r"\s*(?:[^\n]+\.go:\d+: )?"
    patterns = (
        ("finalization=", re.compile(prefix + r"finalization=([a-z-]+) attempt=([12]) injected=1 reached=1 reopened=verified\n")),
        ("crash-point=", re.compile(prefix + r"crash-point=([a-z]+) reached=1 signal=SIGKILL reaped=1 recovery=verified retry=verified\n")),
        ("STORAGE-IO point=", re.compile(prefix + r"STORAGE-IO point=([a-z]+) native_errors=1 uncertain=1 atomic=1 retry=1 retained=0\n")),
    )
    for line in data.splitlines():
        event = v.decode(line)
        text = event.get("Output", "") if isinstance(event, dict) else ""
        if not isinstance(text, str):
            v.reject("retry-recovery-output")
        for marker, pattern in patterns:
            if marker not in text:
                continue
            match = pattern.fullmatch(text)
            name = event.get("Test")
            if event.get("Action") != "output" or event.get("Package") != check["package"] or match is None or name not in observed:
                v.reject("retry-recovery-witness")
            point = match.group(1)
            if not name.endswith("/" + point):
                v.reject("retry-recovery-attribution")
            observed[name].append(int(match.group(2)) if marker == "finalization=" else point)
            if len(observed[name]) > len(expected[name]):
                v.reject("retry-recovery-duplicate")
    if v.encode(observed) != v.encode(expected):
        v.reject("retry-recovery-incomplete")
    return {"finalization_attempts": 12 if full else 0, "crash_points": 3 if full else 0, "wal_attempts": 4}


def configuration(check: dict) -> None:
    """Require the complete native retry selection and independently fixed exposure budget."""
    if (
        check.get("model") != "storage-retry-v1"
        or check["component"] != "polaris-storage"
        or check["package"] != storage_numeric.PACKAGE
        or check["argv"]
        != ["go", "test", "-json", "-count=1", "-parallel=1", "-p=2", "-timeout=180s", "-run=^TestRetryIdentity$", "./polaris/internal/storage"]
        or check["expected_tests"] != ["TestRetryIdentity"]
        or v.encode(check["probes"]) != v.encode([{"contract": "STORAGE-RETRY-IDENTITY", "test": "TestRetryIdentity", "minimum_hits": HITS}])
    ):
        v.reject("retry-configuration")


def proof(root: Path) -> dict:
    """Pin each deduplication dimension and the commit/notification ordering without asserting external exactly-once effects."""
    identity = storage_numeric.manifest(root)
    source = {
        name: (root / storage_numeric.DIRECTORY / name).read_text(encoding="utf-8") for name in ("commit.go", "batch.go", "store.go", "model.go", "schema.go")
    }
    required = {
        "commit.go": (
            'Where("sector=? AND spectrum=? AND version=?", scope.Sector, scope.Spectrum, expected.Version)',
            "actual.Key != expected.Key || actual.Erase != expected.Erase || !bytes.Equal(actual.Value, expected.Value)",
            "if change.Version <= state.Version",
            "return confirm(tx, scope, change)",
            "applied := false",
            "if applied",
            "if err != nil",
            "event.Value = bytes.Clone(change.Value)",
            "ctx, cancel := context.WithTimeout(ctx, store.limits.Timeout)",
            "case store.writer <- struct{}{}:",
            "case <-ctx.Done():",
            "return 0, ctx.Err()",
        ),
        "batch.go": ('data := []byte("AB02")', "for _, change := range changes", "change.Version != 0 && change.Version != version", "seen[change.Key]"),
        "store.go": ("if store.poisoned.Load()", "return ErrUncertain", "store.poisoned.Store(true)", "tx.Commit().Error"),
        "model.go": ("binary.BigEndian.AppendUint64(nil, uint64(version))",),
        "schema.go": ("meta.Galaxy != binding.Galaxy || meta.Username != binding.Username || meta.Advertise != binding.Advertise", "return ErrBinding"),
    }
    for name, anchors in required.items():
        if any(anchor not in source[name] for anchor in anchors):
            v.reject("retry-source-boundary", name)
    if source["commit.go"].index("return confirm(tx, scope, change)") >= source["commit.go"].index("previous := state.Bytes"):
        v.reject("retry-before-mutation")
    return {
        "sources": identity["sources"],
        "identity": "deployment-bound database, Scope, authority version and complete ordered normalized key/erase/value bytes",
        "window": "transactional retained history; zero/evicted evidence yields ErrUncertain, never inferred success from current values",
        "receipt": "retained identical intent confirms the original version; conflicting retained intent yields ErrVersion; no notifications or accounting change",
        "unknown": "COMMIT failure returns no receipt and poisons writes until reopen validates durable old-or-committed state",
        "admission": "One bounded writer admission and one transaction attempt per call; caller cancellation/configured timeout does not confirm nonexecution. No automatic mutating retry, backoff or asynchronous attempt owner exists in this component.",
        "boundary": "Storage does not automatically retry, bind transport principal identity or own cross-system effects. Network authentication and retry/backoff budgets remain caller obligations.",
    }


def expected() -> list[dict]:
    """Derive the entire declared identity/window grid from public request intent, not production comparisons."""
    rows = []
    for mode in ("retained", "evicted", "disabled"):
        for name in CASES:
            confirmed = mode == "retained" and name in CASES[:3]
            rows.append(
                {
                    "mode": mode,
                    "case": name,
                    "result": "confirmed" if confirmed else "conflict" if mode == "retained" else "uncertain",
                    "version": int(confirmed),
                    "unchanged": True,
                    "published": 0,
                }
            )
        rows.extend({"mode": mode, "scope": index, "version": 1, "records": 2, "published": 1} for index in range(2))
    return rows


def observations(data: bytes, check: dict, root: Path) -> dict[str, int]:
    """Require every actual retained/expired intent and scope-isolation row; scalar markers alone cannot qualify retries."""
    configuration(check)
    proof(root)
    rows = equality.frames(data, check["package"], test="TestRetryIdentity", marker="STORAGE-RETRY-IDENTITY ", maximum=33)
    if v.encode(rows) != v.encode(expected()):
        v.reject("retry-native-intent-grid")
    return {"STORAGE-RETRY-IDENTITY": HITS}
