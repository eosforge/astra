"""Reconcile native statements, Boolean outcomes and controls for explicitly reviewed Go domains."""

import argparse
import base64
import ctypes
import os
from pathlib import Path
import re
import shutil
import signal
import sys

# Script execution and imported adapters share the same project validator and exception types.
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from tools import admission, defenses, flow, logic, statements, verify as v, watchdog

# Native AST geometry is frozen independently of observed hits, including literal returns and every control arm.
FOREST = "8568d32770df04c8ad4cc58b724491501cb40a0a7e5a6272ef31a05970b95a2e"
EDGES = "478b71c16152171f5629f5a4857050c1cb0ed538801f614111ef7a0acb8862eb"
DEPENDENCIES = {**defenses.DEPENDENCIES, "encoding/json/stream.go": "065501364e4954cf1c8f1887900248d4c0983593b8c058b2fe7997d9635b793d"}
# This adapter qualifies one ordinary Linux build; Race and MC/DC keep separate obligations.
PACKAGE = "internal/admission"
PLATFORM = "linux-amd64-cgo"
# Each entry names one impossible atom outcome, not a waiver for the containing decision or function.
ASSUMPTIONS = (
    ("internal/admission/identity.go:2561", 1, True, "parsed-chain"),
    ("internal/admission/identity.go:2854", 0, True, "parsed-leaf"),
    ("internal/admission/identity.go:4042", 1, False, "object-key"),
    ("internal/admission/identity.go:4397", 1, True, "object-close"),
    ("internal/admission/node.go:1424", 0, True, "validated-directory"),
    ("internal/admission/node.go:1521", 0, True, "random-return"),
)
REASONS = {
    **{item["id"]: {key: item[key] for key in ("assumption", "invalidated_by")} for item in defenses.DEFENSES},
    "parsed-chain": {
        "assumption": "Successful pinned tls.X509KeyPair requires a nonempty privately owned certificate chain; the second operand runs only after success.",
        "invalidated_by": "Changed TLS behavior, changed ownership or mutation of the certificate slice, or memory corruption.",
    },
    "object-key": {
        "assumption": "After the verified object opener and More, a successful pinned Decoder.Token at the key position returns a string; the complete preceding value was consumed.",
        "invalidated_by": "Changed JSON token state machine, different call ordering, concurrent decoder access or memory corruption.",
    },
    "object-close": {
        "assumption": "After the object value loop ends, the pinned Decoder.Token returns the matching closing object delimiter or an error; short circuit skips comparison on error.",
        "invalidated_by": "Changed JSON token state machine, different call ordering, concurrent decoder access or memory corruption.",
    },
}
# Storage's native inventory includes its inactive platform file, never imaginary Linux hits for that file.
STORAGE = "polaris/internal/storage"
STORAGE_DEPENDENCIES = {
    "database/sql/sql.go": "5d5ec3cd3519e1d4a388a372e29ddeaedea45dde86845cb4e9002a5ef52f27f0",
    "database/sql/driver/driver.go": "bfcb06efe2ddb37d4514a82aca26a23208f83b4e42b5a54114589982ce7e07b0",
    "sqlite/sqlite3.go": "1e1ecd7e523bc587aa7bdc4119b470b61f51aff913e4cc4856075df0af3bd2f2",
}
STORAGE_ASSUMPTIONS = (
    (STORAGE + "/commit.go:2317", 0, True, "version-dominated"),
    (STORAGE + "/schema.go:7432", 2, True, "cursor-completion"),
)
STORAGE_REASONS = {
    "version-dominated": {
        "assumption": "The preceding uint64 change.Version <= state.Version guard returns first; the unchanged locked state at MaxUint64 cannot reach this comparison.",
        "invalidated_by": "Changed version representation, guard order, argument ownership, state synchronization or memory corruption.",
    },
    "cursor-completion": {
        "assumption": "The pinned SQLite cursor has no RowsNextResultSet. Pinned Rows.Next closes on EOF/error, Err retains finalization failure and a subsequent Close is idempotent. Earlier true operands skip this atom.",
        "invalidated_by": "Changed database/sql or SQLite behavior, native method set, cursor ordering, concurrent access or memory corruption. TestCursorCompletion includes a result-set driver countercontrol.",
    },
}
# The server's private send path is reachable only after successful concrete admission verification.
SERVER = "polaris/internal/server"
ENTRY = "polaris"
ASTROLABE = "astrolabe"
SERVER_DEPENDENCIES = {
    "astra/internal/admission/directory.go": "935437c56a04d51978c2d2508b0c09b8f1dc51f03e58a6af089f926858ec068b",
    "astra/internal/admission/identity.go": "37e195bcb9412502763e761740705d08e4ec57cd038d911f13068a97ec6e3612",
}
SERVER_ASSUMPTIONS = ((SERVER + "/stream.go:9185", 0, False, "authenticated-send"),)
SERVER_REASONS = {
    "authenticated-send": {
        "assumption": "Open owns the private transfer; its sole protocol worker reaches send only after run assigns the concrete Directory.Verify result and rejects errors. Identity.Verify returns its new Member only on success. No later production assignment clears remote; Directory retains a clone, not that pointer slot.",
        "invalidated_by": "Changed server call graph, entry points, pointer ownership or assignment; changed concrete Directory/Identity verification; test-only bypasses presented as production reachability; data races or memory corruption. No observed false outcome is claimed.",
    },
}


def domain(package: str = PACKAGE, *, legacy: bool = False, acquisition: bool = False, structural: bool = False) -> dict:
    """Select a fixed reviewed scope; package strings cannot invent or reduce the qualification denominator."""
    if acquisition and (legacy or package != PACKAGE):
        v.reject("structure-source-revision")
    if structural and package != ASTROLABE:
        v.reject("structure-package")
    if package == ENTRY:
        return {"adapter": "polaris-entry-qualification", "component": "polaris-server", "contract": "POLARIS_SERVER-ASSURANCE", "counts": [135, 37, 53, 7]}
    if package == ASTROLABE:
        if structural:
            return {"adapter": "astrolabe-structure", "component": "astrolabe", "contract": "ASTROLABE-ASSURANCE", "counts": [818, 361, 715, 73]}
        # The observation unit is a supported condition; source exclusions never add hits.
        return {"adapter": "astrolabe-independence", "component": "astrolabe", "contract": "ASTROLABE-ASSURANCE", "counts": [334]}
    if package == PACKAGE:
        scope = {
            "adapter": "admission-structure",
            "component": "admission",
            "contract": "ADMISSION-ASSURANCE",
            "counts": [277, 154, 355, 28] if legacy else [279, 156, 355, 28],
            "forest": FOREST if legacy else "b2ad906de19a3e400e3a07f9d0e45962df8bb504c9d58be050579b7bdd420fe1",
            "edges": EDGES if legacy else "b8e43be513afe68ad54fac552358191f914b58d84bbad224262a09ab1504d659",
            "dependencies": DEPENDENCIES,
            "assumptions": ASSUMPTIONS,
            "reasons": REASONS,
            "inactive": [],
            "processes": 2,
        }
        if acquisition:
            scope.update(
                counts=[286, 158, 357, 28],
                forest="44d12fa13ee8efe06e2f4de3a5a890c87d3cb686407580b2a6fc37ee8d045aca",
                edges="667606893caf3a6ff3247f29f57a6584c1c71397c1c6bf26696fdb986b7a49b7",
                inactive=["internal/admission/file_other.go"],
                assumptions=(
                    ("internal/admission/identity.go:2750", 1, True, "parsed-chain"),
                    ("internal/admission/identity.go:3043", 0, True, "parsed-leaf"),
                    ("internal/admission/identity.go:4231", 1, False, "object-key"),
                    ("internal/admission/identity.go:4586", 1, True, "object-close"),
                    *ASSUMPTIONS[4:],
                ),
            )
        return scope
    if package == STORAGE:
        return {
            "adapter": "storage-structure",
            "component": "polaris-storage",
            "contract": "STORAGE-ASSURANCE",
            "counts": [622, 317, 553, 34],
            "forest": "271038167a5a2a54fc7555b33eabea7ad7012e3ae8b41e92c46694dd1d73ec93",
            "edges": "b17b139cd3f097e917b087785f173a666b557adef4d8e8bd3ca11bc5d3e546ce",
            "dependencies": STORAGE_DEPENDENCIES,
            "assumptions": STORAGE_ASSUMPTIONS,
            "reasons": STORAGE_REASONS,
            "inactive": [STORAGE + "/lock_other.go"],
            "processes": 32,
            "profile": "0b070730781e6392658d0d4663179ea72eb44fd20050013e154a3f23c54ad39b",
        }
    if package == SERVER:
        return {
            "adapter": "server-structure",
            "component": "polaris-server",
            "contract": "POLARIS_SERVER-ASSURANCE",
            "counts": [648, 325, 424, 93],
            "forest": "76977ed7af60786d8cd6b50568ba9ee5fc37e95e73436997588e979edf78b6ec",
            "edges": "567854632340336fba716c2fcec6adc8e87b70624fcb046a1fff8bde861cbfdf",
            "dependencies": SERVER_DEPENDENCIES,
            "assumptions": SERVER_ASSUMPTIONS,
            "reasons": SERVER_REASONS,
            "inactive": [],
            "processes": 1,
            "profile": "a14dfe8a43e6eb7f34b23bf3a68738a5405fff07660889b2efebdb113b143155",
        }
    v.reject("structure-package")


def revision(root: Path, package: str) -> dict:
    """Select reviewed geometry by exact source bytes; reconciliation still validates the full inventory."""
    if package == STORAGE:
        from tools import idle

        if idle.current(root):
            return {**domain(STORAGE), **idle.GEOMETRY}
    if package == SERVER and v.file_digest(root / SERVER / "authority.go") == "76348643eb6b779fe7bd42fb2e438439d247367739c7a523b898ff872dbbc481":
        from tools import ingress

        return {**domain(SERVER), "counts": ingress.COUNTS, "forest": ingress.FOREST, "edges": ingress.EDGES, "profile": ingress.PROFILE}
    acquisition = package == PACKAGE and admission.matches(root, "internal/admission/identity.go", admission.MATERIAL)
    legacy = package == PACKAGE and not acquisition and v.file_digest(root / "internal/admission/node.go") == admission.SOURCES["internal/admission/node.go"]
    return domain(package, legacy=legacy, acquisition=acquisition)


def selection(check: dict) -> str:
    """Bind each named adapter to its sole package without accepting caller-chosen paths."""
    if check.get("adapter") == "polaris-entry-qualification":
        return ENTRY
    if check.get("adapter") in {"astrolabe-independence", "astrolabe-structure"}:
        return ASTROLABE
    if check.get("adapter") in {"admission-structure", "admission-independence"}:
        return PACKAGE
    if check.get("adapter") == "storage-structure":
        return STORAGE
    if check.get("adapter") in {"server-structure", "server-independence"}:
        return SERVER
    v.reject("structure-adapter")


def storage_counters(profile: bytes, root: Path, trace: dict, *, package: str = STORAGE, compiler: str = "1.27.1") -> dict:
    """Keep all original compiler blocks and weights for domains with no unexecuted-statement exclusions."""
    if package not in (STORAGE, SERVER):
        v.reject("structure-profile-package")
    scope = revision(root, package)
    names = {item["file"]: item["sha256"] for item in trace["files"]}
    actual = {p.relative_to(root).as_posix() for p in (root / package).rglob("*.go") if not p.name.endswith("_test.go")}
    if actual != set(names):
        v.reject("structure-storage-source-scope")
    files = {}
    for name, digest in names.items():
        data = v.read(v.inside(root, name))
        if v.digest(data) != digest:
            v.reject("structure-storage-source-drift", name)
        if name not in scope["inactive"]:
            files[name] = {"data": data}
    selected = {"github.com/eosforge/astra/" + name: name for name in files}
    mode, blocks, records = statements.profile(profile, files, selected)
    shape = [{key: block[key] for key in ("file", "span", "statements")} for block in blocks]
    weights = None
    if compiler == "1.27.2" and package == STORAGE:
        from tools import profileweights

        weights = profileweights.reconcile(root, package, blocks)
        valid = weights["shape_sha256"]["1.27.1"] == scope["profile"]
    elif compiler == "1.27.1":
        valid = v.digest(v.encode(shape)) == scope["profile"]
    else:
        v.reject("structure-profile-compiler")
    if mode != "atomic" or records != len(blocks) or not valid:
        v.reject("structure-storage-profile-denominator")
    raw, hit = sum(b["statements"] for b in blocks), sum(b["statements"] for b in blocks if b["count"])
    missing = [b for b in blocks if b["statements"] and not b["count"]]
    result = {
        "sources": names,
        "profiles": [{"bytes": len(profile), "sha256": v.digest(profile)}],
        "mode": mode,
        "raw": {"blocks": len(blocks), "statements": raw, "statements_hit": hit},
        "reachable_under_assumptions": {"statements": raw, "statements_hit": hit},
        "unhit": missing,
        "unexplained": missing,
        "defenses": [],
    }
    if weights is not None:
        result["compiler_weights"] = weights
    return result


def boolean(decisions: dict, rows: dict, assumptions: tuple) -> dict:
    """Keep every original outcome; separate literal impossibility, conditional reasoning and missing observations.

    Inputs are validated native trees/receipts. A missing outcome is never its own infeasibility proof.
    """
    excluded = {}
    for identity, index, outcome, reason in assumptions:
        decision = decisions.get(identity)
        key = (identity, index, outcome)
        if not decision or type(index) is not int or not 0 <= index < len(decision["atoms"]) or type(outcome) is not bool or key in excluded:
            v.reject("structure-assumption-domain")
        excluded[key] = reason
    roots, atoms, missing = [], [], []
    for identity, decision in decisions.items():
        actual = rows[identity]
        literal = decision["kind"] == "return" and decision["text"] in {"true", "false"}
        for index in [None, *range(len(decision["atoms"]))]:
            observed = {result for _, result in actual} if index is None else {vector[index] == "2" for vector, _ in actual if vector[index] != "0"}
            impossible, conditional = [], []
            for outcome in (False, True):
                if literal and outcome != (decision["text"] == "true"):
                    impossible.append(outcome)
                else:
                    # A single atom is the whole decision only when its tree is exactly that atom, without negation.
                    leaf = index if index is not None else 0 if decision["tree"] == [{"kind": "atom", "atom": 0}] else None
                    reason = excluded.get((identity, leaf, outcome)) if leaf is not None else None
                    if reason:
                        conditional.append({"outcome": outcome, "reason": reason})
            forbidden = set(impossible) | {item["outcome"] for item in conditional}
            if observed & forbidden:
                v.reject("structure-assumption-contradicted", identity)
            absent = sorted({False, True} - observed - forbidden)
            item = {
                "id": identity,
                "atom": index,
                "observed": sorted(observed),
                "literal_impossible": impossible,
                "conditional": conditional,
                "missing": absent,
            }
            (roots if index is None else atoms).append(item)
            if absent:
                missing.append({"id": identity, "atom": index, "outcomes": absent})

    def totals(items: list) -> dict:
        """Calculate raw and qualified denominators independently of the success label."""
        raw = 2 * len(items)
        literal = sum(len(item["literal_impossible"]) for item in items)
        conditional = sum(len(item["conditional"]) for item in items)
        return {
            "raw": raw,
            "observed": sum(len(item["observed"]) for item in items),
            "literal_impossible": literal,
            "conditional": conditional,
            "reachable_under_assumptions": raw - literal - conditional,
        }

    return {"roots": roots, "atoms": atoms, "totals": {"roots": totals(roots), "atoms": totals(atoms)}, "missing": missing}


def controls(report: dict) -> dict:
    """Require finite-loop body/exhaustion and every select arm, retaining zero-iteration diagnostics separately."""
    items, missing = [], []
    for edge in report["edges"]:
        kind, vectors = edge["kind"], edge["vectors"]
        required = ["selected"] if kind in flow.ARMS else ["body"] if kind == "loop" else ["body", "exhausted"]
        observed = []
        if kind in flow.ARMS:
            if "2" in vectors:
                observed.append("selected")
        else:
            if any(vector.startswith("2") for vector in vectors):
                observed.append("body")
            if kind != "loop" and any(vector.endswith("2") for vector in vectors):
                observed.append("exhausted")
        absent = [name for name in required if name not in observed]
        items.append({"id": edge["id"], "kind": kind, "required": required, "observed": observed, "missing": absent})
        if absent:
            missing.append({"id": edge["id"], "outcomes": absent})
    return {
        "items": items,
        "required": sum(len(item["required"]) for item in items),
        "observed": sum(len(item["observed"]) for item in items),
        "missing": missing,
        "without_empty": report["without_empty"],
        "basis": "Finite-loop false is exhaustion, whether before or after iterations. Unconditional loops require entry, not invented false edges. This does not establish liveness.",
    }


def reconcile(
    *,
    root: Path,
    source_sha256: str,
    tests: list[str],
    profiles: tuple[bytes, ...],
    dependency: dict[str, bytes],
    trace: dict,
    boolean_events: bytes,
    control: dict,
    control_events: bytes,
    package: str = PACKAGE,
    compiler: str = "1.27.1",
) -> dict:
    """Recompute one same-source structural ledger from raw inputs, without accepting precomputed summaries.

    The enclosing collector must also verify native commands, compiler selection, overlays and provenance.
    This report does not grant gate, MC/DC, performance, race or release qualification.
    """
    acquisition = package == PACKAGE and admission.matches(root, "internal/admission/identity.go", admission.MATERIAL)
    if package == PACKAGE:
        defenses.sources(root, acquisition=acquisition)
    # Historical geometry remains readable only with its original exact source, never as current coverage.
    scope = revision(root, package)
    if set(dependency) != set(scope["dependencies"]):
        v.reject("structure-dependency-scope")
    for name, digest in scope["dependencies"].items():
        if not isinstance(dependency[name], bytes) or v.digest(dependency[name]) != digest:
            v.reject("structure-dependency-drift", name)
    decisions = logic.inventory(trace)
    flow.inventory(control, root, source_sha256)
    if (
        trace["version"] != 2
        or trace["source_sha256"] != source_sha256
        or trace["files"] != control["files"]
        or v.digest(v.encode(trace["files"])) != scope["forest"]
        or v.digest(v.encode(control["edges"])) != scope["edges"]
        or trace["typing"]["inactive"] != scope["inactive"]
        or trace["typing"]["constants"]
        or set(trace["observed"]) != decisions.keys()
    ):
        v.reject("structure-inventory-binding")
    if (
        not isinstance(tests, list)
        or not tests
        or any(not isinstance(name, str) or not name.startswith(("Test", "Fuzz") if package == STORAGE else ("Test",)) for name in tests)
        or len(tests) != len(set(tests))
    ):
        v.reject("structure-test-inventory")
    traced_tests = tests + sorted(watchdog.TESTS) if package == SERVER else tests
    for raw, selected, scheduled in ((boolean_events, traced_tests, package == SERVER), (control_events, tests, False)):
        if not isinstance(raw, bytes) or len(raw) > statements.LIMIT:
            v.reject("structure-stream-size")
        terminals(raw, selected, package=package, schedule=scheduled)
    native_package = "github.com/eosforge/astra/" + package
    rows, processes = logic.observe(trace, boolean_events, native_package, len(traced_tests))
    completion = flow.summary(control, control_events, native_package, len(tests), root, source_sha256)
    # Each campaign requires both the test process and the isolated resolver child, even if hit unions coincide.
    if processes != scope["processes"] or completion["processes"] != scope["processes"]:
        v.reject("structure-process-completeness")
    if len(profiles) != (2 if package == PACKAGE else 1):
        v.reject("structure-profile-scope")
    counters = (
        defenses.reconcile(*profiles, root, {name: dependency[name] for name in defenses.DEPENDENCIES}, acquisition=acquisition, compiler=compiler)
        if package == PACKAGE
        else storage_counters(profiles[0], root, trace, package=package, compiler=compiler)
    )
    outcomes = boolean(decisions, rows, scope["assumptions"])
    branches = controls(completion)
    missing = bool(counters["unexplained"] or outcomes["missing"] or branches["missing"])
    return {
        "version": 1,
        "status": "incomplete" if missing else "complete-under-assumptions",
        "qualification": "not-evaluated",
        "source_sha256": source_sha256,
        "statements": counters,
        "boolean": outcomes,
        "controls": branches,
        "assumptions": scope["reasons"],
        "dependencies": {name: {"bytes": len(data), "sha256": v.digest(data)} for name, data in dependency.items()},
        "inputs": {
            "trace_sha256": v.digest(v.encode(trace)),
            "control_sha256": v.digest(v.encode(control)),
            "boolean_events_sha256": v.digest(boolean_events),
            "control_events_sha256": v.digest(control_events),
        },
        "basis": "Separate native statement, root/short-circuit-atom and loop/select outcome denominators. Literal and dependency-conditioned impossibility never create hits. Counts are not MC/DC or a whole-component gate decision.",
    }


def configuration(check: dict, *, retained: bool = False) -> None:
    """Freeze the named adapter, native test inventory, offline settings and observation unit."""
    package = selection(check)
    # Archived declarations remain readable; reconciliation enforces the exact source's denominator.
    acquisition = check.get("adapter") == "admission-structure" and check.get("probes") == [
        {"contract": "ADMISSION-ASSURANCE", "test": "structure", "minimum_hits": 829}
    ]
    structural = check.get("adapter") == "astrolabe-structure"
    scope = domain(package, acquisition=acquisition, structural=structural)
    maintenance = False
    if package == STORAGE:
        from tools import idle

        maintenance = check.get("probes") == [{"contract": scope["contract"], "test": "structure", "minimum_hits": sum(idle.GEOMETRY["counts"])}]
        if maintenance:
            scope = {**scope, **idle.GEOMETRY}
    expected = {
        "id": scope["adapter"],
        "adapter": scope["adapter"],
        "component": scope["component"],
        "argv": ["python3", "-B", "tools/structure.py", "--collect"] + (["--package", package] if package != PACKAGE else []),
        "expected_tests": ["structure"],
        "platforms": [PLATFORM],
        "probes": [{"contract": scope["contract"], "test": "structure", "minimum_hits": sum(scope["counts"])}],
        "timeout_s": 1500,
        "log_bytes": 1024 * 1024,
    }
    if check.get("adapter") == "server-independence":
        expected.update(
            id="server-independence",
            adapter="server-independence",
            argv=expected["argv"] + ["--independence"],
            expected_tests=["independence"],
            probes=[{"contract": scope["contract"], "test": "independence", "minimum_hits": 210}],
            timeout_s=2400,
        )
    if check.get("adapter") == "admission-independence":
        repaired = check.get("probes") == [{"contract": scope["contract"], "test": "independence", "minimum_hits": 165}]
        expected.update(
            id="admission-independence",
            adapter="admission-independence",
            argv=expected["argv"] + ["--independence"],
            expected_tests=["independence"],
            probes=[{"contract": scope["contract"], "test": "independence", "minimum_hits": 165 if repaired else 164}],
            timeout_s=120,
        )
    if package == ENTRY:
        expected.update(expected_tests=["entry"], probes=[{"contract": scope["contract"], "test": "entry", "minimum_hits": 26}], timeout_s=120)
    if package == ASTROLABE:
        expected.update(
            argv=expected["argv"] + ([] if structural else ["--independence"]),
            expected_tests=["structure" if structural else "independence"],
            probes=[{"contract": scope["contract"], "test": "structure" if structural else "independence", "minimum_hits": sum(scope["counts"])}],
            timeout_s=120,
        )
    if any(v.encode(check.get(key)) != v.encode(value) for key, value in expected.items()):
        v.reject("structure-configuration")
    tests = check.get("native_tests")
    if not isinstance(tests, list) or not tests or any(not isinstance(name, str) for name in tests) or len(set(tests)) != len(tests):
        v.reject("structure-native-tests")
    if package == ASTROLABE:
        from tools import astrolabe

        if len(tests) != 468 or v.digest(v.encode(tests)) != astrolabe.TESTS:
            v.reject("astrolabe-native-inventory-policy")
    elif any(not name.startswith(("Test", "Fuzz") if package == STORAGE else ("Test",)) for name in tests):
        v.reject("structure-native-tests")
    if package == ENTRY and (len(tests) != 50 or v.digest(v.encode(tests)) != "b583d524e624f2a7d56dac20f78e6f8b248ea9269458c17854a92b844025a35a"):
        v.reject("entry-native-inventory-policy")
    if package == STORAGE:
        inventories = (
            {(257, idle.TESTS), (259, idle.BACKUP_TESTS)} if maintenance else {(247, "ce57df5ffffd86ce48eea17d0ee4546bd1db92204e8d54b92369a02cf02e730e")}
        )
        if (len(tests), v.digest(v.encode(tests))) not in inventories:
            v.reject("structure-native-inventory-policy")
    # Preserve the archived inventory and require the complete acquisition supplement in new campaigns.
    # Accepting its declaration does not qualify changed sources against historical native observations.
    if check["adapter"] == "admission-independence" and (check["probes"][0]["minimum_hits"], len(tests), v.digest(v.encode(tests))) not in {
        (164, 41, "70690d7f05661644adb8080d32e8e49839e640187ff25380fa8b4efdc6251bca"),
        (164, 48, "c11a7471a4b9e1d8133c7052410810a23bfaca3eb273506213bb08fd039630f8"),
        (165, 49, "97abdbb9bbba8d28e8f83b0dec0fad4c9dc5e673d8af795bbeb54c57049112e5"),
    }:
        v.reject("predicates-native-inventory-policy")
    if type(retained) is not bool:
        v.reject("structure-retained-policy")
    # Only the fixed archived reader selects this metadata version; execution always validates the current toolchain.
    go_version = "1.27.1" if retained else "1.27.2"
    for key, value in {
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOTOOLCHAIN": "local",
        "GOWORK": "off",
        "GOFLAGS": "-mod=readonly",
        "GOMAXPROCS": "2",
        "CGO_ENABLED": "1",
        "GOOS": "linux",
        "GOARCH": "amd64",
        "TMPDIR": "{run}/tmp",
        "GOCACHE": "{root}/build/cache/go",
        "ASTRA_CACHE_ROOT": "{cache}",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PATH": "{cache}/tools/go-" + go_version + "/bin:{cache}/tools/gcc-16.2.0/bin:/usr/bin:/bin",
    }.items():
        if check.get("environment", {}).get(key) != value:
            v.reject("structure-environment", key)


def plan(directory: Path, *, package: str = PACKAGE, independence: bool = False) -> list[tuple[str, list[str], int]]:
    """Declare every native command before results; no filters, retries or cross-configuration unions."""
    domain(package)
    if independence and package != SERVER:
        v.reject("structure-independence-package")
    target = "./" + package
    tests = ["go", "test", "-json", "-count=1", "-p=2", "-parallel=" + ("1" if package == SERVER else "4"), "-timeout=180s"]
    result = [("coverage", tests + ["-covermode=atomic", "-coverprofile=" + str(directory / "coverage.profile"), target], 240)]
    for name in ("typed", "control"):
        output = directory / name / "overlay"
        if name == "typed":
            result.append(("typed/exports", ["go", "list", "-deps", "-export", "-json", target], 180))
        collector = [
            "go",
            "run",
            "-p=2",
            "./tools/decisions",
            "-root",
            "{root}",
            "-source",
            str(directory / "source.json"),
            "-trace",
            package,
            "-output",
            str(output),
        ]
        collector += ["-export", str(directory / "typed/exports/exports.stdout.log")] if name == "typed" else ["-controls"]
        active = directory / name / "schedule" if package == SERVER and name == "typed" else output
        result.extend(
            [
                (name + "/collector", collector, 180),
                (name + "/packages", ["go", "list", "-json", "-overlay=" + str(active / "overlay.json"), target], 60),
                (name + "/tests", tests + ["-overlay=" + str(active / "overlay.json"), target], 240),
            ]
        )
    if independence:
        from tools import authority

        # Cold compilation has its own budget; existing native test deadlines remain unchanged.
        result.insert(0, ("compile", ["go", "test", "-c", "-p=2", "-covermode=atomic", "-o", str(directory / "coverage.test"), target], 300))
        for profile in authority.PROFILES:
            result.append(("authority/" + profile, ["go", *authority.command(directory / "authority/overlay", profile)[1:]], 300))
    return result


def artifact(directory: Path, path: Path) -> dict:
    """Describe existing bounded bytes; all paths stay within this owned bundle."""
    name = path.relative_to(directory).as_posix()
    data = v.read(v.inside(directory, name), statements.LIMIT)
    return {"path": name, "bytes": len(data), "sha256": v.digest(data)}


def reference(directory: Path, value: dict, name: str | None = None) -> bytes:
    """Validate a closed reference before resolving untrusted paths or opening evidence."""
    v.schema(value, "evidence", ("properties", "source_before"))
    if name is not None and value["path"] != name:
        v.reject("structure-artifact-location", name)
    try:
        return v.reference(directory, value, statements.LIMIT)
    except OSError as error:
        v.reject("structure-artifact-unreadable", type(error).__name__)


def terminals(data: bytes, tests: list[str], *, package: str = PACKAGE, schedule: bool = False) -> None:
    """Require the full planned package and test inventory, not just a successful final exit."""
    domain(package)
    events = [v.decode(line) for line in data.splitlines()]
    actual = {event["Test"] for event in events if event.get("Action") == "pass" and "Test" in event}
    if schedule and package != SERVER:
        v.reject("structure-schedule-package")
    if package == STORAGE:
        # Every named native case is mandatory, including joined-child helpers and data-driven descendants.
        from tools import idle

        if actual != set(tests) or (len(actual), v.digest(v.encode(sorted(actual)))) not in {
            (247, "ce57df5ffffd86ce48eea17d0ee4546bd1db92204e8d54b92369a02cf02e730e"),
            (257, idle.TESTS),
            (259, idle.BACKUP_TESTS),
        }:
            v.reject("structure-test-selection")
    elif package == SERVER:
        base = actual - watchdog.TESTS if schedule else actual
        if (
            actual != set(tests)
            or len(base) != 300
            or v.digest(v.encode(sorted(base))) != "f3fc71d718ada189100a7f9c079f3c3b451dbae3a049a51ad60bc72ea817fe99"
            or schedule
            and not watchdog.TESTS <= actual
        ):
            v.reject("structure-test-selection")
        if schedule:
            for name, count in (("cleared", 1), ("extended", 2)):
                text = "".join(event.get("Output", "") for event in events if event.get("Test") == "TestWatchdog/" + name)
                if text.count("WATCHDOG-SCHEDULE " + name + " complete " + str(count)) != 1:
                    v.reject("structure-schedule-witness")
    elif actual != set(tests):
        v.reject("structure-test-selection")
    statements.terminals(data, {"github.com/eosforge/astra/" + package: {"tests": len(tests)}})


def resolver(data: bytes) -> bytes:
    """Extract only the resolver child's original complete coverage receipt from its owning test."""
    events = [v.decode(line) for line in data.splitlines()]
    parts = [event.get("Output", "") for event in events if event.get("Test") == "TestNodeOpen"]
    if any(not isinstance(part, str) for part in parts):
        v.reject("structure-resolver-output")
    marker = "ADMISSION-RESOLVER-PROFILE "
    rows = [line.split(marker, 1)[1] for line in "".join(parts).splitlines() if marker in line]
    if len(rows) != 1 or not 0 < len(rows[0]) <= 2 * 1024**2:
        v.reject("structure-resolver-receipt")
    try:
        result = base64.b64decode(rows[0], validate=True)
    except ValueError:
        v.reject("structure-resolver-encoding")
    if not 0 < len(result) <= 1024**2:
        v.reject("structure-resolver-size")
    return result


def native(directory: Path, root: Path, name: str, arguments: list[str], timeout: int, environment: dict) -> tuple[dict, bytes]:
    """Bind native record shape, executable bytes, original process identity, arguments and resource budgets."""
    parent = v.inside(directory, name)
    record = v.decode(v.read(parent / "record.json"))
    v.schema(record, "evidence", ("properties", "checks", "items"))
    expected = [argument.replace("{root}", str(root)) for argument in arguments]
    child = {**environment, "TMPDIR": str(parent / "tmp"), "ASTRA_TEST_LOG_DIR": str(parent / "logs")}
    executable = shutil.which("go", path=environment["PATH"])
    if (
        not executable
        or record["id"] != parent.name
        or record["platform"] != PLATFORM
        or record["argv"] != expected
        or record["environment"] != child
        or record["resolved_environment"] != child
        or record["executable"] != executable
        or record["executable_sha256"] != v.file_digest(executable)
        or record["duration_ms"] > timeout * 1000
        or any(key in record for key in ("profile", "resolved_argv", "structure"))
    ):
        v.reject("structure-native-binding", name)
    tools = {"command": {"path": executable, "sha256": v.file_digest(executable)}}
    for key in ("CC", "CXX"):
        path = shutil.which(child[key], path=child["PATH"])
        if path is None:
            v.reject("structure-tool-missing", key)
        tools[key] = {"path": path, "sha256": v.file_digest(path)}
    if record["toolchain"] != tools:
        v.reject("structure-tool-identity", name)
    process = v.decode(v.read(parent / (parent.name + ".process.json")))
    logic.fields(process, ("identity", "boot_id", "argv", "cwd"), "structure-process")
    identity = process["identity"]
    if (
        not isinstance(identity, dict)
        or type(identity.get("pid")) is not int
        or identity["pid"] <= 0
        or not isinstance(identity.get("start_ticks"), str)
        or not identity["start_ticks"].isdecimal()
        or int(identity["start_ticks"]) <= 0
        or type(identity.get("parent")) is not int
        or identity["parent"] <= 0
        or not isinstance(process["boot_id"], str)
        or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", process["boot_id"])
    ):
        v.reject("structure-process-identity", name)
    return statements.completed(directory, artifact(directory, parent / "record.json"), root)


def dependency_paths(go: Path, environment: dict, *, package: str = PACKAGE, root: Path = ROOT) -> dict[str, Path]:
    """Locate the installed, offline source bytes actually used by this fixed compiler/dependency selection."""
    scope = domain(package)
    result = {}
    for name in scope["dependencies"]:
        result[name] = (
            root / name[6:]
            if name.startswith("astra/")
            else (
                Path(environment["GOMODCACHE"]) / "github.com/mattn/go-sqlite3@v1.14.52" / name[7:]
                if name.startswith("sqlite/")
                else go.parent.parent / "src" / name
            )
        )
    return result


def independence(directory: Path, root: Path, bundle: dict, typed: dict, records: dict, streams: dict) -> dict:
    """Join full native short-circuit traces with same-source ordinary/Race input witnesses, never summary claims."""
    from tools import authority

    overlay = directory / "authority/overlay"
    expected = authority.contents(root, overlay)
    logic.fields(bundle, expected, "structure-authority-files")
    for name, data in expected.items():
        if reference(directory, bundle[name], "authority/overlay/" + name) != data:
            v.reject("structure-authority-overlay")
    # Both profiles have already passed native owner, environment, timing and complete-stream validation in load.
    profiles = {
        profile: {
            "record": records["authority/" + profile],
            "stdout": streams["authority/" + profile],
            "stderr": v.reference(directory / "authority" / profile, records["authority/" + profile]["stderr"], authority.LOG_BYTES),
        }
        for profile in authority.PROFILES
    }
    packages = statements.stream(streams["typed/packages"])
    if len(packages) != 1 or packages[0].get("ImportPath") != authority.PACKAGE:
        v.reject("structure-authority-package")
    count = sum(len(packages[0].get(field, [])) for field in ("TestGoFiles", "XTestGoFiles"))
    report = authority.correlate(root, typed["trace"], typed["events"], count, profiles)
    # The raw denominator and every exclusion stay visible; an unexplained condition blocks this whole check.
    if (
        report["status"] != "complete-under-declared-domains"
        or report["raw_conditions"] != 214
        or report["supported_conditions"] != 210
        or report["qualified_denominator"] != 210
        or len(report["conditions"]) != 210
        or len(report["literal_exclusions"]) != 3
        or len(report["domain_exclusions"]) != 1
        or report["unresolved"]
    ):
        v.reject("structure-independence-uncovered")
    return report


def load(directory: Path, root: Path, check: dict, outer: dict, *, source_association: dict | None = None) -> dict:
    """Reconstruct structure from eight native runs and actual artifacts, independently of the collector's summary."""
    configuration(check)
    package = selection(check)
    bundle = v.decode(v.read(directory / "bundle.json"))
    retained_server = package == SERVER and bundle.get("version") == 7
    retained_storage = package == STORAGE and bundle.get("version") == 9
    retained_admission = check["adapter"] == "admission-structure" and bundle.get("version") == 5
    if source_association is not None and not (retained_admission or check["adapter"] == "admission-independence"):
        v.reject("structure-source-association-scope")
    if package in {ENTRY, ASTROLABE} or check["adapter"] == "admission-independence" or retained_server or retained_storage or retained_admission:
        from tools import astrolabe, entry, idle, predicates, server, storage

        logic.fields(bundle, ("version", "source", "retained"), "entry-bundle")
        structural = check["adapter"] in {"astrolabe-structure", "admission-structure"}
        if retained_storage:
            reader, expected = (idle, idle.references(root)) if idle.current(root) else (storage, storage.ARTIFACTS)
            version = 9
        elif retained_server:
            reader, expected = server, server.artifacts(root)
            version = 7
        elif package == ASTROLABE:
            reader, expected = astrolabe, astrolabe.artifacts(structural=structural)
            version = 6 if structural else 5
        elif package == ENTRY:
            reader, expected = entry, entry.artifacts(root)
            version = 8 if len(expected) != len(entry.ARCHIVES) else 4
        else:
            reader, expected = predicates, predicates.archives(root)
            version = 5 if structural else 4
        if type(bundle["version"]) is not int or bundle["version"] != version or set(bundle["retained"]) != set(expected):
            v.reject("entry-bundle-version-or-inventory")
        source_data = reference(directory, bundle["source"], "source.json")
        source = v.decode(source_data)
        workspace = v.source(root)
        expected_source = workspace
        if source_association is not None:
            from tools import verifierdata

            logic.fields(source_association, ("path", "sha256"), "structure-source-association")
            expected_source, _, _ = verifierdata.association(root, Path(source_association["path"]), source_association["sha256"], workspace)
        if expected_source != source:
            v.reject("entry-workspace-drift")
        archives = {
            name: reference(
                directory,
                item,
                "retained/"
                + (entry.filename(name) if package == ENTRY else name + ("" if package == ASTROLABE or retained_server or retained_storage else ".tar.gz")),
            )
            for name, item in bundle["retained"].items()
        }
        if reader is idle:
            result = idle.structural(root, archives)
        else:
            result = reader.reconcile(root, archives, structural=structural) if package == ASTROLABE or retained_admission else reader.reconcile(root, archives)
        if package == ASTROLABE:
            result = astrolabe.qualify(result, structural=structural)
            if result["native_tests"] != check["native_tests"]:
                v.reject("astrolabe-native-inventory-policy")
        if v.source(root) != workspace:
            v.reject("entry-source-changed")
        result["source_sha256"] = v.digest(source_data)
        return result
    scope = revision(root, package)
    independent = check["adapter"] == "server-independence"
    fields = ("version", "source", "coverage", "profiles", "typed", "control", "dependencies", "preflight")
    logic.fields(bundle, fields + (("authority",) if independent else ()), "structure-bundle")
    if type(bundle["version"]) is not int or bundle["version"] != (3 if independent else 2):
        v.reject("structure-bundle-version")
    source_data = reference(directory, bundle["source"], "source.json")
    source = v.decode(source_data)
    if v.source(root) != source:
        v.reject("structure-workspace-drift")
    # The outer native environment is checked against the policy's concrete project/cache/run expansion.
    environment = outer["resolved_environment"]
    cache = str(Path(os.environ.get("ASTRA_CACHE_ROOT", root / "build")).resolve())
    requested = {
        key: value.replace("{root}", str(root)).replace("{cache}", cache).replace("{run}", str(directory.parent)) for key, value in check["environment"].items()
    }
    if (
        set(environment) != set(requested) | {"HOME", "LANG"}
        or environment.get("LANG") != "C.UTF-8"
        or any(environment.get(key) != value for key, value in requested.items())
    ):
        v.reject("structure-outer-environment")
    limits = v.decode(reference(directory, bundle["preflight"], "preflight.json"))
    bounded(limits)
    expected = plan(directory, package=package, independence=independent)
    if {path.relative_to(directory).as_posix() for path in directory.rglob("record.json")} != {name + "/record.json" for name, _, _ in expected}:
        v.reject("structure-native-inventory")
    records, streams = {}, {}
    owner = v.decode(v.read(directory.parent / (check["id"] + ".process.json")))
    logic.fields(owner, ("identity", "boot_id", "argv", "cwd"), "structure-owner")
    identity = owner["identity"]
    if (
        owner["argv"] != check["argv"]
        or owner["cwd"] != str(root)
        or not isinstance(identity, dict)
        or type(identity.get("pid")) is not int
        or identity["pid"] <= 0
        or not isinstance(identity.get("start_ticks"), str)
        or not identity["start_ticks"].isdecimal()
        or int(identity["start_ticks"]) <= 0
    ):
        v.reject("structure-owner-identity")
    previous = outer["started_at"]
    for name, arguments, timeout in expected:
        record, data = native(directory, root, name, arguments, timeout, environment)
        process = v.decode(v.read(directory / name / (Path(name).name + ".process.json")))
        if process["boot_id"] != owner["boot_id"] or process["identity"].get("parent") != owner["identity"].get("pid"):
            v.reject("structure-native-owner", name)
        if v.stamp(record["started_at"]) < v.stamp(previous) or v.stamp(record["finished_at"]) > v.stamp(outer["finished_at"]):
            v.reject("structure-native-order", name)
        previous = record["finished_at"]
        records[name], streams[name] = record, data
    reference(directory, bundle["coverage"], "coverage/record.json")
    logic.fields(bundle["profiles"], ("parent", "child") if package == PACKAGE else ("parent",), "structure-profiles")
    parent = reference(directory, bundle["profiles"]["parent"], "coverage.profile")
    profiles = (parent,)
    terminals(streams["coverage"], check["native_tests"], package=package)
    if package == PACKAGE:
        child = reference(directory, bundle["profiles"]["child"], "resolver.profile")
        if resolver(streams["coverage"]) != child:
            v.reject("structure-resolver-binding")
        profiles += (child,)
    loaded = {}
    for name in ("typed", "control"):
        data = reference(directory, bundle[name], name + "/bundle.json")
        nested = v.decode(data)
        # No alternative record, source, generated manifest or older successful attempt may be substituted.
        fields = {
            "collector": "collector/record.json",
            "packages": "packages/record.json",
            "tests": "tests/record.json",
            "source": "source.json",
            "trace": "overlay/" + ("trace.json" if name == "typed" else "flow.json"),
            "overlay": "overlay/overlay.json",
        }
        if name == "typed":
            fields["exports"] = "exports/record.json"
            if package == SERVER:
                fields["schedule"] = "schedule/composition.json"
        for field, path in fields.items():
            reference(directory / name, nested[field], path)
        scheduled = package == SERVER and name == "typed"
        item = logic.load(directory / name, root, controls=name == "control", schedule=scheduled)
        if item["source_sha256"] != v.digest(source_data) or nested["directory"] != package or item["events"] != streams[name + "/tests"]:
            v.reject("structure-overlay-binding", name)
        terminals(item["events"], check["native_tests"] + sorted(watchdog.TESTS) if scheduled else check["native_tests"], package=package, schedule=scheduled)
        loaded[name] = item
    if not isinstance(bundle["dependencies"], dict) or set(bundle["dependencies"]) != set(scope["dependencies"]):
        v.reject("structure-dependency-scope")
    dependency = {}
    go = Path(records["coverage"]["executable"])
    for name, path in dependency_paths(go, environment, package=package, root=root).items():
        data = reference(directory, bundle["dependencies"][name], "_dependencies/" + name)
        if v.read(path) != data:
            v.reject("structure-dependency-origin", name)
        dependency[name] = data
    result = reconcile(
        root=root,
        source_sha256=v.digest(source_data),
        tests=check["native_tests"],
        profiles=profiles,
        dependency=dependency,
        trace=loaded["typed"]["trace"],
        boolean_events=loaded["typed"]["events"],
        control=loaded["control"]["trace"],
        control_events=loaded["control"]["events"],
        package=package,
    )
    if independent:
        result["independence"] = independence(directory, root, bundle["authority"], loaded["typed"], records, streams)
    if v.source(root) != source:
        v.reject("structure-source-changed")
    return result


def observations(data: bytes, check: dict, root: Path, evidence: dict | None) -> tuple[dict, list]:
    """Permit one scoped observation only after all raw denominators and command bindings agree."""
    configuration(check)
    scope = revision(root, selection(check))
    if evidence is None:
        v.reject("structure-evidence-missing")
    directory, record = evidence["directory"], evidence["record"]
    raw = reference(directory, record["structure"], "structure/bundle.json")
    receipt = v.decode(data)
    logic.fields(receipt, ("bundle_sha256", "source_sha256"), "structure-receipt")
    if receipt["bundle_sha256"] != v.digest(raw):
        v.reject("structure-receipt-binding")
    try:
        result = load(directory / "structure", root, check, record, source_association=evidence.get("source_association"))
    except v.Invalid:
        raise
    except (OSError, KeyError, TypeError, ValueError) as error:
        v.reject("structure-evidence-invalid", type(error).__name__)
    if receipt["source_sha256"] != result["source_sha256"]:
        v.reject("structure-receipt-source")
    if result["status"] != "complete-under-assumptions":
        return {}, ["structure-uncovered"]
    if selection(check) == ENTRY:
        return {scope["contract"]: result["independence"]["supported"]}, []
    if check["adapter"] == "admission-independence":
        return {scope["contract"]: result["independence"]["supported_conditions"]}, []
    if selection(check) == ASTROLABE:
        if check["adapter"] == "astrolabe-structure":
            return {scope["contract"]: result["structure"]["native_observations"]}, []
        return {scope["contract"]: result["independence"]["supported_conditions"]}, []
    counts = [
        result["statements"].get("compiler_weights", {}).get("obligations", result["statements"]["reachable_under_assumptions"])["statements_hit"],
        result["boolean"]["totals"]["roots"]["observed"],
        result["boolean"]["totals"]["atoms"]["observed"],
        result["controls"]["observed"],
    ]
    if counts != scope["counts"]:
        v.reject("structure-denominator-drift")
    if check["adapter"] == "server-independence":
        return {scope["contract"]: result["independence"]["supported_conditions"]}, []
    return {scope["contract"]: sum(counts)}, []


def bounded(value: dict) -> None:
    """Require explicit finite host enforcement; recorded recommendations are not hard limits."""
    logic.fields(value, ("cpu_quota", "cpu_period", "memory_bytes", "tasks", "available_bytes", "disk_free_bytes"), "structure-limits")
    if (
        any(type(item) is not int or item <= 0 for item in value.values())
        or not 2 <= value["cpu_quota"] / value["cpu_period"] <= 4
        or not 1536 * 1024**2 <= value["memory_bytes"] <= 2 * 1024**3
        or not 128 <= value["tasks"] <= 512
        or value["available_bytes"] < 1024**3
        or value["disk_free_bytes"] < 4 * 1024**3
    ):
        v.reject("structure-resource-boundary")


def collect(root: Path, check: dict, directory: Path) -> int:
    """Collect one fresh, bounded Linux campaign; cancellation drains each native group and never retries."""
    from tools import build

    configuration(check)
    if check["adapter"] == "admission-independence" or selection(check) in {ENTRY, ASTROLABE}:
        v.reject("structure-reuse-only")
    package = selection(check)
    independent = check["adapter"] == "server-independence"
    if sys.platform != "linux" or ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0):
        v.reject("structure-linux-subreaper-required")
    if (
        directory != directory.resolve()
        or directory.exists()
        or not directory.is_relative_to(root / "build")
        or directory.parent / "tmp" != Path(os.environ.get("TMPDIR", ""))
    ):
        v.reject("structure-output-boundary")
    # Enforce the existing supervisor's limits; this tool neither changes them nor launches another supervisor.
    group = Path("/sys/fs/cgroup") / next(line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines() if line.startswith("0::")).lstrip("/")
    quota, period = map(int, (group / "cpu.max").read_text().split())
    _, available = build.resources()
    limits = {
        "cpu_quota": quota,
        "cpu_period": period,
        "memory_bytes": int((group / "memory.max").read_text()),
        "tasks": int((group / "pids.max").read_text()),
        "available_bytes": available,
        "disk_free_bytes": shutil.disk_usage(directory.parent).free,
    }
    bounded(limits)
    directory.mkdir()
    v.write_new(directory / "preflight.json", limits)
    source_data = v.encode(v.source(root))
    v.write_new(directory / "source.json", source_data)
    started, stopped = v.utc(), False
    environment = v.public_environment(dict(os.environ))
    records = {}

    def cancel(*_: object) -> None:
        """Stop before the next command and let the active executor drain its owned process group."""
        nonlocal stopped
        stopped = True

    handlers = {number: signal.signal(number, cancel) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        if independent:
            from tools import authority

            authority.generate(root, directory / "authority/overlay")
        for name, arguments, timeout in plan(directory, package=package, independence=independent):
            if stopped:
                v.reject("structure-interrupted")
            parent = directory / name
            parent.mkdir(parents=True)
            command = {
                "id": parent.name,
                "argv": [argument.replace("{root}", str(root)) for argument in arguments],
                "environment": {**environment, "TMPDIR": str(parent / "tmp"), "ASTRA_TEST_LOG_DIR": str(parent / "logs")},
                "timeout_s": timeout,
                "log_bytes": statements.LIMIT,
            }
            v.write_new(parent / "plan.json", command)
            record = v.execute(command, root, parent, PLATFORM, lambda: stopped)
            v.write_new(parent / "record.json", record)
            records[name] = record
            if record["exit_code"] != 0 or not record["complete"] or not record["cleanup"] or record["termination"] != "exited":
                v.reject("structure-native-failed", name)
            if package == SERVER and name == "typed/collector":
                watchdog.compose(root, directory / "typed/overlay", directory / "typed/schedule", create=True)
        if stopped:
            v.reject("structure-interrupted")
        if package == PACKAGE:
            v.write_new(directory / "resolver.profile", resolver(v.reference(directory / "coverage", records["coverage"]["stdout"], statements.LIMIT)))
        bundle = {
            "version": 3 if independent else 2,
            "source": artifact(directory, directory / "source.json"),
            "coverage": artifact(directory, directory / "coverage/record.json"),
            "preflight": artifact(directory, directory / "preflight.json"),
            "profiles": {"parent": artifact(directory, directory / "coverage.profile")},
            "dependencies": {},
        }
        if independent:
            overlay = directory / "authority/overlay"
            bundle["authority"] = {name: artifact(directory, overlay / name) for name in authority.contents(root, overlay)}
        if package == PACKAGE:
            bundle["profiles"]["child"] = artifact(directory, directory / "resolver.profile")
        for name in ("typed", "control"):
            parent = directory / name
            v.write_new(parent / "source.json", source_data)
            overlay = parent / "overlay"
            item = {
                "version": 2 if name == "typed" else 1,
                "directory": package,
                "source": artifact(parent, parent / "source.json"),
                "trace": artifact(parent, overlay / ("trace.json" if name == "typed" else "flow.json")),
                "overlay": artifact(parent, overlay / "overlay.json"),
                "generated": {},
            }
            for field in (["exports"] if name == "typed" else []) + ["collector", "packages", "tests"]:
                item[field] = artifact(parent, parent / field / "record.json")
            for original, replacement in v.decode(v.read(overlay / "overlay.json"))["Replace"].items():
                item["generated"][Path(original).relative_to(root).as_posix()] = artifact(parent, Path(replacement))
            if package == SERVER and name == "typed":
                item["schedule"] = artifact(parent, parent / "schedule/composition.json")
            v.write_new(parent / "bundle.json", item)
            bundle[name] = artifact(directory, parent / "bundle.json")
        go = Path(records["coverage"]["executable"])
        for name, origin in dependency_paths(go, environment, package=package, root=root).items():
            # Go's recursive package discovery excludes underscore directories, not Git-ignored build paths.
            path = directory / "_dependencies" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            v.write_new(path, v.read(origin))
            bundle["dependencies"][name] = artifact(directory, path)
        v.write_new(directory / "bundle.json", bundle)
        outer = {"resolved_environment": environment, "started_at": started, "finished_at": v.utc()}
        result = load(directory, root, check, outer)
        v.write_new(directory / "ledger.json", result)
        if stopped or result["status"] != "complete-under-assumptions":
            v.reject("structure-interrupted" if stopped else "structure-uncovered")
        print(v.encode({"bundle_sha256": v.file_digest(directory / "bundle.json"), "source_sha256": v.digest(source_data)}).decode(), end="")
        return 0
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)


def reuse(root: Path, check: dict, directory: Path) -> int:
    """Attach retained native campaigns to a fresh evaluation; this path never starts application commands."""
    from tools import astrolabe, entry, idle, predicates, server, storage

    configuration(check)
    structural = check["adapter"] in {"astrolabe-structure", "admission-structure"}
    retained_server = selection(check) == SERVER
    retained_storage = selection(check) == STORAGE
    if retained_storage:
        reader, archives = (idle, idle.references(root)) if idle.current(root) else (storage, storage.ARTIFACTS)
        version = 9
    elif retained_server:
        reader, archives = server, server.artifacts(root)
        version = 7
    elif selection(check) == ASTROLABE:
        reader, archives = astrolabe, astrolabe.artifacts(structural=structural)
        version = 6 if structural else 5
    elif check["adapter"] in {"admission-independence", "admission-structure"}:
        reader, archives = predicates, predicates.archives(root)
        version = 5 if structural else 4
    else:
        reader, archives = entry, entry.artifacts(root)
        version = 8 if len(archives) != len(entry.ARCHIVES) else 4
    directory.mkdir(parents=True, exist_ok=False)
    source_data = v.encode(v.source(root))
    v.write_new(directory / "source.json", source_data)
    retained = {}
    for name, expected in archives.items():
        additional_entry = reader is entry and name not in entry.ARCHIVES
        relative = name if reader is astrolabe or retained_server or retained_storage or additional_entry else name + "/evidence.tar.gz"
        prefix = "build/results/assurance/" if retained_server or retained_storage or additional_entry else "build/results/assurance/reuse-plan/"
        origin = v.inside(root, prefix + relative)
        data = v.read(origin, statements.LIMIT)
        if expected is not None and v.digest(data) != expected:
            v.reject("entry-archive-integrity", name)
        target = (
            directory
            / "retained"
            / (entry.filename(name) if reader is entry else name + ("" if reader is astrolabe or retained_server or retained_storage else ".tar.gz"))
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        v.write_new(target, data)
        retained[name] = artifact(directory, target)
    v.write_new(
        directory / "bundle.json",
        {
            "version": version,
            "source": artifact(directory, directory / "source.json"),
            "retained": retained,
        },
    )
    result = load(directory, root, check, {})
    v.write_new(directory / "ledger.json", result)
    print(v.encode({"bundle_sha256": v.file_digest(directory / "bundle.json"), "source_sha256": v.digest(source_data)}).decode(), end="")
    return 0


def main(arguments: list[str] | None = None) -> int:
    """Use only the versioned structure check; importing this module never executes tests."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collect", action="store_true", required=True)
    parser.add_argument("--package", choices=[PACKAGE, STORAGE, SERVER, ENTRY, ASTROLABE], default=PACKAGE)
    parser.add_argument("--independence", action="store_true")
    args = parser.parse_args(arguments)
    try:
        config, _, _ = v.configuration(ROOT / "development.json", ROOT)
        if args.independence and args.package not in {PACKAGE, SERVER, ASTROLABE}:
            v.reject("structure-independence-package")
        if args.package == ASTROLABE:
            adapter = domain(ASTROLABE, structural=not args.independence)["adapter"]
        elif args.independence:
            adapter = "admission-independence" if args.package == PACKAGE else "server-independence"
        else:
            adapter = domain(args.package)["adapter"]
        check = next(item for item in config["checks"] if item["adapter"] == adapter)
        if not os.environ.get("TMPDIR"):
            v.reject("structure-output-missing")
        current_server = args.package == SERVER and admission.matches(ROOT, "internal/admission/identity.go", admission.MATERIAL)
        current_admission = adapter == "admission-structure" and admission.matches(ROOT, "internal/admission/identity.go", admission.MATERIAL)
        from tools import idle

        current_storage = args.package == STORAGE and (
            v.file_digest(ROOT / STORAGE / "store.go") == "7c914530e29059161f9665f867c1ce7f114cdec5c0be7bad43fdcbba3dfd0f16" or idle.current(ROOT)
        )
        if args.package in {ENTRY, ASTROLABE} or adapter == "admission-independence" or current_server or current_storage or current_admission:
            return reuse(ROOT, check, Path(os.environ["TMPDIR"]).parent / "structure")
        return collect(ROOT, check, Path(os.environ["TMPDIR"]).parent / "structure")
    except (OSError, v.Invalid, KeyError, TypeError, ValueError, StopIteration) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
