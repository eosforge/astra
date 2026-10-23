"""Reconstruct current Server structure and independence from the sealed post-ingress native campaign."""

from pathlib import Path
import tempfile

from tools import authority, consumers, delivery, flow, installation, logic, server, statements, structure, verify as v, watchdog

NAME = "server-structure-current-1"
PREFIX = "source/build/commands/server/"
ARTIFACT = "reuse-plan/" + NAME + "/native/evidence.tar.gz"
ARCHIVE = "bc740f5059d70bb8639985b9e4421d5736e02366d748ba0d3a714142d4644fea"
# Fresh compiler-backed observations bind the exact Storage maintenance dependency revision.
MAINTENANCE = {"reuse-plan/server-maintenance-current-1/native/evidence.tar.gz": "8e7928ee83f82669339d1ef1da740e3939a1b6d45075aa03794fb9db65fc0f2e"}
COUNTS = [659, 329, 430, 95]
FOREST = "c730c128e2213afb2e9bd7bf3c292b9db6e57cab10f8c918747ab4c880690494"
EDGES = "0c959de1852d8fb2661fd3845d068634404b6ed396dc480b88f66b643c011efc"
PROFILE = "0688fd18428c4c66eb65d9fad26ec11a3f9b1f16c8a5202aa94802a1f32f6176"
COMMANDS = (
    "typed/exports",
    "typed/collector",
    "control/collector",
    "typed/packages",
    "control/packages",
    "coverage",
    "typed/tests",
    "control/tests",
    "authority/baseline",
    "authority/race",
)
FIXTURES = {
    "polaris/internal/server/predicates_test.go": authority.FIXTURE,
    "polaris/internal/server/batch_test.go": "tests/fixtures/server-batch.go.in",
    "polaris/internal/server/pointers_test.go": "tests/fixtures/batchpointers.go.in",
}
ADDITIONS = (
    b"\t// Retain batch-wide key identity so a known-invalid prefix never waits for more transport input.\n\tseen := make(map[string]struct{})\n",
    b'\t\tfor _, change := range page.Changes {\n\t\t\tif change == nil || change.Key == "" {\n\t\t\t\treturn status.Error(codes.InvalidArgument, "Missing batch entry")\n\t\t\t}\n\t\t\tif _, exists := seen[change.Key]; exists {\n\t\t\t\treturn status.Error(codes.InvalidArgument, "Duplicate batch key")\n\t\t\t}\n\t\t\tseen[change.Key] = struct{}{}\n\t\t}\n',
)


def archives(root: Path) -> dict[str, str]:
    """Select only reviewed native collections; unfamiliar dependency edits still fail full source binding."""
    from tools import idle

    if idle.current(root):
        return consumers.acquisition(root) if (root / idle.BACKUP_FILE).is_file() else MAINTENANCE
    return {ARTIFACT: ARCHIVE}


def previous(data: bytes) -> tuple[bytes, list[tuple[int, int]]]:
    """Remove exactly the reviewed ingress additions and retain a reversible legacy-to-current offset map."""
    if v.digest(data) != installation.SOURCE:
        v.reject("ingress-current-source")
    original, inserted = data, []
    for fragment in ADDITIONS:
        if original.count(fragment) != 1:
            v.reject("ingress-delta-shape")
        inserted.append((original.index(fragment), len(fragment)))
        original = original.replace(fragment, b"", 1)
    if v.digest(original) != installation.ORIGINAL:
        v.reject("ingress-original-source")
    return original, inserted


def shifted(offset: int, insertions: list[tuple[int, int]]) -> int:
    """Translate a frozen legacy byte offset through the two separately authenticated additions."""
    return offset + sum(size for begin, size in insertions if offset >= begin)


def nil_pair(guard: dict, actual: set) -> dict:
    """Certify the pointer-domain pair without assigning a Boolean value to an absent Key dereference."""
    if guard["text"] != 'change == nil || change.Key == ""' or len(guard["atoms"]) != 2:
        v.reject("ingress-nil-guard")
    before, after = [False, False], [True, None]
    witnesses = [authority.project(guard, values) for values in (before, after)]
    if witnesses != [("11", False), ("20", True)] or not set(witnesses) <= actual:
        v.reject("ingress-nil-native-pair")
    return {
        "criterion": "defined-domain-short-circuit-v1",
        "witness": {"before": before, "after": after, "undefined_domain": "nil-entry-key", "native_vectors": witnesses},
    }


def independent(root: Path, trace: dict, data: bytes, tests: int, profiles: dict, sources: dict[str, bytes]) -> dict:
    """Bind old unchanged guard input pairs to current executed vectors and preserve undefined nil fields."""
    original, insertions = previous(sources[installation.PATH])
    with tempfile.TemporaryDirectory() as directory:
        mirror = Path(directory)
        for name, digest in authority.SOURCES.items():
            raw = original if name == "authority.go" else sources[structure.SERVER + "/" + name]
            if v.digest(raw) != digest:
                v.reject("ingress-pair-source")
            path = mirror / structure.SERVER / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        decoded = {profile: authority.outcome(**value, root=mirror) for profile, value in profiles.items()}
    if set(decoded) != set(authority.PROFILES) or decoded["baseline"] != decoded["race"]:
        v.reject("ingress-pair-profiles")
    inventory = logic.inventory(trace)
    report = logic.summary(trace, data, authority.PACKAGE, tests)
    if report["independence"]["search_incomplete"] or report["totals"]["search_incomplete"]:
        v.reject("ingress-pair-budget")
    rows = {row["id"]: row for row in report["decisions"]}
    covered = {
        (row["id"], atom["index"]): {"criterion": "universal-common-cube-v1", "witness": atom["independent"]}
        for row in rows.values()
        for atom in row["atoms"]
        if atom["independent"] is not None
    }
    proofs = []
    for group in ("pairs", "guarded"):
        for index, pair in enumerate(decoded["baseline"][group]):
            legacy, offset = pair["decision"].rsplit(":", 1)
            offset = shifted(int(offset), insertions) if legacy.endswith("/authority.go") else int(offset)
            current = legacy + ":" + str(offset)
            decision = inventory[current]
            actual = {(row["values"], row["result"]) for row in rows[current]["vectors"] if row["hits"] > 0}
            proof = authority.correlate_pair(
                {**decision, "id": pair["decision"]}, pair, actual, guard=list(authority.GUARDED)[index] if group == "guarded" else None
            )
            proof.update(decision=current, original_decision=pair["decision"])
            covered[(current, pair["condition"])] = {"criterion": proof["criterion"], "witness": proof}
            proofs.append(proof)
    # A nil entry has no Key value. Its guarded pair cannot manufacture a hit for that absent dereference.
    guard = next(decision for decision in inventory.values() if decision["text"] == 'change == nil || change.Key == ""')
    actual = {(row["values"], row["result"]) for row in rows[guard["id"]]["vectors"] if row["hits"] > 0}
    covered[(guard["id"], 0)] = nil_pair(guard, actual)
    old_identity = sources["tests/fixtures/admission-identity.go.in"]
    runtime = server.authentication(old_identity, sources["internal/admission/identity.go"])
    with tempfile.TemporaryDirectory() as directory:
        mirror = Path(directory)
        for name, digest in structure.SERVER_DEPENDENCIES.items():
            relative = name.removeprefix("astra/")
            raw = old_identity if relative.endswith("/identity.go") else sources[relative]
            if v.digest(raw) != digest:
                v.reject("ingress-authentication-source")
            path = mirror / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        authenticated = authority.authentication(mirror, inventory["polaris/internal/server/stream.go:9185"], rows["polaris/internal/server/stream.go:9185"])
    authenticated["dependency_delta"] = {
        "original": structure.SERVER_DEPENDENCIES,
        "current": {name: v.digest(sources[name.removeprefix("astra/")]) for name in structure.SERVER_DEPENDENCIES},
        "unchanged_runtime_sha256": runtime,
    }
    excluded, unresolved = [], []
    for identity, decision in inventory.items():
        for index, atom in enumerate(decision["atoms"]):
            if decision["kind"] == "return" and decision["text"] in ("true", "false"):
                if (identity, index) in covered or any(row["result"] != (decision["text"] == "true") for row in rows[identity]["vectors"]):
                    v.reject("ingress-literal-contradiction")
                excluded.append({"decision": identity, "condition": index, "reason": "literal-return-not-variable"})
            elif (identity, index) not in covered and (identity, index) != (authenticated["decision"], authenticated["condition"]):
                unresolved.append({"decision": identity, "condition": index, "text": atom["text"]})
    return {
        "status": "incomplete" if unresolved else "complete-under-declared-domains",
        "raw_conditions": report["totals"]["atoms"],
        "supported_conditions": len(covered),
        "qualified_denominator": report["totals"]["atoms"] - len(excluded) - 1,
        "conditions": [{"decision": identity, "condition": index, **value} for (identity, index), value in sorted(covered.items())],
        "pairs": proofs,
        "literal_exclusions": excluded,
        "domain_exclusions": [authenticated],
        "unresolved": unresolved,
        "qualification": "not-evaluated",
    }


def reconcile(root: Path, artifacts: dict[str, bytes]) -> dict:
    """Authenticate original native facts before rederiving current-source denominators; never run the application."""
    expected = archives(root)
    if set(artifacts) != set(expected) or any(not digest or v.digest(artifacts[name]) != digest for name, digest in expected.items()):
        v.reject("ingress-archive")
    name, digest = next(iter(expected.items()))
    files = consumers.unpack(artifacts[name], digest)
    acquired = expected in (consumers.ACQUISITION, consumers.LEGACY_ACQUISITION)
    prefix = "commands/server/" if acquired else PREFIX
    if acquired:
        source, collected, streams = consumers.acquired(files)
        records = {name: collected["server/" + name] for name in COMMANDS}
        outputs = {name: streams["server/" + name] for name in COMMANDS}
    else:
        collection = "server-maintenance-current-1" if expected == MAINTENANCE else NAME
        source, records, outputs = consumers.native(files, collection, commands=COMMANDS, prefix=prefix)
    inputs = v.decode(files["inputs.json"])
    if inputs["fixtures"] != FIXTURES:
        v.reject("ingress-fixtures")
    native_source = files[prefix + "source.json"]
    frozen = v.decode(native_source)
    if {row["path"]: row["sha256"] for row in frozen["files"] if row["sha256"] is not None} != inputs["files"]:
        v.reject("ingress-trace-workspace")
    packages = statements.stream(outputs["typed/exports"])
    directories = {
        item["ImportPath"].removeprefix("github.com/eosforge/astra/") for item in packages if item["ImportPath"].startswith("github.com/eosforge/astra/")
    }
    if structure.SERVER not in directories or any(item.get("Incomplete") or item.get("DepsErrors") for item in packages):
        v.reject("ingress-import-closure")
    relevant = {name for name in source if name.endswith(".go") and Path(name).parent.as_posix() in directories}
    relevant.update(
        name
        for name in source
        if name.startswith("tools/decisions/")
        or name in (*FIXTURES.values(), watchdog.FIXTURE, "tests/fixtures/admission-identity.go.in", "go.mod", "go.sum", "dependencies.lock.json")
    )
    for name in relevant:
        if v.read(root / name) != source[name]:
            v.reject("ingress-current-input", name)
    actual = {path.relative_to(root).as_posix() for directory in directories | {"tools/decisions"} for path in (root / directory).glob("*.go")}
    if actual != {name for name in relevant if name.endswith(".go")}:
        v.reject("ingress-current-inventory")
    trace = v.decode(files[prefix + "typed/overlay/trace.json"], maximum=statements.LIMIT)
    control = v.decode(files[prefix + "control/overlay/flow.json"], maximum=statements.LIMIT)
    if trace["files"] != control["files"] or trace["source_sha256"] != control["source_sha256"] or trace["source_sha256"] != v.digest(native_source):
        v.reject("ingress-trace-binding")
    for row in trace["files"]:
        if v.digest(source[row["file"]]) != row["sha256"]:
            v.reject("ingress-trace-source")
    if trace["typing"]["inactive"] or trace["typing"]["constants"]:
        v.reject("ingress-unsupported-typing")
    tests = inputs["server_tests"] if acquired else inputs["tests"]
    policy, _, _ = v.configuration(root / "development.json", root)
    check = next(item for item in policy["checks"] if item["adapter"] == "server-independence")
    structure.configuration(check)
    extra = [
        "TestPredicates",
        "TestBatchAdmission",
        "TestBatchAdmission/across-pages",
        "TestBatchAdmission/in-page",
        "TestBatchAdmission/nil-entry",
        "TestBatchAdmission/unique",
        "TestBatchPointers",
        "TestBatchPointers/nil",
        "TestBatchPointers/empty",
    ]
    if sorted(tests) != sorted(check["native_tests"] + extra) or inputs["pairs"] != ["TestPredicates"]:
        v.reject("ingress-policy-inventory")
    inventories = {}
    for name in ("coverage", "typed/tests", "control/tests", "authority/baseline", "authority/race"):
        expected = inputs["pairs"] if name.startswith("authority/") else tests + (sorted(watchdog.TESTS) if name == "typed/tests" else [])
        inventories[name] = consumers.cases(outputs[name], authority.PACKAGE, expected)
    decisions = logic.inventory(trace)
    rows, processes = logic.observe(trace, outputs["typed/tests"], authority.PACKAGE, len(tests) + len(watchdog.TESTS))
    boolean = structure.boolean(decisions, rows, structure.SERVER_ASSUMPTIONS)
    completion = flow.summary(control, outputs["control/tests"], authority.PACKAGE, len(tests), root, v.digest(native_source))
    branches = structure.controls(completion)
    profile = files[prefix + "coverage.profile"]
    selected = {row["file"]: {"data": source[row["file"]]} for row in trace["files"]}
    mode, blocks, count = statements.profile(profile, selected, {"github.com/eosforge/astra/" + name: name for name in selected})
    if mode != "atomic" or count != len(blocks) or processes != 1 or completion["processes"] != 1:
        v.reject("ingress-native-completeness")
    missing = [row for row in blocks if row["statements"] and not row["count"]]
    statement = {
        "raw": {"statements": sum(row["statements"] for row in blocks), "statements_hit": sum(row["statements"] for row in blocks if row["count"])},
        "unhit": missing,
        "unexplained": missing,
    }
    statement["reachable_under_assumptions"] = statement["raw"]
    weighted = None
    if acquired and consumers.compiler(files) == "1.27.2":
        from tools import profileweights

        weighted = profileweights.reconcile(root, structure.SERVER, blocks)
        statement["compiler_weights"] = weighted
    profiles = {
        name: {
            "data": outputs["authority/" + name],
            "errors": delivery.receipt(files, prefix + "authority/" + name + "/")[0]["stderr"],
            "record": records["authority/" + name],
        }
        for name in authority.PROFILES
    }
    for name, item in profiles.items():
        item["errors"] = files[prefix + "authority/" + name + "/" + item["errors"]["path"]]
    independence = independent(root, trace, outputs["typed/tests"], len(tests) + len(watchdog.TESTS), profiles, source)
    counts = [
        (weighted["obligations"] if weighted else statement["raw"])["statements_hit"],
        boolean["totals"]["roots"]["observed"],
        boolean["totals"]["atoms"]["observed"],
        branches["observed"],
    ]
    if (
        counts != COUNTS
        or v.digest(v.encode(trace["files"])) != FOREST
        or v.digest(v.encode(control["edges"])) != EDGES
        or (
            weighted["shape_sha256"]["1.27.1"]
            if weighted
            else v.digest(v.encode([{key: block[key] for key in ("file", "span", "statements")} for block in blocks]))
        )
        != PROFILE
    ):
        v.reject("ingress-denominator")
    if (
        [independence[key] for key in ("raw_conditions", "supported_conditions", "qualified_denominator")] != [217, 213, 213]
        or len(independence["literal_exclusions"]) != 3
        or len(independence["domain_exclusions"]) != 1
    ):
        v.reject("ingress-independence-denominator")
    return {
        "status": "incomplete" if missing or boolean["missing"] or branches["missing"] or independence["unresolved"] else "complete-under-assumptions",
        "statements": statement,
        "boolean": boolean,
        "controls": branches,
        "independence": independence,
        "assumptions": structure.SERVER_REASONS,
        "dependency_impact": {"directories": sorted(directories), "sources": {name: v.digest(source[name]) for name in sorted(relevant)}},
        "current_regression": {"archive_sha256": digest, "inventories": inventories},
        "application_commands": 0,
        "qualification": "Current native Server structure and MC/DC at local trust; entry qualification, other rules and protected release remain separate.",
    }
