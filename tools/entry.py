"""Reconcile reviewed Polaris entry archives without rebuilding or rerunning the application."""

import base64
import io
from pathlib import Path, PurePosixPath
import tarfile

from tools import authority, flow, logic, statements, verify as v

# These are reviewed, sealed native campaigns, not caller-supplied claims of success.
# Changing this catalog requires reviewing native provenance and source impact again.
ARCHIVES = {
    "entry-closure": "376b066c0af0650afa26656982c15c5fa553082a543fdcbb208765a764133dd6",
    "entry-proof-2": "84de2ea76a16156e3ae6ebf740c0d3c554ef4a5d0141f26c30de926d92bb3a55",
    "lifecycle": "24e2867d309d6d3dece7db5d4dff0af2558d2cd47dee96585af792cde2848a38",
}
PACKAGE = "github.com/eosforge/astra/polaris"
SOURCE = "ccd18fea581e3500cf9ed9b12e80277d060903af4603fd3e138b90d3695e0471"
PREFIX = "source/build/entry/"
LIMIT = 256 * 1024**2
CURRENT = {"reuse-plan/entry-current-1/native/evidence.tar.gz": "68da4e85f6b65d0cbc633be350b0cfdfb842ea1c249018e689e2e57940c2d569"}
COMMANDS = ("typed/exports", "typed/collector", "control/collector", "typed/packages", "control/packages", "typed/tests", "control/tests")
# Current Storage maintenance invalidates the old dependency closure; this archive owns all three current entry selections.
MAINTENANCE = {"reuse-plan/entry-maintenance-current-2/native/evidence.tar.gz": "b743af725bfaa653e472891063b07ee0c1866b0ffe3c9ebf898eab76336c0c6c"}


def unpack(data: bytes) -> dict[str, bytes]:
    """Read bounded regular archive members in memory; never extract paths onto the host."""
    files, names, total = {}, set(), 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive:
                name = member.name
                path = PurePosixPath(name)
                total += member.size
                if (
                    not member.isfile()
                    or not name
                    or "\\" in name
                    or ":" in name
                    or path.is_absolute()
                    or ".." in path.parts
                    or path.as_posix() != name
                    or name.casefold() in names
                    or not 0 <= member.size <= 64 * 1024**2
                    or total > LIMIT
                    or len(files) >= 4096
                ):
                    v.reject("entry-archive-member", name)
                names.add(name.casefold())
                with archive.extractfile(member) as stream:
                    content = stream.read(member.size + 1)
                if len(content) != member.size:
                    v.reject("entry-archive-truncated", name)
                files[name] = content
    except (tarfile.TarError, EOFError, OSError) as error:
        v.reject("entry-archive-invalid", type(error).__name__)
    return files


def retained(data: bytes, expected: str) -> dict[str, bytes]:
    """Verify the approved archive before parsing; preserve local trust and original runner facts."""
    if v.digest(data) != expected:
        v.reject("entry-archive-integrity")
    files = unpack(data)
    manifest = v.decode(files["manifest.json"])
    if manifest["trust"] != "local" or set(manifest["files"]) != set(files) - {"manifest.json"}:
        v.reject("entry-archive-inventory")
    for name, item in manifest["files"].items():
        if item != {"bytes": len(files[name]), "sha256": v.digest(files[name])}:
            v.reject("entry-member-integrity", name)
    terminal, cleanup, owner = (v.decode(files[name]) for name in ("terminal.json", "cleanup.native.json", "controller.json"))
    service = cleanup["service"]
    if (
        terminal["errors"]
        or terminal["interrupted"] is not False
        or terminal["remaining_owned"]
        or terminal["pins_unchanged"] is not True
        or terminal["source_unchanged"] is not True
        or cleanup["pins_verified"] is not True
        or cleanup["products_verified"] is not True
        or service["ExecMainStatus"] != "0"
        or service["MainPID"] != "0"
        or service["ControlGroup"] != ""
        or service["SubState"] != "exited"
        or service["InvocationID"] != owner["invocation_id"]
        or cleanup["boot_id"] != owner["boot_id"]
        or owner["identity"] not in cleanup["retired"]
    ):
        v.reject("entry-native-retirement")
    for name, data in files.items():
        if not name.endswith("/record.json"):
            continue
        record = v.decode(data)
        directory = str(PurePosixPath(name).parent) + "/"
        if record["exit_code"] != 0 or record["termination"] != "exited" or record["complete"] is not True or record["cleanup"] is not True:
            v.reject("entry-native-incomplete", name)
        if record["platform"] != "linux-amd64-cgo" or v.stamp(record["finished_at"]) < v.stamp(record["started_at"]):
            v.reject("entry-native-platform-or-time", name)
        for channel in ("stdout", "stderr"):
            item = record[channel]
            data = files[directory + item["path"]]
            if len(data) != item["bytes"] or v.digest(data) != item["sha256"]:
                v.reject("entry-native-stream", name)
    return files


def artifacts(root: Path) -> dict[str, str | None]:
    """Require separate current acquisition facts when startup dependencies differ from the entry campaign."""
    from tools import admission, consumers, idle, installation, server

    if idle.current(root):
        return consumers.acquisition(root) if (root / idle.BACKUP_FILE).is_file() else MAINTENANCE
    if admission.matches(root, installation.PATH, {installation.PATH: installation.SOURCE}):
        return {**CURRENT, **{name: digest for name, digest in consumers.ARTIFACTS.items() if "server-batch-consumers-current-1/" in name}}
    if not admission.matches(root, "internal/admission/identity.go", admission.MATERIAL):
        return ARCHIVES
    return {**ARCHIVES, **{name: digest for name, digest in server.ARTIFACTS.items() if name != "server-independence-linux-2/evidence.tar.gz"}}


def filename(name: str) -> str:
    """Preserve historical bundle member names and actual extensions of additional current facts."""
    return name + ".tar.gz" if name in ARCHIVES else name


def sources(root: Path, files: dict[str, bytes], *, current: dict[str, bytes] | None = None) -> dict[str, str]:
    """Bind the latest native production dependency closure and all entry fixtures, including new files."""
    frozen = v.decode(files["inputs.json"])["files"]
    packages = statements.stream(files[PREFIX + "typed/exports/exports.stdout.log"])
    module = "github.com/eosforge/astra/"
    directories = {item["ImportPath"][len(module) :] for item in packages if item["ImportPath"].startswith(module)}
    directories.add("tools/decisions")
    expected = {
        name: digest
        for name, digest in frozen.items()
        if PurePosixPath(name).parent.as_posix() in directories and name.endswith(".go") or name in {"go.mod", "go.sum", "dependencies.lock.json"}
    }
    actual = {path.relative_to(root).as_posix() for name in directories for path in v.inside(root, name).glob("*.go")}
    actual.update(("go.mod", "go.sum", "dependencies.lock.json"))
    from tools import admission

    added = actual - set(expected)
    if (
        current is None
        and actual != set(expected)
        or current is not None
        and (
            set(expected) - actual
            or any(name not in admission.MATERIAL and not (name.startswith("internal/admission/") and name.endswith("_test.go")) for name in added)
        )
    ):
        v.reject("entry-source-inventory")
    bindings = {}
    for name in actual:
        data = v.read(v.inside(root, name))
        digest = v.digest(data)
        accepted = digest == expected.get(name)
        if current is not None:
            if name not in current or current[name] != data:
                v.reject("entry-current-regression-source", name)
            if name == "internal/admission/identity.go":
                accepted = expected.get(name) == admission.SOURCES[name] and digest == admission.MATERIAL[name]
            elif name == "internal/admission/node.go":
                accepted = expected.get(name) in {admission.SOURCES[name], admission.NODE} and digest == admission.NODE
            elif name.startswith("internal/admission/") and name.endswith("_test.go"):
                # Dependency tests are not linked into Polaris; their changed inputs have separate current Race facts.
                accepted = True
            elif name in added:
                accepted = True
        if not accepted:
            v.reject("entry-source-drift", name)
        bindings[name] = digest
    if expected.get("polaris/main.go") != SOURCE:
        v.reject("entry-source-revision")
    return bindings


def counters(root: Path, profiles: list[bytes], *, compiler: str = "1.27.1") -> dict:
    """Union hit presence only for identical native block geometry; never sum assertion or process counts."""
    files = {"polaris/main.go": {"data": v.read(root / "polaris/main.go")}}
    selected = {PACKAGE + "/main.go": "polaris/main.go"}
    if compiler not in {"1.27.1", "1.27.2"}:
        v.reject("entry-profile-compiler")
    shape, hit = None, set()
    weighted = None
    references = []
    for data in profiles:
        mode, blocks, records = statements.profile(data, files, selected)
        current = [(tuple(row["span"]), row["statements"]) for row in blocks]
        if mode != "atomic" or records != 63 or len(blocks) != 63 or shape is not None and current != shape:
            v.reject("entry-profile-denominator")
        if compiler == "1.27.2":
            from tools import profileweights

            weighted = profileweights.reconcile(root, "polaris", blocks)
        shape = current
        hit.update(tuple(row["span"]) for row in blocks if row["count"])
        references.append({"sha256": v.digest(data), "bytes": len(data)})
    if shape is None or sum(count for _, count in shape) != (101 if weighted else 136):
        v.reject("entry-profile-empty")
    if weighted:
        weighted = profileweights.reconcile(root, "polaris", [{**row, "count": int(tuple(row["span"]) in hit)} for row in blocks])
    missing = [{"span": list(span), "statements": count} for span, count in shape if count and span not in hit]
    if missing != [{"span": [76, 3, 77, 1], "statements": 1}]:
        v.reject("entry-profile-uncovered")
    return {
        "raw": 101 if weighted else 136,
        "hit": 100 if weighted else 135,
        **({"compiler_weights": weighted} if weighted else {}),
        "profiles": references,
        "unhit": missing,
        "conditional": "Linux fixes runtime.GOOS; no opposite-platform execution is claimed.",
    }


def reconcile(root: Path, archives: dict[str, bytes]) -> dict:
    """Replay native entry facts and source-defined pairs, keeping historical inputs and assumptions explicit."""
    from tools import consumers, structure

    expected = artifacts(root)
    if set(archives) != set(expected):
        v.reject("entry-input-inventory")
    if set(CURRENT) <= set(expected) or set(MAINTENANCE) <= set(expected) or expected in (consumers.ACQUISITION, consumers.LEGACY_ACQUISITION):
        return renew(root, archives)
    facts = {name: retained(archives[name], ARCHIVES[name]) for name in ARCHIVES}
    current, impact = None, None
    if set(expected) != set(ARCHIVES):
        from tools import astrolabe, server

        for name in set(expected) - set(ARCHIVES):
            if expected[name] is not None and v.digest(archives[name]) != expected[name]:
                v.reject("entry-current-archive-integrity", name)
        acquired, regression, events = astrolabe.acquisition(
            root, archives["reuse-plan/material-2/evidence.tar.gz"], v.decode(archives["reuse-plan/material-2/sealed.native.json"])
        )
        current = {name.removeprefix("source/"): data for name, data in acquired.items() if name.startswith("source/") and not name.startswith("source/build/")}
        impact = {
            **server.delta(unpack(archives["server-independence-linux-2/inputs.tar.gz"]), current),
            "current_race_archive_sha256": astrolabe.BASELINE,
            "current_race_stdout_sha256": v.digest(events),
            "current_race_record_sha256": v.digest(v.encode(regression)),
        }
    latest, prior, lifecycle = (facts[name] for name in ARCHIVES)
    dependencies = sources(root, latest, current=current)
    trace = v.decode(latest[PREFIX + "typed/overlay/trace.json"])
    control = v.decode(prior[PREFIX + "control/overlay/flow.json"])
    for manifest in (trace, control):
        if len(manifest["files"]) != 1 or manifest["files"][0]["file"] != "polaris/main.go" or manifest["files"][0]["sha256"] != SOURCE:
            v.reject("entry-native-scope")
    # Historical native hashes remain intact. Only unchanged main.go geometry is combined.
    # The later Join cancellation fix is covered by the latest native campaign, not inferred from old records.
    events = latest[PREFIX + "typed/tests/tests.stdout.log"]
    structure.terminals(events, tests(events), package=structure.ENTRY)
    report = logic.summary(trace, events, PACKAGE, 50)
    inventory = logic.inventory(trace)
    rows, processes = logic.observe(trace, events, PACKAGE, 50)
    if processes != 4 or report["totals"]["atoms"] != 27 or report["independence"]["search_incomplete"]:
        v.reject("entry-native-denominator")
    outcomes = structure.boolean(inventory, rows, (("polaris/main.go:3728", 0, True, "linux-target"),))
    branches = structure.controls(flow.summary(control, prior[PREFIX + "control/tests/tests.stdout.log"], PACKAGE, 44, root, control["source_sha256"]))
    supported = {(row["id"], atom["index"]) for row in report["decisions"] for atom in row["atoms"] if atom["independent"] is not None}
    pairs = []
    baseline = [False, True, True, False, False, False, False]
    for condition in range(6):
        changed = baseline.copy()
        changed[condition] = not changed[condition]
        pairs.append(("polaris/main.go:3093", condition, baseline, changed))
    pairs += [("polaris/main.go:7444", 0, [False, False], [True, False]), ("polaris/main.go:7975", 0, [False, False], [True, False])]
    proofs = []
    for identity, condition, before, after in pairs:
        decision = inventory[identity]
        pair = {
            "decision": identity,
            "condition": condition,
            "before": {"values": before, "result": authority.project(decision, before)[1]},
            "after": {"values": after, "result": authority.project(decision, after)[1]},
        }
        proofs.append(authority.correlate_pair(decision, pair, set(rows[identity])))
        supported.add((identity, condition))
    missing = {(identity, index) for identity, decision in inventory.items() for index in range(len(decision["atoms"]))} - supported
    if missing != {("polaris/main.go:3728", 0)} or outcomes["missing"] or branches["missing"]:
        v.reject("entry-decisions-uncovered")
    profiles = [latest[PREFIX + "focused/coverage.out"], lifecycle[PREFIX + "entry.cover"]]
    focused = latest[PREFIX + "focused/focused.stdout.log"]
    statements.terminals(focused, {PACKAGE: {"tests": 9}})
    count, outputs = 0, {}
    for line in focused.splitlines():
        event = v.decode(line)
        name = event.get("Test", "")
        outputs[name] = outputs.get(name, "") + event.get("Output", "")
    # go test -json may split a single long native output line across several events.
    for name, output in outputs.items():
        for line in output.splitlines():
            if "POLARIS-ENTRY-PROFILE " in line:
                if not name.startswith("TestStart/"):
                    v.reject("entry-child-profile-owner")
                profiles.append(base64.b64decode(line.split("POLARIS-ENTRY-PROFILE ", 1)[1].strip(), validate=True))
                count += 1
    if count != 3:
        v.reject("entry-child-profile-inventory")
    statements_result = counters(root, profiles)
    if [outcomes["totals"][name]["observed"] for name in ("roots", "atoms")] != [37, 53] or branches["observed"] != 7 or len(supported) != 26:
        v.reject("entry-qualified-denominator")
    return {
        "status": "complete-under-assumptions",
        "qualification": "scoped-local-evidence-only",
        "archives": expected,
        "dependencies": dependencies,
        **({"dependency_impact": impact} if impact is not None else {}),
        "statements": statements_result,
        "boolean": outcomes,
        "controls": branches,
        "independence": {"raw": 27, "supported": 26, "concrete_pairs": proofs, "conditional": sorted(missing)},
        "basis": "Frozen TestParse/TestOptions inputs vary one total predicate; lifecycle nil/Canceled and startup nil/ErrIdentity pairs preserve the other predicate. Skipped operands have source-defined values, not native hits. Linux's platform constant supplies no opposite-outcome hit.",
    }


def tests(events: bytes) -> list[str]:
    """Recover names from the pinned native inventory; lifecycle validation separately rejects missing terminals."""
    return sorted({row["Test"] for line in events.splitlines() if (row := v.decode(line)).get("Action") == "run" and "Test" in row})


def bindings(root: Path, source: dict[str, bytes], reused: dict[str, bytes], exports: bytes) -> dict[str, str]:
    """Require identical current compiled/test/protocol inputs in both native campaigns and the actual workspace."""
    module = "github.com/eosforge/astra/"
    packages = statements.stream(exports)
    if not packages or any(
        not isinstance(row.get("ImportPath"), str) or not row["ImportPath"] or row.get("Incomplete") or row.get("DepsErrors") or row.get("Error")
        for row in packages
    ):
        v.reject("entry-current-import-closure")
    directories = {row["ImportPath"].removeprefix(module) for row in packages if row["ImportPath"].startswith(module)} | {"tools/decisions"}
    if "polaris" not in directories or "polaris/internal/server" not in directories or "polaris/internal/storage" not in directories:
        v.reject("entry-current-import-closure")
    actual = {path.relative_to(root).as_posix() for directory in directories for path in v.inside(root, directory).glob("*.go")}
    frozen = {name for name in source if name.endswith(".go") and PurePosixPath(name).parent.as_posix() in directories}
    if actual != frozen:
        v.reject("entry-current-input-inventory")
    protocol = {name for name in source if name.startswith("proto/") and name.endswith(".proto")}
    if protocol != {path.relative_to(root).as_posix() for path in (root / "proto").rglob("*.proto")}:
        v.reject("entry-current-protocol-inventory")
    selected = frozen | protocol | {"go.mod", "go.sum", "dependencies.lock.json", "tools/decisions/runtime.go.in"}
    if {name for name in reused if name.endswith(".go") and PurePosixPath(name).parent.as_posix() in directories} != frozen:
        v.reject("entry-current-reuse-inventory")
    result = {}
    for name in sorted(selected):
        data = v.read(v.inside(root, name))
        if source.get(name) != data or reused.get(name) != data:
            v.reject("entry-current-source-drift", name)
        result[name] = v.digest(data)
    if result["polaris/main.go"] != SOURCE:
        v.reject("entry-source-revision")
    return result


def renew(root: Path, archives: dict[str, bytes]) -> dict:
    """Join fresh current decision/control vectors with unchanged current Race statement coverage, never old dependency facts."""
    from tools import consumers, structure

    expected = artifacts(root)
    if set(archives) != set(expected) or any(not digest or v.digest(archives[name]) != digest for name, digest in expected.items()):
        v.reject("entry-current-archive-integrity")
    acquired = expected in (consumers.ACQUISITION, consumers.LEGACY_ACQUISITION)
    prefix = "commands/entry/" if acquired else "source/build/commands/entry/"
    profile_prefix = "commands/" if acquired else consumers.PREFIX
    if acquired:
        name, digest = next(iter(expected.items()))
        files = consumers.unpack(archives[name], digest)
        source, collected, streams = consumers.acquired(files)
        records = {item: collected["entry/entry-" + item.replace("/", "-")] for item in COMMANDS}
        outputs = {item: streams["entry/entry-" + item.replace("/", "-")] for item in COMMANDS}
        original, reused = files, source
        reused_records = {"entry-race": collected["entry/entry-race"]}
        reused_outputs = {"entry-race": streams["entry/entry-race"]}
    elif expected == MAINTENANCE:
        name, digest = next(iter(MAINTENANCE.items()))
        files = consumers.unpack(archives[name], digest)
        commands = tuple("entry-" + item.replace("/", "-") for item in COMMANDS) + ("entry-race",)
        source, collected, streams = consumers.native(files, "entry-maintenance-current-2", commands=commands, collected=True)
        # Names select original native records; no command or stream bytes are rewritten.
        records = {item: collected["entry-" + item.replace("/", "-")] for item in COMMANDS}
        outputs = {item: streams["entry-" + item.replace("/", "-")] for item in COMMANDS}
        original, reused, reused_records, reused_outputs = files, source, collected, streams
    else:
        name, digest = next(iter(CURRENT.items()))
        files = consumers.unpack(archives[name], digest)
        source, records, outputs = consumers.native(files, "entry-current-1", commands=COMMANDS, prefix="source/build/commands/entry/")
        original, reused, reused_records, reused_outputs = consumers.load(archives, "server-batch-consumers-current-1")
    dependencies = bindings(root, source, reused, outputs["typed/exports"])
    policy, _, _ = v.configuration(root / "development.json", root)
    check = next(row for row in policy["checks"] if row["id"] == "polaris-entry-qualification")
    inputs = v.decode(files["inputs.json"])
    test_names = inputs["entry_tests"] if acquired else inputs["tests"]
    if test_names != check["native_tests"] or inputs["package"] != "polaris" or not acquired and inputs["fixtures"]:
        v.reject("entry-current-test-policy")
    for key in ("typed/tests", "control/tests"):
        consumers.cases(outputs[key], PACKAGE, test_names)
        structure.terminals(outputs[key], test_names, package=structure.ENTRY)
    consumers.cases(reused_outputs["entry-race"], PACKAGE, test_names)
    owner = v.decode(original["owner.json" if acquired else "controller.json"])
    race_argv = v.decode(original["commands/entry-race/exec.native.json"])["declared_argv"] if acquired else reused_records["entry-race"]["argv"]
    if race_argv != [
        "/home/ubuntu/verdandi/build/tools/go-" + consumers.compiler(files) + "/bin/go" if acquired else "go",
        "test",
        "-json",
        "-race",
        "-count=1",
        "-p=2",
        "-parallel=1",
        "-timeout=180s",
        "-covermode=atomic",
        "-coverprofile=" + owner["cwd"] + "/source/build/commands/entry-race/coverage.out",
        "./polaris",
    ]:
        v.reject("entry-current-race-command")
    source_raw = files[prefix + "source.json"]
    frozen = v.decode(source_raw)
    if {row["path"]: row["sha256"] for row in frozen["files"] if row["sha256"] is not None} != inputs["files"]:
        v.reject("entry-current-trace-workspace")
    trace, control = (v.decode(files[prefix + name], maximum=statements.LIMIT) for name in ("typed/overlay/trace.json", "control/overlay/flow.json"))
    if trace["files"] != control["files"] or trace["source_sha256"] != control["source_sha256"] or trace["source_sha256"] != v.digest(source_raw):
        v.reject("entry-current-trace-binding")
    if len(trace["files"]) != 1 or trace["files"][0]["file"] != "polaris/main.go" or trace["files"][0]["sha256"] != SOURCE:
        v.reject("entry-native-scope")
    typed, edges = outputs["typed/tests"], outputs["control/tests"]
    report = logic.summary(trace, typed, PACKAGE, 50)
    inventory = logic.inventory(trace)
    rows, processes = logic.observe(trace, typed, PACKAGE, 50)
    if processes != 4 or report["totals"]["atoms"] != 27 or report["independence"]["search_incomplete"]:
        v.reject("entry-native-denominator")
    outcomes = structure.boolean(inventory, rows, (("polaris/main.go:3728", 0, True, "linux-target"),))
    completed = flow.summary(control, edges, PACKAGE, 50, root, control["source_sha256"])
    if completed["processes"] != 4:
        v.reject("entry-current-control-processes")
    branches = structure.controls(completed)
    supported = {(row["id"], atom["index"]) for row in report["decisions"] for atom in row["atoms"] if atom["independent"] is not None}
    baseline = [False, True, True, False, False, False, False]
    pairs = []
    for condition in range(6):
        changed = baseline.copy()
        changed[condition] = not changed[condition]
        pairs.append(("polaris/main.go:3093", condition, baseline, changed))
    pairs += [("polaris/main.go:7444", 0, [False, False], [True, False]), ("polaris/main.go:7975", 0, [False, False], [True, False])]
    proofs = []
    for identity, condition, before, after in pairs:
        decision = inventory[identity]
        pair = {
            "decision": identity,
            "condition": condition,
            "before": {"values": before, "result": authority.project(decision, before)[1]},
            "after": {"values": after, "result": authority.project(decision, after)[1]},
        }
        proofs.append(authority.correlate_pair(decision, pair, set(rows[identity])))
        supported.add((identity, condition))
    missing = {(identity, index) for identity, decision in inventory.items() for index in range(len(decision["atoms"]))} - supported
    if missing != {("polaris/main.go:3728", 0)} or outcomes["missing"] or branches["missing"]:
        v.reject("entry-decisions-uncovered")
    statements_result = counters(root, [original[profile_prefix + "entry-race/coverage.out"]], compiler=consumers.compiler(files) if acquired else "1.27.1")
    if [outcomes["totals"][key]["observed"] for key in ("roots", "atoms")] != [37, 53] or branches["observed"] != 7 or len(supported) != 26:
        v.reject("entry-qualified-denominator")
    return {
        "status": "complete-under-assumptions",
        "qualification": "scoped-local-evidence-only",
        "archives": expected,
        "dependencies": dependencies,
        "statements": statements_result,
        "boolean": outcomes,
        "controls": branches,
        "independence": {"raw": 27, "supported": 26, "concrete_pairs": proofs, "conditional": sorted(missing)},
        "current_native": {
            "decision_commands": {name: {"duration_ms": row["duration_ms"], "argv": row["argv"]} for name, row in records.items()},
            "race_record_sha256": v.digest(original[profile_prefix + "entry-race/record.json"]),
            "test_cases": 50,
            "trace_processes": processes,
            "control_processes": completed["processes"],
        },
        "basis": "Fresh current typed/control execution, exact current compiled/test/protocol inputs and the existing current Race atomic profile. Eight single-predicate pairs retain the original pure input axiom. Linux's platform constant creates no opposite hit. No historical dependency changes or native summaries supply current credit.",
    }
