"""Requalify unchanged Server logic with sealed native facts and explicit Admission dependency deltas."""

from pathlib import Path, PurePosixPath
import tempfile

from tools import admission, authority, astrolabe, entry, logic, statements, structure, verify as v, watchdog

# These original inputs retain their own identities; the current Race campaign is a separate fact source.
ARTIFACTS = {
    "server-independence-linux-2/evidence.tar.gz": "a73e9307c8b37bceb5950a4623fdaabb07521ceefad8c8d4843dcc90a6d7851b",
    "server-independence-linux-2/inputs.tar.gz": "fb5c77f80ac63533e1463a752099cfb2b7b7b0c764de27f42ce891c7f29f3e09",
    "reuse-plan/material-2/evidence.tar.gz": astrolabe.BASELINE,
    "reuse-plan/material-2/sealed.native.json": None,
}
PREFIX = "source/build/commands/server-independence/structure/"


def artifacts(root: Path) -> dict:
    """Select a reviewed native campaign by exact production bytes, preserving historical evidence separately."""
    from tools import ingress, installation

    if v.file_digest(root / installation.PATH) == installation.SOURCE:
        return ingress.archives(root)
    return ARTIFACTS


def authentication(before: bytes, after: bytes) -> str:
    """Prove that the reviewed material-loading revision preserves concrete runtime authentication bytes."""
    name = "internal/admission/identity.go"
    if v.digest(before) != admission.SOURCES[name] or v.digest(after) != admission.MATERIAL[name]:
        v.reject("server-identity-source")
    start, end = b"// Load reads bounded material", b"// login "
    if any(data.count(marker) != 1 for data in (before, after) for marker in (start, end)):
        v.reject("server-identity-boundary")
    if before.split(start)[0] != after.split(start)[0] or before.split(end)[1] != after.split(end)[1]:
        v.reject("server-runtime-authentication-drift")
    return v.digest(before.split(end)[1])


def delta(original: dict[str, bytes], current: dict[str, bytes]) -> dict:
    """Accept only the two reviewed changes, proving their unchanged runtime authentication boundary."""
    identity, node = "internal/admission/identity.go", "internal/admission/node.go"
    expected = {identity: admission.MATERIAL[identity], node: admission.NODE, **admission.MATERIAL}
    for name, digest in expected.items():
        if name not in current or v.digest(current[name]) != digest:
            v.reject("server-current-dependency", name)
    if any(name not in original or v.digest(original[name]) != admission.SOURCES[name] for name in (identity, node)):
        v.reject("server-original-dependency")
    # Neither the Identity representation/imports nor any decoder, TLS accessor or signature verifier changes.
    runtime = authentication(original[identity], current[identity])
    old = b"\t\tif err == nil || fatal(err) || ctx.Err() != nil {\n\t\t\treturn err\n\t\t}"
    new = (
        b"\t\tif err == nil || fatal(err) {\n\t\t\treturn err\n\t\t}\n"
        b"\t\t// Preserve permanent refusals and completed admission, but expose the owner's cancellation cause.\n"
        b"\t\tif ctx.Err() != nil {\n\t\t\treturn ctx.Err()\n\t\t}"
    )
    if original[node].count(old) != 1 or original[node].replace(old, new, 1) != current[node]:
        v.reject("server-node-delta")
    return {
        "original": {name: v.digest(original[name]) for name in (identity, node)},
        "current": {name: v.digest(current[name]) for name in sorted(expected)},
        "unchanged_identity_runtime_sha256": runtime,
        "boundary": "Load file acquisition and Join cancellation change; the Identity representation, runtime verification and all other Node methods remain byte-identical. Changed paths retain separate current Race evidence.",
    }


def impact(root: Path, original: dict[str, bytes], current: dict[str, bytes], exports: bytes) -> dict:
    """Bind the complete owned production import closure, Server tests, generators and concrete schedule fixtures."""
    module = "github.com/eosforge/astra/"
    packages = statements.stream(exports)
    if not packages or any(not isinstance(item.get("ImportPath"), str) for item in packages):
        v.reject("server-production-closure")
    directories = {item["ImportPath"][len(module) :] for item in packages if item["ImportPath"].startswith(module)}
    directories.add("tools/decisions")
    if structure.SERVER not in directories or structure.PACKAGE not in directories or structure.ENTRY in directories:
        v.reject("server-production-closure")
    expected = {
        name
        for name in original
        if name.endswith(".go")
        and PurePosixPath(name).parent.as_posix() in directories
        and (not name.endswith("_test.go") or name.startswith(structure.SERVER + "/"))
    }
    actual = {
        path.relative_to(root).as_posix()
        for directory in directories
        for path in v.inside(root, directory).glob("*.go")
        if not path.name.endswith("_test.go") or directory == structure.SERVER
    }
    added = set(admission.MATERIAL) - {"internal/admission/identity.go"}
    if actual != expected | added:
        v.reject("server-source-inventory")
    proof = delta(original, current)
    changed = {"internal/admission/identity.go", "internal/admission/node.go"}
    bindings = {}
    for name in sorted(actual | {"go.mod", "go.sum", "dependencies.lock.json", authority.FIXTURE, watchdog.FIXTURE}):
        data = v.read(v.inside(root, name))
        if name in changed | added:
            if data != current[name]:
                v.reject("server-current-source", name)
        elif name not in original or data != original[name]:
            v.reject("server-unreviewed-source-delta", name)
        # Server's complete current test package was executed, as were all owned runtime dependencies.
        if name.endswith(".go") and name not in current:
            v.reject("server-current-regression-source", name)
        if name in current and data != current[name]:
            v.reject("server-regression-source-drift", name)
        bindings[name] = v.digest(data)
    return {**proof, "sources": bindings, "directories": sorted(directories)}


def reference(files: dict[str, bytes], prefix: str, item: dict) -> bytes:
    """Resolve an exact original bundle member without extracting or remapping its recorded paths."""
    logic.fields(item, ("path", "bytes", "sha256"), "server-artifact")
    path = PurePosixPath(item["path"])
    if path.is_absolute() or ".." in path.parts or path.as_posix() != item["path"] or "\\" in item["path"] or ":" in item["path"]:
        v.reject("server-artifact-path")
    data = files[prefix + item["path"]]
    if item["bytes"] != len(data) or item["sha256"] != v.digest(data):
        v.reject("server-artifact-integrity")
    return data


def reconcile(root: Path, artifacts: dict[str, bytes]) -> dict:
    """Reconstruct original native denominators, then join a separately verified current dependency regression."""
    from tools import ingress

    if set(artifacts) == set(ingress.archives(root)):
        return ingress.reconcile(root, artifacts)
    if set(artifacts) != set(ARTIFACTS) or any(digest is not None and v.digest(artifacts[name]) != digest for name, digest in ARTIFACTS.items()):
        v.reject("server-retained-inventory-or-integrity")
    files = entry.retained(artifacts["server-independence-linux-2/evidence.tar.gz"], ARTIFACTS["server-independence-linux-2/evidence.tar.gz"])
    original = entry.unpack(artifacts["server-independence-linux-2/inputs.tar.gz"])
    inputs = v.decode(files["inputs.json"])
    if inputs["archive_sha256"] != ARTIFACTS["server-independence-linux-2/inputs.tar.gz"] or inputs["files"] != {
        name: v.digest(data) for name, data in original.items()
    }:
        v.reject("server-original-inputs")
    acquired, regression, events = astrolabe.acquisition(
        root, artifacts["reuse-plan/material-2/evidence.tar.gz"], v.decode(artifacts["reuse-plan/material-2/sealed.native.json"])
    )
    current = {name.removeprefix("source/"): data for name, data in acquired.items() if name.startswith("source/") and not name.startswith("source/build/")}
    proof = impact(root, original, current, files[PREFIX + "typed/exports/exports.stdout.log"])
    config = v.decode(original["development.json"])
    check = next(item for item in config["checks"] if item["adapter"] == "server-independence")
    structure.configuration(check)
    active, _, _ = v.configuration(root / "development.json", root)
    for item in active["checks"]:
        if item["adapter"] in {"server-independence", "server-structure"} and item["native_tests"] != check["native_tests"]:
            v.reject("server-native-inventory-policy")
    bundle = v.decode(files[PREFIX + "bundle.json"])
    source = reference(files, PREFIX, bundle["source"])
    trace = v.decode(files[PREFIX + "typed/overlay/trace.json"])
    control = v.decode(files[PREFIX + "control/overlay/flow.json"])
    dependencies = {name: reference(files, PREFIX, item) for name, item in bundle["dependencies"].items()}
    # Native argv, tool identities, original streams and their owned retirement remain original facts.
    native_root = PurePosixPath("/home/ubuntu/verdandi/astra/build/results/assurance/server-independence-linux-2/source")
    native_directory = native_root / "build/commands/server-independence/structure"
    for name, arguments, _ in structure.plan(native_directory, package=structure.SERVER, independence=True):
        record = v.decode(files[PREFIX + name + "/record.json"])
        if record["argv"] != [argument.replace("{root}", str(native_root)) for argument in arguments]:
            v.reject("server-native-command", name)
        if record["executable_sha256"] != astrolabe.GO and name not in {"typed/collector", "control/collector"}:
            v.reject("server-native-tool", name)
    package = authority.PACKAGE
    astrolabe.terminals(events, package, check["native_tests"])
    with tempfile.TemporaryDirectory() as directory:
        mirror = Path(directory)
        for name, data in original.items():
            if name.endswith(".go") or name in {authority.FIXTURE, watchdog.FIXTURE}:
                path = mirror / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        report = structure.reconcile(
            root=mirror,
            source_sha256=v.digest(source),
            tests=check["native_tests"],
            profiles=(reference(files, PREFIX, bundle["profiles"]["parent"]),),
            dependency=dependencies,
            trace=trace,
            boolean_events=files[PREFIX + "typed/tests/tests.stdout.log"],
            control=control,
            control_events=files[PREFIX + "control/tests/tests.stdout.log"],
            package=structure.SERVER,
        )
        profiles = {}
        for profile in authority.PROFILES:
            prefix = PREFIX + "authority/" + profile + "/"
            record = v.decode(files[prefix + "record.json"])
            profiles[profile] = {"record": record, **{key: files[prefix + record[key]["path"]] for key in ("stdout", "stderr")}}
        packages = statements.stream(files[PREFIX + "typed/packages/packages.stdout.log"])
        if len(packages) != 1 or packages[0].get("ImportPath") != package:
            v.reject("server-native-package")
        count = sum(len(packages[0].get(field, [])) for field in ("TestGoFiles", "XTestGoFiles"))
        independent = authority.correlate(mirror, trace, files[PREFIX + "typed/tests/tests.stdout.log"], count, profiles)
    counts = [
        report["statements"]["reachable_under_assumptions"]["statements_hit"],
        report["boolean"]["totals"]["roots"]["observed"],
        report["boolean"]["totals"]["atoms"]["observed"],
        report["controls"]["observed"],
    ]
    if (
        report["status"] != "complete-under-assumptions"
        or counts != structure.domain(structure.SERVER)["counts"]
        or independent["status"] != "complete-under-declared-domains"
        or [independent[key] for key in ("raw_conditions", "supported_conditions", "qualified_denominator")] != [214, 210, 210]
        or independent["unresolved"]
        or len(independent["literal_exclusions"]) != 3
        or len(independent["domain_exclusions"]) != 1
    ):
        v.reject("server-retained-uncovered")
    return {
        **report,
        "independence": independent,
        "dependency_impact": proof,
        "current_regression": {"archive_sha256": astrolabe.BASELINE, "record_sha256": v.digest(v.encode(regression)), "stdout_sha256": v.digest(events)},
        "application_commands": 0,
        "qualification": "Current unchanged Server package structure and MC/DC at local trust under explicit dependency assumptions; Polaris entry, whole-rule and protected release qualification remain separate.",
    }
