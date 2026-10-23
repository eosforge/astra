"""Bind real Admission defect counterexamples to native old/new runs and current compiler-owned inputs."""

from pathlib import Path, PurePosixPath
import sys

from tools import admissioncompiler, consumers, entry, impact, predicates, statements, verify as v

ARCHIVES = {
    "admission-red/evidence.tar.gz": "455b586fb9efaea50d76d539c12e260fe796ce062640423022d72a1926596bc2",
    "admission-green/evidence.tar.gz": "c60a844a1c9fa18171c7fd05caa5eaabef0d2ff75b90ddfef81743696f287999",
    "admission-reuse-current/native/evidence.tar.gz": "fbb0d24978ce79fb6afa9e1d019840b93a52d7f36d65dfca44a8660392fb7335",
    "admission-replacement-red-current-2/native/evidence.tar.gz": "e57e202ab08ac2cfc4562d95071784e3a828a59551159bbfe88ae794100d6820",
    "server-batch-consumers-current-1/native/evidence.tar.gz": consumers.ARCHIVES["server-batch-consumers-current-1"],
}
RENEWED = {
    "go-upgrade-contracts-current-3/native/evidence.tar.gz": "bd374f0c01f159579b7d6a5d997f18537efdd9ee7b8ef22163ece1ecbd7fb93d",
    "go-upgrade-admission-structure-current-1/evidence.tar.gz": admissioncompiler.ARTIFACTS[admissioncompiler.GEOMETRY],
}
GO = "30969f97169d7f43fe6a085873d75613adc21e30818a8c61d95bd27275df4624"
NODE = "375da6dfab3ad7e58f8314e339c271e4ab3a8b50050a53cec765b2980249148c"
IDENTITY = "d172cc85f0e6a6099699b0c4a3cea3813cbf5e7e04d7be23ffca464be56ea09b"
REPLACEMENT = "2d2fa95ccdc93582e79d8a862b4de3926d8373952e4b6e68486c9e0392687595"
CASES = {"TestLoadReplacement/" + name for name in ("ca.pem", "cert.pem", "key.pem", "admission.pub", "login.json")}
CHECK = {
    "id": "admission-gap-redgreen",
    "adapter": "admission-repair",
    "component": "admission",
    "argv": ["python3", "-B", "-m", "tools.repair"],
    "environment": {"PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": "{run}/tmp"},
    "expected_tests": ["counterexamples"],
    "native_tests": ["TestProcess/admission", *sorted(CASES)],
    "platforms": ["linux-amd64-cgo"],
    "probes": [{"contract": "ADMISSION-ASSURANCE", "test": "counterexamples", "minimum_hits": 6}],
    "timeout_s": 120,
    "log_bytes": 1024 * 1024,
}


def configuration(check: dict) -> None:
    """Fix the six-counterexample denominator and actual native product platform."""
    if check != CHECK:
        v.reject("repair-configuration")


def archive(raw: bytes, name: str) -> dict[str, bytes]:
    """Accept only reviewed original archives, retaining the older collection's absent member manifest."""
    if name not in ARCHIVES or v.digest(raw) != ARCHIVES[name]:
        v.reject("repair-archive-integrity")
    # This earlier native collection predates the member manifest. Its exact archive digest still binds every byte.
    if name == "admission-reuse-current/native/evidence.tar.gz":
        return entry.unpack(raw)
    return consumers.unpack(raw, ARCHIVES[name])


def command(files: dict[str, bytes], prefix: str, expected: int) -> tuple[dict, list[dict]]:
    """Read a native command's hashed channels, preserving its actual nonzero expected-red exit."""
    record = v.decode(files[prefix + "record.json"])
    v.schema(record, "evidence", ("properties", "checks", "items"))
    if (
        record["platform"] != "linux-amd64-cgo"
        or record["exit_code"] != expected
        or record["complete"] is not True
        or record["cleanup"] is not True
        or record["termination"] != "exited"
        or record["executable_sha256"] != GO
        or record["toolchain"]["command"]["sha256"] != GO
        or record["toolchain"]["command"]["path"] != record["executable"]
        or v.stamp(record["finished_at"]) < v.stamp(record["started_at"])
    ):
        v.reject("repair-command-incomplete")
    channels = {}
    for name in ("stdout", "stderr"):
        reference = record[name]
        path = reference["path"]
        if not path or PurePosixPath(path).name != path:
            v.reject("repair-channel-path")
        data = files[prefix + path]
        if len(data) != reference["bytes"] or v.digest(data) != reference["sha256"]:
            v.reject("repair-channel-integrity")
        channels[name] = data
    if channels["stderr"]:
        v.reject("repair-command-diagnostic")
    return record, statements.stream(channels["stdout"])


def native(files: dict[str, bytes], prefix: str) -> dict[str, bytes]:
    """Authenticate legacy and current source collections without treating expected product failure as runner failure."""
    inputs, owner, terminal, cleanup = (v.decode(files[name]) for name in ("inputs.json", "controller.json", "terminal.json", "cleanup.native.json"))
    modern = "source_archive_sha256" in inputs
    source_name = "source.tar.gz" if "source.tar.gz" in files else "inputs.tar.gz"
    source = entry.unpack(files[source_name])
    key = "source_archive_sha256" if modern else "archive_sha256"
    service = cleanup.get("unit", cleanup.get("service"))
    if (
        v.digest(files[source_name]) != inputs[key]
        or {name: v.digest(data) for name, data in source.items()} != inputs["files"]
        or {row["path"]: row["sha256"] for row in inputs["source"]["files"] if row["sha256"] is not None} != inputs["files"]
        or v.digest(files["run.py"]) != owner["script_sha256"]
        or owner["boot_id"] != cleanup["boot_id"]
        or terminal["errors"]
        or terminal["interrupted"] is not False
        or terminal["remaining_owned"]
        or service["MainPID"] != "0"
        or service["ControlGroup"]
        or service["InvocationID"] not in ("", owner["invocation_id"])
        or service["ExecMainStatus"] != "0"
        or owner["identity"] not in cleanup["retired"]
        or len({(row["pid"], row["start_ticks"]) for row in cleanup["retired"]}) != len(cleanup["retired"])
    ):
        v.reject("repair-native-source-or-lifecycle")
    if modern:
        mirror = v.decode(files["git-mirror.native.json"])
        returned = v.decode(files["cache-restored.native.json"])
        handed = v.decode(files["cache-handoff.native.json"])
        if (
            owner["inputs_sha256"] != v.digest(files["inputs.json"])
            or owner["script_sha256"] != inputs["run_sha256"]
            or inputs["boot_id"] != owner["boot_id"]
            or cleanup["source_verified"] != len(source)
            or cleanup["original_exit_code"] != 0
            or cleanup["cache_inode"] != 713912
            or terminal["cache_restored"] is not True
            or handed["inode"] != 713912
            or returned["inode"] != 713912
            or returned["path"] != handed["from"]
            or returned["remaining_owned"]
            or handed["to"] != owner["cwd"] + "/source/build/cache/go"
            or mirror["origin_source"] != inputs["source"]
            or {row["path"]: row["sha256"] for row in mirror["source"]["files"]} != inputs["files"]
        ):
            v.reject("repair-native-current-boundary")
        journal = [v.decode(row) for row in files["journal.native.jsonl"].splitlines()]
        unit = "astra-" + PurePosixPath(owner["cwd"]).name + ".service"
        if (
            not journal
            or any(
                row.get("_BOOT_ID") != owner["boot_id"].replace("-", "")
                or (row.get("INVOCATION_ID") or row.get("_SYSTEMD_INVOCATION_ID")) != owner["invocation_id"]
                for row in journal
            )
            or sum(row.get("MESSAGE", "").startswith("Started " + unit + " - ") for row in journal) != 1
            or sum(row.get("MESSAGE") == unit + ": Deactivated successfully." for row in journal) != 1
            or [v.decode(row["MESSAGE"]) for row in journal if row.get("MESSAGE", "").startswith('{"at":')] != [terminal]
        ):
            v.reject("repair-native-journal")
    elif terminal["source_unchanged"] is not True or ("pins_unchanged" in terminal and terminal["pins_unchanged"] is not True):
        v.reject("repair-native-legacy-boundary")
    active = [name for name in files if name.startswith(prefix) and name.endswith(".process.json")]
    if len(active) != 1:
        v.reject("repair-command-owner")
    process = v.decode(files[active[0]])
    record = v.decode(files[prefix + "record.json"])
    if (
        process["boot_id"] != owner["boot_id"]
        or process["identity"]["parent"] != owner["identity"]["pid"]
        or process["identity"] not in cleanup["retired"]
        or process["argv"] != record["argv"]
        or process["cwd"] != owner["cwd"] + "/source"
    ):
        v.reject("repair-command-owner")
    return source


def cases(frames: list[dict], expected: set[str], status: str, reason: str | None = None, *, packages: set[str] | None = None) -> None:
    """Require each named semantic counterexample to run and terminate once for its actual target reason."""
    package = "github.com/eosforge/astra/" + ("polaris" if "TestProcess/admission" in expected else "internal/admission")
    allowed = packages if packages is not None else {package}
    if (
        not expected
        or status not in {"pass", "fail"}
        or package not in allowed
        or not frames
        or any(row.get("Package") not in allowed or row.get("Action") in {"skip", "build-fail"} for row in frames)
    ):
        v.reject("repair-case-package-or-status")
    opposite = "fail" if status == "pass" else "pass"
    if any(row.get("Action") == opposite for row in frames):
        v.reject("repair-case-contradictory")
    runs = [(row["Package"], row["Test"]) for row in frames if row.get("Action") == "run" and "Test" in row]
    finished = [(row["Package"], row["Test"]) for row in frames if row.get("Action") == status and "Test" in row]
    if not runs or len(set(runs)) != len(runs) or sorted(runs) != sorted(finished):
        v.reject("repair-case-incomplete")
    if status == "fail":
        parents = {name.rsplit("/", 1)[0] for name in expected if "/" in name}
        if set(runs) != {(package, name) for name in expected | parents}:
            v.reject("repair-case-unrelated-failure")
    for name in expected:
        selected = [row for row in frames if row.get("Package") == package and row.get("Test") == name]
        if sum(row.get("Action") == "run" for row in selected) != 1 or sum(row.get("Action") == status for row in selected) != 1:
            v.reject("repair-case-missing-or-duplicate", name)
        if any(row.get("Action") in ({"fail", "pass"} - {status}) for row in selected):
            v.reject("repair-case-contradictory", name)
        if reason and sum(reason in row.get("Output", "") for row in selected) != 1:
            v.reject("repair-case-wrong-reason", name)
    if any(sum(row.get("Package") == name and row.get("Action") == status and "Test" not in row for row in frames) != 1 for name in allowed):
        v.reject("repair-package-incomplete")


def project(data: bytes, targets: dict[str, set[str]]) -> list[dict]:
    """Select exact counterexamples and their parents from complete authenticated native package streams."""
    selected = {package: names | {name.rsplit("/", 1)[0] for name in names if "/" in name} for package, names in targets.items()}
    result = []
    for line in data.splitlines():
        row = v.decode(line)
        if not isinstance(row, dict) or not isinstance(row.get("Action"), str) or not isinstance(row.get("Package"), str):
            v.reject("repair-current-event")
        package, name = row["Package"], row.get("Test")
        if package in selected and (name is None or name in selected[package]):
            result.append(row)
    return result


def profiles(root: Path, files: dict[str, bytes], bindings: dict[str, str], fixture: str, *, inventory: dict[str, list[str]] | None = None) -> dict:
    """Authenticate the two retained Go 1.27.2 green profiles without relabeling their original commands or old causal fixtures."""
    inputs, owner, terminal, cleanup = (v.decode(files[name]) for name in ("inputs.json", "controller.json", "terminal.json", "cleanup.native.json"))
    source = entry.unpack(files["source.tar.gz"])
    native = "/home/ubuntu/verdandi/astra/build/results/assurance/go-upgrade-contracts-current-3"
    if (
        inputs["linux_go"] != admissioncompiler.GO
        or inputs["linux_go_sha256"] != admissioncompiler.GO_SHA
        or v.digest(files["run.py"]) != inputs["run_sha256"]
        or v.digest(files["source.tar.gz"]) != inputs["source_archive_sha256"]
        or {name: v.digest(data) for name, data in source.items()} != inputs["files"]
        or terminal["errors"]
        or terminal["interrupted"] is not False
        or terminal["remaining_owned"]
        or terminal["cache_returned"] is not True
        or cleanup["failed"] is not False
        or cleanup["unit"]["MainPID"] != "0"
        or cleanup["unit"]["ControlGroup"]
        or cleanup["unit"]["ExecMainStatus"] != "0"
        or owner["identity"] not in cleanup["retired"]
        or owner["limits"] != {"cpu.max": "400000 100000", "memory.max": "3221225472", "memory.swap.max": "0", "pids.max": "512"}
        or any(int(value) for _, value in (line.split() for line in terminal["resources"]["memory.events"].splitlines()))
        or int(terminal["resources"]["memory.peak"]) > 3221225472
        or int(terminal["resources"]["pids.peak"]) > 512
    ):
        v.reject("repair-current-native")
    if any(name not in source or v.digest(source[name]) != digest for name, digest in bindings.items()):
        v.reject("repair-current-compiled-source")
    actual = {row["path"]: row["sha256"] for row in v.source(root)["files"] if row["sha256"] is not None}

    def production(name: str) -> bool:
        """Include every current root-module production file and the cancellation package's complete test helpers."""
        return name.endswith(".go") and (
            name.startswith(("internal/", "polaris/", "astrolabe/")) and not name.endswith("_test.go") or PurePosixPath(name).parent.as_posix() == "polaris"
        )

    owned = {name: digest for name, digest in actual.items() if production(name)}
    if not owned or {name: v.digest(data) for name, data in source.items() if production(name)} != owned:
        v.reject("repair-current-root-source")
    # Current cancellation uses its actual later oracle; the historical defect pair retains its older file identity.
    if v.digest(source["polaris/process_test.go"]) != v.file_digest(root / "polaris/process_test.go"):
        v.reject("repair-current-cancellation-fixture")
    modules = {name: v.file_digest(root / name) for name in ("go.mod", "go.sum", "dependencies.lock.json")}
    if any(v.digest(source[name]) != digest for name, digest in modules.items()):
        v.reject("repair-current-modules")
    journal = [v.decode(line) for line in files["journal.native.jsonl"].splitlines()]
    if (
        not journal
        or any(row.get("_BOOT_ID") != owner["boot_id"].replace("-", "") for row in journal)
        or any((row.get("INVOCATION_ID") or row.get("_SYSTEMD_INVOCATION_ID")) != owner["invocation_id"] for row in journal)
        or not any(
            row.get("_PID") == "1" and row.get("MESSAGE") == "astra-go-upgrade-contracts-current-3.service: Deactivated successfully." for row in journal
        )
    ):
        v.reject("repair-current-journal")
    observed = {}
    targets = {
        "github.com/eosforge/astra/internal/admission": CASES,
        "github.com/eosforge/astra/polaris": {"TestProcess/admission"},
    }
    if inventory is not None and (
        not inventory
        or any(
            not package.startswith("github.com/eosforge/astra/") or not expected or len(expected) != len(set(expected))
            for package, expected in inventory.items()
        )
    ):
        v.reject("repair-current-package-inventory")
    for profile in ("ordinary", "race"):
        label = "root-" + profile
        prefix = "source/build/commands/" + label + "-test/"
        worker, stopped = (v.decode(files[label + suffix + ".json"]) for suffix in ("-owner", "-terminal"))
        record, request, process = (v.decode(files[prefix + name]) for name in ("record.json", "request.json", label + "-test.process.json"))
        v.schema(record, "evidence", ("properties", "checks", "items"))
        argv = [admissioncompiler.GO, "-C", native + "/source", "test"]
        argv += (["-race"] if profile == "race" else []) + [
            "-p=2",
            "-parallel=2",
            "-count=1",
            "-timeout=300s",
            "-skip=^TestSystemThreeStars$",
            "-json",
            "./...",
        ]
        if (
            worker["inputs_sha256"] != v.digest(files["inputs.json"])
            or worker["script_sha256"] != inputs["run_sha256"]
            or worker["identity"]["parent"] != owner["identity"]["pid"]
            or worker["identity"] not in cleanup["retired"]
            or stopped["errors"]
            or stopped["interrupted"] is not False
            or stopped["remaining_owned"]
            or record["argv"] != argv
            or request["argv"] != argv
            or process["argv"] != argv
            or process["identity"]["parent"] != worker["identity"]["pid"]
            or process["identity"] not in cleanup["retired"]
            or process["boot_id"] != owner["boot_id"]
            or process["cwd"] != native + "/source"
            or record["platform"] != "linux-amd64-cgo"
            or record["exit_code"] != 0
            or record["complete"] is not True
            or record["cleanup"] is not True
            or record["termination"] != "exited"
            or record["executable"] != admissioncompiler.GO
            or record["executable_sha256"] != admissioncompiler.GO_SHA
            or record["toolchain"]["command"] != {"path": admissioncompiler.GO, "sha256": admissioncompiler.GO_SHA}
            or request["timeout_s"] != 900
            or record["duration_ms"] > 900000
            or request["log_bytes"] != 32 * 1024**2
            or record["environment"] != request["environment"]
            or record["resolved_environment"] != request["environment"] | {"LANG": "C.UTF-8"}
            or any(
                record["environment"].get(key) != value
                for key, value in {
                    "GOMAXPROCS": "2",
                    "GOTOOLCHAIN": "local",
                    "GOFLAGS": "-mod=readonly",
                    "CGO_ENABLED": "1",
                    "GOPROXY": "off",
                    "GOSUMDB": "off",
                    "GOWORK": "off",
                }.items()
            )
        ):
            v.reject("repair-current-command")
        channels = {}
        for field in ("stdout", "stderr"):
            reference = record[field]
            if PurePosixPath(reference["path"]).name != reference["path"] or reference["bytes"] > request["log_bytes"]:
                v.reject("repair-current-channel")
            data = files[prefix + reference["path"]]
            if len(data) != reference["bytes"] or v.digest(data) != reference["sha256"]:
                v.reject("repair-current-channel")
            channels[field] = data
        if channels["stderr"]:
            v.reject("repair-current-diagnostic")
        packages = {}
        if inventory is None:
            selected = project(channels["stdout"], targets)
            cases(selected, CASES, "pass", packages=set(targets))
            cases(selected, {"TestProcess/admission"}, "pass", packages=set(targets))
        else:
            rows = [(line, v.decode(line)) for line in channels["stdout"].splitlines(keepends=True)]
            for package, expected in inventory.items():
                selected = [(line, row) for line, row in rows if row.get("Package") == package]
                data = b"".join(line for line, _ in selected)
                consumers.cases(data, package, expected)
                if any(row.get("Action") in {"fail", "skip", "build-fail"} for _, row in selected):
                    v.reject("repair-current-package-failed", package)
                packages[package] = {"expected": sorted(expected), "tests": len(expected), "projection_sha256": v.digest(data)}
        observed[profile] = {
            "record_sha256": v.digest(files[prefix + "record.json"]),
            "argv": argv,
            "GOMAXPROCS": "2",
            "cases": CHECK["native_tests"],
            "duration_ms": record["duration_ms"],
            "host_timeout_s": request["timeout_s"],
        }
        if inventory is not None:
            observed[profile].pop("cases")
            observed[profile].update(packages=packages, original_stdout_sha256=record["stdout"]["sha256"])
    if inventory is not None:
        return {
            "compiler": "1.27.2",
            "profiles": observed,
            "boundary": "Exact complete consumer inventories projected from the original current two-processor root commands; original source, argv, streams and retirement stay intact. No separately configured command, skipped scenario, new coverage or new mutation is inferred.",
        }
    return {
        "compiler": "1.27.2",
        "profiles": observed,
        "current_fixture_sha256": v.digest(source["polaris/process_test.go"]),
        "historical_fixture_sha256": fixture,
        "boundary": "Original same-environment defect pairs remain historical. These are actual later two-processor ordinary/Race green extensions, not executions of today's differently configured direct check or new red runs.",
    }


def renewal(root: Path, artifacts: dict[str, bytes], original: dict[str, bytes], history: dict) -> dict:
    """Join the exact permitted module upgrade, fresh compiler-owned closure and original causal proof."""
    from tools import qualificationdata

    geometry = entry.unpack(artifacts["go-upgrade-admission-structure-current-1/evidence.tar.gz"])
    inputs, streams = admissioncompiler.receipt(root, geometry)
    bindings = predicates.sources(root, inputs["files"], statements.stream(streams["typed/exports"]))
    owned = {PurePosixPath(name).parent.as_posix() for name in bindings if name.startswith("internal/") and name.endswith(".go")}
    if sorted(owned) != history["owned_imports"]:
        v.reject("repair-current-import-closure")
    bindings.update({name: digest for name, digest in inputs["files"].items() if name.startswith("tests/fixtures/")})
    differences = {name for name in history["bindings"] if history["bindings"][name] != bindings.get(name)}
    if differences != {"go.mod", "go.sum"} or any(name not in original for name in history["bindings"]):
        v.reject("repair-current-upgrade-delta")
    files = qualificationdata.unpack(artifacts["go-upgrade-contracts-current-3/native/evidence.tar.gz"])
    current = profiles(root, files, {name: bindings[name] for name in history["bindings"]}, history["repairs"]["cancellation"]["fixture_sha256"])
    current["module_changes"] = {name: {"before": history["bindings"][name], "after": bindings[name]} for name in sorted(differences)}
    return history | {"historical_bindings": history["bindings"], "bindings": bindings, "current": current, "archives": ARCHIVES | RENEWED}


def reconcile(root: Path, artifacts: dict[str, bytes] | None = None) -> dict:
    """Join two real production fixes; synthetic reader controls and historical fixtures retain their separate identities."""
    upgraded = admissioncompiler.upgraded(root)
    expected = ARCHIVES | RENEWED if upgraded else ARCHIVES
    if artifacts is None:
        artifacts = {name: v.read(root / "build/results/assurance/reuse-plan" / name, 64 * 1024**2) for name in expected}
    if set(artifacts) != set(expected) or any(v.digest(data) != expected[name] for name, data in artifacts.items()):
        v.reject("repair-archive-inventory")
    files = {name: archive(artifacts[name], name) for name in ARCHIVES}
    red = files["admission-red/evidence.tar.gz"]
    green = files["admission-green/evidence.tar.gz"]
    latest = files["admission-reuse-current/native/evidence.tar.gz"]
    replacement = files["admission-replacement-red-current-2/native/evidence.tar.gz"]
    old, fixed = (native(item, "source/build/entry/") for item in (red, green))
    original = native(latest, "source/build/commands/admission-model/")
    current = native(replacement, "source/build/commands/admission-replacement-red/")
    changed = {name for name in old.keys() | fixed.keys() if old.get(name) != fixed.get(name)}
    if changed != {"internal/admission/node.go", "internal/admission/node_test.go"} or v.digest(fixed["internal/admission/node.go"]) != NODE:
        v.reject("repair-cancellation-source-pair")
    if old["polaris/process_test.go"] != fixed["polaris/process_test.go"]:
        v.reject("repair-cancellation-counterexample")
    _, node_red = command(red, "source/build/entry/", 1)
    _, node_green = command(green, "source/build/entry/", 0)
    cases(node_red, {"TestProcess/admission"}, "fail", "entry failed to exit normally before the cancellation budget")
    cases(node_green, {"TestProcess/admission"}, "pass", packages={"github.com/eosforge/astra/" + name for name in ("internal/admission", "polaris")})
    record, replaced_red = command(replacement, "source/build/commands/admission-replacement-red/", 1)
    _, replaced_green = command(latest, "source/build/commands/admission-model/", 0)
    cases(replaced_red, CASES, "fail", "replacement material published an identity")
    cases(replaced_green, CASES, "pass")
    expected = CASES | {"TestLoadReplacement"}
    if {row["Test"] for row in replaced_red if row.get("Action") == "run" and "Test" in row} != expected:
        v.reject("repair-replacement-selection")
    overlay = str(PurePosixPath(v.decode(replacement["controller.json"])["cwd"]) / "source/build/identity-before.json")
    if "-overlay=" + overlay not in record["argv"] or "-run=^TestLoadReplacement$" not in record["argv"]:
        v.reject("repair-replacement-overlay")
    observed = v.decode(replacement["observed.native.json"])
    if (
        observed["baseline_sha256"] != v.digest(old["internal/admission/identity.go"])
        or observed["counterexample_sha256"] != REPLACEMENT
        or observed["record_sha256"] != v.digest(replacement["source/build/commands/admission-replacement-red/record.json"])
        or observed["target_failures"] != len(CASES)
        or observed["kind"] != "expected-red"
        or set(observed["failed_cases"]) != expected
        or len(observed["failed_cases"]) != len(expected)
    ):
        v.reject("repair-replacement-native-observation")
    compiler = files["server-batch-consumers-current-1/native/evidence.tar.gz"]
    compiler_source, _, outputs = consumers.native(compiler, "server-batch-consumers-current-1")
    graph = impact.graph(outputs["exports"])
    owned, pending = {"internal/admission"}, ["internal/admission"]
    while pending:
        for name in graph[pending.pop()]:
            if name not in owned:
                owned.add(name)
                pending.append(name)
    names = {name for name in current if name.endswith(".go") and PurePosixPath(name).parent.as_posix() in owned}
    names |= {"go.mod", "go.sum", "dependencies.lock.json", "tests/fixtures/admission-v1.json", "tests/fixtures/pulsar/admission.key"}
    names |= {name for name in current if any(name.startswith("tests/fixtures/" + value + "/") for value in ("star-a", "star-b", "expired"))}
    actual = {row["path"]: row["sha256"] for row in v.source(root)["files"] if row["sha256"] is not None}
    current_go = {name for name in actual if name.endswith(".go") and PurePosixPath(name).parent.as_posix() in owned}
    if current_go != {name for name in names if name.endswith(".go")}:
        v.reject("repair-owned-source-inventory")
    bindings = {}
    for name in sorted(names):
        if (
            name not in original
            or name not in compiler_source
            or original[name] != current[name]
            or compiler_source[name] != current[name]
            or not upgraded
            and actual.get(name) != v.digest(current[name])
        ):
            v.reject("repair-current-source-drift", name)
        bindings[name] = v.digest(current[name])
    if (
        bindings.get("internal/admission/node.go") != NODE
        or bindings.get("internal/admission/identity.go") != IDENTITY
        or bindings.get("internal/admission/replacement_linux_amd64_test.go") != REPLACEMENT
    ):
        v.reject("repair-current-production-or-counterexample")
    result = {
        "trust": "local",
        "repairs": {
            "cancellation": {
                "red": "admission-red",
                "green": "admission-green",
                "cases": ["TestProcess/admission"],
                "fixture_sha256": v.digest(old["polaris/process_test.go"]),
                "current_production_sha256": NODE,
            },
            "replacement": {
                "red": "admission-replacement-red-current-2",
                "green": "admission-reuse-current",
                "cases": sorted(CASES),
                "fixture_sha256": REPLACEMENT,
                "current_production_sha256": IDENTITY,
                "old_identity_sha256": observed["baseline_sha256"],
            },
        },
        "bindings": bindings,
        "owned_imports": sorted(owned),
        "archives": ARCHIVES,
        "boundary": "Two known production fixes, six semantic counterexamples and their native old/new source identities. The historical cancellation fixture remains historical. The replacement overlay is bound by its frozen deterministic runner recipe and archived original source; generated overlay files were not retained. No new green execution, generic defect-freedom, protected CI or release claim.",
    }
    return renewal(root, artifacts, current, result) if upgraded else result


def observations(data: bytes, check: dict, root: Path) -> tuple[dict, list]:
    """Recompute native proof before admitting output; a fabricated six-case report supplies no credit."""
    configuration(check)
    try:
        actual = reconcile(root)
    except (OSError, KeyError, TypeError, ValueError) as error:
        v.reject("repair-facts-unavailable", type(error).__name__)
    if v.decode(data) != actual:
        v.reject("repair-observation-mismatch")
    return {"ADMISSION-ASSURANCE": sum(len(item["cases"]) for item in actual["repairs"].values())}, []


def main() -> int:
    """Print only source-bound interpretation; original expected-red records remain unchanged."""
    try:
        if len(sys.argv) != 1:
            v.reject("repair-arguments")
        print(v.encode(reconcile(Path.cwd())).decode(), end="")
        return 0
    except (v.Invalid, OSError, KeyError, TypeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
