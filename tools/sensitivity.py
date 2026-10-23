"""Join sealed Storage mutation facts without rerunning unchanged operators or rewriting failures."""

import base64
import io
from pathlib import Path, PurePosixPath
import tarfile
import tempfile

from tools import mutate, storage, verify as v

BASE = "build/results/assurance/reuse-plan"
ORIGINS = {
    "storage-core-current-3": "3e1f13d88afcf3a320ff22bf0de9c25ad2877fa39f471e7878949cf84c644e70",
    "storage-boundaries-current-1": "20357cc4e2bb17161caa698b3cc9f96a93d5535f98caa6e6706154b9811f8d92",
}
SURVIVORS = {"commit-scope-limit", "commit-total-write", "receipt-key", "receipt-erase", "history-prefix-delete"}
PACKAGE = "polaris/internal/storage/"
TOOLS = {
    "command": "30969f97169d7f43fe6a085873d75613adc21e30818a8c61d95bd27275df4624",
    "CC": "5ba72afdc29ac57b805ee21e48babe16b31385c03caf91fdd4336483c5a84195",
    "CXX": "1d90c88f14873d7a56f015f31ebe1b72a24942fe379d63eac35d18c1d22970f1",
}
MAXIMUM = 64 * 1024**2
CURRENT = {
    "storage-idle-core-current-1": "b10455c0849617d1a1d21d0a4a1c811a817697fadbea5b7fc792a08e2b7f0697",
    "storage-idle-operators-1": "115443072e2c19582cbe31cef0342c9716d5e83ac9f195c31f5ded29ef7a664c",
    "storage-version-boundary-current-2": "5f623e6a89c7cfc4fcf9515358a0fef75a6cc98046b0ede4785f7017ed23b6ca",
}
WITNESSES = {
    "maintenance-cadence": "one bounded maintenance attempt reaches the exact refusal",
    "maintenance-child": "completed maintenance cancels its child before the next iteration",
    "version-size": "version scanner accepts the exact eight-byte BLOB",
}


def packed(files: dict, inputs: dict, name: str) -> dict[str, bytes]:
    """Read a bounded original input pack, requiring its complete declared inventory and byte identities."""
    key = "files" if name == "source" else "artifacts"
    data = files[name + ".tar.gz"]
    if v.digest(data) != inputs[("source" if name == "source" else "artifact") + "_archive_sha256"]:
        v.reject("sensitivity-input-archive", name)
    values, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            total += member.size
            if (
                not member.isfile()
                or str(path) != member.name
                or path.is_absolute()
                or ".." in path.parts
                or member.name in values
                or member.name not in inputs[key]
                or member.size > MAXIMUM
                or total > 128 * 1024**2
            ):
                v.reject("sensitivity-input-boundary", member.name)
            values[member.name] = archive.extractfile(member).read()
    if {name: v.digest(data) for name, data in values.items()} != inputs[key]:
        v.reject("sensitivity-input-inventory", name)
    return values


def acquired(root: Path, name: str, artifacts: dict | None = None) -> tuple[dict, dict, dict]:
    """Authenticate current native inputs, controller retirement and cache return without trusting summary counts."""
    from tools import idle

    directory = root / BASE / name / "native"
    data, seal = (
        artifacts[name] if artifacts is not None else (v.read(directory / "evidence.tar.gz", MAXIMUM), v.decode(v.read(directory / "sealed.native.json")))
    )
    if seal["sha256"] != CURRENT[name] or v.digest(data) != CURRENT[name] or seal["bytes"] != len(data) or seal["trust"] != "local":
        v.reject("sensitivity-current-integrity", name)
    files = idle.unpack(data)
    inputs, owner, cleanup, terminal, returned = (
        v.decode(files[key + ".json"]) for key in ("inputs", "controller", "cleanup.native", "terminal", "cache-return.native")
    )
    location = PurePosixPath(owner["cwd"])
    if (
        seal["files"] != len(files)
        or seal["cleanup"] != cleanup
        or seal["terminal"] != terminal
        or location.name != name
        or str(location) != owner["cwd"]
        or not location.is_absolute()
        or ".." in location.parts
        or owner["argv"] != ["/usr/bin/python3", "-B", str(location / "run.py")]
        or owner["inputs_sha256"] != v.digest(files["inputs.json"])
        or owner["script_sha256"] != inputs["run_sha256"]
        or owner["script_sha256"] != v.digest(files["run.py"])
        or owner["boot_id"] != inputs["boot_id"]
        or owner["boot_id"] != cleanup["boot_id"]
        or owner["identity"] not in cleanup["retired"]
        or cleanup["original_exit_code"] != 0
        or cleanup["unit"]["MainPID"] != "0"
        or cleanup["unit"]["ControlGroup"]
        or cleanup["unit"]["Result"] != "success"
        or cleanup["unit"]["ExecMainStatus"] != "0"
        or cleanup["cache_inode"] != 713912
        or returned["owner"] != owner
        or returned["remaining_owned"]
        or (returned["device"], returned["inode"]) != (64512, 713912)
    ):
        v.reject("sensitivity-current-owner", name)
    source = packed(files, inputs, "source")
    extra = packed(files, inputs, "artifacts")
    sources(root, inputs, source=source)
    if inputs["files"].get("dependencies.lock.json") != v.file_digest(root / "dependencies.lock.json"):
        v.reject("sensitivity-current-dependencies")
    journal = [v.decode(line) for line in files["journal.native.jsonl"].splitlines()]
    rows = [
        row
        for row in journal
        if row.get("_BOOT_ID") == owner["boot_id"].replace("-", "")
        and (row.get("INVOCATION_ID") or row.get("_SYSTEMD_INVOCATION_ID")) == owner["invocation_id"]
    ]
    messages = [row.get("MESSAGE", "") for row in rows]
    if (
        not any(message.startswith("Started astra-" + name + ".service - ") for message in messages)
        or "astra-" + name + ".service: Deactivated successfully." not in messages
    ):
        v.reject("sensitivity-current-journal")
    if not any(message.startswith("{") and v.decode(message.encode()) == terminal for message in messages):
        v.reject("sensitivity-current-terminal")
    return files, source, extra


def command(files: dict, prefix: str, check: dict, parent: dict, *, exit_code: int = 0) -> tuple[dict, dict, bytes]:
    """Match a complete native child to its declared command, actual streams and retired process identity."""
    inputs, owner, cleanup = (v.decode(files[key + ".json"]) for key in ("inputs", "controller", "cleanup.native"))
    record = v.decode(files[prefix + "record.json"])
    v.schema(record, "evidence", ("properties", "checks", "items"))
    process = v.decode(files[prefix + check["id"] + ".process.json"])
    python = "52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41"
    tool = python if PurePosixPath(record["executable"]).name == "python3" else TOOLS["command"]
    if (
        record["id"] != check["id"]
        or record["argv"] != check["argv"]
        or record["argv"] != process["argv"]
        or record["environment"] != check["environment"]
        or record["platform"] != "linux-amd64-cgo"
        or record["exit_code"] != exit_code
        or record["termination"] != "exited"
        or not record["complete"]
        or not record["cleanup"]
        or record["duration_ms"] > check["timeout_s"] * 1000
        or v.stamp(record["finished_at"]) < v.stamp(record["started_at"])
        or record["executable_sha256"] != tool
        or {key: item["sha256"] for key, item in record["toolchain"].items()} != {**TOOLS, "command": tool}
        or process["cwd"] != owner["cwd"] + "/source"
        or process["boot_id"] != inputs["boot_id"]
        or process["identity"] not in cleanup["retired"]
        or process["identity"]["parent"] != parent["identity"]["pid"]
    ):
        v.reject("sensitivity-current-command", check["id"])
    environment = {
        key: value.replace("{root}", process["cwd"])
        .replace("{cache}", "/home/ubuntu/verdandi/build")
        .replace("{run}", process["cwd"] + "/" + prefix.removeprefix("source/").rstrip("/"))
        for key, value in check["environment"].items()
    }
    if record["resolved_environment"] != {"HOME": "/home/ubuntu", "LANG": "C.UTF-8", **environment}:
        v.reject("sensitivity-current-environment", check["id"])
    for field in ("stdout", "stderr"):
        ref = record[field]
        path = PurePosixPath(ref["path"])
        if str(path) != ref["path"] or path.is_absolute() or ".." in path.parts:
            v.reject("sensitivity-current-stream-path")
        data = files[prefix + ref["path"]]
        if len(data) != ref["bytes"] or len(data) > check["log_bytes"] or v.digest(data) != ref["sha256"]:
            v.reject("sensitivity-current-stream")
    return record, process, files[prefix + record["stdout"]["path"]]


def failure(data: bytes, test: str, witness: str | None = None) -> None:
    """Require an executed assertion failure; panics, race reports and test timeouts never supply mutation credit."""
    rows = [v.decode(line) for line in data.splitlines()]
    text = "".join(row.get("Output", "") for row in rows)
    if (
        not all(row.get("Package") == "github.com/eosforge/astra/polaris/internal/storage" for row in rows)
        or not any(row.get("OutputType") == "error" and (row.get("Test") == test or row.get("Test", "").startswith(test + "/")) for row in rows)
        or any(value in text for value in ("test timed out", "panic:", "fatal error:", "WARNING: DATA RACE"))
        or witness is not None
        and text.count(witness) != 1
    ):
        v.reject("sensitivity-current-counterexample", test)


def campaign(root: Path, files: dict, source: dict, extra: dict, check: dict) -> dict:
    """Reconstruct standard mutation facts and their actual overlay files against the frozen current program."""
    owner = v.decode(files["controller.json"])
    prefix = "source/build/commands/" + check["id"] + "/"
    outer, parent, data = command(files, prefix, check, owner)
    manifest = v.decode((source | extra)[check["manifest"]])
    # The parser needs a filesystem for the archived manifest, not a hidden permanent dependency on the acquisition recipe.
    (root / "build").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=root / "build") as directory:
        shadow = Path(directory)
        names = {item["file"] for item in manifest["mutations"]} | {item["source"] for item in manifest.get("fixtures", [])} | {check["manifest"]}
        (shadow / manifest["package"][2:]).mkdir(parents=True)
        for name in names:
            path = shadow / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(extra[name] if name in extra else source[name])
        observed, failures = mutate.observations(data, check, shadow, origin=owner["cwd"] + "/source")
    expected_failure = ["version-size:invalid"] if check["id"] == "current-core-mutants" else []
    expected_observed = {} if expected_failure else {"STORAGE-ASSURANCE": len(manifest["mutations"])}
    if failures != expected_failure or observed != expected_observed:
        v.reject("sensitivity-current-outcome", check["id"])
    cells = {}
    for row in [v.decode(line.removeprefix(b"ASTRA-MUTATION "), maximum=MAXIMUM) for line in data.splitlines()][1:-1]:
        nested = row["record"]
        temporary = PurePosixPath(nested["resolved_environment"]["TMPDIR"])
        child_prefix = "source/" + str(temporary.parent.relative_to(PurePosixPath(owner["cwd"]) / "source")) + "/"
        child_check = {"id": row["id"], "argv": nested["argv"], "environment": nested["environment"], "timeout_s": 240, "log_bytes": 16 * 1024**2}
        record, _, output = command(files, child_prefix, child_check, parent, exit_code=0 if row["id"].startswith("baseline-") else 1)
        if (
            record != nested
            or output != base64.b64decode(row["stdout"], validate=True)
            or not v.stamp(outer["started_at"]) <= v.stamp(record["started_at"]) <= v.stamp(record["finished_at"]) <= v.stamp(outer["finished_at"])
        ):
            v.reject("sensitivity-current-nested-record")
        if row["id"] == "baseline-TestVersionBoundary":
            baseline = {
                "package": manifest["import"],
                "expected_tests": ["TestVersionBoundary"],
                "probes": [{"contract": "STORAGE-MUTATION-VERSION", "test": "TestVersionBoundary", "minimum_hits": 3}],
            }
            observed, failures = v.go_observations(output, baseline)
            if failures or observed != {"STORAGE-MUTATION-VERSION": 3}:
                v.reject("sensitivity-version-baseline")
        if row["overlay"]:
            mapping = next(value.removeprefix("-overlay=") for value in record["argv"] if value.startswith("-overlay="))
            key = "source/" + str(PurePosixPath(mapping).relative_to(PurePosixPath(owner["cwd"]) / "source"))
            if v.decode(files[key]) != row["overlay"]:
                v.reject("sensitivity-current-overlay")
            for target, replacement in row["overlay"]["Replace"].items():
                name = str(PurePosixPath(target).relative_to(PurePosixPath(owner["cwd"]) / "source"))
                key = "source/" + str(PurePosixPath(replacement).relative_to(PurePosixPath(owner["cwd"]) / "source"))
                fixture = next((item for item in manifest.get("fixtures", []) if item["target"] == name), None)
                planned = next((item for item in manifest["mutations"] if item["id"] == row["id"]), None)
                expected = source[fixture["source"]] if fixture else source[name].decode().replace(planned["before"], planned["after"], 1).encode()
                if files[key] != expected:
                    v.reject("sensitivity-current-replacement")
        if not row["id"].startswith("baseline-"):
            item = next(item for item in manifest["mutations"] if item["id"] == row["id"])
            if check["id"] == "current-core-mutants" and item["id"] == "version-size":
                text = "".join(event.get("Output", "") for event in (v.decode(line) for line in output.splitlines()))
                if (
                    "panic: runtime error: index out of range [7] with length 7" not in text
                    or mutate.outcome(record, output, manifest["import"], item["test"]) != "invalid"
                ):
                    v.reject("sensitivity-original-panic")
                # Preserve this original invalid outcome. A separate valid-width-first assertion must supply its credit.
                continue
            failure(output, item["test"], WITNESSES.get(item["id"]))
            cells[item["id"]] = {
                "status": "killed",
                "file": item["file"],
                "source_sha256": v.digest(source[item["file"]]),
                "record_sha256": v.digest(files[child_prefix + "record.json"]),
            }
    return cells


def current(root: Path, artifacts: dict | None = None) -> dict:
    """Qualify 99 current core kills, two current timer kills and five unchanged native owner counterexamples."""
    from tools import idle

    files, source, extra = acquired(root, "storage-idle-core-current-1", artifacts)
    inputs = v.decode(files["inputs.json"])
    original = v.decode(v.read(root / PACKAGE / "core-mutations.json"))
    boundary = v.decode(v.read(root / PACKAGE / "boundary-mutations.json"))
    maintenance = v.decode(v.read(root / PACKAGE / "maintenance-mutations.json"))
    checks = {item["id"]: item for item in inputs["auxiliary"]}
    core = v.decode(extra[checks["current-core-mutants"]["manifest"]])
    timer = v.decode(extra[checks["maintenance-timer-mutants"]["manifest"]])
    expected = [{**item, "test": "TestMutationBoundaries"} if item["id"] in SURVIVORS else item for item in original["mutations"]]
    if (
        core["mutations"] != expected
        or core.get("fixtures") != boundary["fixtures"]
        or timer["mutations"] != maintenance["mutations"][5:]
        or timer.get("fixtures") != maintenance["fixtures"]
    ):
        v.reject("sensitivity-current-denominator")
    cells = {}
    for name in ("current-core-mutants", "maintenance-timer-mutants"):
        for identity, item in campaign(root, files, source, extra, checks[name]).items():
            cells[identity] = {**item, "archive_sha256": CURRENT["storage-idle-core-current-1"], "campaign": "storage-idle-core-current-1"}
    if len(cells) != 100 or "version-size" in cells:
        v.reject("sensitivity-current-original-credit")
    version_files, version_source, version_extra = acquired(root, "storage-version-boundary-current-2", artifacts)
    version_check = v.decode(version_files["inputs.json"])["auxiliary"][0]
    manifest = v.decode(version_source[version_check["manifest"]])
    operator = next(item for item in original["mutations"] if item["id"] == "version-size")
    if manifest["mutations"] != [{**operator, "test": "TestVersionBoundary"}] or manifest != v.decode(v.read(root / PACKAGE / "version-mutations.json")):
        v.reject("sensitivity-version-operator")
    version_cells = campaign(root, version_files, version_source, version_extra, version_check)
    if set(version_cells) != {"version-size"}:
        v.reject("sensitivity-version-credit")
    cells["version-size"] = {
        **version_cells["version-size"],
        "archive_sha256": CURRENT["storage-version-boundary-current-2"],
        "campaign": "storage-version-boundary-current-2",
    }
    prefix = "source/build/commands/maintenance-context-race/"
    record, _, data = command(files, prefix, checks["maintenance-context-race"], v.decode(files["controller.json"]))
    observed, failures = v.go_observations(data, checks["maintenance-context-race"])
    if failures or observed != {"STORAGE-LIFETIME": 8} or "-race" not in record["argv"] or b"WARNING: DATA RACE" in data:
        v.reject("sensitivity-current-context-baseline")
    location = v.decode(files["controller.json"])["cwd"] + "/source/"
    context = BASE + "/storage-idle-core-current-1/context/"
    mapping = {"Replace": {location + PACKAGE + "maintenancecontext_test.go": location + context + "fixture-0.go.txt"}}
    if (
        v.decode(files["source/" + context + "baseline.json"]) != mapping
        or files["source/" + context + "fixture-0.go.txt"] != source["tests/fixtures/maintenance.go.in"]
    ):
        v.reject("sensitivity-current-context-overlay")
    # The earlier full ordinary/Race package and strengthened stop/deadline positives remain independently source-bound.
    operator_data = (
        artifacts["storage-idle-operators-1"][0] if artifacts is not None else v.read(root / BASE / "storage-idle-operators-1/native/evidence.tar.gz", MAXIMUM)
    )
    race = v.read(root / "build/results/assurance" / idle.RACE, MAXIMUM)
    if v.digest(race) != idle.ARTIFACTS[idle.RACE] or v.digest(operator_data) != CURRENT["storage-idle-operators-1"]:
        v.reject("sensitivity-current-positive-integrity")
    idle.lifecycle(root, {idle.RACE: race, idle.OPERATORS: operator_data})
    prior, previous, extra = acquired(root, "storage-idle-operators-1", artifacts)
    context = BASE + "/storage-idle-operators-1/"
    operators = v.decode(extra[context + "operators.json"])
    owner = v.decode(prior["controller.json"])
    check = v.decode(prior["inputs.json"])["auxiliary"][0]
    _, parent, _ = command(prior, "source/build/commands/operators/", check, owner)
    prefix = "source/build/commands/operators/operators/"
    for declared, item in zip(maintenance["mutations"][:5], operators):
        if declared != {key: value for key, value in {**item, "file": item["path"]}.items() if key not in {"path", "source_sha256", "witness"}}:
            v.reject("sensitivity-maintenance-operator")
        plan = v.decode(prior[prefix + item["id"] + "/plan.json"])
        mapping = owner["cwd"] + "/" + prefix + item["id"] + "-overlay/overlay.json"
        expected = [
            "go",
            "test",
            "-json",
            "-count=1",
            "-p=2",
            "-parallel=1",
            "-timeout=30s",
            "-overlay=" + mapping,
            "-run=^" + item["test"] + "$",
            original["package"],
        ]
        if plan["argv"] != expected or v.decode(prior[prefix + item["id"] + "-overlay/overlay.json"]) != {
            "Replace": {owner["cwd"] + "/source/" + item["path"]: owner["cwd"] + "/" + prefix + item["id"] + "-overlay/" + PurePosixPath(item["path"]).name}
        }:
            v.reject("sensitivity-maintenance-overlay")
        record, _, data = command(prior, prefix + item["id"] + "/", plan, parent, exit_code=1)
        if mutate.outcome(record, data, original["import"], item["test"]) != "killed":
            v.reject("sensitivity-maintenance-outcome")
        failure(data, item["test"], item["witness"])
        replacement = previous[item["path"]].decode().replace(item["before"], item["after"], 1).encode()
        if prior[prefix + item["id"] + "-overlay/" + PurePosixPath(item["path"]).name] != replacement:
            v.reject("sensitivity-maintenance-replacement")
        cells[item["id"]] = {
            "status": "killed",
            "file": item["path"],
            "source_sha256": item["source_sha256"],
            "record_sha256": v.digest(prior[prefix + item["id"] + "/record.json"]),
            "archive_sha256": CURRENT["storage-idle-operators-1"],
            "campaign": "storage-idle-operators-1",
        }
    if len(operators) != 5 or len(original["mutations"]) != 99 or len(maintenance["mutations"]) != 7 or len(cells) != 106:
        v.reject("sensitivity-current-coverage")
    return {
        "trust": "local",
        "platform": "linux-amd64-cgo",
        "cells": cells,
        "reused": 5,
        "supplemented": 101,
        "invalid_original": ["version-size"],
        "campaigns": {
            name: {"archive_sha256": digest, "exit_code": 0, "failures": ["version-size:invalid"] if name == "storage-idle-core-current-1" else []}
            for name, digest in CURRENT.items()
        },
    }


def sources(root: Path, inputs: dict, *, source: dict[str, bytes] | None = None) -> None:
    """Freeze compiled product/oracle inputs; authenticate historical Python producers in their original archives."""
    # Current interpretation is a separate verification target. Uninvoked planners and delivery
    # readers do not change completed Go experiments or their frozen producer identities.
    # Only compiled Go, runtime test vectors and actually consumed mutation declarations affect these experiments.
    # Range/fault policy ledgers are independently checked by their readers; an uninvoked ledger is not Go input.
    manifests = {PACKAGE + name for name in ("core-mutations.json", "boundary-mutations.json", "maintenance-mutations.json", "version-mutations.json")}
    names = {
        name for name in inputs["files"] if name.startswith(PACKAGE) and (name.endswith(".go") or name.startswith(PACKAGE + "testdata/") or name in manifests)
    } | {"go.mod", "go.sum"}
    names |= {name for name in inputs["files"] if name.startswith("tests/fixtures/") and name.endswith(".go.in")}
    if source is not None:
        from tools import storagecompiler

        if storagecompiler.upgraded(root):
            if {name: v.digest(data) for name, data in source.items()} != inputs["files"]:
                v.reject("storage-sensitivity-inputs")
            storagecompiler.review(root, source, names)
            return
    actual = {path.relative_to(root).as_posix() for path in (root / PACKAGE).glob("*.go")}
    actual -= storage.additions(root, names)
    if actual != {name for name in names if name.startswith(PACKAGE) and name.endswith(".go")}:
        v.reject("storage-sensitivity-source-inventory")
    for name in sorted(names):
        if v.file_digest(v.inside(root, name)) != inputs["files"][name]:
            v.reject("storage-sensitivity-source", name)


def native(root: Path, name: str, data: bytes, seal: dict) -> dict:
    """Authenticate archived runner, owner retirement, original command, logs and every nested Go record."""
    files = storage.retained(data, seal, ORIGINS[name])
    inputs = v.decode(files["inputs.json"])
    owner = v.decode(files["controller.json"])
    terminal = v.decode(files["terminal.json"])
    cleanup = v.decode(files["cleanup.native.json"])
    returned = v.decode(files["cache-return.native.json"])
    location = PurePosixPath(owner["cwd"])
    if (
        str(location) != owner["cwd"]
        or not location.is_absolute()
        or ".." in location.parts
        or location.name != name
        or owner["argv"] != ["/usr/bin/python3", "-B", str(location / "run.py")]
        or v.digest(files["run.py"]) != inputs["run_sha256"]
        or owner["script_sha256"] != inputs["run_sha256"]
        or owner["inputs_sha256"] != v.digest(files["inputs.json"])
    ):
        v.reject("storage-sensitivity-controller")
    if (
        cleanup["boot_id"] != inputs["boot_id"]
        or owner["boot_id"] != inputs["boot_id"]
        or returned["boot_id"] != inputs["boot_id"]
        or cleanup["unit"]["MainPID"] != "0"
        or cleanup["unit"]["ControlGroup"]
        or cleanup["unit"]["ActiveState"] not in {"failed", "inactive"}
        or terminal["remaining_owned"]
        or terminal["interrupted"]
        or returned["owner_retired"] != cleanup["retired"]
        or owner["identity"] not in cleanup["retired"]
    ):
        v.reject("storage-sensitivity-cleanup")
    sources(root, inputs)
    core = name == "storage-core-current-3"
    check = next(item for item in v.decode(files["source/development.json"])["checks"] if item["id"] == "storage-core-mutants") if core else inputs["selection"]
    directory = "source/build/commands/" + check["id"] + "/"
    record = v.decode(files[directory + "record.json"])
    process = v.decode(files[directory + check["id"] + ".process.json"])
    if process["boot_id"] != inputs["boot_id"] or process["identity"]["parent"] != owner["identity"]["pid"] or process["identity"] not in cleanup["retired"]:
        v.reject("storage-sensitivity-command-owner")
    origin = str(location / "source")
    if (
        record["id"] != check["id"]
        or record["platform"] != "linux-amd64-cgo"
        or record["argv"] != check["argv"]
        or record["environment"] != check["environment"]
        or record["executable_sha256"] != "52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41"
        or not record["complete"]
        or not record["cleanup"]
        or record["termination"] != "exited"
        or record["exit_code"] != (2 if core else 0)
        or terminal["errors"] != (["AssertionError: "] if core else [])
    ):
        v.reject("storage-sensitivity-command")
    outputs = {}
    for field in ("stdout", "stderr"):
        ref = record[field]
        outputs[field] = files[directory + ref["path"]]
        if len(outputs[field]) != ref["bytes"] or v.digest(outputs[field]) != ref["sha256"]:
            v.reject("storage-sensitivity-log")
    observed, failures = mutate.observations(outputs["stdout"], check, root, origin=origin)
    expected = ({}, sorted(name + ":survived" for name in SURVIVORS)) if core else ({"STORAGE-ASSURANCE": 5}, [])
    if (observed, sorted(failures)) != expected:
        v.reject("storage-sensitivity-native-outcome")
    rows = [v.decode(line.removeprefix(b"ASTRA-MUTATION "), maximum=MAXIMUM) for line in outputs["stdout"].splitlines()]
    facts = {}
    for row in rows[1:-1]:
        child = row["record"]
        if {key: item["sha256"] for key, item in child["toolchain"].items()} != TOOLS:
            v.reject("storage-sensitivity-toolchain")
        temporary = PurePosixPath(child["resolved_environment"]["TMPDIR"])
        child_directory = directory + str(temporary.parent.relative_to(PurePosixPath(origin) / "build/commands" / check["id"])) + "/"
        if v.decode(files[child_directory + "record.json"]) != child:
            v.reject("storage-sensitivity-native-record")
        for field in ("stdout", "stderr"):
            if files[child_directory + child[field]["path"]] != base64.b64decode(row[field], validate=True):
                v.reject("storage-sensitivity-native-output")
        baseline = row["id"].startswith("baseline-")
        test = child["argv"][7].removeprefix("-run=^").removesuffix("$")
        facts[row["id"]] = {
            "status": mutate.outcome(
                child, base64.b64decode(row["stdout"], validate=True), "github.com/eosforge/astra/polaris/internal/storage", test, baseline
            ),
            "record_sha256": v.digest(files[child_directory + "record.json"]),
            "archive_sha256": ORIGINS[name],
        }
    return {"facts": facts, "exit_code": record["exit_code"], "failures": failures, "source": inputs["source"], "archive_sha256": ORIGINS[name]}


def reconcile(root: Path, archives: dict | None = None) -> dict:
    """Select only the matching source revision; current task ownership cannot inherit the earlier 99-operator verdict."""
    from tools import idle

    if idle.current(root):
        return current(root, archives)
    campaigns = {}
    for name, digest in ORIGINS.items():
        directory = v.inside(root, BASE + "/" + name + "/native")
        data, seal = (
            archives[name] if archives is not None else (v.read(directory / "evidence.tar.gz", MAXIMUM), v.decode(v.read(directory / "sealed.native.json")))
        )
        campaigns[name] = native(root, name, data, seal)
    core = v.decode(v.read(root / (PACKAGE + "core-mutations.json")))
    supplement = v.decode(v.read(root / (PACKAGE + "boundary-mutations.json")))
    old = mutate.plan(core, root)
    new = mutate.plan(supplement, root)
    if len(old) != 99 or {item["id"] for item in new} != SURVIVORS:
        v.reject("storage-sensitivity-denominator")
    originals = {item["id"]: item for item in old}
    for item in new:
        if any(item[key] != originals[item["id"]][key] for key in ("file", "before", "after", "replacement", "source_sha256")):
            v.reject("storage-sensitivity-operator-changed", item["id"])
    cells = {}
    for item in old:
        name = "storage-boundaries-current-1" if item["id"] in SURVIVORS else "storage-core-current-3"
        fact = campaigns[name]["facts"][item["id"]]
        if fact["status"] != "killed":
            v.reject("storage-sensitivity-uncovered", item["id"])
        cells[item["id"]] = {**fact, "file": item["file"], "source_sha256": item["source_sha256"], "campaign": name}
    return {"trust": "local", "platform": "linux-amd64-cgo", "cells": cells, "campaigns": campaigns, "reused": 94, "supplemented": 5}
