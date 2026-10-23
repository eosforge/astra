"""Check a bounded Linux candidate tree and native loader observations without granting release eligibility."""

import argparse
from pathlib import Path
import re
import stat
import struct
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import statements, verify as v

PROGRAMS = ("star", "planet", "pulsar", "polaris", "astrolabe")
RUNTIMES = ("libstdc++.so.6", "libgcc_s.so.1")
SYSTEM = {"libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2", "librt.so.1", "libresolv.so.2", "ld-linux-x86-64.so.2"}
HEADERS = ("beacon", "client", "observer", "publisher", "reader", "subscriber", "types")
EXPORTS = ("CometConfig.cmake", "CometConfigVersion.cmake", "CometTargets.cmake", "CometTargets-release.cmake")
# Reviewed native archives remain immutable. Updating these pins requires a new source/consumer reconciliation.
ARCHIVES = {
    "inventory.tar.gz": "6cd8cd8a0c4f349a39476f463934ad27b95ef3f4184eba2a6a75296bace4ec35",
    "evidence.tar.gz": "c4f5042ccc6aa65225c3200e229d91ad1f88786a1fd9d0363f3992fa5bd012c7",
}
# Acquisition repair keeps the same delivery obligation and consumes one combined native collection.
MATERIAL = "a2310ee5e990c4ca1f5ab791bf243e56aeb191a241ace652defd2abba7d5c701"
CHECK = {
    "id": "admission-gap-delivery-matrix",
    "adapter": "admission-delivery",
    "component": "admission",
    "argv": ["python3", "-B", "tools/delivery.py", "--retained"],
    "environment": {"PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": "{run}/tmp"},
    "expected_tests": ["consumers"],
    "native_tests": ["polaris", "astrolabe"],
    "platforms": ["linux-amd64-cgo"],
    "probes": [{"contract": "ADMISSION-ASSURANCE", "test": "consumers", "minimum_hits": 2}],
    "timeout_s": 60,
    "log_bytes": 1024 * 1024,
}
# Storage has one shipping Linux/CGO consumer; Admission retains its two-consumer denominator.
STORAGE = {
    **CHECK,
    "id": "gap-delivery-matrix",
    "adapter": "storage-delivery",
    "component": "polaris-storage",
    "argv": ["python3", "-B", "tools/delivery.py", "--retained", "--component", "polaris-storage"],
    "native_tests": ["polaris"],
    "probes": [{"contract": "STORAGE-ASSURANCE", "test": "consumers", "minimum_hits": 1}],
}
# Native build, assembled bytes and finite recovery are separately sealed, including failed predecessors.
CURRENT = {
    3: "316384985eddb76132a6a6e45693b7b3025a43a523273afb4c92daac7b88970c",
    4: "bd51d5a6ce39564c786dc9967dd32d042e4a7ff6e8d1ce9d1c3fe0eed386cf90",
    5: "c99c92f18c652b6a111e11101e70281a4ab22344c783021268980e49c9a98fd1",
}
CURRENT_SOURCE = "c81b9b809a7ecd67b8599cf61526b3aa752accae66bc8b715c7fea2a1efab926"
COMMANDS = {
    3: ("cpp-build", "cpp-install", "module-integrity", "go-build", "modules-polaris", "loader-polaris", "modules-astrolabe", "loader-astrolabe"),
    4: (),
    5: ("resolved-comet-mesh-probe", "resolved-comet-process-probe", "consumer-graph", "candidate-cluster"),
    6: (
        "go-build-polaris",
        "modules-polaris",
        "loader-polaris",
        "consumer-graph",
        "resolved-comet-mesh-probe",
        "resolved-comet-process-probe",
        "candidate-cluster",
    ),
    7: (
        "install-prerequisite",
        "cpp-install",
        "loader-star",
        "resolved-star",
        "resolved-comet-mesh-probe",
        "resolved-comet-process-probe",
        "candidate-cluster",
    ),
    8: (
        "go-build-polaris",
        "modules-polaris",
        "loader-polaris",
        "consumer-graph",
        "resolved-comet-mesh-probe",
        "resolved-comet-process-probe",
        "candidate-cluster",
    ),
}


def configuration(check: dict) -> None:
    """Fix the supported consumer/platform denominator; callers cannot qualify only one executable."""
    if check not in (CHECK, STORAGE):
        v.reject("delivery-configuration")


def campaign(files: dict[str, bytes], number: int) -> dict:
    """Check source, original outcomes, native journals and each retired command owner before reuse."""
    from tools import entry

    inputs, owner, cleanup, terminal = (v.decode(files[name]) for name in ("inputs.json", "controller.json", "cleanup.native.json", "terminal.json"))
    expected = {3: ["Invalid: delivery-missing-file: "], 4: ["AssertionError: "], 5: [], 6: [], 7: [], 8: []}[number]
    source = inputs["warm_files"] if number == 7 else inputs["files"]
    state = cleanup["unit"]
    if (
        inputs["boot_id"] != owner["boot_id"]
        or cleanup["boot_id"] != owner["boot_id"]
        or owner["identity"] not in cleanup["retired"]
        or owner["inputs_sha256"] != v.digest(files["inputs.json"])
        or owner["script_sha256"] != v.digest(files["run.py"])
        or inputs["run_sha256"] != v.digest(files["run.py"])
        or (number != 7 and v.digest(files["source.tar.gz"]) != inputs["source_archive_sha256"])
        or {name: v.digest(raw) for name, raw in entry.unpack(files["source.tar.gz"]).items()} != source
        or cleanup["source_verified"] != len(source)
        or owner["argv"] != (["/usr/bin/python3", "-B", owner["cwd"] + "/run.py"] if number >= 6 else [owner["cwd"] + "/run.py"])
        or not owner["cwd"].endswith(f"/storage-delivery-current-{number}")
        or terminal["errors"] != expected
        or terminal["interrupted"] is not False
        or terminal["remaining_owned"]
        or terminal["protected_unchanged"] is not True
        or terminal["products_unchanged"] is not (number in (5, 6, 7, 8))
        or (number == 7 and terminal.get("lock_released") is not True)
        or cleanup["original_exit_code"] != (2 if expected else 0)
        or state["MainPID"] != "0"
        or state["ControlGroup"]
        or state["InvocationID"] not in ("", owner["invocation_id"])
        or (state["InvocationID"] and state["ExecMainStatus"] != str(cleanup["original_exit_code"]))
        or [item["id"] for item in terminal["completed"]] != list(COMMANDS[number])
    ):
        v.reject("delivery-current-lifecycle", str(number))
    journal = [v.decode(row) for row in files["journal.native.jsonl"].splitlines()]
    if not journal or any(
        row.get("_BOOT_ID") != owner["boot_id"].replace("-", "") or (row.get("INVOCATION_ID") or row.get("_SYSTEMD_INVOCATION_ID")) != owner["invocation_id"]
        for row in journal
    ):
        v.reject("delivery-current-journal", str(number))
    messages = [row.get("MESSAGE") or "" for row in journal]
    unit = f"astra-storage-delivery-current-{number}.service"
    native_terminal = [v.decode(message) for message in messages if message.startswith(('{"errors":', '{"completed":', '{"at":'))]
    if (
        not any(message.startswith("Started " + unit + " - ") for message in messages)
        or native_terminal != [terminal]
        or not any(("status=2/" in message) if expected else message == unit + ": Deactivated successfully." for message in messages)
    ):
        v.reject("delivery-current-outcome", str(number))
    prefix = "source/build/commands/" if number >= 6 else "source/build/commands/control-plane-delivery/"
    if {name for name in files if name.endswith("/record.json")} != {prefix + name + "/record.json" for name in COMMANDS[number]}:
        v.reject("delivery-current-commands", str(number))
    records = {}
    for done in terminal["completed"]:
        name = done["id"]
        path = prefix + name + "/"
        record, _ = receipt(files, path)
        process = v.decode(files[path + name + ".process.json"])
        if (
            process["identity"] not in cleanup["retired"]
            or process["identity"]["parent"] != owner["identity"]["pid"]
            or process["boot_id"] != owner["boot_id"]
            or process["cwd"] != (inputs["warm_root"] if number == 7 else owner["cwd"] + "/source")
            or process["argv"] != record["argv"]
            or any(done[key] != record[key] for key in ("exit_code", "duration_ms", "complete", "cleanup", "termination"))
        ):
            v.reject("delivery-current-owner", name)
        records[name] = record
    if len(cleanup["retired"]) != len(records) + 1 or (number != 7 and cleanup["cache_inode"] != 713912):
        v.reject("delivery-current-retirement", str(number))
    return records


def compose(root: Path) -> tuple[dict, dict, bytes, dict]:
    """Compose only successful native commands and unchanged package bytes; failed campaigns remain failed."""
    from tools import entry

    campaigns, records, archives = {}, {}, {}
    for number, sha in CURRENT.items():
        name = f"storage-delivery-current-{number}/native/evidence.tar.gz"
        data = v.read(root / "build/results/assurance/reuse-plan" / name, 128 * 1024**2)
        if v.digest(data) != sha:
            v.reject("delivery-current-archive", str(number))
        files = entry.unpack(data)
        manifest = v.decode(files["manifest.json"])
        if manifest["trust"] != "local" or set(manifest["files"]) != set(files) - {"manifest.json"}:
            v.reject("delivery-current-members", str(number))
        if any(item != {"bytes": len(files[name]), "sha256": v.digest(files[name])} for name, item in manifest["files"].items()):
            v.reject("delivery-current-integrity", str(number))
        campaigns[number] = files
        records[number] = campaign(files, number)
        archives[name] = sha
    plans = {number: v.decode(files["inputs.json"]) for number, files in campaigns.items()}
    if (
        any(plans[number]["source"] != plans[3]["source"] or plans[number]["files"] != plans[3]["files"] for number in (4, 5))
        or plans[5]["build_archive_sha256"] != CURRENT[3]
        or plans[5]["assembled_archive_sha256"] != CURRENT[4]
        or plans[5]["prior_archive_sha256"] != MATERIAL
    ):
        v.reject("delivery-current-handoff")
    package = {name.removeprefix("candidate/"): v.digest(raw) for name, raw in campaigns[4].items() if name.startswith("candidate/")}
    built = v.decode(campaigns[3]["partial-candidate.native.json"])
    if (
        len(package) != 51
        or package != v.decode(campaigns[4]["candidate-manifest.json"])
        or package != plans[5]["assembled_products"]
        or package != v.decode(campaigns[5]["candidate-manifest.json"])
        or package != v.decode(campaigns[5]["partial-candidate.native.json"])
        or built != plans[5]["built_products"]
        or any(package.get(name) != sha for name, sha in built.items())
        or len(set(package) - set(built)) != 16
        or any(not name.startswith("share/astra/licenses/go/") for name in set(package) - set(built))
    ):
        v.reject("delivery-current-package")
    # Normalize path views only; retain original records, streams and failed terminals byte for byte.
    facts = dict(campaigns[5])
    facts.update({name: raw for name, raw in campaigns[4].items() if name.startswith("candidate/")})
    prefix = "source/build/commands/control-plane-delivery/"
    for number in (3, 5):
        facts.update({"command/" + name.removeprefix(prefix): raw for name, raw in campaigns[number].items() if name.startswith(prefix)})
    graph, packages = receipt(facts, "command/consumer-graph/")
    build = records[3]["go-build"]
    pins = v.decode(campaigns[5]["preflight.json"])["pins"]
    if (
        graph["argv"] != ["go", "list", "-json", "./..."]
        or graph["executable_sha256"] != pins.get(graph["executable"])
        or build["executable_sha256"] != graph["executable_sha256"]
        or any(
            graph["resolved_environment"].get(key) != value
            for key, value in {"GOFLAGS": "-mod=readonly", "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local"}.items()
        )
    ):
        v.reject("delivery-current-tools")
    inputs = {"source": plans[3]["files"], "go_sha256": graph["executable_sha256"]}
    # The merged facts own every retained byte needed downstream; release the complete historical unpacking views.
    del campaigns, data, files
    from tools import installation

    if v.file_digest(root / installation.PATH) == installation.SOURCE:
        return installation.reconcile(root, facts, inputs, packages, archives)
    return facts, inputs, packages, archives


def retained(data: bytes, expected: str) -> dict[str, bytes]:
    """Authenticate the original native archive before interpreting any inner success statement."""
    from tools import entry

    if v.digest(data) != expected:
        v.reject("delivery-archive-integrity")
    files = entry.unpack(data)
    owner, cleanup = (v.decode(files[name]) for name in ("controller.json", "cleanup.native.json"))
    state = cleanup["service"]
    if (
        state["InvocationID"] != owner["invocation_id"]
        or cleanup["boot_id"] != owner["boot_id"]
        or state["MainPID"] != "0"
        or state["SubState"] != "exited"
        or state["ExecMainStatus"] != "0"
        or state["ControlGroup"]
        or owner["identity"] not in cleanup["retired"]
    ):
        v.reject("delivery-native-retirement")
    return files


def receipt(files: dict[str, bytes], prefix: str) -> tuple[dict, bytes]:
    """Require a complete native Linux execution and its original bounded stdout/stderr bytes."""
    record = v.decode(files[prefix + "record.json"])
    v.schema(record, "evidence", ("properties", "checks", "items"))
    if (
        record["platform"] != "linux-amd64-cgo"
        or record["complete"] is not True
        or record["cleanup"] is not True
        or record["exit_code"] != 0
        or record["termination"] != "exited"
        or v.stamp(record["finished_at"]) < v.stamp(record["started_at"])
    ):
        v.reject("delivery-native-incomplete")
    for channel in ("stdout", "stderr"):
        item = record[channel]
        raw = files[prefix + item["path"]]
        if len(raw) != item["bytes"] or v.digest(raw) != item["sha256"]:
            v.reject("delivery-native-stream")
    return record, files[prefix + record["stdout"]["path"]]


def collection(root: Path) -> tuple[dict, dict, bytes, dict]:
    """Select source-bound native facts; a later collection cannot certify earlier or unknown production bytes."""
    from tools import admission

    if admission.matches(root, "internal/admission/identity.go", admission.MATERIAL):
        base = root / "build/results/assurance/reuse-plan/material-delivery"
        facts = retained(v.read(base / "evidence.tar.gz", 64 * 1024**2), MATERIAL)
        plan = v.decode(facts["inputs.json"])
        preflight = v.decode(facts["preflight.json"])
        native, packages = receipt(facts, "command/consumer-graph/")
        build, _ = receipt(facts, "command/go-build/")
        cleanup = v.decode(facts["cleanup.native.json"])
        for name, record in (("consumer-graph", native), ("go-build", build)):
            owner = v.decode(facts[f"command/{name}/{name}.process.json"])
            if owner["boot_id"] != cleanup["boot_id"] or owner["identity"] not in cleanup["retired"] or owner["argv"] != record["argv"]:
                v.reject("delivery-native-owner")
        if (
            native["argv"] != ["go", "list", "-json", "./..."]
            or native["resolved_environment"].get("GOFLAGS") != "-mod=readonly"
            or native["executable_sha256"] != preflight["pins"].get(native["executable"])
            or build["executable_sha256"] != native["executable_sha256"]
            or plan["prior_archive_sha256"] != ARCHIVES["evidence.tar.gz"]
            or v.digest(facts["source.tar.gz"]) != plan["source_archive_sha256"]
        ):
            v.reject("delivery-inventory-binding")
        inputs = {"source": plan["files"], "go_sha256": native["executable_sha256"]}
        return facts, inputs, packages, {"material-delivery/evidence.tar.gz": MATERIAL}
    base = root / "build/results/assurance/reuse-plan/control-plane-delivery"
    inventory, facts = (retained(v.read(base / name, 64 * 1024**2), sha) for name, sha in ARCHIVES.items())
    inputs, terminal = (v.decode(inventory[name]) for name in ("inputs.json", "terminal.json"))
    native, packages = receipt(inventory, "command/")
    if (
        terminal["source_unchanged"] is not True
        or terminal["owned"]
        or native["argv"] != ["go", "list", "-mod=readonly", "-json", "./..."]
        or v.digest(inventory["command/record.json"]) != terminal["record"]
        or native["toolchain"]["command"]["sha256"] != inputs["go_sha256"]
        or inputs["delivery_inputs_sha256"] != v.digest(facts["inputs.json"])
    ):
        v.reject("delivery-inventory-binding")
    return facts, inputs, packages, ARCHIVES


def reconcile(root: Path, *, component: str = "admission") -> dict:
    """Revalidate retained Admission delivery facts against current inputs, without launching applications.

    This qualifies Linux/CGO delivery for both shipping Go consumers. It does not qualify their entire
    behavior, C++ delivery, residence, other platforms, protected CI, or release authorization.
    """
    if component not in {"admission", "polaris-storage"}:
        v.reject("delivery-component", component)
    from tools import shipping

    if shipping.current(root):
        return shipping.reconcile(root, component=component)
    refreshed = v.file_digest(root / "polaris/internal/storage/read.go") == CURRENT_SOURCE
    if component == "polaris-storage" and not refreshed:
        v.reject("delivery-storage-source")
    facts, inputs, packages, archives = compose(root) if refreshed else collection(root)
    graph = consumers(packages, "internal/admission", ("polaris", "astrolabe"))
    selected_graph = consumers(packages, "polaris/internal/storage", ("polaris",)) if component == "polaris-storage" else graph
    current = {
        p.relative_to(root).as_posix(): v.file_digest(p)
        for folder in ("internal", "polaris", "astrolabe")
        for p in (root / folder).rglob("*.go")
        if not p.name.endswith("_test.go") and "generated" not in p.relative_to(root).parts
    }
    expected = {
        name: sha
        for name, sha in inputs["source"].items()
        if name.startswith(("internal/", "polaris/", "astrolabe/")) and name.endswith(".go") and not name.endswith("_test.go") and "/generated/" not in name
    }
    if current != expected:
        v.reject("delivery-source-inventory")
    selected = set().union(*map(set, graph["consumers"].values()))
    native_sources = set()
    for package in statements.stream(packages):
        name = package["ImportPath"].removeprefix("github.com/eosforge/astra/")
        if name in selected and not name.startswith("internal/generated/"):
            native_sources.update(name + "/" + p for key in ("GoFiles", "CgoFiles", "IgnoredGoFiles") for p in package.get(key, []))
    if native_sources != current.keys():
        v.reject("delivery-native-sources")
    plan = v.decode(facts["inputs.json"])
    for name, sha in {**plan["relevant"], **plan["cpp_production"]}.items():
        if v.file_digest(v.inside(root, name)) != sha:
            v.reject("delivery-source-drift", name)
    if any(plan["relevant"].get(name) != sha for name, sha in current.items()) or any(
        v.file_digest(root / name) != inputs["source"][name] for name in ("go.mod", "go.sum", "dependencies.lock.json")
    ):
        v.reject("delivery-build-sources")
    done = v.decode(facts["terminal.json"])
    if done["errors"] or done["interrupted"] or done["remaining_owned"] or not done["protected_unchanged"] or not done["products_unchanged"]:
        v.reject("delivery-native-terminal")
    builds = inputs.get("builds", {"go-build": ["./polaris", "./astrolabe"]})
    for name, targets in builds.items():
        build, _ = receipt(facts, "command/" + name + "/")
        if (
            build["toolchain"]["command"]["sha256"] != inputs["go_sha256"]
            or build["argv"][:6] != ["go", "build", "-mod=readonly", "-p", "4", "-o"]
            or build["argv"][7:] != targets
        ):
            v.reject("delivery-build-command", name)
    candidate = v.decode(facts["candidate-manifest.json"])
    events = [v.decode(row) for row in facts["recovery/events.jsonl"].splitlines()]
    if (
        not events
        or events[0]["event"] != "started"
        or events[-1]["event"] != "completed"
        or events[-1]["cycles"] != 3
        or any(e["event"] in {"failed", "interrupted"} for e in events)
    ):
        v.reject("delivery-native-recovery")
    bindings = {}
    for name in sorted(selected_graph["consumers"]):
        sha = v.digest(facts["candidate/bin/" + name])
        if sha != candidate["bin/" + name] or sha != events[0]["binaries"][name]:
            v.reject("delivery-candidate-identity", name)
        record, module = receipt(facts, "command/modules-" + name + "/")
        if (
            record["argv"][:3] != ["go", "version", "-m"]
            or b"\tpath\tgithub.com/eosforge/astra/" + name.encode() + b"\n" not in module
            or not all(b"\tbuild\t" + flag + b"\n" in module for flag in (b"CGO_ENABLED=1", b"GOOS=linux", b"GOARCH=amd64"))
            or any(flag in module for flag in (b"-race=true", b"-asan=true", b"-msan=true"))
        ):
            v.reject("delivery-build-mode", name)
        _, tags = receipt(facts, "command/loader-" + name + "/")
        bindings[name] = {"sha256": sha, "loader": dynamic(tags, cpp=False), "dependencies": selected_graph["consumers"][name]}
    cluster, stdout = receipt(facts, "command/candidate-cluster/")
    if (
        "--installed" not in cluster["argv"]
        or "--persistent" not in cluster["argv"]
        or {"LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"}.intersection(cluster["resolved_environment"])
        or b"PASS real Almanac persistence and native multi-Star replication, crash, failover, trusted restart, TTL and owned cleanup" not in stdout
    ):
        v.reject("delivery-native-fixture")
    logs = [raw for path, raw in facts.items() if path.startswith("command/candidate-cluster/logs/") and path.endswith("-sequence.log")]
    if len(logs) != 1:
        v.reject("delivery-sequence-inventory")
    return {
        "archives": archives,
        "platform": "linux-amd64-cgo",
        "trust": "local",
        "source": current,
        "consumers": bindings,
        "sequence": sequence(logs[0]),
        "qualification": f"retained Linux/CGO {component} consumer delivery only; no CI or release eligibility",
    }


def observations(data: bytes, check: dict, root: Path) -> tuple[dict, list]:
    """Recompute the native bindings independently; a self-reported JSON success earns no credit."""
    configuration(check)
    try:
        actual = reconcile(root, component="polaris-storage") if check == STORAGE else reconcile(root)
    except (OSError, KeyError, TypeError) as error:
        v.reject("delivery-facts-unavailable", type(error).__name__)
    if v.decode(data) != actual:
        v.reject("delivery-observation-mismatch")
    return ({"STORAGE-ASSURANCE": 1} if check == STORAGE else {"ADMISSION-ASSURANCE": 2}), []


def consumers(data: bytes, package: str, expected: tuple[str, ...]) -> dict:
    """Resolve every shipping main that transitively consumes a package in a complete native module listing.

    The caller must bind the original go-list command, platform, source inventory and stream digest.
    This graph check does not prove that a consumer was built, executed or exercised every contract.
    """
    module = "github.com/eosforge/astra/"
    pattern = r"[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*"
    if (
        not isinstance(data, bytes)
        or not isinstance(package, str)
        or not re.fullmatch(pattern, package)
        or any(p in {".", ".."} for p in package.split("/"))
        or type(expected) is not tuple
        or not expected
        or any(not isinstance(n, str) or not re.fullmatch(pattern, n) or any(p in {".", ".."} for p in n.split("/")) for n in expected)
        or len(expected) != len(set(expected))
    ):
        v.reject("delivery-consumer-policy")
    rows = statements.stream(data)
    if len(rows) > 512:
        v.reject("delivery-consumer-budget")
    graph, names = {}, {}
    for row in rows:
        name = row.get("ImportPath")
        imports = row.get("Imports", [])
        if (
            not isinstance(name, str)
            or not name.startswith(module)
            or not re.fullmatch(pattern, name)
            or any(p in {".", ".."} for p in name.split("/"))
            or name in graph
            or not isinstance(row.get("Name"), str)
            or not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", row["Name"])
            or any(row.get(key) for key in ("Error", "DepsErrors", "Incomplete", "ForTest"))
            or type(imports) is not list
            or len(imports) > 4096
            or any(not isinstance(item, str) or not item for item in imports)
            or len(imports) != len(set(imports))
        ):
            v.reject("delivery-consumer-package")
        graph[name] = {item for item in imports if item.startswith(module)}
        names[name] = row["Name"]
    if sum(map(len, graph.values())) > 8192:
        v.reject("delivery-consumer-budget")
    if any(not children <= graph.keys() for children in graph.values()):
        v.reject("delivery-consumer-incomplete")
    target = module + package
    if target not in graph:
        v.reject("delivery-consumer-target")
    # Kahn's order checks the entire module, including unrelated cycles that invalidate go-list completeness.
    remaining = {name: set(children) for name, children in graph.items()}
    closure = {}
    while remaining:
        ready = sorted(name for name, children in remaining.items() if not children)
        if not ready:
            v.reject("delivery-consumer-cycle")
        for name in ready:
            closure[name] = {name}.union(*(closure[child] for child in graph[name]))
            del remaining[name]
        for children in remaining.values():
            children.difference_update(ready)
    selected = {name for name in graph if names[name] == "main" and target in closure[name]}
    if selected != {module + name for name in expected}:
        v.reject("delivery-consumer-matrix")
    return {
        "package": package,
        "consumers": {name[len(module) :]: sorted(item[len(module) :] for item in closure[name]) for name in sorted(selected)},
        "packages": len(graph),
        "qualification": "native import graph only; execution, provenance and platform acceptance remain separate",
    }


def residence(data: bytes, *, seconds: int, windows: list, owners: list, maximum_gap: float, minimum_samples: int) -> dict:
    """Summarize complete finite residence windows without granting a plateau or leak-freedom pass.

    The caller binds owners, budgets and input bytes to independently verified native receipts and a single boot.
    PID/start identity, completion, time coverage and positive counters are checked here; resource tolerances are not inferred.
    """
    if (
        type(seconds) is not int
        or not 0 < seconds <= 86400
        or type(minimum_samples) is not int
        or minimum_samples < 2
        or type(maximum_gap) not in (int, float)
        or not 0 < maximum_gap <= seconds
        or not isinstance(data, bytes)
        or not data.endswith(b"\n")
        or len(data) > 32 * 1024**2
        or type(windows) is not list
        or not 1 <= len(windows) <= 1440
        or type(owners) is not list
        or not 1 <= len(owners) <= 64
    ):
        v.reject("delivery-residence-input")
    end = 0
    for window in windows:
        if type(window) is not list or len(window) != 2 or any(type(value) is not int for value in window):
            v.reject("delivery-residence-windows")
        first, last = window
        if first != end or not first < last <= seconds or maximum_gap > last - first:
            v.reject("delivery-residence-windows")
        end = last
    if end != seconds:
        v.reject("delivery-residence-windows")
    expected = {}
    for owner in owners:
        if (
            type(owner) is not dict
            or set(owner) != {"pid", "started", "log"}
            or any(type(owner[key]) is not int or not 0 < owner[key] < 2**63 for key in ("pid", "started"))
            or type(owner["log"]) is not str
            or not owner["log"]
            or owner["pid"] in expected
            or owner["log"] in {item["log"] for item in expected.values()}
        ):
            v.reject("delivery-residence-owners")
        expected[owner["pid"]] = owner
    events = [v.decode(line, maximum=65536) for line in data.splitlines()]
    if not events or len(events) > 100000:
        v.reject("delivery-residence-events")
    elapsed, steady, completed = -1, None, False
    samples = []
    for event in events:
        if (
            type(event) is not dict
            or type(event.get("event")) is not str
            or type(event.get("elapsed")) not in (int, float)
            or not event["elapsed"] > elapsed
            or completed
        ):
            v.reject("delivery-residence-order")
        elapsed = event["elapsed"]
        name = event["event"]
        if name in {"failed", "interrupted"}:
            v.reject("delivery-residence-failure")
        if name == "steady":
            if steady is not None or type(event.get("seconds")) is not int or event["seconds"] != seconds:
                v.reject("delivery-residence-duration")
            if type(event.get("sdk_pid")) is not int or event["sdk_pid"] not in expected:
                v.reject("delivery-residence-sdk")
            steady = elapsed
        elif name == "completed":
            if steady is None or elapsed - steady < seconds:
                v.reject("delivery-residence-completion")
            completed = True
        elif name == "sample" and steady is not None:
            if elapsed - steady >= seconds:
                continue  # The finite SDK may retire during the final drain sample, outside the measured interval.
            rows = event.get("processes")
            if type(rows) is not list or len(rows) != len(expected):
                v.reject("delivery-residence-cohort")
            seen = set()
            for row in rows:
                if type(row) is not dict or any(
                    type(row.get(key)) is not int or not 0 < row[key] < 2**63 for key in ("pid", "started", "rss", "fds", "threads")
                ):
                    v.reject("delivery-residence-counter")
                pid = row["pid"]
                if pid in seen or pid not in expected or any(row.get(key) != expected[pid][key] for key in ("started", "log")):
                    v.reject("delivery-residence-identity")
                seen.add(pid)
            samples.append((elapsed - steady, {row["pid"]: row for row in rows}))
        elif steady is not None or name not in {"started", "sequence", "recovered", "sample", "sampling_exit"}:
            v.reject("delivery-residence-phase")
    if not completed or not samples:
        v.reject("delivery-residence-incomplete")
    if any(b[0] - a[0] > maximum_gap for a, b in zip(samples, samples[1:])):
        v.reject("delivery-residence-gap")
    result = []
    for first, last in windows:
        selected = [(offset, rows) for offset, rows in samples if first <= offset < last]
        if len(selected) < minimum_samples or selected[0][0] - first > maximum_gap or last - selected[-1][0] > maximum_gap:
            v.reject("delivery-residence-window-coverage")
        processes = []
        for pid, owner in sorted(expected.items()):
            fields = {}
            for field in ("rss", "fds", "threads"):
                values = [rows[pid][field] for _, rows in selected]
                fields[field] = {"first": values[0], "last": values[-1], "minimum": min(values), "maximum": max(values), "net_change": values[-1] - values[0]}
            processes.append({**owner, **fields})
        result.append({"seconds": [first, last], "samples": len(selected), "observed_seconds": [selected[0][0], selected[-1][0]], "processes": processes})
    return {"steady_seconds": seconds, "steady_samples": len(samples), "windows": result, "qualification": "descriptive-only"}


def bounds(data: bytes, *, policy: dict, seconds: int, windows: list, owners: list, maximum_gap: float, minimum_samples: int) -> dict:
    """Evaluate explicit finite RSS/FD/thread limits without claiming a plateau or leak freedom.

    Callers must authenticate the policy frozen before execution, trace, boot and owners. Warmup excludes only rise checks;
    absolute maxima apply throughout. Rise measures every later peak above the first measured value, so a final drop cannot hide it.
    """
    observed = residence(data, seconds=seconds, windows=windows, owners=owners, maximum_gap=maximum_gap, minimum_samples=minimum_samples)
    if (
        type(policy) is not dict
        or set(policy) != {"warmup", "processes"}
        or type(policy["warmup"]) is not int
        or not 0 <= policy["warmup"] <= len(windows) - 2
        or type(policy["processes"]) is not list
        or len(policy["processes"]) != len(owners)
    ):
        v.reject("delivery-bounds-policy")
    limits = {}
    for row in policy["processes"]:
        if type(row) is not dict or set(row) != {"pid", "started", "log", "rss", "fds", "threads"}:
            v.reject("delivery-bounds-owner")
        owner = {key: row[key] for key in ("pid", "started", "log")}
        if any(type(row[key]) is not int for key in ("pid", "started")) or type(row["log"]) is not str or owner not in owners or row["pid"] in limits:
            v.reject("delivery-bounds-owner")
        for field in ("rss", "fds", "threads"):
            value = row[field]
            if (
                type(value) is not dict
                or set(value) != {"maximum", "rise"}
                or any(type(value[key]) is not int for key in value)
                or not 0 <= value["rise"] < value["maximum"] < 2**63
            ):
                v.reject("delivery-bounds-limit")
        limits[row["pid"]] = row
    violations, assessed = [], []  # Preserve every failed metric; never shorten the measured cohort or choose a later baseline.
    for pid, limit in sorted(limits.items()):
        rows = [next(row for row in window["processes"] if row["pid"] == pid) for window in observed["windows"]]
        measured = rows[policy["warmup"] :]
        fields = {}
        for field in ("rss", "fds", "threads"):
            peak = max(row[field]["maximum"] for row in rows)
            rise = max(row[field]["maximum"] for row in measured) - measured[0][field]["first"]
            fields[field] = {"maximum": peak, "rise": rise, "limits": dict(limit[field])}
            for name, value in (("maximum", peak), ("rise", rise)):
                if value > limit[field][name]:
                    violations.append({"pid": pid, "field": field, "kind": name, "observed": value, "limit": limit[field][name]})
        assessed.append({**{key: limit[key] for key in ("pid", "started", "log")}, **fields})
    return {
        "status": "failed" if violations else "passed",
        "policy_sha256": v.digest(v.encode(policy)),
        "warmup": policy["warmup"],
        "processes": assessed,
        "violations": violations,
        "residence": observed,
        "qualification": "declared-finite-bounds-only",
    }


def header(data: bytes) -> None:
    """Require a native x86-64 ELF executable/shared object, rather than a renamed file or another platform."""
    if (
        len(data) != 64
        or data[:7] != b"\x7fELF\x02\x01\x01"
        or struct.unpack_from("<HHI", data, 16) not in {(2, 62, 1), (3, 62, 1)}
        or struct.unpack_from("<H", data, 52)[0] != 64
    ):
        v.reject("delivery-elf-header")


def dynamic(data: bytes, *, cpp: bool) -> dict:
    """Read original GNU readelf dynamic tags; unknown library names or private/empty search entries are rejected."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        v.reject("delivery-dynamic-encoding")
    if "\x00" in text or len(data) > 65536:
        v.reject("delivery-dynamic-size")
    if text.strip() == "There is no dynamic section in this file.":
        if cpp:
            v.reject("delivery-missing-dynamic")
        return {"needed": [], "runpath": None, "soname": None}
    if not re.search(r"Dynamic section at offset 0x[0-9a-f]+ contains [1-9][0-9]* entries:", text):
        v.reject("delivery-dynamic-header")
    needed, runpath, soname = [], None, None
    for line in text.splitlines():
        if not re.search(r"\((?:NEEDED|RUNPATH|RPATH|SONAME)\)", line):
            continue
        match = re.fullmatch(r"\s*0x[0-9a-f]+\s+\((NEEDED|RUNPATH|RPATH|SONAME)\)\s+([^\[\n]+)\[([^\]\n]*)\]\s*", line)
        if not match:
            v.reject("delivery-dynamic-tag")
        kind, label, value = match.groups()
        if kind == "NEEDED":
            if label.strip() != "Shared library:" or value not in SYSTEM | set(RUNTIMES) or value in needed:
                v.reject("delivery-needed")
            needed.append(value)
        elif kind == "SONAME":
            if label.strip() != "Library soname:" or soname is not None or value not in RUNTIMES:
                v.reject("delivery-soname")
            soname = value
        else:
            if kind != "RUNPATH" or label.strip() != "Library runpath:" or runpath is not None or value != "$ORIGIN/../lib":
                v.reject("delivery-runpath")
            runpath = value
    if cpp and (runpath is None or not set(RUNTIMES) <= set(needed)):
        v.reject("delivery-runtime-selection")
    return {"needed": sorted(needed), "runpath": runpath, "soname": soname}


def sequence(data: bytes, *, records: int = 48) -> dict:
    """Reconcile the finite three-Star native probe's ordered recovery and replication terminals.

    These are observations, not independent proof of payload correctness, elapsed residence, native origin or SDK ownership.
    Those guarantees require the original process fixture, source, receipts and separately collected resources.
    """
    if type(records) is not int or not 3 <= records <= 48 or records % 3 or not data.endswith(b"\n") or len(data) > 1024**2:
        v.reject("delivery-sequence-input")
    lines = data.splitlines()
    if not 15 <= len(lines) <= 4096:
        v.reject("delivery-sequence-budget")
    expected = []
    for cycle in range(3):
        expected.append("mesh_replicated")
        expected.extend(("mesh_ready", "mesh_failover", "mesh_recovered"))
    expected.extend(("mesh_steady", "mesh_replicated", "mesh_sequence_completed"))
    phase, last, progress, rounds = 0, 0, [], []
    resident = None
    for line in lines:
        event = v.decode(line, maximum=4096)
        if not isinstance(event, dict) or not isinstance(event.get("event"), str):
            v.reject("delivery-sequence-event")
        name = event["event"]
        if name == "mesh_progress":
            fields = set(event)
            workers = "workers" in fields
            if (
                phase not in {0, 4, 8, 13}
                or fields not in ({"event", "round"}, {"event", "round", "workers"})
                or (resident is not None and resident != workers)
                or (workers and (type(event["workers"]) is not int or event["workers"] != 2 * records))
            ):
                v.reject("delivery-sequence-progress")
            resident = workers
            base = (phase // 4 if phase < 12 else 3) * 10000000
            value = event["round"]
            if type(value) is not int or not base < value < base + 10000000 or value <= last or (phase not in progress and value != base + 1):
                v.reject("delivery-sequence-progress")
            last = value
            if phase not in progress:
                progress.append(phase)
            continue
        if phase >= len(expected) or name != expected[phase]:
            v.reject("delivery-sequence-order")
        if name == "mesh_replicated":
            base = (phase // 4 if phase < 12 else 3) * 10000000
            if (
                set(event) != {"event", "rounds", "records"}
                or type(event["records"]) is not int
                or event["records"] != records
                or type(event["rounds"]) is not int
                or not 2 <= event["rounds"] < 10000000
                or phase not in progress
                or event["rounds"] < last - base
            ):
                v.reject("delivery-sequence-replication")
            rounds.append(event["rounds"])
        elif name in {"mesh_ready", "mesh_failover", "mesh_recovered"}:
            cycle = phase // 4
            if set(event) != {"event", "cycle", "star"} or any(type(event[key]) is not int or event[key] != cycle for key in ("cycle", "star")):
                v.reject("delivery-sequence-recovery")
        elif set(event) != {"event", "cycles"} or type(event["cycles"]) is not int or event["cycles"] != 3:
            v.reject("delivery-sequence-completion")
        phase += 1
    if phase != len(expected):
        v.reject("delivery-sequence-incomplete")
    return {"cycles": 3, "pre_fault_rounds": rounds[:3], "steady_rounds": rounds[-1], "records_per_domain": records}


def inventory(directory: Path, expected: dict[str, str], *, forbidden: list[str]) -> dict:
    """Bind every distributed byte to the producer's sealed manifest and reject aliases, extras and private CMake paths.

    This verifies candidate contents only. Compiler/source/license provenance, command receipts and native consumption remain separate obligations.
    """
    if not directory.is_dir() or directory.is_symlink() or not expected or len(expected) > 256:
        v.reject("delivery-directory")
    required = (
        {"bin/" + name for name in PROGRAMS}
        | {"lib/" + name for name in RUNTIMES}
        | {"include/comet/" + name + ".hpp" for name in HEADERS}
        | {"lib/cmake/Comet/" + name for name in EXPORTS}
        | {"lib/libcomet.a", "share/astra/LICENSE", "share/comet/LICENSE"}
    )
    if required - expected.keys():
        v.reject("delivery-required")
    allowed = required | {p for p in expected if p.startswith("share/astra/licenses/")}
    if set(expected) != allowed or not any(p.startswith("share/astra/licenses/gcc-runtime/") for p in expected):
        v.reject("delivery-file-scope")
    for name, digest in expected.items():
        v.inside(directory, name)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            v.reject("delivery-digest")
    actual, total = {}, 0
    for path in sorted(directory.rglob("*")):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)) or mode & stat.S_IWOTH:
            v.reject("delivery-file-type")
        if path.is_dir():
            continue
        name = path.relative_to(directory).as_posix()
        size = path.stat().st_size
        total += size
        if name not in expected or not 0 < size <= 256 * 1024**2 or total > 512 * 1024**2 or len(actual) == 256:
            v.reject("delivery-file-budget")
        digest = v.file_digest(path)
        if digest != expected[name]:
            v.reject("delivery-changed-file", name)
        if name.startswith("bin/"):
            if not mode & stat.S_IXUSR:
                v.reject("delivery-executable-mode")
            with path.open("rb") as stream:
                header(stream.read(64))
        if name in {"lib/" + runtime for runtime in RUNTIMES}:
            with path.open("rb") as stream:
                header(stream.read(64))
        if name.endswith(".cmake"):
            data = v.read(path).decode("utf-8")
            if any(value and value in data for value in forbidden):
                v.reject("delivery-private-export")
        actual[name] = {"bytes": size, "sha256": digest, "executable": bool(mode & stat.S_IXUSR)}
    if actual.keys() != expected.keys():
        v.reject("delivery-missing-file")
    return {"files": actual, "bytes": total, "qualification": "candidate contents only; not release eligibility"}


def main(arguments: list[str] | None = None) -> int:
    """Read existing sealed facts only; this command never starts or rebuilds a product."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retained", action="store_true", required=True)
    parser.add_argument("--component", choices=("admission", "polaris-storage"), default="admission")
    options = parser.parse_args(arguments)
    try:
        print(v.encode(reconcile(Path(__file__).resolve().parents[1], component=options.component)).decode(), end="")
        return 0
    except (OSError, v.Invalid, KeyError, TypeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
