"""Join source-bound service refreshes with unchanged installed products and actual native recovery."""

from pathlib import Path
import posixpath
import re

from tools import delivery, entry, verify as v

# This native collection follows the batch-ingress repair; older package archives remain independently checked.
ARCHIVE = "11eab357ba0f08b9edf7297c8b00e005daef35be83005b64017846cf1cd3fecd"
NAME = "storage-delivery-current-6/native/evidence.tar.gz"
PATH = "polaris/internal/server/authority.go"
SOURCE = "76348643eb6b779fe7bd42fb2e438439d247367739c7a523b898ff872dbbc481"
ORIGINAL = "343c868721dc64bfd8dabd917d55e16283adebe562a4b810683121348d3224be"
PREFIX = "source/build/commands/"
# The ordinary installer changes only the refreshed Star in the retained candidate; its peers stay byte-identical.
REFRESH = "51dbdcf8aa48916990e0f16397ffd88ac7eaed5a63347f16fffc9d5d0217eda9"
BUILD = "e3d0e5b4e6b6c671e4365f06dba392b6bb25090276e43b96fec97f75dbeac994"
STAR = "star/src/catalog_state.cpp"
BEFORE = "b45299e115b035cedeca01784cf7d69f70e461b85441751f0bb5435205f5df69"
AFTER = "86618b757b5aeb7b8dd7f77918771270e299162c1222991dd747b294939406c9"
# The idle checkpoint repair rebuilds only Polaris after the preceding ordinary Star installation.
MAINTENANCE = "27c4876c5a514a0e9f0bc9330885fe67972fa73eb58905cb5558224eaae1d668"
POLARIS = "91f62b9aa5c10b12b5e56286f2c32b1be4bf5d9f55739c433bd144c1ab2056cc"


def load(root: Path) -> dict[str, bytes]:
    """Authenticate bounded native bytes, original outcomes and retired identities before joining records."""
    raw = v.read(root / "build/results/assurance/reuse-plan" / NAME, 128 * 1024**2)
    if v.digest(raw) != ARCHIVE:
        v.reject("installation-archive")
    files = entry.unpack(raw)
    manifest = v.decode(files["manifest.json"])
    if manifest["trust"] != "local" or set(manifest["files"]) != set(files) - {"manifest.json"}:
        v.reject("installation-members")
    if any(item != {"bytes": len(files[name]), "sha256": v.digest(files[name])} for name, item in manifest["files"].items()):
        v.reject("installation-integrity")
    delivery.campaign(files, 6)
    owner = v.decode(files["controller.json"])
    returned = v.decode(files["cache-return.native.json"])
    if returned["boot_id"] != owner["boot_id"] or returned["owner"] != owner["identity"] or returned["inode"] != 713912 or returned["remaining_owned"]:
        v.reject("installation-cache")
    return files


def handoff(files: dict[str, bytes], previous: dict[str, bytes]) -> dict:
    """Permit exactly the reviewed ingress delta and one rebuilt executable, preserving every donor fact."""
    plan, prior = (v.decode(source["inputs.json"]) for source in (files, previous))
    donor = plan["donor"]
    before, after = (v.decode(source["candidate-manifest.json"]) for source in (previous, files))
    if (
        donor["archive_sha256"] != delivery.CURRENT[5]
        or donor["source"] != prior["files"]
        or donor["retirement"] != v.decode(previous["cleanup.native.json"])
        or donor["candidate"] != before
        or plan["cpp_production"] != prior["cpp_production"]
        or set(plan["relevant"]) != set(prior["relevant"])
        or {name for name, sha in plan["relevant"].items() if prior["relevant"][name] != sha} != {PATH}
        or prior["relevant"][PATH] != ORIGINAL
        or plan["relevant"][PATH] != SOURCE
        or any(plan["files"].get(name) != sha for name, sha in {**plan["relevant"], **plan["cpp_production"]}.items())
    ):
        v.reject("installation-handoff")
    candidate = {name.removeprefix("candidate/"): v.digest(raw) for name, raw in files.items() if name.startswith("candidate/")}
    if (
        len(before) != 51
        or set(candidate) != set(before)
        or candidate != after
        or after != v.decode(files["partial-candidate.native.json"])
        or {name for name, sha in after.items() if before[name] != sha} != {"bin/polaris"}
    ):
        v.reject("installation-products")
    reused = v.decode(files["reused-installed.native.json"])
    if (
        reused["donor_archive_sha256"] != donor["archive_sha256"]
        or len(reused["unchanged_files"]) != 50
        or set(reused["unchanged_files"]) != set(after) - {"bin/polaris"}
        or reused["unchanged_cpp_inputs"] != len(plan["cpp_production"])
        or reused["rebuilt"] != {"bin/polaris": after["bin/polaris"]}
        or files["consumers.json"] != previous["consumers.json"]
    ):
        v.reject("installation-reuse")
    probes = v.decode(files["consumers.json"])
    if set(probes) != {"comet_mesh_probe", "comet_process_probe"}:
        v.reject("installation-probes")
    for name, item in probes.items():
        raw = files["fixture/bin/" + name]
        if raw != previous["fixture/bin/" + name] or v.digest(raw) != item["sha256"]:
            v.reject("installation-probe-identity", name)
    return plan


def recovery(files: dict[str, bytes]) -> None:
    """Require all three distinct recoveries and the same surviving SDK, bound to actual installed bytes."""
    events = [v.decode(row) for row in files["recovery/events.jsonl"].splitlines()]
    recovered = [row for row in events if row["event"] == "recovered"]
    if (
        not events
        or events[0]["event"] != "started"
        or events[-1]["event"] != "completed"
        or events[-1]["cycles"] != 3
        or any(sum(row["event"] == event for row in events) != 1 for event in ("started", "steady", "completed"))
        or any(row["event"] in {"failed", "interrupted"} for row in events)
        or [(row["cycle"], row["star"]) for row in recovered] != [(1, 0), (2, 1), (3, 2)]
        or len({row["sdk_pid"] for row in recovered}) != 1
        or any(row.get("sdk_pid", recovered[0]["sdk_pid"]) != recovered[0]["sdk_pid"] for row in events)
        or events[0]["persistent"] is not True
        or any(events[0][key] != value for key, value in {"records": 16, "steady": 0, "faults": 0, "interval": 0}.items())
    ):
        v.reject("installation-recovery")
    candidate, probes = (v.decode(files[name]) for name in ("candidate-manifest.json", "consumers.json"))
    binaries = {name: candidate["bin/" + name] for name in ("star", "pulsar", "polaris", "astrolabe")}
    binaries.update({name: item["sha256"] for name, item in probes.items()})
    if events[0]["binaries"] != binaries:
        v.reject("installation-recovery-binaries")
    record, _ = delivery.receipt(files, PREFIX + "candidate-cluster/")
    base = v.decode(files["controller.json"])["cwd"]
    if (
        record["argv"]
        != [
            "/usr/bin/python3",
            "-B",
            "tests/soak.py",
            "--binaries",
            base + "/fixture/bin",
            "--output",
            base + "/recovery",
            "--installed",
            "--persistent",
            "--fault-seconds",
            "0",
            "--steady-seconds",
            "0",
            "--interval",
            "0",
            "--records",
            "16",
        ]
        or record["resolved_environment"].get("PATH") != "/usr/bin:/bin"
    ):
        v.reject("installation-recovery-command")


def merge(previous: dict[str, bytes], current: dict[str, bytes], *, commands: tuple[str, ...] = delivery.COMMANDS[6]) -> dict[str, bytes]:
    """Replace complete renewed command namespaces, retaining untouched commands and original archived records."""
    renewed = tuple("command/" + name + "/" for name in commands)
    facts = {name: raw for name, raw in previous.items() if not name.startswith(renewed)}
    facts.update(current)
    facts.update({"command/" + name.removeprefix(PREFIX): raw for name, raw in current.items() if name.startswith(PREFIX)})
    return facts


def replacement(files: dict[str, bytes], previous: dict[str, bytes]) -> dict:
    """Require one declared source delta and the same unchanged peers, SDK, runtimes and license files."""
    plan, prior = (v.decode(source["inputs.json"], maximum=8 * 1024**2) for source in (files, previous))
    before, after = (v.decode(source["candidate-manifest.json"]) for source in (previous, files))
    if (
        plan["donor_archive_sha256"] != ARCHIVE
        or plan["build_archive_sha256"] != BUILD
        or plan["donor_products"] != before
        or plan["relevant"] != prior["relevant"]
        or set(plan["cpp_production"]) != set(prior["cpp_production"])
        or {name for name, sha in plan["cpp_production"].items() if prior["cpp_production"][name] != sha} != {STAR}
        or prior["cpp_production"][STAR] != BEFORE
        or plan["cpp_production"][STAR] != AFTER
        or plan["source_delta"] != {STAR: {"before": BEFORE, "after": AFTER}}
        or any(plan["warm_files"].get(name) != sha for name, sha in {**plan["relevant"], **plan["cpp_production"]}.items())
    ):
        v.reject("installation-refresh-source")
    if (
        len(before) != 51
        or set(after) != set(before)
        or {name for name in after if after[name] != before[name]} != {"bin/star"}
        or {name for name in files if name.startswith("candidate/")} != {"candidate/bin/star"}
        or v.digest(files["candidate/bin/star"]) != after["bin/star"]
        or v.decode(files["installed.native.json"]).get("bin/star") != after["bin/star"]
        or files["consumers.json"] != previous["consumers.json"]
    ):
        v.reject("installation-refresh-products")
    # The replacement must originate from the standard installer, with its generated instructions captured as native inputs.
    output = plan["warm_root"] + "/build/cmake/release"
    scripts = v.decode(files["install-scripts.native.json"])
    if (
        set(scripts) != {output + "/cmake_install.cmake", output + "/comet/cpp/cmake_install.cmake"}
        or any(v.digest(files["installer/" + name.removeprefix(output + "/")]) != sha for name, sha in scripts.items())
        or (v.decode(files["controller.json"])["cwd"] + "/stage/bin/star").encode() not in files["install-manifest.native.txt"].splitlines()
    ):
        v.reject("installation-refresh-installer")
    return plan


def resolution(data: bytes, directory: str) -> None:
    """Resolve Linux loader spellings independently of the reader host, retaining exact runtime ownership."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        v.reject("installation-refresh-resolution")
    if "not found" in text:
        v.reject("installation-refresh-resolution")
    for runtime in delivery.RUNTIMES:
        paths = re.findall(r"^\s*" + re.escape(runtime) + r" => (\S+) \(0x[0-9a-f]+\)$", text, re.MULTILINE)
        if len(paths) != 1 or posixpath.normpath(paths[0]) != directory + "/" + runtime:
            v.reject("installation-refresh-resolution", runtime)


def supplement(files: dict[str, bytes], previous: dict[str, bytes]) -> dict:
    """Permit the exact maintenance source/fixture delta and one product, keeping all reused bytes bound."""
    from tools import idle

    plan, prior = (v.decode(source["inputs.json"]) for source in (files, previous))
    before, after = (v.decode(source["candidate-manifest.json"]) for source in (previous, files))
    changed = {idle.STORE, "polaris/internal/storage/storage_test.go"}
    added = {idle.WORKER, "polaris/internal/storage/maintenance_test.go"}
    if (
        plan["donor"]["archive_sha256"] != REFRESH
        or plan["donor"]["source"] != prior["warm_files"]
        or plan["donor"]["retirement"] != v.decode(previous["cleanup.native.json"])
        or plan["donor"]["candidate"] != before
        or plan["cpp_production"] != prior["cpp_production"]
        or set(plan["relevant"]) != set(prior["relevant"]) | added
        or {name for name, sha in prior["relevant"].items() if plan["relevant"].get(name) != sha} != changed
        or plan["source_delta"] != {name: {"before": prior["relevant"][name], "after": plan["relevant"][name]} for name in changed}
        or prior["relevant"][idle.STORE] != "7c914530e29059161f9665f867c1ce7f114cdec5c0be7bad43fdcbba3dfd0f16"
        or plan["relevant"][idle.STORE] != idle.SOURCES[idle.STORE]
        or plan["relevant"][idle.WORKER] != idle.SOURCES[idle.WORKER]
        or any(plan["files"].get(name) != sha for name, sha in {**plan["relevant"], **plan["cpp_production"]}.items())
    ):
        v.reject("installation-maintenance-source")
    if (
        len(before) != 51
        or set(after) != set(before)
        or {name for name in after if after[name] != before[name]} != {"bin/polaris"}
        or after["bin/polaris"] != POLARIS
        or {name for name in files if name.startswith("candidate/")} != {"candidate/bin/polaris"}
        or v.digest(files["candidate/bin/polaris"]) != after["bin/polaris"]
        or v.decode(files["partial-candidate.native.json"]) != after
        or files["consumers.json"] != previous["consumers.json"]
    ):
        v.reject("installation-maintenance-products")
    reused = v.decode(files["reused-installed.native.json"])
    if (
        reused["donor_archive_sha256"] != REFRESH
        or set(reused["unchanged_files"]) != set(after) - {"bin/polaris"}
        or len(reused["unchanged_files"]) != 50
        or reused["unchanged_cpp_inputs"] != len(plan["cpp_production"])
        or reused["rebuilt"] != {"bin/polaris": after["bin/polaris"]}
    ):
        v.reject("installation-maintenance-reuse")
    for name, item in v.decode(files["consumers.json"]).items():
        raw = files["fixture/bin/" + name]
        if raw != previous["fixture/bin/" + name] or v.digest(raw) != item["sha256"]:
            v.reject("installation-maintenance-probe", name)
    return plan


def maintenance(root: Path, previous: dict, inputs: dict, packages: bytes, archives: dict) -> tuple[dict, dict, bytes, dict]:
    """Join the already executed Polaris build and installed recovery, without starting native work."""
    name = "storage-delivery-current-8/native/evidence.tar.gz"
    raw = v.read(root / "build/results/assurance/reuse-plan" / name, 128 * 1024**2)
    if v.digest(raw) != MAINTENANCE:
        v.reject("installation-maintenance-archive")
    files = entry.unpack(raw)
    manifest = v.decode(files["manifest.json"])
    if manifest["trust"] != "local" or set(manifest["files"]) != files.keys() - {"manifest.json"}:
        v.reject("installation-maintenance-members")
    if any(item != {"bytes": len(files[path]), "sha256": v.digest(files[path])} for path, item in manifest["files"].items()):
        v.reject("installation-maintenance-integrity")
    records = delivery.campaign(files, 8)
    plan = supplement(files, previous)
    base = v.decode(files["controller.json"])["cwd"]
    for command, record in records.items():
        frozen = v.decode(files[PREFIX + command + "/plan.json"])
        if record["argv"] != frozen["argv"] or record["environment"] != frozen["environment"] or record["duration_ms"] > frozen["timeout_s"] * 1000:
            v.reject("installation-maintenance-command", command)
        for channel in ("stdout", "stderr"):
            if record[channel]["bytes"] > frozen["log_bytes"]:
                v.reject("installation-maintenance-stream", command)
    expected = {
        "go-build-polaris": ["go", "build", "-mod=readonly", "-p", "4", "-o", base + "/candidate/bin/polaris", "./polaris"],
        "modules-polaris": ["go", "version", "-m", base + "/candidate/bin/polaris"],
        "loader-polaris": ["readelf", "-d", base + "/candidate/bin/polaris"],
        "consumer-graph": ["go", "list", "-json", "./..."],
        **{"resolved-" + role.replace("_", "-"): ["ldd", base + "/fixture/bin/" + role] for role in ("comet_mesh_probe", "comet_process_probe")},
    }
    if any(records[command]["argv"] != argv for command, argv in expected.items()):
        v.reject("installation-maintenance-command")
    for command in ("go-build-polaris", "consumer-graph", "modules-polaris"):
        record = records[command]
        if record["executable_sha256"] != inputs["go_sha256"] or plan["tools"].get(record["executable"]) != record["executable_sha256"]:
            v.reject("installation-maintenance-compiler")
        if any(
            record["resolved_environment"].get(key) != value
            for key, value in {"GOFLAGS": "-mod=readonly", "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local"}.items()
        ):
            v.reject("installation-maintenance-environment")
    for command in ("resolved-comet-mesh-probe", "resolved-comet-process-probe"):
        record, text = delivery.receipt(files, PREFIX + command + "/")
        if record["resolved_environment"].get("PATH") != "/usr/bin:/bin" or {"LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"}.intersection(
            record["resolved_environment"]
        ):
            v.reject("installation-maintenance-loader")
        resolution(text, base + "/fixture/lib")
    _, current = delivery.receipt(files, PREFIX + "consumer-graph/")
    if delivery.consumers(current, "internal/admission", ("polaris", "astrolabe")) != delivery.consumers(
        packages, "internal/admission", ("polaris", "astrolabe")
    ):
        v.reject("installation-maintenance-consumers")
    recovery(files)
    return merge(previous, files, commands=delivery.COMMANDS[8]), {**inputs, "source": plan["files"]}, current, {**archives, name: MAINTENANCE}


def refresh(root: Path, previous: dict, archives: dict) -> tuple[dict, dict]:
    """Authenticate the later ordinary Star build and installed recovery without rebuilding unchanged consumers."""
    name = "storage-delivery-current-7/native/evidence.tar.gz"
    raw = v.read(root / "build/results/assurance/reuse-plan" / name, 128 * 1024**2)
    if v.digest(raw) != REFRESH:
        v.reject("installation-refresh-archive")
    files = entry.unpack(raw)
    manifest = v.decode(files["manifest.json"])
    if manifest["trust"] != "local" or set(manifest["files"]) != set(files) - {"manifest.json"}:
        v.reject("installation-refresh-members")
    if any(item != {"bytes": len(files[path]), "sha256": v.digest(files[path])} for path, item in manifest["files"].items()):
        v.reject("installation-refresh-integrity")
    records = delivery.campaign(files, 7)
    plan = replacement(files, previous)
    base = v.decode(files["controller.json"])["cwd"]
    output = plan["warm_root"] + "/build/cmake/release"
    expected = {
        "install-prerequisite": ["/usr/bin/cmake", "--build", output, "--target", "planet", "--parallel", "2"],
        "cpp-install": ["/usr/bin/cmake", "--install", output, "--prefix", base + "/stage"],
        "loader-star": ["/usr/bin/readelf", "-d", base + "/candidate/bin/star"],
        **{
            "resolved-" + role.replace("_", "-"): ["/usr/bin/ldd", base + "/fixture/bin/" + role]
            for role in ("star", "comet_mesh_probe", "comet_process_probe")
        },
    }
    for command, argv in expected.items():
        if records[command]["argv"] != argv:
            v.reject("installation-refresh-command", command)
    _, tags = delivery.receipt(files, PREFIX + "loader-star/")
    delivery.dynamic(tags, cpp=True)
    for command in ("resolved-star", "resolved-comet-mesh-probe", "resolved-comet-process-probe"):
        record, text = delivery.receipt(files, PREFIX + command + "/")
        if record["resolved_environment"].get("PATH") != "/usr/bin:/bin" or {"LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"}.intersection(
            record["resolved_environment"]
        ):
            v.reject("installation-refresh-loader", command)
        resolution(text, base + "/fixture/lib")
    build_name = "candidate-residence-prepare-current-1/residence-preparation/evidence.tar.gz"
    raw = v.read(root / "build/results/assurance/reuse-plan" / build_name, 32 * 1024**2)
    if v.digest(raw) != BUILD:
        v.reject("installation-refresh-build")
    built = entry.unpack(raw)
    frozen = v.decode(built["inputs.json"], maximum=8 * 1024**2)
    product = v.decode(built["products.native.json"])["star"]
    record, _ = delivery.receipt(built, "work/commands/release-build/")
    terminal = v.decode(built["terminal.json"])
    if (
        product["sha256"] != plan["star_build_sha256"]
        or product["path"] != output + "/star"
        or any(frozen["native_files"].get(path) != sha for path, sha in plan["cpp_production"].items())
        or record["argv"] != ["/usr/bin/cmake", "--build", output, "--target", "star", "pulsar", "comet_mesh_probe", "comet_process_probe", "--parallel", "2"]
        or record["executable_sha256"] != plan["dependencies"].get(record["executable"])
        or terminal["errors"]
        or terminal["interrupted"]
        or terminal["remaining_owned"]
        or v.decode(built["controller.json"]) not in plan["retired_owners"]
    ):
        v.reject("installation-refresh-build-binding")
    recovery(files)
    return merge(previous, files, commands=delivery.COMMANDS[7]), {**archives, name: REFRESH, build_name: BUILD}


def reconcile(root: Path, previous: dict, inputs: dict, packages: bytes, archives: dict) -> tuple[dict, dict, bytes, dict]:
    """Keep original command bytes while replacing only observations actually renewed by the native refresh."""
    if v.file_digest(root / PATH) != SOURCE:
        v.reject("installation-source")
    files = load(root)
    plan = handoff(files, previous)
    recovery(files)
    facts = merge(previous, files)
    graph, current = delivery.receipt(facts, "command/consumer-graph/")
    build, _ = delivery.receipt(facts, "command/go-build-polaris/")
    if (
        graph["argv"] != ["go", "list", "-json", "./..."]
        or graph["executable_sha256"] != inputs["go_sha256"]
        or plan["tools"].get(graph["executable"]) != graph["executable_sha256"]
        or build["executable_sha256"] != graph["executable_sha256"]
        or build["argv"][6] != v.decode(files["controller.json"])["cwd"] + "/candidate/bin/polaris"
        or any(
            record["resolved_environment"].get(key) != value
            for record in (graph, build)
            for key, value in {"GOFLAGS": "-mod=readonly", "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local"}.items()
        )
    ):
        v.reject("installation-toolchain")
    old = delivery.consumers(packages, "internal/admission", ("polaris", "astrolabe"))
    new = delivery.consumers(current, "internal/admission", ("polaris", "astrolabe"))
    if new != old or "polaris/internal/server" in new["consumers"]["astrolabe"]:
        v.reject("installation-consumer-impact")
    # Astrolabe keeps its authenticated original build; its full owned closure and all other relevant inputs are unchanged.
    builds = {"go-build": ["./polaris", "./astrolabe"], "go-build-polaris": ["./polaris"]}
    archives = {**archives, NAME: ARCHIVE}
    if v.file_digest(root / STAR) == AFTER:
        facts, archives = refresh(root, facts, archives)
    inputs = {"source": plan["files"], "go_sha256": graph["executable_sha256"], "builds": builds}
    from tools import idle

    if idle.current(root):
        return maintenance(root, facts, inputs, current, archives)
    return facts, inputs, current, archives
