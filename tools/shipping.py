"""Qualify the current installed candidate from native builds, linked inputs and real consumers."""

from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
import tarfile

from tools import delivery, entry, statements, verify as v

# Each archive retains its original commands and failures; a new reader does not rewrite them.
ARCHIVES = {
    "ephemeris-delivery-current-1/native/evidence.tar.gz": "4bc6680dc024209230f5dd0b79161222d96633d36616151905efd05d9a331503",
    "release-delivery-current-2/linux/evidence.tar.gz": "b4f6f6c2069f963678f0d8ef2ffdf34d00b31cbd4f6881c0f30f1c9070a6be5d",
    "ephemeris-system-ordinary-current-1/linux/evidence.tar.gz": "db41f21d474c3c93e57775394450b78fcd3f32a03ca0df1e44609872b4dfd743",
    "ephemeris-system-race-current-1/linux/evidence.tar.gz": "c0f72bbd3b31d4d246ecef069a7c1324cf629b4b6ab0e0fe7f143ab13261ab29",
    "installed-delivery-impact-current-1/native-inspection-1/evidence.tar.gz": "dcedab4f56ef76b1f66b7fedcfd49e5dae65cdd5492125339252e0b837d6633e",
    "installed-delivery-impact-current-1/native-inspection-3/evidence.tar.gz": "f8ca60cb5de42f2a6f70b0421d26630dec25ba2b7b50906bebf40cb3a93f0d43",
    "comet-go-system-build-current-1/native/evidence.tar.gz": "539e8589312d98d4928ce747eb7da5af7009bde81736a19610678b515743e73b",
}
PREFIX = "build/results/assurance/reuse-plan/"
GO = "/home/ubuntu/verdandi/build/tools/go-1.27.1/bin/go"
# The approved runtime/module upgrade renews installation and its direct finite consumers separately.
RENEWED = {
    "go-upgrade-delivery-current-3/native-correction/evidence-regular.tar.gz": "11a454de7769da4ff4c5922e453b60da6254dbd056a5dd079a5157e77b65b9fb",
    "go-upgrade-contracts-current-3/native/evidence.tar.gz": "bd374f0c01f159579b7d6a5d997f18537efdd9ee7b8ef22163ece1ecbd7fb93d",
    "go-upgrade-contracts-current-2/native/evidence.tar.gz": "6f5ae7ad4a9cd2a89f17dfe7447a3a37ea83a8c45b53b92c944cb2d06976effc",
    "go-upgrade-system-functional-ordinary-current-1/native/evidence.tar.gz": "67adf221e3648a4d3099b4d76f313e9fb962a93c9168cdecf3c28ae291a31e58",
    "go-upgrade-system-functional-race-current-1/native/evidence.tar.gz": "b3a111a61a12c5c19e6b21581623ed7c669e5c7f2eb030f82bcf5c3c72c7089a",
}
RENEWED_GO = "/home/ubuntu/verdandi/build/tools/go-1.27.2/bin/go"
RENEWED_COMPILER = "548d3c32f83fa81152f543eb1526be7884cfe0526eb5e9ce29d3eca14786e7e0"


@dataclass(frozen=True)
class Archive:
    """Keep authenticated metadata in memory while hashing large products incrementally."""

    files: dict[str, bytes]
    hashes: dict[str, str]
    sizes: dict[str, int]
    modes: dict[str, int]
    headers: dict[str, bytes]


def current(root: Path) -> bool:
    """Select this reviewed acquisition when present; damaged evidence cannot select an older fallback."""
    return (root / PREFIX / next(iter(RENEWED))).exists() or (root / PREFIX / next(iter(ARCHIVES))).exists()


def archive(path: Path, expected: str, *, builds: bool = False) -> Archive:
    """Authenticate every archive byte and member with fixed streaming memory and explicit expansion limits."""
    if type(builds) is not bool:
        v.reject("shipping-archive-policy")
    if path.stat().st_size > 256 * 1024**2 or v.file_digest(path) != expected:
        v.reject("shipping-archive", path.name)
    files, hashes, sizes, modes, headers = {}, {}, {}, {}, {}
    expanded, retained = 0, 0
    try:
        with tarfile.open(path, "r|gz") as stream:
            for member in stream:
                name = member.name
                if (
                    not member.isfile()
                    or name in hashes
                    or len(hashes) >= 2048
                    or PurePosixPath(name).as_posix() != name
                    or name.startswith("/")
                    or any(character in name for character in "\\:")
                    or any(part in {".", ".."} for part in name.split("/"))
                    or not 0 <= member.size <= 128 * 1024**2
                ):
                    v.reject("shipping-member", name)
                expanded += member.size
                if expanded > 1024**3:
                    v.reject("shipping-expansion")
                contents = stream.extractfile(member)
                header = contents.read(64)
                digest, count = hashlib.sha256(header), len(header)
                keep = (not name.startswith(("candidate/", "fixture/")) or name.endswith((".cmake", ".hpp"))) and not header.startswith(
                    (b"\x7fELF", b"!<arch>\n")
                )
                if builds and name.startswith(("source/build/commands/", "commands/")):
                    command = name.removeprefix("source/build/").split("/")[1]
                    keep = keep and command in {
                        "root-ordinary-polaris",
                        "root-ordinary-polaris-metadata",
                        "root-ordinary-astrolabe",
                        "root-ordinary-astrolabe-metadata",
                        "sdk-ordinary-binary",
                        "sdk-ordinary-metadata",
                        "sdk-race-binary",
                        "sdk-race-metadata",
                    }
                chunks = [header] if keep else []
                while chunk := contents.read(1024**2):
                    digest.update(chunk)
                    count += len(chunk)
                    if keep:
                        chunks.append(chunk)
                if count != member.size:
                    v.reject("shipping-truncated", name)
                hashes[name], sizes[name], modes[name], headers[name] = digest.hexdigest(), count, member.mode, header
                if keep:
                    retained += count
                    if count > 16 * 1024**2 or retained > 64 * 1024**2:
                        v.reject("shipping-metadata-size", name)
                    files[name] = b"".join(chunks)
    except tarfile.TarError as error:
        v.reject("shipping-format", type(error).__name__)
    if not hashes or v.file_digest(path) != expected:
        v.reject("shipping-archive-changed")
    return Archive(files, hashes, sizes, modes, headers)


def sources(files: dict[str, bytes], name: str, expected: dict[str, str]) -> None:
    """Check the original source snapshot without transferring historical whole-tree pass credit."""
    if {path: v.digest(data) for path, data in entry.unpack(files[name]).items()} != expected:
        v.reject("shipping-source-archive", name)


def campaign(files: dict[str, bytes], prefix: str, names: set[str], *, errors: tuple[str, ...] = ()) -> dict[str, dict]:
    """Require original native streams, exact command owners and retired resources, including known failed parents."""
    inputs, owner, terminal, cleanup = (v.decode(files[name]) for name in ("inputs.json", "controller.json", "terminal.json", "cleanup.native.json"))
    state = cleanup["unit"]
    if (
        owner["inputs_sha256"] != v.digest(files["inputs.json"])
        or owner["script_sha256"] != inputs["run_sha256"]
        or inputs["run_sha256"] != v.digest(files["run.py"])
        or owner["boot_id"] != inputs["boot_id"]
        or terminal["errors"] != list(errors)
        or terminal["interrupted"] is not False
        or terminal["remaining_owned"]
        or state["MainPID"] != "0"
        or state["ControlGroup"]
        or state["InvocationID"] not in ("", owner["invocation_id"])
    ):
        v.reject("shipping-campaign")
    outcomes = terminal.get("records", terminal.get("completed", {}))
    if set(outcomes) != names:
        v.reject("shipping-command-inventory")
    records, identities = {}, [owner["identity"]]
    for name in sorted(names):
        location = prefix + name + "/"
        record, _ = delivery.receipt(files, location)
        process = v.decode(files[location + name + ".process.json"])
        plan = v.decode(files[location + ("plan.json" if location + "plan.json" in files else "request.json")])
        if (
            record["argv"] != process["argv"]
            or record["argv"] != plan["argv"]
            or process["boot_id"] != owner["boot_id"]
            or process["identity"]["parent"] != owner["identity"]["pid"]
            or ("record_sha256" in outcomes[name] and outcomes[name]["record_sha256"] != v.digest(files[location + "record.json"]))
            or any(record.get(key) != value for key, value in outcomes[name].items() if key in record)
        ):
            v.reject("shipping-command-binding", name)
        records[name] = record
        identities.append(process["identity"])
    if len(cleanup["retired"]) != len(identities) or {v.encode(row) for row in cleanup["retired"]} != {v.encode(row) for row in identities}:
        v.reject("shipping-retirement")
    if "records" in terminal:
        if cleanup["failed"] or cleanup["remaining_owned"]:
            v.reject("shipping-retirement")
        journal = v.decode(files["journal.native.json"])
    else:
        if cleanup["boot_id"] != owner["boot_id"] or cleanup["original_exit_code"] != int(bool(errors)):
            v.reject("shipping-original-exit")
        journal = [v.decode(row) for row in files["journal.native.jsonl"].splitlines()]
    if (
        not journal
        or any(row.get("_BOOT_ID") != owner["boot_id"].replace("-", "") for row in journal)
        or any((row.get("INVOCATION_ID") or row.get("_SYSTEMD_INVOCATION_ID")) != owner["invocation_id"] for row in journal)
        or terminal not in [v.decode(row["MESSAGE"]) for row in journal if row.get("MESSAGE", "").startswith('{"at":')]
    ):
        v.reject("shipping-journal")
    return records


def inspection(files: dict[str, bytes]) -> tuple[dict, dict]:
    """Recompute the native read owner, manifest, unchanged inputs and actual retirement facts."""
    manifest = v.decode(files["manifest.json"])
    if manifest["trust"] != "local" or manifest["files"] != {
        name: {"bytes": len(raw), "sha256": v.digest(raw)} for name, raw in files.items() if name != "manifest.json"
    }:
        v.reject("shipping-inspection-members")
    inputs, owner, facts, terminal, observation = (
        v.decode(files[name], maximum=16 * 1024**2)
        for name in ("inputs.json", "owner.native.json", "facts.native.json", "terminal.native.json", "observation.native.json")
    )
    state = observation["state"]
    if (
        owner["inputs_sha256"] != v.digest(files["inputs.json"])
        or owner["driver_sha256"] != inputs["driver_sha256"]
        or owner["driver_sha256"] != v.digest(files["run.py"])
        or owner["identity"] != terminal["identity"]
        or owner["identity"] != observation["retirement"]["identity"]
        or owner["identity"]["boot_id"] != inputs["boot_id"]
        or observation["retirement"]["current_start_ticks"] == owner["identity"]["start_ticks"]
        or terminal != observation["terminal"]
        or terminal["errors"]
        or terminal["complete"] is not True
        or facts["checked"] != inputs["expected"]
        or facts["unchanged_after"] is not True
        or state["MainPID"] != "0"
        or state["ControlGroup"]
        or state["ExecMainStatus"] != "0"
        or state["Result"] != "success"
        or owner["limits"] != {"memory.max": "268435456", "memory.swap.max": "0", "cpu.max": "100000 100000", "pids.max": "32"}
        or not any(row.get("MESSAGE") == inputs["unit"] + ": Deactivated successfully." for row in observation["journal"])
    ):
        v.reject("shipping-inspection")
    return inputs, facts


def absolute(directory: str, operand: str) -> str:
    """Interpret native POSIX recipe paths as data, never Windows paths or shell commands."""
    return posixpath.normpath(posixpath.join(directory, operand))


def closure(files: dict[str, bytes], inputs: dict, native: dict, current: dict[str, str], candidate: dict[str, str]) -> dict:
    """Derive actual linked objects recursively; unrelated test objects cannot invalidate or qualify shipped bytes."""
    root, build = inputs["root"], inputs["build"]
    destination = str(PurePosixPath(next(path for path in v.decode(files["products.native.json"]) if "/candidate/" in path)).parents[2])
    directories = {"production": build, "consumer": inputs["consumer"]}
    recipes, commands, units = {}, {}, {}
    for label, directory in directories.items():
        prefix = "metadata/" + label + "/"
        links = {name.removeprefix(prefix): raw for name, raw in files.items() if name.startswith(prefix) and name.endswith("/link.txt")}
        for name, row in native["metadata"].items():
            if label == "production" and name.endswith("/link.txt"):
                if not name.startswith(directory + "/") or v.digest(row["text"].encode()) != row["sha256"]:
                    v.reject("shipping-native-recipe")
                links[name[len(directory) + 1 :]] = row["text"].encode()
        for name, raw in links.items():
            directory_native = absolute(directory, PurePosixPath(name).parents[2].as_posix())
            lines = raw.decode().splitlines()
            arguments = shlex.split(lines[0])
            if not arguments or any(argument.startswith("@") for argument in arguments):
                v.reject("shipping-recipe")
            if arguments.count("-o") == 1:
                output = absolute(directory_native, arguments[arguments.index("-o") + 1])
            elif (
                len(lines) == 2
                and PurePosixPath(arguments[0]).name == "ar"
                and arguments[1] == "qc"
                and PurePosixPath(shlex.split(lines[1])[0]).name == "ranlib"
            ):
                output = absolute(directory_native, arguments[2])
            else:
                v.reject("shipping-recipe")
            if output in recipes:
                v.reject("shipping-recipe-duplicate")
            recipes[output] = {
                "sha256": v.digest(raw),
                "inputs": sorted({absolute(directory_native, argument) for argument in arguments[1:] if argument.endswith((".a", ".o"))} - {output}),
            }
        for command in v.decode(files[prefix + "compile_commands.json"], maximum=8 * 1024**2):
            arguments = shlex.split(command["command"])
            if arguments.count("-o") != 1:
                v.reject("shipping-compile-command")
            output = absolute(command["directory"], arguments[arguments.index("-o") + 1])
            if output in commands:
                v.reject("shipping-compile-duplicate")
            commands[output] = command
    for row in v.decode(files["compiled-inputs.native.json"], maximum=16 * 1024**2):
        name = row["path"]
        output = absolute(directories[row["build"]], name[:-2])
        if not name.endswith(".o.d") or output in units or output not in commands or v.digest(files["metadata/" + row["build"] + "/" + name]) != row["sha256"]:
            v.reject("shipping-compiled-input")
        source = commands[output]["file"]
        if source not in row["files"]:
            alias = native["aliases"].get(source)
            if alias is None or row["files"].get(alias["resolved"]) != alias["sha256"]:
                v.reject("shipping-compiled-source")
        units[output] = row
    comet = build + "/comet/cpp/libcomet.a"
    if native["checked"].get(comet) != candidate["lib/libcomet.a"]:
        v.reject("shipping-installed-archive")
    aliases = {destination + "/candidate/lib/libcomet.a": comet}
    protected = v.decode(files["protected.native.json"])
    linked, selected, external = {}, {}, {}

    def visit(path: str) -> None:
        """Require every recursive project library/object edge; only pinned external archives terminate it."""
        path = aliases.get(path, path)
        if path in linked or path in selected or path in external:
            return
        if path in recipes:
            linked[path] = recipes[path]
            for dependency in recipes[path]["inputs"]:
                visit(dependency)
        elif path in units:
            selected[path] = units[path]
        elif path.endswith(".a") and not path.startswith(root + "/") and path in protected and native["checked"].get(path) == protected[path]:
            external[path] = protected[path]
        else:
            v.reject("shipping-link-input", path)

    seeds = [build + "/" + name for name in ("star", "planet", "pulsar")]
    seeds += [inputs["consumer"] + "/" + name for name in ("consumer", "comet_batch_test", "comet_mesh_probe", "comet_process_probe")]
    for seed in [*seeds, comet]:
        if seed not in recipes:
            v.reject("shipping-link-root", seed)
        visit(seed)
    original, project = {}, {}
    for row in units.values():
        for path, sha in row["files"].items():
            if path.startswith(root + "/") and not path.startswith(root + "/build/"):
                name = path[len(root) + 1 :]
                if inputs["files"].get(name) != sha or original.setdefault(name, sha) != sha:
                    v.reject("shipping-original-source", name)
    for row in selected.values():
        for path, sha in row["files"].items():
            if native["checked"].get(path) != sha:
                v.reject("shipping-native-input", path)
            if path.startswith(root + "/") and not path.startswith(root + "/build/"):
                name = path[len(root) + 1 :]
            elif path.startswith(destination + "/candidate/include/"):
                name = "comet/cpp/include/" + path[len(destination + "/candidate/include/") :]
                if candidate.get(name.removeprefix("comet/cpp/")) != sha:
                    v.reject("shipping-public-header")
            else:
                continue
            if current.get(name) != sha or project.setdefault(name, sha) != sha:
                v.reject("shipping-source-drift", name)
    operands = recipes[comet]["inputs"]
    if set(native["archive_members"]) != set(operands) or any(native["archive_members"][path]["member"] != PurePosixPath(path).name for path in operands):
        v.reject("shipping-archive-objects")
    build_inputs = {
        name: sha
        for name, sha in inputs["files"].items()
        if PurePosixPath(name).name == "CMakeLists.txt" or name.endswith((".cmake", ".proto", ".cmake.in")) or name.startswith(("proto/", "tools/generate"))
    }
    for name, sha in build_inputs.items():
        if current.get(name) != sha:
            v.reject("shipping-build-drift", name)
    return {
        "linked_units": len(selected),
        "recipes": len(linked),
        "project_inputs": project,
        "build_inputs": build_inputs,
        "external_libraries": external,
        "unlinked_drift": {name: {"original": sha, "current": current.get(name)} for name, sha in original.items() if current.get(name) != sha},
    }


def candidate(assembled: Archive, native: dict) -> tuple[dict, dict]:
    """Bind the standard installer, public SDK execution, native loader closure and complete candidate bytes."""
    files = assembled.files
    inputs, result, inventory, products = (
        v.decode(files[name]) for name in ("inputs.json", "result.native.json", "inventory.native.json", "products.native.json")
    )
    manifest = v.decode(files["candidate-manifest.json"])
    if (
        len(manifest) != 51
        or manifest != {name.removeprefix("candidate/"): sha for name, sha in assembled.hashes.items() if name.startswith("candidate/")}
        or manifest != result["candidate"]
        or set(inventory["files"]) != set(manifest)
        or result["consumer_hits"] != 8
        or any(result[name] is not True for name in ("batch_passed", "protected_unchanged", "compiled_inputs_unchanged", "products_unchanged"))
    ):
        v.reject("shipping-candidate")
    names = {"cpp-build", "cpp-install", "consumer-configure", "consumer-build", "consumer-run", "batch-run"}
    roles = ("star", "planet", "pulsar", "polaris", "astrolabe", "consumer", "comet_mesh_probe", "comet_process_probe")
    names |= {stage + "-" + role.replace("_", "-") for stage in ("loader", "resolved") for role in roles}
    records = campaign(files, "command/", names)
    root, build = inputs["root"], inputs["build"]
    destination = records["cpp-install"]["argv"][-1]
    expected = {
        "cpp-build": ["/usr/bin/cmake", "--build", build, "--target", "star", "planet", "pulsar", "comet", "--parallel", "2"],
        "cpp-install": ["/usr/bin/cmake", "--install", build, "--prefix", destination],
        "consumer-build": ["/usr/bin/cmake", "--build", inputs["consumer"], "--parallel", "2"],
    }
    for name, arguments in expected.items():
        if records[name]["argv"] != arguments:
            v.reject("shipping-install-command", name)
    required = (
        "CMAKE_BUILD_TYPE:STRING=Release",
        "ASTRA_PROFILE:BOOL=OFF",
        "ASTRA_COVERAGE:BOOL=OFF",
        "ASTRA_SANITIZER:STRING=",
        "ASTRA_CONTRACT_SEMANTIC:STRING=enforce",
        "FETCHCONTENT_FULLY_DISCONNECTED:BOOL=ON",
        "FETCHCONTENT_UPDATES_DISCONNECTED:BOOL=ON",
    )
    if not set(required) <= set(files["metadata/production/CMakeCache.txt"].decode().splitlines()):
        v.reject("shipping-build-mode")
    for name, sha in manifest.items():
        path = "candidate/" + name
        if (
            inventory["files"][name] != {"bytes": assembled.sizes[path], "sha256": sha, "executable": bool(assembled.modes[path] & 0o100)}
            or assembled.modes[path] & 0o002
            or assembled.hashes.get("fixture/" + name) != sha
            or products.get(destination + "/" + name) != sha
        ):
            v.reject("shipping-inventory", name)
        if name.startswith("bin/") or name in {"lib/" + runtime for runtime in delivery.RUNTIMES}:
            delivery.header(assembled.headers[path])
        if name.startswith("bin/") and not assembled.modes[path] & 0o100:
            v.reject("shipping-executable", name)
        if name.endswith(".cmake") and any(forbidden.encode() in files[path] for forbidden in (root, inputs["donor"])):
            v.reject("shipping-export-path", name)
    if any(native["checked"].get(path) != sha for path, sha in {**products, **v.decode(files["runtimes.native.json"])}.items()):
        v.reject("shipping-physical-products")
    for role in roles:
        label = role.replace("_", "-")
        loader, tags = delivery.receipt(files, "command/loader-" + label + "/")
        resolved, output = delivery.receipt(files, "command/resolved-" + label + "/")
        cpp = role not in {"polaris", "astrolabe"}
        if (
            loader["argv"] != ["/usr/bin/readelf", "-d", destination.removesuffix("/candidate") + "/fixture/bin/" + role]
            or resolved["argv"] != ["/usr/bin/ldd", loader["argv"][-1]]
            or any({"LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"} & record["resolved_environment"].keys() for record in (loader, resolved))
        ):
            v.reject("shipping-loader-command", role)
        dynamic = delivery.dynamic(tags, cpp=cpp)
        if dynamic["needed"]:
            text = output.decode()
            if "not found" in text:
                v.reject("shipping-loader-missing", role)
            if cpp:
                for runtime in delivery.RUNTIMES:
                    paths = re.findall(r"^\s*" + re.escape(runtime) + r" => (\S+) \(0x[0-9a-f]+\)$", text, re.MULTILINE)
                    if len(paths) != 1 or posixpath.normpath(paths[0]) != destination.removesuffix("/candidate") + "/fixture/lib/" + runtime:
                        v.reject("shipping-loader-runtime", role)
    _, output = delivery.receipt(files, "command/consumer-run/")
    _, batch = delivery.receipt(files, "command/batch-run/")
    markers = re.findall(rb"^ASTRA-CHECKS (\{[^\n]*\})\r?$", batch, re.MULTILINE)
    if output.strip() != b'ASTRA-DELIVERY {"contract":"DELIVERY-SDK","hits":8}' or len(markers) != 1 or v.decode(markers[0])["hits"] <= 0:
        v.reject("shipping-public-consumer")
    compiled = v.decode(files["metadata/consumer/compile_commands.json"])
    public = [row for row in compiled if row["file"] == root + "/tests/delivery/main.cpp"]
    link = files["metadata/consumer/CMakeFiles/consumer.dir/link.txt"].decode()
    if len(public) != 1 or destination + "/include" not in public[0]["command"] or destination + "/lib/libcomet.a" not in link or root + "/comet/cpp" in link:
        v.reject("shipping-public-inputs")
    sources(files, "source.tar.gz", inputs["files"])
    sources(files, "original-source.tar.gz", inputs["original_files"])
    if v.decode(files["source-before.native.json"]) != v.decode(files["source-after.native.json"]):
        v.reject("shipping-native-source-changed")
    return inputs, manifest


def programs(built: Archive, inspected: dict[str, bytes], inputs: dict, native: dict, current: dict[str, str], installed: dict[str, str]) -> tuple[dict, dict]:
    """Tie both Go services to actual native builds, fresh installed metadata and the complete native import graph."""
    files = built.files
    plan = v.decode(files["inputs.json"])
    source = inputs["go_production"]
    expected = {
        name: sha
        for name, sha in current.items()
        if name in {"go.mod", "go.sum"} or name.startswith(("internal/", "polaris/", "astrolabe/")) and name.endswith(".go") and not name.endswith("_test.go")
    }
    if (
        source != expected
        or any(plan["files"].get(name) != sha for name, sha in source.items())
        or current.get("dependencies.lock.json") != plan["files"]["dependencies.lock.json"]
    ):
        v.reject("shipping-go-source")
    records = campaign(files, "source/build/commands/", {"go-mod-verify", "go-build-polaris", "go-build-astrolabe", "install"}, errors=("AssertionError: ",))
    sources(files, "source.tar.gz", plan["files"])
    original = v.decode(files["partial-candidate.native.json"])
    inspection_inputs, facts = inspection(inspected)
    commands = {name: text.encode() for name, text in facts["commands"].items()}
    owner = v.decode(inspected["owner.native.json"])
    observation = v.decode(inspected["observation.native.json"])
    identities = []
    fresh = {}
    for name in ("graph", "modules-polaris", "modules-astrolabe"):
        record, output = delivery.receipt(commands, name + "/")
        process = v.decode(commands[name + "/" + name + ".process.json"])
        if (
            record["argv"] != next(row["argv"] for row in inspection_inputs["commands"] if row["id"] == name)
            or record["argv"] != process["argv"]
            or process["identity"]["parent"] != owner["identity"]["pid"]
            or record["executable"] != GO
            or record["executable_sha256"] != facts["checked"].get(GO)
            or any(
                record["resolved_environment"].get(key) != value
                for key, value in {"GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": "-mod=readonly"}.items()
            )
        ):
            v.reject("shipping-go-inspection-command", name)
        identities.append(process["identity"])
        fresh[name] = (record, output)
    retired = observation["retired_commands"]
    if (
        len(retired) != len(identities)
        or {v.encode(row["identity"]) for row in retired} != {v.encode(row) for row in identities}
        or any(row["current_start_ticks"] == row["identity"]["start_ticks"] for row in retired)
    ):
        v.reject("shipping-go-inspection-retirement")
    if fresh["graph"][0]["argv"] != [GO, "-C", inputs["root"], "list", "-mod=readonly", "-json", "./..."]:
        v.reject("shipping-go-graph-command")
    graph = delivery.consumers(fresh["graph"][1], "internal/admission", ("polaris", "astrolabe"))
    storage = delivery.consumers(fresh["graph"][1], "polaris/internal/storage", ("polaris",))
    selected = set().union(*map(set, graph["consumers"].values()))
    native_sources = {}
    for package in statements.stream(fresh["graph"][1]):
        name = package["ImportPath"].removeprefix("github.com/eosforge/astra/")
        if name in selected or name.startswith(("internal/", "polaris/", "astrolabe/")):
            if package["Dir"] != inputs["root"] + "/" + name:
                v.reject("shipping-go-package-directory")
            for field in ("GoFiles", "CgoFiles", "IgnoredGoFiles"):
                for filename in package.get(field, []):
                    path = name + "/" + filename
                    native_sources[path] = source[path]
    if native_sources != {name: sha for name, sha in source.items() if name.endswith(".go")}:
        v.reject("shipping-go-native-inventory")
    for name in ("polaris", "astrolabe"):
        path = "bin/" + name
        record = records["go-build-" + name]
        arguments = record["argv"]
        metadata_record, metadata = fresh["modules-" + name]
        if (
            original[path] != installed[path]
            or built.hashes.get("candidate/" + path) != installed[path]
            or native["checked"].get(arguments[0]) not in (None, record["executable_sha256"])
            or record["executable_sha256"] != facts["checked"].get(GO)
            or arguments[:6] != [GO, "build", "-mod=readonly", "-p", "4", "-o"]
            or arguments[7:] != ["./" + name]
            or record["resolved_environment"].get("CGO_ENABLED") != "1"
            or any(
                record["resolved_environment"].get(key) != value
                for key, value in {"GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=readonly"}.items()
            )
            or metadata_record["argv"] != [GO, "version", "-m", inspection_inputs["commands"][("polaris", "astrolabe").index(name) + 1]["argv"][-1]]
            or facts["checked"].get(metadata_record["argv"][-1]) != installed[path]
            or b"\tpath\tgithub.com/eosforge/astra/" + name.encode() + b"\n" not in metadata
            or not all(b"\tbuild\t" + flag + b"\n" in metadata for flag in (b"CGO_ENABLED=1", b"GOOS=linux", b"GOARCH=amd64"))
            or any(flag in metadata for flag in (b"-race=true", b"-asan=true", b"-msan=true"))
        ):
            v.reject("shipping-go-build", name)
    return graph, storage


def sdk(built: Archive, current: dict[str, str]) -> dict:
    """Recompute ordinary/race Go system fixture provenance from native selected sources and original build output."""
    files = built.files
    inputs, products, selections = (v.decode(files[name]) for name in ("inputs.json", "products.native.json", "selected-sdk.native.json"))
    owned = {name: sha for name, sha in current.items() if name.startswith("comet/go/") and name.endswith((".go", "go.mod", "go.sum"))}
    if owned != {name: sha for name, sha in inputs["files"].items() if name.startswith("comet/go/") and name.endswith((".go", "go.mod", "go.sum"))}:
        v.reject("shipping-sdk-inventory")
    names = {"module-verify"} | {stage + "-" + profile for stage in ("graph", "build", "metadata", "list") for profile in ("ordinary", "race")}
    records = campaign(files, "command/", names)
    sources(files, "source.tar.gz", inputs["files"])
    for profile in ("ordinary", "race"):
        arguments = records["build-" + profile]["argv"]
        _, graph = delivery.receipt(files, "command/graph-" + profile + "/")
        _, listed = delivery.receipt(files, "command/list-" + profile + "/")
        selected = {}
        for package in statements.stream(graph):
            path = package.get("ImportPath", "").removeprefix("github.com/eosforge/astra/")
            if path == "comet/go" or path.startswith("comet/go/internal/"):
                if package["Dir"] != inputs["root"] + "/" + path:
                    v.reject("shipping-sdk-directory")
                fields = ("GoFiles", "TestGoFiles", "XTestGoFiles") if path == "comet/go" else ("GoFiles",)
                for field in fields:
                    for filename in package.get(field, []):
                        name = path + "/" + filename
                        selected[name] = inputs["native_files"][name]
        product = products[profile]
        if (
            selected != selections[profile]
            or "comet/go/system_test.go" not in selected
            or any(current.get(name) != sha or inputs["files"].get(name) != sha for name, sha in selected.items())
            or listed.strip() != b"TestSystemThreeStars"
            or ("-race" in arguments) != (profile == "race")
            or not {"-c", "-mod=readonly"} <= set(arguments)
            or records["build-" + profile]["resolved_environment"].get("CGO_ENABLED") != "1"
            or built.hashes.get("binaries/comet-go-system-" + profile) != product["sha256"]
        ):
            v.reject("shipping-sdk-build", profile)
        delivery.header(built.headers["binaries/comet-go-system-" + profile])
    return products


def system(observed: Archive, profile: str, installed: dict[str, str], products: dict, current: dict[str, str]) -> dict:
    """Require simultaneous local writers, cross subscriptions, bidirectional replication and surviving SDK owners."""
    files = observed.files
    inputs, terminal = (v.decode(files[name]) for name in ("inputs.json", "terminal.json"))
    records = campaign(files, "source/build/commands/", {"baseline", "cluster"})
    sources(files, "source.tar.gz", inputs["files"])
    if (
        inputs["candidate"] != installed
        or v.decode(files["candidate-manifest.json"]) != installed
        or inputs["profile"] != profile
        or inputs["go_system_sha256"] != products[profile]["sha256"]
        or inputs["go_program"] != products[profile]["path"]
        or any(terminal[name] is not True for name in ("source_unchanged", "products_unchanged", "protected_unchanged"))
    ):
        v.reject("shipping-system-products")
    # These source inputs actually drive the installed runtime/oracles; other unit/collector changes earn no credit here.
    runtime = {name: sha for name, sha in inputs["files"].items() if name.startswith("comet/go/") and name.endswith((".go", "go.mod", "go.sum"))}
    runtime.update({name: inputs["files"][name] for name in ("tests/soak.py", "tests/resources.py", "tests/support.py")})
    if any(current.get(name) != sha for name, sha in runtime.items()):
        v.reject("shipping-system-source")
    sequences = {}
    for label in ("baseline", "cluster"):
        record, stdout = delivery.receipt(files, "source/build/commands/" + label + "/")
        if (
            b"PASS real Almanac persistence and native multi-Star replication, crash, failover, trusted restart, TTL and owned cleanup" not in stdout
            or "--installed" not in record["argv"]
            or "--persistent" not in record["argv"]
            or {"LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"} & record["resolved_environment"].keys()
            or ("--comet-go" in record["argv"]) != (label == "cluster")
        ):
            v.reject("shipping-system-command", label)
        logs = [raw for name, raw in files.items() if name.startswith("source/build/commands/" + label + "/logs/") and name.endswith("-sequence.log")]
        if len(logs) != 1:
            v.reject("shipping-system-sequence")
        sequences[label] = delivery.sequence(logs[0])
    events = [v.decode(row) for row in files["recovery/events.jsonl"].splitlines()]
    resources = v.decode(files["resources.native.json"])
    owner = v.decode(files["controller.json"])
    clocks = [v.decode(row) for row in files["clock.native.jsonl"].splitlines()]
    if (
        resources["properties"] != {"PrivateNetwork": "yes", "JoinsNamespaceOf": ""}
        or resources["network_namespace"] != owner["network_namespace"]
        or len(clocks) < records["cluster"]["duration_ms"] // 1000 - 2
        or any(row["modes"] != 0 or row["return"] != 0 or row["fields"]["status"] & (64 | 4096) for row in clocks)
        or any(
            max(row["fields"]["maxerror"], row["fields"]["esterror"]) * 1000 + abs(row["fields"]["offset"]) + row["window_ns"] >= 500000000 for row in clocks
        )
        or events[0]["event"] != "started"
        or events[0]["records"] != 16
        or events[0]["persistent"] is not True
        or any(events[0][field] != 0 for field in ("faults", "steady", "interval"))
        or [(row["cycle"], row["star"]) for row in events if row["event"] == "recovered"] != [(1, 0), (2, 1), (3, 2)]
        or any(row["event"] in {"failed", "interrupted"} for row in events)
    ):
        v.reject("shipping-system-runtime")
    phases = ["ready", "before", "cached", "deleted", "empty", "restored"]
    expected = [{"event": "go_authority_" + phase, "cycle": 0, "star": 0} for phase in phases]
    expected += [{"event": event, "cycle": cycle, "star": cycle} for cycle in range(3) for event in ("go_mesh_ready", "go_mesh_failover", "go_mesh_recovered")]
    sdk_events = [row for row in events if row["event"] == "comet_go"]
    logs = [raw for name, raw in files.items() if name.startswith("recovery/") and name.endswith("-comet-go.log")]
    if len(sdk_events) != 1 or len(logs) != 1:
        v.reject("shipping-system-sdk")
    text = logs[0].decode()
    actual = [v.decode(line) for line in text.splitlines() if line.startswith("{")]
    recovered = [row for row in events if row["event"] == "comet_go_recovered"]
    authority = [row for row in events if row["event"] == "comet_go_authority"]
    crashed = [row for row in events if row["event"] == "comet_go_authority_crash"]
    restarted = [row for row in events if row["event"] == "comet_go_authority_restart"]
    if (
        actual != expected
        or not text.startswith("=== RUN   TestSystemThreeStars\n")
        or not text.endswith("\nPASS\n")
        or "--- PASS: TestSystemThreeStars (" not in text
        or any(marker in text for marker in ("DATA RACE", "SKIP", "FAIL"))
        or sdk_events[0]["nodes"] != 3
        or [(row["cycle"], row["star"]) for row in recovered] != [(1, 0), (2, 1), (3, 2)]
        or any(row["sdk_pid"] != sdk_events[0]["sdk_pid"] for row in recovered + authority)
        or any(row["elapsed"] >= sdk_events[0]["elapsed"] for row in recovered)
        or [row["phase"] for row in authority] != ["go_authority_" + phase for phase in phases]
        or len(crashed) != 1
        or len(restarted) != 1
        or crashed[0]["exit_code"] != -9
        or restarted[0]["previous_pid"] != crashed[0]["pid"]
        or restarted[0]["pid"] == crashed[0]["pid"]
        or restarted[0]["initialize"] is not False
        or not authority[1]["elapsed"] < crashed[0]["elapsed"] < authority[2]["elapsed"] < restarted[0]["elapsed"] < authority[3]["elapsed"]
        or events[0]["binaries"]["comet_go"] != products[profile]["sha256"]
        or events[-1]["event"] != "completed"
        or events[-1]["cycles"] != 3
    ):
        v.reject("shipping-system-oracle")
    physical = v.decode(files["products.json"])
    for name, sha in events[0]["binaries"].items():
        if (
            physical.get(
                records["cluster"]["argv"][records["cluster"]["argv"].index("--binaries") + 1] + "/" + ("comet-go-system" if name == "comet_go" else name)
            )
            != sha
        ):
            v.reject("shipping-system-identity", name)
        if "bin/" + name in installed and installed["bin/" + name] != sha:
            v.reject("shipping-system-candidate", name)
    return {"profile": profile, "sequence": sequences["cluster"], "baseline": sequences["baseline"], "go_phases": actual, "cycles": 3}


def native(files: dict[str, bytes], prefix: str, names: set[str], *, unit: str, boot: str, flat: bool = False) -> dict[str, dict]:
    """Read the current collector format without changing historical command or lifecycle interpretation."""
    if type(flat) is not bool:
        v.reject("shipping-native-format")
    inputs, owner, terminal, cleanup = (v.decode(files[name]) for name in ("inputs.json", "controller.json", "terminal.json", "cleanup.native.json"))
    state = cleanup["unit"]
    if (
        owner["boot_id"] != boot
        or owner["inputs_sha256"] != v.digest(files["inputs.json"])
        or owner["script_sha256"] != inputs["run_sha256"]
        or inputs["run_sha256"] != v.digest(files["run.py"])
        or terminal["errors"]
        or terminal["interrupted"] is not False
        or terminal["remaining_owned"]
        or cleanup["failed"] is not False
        or state["MainPID"] != "0"
        or state["ControlGroup"]
        or state["InvocationID"] not in ("", owner["invocation_id"])
        or (state["InvocationID"] and state["ExecMainStatus"] != "0")
        or any(int(value) for line in terminal["resources"]["memory.events"].splitlines() for _, value in [line.split()])
    ):
        v.reject("shipping-native-campaign")
    if (flat and (terminal.get("inputs_unchanged") is not True or names != {"three-star-go-upgrade"})) or (not flat and set(terminal["records"]) != names):
        v.reject("shipping-native-inventory")
    records, identities = {}, [owner["identity"]]
    for name in sorted(names):
        location = prefix if flat else prefix + name + "/"
        record, _ = delivery.receipt(files, location)
        process, request = (v.decode(files[location + filename]) for filename in (name + ".process.json", "request.json"))
        if (
            record["argv"] != process["argv"]
            or record["argv"] != request["argv"]
            or process["boot_id"] != boot
            or process["identity"]["parent"] != owner["identity"]["pid"]
            or not flat
            and (
                terminal["records"][name]["record_sha256"] != v.digest(files[location + "record.json"])
                or any(record.get(key) != value for key, value in terminal["records"][name].items() if key in record)
            )
        ):
            v.reject("shipping-native-command", name)
        identities.append(process["identity"])
        records[name] = record
    if flat:
        events = [v.decode(line) for line in files["recovery/events.jsonl"].splitlines()]
        identities += [{"pid": row["pid"], "start_ticks": str(row["started"])} for event in events if event["event"] == "sample" for row in event["processes"]]
        expected = {(row["pid"], str(row["start_ticks"])) for row in identities}
        if len(cleanup["retired"]) != len(expected) or {(row["pid"], str(row["start_ticks"])) for row in cleanup["retired"]} != expected:
            v.reject("shipping-native-retirement")
    elif len(cleanup["retired"]) != len(identities) or {v.encode(row) for row in cleanup["retired"]} != {v.encode(row) for row in identities}:
        v.reject("shipping-native-retirement")
    journal = [v.decode(line) for line in files["journal.native.jsonl"].splitlines()]
    if (
        not journal
        or any(row.get("_BOOT_ID") != boot.replace("-", "") for row in journal)
        or any((row.get("INVOCATION_ID") or row.get("_SYSTEMD_INVOCATION_ID")) != owner["invocation_id"] for row in journal)
        or not any(row.get("_PID") == "1" and row.get("MESSAGE") == unit + ": Deactivated successfully." for row in journal)
    ):
        v.reject("shipping-native-journal")
    # The installer prints its terminal; the fixed system controller records files and relies on the manager's native exit.
    if not flat:
        messages = "\n".join(row.get("MESSAGE", "") for row in journal if row.get("_PID") == str(owner["identity"]["pid"]))
        if terminal not in statements.stream(messages.encode()):
            v.reject("shipping-native-terminal")
    return records


def product(built: Archive, selection: str, name: str, current: dict[str, str]) -> dict:
    """Bind a successful original Go build child independently of its enclosing campaign's outcome."""
    files = built.files
    inputs, worker, result, terminal, cleanup = (
        v.decode(files[path])
        for path in ("inputs.json", selection + "-owner.json", selection + "-result.json", selection + "-terminal.json", "cleanup.native.json")
    )
    if (
        worker["inputs_sha256"] != v.digest(files["inputs.json"])
        or worker["script_sha256"] != inputs["run_sha256"]
        or v.digest(files["run.py"]) != inputs["run_sha256"]
        or terminal["errors"]
        or terminal["interrupted"] is not False
        or terminal["remaining_owned"]
        or inputs["linux_go"] != RENEWED_GO
        or inputs["linux_go_sha256"] != RENEWED_COMPILER
        or cleanup["unit"]["MainPID"] != "0"
        or cleanup["unit"]["ControlGroup"]
        or not any(row["pid"] == worker["identity"]["pid"] and row["start_ticks"] == worker["identity"]["start_ticks"] for row in cleanup["retired"])
    ):
        v.reject("shipping-renewed-build-owner")
    sources(files, "source.tar.gz", inputs["files"])
    sdk = selection.startswith("sdk-")
    # Compare complete inventories in both directions, so deletion cannot reuse an obsolete executable.
    expected, original = (
        (
            {path: sha for path, sha in source.items() if path.startswith("comet/go/") and path.endswith((".go", "go.mod", "go.sum"))}
            if sdk
            else {
                path: sha
                for path, sha in source.items()
                if path in {"go.mod", "go.sum"}
                or path.startswith(("internal/", "polaris/", "astrolabe/"))
                and path.endswith(".go")
                and not path.endswith("_test.go")
            }
        )
        for source in (current, inputs["files"])
    )
    if not expected or original != expected:
        v.reject("shipping-renewed-build-source")
    root = "/home/ubuntu/verdandi/astra/build/results/assurance/go-upgrade-contracts-current-" + ("2" if selection == "sdk-ordinary" else "3")
    prefix = "commands/" if selection == "sdk-ordinary" else "source/build/commands/"
    build_name = selection + ("-binary" if sdk else "-" + name)
    metadata_name = selection + ("-metadata" if sdk else "-" + name + "-metadata")
    item = result["products"][name]
    for label in (build_name, metadata_name):
        location = prefix + label + "/"
        record, output = delivery.receipt(files, location)
        process, request = (v.decode(files[location + filename]) for filename in (label + ".process.json", "request.json"))
        if (
            record["argv"] != process["argv"]
            or record["argv"] != request["argv"]
            or process["identity"]["parent"] != worker["identity"]["pid"]
            or record["executable"] != RENEWED_GO
            or record["executable_sha256"] != RENEWED_COMPILER
            or any(
                record["resolved_environment"].get(key) != value
                for key, value in {
                    "GOPROXY": "off",
                    "GOSUMDB": "off",
                    "GOTOOLCHAIN": "local",
                    "GOWORK": "off",
                    "GOFLAGS": "-mod=readonly",
                    "CGO_ENABLED": "1",
                }.items()
            )
            or not any(row["pid"] == process["identity"]["pid"] and row["start_ticks"] == process["identity"]["start_ticks"] for row in cleanup["retired"])
        ):
            v.reject("shipping-renewed-build-command", label)
        if label == build_name:
            arguments = [RENEWED_GO, "-C", root + "/source" + ("/comet/go" if sdk else "")]
            arguments += ["test", "-c"] + (["-race"] if selection == "sdk-race" else []) if sdk else ["build"]
            arguments += ["-p=2", "-o", root + "/" + name, "." if sdk else "./" + name]
            if record["argv"] != arguments:
                v.reject("shipping-renewed-build-arguments")
        elif record["argv"] != [RENEWED_GO, "version", "-m", root + "/" + name] or output.decode() != item["metadata"]:
            v.reject("shipping-renewed-build-metadata")
    if (
        built.hashes.get(name) != item["sha256"]
        or built.sizes[name] != item["bytes"]
        or not item["metadata"].splitlines()[0].endswith(": go1.27.2")
        or "golang.org/x/net\tv0.60.0\th1:79p50tfZlm0J9YfoDsSi639qSXNGVwEzOPLCxM2FsYU=" not in item["metadata"]
        or ("\tbuild\t-race=true\n" in item["metadata"]) != (selection == "sdk-race")
    ):
        v.reject("shipping-renewed-product")
    delivery.header(built.headers[name])
    return item


def witness(
    observed: Archive, profile: str, installed: dict[str, str], products: dict, current: dict[str, str], boot: str, producer: Archive, probes: dict
) -> dict:
    """Recompute the new finite authority/recovery sequence against the actual installed products."""
    files = observed.files
    inputs = v.decode(files["inputs.json"])
    unit = "astra-go-upgrade-system-functional-" + profile + "-current-1.service"
    records = native(files, "command/", {"three-star-go-upgrade"}, unit=unit, boot=boot, flat=True)
    produced = v.decode(producer.files["inputs.json"])
    if inputs["files"] != produced["files"] or inputs["producer_inputs_sha256"] != v.digest(producer.files["inputs.json"]):
        v.reject("shipping-renewed-system-producer")
    sources(producer.files, "source.tar.gz", inputs["files"])
    runtime = {name: sha for name, sha in inputs["files"].items() if name.startswith("comet/go/") and name.endswith((".go", "go.mod", "go.sum"))}
    runtime.update({name: inputs["files"][name] for name in ("tests/soak.py", "tests/resources.py", "tests/support.py", "tests/test_comet_process.py")})
    if inputs["profile"] != profile or inputs["mode"] != "functional" or any(current.get(name) != sha for name, sha in runtime.items()):
        v.reject("shipping-renewed-system-source")
    for name in ("star", "pulsar", "polaris", "astrolabe"):
        if inputs["products"]["bin/" + name]["sha256"] != installed["bin/" + name]:
            v.reject("shipping-renewed-system-product", name)
    if inputs["products"]["bin/comet-go-system"]["sha256"] != products[profile]["sha256"]:
        v.reject("shipping-renewed-system-sdk")
    events = [v.decode(line) for line in files["recovery/events.jsonl"].splitlines()]
    binaries = {name: installed["bin/" + name] for name in ("star", "pulsar", "polaris", "astrolabe")}
    binaries.update(probes)
    binaries["comet_go"] = products[profile]["sha256"]
    if events[0]["binaries"] != binaries or any(inputs["products"]["bin/" + name]["sha256"] != sha for name, sha in probes.items()):
        v.reject("shipping-renewed-system-bindings")
    authority = [row for row in events if row["event"] == "comet_go_authority"]
    recovered = [row for row in events if row["event"] == "comet_go_recovered"]
    crashed = [row for row in events if row["event"] == "comet_go_authority_crash"]
    restarted = [row for row in events if row["event"] == "comet_go_authority_restart"]
    if (
        events[0]["event"] != "started"
        or events[0]["persistent"] is not True
        or events[0]["comet_go_residence"] is not False
        or events[0]["records"] != 16
        or events[-1]["event"] != "completed"
        or events[-1]["cycles"] != 3
        or [row["phase"] for row in authority] != ["go_authority_" + phase for phase in ("ready", "before", "cached", "deleted", "empty", "restored")]
        or [(row["cycle"], row["star"]) for row in recovered] != [(1, 0), (2, 1), (3, 2)]
        or len({row["sdk_pid"] for row in authority + recovered}) != 1
        or len(crashed) != 1
        or len(restarted) != 1
        or crashed[0]["exit_code"] != -9
        or restarted[0]["previous_pid"] != crashed[0]["pid"]
        or restarted[0]["initialize"] is not False
        or not authority[1]["elapsed"] < crashed[0]["elapsed"] < authority[2]["elapsed"] < restarted[0]["elapsed"] < authority[3]["elapsed"]
    ):
        v.reject("shipping-renewed-system-history")
    sequences = [raw for name, raw in files.items() if name.startswith("command/logs/") and name.endswith("-sequence.log")]
    logs = [raw for name, raw in files.items() if name.startswith("command/logs/") and name.endswith("-comet-go.log")]
    if len(sequences) != 1 or len(logs) != 1:
        v.reject("shipping-renewed-system-logs")
    sequence = delivery.sequence(sequences[0])
    text = logs[0].decode()
    phases = [v.decode(line) for line in logs[0].splitlines() if line.startswith(b"{")]
    if (
        not text.startswith("=== RUN   TestSystemThreeStars\n")
        or not text.endswith("\nPASS\n")
        or text.count("--- PASS: TestSystemThreeStars (") != 1
        or any(marker in text for marker in ("FAIL", "SKIP", "DATA RACE"))
        or [row["event"] for row in phases if row["event"].startswith("go_authority_")] != [row["phase"] for row in authority]
        or [(row["event"], row["cycle"], row["star"]) for row in phases if row["event"].startswith("go_mesh_")]
        != [("go_mesh_" + phase, index, index) for index in range(3) for phase in ("ready", "failover", "recovered")]
        or sequence["cycles"] != 3
        or sequence["records_per_domain"] != 48
    ):
        v.reject("shipping-renewed-system-oracle")
    _, output = delivery.receipt(files, "command/")
    if b"PASS real Almanac persistence and native multi-Star replication, crash, failover, trusted restart, TTL and owned cleanup" not in output:
        v.reject("shipping-renewed-system-completion")
    argv = records["three-star-go-upgrade"]["argv"]
    base = "/home/ubuntu/verdandi/astra/build/results/assurance/go-upgrade-system-functional-" + profile + "-current-1"
    if argv != [
        "/usr/bin/python3",
        "-B",
        "/home/ubuntu/verdandi/astra/build/results/assurance/go-upgrade-contracts-current-3/source/tests/soak.py",
        "--binaries",
        base + "/fixture/bin",
        "--output",
        base + "/recovery",
        "--installed",
        "--comet-go",
        base + "/fixture/bin/comet-go-system",
        "--persistent",
        "--fault-seconds",
        "0",
        "--steady-seconds",
        "0",
        "--interval",
        "0",
        "--records",
        "16",
    ]:
        v.reject("shipping-renewed-system-command")
    clocks = [v.decode(line) for line in files["clock.native.jsonl"].splitlines()]
    if not clocks or any(
        row["return"] or row["modes"] or row["status"] & (64 | 4096) or max(row["maxerror_us"], row["esterror_us"]) >= 500000 for row in clocks
    ):
        v.reject("shipping-renewed-system-clock")
    return {"profile": profile, "sequence": sequence, "authority_phases": len(authority), "star_recoveries": len(recovered), "clock_samples": len(clocks)}


def renewal(root: Path, *, component: str) -> dict:
    """Join the current standard installation with unchanged C++ closure and genuine current Go builds/recovery."""
    loaded = [archive(root / PREFIX / name, pin, builds=index in (1, 2)) for index, (name, pin) in enumerate(RENEWED.items())]
    assembled, built, sdk_build, ordinary, race = loaded
    files = assembled.files
    inputs, owner, manifest = (v.decode(files[name]) for name in ("inputs.json", "controller.json", "candidate-manifest.json"))
    roles = ("star", "planet", "pulsar", "polaris", "astrolabe", "consumer", "comet_process_probe", "comet_mesh_probe")
    names = {"cpp-install", "go-production-graph", "module-verify", "metadata-polaris", "metadata-astrolabe", "consumer-run", "batch-run"}
    names |= {stage + "-" + role.replace("_", "-") for stage in ("loader", "resolved") for role in roles}
    records = native(files, "source/build/commands/", names, unit="astra-go-upgrade-delivery-current-3.service", boot=inputs["preflight"]["boot_id"])
    sources(files, "source.tar.gz", inputs["files"])
    current = {row["path"]: row["sha256"] for row in v.source(root)["files"] if row["sha256"] is not None}
    if (
        len(manifest) != 51
        or manifest != inputs["expected_candidate"]
        or manifest != {name.removeprefix("candidate/"): sha for name, sha in assembled.hashes.items() if name.startswith("candidate/")}
        or any(assembled.hashes.get("fixture/" + name) != sha for name, sha in manifest.items())
        or v.decode(files["result.native.json"])["candidate"] != manifest
        or v.decode(files["terminal.json"])["cache_returned"] is not True
        or v.decode(files["cache-return.native.json"])["inode"] != inputs["cache_repair"]["inode"]
        or v.decode(files["install-manifest-return.native.json"])["restored"] is not True
    ):
        v.reject("shipping-renewed-installation")
    origin = records["cpp-install"]["argv"]
    if origin != [
        "/usr/bin/cmake",
        "--install",
        inputs["cpp_build"],
        "--prefix",
        "/home/ubuntu/verdandi/astra/build/results/assurance/go-upgrade-delivery-current-3/candidate",
    ]:
        v.reject("shipping-renewed-installer")
    original = archive(root / PREFIX / next(iter(ARCHIVES)), ARCHIVES[next(iter(ARCHIVES))])
    inspection_name = list(ARCHIVES)[4]
    inspected = archive(root / PREFIX / inspection_name, ARCHIVES[inspection_name])
    inspection_inputs, checked = inspection(inspected.files)
    old_inputs, old_candidate = candidate(original, checked)
    cpp = closure(original.files, old_inputs, checked, current, old_candidate)
    if cpp != inputs["cpp_input_closure"] or inspection_inputs["expected"] != inputs["physical_expected"]:
        v.reject("shipping-renewed-cpp-closure")
    before = v.decode(files["physical-before.native.json"])
    if any(before.get(path) != sha for path, sha in inputs["physical_expected"].items()):
        v.reject("shipping-renewed-physical-inputs")
    for name, sha in old_candidate.items():
        if name not in {"bin/polaris", "bin/astrolabe"} and not name.startswith("share/astra/licenses/go/") and manifest.get(name) != sha:
            v.reject("shipping-renewed-cpp-products", name)
    inventory = v.decode(files["inventory.native.json"])["files"]
    if set(inventory) != set(manifest):
        v.reject("shipping-renewed-inventory")
    for name, sha in manifest.items():
        path = "candidate/" + name
        if (
            inventory[name] != {"bytes": assembled.sizes[path], "sha256": sha, "executable": bool(assembled.modes[path] & 0o100)}
            or assembled.modes[path] & 0o002
        ):
            v.reject("shipping-renewed-inventory", name)
        if name.startswith("bin/") or name in {"lib/" + runtime for runtime in delivery.RUNTIMES}:
            delivery.header(assembled.headers[path])
        if name.startswith("bin/") and not assembled.modes[path] & 0o100:
            v.reject("shipping-renewed-executable", name)
        if name.endswith(".cmake") and inputs["cpp_root"].encode() in files[path]:
            v.reject("shipping-renewed-export", name)
    for name in ("polaris", "astrolabe"):
        item = product(built, "root-ordinary", name, current)
        _, metadata = delivery.receipt(files, "source/build/commands/metadata-" + name + "/")
        if manifest["bin/" + name] != item["sha256"] or metadata.decode().splitlines()[1:] != item["metadata"].splitlines()[1:]:
            v.reject("shipping-renewed-installed-go")
    notices = v.decode(files["current-go-origins.native.json"])
    if len(inputs["notices"]) != 16 or any("golang.org/x/net@v0.59.0/" in name for name in manifest):
        v.reject("shipping-renewed-notice-inventory")
    for name, item in inputs["notices"].items():
        suffix = name.removeprefix("share/astra/licenses/go/")
        expected_path = (
            RENEWED_GO.removesuffix("bin/go") + suffix.removeprefix("toolchain/")
            if suffix == "toolchain/LICENSE"
            else "/home/ubuntu/verdandi/build/deps/go/pkg/mod/" + suffix
        )
        if (
            not name.startswith("share/astra/licenses/go/")
            or posixpath.dirname(item["path"]) != posixpath.dirname(expected_path)
            or posixpath.basename(item["path"])
            not in {posixpath.basename(expected_path), "License" if expected_path.endswith("/LICENSE") else posixpath.basename(expected_path)}
            or notices.get(name) != item
            or before.get(item["path"]) != manifest.get(name)
            or manifest.get(name) != item["sha256"]
        ):
            v.reject("shipping-renewed-notice-source", name)
    for role in roles:
        label = role.replace("_", "-")
        _, tags = delivery.receipt(files, "source/build/commands/loader-" + label + "/")
        _, text = delivery.receipt(files, "source/build/commands/resolved-" + label + "/")
        cpp_role = role not in {"polaris", "astrolabe"}
        dynamic = delivery.dynamic(tags, cpp=cpp_role)
        executable = origin[-1].removesuffix("/candidate") + "/fixture/bin/" + role
        if records["loader-" + label]["argv"] != ["/usr/bin/readelf", "-d", executable] or records["resolved-" + label]["argv"] != ["/usr/bin/ldd", executable]:
            v.reject("shipping-renewed-loader-command", role)
        if b"not found" in text or any(
            {"LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"} & records[stage + "-" + label]["resolved_environment"].keys() for stage in ("loader", "resolved")
        ):
            v.reject("shipping-renewed-runtime", role)
        if cpp_role and dynamic["needed"]:
            for runtime in delivery.RUNTIMES:
                paths = re.findall(r"^\s*" + re.escape(runtime) + r" => (\S+) \(0x[0-9a-f]+\)$", text.decode(), re.MULTILINE)
                if [posixpath.normpath(path) for path in paths] != [origin[-1].removesuffix("/candidate") + "/fixture/lib/" + runtime]:
                    v.reject("shipping-renewed-runtime-path", role)
    _, output = delivery.receipt(files, "source/build/commands/consumer-run/")
    _, batch = delivery.receipt(files, "source/build/commands/batch-run/")
    assertions = re.findall(rb"^ASTRA-CHECKS (\{[^\n]*\})\r?$", batch, re.MULTILINE)
    if output.strip() != b'ASTRA-DELIVERY {"contract":"DELIVERY-SDK","hits":8}' or len(assertions) != 1 or v.decode(assertions[0])["hits"] <= 0:
        v.reject("shipping-renewed-public-consumer")
    _, graph = delivery.receipt(files, "source/build/commands/go-production-graph/")
    for name in ("go-production-graph", "module-verify", "metadata-polaris", "metadata-astrolabe"):
        record = records[name]
        if (
            record["executable"] != RENEWED_GO
            or record["executable_sha256"] != RENEWED_COMPILER
            or any(
                record["resolved_environment"].get(key) != value
                for key, value in {
                    "GOPROXY": "off",
                    "GOSUMDB": "off",
                    "GOTOOLCHAIN": "local",
                    "GOWORK": "off",
                    "GOFLAGS": "-mod=readonly",
                    "CGO_ENABLED": "1",
                }.items()
            )
        ):
            v.reject("shipping-renewed-go-command", name)
    _, verified = delivery.receipt(files, "source/build/commands/module-verify/")
    if (
        records["go-production-graph"]["argv"] != [RENEWED_GO, "list", "-mod=readonly", "-json", "./..."]
        or records["module-verify"]["argv"] != [RENEWED_GO, "mod", "verify"]
        or verified.strip() != b"all modules verified"
    ):
        v.reject("shipping-renewed-go-graph")
    admission = delivery.consumers(graph, "internal/admission", ("polaris", "astrolabe"))
    storage = delivery.consumers(graph, "polaris/internal/storage", ("polaris",))
    products = {
        "ordinary": product(sdk_build, "sdk-ordinary", "comet-go-system-ordinary", current),
        "race": product(built, "sdk-race", "comet-go-system-race", current),
    }
    probes = {name: assembled.hashes["fixture/bin/" + name] for name in ("comet_process_probe", "comet_mesh_probe")}
    systems = {
        profile: witness(observed, profile, manifest, products, current, owner["boot_id"], built, probes)
        for profile, observed in (("ordinary", ordinary), ("race", race))
    }
    selected = storage if component == "polaris-storage" else admission
    if component not in {"admission", "polaris-storage"}:
        v.reject("shipping-component")
    correction = v.decode(files["collection-2/correction.native.json"])
    if (
        correction["original_failed_collector"]["ExecMainStatus"] != "1"
        or correction["original_archive_sha256"] != "1f35eb6b8cb6a274968bfc554cc161fa73a81d103e5da55553662dc891fe2d92"
    ):
        v.reject("shipping-renewed-collection-failure")
    return {
        "archives": RENEWED | {name: ARCHIVES[name] for name in (next(iter(ARCHIVES)), inspection_name)},
        "platform": "linux-amd64-cgo",
        "trust": "local",
        "source": {
            name: sha
            for name, sha in current.items()
            if name in {"go.mod", "go.sum"}
            or name.startswith(("internal/", "polaris/", "astrolabe/"))
            and name.endswith(".go")
            and not name.endswith("_test.go")
        },
        "consumers": {name: {"sha256": manifest["bin/" + name], "dependencies": dependencies} for name, dependencies in selected["consumers"].items()},
        "sequence": systems["ordinary"]["sequence"],
        "installation": {"candidate": manifest, "cpp": cpp, "systems": systems},
        "retained_failure": {
            "collector_archive_sha256": correction["original_archive_sha256"],
            "collector_exit_code": 1,
            "sdk_build_parent_errors": v.decode(sdk_build.files["terminal.json"])["errors"],
        },
        "qualification": "Current Go 1.27.2/x-net v0.60.0 Linux/CGO installed consumer delivery only; no long-resource, performance, protected CI or release eligibility",
    }


def reconcile(root: Path, *, component: str) -> dict:
    """Join exact current installed source/build identities with both genuine native three-Star consumer profiles."""
    if (root / PREFIX / next(iter(RENEWED))).exists():
        return renewal(root, component=component)
    paths = list(ARCHIVES)
    loaded = {name: archive(root / PREFIX / name, pin) for name, pin in ARCHIVES.items()}
    _, native = inspection(loaded[paths[4]].files)
    inputs, installed = candidate(loaded[paths[0]], native)
    current = {row["path"]: row["sha256"] for row in v.source(root)["files"] if row["sha256"] is not None}
    compiled = closure(loaded[paths[0]].files, inputs, native, current, installed)
    admission, storage = programs(loaded[paths[1]], loaded[paths[5]].files, inputs, native, current, installed)
    products = sdk(loaded[paths[6]], current)
    systems = {profile: system(loaded[name], profile, installed, products, current) for profile, name in (("ordinary", paths[2]), ("race", paths[3]))}
    selected = storage if component == "polaris-storage" else admission
    if component not in {"admission", "polaris-storage"}:
        v.reject("shipping-component")
    bindings = {}
    for name, dependencies in selected["consumers"].items():
        _, tags = delivery.receipt(loaded[paths[0]].files, "command/loader-" + name + "/")
        bindings[name] = {"sha256": installed["bin/" + name], "loader": delivery.dynamic(tags, cpp=False), "dependencies": dependencies}
    return {
        "archives": ARCHIVES,
        "platform": "linux-amd64-cgo",
        "trust": "local",
        "source": inputs["go_production"],
        "consumers": bindings,
        "sequence": systems["ordinary"]["sequence"],
        "installation": {"candidate": installed, "cpp": compiled, "systems": systems},
        "retained_failure": {"archive": paths[1], "errors": ["AssertionError: "], "native_exit_code": 1, "qualified_commands": 4},
        "qualification": f"retained Linux/CGO {component} consumer delivery only; no CI or release eligibility",
    }
