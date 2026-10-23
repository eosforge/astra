"""Authenticate the incremental Server and Polaris consumer facts without transferring old coverage credit."""

import re
from pathlib import Path, PurePosixPath

from tools import delivery, entry, installation, server, verify as v

CURRENT = "storage-idle-consumers-current-1"
# Only these sealed native campaigns establish the current ingress consumer identity.
ARCHIVES = {
    "server-batch-green-current-3": "daedff2ab80e85e5b9f10c0fc940c5be9a785cc65c672bef128db642ebfa29a8",
    "server-batch-consumers-current-1": "03cd832db23c1b4030c996c1b6c2ddc6a9524221ac1d485161b455acb9c11eaa",
    CURRENT: "1e690810520f40a1784eaa6aefabd6330e0c304d1cd766a1dfc4dda3c8516fa6",
}
ARTIFACTS = {"reuse-plan/" + name + "/native/evidence.tar.gz": sha for name, sha in ARCHIVES.items()}
PREFIX = "source/build/commands/"
BOOT = "fcd14352-65a1-438d-bca3-a98551636e54"
COMMANDS = {
    "server-batch-green-current-3": ["polaris-batch-admission", "polaris-server-boundaries", "server-batch-race", "fixed-obligations", "consumer-policy"],
    "server-batch-consumers-current-1": ["exports", "entry-list", "entry-race"],
    CURRENT: ["exports", "entry-list", "entry-race", "server-plain", "server-race"],
}


# Independently received current Entry and Server facts; historical campaigns remain immutable.
LEGACY_ACQUISITION = {"reuse-plan/polaris-consumers-native-current-2/evidence.tar.gz": "2668354a7df4e5ea10002703d2e889b011150d5bc436d70a50779e8f32c708fb"}
ACQUISITION = {
    "reuse-plan/go-upgrade-polaris-consumers-current-1/postboot-collection-2/evidence.tar.gz": "7819e6a2aac94aaccb72dd5e21c61be06637365d766d020c5fab2f15490f2f13"
}
OBSERVED_BOOT = "bd2131fa-75af-458c-9225-8e5c1a16229b"
ORIGINAL_QUERY_SHA = "a8fd16c3510d90ace88d6615680b15b57332869593a6a7bf2d8a7656f8f54bc3"
PREFLIGHT_SHA = "64db7d0bc4cc80ecad5df6d7ec0b485ec5b767351155ba18589b3ed91dc70475"


def acquisition(root: Path) -> dict[str, str]:
    """Bind archive selection to the declared compiler; historical module bytes alone cannot select an old runtime."""
    policy = v.decode(v.read(root / "development.json"))
    check = next((item for item in policy["checks"] if item["id"] == "polaris-entry-qualification"), None)
    path = check.get("environment", {}).get("PATH", "") if check else ""
    if path.count("/go-1.27.2/bin:") == 1 and "/go-1.27.1/" not in path:
        return ACQUISITION
    if (
        path.count("/go-1.27.1/bin:") == 1
        and "/go-1.27.2/" not in path
        and v.file_digest(root / "go.mod") == "032ebbb75ea6b415d4cccea2edd9d43f706e8dfcc9700593c3cd3754f937d3a0"
    ):
        return LEGACY_ACQUISITION
    v.reject("consumers-acquisition-compiler")


def compiler(files: dict[str, bytes]) -> str:
    """Accept only the two reviewed native campaign identities, never caller-chosen compiler versions."""
    roots = {
        "/home/ubuntu/verdandi/astra/build/results/assurance/polaris-consumers-native-current-2": "1.27.1",
        "/home/ubuntu/verdandi/astra/build/results/assurance/go-upgrade-polaris-consumers-current-1": "1.27.2",
    }
    root = v.decode(files["inputs.json"])["native_root"]
    if root not in roots:
        v.reject("consumers-acquisition-source")
    return roots[root]


def protocol_document(before: bytes, after: bytes) -> None:
    """Require identical Admission/Polaris clauses; the explicitly deferred directory candidate supplies no current contract credit."""
    start, end = b"## Admission Identity\n", b"\n## Internal Sessions and Source Synchronization"
    candidate, following = b'<a id="directory-revision-candidate"></a>', b"### Polaris and Astrolabe Management Admission"

    def section(data: bytes) -> bytes:
        """Extract the uniquely delimited protocol section or reject an ambiguous document."""
        if data.count(start) != 1 or data.count(end) != 1:
            v.reject("consumers-protocol-document-section")
        return data.split(start, 1)[1].split(end, 1)[0]

    old, new = section(before), section(after)
    if candidate not in old and candidate in new:
        if new.count(candidate) != 1 or new.count(following) != 1:
            v.reject("consumers-protocol-document-candidate")
        left, tail = new.split(candidate, 1)
        proposed, right = tail.split(following, 1)
        if b"This is a future query-cost candidate, not the current List contract." not in proposed:
            v.reject("consumers-protocol-document-candidate")
        new = left + following + right
    if old != new:
        v.reject("consumers-protocol-document-contract")


def rebinding(
    root: Path, previous: dict[str, bytes | str], directories: set[str], *, reviewed: dict[str, str] | None = None, extra: set[str] | None = None
) -> tuple[dict[str, bytes], dict]:
    """Bind linked consumer inputs through the fixed current compiler acquisition, keeping historical executions separate."""
    from tools import storagecompiler

    expected = acquisition(root)
    if expected != ACQUISITION:
        v.reject("consumers-rebinding-compiler")
    name, sha = next(iter(expected.items()))
    raw = v.read(root / "build/results/assurance" / name, 32 * 1024**2)
    current, _, outputs = acquired(unpack(raw, sha))
    snapshot = {row["path"]: row["sha256"] for row in v.source(root)["files"] if row["sha256"] is not None}
    module_go = lambda paths: {name for name in paths if name.endswith(".go") and not name.startswith("comet/go/")}
    if module_go(snapshot) != module_go(current):
        v.reject("consumers-rebinding-inventory")
    package = "polaris/internal/storage/"
    if reviewed is None:
        names = {name for name in previous if name.startswith(package) and name.endswith(".go")} | {"go.mod", "go.sum"}
        reviewed = storagecompiler.review(root, previous, names)
    owned = lambda paths: {name for name in paths if name.endswith(".go") and PurePosixPath(name).parent.as_posix() in directories}
    before, after = owned(previous), owned(current)
    if before - after or any(reviewed.get(name) != v.digest(current[name]) for name in after - before):
        v.reject("consumers-rebinding-additions")
    boundary = lambda paths: {name for name in paths if name.startswith(("proto/", "internal/generated/"))}
    if boundary(previous) != boundary(current) or boundary(snapshot) != boundary(current):
        v.reject("consumers-rebinding-protocol")
    selected = after | boundary(current) | {"go.mod", "go.sum", "dependencies.lock.json", "tools/decisions/runtime.go.in", "tests/fixtures/storage.tests.json"}
    selected |= extra or set()
    bindings, documents = {}, []
    for name in sorted(selected):
        body = current[name]
        if name == "proto/README.md":
            live = v.read(v.inside(root, name))
            original = previous[name] if isinstance(previous[name], bytes) else None
            if original is not None:
                protocol_document(original, live)
            protocol_document(body, live)
            if snapshot.get(name) != v.digest(live):
                v.reject("consumers-rebinding-source", name)
            bindings[name] = v.digest(live)
            documents.append(
                {
                    "path": name,
                    "source_sha256": v.digest(body),
                    "current_sha256": v.digest(live),
                    "scope": "Admission and Polaris clauses only; business protocol and candidate designs are not evaluated",
                }
            )
            continue
        if name == "proto/README_CN.md":
            live = v.read(v.inside(root, name))
            if snapshot.get(name) != v.digest(live):
                v.reject("consumers-rebinding-source", name)
            bindings[name] = v.digest(live)
            documents.append(
                {
                    "path": name,
                    "source_sha256": v.digest(body),
                    "current_sha256": v.digest(live),
                    "scope": "Translation is not a compiled consumer input and receives no contract qualification",
                }
            )
            continue
        prior_sha = previous[name] if name in previous and isinstance(previous[name], str) else v.digest(previous[name]) if name in previous else None
        if name in previous and prior_sha != v.digest(body) and reviewed.get(name) != v.digest(body):
            v.reject("consumers-rebinding-delta", name)
        if snapshot.get(name) != v.digest(body) or v.read(v.inside(root, name)) != body:
            v.reject("consumers-rebinding-source", name)
        bindings[name] = v.digest(body)
    return current, {
        "archive_sha256": sha,
        "bindings": bindings,
        "documents": documents,
        "compiler_graph": outputs["entry/entry-typed-exports"],
        "boundary": "Current compiler-bound linked input association only. The independent nested Comet Go module receives no qualification here. Original semantic profiles keep their original runtime identities.",
    }


def recipes(root: str, *, upgraded: bool = False) -> list[dict]:
    """Derive the fixed current Entry/Server compiler commands independently of native declarations."""
    go = "/home/ubuntu/verdandi/build/tools/go-" + ("1.27.2" if upgraded else "1.27.1") + "/bin/go"
    commands = []
    for consumer, package in (("entry", "polaris"), ("server", "polaris/internal/server")):
        directory = root + "/build/commands/" + consumer
        exports = (
            root + "/build/commands/entry-typed-exports/entry-typed-exports.stdout.log"
            if consumer == "entry"
            else directory + "/typed/exports/exports.stdout.log"
        )
        selected = [("typed/exports", ["list", "-deps", "-export", "-json", "./" + package], 180)]
        for kind in ("typed", "control"):
            arguments = [
                "run",
                "-p=2",
                "./tools/decisions",
                "-root",
                root,
                "-source",
                directory + "/source.json",
                "-trace",
                package,
                "-output",
                directory + "/" + kind + "/overlay",
            ]
            arguments += ["-export", exports] if kind == "typed" else ["-controls"]
            selected.append((kind + "/collector", arguments, 180))
        for kind in ("typed", "control"):
            overlay = directory + "/" + kind + ("/overlay" if consumer == "entry" else "/active") + "/overlay.json"
            selected.append((kind + "/packages", ["list", "-json", "-overlay=" + overlay, "./" + package], 60))
        test = ["test", "-json", "-count=1", "-p=2", "-parallel=1", "-timeout=180s"]
        if consumer == "server":
            selected.append(
                (
                    "coverage",
                    test
                    + [
                        "-covermode=atomic",
                        "-coverprofile=" + directory + "/coverage.profile",
                        "-overlay=" + directory + "/fixtures/overlay.json",
                        "./" + package,
                    ],
                    240,
                )
            )
        for kind in ("typed", "control"):
            overlay = directory + "/" + kind + ("/overlay" if consumer == "entry" else "/active") + "/overlay.json"
            selected.append((kind + "/tests", test + ["-overlay=" + overlay, "./" + package], 240))
        if consumer == "entry":
            selected.append(
                (
                    "race",
                    [
                        "test",
                        "-json",
                        "-race",
                        "-count=1",
                        "-p=2",
                        "-parallel=1",
                        "-timeout=180s",
                        "-covermode=atomic",
                        "-coverprofile=" + root + "/build/commands/entry-race/coverage.out",
                        "./polaris",
                    ],
                    240,
                )
            )
        else:
            for profile in ("baseline", "race"):
                arguments = (
                    test
                    + (["-race"] if profile == "race" else [])
                    + ["-overlay=" + directory + "/fixtures/overlay.json", "-run=^TestPredicates$", "./" + package]
                )
                selected.append(("authority/" + profile, arguments, 180))
        for name, arguments, timeout in selected:
            identifier = "entry-" + name.replace("/", "-") if consumer == "entry" else name
            stage = "build/commands/" + (identifier if consumer == "entry" else "server/" + name)
            commands.append(
                {
                    "id": consumer + "/" + identifier,
                    "consumer": consumer,
                    "name": identifier,
                    "stage": stage,
                    "argv": [go, *arguments],
                    "timeout_s": timeout,
                    "expected_exit_code": 0,
                }
            )
    return commands


def postboot(files: dict[str, bytes], owner: dict, cleanup: dict, terminal: dict) -> None:
    """Bind ended-boot identities to the original retired-owner query and persistent terminal journal."""
    if (
        cleanup.get("observed_boot_id") != OBSERVED_BOOT
        or cleanup["observed_boot_id"] == BOOT
        or cleanup.get("original_query_sha256") != ORIGINAL_QUERY_SHA
        or cleanup.get("observed_unit", {}).get("MainPID") != "0"
        or cleanup["observed_unit"].get("ControlGroup")
        or cleanup["observed_unit"].get("InvocationID") not in ("", owner["invocation_id"])
    ):
        v.reject("consumers-postboot-lifetime")
    if v.digest(files["postboot/original-query6.json"]) != ORIGINAL_QUERY_SHA or v.digest(files["postboot/preflight.json"]) != PREFLIGHT_SHA:
        v.reject("consumers-postboot-proof")
    prior = v.decode(files["postboot/original-query6.json"])
    preflight = v.decode(files["postboot/preflight.json"])
    if (
        prior["owner"] != owner
        or prior["terminal"] != terminal
        or prior["state"] != cleanup["unit"]
        or prior["state"]["Result"] != "success"
        or prior["state"]["ExecMainStatus"] != "0"
        or len(prior["records"]) != 19
        or any(row["exit_code"] != 0 or not row["complete"] or not row["cleanup"] or row["termination"] != "exited" for row in prior["records"])
        or preflight["boot_id"] != OBSERVED_BOOT
        or preflight["prior_evidence"]["collection-dispatch.native.json"] != v.decode(files["collection-dispatch.native.json"])
        or preflight["prior_evidence"]["collector-owner.native.json"] != v.decode(files["collector-owner.native.json"])
        or preflight["prior_evidence"]["collection-dispatch.native.json"]["exit_code"] != 1
    ):
        v.reject("consumers-postboot-proof")


def acquired(files: dict[str, bytes]) -> tuple[dict[str, bytes], dict, dict]:
    """Verify the current reserved-controller acquisition, preserving every original command and stream."""
    inputs, owner, cleanup, terminal = (v.decode(files[name]) for name in ("inputs.json", "owner.json", "cleanup.native.json", "terminal.json"))
    version = compiler(files)
    upgraded = version == "1.27.2"
    base = inputs["native_root"]
    root = base + "/source"
    unit = "astra-" + base.rsplit("/", 1)[1] + ".service"
    source = entry.unpack(files["source.tar.gz"])
    hashes = {name: v.digest(data) for name, data in source.items()}
    before = v.decode(files["source.native.before.json"])
    if (
        inputs["native_root"] != base
        or inputs["files"] != hashes
        or len(hashes) != (1068 if upgraded else 1066)
        or v.digest(files["source.tar.gz"]) != inputs["source_archive_sha256"]
        or hashes != {row["path"]: row["sha256"] for row in inputs["source"]["files"] if row["sha256"] is not None}
        or {row["path"] for row in inputs["source"]["files"] if row["sha256"] is None} != {"astrolabe/src/main.cpp"}
        or before["commit"] is not None
        or hashes != {row["path"]: row["sha256"] for row in before["files"]}
        or files["source.native.before.json"] != files["source.native.after.json"]
        or files["git.native.HEAD"] != b"ref: refs/heads/fixture\n"
        or b"[remote " in files["git.native.config"]
        or owner["cwd"] != base
        or owner["argv"] != ["/usr/bin/python3", "-B", base + "/run.py"]
        or owner["boot_id"] != BOOT
        or owner["inputs_sha256"] != v.digest(files["inputs.json"])
        or owner["script_sha256"] != inputs["driver_sha256"]
        or inputs["driver_sha256"] != v.digest(files["run.py"])
        or inputs["enter_sha256"] != v.digest(files["enter.py"])
    ):
        v.reject("consumers-acquisition-source")
    if (
        terminal["errors"]
        or terminal["interrupted"] is not False
        or terminal["remaining_owned"]
        or terminal["inputs_unchanged"] is not True
        or terminal["cache_returned"] is not True
        or cleanup["original_failed"] is not False
        or cleanup["remaining_owned"]
        or cleanup["cache_returned"] is not True
        or cleanup["boot_id"] != owner["boot_id"]
        or cleanup["original_invocation_id"] != owner["invocation_id"]
        or cleanup["unit"]["MainPID"] != "0"
        or cleanup["unit"]["ControlGroup"]
        or cleanup["unit"]["InvocationID"] not in ("", owner["invocation_id"])
    ):
        v.reject("consumers-acquisition-lifecycle")
    journal = v.decode(files["journal.native.json"])
    messages = [row.get("MESSAGE", "") for row in journal]
    if (
        not journal
        or any(
            row.get("_BOOT_ID") != BOOT.replace("-", "") or (row.get("INVOCATION_ID") or row.get("_SYSTEMD_INVOCATION_ID")) != owner["invocation_id"]
            for row in journal
        )
        or sum(message.startswith("Started " + unit + " - ") for message in messages) != 1
        or messages.count(unit + ": Deactivated successfully.") != 1
        or [v.decode(message.encode()) for message in messages if message.startswith('{"at":')] != [terminal]
    ):
        v.reject("consumers-acquisition-journal")
    if upgraded:
        postboot(files, owner, cleanup, terminal)
    returned, handed = (v.decode(files[name]) for name in ("cache-return.json", "cache-handoff.json"))
    donor = (
        "/home/ubuntu/verdandi/astra/build/cache/go"
        if upgraded
        else "/home/ubuntu/verdandi/astra/build/results/assurance/storage-retention-pairs-current-1/source/build/cache/go"
    )
    inode = 660744 if upgraded else 713912
    if returned != {"path": donor, "inode": inode, "device": 64512, "remaining_owned": []} or handed != {
        "from": donor,
        "to": root + "/build/cache/go",
        "inode": inode,
        "device": 64512,
    }:
        v.reject("consumers-acquisition-cache")
    dependencies = v.decode(files["dependencies.before.json"])
    modules = {
        "/home/ubuntu/verdandi/build/deps/go/pkg/mod/" + fields[0] + "@" + fields[1]
        for line in source["go.mod"].decode().splitlines()
        if len(fields := line.split()) >= 2 and fields[1].startswith("v")
    }
    tools = "/home/ubuntu/verdandi/build/tools/"
    if (
        files["dependencies.before.json"] != files["dependencies.after.json"]
        or set(dependencies) != modules | {tools + "go-" + version, tools + "gcc-16.2.0"}
        or set(dependencies) != set(inputs["dependency_roots"])
        or len(modules) != 11
        or any(not tree for tree in dependencies.values())
    ):
        v.reject("consumers-acquisition-dependencies")
    for tree, name, digest in (
        (
            "go-" + version,
            "bin/go",
            (
                "548d3c32f83fa81152f543eb1526be7884cfe0526eb5e9ce29d3eca14786e7e0"
                if upgraded
                else "30969f97169d7f43fe6a085873d75613adc21e30818a8c61d95bd27275df4624"
            ),
        ),
        ("gcc-16.2.0", "bin/gcc", "5ba72afdc29ac57b805ee21e48babe16b31385c03caf91fdd4336483c5a84195"),
        ("gcc-16.2.0", "bin/g++", "1d90c88f14873d7a56f015f31ebe1b72a24942fe379d63eac35d18c1d22970f1"),
    ):
        if dependencies[tools + tree][name] != digest:
            v.reject("consumers-acquisition-toolchain", name)

    if upgraded:
        manifests = {
            "expected-dependencies.json": "32c89b142e695c8a36c6628279696614b788f3a3108a5fb2aa58c0da9c9aa855",
            "installed-go.json": "96b97559474c1ad6421c0c776f4671a0e114e6252fb11cb0cf8d44198c243ce2",
        }
        if any(name not in files or v.digest(files[name]) != digest for name, digest in manifests.items()) or dependencies != v.decode(
            files["expected-dependencies.json"]
        ):
            v.reject("consumers-acquisition-dependency-manifest")

    def counters(text: str) -> dict[str, int]:
        """Interpret the complete recorded native cgroup counters."""
        return {key: int(value) for key, value in (row.split() for row in text.splitlines())}

    def resources(before: dict, after: dict, limits: dict[str, str]) -> None:
        """Require unchanged hard limits and no native admission/kill events."""
        if (
            any(before.get(name) != value or after.get(name) != value for name, value in limits.items())
            or any(counters(after["memory.events"]).values())
            or counters(after["pids.events"])["max"]
        ):
            v.reject("consumers-acquisition-resources")

    resources(
        owner["whole_limits"],
        terminal["whole_resources"],
        {"memory.high": "1879048192", "memory.max": "2147483648", "memory.swap.max": "0", "cpu.max": "300000 100000", "pids.max": "2048"},
    )
    resources(
        owner["controller_limits"],
        terminal["controller_resources"],
        {"memory.high": "402653184", "memory.max": "469762048", "memory.swap.max": "0", "cpu.max": "100000 100000", "pids.max": "32"},
    )
    expected = recipes(root, upgraded=upgraded)
    if inputs["commands"] != expected or inputs["variant_files"] or len(expected) != 18:
        v.reject("consumers-acquisition-recipes")
    prefix = "commands/"
    setup = v.decode(files[prefix + "git-init/record.json"])
    setup_process = v.decode(files[prefix + "git-init/git-init.process.json"])
    if (
        setup["argv"] != ["/usr/bin/git", "-c", "init.templateDir=", "-c", "init.defaultBranch=fixture", "init", "--quiet", root]
        or setup["executable_sha256"] != inputs["git_sha256"]
        or setup["exit_code"] != 0
        or not setup["complete"]
        or not setup["cleanup"]
    ):
        v.reject("consumers-acquisition-git")
    records, outputs, identities = {}, {}, [owner["identity"], setup_process["identity"]]
    stages = {"commands/git-init/record.json"} | {item["stage"].removeprefix("build/") + "/record.json" for item in expected}
    if {name for name in files if name.endswith("/record.json")} != stages:
        v.reject("consumers-acquisition-command-inventory")
    summaries = []
    environment = {
        "PATH": tools + "go-" + version + "/bin:" + tools + "gcc-16.2.0/bin:/usr/bin:/bin",
        "CGO_ENABLED": "1",
        "CC": tools + "gcc-16.2.0/bin/gcc",
        "CXX": tools + "gcc-16.2.0/bin/g++",
        "LD_LIBRARY_PATH": tools + "gcc-16.2.0/lib64",
        "GOCACHE": root + "/build/cache/go",
        "GOMODCACHE": "/home/ubuntu/verdandi/build/deps/go/pkg/mod",
        "GOPATH": "/home/ubuntu/verdandi/build/deps/go",
        "GOMAXPROCS": "2",
        "ASTRA_CACHE_ROOT": "/home/ubuntu/verdandi/build",
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOTOOLCHAIN": "local",
        "GOWORK": "off",
        "GOFLAGS": "-mod=readonly",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for command in expected:
        active = command["stage"].removeprefix("build/") + "/"
        identifier = PurePosixPath(command["stage"]).name
        record, request, process, execution, before, after = (
            v.decode(files[active + name])
            for name in ("record.json", "request.json", identifier + ".process.json", "exec.native.json", "leaf.before.json", "leaf.after.json")
        )
        v.schema(record, "evidence", ("properties", "checks", "items"))
        leaf = owner["group"] + "/" + command["id"].replace("/", "-")
        argv = ["/usr/bin/python3", "-B", base + "/enter.py", "--enter", leaf, "--", *command["argv"]]
        requested = environment | {"TMPDIR": root + "/" + command["stage"] + "/tmp"}
        if (
            request != {"id": identifier, "argv": argv, "environment": requested, "timeout_s": command["timeout_s"], "log_bytes": 32 * 1024**2}
            or record["id"] != identifier
            or record["argv"] != argv
            or process["argv"] != argv
            or record["environment"] != requested
            or record["resolved_environment"] != requested | {"HOME": "/home/ubuntu", "LANG": "C.UTF-8"}
        ):
            v.reject("consumers-acquisition-command", command["id"])
        if (
            record["exit_code"] != 0
            or not record["complete"]
            or not record["cleanup"]
            or record["termination"] != "exited"
            or record["platform"] != "linux-amd64-cgo"
            or record["duration_ms"] > command["timeout_s"] * 1000
            or v.stamp(record["finished_at"]) < v.stamp(record["started_at"])
        ):
            v.reject("consumers-acquisition-completion", command["id"])
        if (
            process["cwd"] != root
            or process["boot_id"] != BOOT
            or process["identity"]["parent"] != owner["identity"]["pid"]
            or record["executable_sha256"] != "52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41"
        ):
            v.reject("consumers-acquisition-owner", command["id"])
        if execution["declared_argv"] != command["argv"] or len(execution["observed"]) != 1:
            v.reject("consumers-acquisition-exec", command["id"])
        actual = execution["observed"][0]
        if (
            actual["argv"] != command["argv"]
            or actual["executable"] != command["argv"][0]
            or actual["cgroup"] != leaf
            or any(actual["identity"][name] != process["identity"][name] for name in ("pid", "start_ticks", "parent", "session"))
        ):
            v.reject("consumers-acquisition-exec", command["id"])
        resources(
            before, after, {"memory.high": "1342177280", "memory.max": "1610612736", "memory.swap.max": "0", "cpu.max": "200000 100000", "pids.max": "256"}
        )
        if after["cgroup.procs"] or counters(after["cgroup.events"])["populated"]:
            v.reject("consumers-acquisition-drain", command["id"])
        stdout = b""
        for channel in ("stdout", "stderr"):
            item = record[channel]
            if item["path"] != identifier + "." + channel + ".log":
                v.reject("consumers-acquisition-stream-path", command["id"])
            data = files[active + item["path"]]
            if len(data) != item["bytes"] or len(data) > request["log_bytes"] or v.digest(data) != item["sha256"]:
                v.reject("consumers-acquisition-stream", command["id"])
            if channel == "stdout":
                stdout = data
        records[command["id"]], outputs[command["id"]] = record, stdout
        identities.append(process["identity"])
        summaries.append({"id": command["id"], **{name: record[name] for name in ("exit_code", "complete", "cleanup", "termination", "duration_ms")}})
    retired = cleanup["retired"]
    if (
        terminal["records"] != summaries
        or len(retired) != len(identities)
        or any(sum(row["identity"] == identity for row in retired) != 1 for identity in identities)
        or (
            any(row != {"identity": row["identity"], "status": "boot-ended", "original_boot_id": BOOT, "observed_boot_id": OBSERVED_BOOT} for row in retired)
            if upgraded
            else any(row["status"] not in {"absent", "reused"} or row["current_start_ticks"] == row["identity"]["start_ticks"] for row in retired)
        )
    ):
        v.reject("consumers-acquisition-retirement")
    return source, records, outputs


def native(
    files: dict[str, bytes], name: str, *, commands: tuple[str, ...] | None = None, prefix: str = PREFIX, collected: bool = False
) -> tuple[dict[str, bytes], dict, dict]:
    """Verify the immutable dirty source, native completion, command owners and the returned sole cache."""
    inputs, owner, cleanup, terminal = (v.decode(files[key]) for key in ("inputs.json", "controller.json", "cleanup.native.json", "terminal.json"))
    source = entry.unpack(files["source.tar.gz"])
    hashes = {path: v.digest(data) for path, data in source.items()}
    mirror = v.decode(files["git-mirror.native.json"])
    state = cleanup["unit"]
    modern = collected or name == CURRENT
    if collected and name in ARCHIVES and name != CURRENT:
        v.reject("consumers-collector-format", name)
    if (
        owner["boot_id"] != BOOT
        or inputs["boot_id"] != BOOT
        or cleanup["boot_id"] != BOOT
        or owner["cwd"] != "/home/ubuntu/verdandi/astra/build/results/assurance/" + name
        or owner["argv"] != ["/usr/bin/python3", "-B", owner["cwd"] + "/run.py"]
        or owner["inputs_sha256"] != v.digest(files["inputs.json"])
        or owner["script_sha256"] != inputs["run_sha256"]
        or inputs["run_sha256"] != v.digest(files["run.py"])
        or inputs["source_archive_sha256"] != v.digest(files["source.tar.gz"])
        or hashes != inputs["files"]
        or {row["path"]: row["sha256"] for row in inputs["source"]["files"] if row["sha256"] is not None} != hashes
        or mirror["origin_source"] != inputs["source"]
        or mirror["source"]["commit"] is not None
        or {row["path"]: row["sha256"] for row in mirror["source"]["files"]} != hashes
        or terminal["errors"]
        or terminal["interrupted"] is not False
        or terminal["remaining_owned"]
        or state["MainPID"] != "0"
        or state["ControlGroup"]
        or state["InvocationID"] not in ("", owner["invocation_id"])
        or (state["InvocationID"] and state["ExecMainStatus"] != "0")
        or cleanup["original_exit_code"] != 0
        or cleanup["source_verified"] != len(source)
        or cleanup["cache_inode"] != 713912
    ):
        v.reject("consumers-native-lifecycle", name)
    if name == "server-batch-green-current-3":
        returned = v.decode(files["cache-return.native.json"])
        if returned["boot_id"] != BOOT or returned["inode"] != 713912 or returned["owner"] != owner["identity"] or returned["remaining_owned"]:
            v.reject("consumers-cache-return")
    elif modern:
        returned = v.decode(files["cache-return.native.json"])
        handed = v.decode(files["cache-handoff.native.json"])
        donor = "/home/ubuntu/verdandi/astra/build/results/assurance/storage-retention-pairs-current-1/source/build/cache/go"
        if (
            set(terminal) != {"at", "errors", "interrupted", "remaining_owned"}
            or inputs.get("capture_scope", {}).get("excluded") != ["comet/go"]
            or any(path == "comet/go" or path.startswith("comet/go/") for path in source)
            or handed != {"owner": owner, "from": donor, "to": owner["cwd"] + "/source/build/cache/go", "device": 64512, "inode": 713912}
            or returned != {"owner": owner, "path": donor, "device": 64512, "inode": 713912, "remaining_owned": []}
        ):
            v.reject("consumers-cache-return")
    elif terminal["cache_restored"] is not True:
        v.reject("consumers-cache-return")
    journal = [v.decode(row) for row in files["journal.native.jsonl"].splitlines()]
    unit = "astra-" + name + ".service"
    if (
        not journal
        or any(
            row.get("_BOOT_ID") != BOOT.replace("-", "") or (row.get("INVOCATION_ID") or row.get("_SYSTEMD_INVOCATION_ID")) != owner["invocation_id"]
            for row in journal
        )
        or sum(row.get("MESSAGE", "").startswith("Started " + unit + " - ") for row in journal) != 1
        or sum(row.get("MESSAGE") == unit + ": Deactivated successfully." for row in journal) != 1
        or [v.decode(row["MESSAGE"]) for row in journal if row.get("MESSAGE", "").startswith('{"at":')] != [terminal]
    ):
        v.reject("consumers-native-journal", name)
    selections = inputs["selections"] + inputs["auxiliary"]
    selected = list(commands) if commands is not None else COMMANDS[name]
    if (
        not selected
        or len(set(selected)) != len(selected)
        or [item["id"] for item in selections] != selected
        or {path for path in files if path.endswith("/record.json")} != {prefix + item + "/record.json" for item in selected}
    ):
        v.reject("consumers-native-selection", name)
    records, outputs, identities = {}, {}, [owner["identity"]]
    for selection in selections:
        key = selection["id"]
        active = prefix + key + "/"
        record, output = delivery.receipt(files, active)
        process = v.decode(files[active + key.rsplit("/", 1)[-1] + ".process.json"])
        argv = [value.replace("{run}", owner["cwd"] + "/" + active.removesuffix("/")) for value in selection["argv"]]
        # The Server campaign freezes plans in inputs.json; the later consumer campaign also emits per-command plans.
        if not modern and (name == "server-batch-consumers-current-1" or commands is not None) and v.decode(files[active + "plan.json"])["argv"] != argv:
            v.reject("consumers-command-plan", key)
        if (
            record["argv"] != argv
            or process["argv"] != argv
            or process["boot_id"] != BOOT
            or process["cwd"] != owner["cwd"] + "/source"
            or process["identity"]["parent"] != owner["identity"]["pid"]
            or process["identity"] not in cleanup["retired"]
        ):
            v.reject("consumers-command-owner", key)
        go = argv[0] == "go"
        expected = (
            "30969f97169d7f43fe6a085873d75613adc21e30818a8c61d95bd27275df4624" if go else "52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41"
        )
        if record["executable_sha256"] != expected or record["toolchain"]["command"]["sha256"] != expected:
            v.reject("consumers-native-toolchain", key)
        if go:
            for tool, sha in {
                "CC": "5ba72afdc29ac57b805ee21e48babe16b31385c03caf91fdd4336483c5a84195",
                "CXX": "1d90c88f14873d7a56f015f31ebe1b72a24942fe379d63eac35d18c1d22970f1",
            }.items():
                if record["toolchain"][tool]["sha256"] != sha:
                    v.reject("consumers-native-toolchain", tool)
            # This pinned Linux/amd64 Go executable supplies host defaults in the earlier campaign's controlled environment.
            # The later campaign records explicit target overrides; neither archive may silently gain a different override.
            target = {"GOOS": None, "GOARCH": None} if modern or name == "server-batch-green-current-3" else {"GOOS": "linux", "GOARCH": "amd64"}
            for variable, value in {
                **target,
                "CGO_ENABLED": "1",
                "GOPROXY": "off",
                "GOSUMDB": "off",
                "GOTOOLCHAIN": "local",
                "GOWORK": "off",
                "GOFLAGS": "-mod=readonly",
                "GOMAXPROCS": "4",
            }.items():
                if record["resolved_environment"].get(variable) != value:
                    v.reject("consumers-native-environment", variable)
        if modern and go:
            from tools import sensitivity

            # This collector freezes complete command plans in inputs.json before execution.
            sensitivity.command(files, active, selection, owner)
        elif modern:
            environment = {"HOME": "/home/ubuntu", "LANG": "C.UTF-8", "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin"}
            environment.update(
                {
                    key: value.replace("{root}", owner["cwd"] + "/source")
                    .replace("{cache}", "/home/ubuntu/verdandi/build")
                    .replace("{run}", owner["cwd"] + "/" + active.rstrip("/"))
                    for key, value in selection["environment"].items()
                }
            )
            environment.update({"GOFLAGS": "-mod=readonly", "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOWORK": "off"})
            if (
                record["id"] != key
                or record["environment"] != selection["environment"]
                or record["resolved_environment"] != environment
                or record["platform"] != "linux-amd64-cgo"
                or record["duration_ms"] > selection["timeout_s"] * 1000
                or record["toolchain"] != {"command": {"path": "/usr/bin/python3", "sha256": expected}}
            ):
                v.reject("consumers-collected-environment", key)
        records[key], outputs[key] = record, output
        identities.append(process["identity"])
    if len(cleanup["retired"]) != len(identities) or any(cleanup["retired"].count(identity) != 1 for identity in identities):
        v.reject("consumers-native-retirement", name)
    return source, records, outputs


def unpack(raw: bytes, expected: str) -> dict[str, bytes]:
    """Authenticate the current collector's manifested archive before applying its separate lifecycle reader."""
    if v.digest(raw) != expected:
        v.reject("consumers-archive-integrity")
    files = entry.unpack(raw)
    manifest = v.decode(files["manifest.json"])
    if manifest["trust"] != "local" or manifest["files"] != {
        path: {"bytes": len(data), "sha256": v.digest(data)} for path, data in files.items() if path != "manifest.json"
    }:
        v.reject("consumers-archive-manifest")
    return files


def load(artifacts: dict[str, bytes], name: str) -> tuple[dict[str, bytes], dict[str, bytes], dict, dict]:
    """Require the exact native archive and every complete manifested member before interpretation."""
    files = unpack(artifacts["reuse-plan/" + name + "/native/evidence.tar.gz"], ARCHIVES[name])
    return files, *native(files, name)


def cases(data: bytes, package: str, expected: list[str]) -> list[str]:
    """Match every run and successful terminal to the independent full inventory, including nested cases."""
    events = [v.decode(row) for row in data.splitlines()]
    ran = sorted(row["Test"] for row in events if row.get("Action") == "run" and "Test" in row)
    passed = sorted(row["Test"] for row in events if row.get("Action") == "pass" and "Test" in row)
    if (
        not expected
        or len(expected) != len(set(expected))
        or ran != sorted(expected)
        or passed != sorted(expected)
        or any(row.get("Package") != package or row.get("Action") in ("fail", "skip") for row in events)
        or sum(row.get("Action") == "pass" and "Test" not in row for row in events) != 1
    ):
        v.reject("consumers-current-test-inventory", package)
    return sorted(case for case in passed if "/" not in case)


def refresh(artifacts: dict[str, bytes], previous: dict[str, bytes], baseline: dict[str, bytes], results: dict) -> tuple[dict[str, bytes], dict, bytes]:
    """Join actual current regressions with unchanged discovery; no old profile certifies repaired Server bytes."""
    _, current, records, outputs = load(artifacts, "server-batch-green-current-3")
    files, latest, entry_records, entry_outputs = load(artifacts, "server-batch-consumers-current-1")
    relevant = lambda source: {
        path: data
        for path, data in source.items()
        if path.endswith(".go")
        or path.startswith("proto/")
        or path in {"go.mod", "go.sum", "dependencies.lock.json", "tools/decisions/runtime.go.in", "tests/fixtures/storage.tests.json"}
    }
    old, new = relevant(previous), relevant(current)
    if (
        relevant(latest) != new
        or set(old) != set(new)
        or {path for path in old if old[path] != new[path]} != {installation.PATH}
        or v.digest(old[installation.PATH]) != installation.ORIGINAL
        or v.digest(new[installation.PATH]) != installation.SOURCE
    ):
        v.reject("consumers-current-source-delta")
    full = v.decode(current["tests/fixtures/server.tests.json"])
    package = "github.com/eosforge/astra/polaris/internal/server"
    server_cases = []
    for name, race in (("polaris-server-boundaries", False), ("server-batch-race", True)):
        if records[name]["argv"] != [
            "go",
            "test",
            "-json",
            *(["-race"] if race else []),
            "-count=1",
            "-p=2",
            "-parallel=1",
            "-timeout=180s",
            "./polaris/internal/server",
        ]:
            v.reject("consumers-server-command", name)
        server_cases = cases(outputs[name], package, full)
        if server_cases != results["server"]["expected"] or len(full) != 300:
            v.reject("consumers-server-discovery")
    if entry_records["exports"]["argv"] != ["go", "list", "-json", "-race", "-compiled", "-deps", "-test", "-export", "./polaris"]:
        v.reject("consumers-compiler-command")
    listing = [v.decode(row) for row in entry_outputs["entry-list"].splitlines()]
    discovered = sorted(row["Output"].strip() for row in listing if re.fullmatch(r"(?:Test|Example|Fuzz)[A-Za-z0-9_]*\n", row.get("Output", "")))
    if (
        entry_records["entry-list"]["argv"] != ["go", "test", "-json", "-race", "-p=2", "-list", ".", "-timeout=180s", "./polaris"]
        or discovered != results["entry"]["expected"]
        or any(row.get("Action") in ("fail", "skip") or row.get("Package") != "github.com/eosforge/astra/polaris" for row in listing)
    ):
        v.reject("consumers-entry-discovery")
    prior = v.decode(baseline[PREFIX + "entry-race/record.json"])
    original = server.reference(baseline, PREFIX + "entry-race/", prior["stdout"])
    entry_cases = cases(entry_outputs["entry-race"], "github.com/eosforge/astra/polaris", entry.tests(original))
    profile = files[PREFIX + "entry-race/coverage.out"]
    terminal = v.decode(files["terminal.json"])
    owner = v.decode(files["controller.json"])
    if (
        entry_records["entry-race"]["argv"]
        != [
            "go",
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
        ]
        or entry_cases != discovered
        or not profile.startswith(b"mode: atomic\n")
        or v.digest(profile) != terminal["checks"]["entry-race"]["coverage_sha256"]
    ):
        v.reject("consumers-entry-profile")
    refreshed = {
        "server": {
            "expected": server_cases,
            "tests": len(server_cases),
            "cases": len(full),
            "duration_ms": records["server-batch-race"]["duration_ms"],
            "plain_duration_ms": records["polaris-server-boundaries"]["duration_ms"],
            "coverage_sha256": None,
            "coverage_status": "not-collected-for-current-source",
        },
        "entry": {
            "expected": entry_cases,
            "tests": len(entry_cases),
            "duration_ms": entry_records["entry-race"]["duration_ms"],
            "coverage_sha256": v.digest(profile),
        },
    }
    return maintenance(artifacts, latest, refreshed, entry_outputs["exports"])


def maintenance(artifacts: dict[str, bytes], previous: dict[str, bytes], results: dict, exports: bytes) -> tuple[dict[str, bytes], dict, bytes]:
    """Bind the exact owner revision and actual complete current consumers without transferring old profiles."""
    from tools import impact

    _, current, records, outputs = load(artifacts, CURRENT)
    sources(previous, current)
    if records["exports"]["argv"] != ["go", "list", "-json", "-race", "-compiled", "-deps", "-test", "-export", "./polaris"]:
        v.reject("consumers-maintenance-compiler")
    if impact.graph(outputs["exports"]) != impact.graph(exports):
        v.reject("consumers-maintenance-graph")
    listing = [v.decode(row) for row in outputs["entry-list"].splitlines()]
    roots = sorted(row["Output"].strip() for row in listing if re.fullmatch(r"(?:Test|Example|Fuzz)[A-Za-z0-9_]*\n", row.get("Output", "")))
    if (
        records["entry-list"]["argv"] != ["go", "test", "-json", "-race", "-p=2", "-list", ".", "-timeout=180s", "./polaris"]
        or roots != results["entry"]["expected"]
        or any(row.get("Action") in {"fail", "skip"} or row.get("Package") != "github.com/eosforge/astra/polaris" for row in listing)
    ):
        v.reject("consumers-maintenance-discovery")
    config = v.decode(current["development.json"])
    declared = {item["id"]: item for item in config["checks"]}
    entry_cases = declared["polaris-entry-qualification"]["native_tests"]
    full = v.decode(current["tests/fixtures/server.tests.json"])
    for name, package, inventory, race in (
        ("entry-race", "polaris", entry_cases, True),
        ("server-plain", "polaris/internal/server", full, False),
        ("server-race", "polaris/internal/server", full, True),
    ):
        if records[name]["argv"] != ["go", "test", "-json", *(["-race"] if race else []), "-count=1", "-p=2", "-parallel=1", "-timeout=180s", "./" + package]:
            v.reject("consumers-maintenance-command", name)
        actual = cases(outputs[name], "github.com/eosforge/astra/" + package, inventory)
        if actual != results["entry" if name == "entry-race" else "server"]["expected"]:
            v.reject("consumers-maintenance-inventory", name)
    if len(entry_cases) != 50 or len(full) != 300:
        v.reject("consumers-maintenance-denominator")
    current_results = {
        "server": {**results["server"], "duration_ms": records["server-race"]["duration_ms"], "plain_duration_ms": records["server-plain"]["duration_ms"]},
        "entry": {
            **results["entry"],
            "cases": len(entry_cases),
            "duration_ms": records["entry-race"]["duration_ms"],
            "coverage_sha256": None,
            "coverage_status": "not-collected-for-current-source",
        },
    }
    return current, current_results, outputs["exports"]


def sources(previous: dict[str, bytes], current: dict[str, bytes]) -> None:
    """Conserve every earlier compiled input outside the exact owner, fixture and compatibility additions."""
    from tools import idle

    inputs = {
        name
        for name in previous.keys() | current.keys()
        if name.endswith(".go")
        or name.startswith("proto/")
        or name in {"go.mod", "go.sum", "dependencies.lock.json", "tools/decisions/runtime.go.in", "tests/fixtures/storage.tests.json"}
    }
    expected = {
        **idle.SOURCES,
        "polaris/internal/storage/compatibility_test.go": "57b1b9dbb3fb51332b0c807f7408dcad93181913833d3ea6d6734d20b835b09f",
        "polaris/internal/storage/maintenance_test.go": "219006b05a23f979a0afa6528f9544e5dbc03858e2c6493fc3042f30b72f1bd1",
        "polaris/internal/storage/storage_test.go": "94396613748dc1846f66f6755eb562b313fb62b8c4ea28f7402461851291f3c2",
    }
    if {name for name in inputs if previous.get(name) != current.get(name)} != set(expected) or any(
        name not in current or v.digest(current[name]) != digest for name, digest in expected.items()
    ):
        v.reject("consumers-maintenance-source-delta")
    idle.source_guard(previous[idle.STORE], current[idle.STORE])
