"""Run explicit Go/C++ mutation denominators with isolated replacements, native failures and bounded cleanup."""

import argparse
import base64
import binascii
from collections.abc import Sequence
import ctypes
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import shlex
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import build, verify as v

# Complete model traces can exceed 16 MiB; retain the native suite's finite per-case ceiling.
CPP_LOG = 32 * 1024**2


def emit(event: str, **values: object) -> None:
    """Carry original runner facts in the outer log so the gate can independently recompute outcomes."""
    print("ASTRA-MUTATION " + json.dumps({"event": event, **values}, separators=(",", ":")), flush=True)


def observations(data: bytes, check: dict, root: Path, *, origin: str | None = None) -> tuple[dict[str, int], list[str]]:
    """Read Linux facts against local source bytes; an explicit origin must come from the verified collection context."""
    location = root.as_posix() if origin is None else origin
    native = PurePosixPath(location)
    if not native.is_absolute() or str(native) != location or "\\" in location or ".." in native.parts or native.anchor != "/":
        v.reject("mutation-native-root")
    manifest = v.decode(v.read(v.inside(root, check["manifest"])))
    planned = plan(manifest, root)
    oracles = fixtures(manifest, root)
    entries = []
    for line in data.splitlines():
        if not line.startswith(b"ASTRA-MUTATION "):
            v.reject("mutation-stream-format")
        entries.append(v.decode(line[len(b"ASTRA-MUTATION ") :], maximum=check["log_bytes"]))
    expected = [("baseline-" + test, test, None) for test in sorted({item["test"] for item in planned})]
    expected += [(item["id"], item["test"], item) for item in planned]
    header = {
        "event": "start",
        "manifest_sha256": v.file_digest(v.inside(root, check["manifest"])),
        "sources": {item["file"]: item["source_sha256"] for item in planned},
    }
    if oracles:
        header["fixtures"] = [{key: val for key, val in item.items() if key != "data"} for item in oracles]
    if len(entries) != len(expected) + 2 or entries[0] != header:
        v.reject("mutation-stream-plan")
    if v.encode(entries[-1]) != v.encode({"event": "finish", "source_unchanged": True, "interrupted": False}):
        v.reject("mutation-stream-incomplete")
    failures, directories = [], set()
    for entry, (name, test, item) in zip(entries[1:-1], expected):
        if not isinstance(entry, dict) or set(entry) != {"event", "id", "record", "stdout", "stderr", "overlay", "replacement_sha256"}:
            v.reject("mutation-result-shape")
        if entry["event"] != "result" or entry["id"] != name:
            v.reject("mutation-result-order")
        record = entry["record"]
        v.schema(record, "evidence", ("properties", "checks", "items"))
        if record["id"] != name or record["platform"] != "linux-amd64-cgo":
            v.reject("mutation-record-identity")
        temporary = record["resolved_environment"].get("TMPDIR", "")
        path = PurePosixPath(temporary)
        output = path.parent.parent
        if (
            str(path) != temporary
            or "\\" in temporary
            or ".." in path.parts
            or not output.is_relative_to(native / "build")
            or path.name != "tmp"
            or path.parent.name != name
        ):
            v.reject("mutation-temporary-boundary")
        directories.add(output)
        if len(directories) != 1:
            v.reject("mutation-temporary-boundary")
        argv = [record["executable"], "test", "-json", "-count=1", "-p=2", "-parallel=1", "-timeout=180s", "-run=^" + test + "$"]
        replacements = {str(native / oracle["target"]): str(output / ("fixture-" + str(index) + ".go.txt")) for index, oracle in enumerate(oracles)}
        if item is not None:
            replacements[str(native / item["file"])] = str(output / (name + ".go.txt"))
        mapping = {"Replace": replacements} if replacements else None
        if mapping:
            argv.append("-overlay=" + str(output / (name + ".json")))
        argv.append(manifest["package"])
        if record["argv"] != argv or PurePosixPath(record["executable"]).name != "go":
            v.reject("mutation-command-mismatch")
        replacement = v.digest(item["replacement"].encode()) if item else None
        if entry["replacement_sha256"] != replacement or entry["overlay"] != mapping:
            v.reject("mutation-replacement-mismatch")
        for key, value in {"GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": "-mod=readonly"}.items():
            if record["resolved_environment"].get(key) != value:
                v.reject("mutation-environment")
        outputs = {}
        for field in ("stdout", "stderr"):
            try:
                outputs[field] = base64.b64decode(entry[field], validate=True)
            except (ValueError, TypeError, binascii.Error):
                v.reject("mutation-output-encoding")
            ref = record[field]
            if len(outputs[field]) != ref["bytes"] or v.digest(outputs[field]) != ref["sha256"]:
                v.reject("mutation-output-digest")
        if record["duration_ms"] > 240000 or v.stamp(record["finished_at"]) < v.stamp(record["started_at"]):
            v.reject("mutation-execution-budget")
        state = outcome(record, outputs["stdout"], manifest["import"], test, baseline=item is None)
        if state != ("passed" if item is None else "killed"):
            failures.append(name + ":" + state)
    return ({probe["contract"]: len(planned) for probe in check["probes"]} if not failures else {}), failures


def plan(value: dict, root: Path) -> list[dict]:
    """Reject ambiguous edits and freeze every mutation against the actual production source."""
    v.schema(value, "mutations")
    fixtures(value, root)
    v.unique(value["mutations"])
    result = []
    for item in value["mutations"]:
        path = v.inside(root, item["file"])
        if path.suffix != ".go" or path.name.endswith("_test.go"):
            v.reject("mutation-production-go", item["file"])
        original = path.read_text(encoding="utf-8")
        if original.count(item["before"]) != 1 or item["before"] == item["after"]:
            v.reject("mutation-anchor", item["id"])
        if not re.fullmatch(r"Test[A-Za-z0-9_]+", item["test"]):
            v.reject("mutation-test", item["test"])
        result.append({**item, "source_sha256": v.file_digest(path), "replacement": original.replace(item["before"], item["after"], 1)})
    return result


def fixtures(value: dict, root: Path) -> list[dict]:
    """Bind added same-package test oracles without replacing any existing source or test file."""
    result, sources, targets = [], set(), set()
    for item in value.get("fixtures", []):
        source, target = (v.inside(root, item[key]) for key in ("source", "target"))
        package = v.inside(root, value["package"][2:])
        if (
            not source.is_file()
            or not source.name.endswith(".go.in")
            or target.parent != package
            or not target.parent.is_dir()
            or not target.name.endswith("_test.go")
            or target.exists()
            or item["source"] in sources
            or item["target"] in targets
        ):
            v.reject("mutation-fixture-boundary", item["source"])
        data = v.read(source)
        result.append({**item, "sha256": v.digest(data), "data": data})
        sources.add(item["source"])
        targets.add(item["target"])
    return result


def outcome(record: dict, data: bytes, package: str, test: str, baseline: bool = False) -> str:
    """Count only a complete native failure of the named test as a killed mutant."""
    if not record["complete"] or not record["cleanup"] or record["termination"] != "exited":
        return "invalid"
    try:
        entries = [v.decode(line) for line in data.splitlines() if line.strip()]
    except v.Invalid:
        return "invalid"
    if any(not isinstance(entry, dict) for entry in entries):
        return "invalid"
    entries = [entry for entry in entries if entry.get("Package") == package]
    runs = sum(entry.get("Test") == test and entry.get("Action") == "run" for entry in entries)
    results = [entry["Action"] for entry in entries if entry.get("Test") == test and entry.get("Action") in ("pass", "fail", "skip")]
    terminal = [entry["Action"] for entry in entries if not entry.get("Test") and entry.get("Action") in ("pass", "fail", "skip")]
    if runs != 1 or len(results) != 1 or len(terminal) != 1:
        return "invalid"
    if results == terminal == ["pass"] and record["exit_code"] == 0:
        return "passed" if baseline else "survived"
    if not baseline and results == terminal == ["fail"] and record["exit_code"] != 0:
        text = "".join(entry.get("Output", "") for entry in entries if isinstance(entry.get("Output", ""), str))
        if any(value in text for value in ("panic:", "fatal error:", "test timed out", "WARNING: DATA RACE")):
            return "invalid"
        return "killed"
    return "invalid"


def overlay(output: Path, item: dict | None, root: Path, *, oracles: Sequence[dict] = (), name: str | None = None) -> Path:
    """Keep added test oracles identical across baselines/mutants and save replacements outside Go discovery."""
    replacements = {}
    for index, oracle in enumerate(oracles):
        saved = output / ("fixture-" + str(index) + ".go.txt")
        if saved.exists():
            if v.file_digest(saved) != oracle["sha256"]:
                v.reject("mutation-fixture-changed", oracle["source"])
        else:
            v.write_new(saved, oracle["data"])
        replacements[str(v.inside(root, oracle["target"]))] = str(saved)
    if item is not None:
        name = item["id"]
        replacement = output / (name + ".go.txt")
        v.write_new(replacement, item["replacement"].encode())
        replacements[str(v.inside(root, item["file"]))] = str(replacement)
    if not name or not replacements:
        v.reject("mutation-overlay-empty")
    mapping = output / (name + ".json")
    v.write_new(mapping, {"Replace": replacements})
    return mapping


def cpp_plan(value: dict, root: Path) -> list[dict]:
    """Freeze exact production C++ replacements and unchanged, separately compiled assertion oracles."""
    v.schema(value, "cpp-mutations")
    v.unique(value["mutations"])
    result = []
    for item in value["mutations"]:
        path, oracle = (v.inside(root, item[field]) for field in ("file", "oracle"))
        if (
            path.suffix != ".cpp"
            or path.name.endswith("_test.cpp")
            or "/src/" not in item["file"]
            or oracle.suffix != ".cpp"
            or "/tests/" not in item["oracle"]
            or not oracle.name.endswith("_test.cpp")
        ):
            v.reject("mutation-production-cpp", item["file"])
        original = path.read_text(encoding="utf-8")
        if original.count(item["before"]) != 1 or item["before"] == item["after"]:
            v.reject("mutation-anchor", item["id"])
        result.append(
            {
                **item,
                "source_sha256": v.file_digest(path),
                "oracle_sha256": v.file_digest(oracle),
                "replacement": original.replace(item["before"], item["after"], 1),
            }
        )
    return result


def cpp_recipe(directory: Path, item: dict, root: Path, replacement: Path, object_file: Path, executable: Path) -> tuple[list[str], list[str], dict[str, str]]:
    """Reuse native compile/link flags, replacing only one production object before its original static library."""
    commands = v.decode(v.read(directory / "compile_commands.json"))
    source = v.inside(root, item["file"])
    matching = [command for command in commands if Path(command["file"]).resolve() == source]
    if len(matching) != 1:
        v.reject("mutation-compile-recipe", item["id"])
    recipe = matching[0]
    compile = recipe.get("arguments") or shlex.split(recipe["command"])
    if Path(compile[0]).name.lower() == "cl.exe":
        return msvc_recipe(directory, item, root, replacement, object_file, executable, commands, recipe)
    links = list(directory.glob("**/CMakeFiles/" + item["test"] + ".dir/link.txt"))
    if len(links) != 1:
        v.reject("mutation-link-recipe", item["id"])
    link_directory = links[0].parent.parent.parent.resolve()
    link = shlex.split(v.read(links[0]).decode())
    compiler = str((build.CACHE / "tools/gcc-16.2.0/bin/g++").resolve())
    if str(Path(compile[0]).resolve()) != compiler or str(Path(link[0]).resolve()) != compiler:
        v.reject("mutation-compiler")
    if compile.count("-o") != 1 or compile.count("-c") != 1 or link.count("-o") != 1 or compile.count(str(source)) != 1:
        v.reject("mutation-recipe-shape")
    if any(arg.startswith(("-MD", "-MMD", "-MF", "-MT", "-MQ", "-save-temps", "-fprofile")) for arg in compile):
        v.reject("mutation-recipe-side-output")
    working = Path(recipe["directory"]).resolve()
    if compile[compile.index("-c") + 1] != str(source) or not working.is_relative_to(directory) or not working.is_dir():
        v.reject("mutation-recipe-source")
    # Resolve include/file flags against the native recipe, not the runner's source-root cwd.
    paths = ("-I", "-isystem", "-iquote", "-idirafter", "-include", "-imacros")
    index = 1
    while index < len(compile):
        arg = compile[index]
        if arg in paths:
            if index + 1 == len(compile):
                v.reject("mutation-recipe-shape")
            compile[index + 1] = str((working / compile[index + 1]).resolve())
            index += 2
            continue
        flag = next((flag for flag in paths if arg.startswith(flag) and len(arg) > len(flag)), None)
        if flag:
            compile[index] = flag + str((working / arg[len(flag) :]).resolve())
        elif arg.startswith("@"):
            v.reject("mutation-recipe-response-file")
        index += 1
    compile[compile.index("-o") + 1] = str(object_file)
    compile[compile.index(str(source))] = str(replacement)
    compile.extend(["-iquote", str(source.parent)])
    link[link.index("-o") + 1] = str(executable)
    link.insert(1, str(object_file))
    # CMake's linker dependency file is an output, not a borrowed build input.
    # Keep it with this attempt instead of writing into the original target's directory.
    for index, arg in enumerate(link):
        if arg.startswith("-Wl,--dependency-file="):
            link[index] = "-Wl,--dependency-file=" + str(executable.with_suffix(".d"))
    # Native recipes use build-relative objects/libraries; run from the source root so temporary ownership stays explicit.
    link = [str((link_directory / arg).resolve()) if (link_directory / arg).is_file() else arg for arg in link]
    # The test's original object must appear in its own link recipe; no mutant edits that oracle.
    oracle = v.inside(root, item["oracle"])
    test = [command for command in commands if Path(command["file"]).resolve() == oracle]
    if len(test) != 1:
        v.reject("mutation-oracle-recipe")
    test_argv = test[0].get("arguments") or shlex.split(test[0]["command"])
    if test_argv.count("-o") != 1:
        v.reject("mutation-oracle-object")
    test_directory = Path(test[0]["directory"]).resolve()
    if not test_directory.is_relative_to(directory) or not test_directory.is_dir():
        v.reject("mutation-oracle-directory")
    test_object = (test_directory / test_argv[test_argv.index("-o") + 1]).resolve()
    inputs = {}
    for arg in link[1:]:
        path = (link_directory / arg).resolve()
        if path.is_file():
            inputs[str(path)] = v.file_digest(path)
    if str(test_object) not in inputs:
        v.reject("mutation-oracle-link")
    return compile, link, inputs


def msvc_recipe(directory: Path, item: dict, root: Path, replacement: Path, object_file: Path, executable: Path, commands: list, recipe: dict) -> tuple:
    """Admit explicit MSVC argument arrays and one structured link recipe, rejecting implicit side outputs.

    This bounded recipe form does not interpret Windows shell strings, response files, PCH, modules or incremental PDB generation.
    """
    compiler = Path(os.environ.get("CXX", "")).resolve()
    if compiler.name.lower() != "cl.exe" or not compiler.is_file():
        v.reject("mutation-compiler")
    source = v.inside(root, item["file"])
    oracle = v.inside(root, item["oracle"])

    def arguments(command: dict, path: Path) -> tuple[list[str], Path, Path]:
        """Validate the compile command before changing only its source/output and resolving borrowed include paths."""
        values = command.get("arguments")
        if not isinstance(values, list) or not values or any(not isinstance(value, str) or not value for value in values):
            v.reject("mutation-msvc-arguments")
        values = values.copy()
        working = Path(command["directory"]).resolve()
        if not working.is_relative_to(directory) or not working.is_dir():
            v.reject("mutation-oracle-directory")
        outputs = [index for index, value in enumerate(values) if value.startswith("/Fo") and len(value) > 3]
        if Path(values[0]).resolve() != compiler or values.count("/c") != 1 or len(outputs) != 1 or values.count(str(path)) != 1:
            v.reject("mutation-recipe-shape")
        # All admitted debug information stays in the object; /Zi, PCH, module and analysis output switches are not supported.
        flags = {"/nologo", "/c", "/std:c++20", "/std:c++23preview", "/EHsc", "/Od", "/O1", "/O2", "/Z7", "/MD", "/MT", "/W4", "/WX", "/permissive-"}
        index = 1
        output = None
        while index < len(values):
            value = values[index]
            if index in outputs:
                output = (working / value[3:]).resolve()
                values[index] = "/Fo" + str(output)
                index += 1
                continue
            if value in {"/I", "/FI", "/D", "/U"}:
                if index + 1 == len(values):
                    v.reject("mutation-recipe-shape")
                if value in {"/I", "/FI"}:
                    values[index + 1] = str((working / values[index + 1]).resolve())
                index += 2
                continue
            if value.startswith(("/D", "/U")) and len(value) > 2:
                index += 1
                continue
            if value != str(path) and value not in flags:
                v.reject("mutation-recipe-side-output", value)
            index += 1
        if output is None or output.suffix.lower() != ".obj" or not output.is_relative_to(directory):
            v.reject("mutation-oracle-object")
        return values, working, output

    compile, _, _ = arguments(recipe, source)
    tests = [command for command in commands if Path(command["file"]).resolve() == oracle]
    if len(tests) != 1:
        v.reject("mutation-oracle-recipe")
    _, _, test_object = arguments(tests[0], oracle)
    links = list(directory.glob("**/CMakeFiles/" + item["test"] + ".dir/link.json"))
    if len(links) != 1:
        v.reject("mutation-link-recipe", item["id"])
    working = links[0].parent.parent.parent.resolve()
    link = v.decode(v.read(links[0]))
    if not isinstance(link, list) or not link or any(not isinstance(value, str) or not value for value in link):
        v.reject("mutation-msvc-arguments")
    outputs = [index for index, value in enumerate(link) if value.startswith("/Fe") and len(value) > 3]
    if Path(link[0]).resolve() != compiler or len(outputs) != 1:
        v.reject("mutation-recipe-shape")
    inputs = {}
    output = outputs[0]
    for index, value in enumerate(link[1:], 1):
        if index == output or value in {"/nologo", "/link", "/INCREMENTAL:NO", "/DEBUG:NONE"}:
            continue
        path = (working / value).resolve()
        if path.suffix.lower() not in {".obj", ".lib"} or not path.is_file() or not path.is_relative_to(directory):
            v.reject("mutation-recipe-side-output", value)
        link[index] = str(path)
        inputs[str(path)] = v.file_digest(path)
    if str(test_object) not in inputs or not any(Path(path).suffix.lower() == ".lib" for path in inputs):
        v.reject("mutation-oracle-link")
    compile[compile.index(str(source))] = str(replacement)
    compile[next(index for index, value in enumerate(compile) if value.startswith("/Fo"))] = "/Fo" + str(object_file)
    compile.extend(["/I", str(source.parent)])
    link[output] = "/Fe" + str(executable)
    link.insert(1, str(object_file))
    return compile, link, inputs


def environment(root: Path, *, jobs: int = 1) -> dict[str, str]:
    """Use existing offline native tools; Windows fixtures neither select Linux GCC nor enable unavailable Cgo."""
    if os.name != "nt":
        return build.environment(jobs=jobs)
    return {
        **v.public_environment(os.environ),
        "GOPATH": str(build.CACHE / "deps/go"),
        "GOMODCACHE": str(build.CACHE / "deps/go/pkg/mod"),
        "GOCACHE": str(root / "build/cache/go"),
        "CGO_ENABLED": "0",
        "GOMAXPROCS": str(jobs),
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def cpp_outcome(record: dict, stdout: bytes, stderr: bytes, oracle: Path, baseline: bool = False) -> str:
    """Only a completed named assertion failure kills a C++ mutant; signals/compile errors are invalid."""
    if not record["complete"] or not record["cleanup"] or record["termination"] != "exited":
        return "invalid"
    markers = re.findall(rb"^ASTRA-CHECKS (\{[^\n]*\})\r?$", stdout, re.MULTILINE)
    if len(markers) != 1:
        return "invalid"
    try:
        counts = v.decode(markers[0])
    except v.Invalid:
        return "invalid"
    if not isinstance(counts, dict) or set(counts) != {"hits"} or type(counts["hits"]) is not int or counts["hits"] < 0:
        return "invalid"
    if record["exit_code"] == 0 and counts["hits"] > 0:
        return "passed" if baseline else "survived"
    if baseline or record["exit_code"] != 1:
        return "invalid"
    match = re.search(re.escape(str(oracle)).encode() + rb":([1-9][0-9]*): [^\r\n]+", stderr)
    if match:
        lines = oracle.read_text(encoding="utf-8").splitlines()
        line = int(match[1])
        if line <= len(lines) and "CHECK(" in lines[line - 1]:
            return "killed"
    return "invalid"


def cpp_run(manifest: dict, directory: Path, output: Path, root: Path, *, prune: bool = False) -> int:
    """Build direct isolated replacement objects, preserve all native records, and never edit an input tree."""
    mutations = cpp_plan(manifest, root)
    if not directory.is_relative_to(root / "build") or not directory.is_dir():
        v.reject("mutation-build-boundary")
    output.mkdir(parents=True, exist_ok=False)
    source = v.source(root)
    recipes = {str(directory / "compile_commands.json"): v.file_digest(directory / "compile_commands.json")}
    for test in {item["test"] for item in mutations}:
        links = [path for suffix in ("txt", "json") for path in directory.glob("**/CMakeFiles/" + test + ".dir/link." + suffix)]
        if len(links) != 1:
            v.reject("mutation-link-recipe", test)
        recipes[str(links[0])] = v.file_digest(links[0])
    v.write_new(output / "inputs.json", {"source": source, "manifest": manifest, "build": str(directory), "recipes": recipes, "prune": prune})
    stopped = False

    def cancel(*_: object) -> None:
        """Drain owned compilers/test children before recording interruption."""
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)
    results = []

    def execute(name: str, argv: list[str], cwd: Path, destination: Path, budget: int) -> tuple[dict, bytes, bytes]:
        """Bind native command/stream digests and cleanup before accepting any compilation or test outcome."""
        target = destination / name
        target.mkdir()
        if os.name != "nt" and len(argv) > 64:
            # Preserve every native argument while respecting the evidence format's argv bound.
            response = target / "arguments.rsp"
            v.write_new(target / "arguments.json", argv)
            v.write_new(response, ("\n".join('"' + arg.replace("\\", "\\\\").replace('"', '\\"') + '"' for arg in argv[1:]) + "\n").encode())
            argv = [argv[0], "@" + str(response)]
        check = {
            "id": name,
            "argv": argv,
            "environment": {**environment(cwd), "TMPDIR": str(target / "tmp")},
            "timeout_s": budget,
            "log_bytes": CPP_LOG,
        }
        v.write_new(target / "plan.json", check)
        record = v.execute(check, cwd, target, "windows-amd64" if os.name == "nt" else "linux-amd64-cgo", lambda: stopped)
        v.write_new(target / "record.json", record)
        return record, v.reference(target, record["stdout"], CPP_LOG), v.reference(target, record["stderr"], CPP_LOG)

    def attempt(item: dict, baseline: bool) -> str:
        """Compilation and linking must pass before the unmodified model is allowed to reject a mutation."""
        name = ("baseline-" if baseline else "") + item["id"]
        destination = output / name
        destination.mkdir()
        path = v.inside(root, item["file"])
        names = ("source.cpp", "source.obj", "program.exe") if os.name == "nt" else ("source.cpp", "source.o", "program")
        replacement, object_file, executable = (destination / name for name in names)
        v.write_new(replacement, path.read_bytes() if baseline else item["replacement"].encode())
        compile, link, inputs = cpp_recipe(directory, item, root, replacement, object_file, executable)
        inputs.update(recipes)
        v.write_new(
            destination / "recipe.json",
            {"compile": compile, "link": link, "inputs": inputs, "production": item["source_sha256"], "oracle": item["oracle_sha256"]},
        )
        state = "invalid"
        for stage, argv, budget in (("compile", compile, 180), ("link", link, 120), ("test", [str(executable)], 120)):
            if stopped or v.source(root) != source or any(v.file_digest(Path(path)) != checksum for path, checksum in inputs.items()):
                break
            record, stdout, stderr = execute(stage, argv, root, destination, budget)
            if stage == "test":
                state = cpp_outcome(record, stdout, stderr, v.inside(root, item["oracle"]), baseline)
            elif record["exit_code"] or not record["complete"] or not record["cleanup"]:
                break
            else:
                artifact = object_file if stage == "compile" else executable
                inputs[str(artifact)] = v.file_digest(artifact)
                v.write_new(
                    destination / (stage + "-artifact.json"), {"path": artifact.name, "sha256": inputs[str(artifact)], "bytes": artifact.stat().st_size}
                )
        if v.source(root) != source or any(v.file_digest(Path(path)) != checksum for path, checksum in inputs.items()):
            state = "invalid"
        row = {"id": name, "status": state, "recipe_sha256": v.file_digest(destination / "recipe.json")}
        results.append(row)
        v.write_new(destination / "outcome.json", row)
        if prune and state in {"passed", "killed"}:
            # Only drained, successful attempts release their owned rebuildable artifacts; failed programs remain inspectable.
            artifacts = []
            for artifact in (object_file, executable):
                if artifact.is_symlink() or not artifact.resolve().is_relative_to(destination.resolve()) or v.file_digest(artifact) != inputs[str(artifact)]:
                    v.reject("mutation-artifact-ownership", str(artifact))
                artifacts.append({"path": artifact.name, "bytes": artifact.stat().st_size, "sha256": inputs[str(artifact)]})
            v.write_new(destination / "prune-plan.json", {"status": state, "files": artifacts, "owned_process_cleanup": True})
            for artifact in (object_file, executable):
                artifact.unlink()
            v.write_new(destination / "pruned.json", {"at": v.utc(), "files": artifacts, "owned_process_cleanup": True})
        print(json.dumps(row), flush=True)
        return state

    ready = True
    baselines = {}
    groups = {}
    for item in mutations:
        key = (item["file"], item["test"], item["oracle"])
        if key not in groups:
            if stopped or attempt(item, True) != "passed":
                ready = False
                break
            groups[key] = "baseline-" + item["id"]
        baselines[item["id"]] = groups[key]
        if stopped:
            ready = False
            break
    if ready:
        for item in mutations:
            if stopped:
                break
            state = attempt(item, False)
            if prune and state != "killed":
                break
    killed = sum(row["status"] == "killed" for row in results)
    unchanged = v.source(root) == source
    passed = ready and not stopped and unchanged and killed == len(mutations)
    v.write_new(
        output / "result.json",
        {
            "status": "passed" if passed else "blocked",
            "scope": manifest["scope"],
            "planned": len(mutations),
            "killed": killed,
            "source_unchanged": unchanged,
            "interrupted": stopped,
            "checks": results,
            "baselines": baselines,
        },
    )
    return 0 if passed else 2


def main(arguments: list[str] | None = None) -> int:
    """Execute a frozen targeted plan without editing production code or installing dependencies."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=build.ROOT / "tests/mutations.json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--build", type=Path, default=build.ROOT / "build/cmake/release")
    parser.add_argument("--prune", action="store_true", help="Remove only successful C++ attempts' drained, rebuildable objects and programs")
    args = parser.parse_args(arguments)
    if sys.platform != "linux" or ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0):
        v.reject("mutation-linux-subreaper-required")
    root = build.ROOT
    if args.output is None:
        if not os.environ.get("TMPDIR"):
            v.reject("mutation-output-missing")
        args.output = Path(os.environ["TMPDIR"]).parent / ("mutations-" + v.digest(str(args.manifest).encode())[:16])
    output = args.output.resolve()
    if not output.is_relative_to(root / "build"):
        v.reject("mutation-output-boundary")
    manifest = v.decode(v.read(args.manifest))
    if isinstance(manifest, dict) and manifest.get("engine") == "cpp":
        return cpp_run(manifest, args.build.resolve(), output, root, prune=args.prune)
    if args.prune:
        v.reject("mutation-prune-cpp-required")
    mutations = plan(manifest, root)
    oracles = fixtures(manifest, root)
    output.mkdir(parents=True, exist_ok=False)
    source = v.source(root)
    binding = {"fixtures": [{key: val for key, val in item.items() if key != "data"} for item in oracles]} if oracles else {}
    emit("start", manifest_sha256=v.file_digest(args.manifest), sources={item["file"]: item["source_sha256"] for item in mutations}, **binding)
    v.write_new(
        output / "inputs.json",
        {"source": source, "manifest": manifest, "mutations": [{k: val for k, val in item.items() if k != "replacement"} for item in mutations]},
    )
    stopped = False

    def cancel(*_: object) -> None:
        """Ask the native runner to drain before returning from a cancelled mutation campaign."""
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)
    env = build.environment(jobs=2)
    results = []

    def run(name: str, test: str, overlay: Path | None = None, baseline: bool = False) -> str:
        """Capture and classify a single baseline or mutant; never retry to green."""
        directory = output / name
        directory.mkdir()
        argv = [str(build.CACHE / "tools/go-1.27.2/bin/go"), "test", "-json", "-count=1", "-p=2", "-parallel=1", "-timeout=180s", "-run=^" + test + "$"]
        if overlay:
            argv.append("-overlay=" + str(overlay))
        argv.append(manifest["package"])
        replacement = output / (name + ".go.txt") if overlay and not baseline else None
        before = v.file_digest(replacement) if replacement else None
        mapping = v.decode(v.read(overlay)) if overlay else None
        artifacts = {path: v.file_digest(path) for path in mapping["Replace"].values()} if mapping else {}
        record = v.execute(
            {"id": name, "argv": argv, "environment": {**env, "TMPDIR": str(directory / "tmp")}, "timeout_s": 240, "log_bytes": 16 * 1024 * 1024},
            root,
            directory,
            "linux-amd64-cgo",
            lambda: stopped,
        )
        v.write_new(directory / "record.json", record)
        state = outcome(record, v.read(directory / record["stdout"]["path"], 16 * 1024 * 1024), manifest["import"], test, baseline)
        results.append(
            {"id": name, "status": state, "record": str((directory / "record.json").relative_to(output)), "sha256": v.file_digest(directory / "record.json")}
        )
        if mapping and (any(v.file_digest(path) != digest for path, digest in artifacts.items()) or v.decode(v.read(overlay)) != mapping):
            v.reject("mutation-replacement-changed", name)
        emit(
            "result",
            id=name,
            record=record,
            overlay=mapping,
            replacement_sha256=before,
            **{field: base64.b64encode(v.reference(directory, record[field], 16 * 1024 * 1024)).decode("ascii") for field in ("stdout", "stderr")},
        )
        return state

    ready = True
    for test in sorted({item["test"] for item in mutations}):
        name = "baseline-" + test
        mapping = overlay(output, None, root, oracles=oracles, name=name) if oracles else None
        if stopped or run(name, test, mapping, baseline=True) != "passed":
            ready = False
            break
    if ready:
        for item in mutations:
            if stopped:
                break
            path = v.inside(root, item["file"])
            if v.file_digest(path) != item["source_sha256"]:
                v.reject("mutation-source-changed", item["file"])
            mapping = overlay(output, item, root, oracles=oracles)
            run(item["id"], item["test"], mapping)
    killed = sum(item["status"] == "killed" for item in results)
    unchanged = v.source(root) == source
    passed = ready and not stopped and unchanged and killed == len(mutations)
    emit("finish", source_unchanged=unchanged, interrupted=stopped)
    v.write_new(
        output / "result.json",
        {
            "status": "passed" if passed else "blocked",
            "scope": manifest["scope"],
            "planned": len(mutations),
            "killed": killed,
            "source_unchanged": unchanged,
            "interrupted": stopped,
            "checks": results,
        },
    )
    return 0 if passed else 2


if __name__ == "__main__":
    sys.exit(main())
