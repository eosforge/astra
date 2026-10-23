"""Reconcile native Go statement counters with frozen source bytes and actual build selection."""

import json
from pathlib import Path
import re

from tools import verify as v

# Raw compiler/package streams have their own budget, separate from policy JSON.
LIMIT = 32 * 1024 * 1024
BLOCK = re.compile(r"([^\s]+\.go):([1-9][0-9]*)\.([1-9][0-9]*),([1-9][0-9]*)\.([1-9][0-9]*) (0|[1-9][0-9]*) (0|[1-9][0-9]*)")
GENERATED = re.compile(rb"(?m)^// Code generated [^\r\n]+ DO NOT EDIT\.[\r]?$")
FIELDS = ("GoFiles", "CgoFiles", "IgnoredGoFiles", "InvalidGoFiles", "TestGoFiles", "XTestGoFiles")


def stream(data: bytes) -> list[dict]:
    """Decode concatenated native package JSON, retaining duplicate-key and size rejection."""
    if len(data) > LIMIT:
        v.reject("go-packages-size")
    try:
        text = data.decode("utf-8")
        decoder = json.JSONDecoder()
        position, values = 0, []
        while position < len(text):
            while position < len(text) and text[position].isspace():
                position += 1
            if position == len(text):
                break
            start = position
            _, position = decoder.raw_decode(text, position)
            value = v.decode(text[start:position].encode(), maximum=LIMIT)
            if not isinstance(value, dict):
                v.reject("go-package-shape")
            values.append(value)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        v.reject("go-packages-invalid", type(error).__name__)
    if not values:
        v.reject("go-packages-empty")
    return values


def sources(source: dict, root: Path) -> tuple[str, dict[str, dict]]:
    """Bind all registered Go files, including ignored-platform, generated and test inputs."""
    files = v.unique(source["files"], "path")
    if "go.mod" not in files or files["go.mod"]["sha256"] != v.file_digest(root / "go.mod"):
        v.reject("go-module-identity")
    module = re.findall(rb"(?m)^module ([^\s]+)\s*$", v.read(root / "go.mod"))
    if len(module) != 1:
        v.reject("go-module-format")
    name = module[0].decode("utf-8")
    v.inside(root, name)
    result = {}
    for path, item in files.items():
        if not path.endswith(".go") or item["sha256"] is None:
            continue
        target = v.inside(root, path)
        data = v.read(target, maximum=LIMIT)
        if v.digest(data) != item["sha256"]:
            v.reject("go-source-drift", path)
        # Go's generated marker is meaningful only before the package declaration.
        declaration = re.search(rb"(?m)^package[ \t]", data)
        prefix = data[: declaration.start()] if declaration else data
        kind = "test" if path.endswith("_test.go") else "generated" if GENERATED.search(prefix) else "owned"
        result[path] = {"kind": kind, "sha256": item["sha256"], "data": data}
    if not result:
        v.reject("go-source-empty")
    return name, result


def packages(data: bytes, files: dict[str, dict], module: str, root: Path) -> tuple[dict[str, dict], dict[str, str]]:
    """Use native build metadata without inferring platform applicability from absent counters."""
    result, selected, claimed = {}, {}, set()
    for value in stream(data):
        directory = value.get("Dir")
        if not isinstance(directory, str) or not Path(directory).is_absolute():
            v.reject("go-package-directory")
        try:
            relative = Path(directory).relative_to(root).as_posix()
        except ValueError:
            v.reject("go-package-outside", directory)
        relative = "" if relative == "." else relative
        if relative:
            v.inside(root, relative)
        expected = module + ("/" + relative if relative else "")
        identity = value.get("Module", {})
        if (
            value.get("ImportPath") != expected
            or identity.get("Path") != module
            or identity.get("Main") is not True
            or identity.get("Dir") != str(root)
            or value.get("Incomplete")
            or value.get("Error")
            or value.get("DepsErrors")
            or expected in result
        ):
            v.reject("go-package-identity", expected)
        names, active = set(), []
        for field in FIELDS:
            entries = value.get(field, [])
            if not isinstance(entries, list):
                v.reject("go-package-files", field)
            for entry in entries:
                if not isinstance(entry, str) or "/" in entry or not entry.endswith(".go") or entry in names:
                    v.reject("go-package-file", field)
                names.add(entry)
                path = relative + "/" + entry if relative else entry
                if path not in files or path in claimed:
                    v.reject("go-package-unregistered", path)
                claimed.add(path)
                if field in ("GoFiles", "CgoFiles"):
                    if files[path]["kind"] == "test":
                        v.reject("go-test-as-production", path)
                    selected[module + "/" + path] = path
                    active.append(path)
        result[expected] = {"files": sorted(active), "tests": len(value.get("TestGoFiles", [])) + len(value.get("XTestGoFiles", []))}
    return result, selected


def profile(data: bytes, files: dict[str, dict], selected: dict[str, str]) -> tuple[str, list[dict], int]:
    """Preserve zero counters and merge only identical native blocks of a single profile mode."""
    if len(data) > LIMIT:
        v.reject("go-profile-size")
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError:
        v.reject("go-profile-encoding")
    if not lines or lines[0] not in ("mode: set", "mode: count", "mode: atomic"):
        v.reject("go-profile-mode")
    mode, blocks, records = lines[0][6:], {}, 0
    for line in lines[1:]:
        match = BLOCK.fullmatch(line)
        if match is None:
            v.reject("go-profile-block")
        native, *numbers = match.groups()
        if native not in selected:
            v.reject("go-profile-unregistered", native)
        if any(len(number) > 19 for number in numbers):
            v.reject("go-profile-counter")
        start, column, end, last, statements, count = map(int, numbers)
        if (
            max(statements, count) > 2**63 - 1
            or (start, column) > (end, last)
            or ((start, column) == (end, last) and statements != 0)
            or (mode == "set" and count > 1)
        ):
            v.reject("go-profile-counter")
        path = selected[native]
        rows = files[path]["data"].splitlines(keepends=True)
        if end > len(rows) or column > len(rows[start - 1]) + 1 or last > len(rows[end - 1]) + 1:
            v.reject("go-profile-position", path)
        key = (path, start, column, end, last)
        if key in blocks:
            if blocks[key]["statements"] != statements:
                v.reject("go-profile-conflicting-block", path)
            blocks[key]["count"] = max(count, blocks[key]["count"]) if mode == "set" else count + blocks[key]["count"]
        else:
            blocks[key] = {"file": path, "span": [start, column, end, last], "statements": statements, "count": count}
        records += 1
    if not blocks:
        v.reject("go-profile-empty")
    return mode, [blocks[key] for key in sorted(blocks)], records


def configuration(check: dict) -> None:
    """Freeze the sole-file Command structural scope and both native compiler-profile variants."""
    arguments = ["go", "test", "-json"]
    if "-race" in check["argv"]:
        arguments.append("-race")
    arguments += ["-count=1", "-p=2", "-parallel=1", "-timeout=180s", "-covermode=atomic", "-coverprofile={run}/command.cover", "./internal/command"]
    required = {
        "COMMAND-BOUNDARY": ("TestVerification", 1),
        "COMMAND-MCDC": ("TestDecisions", 15),
        "COMMAND-DECISION-INVENTORY": ("TestDecisionInventory", 12),
        "COMMAND-ASSURANCE": ("TestDecisionInventory", 12),
    }
    tests = {"TestDecisionInventory", "TestDecisions", "TestParse", "TestVerification"}
    if "faults" in check:
        tests.add("TestFault")
        required["COMMAND-FAULT"] = ("TestFault", 63)
    if any(item["contract"] == "COMMAND-ISOLATION" for item in check["probes"]):
        required["COMMAND-ISOLATION"] = ("TestDecisionInventory", 16)
    if any(item["contract"] == "COMMAND-NUMERIC" for item in check["probes"]):
        tests.add("TestNumeric")
        required["COMMAND-NUMERIC"] = ("TestNumeric", 1)
        required["COMMAND-NUMERIC-CONTROLS"] = ("TestNumeric", 19)
    if check.get("model") == "command-state-v1":
        tests.update(("TestModel", "TestModelOracle"))
        required["COMMAND-MODEL"] = ("TestModel", 6220)
        required["COMMAND-MODEL-CONTROLS"] = ("TestModelOracle", 10)
    if any(item["contract"] == "COMMAND-COMPATIBILITY" for item in check["probes"]):
        tests.add("TestCompatibility")
        required["COMMAND-COMPATIBILITY"] = ("TestCompatibility", 182)
    actual = {item["contract"]: (item["test"], item["minimum_hits"]) for item in check["probes"]}
    if (
        check.get("coverage") != "command-structure-v1"
        or check["component"] != "command"
        or check["package"] != "github.com/eosforge/astra/internal/command"
        or len(check["expected_tests"]) != len(tests)
        or set(check["expected_tests"]) != tests
        or len(check["probes"]) != len(required)
        or v.encode(actual) != v.encode(required)
        or check["argv"] != arguments
    ):
        v.reject("command-structure-configuration")


def observations(data: bytes | None, check: dict, root: Path) -> dict[str, int]:
    """Reconcile the compiler's complete block denominator with the frozen Command source and decision domain."""
    configuration(check)
    if data is None:
        v.reject("command-profile-missing")
    name = "internal/command/flags.go"
    directory = v.inside(root, "internal/command")
    if sorted(path.relative_to(directory).as_posix() for path in directory.rglob("*.go") if not path.name.endswith("_test.go")) != ["flags.go"]:
        v.reject("command-structure-scope")
    source = v.read(v.inside(root, name))
    if v.digest(source) != "a85cf555ec0387a915624a672fc6037362b6b3c6277684f458f747db9c7a1979":
        v.reject("command-structure-source")
    mode, blocks, _ = profile(data, {name: {"data": source}}, {"github.com/eosforge/astra/" + name: name})
    # Original ordinary/Race compiler profiles independently agree on these ten weighted blocks.
    expected = [
        ([15, 2, 15, 24], 1),
        ([16, 3, 17, 1], 1),
        ([18, 2, 18, 29], 1),
        ([22, 2, 22, 15], 1),
        ([23, 3, 24, 1], 1),
        ([25, 2, 26, 30], 2),
        ([30, 2, 32, 1], 2),
        ([36, 2, 36, 41], 1),
        ([36, 43, 36, 86], 1),
        ([37, 2, 37, 31], 1),
    ]
    if mode != "atomic" or [(item["span"], item["statements"]) for item in blocks] != expected:
        v.reject("command-profile-denominator")
    if any(item["count"] == 0 for item in blocks):
        v.reject("command-profile-uncovered")
    # This is the completed inventory oracle's hit count, not a fabricated compiler statement count.
    return {"COMMAND-ASSURANCE": 12}


def summary(data: bytes, metadata: bytes, source: dict, root: Path) -> dict:
    """Report the complete source inventory and raw statement gaps, never branch or MC/DC qualification."""
    module, files = sources(source, root)
    groups, selected = packages(metadata, files, module, root)
    mode, blocks, records = profile(data, files, selected)
    active, observed = set(selected.values()), {item["file"] for item in blocks}
    totals, entries = {}, []
    for path, item in sorted(files.items()):
        spans = [block for block in blocks if block["file"] == path]
        actual = {
            "statements": sum(block["statements"] for block in spans),
            "statements_hit": sum(block["statements"] for block in spans if block["count"] > 0),
        }
        target = totals.setdefault(item["kind"], {"files": 0, "statements": 0, "statements_hit": 0})
        target["files"] += 1
        for key, count in actual.items():
            target[key] += count
        entries.append({"file": path, "kind": item["kind"], "sha256": item["sha256"], "selected": path in active, "native_blocks": len(spans), **actual})
    return {
        "status": "collected",
        "qualification": "not-evaluated",
        "unit": "native Go statement blocks; no branch, decision or MC/DC evidence",
        "module": module,
        "mode": mode,
        "native_records": records,
        "unique_blocks": len(blocks),
        "totals": totals,
        "scope": {
            "declared": sorted(path for path, item in files.items() if item["kind"] == "owned"),
            "selected": sorted(active),
            "without_build_selection": sorted(path for path, item in files.items() if item["kind"] == "owned" and path not in active),
            "without_native_counters": sorted(path for path in active - observed if files[path]["kind"] == "owned"),
            "zero_statement_files": sorted(item["file"] for item in entries if item["kind"] == "owned" and item["selected"] and item["statements"] == 0),
            "untested_packages": sorted(name for name, item in groups.items() if item["tests"] == 0),
        },
        "packages": groups,
        "files": entries,
        "unhit": [item for item in blocks if item["count"] == 0 and item["statements"] > 0],
    }


def completed(directory: Path, reference: dict, root: Path) -> tuple[dict, bytes]:
    """Verify native command records, raw streams and their executor-owned working directory."""
    value = v.decode(v.reference(directory, reference))
    parent = v.inside(directory, reference["path"]).parent
    process = v.decode(v.read(v.inside(parent, value["id"] + ".process.json")))
    if (
        type(value.get("exit_code")) is not int
        or value.get("exit_code") != 0
        or value.get("complete") is not True
        or value.get("cleanup") is not True
        or value.get("termination") != "exited"
        or process.get("argv") != value.get("resolved_argv", value.get("argv"))
        or process.get("cwd") != str(root)
        or v.stamp(value["finished_at"]) < v.stamp(value["started_at"])
    ):
        v.reject("go-native-incomplete")
    data = v.reference(parent, value["stdout"], LIMIT)
    v.reference(parent, value["stderr"], LIMIT)
    return value, data


def terminals(data: bytes, groups: dict[str, dict]) -> dict[str, str]:
    """Require every selected package's native terminal event, retaining packages without tests."""
    states, tests = {}, {}
    for line in data.splitlines():
        value = v.decode(line)
        name, action, test = value.get("Package"), value.get("Action"), value.get("Test")
        if name not in groups or action not in {"start", "run", "pause", "cont", "pass", "skip", "fail", "output", "bench"}:
            v.reject("go-native-event")
        if states.get(name) in ("pass", "untested"):
            v.reject("go-native-after-terminal", name)
        if action == "fail":
            v.reject("go-native-failure", name)
        if test:
            if not isinstance(test, str) or states.get(name) != "running":
                v.reject("go-native-test-order")
            key = (name, test)
            if action == "run":
                if key in tests:
                    v.reject("go-native-duplicate-test")
                tests[key] = "running"
            elif action in ("pass", "skip"):
                if tests.get(key) != "running" or action != "pass":
                    v.reject("go-native-test-incomplete", test)
                tests[key] = "pass"
        elif action == "start":
            if name in states:
                v.reject("go-native-duplicate-package")
            states[name] = "running"
        elif action in ("pass", "skip"):
            if states.get(name) != "running" or (action == "skip" and groups[name]["tests"]):
                v.reject("go-native-package-incomplete", name)
            states[name] = "pass" if groups[name]["tests"] else "untested"
    if set(states) != set(groups) or any(state == "running" for state in states.values()) or any(state != "pass" for state in tests.values()):
        v.reject("go-native-missing-terminal")
    for name, item in groups.items():
        if item["tests"] and not any(package == name for package, _ in tests):
            v.reject("go-native-empty-tests", name)
    return states


def collect(directory: Path, output: Path, root: Path) -> int:
    """Import a same-source whole-module native bundle without running Go or claiming gate eligibility."""
    bundle = v.decode(v.read(directory / "bundle.json"))
    if set(bundle) != {"version", "source", "packages", "tests", "profile"} or type(bundle["version"]) is not int or bundle["version"] != 1:
        v.reject("go-bundle-format")
    source = v.decode(v.reference(directory, bundle["source"]))
    if v.source(root) != source:
        v.reject("go-workspace-drift")
    listing, metadata = completed(directory, bundle["packages"], root)
    testing, events = completed(directory, bundle["tests"], root)
    executable = listing["argv"][0]
    if (
        listing["argv"] != [executable, "list", "-json", "./..."]
        or testing["argv"][:2] != [executable, "test"]
        or listing["executable_sha256"] != testing["executable_sha256"]
        or listing["platform"] != testing["platform"]
        or {key: value for key, value in listing["resolved_environment"].items() if key != "TMPDIR"}
        != {key: value for key, value in testing["resolved_environment"].items() if key != "TMPDIR"}
        or v.stamp(listing["finished_at"]) > v.stamp(testing["started_at"])
    ):
        v.reject("go-native-configuration")
    arguments = testing["argv"][2:]
    module, _ = sources(source, root)
    # Relative coverage patterns also match dependencies cached physically below the project root.
    fixed = {"-json", "-count=1", "-coverpkg=" + module + "/...", "-covermode=atomic", "./..."}
    profile_path = v.inside(directory, bundle["profile"]["path"])
    required = fixed | {"-coverprofile=" + str(profile_path)}
    keys = [argument.split("=", 1)[0] for argument in arguments]
    if (
        not required <= set(arguments)
        or len(keys) != len(set(keys))
        or any(
            argument not in required and argument != "-race" and not re.fullmatch(r"-(?:p|parallel)=[1-9][0-9]*|-timeout=[1-9][0-9]*s", argument)
            for argument in arguments
        )
    ):
        v.reject("go-native-instrumentation")
    data = v.reference(directory, bundle["profile"], LIMIT)
    result = summary(data, metadata, source, root)
    result["native_terminals"] = terminals(events, result["packages"])
    if result["mode"] != "atomic" or v.source(root) != source:
        v.reject("go-collection-drift")
    output.mkdir(parents=True, exist_ok=False)
    result["inputs"] = {"bundle": v.write_new(output / "bundle.json", bundle), "source": bundle["source"], "trust": "local"}
    v.write_new(output / "summary.json", result)
    print(json.dumps({key: result[key] for key in ("status", "qualification", "unit", "totals", "scope")}), flush=True)
    return 0
