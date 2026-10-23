"""Export raw GCC and Go counters without inventing exclusions or qualification."""

import argparse
import json
from pathlib import Path
import shlex
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import build, statements, verify as v

# Native compiler reports have a separate byte budget; policy/configuration JSON keeps its smaller default.
LIMIT = 32 * 1024 * 1024


def decode(data: bytes) -> dict | list | str | int | float | bool | None:
    """Parse compiler-counter JSON within its declared budget, preserving strict duplicate/depth/number checks."""
    return v.decode(data, maximum=LIMIT)


def owned(path: Path, root: Path) -> bool:
    """Select maintained C++ production and benchmark tools; retain test/generated/system exclusions."""
    try:
        name = path.resolve().relative_to(root).as_posix()
    except ValueError:
        return False
    return (
        any(
            name.startswith(prefix)
            for prefix in ("common/src/", "common/include/", "star/src/", "pulsar/src/", "comet/cpp/src/", "comet/cpp/include/", "bench/")
        )
        and "/generated/" not in name
        and not path.name.endswith("_test.cpp")
    )


def counts(record: dict) -> dict[str, int]:
    """Preserve native per-object/function counters, including uncovered and compiler-generated branches."""
    total = {key: 0 for key in ("lines", "lines_hit", "branches", "branches_hit", "conditions", "conditions_hit")}
    for line in record["lines"]:
        if type(line["count"]) is not int or line["count"] < 0:
            v.reject("line-counter-invalid")
        total["lines"] += 1
        total["lines_hit"] += line["count"] > 0
        for branch in line["branches"]:
            if type(branch["count"]) is not int or branch["count"] < 0:
                v.reject("branch-counter-invalid")
            total["branches"] += 1
            total["branches_hit"] += branch["count"] > 0
        conditions = line.get("conditions")
        if not isinstance(conditions, list):
            v.reject("condition-counter-invalid")
        for condition in conditions:
            if not isinstance(condition, dict) or set(condition) != {"count", "covered", "not_covered_true", "not_covered_false"}:
                v.reject("condition-counter-invalid")
            count, hit = condition["count"], condition["covered"]
            if type(count) is not int or type(hit) is not int or count <= 0 or count % 2 or not 0 <= hit <= count:
                v.reject("condition-counter-invalid")
            # GCC reports two outcomes per term. Each missing polarity contributes separately to the deficit.
            absent = 0
            for polarity in ("not_covered_true", "not_covered_false"):
                terms = condition[polarity]
                if not isinstance(terms, list) or any(type(term) is not int or not 0 <= term < count // 2 for term in terms) or len(set(terms)) != len(terms):
                    v.reject("condition-counter-invalid")
                absent += len(terms)
            if count - absent != hit:
                v.reject("condition-counter-invalid")
            total["conditions"] += count
            total["conditions_hit"] += hit
    return total


def recipe(unit: dict) -> list[str]:
    """Read the actual GCC invocation; ambiguous shell or response-file recipes cannot prove an output."""
    command, arguments = unit.get("command"), unit.get("arguments")
    parsed = None
    if command is not None:
        if not isinstance(command, str) or not command:
            v.reject("coverage-recipe-metadata")
        try:
            parsed = shlex.split(command)
        except ValueError:
            v.reject("coverage-recipe-metadata")
    if arguments is not None:
        if not isinstance(arguments, list) or not arguments or any(not isinstance(arg, str) or not arg for arg in arguments):
            v.reject("coverage-recipe-metadata")
        if parsed is not None and parsed != arguments:
            v.reject("coverage-recipe-mismatch")
        parsed = arguments
    if (
        not parsed
        or parsed.count("-o") != 1
        or parsed.count("-c") != 1
        or any(arg.startswith("@") or arg in {"&&", "||", "|", ";", ">", "<"} for arg in parsed)
        or any(parsed.index(flag) + 1 == len(parsed) or parsed[parsed.index(flag) + 1].startswith("-") for flag in ("-o", "-c"))
    ):
        v.reject("coverage-recipe-metadata")
    return parsed


def note(unit: dict, root: Path, build: Path) -> Path:
    """Locate the native compilation note, keeping generated recipes and built objects distinct."""
    directory, output, source = (unit.get(key) for key in ("directory", "output", "file"))
    if any(not isinstance(value, str) or not value for value in (directory, output, source)):
        v.reject("coverage-recipe-metadata")
    directory = Path(directory)
    if not directory.is_absolute() or not build.is_relative_to(root / "build") or not directory.resolve().is_relative_to(build):
        v.reject("coverage-recipe-boundary")
    arguments = recipe(unit)
    path = directory / arguments[arguments.index("-o") + 1]
    actual = path.resolve()
    aliases = [base / output for base in (build, directory)]
    declared = [alias.resolve() for alias in aliases]
    if not actual.is_relative_to(build) or not any(candidate.is_relative_to(build) for candidate in declared):
        v.reject("coverage-recipe-boundary")
    # CMake may describe output from the top build directory while -o is relative to the compiler's cwd.
    if actual not in declared or (directory / arguments[arguments.index("-c") + 1]).resolve() != (directory / source).resolve():
        v.reject("coverage-recipe-mismatch")
    native = path.with_suffix(".gcno")
    if any(alias.is_symlink() for target in (directory, path, native, *aliases) for alias in (target, *target.parents) if alias.is_relative_to(root / "build")):
        v.reject("coverage-recipe-boundary")
    return native.resolve()


def inventory(names: list[str], units: list[dict], entries: list[dict], root: Path, directory: Path) -> dict[str, list[str]]:
    """Reconcile counters with source ownership so unbuilt files cannot disappear from the denominator."""
    suffixes = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx"}
    declared = {name for name in names if Path(name).suffix in suffixes and owned(root / name, root)}
    configured = {Path(item["file"]).resolve().relative_to(root).as_posix() for item in units}
    compiled = {Path(item["file"]).resolve().relative_to(root).as_posix() for item in units if note(item, root, directory).is_file()}
    observed = {item["file"] for item in entries if item["lines"] > 0}
    return {
        "declared": sorted(declared),
        "configured_translation_units": sorted(configured),
        "compiled": sorted(compiled),
        "observed": sorted(observed),
        "uncompiled_translation_units": sorted(name for name in declared - compiled if Path(name).suffix in {".c", ".cc", ".cpp", ".cxx"}),
        "without_native_counters": sorted(declared - observed),
        "unregistered_counters": sorted(observed - declared),
    }


def main(arguments: list[str] | None = None) -> int:
    """Read only a completed isolated coverage build, preserving unexecuted objects and all raw JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--build", type=Path, help="Completed GCC coverage build")
    selection.add_argument("--go", type=Path, help="Completed whole-Go native bundle; no implicit test execution")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(arguments)
    root = build.ROOT.resolve()
    directory, output = (args.build or args.go).resolve(), args.output.resolve()
    if not directory.is_relative_to(root / "build") or not output.is_relative_to(root / "build") or output.is_relative_to(directory):
        v.reject("coverage-output-boundary")
    if args.go:
        return statements.collect(directory, output, root)
    commands = v.decode(v.read(directory / "compile_commands.json"))
    units = [entry for entry in commands if owned(Path(entry["file"]), root)]
    missing = [entry["file"] for entry in units if any(flag not in recipe(entry) for flag in ("--coverage", "-fcondition-coverage"))]
    notes = sorted(directory.rglob("*.gcno"))
    if not notes or not units:
        v.reject("coverage-empty")
    output.mkdir(parents=True, exist_ok=False)
    tool = build.CACHE / "tools/gcc-16.2.0/bin/gcov"
    entries, excluded, errors = [], [], []
    totals = {key: 0 for key in ("lines", "lines_hit", "branches", "branches_hit", "conditions", "conditions_hit")}
    for index, note in enumerate(notes):
        before = {str(path.relative_to(directory)): v.file_digest(path) for path in (note, note.with_suffix(".gcda")) if path.exists()}
        argv = [str(tool), "-j", "-t", "-b", "-c", "-g", str(note)]
        capture = output / str(index)
        capture.mkdir()
        record = v.execute(
            {"id": "gcov", "argv": argv, "environment": {**build.environment(), "TMPDIR": str(capture / "tmp")}, "timeout_s": 60, "log_bytes": LIMIT},
            root,
            capture,
            "linux-amd64-cgo",
        )
        v.write_new(capture / "record.json", {**record, "inputs": before})
        stdout = {**record["stdout"], "path": f"{index}/" + record["stdout"]["path"]}
        if record["exit_code"] or not record["complete"] or not record["cleanup"]:
            errors.append(str(note.relative_to(directory)))
            continue
        value = decode(v.read(output / stdout["path"], maximum=LIMIT))
        if value.get("format_version") != "2" or value.get("gcc_version") != "16.2.0":
            v.reject("coverage-format")
        for record in value["files"]:
            path = Path(value["current_working_directory"]) / record["file"]
            if not owned(path, root):
                excluded.append({"object": str(note.relative_to(directory)), "file": str(path), "reason": "outside maintained C++ production scope"})
                continue
            actual = counts(record)
            for key, number in actual.items():
                totals[key] += number
            entries.append({"file": path.resolve().relative_to(root).as_posix(), "object": str(note.relative_to(directory)), "raw": stdout, **actual})
        if before != {str(path.relative_to(directory)): v.file_digest(path) for path in (note, note.with_suffix(".gcda")) if path.exists()}:
            v.reject("coverage-input-drift", str(note))
    # Reporting success means counters were collected, not that the development gate's thresholds passed.
    source = v.source(root)
    scope = inventory([item["path"] for item in source["files"] if item["sha256"] is not None], units, entries, root, directory)
    source_reference = v.write_new(output / "source.json", source)
    complete = bool(entries) and not errors and not missing and not scope["unregistered_counters"]
    summary = {
        "status": "collected" if complete else "blocked",
        "qualification": "not-evaluated",
        "unit": "native object/function line instances; no template deduplication or branch exclusions",
        "source": source_reference,
        "scope": scope,
        "totals": totals,
        "missing_instrumentation": missing,
        "tool_errors": errors,
        "files": entries,
        "exclusions": excluded,
    }
    v.write_new(output / "summary.json", summary)
    print(json.dumps({key: summary[key] for key in ("status", "unit", "totals", "missing_instrumentation", "tool_errors")}), flush=True)
    return 0 if complete else 2


if __name__ == "__main__":
    sys.exit(main())
