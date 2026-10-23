"""Reconcile Go Boolean traces, candidate pairs and conservative independence proofs without granting component qualification."""

from collections.abc import Iterable, Sequence
import argparse
from pathlib import Path, PurePosixPath
import re
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import statements, verify as v

# Match the native recorder's finite vector domain and bound pair search before consuming observations.
VECTORS = 65536
COMPARISONS = 2_000_000
KINDS = {"if", "for", "case", "boolean", "return"}


def fields(value: object, expected: Iterable[str], reason: str) -> None:
    """Reject omitted or invented fields instead of silently interpreting a changed evidence format."""
    if not isinstance(value, dict) or set(value) != set(expected):
        v.reject("logic-" + reason)


def position(value: dict) -> None:
    """Require exact integer byte coordinates, without accepting booleans as integers."""
    fields(value, ("offset", "line", "column"), "position")
    if any(type(value[k]) is not int or value[k] < (0 if k == "offset" else 1) for k in value):
        v.reject("logic-position")


def span(value: dict) -> None:
    """Check ordered, nonempty native source intervals."""
    position(value["begin"])
    position(value["end"])
    if value["begin"]["offset"] >= value["end"]["offset"]:
        v.reject("logic-span")


def inventory(manifest: dict, *, allow_empty: bool = False) -> dict[str, dict]:
    """Validate the Boolean forest; a separate control-only reader may validate an empty forest's file metadata."""
    typed = isinstance(manifest, dict) and type(manifest.get("version")) is int and manifest["version"] in {2, 3}
    partition = typed and manifest["version"] == 3
    fields(
        manifest,
        ("version", "source_sha256", "qualification", "basis", "files", "observed") + (("typing",) if typed else ()) + (("partition",) if partition else ()),
        "manifest",
    )
    if (
        type(manifest["version"]) is not int
        or manifest["version"] not in {1, 2, 3}
        or partition
        and manifest["partition"] != "native-go-files"
        or manifest["qualification"] != "not-evaluated"
        or not isinstance(manifest["basis"], str)
        or not manifest["basis"]
        or not isinstance(manifest["source_sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", manifest["source_sha256"])
        or not isinstance(manifest["files"], list)
        or not manifest["files"]
    ):
        v.reject("logic-manifest")
    files, result, selected = set(), {}, []
    for file in manifest["files"]:
        fields(file, ("file", "sha256", "functions", "decisions", "controls"), "file")
        name = file["file"]
        if not isinstance(name, str):
            v.reject("logic-file")
        v.inside(Path.cwd(), name)
        if name in files or not name.endswith(".go") or not isinstance(file["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", file["sha256"]):
            v.reject("logic-file")
        files.add(name)
        for key in ("functions", "decisions", "controls"):
            if not isinstance(file[key], list):
                v.reject("logic-file")
        for item in file["functions"]:
            fields(item, ("name", "begin", "end"), "function")
            span(item)
            if not isinstance(item["name"], str) or not item["name"]:
                v.reject("logic-function")
        for item in file["controls"]:
            fields(item, ("kind", "begin", "end"), "control")
            span(item)
            if not isinstance(item["kind"], str) or item["kind"] not in {"switch", "type-switch", "select", "range", "loop", "go", "defer"}:
                v.reject("logic-control")
        for item in file["decisions"]:
            fields(item, ("id", "kind", "text", "begin", "end", "tree", "root", "atoms"), "decision")
            span(item)
            identity = f"{name}:{item['begin']['offset']}"
            if (
                item["id"] != identity
                or identity in result
                or not isinstance(item["kind"], str)
                or item["kind"] not in KINDS
                or not isinstance(item["text"], str)
                or not item["text"]
            ):
                v.reject("logic-decision")
            atoms, tree = item["atoms"], item["tree"]
            if not isinstance(atoms, list) or not 1 <= len(atoms) <= 64 or not isinstance(tree, list) or not 1 <= len(tree) <= 256:
                v.reject("logic-tree-size")
            previous = item["begin"]["offset"]
            for atom in atoms:
                fields(atom, ("text", "begin", "end"), "atom")
                span(atom)
                if (
                    not isinstance(atom["text"], str)
                    or not atom["text"]
                    or not previous <= atom["begin"]["offset"] < atom["end"]["offset"] <= item["end"]["offset"]
                ):
                    v.reject("logic-atom")
                previous = atom["end"]["offset"]
            parents, leaves = [0] * len(tree), []
            for index, node in enumerate(tree):
                if not isinstance(node, dict) or not isinstance(node.get("kind"), str):
                    v.reject("logic-node")
                kind = node["kind"]
                if kind == "atom":
                    fields(node, ("kind", "atom"), "node")
                    if type(node["atom"]) is not int or not 0 <= node["atom"] < len(atoms):
                        v.reject("logic-leaf")
                    leaves.append(node["atom"])
                else:
                    fields(node, ("kind", "children"), "node")
                    children = node["children"]
                    if kind not in {"and", "or", "not"} or not isinstance(children, list) or len(children) != (1 if kind == "not" else 2):
                        v.reject("logic-children")
                    if len(children) == 2 and all(type(child) is int for child in children) and children[0] >= children[1]:
                        v.reject("logic-child-order")
                    for child in children:
                        if type(child) is not int or not 0 <= child < index:
                            v.reject("logic-postorder")
                        parents[child] += 1
            if type(item["root"]) is not int or item["root"] != len(tree) - 1 or parents != [1] * (len(tree) - 1) + [0] or leaves != list(range(len(atoms))):
                v.reject("logic-tree")
            result[identity] = item
            if item["kind"] != "boolean":
                selected.append(identity)
    if typed:
        annotations = manifest["typing"]
        fields(annotations, ("metadata_sha256", "package", "files", "inactive", "results", "constants", "exports"), "typing")
        if (
            not isinstance(annotations["metadata_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", annotations["metadata_sha256"])
            or not isinstance(annotations["package"], str)
            or not annotations["package"]
            or not isinstance(annotations["results"], dict)
            or not isinstance(annotations["exports"], dict)
            or len(annotations["exports"]) > 4096
        ):
            v.reject("logic-typing")
        for key in ("files", "inactive", "constants"):
            names = annotations[key]
            if not isinstance(names, list) or any(not isinstance(name, str) for name in names) or names != sorted(set(names)):
                v.reject("logic-typing-domain")
        active, inactive, constants = (set(annotations[key]) for key in ("files", "inactive", "constants"))
        if not active or active & inactive or active | inactive != files:
            v.reject("logic-typing-files")
        if not partition and any(file["decisions"] or file["controls"] for file in manifest["files"] if file["file"] in inactive):
            v.reject("logic-typing-inactive")
        runtime = {item["id"] for file in manifest["files"] if file["file"] in active for item in file["decisions"]}
        if constants - runtime or any(result[name]["kind"] != "boolean" for name in constants):
            v.reject("logic-typing-constants")
        if set(annotations["results"]) != runtime - constants:
            v.reject("logic-typing-results")
        for spelling in annotations["results"].values():
            if not isinstance(spelling, str) or len(spelling) > 256 or not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)?", spelling):
                v.reject("logic-typing-spelling")
        for name, archive in annotations["exports"].items():
            fields(archive, ("path", "sha256", "bytes"), "typing-export")
            if (
                not isinstance(name, str)
                or not name
                or not isinstance(archive["path"], str)
                or not (Path(archive["path"]).is_absolute() or PurePosixPath(archive["path"]).is_absolute())
                or not isinstance(archive["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", archive["sha256"])
                or type(archive["bytes"]) is not int
                or not 0 < archive["bytes"] <= 64 * 1024**2
            ):
                v.reject("logic-typing-export")
        selected = [name for name in result if name in annotations["results"]]
    if manifest["observed"] != selected or not selected and not allow_empty:
        v.reject("logic-selected")
    return result


def bind_typing(
    manifest: dict, metadata: bytes, root: Path, directory: str, module: str, *, package: str | None = None, module_root: Path | None = None
) -> None:
    """Reconcile typed annotations with original compiler selection and every actually consumed gc archive."""
    annotations = manifest["typing"]
    if annotations["metadata_sha256"] != v.digest(metadata) or annotations["package"] != (module + "/" + directory if package is None else package):
        v.reject("logic-typing-binding")
    packages = {}
    for package in statements.stream(metadata):
        name = package.get("ImportPath")
        if (
            not isinstance(name, str)
            or not name
            or name in packages
            or not isinstance(package.get("Name"), str)
            or not package["Name"]
            or package.get("Incomplete", False) is not False
            or package.get("Error") is not None
            or package.get("DepsErrors") not in (None, [])
        ):
            v.reject("logic-typing-package")
        packages[name] = package
    if len(packages) > 4096:
        v.reject("logic-typing-capacity")
    selected = [p for p in packages.values() if p.get("Dir") == str(v.inside(root, directory))]
    if len(selected) != 1 or selected[0]["ImportPath"] != annotations["package"] or selected[0].get("CgoFiles") not in (None, []):
        v.reject("logic-typing-selection")
    selected = selected[0]
    if module_root is not None:
        identity = selected.get("Module", {})
        if identity.get("Path") != module or identity.get("Main") is not True or identity.get("Dir") != str(module_root):
            v.reject("logic-typing-module")
    names = {}
    for key in ("GoFiles", "IgnoredGoFiles"):
        values = selected.get(key, [])
        if not isinstance(values, list) or any(not isinstance(name, str) or "/" in name or not name.endswith(".go") for name in values):
            v.reject("logic-typing-native-files")
        for name in values:
            v.inside(root, directory + "/" + name)
        if len(values) != len(set(values)):
            v.reject("logic-typing-native-files")
        names[key] = {directory + "/" + name for name in values if not name.endswith("_test.go")}
    if names["GoFiles"] != set(annotations["files"]) or names["IgnoredGoFiles"] != set(annotations["inactive"]):
        v.reject("logic-typing-native-denominator")
    total = 0
    for name, archive in annotations["exports"].items():
        if name not in packages or packages[name].get("Export") != archive["path"]:
            v.reject("logic-typing-native-export")
        path = Path(archive["path"])
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            v.reject("logic-typing-export-outside")
        if not relative.startswith("build/cache/go/") or v.inside(root, relative) != path:
            v.reject("logic-typing-export-outside")
        data = v.read(path, 64 * 1024**2)
        total += len(data)
        if len(data) != archive["bytes"] or v.digest(data) != archive["sha256"] or total > 256 * 1024**2:
            v.reject("logic-typing-export-drift")


def evaluate(decision: dict, vector: str) -> bool:
    """Execute only the recorded Boolean tree; skipped values must stay unknown and cannot affect the result."""
    visited = set()

    def visit(index: int) -> bool:
        """Interpret one validated tree node in native left-to-right short-circuit order."""
        node = decision["tree"][index]
        kind = node["kind"]
        if kind == "atom":
            atom = node["atom"]
            if vector[atom] == "0" or atom in visited:
                v.reject("logic-unobserved-evaluation")
            visited.add(atom)
            return vector[atom] == "2"
        left = visit(node["children"][0])
        if kind == "not":
            return not left
        return left and visit(node["children"][1]) if kind == "and" else left or visit(node["children"][1])

    result = visit(decision["root"])
    if visited != {i for i, value in enumerate(vector) if value != "0"}:
        v.reject("logic-extra-evaluation")
    return result


def observe(manifest: dict, data: bytes, package: str, test_files: int) -> tuple[dict[str, dict[tuple[str, bool], int]], int]:
    """Require complete native test events and reconcile every process receipt against the exact selected tree."""
    decisions = inventory(manifest)
    if len(data) > statements.LIMIT:
        v.reject("logic-stream-size")
    statements.terminals(data, {package: {"tests": test_files}})
    events = [v.decode(line) for line in data.splitlines()]
    parts = [event.get("Output", "") for event in events]
    if any(not isinstance(part, str) for part in parts):
        v.reject("logic-output")
    stream = "".join(parts)
    processes, rows = set(), {identity: {} for identity in decisions}
    selected = set(manifest["observed"])
    for line in stream.splitlines():
        marker = "GO-DECISIONS "
        if marker not in line:
            continue
        if line.count(marker) != 1:
            v.reject("logic-framing")
        receipt = v.decode(line.split(marker, 1)[1].encode(), maximum=statements.LIMIT)
        fields(receipt, ("pid", "code", "rows"), "receipt")
        pid = receipt["pid"]
        if (
            type(pid) is not int
            or pid <= 0
            or pid in processes
            or type(receipt["code"]) is not int
            or receipt["code"] != 0
            or not isinstance(receipt["rows"], list)
            or len(receipt["rows"]) > VECTORS
        ):
            v.reject("logic-process")
        processes.add(pid)
        seen = set()
        for row in receipt["rows"]:
            fields(row, ("id", "values", "result", "hits"), "row")
            identity, vector, result, hits = (row[key] for key in ("id", "values", "result", "hits"))
            if not isinstance(identity, str) or identity not in selected:
                v.reject("logic-unregistered")
            if (
                not isinstance(vector, str)
                or len(vector) != len(decisions[identity]["atoms"])
                or set(vector) - set("012")
                or type(result) is not bool
                or type(hits) is not int
                or not 1 <= hits <= 2**64 - 1
            ):
                v.reject("logic-vector")
            key = (identity, vector, result)
            if key in seen or evaluate(decisions[identity], vector) != result:
                v.reject("logic-observation")
            seen.add(key)
            rows[identity][(vector, result)] = rows[identity].get((vector, result), 0) + hits
    if not processes or not any(rows.values()) or sum(len(values) for values in rows.values()) > VECTORS:
        v.reject("logic-empty-or-size")
    return rows, len(processes)


def cube(decision: dict, values: Sequence[str]) -> bool | None:
    """Evaluate a validated read-once Boolean tree for every completion of its unknown operands.

    True/False certify a constant result throughout the cube; None preserves
    uncertainty. This algebra examines recorded values without calling a source
    expression or inventing the value of an unexecuted operand.
    """
    results = []
    for node in decision["tree"]:
        kind = node["kind"]
        if kind == "atom":
            value = values[node["atom"]]
            result = None if value == "0" else value == "2"
        else:
            left = results[node["children"][0]]
            if kind == "not":
                result = None if left is None else not left
            else:
                right = results[node["children"][1]]
                if kind == "and":
                    result = False if left is False or right is False else True if left is True and right is True else None
                else:
                    result = True if left is True or right is True else False if left is False and right is False else None
        results.append(result)
    return results[decision["root"]]


def candidates(decision: dict, rows: dict[tuple[str, bool], int], budget: int, *, certify: bool = False) -> tuple[dict[int, dict[str, str]], int, bool]:
    """Search actual opposite-outcome witnesses within a fixed comparison budget.

    Certification holds only conditions observed equal in both runs fixed. All
    other nontarget conditions remain universally quantified, including skipped
    and potentially coupled operands. It therefore proves less than an oracle
    that records independent concrete input semantics, but cannot guess them.
    """
    values = sorted(rows)
    masks = [(sum(1 << i for i, c in enumerate(vector) if c != "0"), sum(1 << i for i, c in enumerate(vector) if c == "2")) for vector, _ in values]
    witnesses = {}
    searched = 0
    false = [index for index, (_, outcome) in enumerate(values) if not outcome]
    true = [index for index, (_, outcome) in enumerate(values) if outcome]
    for left in false:
        for right in true:
            if searched == budget:
                return witnesses, searched, False
            searched += 1
            known = masks[left][0] & masks[right][0]
            changed = (masks[left][1] ^ masks[right][1]) & known
            if changed and changed & (changed - 1) == 0:
                atom = changed.bit_length() - 1
                pair = {"false": values[left][0], "true": values[right][0]}
                if certify:
                    fixed = [a if a == b else "0" for a, b in zip(pair["false"], pair["true"])]
                    fixed[atom] = "0"
                    before, after = fixed.copy(), fixed.copy()
                    before[atom], after[atom] = pair["false"][atom], pair["true"][atom]
                    if cube(decision, before) is not False or cube(decision, after) is not True:
                        continue
                    pair["fixed"] = "".join(fixed)
                witnesses.setdefault(atom, pair)
            if len(witnesses) == len(decision["atoms"]):
                return witnesses, searched, True
    return witnesses, searched, True


def summary(manifest: dict, data: bytes, package: str, test_files: int, budget: int = COMPARISONS, *, independence_budget: int = COMPARISONS) -> dict:
    """Retain candidate and independently certified pairs, all gaps and both fixed search budgets."""
    if any(type(value) is not int or value < 0 for value in (budget, independence_budget)):
        v.reject("logic-budget")
    rows, processes = observe(manifest, data, package, test_files)
    result, remaining, independent_remaining = [], budget, independence_budget
    for file in manifest["files"]:
        for decision in file["decisions"]:
            actual = rows[decision["id"]]
            pairs, used, complete = candidates(decision, actual, remaining)
            remaining -= used
            proofs, used, independent_complete = candidates(decision, actual, independent_remaining, certify=True)
            independent_remaining -= used
            atoms = []
            for index, atom in enumerate(decision["atoms"]):
                observed = sorted({vector[index] for vector, _ in actual} - {"0"})
                atoms.append({"index": index, "text": atom["text"], "observed": observed, "candidate": pairs.get(index), "independent": proofs.get(index)})
            result.append(
                {
                    "id": decision["id"],
                    "kind": decision["kind"],
                    "text": decision["text"],
                    "instrumented": decision["id"] in manifest["observed"],
                    "outcomes": sorted({value for _, value in actual}),
                    "vectors": [{"values": vector, "result": outcome, "hits": hits} for (vector, outcome), hits in sorted(actual.items())],
                    "atoms": atoms,
                    "search_complete": complete,
                    "independence_search_complete": independent_complete,
                }
            )
    return {
        "version": 1,
        "qualification": "not-evaluated",
        "basis": "Candidates preserve syntactic short-circuit compatibility. Independent pairs additionally certify opposite results for every completion of a common observed-value cube. Missing proofs, source feasibility, unsupported roots/controls and instrumentation effects remain unqualified.",
        "process_receipts": processes,
        "pair_budget": budget,
        "pair_comparisons": budget - remaining,
        "independence": {
            "criterion": "universal-common-cube-v1",
            "budget": independence_budget,
            "comparisons": independence_budget - independent_remaining,
            "pairs": sum(atom["independent"] is not None for item in result for atom in item["atoms"]),
            "search_incomplete": sum(not item["independence_search_complete"] for item in result),
        },
        "decisions": result,
        "controls": [{"file": file["file"], "controls": file["controls"]} for file in manifest["files"] if file["controls"]],
        "totals": {
            "roots": len(result),
            "observed": sum(bool(item["vectors"]) for item in result),
            "both": sum(len(item["outcomes"]) == 2 for item in result),
            "atoms": sum(len(item["atoms"]) for item in result),
            "candidates": sum(atom["candidate"] is not None for item in result for atom in item["atoms"]),
            "search_incomplete": sum(not item["search_complete"] for item in result),
        },
    }


def partition_module(source: dict, root: Path, directory: str) -> tuple[str, str]:
    """Bind the closest actual module manifest; v3 nested commands are confined to that module's root package."""
    files = v.unique(source["files"], "path")
    package = PurePosixPath(directory)
    for parent in (package, *package.parents):
        relative = "" if parent.as_posix() == "." else parent.as_posix()
        name = (relative + "/" if relative else "") + "go.mod"
        if not (root / name).exists():
            continue
        if name not in files or files[name]["sha256"] is None:
            v.reject("logic-module-unowned")
        data = v.read(v.inside(root, name))
        if v.digest(data) != files[name]["sha256"]:
            v.reject("logic-module-drift")
        names = re.findall(rb"(?m)^module ([^\s]+)\s*$", data)
        if len(names) != 1:
            v.reject("logic-module-format")
        try:
            module = names[0].decode("utf-8")
        except UnicodeError:
            v.reject("logic-module-encoding")
        v.inside(root, module)
        if relative and directory != relative:
            v.reject("logic-module-root")
        return relative, module
    v.reject("logic-module-missing")


def load(directory: Path, root: Path, *, controls: bool = False, schedule: bool = False) -> dict:
    """Read a complete overlay campaign without creating output or trusting a previously computed summary."""
    bundle_data = v.read(directory / "bundle.json")
    bundle = v.decode(bundle_data)
    typed = isinstance(bundle, dict) and type(bundle.get("version")) is int and bundle["version"] in {2, 3}
    partition = typed and bundle["version"] == 3
    declared = partition and "selection" in bundle
    fields(
        bundle,
        ("version", "directory", "source", "collector", "packages", "tests", "trace", "overlay", "generated")
        + (("exports",) if typed else ())
        + (("partition",) if partition else ())
        + (("selection",) if declared else ())
        + (("schedule",) if schedule else ()),
        "bundle",
    )
    if (
        type(bundle["version"]) is not int
        or bundle["version"] not in {1, 2, 3}
        or partition
        and bundle["partition"] != "native-go-files"
        or not isinstance(bundle["directory"], str)
        or not isinstance(bundle["generated"], dict)
    ):
        v.reject("logic-bundle")
    package_directory = bundle["directory"]
    # A finite named selection binds exact native completions without narrowing the source denominator.
    selected_tests = bundle["selection"] if declared else None
    if declared and (
        not isinstance(selected_tests, list)
        or not 1 <= len(selected_tests) <= 4096
        or any(
            not isinstance(name, str) or not re.fullmatch(r"(?:Test|Fuzz)[A-Z_0-9][A-Za-z0-9_]*|Example(?:[A-Z_0-9][A-Za-z0-9_]*)?", name)
            for name in selected_tests
        )
        or selected_tests != sorted(set(selected_tests))
    ):
        v.reject("logic-test-selection")
    if partition and (controls or schedule):
        v.reject("logic-partition-mode")
    if schedule and (controls or not typed or package_directory != "polaris/internal/server"):
        v.reject("logic-schedule-domain")
    v.inside(root, package_directory)
    source_data = v.reference(directory, bundle["source"])
    source = v.decode(source_data)
    if v.source(root) != source:
        v.reject("logic-workspace-drift")
    module, files = statements.sources(source, root)
    module_directory = ""
    if partition:
        module_directory, module = partition_module(source, root, package_directory)
    module_root = v.inside(root, module_directory) if module_directory else root
    package = module if module_directory else module + "/" + package_directory
    collector, collected = statements.completed(directory, bundle["collector"], root)
    listing, metadata = statements.completed(directory, bundle["packages"], root)
    testing, events = statements.completed(directory, bundle["tests"], root)
    report = v.decode(collected, maximum=statements.LIMIT)
    fields(report, ("version", "source_sha256", "qualification", "basis", "files", "generated", "tests"), "collection")
    if (
        type(report["version"]) is not int
        or report["version"] != 1
        or report["qualification"] != "not-evaluated"
        or not isinstance(report["generated"], list)
        or not isinstance(report["tests"], list)
    ):
        v.reject("logic-collection")
    manifest = v.decode(v.reference(directory, bundle["trace"]))
    if controls:
        from tools import flow

        flow.inventory(manifest, root, v.digest(source_data))
    else:
        inventory(manifest)
    if controls and typed:
        v.reject("logic-control-typing")
    if manifest["version"] != bundle["version"]:
        v.reject("logic-trace-version")
    if partition and manifest["partition"] != bundle["partition"]:
        v.reject("logic-partition-binding")
    if report["source_sha256"] != v.digest(source_data) or manifest["source_sha256"] != report["source_sha256"]:
        v.reject("logic-source-binding")
    if not isinstance(report["files"], list) or manifest["files"] != [
        file for file in report["files"] if Path(file["file"]).parent.as_posix() == package_directory
    ]:
        v.reject("logic-denominator")
    expected = {name for name, file in files.items() if Path(name).parent.as_posix() == package_directory and file["kind"] == "owned"}
    if {file["file"] for file in manifest["files"]} != expected or any(files[file["file"]]["sha256"] != file["sha256"] for file in manifest["files"]):
        v.reject("logic-files-binding")
    helpers = {package_directory + "/zz_astra_probe.go", package_directory + "/zz_astra_probe_test.go"}
    if helpers & files.keys() or set(bundle["generated"]) != expected | helpers:
        v.reject("logic-generated-domain")
    overlay_data = v.reference(directory, bundle["overlay"])
    overlay = v.decode(overlay_data)
    fields(overlay, ("Replace",), "overlay")
    replacements = overlay["Replace"]
    if not isinstance(replacements, dict) or set(replacements) != {str(v.inside(root, name)) for name in expected | helpers}:
        v.reject("logic-overlay-domain")
    destinations = set()
    for name, reference in bundle["generated"].items():
        data = v.reference(directory, reference, statements.LIMIT)
        replaced = replacements[str(v.inside(root, name))]
        if not isinstance(replaced, str) or not Path(replaced).is_absolute():
            v.reject("logic-overlay-path")
        path = Path(replaced)
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            v.reject("logic-overlay-outside")
        if v.inside(root, relative) != path or not relative.startswith("build/") or path.name != Path(name).name or v.read(path, statements.LIMIT) != data:
            v.reject("logic-overlay-drift")
        if partition and name in manifest["typing"]["inactive"] and data != files[name]["data"]:
            v.reject("logic-inactive-overlay")
        destinations.add(path.parent)
        if name in helpers:
            files[name] = {"kind": "test" if name.endswith("_test.go") else "owned", "sha256": v.digest(data), "data": data}
    if len(destinations) != 1:
        v.reject("logic-overlay-location")
    generated = destinations.pop()
    filename = "flow.json" if controls else "trace.json"
    if v.read(generated / "overlay.json") != overlay_data or v.read(generated / filename) != v.reference(directory, bundle["trace"]):
        v.reject("logic-overlay-manifest-drift")
    arguments = collector["argv"]
    go = arguments[0]
    prefix = arguments[:3]
    if (
        len(arguments) != (15 if partition else 14 if typed else 13 if controls else 12)
        or prefix[:2] != [go, "run"]
        or not re.fullmatch(r"-p=[1-9][0-9]*", prefix[2])
        or arguments[3:6] != ["./tools/decisions", "-root", str(root)]
        or arguments[6] != "-source"
        or arguments[8:12] != ["-trace", package_directory, "-output", str(generated)]
        or typed
        and arguments[12] != "-export"
        or controls
        and arguments[12] != "-controls"
        or partition
        and arguments[14] != "-partition"
    ):
        v.reject("logic-collector-command")
    source_path = Path(arguments[7])
    try:
        source_relative = source_path.relative_to(root.parent).as_posix()
    except ValueError:
        v.reject("logic-source-location")
    if v.read(v.inside(root.parent, source_relative)) != source_data:
        v.reject("logic-source-file-drift")
    sequence = [collector, listing, testing]
    prefix = [go, "-C", module_directory] if module_directory else [go]
    selection = "." if module_directory else "./" + package_directory
    if typed:
        exports, export_data = statements.completed(directory, bundle["exports"], root)
        if exports["argv"] != [*prefix, "list", "-deps", "-export", "-json", selection]:
            v.reject("logic-typing-command")
        path = Path(arguments[13])
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            v.reject("logic-typing-metadata-outside")
        if not relative.startswith("build/") or v.inside(root, relative) != path or v.read(path, statements.LIMIT) != export_data:
            v.reject("logic-typing-metadata-drift")
        bind_typing(manifest, export_data, root, package_directory, module, package=package, module_root=module_root if partition else None)
        sequence.insert(0, exports)
    active = generated
    if schedule:
        from tools import watchdog

        active = directory / "schedule"
        receipt = watchdog.compose(root, generated, active)
        if bundle["schedule"]["path"] != "schedule/composition.json" or v.decode(v.reference(directory, bundle["schedule"])) != receipt:
            v.reject("logic-schedule-binding")
        name = package_directory + "/watchdog_test.go"
        data = v.read(root / watchdog.FIXTURE)
        files[name] = {"kind": "test", "sha256": v.digest(data), "data": data}
    if listing["argv"] != [*prefix, "list", "-json", "-overlay=" + str(active / "overlay.json"), selection]:
        v.reject("logic-list-command")
    arguments = testing["argv"]
    required = {"-json", "-count=1", "-overlay=" + str(active / "overlay.json"), selection}
    if declared:
        required.add("-run=^(" + "|".join(selected_tests) + ")$")
    command = [*prefix, "test"]
    flags = arguments[len(command) :]
    keys = [argument.split("=", 1)[0] for argument in flags]
    if (
        arguments[: len(command)] != command
        or not required <= set(flags)
        or len(keys) != len(set(keys))
        or any(argument not in required and not re.fullmatch(r"-(?:p|parallel)=[1-9][0-9]*|-timeout=[1-9][0-9]*s", argument) for argument in flags)
    ):
        v.reject("logic-test-command")
    names = ("exports", "collector", "packages", "tests") if typed else ("collector", "packages", "tests")
    environments = []
    for name, record in zip(names, sequence):
        environment = record["resolved_environment"]
        ignored = {"TMPDIR", "ASTRA_TEST_LOG_DIR"}
        if partition and environment.get("GOOS") == "windows":
            # The Windows executor supplies all three aliases from this original owned command directory.
            folder = v.inside(directory, bundle[name]["path"]).parent
            try:
                relative = folder.relative_to(root).as_posix()
            except ValueError:
                v.reject("logic-native-temporary")
            temporary = str(folder / "tmp")
            if not relative.startswith("build/") or any(environment.get(key) != temporary for key in ("TMPDIR", "TMP", "TEMP")):
                v.reject("logic-native-temporary")
            ignored.update(("TMP", "TEMP"))
        environments.append({key: value for key, value in environment.items() if key not in ignored})
    baseline = environments[names.index("collector")]
    if partition and (
        baseline.get("GOOS") not in {"windows", "linux"}
        or baseline.get("GOARCH") != "amd64"
        or collector["platform"] != baseline["GOOS"] + "-" + baseline["GOARCH"]
    ):
        v.reject("logic-native-platform")
    for index, (previous, current) in enumerate(zip(sequence, sequence[1:])):
        environment = environments[index + 1]
        if (
            previous["executable_sha256"] != collector["executable_sha256"]
            or previous["platform"] != collector["platform"]
            or environments[index] != baseline
            or current["executable_sha256"] != collector["executable_sha256"]
            or current["platform"] != collector["platform"]
            or environment != baseline
            or v.stamp(previous["finished_at"]) > v.stamp(current["started_at"])
        ):
            v.reject("logic-native-identity")
    module_files = (
        {name.removeprefix(module_directory + "/"): value for name, value in files.items() if name.startswith(module_directory + "/")}
        if module_directory
        else files
    )
    groups, _ = statements.packages(metadata, module_files, module, module_root)
    if set(groups) != {package} or groups[package]["tests"] < 2:
        v.reject("logic-package-selection")
    listed = statements.stream(metadata)[0]
    selected = {package_directory + "/" + name for field in statements.FIELDS for name in listed.get(field, [])}
    if (
        selected != {name for name in files if Path(name).parent.as_posix() == package_directory}
        or "zz_astra_probe.go" not in listed.get("GoFiles", [])
        or "zz_astra_probe_test.go" not in listed.get("TestGoFiles", [])
    ):
        v.reject("logic-build-selection")
    result = (
        flow.summary(manifest, events, package, groups[package]["tests"], root, v.digest(source_data))
        if controls
        else summary(manifest, events, package, groups[package]["tests"])
    )
    if typed:
        result["typing"] = manifest["typing"]
    if partition:
        result["partition"] = manifest["partition"]
    if declared:
        completed_tests = sorted(
            event["Test"] for event in statements.stream(events) if event.get("Action") == "pass" and "Test" in event and "/" not in event["Test"]
        )
        if completed_tests != selected_tests:
            v.reject("logic-test-completions")
        result["selection"] = {"basis": "explicit-subset", "tests": selected_tests}
    if v.source(root) != source:
        v.reject("logic-collection-drift")
    return {"bundle": bundle, "source_sha256": v.digest(source_data), "result": result, "trace": manifest, "events": events, "records": sequence}


def collect(directory: Path, root: Path, output: Path) -> int:
    """Import original runner facts exclusively; the reusable reader itself never writes evidence."""
    loaded = load(directory, root)
    result = loaded["result"]
    output.mkdir(parents=True, exist_ok=False)
    result["inputs"] = {"bundle": v.write_new(output / "bundle.json", loaded["bundle"]), "source_sha256": loaded["source_sha256"], "trust": "local"}
    v.write_new(output / "summary.json", result)
    print(
        v.encode(
            {
                "qualification": result["qualification"],
                "process_receipts": result["process_receipts"],
                "totals": result["totals"],
                "independence": result["independence"],
            }
        ).decode(),
        end="",
    )
    return 0


def main(arguments: list[str] | None = None) -> int:
    """Read sealed runner facts only; never execute Go, change source or promote local evidence to a gate pass."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(arguments)
    try:
        return collect(args.bundle.resolve(), args.root.resolve(), args.output.resolve())
    except (OSError, v.Invalid, KeyError, TypeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
