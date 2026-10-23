"""Reconcile diagnostic loop completions and select-arm receipts without granting structural qualification."""

from pathlib import Path
import re

from tools import logic, statements, verify as v

# Only explicit, source-bound arms are supported; implicit switch fallthrough is rejected by the native collector.
ARMS = {"select-arm": "select", "switch-arm": "switch", "type-arm": "type-switch"}


def inventory(manifest: dict, root: Path, source_sha256: str) -> dict:
    """Bind native control declarations to original source coordinates and the Boolean collector's retained controls.

    The sealed native Go AST collector owns arm enumeration; this reader checks its declared scope and receipts.
    It is not an independent Go parser or an authority for feasibility exclusions.
    """
    logic.fields(manifest, ("version", "source_sha256", "qualification", "basis", "files", "observed", "edges"), "flow-manifest")
    if manifest["source_sha256"] != source_sha256 or not re.fullmatch(r"[0-9a-f]{64}", source_sha256):
        v.reject("flow-source-binding")
    # Reuse validation of the unchanged syntactic forest, without treating control vectors as Boolean traces.
    forest = {key: value for key, value in manifest.items() if key != "edges"}
    forest["observed"] = [item["id"] for file in manifest["files"] for item in file["decisions"] if item["kind"] != "boolean"]
    logic.inventory(forest, allow_empty=True)
    if not isinstance(manifest["edges"], list) or not 1 <= len(manifest["edges"]) <= logic.VECTORS:
        v.reject("flow-edge-capacity")
    files, controls, conditions = {}, {}, {}
    for file in manifest["files"]:
        name = file["file"]
        data = v.read(v.inside(root, name))
        if v.digest(data) != file["sha256"]:
            v.reject("flow-source-drift")
        files[name] = data
        for item in file["controls"]:
            if item["kind"] not in {"range", "loop", "select", "switch", "type-switch", "go", "defer"}:
                v.reject("flow-unsupported-control")
            controls[f"{name}:{item['begin']['offset']}"] = item
        for item in file["decisions"]:
            if item["kind"] == "for":
                conditions[item["id"]] = item
    edges, selected, loops = {}, {}, {}
    for edge in manifest["edges"]:
        logic.fields(edge, ("id", "kind", "parent", "begin", "end"), "flow-edge")
        logic.span(edge)
        identity, kind, parent = (edge[key] for key in ("id", "kind", "parent"))
        if not isinstance(identity, str) or not isinstance(parent, str) or not isinstance(kind, str) or kind not in {"range", "for", "loop", *ARMS}:
            v.reject("flow-edge")
        name, _, offset = identity.rpartition(":")
        if name not in files or offset != str(edge["begin"]["offset"]) or identity in edges:
            v.reject("flow-edge-identity")
        data = files[name]
        for key in ("begin", "end"):
            point = edge[key]
            start = point["offset"]
            if start > len(data) or point["line"] != data[:start].count(b"\n") + 1 or point["column"] != start - data.rfind(b"\n", 0, start):
                v.reject("flow-coordinate")
        fragment = data[edge["begin"]["offset"] : edge["end"]["offset"]]
        if kind in ARMS:
            control = controls.get(parent)
            if not control or control["kind"] != ARMS[kind] or not parent.startswith(name + ":") or not fragment.startswith((b"case ", b"default:")):
                v.reject("flow-select")
            if not control["begin"]["offset"] < edge["begin"]["offset"] < edge["end"]["offset"] < control["end"]["offset"]:
                v.reject("flow-select-span")
            selected.setdefault(parent, []).append(identity)
        else:
            if parent != identity or not fragment.startswith(b"for "):
                v.reject("flow-loop")
            if kind in {"range", "loop"}:
                control = controls.get(identity)
                if control != {key: edge[key] for key in ("kind", "begin", "end")}:
                    v.reject("flow-loop-inventory")
            else:
                candidates = [
                    key
                    for key, item in conditions.items()
                    if key.startswith(name + ":") and edge["begin"]["offset"] < item["begin"]["offset"] < item["end"]["offset"] < edge["end"]["offset"]
                ]
                if not candidates:
                    v.reject("flow-for-condition")
                loops[identity] = min(candidates, key=lambda key: conditions[key]["begin"]["offset"])
        edges[identity] = edge
    if set(selected) != {key for key, value in controls.items() if value["kind"] in ARMS.values()} or set(loops.values()) != set(conditions):
        v.reject("flow-missing-control")
    if {key for key, value in controls.items() if value["kind"] in {"range", "loop"}} != {
        key for key, value in edges.items() if value["kind"] in {"range", "loop"}
    }:
        v.reject("flow-missing-loop")
    if manifest["observed"] != list(edges):
        v.reject("flow-observed-domain")
    return edges


def summary(manifest: dict, data: bytes, package: str, tests: int, root: Path, source_sha256: str) -> dict:
    """Require complete native terminals and retain every missing arm/body/exhaustion observation explicitly."""
    edges = inventory(manifest, root, source_sha256)
    if len(data) > statements.LIMIT:
        v.reject("flow-stream-size")
    statements.terminals(data, {package: {"tests": tests}})
    parts = [v.decode(line).get("Output", "") for line in data.splitlines()]
    if any(not isinstance(part, str) for part in parts):
        v.reject("flow-output")
    processes, rows = set(), {identity: {} for identity in edges}
    for line in "".join(parts).splitlines():
        marker = "GO-CONTROLS "
        if marker not in line:
            continue
        if line.count(marker) != 1:
            v.reject("flow-framing")
        receipt = v.decode(line.split(marker, 1)[1].encode(), maximum=statements.LIMIT)
        logic.fields(receipt, ("pid", "code", "rows"), "flow-receipt")
        pid = receipt["pid"]
        if (
            type(pid) is not int
            or pid <= 0
            or pid in processes
            or type(receipt["code"]) is not int
            or receipt["code"] != 0
            or not isinstance(receipt["rows"], list)
            or len(receipt["rows"]) > logic.VECTORS
        ):
            v.reject("flow-process")
        processes.add(pid)
        seen = set()
        for row in receipt["rows"]:
            logic.fields(row, ("id", "values", "result", "hits"), "flow-row")
            identity, vector, result, hits = (row[key] for key in ("id", "values", "result", "hits"))
            if (
                not isinstance(identity, str)
                or identity not in edges
                or not isinstance(vector, str)
                or type(result) is not bool
                or type(hits) is not int
                or not 1 <= hits < 2**64
            ):
                v.reject("flow-row")
            allowed = {"2"} if edges[identity]["kind"] in ARMS else {"11", "21"} if edges[identity]["kind"] == "loop" else {"11", "12", "21", "22"}
            if vector not in allowed or result != vector.endswith("2") or (identity, vector) in seen:
                v.reject("flow-vector")
            seen.add((identity, vector))
            rows[identity][vector] = rows[identity].get(vector, 0) + hits
    if not processes or not any(rows.values()):
        v.reject("flow-empty")
    return {
        "qualification": "not-evaluated",
        "processes": len(processes),
        "edges": [{**edge, "vectors": rows[identity]} for identity, edge in edges.items()],
        "unobserved": [key for key, values in rows.items() if not values],
        "without_empty": [key for key, edge in edges.items() if edge["kind"] in {"range", "for"} and "12" not in rows[key]],
        "without_body": [key for key, edge in edges.items() if edge["kind"] not in ARMS and not any(vector.startswith("2") for vector in rows[key])],
        "without_exhaustion": [
            key for key, edge in edges.items() if edge["kind"] in {"range", "for"} and not any(vector.endswith("2") for vector in rows[key])
        ],
        "basis": "Native Go AST declarations and completed process observations only; missing combinations are not automatically feasible obligations or exclusions. Instrumented defers/locks alter scheduling and resource costs; no timing, allocation-fault, native-race, liveness or whole-structure qualification.",
    }
