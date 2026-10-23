"""Qualify the fixed Storage fault inventory from unchanged, authenticated native executions."""

from pathlib import Path
import re

from tools import storage, verify as v

MANIFEST = "polaris/internal/storage/faults.json"
DIGEST = "4426d4eafe17bc16785219f128f32c5523782dbf0cf9a84581dad7772d848924"
LEGACY = "bb299ab73cc6c4349288245ae645c87fae5522cd87a41941117c14ec22053852"
ARCHIVES = {
    "storage-idle-fault-native-current-1": "43ec5db674ad8654871ac7226f10f62af0496246398f576e9c7248c77c58411a",
    "storage-idle-fault-io-current-1": "caf8260e81a19b7089312ab5e4aa176493ef34f83c5ebb999a4951dde9e40305",
}
TESTS = [
    "tests.test_storage_faults.StorageFaultTests.test_current",
    "tests.test_storage_faults.StorageFaultTests.test_controls",
    "tests.test_storage_faults.StorageFaultTests.test_inputs",
    "tests.test_storage_faults.StorageFaultTests.test_policy",
]


def inventory(data: bytes) -> dict:
    """Freeze expectation provenance independently of any captured success stream."""
    digest = v.digest(data)
    if digest not in {DIGEST, LEGACY}:
        v.reject("storage-fault-inventory-identity")
    plan = v.decode(data)
    if set(plan) != {"version", "platform", "package", "scope", "expectation", "groups", "composition", "equivalence"}:
        v.reject("storage-fault-inventory-fields")
    current = digest == DIGEST
    if (
        plan["version"] != (2 if current else 1)
        or plan["platform"] != "linux-amd64-cgo"
        or plan["package"] != "github.com/eosforge/astra/polaris/internal/storage"
    ):
        v.reject("storage-fault-inventory-scope")
    cases = [case for group in plan["groups"] for case in group["cases"]]
    if len(plan["groups"]) != (30 if current else 25) or len(cases) != (190 if current else 185) or len(set(cases)) != len(cases):
        v.reject("storage-fault-inventory-denominator")
    return plan


def observations(data: bytes, plan: dict) -> list[dict]:
    """Require every declared native case, positive assertion and owning parent lifetime."""
    starts, stops, markers, pending = {}, {}, {}, {}
    selected = {case for group in plan["groups"] for case in group["cases"]}
    parents = {group["test"] for group in plan["groups"]}
    actions = {"start", "run", "pause", "cont", "output", "pass", "fail", "skip", "bench", "build-output", "build-fail"}
    for index, line in enumerate(data.splitlines()):
        event = v.decode(line)
        action, test = event.get("Action"), event.get("Test", "")
        if action not in actions or not isinstance(test, str) or ("Package" in event and event["Package"] != plan["package"]):
            v.reject("storage-fault-event-identity")
        if action in {"fail", "skip", "build-fail"}:
            v.reject("storage-fault-native-failure")
        if any(test == parent or test.startswith(parent + "/") for parent in parents) and test not in selected:
            v.reject("storage-fault-undeclared-case")
        if test in selected and action in {"run", "pass"}:
            target = starts if action == "run" else stops
            if test in target:
                v.reject("storage-fault-duplicate-terminal")
            target[test] = index
        if action != "output":
            continue
        output = event.get("Output")
        if not isinstance(output, str):
            v.reject("storage-fault-output-shape")
        text = pending.get(test, "") + output
        if len(text.encode()) > 65536:
            v.reject("storage-fault-output-budget")
        lines = text.split("\n")
        pending[test] = lines.pop()
        for part in lines:
            found = re.search(r"ASTRA-CONTRACT (.*)$", part)
            if found is None or test not in parents:
                continue
            marker = v.decode(found.group(1).encode())
            if set(marker) != {"contract", "hits"} or type(marker["hits"]) is not int or marker["hits"] <= 0:
                v.reject("storage-fault-vacuous-marker")
            key = test, marker["contract"]
            if key in markers:
                v.reject("storage-fault-duplicate-marker")
            markers[key] = index, marker["hits"]
    if any(pending.values()) or set(starts) != selected or set(stops) != selected:
        v.reject("storage-fault-missing-case")
    required = {(group["test"], group["contract"]) for group in plan["groups"]}
    if set(markers) != required:
        v.reject("storage-fault-marker-inventory")
    result = []
    for group in plan["groups"]:
        parent = group["test"]
        position, hits = markers[parent, group["contract"]]
        if not starts[parent] < position < stops[parent] or hits < group["minimum_hits"]:
            v.reject("storage-fault-parent-observation")
        for case in group["cases"]:
            if not starts[case] < stops[case] or not starts[parent] <= starts[case] < stops[case] <= stops[parent]:
                v.reject("storage-fault-case-lifetime")
            result.append({"group": group["id"], "test": case, "contract": group["contract"], "status": "passed", "parent_assertions": hits})
    return result


def acquired(root: Path, name: str, *, archive: bytes | None = None, seal: dict | None = None) -> tuple[dict, dict, dict]:
    """Authenticate each original acquisition, including the first controller's unchanged failed status."""
    from tools import entry, sensitivity

    if name not in ARCHIVES:
        v.reject("storage-fault-current-origin")
    directory = root / "build/results/assurance/reuse-plan" / name / "native"
    data = v.read(directory / "evidence.tar.gz", 64 * 1024**2) if archive is None else archive
    seal = v.decode(v.read(directory / "sealed.native.json")) if seal is None else seal
    if seal["sha256"] != ARCHIVES[name] or v.digest(data) != ARCHIVES[name] or seal["bytes"] != len(data) or seal["trust"] != "local":
        v.reject("storage-fault-current-archive", name)
    files = entry.unpack(data)
    manifest = v.decode(files["manifest.json"])
    if manifest["trust"] != "local" or set(manifest["files"]) != files.keys() - {"manifest.json"} or seal["files"] != len(files):
        v.reject("storage-fault-current-manifest")
    for path, item in manifest["files"].items():
        if item != {"bytes": len(files[path]), "sha256": v.digest(files[path])}:
            v.reject("storage-fault-current-member", path)
    inputs, owner, cleanup, terminal, returned = (
        v.decode(files[key + ".json"]) for key in ("inputs", "controller", "cleanup.native", "terminal", "cache-return.native")
    )
    failed = name == "storage-idle-fault-native-current-1"
    location = "/home/ubuntu/verdandi/astra/build/results/assurance/" + name
    service = cleanup["unit"]
    if (
        seal["cleanup"] != cleanup
        or seal["terminal"] != terminal
        or terminal["errors"] != (["AssertionError: "] if failed else [])
        or terminal["interrupted"] is not False
        or terminal["remaining_owned"]
        or cleanup["original_exit_code"] != int(failed)
        or service["MainPID"] != "0"
        or service["ControlGroup"]
        or service["Result"] != ("exit-code" if failed else "success")
        or service["ExecMainStatus"] != str(int(failed))
        or service["InvocationID"] not in {"", owner["invocation_id"]}
        or owner["cwd"] != location
        or owner["argv"] != ["/usr/bin/python3", "-B", location + "/run.py"]
        or owner["inputs_sha256"] != v.digest(files["inputs.json"])
        or owner["script_sha256"] != inputs["run_sha256"]
        or owner["script_sha256"] != v.digest(files["run.py"])
        or owner["boot_id"] != inputs["boot_id"]
        or owner["boot_id"] != cleanup["boot_id"]
        or owner["identity"] not in cleanup["retired"]
        or cleanup["cache_inode"] != 713912
        or returned["owner"] != owner
        or returned["remaining_owned"]
        or (returned["device"], returned["inode"]) != (64512, 713912)
    ):
        v.reject("storage-fault-current-owner", name)
    rows = [v.decode(line) for line in files["journal.native.jsonl"].splitlines()]
    rows = [
        row
        for row in rows
        if row.get("_BOOT_ID") == owner["boot_id"].replace("-", "")
        and (row.get("INVOCATION_ID") or row.get("_SYSTEMD_INVOCATION_ID")) == owner["invocation_id"]
    ]
    messages = [row.get("MESSAGE", "") for row in rows]
    if (
        not any(message.startswith("Started astra-" + name + ".service - ") for message in messages)
        or not any("status=1/" in message if failed else message == "astra-" + name + ".service: Deactivated successfully." for message in messages)
        or not any(message.startswith("{") and v.decode(message.encode()) == terminal for message in messages)
    ):
        v.reject("storage-fault-current-journal", name)
    source = sensitivity.packed(files, inputs, "source")
    sensitivity.packed(files, inputs, "artifacts")
    sensitivity.sources(root, inputs, source=source)
    if source[MANIFEST] != v.read(root / MANIFEST) or source["dependencies.lock.json"] != v.read(root / "dependencies.lock.json"):
        v.reject("storage-fault-current-inputs")
    return files, inputs, owner


def current(root: Path, archive: bytes | None = None) -> dict:
    """Join 188 original cases and the two separately completed WAL cases without inventing a native run."""
    from tools import sensitivity

    plan = inventory(v.read(root / MANIFEST))
    if plan["version"] != 2:
        v.reject("storage-fault-current-inventory")
    missing = {"TestNativeIO/write", "TestNativeIO/sync"}
    streams, records, bindings = [], {}, None
    for name in ARCHIVES:
        files, inputs, owner = acquired(root, name, archive=archive if name == "storage-idle-fault-native-current-1" else None)
        if inputs["selections"] or len(inputs["auxiliary"]) != 1:
            v.reject("storage-fault-current-selection")
        check = inputs["auxiliary"][0]
        supplement = name == "storage-idle-fault-io-current-1"
        selected = [group for group in plan["groups"] if (group["test"] in missing) == supplement]
        expected = [case for group in selected for case in group["cases"]]
        declared = ["TestNativeIO", *expected] if supplement else [case for group in plan["groups"] for case in group["cases"]]
        selector = "^TestNativeIO$/(write|sync)$" if supplement else "^(" + "|".join(group["test"] for group in plan["groups"]) + ")$"
        if (
            check["id"] != ("current-fault-io" if supplement else "current-fault-matrix")
            or check["adapter"] != "go-test-json"
            or check["package"] != plan["package"]
            or check["argv"] != ["go", "test", "-json", "-count=1", "-p=2", "-parallel=1", "-timeout=180s", "-run=" + selector, "./polaris/internal/storage"]
            or check["expected_tests"] != declared
            or check["timeout_s"] != 240
            or check["log_bytes"] != 32 * 1024**2
        ):
            v.reject("storage-fault-current-declaration")
        prefix = "source/build/commands/" + check["id"] + "/"
        record, _, data = sensitivity.command(files, prefix, check, owner)
        _, failures = v.parse_observations(data, check, root)
        if failures != ([] if supplement else ["go-required-test:TestNativeIO/write", "go-required-test:TestNativeIO/sync", "undeclared-probe"]):
            v.reject("storage-fault-current-original-outcome")
        events = [v.decode(line) for line in data.splitlines()]
        actual = {event["Test"] for event in events if event.get("Test") and event.get("Action") == "pass"}
        if actual != set(expected) | ({"TestNativeIO"} if supplement else set()):
            v.reject("storage-fault-current-native-selection")
        observations(data, {**plan, "groups": selected})
        sources = {path: digest for path, digest in inputs["files"].items() if path.startswith("polaris/internal/storage/") and path.endswith(".go")}
        if bindings is not None and bindings != sources:
            v.reject("storage-fault-current-source-composition")
        bindings = sources
        records[name] = {
            "archive_sha256": ARCHIVES[name],
            "record_sha256": v.digest(files[prefix + "record.json"]),
            "duration_ms": record["duration_ms"],
            "program_exit_code": record["exit_code"],
            "controller_exit_code": v.decode(files["cleanup.native.json"])["original_exit_code"],
            "cases": len(expected),
            "original_failures": failures,
        }
        streams.append(data)
    data = b"\n".join(stream.rstrip(b"\n") for stream in streams) + b"\n"
    return {
        "trust": "local",
        "inventory_sha256": DIGEST,
        "native_archives": records,
        "groups": len(plan["groups"]),
        "cells": observations(data, plan),
        "sources": bindings,
        "original_entry": {"exit_code": 0, "kind": "two complete native children; first enclosing controller remains failed"},
        "raw": data,
    }


def reconcile(root: Path) -> dict:
    """Authenticate all original commands, compiler exports, source closure and retired native owners."""
    from tools import idle

    if idle.current(root):
        return current(root)
    plan = inventory(v.read(root / MANIFEST))
    artifacts = {name: v.read(root / "build/results/assurance" / name, 64 * 1024**2) for name in storage.ARTIFACTS}
    qualified = storage.reconcile(root, artifacts)
    files = storage.retained(artifacts[storage.BASE + "evidence.tar.gz"], v.decode(artifacts[storage.BASE + "sealed.native.json"]), storage.ARCHIVE)
    prefix = storage.PREFIX + "coverage/"
    record = v.decode(files[prefix + "record.json"])
    data = storage.reference(files, prefix, record["stdout"])
    cells = observations(data, plan)
    return {
        "trust": "local",
        "inventory_sha256": DIGEST,
        "native_archive_sha256": storage.ARCHIVE,
        "native_record_sha256": v.digest(files[prefix + "record.json"]),
        "groups": len(plan["groups"]),
        "cells": cells,
        "sources": qualified["sources"],
        "original_entry": qualified["original_entry"],
        "raw": data,
    }


def policy(config: dict, plan: dict) -> None:
    """Keep reader controls mandatory and preserve the separately proven repeated SQL recovery prerequisite."""
    check = next(item for item in config["checks"] if item["id"] == "gap-fault-matrix")
    total = sum(len(group["cases"]) for group in plan["groups"])
    probe = [{"contract": "STORAGE-ASSURANCE", "test": TESTS[0], "minimum_hits": total}]
    if (
        check["adapter"] != "observed-cases"
        or check["component"] != "polaris-storage"
        or check["argv"] != ["python3", "-B", "tools/observe.py", "python", *TESTS]
        or check["expected_tests"] != TESTS
        or check["probes"] != probe
    ):
        v.reject("storage-fault-policy-check")
    component = next(item for item in config["components"] if item["id"] == "polaris-storage")
    requirement = next(item for item in component["requirements"] if item["rule"] == "DEV-FAULT" and item["scenario"] == "fault-matrix")
    if requirement["checks"] != ["gap-fault-matrix"] or requirement.get("requires") != [
        {"rule": "DEV-FAULT", "contract": "STORAGE-SQL-FAULT", "scenario": "sql-recovery"}
    ]:
        v.reject("storage-fault-policy-recovery")
