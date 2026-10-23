"""Run an explicitly authorized offline verification campaign with native records and no release self-certification."""

import argparse
import ctypes
import os
from pathlib import Path
import platform
import signal
import sys
import uuid

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import build, verify as v


def host(config: dict, campaign: dict) -> None:
    """Reject a requested platform that does not describe this actual collector host."""
    target = v.unique(config["platforms"])[campaign["platform"]]
    if (platform.system(), platform.machine()) != (target["system"], target["machine"]):
        v.reject("campaign-platform-mismatch")


def select(campaign: dict, requested: list[str] | None) -> list[dict]:
    """Expand prerequisites in declared order and reject unknown, cyclic or forward dependencies."""
    steps = v.unique(campaign["steps"])
    seen = set()
    for step in steps.values():
        if not set(step["requires"]) <= seen:
            v.reject("campaign-dependency", step["id"])
        seen.add(step["id"])
    selected = set(requested) if requested else set(steps)
    if not selected <= steps.keys():
        v.reject("campaign-step-unknown")
    for step in reversed(list(steps.values())):
        if step["id"] in selected:
            selected.update(step["requires"])
    return [step for name, step in steps.items() if name in selected]


def policy(config: dict, previous: dict) -> set[str]:
    """Find changed configuration obligations and their dependents without accepting source or runtime evidence."""
    before, after = (v.expand(value) for value in (previous, config))
    v.dependency_order(before)
    ordered, required = v.dependency_order(after)
    components = [v.unique(value["components"]) for value in (previous, config)]
    checks = [v.unique(value["checks"]) for value in (previous, config)]
    platforms = [v.unique(value.get("platforms", [])) for value in (previous, config)]
    # Unknown/global policy fields remain conservative; only these keyed collections are sliced.
    global_change = {key: value for key, value in previous.items() if key not in {"components", "checks", "platforms"}} != {
        key: value for key, value in config.items() if key not in {"components", "checks", "platforms"}
    }
    changed = set()
    for key in ordered:
        item = after[key]
        component = item["component"]
        metadata = [{key: value for key, value in group.get(component, {}).items() if key != "requirements"} for group in components]
        if (
            global_change
            or before.get(key) != item
            or metadata[0] != metadata[1]
            or platforms[0].get(item["platform"]) != platforms[1].get(item["platform"])
            or any(checks[0].get(name) != checks[1][name] for name in item["checks"])
            or changed.intersection(required[key])
        ):
            changed.add(key)
    return changed


def batches(config: dict, obligations: dict, pending: set[str], records: list[dict]) -> dict:
    """Deduplicate proof work after expanding prerequisites, without scheduling execution or granting reuse."""
    ordered, required = v.dependency_order(obligations)
    if not pending <= obligations.keys():
        v.reject("review-pending-unknown")
    selected = set(pending)
    for key in reversed(ordered):
        if key in selected:
            selected.update(required[key])
    checks = v.unique(config["checks"])
    retained = {(item["check"], item["platform"]): item for item in records}
    if len(retained) != len(records):
        v.reject("review-duplicate-record")
    groups, decisions, unmapped = {}, [], []
    for key in sorted(selected):
        item = obligations[key]
        if item.get("aggregate"):
            continue
        if not item["checks"]:
            unmapped.append(key)
        for name in item["checks"]:
            coordinate = (name, item["platform"])
            check = checks[name]
            record = retained.get(coordinate)
            action = "implement-proof" if check["adapter"] == "unavailable" else "replay-retained" if record else "locate-evidence"
            group = groups.setdefault(
                coordinate,
                {
                    "check": name,
                    "platform": item["platform"],
                    "action": action,
                    "record": record,
                    "obligations": [],
                    "prerequisites": [],
                },
            )
            group["obligations" if key in pending else "prerequisites"].append(key)
    for key in ordered:
        if key in selected and required[key]:
            decisions.append({"obligation": key, "requires": required[key], "checks": obligations[key]["checks"]})
    # A missing record is a search task, not permission to rebuild. An unavailable adapter cannot consume old facts yet.
    priority = {"replay-retained": 0, "locate-evidence": 1, "implement-proof": 2}
    return {
        "proofs": sorted(groups.values(), key=lambda item: (priority[item["action"]], item["check"], item["platform"])),
        "decisions": decisions,
        "unmapped": unmapped,
        "pending": sorted(pending),
        "prerequisites": sorted(selected - pending),
    }


def review(config: dict, baseline: dict, current: dict, root: Path, previous: bytes | None = None) -> dict:
    """Group retained evidence and unresolved work without executing checks or granting a current pass."""
    obligations = v.expand(config)
    gate = baseline["gate"]
    sets = {}
    for name in ("required", "passed", "missing", "exceptions"):
        values = gate[name]
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values) or len(set(values)) != len(values):
            v.reject("review-obligation-inventory", name)
        sets[name] = set(values)
    if (
        sets["passed"] & sets["missing"]
        or sets["passed"] & sets["exceptions"]
        or sets["missing"] & sets["exceptions"]
        or sets["required"] != sets["passed"] | sets["missing"] | sets["exceptions"]
    ):
        v.reject("review-obligation-partition")
    before, after = (v.unique(source["files"], "path") for source in (baseline["source"], current))
    changed = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
    assigned = v.inventory(config, changed)
    records, seen = [], set()
    boundary = (root / "build/results").resolve()
    for item in baseline["checks"]:
        key = (item["check"], item["platform"])
        if key in seen:
            v.reject("review-duplicate-record", repr(key))
        seen.add(key)
        path = Path(item["record"]).resolve()
        if not path.is_relative_to(boundary):
            v.reject("review-record-boundary", str(path))
        path = v.inside(boundary, path.relative_to(boundary).as_posix())
        # Older Windows collections include paths longer than MAX_PATH.
        native = Path("\\\\?\\" + str(path)) if os.name == "nt" else path
        if v.file_digest(native) != item["record_sha256"]:
            v.reject("review-record-integrity", item["check"])
        records.append({key: item[key] for key in ("check", "platform", "record", "record_sha256")})
    checks = v.unique(config["checks"])
    groups = {}
    unchanged = baseline["configuration_sha256"] == v.file_digest(root / "development.json")
    affected = set(obligations) if not unchanged else set()
    if previous is not None:
        if v.digest(previous) != baseline["configuration_sha256"]:
            v.reject("review-policy-integrity")
        old = v.decode(previous)
        if set(v.expand(old)) != sets["required"]:
            v.reject("review-policy-obligations")
        affected = policy(config, old)
    # Missing historical policy stays conservative. Configuration equality never certifies current inputs.
    recheck = (sets["passed"] | sets["exceptions"]) & affected
    git_unchanged = all(baseline["source"][key] == current[key] for key in ("commit", "status"))
    # Ownership is not a dependency proof. Review retained facts conservatively until their native readers establish reuse.
    source_recheck = (sets["passed"] | sets["exceptions"]) & obligations.keys() if changed or not git_unchanged else set()
    pending = (sets["missing"] & obligations.keys()) | (obligations.keys() - sets["required"]) | recheck | source_recheck
    for key in sorted(pending):
        item = obligations[key]
        for name in item["checks"]:
            group = groups.setdefault(
                (item["component"], item["platform"], name),
                {
                    "component": item["component"],
                    "platform": item["platform"],
                    "check": name,
                    "action": "implement-proof" if checks[name]["adapter"] == "unavailable" else "review-evidence",
                    "obligations": [],
                },
            )
            group["obligations"].append(key)
    return {
        "qualification": "not-evaluated",
        "execution": "none",
        "baseline_gate": {name: gate[name] for name in ("status", "hard")},
        "baseline_counts": {name: len(values) for name, values in sets.items()},
        "configuration_unchanged": unchanged,
        "policy_comparison": "itemwise" if previous is not None else "digest-only",
        "policy_changed": sorted(affected),
        "policy_review": sorted(recheck),
        "source_review": sorted(source_recheck),
        "changed_files": changed,
        "changed_owners": assigned,
        "git_identity_unchanged": git_unchanged,
        "retained_records": records,
        "work": list(groups.values()),
        "batches": batches(config, obligations, pending, records),
        "pending_aggregates": sorted(key for key in pending if obligations[key].get("aggregate")),
        "removed_obligations": sorted(sets["required"] - obligations.keys()),
        "new_obligations": sorted(obligations.keys() - sets["required"]),
        "reuse_boundary": (
            "Record digests identify retained local facts, not current qualification. Reuse requires itemwise input, artifact, "
            "environment, policy and dependency review plus the existing native reader. Changed owners are a starting point, "
            "not a transitive impact closure. Missing prerequisites cannot be replaced with old test results."
        ),
    }


def main(arguments: list[str] | None = None) -> int:
    """Freeze scope before starting; every interruption drains only owned children and preserves evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", default="system")
    parser.add_argument("--step", action="append")
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--baseline", type=Path, help="Review an existing reconciliation during --plan; never execute or accept it as a new run")
    parser.add_argument("--sha256", help="Previously recorded baseline digest, required with --baseline")
    parser.add_argument("--policy", type=Path, help="Original configuration bytes pinned by the baseline; narrows policy review only")
    parser.add_argument("--authorization", help="Actual current-task run authorization reference; not CI policy approval")
    args = parser.parse_args(arguments)
    if bool(args.baseline) != bool(args.sha256) or args.baseline and not args.plan or args.policy and not args.baseline:
        v.reject("review-plan-and-pin-required")
    root = build.ROOT.resolve()
    config, _, pins = v.configuration(root / "development.json", root)
    campaigns = v.unique(config["campaigns"])
    if args.campaign not in campaigns:
        v.reject("campaign-unknown")
    campaign = campaigns[args.campaign]
    steps = select(campaign, args.step)
    if args.plan:
        result = {"policy": pins, "campaign": args.campaign, "steps": steps}
        if args.baseline:
            raw = v.read(args.baseline)
            if v.digest(raw) != args.sha256:
                v.reject("review-baseline-integrity")
            current = v.source(root)
            previous = v.read(args.policy) if args.policy else None
            result["review"] = review(config, v.decode(raw), current, root, previous)
            if current != v.source(root):
                v.reject("review-source-changed")
            result["baseline"] = {"path": str(args.baseline.resolve()), "sha256": args.sha256}
            if args.policy:
                result["baseline"]["policy"] = {"path": str(args.policy.resolve()), "sha256": v.digest(previous)}
        print(v.encode(result).decode())
        return 0
    if not args.authorization:
        v.reject("campaign-authorization-missing")
    host(config, campaign)
    if sys.platform != "linux" or ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0):
        v.reject("campaign-linux-subreaper-required")
    cpus, memory = build.resources()
    if memory < campaign["minimum_memory_bytes"]:
        v.reject("campaign-memory-budget")
    directory = root / "build/results/assurance" / str(uuid.uuid4())
    directory.mkdir(parents=True, exist_ok=False)
    before = v.source(root)
    v.write_new(
        directory / "inputs.json",
        {"source": before, "policy": pins, "steps": steps, "authorization": args.authorization, "cpus": cpus, "available_bytes": memory, "trust": "local"},
    )
    v.write_new(
        directory / "controller.json",
        {"identity": v.proc_identity(os.getpid()), "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(), "argv": sys.argv, "cwd": str(root)},
    )
    stopped = False

    def cancel(*_: object) -> None:
        """Request bounded cancellation; the current native executor performs identity-safe draining."""
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)
    records, errors = [], []
    env = build.environment(jobs=2)
    try:
        for step in steps:
            if stopped:
                break
            if v.source(root) != before:
                v.reject("campaign-source-drift")
            output = directory / step["id"]
            output.mkdir()
            replacements = {"{python}": sys.executable, "{root}": str(root), "{cache}": str(build.CACHE), "{run}": str(directory)}
            argv = []
            for value in step["argv"]:
                for key, actual in replacements.items():
                    value = value.replace(key, actual)
                argv.append(value)
            print(step["id"], flush=True)
            record = v.execute(
                {**step, "argv": argv, "environment": {**env, "TMPDIR": str(output / "tmp")}}, root, output, campaign["platform"], lambda: stopped
            )
            reference = v.write_new(output / "record.json", record)
            records.append(
                {
                    "id": step["id"],
                    "path": step["id"] + "/record.json",
                    "sha256": reference["sha256"],
                    "complete": record["complete"],
                    "cleanup": record["cleanup"],
                    "exit_code": record["exit_code"],
                }
            )
            if not record["complete"] or not record["cleanup"] or record["exit_code"] != 0:
                break
    except (OSError, v.Invalid) as error:
        errors.append(str(error))
    after = None
    try:
        after = v.source(root)
    except (OSError, v.Invalid) as error:
        errors.append(str(error))
    remaining = v.owned_members()
    complete = (
        not errors
        and not stopped
        and before == after
        and not remaining
        and len(records) == len(steps)
        and all(record["complete"] and record["cleanup"] and record["exit_code"] == 0 for record in records)
    )
    result = {
        "status": "completed" if complete else "interrupted" if stopped else "blocked",
        "qualification": "not-evaluated",
        "trust": "local",
        "selected": len(steps),
        "available": len(campaign["steps"]),
        "records": records,
        "errors": errors,
        "source_unchanged": before == after,
        "remaining_owned": remaining,
    }
    v.write_new(directory / "source-after.json", after)
    v.write_new(directory / "result.json", result)
    print(directory, flush=True)
    return 0 if complete and not result["remaining_owned"] else 2


if __name__ == "__main__":
    sys.exit(main())
