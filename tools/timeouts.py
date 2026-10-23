"""Verify native Storage clock histories, physical mutation controls and their exact current source boundary."""

from pathlib import Path
import re

from tools import entry, server, verify as v

PACKAGE = "github.com/eosforge/astra/polaris/internal/storage"
DIRECTORY = "polaris/internal/storage/"
ARCHIVES = {
    1: "96e77c4a1d27e0cb0be59bdf4273a3d753653475f795445a8b93d7dcf2e1973a",
    2: "fd0915941678e49f523d4928d8fec79ecc2d7674233bf2cbf61b1ece397ea4dc",
    3: "84e01d773c46113040609d4dd73d456dd2a1e15f1eff36add0e13ab3568be5d0",
    5: "485fcfcfed7d0b3bb9c3a2ad52aa6a16fd7bef0fa1db7333eb8ec0b05ae64a20",
    6: "a80738755cfb668e97a529bf32fa9952694f91a46885395617a21b707324b09d",
    7: "27b902f066d26175bcaf5d6bedfe137660e554c4f246393e61ea61a9310c5c7a",
}
ARTIFACTS = {f"reuse-plan/storage-time-current-{number}/native/evidence.tar.gz": digest for number, digest in ARCHIVES.items()}
TESTS = ["tests.test_timeouts.TimeoutTests.test_" + name for name in ("current", "archive", "native", "boundaries", "mutants", "sources", "policy")]
CASES = {
    "write": ("TestTimeouts", ("permit", "minimum", "maximum", "parent", "cancel", "past", "jump")),
    "read": ("TestReadTimeouts", ("permit", "minimum", "maximum", "parent", "cancel", "past", "jump")),
    "open": ("TestOpenTimeouts", ("permit", "before", "default", "minimum", "maximum", "parent", "cancel", "jump")),
    "native": ("TestTimers", ("write", "read")),
}
COMMANDS = {
    1: {"list": 0, "baseline": 0, "disabled": 0},
    2: {"disabled": 1},
    3: {"early": 1, "cause": 1},
    5: {"list": 0, "baseline": 0, "read-disabled": 1, "read-early": 1, "read-cause": 1, "open-disabled": 1, "open-early": 1},
    6: {"list": 0, "baseline": 0},
}
MUTANTS = {
    (2, "disabled"): (
        "commit.go",
        "ctx, cancel := context.WithTimeout(ctx, store.limits.Timeout)",
        "ctx, cancel := context.WithCancel(ctx)",
        "write",
        "minimum",
        "operation did not finish at the controlled boundary",
    ),
    (3, "early"): (
        "commit.go",
        "ctx, cancel := context.WithTimeout(ctx, store.limits.Timeout)",
        "ctx, cancel := context.WithTimeout(ctx, store.limits.Timeout/2)",
        "write",
        "minimum",
        "initial durable receipt",
    ),
    (3, "cause"): ("commit.go", "return 0, ctx.Err()", "return 0, ErrUnavailable", "write", "minimum", "wrong refusal or lost admission ownership"),
    (5, "read-disabled"): (
        "read.go",
        "ctx, cancel := context.WithTimeout(ctx, store.limits.Timeout)",
        "ctx, cancel := context.WithCancel(ctx)",
        "read",
        "minimum",
        "read did not finish at the controlled boundary",
    ),
    (5, "read-early"): (
        "read.go",
        "ctx, cancel := context.WithTimeout(ctx, store.limits.Timeout)",
        "ctx, cancel := context.WithTimeout(ctx, store.limits.Timeout/2)",
        "read",
        "minimum",
        "read completed before its exact deadline",
    ),
    (5, "read-cause"): (
        "read.go",
        "db, conn, err := session(ctx, store.readSQL, store.read)\n\tif err != nil {\n\t\treturn err",
        "db, conn, err := session(ctx, store.readSQL, store.read)\n\tif err != nil {\n\t\treturn ErrUnavailable",
        "read",
        "minimum",
        "wrong read refusal or lost connection ownership",
    ),
    (5, "open-disabled"): (
        "store.go",
        "ctx, cancel := context.WithTimeout(ctx, limits.Timeout)",
        "ctx, cancel := context.WithCancel(ctx)",
        "open",
        "default",
        "opening ignored the expired context",
    ),
    (5, "open-early"): (
        "store.go",
        "ctx, cancel := context.WithTimeout(ctx, limits.Timeout)",
        "ctx, cancel := context.WithTimeout(ctx, limits.Timeout/2)",
        "open",
        "before",
        "opening rejected before its configured deadline",
    ),
}
COMMANDS[7] = {"baseline": 0, **{name: 1 for _, name in MUTANTS}}


def mutation(number: int, name: str) -> tuple:
    """Reuse the eight original operators for the current acquisition without changing their expectations."""
    matches = [value for (campaign, identifier), value in MUTANTS.items() if identifier == name and (number == 7 or campaign == number)]
    if len(matches) != 1:
        v.reject("timeouts-mutation-identity")
    return matches[0]


def retained(artifacts: dict[str, bytes]) -> dict[int, tuple[dict, dict]]:
    """Authenticate native facts, including the unsuccessful attempts, before interpreting any passing slice."""
    if set(artifacts) != set(ARTIFACTS):
        v.reject("timeouts-artifact-inventory")
    result = {}
    for number, digest in ARCHIVES.items():
        data = artifacts[f"reuse-plan/storage-time-current-{number}/native/evidence.tar.gz"]
        if v.digest(data) != digest:
            v.reject("timeouts-archive-integrity")
        files = entry.unpack(data)
        manifest = v.decode(files["manifest.json"])
        if manifest["trust"] != "local" or set(manifest["files"]) != set(files) - {"manifest.json"}:
            v.reject("timeouts-member-inventory")
        if any(item != {"bytes": len(files[name]), "sha256": v.digest(files[name])} for name, item in manifest["files"].items()):
            v.reject("timeouts-member-integrity")
        inputs = v.decode(files["inputs.json"])
        if v.digest(files["source.tar.gz"]) != inputs["source_archive_sha256"]:
            v.reject("timeouts-source-archive")
        original = entry.unpack(files["source.tar.gz"])
        if {name: v.digest(body) for name, body in original.items()} != inputs["files"]:
            v.reject("timeouts-source-inventory")
        result[number] = files, original
    return result


def native(files: dict[str, bytes], number: int) -> dict:
    """Check actual exits, complete streams, retired process identities, offline tools and the original systemd outcome."""
    inputs, owner, cleanup, terminal = (v.decode(files[name]) for name in ("inputs.json", "controller.json", "cleanup.native.json", "terminal.json"))
    boot = inputs["boot_id"]
    failed = number in (1, 2)
    unit = f"astra-storage-time-current-{number}.service"
    native_root = owner["cwd"] + "/source"
    if (
        boot != owner["boot_id"]
        or boot != cleanup["boot_id"]
        or owner["identity"] not in cleanup["retired"]
        or owner["inputs_sha256"] != v.digest(files["inputs.json"])
        or owner["script_sha256"] != v.digest(files["run.py"])
        or inputs["run_sha256"] != v.digest(files["run.py"])
        or terminal["errors"] != (["AssertionError: "] if failed else [])
        or terminal["interrupted"] is not False
        or terminal["remaining_owned"]
        or terminal["cache_restored"] is not True
        or cleanup["unit"]["MainPID"] != "0"
        or cleanup["unit"]["ControlGroup"]
        or set(terminal["checks"]) != set(COMMANDS[number])
    ):
        v.reject("timeouts-native-lifecycle")
    libraries = v.decode(files["stdlib.native.json"])
    if set(libraries["files"]) != {
        "src/context/context.go",
        "src/time/time.go",
        "src/testing/synctest/synctest.go",
        "src/internal/synctest/synctest.go",
        "src/runtime/synctest.go",
    }:
        v.reject("timeouts-standard-library-inventory")
    for item in libraries["files"].values():
        data = item["data"].encode()
        if item["sha256"] != v.digest(data) or item["bytes"] != len(data):
            v.reject("timeouts-standard-library-integrity")
    journal = [v.decode(line) for line in files["journal.native.jsonl"].splitlines()]
    outcome = ": Failed with result 'exit-code'." if failed else ": Deactivated successfully."
    if (
        not journal
        or any(
            row["_BOOT_ID"] != boot.replace("-", "") or (row.get("INVOCATION_ID") or row.get("_SYSTEMD_INVOCATION_ID")) != owner["invocation_id"]
            for row in journal
        )
        or not any(row.get("MESSAGE") == unit + outcome for row in journal)
        or not any(
            isinstance(row.get("MESSAGE"), str) and row["MESSAGE"].startswith('{"at":') and v.decode(row["MESSAGE"].encode()) == terminal for row in journal
        )
    ):
        v.reject("timeouts-native-journal")
    selections = {selection["id"]: selection for selection in inputs["selections"]}
    actual = {name.split("/")[-2] for name in files if name.startswith("source/build/commands/") and name.endswith("/record.json")}
    if actual != set(COMMANDS[number]) or not actual <= set(selections):
        v.reject("timeouts-native-command-inventory")
    result = {}
    for name, code in COMMANDS[number].items():
        prefix = "source/build/commands/" + name + "/"
        plan, record, process = (v.decode(files[prefix + item]) for item in ("plan.json", "record.json", name + ".process.json"))
        expected_argv = [value.replace("{run}", native_root + "/build/commands/" + name) for value in selections[name]["argv"]]
        if (
            type(record["exit_code"]) is not int
            or record["exit_code"] != code
            or record["termination"] != "exited"
            or record["complete"] is not True
            or record["cleanup"] is not True
            or type(record["duration_ms"]) is not int
            or not 0 < record["duration_ms"] <= 120_000
            or record["platform"] != "linux-amd64-cgo"
            or v.stamp(record["finished_at"]) < v.stamp(record["started_at"])
            or record["executable_sha256"] != record["toolchain"]["command"]["sha256"]
            or process["boot_id"] != boot
            or process["cwd"] != native_root
            or process["identity"] not in cleanup["retired"]
            or not (record["argv"] == plan["argv"] == process["argv"] == expected_argv)
            or expected_argv[:8] != ["go", "test", "-json", "-race", "-count=1", "-p=2", "-parallel=1", "-timeout=60s"]
            or expected_argv[-1] != "./polaris/internal/storage"
        ):
            v.reject("timeouts-native-command", name)
        for key, digest in (
            ("command", "30969f97169d7f43fe6a085873d75613adc21e30818a8c61d95bd27275df4624"),
            ("CC", "5ba72afdc29ac57b805ee21e48babe16b31385c03caf91fdd4336483c5a84195"),
            ("CXX", "1d90c88f14873d7a56f015f31ebe1b72a24942fe379d63eac35d18c1d22970f1"),
        ):
            if record["toolchain"][key]["sha256"] != digest:
                v.reject("timeouts-native-tools")
        for key, value in {
            "GOOS": "linux",
            "GOARCH": "amd64",
            "CGO_ENABLED": "1",
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
            "GOFLAGS": "-mod=readonly",
        }.items():
            if record["resolved_environment"][key] != value:
                v.reject("timeouts-native-environment")
        output = server.reference(files, prefix, record["stdout"])
        server.reference(files, prefix, record["stderr"])
        events = [v.decode(line) for line in output.splitlines()]
        if not events or any(row.get("Package") != PACKAGE or row.get("Action") == "skip" for row in events):
            v.reject("timeouts-native-package")
        endings = [row for row in events if "Test" not in row and row.get("Action") in ("pass", "fail")]
        runs = [row["Test"] for row in events if row.get("Action") == "run"]
        closed = [row["Test"] for row in events if "Test" in row and row.get("Action") in ("pass", "fail")]
        if len(endings) != 1 or endings[0]["Action"] != ("pass" if code == 0 else "fail") or sorted(runs) != sorted(closed) or len(runs) != len(set(runs)):
            v.reject("timeouts-native-completion")
        if name != "list":
            profile = files[prefix + "coverage.out"]
            if not profile.startswith(b"mode: atomic\n") or len(profile.splitlines()) < 2:
                v.reject("timeouts-native-coverage")
        result[name] = {"record": record, "plan": plan, "output": output, "events": events}
    return result


def expected(scope: str, mode: str) -> dict:
    """Derive observations from declared time and ownership contracts, independently of production output."""
    if scope not in CASES or mode not in CASES[scope][1]:
        v.reject("timeouts-case")
    if scope == "native":
        return {"scope": scope, "mode": mode, "budget": 20_000_000, "version": 0}
    budget = {"permit": 0, "minimum": 1, "maximum": 30_000_000_000, "parent": 2_000_000_000, "cancel": 0, "past": 0}.get(mode, 5_000_000_000)
    row = {
        "mode": mode,
        "budget": budget,
        "before": max(0, budget - 1) if mode != "jump" else 0,
        "elapsed": budget,
        "recovered": 2 if scope == "write" else 1,
        "records": 2,
        "writer": 0,
        "in_use": 0,
    }
    if scope == "write":
        row["expired"] = int(mode != "permit")
    else:
        row["scope"] = scope
    if scope == "open":
        row["closed"] = 1
        if mode == "before":
            row["elapsed"] -= 1
        elif mode == "jump":
            row["elapsed"] = 86_400_000_000_000
    return row


def histories(data: bytes, scopes: tuple[str, ...]) -> list[dict]:
    """Require every exact nonempty boundary observation; native elapsed time has no invented latency SLO."""
    rows = {}
    for line in data.splitlines():
        event = v.decode(line)
        if event.get("Package") != PACKAGE:
            v.reject("timeouts-history-package")
        output = event.get("Output", "")
        if "STORAGE-TIME " not in output:
            continue
        if output.count("STORAGE-TIME ") != 1 or "\n" in output.rstrip("\n"):
            v.reject("timeouts-history-framing")
        fields = output.split("STORAGE-TIME ", 1)[1].strip().split()
        if any(re.fullmatch(r"[a-z_]+=[a-z]+|[a-z_]+=[0-9]+", field) is None for field in fields):
            v.reject("timeouts-history-fields")
        pairs = [field.split("=", 1) for field in fields]
        if len({key for key, _ in pairs}) != len(pairs):
            v.reject("timeouts-history-duplicate-field")
        row = {key: int(value) if value.isdecimal() else value for key, value in pairs}
        scope, mode = row.get("scope", "write"), row.get("mode")
        wanted = expected(scope, mode)
        if scope not in scopes or event.get("Test") != CASES[scope][0] + "/" + mode or (scope, mode) in rows:
            v.reject("timeouts-history-attribution")
        if scope == "native":
            elapsed = row.pop("elapsed", None)
            if type(elapsed) is not int or elapsed < wanted["budget"]:
                v.reject("timeouts-native-early-timer")
            row["elapsed"] = elapsed
            wanted["elapsed"] = elapsed
        if row != wanted or any(type(value) is not int for key, value in row.items() if key not in {"scope", "mode"}):
            v.reject("timeouts-history-outcome")
        rows[scope, mode] = row
    if set(rows) != {(scope, mode) for scope in scopes for mode in CASES[scope][1]}:
        v.reject("timeouts-history-denominator")
    return list(rows.values())


def sensitivity(files: dict[str, bytes], original: dict[str, bytes], number: int, name: str, command: dict) -> None:
    """Require a physical owned-source change and a semantic native test failure, excluding the ineffective overlay attempt."""
    file, old, new, scope, cell, diagnostic = mutation(number, name)
    prefix = "source/build/commands/" + name + "/"
    before = original[DIRECTORY + file]
    if before.count(old.encode()) != 1:
        v.reject("timeouts-mutation-location")
    after = before.replace(old.encode(), new.encode(), 1)
    variant = files[prefix + file]
    facts = v.decode(files[prefix + "mutation.native.json"])
    mapping = v.decode(files[prefix + "overlay.json"])["Replace"]
    failed = sorted(row["Test"] for row in command["events"] if row.get("Action") == "fail" and "Test" in row)
    suite = CASES[scope][0]
    if (
        variant != after
        or facts["original_sha256"] != v.digest(before)
        or facts["mutant_sha256"] != v.digest(after)
        or facts["before"] != old
        or facts["after"] != new
        or any(path.endswith("/" + file) for path in mapping)
        or failed != sorted([suite, suite + "/" + cell])
        or command["record"]["exit_code"] != 1
        or diagnostic.encode() not in command["output"]
        or any(text in command["output"] for text in (b"panic:", b"DATA RACE", b"[build failed]"))
        or b"production.write_bytes(changed)" not in files["run.py"]
        or b"production.write_bytes(original_body)" not in files["run.py"]
    ):
        v.reject("timeouts-mutation-proof")


def sources(root: Path, retained_sources: dict[int, tuple[dict, dict]]) -> dict:
    """Bind all handwritten Storage sources/tests and fixtures, including dirty workspace contents rather than commit alone."""
    current = {path.relative_to(root).as_posix() for path in (root / DIRECTORY).glob("*.go")}
    selected = current | {"go.mod", "go.sum", "tests/fixtures/timeouts.go.in", "tests/fixtures/deadlines.go.in", "tests/fixtures/timers.go.in"}
    maintenance = 7 in retained_sources
    if maintenance:
        from tools import idle

        if not idle.current(root):
            v.reject("timeouts-current-maintenance-source")
        retained_sources = {7: retained_sources[7]}
        selected.add("dependencies.lock.json")
    result = {}
    for number, (_, original) in retained_sources.items():
        from tools import storagecompiler

        if (root / "development.json").is_file() and storagecompiler.upgraded(root):
            names = selected - {name for name in current if name not in original}
            result.update(storagecompiler.review(root, original, names))
            continue
        if {name for name in original if name.startswith(DIRECTORY) and name.endswith(".go")} != current:
            v.reject("timeouts-current-source-inventory")
        for name in selected & set(original):
            data = v.read(root / name)
            if original[name] != data:
                v.reject("timeouts-current-source-drift", name)
            result[name] = v.digest(data)
    if set(result) != selected:
        v.reject("timeouts-current-fixture-inventory")
    production = {name: v.read(root / name).decode() for name in current if not name.endswith("_test.go")}
    owners = {name.removeprefix(DIRECTORY): text.count("context.WithTimeout(") for name, text in production.items() if "context.WithTimeout(" in text}
    expected_owners = {"commit.go": 1, "read.go": 1, "store.go": 1, **({"maintenance.go": 1} if maintenance else {})}
    if owners != expected_owners or any(re.search(r"\b(?:time\.(?:Now|Sleep|After|NewTimer)|rand\.)", text) for text in production.values()):
        v.reject("timeouts-clock-boundary")
    return result


def policy(config: dict) -> None:
    """Keep numeric and full-core prerequisites; native local clock facts confer no CI or release authority."""
    check = next(item for item in config["checks"] if item["id"] == "gap-time")
    component = next(item for item in config["components"] if item["id"] == "polaris-storage")
    full = next(item for item in component["requirements"] if item["rule"] == "DEV-TIME" and item["scenario"] == "full-rule")
    if (
        check.get("adapter") != "observed-cases"
        or check.get("argv") != ["python3", "-B", "tools/observe.py", "python", *TESTS]
        or check.get("expected_tests") != TESTS
        or check.get("probes") != [{"contract": "STORAGE-TIME", "test": TESTS[0], "minimum_hits": 26}]
        or full.get("aggregate") is not True
        or full.get("checks") != []
        or full.get("requires")
        != [
            {"rule": "DEV-TIME", "contract": "STORAGE-TIME", "scenario": "virtual-and-host-deadlines"},
            {"rule": "DEV-NUMERIC", "contract": "STORAGE-ASSURANCE", "scenario": "full-rule"},
            {"rule": "DEV-CORE", "contract": "STORAGE-ASSURANCE", "scenario": "full-rule"},
        ]
    ):
        v.reject("timeouts-policy")


def reconcile(root: Path, artifacts: dict[str, bytes] | None = None) -> dict:
    """Reconstruct the complete declared local temporal scope from original native facts and independent expected outcomes."""
    if artifacts is None:
        artifacts = {name: v.read(root / "build/results/assurance" / name, 128 * 1024**2) for name in ARTIFACTS}
    retained_sources = retained(artifacts)
    rows, kills, maintenance = [], [], []
    for number, (files, original) in retained_sources.items():
        if 7 in retained_sources and number != 7:
            continue
        commands = native(files, number)
        if number in (1, 5, 6, 7):
            scopes = {1: ("write",), 5: ("read", "open"), 6: ("native",), 7: tuple(CASES)}[number]
            expected_tests = [name for scope in scopes for name in (CASES[scope][0], *(CASES[scope][0] + "/" + mode for mode in CASES[scope][1]))]
            probes = [{"contract": "STORAGE-TIME", "test": CASES[scope][0], "minimum_hits": len(CASES[scope][1])} for scope in scopes]
            if number == 7:
                expected_tests += ["TestMaintenanceFailure", "TestMaintenanceDeadline"]
                maintenance = [
                    {"test": "TestMaintenanceFailure", "contract": "STORAGE-CHECKPOINT", "minimum_hits": 7},
                    {"test": "TestMaintenanceDeadline", "contract": "STORAGE-TIME", "minimum_hits": 6},
                ]
                probes += maintenance
            check = {
                **commands["baseline"]["plan"],
                "expected_tests": expected_tests,
                "probes": probes,
            }
            observed, failures = v.go_observations(commands["baseline"]["output"], check)
            passed = [row["Test"] for row in commands["baseline"]["events"] if row.get("Action") == "pass" and "Test" in row]
            expected = {"STORAGE-TIME": sum(len(CASES[scope][1]) for scope in scopes)}
            if number == 7:
                expected["STORAGE-TIME"] += 6
                expected["STORAGE-CHECKPOINT"] = 7
            if failures or sorted(passed) != sorted(expected_tests) or observed != expected:
                v.reject("timeouts-positive-inventory")
            rows.extend(histories(commands["baseline"]["output"], scopes))
        for campaign, name in MUTANTS:
            if number == campaign or number == 7:
                sensitivity(files, original, number, name, commands[name])
                kills.append(name)
    bindings = sources(root, retained_sources)
    if len(rows) != 24 or len(kills) != 8:
        v.reject("timeouts-total-denominator")
    return {
        "trust": "local",
        "cases": rows,
        "killed": kills,
        "sources": bindings,
        "maintenance": maintenance,
        "observations": len(rows) + len(maintenance),
        "excluded": "The ineffective overlay mutation remains unsuccessful; original failed controllers are not relabelled as passed.",
        "domain": "Go monotonic context durations; native I/O drains cooperatively. No persisted deadlines, leases, civil-time scheduling or random source belongs to this Storage component.",
    }
