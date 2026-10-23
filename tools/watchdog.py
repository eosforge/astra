"""Exercise watchdog rescheduling with immutable overlays, native receipts and an exact negative oracle."""

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import signal
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import build, verify as v

# The checkpoint follows timer selection; only production code may publish or inspect a deadline.
SOURCE = "polaris/internal/server/stream.go"
FIXTURE = "tests/fixtures/watchdog.go.in"
ANCHOR = "\t\tcase <-timer.C:\n\t\t\t// A wake may have extended or cleared the phase after this timer became ready."
GUARD = "if err := transfer.expire(timer); err != nil {"
BROKEN = 'if err := status.Error(codes.DeadlineExceeded, "forced stale notification"); err != nil {'
# Native profiles share two required schedules; the negative profile must reject both, not merely exit nonzero.
PROFILES = ("baseline", "race", "expired")
PACKAGE = "github.com/eosforge/astra/polaris/internal/server"
TESTS = {"TestWatchdog", "TestWatchdog/cleared", "TestWatchdog/extended"}
LOG_BYTES = 4 * 1024**2
HOOK = """
// Test-only scheduler ownership ends after both the handler and its workers retire.
var watchpoint func(*transfer, *time.Timer)

// checkpoint selects an existing interleaving without changing the production phase state.
func checkpoint(state *transfer, timer *time.Timer) {
	if watchpoint != nil {
		watchpoint(state, timer)
	}
}
"""


def pause(text: str, *, traced: bool = False) -> str:
    """Insert only the schedule checkpoint, preserving existing native Boolean instrumentation.

    Traced input still needs its collector/source receipts verified by the caller.
    This transformation provides neither coverage counts nor acceptance evidence.
    """
    guard = "if err := transfer.expire(timer); func() bool {" if traced else GUARD
    if text.count(ANCHOR) != 1 or text.count(guard) != 1 or "watchpoint" in text or "checkpoint(" in text:
        raise ValueError("watchdog source no longer has the reviewed checkpoint and guard")
    return text.replace(ANCHOR, ANCHOR.replace("\n", "\n\t\t\tcheckpoint(transfer, timer)\n", 1)) + HOOK


def compose(root: Path, origin: Path, output: Path, *, create: bool = False) -> dict:
    """Bind a schedule overlay to exact collector bytes; the caller must authenticate the collector's native receipt."""
    root, origin, output = root.resolve(), origin.resolve(), output.resolve()
    for directory in (origin, output):
        if not directory.is_relative_to(root / "build") or directory == root / "build":
            v.reject("watchdog-compose-boundary")
    if origin == output or origin.is_relative_to(output) or output.is_relative_to(origin):
        v.reject("watchdog-compose-overlap")
    overlay = v.decode(v.read(origin / "overlay.json"))
    if not isinstance(overlay, dict) or set(overlay) != {"Replace"} or not isinstance(overlay["Replace"], dict):
        v.reject("watchdog-compose-overlay")
    folder = Path(SOURCE).parent
    owned = {path.relative_to(root).as_posix() for path in (root / folder).rglob("*.go") if not path.name.endswith("_test.go")}
    helpers = {str(folder / name).replace("\\", "/") for name in ("zz_astra_probe.go", "zz_astra_probe_test.go")}
    fixture = folder / "watchdog_test.go"
    if SOURCE not in owned or any(Path(name).parent != folder for name in owned) or any((root / name).exists() for name in helpers | {fixture.as_posix()}):
        v.reject("watchdog-compose-source")
    expected = {str(root / name) for name in owned | helpers}
    if set(overlay["Replace"]) != expected:
        v.reject("watchdog-compose-domain")
    contents, mapping = {}, {}
    for original, replacement in overlay["Replace"].items():
        if replacement != str(origin / Path(original).name):
            v.reject("watchdog-compose-replacement")
        data = v.read(v.inside(root, Path(replacement).relative_to(root).as_posix()))
        if original == str(root / SOURCE):
            changed = pause(data.decode("utf-8"), traced=True).encode("utf-8")
            if changed.removesuffix(HOOK.encode()).replace(b"\t\t\tcheckpoint(transfer, timer)\n", b"") != data:
                v.reject("watchdog-compose-restoration")
            data = changed
        contents[Path(original).name] = data
        mapping[original] = str(output / Path(original).name)
    contents[fixture.name] = v.read(root / FIXTURE)
    mapping[str(root / fixture)] = str(output / fixture.name)
    contents["overlay.json"] = v.encode({"Replace": mapping})
    receipt = {
        "collector_overlay": v.file_digest(origin / "overlay.json"),
        "trace": v.file_digest(origin / "trace.json"),
        "fixture": v.file_digest(root / FIXTURE),
        "generated": {name: v.digest(data) for name, data in sorted(contents.items())},
        "qualification": "not-evaluated",
    }
    if create:
        output.mkdir(parents=True, exist_ok=False)
        for name, data in contents.items():
            v.write_new(output / name, data)
        v.write_new(output / "composition.json", receipt)
    else:
        if {p.name for p in output.iterdir()} != set(contents) | {"composition.json"}:
            v.reject("watchdog-compose-files")
        for name, data in contents.items():
            if v.read(v.inside(root, (output / name).relative_to(root).as_posix())) != data:
                v.reject("watchdog-compose-drift", name)
        if v.decode(v.read(output / "composition.json")) != receipt:
            v.reject("watchdog-compose-receipt")
    return receipt


def generate(root: Path, output: Path) -> dict:
    """Bind two immutable compiler overlays to exact source and fixture bytes; refuse ambiguous rewrites."""
    root, output = root.resolve(), output.resolve()
    if not output.is_relative_to(root / "build") or output == root / "build":
        raise ValueError("watchdog output must be a fresh project build subdirectory")
    source, fixture = root / SOURCE, root / FIXTURE
    if (source.parent / "watchdog_test.go").exists():
        raise ValueError("watchdog overlay must not replace an existing test")
    original, tests = source.read_bytes(), fixture.read_bytes()
    text = original.decode("utf-8").replace("\r\n", "\n")
    target = pause(text)
    if tests.count(b"func TestWatchdog(") != 1 or b"package server" not in tests:
        raise ValueError("watchdog fixture identity is incomplete")
    output.mkdir(parents=True, exist_ok=False)
    records = {}
    for name in ("baseline", "expired"):
        directory = output / name
        directory.mkdir()
        data = target if name == "baseline" else target.replace(GUARD, BROKEN)
        body, case = directory / "stream.go", directory / "watchdog_test.go"
        body.write_bytes(data.encode("utf-8"))
        case.write_bytes(tests)
        overlay = {"Replace": {str(source): str(body), str(source.parent / "watchdog_test.go"): str(case)}}
        (directory / "overlay.json").write_text(json.dumps(overlay, sort_keys=True) + "\n", encoding="utf-8")
        records[name] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (body, case, directory / "overlay.json")}
    manifest = {
        "source": {SOURCE: hashlib.sha256(original).hexdigest(), FIXTURE: hashlib.sha256(tests).hexdigest()},
        "variants": records,
        "qualification": "not-evaluated",
        "boundary": "A test-only pause follows timer selection. The expired variant deliberately skips production deadline revalidation; it must fail both schedule oracles.",
    }
    (output / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def outcome(data: bytes, errors: bytes, record: dict, profile: str) -> dict:
    """Require ordered native test terminals and the two exact semantic witnesses; reject unrelated failures."""
    if profile not in PROFILES:
        v.reject("watchdog-profile")
    if not record["complete"] or not record["cleanup"] or record["termination"] != "exited":
        v.reject("watchdog-incomplete")
    expected = "fail" if profile == "expired" else "pass"
    if record["exit_code"] != (1 if profile == "expired" else 0):
        v.reject("watchdog-exit")
    # Package-level and per-test lifecycle facts are independent of the text witnesses.
    states, outputs, started, complete = {}, {}, False, False
    for line in data.splitlines():
        row = v.decode(line)
        if not isinstance(row, dict) or row.get("Package") != PACKAGE or complete:
            v.reject("watchdog-stream")
        action, test = row.get("Action"), row.get("Test")
        if action == "start":
            if started or test is not None:
                v.reject("watchdog-package-start")
            started = True
            continue
        if not started:
            v.reject("watchdog-package-start")
        if action == "run":
            if test not in TESTS or test in states or (test != "TestWatchdog" and states.get("TestWatchdog") != "running"):
                v.reject("watchdog-test-start")
            states[test] = "running"
        elif action == "output":
            if not isinstance(row.get("Output"), str) or (test is not None and states.get(test) != "running"):
                v.reject("watchdog-output")
            outputs[test] = outputs.get(test, "") + row["Output"]
        elif action in ("pass", "fail", "skip"):
            if action != expected:
                v.reject("watchdog-result")
            if test is None:
                if set(states) != TESTS or any(state != expected for state in states.values()):
                    v.reject("watchdog-tests-incomplete")
                complete = True
            elif states.get(test) != "running":
                v.reject("watchdog-test-end")
            else:
                states[test] = action
        else:
            v.reject("watchdog-action")
    if not complete:
        v.reject("watchdog-no-terminal")
    markers = (
        ("stale timer replaced completed send result", "stale timer ended replacement phase")
        if profile == "expired"
        else ("WATCHDOG-SCHEDULE cleared complete 1", "WATCHDOG-SCHEDULE extended complete 2")
    )
    for name, marker in zip(("cleared", "extended"), markers):
        if outputs.get("TestWatchdog/" + name, "").count(marker) != 1:
            v.reject("watchdog-witness", name)
    text = "".join(outputs.values()) + errors.decode("utf-8", errors="replace")
    if any(marker in text for marker in ("WARNING: DATA RACE", "panic:", "fatal error:")):
        v.reject("watchdog-runtime-failure")
    return {"terminals": len(states), "outcome": expected, "markers": list(markers)}


def command(output: Path, profile: str) -> list[str]:
    """Select one reviewed compiler overlay and retain the same deterministic test selection in every profile."""
    if profile not in PROFILES:
        v.reject("watchdog-profile")
    variant = "expired" if profile == "expired" else "baseline"
    argv = [str(build.CACHE / "tools/go-1.27.2/bin/go"), "test"]
    if profile == "race":
        argv.append("-race")
    return argv + [
        "-json",
        "-count=1",
        "-p=2",
        "-parallel=1",
        "-timeout=60s",
        "-run=^TestWatchdog$",
        "-overlay=" + str(output / variant / "overlay.json"),
        "./polaris/internal/server",
    ]


def inspect(root: Path, output: Path) -> dict:
    """Independently bind recorded streams to current source, exact overlay edits and native execution facts."""
    root, output = root.resolve(), output.resolve()
    manifest = v.decode(v.read(output / "manifest.json"))
    if set(manifest["variants"]) != {"baseline", "expired"}:
        v.reject("watchdog-variants")
    if manifest["source"] != {name: v.file_digest(root / name) for name in (SOURCE, FIXTURE)}:
        v.reject("watchdog-source-drift")
    original = (root / SOURCE).read_text(encoding="utf-8")
    normal = (output / "baseline/stream.go").read_text(encoding="utf-8")
    pause = "\t\t\tcheckpoint(transfer, timer)\n"
    if normal.count(pause) != 1 or not normal.endswith(HOOK) or normal.removesuffix(HOOK).replace(pause, "") != original:
        v.reject("watchdog-transform")
    broken = (output / "expired/stream.go").read_text(encoding="utf-8")
    if broken == normal or broken.replace(BROKEN, GUARD) != normal:
        v.reject("watchdog-negative-transform")
    for name in ("baseline", "expired"):
        directory = output / name
        expected = {path: v.file_digest(directory / path) for path in ("stream.go", "watchdog_test.go", "overlay.json")}
        if manifest["variants"][name] != expected or v.read(directory / "watchdog_test.go") != v.read(root / FIXTURE):
            v.reject("watchdog-overlay-drift")
        mapping = {
            str(root / SOURCE): str(directory / "stream.go"),
            str(root / "polaris/internal/server/watchdog_test.go"): str(directory / "watchdog_test.go"),
        }
        if v.decode(v.read(directory / "overlay.json")) != {"Replace": mapping}:
            v.reject("watchdog-overlay-path")
    profiles = {}
    for profile in PROFILES:
        directory = output / "records" / profile
        record = v.decode(v.read(directory / "record.json"))
        v.schema(record, "evidence", ("properties", "checks", "items"))
        if record["id"] != profile or record["platform"] != "linux-amd64-cgo" or record["argv"] != command(output, profile):
            v.reject("watchdog-command")
        for key, expected in {"GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": "-mod=readonly"}.items():
            if record["resolved_environment"].get(key) != expected:
                v.reject("watchdog-environment")
        profiles[profile] = outcome(v.reference(directory, record["stdout"], LOG_BYTES), v.reference(directory, record["stderr"], LOG_BYTES), record, profile)
    return {"profiles": profiles, "qualification": "not-evaluated", "trust": "local"}


def run(root: Path, output: Path) -> int:
    """Run the finite three-profile plan under its authorized owner's resource limits and drain on cancellation."""
    if sys.platform != "linux" or ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0):
        v.reject("watchdog-linux-subreaper-required")
    generate(root, output)
    source = v.source(root)
    v.write_new(output / "inputs.json", source)
    stopped = False

    def cancel(*_: object) -> None:
        """Forward a stop request to the active native executor before returning from this owner."""
        nonlocal stopped
        stopped = True

    handlers = {number: signal.signal(number, cancel) for number in (signal.SIGTERM, signal.SIGINT)}
    errors, results = [], None
    try:
        environment = build.environment(jobs=2)
        for profile in PROFILES:
            if stopped or v.source(root) != source:
                v.reject("watchdog-interrupted-or-source-drift")
            directory = output / "records" / profile
            directory.mkdir(parents=True)
            plan = {
                "id": profile,
                "argv": command(output, profile),
                "environment": {**environment, "TMPDIR": str(directory / "tmp")},
                "timeout_s": 300,
                "log_bytes": LOG_BYTES,
            }
            v.write_new(directory / "plan.json", plan)
            record = v.execute(plan, root, directory, "linux-amd64-cgo", lambda: stopped)
            v.write_new(directory / "record.json", record)
            outcome(v.reference(directory, record["stdout"], LOG_BYTES), v.reference(directory, record["stderr"], LOG_BYTES), record, profile)
        results = inspect(root, output)
    except (OSError, ValueError, v.Invalid) as error:
        errors.append(str(error))
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)
    unchanged, remaining = v.source(root) == source, v.owned_members()
    complete = results is not None and not errors and not stopped and unchanged and not remaining
    result = {
        "status": "completed" if complete else "interrupted" if stopped else "blocked",
        "results": results,
        "errors": errors,
        "source_unchanged": unchanged,
        "remaining_owned": remaining,
    }
    v.write_new(output / "result.json", result)
    print(v.encode(result).decode())
    return 0 if complete else 2


def main() -> int:
    """Generate without execution by default; the explicit run mode also needs current test authorization."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--inspect", action="store_true")
    args = parser.parse_args()
    if args.run:
        return run(args.root.resolve(), args.output.resolve())
    if args.inspect:
        print(v.encode(inspect(args.root, args.output)).decode())
        return 0
    print(json.dumps(generate(args.root, args.output), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
