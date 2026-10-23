"""Verify subscription ordering with a real durable commit and source-bound compiler overlays."""

import argparse
import ctypes
from pathlib import Path
import signal
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import build, verify as v

# These exact boundaries preserve List and move only the feed's acquisition, error handling and cleanup.
SOURCE = "polaris/internal/server/stream.go"
FIXTURE = "tests/fixtures/subscription.go.in"
BLOCK = "\tfeed, err := transfer.owner.authority.store.Subscribe(8<<20, 16384)\n\tif err != nil {\n\t\treturn failure(err)\n\t}\n\tdefer feed.Close()\n"
ANCHOR = "\tpositions, err := transfer.owner.authority.store.List(transfer.ctx)\n\tif err != nil {\n\t\treturn failure(err)\n\t}\n\ttransfer.plan = make(map[storage.Scope]storage.Version, len(positions))"
POINT = "\tinventoryCheckpoint(transfer)\n"
HOOK = """
// The callback runs after List releases its transaction; it cannot change captured positions or feed contents.
var inventoryPoint func(*transfer)

// inventoryCheckpoint permits a durable commit in the existing gap after inventory capture.
func inventoryCheckpoint(state *transfer) {
	if inventoryPoint != nil {
		inventoryPoint(state)
	}
}
"""
# Every profile selects one test; only the reordered profile may fail, at its exact missing-delivery assertion.
PROFILES = ("baseline", "race", "late")
PACKAGE = "github.com/eosforge/astra/polaris/internal/server"
TEST = "TestSubscription"
SUCCESS = "SUBSCRIPTION-SCHEDULE complete 1"
FAILURE = "scope committed after inventory capture was lost before subscription"
LOG_BYTES = 4 * 1024**2


def transform(text: str) -> dict[str, str]:
    """Keep both variants identical except for the subscription block's position around one shared checkpoint."""
    if text.count(BLOCK) != 1 or text.count(ANCHOR) != 1 or text.index(BLOCK) > text.index(ANCHOR):
        v.reject("subscription-source")
    if "inventoryPoint" in text or "inventoryCheckpoint" in text:
        v.reject("subscription-reserved")
    head, tail = ANCHOR.rsplit("\n", 1)
    normal = text.replace(ANCHOR, head + "\n" + POINT + tail) + HOOK
    late = normal.replace(BLOCK, "").replace(POINT, POINT + BLOCK)
    return {"baseline": normal, "late": late}


def contents(root: Path, output: Path) -> dict[str, bytes]:
    """Derive all overlay bytes from current inputs, without running or accepting any test."""
    if not output.is_relative_to(root / "build") or output == root / "build":
        v.reject("subscription-output")
    source, fixture = root / SOURCE, root / FIXTURE
    virtual = source.parent / "subscription_test.go"
    if virtual.exists():
        v.reject("subscription-existing-test")
    tests = v.read(fixture)
    if tests.count(b"func TestSubscription(") != 1 or b"package server" not in tests:
        v.reject("subscription-fixture")
    files, variants = {}, {}
    for name, text in transform(source.read_text(encoding="utf-8")).items():
        folder = output / name
        items = {"stream.go.txt": text.encode("utf-8"), "subscription.go.txt": tests}
        items["overlay.json"] = v.encode({"Replace": {str(source): str(folder / "stream.go.txt"), str(virtual): str(folder / "subscription.go.txt")}})
        variants[name] = {path: v.digest(data) for path, data in items.items()}
        files.update({name + "/" + path: data for path, data in items.items()})
    files["manifest.json"] = v.encode(
        {
            "source": {name: v.file_digest(root / name) for name in (SOURCE, FIXTURE)},
            "variants": variants,
            "qualification": "not-evaluated",
            "boundary": "A real commit follows captured inventory. Only the negative overlay subscribes afterwards; timer advancement is forbidden.",
        }
    )
    return files


def generate(root: Path, output: Path) -> dict:
    """Write one fresh immutable plan; generated text is not native execution evidence."""
    root, output = root.resolve(), output.resolve()
    files = contents(root, output)
    output.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        (output / name).parent.mkdir(parents=True, exist_ok=True)
        v.write_new(output / name, data)
    return v.decode(files["manifest.json"])


def outcome(data: bytes, errors: bytes, record: dict, profile: str) -> dict:
    """Reject incomplete lifecycles, borrowed witnesses and unrelated failures, even for a nonzero negative exit."""
    if profile not in PROFILES:
        v.reject("subscription-profile")
    if record.get("complete") is not True or record.get("cleanup") is not True or record.get("termination") != "exited":
        v.reject("subscription-incomplete")
    expected = "fail" if profile == "late" else "pass"
    if record.get("exit_code") != (1 if profile == "late" else 0):
        v.reject("subscription-exit")
    started, state, complete = False, None, False
    outputs = {}
    for line in data.splitlines():
        row = v.decode(line)
        if not isinstance(row, dict) or row.get("Package") != PACKAGE or complete:
            v.reject("subscription-stream")
        action, test = row.get("Action"), row.get("Test")
        if test not in (None, TEST):
            v.reject("subscription-test")
        if action == "start":
            if started or test is not None:
                v.reject("subscription-package-start")
            started = True
            continue
        if not started:
            v.reject("subscription-package-start")
        if action == "run":
            if test != TEST or state is not None:
                v.reject("subscription-test-start")
            state = "running"
        elif action == "output":
            if not isinstance(row.get("Output"), str) or (test is not None and state != "running"):
                v.reject("subscription-output")
            outputs[test] = outputs.get(test, "") + row["Output"]
        elif action in ("pass", "fail", "skip"):
            if action != expected:
                v.reject("subscription-result")
            if test is None:
                if state != expected:
                    v.reject("subscription-test-incomplete")
                complete = True
            elif state != "running":
                v.reject("subscription-test-end")
            else:
                state = action
        else:
            v.reject("subscription-action")
    if not complete:
        v.reject("subscription-no-terminal")
    marker = FAILURE if profile == "late" else SUCCESS
    if outputs.get(TEST, "").count(marker) != 1:
        v.reject("subscription-witness")
    combined = "".join(outputs.values()) + errors.decode("utf-8", errors="replace")
    forbidden = (
        "WARNING: DATA RACE",
        "panic:",
        "fatal error:",
        "inventory-boundary stream did not release its owned state",
        "inventory-boundary store did not close",
        SUCCESS if profile == "late" else FAILURE,
    )
    if any(word in combined for word in forbidden):
        v.reject("subscription-runtime-failure")
    return {"terminals": 1, "outcome": expected, "marker": marker}


def command(output: Path, profile: str) -> list[str]:
    """Run precisely the same fixture for the ordinary, Race and intentionally reordered profiles."""
    if profile not in PROFILES:
        v.reject("subscription-profile")
    variant = "late" if profile == "late" else "baseline"
    return (
        [str(build.CACHE / "tools/go-1.27.2/bin/go"), "test"]
        + (["-race"] if profile == "race" else [])
        + [
            "-json",
            "-count=1",
            "-p=2",
            "-parallel=1",
            "-timeout=60s",
            "-run=^TestSubscription$",
            "-overlay=" + str(output / variant / "overlay.json"),
            "./polaris/internal/server",
        ]
    )


def inspect(root: Path, output: Path) -> dict:
    """Reconstruct each overlay before interpreting native command receipts and exact lifecycle outcomes."""
    root, output = root.resolve(), output.resolve()
    files = contents(root, output)
    for name, expected in files.items():
        if v.read(v.inside(root, (output / name).relative_to(root).as_posix())) != expected:
            v.reject("subscription-overlay-drift", name)
    for name in ("baseline", "late"):
        if {path.name for path in (output / name).iterdir()} != {"stream.go.txt", "subscription.go.txt", "overlay.json"}:
            v.reject("subscription-overlay-files")
    profiles = {}
    for profile in PROFILES:
        directory = output / "records" / profile
        record = v.decode(v.read(directory / "record.json"))
        v.schema(record, "evidence", ("properties", "checks", "items"))
        if record["id"] != profile or record["platform"] != "linux-amd64-cgo" or record["argv"] != command(output, profile):
            v.reject("subscription-command")
        for key, expected in {"GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": "-mod=readonly"}.items():
            if record["resolved_environment"].get(key) != expected:
                v.reject("subscription-environment")
        profiles[profile] = outcome(v.reference(directory, record["stdout"], LOG_BYTES), v.reference(directory, record["stderr"], LOG_BYTES), record, profile)
    return {"profiles": profiles, "qualification": "not-evaluated", "trust": "local"}


def run(root: Path, output: Path) -> int:
    """Execute the finite plan inside its authorized owner's limits, preserving native facts before interpretation."""
    if sys.platform != "linux" or ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0):
        v.reject("subscription-linux-subreaper-required")
    generate(root, output)
    source = v.source(root)
    v.write_new(output / "inputs.json", source)
    stopped = False

    def cancel(*_: object) -> None:
        """Drain the active executor before returning from its owner."""
        nonlocal stopped
        stopped = True

    handlers = {number: signal.signal(number, cancel) for number in (signal.SIGTERM, signal.SIGINT)}
    errors, results = [], None
    try:
        environment = build.environment(jobs=2)
        for profile in PROFILES:
            if stopped or v.source(root) != source:
                v.reject("subscription-interrupted-or-source-drift")
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
    """Generate without execution by default; running requires current test authorization and bounded ownership."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--inspect", action="store_true")
    args = parser.parse_args()
    if args.run:
        return run(args.root.resolve(), args.output.resolve())
    print(v.encode(inspect(args.root, args.output) if args.inspect else generate(args.root, args.output)).decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
