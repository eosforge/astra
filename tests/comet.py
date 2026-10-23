"""Prepare isolated SDK dependency-stub inputs without compiling, testing, networking, or changing maintained source."""

import argparse
import hashlib
from pathlib import Path

# Resolve source and public fixture inputs independently of the caller's directory.
ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "comet/go"
FIXTURES = ROOT / "tests/fixtures/comet"
# Exact original inputs used by the retained login and Linux clock experiments.
CONNECTION_SHA256 = "e95f4847db425f8b15d108c1caa61e24e65b83c9f31ecdfd18edbe9f1272d83e"
SYSCALL_SHA256 = "2903ee63248999159b31618b694ef2be85ec4bc917d91bcef019a2bf1deccf9a"


def replace(text: str, original: str, replacement: str, count: int) -> str:
    """Reject changed injection sites instead of silently preparing a different experiment."""
    if text.count(original) != count:
        raise ValueError(f"Changed fixture injection site: {original}")
    return text.replace(original, replacement)


def pinned(path: Path, expected: str) -> str:
    """Read an exact source input before any test-only dependency substitution."""
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError(f"Source differs from the retained fixture: {path}")
    return raw.decode("utf-8")


def prepare(profile: str, output: Path, dependency: Path | None) -> None:
    """Materialize one fresh module under build/; preserve the original SDK and dependency cache.

    Args:
        profile: Login fences or Linux clock failure models.
        output: A new directory inside this checkout's ignored build tree.
        dependency: Existing golang.org/x/sys v0.48.0 source, required for clock models.

    Raises:
        ValueError: An input, injection site, or output boundary differs from the declared fixture.
        OSError: A required local file cannot be read or the fresh output cannot be written.
    """
    output = output.resolve()
    build = ROOT / "build"
    if build.is_symlink() or output == build or not output.is_relative_to(build) or output.exists():
        raise ValueError("Output must be a new directory inside this checkout's build tree")
    # Root tests supply shared helpers; only the explicitly selected fixture is executed by the later Go command.
    paths = [*MODULE.glob("*.go"), *MODULE.joinpath("internal").rglob("*.go"), MODULE / "go.mod", MODULE / "go.sum"]
    contents = {Path("module") / path.relative_to(MODULE): path.read_bytes() for path in paths}
    if profile == "login":
        if dependency is not None:
            raise ValueError("The login fixture does not replace a module dependency")
        connection = pinned(MODULE / "connection.go", CONNECTION_SHA256)
        for original, replacement, count in (
            ("client.transport(endpoint)", "loginBoundary.transport(client, endpoint)", 2),
            ("ready(ctx, streams)", "loginBoundary.ready(ctx, streams)", 1),
            ("ready(ctx, unary)", "loginBoundary.ready(ctx, unary)", 1),
            ("protocol.NewGatewayClient(streams).Session(ctx,", "loginBoundary.session(streams, ctx,", 1),
        ):
            connection = replace(connection, original, replacement, count)
        contents[Path("module/connection.go")] = connection.encode("utf-8")
        contents[Path("module/loginboundary.go")] = (FIXTURES / "login.go.in").read_bytes()
        contents[Path("module/loginboundary_test.go")] = (FIXTURES / "login_test.go.in").read_bytes()
    elif profile == "clock":
        if dependency is None:
            raise ValueError("Clock preparation requires --sys-module pointing to an existing golang.org/x/sys v0.48.0")
        dependency = dependency.resolve()
        syscall = pinned(dependency / "unix/zsyscall_linux.go", SYSCALL_SHA256)
        syscall = replace(syscall, "func ClockGettime(", "func astraOriginalClockGettime(", 1)
        # Copy the dependency's source and license, never alter its installed cache or publish generated dependency copies.
        for path in dependency.rglob("*"):
            if path.is_file() and path.suffix in {".go", ".s", ".h", ".c"}:
                contents[Path("sys") / path.relative_to(dependency)] = path.read_bytes()
        for name in ("go.mod", "LICENSE", "PATENTS"):
            contents[Path("sys") / name] = (dependency / name).read_bytes()
        contents[Path("sys/unix/zsyscall_linux.go")] = syscall.encode("utf-8")
        contents[Path("sys/unix/zz_astra_unit_clock_linux.go")] = (FIXTURES / "clock_linux.go.in").read_bytes()
        contents[Path("module/isolatedclock_linux_test.go")] = (FIXTURES / "clock_linux_test.go.in").read_bytes()
        module = contents[Path("module/go.mod")].decode("utf-8")
        if "golang.org/x/sys v0.48.0" not in module or "replace " in module:
            raise ValueError("Clock fixture requires the unchanged SDK module dependency declaration")
        contents[Path("module/go.mod")] = (module.rstrip() + "\n\nreplace golang.org/x/sys => ../sys\n").encode("utf-8")
    else:
        raise ValueError("Unknown dependency-stub profile")
    # Validate all inputs before creating output. An interrupted write remains visibly incomplete and is never reused.
    output.mkdir(parents=True, exist_ok=False)
    for relative, raw in sorted(contents.items()):
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    print(f"Prepared {profile} fixture at {output / 'module'}; no build or test was run.")


def main() -> None:
    """Parse preparation inputs only; execution and host resource limits remain explicit caller responsibilities."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=("login", "clock"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sys-module", type=Path)
    options = parser.parse_args()
    prepare(options.profile, options.output, options.sys_module)


if __name__ == "__main__":
    main()
