"""Offline C++26/Go core service build, generation and owned process regression."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tools.paths import CACHE, isolate

SOURCE = ROOT
PREFIX = CACHE / "deps/astra/linux-gcc16/install"


def environment(prefix: Path = PREFIX, jobs: int = 1) -> dict[str, str]:
    """Select project tools and libraries for children without changing the caller or system."""
    isolate(ROOT / "build")
    result = dict(os.environ)
    gcc = CACHE / "tools/gcc-16.2.0"
    # GCC distributions may also ship a gccgo-backed command named go; select the locked Go toolchain first.
    result["PATH"] = os.pathsep.join(
        path for path in (str(CACHE / "tools/go-1.27.2/bin"), str(gcc / "bin"), str(prefix / "bin"), result.get("PATH", "")) if path
    )
    # Dependencies link statically. A global library path could make Rust/LLVM load TSan zlib into the compiler.
    # Omit empty inherited values: a trailing separator would add the working directory to library search paths.
    result["LD_LIBRARY_PATH"] = os.pathsep.join(path for path in (str(gcc / "lib64"), result.get("LD_LIBRARY_PATH", "")) if path)
    result["CMAKE_BUILD_PARALLEL_LEVEL"] = str(jobs)
    result["GOMAXPROCS"] = str(jobs)
    result["GOPATH"] = str(CACHE / "deps/go")
    result["GOMODCACHE"] = str(CACHE / "deps/go/pkg/mod")
    result["GOCACHE"] = str(ROOT / "build/cache/go")
    result["GOTOOLCHAIN"] = "local"
    result["GOWORK"] = "off"
    result["GOPROXY"] = "off"
    result["GOSUMDB"] = "off"
    result["GOFLAGS"] = "-mod=readonly"
    result["CGO_ENABLED"] = "1"
    result["CC"] = str(gcc / "bin/gcc")
    result["CXX"] = str(gcc / "bin/g++")
    result["PYTHONDONTWRITEBYTECODE"] = "1"
    result["TMPDIR"] = str(ROOT / "build/tmp")
    Path(result["TMPDIR"]).mkdir(parents=True, exist_ok=True)
    return result


def resources() -> tuple[int, int | None]:
    """Read current Linux allocation and cgroup v2 limits, not the VM's configured maximum."""
    cpus = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count() or 1
    available = None
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                available = int(line.split()[1]) * 1024
        group = next(
            (line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines() if line.startswith("0::")),
            None,
        )
        base = Path("/sys/fs/cgroup")
        current = base / group.lstrip("/") if group is not None else base
        while current.is_relative_to(base):
            try:
                maximum = (current / "memory.max").read_text().strip()
                if maximum != "max":
                    unused = max(0, int(maximum) - int((current / "memory.current").read_text()))
                    available = unused if available is None else min(available, unused)
            except (OSError, ValueError):
                pass
            try:
                quota, period = (current / "cpu.max").read_text().split()
                if quota != "max":
                    cpus = min(cpus, max(1, int(quota) // int(period)))
            except (OSError, ValueError, ZeroDivisionError):
                pass
            current = current.parent
    except (OSError, ValueError):
        pass
    return cpus, available


def parallel(cpus: int, available: int | None, profile: str, build: int = 0, tests: int = 0) -> tuple[int, int]:
    """Budget sequential phases independently; explicit job counts can only lower the estimated limits."""
    reserve = 512 << 20
    budget = max(0, available - reserve) if available is not None else 0
    heavy = profile in {"asan", "tsan"}
    builds = min(cpus, max(1, budget // ((1400 if heavy else 900) << 20)))
    cases = min(cpus, max(1, budget // ((512 if heavy else 256) << 20)))
    return min(builds, build or builds), min(cases, tests or cases)


def run(command: list[str | Path], env: dict[str, str]) -> None:
    """Pass argument lists without a shell; preserve failures without invoking package-manager repair."""
    print("Running: " + subprocess.list2cmdline(list(map(str, command))), flush=True)
    subprocess.run(list(map(str, command)), cwd=ROOT, env=env, check=True)


def generated(check: bool, env: dict[str, str]) -> None:
    """Generate in project temporary storage; check mode compares bytes without changing sources."""
    protoc = CACHE / "tools/protoc/36.1/bin/protoc"
    if not protoc.is_file():
        protoc = PREFIX / "bin/protoc"
    plugin = CACHE / "tools/grpc-cpp-plugin/1.84.0/bin/grpc_cpp_plugin"
    if not plugin.is_file():
        plugin = PREFIX / "bin/grpc_cpp_plugin"
    if not protoc.is_file() or not plugin.is_file():
        raise RuntimeError("Missing approved protoc 36.1 or grpc_cpp_plugin 1.84.0; generation never downloads tools")
    version = subprocess.check_output([str(protoc), "--version"], env=env, text=True).strip()
    if version != "libprotoc 36.1":
        raise RuntimeError("Unexpected protoc version: " + version)
    for schemas, names, destination in (
        (
            ROOT / "proto",
            [
                "astra.proto",
                "orbit.proto",
                "comet.proto",
                "pulsar.proto",
                "polaris.proto",
            ],
            SOURCE / "common/src/generated",
        ),
        (SOURCE / "bench/proto", ["probe.proto"], SOURCE / "bench/generated"),
    ):
        with tempfile.TemporaryDirectory(prefix="astra-proto-", dir=ROOT / "build/tmp") as temporary:
            run(
                [
                    protoc,
                    "--proto_path=" + str(schemas),
                    "--cpp_out=" + temporary,
                    "--grpc_out=" + temporary,
                    "--plugin=protoc-gen-grpc=" + str(plugin),
                    *names,
                ],
                env,
            )
            files = sorted(Path(temporary).iterdir())
            if check:
                if not destination.exists() or {p.name for p in destination.iterdir()} != {p.name for p in files}:
                    raise RuntimeError("Generated protocol file set differs: " + str(destination))
                for path in files:
                    if path.read_bytes() != (destination / path.name).read_bytes():
                        raise RuntimeError("Generated protocol differs: " + path.name)
            else:
                destination.mkdir(parents=True, exist_ok=True)
                for path in files:
                    target = destination / path.name
                    if not target.is_file() or target.read_bytes() != path.read_bytes():
                        shutil.copyfile(path, target)
    run([sys.executable, ROOT / "tools/generate.py", *(["--check"] if check else [])], env)
    print(
        ("Protocol generation comparison passed" if check else "Generated C++ and Go protocol sources"),
        flush=True,
    )


def parse_options(arguments: list[str] | None = None) -> argparse.Namespace:
    """Validate the complete action combination before creating caches or invoking build commands."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=[
            "configure",
            "build",
            "test",
            "regression",
            "soak",
            "scale",
            "generate",
            "check-generated",
        ],
    )
    parser.add_argument("--profile", choices=["debug", "release", "asan", "tsan"], default="debug")
    parser.add_argument("--coverage", action="store_true", help="Separate GCC line/branch/masking MC/DC build; not performance evidence")
    parser.add_argument(
        "--probes",
        action="store_true",
        help="Compile scoped diagnostics in a separate build directory",
    )
    parser.add_argument("--duration", type=int, default=3600)
    parser.add_argument(
        "--jobs",
        type=int,
        default=0,
        help="Build job ceiling; 0 selects from current CPU/memory",
    )
    parser.add_argument(
        "--test-jobs",
        type=int,
        default=0,
        help="Independent test job ceiling; 0 selects from current CPU/memory",
    )
    parser.add_argument(
        "--core-only",
        action="store_true",
        help="Only offline core tests; no service qualification",
    )
    parser.add_argument(
        "--contracts",
        choices=["enforce", "ignore"],
        default="enforce",
        help="Internal diagnostic comparison; default enforces contracts",
    )
    parser.add_argument(
        "--measure-allocations",
        action="store_true",
        help="Separate Release-only C++ new measurement, excluded from timing comparisons",
    )
    parser.add_argument(
        "--benchmarks",
        action="store_true",
        help="Build the isolated push fixture alongside services",
    )
    options = parser.parse_args(arguments)
    if not 0 <= options.jobs <= 256 or not 0 <= options.test_jobs <= 256:
        parser.error("jobs and test-jobs must be 0..256")
    if not 1 <= options.duration <= 604800:
        parser.error("duration must be 1..604800 seconds")
    if options.core_only and options.command in {
        "regression",
        "soak",
        "scale",
    }:
        parser.error("Core-only mode cannot qualify service processes")
    if options.core_only and (options.benchmarks or options.measure_allocations):
        parser.error("Core-only mode has no service allocation or benchmark targets")
    if options.measure_allocations and options.profile != "release":
        parser.error("Allocation measurement requires the release profile")
    if options.probes and (options.measure_allocations or options.profile in {"asan", "tsan"}):
        parser.error("Performance probes require a build separate from sanitizers and allocation interception")
    if options.coverage and (options.profile != "debug" or options.probes or options.measure_allocations or options.benchmarks):
        parser.error("Coverage requires a separate Debug build without probes, sanitizers or benchmarks")
    return options


def main() -> None:
    # The IDE workspace is language-free and must not enter Linux build or test setup.
    """Validate requested operations, then run only the selected offline generation, build, or test phases."""
    if sys.argv[1:2] == ["solution"]:
        from tools.solution import main as solution

        solution(sys.argv[2:])
        return
    options = parse_options()
    if sys.platform != "linux":
        print(
            "Error: The C++26 runtime currently requires Linux and the project GCC 16.2 toolchain",
            file=sys.stderr,
        )
        raise SystemExit(2)
    prefix = CACHE / "deps/astra/linux-gcc16-tsan/install" if options.profile == "tsan" and not options.core_only else PREFIX
    cpus, available = resources()
    jobs, cases = parallel(cpus, available, options.profile, options.jobs, options.test_jobs)
    env = environment(prefix, jobs)
    # Sanitizer findings must fail; recoverable UBSan reports must not disappear inside successful CTest output.
    if options.profile == "asan":
        env["ASAN_OPTIONS"] = "detect_leaks=1:halt_on_error=1"
        env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    elif options.profile == "tsan":
        env["TSAN_OPTIONS"] = "halt_on_error=1:exitcode=66"
    if options.command in {"generate", "check-generated"}:
        generated(options.command == "check-generated", env)
        return
    if options.command in {"soak", "scale"}:
        raise RuntimeError(
            "The old Supervisor/Planet soak and scale scenarios do not qualify the new Pulsar/Polaris startup; use the current test or regression suite until those scenarios are migrated"
        )
    if options.profile == "tsan" and not options.core_only and not (CACHE / "deps/astra/artifacts-tsan.json").is_file():
        raise RuntimeError("TSan requires the explicit offline dependency build: prepare_dependencies.py build --profile tsan")
    gcc = CACHE / "tools/gcc-16.2.0/bin"
    if not (gcc / "g++").is_file():
        raise RuntimeError("Missing project-local GCC 16.2 toolchain")
    output = (
        ROOT
        / "build/cmake"
        / (
            ("core-" if options.core_only else "")
            + options.profile
            + ("-contracts-ignore" if options.contracts == "ignore" else "")
            + ("-allocations" if options.measure_allocations else "")
            + ("-probes" if options.probes else "")
            + ("-coverage" if options.coverage else "")
        )
    )
    go = CACHE / "tools/go-1.27.2/bin/go"
    if not options.core_only and not go.is_file():
        raise RuntimeError("Missing approved project Go 1.27.2; no automatic toolchain download")
    print(
        f"Resource budget: cpus={cpus}, available_bytes={available}, build_jobs={jobs}, test_jobs={cases}",
        flush=True,
    )
    configure = [
        "cmake",
        # Select the fixed prefix explicitly so stale CMake library paths cannot link TSan services to uninstrumented dependencies.
        *[
            "-U" + name
            for name in (
                "gRPC_DIR",
                "Protobuf_DIR",
                "absl_DIR",
                "utf8_range_DIR",
                "re2_DIR",
                "c-ares_DIR",
                "yyjson_DIR",
                "ZLIB_*",
                "star_yyjson_headers",
            )
        ],
        "-S",
        SOURCE,
        "-B",
        output,
        "-DCMAKE_C_COMPILER=" + str(gcc / "gcc"),
        "-DCMAKE_CXX_COMPILER=" + str(gcc / "g++"),
        "-DCMAKE_PREFIX_PATH=" + str(prefix),
        "-DCMAKE_BUILD_TYPE=" + ("Release" if options.profile == "release" else "Debug"),
        # Override a cached OFF value explicitly; a test entry point must not report success after discovering zero tests.
        "-DBUILD_TESTING=ON",
        "-DASTRA_CORE_ONLY=" + ("ON" if options.core_only else "OFF"),
        "-DASTRA_PROFILE=" + ("ON" if options.probes else "OFF"),
        "-DASTRA_COVERAGE=" + ("ON" if options.coverage else "OFF"),
        "-DASTRA_SANITIZER=" + {"asan": "address,undefined", "tsan": "thread"}.get(options.profile, ""),
        "-DASTRA_CONTRACT_SEMANTIC=" + options.contracts,
        "-DPython3_EXECUTABLE=" + sys.executable,
        "-DASTRA_MEASURE_ALLOCATIONS=" + ("ON" if options.measure_allocations else "OFF"),
        "-DASTRA_BUILD_BENCHMARKS=" + ("ON" if options.benchmarks else "OFF"),
        "-DASTRA_POLARIS_EXECUTABLE=" + str(output / "polaris"),
    ]
    run(configure, env)
    if options.command == "configure":
        return
    run(["cmake", "--build", output, "--parallel", str(jobs)], env)
    if not options.core_only:
        for service in ("polaris", "astrolabe"):
            run(
                [
                    go,
                    "-C",
                    SOURCE,
                    "build",
                    "-mod=readonly",
                    "-p",
                    jobs,
                    "-o",
                    output / service,
                    "./" + service,
                ],
                env,
            )
    if options.command == "build":
        return
    # Run Go and CTest sequentially within one resource budget. CTest enforces RUN_SERIAL and RESOURCE_LOCK itself.
    env["GOMAXPROCS"] = str(cases)
    if not options.core_only:
        run(
            [
                go,
                "-C",
                SOURCE,
                "test",
                "-mod=readonly",
                "-count=1",
                "-p",
                cases,
                "-parallel",
                1,
                # Keep the separately developed Go SDK outside the current service qualification.
                "./internal/...",
                "./polaris/...",
                "./astrolabe/...",
            ],
            env,
        )
    run(
        [
            "ctest",
            "--test-dir",
            output,
            "--output-on-failure",
            "--no-tests=error",
            "--parallel",
            str(cases),
        ],
        env,
    )
    if options.command == "regression":
        generated(True, env)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Error: {error}", file=sys.stderr)
        raise SystemExit(1)
