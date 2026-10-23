"""Explicit SDK-only and installed-package consumption; no downloads or service launch."""

from __future__ import annotations

from types import FrameType
import argparse
import os
from pathlib import Path
import signal
import socket
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tests.support import available_memory, run_command, temporary_directory
from tools.build import parallel, resources


def main() -> None:
    """Run only from an authorized test entry point; own all configuration, build, and consumer artifacts in one temporary tree."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--sanitizer", default="")
    parser.add_argument("--instance", help="Explicit existing Visual Studio instance and version for Windows qualification")
    options = parser.parse_args()
    if sys.platform not in ("linux", "win32") or not options.compiler.is_file():
        raise RuntimeError("Comet package qualification requires an existing compiler on Linux or Windows")
    windows = sys.platform == "win32"
    if windows and (not options.instance or options.sanitizer):
        raise RuntimeError("Windows package qualification requires an explicit Visual Studio instance and no GCC sanitizer")
    if not windows and options.instance:
        raise RuntimeError("Visual Studio instances apply only to Windows qualification")
    cpus, available = resources()
    if windows:
        # Share the established four-GiB Windows build budget, rather than sizing against all host memory.
        available = min(available_memory(), 4 * 1024**3)
    jobs, _ = parallel(
        cpus,
        available,
        ("tsan" if options.sanitizer == "thread" else "asan" if options.sanitizer else "release"),
        build=4 if windows else 0,
    )
    consumer = ROOT / "comet/cpp/tests/consumer"
    source = ROOT / "comet/cpp"
    with temporary_directory("comet-package-") as directory, socket.socket() as reservation:
        temporary = Path(directory)
        # Reserve without listening so configuration checks cannot reach an existing service; no extra test server is needed.
        reservation.bind(("127.0.0.1", 0))
        endpoint = f"127.0.0.1:{reservation.getsockname()[1]}"
        arguments = [endpoint, str(temporary / "missing-ca.pem")]
        env = dict(os.environ)
        built, installed, packaged = (temporary / name for name in ("source", "installed", "consumer"))
        common = [
            f"-DCMAKE_CXX_COMPILER={options.compiler}",
            f"-DCMAKE_PREFIX_PATH={options.prefix}",
            "-DCMAKE_BUILD_TYPE=Release",
            f"-DCOMET_SANITIZER={options.sanitizer}",
            "-DCOMET_BUILD_TESTS=OFF",
            f"-DCOMET_CA_FILE={ROOT / 'tests/fixtures/star-a/ca.pem'}",
            "-DFETCHCONTENT_FULLY_DISCONNECTED=ON",
        ]
        if windows:
            common += [
                "-G",
                "Visual Studio 18 2026",
                "-A",
                "x64",
                f"-DCMAKE_GENERATOR_INSTANCE={options.instance}",
                "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL",
            ]
        configuration = ["--config", "Release"] if windows else []
        executable = Path("Release/consumer.exe") if windows else Path("consumer")
        run_command(
            "comet source configure",
            ["cmake", "-S", consumer, "-B", built, f"-DCOMET_SOURCE={source}", *common],
            env=env,
            timeout=120,
        )
        run_command(
            "comet source consume",
            ["cmake", "--build", built, *configuration, "--target", "consumer", "--parallel", jobs],
            env=env,
            timeout=600,
        )
        run_command(
            "comet source executable",
            [built / executable, *arguments],
            env=env,
            timeout=20,
        )
        run_command(
            "comet install",
            [
                "cmake",
                "--install",
                built,
                *configuration,
                "--prefix",
                installed,
                "--component",
                "Comet",
            ],
            env=env,
            timeout=60,
        )
        if any(installed.rglob("*.proto")) or any(installed.rglob("*key.pem")) or (installed / "bin").exists():
            raise RuntimeError("SDK installation unexpectedly contains service/protocol/private material")
        # The fresh consumer gets no source paths or private includes; it discovers the SDK and existing dependencies only through install prefixes.
        run_command(
            "comet installed configure",
            [
                "cmake",
                "-S",
                consumer,
                "-B",
                packaged,
                *common,
                f"-DCMAKE_PREFIX_PATH={installed};{options.prefix}",
            ],
            env=env,
            timeout=120,
        )
        run_command(
            "comet installed consume",
            ["cmake", "--build", packaged, *configuration, "--parallel", jobs],
            env=env,
            timeout=120,
        )
        run_command(
            "comet installed executable",
            [packaged / executable, *arguments],
            env=env,
            timeout=20,
        )
        for path in installed.rglob("*.cmake"):
            text = path.read_text(encoding="utf-8")
            if str(temporary) in text or str(ROOT) in text:
                raise RuntimeError("Installed CMake export leaks build/source paths")


if __name__ == "__main__":
    # CTest cancellation must clean resources before temporary storage disappears, leaving no compiler descendants.
    def interrupted(number: int, frame: FrameType | None) -> None:
        """Turn cancellation into stack unwinding so child processes are cleaned before temporary files."""
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    main()
