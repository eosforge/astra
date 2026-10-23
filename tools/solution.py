"""Generate an offline Visual Studio workspace without probing a C++ compiler."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid
import xml.etree.ElementTree as XML

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tools.paths import CACHE

# Project ownership is shared by the generator and explicit IDE build actions.
PROJECTS = ("Comet", "Star", "Pulsar", "Common", "Planet")
GENERATOR = "Visual Studio 18 2026"


def run(command: list[str | Path]) -> None:
    """Run existing tools directly; never repair missing tools or dependencies."""
    print(subprocess.list2cmdline(list(map(str, command))), flush=True)
    subprocess.run(list(map(str, command)), cwd=ROOT, check=True)


def cache(path: Path, source: Path, generator: str, settings: dict[str, str] | None = None) -> None:
    """Reject unrelated caches before CMake can rewrite their identity."""
    file = path / "CMakeCache.txt"
    if not file.exists():
        return
    values = {}
    for line in file.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith(("//", "#")) and "=" in line:
            name, value = line.split("=", 1)
            values[name.split(":", 1)[0]] = value
    if (
        Path(values.get("CMAKE_HOME_DIRECTORY", "")).resolve() != source.resolve()
        or values.get("CMAKE_GENERATOR") != generator
        or values.get("CMAKE_GENERATOR_PLATFORM") != "x64"
    ):
        raise RuntimeError(f"Incompatible CMake cache preserved: {file}")
    for name, expected in (settings or {}).items():
        actual = values.get(name)
        matches = Path(actual).resolve() == Path(expected).resolve() if name == "CMAKE_PREFIX_PATH" and actual else actual == expected
        if not matches:
            raise RuntimeError(f"Incompatible {name} in preserved cache: {file}")


def solution(output: Path, browse: bool) -> str:
    """Publish legacy .sln format from CMake's project identities, including .slnx generators."""
    namespace = {"ms": "http://schemas.microsoft.com/developer/msbuild/2003"}
    lines = [
        "Microsoft Visual Studio Solution File, Format Version 12.00",
        "# Visual Studio Version 18",
    ]
    identities = []
    for name in PROJECTS:
        path = output / name / f"{name}.vcxproj"
        if not path.resolve().is_relative_to(output.resolve()):
            raise RuntimeError(f"Project escapes its output tree: {path}")
        root = XML.parse(path).getroot()
        identity = "{" + str(uuid.UUID(root.findtext("ms:PropertyGroup/ms:ProjectGuid", namespaces=namespace))).upper() + "}"
        configurations = root.findall("ms:ItemGroup/ms:ProjectConfiguration", namespace)
        if [entry.attrib["Include"] for entry in configurations] != ["Release|x64"]:
            raise RuntimeError(f"Unexpected generated project configuration: {path}")
        identities.append((name, identity))
        label = name if name == "Comet" and not browse else name + " (browse only)"
        lines += [f'Project("{{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}}") = "{label}", "{name}\\{name}.vcxproj", "{identity}"', "EndProject"]
    if len({identity for _, identity in identities}) != len(PROJECTS):
        raise RuntimeError("Generated projects must have distinct identities")
    lines += [
        "Global",
        "\tGlobalSection(SolutionConfigurationPlatforms) = preSolution",
        "\t\tRelease|x64 = Release|x64",
        "\tEndGlobalSection",
        "\tGlobalSection(ProjectConfigurationPlatforms) = postSolution",
    ]
    for name, identity in identities:
        lines.append(f"\t\t{identity}.Release|x64.ActiveCfg = Release|x64")
        if name == "Comet" and not browse:
            lines.append(f"\t\t{identity}.Release|x64.Build.0 = Release|x64")
    lines += ["\tEndGlobalSection", "EndGlobal", ""]
    return "\n".join(lines)


def generate(options: argparse.Namespace) -> None:
    """Generate only language-free projects; defer all compilation to IDE actions."""
    if sys.platform != "win32":
        raise RuntimeError("Visual Studio solution generation requires Windows")
    output = ROOT / "build"
    coordinator = output / "Astra"
    source = ROOT / "cmake/ide"
    for directory in (coordinator, *(output / name for name in PROJECTS)):
        if not directory.resolve().is_relative_to(output.resolve()):
            raise RuntimeError(f"Output directory escapes the build tree: {directory}")
    settings = {"CMAKE_GENERATOR_INSTANCE": options.instance} if options.instance else {}
    instance = ["-DCMAKE_GENERATOR_INSTANCE=" + options.instance] if options.instance else []
    cache(coordinator, source, options.generator, settings)
    # Resolve the optional prefix once so IDE launches do not depend on their cwd.
    prefix = (options.prefix or CACHE / "deps/comet-msvc/install").resolve()
    if options.runtime:
        # This explicit mode can compile feature probes, unlike ordinary generation.
        runtime = output / "Common/runtime"
        cache(runtime, ROOT, options.generator, settings)
        run(
            [
                "cmake",
                "-S",
                ROOT,
                "-B",
                runtime,
                "-G",
                options.generator,
                "-A",
                "x64",
                *instance,
                "-DASTRA_WINDOWS_RUNTIME=ON",
                "-DBUILD_TESTING=OFF",
                "-DCMAKE_PREFIX_PATH=" + str(prefix),
                "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL",
            ]
        )
    run(
        [
            "cmake",
            "-S",
            source,
            "-B",
            coordinator,
            "-G",
            options.generator,
            "-A",
            "x64",
            *instance,
            "-DASTRA_ROOT=" + str(ROOT),
            "-DASTRA_OUTPUT=" + str(output),
            "-DASTRA_PYTHON=" + sys.executable,
            "-DASTRA_BROWSE_ONLY=" + ("ON" if options.browse_only else "OFF"),
        ]
    )
    content = solution(output, options.browse_only)
    # Keep the previous root solution until generation and path validation succeed.
    state = {"version": 1, "generator": options.generator, "instance": options.instance, "prefix": str(prefix), "browse": options.browse_only}
    temporary = coordinator / "solution.json.tmp"
    temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    temporary.replace(coordinator / "solution.json")
    temporary = output / "Astra.sln.tmp"
    temporary.write_text(content, encoding="utf-8-sig", newline="\r\n")
    temporary.replace(output / "Astra.sln")
    print(f"Generated {output / 'Astra.sln'}; no compilation or tests executed")


def build(project: str, configuration: str) -> None:
    """Build the SDK on explicit IDE request; browsing is never a successful build."""
    state = json.loads((ROOT / "build/Astra/solution.json").read_text(encoding="utf-8"))
    if project != "Comet" or state["browse"]:
        raise RuntimeError(f"{project} is a source browsing project; native service qualification remains pending")
    if configuration != "Release":
        raise RuntimeError("This workspace uses Release /MD dependencies; prepare a separate prefix before enabling Debug")
    prefix = Path(state["prefix"])
    if not prefix.is_dir():
        raise RuntimeError(f"Missing approved dependency prefix: {prefix}; no implicit download")
    source = ROOT / "comet/cpp"
    output = ROOT / "build/Comet/native"
    instance = state.get("instance")
    settings = {"CMAKE_PREFIX_PATH": str(prefix), "CMAKE_MSVC_RUNTIME_LIBRARY": "MultiThreadedDLL"}
    if instance:
        settings["CMAKE_GENERATOR_INSTANCE"] = instance
    cache(output, source, state["generator"], settings)
    run(
        [
            "cmake",
            "-S",
            source,
            "-B",
            output,
            "-G",
            state["generator"],
            "-A",
            "x64",
            *(["-DCMAKE_GENERATOR_INSTANCE=" + instance] if instance else []),
            "-DCMAKE_PREFIX_PATH=" + str(prefix),
            "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL",
            "-DFETCHCONTENT_FULLY_DISCONNECTED=ON",
            "-DCOMET_BUILD_TESTS=OFF",
            "-DASTRA_PROFILE=OFF",
            "-DASTRA_SANITIZER=",
            "-DCOMET_SANITIZER=",
            "-DCMAKE_CONFIGURATION_TYPES=Release",
        ]
    )
    run(["cmake", "--build", output, "--config", configuration, "--target", "comet", "--parallel", "4"])


def main(arguments: list[str] | None = None) -> None:
    """Expose generation separately from the explicit build callback in each project."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generator", default=GENERATOR)
    parser.add_argument("--instance", help="Existing CMake Visual Studio instance specification; no discovery repair or installation")
    parser.add_argument("--prefix", type=Path)
    parser.add_argument("--browse-only", action="store_true")
    parser.add_argument("--runtime", action="store_true", help="Explicitly configure service capability probes; may compile")
    parser.add_argument("--build", choices=PROJECTS)
    parser.add_argument("--config", choices=("Release", "Debug"), default="Release")
    options = parser.parse_args(arguments)
    if options.build and (options.runtime or options.browse_only or options.prefix or options.instance):
        parser.error("Build callbacks use the generated workspace settings; regenerate to change them")
    if options.browse_only and options.runtime:
        parser.error("browse-only and runtime are mutually exclusive")
    if not re.fullmatch(r"Visual Studio \d+ \d{4}", options.generator):
        parser.error("An installed Visual Studio generator is required")
    if options.build:
        build(options.build, options.config)
    else:
        generate(options)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, XML.ParseError, subprocess.CalledProcessError) as error:
        print(f"Error: {error}", file=sys.stderr)
        raise SystemExit(1)
