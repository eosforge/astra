"""Check solution publication, cache isolation and explicit IDE build boundaries."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import build, solution


class SolutionTests(unittest.TestCase):
    """All fixtures live below the repository build tree; no compiler is invoked."""

    def setUp(self) -> None:
        """Own a temporary workspace with spaces and Unicode in its path."""
        base = solution.ROOT / "build/tmp"
        base.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="solution space カナ-", dir=base)
        self.root = Path(temporary.name).resolve()
        self.assertTrue(self.root.is_relative_to(base.resolve()))
        self.addCleanup(temporary.cleanup)
        self.output = self.root / "build"
        (self.output / "Astra").mkdir(parents=True)

    def projects(self, configuration: str = "Release|x64") -> None:
        """Supply native project metadata independently of the solution serializer."""
        for name in solution.PROJECTS:
            directory = self.output / name
            directory.mkdir(exist_ok=True)
            identity = str(uuid.uuid5(uuid.NAMESPACE_DNS, name))
            (directory / f"{name}.vcxproj").write_text(
                '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
                f"<PropertyGroup><ProjectGuid>{{{identity}}}</ProjectGuid></PropertyGroup>"
                f'<ItemGroup><ProjectConfiguration Include="{configuration}" /></ItemGroup></Project>',
                encoding="utf-8",
            )

    def options(self, **changes: object) -> argparse.Namespace:
        """Default generation explicitly excludes runtime capability probes."""
        values = dict(generator=solution.GENERATOR, instance=None, prefix=self.root / "deps", runtime=False, browse_only=False)
        return argparse.Namespace(**(values | changes))

    def test_solution_builds_only_comet_and_has_relative_paths(self) -> None:
        """A normal solution builds the SDK; browse mode cannot silently build services."""
        self.projects()
        text = solution.solution(self.output, False)
        self.assertEqual(text.count(".Build.0 ="), 1)
        self.assertEqual(text.count(".ActiveCfg ="), 5)
        self.assertNotIn(str(self.root), text)
        for name in solution.PROJECTS:
            self.assertIn(f'"{name}\\{name}.vcxproj"', text)
        self.assertNotIn(".Build.0 =", solution.solution(self.output, True))

    def test_generation_preserves_root_ninja_cache_without_compilation(self) -> None:
        """Generation has one language-free CMake command and leaves old caches untouched."""
        self.projects()
        original = "CMAKE_GENERATOR:INTERNAL=Ninja\n"
        (self.output / "CMakeCache.txt").write_text(original, encoding="utf-8")
        with patch.object(solution, "ROOT", self.root), patch.object(sys, "platform", "win32"), patch.object(solution, "run") as run:
            solution.generate(self.options())
        self.assertEqual(run.call_count, 1)
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("-S") + 1], self.root / "cmake/ide")
        self.assertNotIn("--build", command)
        self.assertEqual((self.output / "CMakeCache.txt").read_text(encoding="utf-8"), original)
        self.assertTrue((self.output / "Astra.sln").is_file())

    def test_failed_generation_keeps_previous_solution(self) -> None:
        """CMake failure cannot publish a truncated replacement."""
        target = self.output / "Astra.sln"
        target.write_text("previous", encoding="utf-8")
        with (
            patch.object(solution, "ROOT", self.root),
            patch.object(sys, "platform", "win32"),
            patch.object(solution, "run", side_effect=subprocess.CalledProcessError(1, "cmake")),
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                solution.generate(self.options())
        self.assertEqual(target.read_text(encoding="utf-8"), "previous")

    def test_cache_conflict_and_invalid_configuration_are_rejected(self) -> None:
        """Unrelated caches and unexpected configuration mappings are not silently reused."""
        file = self.output / "Astra/CMakeCache.txt"
        file.write_text("CMAKE_GENERATOR:INTERNAL=Ninja\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "cache preserved"):
            solution.cache(file.parent, self.root / "cmake/ide", solution.GENERATOR)
        self.projects("Debug|Win32")
        with self.assertRaisesRegex(RuntimeError, "configuration"):
            solution.solution(self.output, False)

    def test_service_build_and_missing_dependency_do_not_start_tools(self) -> None:
        """A browse project or absent prefix is an explicit error, not a download or successful build."""
        (self.output / "Astra/solution.json").write_text(
            json.dumps({"version": 1, "generator": solution.GENERATOR, "prefix": str(self.root / "absent"), "browse": False}),
            encoding="utf-8",
        )
        with patch.object(solution, "ROOT", self.root), patch.object(solution, "run") as run:
            for name in ("Star", "Pulsar", "Common", "Planet", "Comet"):
                with self.subTest(project=name), self.assertRaises(RuntimeError):
                    solution.build(name, "Release")
            run.assert_not_called()

    def test_dispatch_bypasses_linux_build_setup(self) -> None:
        """The common build entry delegates before resource probes or compiler selection."""
        with (
            patch.object(sys, "argv", ["build.py", "solution", "--browse-only"]),
            patch.object(solution, "main") as main,
            patch.object(build, "environment") as environment,
        ):
            build.main()
            main.assert_called_once_with(["--browse-only"])
            environment.assert_not_called()

    def test_instance(self) -> None:
        """Pin generation and the later SDK callback to one existing instance, preserving mismatched caches."""
        self.projects()
        prefix = self.root / "deps"
        prefix.mkdir()
        instance = str(self.root / "existing VS") + ",version=18.10.12224.181"
        flag = "-DCMAKE_GENERATOR_INSTANCE=" + instance
        with patch.object(solution, "ROOT", self.root), patch.object(sys, "platform", "win32"), patch.object(solution, "run") as run:
            solution.generate(self.options(instance=instance, runtime=True))
            self.assertEqual(run.call_count, 2)
            for call in run.call_args_list:
                self.assertIn(flag, call.args[0])
            self.assertEqual(json.loads((self.output / "Astra/solution.json").read_text(encoding="utf-8"))["instance"], instance)
            run.reset_mock()
            solution.build("Comet", "Release")
            self.assertIn(flag, run.call_args_list[0].args[0])
            self.assertEqual(run.call_args_list[1].args[0][:2], ["cmake", "--build"])
            file = self.output / "Astra/CMakeCache.txt"
            file.write_text(
                "CMAKE_HOME_DIRECTORY:INTERNAL="
                + str(self.root / "cmake/ide")
                + "\nCMAKE_GENERATOR:INTERNAL="
                + solution.GENERATOR
                + "\nCMAKE_GENERATOR_PLATFORM:INTERNAL=x64\nCMAKE_GENERATOR_INSTANCE:INTERNAL=other\n",
                encoding="utf-8",
            )
            run.reset_mock()
            with self.assertRaisesRegex(RuntimeError, "CMAKE_GENERATOR_INSTANCE"):
                solution.generate(self.options(instance=instance))
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
