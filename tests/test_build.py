"""Offline entry checks, including real CMake cache recovery and empty CTest rejection."""

from __future__ import annotations

import contextlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import build, paths


class BuildEntryTests(unittest.TestCase):
    """Check offline build dispatch, resource budgets, and nonempty test discovery."""

    def test_invalid_operation_combinations(self) -> None:
        """Reject conflicting operations before creating output or invoking build tools."""
        for arguments in (
            ["regression", "--core-only"],
            ["soak", "--core-only"],
            ["scale", "--core-only"],
            ["benchmark", "--core-only"],
            ["build", "--core-only", "--benchmarks"],
            ["build", "--core-only", "--measure-allocations", "--profile", "release"],
            ["scale", "--measure-allocations"],
            ["benchmark", "--profile", "tsan"],
            ["benchmark", "--profile", "release"],
            ["benchmark", "--profile", "tsan", "--benchmark-smoke"],
            ["build", "--benchmark-smoke"],
            ["soak", "--duration", "0"],
            ["soak", "--duration", "604801"],
            ["build", "--jobs", "-1"],
            ["test", "--test-jobs", "257"],
            ["build", "--probes", "--profile", "tsan"],
            ["build", "--probes", "--profile", "asan"],
            ["build", "--probes", "--profile", "release", "--measure-allocations"],
            ["build", "--coverage", "--profile", "release"],
            ["build", "--coverage", "--profile", "asan"],
            ["build", "--coverage", "--probes"],
            ["build", "--coverage", "--benchmarks"],
        ):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                build.parse_options(arguments)
            self.assertEqual(error.exception.code, 2)

    def test_supported_profiles_and_operations(self) -> None:
        """Accept the supported profile and operation combinations without executing them."""
        for arguments in (
            ["build"],
            ["test", "--core-only"],
            ["regression", "--profile", "asan"],
            ["soak", "--duration", "60", "--profile", "release"],
            ["scale", "--measure-allocations", "--profile", "release"],
            ["check-generated"],
            ["regression", "--coverage"],
            ["build", "--probes", "--profile", "release"],
        ):
            with self.subTest(arguments=arguments):
                self.assertEqual(build.parse_options(arguments).command, arguments[0])

    def temporary_project(self) -> Path:
        """Own a temporary project tree and register cleanup with the test case."""
        temporary_root = build.ROOT / "build/tmp"
        temporary_root.mkdir(parents=True, exist_ok=True)
        directory = tempfile.TemporaryDirectory(prefix="astra-build-test-", dir=temporary_root)
        project = Path(directory.name).resolve()
        self.assertTrue(project.is_relative_to(temporary_root.resolve()))
        self.addCleanup(directory.cleanup)
        return project

    def test_environment_is_child_only_and_avoids_empty_search_paths(self) -> None:
        """Keep caller settings intact and prevent empty loader-path entries from adding the working directory."""
        project = self.temporary_project()
        inherited = {
            "PATH": "parent-bin",
            "LD_LIBRARY_PATH": "",
            "CMAKE_BUILD_PARALLEL_LEVEL": "8",
        }
        with patch.object(build, "ROOT", project), patch.object(build, "CACHE", project / "build"), patch.dict(os.environ, inherited, clear=True):
            actual = build.environment(project / "deps")
            self.assertEqual(dict(os.environ), inherited)
        self.assertEqual(actual["LD_LIBRARY_PATH"], str(project / "build/tools/gcc-16.2.0/lib64"))
        self.assertNotIn(str(project / "deps/lib"), actual["LD_LIBRARY_PATH"])
        self.assertEqual(actual["CMAKE_BUILD_PARALLEL_LEVEL"], "1")
        self.assertEqual(actual["PATH"].split(os.pathsep)[-1], "parent-bin")

    def test_explicit_parent_runtime_path_is_preserved(self) -> None:
        """Preserve a nonempty caller-provided runtime path after project toolchain selection."""
        project = self.temporary_project()
        with (
            patch.object(build, "ROOT", project),
            patch.object(build, "CACHE", project / "build"),
            patch.dict(os.environ, {"LD_LIBRARY_PATH": "parent-lib"}, clear=True),
        ):
            actual = build.environment(project / "deps")
        self.assertEqual(actual["LD_LIBRARY_PATH"].split(os.pathsep)[-1], "parent-lib")

    def test_budget_respects_current_memory_and_explicit_ceilings(self) -> None:
        """Derive phase budgets from available memory while honoring lower explicit job ceilings."""
        self.assertEqual(build.parallel(16, 8 << 30, "debug"), (8, 16))
        self.assertEqual(build.parallel(16, 1536 << 20, "debug"), (1, 4))
        self.assertEqual(build.parallel(16, 8 << 30, "asan"), (5, 15))
        self.assertEqual(build.parallel(16, 8 << 30, "tsan", 2, 3), (2, 3))
        self.assertEqual(build.parallel(16, 1536 << 20, "asan", 16, 16), (1, 2))
        self.assertEqual(build.parallel(2, 8 << 30, "debug"), (2, 2))
        self.assertEqual(build.parallel(16, None, "debug"), (1, 1))
        self.assertEqual(build.parallel(16, 0, "debug"), (1, 1))

    def test_go_caches_and_download_controls_are_child_only(self) -> None:
        """Keep Go caches local and downloads disabled without mutating the parent environment."""
        project = self.temporary_project()
        inherited = {
            "GOPATH": "global",
            "GOPROXY": "https://example.invalid",
            "GOFLAGS": "-mod=mod",
            "GOTOOLCHAIN": "auto",
        }
        with patch.object(build, "ROOT", project), patch.object(build, "CACHE", project / "build"), patch.dict(os.environ, inherited, clear=True):
            actual = build.environment(project / "deps", 3)
            self.assertEqual(dict(os.environ), inherited)
        self.assertEqual(actual["GOPATH"], str(project / "build/deps/go"))
        self.assertEqual(actual["GOMODCACHE"], str(project / "build/deps/go/pkg/mod"))
        self.assertEqual(actual["GOCACHE"], str(project / "build/cache/go"))
        self.assertEqual(actual["GOPROXY"], "off")
        self.assertEqual(actual["GOSUMDB"], "off")
        self.assertEqual(actual["GOTOOLCHAIN"], "local")
        self.assertEqual(actual["GOWORK"], "off")
        self.assertEqual(actual["GOFLAGS"], "-mod=readonly")
        self.assertEqual(actual["CMAKE_BUILD_PARALLEL_LEVEL"], "3")
        self.assertEqual(actual["GOMAXPROCS"], "3")
        self.assertEqual(actual["PATH"].split(os.pathsep)[:2], [str(project / "build/tools/go-1.27.2/bin"), str(project / "build/tools/gcc-16.2.0/bin")])

    def test_service_scope(self) -> None:
        """Dispatch service regression without discovering the independently developed Go SDK."""
        project = self.temporary_project()
        cache = project / "build"
        for name in ("tools/gcc-16.2.0/bin/g++", "tools/go-1.27.2/bin/go"):
            marker = cache / name
            marker.parent.mkdir(parents=True)
            marker.touch()
        with (
            patch.object(build, "ROOT", project),
            patch.object(build, "SOURCE", project),
            patch.object(build, "CACHE", cache),
            patch.object(build, "PREFIX", cache / "deps"),
            patch.object(build.sys, "platform", "linux"),
            patch.object(build.sys, "argv", ["build.py", "regression"]),
            patch.object(build, "resources", return_value=(2, 4 << 30)),
            patch.object(build, "environment", return_value={}),
            patch.object(build, "run") as execute,
            patch.object(build, "generated") as generated,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            build.main()
        commands = [list(map(str, call.args[0])) for call in execute.call_args_list]
        tests = [command for command in commands if Path(command[0]).name == "go" and "test" in command]
        self.assertEqual(len(tests), 1)
        self.assertEqual([value for value in tests[0] if value.startswith("./")], ["./internal/...", "./polaris/...", "./astrolabe/..."])
        services = [command[-1] for command in commands if Path(command[0]).name == "go" and "build" in command]
        self.assertEqual(services, ["./polaris", "./astrolabe"])
        self.assertTrue(any(command[0] == "ctest" and "--no-tests=error" in command for command in commands))
        generated.assert_called_once_with(True, {"GOMAXPROCS": "2"})

    def test_cache_module_boundary(self) -> None:
        """Use real offline Go discovery to expose cache packages, then retain every owned package."""
        go = shutil.which("go")
        if go is None:
            self.skipTest("Go discovery requires an existing Go executable")
        project = self.temporary_project()
        cache = project / "build"
        cache.mkdir()
        (project / "go.mod").write_text("module example.invalid/owned\n\ngo 1.20\n", encoding="utf-8")
        (project / "owned.go").write_text("package owned\n", encoding="utf-8")
        (cache / "a.go").write_text("package a\n", encoding="utf-8")
        (cache / "b.go").write_text("package b\n", encoding="utf-8")
        env = dict(os.environ)
        env.update(
            GOTOOLCHAIN="local",
            GOPROXY="off",
            GOSUMDB="off",
            GOWORK="off",
            GOENV="off",
            GOFLAGS="-mod=readonly",
            GOPATH=str(cache / "deps/go"),
            GOMODCACHE=str(cache / "deps/go/pkg/mod"),
            GOCACHE=str(cache / "cache/go"),
        )
        before = subprocess.run([go, "list", "./..."], cwd=project, env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(before.returncode, 0)
        self.assertIn("found packages a", before.stderr)
        paths.isolate(cache)
        after = subprocess.run([go, "list", "./..."], cwd=project, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(after.returncode, 0, after.stderr)
        self.assertEqual(after.stdout.splitlines(), ["example.invalid/owned"])
        marker = cache / "go.mod"
        marker.write_text("module example.invalid/custom\n", encoding="utf-8")
        paths.isolate(cache)
        self.assertEqual(marker.read_text(encoding="utf-8"), "module example.invalid/custom\n")

    def run_fixture(self, *, no_tests: bool = False) -> Path:
        """Check entry-point behavior with real language-free CMake/CTest fixtures, not mocked results or project compilation."""
        if not shutil.which("cmake") or not shutil.which("ctest"):
            self.fail("Build entry tests require the already installed CMake and CTest")
        project = self.temporary_project()
        source = project / "astra"
        output = project / "build/cmake/core-debug"
        source.mkdir()
        (source / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.28)\n"
            "project(build_entry_fixture LANGUAGES NONE)\n"
            "include(CTest)\n"
            "if(BUILD_TESTING AND NOT FIXTURE_NO_TESTS)\n"
            '  add_test(NAME executed COMMAND "${CMAKE_COMMAND}" -E touch "${CMAKE_CURRENT_BINARY_DIR}/executed")\n'
            "endif()\n",
            encoding="utf-8",
        )
        # The language-free fixture invokes no compiler; this marker only satisfies the offline tool-presence check.
        compiler = project / "build/tools/gcc-16.2.0/bin/g++"
        compiler.parent.mkdir(parents=True)
        compiler.touch()

        def execute(command: list[str | Path], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
            # Existing Windows CMake defaults to Visual Studio; select Debug only for this multi-configuration fixture.
            # Production services remain Linux-only; this fixture adaptation does not enter build.py.
            """Run the language-free fixture's existing tools with the platform's selected test configuration."""
            command = list(map(str, command))
            if os.name == "nt" and command[0] == "cmake" and "-S" in command and env.get("CMAKE_GENERATOR_INSTANCE"):
                # The fixture may pin an existing installation when automatic VS discovery is unavailable.
                command.append("-DCMAKE_GENERATOR_INSTANCE=" + env["CMAKE_GENERATOR_INSTANCE"])
            if os.name == "nt" and command[0] == "ctest":
                command += ["-C", "Debug"]
            try:
                return subprocess.run(command, cwd=project, env=env, check=True, capture_output=True, text=True, encoding="utf-8")
            except subprocess.CalledProcessError as error:
                error.add_note(error.stdout + error.stderr)
                raise

        execute(
            [
                "cmake",
                "-S",
                source,
                "-B",
                output,
                "-DBUILD_TESTING=OFF",
                "-DFIXTURE_NO_TESTS=" + ("ON" if no_tests else "OFF"),
            ],
            dict(os.environ),
        )
        # Exercise the same Linux entry policy on both hosts using portable cmake -E, without claiming a Windows service build.
        with (
            patch.object(build, "ROOT", project),
            patch.object(build, "CACHE", project / "build"),
            patch.object(build, "SOURCE", source),
            patch.object(build, "PREFIX", project / "deps"),
            patch.object(build, "run", execute),
            patch.object(sys, "platform", "linux"),
            patch.object(sys, "argv", ["build.py", "test", "--core-only"]),
        ):
            build.main()
        return output

    def test_cached_disabled_tests_are_reenabled_and_executed(self) -> None:
        """Override a stale disabled-test cache so explicit test requests execute discovered cases."""
        output = self.run_fixture()
        self.assertTrue((output / "executed").is_file())
        self.assertIn(
            "BUILD_TESTING:BOOL=ON",
            (output / "CMakeCache.txt").read_text(encoding="utf-8"),
        )

    def test_empty_suite_fails_the_entry(self) -> None:
        """Reject successful command execution that discovered no test cases."""
        with self.assertRaises(subprocess.CalledProcessError) as error:
            self.run_fixture(no_tests=True)
        self.assertEqual(Path(error.exception.cmd[0]).stem, "ctest")
        self.assertIn("No tests were found", error.exception.stderr + error.exception.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
