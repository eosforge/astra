"""Verify native coverage accounting cannot discard uncovered conditions or mistake test code for production."""

import copy
import json
import os
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest.mock import patch

from tools import coverage, verify


class CoverageTests(unittest.TestCase):
    """Keep native denominators visible, including unexecuted lines and condition outcomes."""

    def test_counts(self) -> None:
        """A partially covered compound condition retains every missing outcome."""
        record = {
            "lines": [
                {
                    "count": 1,
                    "branches": [{"count": 0}, {"count": 1}, {"count": 0}, {"count": 0}],
                    "conditions": [{"count": 4, "covered": 1, "not_covered_true": [0, 1], "not_covered_false": [1]}],
                },
                {"count": 0, "branches": [], "conditions": []},
            ]
        }
        self.assertEqual(coverage.counts(record), {"lines": 2, "lines_hit": 1, "branches": 4, "branches_hit": 1, "conditions": 4, "conditions_hit": 1})
        record["lines"][0]["conditions"][0]["covered"] = 5
        with self.assertRaises(verify.Invalid):
            coverage.counts(record)
        for count in (True, -1, 0.5):
            with self.subTest(count=count):
                with self.assertRaisesRegex(verify.Invalid, "line-counter-invalid"):
                    coverage.counts({"lines": [{"count": count, "branches": []}]})
                with self.assertRaisesRegex(verify.Invalid, "branch-counter-invalid"):
                    coverage.counts({"lines": [{"count": 1, "branches": [{"count": count}]}]})
                with self.assertRaisesRegex(verify.Invalid, "condition-counter-invalid"):
                    coverage.counts(
                        {
                            "lines": [
                                {"count": 1, "branches": [], "conditions": [{"count": 2, "covered": count, "not_covered_true": [], "not_covered_false": []}]}
                            ]
                        }
                    )

        # A claimed MC/DC total must reconcile with unique, in-range missing terms of each polarity.
        valid = {"count": 4, "covered": 1, "not_covered_true": [0, 1], "not_covered_false": [1]}

        def count(value: dict) -> dict[str, int]:
            """Exercise the same native file-accounting entry used by the exporter."""
            return coverage.counts({"lines": [{"count": 1, "branches": [], "conditions": [value]}]})

        for true, false, hit in (([], [], 4), ([0, 1], [0, 1], 0), ([1, 0], [1], 1), ([0], [], 3)):
            self.assertEqual(count({**valid, "not_covered_true": true, "not_covered_false": false, "covered": hit})["conditions_hit"], hit)
        # Overstating hits, disappearing outcomes and duplicate indices are distinct corruptions.
        for key, value in (
            ("covered", 4),
            ("covered", 0),
            ("count", 3),
            ("count", 0),
            ("count", True),
            ("count", 4.0),
            ("not_covered_true", [0, 0]),
            ("not_covered_false", [2]),
            ("not_covered_false", [-1]),
            ("not_covered_false", [True]),
            ("not_covered_false", [1.0]),
            ("not_covered_false", [[]]),
            ("not_covered_true", None),
            ("not_covered_true", "01"),
            ("not_covered_false", {"1": True}),
            ("extra", 0),
        ):
            with self.subTest(key=key, value=value), self.assertRaisesRegex(verify.Invalid, "condition-counter-invalid"):
                count({**valid, key: value})
        for key in valid:
            incomplete = copy.deepcopy(valid)
            del incomplete[key]
            with self.subTest(missing=key), self.assertRaisesRegex(verify.Invalid, "condition-counter-invalid"):
                count(incomplete)
        for invalid in (None, [], 4):
            with self.subTest(record=invalid), self.assertRaisesRegex(verify.Invalid, "condition-counter-invalid"):
                count(invalid)
        line = {"count": 1, "branches": []}
        with self.assertRaisesRegex(verify.Invalid, "condition-counter-invalid"):
            coverage.counts({"lines": [line]})
        for invalid in (None, {}, "", 0):
            with self.subTest(conditions=invalid), self.assertRaisesRegex(verify.Invalid, "condition-counter-invalid"):
                coverage.counts({"lines": [{**line, "conditions": invalid}]})
        self.assertEqual(coverage.counts({"lines": [{**line, "conditions": []}]})["conditions"], 0)

    def test_raw_budget(self) -> None:
        """Large native counters use a bounded raw budget without enlarging policy JSON or accepting malformed data."""
        report = b" " * (verify.LIMIT + 1) + b"{}"
        with self.assertRaisesRegex(verify.Invalid, "json-size"):
            verify.decode(report)
        self.assertEqual(coverage.decode(report), {})
        for invalid in (b" " * (coverage.LIMIT + 1), b'{"file":1,"file":2}', b'{"count":NaN}'):
            with self.assertRaises(verify.Invalid):
                coverage.decode(invalid)

    def test_scope(self) -> None:
        """Use directory boundaries, never similar prefixes or a blanket header exclusion."""
        root = Path(__file__).resolve().parents[1]
        for name in ("common/include/astra/scope.hpp", "star/src/scene.hpp", "comet/cpp/src/core.cpp", "bench/measure.hpp", "bench/baseline/comet.cpp"):
            self.assertTrue(coverage.owned(root / name, root))
        for name in (
            "common/tests/core_test.cpp",
            "common/src/generated/astra.pb.cc",
            "star/src-extra/fake.cpp",
            "../sdk/client.cpp",
            "bench/baseline/workload_test.cpp",
            "bench/generated/bench.pb.cc",
        ):
            self.assertFalse(coverage.owned(root / name, root))

    def test_unbuilt_scope(self) -> None:
        """Generated recipes alone cannot prove compilation or remove an unbuilt file from the denominator."""
        temporary = Path(__file__).resolve().parents[1] / "build/tmp"
        temporary.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temporary, prefix="coverage-recipes-") as directory:
            root = Path(directory).resolve()
            output = root / "build/object files"
            output.mkdir(parents=True)
            (output / "active.gcno").write_bytes(b"native note identity; contents are consumed by gcov separately")
            names = ["star/src/active.cpp", "star/src/forgotten.cpp", "star/src/types.hpp", "star/tests/example.cpp", "bench/comet.cpp"]
            units = [
                {
                    "file": str(root / ("star/src/" + name + ".cpp")),
                    "directory": str(output),
                    "output": name + ".o",
                    "command": shlex.join(["c++", "--coverage", "-fcondition-coverage", "-o", name + ".o", "-c", str(root / ("star/src/" + name + ".cpp"))]),
                }
                for name in ("active", "forgotten")
            ]
            entries = [{"file": "star/src/active.cpp", "lines": 1}, {"file": "star/src/types.hpp", "lines": 0}]
            actual = coverage.inventory(names, units, entries, root, output)
            self.assertEqual(actual["compiled"], ["star/src/active.cpp"])
            self.assertEqual(actual["configured_translation_units"], ["star/src/active.cpp", "star/src/forgotten.cpp"])
            self.assertEqual(actual["uncompiled_translation_units"], ["bench/comet.cpp", "star/src/forgotten.cpp"])
            self.assertEqual(actual["without_native_counters"], ["bench/comet.cpp", "star/src/forgotten.cpp", "star/src/types.hpp"])
            self.assertEqual(actual["unregistered_counters"], [])
            entries.append({"file": "star/src/untracked.cpp", "lines": 1})
            self.assertEqual(coverage.inventory(names, units, entries, root, output)["unregistered_counters"], ["star/src/untracked.cpp"])

            # A note records compilation even when every instrumented source line is unexecuted.
            entries[0]["lines"] = 0
            self.assertEqual(coverage.inventory(names, units, entries, root, output)["compiled"], ["star/src/active.cpp"])
            (output / "active.gcno").unlink()
            self.assertEqual(coverage.inventory(names, units, entries, root, output)["compiled"], [])
            (output / "active.gcda").write_bytes(b"a stale execution file is not a compilation note")
            self.assertEqual(coverage.inventory(names, units, entries, root, output)["compiled"], [])

            # Missing metadata and output aliases cannot manufacture a native compilation fact.
            for field in ("directory", "output"):
                invalid = copy.deepcopy(units)
                del invalid[0][field]
                with self.subTest(missing=field), self.assertRaisesRegex(verify.Invalid, "coverage-recipe-metadata"):
                    coverage.inventory(names, invalid, entries, root, output)
                for value in (None, "", 1, [], {}):
                    invalid = copy.deepcopy(units)
                    invalid[0][field] = value
                    with self.subTest(field=field, value=value), self.assertRaisesRegex(verify.Invalid, "coverage-recipe-metadata"):
                        coverage.inventory(names, invalid, entries, root, output)
            for field, value in (("directory", str(root)), ("directory", "relative"), ("output", "../../outside.o"), ("output", str(root / "outside.o"))):
                invalid = copy.deepcopy(units)
                invalid[0][field] = value
                with self.subTest(field=field, value=value), self.assertRaisesRegex(verify.Invalid, "coverage-recipe-boundary"):
                    coverage.inventory(names, invalid, entries, root, output)

            # Output identity comes from -o, never from choosing whichever candidate happens to exist.
            for command in (
                "c++ -c active.cpp",
                "c++ -o active.o -c",
                "c++ -o active.o -o duplicate.o -c active.cpp",
                "c++ -o active.o -c active.cpp -c duplicate.cpp",
                "c++ @hidden.rsp -o active.o -c active.cpp",
                "c++ -o active.o -c active.cpp && echo substituted",
                "c++ -o 'broken -c active.cpp",
                "c++ -o other.o -c active.cpp",
            ):
                invalid = copy.deepcopy(units)
                invalid[0]["command"] = command
                with self.subTest(command=command), self.assertRaises(verify.Invalid):
                    coverage.inventory(names, invalid, entries, root, output)
            for arguments in (None, [], "c++ -o active.o", ["c++", None], ["c++", "-o", "different.o", "-c", units[0]["file"]]):
                invalid = copy.deepcopy(units)
                invalid[0].pop("command")
                invalid[0]["arguments"] = arguments
                with self.subTest(arguments=arguments), self.assertRaises(verify.Invalid):
                    coverage.inventory(names, invalid, entries, root, output)
            valid = copy.deepcopy(units)
            for unit in valid:
                unit["arguments"] = shlex.split(unit["command"])
                del unit["command"]
            (output / "active.gcno").write_bytes(b"native note identity")
            self.assertEqual(coverage.inventory(names, valid, entries, root, output)["compiled"], ["star/src/active.cpp"])
            invalid = copy.deepcopy(units)
            invalid[0]["arguments"] = ["c++", "-o", "different.o", "-c", units[0]["file"]]
            with self.assertRaisesRegex(verify.Invalid, "coverage-recipe-mismatch"):
                coverage.inventory(names, invalid, entries, root, output)
            if os.name == "posix":
                # A path alias must not borrow a neighboring compilation note, even within the owned build.
                alias = output / "alias"
                alias.symlink_to(output, target_is_directory=True)
                for field in ("directory", "output", "command"):
                    invalid = copy.deepcopy(units)
                    invalid[0][field] = {
                        "directory": str(alias),
                        "output": "alias/active.o",
                        "command": shlex.join(["c++", "-o", "alias/active.o", "-c", units[0]["file"]]),
                    }[field]
                    with self.subTest(alias=field), self.assertRaisesRegex(verify.Invalid, "coverage-recipe-boundary"):
                        coverage.inventory(names, invalid, entries, root, output)

    def test_export_scope(self) -> None:
        """A complete synthetic counter stream still blocks when its source is absent from the input inventory."""
        temporary = Path(__file__).resolve().parents[1] / "build/tmp"
        temporary.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temporary, prefix="coverage-scope-") as directory:
            root = Path(directory).resolve()
            build = root / "build/objects"
            build.mkdir(parents=True)
            (build / "unit.gcno").write_bytes(b"fixture")
            nested = build / "comet/cpp"
            nested.mkdir(parents=True)
            (nested / "core.gcno").write_bytes(b"nested native note fixture")
            tool = root / "tools/gcc-16.2.0/bin/gcov"
            tool.parent.mkdir(parents=True)
            tool.write_bytes(b"synthetic tool identity; never executed")
            (build / "compile_commands.json").write_text(
                json.dumps(
                    [
                        {
                            "file": str(root / "star/src/active.cpp"),
                            "directory": str(build),
                            "output": "unit.o",
                            "command": shlex.join(["c++", "--coverage", "-fcondition-coverage", "-o", "unit.o", "-c", str(root / "star/src/active.cpp")]),
                        },
                        {
                            "file": str(root / "comet/cpp/src/core.cpp"),
                            "directory": str(nested),
                            # CMake's output metadata is build-relative; the actual -o operand is cwd-relative.
                            "output": "comet/cpp/core.o",
                            "command": shlex.join(["c++", "--coverage", "-fcondition-coverage", "-o", "core.o", "-c", str(root / "comet/cpp/src/core.cpp")]),
                        },
                    ]
                )
            )
            source = {"files": [{"path": name, "sha256": "0" * 64} for name in ("star/src/active.cpp", "star/src/forgotten.cpp", "comet/cpp/src/core.cpp")]}
            for name, expected in (("active", 0), ("unregistered", 2)):
                stream = {
                    "format_version": "2",
                    "gcc_version": "16.2.0",
                    "current_working_directory": str(root),
                    "files": [{"file": f"star/src/{name}.cpp", "lines": [{"count": 1, "branches": [], "conditions": []}]}],
                }
                output = root / ("build/report-" + name)

                def capture(check: dict, source_root: Path, destination: Path, platform: str) -> dict:
                    """Supply a declared synthetic compiler stream to the actual exporter and scope checks."""
                    actual = copy.deepcopy(stream)
                    if Path(check["argv"][-1]).parent == nested:
                        actual["files"][0]["file"] = "comet/cpp/src/core.cpp"
                    return {
                        "exit_code": 0,
                        "complete": True,
                        "cleanup": True,
                        "stdout": {**verify.write_new(destination / "gcov.stdout.log", json.dumps(actual).encode()), "path": "gcov.stdout.log"},
                        "stderr": {**verify.write_new(destination / "gcov.stderr.log", b""), "path": "gcov.stderr.log"},
                    }

                with (
                    patch.object(coverage.build, "ROOT", root),
                    patch.object(coverage.build, "CACHE", root),
                    patch.object(coverage.v, "source", return_value=source),
                    patch.object(coverage.v, "execute", side_effect=capture),
                    patch("builtins.print"),
                ):
                    self.assertEqual(coverage.main(["--build", str(build), "--output", str(output)]), expected)
                summary = json.loads((output / "summary.json").read_text())
                self.assertEqual(summary["scope"]["uncompiled_translation_units"], ["star/src/forgotten.cpp"])
                self.assertEqual(summary["scope"]["compiled"], ["comet/cpp/src/core.cpp", "star/src/active.cpp"])
                self.assertEqual(summary["qualification"], "not-evaluated")
                self.assertEqual(summary["status"], "collected" if expected == 0 else "blocked")


if __name__ == "__main__":
    unittest.main()
