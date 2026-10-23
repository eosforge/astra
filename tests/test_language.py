"""Check real CLI metadata diagnostics and isolated contract/STL failures offline."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parents[1]


def compile_metadata(compiler: str | Path, directory: Path) -> list[str]:
    """Check compile-time rejection using real configuration translation units in temporary copies, not duplicated validation logic."""
    original = (SOURCE / "common/src/options.hpp").read_text(encoding="utf-8")
    (directory / "config.cpp").write_text((SOURCE / "common/src/config.cpp").read_text(encoding="utf-8"), encoding="utf-8")
    cluster = '[[=Option{"galaxy", "Galaxy identifier: 1..64 safe ASCII bytes", 0, 0, true}]]'
    cases = [
        ("valid_metadata", None, None, None),
        ("duplicate_name", 'Option{"listen",', 'Option{"galaxy",', "static assertion failed"),
        ("missing_annotation", cluster, "", "Each CLI field requires exactly one annotation"),
        ("empty_description", '"Preferred connection group; 1..64 safe ASCII bytes"', '""', "static assertion failed"),
        (
            "reversed_range",
            '"Capacity per role; Star capacity includes self", 1, 4096',
            '"Capacity per role; Star capacity includes self", 4096, 1',
            "static assertion failed",
        ),
        ("invalid_default", "std::uint64_t maximum = 64;", "std::uint64_t maximum = 0;", "static assertion failed"),
        ("unsupported_type", 'std::string identity = "identity";', 'std::string_view identity = "identity";', "no matching function"),
        ("annotation_capacity", 'Option{"galaxy",', 'Option{"' + "c" * 48 + '",', "CLI annotation text exceeds its compile-time capacity"),
    ]
    passed = []
    env = dict(os.environ, LC_ALL="C")
    command = [
        compiler,
        "-std=c++26",
        "-freflection",
        "-fcontracts",
        "-fcontract-evaluation-semantic=enforce",
        "-fsyntax-only",
        "-fdiagnostics-color=never",
        "-fmax-errors=5",
        "-I" + str(SOURCE / "common/include"),
        str(directory / "config.cpp"),
    ]
    for name, before, after, diagnostic in cases:
        text = original
        if before is not None:
            if original.count(before) != 1:
                raise RuntimeError("Metadata fixture no longer selects exactly one declaration: " + name)
            text = original.replace(before, after, 1)
        (directory / "options.hpp").write_text(text, encoding="utf-8")
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=60)
        if (diagnostic is None and result.returncode != 0) or (diagnostic is not None and (result.returncode <= 0 or diagnostic not in result.stderr)):
            raise RuntimeError(f"Unexpected compiler result for {name}: {result.returncode}\n{result.stderr[-6000:]}")
        passed.append(name)
    return passed


def runtime_checks(probe: str | Path, semantic: str) -> list[str]:
    """Require the expected diagnostic and SIGABRT for contract violations; arbitrary crashes are not success."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    passed = []
    for mode in ("valid", "contract", "stl"):
        result = subprocess.run([probe, mode], capture_output=True, text=True, timeout=10, env=dict(os.environ, LC_ALL="C"))
        abort = mode == "stl" or (mode == "contract" and semantic == "enforce")
        expected = -signal.SIGABRT if abort else 0
        marker = "contract violation" if mode == "contract" else "Assertion"
        if result.returncode != expected or (abort and marker.lower() not in result.stderr.lower()):
            raise RuntimeError(f"Unexpected {semantic}/{mode} result: {result.returncode}\n{result.stderr[-3000:]}")
        passed.append(f"{semantic}_{mode}")
    return passed


def main() -> None:
    """Dispatch explicitly selected compile-time and contract-violation checks."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--probe", required=True)
    parser.add_argument("--semantic", choices=("enforce", "ignore"), required=True)
    parser.add_argument("--temporary-root", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="language-", dir=args.temporary_root) as temporary:
        cases = compile_metadata(args.compiler, Path(temporary))
        cases += runtime_checks(args.probe, args.semantic)
    print(json.dumps({"status": "pass", "cases": cases, "cleanup": "owned temporary source directory removed"}))


if __name__ == "__main__":
    main()
