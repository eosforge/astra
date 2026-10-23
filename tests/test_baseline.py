"""Include existing baseline-runner unit cases in the central discovery and line-coverage campaigns."""

import importlib.util
from pathlib import Path
import unittest


def load_tests(loader: unittest.TestLoader, tests: unittest.TestSuite, pattern: str | None) -> unittest.TestSuite:
    """Load the actual benchmark fixture once; an empty suite is a broken registration, not a pass."""
    path = Path(__file__).resolve().parents[1] / "bench/baseline/test_run.py"
    spec = importlib.util.spec_from_file_location("baseline_tests", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Baseline unit fixture cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite = loader.loadTestsFromModule(module)
    if suite.countTestCases() == 0:
        raise RuntimeError("Baseline unit fixture discovered no cases")
    return suite
