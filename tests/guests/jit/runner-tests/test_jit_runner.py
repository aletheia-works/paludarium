"""Expose the approved JIT runner-test command without duplicating its cases."""

import importlib.util
import sys
import unittest
from pathlib import Path


def load_tests(loader, tests, pattern):
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    suite = unittest.TestSuite()
    for name in ("test_runner", "test_validation", "test_cost_profile", "test_cost_builder"):
        spec = importlib.util.spec_from_file_location(f"u14_scoped_{name}", root / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        suite.addTests(loader.loadTestsFromModule(module))
    for name in ("test_evidence", "test_policy", "test_build"):
        path = root.parent / "programs/runner-tests" / f"{name}.py"
        spec = importlib.util.spec_from_file_location(f"u14_shared_{name}", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        suite.addTests(loader.loadTestsFromModule(module))
    return suite
